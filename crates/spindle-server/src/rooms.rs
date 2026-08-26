//! Rooms: creation, sending, and reading back.
//!
//! This is where the linear log stops being a library and starts being the
//! server. Two things follow from that and are worth stating before the code.
//!
//! **The pagination token is the linear index.** SPEC §10.2 notes that sync and
//! pagination tokens are opaque to clients, which is exactly what lets §10.4 put
//! `li` inside one. A DAG homeserver has to maintain a separate ordering to
//! paginate in; here the ordering already exists, because it was assigned once
//! at write.
//!
//! **Rooms are held open, not reloaded per request.** Rebuilding a `RoomLog`
//! from storage costs `O(room)`, so doing it per send would make the hot path
//! proportional to history — the precise cost this project exists to remove. A
//! room is loaded once and kept, which is the shape SPEC §15's per-room executor
//! takes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ruma::signatures::Ed25519KeyPair;
use ruma::{CanonicalJsonObject, CanonicalJsonValue, RoomVersionId};
use serde_json::{Map, Value};
use spindle_core::{EventId, EventInput, Pdu, RoomLog, StateKey};
use spindle_store::{Durability, FjallStore, RoomStore, StoreError};

/// Native rooms are v11 (SPEC §11.6).
const ROOM_VERSION: &str = "11";

/// Rooms held open, keyed by room ID.
pub struct Rooms {
    store: Arc<FjallStore>,
    server_name: String,
    open: Mutex<HashMap<String, RoomLog>>,
}

/// One stored event, as a client sees it.
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    pub event_id: String,
    pub li: i64,
    pub json: Value,
}

impl Rooms {
    #[must_use]
    pub fn new(store: Arc<FjallStore>, server_name: impl Into<String>) -> Self {
        Self {
            store,
            server_name: server_name.into(),
            open: Mutex::new(HashMap::new()),
        }
    }

    /// Create a room and return its ID.
    ///
    /// The create sequence is fixed and ordered: create, the creator's
    /// membership, power levels, join rules. That order is not stylistic —
    /// each event's authorization is checked against the state the previous
    /// ones established, so a power-levels event before a membership has no
    /// sender in the room to authorise it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if an event cannot be signed or stored.
    pub fn create(
        &self,
        creator: &str,
        key: &Ed25519KeyPair,
        name: Option<&str>,
        topic: Option<&str>,
    ) -> Result<String, RoomError> {
        let room_id = format!("!{}:{}", random_id(), self.server_name);
        let mut log = RoomLog::new();

        let mut events: Vec<(&str, String, Value)> = vec![
            (
                "m.room.create",
                String::new(),
                serde_json::json!({ "room_version": ROOM_VERSION, "creator": creator }),
            ),
            (
                "m.room.member",
                creator.to_owned(),
                serde_json::json!({ "membership": "join" }),
            ),
            (
                "m.room.power_levels",
                String::new(),
                serde_json::json!({
                    "users": { creator: 100 },
                    "users_default": 0,
                    "events_default": 0,
                    "state_default": 50,
                    "ban": 50, "kick": 50, "redact": 50, "invite": 0,
                }),
            ),
            (
                "m.room.join_rules",
                String::new(),
                serde_json::json!({ "join_rule": "invite" }),
            ),
        ];
        if let Some(name) = name {
            events.push((
                "m.room.name",
                String::new(),
                serde_json::json!({ "name": name }),
            ));
        }
        if let Some(topic) = topic {
            events.push((
                "m.room.topic",
                String::new(),
                serde_json::json!({ "topic": topic }),
            ));
        }

        for (event_type, state_key, content) in events {
            self.append(
                &mut log,
                &room_id,
                creator,
                key,
                event_type,
                Some(state_key.as_str()),
                &content,
            )?;
        }

        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.clone(), log);
        Ok(room_id)
    }

    /// Append a message event to a room the sender is in.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown, or the event cannot be
    /// signed or stored.
    pub fn send(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        content: &Value,
    ) -> Result<String, RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.append(log, room_id, sender, key, event_type, None, content)
        })
    }

    /// Events in `li` order, newest first, starting below `from`.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its records cannot be
    /// read.
    pub fn messages(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<TimelineEvent>, Option<i64>), RoomError> {
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        let restored = room_store
            .load()?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;

        let mut out = Vec::new();
        let mut next = None;
        for entry in restored.log.entries().rev() {
            let li = entry.li.get();
            if from.is_some_and(|from| li >= from) {
                continue;
            }
            if out.len() == limit {
                next = Some(li + 1);
                break;
            }
            let json = self.read_event(room_id, &entry.event_id)?;
            out.push(TimelineEvent {
                event_id: entry.event_id.as_str().to_owned(),
                li,
                json,
            });
        }
        Ok((out, next))
    }

    /// Room IDs a user is joined to.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if a room's records cannot be read.
    pub fn joined(&self, user_id: &str) -> Result<Vec<String>, RoomError> {
        let open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rooms = Vec::new();
        for (room_id, log) in open.iter() {
            let head = log.entries().next_back().map(|entry| entry.li);
            let joined = head
                .and_then(|li| log.state_after(li))
                .and_then(|state| state.get(&StateKey::new("m.room.member", user_id)))
                .is_some();
            if joined {
                rooms.push(room_id.clone());
            }
        }
        rooms.sort();
        Ok(rooms)
    }

    fn with_room<T>(
        &self,
        room_id: &str,
        work: impl FnOnce(&Self, &mut RoomLog) -> Result<T, RoomError>,
    ) -> Result<T, RoomError> {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log = open
            .get_mut(room_id)
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
        work(self, log)
    }

    /// Build, sign, append and persist one event.
    #[allow(clippy::too_many_arguments, reason = "an event is what it is")]
    fn append(
        &self,
        log: &mut RoomLog,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Result<String, RoomError> {
        let depth = log
            .entries()
            .next_back()
            .map_or(0, |entry| entry.depth.saturating_add(1));
        let prev: Vec<String> = log
            .forward_extremities()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect();

        let canonical = build_canonical(
            room_id, sender, event_type, state_key, content, &prev, depth,
        )?;
        let version = RoomVersionId::try_from(ROOM_VERSION)
            .map_err(|error| RoomError::Build(error.to_string()))?;
        let pdu = Pdu::sign(version, canonical, &self.server_name, key)
            .map_err(|error| RoomError::Build(format!("{error:?}")))?;

        let event_id = pdu.event_id().as_str().to_owned();
        let input = EventInput::new(
            event_id.clone(),
            prev.into_iter().map(EventId::new).collect(),
        );
        let input = match state_key {
            Some(state_key) => input.with_state_key(StateKey::new(event_type, state_key)),
            None => input,
        };

        let entry = log
            .append_remote(input)
            .map_err(|error| RoomError::Append(format!("{error:?}")))?
            .clone();

        // The signed JSON is stored beside the log entry. The log holds
        // ordering and state; the event body is what a client actually reads
        // back, and reconstructing it from the log would mean re-signing, which
        // would produce a different event ID.
        let json = canonical_to_json(pdu.canonical());
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        spindle_store::Store::put(
            self.store.as_ref(),
            &event_body_key(room_id, &event_id),
            &serde_json::to_vec(&json)?,
        )?;
        room_store.commit_entry(&entry, log, Durability::Group)?;
        Ok(event_id)
    }

    fn read_event(&self, room_id: &str, event_id: &EventId) -> Result<Value, RoomError> {
        let raw = spindle_store::ReadView::get(
            self.store.as_ref(),
            &event_body_key(room_id, event_id.as_str()),
        )?
        .ok_or_else(|| RoomError::MissingBody(event_id.as_str().to_owned()))?;
        Ok(serde_json::from_slice(&raw)?)
    }
}

/// Event bodies live beside the log, keyed by room and event ID.
fn event_body_key(room_id: &str, event_id: &str) -> Vec<u8> {
    let mut key =
        spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::EventIndex, room_id);
    key.extend_from_slice(event_id.as_bytes());
    key
}

fn build_canonical(
    room_id: &str,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
    prev_events: &[String],
    depth: u64,
) -> Result<CanonicalJsonObject, RoomError> {
    let mut object = CanonicalJsonObject::new();
    object.insert(
        "room_id".to_owned(),
        CanonicalJsonValue::String(room_id.to_owned()),
    );
    object.insert(
        "sender".to_owned(),
        CanonicalJsonValue::String(sender.to_owned()),
    );
    object.insert(
        "type".to_owned(),
        CanonicalJsonValue::String(event_type.to_owned()),
    );
    if let Some(state_key) = state_key {
        object.insert(
            "state_key".to_owned(),
            CanonicalJsonValue::String(state_key.to_owned()),
        );
    }
    object.insert("content".to_owned(), to_canonical(content)?);
    object.insert(
        "prev_events".to_owned(),
        CanonicalJsonValue::Array(
            prev_events
                .iter()
                .map(|id| CanonicalJsonValue::String(id.clone()))
                .collect(),
        ),
    );
    object.insert(
        "auth_events".to_owned(),
        CanonicalJsonValue::Array(Vec::new()),
    );
    object.insert(
        "depth".to_owned(),
        CanonicalJsonValue::Integer(depth.try_into().unwrap_or_default()),
    );
    object.insert(
        "origin_server_ts".to_owned(),
        CanonicalJsonValue::Integer(now_ms().try_into().unwrap_or_default()),
    );
    Ok(object)
}

fn to_canonical(value: &Value) -> Result<CanonicalJsonValue, RoomError> {
    CanonicalJsonValue::try_from(value.clone()).map_err(|error| RoomError::Build(error.to_string()))
}

fn canonical_to_json(object: &CanonicalJsonObject) -> Value {
    let mut out = Map::new();
    for (key, value) in object {
        out.insert(
            key.clone(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        );
    }
    Value::Object(out)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn random_id() -> String {
    use rand::RngCore as _;
    let mut bytes = [0_u8; 9];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| char::from(b'A' + (byte % 26)))
        .collect()
}

/// Why a room operation failed.
#[derive(Debug)]
pub enum RoomError {
    UnknownRoom(String),
    MissingBody(String),
    Build(String),
    Append(String),
    Storage(StoreError),
    Codec(String),
}

impl From<StoreError> for RoomError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<serde_json::Error> for RoomError {
    fn from(error: serde_json::Error) -> Self {
        Self::Codec(error.to_string())
    }
}

impl std::fmt::Display for RoomError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRoom(id) => write!(formatter, "no such room: {id}"),
            Self::MissingBody(id) => write!(formatter, "the body of {id} is missing"),
            Self::Build(message) => write!(formatter, "cannot build the event: {message}"),
            Self::Append(message) => write!(formatter, "cannot append: {message}"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Codec(message) => write!(formatter, "unreadable: {message}"),
        }
    }
}

impl std::error::Error for RoomError {}
