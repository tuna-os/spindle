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

use crate::authorize::StoredEvent;
use ruma::room_version_rules::RoomVersionRules;
use ruma::signatures::Ed25519KeyPair;
use ruma::{CanonicalJsonObject, CanonicalJsonValue, RoomVersionId};
use serde_json::{Map, Value};
use spindle_core::{EventId, EventInput, Pdu, RoomLog, StateKey};
use spindle_store::{Durability, FjallStore, RoomStore, StoreError};

/// Native rooms are v11 (SPEC §11.6).
const ROOM_VERSION: &str = "11";

/// The membership index stores the membership verbatim, not a flag. `join` and
/// `leave` are two of six states, and a boolean would have to be recomputed
/// from the room the moment invites or knocks matter.
const JOIN: &[u8] = b"join";

/// Invited, which is not joined -- `/sync` reports the two in different
/// sections and a client acts on them differently.
const INVITE: &[u8] = b"invite";

/// Rooms held open, keyed by room ID.
pub struct Rooms {
    store: Arc<FjallStore>,
    server_name: String,
    open: Mutex<HashMap<String, RoomLog>>,
    /// The server-global order `/sync` needs (SPEC §10.2). The linear index
    /// orders events within one room; nothing orders them across rooms, so
    /// this is the one counter that exists purely because a per-room order is
    /// not a server order.
    ///
    /// SPEC §10.2 describes a sharded counter with a watermark over in-flight
    /// ids, because commits there complete out of order. Here every append
    /// holds the same lock, so ids are assigned and committed in the same
    /// order and the watermark *is* the counter. That equivalence is a
    /// property of the single lock, and stops holding the moment §15's
    /// per-room executors land -- at which point the interval set the spec
    /// describes has to come back.
    stream: Mutex<u64>,
    /// Woken whenever an event lands, so a long-polling `/sync` does not have
    /// to spin. SPEC §10.3 wants per-room subscriber lists; this is the same
    /// shape at server granularity, which is enough while there is one lock.
    appended: tokio::sync::Notify,
}

/// A user's position in a room.
pub struct Receipt {
    pub event_id: String,
    pub li: i64,
    pub ts: u64,
}

/// What a client shows as a badge.
pub struct Unread {
    pub notification_count: usize,
    pub read_up_to: Option<String>,
}

/// What one `/sync` call found.
pub struct SyncResult {
    pub next_batch: u64,
    pub rooms: Vec<SyncRoom>,
    pub invited: Vec<String>,
}

/// One room's share of a sync response.
pub struct SyncRoom {
    pub room_id: String,
    pub state: Vec<Value>,
    pub events: Vec<Value>,
    /// Whether older events were left out, so a client knows to back-paginate
    /// rather than assume it has the room's whole history.
    pub limited: bool,
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
        let store_for_stream = Arc::clone(&store);
        Self {
            store,
            server_name: server_name.into(),
            open: Mutex::new(HashMap::new()),
            // Resumed, not reset. A counter that restarted at zero would
            // re-issue stream ids already on disk, overwriting the entries
            // they point at -- the same shape of bug as a room registry that
            // does not survive a restart, and worse, because it corrupts
            // rather than merely forgets.
            stream: Mutex::new(highest_stream_id(store_for_stream.as_ref())),
            appended: tokio::sync::Notify::new(),
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

    /// Set a user's membership in a room.
    ///
    /// Invite, join and leave are all one state event with a different
    /// `membership`, and none of them is checked here. Whether the sender may
    /// invite, whether the room's join rules admit this join, whether a leave
    /// is a leave or a kick — every one of those is a rule in the spec, and
    /// [`crate::authorize`] runs the spec's own implementation of them on the
    /// way through `append`. Re-deciding any of it here would be a second,
    /// divergent copy of the auth rules, which `docs/divergence.md` names as
    /// the thing that must not happen.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::Forbidden`] if the rules refuse the transition.
    pub fn set_membership(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        membership: &str,
        key: &Ed25519KeyPair,
    ) -> Result<String, RoomError> {
        let content = serde_json::json!({ "membership": membership });
        self.with_room(room_id, |rooms, log| {
            rooms.append(
                log,
                room_id,
                sender,
                key,
                "m.room.member",
                Some(target),
                &content,
            )
        })
    }

    /// Every current state event of a room, as full events.
    ///
    /// This is the one read that is `O(state)` rather than `O(1)`, and it is
    /// deliberately not on any write path: authorization uses point queries
    /// into the same snapshot, so sending an event never walks the room. The
    /// snapshot itself needs no computing — it is the one hanging off the head
    /// entry, already materialized.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or an event body is
    /// missing.
    pub fn state(&self, room_id: &str) -> Result<Vec<Value>, RoomError> {
        let ids = self.with_room(room_id, |_, log| Ok(current_state(log)))?;
        let mut events = Vec::with_capacity(ids.len());
        for (_, event_id) in ids {
            events.push(self.event(room_id, &event_id)?);
        }
        Ok(events)
    }

    /// The content of one current state event.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownState`] when the room has no such state,
    /// which is a different answer from an empty content and must stay that
    /// way: a client reading `m.room.topic` needs to tell "no topic" from "a
    /// topic that is the empty string".
    pub fn state_event(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Value, RoomError> {
        let wanted = StateKey::new(event_type, state_key);
        let found = self.with_room(room_id, |_, log| {
            Ok(current_state(log)
                .into_iter()
                .find(|(key, _)| *key == wanted)
                .map(|(_, id)| id))
        })?;
        let event_id = found.ok_or_else(|| {
            RoomError::UnknownState(format!("{event_type} with state key {state_key:?}"))
        })?;
        let event = self.read_event(room_id, &EventId::new(event_id))?;
        Ok(event
            .get("content")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())))
    }

    /// Set a state event.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the rules refuse it.
    pub fn set_state(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: &str,
        content: &Value,
    ) -> Result<String, RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.append(
                log,
                room_id,
                sender,
                key,
                event_type,
                Some(state_key),
                content,
            )
        })
    }

    /// One event by ID.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or the event is unknown.
    pub fn event(&self, room_id: &str, event_id: &str) -> Result<Value, RoomError> {
        // The room has to exist before its events can be looked up, or an
        // unknown room would answer "no such event" and a client could not
        // tell the two apart.
        self.with_room(room_id, |_, _| Ok(()))?;
        let mut event = self.read_event(room_id, &EventId::new(event_id))?;
        if let Some(object) = event.as_object_mut() {
            object.insert("event_id".to_owned(), Value::String(event_id.to_owned()));
        }
        Ok(event)
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
        // Against the open log, not a fresh `load()`. Reloading rebuilt the
        // whole `RoomLog` from storage on every page, which made the one
        // endpoint SPEC §10.4 calls "a reverse range scan ... that is the
        // whole implementation" cost `O(room)` per request instead. The API
        // benchmark caught it: `/messages` grew 2.47x between a 10-event room
        // and a 500-event one, and `/sync` 4.79x, while `send` stayed flat.
        let wanted = self.with_room(room_id, |_, log| {
            let mut wanted = Vec::new();
            let mut next = None;
            for entry in log.entries().rev() {
                let li = entry.li.get();
                if from.is_some_and(|from| li >= from) {
                    continue;
                }
                if wanted.len() == limit {
                    next = Some(li + 1);
                    break;
                }
                wanted.push((li, entry.event_id.as_str().to_owned()));
            }
            Ok((wanted, next))
        })?;

        let (wanted, next) = wanted;
        let mut out = Vec::with_capacity(wanted.len());
        for (li, event_id) in wanted {
            let json = self.read_event(room_id, &EventId::new(event_id.as_str()))?;
            out.push(TimelineEvent { event_id, li, json });
        }
        Ok((out, next))
    }

    /// Room IDs a user is joined to.
    ///
    /// A prefix scan of that user's membership rows, so the cost is
    /// proportional to the rooms they are in rather than to the rooms the
    /// server knows. Reading it from storage rather than from the open-rooms
    /// map is what makes it correct after a restart, when nothing is open yet.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn joined(&self, user_id: &str) -> Result<Vec<String>, RoomError> {
        self.membership_rooms(user_id, JOIN)
    }

    /// Record that `user_id` has read up to `event_id`.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::MissingBody`] if the event is not one of its events — a
    /// receipt for an event the room does not have would set an unread
    /// boundary at a position that means nothing.
    pub fn set_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        event_id: &str,
    ) -> Result<(), RoomError> {
        let li = self
            .with_room(room_id, |_, log| {
                Ok(log.get(&EventId::new(event_id)).map(|entry| entry.li.get()))
            })?
            .ok_or_else(|| RoomError::MissingBody(event_id.to_owned()))?;

        spindle_store::Store::put(
            self.store.as_ref(),
            &receipt_key(room_id, user_id, receipt_type),
            &ReceiptRecord {
                event_id: event_id.to_owned(),
                li,
                ts: now_ms(),
            }
            .encode(),
        )?;
        Ok(())
    }

    /// How many events a user has not read, and where they read up to.
    ///
    /// **The unread boundary is arithmetic, not a traversal.** Every accepted
    /// event holds a linear index, and the occupied range is contiguous --
    /// backfill fills `0, -1, -2, …` while live events fill `1, 2, 3, …`, so
    /// the two meet rather than leaving a hole. "Which events come after this
    /// one" is therefore `head - receipt`, exactly, including for a receipt on
    /// backfilled history. A DAG server answers the same question by ordering
    /// a graph first.
    ///
    /// The *count* still reads the events, because not everything in that
    /// range notifies: a user's own messages do not, and neither do state
    /// events. That is a scan of a contiguous range rather than a graph walk,
    /// and it is proportional to how far behind the user is -- which is a real
    /// cost for a long-absent one, and the reason SPEC §15's per-room executor
    /// eventually caches it.
    ///
    /// Push rules are not applied, because there are none yet (#7 lists them
    /// separately). Until then every message from somebody else counts, which
    /// is an over-count for a room with a mute rule and the honest behaviour
    /// for a server that has no rules to consult.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its events cannot be read.
    pub fn unread(&self, room_id: &str, user_id: &str) -> Result<Unread, RoomError> {
        let read_up_to = self.receipt(room_id, user_id, "m.read")?;
        // No receipt means nothing has been read, so the boundary sits below
        // every index the log can hold -- including backfilled history, which
        // is why this is `i64::MIN` and not zero.
        let boundary = read_up_to.as_ref().map_or(i64::MIN, |receipt| receipt.li);

        // Which events are after the receipt: arithmetic on the index, no
        // ordering step. Walking backwards from the head and stopping at the
        // boundary touches exactly the unread ones.
        let unread_ids = self.with_room(room_id, |_, log| {
            Ok(log
                .entries()
                .rev()
                .take_while(|entry| entry.li.get() > boundary)
                .filter(|entry| entry.state_key.is_none())
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect::<Vec<_>>())
        })?;

        let mut notification_count = 0;
        for id in unread_ids {
            // The sender lives in the body, so this is the part that reads.
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
            if event["sender"].as_str() != Some(user_id) {
                notification_count += 1;
            }
        }

        Ok(Unread {
            notification_count,
            read_up_to: read_up_to.map(|receipt| receipt.event_id),
        })
    }

    /// One user's receipt of one type, if they have set it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the record cannot be read.
    pub fn receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
    ) -> Result<Option<Receipt>, RoomError> {
        let Some(raw) = spindle_store::ReadView::get(
            self.store.as_ref(),
            &receipt_key(room_id, user_id, receipt_type),
        )?
        else {
            return Ok(None);
        };
        Ok(ReceiptRecord::decode(&raw).map(|record| Receipt {
            event_id: record.event_id,
            li: record.li,
            ts: record.ts,
        }))
    }

    /// The current global stream position.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        *self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Wait until an event lands, or the deadline passes.
    ///
    /// SPEC §10.3 wants `/sync` to be push rather than poll, and this is the
    /// smallest thing that is: a waiter is woken by the append itself, so a
    /// client blocked here costs nothing until there is something to send. It
    /// is server-wide rather than per-room, which wakes more clients than
    /// strictly needed -- correct, and coarser than §10.3's per-room
    /// subscriber lists, which is the shape to reach for when rooms stop
    /// sharing one lock.
    pub async fn wait_for_event(&self, timeout: std::time::Duration) {
        // `notified()` must be created *before* the position is re-checked by
        // the caller, or an append landing in between is missed and the client
        // waits out the full timeout for news that already arrived.
        let notified = self.appended.notified();
        let _ = tokio::time::timeout(timeout, notified).await;
    }

    /// Everything that happened after `since`, grouped by room.
    ///
    /// `since` of `None` is an initial sync: every joined room, with its
    /// current state and a tail of its timeline. Otherwise it is a range scan
    /// of the global stream from `since`, which is the cheap case and the
    /// common one.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the stream or an event cannot be read.
    pub fn sync(
        &self,
        user_id: &str,
        since: Option<u64>,
        timeline_limit: usize,
    ) -> Result<SyncResult, RoomError> {
        let position = self.stream_position();
        let joined = self.joined(user_id)?;
        let invited = self.invited(user_id)?;

        let mut rooms = Vec::new();
        for room_id in joined {
            let (events, limited) = match since {
                None => self.timeline_tail(&room_id, timeline_limit)?,
                Some(since) => (self.timeline_since(&room_id, since, position)?, false),
            };
            // An incremental sync says nothing about a room where nothing
            // happened. A client diffing rooms it was sent against rooms it
            // knows would otherwise see an empty timeline as a change.
            if since.is_some() && events.is_empty() {
                continue;
            }
            rooms.push(SyncRoom {
                room_id: room_id.clone(),
                // State only on an initial sync. Incrementally, the state
                // events are in the timeline already, and sending them twice
                // would make a client apply each one twice.
                state: if since.is_none() {
                    self.state(&room_id)?
                } else {
                    Vec::new()
                },
                events,
                limited,
            });
        }

        Ok(SyncResult {
            next_batch: position,
            rooms,
            invited,
        })
    }

    /// Rooms this user has been invited to but has not joined.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn invited(&self, user_id: &str) -> Result<Vec<String>, RoomError> {
        self.membership_rooms(user_id, INVITE)
    }

    /// The newest `limit` events of a room, oldest first.
    fn timeline_tail(&self, room_id: &str, limit: usize) -> Result<(Vec<Value>, bool), RoomError> {
        let (events, more) = self.messages(room_id, None, limit)?;
        let mut out: Vec<Value> = events
            .into_iter()
            .map(|event| stamp(event.json, &event.event_id))
            .collect();
        out.reverse();
        Ok((out, more.is_some()))
    }

    /// Events of one room that entered the global stream after `since`.
    fn timeline_since(
        &self,
        room_id: &str,
        since: u64,
        position: u64,
    ) -> Result<Vec<Value>, RoomError> {
        let mut out = Vec::new();
        for stream_id in (since + 1)..=position {
            let Some(raw) = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::stream(stream_id),
            )?
            else {
                continue;
            };
            let Some(record) = StreamRecord::decode(&raw) else {
                continue;
            };
            if record.room_id != room_id {
                continue;
            }
            let event_id = self.with_room(room_id, |_, log| {
                Ok(log
                    .entries()
                    .find(|entry| entry.li.get() == record.li)
                    .map(|entry| entry.event_id.as_str().to_owned()))
            })?;
            if let Some(event_id) = event_id {
                out.push(self.event(room_id, &event_id)?);
            }
        }
        Ok(out)
    }

    fn membership_rooms(&self, user_id: &str, wanted: &[u8]) -> Result<Vec<String>, RoomError> {
        let prefix =
            spindle_core::keys::user_prefix(spindle_core::keys::Keyspace::Membership, user_id);
        let mut rooms: Vec<String> =
            spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?
                .into_iter()
                .filter(|(_, membership)| membership.as_slice() == wanted)
                .filter_map(|(key, _)| spindle_core::keys::room_from_user_room(user_id, &key))
                .collect();
        rooms.sort();
        rooms.dedup();
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
        if !open.contains_key(room_id) {
            let restored = RoomStore::new(self.store.as_ref(), room_id)
                .load()?
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            open.insert(room_id.to_owned(), restored.log);
        }
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

        let auth = auth_events_for(log, sender, event_type, state_key, content)?;
        let canonical = build_canonical(
            room_id, sender, event_type, state_key, content, &prev, &auth, depth,
        )?;
        let version = RoomVersionId::try_from(ROOM_VERSION)
            .map_err(|error| RoomError::Build(error.to_string()))?;
        let pdu = Pdu::sign(version, canonical, &self.server_name, key)
            .map_err(|error| RoomError::Build(format!("{error:?}")))?;

        let event_id = pdu.event_id().as_str().to_owned();
        let json = canonical_to_json(pdu.canonical());

        // Authorized before it is appended, against the state the log already
        // holds materialized. Signing first costs a wasted signature on a
        // refused event and buys something worth more: what gets authorized is
        // exactly the bytes a peer would receive, event ID included.
        self.authorize(log, room_id, &event_id, &json)?;

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
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        spindle_store::Store::put(
            self.store.as_ref(),
            &event_body_key(room_id, &event_id),
            &serde_json::to_vec(&json)?,
        )?;
        // The stream id goes in the entry's own batch, so an event is either
        // in the global order or not stored at all. Assigned under the same
        // lock that serialises appends, which is what makes the watermark the
        // counter -- see the field's own note.
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stream_id = stream.saturating_add(1);
        room_store.commit_entry_with(
            &entry,
            log,
            &[(
                spindle_core::keys::stream(stream_id),
                StreamRecord {
                    room_id: room_id.to_owned(),
                    li: entry.li.get(),
                }
                .encode(),
            )],
            Durability::Group,
        )?;
        *stream = stream_id;
        drop(stream);

        // The index is derived from the event that just landed, and only from
        // an event that landed: writing it before the commit would leave a
        // user joined to a room whose membership event was never stored.
        if event_type == "m.room.member" {
            self.index_membership(room_id, state_key, content)?;
        }
        self.appended.notify_waiters();
        Ok(event_id)
    }

    /// Record `(user, room) -> membership` so `/joined_rooms` need not open
    /// every room the server knows to answer.
    ///
    /// A membership other than `join` is written rather than deleted: the
    /// difference between "left" and "never joined" is one a later invite or
    /// ban check needs, and a delete would erase it.
    fn index_membership(
        &self,
        room_id: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Result<(), RoomError> {
        let (Some(user_id), Some(membership)) = (state_key, content["membership"].as_str()) else {
            return Ok(());
        };
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Membership,
                user_id,
                room_id,
            ),
            membership.as_bytes(),
        )?;
        Ok(())
    }

    /// Refuse the candidate unless ruma's predicate allows it.
    ///
    /// The state lookups go through the snapshot the log already holds, which
    /// is the whole point (`docs/divergence.md` §3): a DAG server has to
    /// compute or fetch the state to check against, and we index into it. Each
    /// hit still costs one keyed read for the event body, because the snapshot
    /// stores event IDs rather than bodies — at most five reads, and none of
    /// them proportional to the room.
    fn authorize(
        &self,
        log: &RoomLog,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        let candidate = StoredEvent::parse(event_id, json).map_err(|error| {
            RoomError::Build(format!("cannot authorize a malformed event: {error}"))
        })?;

        // Nothing is resident before the create event, and the create event is
        // the one the rules check without any state at all.
        let state = log
            .entries()
            .next_back()
            .map(|entry| entry.li)
            .and_then(|li| log.state_after(li));

        let load = |id: &str| -> Option<StoredEvent> {
            let body = self.read_event(room_id, &EventId::new(id)).ok()?;
            StoredEvent::parse(id, &body).ok()
        };

        crate::authorize::authorize(
            &RoomVersionRules::V11.authorization,
            &candidate,
            |event_type: &ruma::events::StateEventType, state_key: &str| {
                let id = state?.get(&StateKey::new(event_type.to_string().as_str(), state_key))?;
                load(id)
            },
        )
        .map_err(RoomError::Forbidden)
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

/// Put the event ID into the body a client sees.
///
/// A v11 event does not carry its own ID -- the ID *is* the hash of the body,
/// so storing it inside would change what it hashes to.
fn stamp(mut json: Value, event_id: &str) -> Value {
    if let Some(object) = json.as_object_mut() {
        object.insert("event_id".to_owned(), Value::String(event_id.to_owned()));
    }
    json
}

/// The room's current state, as `(key, event_id)` pairs.
fn current_state(log: &RoomLog) -> Vec<(StateKey, String)> {
    let Some(state) = log
        .entries()
        .next_back()
        .map(|entry| entry.li)
        .and_then(|li| log.state_after(li))
    else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(state.len());
    // Key order comes from `for_each`, which sorts. The trie itself places
    // entries by hash, so its raw walk order is an artefact of the digest --
    // sorting again here would be a second copy of a guarantee that already
    // has one, and one that could silently disagree with it.
    state.for_each(|key, event_id| out.push((key.clone(), event_id.to_owned())));
    out
}

/// Receipts live per room, per user, per type.
fn receipt_key(room_id: &str, user_id: &str, receipt_type: &str) -> Vec<u8> {
    let mut key = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Receipt, room_id);
    // Length-prefixed for the same reason room and user keys are: `@ab` must
    // not be read as `@a` followed by a type beginning `b`.
    let user = user_id.as_bytes();
    key.extend_from_slice(&u16::try_from(user.len()).unwrap_or(u16::MAX).to_be_bytes());
    key.extend_from_slice(user);
    key.extend_from_slice(receipt_type.as_bytes());
    key
}

struct ReceiptRecord {
    event_id: String,
    li: i64,
    ts: u64,
}

impl ReceiptRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.event_id.len());
        out.extend_from_slice(&self.li.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(self.event_id.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let li = i64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let ts = u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?);
        let event_id = String::from_utf8(bytes.get(16..)?.to_vec()).ok()?;
        Some(Self { event_id, li, ts })
    }
}

/// Event bodies live beside the log, keyed by room and event ID.
fn event_body_key(room_id: &str, event_id: &str) -> Vec<u8> {
    let mut key =
        spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::EventIndex, room_id);
    key.extend_from_slice(event_id.as_bytes());
    key
}

/// The state events a new event must cite to be authorizable (room v11's
/// auth-events selection rules).
///
/// `m.room.create` cites nothing — it is the root of the auth chain. Every
/// other event names the create event, the current power levels, and the
/// sender's own membership; a membership event additionally names the join
/// rules and, when it targets somebody else, that person's membership.
///
/// This is not bookkeeping that can wait for the second participant. A v11
/// event with an empty `auth_events` fails `auth_check` on any peer that
/// receives it, whatever the room's size — so a server that omits it is not
/// building a local-only room on purpose, it is minting events nobody else
/// will ever accept.
///
/// Missing state is an error rather than an empty list, because the two are
/// indistinguishable on the wire and only one of them is correct.
fn auth_events_for(
    log: &RoomLog,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
) -> Result<Vec<String>, RoomError> {
    if event_type == "m.room.create" {
        return Ok(Vec::new());
    }
    let head = log
        .entries()
        .next_back()
        .map(|entry| entry.li)
        .ok_or_else(|| RoomError::StateUnavailable("the room has no events".to_owned()))?;
    let state = log.state_after(head).ok_or_else(|| {
        RoomError::StateUnavailable(format!("the state after li {} is not resident", head.get()))
    })?;

    let mut auth = Vec::new();
    let mut cite = |kind: &str, key: &str| {
        if let Some(id) = state.get(&StateKey::new(kind, key)) {
            auth.push(id.to_owned());
        }
    };
    cite("m.room.create", "");
    cite("m.room.power_levels", "");
    cite("m.room.member", sender);
    if event_type == "m.room.member" {
        // Only for memberships the join rules have any say over. A leave or a
        // ban is not gated on how the room admits people, so citing the join
        // rules there is not harmless padding -- it is a longer list than the
        // rules call for, and a peer checking the list against its own
        // selection rejects the event. Found by the ruma cross-check
        // disagreeing with what this code originally did, which asserted my
        // reading of the spec rather than the spec.
        if matches!(
            content["membership"].as_str(),
            Some("join" | "invite" | "knock")
        ) {
            cite("m.room.join_rules", "");
        }
        // A membership event that acts on somebody else has to cite what it is
        // acting on: their current membership decides whether the transition is
        // allowed at all.
        if let Some(target) = state_key.filter(|target| *target != sender) {
            cite("m.room.member", target);
        }
    }
    Ok(auth)
}

#[allow(clippy::too_many_arguments, reason = "an event is what it is")]
fn build_canonical(
    room_id: &str,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
    prev_events: &[String],
    auth_events: &[String],
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
        CanonicalJsonValue::Array(
            auth_events
                .iter()
                .map(|id| CanonicalJsonValue::String(id.clone()))
                .collect(),
        ),
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
    StateUnavailable(String),
    UnknownState(String),
    Forbidden(String),
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
            Self::StateUnavailable(message) => {
                write!(formatter, "cannot authorize the event: {message}")
            }
            Self::UnknownState(what) => write!(formatter, "no {what} in this room"),
            Self::Forbidden(rule) => write!(formatter, "{rule}"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Codec(message) => write!(formatter, "unreadable: {message}"),
        }
    }
}

impl std::error::Error for RoomError {}

/// What the global stream stores at each id: which room, and where in it.
///
/// Deliberately not the event itself. The stream exists to give `/sync` a
/// total order across rooms; the events are already in the log, and copying
/// them would make every append write the event twice and every edit to the
/// storage format have two places to change.
struct StreamRecord {
    room_id: String,
    li: i64,
}

impl StreamRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.room_id.len());
        out.extend_from_slice(&self.li.to_be_bytes());
        out.extend_from_slice(self.room_id.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let li = i64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let room_id = String::from_utf8(bytes.get(8..)?.to_vec()).ok()?;
        Some(Self { room_id, li })
    }
}

/// The highest stream id already on disk, or 0 for a fresh store.
fn highest_stream_id(store: &FjallStore) -> u64 {
    // A prefix scan rather than a stored high-water mark: one number that has
    // to be kept in step with the rows it describes is one number that can
    // disagree with them, and the rows are the truth.
    spindle_store::ReadView::scan_prefix(store, &spindle_core::keys::stream_prefix())
        .unwrap_or_default()
        .iter()
        .filter_map(|(key, _)| spindle_core::keys::stream_from_key(key))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod membership_index_tests {
    use std::sync::Arc;

    use spindle_core::keys::{Keyspace, user_room};
    use spindle_store::{FjallStore, Store};
    use tempfile::TempDir;

    use super::Rooms;

    /// `/joined_rooms` must list only rooms the user is *in*. No endpoint can
    /// produce a membership other than `join` yet, so the row is written
    /// directly here — the reader has to be right before the writer that
    /// exercises it exists, or leaving a room would silently keep it in the
    /// list. Delete this in favour of an end-to-end leave once there is a
    /// `/leave` endpoint.
    #[test]
    fn a_room_the_user_left_is_not_a_room_they_are_in() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let rooms = Rooms::new(Arc::clone(&store), "example.org");
        let user = "@alice:example.org";

        for (room, membership) in [
            ("!stayed:example.org", "join"),
            ("!left:example.org", "leave"),
            ("!banned:example.org", "ban"),
            ("!invited:example.org", "invite"),
        ] {
            store
                .put(
                    &user_room(Keyspace::Membership, user, room),
                    membership.as_bytes(),
                )
                .unwrap();
        }

        assert_eq!(
            rooms.joined(user).unwrap(),
            vec!["!stayed:example.org".to_owned()]
        );
    }
}
