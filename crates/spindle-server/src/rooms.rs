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
use spindle_core::{EventId, EventInput, LogEntry, Pdu, RoomLog, StateKey};
use spindle_store::{Durability, FjallStore, RoomStore, StoreError};

/// Native rooms are v11 (SPEC §11.6).
pub const ROOM_VERSION: &str = "11";

/// The membership index stores the membership verbatim, not a flag. `join` and
/// `leave` are two of six states, and a boolean would have to be recomputed
/// from the room the moment invites or knocks matter.
const JOIN: &[u8] = b"join";

/// The same word as [`JOIN`], as a `str`, for comparing against event content
/// rather than against index bytes. One definition would need a conversion at
/// every use; two constants that cannot drift apart are checked below instead.
const JOIN_STR: &str = "join";

const _: () = assert!(
    JOIN_STR.as_bytes()[0] == JOIN[0] && JOIN_STR.len() == JOIN.len(),
    "the membership index and the event content must spell `join` the same way"
);

/// Invited, which is not joined -- `/sync` reports the two in different
/// sections and a client acts on them differently.
const INVITE: &[u8] = b"invite";

/// Left of their own accord.
const LEAVE: &[u8] = b"leave";

/// Removed by someone else. A different membership from [`LEAVE`], and it has
/// to stay one -- the auth rules refuse a rejoin only while the state says
/// `ban` -- but for `/sync` the two are the same section: either way the user
/// is out of the room.
const BAN: &[u8] = b"ban";

/// [`INVITE`] as a `str`, for the same reason [`JOIN_STR`] exists.
const INVITE_STR: &str = "invite";

const _: () = assert!(
    INVITE_STR.as_bytes()[0] == INVITE[0] && INVITE_STR.len() == INVITE.len(),
    "the membership index and the event content must spell `invite` the same way"
);

/// Rooms held open, keyed by room ID.
/// Per-room index answering "how many timeline events after `li`, and how
/// many of them are mine" without reading a single event body.
///
/// Exists because the unread count used to read every body after the
/// receipt floor to learn its sender — O(events since floor) store reads
/// per sync, which for a user with no receipt (every bot, every client
/// that doesn't send read receipts) meant the whole room, every time. The
/// M2 close-out benchmark caught it: the one column where a sibling was
/// faster, and the one whose curve grew with room size. Built once per
/// room per process (the one remaining full walk), updated on append,
/// queried by binary search.
#[derive(Default)]
struct UnreadIndex {
    /// Linear indices of every timeline (non-state) entry, ascending.
    timeline: Vec<i64>,
    /// The same, per sender.
    by_sender: HashMap<String, Vec<i64>>,
}

impl UnreadIndex {
    fn push(&mut self, li: i64, sender: &str) {
        // Appends arrive in li order, so pushing keeps both vectors sorted.
        // Backfill (negative indices, M3) must not use this path: it would
        // break the invariant — invalidate the room's cache instead.
        self.timeline.push(li);
        self.by_sender
            .entry(sender.to_owned())
            .or_default()
            .push(li);
    }

    /// Timeline events after `boundary` not sent by `user_id`.
    fn count_after(&self, boundary: i64, user_id: &str) -> usize {
        let after = |lis: &[i64]| lis.len() - lis.partition_point(|&li| li <= boundary);
        let own = self.by_sender.get(user_id).map_or(0, |lis| after(lis));
        after(&self.timeline) - own
    }
}

/// One cached `/state` render: the root it was rendered from, and the body.
type StateRender = ([u8; 32], Arc<String>);

pub struct Rooms {
    store: Arc<FjallStore>,
    server_name: String,
    open: Mutex<HashMap<String, RoomLog>>,
    /// Lock order: `open` before `unread_index`, always. The fast path takes
    /// only `unread_index`; the build and append paths already hold `open`.
    unread_index: Mutex<HashMap<String, UnreadIndex>>,
    /// Head-event timestamp per room, kept warm on append.
    ///
    /// The sliding-sync room list sorts by recency, so every request reads
    /// this for every joined room. Uncached, that was a stored-body read
    /// and a full JSON parse per room per request — the M3-progress
    /// benchmark measured it as the per-room marginal cost that let the
    /// `sliding_window` cells drift below the noise floor against
    /// Continuwuity across two sittings. A sort key is one i64; it lives
    /// in memory and is refreshed by the append that changes it.
    last_activity: Mutex<HashMap<String, i64>>,
    /// The rendered `/state` body per room, keyed by the state root it was
    /// rendered from.
    ///
    /// The state is content-addressed, so the root *is* the render's
    /// identity: a hit is provably current and a mismatch is the only
    /// invalidation needed. What it buys is the whole marginal cost of the
    /// endpoint — per-event body reads, JSON parses and re-serialization —
    /// which the M3 comparison against Tuwunel measured as the one cell
    /// where a `RocksDB` block cache beat our per-request reads across two
    /// sittings. Serving a memcpy of a proven-current render beats warming
    /// a page cache.
    state_render: Mutex<HashMap<String, StateRender>>,
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

/// The events around one event, and the state there.
pub struct Context {
    pub event: Value,
    pub events_before: Vec<Value>,
    pub events_after: Vec<Value>,
    pub state: Vec<Value>,
    pub start: i64,
    pub end: i64,
}

/// What one `/sync` call found.
pub struct SyncResult {
    pub next_batch: u64,
    pub rooms: Vec<SyncRoom>,
    pub invited: Vec<String>,
    pub left: Vec<SyncRoom>,
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

/// A room as MSC3266 describes it to someone who may not be in it.
///
/// Everything optional is optional because the room may simply not have set
/// it. The two booleans are not optional because "not set" and "false" mean
/// the same thing for them: a room with no `m.room.guest_access` does not
/// admit guests.
pub struct RoomSummary {
    pub room_id: String,
    pub name: Option<String>,
    pub topic: Option<String>,
    pub avatar_url: Option<String>,
    pub canonical_alias: Option<String>,
    pub num_joined_members: usize,
    pub world_readable: bool,
    pub guest_can_join: bool,
    pub join_rule: Option<String>,
    pub room_type: Option<String>,
    pub encryption: Option<String>,
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
            unread_index: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(HashMap::new()),
            state_render: Mutex::new(HashMap::new()),
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
    #[allow(clippy::too_many_arguments, reason = "a room's birth options")]
    pub fn create(
        &self,
        creator: &str,
        key: &Ed25519KeyPair,
        name: Option<&str>,
        topic: Option<&str>,
        preset: Option<&str>,
        initial_state: &[(String, String, Value)],
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
                // The preset names the spec's bundles: public_chat opens the
                // door, everything else keeps the default invite-only.
                serde_json::json!({
                    "join_rule": if preset == Some("public_chat") { "public" } else { "invite" },
                }),
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
        // The client's initial_state, after the bundle so it can override
        // any of it — that is what the field is for.
        for (event_type, state_key, content) in initial_state {
            self.append(
                &mut log,
                &room_id,
                creator,
                key,
                event_type,
                Some(state_key.as_str()),
                content,
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
        reason: Option<&str>,
        key: &Ed25519KeyPair,
    ) -> Result<String, RoomError> {
        let mut content = serde_json::json!({ "membership": membership });
        // Absent rather than null when there is no reason: `reason` is part of
        // the event content, so it is covered by the signature and by the
        // event ID, and a null would make the same kick hash differently from
        // one sent by a server that simply omits the field.
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_owned());
        }
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

    /// Build and sign the invite event for a user on another server,
    /// without appending it.
    ///
    /// The event is authorized against the room's head — an invite this
    /// server's own rules would refuse is refused before any network is
    /// touched — but it does not enter the log here: the invited user's
    /// server must co-sign it first, and [`Self::commit_cosigned`] appends
    /// what comes back.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::Forbidden`] if the rules refuse the invite.
    pub fn build_invite_event(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        reason: Option<&str>,
        key: &Ed25519KeyPair,
    ) -> Result<(String, Value), RoomError> {
        let mut content = serde_json::json!({ "membership": INVITE_STR });
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_owned());
        }
        self.with_room(room_id, |rooms, log| {
            rooms.build_event(
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

    /// Record an invite into a room this server holds no log for.
    ///
    /// A federated invite arrives alone: no history, no state, just the
    /// signed event and whatever stripped state the inviting server chose
    /// to share. What makes it real for the invited user is a membership
    /// row — the same row `/sync` reads for every other invite — plus this
    /// side record holding the stripped state to render it from and the
    /// origin to try first when the user accepts.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store refuses the writes.
    pub fn record_pending_invite(
        &self,
        user_id: &str,
        room_id: &str,
        origin: &str,
        invite_state: &[Value],
    ) -> Result<(), RoomError> {
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::PendingInvite,
                user_id,
                room_id,
            ),
            serde_json::json!({ "origin": origin, "invite_state": invite_state })
                .to_string()
                .as_bytes(),
        )?;
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Membership,
                user_id,
                room_id,
            ),
            INVITE,
        )?;
        // An invite un-forgets, here as in `index_membership`: the user is
        // being asked back in, and a forgotten room would swallow the ask.
        spindle_store::Store::delete(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Forgotten,
                user_id,
                room_id,
            ),
        )?;
        self.wake_sync_waiters();
        Ok(())
    }

    /// The pending-invite record for a user and room, if one stands.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be read.
    pub fn pending_invite(&self, user_id: &str, room_id: &str) -> Result<Option<Value>, RoomError> {
        let row = spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::PendingInvite,
                user_id,
                room_id,
            ),
        )?;
        Ok(row.and_then(|bytes| serde_json::from_slice(&bytes).ok()))
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
            // `read_event` directly rather than `event()`: the room's
            // existence is already established, and `event()` would take
            // the room lock once per state event just to re-prove it.
            let mut event = self.read_event(room_id, &EventId::new(event_id.as_str()))?;
            if let Some(object) = event.as_object_mut() {
                object.insert("event_id".to_owned(), Value::String(event_id));
            }
            events.push(event);
        }
        Ok(events)
    }

    /// The full room state as one serialized JSON array, served from the
    /// render cache when the state root still matches.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or a body is missing.
    pub fn state_serialized(&self, room_id: &str) -> Result<Arc<String>, RoomError> {
        let root = self.with_room(room_id, |_, log| {
            Ok(log
                .entries()
                .next_back()
                .and_then(|head| log.state_after(head.li))
                .map(|state| *state.root().as_bytes()))
        })?;
        let Some(root) = root else {
            // A room with no state renders as the empty array; not worth a
            // cache row.
            return Ok(Arc::new("[]".to_owned()));
        };
        if let Some((cached_root, body)) = self
            .state_render
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
            && *cached_root == root
        {
            return Ok(Arc::clone(body));
        }
        let rendered = Arc::new(Value::Array(self.state(room_id)?).to_string());
        self.state_render
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), (root, Arc::clone(&rendered)));
        Ok(rendered)
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

    /// Redact an event.
    ///
    /// **The redaction algorithm is ruma's**, for the same reason the auth
    /// rules are (`docs/divergence.md` §3): it is spec-defined, fiddly, and
    /// version-dependent, and a second implementation of it is a second thing
    /// to keep in step with the spec. What is ours is only *when* it runs and
    /// what is stored afterwards.
    ///
    /// The redaction is itself an event, authorized like any other — a user
    /// who may not redact is refused by the rules rather than by a check here.
    ///
    /// **The stored body is rewritten in place**, which SPEC §10.5 calls for
    /// and which the log chain permits: `ChainHash::extend` covers the event
    /// *ID*, and a v11 event ID is the reference hash of the **redacted**
    /// form, so redacting changes neither. The chain still verifies, and so
    /// does the event ID over what is left. That is why this can rewrite
    /// history without breaking the integrity construction — the same property
    /// that lets an admin purge bodies (#83).
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or target is unknown, or the rules
    /// refuse the redaction.
    pub fn redact(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        target: &str,
        reason: Option<&str>,
    ) -> Result<String, RoomError> {
        // The target has to be an event of this room. Redacting something the
        // room does not have would mint an event that refers to nothing, and
        // federate that nothing to every peer.
        let known = self.with_room(room_id, |_, log| {
            Ok(log.get(&EventId::new(target)).is_some())
        })?;
        if !known {
            return Err(RoomError::MissingBody(target.to_owned()));
        }

        let mut content = serde_json::Map::new();
        // `redacts` in content, not at the top level: MSC2174, which room v11
        // adopts (SPEC §11's version table).
        content.insert("redacts".to_owned(), Value::String(target.to_owned()));
        if let Some(reason) = reason {
            content.insert("reason".to_owned(), Value::String(reason.to_owned()));
        }
        let content = Value::Object(content);

        let redaction_id = self.with_room(room_id, |rooms, log| {
            rooms.append(
                log,
                room_id,
                sender,
                key,
                "m.room.redaction",
                None,
                &content,
            )
        })?;

        // Only after the redaction is authorized, signed and stored. Rewriting
        // first would strip an event on behalf of a redaction the rules then
        // refused.
        self.apply_redaction(room_id, target, &redaction_id)?;
        Ok(redaction_id)
    }

    /// Rewrite a stored event to its redacted form.
    fn apply_redaction(
        &self,
        room_id: &str,
        target: &str,
        redaction_id: &str,
    ) -> Result<(), RoomError> {
        let stored = self.read_event(room_id, &EventId::new(target))?;
        let object = CanonicalJsonValue::try_from(stored)
            .map_err(|error| RoomError::Build(error.to_string()))?;
        let CanonicalJsonValue::Object(object) = object else {
            return Err(RoomError::Build(
                "a stored event is not an object".to_owned(),
            ));
        };

        let rules = RoomVersionRules::V11.redaction;
        let redacted = ruma::canonical_json::redact(object, &rules, None)
            .map_err(|error| RoomError::Build(format!("cannot redact: {error}")))?;

        let mut json = canonical_to_json(&redacted);
        // `redacted_because` goes in `unsigned`, which is not covered by the
        // event ID -- so a client can see why without the ID changing.
        if let Some(map) = json.as_object_mut() {
            map.insert(
                "unsigned".to_owned(),
                serde_json::json!({ "redacted_because": { "event_id": redaction_id } }),
            );
        }

        spindle_store::Store::put(
            self.store.as_ref(),
            &event_body_key(room_id, target),
            &serde_json::to_vec(&json)?,
        )?;
        Ok(())
    }

    /// Events related to `target`, oldest first.
    ///
    /// Oldest first because that is the order the index already holds them in:
    /// its key ends in `li`, so a prefix scan comes back sorted with nothing
    /// doing the sorting. A DAG server has to order these itself.
    ///
    /// A relation whose event has been redacted is skipped. `m.relates_to`
    /// lives in `content`, which redaction strips, so a redacted reaction
    /// stops being a reaction — filtered by reading the event rather than by
    /// deleting the index entry, because an index kept in step with redaction
    /// is one more thing that can fall out of step with it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the index cannot be
    /// read.
    pub fn relations(
        &self,
        room_id: &str,
        target: &str,
        rel_type: Option<&str>,
        event_type: Option<&str>,
        from: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<Value>, Option<i64>), RoomError> {
        // The room has to exist, or an unknown room answers "no relations"
        // and a client cannot tell that from an event nobody replied to.
        self.with_room(room_id, |_, _| Ok(()))?;

        let prefix = spindle_core::keys::relation_prefix(room_id, target);
        let rows = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?;

        let mut out = Vec::new();
        let mut next = None;
        for (key, value) in rows {
            let Some(li) = spindle_core::keys::li_from_key(&key) else {
                continue;
            };
            if from.is_some_and(|from| li <= from) {
                continue;
            }
            let Some((stored_type, event_id)) = decode_relation(&value) else {
                continue;
            };
            // Filtered here rather than by the key, so the unfiltered arity
            // can stay in timeline order -- see `keys::relation`.
            if rel_type.is_some_and(|wanted| stored_type != wanted) {
                continue;
            }
            let event = self.event(room_id, &event_id)?;

            // Redacted: `m.relates_to` is gone from content, so this is no
            // longer a relation to anything.
            if relates_to(&event["content"]).is_none() {
                continue;
            }
            if event_type.is_some_and(|wanted| event["type"] != wanted) {
                continue;
            }
            if out.len() == limit {
                next = Some(li - 1);
                break;
            }
            out.push(event);
        }
        Ok((out, next))
    }

    /// The events around one event, and the room's state as it stood there.
    ///
    /// SPEC §10.5 in one line: "`/context` is a symmetric scan around it and
    /// `state_at(li)` for the state block". Both halves are cheap here for the
    /// same reason.
    ///
    /// **The window is arithmetic.** "The events around this one" is
    /// `li - n ..= li + n` over a contiguous range, because ordering was
    /// decided once at write. A DAG server has to establish that order before
    /// it can answer at all — which is the same reason `/messages` was the
    /// endpoint SPEC §10.4 singles out.
    ///
    /// **The state is the trie root that entry already carries.** Every
    /// `LogEntry` holds the content address of the state after it, and the
    /// nodes are content-addressed in the store, so state at an arbitrary past
    /// point is a rehydrate rather than a replay. That works at any depth,
    /// not only inside the resident window — a permalink to a five-year-old
    /// message gets the display names people actually had then.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or the event is unknown, or the state
    /// nodes it names cannot be read.
    pub fn context(
        &self,
        room_id: &str,
        event_id: &str,
        limit: usize,
    ) -> Result<Context, RoomError> {
        let found = self.with_room(room_id, |_, log| {
            let Some(entry) = log.get(&EventId::new(event_id)) else {
                return Ok(None);
            };
            let target = entry.li.get();
            let state_root = entry.state_root;

            // Symmetric, and each side stops at the end of the log rather than
            // running off it.
            let before: Vec<String> = log
                .entries()
                .rev()
                .filter(|entry| entry.li.get() < target)
                .take(limit)
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect();
            let after: Vec<String> = log
                .entries()
                .filter(|entry| entry.li.get() > target)
                .take(limit)
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect();

            // The oldest and newest positions this window reached, which are
            // where a client paginates on from.
            let start = before.last().map_or(target, |id| {
                log.get(&EventId::new(id.as_str()))
                    .map_or(target, |entry| entry.li.get())
            });
            let end = after.last().map_or(target, |id| {
                log.get(&EventId::new(id.as_str()))
                    .map_or(target, |entry| entry.li.get())
            });
            Ok(Some((before, after, start, end, state_root)))
        })?;

        let Some((before, after, start, end, state_root)) = found else {
            return Err(RoomError::MissingBody(event_id.to_owned()));
        };

        let mut events_before = Vec::with_capacity(before.len());
        for id in before {
            events_before.push(self.event(room_id, &id)?);
        }
        let mut events_after = Vec::with_capacity(after.len());
        for id in after {
            events_after.push(self.event(room_id, &id)?);
        }

        Ok(Context {
            event: self.event(room_id, event_id)?,
            events_before,
            events_after,
            state: self.state_at(room_id, state_root)?,
            start,
            end,
        })
    }

    /// The room an event lives in, from the reverse index.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the read fails.
    pub fn room_of_event(&self, event_id: &str) -> Result<Option<String>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::event_room(event_id),
        )?
        .and_then(|bytes| String::from_utf8(bytes).ok()))
    }

    /// Whether `domain` has a joined member in the room right now.
    ///
    /// The federation read paths gate on this: room state and history
    /// belong to the servers in the room, and "in" means a joined member,
    /// not an invite and not a memory.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its indexes cannot be read.
    pub fn server_in_room(&self, room_id: &str, domain: &str) -> Result<bool, RoomError> {
        let members = self.with_room(room_id, |_, log| {
            let Some(state) = log
                .entries()
                .next_back()
                .map(|entry| entry.li)
                .and_then(|li| log.state_after(li))
            else {
                return Ok(Vec::new());
            };
            let mut members = Vec::new();
            state.for_each(|state_key, _| {
                if state_key.event_type().as_str() == "m.room.member"
                    && state_key
                        .state_key()
                        .split_once(':')
                        .is_some_and(|(_, d)| d == domain)
                {
                    members.push(state_key.state_key().to_owned());
                }
            });
            Ok(members)
        })?;
        for user_id in members {
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    &user_id,
                    room_id,
                ),
            )?;
            if membership.as_deref() == Some(JOIN_STR.as_bytes()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A join-event template for a remote user, for `make_join`.
    ///
    /// The template is everything but the signature: the caller's server
    /// signs it and brings it back through `send_join`. Authorization is
    /// previewed here — public join rule, or a standing invite — so a
    /// refused server learns at the cheap step, but the template is not a
    /// promise: the signed event is authorized again on the way in, against
    /// whatever the state is *then*.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the rules do not admit the user.
    pub fn make_join_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        self.with_room(room_id, |rooms, log| {
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let state = log
                .state_after(head.li)
                .ok_or_else(|| RoomError::StateUnavailable("no head state".to_owned()))?;

            // `read_event`, not `event()`: the latter re-enters `with_room`
            // on a lock this closure already holds.
            let join_rule = state
                .get(&StateKey::new("m.room.join_rules", ""))
                .map(str::to_owned)
                .and_then(|id| rooms.read_event(room_id, &EventId::new(id.as_str())).ok())
                .and_then(|event| event["content"]["join_rule"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "invite".to_owned());
            let invited = spindle_store::ReadView::get(
                rooms.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    user_id,
                    room_id,
                ),
            )?
            .as_deref()
                == Some(INVITE_STR.as_bytes());
            if join_rule != "public" && !invited {
                return Err(RoomError::Forbidden(
                    "the room is not public and the user holds no invite".to_owned(),
                ));
            }

            let content = serde_json::json!({ "membership": "join" });
            let auth = auth_events_for(log, user_id, "m.room.member", Some(user_id), &content)?;
            let prev: Vec<String> = log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            let depth = head.depth.saturating_add(1);
            Ok(serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
                "depth": depth,
                "prev_events": prev,
                "auth_events": auth,
            }))
        })
    }

    /// A knock-event template for a remote user, for `make_knock`.
    ///
    /// The precondition mirrors the auth rule that will judge the signed
    /// event on the way back in: the room's join rule must be `knock`.
    /// Anything else is refused here, at the cheap step.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the room does not accept knocks.
    pub fn make_knock_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        self.with_room(room_id, |rooms, log| {
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let state = log
                .state_after(head.li)
                .ok_or_else(|| RoomError::StateUnavailable("no head state".to_owned()))?;
            let join_rule = state
                .get(&StateKey::new("m.room.join_rules", ""))
                .map(str::to_owned)
                .and_then(|id| rooms.read_event(room_id, &EventId::new(id.as_str())).ok())
                .and_then(|event| event["content"]["join_rule"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "invite".to_owned());
            if join_rule != "knock" {
                return Err(RoomError::Forbidden(
                    "the room does not accept knocks".to_owned(),
                ));
            }

            let content = serde_json::json!({ "membership": "knock" });
            let auth = auth_events_for(log, user_id, "m.room.member", Some(user_id), &content)?;
            let prev: Vec<String> = log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            let depth = head.depth.saturating_add(1);
            Ok(serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
                "depth": depth,
                "prev_events": prev,
                "auth_events": auth,
            }))
        })
    }

    /// A leave-event template for a remote user, for `make_leave`.
    ///
    /// The mirror of [`Self::make_join_template`], with the mirrored
    /// precondition: there must be a membership to leave — an invite being
    /// rejected, a join being ended, a knock withdrawn. A template for a
    /// stranger would let any server manufacture departures for users who
    /// were never here.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the user has nothing to leave.
    pub fn make_leave_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        self.with_room(room_id, |_, log| {
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    user_id,
                    room_id,
                ),
            )?;
            let leavable = matches!(membership.as_deref(), Some(b"invite" | b"join" | b"knock"));
            if !leavable {
                return Err(RoomError::Forbidden(
                    "the user has no membership to leave".to_owned(),
                ));
            }

            let content = serde_json::json!({ "membership": "leave" });
            let auth = auth_events_for(log, user_id, "m.room.member", Some(user_id), &content)?;
            let prev: Vec<String> = log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            let depth = head.depth.saturating_add(1);
            Ok(serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
                "depth": depth,
                "prev_events": prev,
                "auth_events": auth,
            }))
        })
    }

    /// Erase a pending invite: the membership row and the side record.
    ///
    /// Deletion rather than a `leave` row, deliberately: the leave section
    /// of `/sync` renders a departure from the room's log, and there is no
    /// log here — a `leave` row pointing at a room this server never held
    /// would fail every sync that touched it. An invite that was rejected
    /// (or revoked from the other side) simply stops appearing, which is
    /// also what a client does with it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store refuses the deletes.
    pub fn clear_pending_invite(&self, user_id: &str, room_id: &str) -> Result<(), RoomError> {
        let pending = spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::PendingInvite,
                user_id,
                room_id,
            ),
        )?
        .is_some();
        if !pending {
            return Ok(());
        }
        spindle_store::Store::delete(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Membership,
                user_id,
                room_id,
            ),
        )?;
        spindle_store::Store::delete(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::PendingInvite,
                user_id,
                room_id,
            ),
        )?;
        self.wake_sync_waiters();
        Ok(())
    }

    /// History walking backwards from the given events, newest first —
    /// federation backfill.
    ///
    /// The linear log makes this a range read: the starting point is the
    /// newest of the named events, and "backwards" is the log itself. The
    /// named events are included, the way a paginating server expects.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for,
    /// [`RoomError::MissingBody`] when none of the named events are in it.
    pub fn backfill(
        &self,
        room_id: &str,
        from: &[String],
        limit: usize,
    ) -> Result<Vec<Value>, RoomError> {
        self.with_room(room_id, |rooms, log| {
            let start = from
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .max()
                .ok_or_else(|| RoomError::MissingBody(from.join(", ")))?;
            log.entries()
                .rev()
                .filter(|entry| entry.li <= start)
                .take(limit)
                .map(|entry| {
                    let mut event = rooms.read_event(room_id, &entry.event_id)?;
                    if let Some(object) = event.as_object_mut() {
                        object.insert(
                            "event_id".to_owned(),
                            Value::String(entry.event_id.as_str().to_owned()),
                        );
                    }
                    Ok(event)
                })
                .collect()
        })
    }

    /// The events between `earliest` (theirs) and `latest` (the ones whose
    /// ancestry they are missing) — federation catch-up.
    ///
    /// Exclusive on both ends: they have `earliest`, and they are holding
    /// `latest`. When the gap is wider than `limit`, the events closest to
    /// `latest` win — those are the ones that let the requester connect the
    /// history they are actually holding; the rest they can backfill.
    /// Returned oldest first.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for.
    pub fn missing_events(
        &self,
        room_id: &str,
        earliest: &[String],
        latest: &[String],
        limit: usize,
        min_depth: u64,
    ) -> Result<Vec<Value>, RoomError> {
        self.with_room(room_id, |rooms, log| {
            let floor = earliest
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .max();
            let Some(ceiling) = latest
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .min()
            else {
                // Nothing they name is ours: there is no gap to fill.
                return Ok(Vec::new());
            };
            let mut newest_first: Vec<Value> = log
                .entries()
                .rev()
                .filter(|entry| {
                    entry.li < ceiling
                        && floor.is_none_or(|floor| entry.li > floor)
                        && entry.depth >= min_depth
                })
                .take(limit)
                .map(|entry| {
                    let mut event = rooms.read_event(room_id, &entry.event_id)?;
                    if let Some(object) = event.as_object_mut() {
                        object.insert(
                            "event_id".to_owned(),
                            Value::String(entry.event_id.as_str().to_owned()),
                        );
                    }
                    Ok(event)
                })
                .collect::<Result<_, RoomError>>()?;
            newest_first.reverse();
            Ok(newest_first)
        })
    }

    /// The room's state *before* `event_id`, with the auth chain, for
    /// federation's `/state` and `/state_ids`.
    ///
    /// Before rather than after, matching what a joining or backfilling
    /// server needs: the state its new event was authorized against. This
    /// is the read SPEC §18.1 is about — the state at an arbitrary
    /// historical point is one content-addressed rehydration, not a
    /// resolution: the entry already carries the root.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::MissingBody`] for an event the room does not
    /// hold, or [`RoomError`] if bodies cannot be read.
    pub fn federation_state(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<(Vec<IdentifiedEvent>, Vec<IdentifiedEvent>), RoomError> {
        let previous_root = self.with_room(room_id, |_, log| {
            let Some(entry) = log.get(&EventId::new(event_id)) else {
                return Err(RoomError::MissingBody(event_id.to_owned()));
            };
            let target = entry.li;
            Ok(log
                .entries()
                .rev()
                .find(|entry| entry.li < target)
                .map(|entry| entry.state_root))
        })?;

        let pdus = match previous_root {
            Some(root) => self.state_pairs_at(room_id, root)?,
            // The first event: the state before it is no state at all.
            None => Vec::new(),
        };

        // The auth chain is every event the state transitively cites: a
        // walk over stored bodies, deduplicated, no network.
        let mut seen = std::collections::BTreeSet::new();
        let mut frontier: Vec<String> = pdus
            .iter()
            .flat_map(|(_, event)| {
                event["auth_events"]
                    .as_array()
                    .map(|ids| {
                        ids.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        let mut auth_chain = Vec::new();
        while let Some(id) = frontier.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let Ok(event) = self.event(room_id, &id) else {
                continue;
            };
            if let Some(ids) = event["auth_events"].as_array() {
                frontier.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            auth_chain.push((id, event));
        }
        Ok((pdus, auth_chain))
    }

    /// Like [`Self::state_at`], but keeping each event's ID beside it —
    /// federation answers want both, and the ID is known before the body
    /// is read.
    fn state_pairs_at(
        &self,
        room_id: &str,
        root: spindle_core::StateRoot,
    ) -> Result<Vec<IdentifiedEvent>, RoomError> {
        let mut load = |address: &spindle_core::StateRoot| {
            spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::content_addressed(
                    spindle_core::keys::Keyspace::StateNode,
                    address.as_bytes(),
                ),
            )
            .ok()
            .flatten()
        };
        let snapshot = spindle_core::StateSnapshot::rehydrate(root, &mut load)
            .map_err(|error| RoomError::Build(format!("cannot rebuild state: {error:?}")))?;
        let mut ids = Vec::with_capacity(snapshot.len());
        snapshot.for_each(|_, event_id| ids.push(event_id.to_owned()));
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let event = self.event(room_id, &id)?;
            out.push((id, event));
        }
        Ok(out)
    }

    /// The room's state at a past point, rebuilt from its content address.
    ///
    /// Not from the resident window: that bounds what is kept *materialized*,
    /// and this is a read path where paying to rebuild is the right trade. The
    /// nodes are content-addressed and shared, so an old state that differs
    /// from a newer one by a single entry costs a handful of node reads rather
    /// than a full copy — the property SPEC §6.1 claims and the reason the
    /// trie is a trie.
    fn state_at(
        &self,
        room_id: &str,
        root: spindle_core::StateRoot,
    ) -> Result<Vec<Value>, RoomError> {
        let mut load = |address: &spindle_core::StateRoot| {
            spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::content_addressed(
                    spindle_core::keys::Keyspace::StateNode,
                    address.as_bytes(),
                ),
            )
            .ok()
            .flatten()
        };
        let snapshot = spindle_core::StateSnapshot::rehydrate(root, &mut load)
            .map_err(|error| RoomError::Build(format!("cannot rebuild state: {error:?}")))?;

        let mut ids = Vec::with_capacity(snapshot.len());
        snapshot.for_each(|_, event_id| ids.push(event_id.to_owned()));
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.event(room_id, &id)?);
        }
        Ok(out)
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

    /// Everyone currently joined to a room, with their profile at the time
    /// they joined.
    ///
    /// Read from the room's own state rather than from the membership index:
    /// the index is keyed by user so that "which rooms is this user in" is a
    /// prefix scan, and answering the transpose from it would mean scanning
    /// every user the server knows. The state snapshot already holds exactly
    /// this room's members, so the cost is proportional to the room -- which
    /// is what the caller asked for.
    ///
    /// `display_name` and `avatar_url` are whatever the member event carries.
    /// A member who set neither gets JSON nulls, which is what the spec's
    /// `RoomMember` says and what a client expects to see.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError`] if a member event body cannot be read.
    pub fn joined_members(&self, room_id: &str) -> Result<Map<String, Value>, RoomError> {
        let members = self.with_room(room_id, |_, log| {
            Ok(current_state(log)
                .into_iter()
                .filter(|(key, _)| key.event_type().as_str() == "m.room.member")
                .map(|(key, event_id)| (key.state_key().to_owned(), event_id))
                .collect::<Vec<_>>())
        })?;
        let mut out = Map::new();
        for (user_id, event_id) in members {
            let event = self.event(room_id, &event_id)?;
            if event["content"]["membership"].as_str() != Some(JOIN_STR) {
                continue;
            }
            out.insert(
                user_id,
                serde_json::json!({
                    "display_name": event["content"]["displayname"].clone(),
                    "avatar_url": event["content"]["avatar_url"].clone(),
                }),
            );
        }
        Ok(out)
    }

    /// What a room looks like from outside it.
    ///
    /// Every field is read from current state, and every one of them is
    /// optional in the response because every one of them is optional in the
    /// room: a room with no name, no topic and no avatar is ordinary, not
    /// broken. `UnknownState` is therefore not an error here -- it is the
    /// answer "the room never set that", which the caller renders as absent.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn summary(&self, room_id: &str) -> Result<RoomSummary, RoomError> {
        // Establishes the room exists before any of the optional reads, so an
        // unknown room is a 404 rather than a summary of nothing.
        let joined = self.joined_members(room_id)?;

        let string = |event_type: &str, field: &str| -> Option<String> {
            self.state_event(room_id, event_type, "")
                .ok()
                .and_then(|content| content[field].as_str().map(str::to_owned))
        };

        let join_rule = string("m.room.join_rules", "join_rule");
        Ok(RoomSummary {
            room_id: room_id.to_owned(),
            name: string("m.room.name", "name"),
            topic: string("m.room.topic", "topic"),
            avatar_url: string("m.room.avatar", "url"),
            canonical_alias: string("m.room.canonical_alias", "alias"),
            num_joined_members: joined.len(),
            // `world_readable` is about *history*, not about joining, so it
            // comes from m.room.history_visibility rather than the join rules.
            // Conflating the two would report a public room whose history is
            // members-only as readable by anyone.
            world_readable: self
                .state_event(room_id, "m.room.history_visibility", "")
                .ok()
                .and_then(|content| content["history_visibility"].as_str().map(str::to_owned))
                .as_deref()
                == Some("world_readable"),
            guest_can_join: self
                .state_event(room_id, "m.room.guest_access", "")
                .ok()
                .and_then(|content| content["guest_access"].as_str().map(str::to_owned))
                .as_deref()
                == Some("can_join"),
            join_rule,
            room_type: string("m.room.create", "type"),
            encryption: string("m.room.encryption", "algorithm"),
        })
    }

    /// Drop a room from one user's view of the server.
    ///
    /// Purely local bookkeeping: no event is appended, so nobody else's view
    /// of the room changes and the log still records that the user left. The
    /// spec refuses a forget from someone still in the room, and so does this
    /// -- otherwise a client could hide a room it is still receiving events
    /// for, and every subsequent `/sync` would contradict the hiding.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::Forbidden`] if the user is still joined or invited.
    pub fn forget(&self, user_id: &str, room_id: &str) -> Result<(), RoomError> {
        // Opening the room is what makes an unknown room a 404 rather than a
        // silent success: without it, forgetting a room that never existed
        // would happily write a marker for it.
        self.with_room(room_id, |_, _| Ok(()))?;
        let current = spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Membership,
                user_id,
                room_id,
            ),
        )?;
        if matches!(current.as_deref(), Some(JOIN | INVITE)) {
            return Err(RoomError::Forbidden(format!(
                "{user_id} is still in {room_id} and cannot forget it"
            )));
        }
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Forgotten,
                user_id,
                room_id,
            ),
            &[],
        )?;
        Ok(())
    }

    /// Whether `user_id` has forgotten `room_id`.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn is_forgotten(&self, user_id: &str, room_id: &str) -> Result<bool, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Forgotten,
                user_id,
                room_id,
            ),
        )?
        .is_some())
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
        // A user is not behind on what was said before they arrived, so the
        // count starts at their own membership event however far back the
        // room goes. Without that floor a user with no receipt -- which is
        // every new joiner -- has a boundary of `i64::MIN`, and the walk below
        // reads *every event body in the room* on their first sync. That was
        // #81, and it is the one operation that grew with room size while the
        // rest of the API stayed flat.
        //
        // With a receipt, the later of the two wins. A receipt can sit below
        // the join -- backfilled history carries negative indices, and the
        // spec does not stop a client acknowledging one -- and taking the
        // receipt alone there would walk back into history the user was never
        // present for.
        let joined_at = self.membership_event(room_id, user_id)?.map(|(_, li)| li);
        let boundary = match (read_up_to.as_ref().map(|receipt| receipt.li), joined_at) {
            (Some(receipt), Some(joined)) => receipt.max(joined),
            (Some(receipt), None) => receipt,
            (None, Some(joined)) => joined,
            // Neither a receipt nor a membership: not a member, so there is
            // nothing this user could be behind on, and no range to walk.
            (None, None) => {
                return Ok(Unread {
                    notification_count: 0,
                    read_up_to: None,
                });
            }
        };

        // Two binary searches over the room's sender index: how many
        // timeline events sit after the boundary, minus how many of them are
        // the user's own. The index exists precisely so this never reads an
        // event body — the count is the operation every sync performs for
        // every room, and it used to read every body after the floor to
        // learn its sender (the M2 close-out benchmark's one loss).
        let notification_count = self.with_room(room_id, |rooms, log| {
            let mut cache = rooms
                .unread_index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !cache.contains_key(room_id) {
                // The one remaining full walk: once per room per process,
                // under the room lock so no append can slip past unindexed.
                let mut index = UnreadIndex::default();
                for entry in log.entries() {
                    if entry.state_key.is_some() {
                        continue;
                    }
                    let event = rooms.read_event(room_id, &entry.event_id)?;
                    index.push(entry.li.get(), event["sender"].as_str().unwrap_or(""));
                }
                cache.insert(room_id.to_owned(), index);
            }
            Ok(cache[room_id].count_after(boundary, user_id))
        })?;

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

    /// Wake everything blocked in [`Self::wait_for_event`].
    ///
    /// For appends the append itself notifies; this is for the other thing a
    /// waiting `/sync` can be waiting on — a to-device message, which lands
    /// outside any room and would otherwise wait out the full timeout.
    pub fn wake_sync_waiters(&self) {
        self.appended.notify_waiters();
    }

    /// Take the next global sequence number without writing a stream row.
    ///
    /// To-device messages draw from the same counter room events do, so a
    /// sync token positions both at once — which is what lets `since`
    /// acknowledge to-device deliveries with no second cursor. The stream
    /// scan skips absent ids already, so a gap where a to-device message sat
    /// costs nothing.
    pub fn allocate_stream_id(&self) -> u64 {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *stream += 1;
        *stream
    }

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
                Some(since) => (self.timeline_since(&room_id, since, position, None)?, false),
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

        let left = self.left_rooms(user_id, since, position)?;

        Ok(SyncResult {
            next_batch: position,
            rooms,
            invited,
            left,
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

    /// Rooms the user is out of, and has not forgotten.
    ///
    /// This is where forgetting finally becomes visible: a room the user
    /// forgot is one they asked to stop seeing, and the leave section is the
    /// only place it would otherwise keep appearing.
    ///
    /// **The timeline is capped at the user's own departure.** A left room
    /// keeps receiving events, and `timeline_since` would happily return them
    /// -- so without the cap an incremental sync would hand a departed member
    /// everything said after they left, which is the one thing leaving is
    /// supposed to prevent.
    ///
    /// An initial sync carries just the departure itself. A client needs to
    /// know the room exists and that it is out of it; replaying the whole
    /// history of every room a user ever left would make the first sync
    /// proportional to their entire past.
    fn left_rooms(
        &self,
        user_id: &str,
        since: Option<u64>,
        position: u64,
    ) -> Result<Vec<SyncRoom>, RoomError> {
        let mut out = Vec::new();
        for membership in [LEAVE, BAN] {
            for room_id in self.membership_rooms(user_id, membership)? {
                if self.is_forgotten(user_id, &room_id)? {
                    continue;
                }
                let Some((departure, departed_at)) = self.membership_event(&room_id, user_id)?
                else {
                    continue;
                };
                let events = match since {
                    None => vec![departure],
                    Some(since) => {
                        self.timeline_since(&room_id, since, position, Some(departed_at))?
                    }
                };
                // An incremental sync says nothing about a room the user left
                // long ago, for the same reason it says nothing about a joined
                // room where nothing happened.
                if since.is_some() && events.is_empty() {
                    continue;
                }
                out.push(SyncRoom {
                    room_id,
                    state: Vec::new(),
                    events,
                    limited: false,
                });
            }
        }
        out.sort_by(|a, b| a.room_id.cmp(&b.room_id));
        Ok(out)
    }

    /// `user_id`'s current membership event in `room_id`, and its `li`.
    ///
    /// Read from current state rather than by walking the log: the *latest*
    /// membership is the one that counts, which is exactly what the state
    /// snapshot holds. For someone who has left, that is the event that
    /// removed them; for someone still in the room, it is their join.
    fn membership_event(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Option<(Value, i64)>, RoomError> {
        let wanted = StateKey::new("m.room.member", user_id);
        let found = self.with_room(room_id, |_, log| {
            Ok(current_state(log)
                .into_iter()
                .find(|(key, _)| key == &wanted)
                .map(|(_, event_id)| event_id))
        })?;
        let Some(event_id) = found else {
            return Ok(None);
        };
        let li = self.with_room(room_id, |_, log| {
            Ok(log
                .get(&EventId::new(event_id.as_str()))
                .map(|entry| entry.li.get()))
        })?;
        let Some(li) = li else {
            return Ok(None);
        };
        Ok(Some((self.event(room_id, &event_id)?, li)))
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
    /// `max_li` caps the range at a position in the room's own order, which is
    /// how the leave section stops at the user's departure. `None` means the
    /// whole range, which is what a joined room wants.
    ///
    /// The cap is tested against the stream record's `li` rather than against
    /// anything in the event body -- events do not carry their linear index,
    /// and an earlier draft of this filtered on `unsigned.li`, a field that
    /// does not exist. Every comparison silently succeeded and the cap did
    /// nothing at all.
    fn timeline_since(
        &self,
        room_id: &str,
        since: u64,
        position: u64,
        max_li: Option<i64>,
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
            if max_li.is_some_and(|max| record.li > max) {
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

    /// Bundle an event's relations into `unsigned.m.relations` (MSC2675).
    ///
    /// Read-time aggregation, which is the shape SPEC §10.5 already committed
    /// to for edits: the original is never mutated, so anything derived from
    /// its relations has to be computed when asked. The index scan is in
    /// timeline order for free — the key ends in `li` — which is what makes
    /// "latest edit" a last-write scan rather than a sort.
    ///
    /// Three aggregations, the ones the spec defines:
    /// - `m.replace`: the latest edit, whole, so a client can render the
    ///   replacement without a second fetch.
    /// - `m.annotation`: `(type, key)` reaction counts. Senders are not
    ///   listed — a client that needs them pages `/relations`.
    /// - `m.thread`: count and the latest event, whole, plus whether the
    ///   asking user has participated — which is why this takes `viewer`.
    ///
    /// A redacted relation stops relating here for the same reason it does in
    /// `/relations`: `m.relates_to` lives in content and redaction strips it,
    /// so the check is reading the event rather than trusting the index row.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index or an event body cannot be read.
    pub fn bundle_relations(
        &self,
        room_id: &str,
        target: &str,
        viewer: &str,
    ) -> Result<Option<Value>, RoomError> {
        let prefix = spindle_core::keys::relation_prefix(room_id, target);
        let rows = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?;

        let mut latest_edit: Option<Value> = None;
        let mut annotations: Vec<(String, String, u64)> = Vec::new();
        let mut thread_count: u64 = 0;
        let mut thread_latest: Option<Value> = None;
        let mut viewer_in_thread = false;

        for (_, value) in rows {
            let Some((rel_type, event_id)) = decode_relation(&value) else {
                continue;
            };
            let event = self.event(room_id, &event_id)?;
            // Redacted: the relation is gone from the content, so it is gone
            // from the aggregate.
            if relates_to(&event["content"]).is_none() {
                continue;
            }
            match rel_type.as_str() {
                "m.replace" => latest_edit = Some(event),
                "m.annotation" => {
                    let key = event["content"]["m.relates_to"]["key"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    let event_type = event["type"].as_str().unwrap_or_default().to_owned();
                    match annotations
                        .iter_mut()
                        .find(|(existing_type, existing_key, _)| {
                            existing_type == &event_type && existing_key == &key
                        }) {
                        Some((_, _, count)) => *count += 1,
                        None => annotations.push((event_type, key, 1)),
                    }
                }
                "m.thread" => {
                    thread_count += 1;
                    if event["sender"].as_str() == Some(viewer) {
                        viewer_in_thread = true;
                    }
                    thread_latest = Some(event);
                }
                _ => {}
            }
        }

        let mut bundle = Map::new();
        if let Some(edit) = latest_edit {
            bundle.insert("m.replace".to_owned(), edit);
        }
        if !annotations.is_empty() {
            let chunk: Vec<Value> = annotations
                .into_iter()
                .map(|(event_type, key, count)| {
                    serde_json::json!({ "type": event_type, "key": key, "count": count })
                })
                .collect();
            bundle.insert(
                "m.annotation".to_owned(),
                serde_json::json!({ "chunk": chunk }),
            );
        }
        if let Some(latest) = thread_latest {
            bundle.insert(
                "m.thread".to_owned(),
                serde_json::json!({
                    "count": thread_count,
                    "latest_event": latest,
                    "current_user_participated": viewer_in_thread,
                }),
            );
        }
        Ok((!bundle.is_empty()).then_some(Value::Object(bundle)))
    }

    /// When the room last saw an event, as its head entry's origin timestamp.
    ///
    /// This is sliding sync's sort key. The linear index cannot order rooms
    /// against each other — it is per-room by design — and scanning the
    /// global stream backwards to rank rooms would touch every event since
    /// the quietest room last spoke. The head timestamp is one point read per
    /// room and agrees with what a client shows as "latest activity".
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its head event cannot be read.
    pub fn last_activity(&self, room_id: &str) -> Result<i64, RoomError> {
        if let Some(&cached) = self
            .last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
        {
            return Ok(cached);
        }
        let head = self.with_room(room_id, |_, log| {
            Ok(log
                .entries()
                .next_back()
                .map(|entry| entry.event_id.as_str().to_owned()))
        })?;
        let Some(event_id) = head else {
            return Ok(0);
        };
        let event = self.event(room_id, &event_id)?;
        let activity = event["origin_server_ts"].as_i64().unwrap_or(0);
        self.last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), activity);
        Ok(activity)
    }

    /// Room IDs with at least one event in the stream range `(since, until]`.
    ///
    /// One forward scan, deduplicated — the set an incremental sliding sync
    /// answers about. The classic `/sync` asks a different question (which
    /// *events*), so it walks per room; this asks only *which rooms*, and one
    /// pass over the shared stream answers it for all of them.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the stream cannot be read.
    pub fn changed_rooms(&self, since: u64, until: u64) -> Result<Vec<String>, RoomError> {
        let mut rooms = Vec::new();
        for stream_id in (since + 1)..=until {
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
            if !rooms.contains(&record.room_id) {
                rooms.push(record.room_id);
            }
        }
        Ok(rooms)
    }

    /// The newest `limit` timeline events of a room, oldest first, stamped.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or an event cannot be read.
    pub fn timeline_tail_public(
        &self,
        room_id: &str,
        limit: usize,
    ) -> Result<(Vec<Value>, bool), RoomError> {
        self.timeline_tail(room_id, limit)
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
    /// Build, sign and authorize one event against the log's head, without
    /// appending it.
    ///
    /// This is the front half of [`Self::append`], split out because the
    /// federated invite handshake needs exactly it: the event must exist and
    /// be signed before the invited user's server has co-signed it, and it
    /// must not be in the log until that server has.
    fn build_event(
        &self,
        log: &RoomLog,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Result<(String, Value), RoomError> {
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
        Ok((event_id, json))
    }

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
        let (event_id, json) =
            self.build_event(log, room_id, sender, key, event_type, state_key, content)?;
        let prev: Vec<EventId> = json["prev_events"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(EventId::new)
                    .collect()
            })
            .unwrap_or_default();

        let input = EventInput::new(event_id.clone(), prev);
        let input = match state_key {
            Some(state_key) => input.with_state_key(StateKey::new(event_type, state_key)),
            None => input,
        };

        let entry = log
            .append_remote(input)
            .map_err(|error| RoomError::Append(format!("{error:?}")))?
            .clone();

        self.persist_entry(
            log,
            room_id,
            &entry,
            &event_id,
            &PersistInput {
                event_type,
                state_key,
                sender,
                content,
                json: &json,
            },
        )?;
        self.enqueue_outbound(log, room_id, &json)?;
        Ok(event_id)
    }

    /// Queue a locally-created event for every remote server with a live
    /// member in the room.
    ///
    /// Only the local path enqueues: each server fans out its own events,
    /// and forwarding what we received would deliver everything twice.
    /// Membership is checked per member — a domain whose only members have
    /// left or been banned gets nothing, because "we used to share a room"
    /// is not an entitlement to what is said now.
    fn enqueue_outbound(
        &self,
        log: &RoomLog,
        room_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        // Domains come from member state keys; liveness from the membership
        // index — a point read per member, no body parses.
        let Some(state) = log
            .entries()
            .next_back()
            .map(|entry| entry.li)
            .and_then(|li| log.state_after(li))
        else {
            return Ok(());
        };
        let mut members = Vec::new();
        state.for_each(|state_key, _| {
            if state_key.event_type().as_str() == "m.room.member" {
                members.push(state_key.state_key().to_owned());
            }
        });
        let mut destinations = std::collections::BTreeSet::new();
        for user_id in members {
            let Some((_, domain)) = user_id.split_once(':') else {
                continue;
            };
            if domain == self.server_name || destinations.contains(domain) {
                continue;
            }
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    &user_id,
                    room_id,
                ),
            )?;
            let live = membership.as_deref().is_some_and(|value| {
                value == JOIN_STR.as_bytes() || value == INVITE_STR.as_bytes()
            });
            if live {
                destinations.insert(domain.to_owned());
            }
        }
        // A membership event still goes to the domain it is *about*, live
        // or not: the kick is the one event the removed server must hear,
        // and by this point the membership index already says "leave" — the
        // liveness check above would skip exactly the notification that
        // matters.
        if json["type"].as_str() == Some("m.room.member")
            && let Some((_, domain)) = json["state_key"].as_str().and_then(|u| u.split_once(':'))
            && domain != self.server_name
        {
            destinations.insert(domain.to_owned());
        }
        for destination in destinations {
            let seq = self.allocate_stream_id();
            spindle_store::Store::put(
                self.store.as_ref(),
                &spindle_core::keys::federation_outbox(&destination, seq),
                json.to_string().as_bytes(),
            )?;
        }
        Ok(())
    }

    /// Every remote domain with a live member in the room — the EDU
    /// audience, same liveness rule as event fan-out.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or membership rows cannot be read.
    pub fn remote_domains(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        let members = self.with_room(room_id, |_, log| {
            let Some(state) = log
                .entries()
                .next_back()
                .map(|entry| entry.li)
                .and_then(|li| log.state_after(li))
            else {
                return Ok(Vec::new());
            };
            let mut members = Vec::new();
            state.for_each(|state_key, _| {
                if state_key.event_type().as_str() == "m.room.member" {
                    members.push(state_key.state_key().to_owned());
                }
            });
            Ok(members)
        })?;
        let mut destinations = std::collections::BTreeSet::new();
        for user_id in members {
            let Some((_, domain)) = user_id.split_once(':') else {
                continue;
            };
            if domain == self.server_name || destinations.contains(domain) {
                continue;
            }
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    &user_id,
                    room_id,
                ),
            )?;
            let live = membership.as_deref().is_some_and(|value| {
                value == JOIN_STR.as_bytes() || value == INVITE_STR.as_bytes()
            });
            if live {
                destinations.insert(domain.to_owned());
            }
        }
        Ok(destinations.into_iter().collect())
    }

    /// Whether `user_id` is currently joined to `room_id`, by the
    /// membership index alone — the cheap read inbound EDU checks want.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be read.
    pub fn is_joined(&self, user_id: &str, room_id: &str) -> Result<bool, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::Membership,
                user_id,
                room_id,
            ),
        )?
        .as_deref()
            == Some(JOIN_STR.as_bytes()))
    }

    /// The stripped state an invited user may see: enough to render the
    /// invite (what room, whose, how it admits), nothing they are not yet
    /// entitled to.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if state cannot be read; an unknown room is an
    /// empty list, because an invite can outlive this server's knowledge of
    /// the room behind it.
    pub fn stripped_state(&self, room_id: &str, user_id: &str) -> Result<Vec<Value>, RoomError> {
        const SHOWN: &[&str] = &[
            "m.room.create",
            "m.room.join_rules",
            "m.room.canonical_alias",
            "m.room.name",
            "m.room.avatar",
            "m.room.topic",
            "m.room.encryption",
        ];
        let ids = match self.with_room(room_id, |_, log| {
            let Some(head) = log.entries().next_back() else {
                return Ok(Vec::new());
            };
            let Some(state) = log.state_after(head.li) else {
                return Ok(Vec::new());
            };
            let mut ids: Vec<(String, String, String)> = Vec::new();
            state.for_each(|key, id| {
                let event_type = key.event_type().as_str();
                let shown = SHOWN.contains(&event_type)
                    || (event_type == "m.room.member" && key.state_key() == user_id);
                if shown {
                    ids.push((
                        event_type.to_owned(),
                        key.state_key().to_owned(),
                        id.to_owned(),
                    ));
                }
            });
            Ok(ids)
        }) {
            Ok(ids) => ids,
            // A room this server was never in still renders as an invite:
            // the inviting server handed over stripped state exactly for
            // this moment, and it was recorded beside the membership row.
            Err(RoomError::UnknownRoom(_)) => {
                return Ok(self
                    .pending_invite(user_id, room_id)?
                    .and_then(|record| record["invite_state"].as_array().cloned())
                    .unwrap_or_default());
            }
            Err(error) => return Err(error),
        };
        let mut stripped = Vec::with_capacity(ids.len());
        for (event_type, state_key, id) in ids {
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
            stripped.push(serde_json::json!({
                "type": event_type,
                "state_key": state_key,
                "sender": event["sender"],
                "content": event["content"],
            }));
        }
        Ok(stripped)
    }

    /// Seed a room this server has never held from a `send_join` response,
    /// ending with our own join event — the receiving half of joining a
    /// room that lives on another server.
    ///
    /// The response carries the room's state before the join and its auth
    /// chain, but none of the history between those events: their parents
    /// live on the resident server. So the events are replayed in
    /// dependency order (depth, then timestamp) with each snapshot built by
    /// applying the event to its predecessor's — `append_seeded`, not a
    /// fold over parents this log does not hold.
    ///
    /// Every event's ID is **recomputed from its content**: v11 IDs are
    /// reference hashes, so the resident server cannot hand us a body that
    /// does not match the ID the rest of the room cites. Per-event origin
    /// signature verification is deliberately deferred to the roadmap's
    /// federation-hardening pass; the hash check is what keeps the seeded
    /// room internally consistent.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] when an event fails validation or the room is
    /// already held (join a room we are in through the local path instead).
    #[allow(clippy::too_many_lines, reason = "one seeding, in one place")]
    pub fn join_remote(
        &self,
        room_id: &str,
        state: &[Value],
        auth_chain: &[Value],
        join: &Value,
        join_id: &str,
    ) -> Result<(), RoomError> {
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_held = open.contains_key(room_id)
            || RoomStore::new(self.store.as_ref(), room_id)
                .load()?
                .is_some();
        if already_held {
            return Err(RoomError::Append(format!(
                "{room_id} is already on this server"
            )));
        }

        let version = RoomVersionId::try_from(ROOM_VERSION)
            .map_err(|error| RoomError::Append(error.to_string()))?;
        let identify = |event: &Value| -> Result<(String, Value), RoomError> {
            let ruma::CanonicalJsonValue::Object(canonical) =
                ruma::CanonicalJsonValue::try_from(event.clone())
                    .map_err(|error| RoomError::Append(error.to_string()))?
            else {
                return Err(RoomError::Append("event is not an object".to_owned()));
            };
            let pdu = Pdu::from_remote(version.clone(), canonical).map_err(|error| {
                let mut shown = event.to_string();
                shown.truncate(400);
                RoomError::Append(format!("seeded event refused: {error:?}: {shown}"))
            })?;
            Ok((pdu.event_id().as_str().to_owned(), event.clone()))
        };

        // State and auth chain overlap heavily; dedup by recomputed ID, then
        // order by dependency. Depth is the room's own topological measure;
        // the timestamp and ID only break ties deterministically.
        let mut events: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        for event in state.iter().chain(auth_chain) {
            let (id, body) = identify(event)?;
            events.insert(id, body);
        }
        if events.contains_key(join_id) {
            return Err(RoomError::Append(
                "the join must not be part of the state before it".to_owned(),
            ));
        }
        let mut ordered: Vec<(String, Value)> = events.into_iter().collect();
        ordered.sort_by_key(|(id, event)| {
            (
                event["depth"].as_u64().unwrap_or(0),
                event["origin_server_ts"].as_u64().unwrap_or(0),
                id.clone(),
            )
        });

        let (computed_join_id, join_body) = identify(join)?;
        if computed_join_id != join_id {
            return Err(RoomError::Append(format!(
                "the join hashes to {computed_join_id}, not {join_id}"
            )));
        }

        let mut log = RoomLog::new();
        let mut snapshot = spindle_core::StateSnapshot::new();
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        let seed = |log: &mut RoomLog,
                    snapshot: &mut spindle_core::StateSnapshot,
                    id: &str,
                    event: &Value|
         -> Result<LogEntry, RoomError> {
            let state_key = event["state_key"].as_str().map(|state_key| {
                StateKey::new(event["type"].as_str().unwrap_or_default(), state_key)
            });
            if let Some(key) = state_key.clone() {
                *snapshot = snapshot.apply(key, id);
            }
            let prev: Vec<EventId> = event["prev_events"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(Value::as_str)
                        .map(EventId::new)
                        .collect()
                })
                .unwrap_or_default();
            let input = match state_key {
                Some(key) => EventInput::new(id, prev).with_state_key(key),
                None => EventInput::new(id, prev),
            };
            match log.append_seeded(
                input,
                snapshot.clone(),
                event["depth"].as_u64().unwrap_or(0),
            ) {
                Ok(entry) => Ok(entry.clone()),
                Err(error) => Err(RoomError::Append(format!("{error:?}"))),
            }
        };

        for (id, event) in &ordered {
            let entry = seed(&mut log, &mut snapshot, id, event)?;
            // Body and reverse index ride the entry's own commit, exactly as
            // on the ordinary receive path; seeded history takes no stream
            // row because it is not new activity on this server.
            spindle_store::Store::put(
                self.store.as_ref(),
                &event_body_key(room_id, id),
                &serde_json::to_vec(event)?,
            )?;
            let extra = vec![(
                spindle_core::keys::event_room(id),
                room_id.as_bytes().to_vec(),
            )];
            room_store.commit_entry_with(&entry, &log, &extra, Durability::Group)?;
        }

        // The join itself is new activity: it goes through the shared
        // persistence spine, so it gets a stream row (the joiner's sync must
        // surface the room), the membership index, and waiter notification.
        let join_entry = seed(&mut log, &mut snapshot, join_id, &join_body)?;
        let content = join_body["content"].clone();
        let sender = join_body["sender"].as_str().unwrap_or_default().to_owned();
        let state_key_owned = join_body["state_key"].as_str().map(str::to_owned);
        self.persist_entry(
            &mut log,
            room_id,
            &join_entry,
            join_id,
            &PersistInput {
                event_type: join_body["type"].as_str().unwrap_or_default(),
                state_key: state_key_owned.as_deref(),
                sender: &sender,
                content: &content,
                json: &join_body,
            },
        )?;

        // Membership rows for everyone already in the room, from the final
        // state: `/joined_members`, sync and the outbound queue all read
        // this index instead of walking state.
        let mut member_rows: Vec<(String, String)> = Vec::new();
        snapshot.for_each(|key, id| {
            if key.event_type().as_str() == "m.room.member" {
                member_rows.push((key.state_key().to_owned(), id.to_owned()));
            }
        });
        for (user, id) in member_rows {
            if user == sender {
                continue; // persist_entry indexed the join itself
            }
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
            self.index_membership(room_id, Some(&user), &event["content"])?;
        }

        open.insert(room_id.to_owned(), log);
        Ok(())
    }

    /// Accept one event another server created, after the caller verified
    /// its signatures against the origin's published keys.
    ///
    /// The same authorization predicate local events pass, against the same
    /// materialized state — SPEC §5's whole point is that a received event
    /// costs an index lookup to authorize, not a state computation. A PDU
    /// that fails it soft-fails: refused with a reason the transaction
    /// response carries, poisoning nothing else in the batch. A PDU naming
    /// predecessors this server has never seen is refused too — filling
    /// that gap is `/get_missing_events` and backfill (#15), not guessing.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server is not in,
    /// [`RoomError::Forbidden`] when authorization refuses, and
    /// [`RoomError::Append`] when the log cannot place the event.
    pub fn receive_remote(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        let received = self.with_room(room_id, |rooms, log| {
            rooms.ingest(log, room_id, event_id, json, false)
        });
        // An event for a room this server never held can still say one true
        // thing to us: our user's invite there ended. Without this, an
        // invite revoked or kicked from the other side would haunt the
        // user's sync forever — the resident server fans the leave out to
        // the invitee's domain, and this is the only door it arrives by.
        if let Err(RoomError::UnknownRoom(_)) = &received
            && json["type"].as_str() == Some("m.room.member")
            && matches!(
                json["content"]["membership"].as_str(),
                Some("leave" | "ban")
            )
            && let Some(target) = json["state_key"].as_str()
            && target.split_once(':').map(|(_, domain)| domain) == Some(self.server_name.as_str())
        {
            self.clear_pending_invite(target, room_id)?;
            return Ok(());
        }
        received
    }

    /// Append an event this server authored but a peer completed.
    ///
    /// The federated invite is the one event with two authors: built and
    /// signed here, co-signed by the invited user's server, and only the
    /// co-signed version is worth storing — it is what proves to every other
    /// server in the room that the invitee's server took part. It fans out
    /// like any local event, because this server originated it; the invited
    /// server already holds it and absorbs the redelivery.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the rules refuse the
    /// event — the log may have moved while the peer was co-signing, and the
    /// event is re-authorized against whatever the head is now.
    pub fn commit_cosigned(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.ingest(log, room_id, event_id, json, true)
        })
    }

    /// The shared back half of receiving a complete, signed event: dedupe,
    /// authorize, append, persist — and fan out only when this server is the
    /// event's origin, because each server fans out its own events.
    fn ingest(
        &self,
        log: &mut RoomLog,
        room_id: &str,
        event_id: &str,
        json: &Value,
        fan_out: bool,
    ) -> Result<(), RoomError> {
        // Redelivery is not an error: transactions retry, and the event
        // is already exactly where it would go.
        if log.get(&EventId::new(event_id)).is_some() {
            return Ok(());
        }
        self.authorize(log, room_id, event_id, json)?;

        let event_type = json["type"].as_str().unwrap_or_default().to_owned();
        let state_key = json["state_key"].as_str().map(str::to_owned);
        let sender = json["sender"].as_str().unwrap_or_default().to_owned();
        let prev: Vec<EventId> = json["prev_events"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(EventId::new)
                    .collect()
            })
            .unwrap_or_default();

        let input = EventInput::new(event_id, prev);
        let input = match &state_key {
            Some(state_key) => {
                input.with_state_key(StateKey::new(event_type.as_str(), state_key.as_str()))
            }
            None => input,
        };
        let entry = log
            .append_remote(input)
            .map_err(|error| RoomError::Append(format!("{error:?}")))?
            .clone();

        let content = json["content"].clone();
        self.persist_entry(
            log,
            room_id,
            &entry,
            event_id,
            &PersistInput {
                event_type: &event_type,
                state_key: state_key.as_deref(),
                sender: &sender,
                content: &content,
                json,
            },
        )?;
        if fan_out {
            self.enqueue_outbound(log, room_id, json)?;
        }
        Ok(())
    }

    /// Everything an appended entry writes beside itself, shared by the
    /// local and federation paths so neither can forget an index the other
    /// maintains.
    fn persist_entry(
        &self,
        log: &mut RoomLog,
        room_id: &str,
        entry: &LogEntry,
        event_id: &str,
        input: &PersistInput<'_>,
    ) -> Result<(), RoomError> {
        // Keep the unread index current while it is warm. Only if cached:
        // a cold room's index is built from the log on first use, so there
        // is nothing to maintain until someone asks.
        if input.state_key.is_none() {
            let mut cache = self
                .unread_index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = cache.get_mut(room_id) {
                index.push(entry.li.get(), input.sender);
            }
        }

        // The append that changes a room's recency refreshes the cached
        // sort key, so the sliding-sync room list never re-reads a body
        // for it. Unconditional: an absent entry is filled lazily, a
        // present one must not go stale.
        self.last_activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                room_id.to_owned(),
                input.json["origin_server_ts"].as_i64().unwrap_or(0),
            );

        // The signed JSON is stored beside the log entry. The log holds
        // ordering and state; the event body is what a client actually reads
        // back, and reconstructing it from the log would mean re-signing, which
        // would produce a different event ID.
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        spindle_store::Store::put(
            self.store.as_ref(),
            &event_body_key(room_id, event_id),
            &serde_json::to_vec(input.json)?,
        )?;
        // A relation is indexed in the entry's own batch too, and for the same
        // reason: an index entry written separately can outlive a commit that
        // failed, leaving `/relations` pointing at an event the room does not
        // have.
        let mut extra = Vec::new();
        if let Some((rel_type, target)) = relates_to(input.content) {
            // The type goes in the value, not the key -- see `keys::relation`.
            let mut value = Vec::with_capacity(2 + rel_type.len() + event_id.len());
            value.extend_from_slice(
                &u16::try_from(rel_type.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            value.extend_from_slice(rel_type.as_bytes());
            value.extend_from_slice(event_id.as_bytes());
            extra.push((
                spindle_core::keys::relation(room_id, &target, entry.li),
                value,
            ));
        }

        // The event->room reverse index rides the same batch: federation
        // asks for events by ID alone, and an index row that outlived a
        // failed commit would point at an event the room does not have.
        extra.push((
            spindle_core::keys::event_room(event_id),
            room_id.as_bytes().to_vec(),
        ));

        // The stream id goes in the entry's own batch, so an event is either
        // in the global order or not stored at all. Assigned under the same
        // lock that serialises appends, which is what makes the watermark the
        // counter -- see the field's own note.
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stream_id = stream.saturating_add(1);
        extra.push((
            spindle_core::keys::stream(stream_id),
            StreamRecord {
                room_id: room_id.to_owned(),
                li: entry.li.get(),
            }
            .encode(),
        ));
        room_store.commit_entry_with(entry, log, &extra, Durability::Group)?;
        *stream = stream_id;
        drop(stream);

        // The index is derived from the event that just landed, and only from
        // an event that landed: writing it before the commit would leave a
        // user joined to a room whose membership event was never stored.
        if input.event_type == "m.room.member" {
            self.index_membership(room_id, input.state_key, input.content)?;
        }
        self.appended.notify_waiters();
        Ok(())
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
        // Being brought back into a room undoes forgetting it, and this is the
        // one place every member event passes through -- doing it in the
        // `/join` handler instead would miss an invite, a third-party join and
        // whatever path federation eventually appends through.
        if membership == JOIN_STR || membership == INVITE_STR {
            spindle_store::Store::delete(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Forgotten,
                    user_id,
                    room_id,
                ),
            )?;
        }
        // A membership event in a log this server holds supersedes any
        // out-of-room invite record: the room is here now, and stripped
        // state read from a live log beats a snapshot from the inviter.
        spindle_store::Store::delete(
            self.store.as_ref(),
            &spindle_core::keys::user_room(
                spindle_core::keys::Keyspace::PendingInvite,
                user_id,
                room_id,
            ),
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

/// The event-shaped arguments `persist_entry` needs, in one carrier so the
/// two call sites cannot drift on argument order.
struct PersistInput<'a> {
    event_type: &'a str,
    state_key: Option<&'a str>,
    sender: &'a str,
    content: &'a Value,
    json: &'a Value,
}

/// An event ID with its stored body — federation answers want both, and
/// the ID is known before the body is read.
pub type IdentifiedEvent = (String, Value);

/// Read back the `(rel_type, event_id)` a relation row stores.
fn decode_relation(value: &[u8]) -> Option<(String, String)> {
    let len = usize::from(u16::from_be_bytes(value.get(..2)?.try_into().ok()?));
    let rel_type = String::from_utf8(value.get(2..2 + len)?.to_vec()).ok()?;
    let event_id = String::from_utf8(value.get(2 + len..)?.to_vec()).ok()?;
    Some((rel_type, event_id))
}

/// The `(rel_type, event_id)` an event relates to, if it relates to anything.
///
/// Both fields are required: a `m.relates_to` missing either is not a relation
/// this server can index, and indexing it under an empty key would put every
/// such event in one bucket.
fn relates_to(content: &Value) -> Option<(String, String)> {
    let relates = content.get("m.relates_to")?;
    let rel_type = relates.get("rel_type")?.as_str()?;
    let event_id = relates.get("event_id")?.as_str()?;
    if rel_type.is_empty() || event_id.is_empty() {
        return None;
    }
    Some((rel_type.to_owned(), event_id.to_owned()))
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
    let from_stream =
        spindle_store::ReadView::scan_prefix(store, &spindle_core::keys::stream_prefix())
            .unwrap_or_default()
            .iter()
            .filter_map(|(key, _)| spindle_core::keys::stream_from_key(key))
            .max()
            .unwrap_or(0);
    // Pending to-device messages drew from this counter without writing a
    // stream row, so their sequence numbers are invisible to the scan above.
    // A counter resumed below them would eventually re-allocate a pending
    // message's sequence for the same device and overwrite it — silent loss
    // of session-establishment ciphertext. Their keys end in the big-endian
    // sequence, so the maximum is read off the last eight bytes.
    let from_to_device = spindle_store::ReadView::scan_prefix(
        store,
        &[
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::ToDevice as u8,
        ],
    )
    .unwrap_or_default()
    .iter()
    .filter_map(|(key, _)| {
        key.get(key.len().checked_sub(8)?..)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
    })
    .max()
    .unwrap_or(0);
    // Device-list watermarks are the third drawer the counter allocates into
    // without a stream row. The failure a low resume causes here is subtler
    // than an overwrite: `/sync` hands out `next_batch` tokens read off this
    // counter, so a change recorded at a re-used low sequence would sit at or
    // below a token a client already holds — and that client would never hear
    // that a device changed, and keep encrypting to a stale device set.
    let from_device_lists = spindle_store::ReadView::scan_prefix(
        store,
        &spindle_core::keys::device_list_change_prefix(),
    )
    .unwrap_or_default()
    .iter()
    .filter_map(|(_, value)| value.as_slice().try_into().map(u64::from_be_bytes).ok())
    .max()
    .unwrap_or(0);
    // The federation outbox is the fourth drawer: its rows carry the
    // sequence in the key's last eight bytes and have no stream row, and a
    // counter resumed below one would eventually overwrite a pending
    // delivery for the same destination.
    let from_outbox =
        spindle_store::ReadView::scan_prefix(store, &spindle_core::keys::federation_outbox_all())
            .unwrap_or_default()
            .iter()
            .filter_map(|(key, _)| {
                key.get(key.len().checked_sub(8)?..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
            })
            .max()
            .unwrap_or(0);
    from_stream
        .max(from_to_device)
        .max(from_device_lists)
        .max(from_outbox)
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
