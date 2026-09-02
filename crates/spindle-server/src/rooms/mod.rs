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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

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

/// Asked to be let in, and not yet answered. A sixth membership and its own
/// `/sync` section: a knock is neither an invitation the user can accept nor
/// a room they are in, and a client renders it as neither.
const KNOCK: &[u8] = b"knock";

/// [`KNOCK`] as a `str`, for the same reason [`JOIN_STR`] exists.
const KNOCK_STR: &str = "knock";

const _: () = assert!(
    KNOCK_STR.as_bytes()[0] == KNOCK[0] && KNOCK_STR.len() == KNOCK.len(),
    "the membership index and the event content must spell `knock` the same way"
);

/// [`INVITE`] as a `str`, for the same reason [`JOIN_STR`] exists.
const INVITE_STR: &str = "invite";

const _: () = assert!(
    INVITE_STR.as_bytes()[0] == INVITE[0] && INVITE_STR.len() == INVITE.len(),
    "the membership index and the event content must spell `invite` the same way"
);

/// One cached `/state` render: the root it was rendered from, and the body.
type StateRender = ([u8; 32], Arc<String>);

/// How much of a room's state an initial sync needs materialized.
///
/// Three-way rather than two booleans, because the third case is the point:
/// a client that asked for the whole state block and applied no filter to it
/// is asking for exactly the bytes [`Rooms::state_serialized`] already holds,
/// rendered and cached against the state root. Materializing 800 events into
/// `Value`s so the caller can serialize them straight back is work done to
/// arrive where we started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateBlock {
    /// Materialize it. The caller has a filter to apply.
    Rendered,
    /// Materialize only the members this response makes the client need.
    LazyMembers,
    /// Do not materialize it at all: the caller will serve the cached
    /// render. Only correct when nothing downstream narrows the block.
    Deferred,
}

/// A room's joined user IDs, with the state root they were read from.
type MemberIds = ([u8; 32], Arc<Vec<String>>);
/// Remote domains to fan out to, and the state root they were read from.
type Destinations = ([u8; 32], Arc<Vec<String>>);

mod unread;

use unread::{HighlightTally, UnreadIndex};
pub use unread::{Receipt, Unread, Unscored};

pub struct Rooms {
    store: Arc<FjallStore>,
    server_name: String,
    open: RwLock<HashMap<String, Arc<RwLock<RoomLog>>>>,
    /// Lock order: `open` before `unread_index`, always. The fast path takes
    /// only `unread_index`; the build and append paths already hold `open`.
    unread_index: Mutex<HashMap<String, UnreadIndex>>,
    /// Per `(room, reader)`; taken on its own, never under `open`.
    highlights: Mutex<HashMap<(String, String), HighlightTally>>,
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
    /// Who is joined, per room, keyed by the state root it was read from.
    ///
    /// Same argument as `state_render`, for the same reason: "who is in
    /// this room" and "how many are in this room" are asked constantly --
    /// by sliding sync for every room in the window on every request, by
    /// the room summary, and by the appservice transaction path for every
    /// room in every batch -- and the only way to answer either is to read
    /// each member event's body and look at its `membership`. That is a
    /// stored-body read and a JSON parse per member, per ask. The root is
    /// the answer's identity, so a hit is provably current.
    member_ids: Mutex<HashMap<String, MemberIds>>,
    /// Each room's version, read once from its create event.
    ///
    /// Unlike every other cache here this one is keyed by room alone, with
    /// no root and no invalidation, because a room's version is fixed when
    /// it is created and there is no event that can change it. That is the
    /// whole lifetime rule.
    ///
    /// It is a cache rather than a plain lookup because the authorization
    /// path asks on every single append. Reading and parsing the create
    /// event each time would put a stored-body read in front of every event
    /// this server accepts -- the same "narrow question answered with a
    /// whole read" shape that #172, #173 and #175 were about, freshly
    /// introduced.
    /// Which remote servers an event in this room must be sent to, keyed by
    /// the state root the answer was read from.
    ///
    /// The audience is a function of membership, and membership is part of
    /// the state -- so the root is the answer's identity here exactly as it
    /// is for `state_render` and `member_ids`.
    ///
    /// What makes this one worth caching is the shape of the miss. Answering
    /// it walks every member in the room and then does a **point read per
    /// member** into the membership index, and that ran on every single
    /// append: an N-member room paid N store reads to send one message. The
    /// hit rate is the good part -- a non-state event leaves the state root
    /// untouched, so every message between two membership changes shares a
    /// root, and a busy room recomputes only when who-is-in-it actually
    /// moves.
    destinations: Mutex<HashMap<String, Destinations>>,
    room_versions: Mutex<HashMap<String, RoomVersionId>>,
    /// The server-global order `/sync` needs (SPEC §10.2). The linear index
    /// orders events within one room; nothing orders them across rooms, so
    /// this is the one counter that exists purely because a per-room order is
    /// not a server order.
    ///
    /// SPEC §10.2's counter *and* its watermark over in-flight ids.
    ///
    /// Today every append holds the same lock, so ids are allocated and
    /// committed in the same order and the watermark is exactly the counter
    /// -- see `stream::Stream`'s own tests, one of which pins that
    /// equivalence. The structure is here ahead of the change that needs it
    /// because it is the part with the teeth: once appends to different
    /// rooms proceed at once, a token handed out past an in-flight id skips
    /// that event for that client forever, silently. Building and proving it
    /// first makes the lock change mechanical instead of frightening.
    stream: crate::stream::Stream,
    /// Woken whenever an event lands, so a long-polling `/sync` does not have
    /// to spin. SPEC §10.3 wants per-room subscriber lists; this is the same
    /// shape at server granularity, which is enough while there is one lock.
    appended: tokio::sync::Notify,
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
    /// Rooms knocked on and not yet answered — see [`Rooms::knocked`].
    pub knocked: Vec<String>,
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
    /// Where the window begins: the position of its first event, which is
    /// what `/messages?dir=b` pages back from as `prev_batch` (#331). `None`
    /// only when the window is empty. Sent whether or not the window is
    /// `limited`: matrix-js-sdk keeps it as the live timeline's backwards
    /// token, and without one a client cannot ask for anything before the
    /// window at all -- a joiner's window starts at their join, so they saw
    /// no history.
    pub prev_batch: Option<i64>,
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

/// How a `state_at` query names its point in the log (#83 §4).
#[derive(Clone, Debug)]
pub enum StateAtAnchor {
    /// A linear index; resolves to the newest entry at or before it.
    Li(i64),
    /// A unix-milliseconds timestamp; resolves to the last entry whose
    /// `origin_server_ts` is at or under it.
    Ts(u64),
    /// An event ID; resolves to exactly that entry.
    Event(String),
}

/// Which side of a timestamp `/timestamp_to_event` should look.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampDirection {
    /// The first event at or after the timestamp (`dir=f`).
    Forward,
    /// The last event at or before it (`dir=b`).
    Backward,
}

/// One stored event, as a client sees it.
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    pub event_id: String,
    pub li: i64,
    pub json: Value,
}

/// One log entry as the admin timeline shows it: the spine always, the
/// body only while it exists. `json: None` with the entry present is the
/// mark of a purge — the distinction #83 §3 says a purge must preserve.
#[derive(Clone, Debug)]
pub struct AdminTimelineEntry {
    pub li: i64,
    pub event_id: String,
    /// This server's chain attestation, `None` for backfilled history.
    pub chain: Option<[u8; 32]>,
    /// `None` when the body was purged.
    pub json: Option<Value>,
}

impl Rooms {
    #[must_use]
    pub fn new(store: Arc<FjallStore>, server_name: impl Into<String>) -> Self {
        let store_for_stream = Arc::clone(&store);
        // Read once and used twice: the stream's own high-water mark bounds
        // the index backfill and is one of the four drawers the counter
        // resumes above.
        let stream_high = highest_stream_row(store_for_stream.as_ref());
        // Before anything reads the reverse index, make it complete. A store
        // written by a binary without it has a forward stream and no index,
        // and an incremental `/sync` answered from an empty index would
        // report that nothing had happened -- not slower, wrong.
        backfill_room_stream_index(store_for_stream.as_ref(), stream_high);
        Self {
            store,
            server_name: server_name.into(),
            open: RwLock::new(HashMap::new()),
            unread_index: Mutex::new(HashMap::new()),
            highlights: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(HashMap::new()),
            state_render: Mutex::new(HashMap::new()),
            member_ids: Mutex::new(HashMap::new()),
            destinations: Mutex::new(HashMap::new()),
            room_versions: Mutex::new(HashMap::new()),
            // Resumed, not reset. A counter that restarted at zero would
            // re-issue stream ids already on disk, overwriting the entries
            // they point at -- the same shape of bug as a room registry that
            // does not survive a restart, and worse, because it corrupts
            // rather than merely forgets.
            stream: crate::stream::Stream::resuming_at(highest_stream_id(
                store_for_stream.as_ref(),
                stream_high,
            )),
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
        version: Option<&str>,
        creation_content: Option<&serde_json::Map<String, Value>>,
        creator_profile: &serde_json::Map<String, Value>,
    ) -> Result<String, RoomError> {
        // The requested version, or this build's default. Refused rather
        // than substituted: handing back a different version than was asked
        // for, and reporting success, is a lie the client cannot detect
        // until something that depends on the version fails.
        let version = version.unwrap_or(ROOM_VERSION);
        if !crate::surface::supports_room_version(version) {
            return Err(RoomError::UnsupportedVersion(version.to_owned()));
        }
        // MSC4289: from v12 the create event's *sender* is the creator, so
        // repeating it in `content.creator` is redundant and the field is
        // dropped. Before v12 it is required.
        let privileges_creators = RoomVersionId::try_from(version)
            .ok()
            .and_then(|id| id.rules())
            .is_some_and(|rules| rules.authorization.explicitly_privilege_room_creators);
        let create_content =
            build_create_content(version, creator, privileges_creators, creation_content);
        // MSC4291 inverts the order a room is born in. Before v12 the ID
        // was chosen and the create event then named it; from v12 the ID
        // *is* the create event's hash, so the event must be signed before
        // there is an ID to store it under. Either way the create event is
        // signed exactly once here and committed below -- re-signing it
        // would move `origin_server_ts` and, for v12, break the very
        // identity being established.
        let (create_id, create_json, room_id) = self.birth(creator, key, &create_content)?;
        let mut log = RoomLog::new();
        self.authorize(&log, &room_id, &create_id, &create_json)?;
        self.commit_event(
            &mut log,
            &room_id,
            creator,
            "m.room.create",
            Some(""),
            &create_content,
            &create_id,
            &create_json,
        )?;

        let mut creator_join = Value::Object(creator_profile.clone());
        creator_join["membership"] = Value::String("join".to_owned());
        let mut events: Vec<(&str, String, Value)> = vec![
            ("m.room.member", creator.to_owned(), creator_join),
            (
                "m.room.power_levels",
                String::new(),
                serde_json::json!({
                    // MSC4289: a v12 room privileges its creators
                    // implicitly and *forbids* naming them here -- the
                    // create fails authorization if they appear.
                    "users": if privileges_creators {
                        serde_json::json!({})
                    } else {
                        serde_json::json!({ creator: 100 })
                    },
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
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.clone(), Arc::new(RwLock::new(log)));
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
    /// A restricted room is the one join the rules cannot decide alone, and
    /// the spec says so: it turns on the joiner's membership in *another*
    /// room, which the rules — judging one room's state — cannot see. So this
    /// function fills in `join_authorised_via_users_server` before signing,
    /// and the rules judge that nomination like anything else. See
    /// [`Self::restricted_join_nominee`]; it is an addition to the event, not
    /// a verdict on it.
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
        self.set_membership_with(
            room_id,
            sender,
            target,
            membership,
            reason,
            &serde_json::Map::new(),
            key,
        )
    }

    /// [`Self::set_membership`], with `extra` fields in the content: the
    /// target's `displayname` and `avatar_url`, which the spec has a join
    /// and an invite carry so a client can show who joined or was invited
    /// without a profile lookup (#317). The caller supplies them because
    /// profiles live above this layer; `membership` and `reason` are set
    /// here and win over anything in `extra`.
    ///
    /// # Errors
    ///
    /// As [`Self::set_membership`].
    #[allow(
        clippy::too_many_arguments,
        reason = "one membership event, in one place"
    )]
    pub fn set_membership_with(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        membership: &str,
        reason: Option<&str>,
        extra: &serde_json::Map<String, Value>,
        key: &Ed25519KeyPair,
    ) -> Result<String, RoomError> {
        // An administratively blocked room refuses every join. The check
        // sits here rather than in a route so that every local join path
        // — direct, via alias, accepting an invite — hits it.
        if membership == JOIN_STR && self.room_block(room_id)?.is_some() {
            return Err(RoomError::Forbidden(
                "this room is blocked by a server administrator".to_owned(),
            ));
        }
        let mut content = Value::Object(extra.clone());
        content["membership"] = Value::String(membership.to_owned());
        // Absent rather than null when there is no reason: `reason` is part of
        // the event content, so it is covered by the signature and by the
        // event ID, and a null would make the same kick hash differently from
        // one sent by a server that simply omits the field.
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_owned());
        }
        self.with_room(room_id, |rooms, log| {
            // The one thing about a join this server has to work out for
            // itself, because the rules cannot: see
            // [`Self::restricted_join_nominee`]. It is added to the content
            // before signing, since the nomination is part of what every
            // other server verifies.
            if membership == JOIN_STR
                && let Some(nominee) = rooms.restricted_join_nominee(log, room_id, target)?
            {
                content["join_authorised_via_users_server"] = Value::String(nominee);
            }
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
        self.state_where(room_id, |_| true)
    }

    /// The state block for one room on an initial sync.
    ///
    /// With `lazy_members`, membership is narrowed to the senders the
    /// client is about to see in this room's timeline, plus the syncing
    /// user's own — the spec permits redundant members, and a client that
    /// cannot find itself in the state it was sent tends to conclude it is
    /// not in the room.
    ///
    /// The senders here are the *unfiltered* timeline's. A client filter
    /// may drop timeline events further up, which can only make the needed
    /// set smaller, so this errs towards sending a member event that turns
    /// out to be unnecessary rather than withholding one that was. The
    /// exact narrowing still happens where the filter is applied; what this
    /// removes is the cost of reading the bodies.
    fn initial_state(
        &self,
        room_id: &str,
        user_id: &str,
        state_block: StateBlock,
        timeline: &[Value],
    ) -> Result<Vec<Value>, RoomError> {
        match state_block {
            // Nothing to do: the caller serves the cached render.
            StateBlock::Deferred => return Ok(Vec::new()),
            StateBlock::Rendered => return self.state(room_id),
            StateBlock::LazyMembers => {}
        }
        let mut needed: HashSet<&str> = timeline
            .iter()
            .filter_map(|event| event["sender"].as_str())
            .collect();
        needed.insert(user_id);
        self.state_where(room_id, |key| {
            key.event_type().as_str() != "m.room.member" || needed.contains(key.state_key())
        })
    }

    /// The current state, skipping keys the caller does not want.
    ///
    /// The predicate sees the state *key*, which is the whole point: the
    /// key is already in hand from the trie, and deciding on it means an
    /// unwanted event is never read from the store and never parsed. A
    /// caller that filters the returned vector instead has already paid
    /// for everything it throws away.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or an event body is
    /// missing.
    pub fn state_where(
        &self,
        room_id: &str,
        want: impl Fn(&StateKey) -> bool,
    ) -> Result<Vec<Value>, RoomError> {
        let ids = self.with_room_read(room_id, |_, log| Ok(current_state(log)))?;
        let mut events = Vec::with_capacity(ids.len());
        for (key, event_id) in ids {
            if !want(&key) {
                continue;
            }
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
        let root = self.with_room_read(room_id, |_, log| {
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

    /// What room version this room was created at.
    ///
    /// The version is a property of the *room*, recorded in its create
    /// event's content when the room is made and unchangeable afterwards.
    /// Everything version-dependent -- redaction, authorization, hashing --
    /// should ask this rather than a module constant, because a constant is
    /// only correct while every room this server has ever seen is the same
    /// version, and the moment that stops being true it is silently wrong
    /// rather than loudly wrong.
    ///
    /// A room whose create event names no version is v1, per the spec. That
    /// is not a defensive nicety: it is what a room federated from a server
    /// old enough to omit the field actually is, and guessing our own
    /// default there would apply the wrong rules to someone else's room.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the create event cannot be read, or names a
    /// version this build does not know the rules for -- which is a refusal
    /// to guess, since applying the wrong version's rules is how a server
    /// accepts an event it should have rejected.
    pub fn room_version(&self, room_id: &str) -> Result<RoomVersionId, RoomError> {
        if let Some(version) = self
            .room_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
        {
            return Ok(version.clone());
        }
        let content = self.state_event(room_id, "m.room.create", "")?;
        let version = version_in(&content)?;
        self.room_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), version.clone());
        Ok(version)
    }

    /// The rule set this room's version selects.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the version cannot be determined, or if it
    /// is one `ruma` has no rules for.
    pub fn rules(&self, room_id: &str) -> Result<RoomVersionRules, RoomError> {
        rules_of(&self.room_version(room_id)?)
    }

    /// The room's rules, resolved from a log the caller is already holding.
    ///
    /// [`Self::rules`] must not be used from inside [`Self::with_room`].
    /// It reaches the create event through [`Self::state_event`], which
    /// takes the `open` lock, and `std::sync::Mutex` is not reentrant --
    /// so from within the closure that already holds it, that is a
    /// deadlock rather than a slow path. It hung the federation invite
    /// tests, which is how this function came to exist.
    ///
    /// Here the log is a parameter and the event body comes from
    /// [`Self::read_event`], which goes to the store directly and takes no
    /// lock at all. Same cache, same answer, no re-entry.
    fn rules_in(&self, log: &RoomLog, room_id: &str) -> Result<RoomVersionRules, RoomError> {
        rules_of(&self.version_in_log(log, room_id)?)
    }

    /// Whether this server is the one that speaks for `user_id`.
    fn is_local(&self, user_id: &str) -> bool {
        user_id.split_once(':').map(|(_, domain)| domain) == Some(self.server_name.as_str())
    }

    /// The `join_authorised_via_users_server` a restricted room's join needs
    /// from this server, or `None` when this server has nothing to say.
    ///
    /// MSC3083 is the one join rule the authorization rules deliberately do
    /// not decide. Every other rule is answerable from the room's own state;
    /// `restricted` says *you may join this room because you are in that
    /// one*, and the rules judge one room at a time. So the spec splits it:
    /// a server that can see both rooms decides, and records the decision by
    /// naming a member of *this* room who could have invited the joiner --
    /// the authorising user. The rules then check that nomination, and so
    /// does every server the event reaches.
    ///
    /// That split is why this is not a second copy of the auth rules
    /// (`docs/divergence.md` names that as the thing that must not happen).
    /// Nothing here decides whether the join is allowed. It answers the
    /// question the rules cannot reach -- is the joiner in an allowed room --
    /// and nominates the strongest candidate this server can offer;
    /// [`Self::authorize`] then judges the nomination like any other.
    ///
    /// Returns `None`, leaving the event unchanged, when the room is not
    /// restricted, when the joiner is already invited or joined (the rules
    /// admit that from the room's own state, and an unnecessary nomination
    /// would be a claim nothing asked for), when no `allow` entry names a
    /// room this server can see the joiner in, or when this server holds no
    /// member to nominate.
    fn restricted_join_nominee(
        &self,
        log: &RoomLog,
        room_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, RoomError> {
        let Some(rules) = current_state_id(log, &StateKey::new("m.room.join_rules", ""))
            .and_then(|id| self.read_event(room_id, &EventId::new(id.as_str())).ok())
        else {
            return Ok(None);
        };
        let rules = &rules["content"];
        if !matches!(
            rules["join_rule"].as_str(),
            Some("restricted" | "knock_restricted")
        ) {
            return Ok(None);
        }
        let membership = |user: &str, room: &str| -> Option<Vec<u8>> {
            spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    user,
                    room,
                ),
            )
            .ok()
            .flatten()
        };
        let joined = |user: &str, room: &str| -> bool {
            membership(user, room).as_deref() == Some(JOIN_STR.as_bytes())
        };
        if matches!(membership(user_id, room_id).as_deref(), Some(JOIN | INVITE)) {
            return Ok(None);
        }
        // An `allow` entry naming a room this server does not hold reads as
        // "not joined" rather than as an error: we genuinely cannot see it,
        // and guessing that the joiner is in it would forge the vouching.
        let vouched = rules["allow"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| {
                entry["type"].as_str() == Some("m.room_membership")
                    && entry["room_id"]
                        .as_str()
                        .is_some_and(|allowed| joined(user_id, allowed))
            });
        if !vouched {
            return Ok(None);
        }

        // Candidates strongest first. Power levels are read to *rank* them,
        // never to conclude that the strongest is strong enough -- whether
        // the nominee outranks the room's invite level is the rules' call,
        // and making it here is how the two copies would start to diverge.
        let mut ranked: Vec<(i64, String)> = Vec::new();
        if self
            .rules_in(log, room_id)?
            .authorization
            .explicitly_privilege_room_creators
            && let Some(create) = current_state_id(log, &StateKey::new("m.room.create", ""))
                .and_then(|id| self.read_event(room_id, &EventId::new(id.as_str())).ok())
        {
            // MSC4289: a v12 room's creators hold implicit power that no
            // `users` entry may name, so ranking by that map alone would
            // miss the only members who can vouch in a room that raised
            // its invite level.
            let creators = create["sender"]
                .as_str()
                .into_iter()
                .chain(
                    create["content"]["additional_creators"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str),
                )
                .map(str::to_owned);
            ranked.extend(creators.map(|creator| (i64::MAX, creator)));
        }
        let power = current_state_id(log, &StateKey::new("m.room.power_levels", ""))
            .and_then(|id| self.read_event(room_id, &EventId::new(id.as_str())).ok())
            .map_or(Value::Null, |event| event["content"].clone());
        for (user, level) in power["users"].as_object().into_iter().flatten() {
            if let Some(level) = level.as_i64() {
                ranked.push((level, user.clone()));
            }
        }
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        for (_, candidate) in ranked {
            if self.is_local(&candidate) && joined(&candidate, room_id) {
                return Ok(Some(candidate));
            }
        }

        // Nobody named, or nobody named is here: every remaining member sits
        // at `users_default`, so any of them ranks the same and the lowest
        // ID makes the choice reproducible. `for_each` yields state keys in
        // order, so taking the first is exactly that.
        let mut fallback = None;
        let Some(state) = log
            .entries()
            .next_back()
            .and_then(|head| log.state_after(head.li))
        else {
            return Ok(None);
        };
        state.for_each(|key, _| {
            if fallback.is_none()
                && key.event_type().as_str() == "m.room.member"
                && self.is_local(key.state_key())
                && joined(key.state_key(), room_id)
            {
                fallback = Some(key.state_key().to_owned());
            }
        });
        Ok(fallback)
    }

    /// Mint a room: its create event, and the ID that event implies.
    ///
    /// The two are one step because from v12 they are one fact. Before
    /// v12 the ID is chosen and the create event names it; from v12 the
    /// ID *is* the event's hash and the event must not name it (MSC4291).
    /// Either way the event is signed exactly once and returned for
    /// committing -- see [`Self::sign_create`] for why signing twice is
    /// not an option.
    fn birth(
        &self,
        creator: &str,
        key: &Ed25519KeyPair,
        create_content: &Value,
    ) -> Result<(String, Value, String), RoomError> {
        if derives_room_id(create_content) {
            let (id, json) = self.sign_create(creator, key, create_content, None)?;
            let hash = id
                .strip_prefix('$')
                .ok_or_else(|| RoomError::Build(format!("event id has no sigil: {id}")))?;
            let room_id = format!("!{hash}");
            Ok((id, json, room_id))
        } else {
            let room_id = format!("!{}:{}", random_id(), self.server_name);
            let (id, json) = self.sign_create(creator, key, create_content, Some(&room_id))?;
            Ok((id, json, room_id))
        }
    }

    /// Sign a room's create event, once.
    ///
    /// `room_id` is the ID to name inside the event, or `None` for MSC4291
    /// versions where the event must not name it -- because the room's ID
    /// *is* this event's hash, so naming it would be circular.
    ///
    /// The result is the event that gets committed, not a preview of it.
    /// Signing a second time would move `origin_server_ts` and change the
    /// hash, which for a v12 room means the room ID no longer matches the
    /// create event it was derived from.
    fn sign_create(
        &self,
        creator: &str,
        key: &Ed25519KeyPair,
        content: &Value,
        room_id: Option<&str>,
    ) -> Result<(String, Value), RoomError> {
        let empty = RoomLog::new();
        let auth = auth_events_for(
            &empty,
            &rules_of(&version_in(content)?)?.authorization,
            creator,
            "m.room.create",
            Some(""),
            content,
        )?;
        let canonical = build_canonical(
            room_id,
            creator,
            "m.room.create",
            Some(""),
            content,
            &[],
            &auth,
            0,
        )?;
        let version = version_in(content)?;
        let pdu = Pdu::sign(version, canonical, &self.server_name, key)
            .map_err(|error| RoomError::Build(format!("{error:?}")))?;
        Ok((
            pdu.event_id().as_str().to_owned(),
            canonical_to_json(pdu.canonical()),
        ))
    }

    /// The room's version, resolved from a log the caller is already holding.
    ///
    /// Same re-entrancy rule as [`Self::rules_in`], which it backs: never
    /// reach this through [`Self::room_version`] from inside
    /// [`Self::with_room`].
    fn version_in_log(&self, log: &RoomLog, room_id: &str) -> Result<RoomVersionId, RoomError> {
        if let Some(version) = self
            .room_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
        {
            return Ok(version.clone());
        }
        let id = current_state_id(log, &StateKey::new("m.room.create", ""))
            .ok_or_else(|| RoomError::UnknownState("m.room.create".to_owned()))?;
        let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
        let version = version_in(&event["content"])?;
        self.room_versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), version.clone());
        Ok(version)
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
        let found = self.with_room_read(room_id, |_, log| Ok(current_state_id(log, &wanted)))?;
        let event_id = found.ok_or_else(|| {
            RoomError::UnknownState(format!("{event_type} with state key {state_key:?}"))
        })?;
        let event = self.read_event(room_id, &EventId::new(event_id))?;
        Ok(event
            .get("content")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())))
    }

    /// One current state event, whole, rather than just its content.
    ///
    /// The targeted sibling of [`Self::state`]: a caller that wants three
    /// named keys should read three events, not materialize every state
    /// event in the room and filter the result down.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownState`] when the room has no such state.
    pub fn state_event_full(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Value, RoomError> {
        let wanted = StateKey::new(event_type, state_key);
        let found = self.with_room_read(room_id, |_, log| Ok(current_state_id(log, &wanted)))?;
        let event_id = found.ok_or_else(|| {
            RoomError::UnknownState(format!("{event_type} with state key {state_key:?}"))
        })?;
        let event = self.read_event(room_id, &EventId::new(event_id.as_str()))?;
        // Stamped, because [`Self::state`] stamps: a caller that names its
        // keys and a caller that asks for everything must not receive
        // differently-shaped events. The stored body has no `event_id` --
        // the id is the hash of the body, so carrying it inside would be
        // circular -- and a client cannot redact, reply to or de-duplicate
        // an event it cannot name.
        Ok(stamp(event, &event_id))
    }

    /// How many users are joined, without rendering any of them.
    ///
    /// Cached against the state root, because the count only changes when
    /// the state does. The uncached path is what [`Self::joined_members`]
    /// pays — a body read and a JSON parse per member — and sliding sync
    /// asks for this on every request for every room in the window.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn joined_member_count(&self, room_id: &str) -> Result<usize, RoomError> {
        Ok(self.joined_member_ids(room_id)?.len())
    }

    /// The room exists.
    ///
    /// The whole answer, for callers that only need the question settled --
    /// an alias may not point at a room that is not there. Reading the
    /// room's state to establish it, which is what this replaced, costs a
    /// stored-body read and a JSON parse per state event to produce a
    /// boolean.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn exists(&self, room_id: &str) -> Result<(), RoomError> {
        self.with_room_read(room_id, |_, _| Ok(()))
    }

    /// Who is currently joined, as user IDs, without rendering any of them.
    ///
    /// Cached against the state root, because who is joined only changes
    /// when the state does. Callers that want names and avatars want
    /// [`Self::joined_members`]; callers that want to know *who*, or just
    /// how many, want this and should not pay to render a profile they
    /// will throw away.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn joined_member_ids(&self, room_id: &str) -> Result<Arc<Vec<String>>, RoomError> {
        let (root, members) = self.with_room_read(room_id, |_, log| {
            let root = log
                .entries()
                .next_back()
                .map(|entry| entry.li)
                .and_then(|li| log.state_after(li))
                .map(|state| *state.root().as_bytes());
            let members = current_state(log)
                .into_iter()
                .filter(|(key, _)| key.event_type().as_str() == "m.room.member")
                .map(|(key, event_id)| (key.state_key().to_owned(), event_id))
                .collect::<Vec<_>>();
            Ok((root, members))
        })?;
        let Some(root) = root else {
            return Ok(Arc::new(Vec::new()));
        };
        if let Some((cached_root, ids)) = self
            .member_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
            && *cached_root == root
        {
            return Ok(Arc::clone(ids));
        }
        let mut ids = Vec::new();
        for (user_id, event_id) in members {
            // `read_event`, not `event`: the room's existence is already
            // established above, and `event` re-proves it under the room
            // lock once per member.
            let event = self.read_event(room_id, &EventId::new(event_id.as_str()))?;
            if event["content"]["membership"].as_str() == Some(JOIN_STR) {
                ids.push(user_id);
            }
        }
        let ids = Arc::new(ids);
        self.member_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), (root, Arc::clone(&ids)));
        Ok(ids)
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
        let content = &sanitized_member_content(event_type, content);
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
        self.with_room_read(room_id, |_, _| Ok(()))?;
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
        let known = self.with_room_read(room_id, |_, log| {
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

        // The room's own rules, not this build's default. Redaction is where
        // the versions differ most visibly -- which keys survive a redaction
        // changed in v11 -- so applying ours to someone else's room would
        // strip fields the room's own version keeps.
        let rules = self.rules(room_id)?.redaction;
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
        self.with_room_read(room_id, |_, _| Ok(()))?;

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

    /// A room's thread roots, most recently active first.
    ///
    /// The ordering the spec asks for is by *latest activity in the thread*,
    /// not by when the root was sent, so the sort key is the highest `li`
    /// among a root's live `m.thread` children. That key is free here: the
    /// relation index is keyed by room and ends in `li`, so one prefix scan
    /// over the room hands back every relation already in log order and the
    /// last row for a target is that thread's latest reply. No `latest_event`
    /// column has to be maintained, and nothing can drift out of step with
    /// the events themselves.
    ///
    /// **The root comes out of the child's `content`, not out of the key.**
    /// Both name the same event, but reading it from content makes redaction
    /// handle itself: redaction strips `m.relates_to`, so a redacted reply
    /// stops counting toward the thread it was in — the same rule
    /// [`Rooms::relations`] and [`Rooms::bundle_relations`] apply, and the
    /// reason all three agree about what a thread contains.
    ///
    /// `participated` is the spec's definition and Synapse's: the viewer sent
    /// a reply in the thread, **or** sent the root itself. Applied here rather
    /// than by the caller so that the filter and the
    /// `current_user_participated` flag the bundle carries cannot disagree.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the index cannot be
    /// read.
    pub fn threads(
        &self,
        room_id: &str,
        viewer: &str,
        participated_only: bool,
        from: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<Value>, Option<i64>), RoomError> {
        // The room has to exist, for the reason `relations` gives: an unknown
        // room must not answer "no threads".
        self.with_room_read(room_id, |_, _| Ok(()))?;

        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Relation, room_id);
        let rows = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?;

        // root event id -> (latest reply's li, viewer replied in it)
        let mut roots: HashMap<String, (i64, bool)> = HashMap::new();
        for (key, value) in rows {
            let Some(li) = spindle_core::keys::li_from_key(&key) else {
                continue;
            };
            let Some((rel_type, event_id)) = decode_relation(&value) else {
                continue;
            };
            // Filtered off the index value before the body is read, so a room
            // full of reactions costs one comparison each rather than a load.
            if rel_type != "m.thread" {
                continue;
            }
            let reply = match self.event(room_id, &event_id) {
                Ok(reply) => reply,
                // A purged reply cannot say what it replied to. Skipped, not
                // an error -- the thread's other replies still describe it.
                Err(RoomError::MissingBody(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some((_, root)) = relates_to(&reply["content"]) else {
                continue;
            };
            let replied = reply["sender"].as_str() == Some(viewer);
            let entry = roots.entry(root).or_insert((li, false));
            entry.0 = entry.0.max(li);
            entry.1 |= replied;
        }

        // Descending by latest reply. No tie-break is needed and none would
        // ever fire: an `li` names one event, so two threads cannot share a
        // latest reply.
        let mut ordered: Vec<(i64, String, bool)> = roots
            .into_iter()
            .map(|(root, (li, replied))| (li, root, replied))
            .collect();
        ordered.sort_unstable_by(|left, right| right.0.cmp(&left.0));

        let mut out = Vec::new();
        let mut next = None;
        for (li, root, replied) in ordered {
            // Mirrors `relations`, reflected: that scan runs forward and
            // resumes above the token, this one runs backward and resumes
            // below it.
            if from.is_some_and(|from| li >= from) {
                continue;
            }
            let event = match self.event(room_id, &root) {
                Ok(event) => event,
                // A thread whose root has been purged has nothing to list.
                Err(RoomError::MissingBody(_)) => continue,
                Err(error) => return Err(error),
            };
            if participated_only && !replied && event["sender"].as_str() != Some(viewer) {
                continue;
            }
            if out.len() == limit {
                next = Some(li + 1);
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
        self.context_within(room_id, event_id, limit, None)
    }

    /// [`Self::context`], seeing nothing above `bound`.
    ///
    /// A target above the bound is refused as absent rather than as
    /// forbidden: the caller may not learn that an event exists there. The
    /// window's later half stops at the bound, and `end` with it.
    ///
    /// # Errors
    ///
    /// As [`Self::context`].
    pub fn context_within(
        &self,
        room_id: &str,
        event_id: &str,
        limit: usize,
        bound: Option<i64>,
    ) -> Result<Context, RoomError> {
        self.context_visible(room_id, event_id, limit, &|li| {
            bound.is_none_or(|bound| li <= bound)
        })
    }

    /// As [`Self::context_within`], with the positions `visible` admits: a
    /// target the caller may not see is absent, and both halves of the
    /// window skip what they may not see (#268).
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::MissingBody`] if the event is absent from the
    /// room or outside what the caller may see.
    pub fn context_visible(
        &self,
        room_id: &str,
        event_id: &str,
        limit: usize,
        visible: &(dyn Fn(i64) -> bool + Sync),
    ) -> Result<Context, RoomError> {
        let found = self.with_room_read(room_id, |_, log| {
            let Some(entry) = log.get(&EventId::new(event_id)) else {
                return Ok(None);
            };
            let target = entry.li.get();
            if !visible(target) {
                return Ok(None);
            }
            let state_root = entry.state_root;

            // Symmetric, and each side stops at the end of the log rather than
            // running off it.
            let before: Vec<String> = log
                .entries()
                .rev()
                .filter(|entry| entry.li.get() < target && visible(entry.li.get()))
                .take(limit)
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect();
            let after: Vec<String> = log
                .entries()
                .filter(|entry| entry.li.get() > target && visible(entry.li.get()))
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
        let members = self.with_room_read(room_id, |_, log| {
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
    /// previewed here — public join rule, a standing invite, or a
    /// restricted room this server can vouch the joiner into — so a refused
    /// server learns at the cheap step, but the template is not a promise:
    /// the signed event is authorized again on the way in, against whatever
    /// the state is *then*.
    ///
    /// The restricted case is the one where the preview carries something
    /// the joining server could not have worked out: `restricted_join_nominee`
    /// puts the authorising user into the content, and that field is the
    /// entire basis on which the rules will accept the join.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the rules do not admit the user.
    pub fn make_join_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        if self.room_block(room_id)?.is_some() {
            return Err(RoomError::Forbidden(
                "this room is blocked by a server administrator".to_owned(),
            ));
        }
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
            // A restricted room is the third way in, and it was missing:
            // the joiner is in a room this room admits, and this server can
            // see that. The nomination is the *only* record of it, so it
            // goes into the template -- the joining server signs what we
            // hand back, and `send_join` and every peer after it check the
            // nomination rather than taking our word for the join.
            let nominee = rooms.restricted_join_nominee(log, room_id, user_id)?;
            if join_rule != "public" && !invited && nominee.is_none() {
                return Err(RoomError::Forbidden(
                    "the room is not public, and the user holds no invite and                      is in no room it admits"
                        .to_owned(),
                ));
            }

            let mut content = serde_json::json!({ "membership": "join" });
            if let Some(nominee) = nominee {
                content["join_authorised_via_users_server"] = Value::String(nominee);
            }
            let auth = auth_events_for(
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
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
            let auth = auth_events_for(
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
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
        self.with_room(room_id, |rooms, log| {
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
            let auth = auth_events_for(
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
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
        let previous_root = self.with_room_read(room_id, |_, log| {
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

    /// The room's state at a past point (#83 §4): the query the linear
    /// index turns from a forensic exercise into one seek.
    ///
    /// The anchor resolves to a log entry — the newest at or before an
    /// `li`, the entry of an event ID, or (for a timestamp) the last
    /// entry whose `origin_server_ts` is at or under it, found by binary
    /// search because in a linearized room the storage order *is* the
    /// temporal order. Every entry keeps its 32-byte `state_root`
    /// forever and the log records persist it, so the sparse per-`li`
    /// index #83 anticipated is unnecessary: any entry's state is the
    /// resident snapshot when the window still holds it, and a rehydrate
    /// of shared trie nodes when it does not — slower, never refused.
    ///
    /// Returns the resolved `(li, event_id, resident, state events)` so
    /// the caller can say exactly which point it answered for.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not
    /// exist, and [`RoomError::UnknownState`] when the log starts after
    /// the requested point or the event is not in this room.
    pub fn admin_state_at(
        &self,
        room_id: &str,
        anchor: &StateAtAnchor,
    ) -> Result<(i64, String, bool, Vec<Value>), RoomError> {
        let (li, event_id) = self.resolve_anchor(room_id, anchor)?;

        let root_or_resident = self.with_room_read(room_id, |_, log| {
            if let Some(snapshot) = log.state_after(spindle_core::LinearIndex::from_raw(li)) {
                let mut ids = Vec::with_capacity(snapshot.len());
                snapshot.for_each(|_, id| ids.push(id.to_owned()));
                Ok(Ok(ids))
            } else {
                let entry = log
                    .entry_at_or_before(li)
                    .ok_or_else(|| RoomError::UnknownState("that entry".into()))?;
                Ok(Err(entry.state_root))
            }
        })?;
        let (resident, state) = match root_or_resident {
            Ok(ids) => {
                let mut out = Vec::with_capacity(ids.len());
                for id in ids {
                    out.push(self.event(room_id, &id)?);
                }
                (true, out)
            }
            Err(root) => (false, self.state_at(room_id, root)?),
        };
        Ok((li, event_id, resident, state))
    }

    /// Resolve a [`StateAtAnchor`] to the log entry it names — shared by
    /// `admin_state_at` and `purge_history`, so "the point before 14:03"
    /// means the same entry whether it is being read or purged to.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not
    /// exist, and [`RoomError::UnknownState`] when the log starts after
    /// the requested point or the event is not in this room.
    pub fn resolve_anchor(
        &self,
        room_id: &str,
        anchor: &StateAtAnchor,
    ) -> Result<(i64, String), RoomError> {
        let resolve = |li: i64| -> Result<(i64, String), RoomError> {
            self.with_room_read(room_id, |_, log| {
                log.entry_at_or_before(li)
                    .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                    .ok_or_else(|| RoomError::UnknownState("entry at or before that point".into()))
            })
        };
        match anchor {
            StateAtAnchor::Li(li) => resolve(*li),
            StateAtAnchor::Event(id) => self.with_room_read(room_id, |_, log| {
                log.get(&EventId::new(id.as_str()))
                    .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                    .ok_or_else(|| RoomError::UnknownState("such an event in this room".into()))
            }),
            StateAtAnchor::Ts(wanted) => {
                let (mut low, high) = self.with_room_read(room_id, |_, log| {
                    let mut entries = log.entries();
                    let first = entries.next().map(|entry| entry.li.get());
                    let last = entries.next_back().map(|entry| entry.li.get());
                    Ok((first, last.or(first)))
                })?;
                let (Some(mut low_li), Some(mut high_li)) = (low.take(), high) else {
                    return Err(RoomError::UnknownState("entries in this room".into()));
                };
                let ts_of = |li: i64| -> Result<(i64, u64), RoomError> {
                    let (mut li, mut event_id) = resolve(li)?;
                    loop {
                        match self.event(room_id, &event_id) {
                            Ok(event) => {
                                return Ok((li, event["origin_server_ts"].as_u64().unwrap_or(0)));
                            }
                            // A purged body cannot say when it happened;
                            // the nearest surviving predecessor bounds it
                            // from below — state bodies survive every
                            // purge, so the walk terminates. A fully
                            // purged prefix reads as time zero, which
                            // resolves conservatively into the purge.
                            Err(RoomError::MissingBody(_)) => match resolve(li - 1) {
                                Ok((below_li, below_id)) => {
                                    li = below_li;
                                    event_id = below_id;
                                }
                                Err(_) => return Ok((li, 0)),
                            },
                            Err(error) => return Err(error),
                        }
                    }
                };
                let (first_li, first_ts) = ts_of(low_li)?;
                if first_ts > *wanted {
                    return Err(RoomError::UnknownState(
                        "entry at or before that time".into(),
                    ));
                }
                // Invariant: the entry at or before `low_li` is at or
                // under the wanted time. Probe above the midpoint so the
                // range always narrows; a probe landing in a gap between
                // entries resolves to the nearest entry below it, which
                // both branches handle.
                low_li = first_li;
                while low_li < high_li {
                    let probe = low_li + (high_li - low_li + 1) / 2;
                    let (entry_li, entry_ts) = ts_of(probe)?;
                    if entry_ts <= *wanted {
                        low_li = probe;
                    } else {
                        high_li = entry_li - 1;
                    }
                }
                resolve(low_li)
            }
        }
    }

    /// The event closest to `ts`, on the side `direction` names.
    ///
    /// `/timestamp_to_event`'s whole job. [`StateAtAnchor::Ts`] already
    /// answers the backward side -- the last entry at or under a time -- so
    /// that is what this delegates to; the forward side is the entry after
    /// it, because the log is ordered and "the first entry at or after `ts`"
    /// is the successor of "the last entry strictly before `ts`".
    ///
    /// The one case that is not a successor is a `ts` at or below the room's
    /// first event: there is nothing before it to take the successor of, and
    /// the answer is the first entry itself.
    ///
    /// # The assumption, stated rather than buried
    ///
    /// A binary search over the linear index assumes `origin_server_ts`
    /// rises with it. In a room this server sequenced, it does. In a room
    /// with **backfilled** history it need not: the linear index is arrival
    /// order, and history fetched from a peer arrives now and is stamped
    /// then. Against such a room this returns *an* event near the time
    /// rather than provably the nearest.
    ///
    /// That is the same assumption the admin `state_at?ts` anchor makes and
    /// the same one Synapse makes locally -- Synapse then asks the room's
    /// other servers, which is federation work this does not do yet. The
    /// alternative locally is a scan of the whole room per request, which is
    /// the trade this declines.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room is not held here, and
    /// [`RoomError::UnknownState`] when the room has no event on that side
    /// of the timestamp.
    pub fn event_at_timestamp(
        &self,
        room_id: &str,
        ts: u64,
        direction: TimestampDirection,
    ) -> Result<(String, u64), RoomError> {
        let stamped = |event_id: String| -> Result<(String, u64), RoomError> {
            let ts = self
                .event(room_id, &event_id)
                .map(|event| event["origin_server_ts"].as_u64().unwrap_or(0))
                // A purged body cannot say when it happened. The entry is
                // still the right answer -- the caller asked which event,
                // not what it said -- so the time is reported as 0 rather
                // than the whole call failing.
                .unwrap_or(0);
            Ok((event_id, ts))
        };
        match direction {
            TimestampDirection::Backward => {
                let (_, event_id) = self.resolve_anchor(room_id, &StateAtAnchor::Ts(ts))?;
                stamped(event_id)
            }
            TimestampDirection::Forward => {
                // The last entry strictly before `ts`, then the one after
                // it. `ts - 1` rather than `ts` so an entry stamped exactly
                // `ts` is not itself the predecessor -- the forward side is
                // inclusive of an exact match.
                let before = match ts.checked_sub(1) {
                    Some(before) => self.resolve_anchor(room_id, &StateAtAnchor::Ts(before)),
                    None => Err(RoomError::UnknownState(
                        "entry at or before that time".into(),
                    )),
                };
                let after = match before {
                    Ok((li, _)) => self.with_room_read(room_id, |_, log| {
                        Ok(log
                            .entries()
                            .find(|entry| entry.li.get() > li)
                            .map(|entry| entry.event_id.as_str().to_owned()))
                    })?,
                    // Nothing before it, so the room's first entry is the
                    // first at or after -- which is also the `ts = 0` case,
                    // where there is no `ts - 1` to ask about.
                    Err(RoomError::UnknownState(_)) => self.with_room_read(room_id, |_, log| {
                        Ok(log
                            .entries()
                            .next()
                            .map(|entry| entry.event_id.as_str().to_owned()))
                    })?,
                    Err(error) => return Err(error),
                };
                let event_id = after
                    .ok_or_else(|| RoomError::UnknownState("entry at or after that time".into()))?;
                stamped(event_id)
            }
        }
    }

    /// Every room this server holds, from the stored metadata rows.
    ///
    /// A scan of the `RoomMeta` keyspace rather than the open-rooms map,
    /// for the same reason `joined` reads storage: it is correct after a
    /// restart, when nothing is open yet. The admin listing is the caller;
    /// nothing on the client-serving hot path enumerates every room.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be scanned.
    pub fn all_room_ids(&self) -> Result<Vec<String>, RoomError> {
        let prefix = [
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::RoomMeta as u8,
        ];
        let records = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?;
        let mut out = Vec::with_capacity(records.len());
        for (key, _) in records {
            // Key layout per `keys::room_prefix`: version, keyspace,
            // u16 length, then the room ID bytes.
            let Some(len) = key
                .get(2..4)
                .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            else {
                continue;
            };
            if let Some(room) = key
                .get(4..4 + len)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
            {
                out.push(room.to_owned());
            }
        }
        Ok(out)
    }

    /// The admin view of the log: entries in `li` order, either direction,
    /// paginated by an exclusive `from` boundary.
    ///
    /// Unlike `/messages` this walks storage order both ways, because the
    /// operator's question is "what does the log say" rather than "what is
    /// new" — #83's table calls it out as the query the linear index makes
    /// trivial. The returned token re-includes nothing: pass it back as
    /// `from` verbatim to continue.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its records cannot
    /// be read.
    pub fn admin_timeline(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
        forward: bool,
    ) -> Result<(Vec<AdminTimelineEntry>, Option<i64>), RoomError> {
        let (wanted, next) = self.with_room_read(room_id, |_, log| {
            let mut wanted = Vec::new();
            let mut next = None;
            let mut visit = |entry: &LogEntry| {
                if wanted.len() == limit {
                    next = Some(entry.li.get());
                    return true;
                }
                wanted.push((
                    entry.li.get(),
                    entry.event_id.as_str().to_owned(),
                    entry.chain.map(|chain| *chain.as_bytes()),
                ));
                false
            };
            if forward {
                for entry in log.entries() {
                    if from.is_some_and(|from| entry.li.get() <= from) {
                        continue;
                    }
                    if visit(entry) {
                        break;
                    }
                }
                // Continuing forward from the last returned entry means
                // "everything above it", which is that entry's own `li`.
                next = next.map(|li| li - 1);
            } else {
                for entry in log.entries().rev() {
                    if from.is_some_and(|from| entry.li.get() >= from) {
                        continue;
                    }
                    if visit(entry) {
                        break;
                    }
                }
                next = next.map(|li| li + 1);
            }
            Ok((wanted, next))
        })?;

        let watermark = self.purge_watermark(room_id)?;
        let mut out = Vec::with_capacity(wanted.len());
        for (li, event_id, chain) in wanted {
            let json = match self.read_event(room_id, &EventId::new(event_id.as_str())) {
                Ok(json) => Some(json),
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| li < mark) => None,
                Err(error) => return Err(error),
            };
            out.push(AdminTimelineEntry {
                li,
                event_id,
                chain,
                json,
            });
        }
        Ok((out, next))
    }

    /// Why an administrator blocked this room, if one did.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the row cannot be read.
    pub fn room_block(&self, room_id: &str) -> Result<Option<Value>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::room_block(room_id),
        )?
        .and_then(|raw| serde_json::from_slice(&raw).ok()))
    }

    /// Record an administrative block. The row's presence is the block;
    /// the record says who and when for the audit trail.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be written.
    pub fn set_room_block(&self, room_id: &str, record: &Value) -> Result<(), RoomError> {
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::room_block(room_id),
            serde_json::to_vec(record)
                .map_err(|error| RoomError::Codec(error.to_string()))?
                .as_slice(),
        )?;
        Ok(())
    }

    /// The first `li` NOT covered by a history purge, if one ever ran.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the row cannot be read.
    pub fn purge_watermark(&self, room_id: &str) -> Result<Option<i64>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::purge_watermark(room_id),
        )?
        .and_then(|raw| raw.get(..8).map(|bytes| bytes.try_into().unwrap_or([0; 8])))
        .map(i64::from_be_bytes))
    }

    /// Purge history before `before_li`: delete the bodies, keep the spine.
    ///
    /// What is deleted is exactly the content-bearing records — the bodies
    /// of non-state events below the cutoff. Everything else survives on
    /// purpose (#83 §3): the log entries `(li, event_id, chain)`, because
    /// `ChainHash::extend` hashes event IDs and deleting an entry would
    /// break every chain value after it; state event bodies, because
    /// current state and `state_at` must keep folding from the log; and
    /// the trie nodes, which hold event IDs, never content. The watermark
    /// is written before the deletes so a crash between them leaves
    /// below-the-mark gaps reading as "purged", never as corruption.
    ///
    /// Returns how many event bodies were actually deleted.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not exist,
    /// or [`RoomError`] if the store cannot be written.
    pub fn purge_history(&self, room_id: &str, before_li: i64) -> Result<u64, RoomError> {
        let victims = self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries()
                .take_while(|entry| entry.li.get() < before_li)
                .filter(|entry| entry.state_key.is_none())
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect::<Vec<_>>())
        })?;
        // The watermark only moves forward: a second, shallower purge must
        // not un-mark entries the first one already deleted.
        let mark = self
            .purge_watermark(room_id)?
            .map_or(before_li, |existing| existing.max(before_li));
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::purge_watermark(room_id),
            &mark.to_be_bytes(),
        )?;
        let mut purged = 0;
        for event_id in &victims {
            let key = event_body_key(room_id, event_id);
            if spindle_store::ReadView::get(self.store.as_ref(), &key)?.is_some() {
                spindle_store::Store::delete(self.store.as_ref(), &key)?;
                purged += 1;
            }
        }
        Ok(purged)
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
        self.messages_within(room_id, from, limit, None)
    }

    /// [`Self::messages`], seeing nothing above `bound`.
    ///
    /// The bound is a former member's departure: what was said while they
    /// were there is theirs to read, and what was said after is not. `None`
    /// is the whole room. Applied inside the scan rather than by trimming
    /// the page afterwards, so a page never comes back short because its
    /// newer half was cut off -- the client would read that as the end.
    ///
    /// # Errors
    ///
    /// As [`Self::messages`].
    pub fn messages_within(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
        bound: Option<i64>,
    ) -> Result<(Vec<TimelineEvent>, Option<i64>), RoomError> {
        self.messages_visible(room_id, from, limit, &|li| {
            bound.is_none_or(|bound| li <= bound)
        })
    }

    /// As [`Self::messages`], showing only the positions `visible` admits.
    ///
    /// The general form of the bound above: `joined` and `invited` history
    /// visibility admit a former member to several stretches of the room
    /// rather than one prefix of it (#268), and the predicate is what those
    /// stretches compile to. Positions refused are skipped, not stopped
    /// at, so a page walks on past a gap to the next stretch the caller
    /// may see; the `next` token is the position after the last one taken.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn messages_visible(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
        visible: &(dyn Fn(i64) -> bool + Sync),
    ) -> Result<(Vec<TimelineEvent>, Option<i64>), RoomError> {
        // Against the open log, not a fresh `load()`. Reloading rebuilt the
        // whole `RoomLog` from storage on every page, which made the one
        // endpoint SPEC §10.4 calls "a reverse range scan ... that is the
        // whole implementation" cost `O(room)` per request instead. The API
        // benchmark caught it: `/messages` grew 2.47x between a 10-event room
        // and a 500-event one, and `/sync` 4.79x, while `send` stayed flat.
        let wanted = self.with_room_read(room_id, |_, log| {
            let mut wanted = Vec::new();
            let mut next = None;
            for entry in log.entries().rev() {
                let li = entry.li.get();
                if from.is_some_and(|from| li >= from) {
                    continue;
                }
                if !visible(li) {
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
        let watermark = self.purge_watermark(room_id)?;
        let mut out = Vec::with_capacity(wanted.len());
        for (li, event_id) in wanted {
            let json = match self.read_event(room_id, &EventId::new(event_id.as_str())) {
                Ok(json) => json,
                // SPEC/#83 §3: a purged entry is a marker, not a hole —
                // the client can tell "deleted on purpose" from "never
                // existed", which is the property purge preserves.
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| li < mark) => {
                    purged_marker()
                }
                Err(error) => return Err(error),
            };
            out.push(TimelineEvent { event_id, li, json });
        }
        Ok((out, next))
    }

    /// Events in `room_id` that `matches` accepts, newest first, starting
    /// below `from`, of the positions `visible` admits: at most `limit` of
    /// them, and the position a following page starts below.
    ///
    /// This is `/search` (#7's "search basics"), and it is a walk, not an
    /// index: every body the walk passes is read and put to `matches`, so a
    /// search costs the room it searches, back to the oldest position the
    /// caller may see or until `limit` hits are in hand. The candidates are
    /// taken from the spine under the room's read lock and the bodies read
    /// outside it, as `messages_visible` does. A purged body below the
    /// watermark is not a hit (there is nothing to match), where every
    /// other missing body is the error it is.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn search(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
        visible: &(dyn Fn(i64) -> bool + Sync),
        matches: &(dyn Fn(&Value) -> bool + Sync),
    ) -> Result<(Vec<TimelineEvent>, Option<i64>), RoomError> {
        let candidates: Vec<(i64, String)> = self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries()
                .rev()
                .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                .filter(|(li, _)| from.is_none_or(|from| *li < from) && visible(*li))
                .collect())
        })?;
        let watermark = self.purge_watermark(room_id)?;
        let mut hits = Vec::new();
        for (li, event_id) in candidates {
            if hits.len() == limit {
                // This candidate is where the next page begins: `from` is
                // exclusive, so one above it.
                return Ok((hits, Some(li + 1)));
            }
            let json = match self.read_event(room_id, &EventId::new(event_id.as_str())) {
                Ok(json) => json,
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| li < mark) => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if matches(&json) {
                hits.push(TimelineEvent { event_id, li, json });
            }
        }
        Ok((hits, None))
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
        let members = self.with_room_read(room_id, |_, log| {
            Ok(current_state(log)
                .into_iter()
                .filter(|(key, _)| key.event_type().as_str() == "m.room.member")
                .map(|(key, event_id)| (key.state_key().to_owned(), event_id))
                .collect::<Vec<_>>())
        })?;
        let mut out = Map::new();
        for (user_id, event_id) in members {
            // `read_event`, not `event`: `with_room` above already proved
            // the room exists, and `event` re-proves it under the room lock
            // once per member -- 800 lock acquisitions in an 800-member
            // room, for a fact settled before the loop started.
            let event = self.read_event(room_id, &EventId::new(event_id.as_str()))?;
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
        // The count is all this needs; it used to read and parse every
        // member's body to render a name and an avatar, then keep `.len()`.
        let joined = self.joined_member_count(room_id)?;

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
            num_joined_members: joined,
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
        self.with_room_read(room_id, |_, _| Ok(()))?;
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
        // Allocated and committed together: these ids name positions on
        // side streams (to-device, receipts) that are durable by the time
        // the caller has one, so there is no window for them to be in.
        let id = self.stream.allocate();
        self.stream.commit(id);
        id
    }

    pub fn stream_position(&self) -> u64 {
        self.stream.position()
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
        crate::metrics::sync_waiter_started();
        let _ = tokio::time::timeout(timeout, notified).await;
        crate::metrics::sync_waiter_finished();
    }

    /// Everything that happened after `since`, grouped by room.
    ///
    /// `since` of `None` is an initial sync: every joined room, with its
    /// current state and a tail of its timeline. Otherwise it is a range scan
    /// of the global stream from `since`, which is the cheap case and the
    /// common one.
    ///
    /// `state_block` says how much of the state to materialize, and is
    /// answered *here*, in the read, rather than by filtering what this
    /// returns: in a large room the roster is the initial sync, and a caller
    /// that narrows afterwards has already read and parsed every member body
    /// it then discards. [`StateBlock::Deferred`] materializes nothing --
    /// the caller serves the cached render instead.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the stream or an event cannot be read.
    pub fn sync(
        &self,
        user_id: &str,
        since: Option<u64>,
        timeline_limit: usize,
        state_block: StateBlock,
    ) -> Result<SyncResult, RoomError> {
        let position = self.stream_position();
        let joined = self.joined(user_id)?;
        let invited = self.invited(user_id)?;
        let knocked = self.knocked(user_id)?;

        // The range each room is asked about. `None` on an initial sync,
        // which reads tails instead and has no range to walk.
        let range = since.map(|since| (since, position));

        let mut rooms = Vec::new();
        for room_id in joined {
            // A room joined inside the window is one the client knows only
            // from its invite, if at all, so it is told the room the way an
            // initial sync would: the tail of the timeline rather than the
            // join alone, and the state before it (#331). matrix-js-sdk
            // takes a `prev_batch` for a room it already knew only when the
            // window is `limited`, so a join sent as a one-event slice left
            // Element unable to page back to anything said before it.
            let (events, limited, prev_batch, fresh) = match range {
                None => {
                    let (events, limited, prev_batch) =
                        self.timeline_tail(&room_id, timeline_limit)?;
                    (events, limited, prev_batch, true)
                }
                Some((since, until)) => {
                    let slice = self.room_slice(&room_id, since, until)?;
                    // A join lands in the window, so a quiet room needs no
                    // lookup: `sync_cost.rs` counts reads per joined room,
                    // and this must stay flat across rooms where nothing
                    // happened.
                    let joined_at = if slice.is_empty() {
                        None
                    } else {
                        self.membership_event(&room_id, user_id)?.map(|(_, li)| li)
                    };
                    if joined_at.is_some_and(|li| slice.contains(&li)) {
                        let (events, limited, prev_batch) =
                            self.timeline_tail(&room_id, timeline_limit)?;
                        (events, limited, prev_batch, true)
                    } else {
                        let first = slice.iter().copied().min();
                        (
                            self.timeline_of(&room_id, &slice, None)?,
                            false,
                            first,
                            false,
                        )
                    }
                }
            };
            // An incremental sync says nothing about a room where nothing
            // happened. A client diffing rooms it was sent against rooms it
            // knows would otherwise see an empty timeline as a change.
            if since.is_some() && events.is_empty() {
                continue;
            }
            rooms.push(SyncRoom {
                room_id: room_id.clone(),
                // State only when the client is meeting the room: on an
                // initial sync, or on the sync that joins it. Otherwise the
                // state events are in the timeline already, and sending them
                // twice would make a client apply each one twice.
                state: if fresh {
                    self.initial_state(&room_id, user_id, state_block, &events)?
                } else {
                    Vec::new()
                },
                events,
                limited,
                prev_batch,
            });
        }

        let left = self.left_rooms(user_id, since, range)?;

        // How stale was the freshest thing we just handed over? A client
        // keeping up sees milliseconds; a server falling behind sees this
        // climb, which is the symptom #19's exit criteria ask to alert
        // on. Only when something was delivered — an empty sync is a
        // client that is up to date, not a lagging one, and counting it
        // as zero would flatten the average that matters.
        if let Some(newest) = rooms
            .iter()
            .flat_map(|room| room.events.iter())
            .filter_map(|event| event["origin_server_ts"].as_u64())
            .max()
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since_epoch| {
                    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
                });
            crate::metrics::observe_sync_lag(std::time::Duration::from_millis(
                now.saturating_sub(newest),
            ));
        }

        Ok(SyncResult {
            next_batch: position,
            rooms,
            invited,
            knocked,
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

    /// Rooms this user has knocked on and not yet been answered about.
    ///
    /// Its own section rather than folded into the invited ones: an invite is
    /// something to accept or decline, a knock is something to wait on, and a
    /// client that showed them together would offer a button for a room that
    /// has not agreed to let anyone in.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the membership index cannot be scanned.
    pub fn knocked(&self, user_id: &str) -> Result<Vec<String>, RoomError> {
        self.membership_rooms(user_id, KNOCK)
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
        range: Option<(u64, u64)>,
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
                let (events, prev_batch) = match range {
                    None => (vec![departure], Some(departed_at)),
                    Some((since, until)) => {
                        let slice = self.room_slice(&room_id, since, until)?;
                        let first = slice.iter().copied().min();
                        (
                            self.timeline_of(&room_id, &slice, Some(departed_at))?,
                            first,
                        )
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
                    prev_batch,
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
        // One lookup, under one lock. This walked every state key in the
        // room to find one, then took the room lock a second time to read
        // that entry's position -- on a path `unread` runs for every room
        // on every sync, which made each sync scale with the member list.
        let found = self.with_room_read(room_id, |_, log| {
            let Some(event_id) = current_state_id(log, &wanted) else {
                return Ok(None);
            };
            let li = log
                .get(&EventId::new(event_id.as_str()))
                .map(|entry| entry.li.get());
            Ok(li.map(|li| (event_id, li)))
        })?;
        let Some((event_id, li)) = found else {
            return Ok(None);
        };
        Ok(Some((self.event(room_id, &event_id)?, li)))
    }

    /// The stretches of `room_id` during which `user_id` could see it:
    /// `(first, last)` positions, inclusive, one per stint. A stint opens at
    /// the join (or, with `from_invite`, the invite) and closes at the
    /// event that ended it, which the member themselves may still see; a
    /// stint still open closes at `i64::MAX`.
    ///
    /// This is what `joined` and `invited` history visibility mean: the
    /// caller's membership *as of each event*, which for someone who
    /// joined, left and joined again is several intervals, not one bound.
    ///
    /// Read from the membership-history index. A room that predates the
    /// index has no rows for its earlier members, so a user with a member
    /// event and no history is backfilled once, by the whole-room walk the
    /// index exists to avoid, and never again.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index or the room cannot be read.
    pub fn membership_intervals(
        &self,
        room_id: &str,
        user_id: &str,
        from_invite: bool,
    ) -> Result<Vec<(i64, i64)>, RoomError> {
        let mut rows = self.member_history(room_id, user_id)?;
        if rows.is_empty() && self.membership_event(room_id, user_id)?.is_some() {
            self.backfill_member_history(room_id, user_id)?;
            rows = self.member_history(room_id, user_id)?;
        }
        let mut intervals = Vec::new();
        let mut open: Option<i64> = None;
        for (li, membership) in rows {
            let inside = membership == JOIN_STR || (from_invite && membership == INVITE_STR);
            match (inside, open) {
                (true, None) => open = Some(li),
                (false, Some(start)) => {
                    intervals.push((start, li));
                    open = None;
                }
                _ => {}
            }
        }
        if let Some(start) = open {
            intervals.push((start, i64::MAX));
        }
        Ok(intervals)
    }

    /// `(li, membership)` for every member event of `user_id` in `room_id`
    /// the index holds, oldest first.
    fn member_history(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<Vec<(i64, String)>, RoomError> {
        let prefix = spindle_core::keys::member_history_prefix(user_id, room_id);
        let rows = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?;
        Ok(rows
            .into_iter()
            .filter_map(|(key, value)| {
                let li = spindle_core::keys::member_history_li(user_id, room_id, &key)?;
                Some((li, String::from_utf8_lossy(&value).into_owned()))
            })
            .collect())
    }

    /// Fill the membership-history index for one user in one room from the
    /// log itself. One whole-room walk, for a room older than the index.
    fn backfill_member_history(&self, room_id: &str, user_id: &str) -> Result<(), RoomError> {
        let ids: Vec<(i64, String)> = self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries()
                .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                .collect())
        })?;
        for (li, event_id) in ids {
            let Ok(event) = self.read_event(room_id, &EventId::new(event_id.as_str())) else {
                continue; // purged: its membership, if any, is beyond recovering
            };
            if event["type"] != "m.room.member" || event["state_key"] != user_id {
                continue;
            }
            if let Some(membership) = event["content"]["membership"].as_str() {
                spindle_store::Store::put(
                    self.store.as_ref(),
                    &spindle_core::keys::member_history(user_id, room_id, li),
                    membership.as_bytes(),
                )?;
            }
        }
        Ok(())
    }

    /// Where `user_id` left `room_id`, if they are a former member.
    ///
    /// `Some(li)` is the position of the event that removed them -- their
    /// own leave, a kick, or a ban -- and is the upper bound on what they
    /// may still read. `None` for anyone else: a current member reads the
    /// whole room by another rule, and someone who was never in it reads
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its state cannot be read.
    pub fn departure(&self, room_id: &str, user_id: &str) -> Result<Option<i64>, RoomError> {
        let Some((event, li)) = self.membership_event(room_id, user_id)? else {
            return Ok(None);
        };
        let departed = matches!(
            event["content"]["membership"].as_str(),
            Some("leave" | "ban")
        );
        Ok(departed.then_some(li))
    }

    /// The room's `history_visibility` as it stood at position `li`.
    ///
    /// Read from the state at that point rather than from the current
    /// state, because that is what governs what a former member may see:
    /// a room that tightened its visibility after they left does not take
    /// back what they were entitled to, and one that relaxed it does not
    /// hand them what they were not. Absent means `shared`, per the spec.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or the state at `li` cannot be read.
    pub fn history_visibility_at(&self, room_id: &str, li: i64) -> Result<String, RoomError> {
        let root = self.with_room_read(room_id, |_, log| {
            Ok(log.entry_at_or_before(li).map(|entry| entry.state_root))
        })?;
        let Some(root) = root else {
            return Ok("shared".to_owned());
        };
        let visibility = self
            .state_at(room_id, root)?
            .into_iter()
            .find(|event| event["type"] == "m.room.history_visibility" && event["state_key"] == "")
            .and_then(|event| {
                event["content"]["history_visibility"]
                    .as_str()
                    .map(str::to_owned)
            });
        Ok(visibility.unwrap_or_else(|| "shared".to_owned()))
    }

    /// The room's full state as it stood at position `li`: every state
    /// event in force after the entry at or before `li` was applied, whole,
    /// with its `event_id`.
    ///
    /// What a former member sees on `/state`: the room as it was when the
    /// event that removed them landed, not the room as it is now (#268).
    /// A position before the room's first entry is an empty room.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::Build`] if the snapshot cannot be rebuilt.
    pub fn state_as_of(&self, room_id: &str, li: i64) -> Result<Vec<Value>, RoomError> {
        let root = self.with_room_read(room_id, |_, log| {
            Ok(log.entry_at_or_before(li).map(|entry| entry.state_root))
        })?;
        let Some(root) = root else {
            return Ok(Vec::new());
        };
        self.state_at(room_id, root)
    }

    /// One state event's content as it stood at position `li`, the
    /// as-of sibling of [`Self::state_event`].
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownState`] when the room had no such state
    /// at that position -- the same answer [`Self::state_event`] gives for
    /// the present, for the same reason.
    pub fn state_event_as_of(
        &self,
        room_id: &str,
        li: i64,
        event_type: &str,
        state_key: &str,
    ) -> Result<Value, RoomError> {
        self.state_as_of(room_id, li)?
            .into_iter()
            .find(|event| event["type"] == event_type && event["state_key"] == state_key)
            .map(|event| {
                event
                    .get("content")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
            })
            .ok_or_else(|| {
                RoomError::UnknownState(format!("{event_type} with state key {state_key:?}"))
            })
    }

    /// The linear position of an event in a room, if the room holds it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn event_position(&self, room_id: &str, event_id: &str) -> Result<Option<i64>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log.get(&EventId::new(event_id)).map(|entry| entry.li.get()))
        })
    }

    /// The newest `limit` events of a room, oldest first.
    /// The newest `limit` events of `room_id` in order, whether older ones
    /// were left out, and the position of the oldest one sent (the window's
    /// `prev_batch`; `None` for an empty room).
    fn timeline_tail(
        &self,
        room_id: &str,
        limit: usize,
    ) -> Result<(Vec<Value>, bool, Option<i64>), RoomError> {
        let (events, more) = self.messages(room_id, None, limit)?;
        // Newest first, so the last one is where the window begins.
        let first = events.last().map(|event| event.li);
        let mut out: Vec<Value> = events
            .into_iter()
            .map(|event| stamp(event.json, &event.event_id))
            .collect();
        out.reverse();
        Ok((out, more.is_some(), first))
    }

    /// Where one room's events sit in its own order, for everything it
    /// contributed to the stream range `(since, until]`.
    ///
    /// **The cost is this room's traffic, not the server's.** The stream is a
    /// server-wide order, so answering from it meant reading every event
    /// anyone sent anywhere since the token and keeping the few that were
    /// this room's: a user in one quiet room paid for strangers talking, and
    /// `tests/sync_cost.rs` measured that as one point read per foreign event
    /// on every incremental sync. The reverse index
    /// ([`Keyspace::RoomStream`](spindle_core::keys::Keyspace::RoomStream))
    /// puts the room first in the key, so the same question is a scan that
    /// starts at the client's token and ends at the room's newest event.
    ///
    /// An earlier fix made this one pass per *sync* rather than one per room;
    /// this makes each pass proportional to what the room did. Both were
    /// needed, and neither subsumes the other.
    fn room_slice(&self, room_id: &str, since: u64, until: u64) -> Result<Vec<i64>, RoomError> {
        if until <= since {
            return Ok(Vec::new());
        }
        let rows = spindle_store::ReadView::scan_from(
            self.store.as_ref(),
            &spindle_core::keys::room_stream_prefix(room_id),
            &spindle_core::keys::room_stream(room_id, since + 1),
        )?;
        let mut out = Vec::with_capacity(rows.len());
        for (key, raw) in rows {
            // The scan runs to the end of the room's rows, so it can see an
            // append that landed after `until` was read -- or one whose id
            // is above the watermark because a lower id is still in flight.
            // Either is outside what this sync may answer with: the token
            // the client gets back is `until`, so an event past it is
            // delivered now and delivered again on the next sync. This is
            // the read side of the watermark, and the reason `until` is a
            // parameter rather than "everything the room has".
            if spindle_core::keys::room_stream_from_key(&key).is_some_and(|id| id > until) {
                break;
            }
            if let Ok(bytes) = <[u8; 8]>::try_from(raw.as_slice()) {
                out.push(i64::from_be_bytes(bytes));
            }
        }
        Ok(out)
    }

    /// The events a room contributed to a stream range, as bodies.
    ///
    /// Takes the room's own indices rather than finding them, so the caller
    /// pays for the stream range once -- see [`Self::stream_slice`].
    fn timeline_of(
        &self,
        room_id: &str,
        indices: &[i64],
        max_li: Option<i64>,
    ) -> Result<Vec<Value>, RoomError> {
        let mut out = Vec::new();
        for &li in indices {
            if max_li.is_some_and(|max| li > max) {
                continue;
            }
            // `entry_at` rather than a scan of `entries()`: the log is a
            // BTreeMap, and searching it linearly here made the read
            // quadratic in the room's length on a path that runs per event.
            let event_id = self.with_room_read(room_id, |_, log| {
                Ok(log
                    .entry_at(li)
                    .map(|entry| entry.event_id.as_str().to_owned()))
            })?;
            if let Some(event_id) = event_id {
                out.push(self.event(room_id, &event_id)?);
            }
        }
        Ok(out)
    }

    /// Events that entered the global stream in `(since, until]`, in
    /// stream order, each paired with the room it belongs to.
    ///
    /// `limit` caps the number of events returned; the second half of the
    /// result is the stream position the scan actually reached — `until`
    /// unless the cap cut the range short. Built for the appservice
    /// transaction push, whose cursor must advance to exactly the position
    /// its delivered batch covers: advancing to `until` past an uncut scan
    /// and to the cut point past a cut one is what keeps a capped batch
    /// from silently skipping the remainder.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the stream or an event cannot be read.
    pub fn stream_events(
        &self,
        since: u64,
        until: u64,
        limit: usize,
    ) -> Result<(Vec<(String, Value)>, u64), RoomError> {
        let mut out = Vec::new();
        let mut reached = until;
        for stream_id in (since + 1)..=until {
            if out.len() >= limit {
                reached = stream_id - 1;
                break;
            }
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
            let event_id = self.with_room(&record.room_id, |_, log| {
                Ok(log
                    .entries()
                    .find(|entry| entry.li.get() == record.li)
                    .map(|entry| entry.event_id.as_str().to_owned()))
            })?;
            if let Some(event_id) = event_id {
                let event = self.event(&record.room_id, &event_id)?;
                out.push((record.room_id, event));
            }
        }
        Ok((out, reached))
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
    /// "Participated" is the spec's definition, which the `/threads`
    /// endpoint states outright and this aggregate only implies: the viewer
    /// sent an event in the thread, **or** sent the thread root itself. The
    /// root's sender costs a read the replies do not, so it is only consulted
    /// when the replies have not already settled the question.
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
            // A purged child cannot contribute to an aggregate — its
            // content is gone, so counting or previewing it would invent
            // what was deleted. Skipped, not an error.
            let event = match self.event(room_id, &event_id) {
                Ok(event) => event,
                Err(RoomError::MissingBody(_)) => continue,
                Err(error) => return Err(error),
            };
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
            // Starting a thread is participating in it. Checked last and only
            // when no reply has already answered it, so the common case pays
            // nothing: a thread the viewer is in is settled by the replies.
            if !viewer_in_thread {
                viewer_in_thread = match self.event(room_id, target) {
                    Ok(root) => root["sender"].as_str() == Some(viewer),
                    // A root whose body is gone cannot name its sender. Not
                    // participating is the answer that shows the viewer less,
                    // which is the right way to be wrong here.
                    Err(RoomError::MissingBody(_)) => false,
                    Err(error) => return Err(error),
                };
            }
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
        let head = self.with_room_read(room_id, |_, log| {
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

    /// Which of `rooms` had at least one event in the stream range
    /// `(since, until]`.
    ///
    /// Asked about a named set rather than answered for the whole server:
    /// incremental sliding sync wants to stay silent about rooms where
    /// nothing happened, and it already knows which rooms it might speak
    /// about -- the windows it is serving and the subscriptions it was
    /// handed. Scanning the server's whole stream to find out made the
    /// answer cost other people's traffic, and then threw away every room
    /// the caller was never going to mention.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn changed_rooms<'a>(
        &self,
        rooms: impl IntoIterator<Item = &'a str>,
        since: u64,
        until: u64,
    ) -> Result<HashSet<String>, RoomError> {
        let mut changed = HashSet::new();
        for room_id in rooms {
            if !self.room_slice(room_id, since, until)?.is_empty() {
                changed.insert(room_id.to_owned());
            }
        }
        Ok(changed)
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
    ) -> Result<(Vec<Value>, bool, Option<i64>), RoomError> {
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

    /// Run `work` against a room's log, holding the room lock -- and fsync
    /// **after** letting it go.
    ///
    /// The lock is what orders appends, and ordering is memory work measured
    /// in microseconds. An fsync is a disk barrier measured in hundreds of
    /// them, and while it was inside this critical section it was the whole
    /// server's write ceiling: every append everywhere queued behind the
    /// slowest thing the machine does. Measured before this change, sends
    /// per second were flat from one client to eight
    /// (`tests/probe.rs`) and no two commits ever overlapped, so the group
    /// commit under them had nothing to coalesce.
    ///
    /// **Ordering is unchanged.** The bytes still reach the journal in lock
    /// order; only the barrier moved out. So the `stream` counter's
    /// watermark-equals-counter equivalence still holds, which is the
    /// property a per-room executor would break and this deliberately does
    /// not.
    ///
    /// Whether to sync is decided by the store's journal counter rather than
    /// by remembering: a missed sync is silent data loss, and a rule of the
    /// form "call this after the appending paths" is a rule someone will
    /// eventually not follow. A reading that moved because *another* thread
    /// wrote costs one extra sync; a reading that moved because this one did
    /// can never be missed.
    ///
    /// The cost is that an event is visible to readers for up to one fsync
    /// before it is durable. SPEC §8.3 already permits a crash to lose a
    /// suffix of the log; this widens that window to one sync, and no client
    /// is told the write happened until the sync below returns.
    /// Make sure a room's log is resident, loading it if not.
    ///
    /// Split out so the read path can check residency under a *read* lock
    /// and only reach for the write lock on the miss.
    /// The lock for one room, loading it if this process has not opened it.
    ///
    /// **The registry lock is held only long enough to clone an `Arc`.** That
    /// is the whole change: the map says which rooms exist, and holding it
    /// across an append made every append in the server queue behind every
    /// other one, in rooms they had nothing to do with. Now the map is a
    /// lookup and the *room* is the thing contended.
    ///
    /// The miss path takes the registry exclusively and re-checks, because
    /// two requests for the same cold room would otherwise both load it and
    /// the second would replace the first -- handing two callers different
    /// locks for one room, which is the same as no lock at all.
    fn room(&self, room_id: &str) -> Result<Arc<RwLock<RoomLog>>, RoomError> {
        {
            crate::metrics::record_registry_lock(false);
            let open = self
                .open
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(room) = open.get(room_id) {
                return Ok(Arc::clone(room));
            }
        }
        crate::metrics::record_registry_lock(true);
        let mut open = self
            .open
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(room) = open.get(room_id) {
            return Ok(Arc::clone(room));
        }
        let restored = RoomStore::new(self.store.as_ref(), room_id)
            .load()?
            .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
        let room = Arc::new(RwLock::new(restored.log));
        open.insert(room_id.to_owned(), Arc::clone(&room));
        Ok(room)
    }

    /// [`Self::with_room`] for work that only *reads* the log.
    ///
    /// Takes the room's lock shared, so concurrent readers of one room
    /// proceed together -- and readers of *different* rooms never meet at
    /// all, because the registry is released before the room is taken.
    ///
    /// Which calls belong here is decided by the compiler, not by judgement:
    /// `work` gets `&RoomLog`, so anything that mutates the log fails to
    /// build and stays on [`Self::with_room`].
    fn with_room_read<T>(
        &self,
        room_id: &str,
        work: impl FnOnce(&Self, &RoomLog) -> Result<T, RoomError>,
    ) -> Result<T, RoomError> {
        let room = self.room(room_id)?;
        crate::metrics::record_room_lock(false);
        let log = room
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        work(self, &log)
    }

    fn with_room<T>(
        &self,
        room_id: &str,
        work: impl FnOnce(&Self, &mut RoomLog) -> Result<T, RoomError>,
    ) -> Result<T, RoomError> {
        let before = self.store.journalled();
        let room = self.room(room_id)?;
        let done = {
            crate::metrics::record_room_lock(true);
            let mut log = room
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            work(self, &mut log)
        };
        // The guard is gone by here, so the barrier below is not holding
        // anyone up. Ordered before `?` on `done`: a failed `work` may still
        // have journalled -- a partial append is exactly what must not be
        // left unsynced and then reported as an error.
        if self.store.journalled() != before {
            spindle_store::Store::sync(self.store.as_ref(), Durability::Group)?;
        }
        done
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

        let auth = auth_events_for(
            log,
            &self.rules_in(log, room_id)?.authorization,
            sender,
            event_type,
            state_key,
            content,
        )?;
        // MSC4291: the create event of a room whose ID is that event's
        // hash cannot name the ID, so it is built without one. `create`
        // has already derived the same ID from the same bytes.
        let names_room_id = !(event_type == "m.room.create" && derives_room_id(content));
        let canonical = build_canonical(
            names_room_id.then_some(room_id),
            sender,
            event_type,
            state_key,
            content,
            &prev,
            &auth,
            depth,
        )?;
        // Sign under the room's own version, not this build's default.
        // Event IDs are version-dependent, so signing a v12 room's event
        // under v11 rules mints an ID the rest of that room will not
        // recognise -- the same class of mistake `make_join` made when it
        // answered "this room is version 11" about a room it had never
        // read (#201). The create event is the exception, for the reason
        // `authorize` gives: it is the event that establishes the version,
        // so its own content is the only place the answer exists yet.
        let version = if event_type == "m.room.create" {
            version_in(content)?
        } else {
            self.version_in_log(log, room_id)?
        };
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
        self.commit_event(
            log, room_id, sender, event_type, state_key, content, &event_id, &json,
        )
    }

    /// Put an already-built, already-authorized event into the log and the
    /// store.
    ///
    /// Split out of [`Self::append`] because the v12 create event cannot be
    /// built by it: the room ID is that event's hash, so the event must be
    /// signed *before* there is a room to append it to. Rebuilding it once
    /// the ID is known does not work -- `origin_server_ts` moves between
    /// the two builds, so the second event hashes differently and the room
    /// ID stops matching the create event it was derived from. (A test
    /// caught exactly that; the two IDs agreed only when both builds landed
    /// in the same millisecond.)
    #[allow(clippy::too_many_arguments, reason = "one event, in one place")]
    fn commit_event(
        &self,
        log: &mut RoomLog,
        room_id: &str,
        sender: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
        event_id: &str,
        json: &Value,
    ) -> Result<String, RoomError> {
        let event_id = event_id.to_owned();
        let json = json.clone();
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
            .map_err(|error| {
                // §9.2 case 3: the key is contested inside the window, so
                // this append needs the resolver. Counted where the
                // decision is made (#166), whether it is then resolved or
                // — as today — refused.
                if let spindle_core::AppendError::NeedsStateResolution { key, .. } = &error {
                    crate::metrics::record_contested_state(crate::metrics::Origin::Local);
                    return RoomError::Contested {
                        // The `type/state_key` spelling `/state_ids` uses,
                        // so an operator can match this against what the
                        // room actually reports holding.
                        key: format!("{}/{}", key.event_type().as_str(), key.state_key()),
                    };
                }
                RoomError::Append(format!("{error:?}"))
            })?
            .clone();
        crate::metrics::record_append(crate::metrics::Origin::Local, case_of(state_key.is_some()));

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
        let live = self.destinations_in(log, room_id)?;

        // A membership event still goes to the domain it is *about*, live
        // or not: the kick is the one event the removed server must hear,
        // and by this point the membership index already says "leave" — the
        // liveness rule would skip exactly the notification that matters.
        //
        // Kept outside the cached set deliberately. It is a property of
        // *this event*, not of the room's state, so caching it would send
        // every later message to a server that has left.
        let departing = json["state_key"]
            .as_str()
            .filter(|_| json["type"].as_str() == Some("m.room.member"))
            .and_then(|user| user.split_once(':'))
            .map(|(_, domain)| domain)
            .filter(|domain| *domain != self.server_name)
            .filter(|domain| !live.iter().any(|known| known == *domain));

        for destination in live.iter().map(String::as_str).chain(departing) {
            let seq = self.allocate_stream_id();
            spindle_store::Store::put(
                self.store.as_ref(),
                &spindle_core::keys::federation_outbox(destination, seq),
                json.to_string().as_bytes(),
            )?;
        }
        Ok(())
    }

    /// Every remote domain with a live member, from a log the caller holds.
    ///
    /// Domains come from member state keys; liveness from the membership
    /// index — a point read per member, no body parses. That per-member read
    /// is why the answer is cached against the state root: it ran on every
    /// append, so an N-member room paid N reads to send one message.
    ///
    /// Takes the log rather than reaching for it, because [`Self::append`]
    /// calls this from inside [`Self::with_room`] and the `open` lock is not
    /// reentrant. Same rule as [`Self::rules_in`], and the same deadlock if
    /// it is broken.
    fn destinations_in(&self, log: &RoomLog, room_id: &str) -> Result<Arc<Vec<String>>, RoomError> {
        let Some(state) = log
            .entries()
            .next_back()
            .map(|entry| entry.li)
            .and_then(|li| log.state_after(li))
        else {
            return Ok(Arc::new(Vec::new()));
        };
        let root = *state.root().as_bytes();
        if let Some((cached, domains)) = self
            .destinations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
            && *cached == root
        {
            return Ok(Arc::clone(domains));
        }

        let mut members = Vec::new();
        state.for_each(|state_key, _| {
            if state_key.event_type().as_str() == "m.room.member" {
                members.push(state_key.state_key().to_owned());
            }
        });
        let mut domains = std::collections::BTreeSet::new();
        for user_id in members {
            let Some((_, domain)) = user_id.split_once(':') else {
                continue;
            };
            if domain == self.server_name || domains.contains(domain) {
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
                domains.insert(domain.to_owned());
            }
        }
        let domains = Arc::new(domains.into_iter().collect::<Vec<_>>());
        self.destinations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), (root, Arc::clone(&domains)));
        Ok(domains)
    }

    /// Every remote domain with a live member in the room — the EDU
    /// audience, same liveness rule as event fan-out.
    ///
    /// Literally the same rule now. This and the fan-out in
    /// [`Self::enqueue_outbound`] were two copies of one computation, which
    /// is how one liveness rule becomes two that disagree. Both go through
    /// [`Self::destinations_in`], and so share its cache.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or membership rows cannot be read.
    pub fn remote_domains(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        let domains = self.with_room(room_id, |rooms, log| rooms.destinations_in(log, room_id))?;
        Ok(domains.as_ref().clone())
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
        let ids = match self.with_room_read(room_id, |_, log| {
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
            .write()
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
            room_store.journal_entry_with(&entry, &log, &extra)?;
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
            let li = log
                .get(&EventId::new(id.as_str()))
                .map_or(0, |entry| entry.li.get());
            self.index_membership(room_id, Some(&user), &event["content"], li)?;
        }

        open.insert(room_id.to_owned(), Arc::new(RwLock::new(log)));
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
            .map_err(|error| {
                if let spindle_core::AppendError::NeedsStateResolution { key, .. } = &error {
                    crate::metrics::record_contested_state(crate::metrics::Origin::Federated);
                    return RoomError::Contested {
                        // The `type/state_key` spelling `/state_ids` uses,
                        // so an operator can match this against what the
                        // room actually reports holding.
                        key: format!("{}/{}", key.event_type().as_str(), key.state_key()),
                    };
                }
                RoomError::Append(format!("{error:?}"))
            })?
            .clone();
        crate::metrics::record_append(
            crate::metrics::Origin::Federated,
            case_of(state_key.is_some()),
        );

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
        let stream_id = self.stream.allocate();
        extra.push((
            spindle_core::keys::stream(stream_id),
            StreamRecord {
                room_id: room_id.to_owned(),
                li: entry.li.get(),
            }
            .encode(),
        ));
        // The same fact keyed the other way round, in the same batch. Two
        // rows that must always agree are written by one commit or by
        // neither: an index row without its forward row would answer a sync
        // with an event the stream does not have, and a forward row without
        // its index row would hide the event from every client whose token
        // predates it.
        extra.push((
            spindle_core::keys::room_stream(room_id, stream_id),
            entry.li.get().to_be_bytes().to_vec(),
        ));
        // Timed here rather than around the whole handler: this is the
        // commit SPEC §18.3's local-send target is about, and wrapping
        // the handler would fold request parsing and authorization into
        // a number the target does not describe.
        let started = std::time::Instant::now();
        let landed = room_store.journal_entry_with(entry, log, &extra);
        // The id is released on *both* outcomes, before the `?`. An
        // allocated id that is never resolved holds the watermark forever,
        // which does not lose this event -- it makes every later event
        // invisible to every client.
        match &landed {
            Ok(()) => self.stream.commit(stream_id),
            Err(_) => self.stream.abandon(stream_id),
        }
        landed?;
        crate::metrics::observe_append("group", started.elapsed());

        // The index is derived from the event that just landed, and only from
        // an event that landed: writing it before the commit would leave a
        // user joined to a room whose membership event was never stored.
        if input.event_type == "m.room.member" {
            self.index_membership(room_id, input.state_key, input.content, entry.li.get())?;
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
        li: i64,
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
        // And the same fact filed by position, so that "what was this
        // user's membership as of that event" is a prefix scan rather than
        // a walk of the room (#268).
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::member_history(user_id, room_id, li),
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
        let candidate = StoredEvent::parse_in(event_id, room_id, json).map_err(|error| {
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
            StoredEvent::parse_in(id, room_id, &body).ok()
        };

        // Per-room, for the same reason as redaction above and with more at
        // stake: the authorization rules decide what this server accepts.
        // Judging another version's event by v11's rules is how a server
        // admits an event that version would have refused.
        //
        // The create event is its own exception, and has to be: it is the
        // event that *establishes* the version, so at the moment it is
        // authorized there is no create event in state to read one from.
        // Its own content is the only place the answer exists.
        let rules = if json["type"] == "m.room.create" {
            rules_of(&version_in(&json["content"])?)?
        } else {
            // `rules_in`, not `rules`: this runs inside `with_room`, and the
            // lock is not reentrant. See the note on `rules_in`.
            self.rules_in(log, room_id)?
        };
        crate::authorize::authorize(
            &rules.authorization,
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

/// The event id one state key currently points at.
///
/// The trie is a map, so this is a lookup in it -- not a walk of every key
/// to find one. The difference does not show in a small room and is the
/// whole cost in a large one: every auth check, every power-level read and
/// every sliding-sync `required_state` entry asks this question, and asking
/// it by materialising the room's entire state made each of them scale with
/// the member list.
/// The room version named by an `m.room.create` event's content.
///
/// Absent means v1, per the spec. That is not defensive padding: a room
/// federated from a server old enough to omit the field genuinely *is* v1,
/// and substituting our own default there would apply the wrong rules to
/// someone else's room.
/// Whether a create event with this content names a room whose ID is its
/// own hash (MSC4291).
///
/// Answered from the content rather than from a version list, because this
/// is asked while building the create event -- before the room exists, and
/// therefore before anything else could be asked.
fn derives_room_id(create_content: &Value) -> bool {
    version_in(create_content)
        .ok()
        .and_then(|version| version.rules())
        .is_some_and(|rules| rules.authorization.room_create_event_id_as_room_id)
}

fn version_in(content: &Value) -> Result<RoomVersionId, RoomError> {
    let named = content
        .get("room_version")
        .and_then(Value::as_str)
        .unwrap_or("1");
    RoomVersionId::try_from(named)
        .map_err(|error| RoomError::Build(format!("unknown room version: {error}")))
}

/// The rule set a version selects, refusing rather than guessing.
///
/// A version `ruma` has no rules for is an error and not a fallback: running
/// an unknown version's events through a known version's rules is how a
/// server accepts something it should have rejected.
fn rules_of(version: &RoomVersionId) -> Result<RoomVersionRules, RoomError> {
    version
        .rules()
        .ok_or_else(|| RoomError::Build(format!("no rules for room version {version}")))
}

fn current_state_id(log: &RoomLog, wanted: &StateKey) -> Option<String> {
    log.entries()
        .next_back()
        .map(|entry| entry.li)
        .and_then(|li| log.state_after(li))
        .and_then(|state| state.get(wanted).map(str::to_owned))
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

/// Which of SPEC §9.2's cheap cases an append took.
///
/// Case 3 is never returned here: a contested key does not reach a
/// successful append, so it is counted at the error instead.
fn case_of(is_state: bool) -> crate::metrics::ForkCase {
    if is_state {
        crate::metrics::ForkCase::StateUncontested
    } else {
        crate::metrics::ForkCase::NonState
    }
}

/// The event-shaped marker a purged entry renders as in a timeline.
///
/// The `event_id` is stamped on by the caller like any other timeline
/// event — it is the one thing the purge kept. Everything content-bearing
/// is honestly absent, and the type is unmistakably not a real event, so
/// clients that do not know it render nothing rather than something wrong.
fn purged_marker() -> Value {
    serde_json::json!({
        "type": "org.spindle.purged",
        "content": {},
    })
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
/// Client-supplied member content, with the one field a client may not set.
///
/// `join_authorised_via_users_server` is this server's claim that it saw the
/// joiner in a room this one admits (MSC3083). It is not a claim a client
/// can make, and a client that makes it anyway does real damage: the field
/// is inside the signed event, so every server that receives it asks for a
/// signature from the named user's server. A value that is not a user ID
/// cannot even be asked about -- `verify_event` fails to parse it and the
/// event is refused by every peer, while the sending server, which never
/// verifies its own events, sees nothing wrong.
///
/// That is not hypothetical. Complement sends exactly `"unused"` here on a
/// join -> join transition to check it is ignored, and the resulting member
/// event was refused by the far side, taking the *next* event in the same
/// transaction with it -- `UnknownPredecessor` -- so a later leave never
/// applied and the two servers disagreed about a membership from then on.
///
/// Synapse strips it unconditionally on the client path for this reason
/// ("it won't be properly signed... there should be no reason for a client
/// to include it"); Continuwuity clears it on a join -> join transition and
/// refuses it elsewhere. Stripping is the same answer with a shorter
/// argument: the only thing that may write this field is
/// [`Rooms::restricted_join_nominee`].
fn sanitized_member_content(event_type: &str, content: &Value) -> Value {
    if event_type != "m.room.member" {
        return content.clone();
    }
    let mut content = content.clone();
    if let Some(object) = content.as_object_mut() {
        object.remove("join_authorised_via_users_server");
    }
    content
}

fn auth_events_for(
    log: &RoomLog,
    rules: &ruma::room_version_rules::AuthorizationRules,
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
        // The one selection that reads the event's *content* rather than only
        // its type and target: a restricted join names the member who vouched
        // for it, and the rules cannot check that nomination without their
        // member event. The version gate is ruma's own -- a room version with
        // no restricted join rule has no such member to cite, and citing one
        // anyway is a longer list than the peer selects.
        if (rules.restricted_join_rule || rules.knock_restricted_join_rule)
            && let Some(nominee) = content["join_authorised_via_users_server"].as_str()
        {
            cite("m.room.member", nominee);
        }
    }
    Ok(auth)
}

#[allow(clippy::too_many_arguments, reason = "an event is what it is")]
fn build_canonical(
    room_id: Option<&str>,
    sender: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
    prev_events: &[String],
    auth_events: &[String],
    depth: u64,
) -> Result<CanonicalJsonObject, RoomError> {
    let mut object = CanonicalJsonObject::new();
    // MSC4291: a v12 create event carries no `room_id`, because the room's
    // ID *is* that event's hash -- naming it inside the event it is
    // computed from would be circular. Every other event, in every
    // version, still carries it.
    if let Some(room_id) = room_id {
        object.insert(
            "room_id".to_owned(),
            CanonicalJsonValue::String(room_id.to_owned()),
        );
    }
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
    let mut bytes = [0_u8; 9];
    crate::secrets::fill(&mut bytes);
    bytes
        .iter()
        .map(|byte| char::from(b'A' + (byte % 26)))
        .collect()
}

/// Why a room operation failed.
#[derive(Debug)]
pub enum RoomError {
    /// A room version this server does not advertise. Distinct from
    /// [`RoomError::Build`]'s "no rules for this version": `ruma` may
    /// know a version perfectly well while this server still declines to
    /// create rooms at it, because nothing here has been exercised
    /// against one.
    UnsupportedVersion(String),
    UnknownRoom(String),
    MissingBody(String),
    Build(String),
    Append(String),
    /// SPEC §9.2 case 3: two branches of a fork moved the same state key
    /// away from the value they both inherited, so the merge needs the
    /// room-version resolver that is not yet wired into ingest (#16).
    ///
    /// Distinct from [`RoomError::Append`] because it is the one append
    /// failure that is neither the caller's fault nor a bug: the room is in
    /// a state this server cannot currently fold, and #225 recorded that
    /// answering it with a bare 500 tells a client nothing it can act on
    /// and an operator nothing they can diagnose.
    Contested {
        key: String,
    },
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
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "this server does not support room version {version}"
                )
            }
            Self::Contested { key } => write!(
                formatter,
                "the state key {key} is contested between two branches of a                  fork and needs state resolution"
            ),
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

/// The highest id in the forward stream index, or 0 for a fresh store.
///
/// A prefix scan rather than a stored high-water mark: one number that has to
/// be kept in step with the rows it describes is one number that can disagree
/// with them, and the rows are the truth.
fn highest_stream_row(store: &FjallStore) -> u64 {
    spindle_store::ReadView::scan_prefix(store, &spindle_core::keys::stream_prefix())
        .unwrap_or_default()
        .iter()
        .filter_map(|(key, _)| spindle_core::keys::stream_from_key(key))
        .max()
        .unwrap_or(0)
}

/// Fill in any reverse-index rows the forward stream has and the index does
/// not, and report how many were written.
///
/// Every append writes both rows in one batch, so in the steady state there
/// is nothing to do and this costs one scan of a keyspace holding eight bytes
/// per event. It is not dead code, though: a store written before the reverse
/// index existed has a forward stream and no index at all, and reading it
/// with this binary must not silently answer `/sync` from an index that stops
/// short. That is the whole migration -- no marker, no version gate, no
/// operator step -- and it is safe to run twice because a row is a pure
/// function of the forward row it comes from.
///
/// The comparison is `max` against `max` rather than a count, because the two
/// keyspaces are written together: any id the index is missing is above the
/// highest id it holds.
fn backfill_room_stream_index(store: &FjallStore, through: u64) -> usize {
    let indexed = spindle_store::ReadView::scan_prefix(
        store,
        &[
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::RoomStream as u8,
        ],
    )
    .unwrap_or_default()
    .iter()
    .filter_map(|(key, _)| spindle_core::keys::room_stream_from_key(key))
    .max()
    .unwrap_or(0);
    if indexed >= through {
        return 0;
    }
    let mut written = 0;
    for (key, raw) in
        spindle_store::ReadView::scan_prefix(store, &spindle_core::keys::stream_prefix())
            .unwrap_or_default()
    {
        let Some(stream_id) = spindle_core::keys::stream_from_key(&key) else {
            continue;
        };
        if stream_id <= indexed {
            continue;
        }
        let Some(record) = StreamRecord::decode(&raw) else {
            continue;
        };
        if spindle_store::Store::put(
            store,
            &spindle_core::keys::room_stream(&record.room_id, stream_id),
            &record.li.to_be_bytes(),
        )
        .is_ok()
        {
            written += 1;
        }
    }
    written
}

/// The highest stream id already on disk, or 0 for a fresh store.
///
/// `from_stream` is [`highest_stream_row`], passed in because the caller has
/// already paid for that scan.
fn highest_stream_id(store: &FjallStore, from_stream: u64) -> u64 {
    // Pending to-device messages drew from this counter without writing a
    // stream row, so their sequence numbers are invisible to `from_stream`.
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
mod stream_index_tests {
    use spindle_store::{FjallStore, Store};
    use tempfile::TempDir;

    use super::{StreamRecord, backfill_room_stream_index, highest_stream_row};

    /// Write forward stream rows from `first` and no index rows, which is
    /// what a store written before the reverse index looks like.
    fn unindexed(store: &FjallStore, first: u64, rooms: &[&str]) {
        for (offset, room_id) in rooms.iter().enumerate() {
            let offset = u64::try_from(offset).unwrap();
            store
                .put(
                    &spindle_core::keys::stream(first + offset),
                    &StreamRecord {
                        room_id: (*room_id).to_owned(),
                        li: i64::try_from(offset).unwrap(),
                    }
                    .encode(),
                )
                .unwrap();
        }
    }

    #[test]
    fn a_store_with_no_index_gets_one_row_per_stream_row() {
        let dir = TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        unindexed(
            &store,
            1,
            &["!a:example.org", "!b:example.org", "!a:example.org"],
        );

        assert_eq!(
            backfill_room_stream_index(&store, highest_stream_row(&store)),
            3
        );
        assert_eq!(
            spindle_store::ReadView::scan_prefix(
                &store,
                &spindle_core::keys::room_stream_prefix("!a:example.org")
            )
            .unwrap()
            .len(),
            2,
            "the two rows of one room must land under that room's prefix"
        );
    }

    /// The second open has nothing to write, and does not go looking.
    ///
    /// Two separate claims, and the cheap one is not the interesting one:
    /// the per-row `stream_id <= indexed` skip already keeps a second pass
    /// from rewriting anything, so a count of zero would hold even with the
    /// early return deleted. What the early return buys is the *scan* -- the
    /// forward stream is one row per event the server has ever accepted, and
    /// walking it on every restart to discover there is nothing to do is a
    /// cost that grows with the server's whole history. So the rows read are
    /// asserted too, which is the only counter that tells the two apart.
    #[test]
    fn a_second_pass_writes_nothing_and_reads_only_the_index() {
        let dir = TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        unindexed(&store, 1, &["!a:example.org", "!b:example.org"]);

        let through = highest_stream_row(&store);
        assert_eq!(backfill_room_stream_index(&store, through), 2);

        let before = store.scanned();
        assert_eq!(backfill_room_stream_index(&store, through), 0);
        assert_eq!(
            store.scanned() - before,
            2,
            "a complete index should cost one scan of the index itself; \
             anything more means the forward stream was walked again"
        );
    }

    /// A slice stops at the position the sync will hand back.
    ///
    /// The index is written by the append; the watermark is what `/sync`
    /// reports. Those move apart whenever an id is allocated and not yet
    /// committed, so the room's rows can legitimately run past the position
    /// this response is allowed to describe. Delivering one of them anyway
    /// puts an event above the `next_batch` the client is about to be given,
    /// and the client is sent it a second time on its next request.
    ///
    /// Written against the index directly rather than through two racing
    /// appends: the gap between the two numbers is the *point*, and a test
    /// that has to provoke a race to open it would be testing the scheduler.
    #[test]
    fn a_slice_stops_at_the_position_it_was_given() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(FjallStore::open(dir.path()).unwrap());
        let room = "!a:example.org";
        for (stream_id, li) in [(1u64, 10i64), (2, 11), (3, 12)] {
            store
                .put(
                    &spindle_core::keys::room_stream(room, stream_id),
                    &li.to_be_bytes(),
                )
                .unwrap();
        }
        let rooms = super::Rooms::new(std::sync::Arc::clone(&store), "example.org");

        assert_eq!(rooms.room_slice(room, 0, 3).unwrap(), vec![10, 11, 12]);
        assert_eq!(
            rooms.room_slice(room, 0, 2).unwrap(),
            vec![10, 11],
            "the third row is above the position this sync may describe"
        );
        assert_eq!(rooms.room_slice(room, 1, 2).unwrap(), vec![11]);
    }

    /// A hole above the highest indexed id is filled; the rows below it are
    /// not revisited.
    ///
    /// This is the shape a downgrade leaves behind -- an older binary appends
    /// forward rows and no index rows -- and it is also why the check is
    /// `max` against `max` rather than "is the index empty".
    #[test]
    fn a_gap_left_by_an_older_binary_is_filled() {
        let dir = TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        unindexed(&store, 1, &["!a:example.org", "!b:example.org"]);
        assert_eq!(
            backfill_room_stream_index(&store, highest_stream_row(&store)),
            2
        );

        unindexed(&store, 3, &["!c:example.org"]);
        assert_eq!(
            backfill_room_stream_index(&store, highest_stream_row(&store)),
            1,
            "only the row the older binary missed"
        );
    }
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

#[cfg(test)]
mod room_version_tests {
    use std::sync::Arc;

    use ruma::RoomVersionId;
    use spindle_store::FjallStore;
    use tempfile::TempDir;

    use super::{RoomError, Rooms, version_in};

    fn rooms() -> (TempDir, Arc<FjallStore>, Rooms) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let rooms = Rooms::new(Arc::clone(&store), "example.org");
        (dir, store, rooms)
    }

    fn key() -> ruma::signatures::Ed25519KeyPair {
        let document = ruma::signatures::Ed25519KeyPair::generate();
        ruma::signatures::Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap()
    }

    /// A version this server does not advertise is refused, not substituted.
    ///
    /// The point is the *refusal*: `create` previously ignored the
    /// requested version entirely and stamped its own default, so a client
    /// asking for one version and receiving another was told it had
    /// succeeded. A lie a client cannot detect until something that depends
    /// on the version fails is worse than an error it can handle.
    #[test]
    fn creating_a_room_at_an_unadvertised_version_is_refused() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        for unsupported in ["1", "9", "10"] {
            let result = rooms.create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some(unsupported),
                None,
                &serde_json::Map::new(),
            );
            assert!(
                matches!(result, Err(RoomError::UnsupportedVersion(ref named)) if named == unsupported),
                "v{unsupported} was not refused: {result:?}",
            );
        }
    }

    /// The one advertised version is accepted, and lands in the room.
    #[test]
    fn creating_a_room_at_an_advertised_version_is_accepted() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some("11"),
                None,
                &serde_json::Map::new(),
            )
            .expect("v11 is advertised and must be accepted");
        assert_eq!(rooms.room_version(&room_id).unwrap(), RoomVersionId::V11);
    }

    /// An append resolves the room's version from a cold cache.
    ///
    /// `build_event` now takes the signing version from the room rather
    /// than from the `ROOM_VERSION` constant, because event IDs are
    /// version-dependent -- signing a v12 room's event under v11 rules
    /// mints an ID the rest of that room will not recognise. That is the
    /// same defect `make_join` had (#201): a statement about a room made
    /// without reading the room.
    ///
    /// **This test does not prove that change**, and cannot yet: only v11
    /// is advertised, so the constant and the room's version are the same
    /// value, and reverting `build_event` to the constant leaves every
    /// test here green. What it does prove is the part that can fail
    /// today -- that the lookup works from a cold cache (a second `Rooms`
    /// over the same store), rather than deadlocking on the re-entrant
    /// `open` lock the way the first version of this lookup did.
    ///
    /// Real coverage for the signing version arrives with the second
    /// advertised version, and belongs in that slice.
    #[test]
    fn an_append_resolves_the_rooms_version_from_a_cold_cache() {
        let (_dir, store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();

        let restarted = Rooms::new(store, "example.org");
        let event_id = restarted
            .send(
                &room_id,
                "@alice:example.org",
                &key,
                "m.room.message",
                &serde_json::json!({ "msgtype": "m.text", "body": "hello" }),
            )
            .expect("a cold cache must resolve the room's version, not deadlock or guess");

        // v11 event IDs are URL-safe-base64 reference hashes behind `$`.
        assert!(event_id.starts_with('$'), "unexpected event id: {event_id}");
        assert_eq!(
            restarted.room_version(&room_id).unwrap(),
            RoomVersionId::V11
        );
    }

    /// MSC4291: a v12 room's ID is its create event's hash.
    ///
    /// This is the CVE-2025-54315 fix. A room ID nobody can name without
    /// producing the event that hashes to it cannot be claimed by
    /// assertion, which is what made room hijacking possible when the ID
    /// was an unrelated random string the create event merely mentioned.
    #[test]
    fn a_v12_rooms_id_is_its_create_events_hash() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some("12"),
                None,
                &serde_json::Map::new(),
            )
            .expect("v12 is advertised");

        let create = rooms
            .state(&room_id)
            .unwrap()
            .into_iter()
            .find(|event| event["type"] == "m.room.create")
            .expect("every room has a create event");
        let event_id = create["event_id"].as_str().unwrap();

        assert_eq!(
            room_id,
            format!("!{}", event_id.strip_prefix('$').unwrap()),
            "the room ID must be the create event's hash",
        );
        assert!(
            !room_id.contains(':'),
            "MSC4291 drops the server suffix: {room_id}",
        );
    }

    /// MSC4291: the create event does not name the room it creates.
    ///
    /// Naming it would be circular -- the ID is computed from these very
    /// bytes. MSC4289 likewise drops `creator`, because the event's own
    /// sender is the creator.
    #[test]
    fn a_v12_create_event_names_neither_the_room_nor_the_creator() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some("12"),
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        let create = rooms
            .state(&room_id)
            .unwrap()
            .into_iter()
            .find(|event| event["type"] == "m.room.create")
            .unwrap();

        assert!(
            create.get("room_id").is_none(),
            "a v12 create event carries no room_id: {create}",
        );
        assert!(
            create["content"].get("creator").is_none(),
            "MSC4289 drops content.creator: {}",
            create["content"],
        );
        assert_eq!(create["sender"], "@alice:example.org");
    }

    /// v11 keeps the shape it has always had.
    ///
    /// The v12 work is additive: it must not quietly restyle every room
    /// this server has already created, whose IDs are stored, cited by
    /// peers, and bookmarked by clients.
    #[test]
    fn a_v11_room_keeps_its_server_suffix_and_its_create_fields() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some("11"),
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        assert!(room_id.ends_with(":example.org"), "{room_id}");

        let create = rooms
            .state(&room_id)
            .unwrap()
            .into_iter()
            .find(|event| event["type"] == "m.room.create")
            .unwrap();
        assert_eq!(create["room_id"], room_id.as_str());
        assert_eq!(create["content"]["creator"], "@alice:example.org");
    }

    /// A v12 room takes appends, not just a create event.
    ///
    /// The create event is the interesting one, so it is the easy one to
    /// get right alone -- and a room nobody can speak in is not a room.
    #[test]
    fn a_v12_room_accepts_events_after_its_create() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                Some("12"),
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        let event_id = rooms
            .send(
                &room_id,
                "@alice:example.org",
                &key,
                "m.room.message",
                &serde_json::json!({ "msgtype": "m.text", "body": "hello" }),
            )
            .expect("a v12 room must accept messages");
        assert!(event_id.starts_with('$'));
        assert_eq!(rooms.room_version(&room_id).unwrap(), RoomVersionId::V12);
    }

    /// A create event with no `room_version` is a v1 room, per the spec.
    ///
    /// Substituting this server's own default would be the wrong answer for
    /// the case that produces it: a room federated from a server old enough
    /// to omit the field. Guessing there applies one version's rules to
    /// another version's room.
    #[test]
    fn a_create_event_naming_no_version_is_v1() {
        let content = serde_json::json!({ "creator": "@alice:example.org" });
        assert_eq!(version_in(&content).unwrap(), RoomVersionId::V1);
    }

    #[test]
    fn a_create_event_naming_a_version_is_that_version() {
        for named in ["1", "10", "11", "12"] {
            let content = serde_json::json!({ "room_version": named });
            assert_eq!(
                version_in(&content).unwrap(),
                RoomVersionId::try_from(named).unwrap(),
                "{named} did not round-trip",
            );
        }
    }

    /// The room this server creates records the version it was created at,
    /// and reading it back gives that version rather than a constant.
    ///
    /// This is the property the whole slice rests on: the create event is
    /// written with a version, so every later question about the room can be
    /// answered from the room instead of from a module constant.
    #[test]
    fn a_created_room_reports_the_version_it_was_created_at() {
        let (_dir, _store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();

        assert_eq!(
            rooms.room_version(&room_id).unwrap(),
            RoomVersionId::try_from(super::ROOM_VERSION).unwrap(),
        );
        // Cached, and the cached answer is the same answer.
        assert_eq!(
            rooms.room_version(&room_id).unwrap(),
            RoomVersionId::try_from(super::ROOM_VERSION).unwrap(),
        );
    }

    /// The lookup is cached, and the cache must not answer for a room that
    /// does not exist -- an unknown room is an error, not a default.
    #[test]
    fn an_unknown_room_has_no_version_to_report() {
        let (_dir, _store, rooms) = rooms();
        assert!(rooms.room_version("!nonexistent:example.org").is_err());
    }

    /// An append into a room this process has not seen before must not
    /// deadlock on the version lookup.
    ///
    /// The first version of this change called `Rooms::rules` from
    /// `authorize`. `authorize` runs inside `with_room`, holding the `open`
    /// lock; `rules` reaches the create event through `state_event`, which
    /// takes that same lock. `std::sync::Mutex` is not reentrant, so it
    /// hung -- and it hung at 0% CPU rather than failing, which is the worst
    /// way for a bug to present.
    ///
    /// **The second `Rooms` is the entire test.** Creating a room populates
    /// the version cache while no lock is held, because `create` builds its
    /// log locally rather than through `with_room`. Any append that follows
    /// in the same process is then a cache hit and never reaches
    /// `state_event`, so it cannot deadlock. The first attempt at this test
    /// did exactly that and passed against the bug.
    ///
    /// What deadlocks is a **cold cache at an append inside the lock**: a
    /// restarted server, or a room this process did not create. That is what
    /// the federation invite tests were doing when they hung, and a fresh
    /// `Rooms` over the same store is the smallest way to reproduce it.
    #[test]
    fn an_append_with_a_cold_version_cache_does_not_deadlock() {
        let (_dir, store, rooms) = rooms();
        let key = key();
        let room_id = rooms
            .create(
                "@alice:example.org",
                &key,
                None,
                None,
                None,
                &[],
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();

        // Same store, empty caches -- the state a server comes back up in.
        let restarted = Rooms::new(store, "example.org");
        restarted
            .send(
                &room_id,
                "@alice:example.org",
                &key,
                "m.room.message",
                &serde_json::json!({ "msgtype": "m.text", "body": "hello" }),
            )
            .expect("an append with a cold cache must not hang or fail");
    }
}

/// The `m.room.create` content: what the server decides, plus what the client
/// asked for, with the server's keys winning.
///
/// `creation_content` is how a client says what *kind* of room this is --
/// `type: "m.space"` above all -- and how it sets `m.federate`.
///
/// Two keys are the server's, and are written *after* the client's so a client
/// cannot claim them:
///
/// - **`room_version`**, negotiated and refused-rather-than-substituted by the
///   caller. A client that could set it here would be describing a room that
///   is not the one being built.
/// - **`creator`**, which before v12 is an authorization input. A client that
///   could set it would be handing itself somebody else's privileges.
///
/// Winning silently rather than refusing is deliberate: the spec says the
/// server should ignore these keys, and a client echoing back the same
/// `room_version` it already asked for in the outer field is not doing
/// anything wrong.
fn build_create_content(
    version: &str,
    creator: &str,
    privileges_creators: bool,
    supplied: Option<&serde_json::Map<String, Value>>,
) -> Value {
    let reserved = if privileges_creators {
        serde_json::json!({ "room_version": version })
    } else {
        serde_json::json!({ "room_version": version, "creator": creator })
    };
    let Some(supplied) = supplied else {
        return reserved;
    };
    let mut content = supplied.clone();
    if let Value::Object(reserved) = reserved {
        content.extend(reserved);
    }
    Value::Object(content)
}
