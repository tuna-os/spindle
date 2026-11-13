//! Presence: whether a user is around, and what they said about it (#745).
//!
//! # Where it comes from
//!
//! A local user's presence is set three ways: `PUT /presence/{user}/status`,
//! a `/sync` (online unless its `set_presence` says otherwise, as the spec
//! has it), and the clock. A remote user's arrives as an `m.presence` EDU
//! from their own server -- and only theirs, and only while they share a
//! room with someone here: an EDU is unsigned content in a signed envelope,
//! so the envelope's origin is the whole authority, and a server has no
//! business keeping a stranger's comings and goings.
//!
//! # Where it goes
//!
//! A visible change -- the state, the message, or whether the user is
//! currently active -- takes a position on the server-wide stream `/sync`
//! tokens are written in, and is indexed under it
//! ([`spindle_core::keys::Keyspace::PresenceStream`]), so an incremental
//! `/sync` reads "whose presence moved since my token" as one range. A
//! local user's change also goes out as an `m.presence` EDU to every server
//! sharing a room with them, through the ephemeral EDU queue: a presence
//! update that failed to deliver is stale by the time a retry would land,
//! and the user's next change, or the ping below, says it again.
//!
//! # The clock
//!
//! Synapse's timings, so a client's indicators behave as they do on the
//! server they were written against: online goes `unavailable` after five
//! minutes without activity, a local user whose syncs stopped goes
//! `offline` thirty seconds after the last one, and a remote user nobody
//! has heard about in thirty minutes goes `offline` -- which is why a local
//! user who stays online is re-announced to peers every twenty-five. A
//! sweeper applies them; only users not already offline are looked at.
//!
//! # Why `last_active_ago` is computed rather than stored
//!
//! The spec asks for a duration, and a duration stored at write time is
//! wrong by however long it has been since. The row keeps the instant; the
//! answer is derived when it is asked for.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{Durability, FjallStore, ReadView, Store, StoreError};

use crate::federation::Federation;
use crate::metrics::EduResult;
use crate::rooms::Rooms;

/// How long after their last activity a user still counts as "currently
/// active".
///
/// The spec leaves this to the server. Five minutes is Synapse's, and
/// matching it means a client's idle indicator behaves the same way here as
/// on the server it was written against.
const CURRENTLY_ACTIVE_MS: u64 = 5 * 60 * 1000;

/// Online with no activity for this long becomes `unavailable` (Synapse's
/// `IDLE_TIMER`).
pub const IDLE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// A local user with no `/sync` in flight and none for this long becomes
/// `offline` (Synapse's `SYNC_ONLINE_TIMEOUT`). Long enough to cover the
/// gap between one long-poll returning and the client sending the next.
pub const SYNC_ONLINE_TIMEOUT_MS: u64 = 30 * 1000;

/// A remote user nobody has heard about for this long becomes `offline`
/// (Synapse's `FEDERATION_TIMEOUT`): a peer that went away without saying
/// so must not leave its users online here forever.
pub const FEDERATION_TIMEOUT_MS: u64 = 30 * 60 * 1000;

/// How often a local user who is still around is re-announced to peers,
/// inside their [`FEDERATION_TIMEOUT_MS`] (Synapse's
/// `FEDERATION_PING_INTERVAL`).
pub const FEDERATION_PING_INTERVAL_MS: u64 = 25 * 60 * 1000;

/// How far a sync's activity must move `last_active` before the row is
/// rewritten. Without it every sync of every client would be a write, to
/// record a number that only ever reaches anyone rounded to minutes.
const LAST_ACTIVE_GRANULARITY_MS: u64 = 60 * 1000;

/// How often the sweeper applies the clock. Synapse waits five seconds;
/// once a second costs a pass over the users who are around, and keeps
/// this loop inside the second every background loop answers a shutdown
/// in (`tests/delivery_loops.rs`).
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Users read out of one inbound `m.presence` EDU; the rest are dropped.
pub const MAX_PUSH_PER_EDU: usize = 500;

/// The longest user ID accepted (the spec's 255).
const MAX_ID_LEN: usize = 255;

/// The longest status message accepted from a peer. Local ones are bounded
/// by the request body; a peer's are bounded only by its transaction, and
/// a megabyte of status is not a status.
const MAX_STATUS_MSG_LEN: usize = 1024;

/// The three states the spec defines. Anything else is refused rather than
/// stored: a server that accepted `"busy"` and echoed it back would be
/// inventing protocol, and the client that sent it would have no way to
/// learn that nobody else understands it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Online,
    Offline,
    Unavailable,
}

impl State {
    /// The spec's spelling, or `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What is stored for one user.
///
/// Every field after `at_ms` defaults, so a row written before presence
/// had a stream reads as one that has never been announced.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct Row {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_msg: Option<String>,
    /// Unix milliseconds of the user's last activity.
    at_ms: u64,
    /// The stream position of the last visible change; zero for none.
    #[serde(default)]
    position: u64,
    /// For a local user, when peers were last told; for a remote one,
    /// when their server last told us.
    #[serde(default)]
    updated_ms: u64,
    /// Set through `PUT /presence` rather than by a sync or the clock.
    /// A client that marks its user away and keeps syncing would otherwise
    /// flip them straight back to online with its own next sync.
    #[serde(default)]
    explicit: bool,
    /// What a remote user's server said about `currently_active`; a local
    /// user's is derived from `at_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    currently_active: Option<bool>,
}

impl Row {
    fn state(&self) -> State {
        State::parse(&self.state).unwrap_or(State::Offline)
    }

    fn status(&self, now: u64) -> Status {
        let state = self.state();
        // Saturating rather than wrapping: a row written by a clock that has
        // since gone backwards should read as "just now", not as a duration
        // near u64::MAX.
        let last_active_ago = now.saturating_sub(self.at_ms);
        Status {
            state,
            status_msg: self.status_msg.clone(),
            last_active_ago,
            // Only "online" can be currently active. An idle or offline user
            // who set that state one second ago is recent, but recency is
            // not the question -- the question is whether they are there.
            currently_active: state == State::Online
                && self
                    .currently_active
                    .unwrap_or(last_active_ago < CURRENTLY_ACTIVE_MS),
        }
    }

    /// What a watcher would notice: a change here takes a stream position.
    /// `last_active_ago` alone is not one -- it changes every millisecond.
    fn visible(&self, now: u64) -> (State, Option<&str>, bool) {
        let status = self.status(now);
        (
            status.state,
            self.status_msg.as_deref(),
            status.currently_active,
        )
    }
}

/// What a caller is told.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: State,
    pub status_msg: Option<String>,
    /// Milliseconds since this user was last active.
    pub last_active_ago: u64,
    pub currently_active: bool,
}

impl Status {
    /// A user this server has heard nothing from: offline, the spec's
    /// default and the honest answer.
    #[must_use]
    pub const fn offline() -> Self {
        Self {
            state: State::Offline,
            status_msg: None,
            last_active_ago: 0,
            currently_active: false,
        }
    }

    /// The content of an `m.presence` event, as `/sync` and the status
    /// endpoint shape it.
    #[must_use]
    pub fn content(&self) -> Value {
        let mut content = json!({
            "presence": self.state.as_str(),
            "last_active_ago": self.last_active_ago,
            "currently_active": self.currently_active,
        });
        if let Some(message) = &self.status_msg {
            content["status_msg"] = Value::String(message.clone());
        }
        content
    }

    /// The `m.presence` event `/sync` carries for `user_id`.
    #[must_use]
    pub fn event(&self, user_id: &str) -> Value {
        json!({ "type": "m.presence", "sender": user_id, "content": self.content() })
    }

    /// One entry of an `m.presence` EDU's `push` list.
    fn push_entry(&self, user_id: &str) -> Value {
        let mut entry = self.content();
        entry["user_id"] = Value::String(user_id.to_owned());
        entry
    }
}

/// What a write needs beyond the store: the stream to take a position on
/// and the rooms to find peers in, and the queue to tell them through.
#[derive(Clone, Copy)]
pub struct Peers<'a> {
    pub rooms: &'a Rooms,
    pub federation: &'a Federation,
}

impl<'a> Peers<'a> {
    #[must_use]
    pub fn of(state: &'a crate::AppState) -> Self {
        Self {
            rooms: &state.rooms,
            federation: &state.federation,
        }
    }
}

/// Whether a user has a `/sync` open, and when their last one ended.
#[derive(Clone, Copy, Debug, Default)]
struct SyncMark {
    in_flight: usize,
    last_ms: Option<u64>,
}

/// The presence store.
pub struct Presence {
    store: Arc<FjallStore>,
    enabled: bool,
    server_name: String,
    /// Held across each row's read-modify-write. Two writers for one user
    /// -- a sync and the sweeper -- must not both read the old row and
    /// each write their own successor over the other's.
    writes: Mutex<()>,
    /// In memory only: a restart forgets who was syncing, and the clients
    /// that still are say so again within a long-poll.
    syncing: Mutex<HashMap<String, SyncMark>>,
    /// Everyone whose stored state is not offline: what the sweeper reads,
    /// so a pass costs the users who are around rather than every user who
    /// ever set a presence.
    live: Mutex<HashSet<String>>,
}

impl Presence {
    /// The store, seeded with the users a previous run left not offline.
    #[must_use]
    pub fn new(store: Arc<FjallStore>, enabled: bool, server_name: impl Into<String>) -> Self {
        let mut live = HashSet::new();
        if enabled {
            match ReadView::scan_prefix(store.as_ref(), &keys::presence_prefix()) {
                Ok(rows) => {
                    for (key, value) in rows {
                        let row = serde_json::from_slice::<Row>(&value).unwrap_or_default();
                        if row.state() != State::Offline
                            && let Some(user) = keys::presence_user(&key)
                        {
                            live.insert(user);
                        }
                    }
                }
                Err(error) => tracing::warn!("presence rows not read at start: {error}"),
            }
        }
        Self {
            store,
            enabled,
            server_name: server_name.into(),
            writes: Mutex::new(()),
            syncing: Mutex::new(HashMap::new()),
            live: Mutex::new(live),
        }
    }

    /// `[presence] enabled`.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn is_local(&self, user_id: &str) -> bool {
        domain(user_id) == Some(self.server_name.as_str())
    }

    fn read_row(&self, user_id: &str) -> Result<Option<Row>, StoreError> {
        Ok(
            ReadView::get(self.store.as_ref(), &keys::presence(user_id))?
                .map(|raw| serde_json::from_slice::<Row>(&raw).unwrap_or_default()),
        )
    }

    /// What `user_id`'s presence is now.
    ///
    /// A user who has never set one is offline, which is the spec's default
    /// and also the honest answer: this server has heard nothing from them.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be read.
    pub fn get(&self, user_id: &str) -> Result<Status, StoreError> {
        Ok(self
            .read_row(user_id)?
            .map_or_else(Status::offline, |row| row.status(now_ms())))
    }

    /// `PUT /presence/{user}/status`: record what a local user said.
    ///
    /// Answered and ignored with presence off: the spec gives a client no
    /// way to learn presence is off, so refusing would only break it.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be written.
    pub fn set(
        &self,
        peers: Peers<'_>,
        user_id: &str,
        state: State,
        status_msg: Option<&str>,
    ) -> Result<(), StoreError> {
        if !self.enabled {
            return Ok(());
        }
        let now = now_ms();
        self.update(peers, user_id, now, |old| {
            let mut row = old.cloned().unwrap_or_default();
            state.as_str().clone_into(&mut row.state);
            // An empty message is the spec's way of clearing one, so it is
            // stored as absent rather than as "". Round-tripping "" would
            // make a cleared message indistinguishable from a blank one.
            row.status_msg = status_msg.filter(|msg| !msg.is_empty()).map(str::to_owned);
            row.explicit = true;
            // Saying you are online is activity; saying you are away is not,
            // and stamping it as such would make "last active" mean "last
            // touched the indicator". A first row is stamped either way so
            // the clock has somewhere to count from.
            if state == State::Online || old.is_none() {
                row.at_ms = now;
            }
            Some((row, false))
        })?;
        Ok(())
    }

    /// A local user's `/sync` began, with this `set_presence`.
    ///
    /// `offline` changes nothing and does not count as syncing, as in
    /// Synapse: it is how a client says "do not let this sync speak for
    /// me". The guard, while held, keeps the user from timing out; dropping
    /// it starts their thirty seconds.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be written.
    pub fn sync_started(
        self: &Arc<Self>,
        peers: Peers<'_>,
        user_id: &str,
        wanted: State,
    ) -> Result<Option<SyncGuard>, StoreError> {
        if !self.enabled || wanted == State::Offline {
            return Ok(None);
        }
        let now = now_ms();
        let guard = SyncGuard::start(self, user_id, now);
        self.update(peers, user_id, now, |old| {
            let mut row = old.cloned().unwrap_or_default();
            let current = row.state();
            if wanted == State::Online {
                if current == State::Unavailable && row.explicit {
                    return None;
                }
                if current == State::Online
                    && now.saturating_sub(row.at_ms) < LAST_ACTIVE_GRANULARITY_MS
                {
                    return None;
                }
                row.at_ms = now;
            } else {
                if current == State::Unavailable {
                    return None;
                }
                if row.at_ms == 0 {
                    row.at_ms = now;
                }
            }
            wanted.as_str().clone_into(&mut row.state);
            row.explicit = false;
            Some((row, false))
        })?;
        Ok(Some(guard))
    }

    /// Of `users`, those not offline, and what their presence is now.
    ///
    /// Asked of the in-memory set of users not offline before any row is
    /// read, so an initial sync in a large room reads the users who are
    /// around rather than one row per member (`tests/read_budget.rs`).
    ///
    /// # Errors
    ///
    /// Returns a store error if a row cannot be read.
    pub fn not_offline(
        &self,
        users: impl IntoIterator<Item = String>,
    ) -> Result<Vec<(String, Status)>, StoreError> {
        if !self.enabled {
            return Ok(Vec::new());
        }
        let around: Vec<String> = {
            let live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
            users
                .into_iter()
                .filter(|user| live.contains(user))
                .collect()
        };
        let now = now_ms();
        let mut out = Vec::with_capacity(around.len());
        for user_id in around {
            if let Some(row) = self.read_row(&user_id)?
                && row.state() != State::Offline
            {
                out.push((user_id, row.status(now)));
            }
        }
        Ok(out)
    }

    /// Whose presence visibly changed at a position in `(since, until]`,
    /// and what it is now.
    ///
    /// # Errors
    ///
    /// Returns a store error if the index or a row cannot be read.
    pub fn changes(&self, since: u64, until: u64) -> Result<Vec<(String, Status)>, StoreError> {
        if !self.enabled || until <= since {
            return Ok(Vec::new());
        }
        let rows = ReadView::scan_until(
            self.store.as_ref(),
            &keys::presence_stream_prefix(),
            &keys::presence_stream_at(since.saturating_add(1)),
            &keys::presence_stream_at(until.saturating_add(1)),
        )?;
        let now = now_ms();
        let mut out = Vec::new();
        for (key, _) in rows {
            let Some((position, user_id)) = keys::presence_stream_parts(&key) else {
                continue;
            };
            // A row its user's has moved past is a superseded one whose
            // delete did not land; the user's current row is indexed too.
            if let Some(row) = self.read_row(&user_id)?
                && row.position == position
            {
                out.push((user_id, row.status(now)));
            }
        }
        Ok(out)
    }

    /// Apply one inbound `m.presence` EDU from `origin`.
    ///
    /// Synchronous room work -- deciding whether a user shares a room with
    /// anyone here can load a cold room -- so the caller runs it off the
    /// async workers.
    #[must_use]
    pub fn apply_edu(&self, peers: Peers<'_>, origin: &str, content: &Value) -> EduResult {
        if !self.enabled {
            return EduResult::Unsupported;
        }
        let Some(push) = content["push"].as_array() else {
            return EduResult::Malformed;
        };
        let (mut accepted, mut malformed) = (0_usize, 0_usize);
        for entry in push.iter().take(MAX_PUSH_PER_EDU) {
            let (Some(user_id), Some(state)) = (
                entry["user_id"].as_str(),
                entry["presence"].as_str().and_then(State::parse),
            ) else {
                malformed += 1;
                continue;
            };
            if user_id.len() > MAX_ID_LEN
                || domain(user_id) != Some(origin)
                || self.is_local(user_id)
                || !shares_room_with_local(peers.rooms, user_id, &self.server_name)
            {
                continue;
            }
            let status_msg = entry["status_msg"]
                .as_str()
                .filter(|msg| !msg.is_empty() && msg.len() <= MAX_STATUS_MSG_LEN)
                .map(str::to_owned);
            let ago = entry["last_active_ago"].as_u64().unwrap_or(0);
            let currently_active = entry["currently_active"].as_bool();
            let now = now_ms();
            let applied = self.update(peers, user_id, now, |old| {
                let mut row = old.cloned().unwrap_or_default();
                state.as_str().clone_into(&mut row.state);
                row.status_msg = status_msg;
                row.at_ms = now.saturating_sub(ago);
                row.updated_ms = now;
                row.currently_active = currently_active;
                Some((row, false))
            });
            match applied {
                Ok(_) => accepted += 1,
                Err(error) => tracing::debug!(user_id, "remote presence not stored: {error}"),
            }
        }
        if accepted > 0 {
            EduResult::Accepted
        } else if malformed > 0 {
            EduResult::Malformed
        } else {
            EduResult::Ignored
        }
    }

    /// Apply the clock to everyone not offline, as of `now`: idle, stopped
    /// syncing, a peer gone quiet, a ping due. Returns how many users'
    /// presence visibly changed.
    pub fn sweep(&self, peers: Peers<'_>, now: u64) -> usize {
        let users: Vec<String> = self
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        let mut changed = 0;
        for user_id in users {
            let local = self.is_local(&user_id);
            let sync = self.sync_mark(&user_id);
            let swept = self.update(peers, &user_id, now, |old| {
                let old = old?;
                let mut row = old.clone();
                if let Some(state) = timed_out(old, local, sync, now) {
                    state.as_str().clone_into(&mut row.state);
                    row.explicit = false;
                    if !local {
                        row.currently_active = None;
                    }
                    return Some((row, false));
                }
                let ping_due = local
                    && old.state() != State::Offline
                    && now.saturating_sub(old.updated_ms) > FEDERATION_PING_INTERVAL_MS;
                ping_due.then_some((row, true))
            });
            match swept {
                Ok(true) => changed += 1,
                Ok(false) => {}
                Err(error) => tracing::debug!(user_id, "presence sweep failed: {error}"),
            }
        }
        changed
    }

    fn sync_mark(&self, user_id: &str) -> SyncMark {
        self.syncing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user_id)
            .copied()
            .unwrap_or_default()
    }

    /// Read `user_id`'s row, let `change` decide its successor and whether
    /// peers must hear about it regardless, and write it. A visible change
    /// takes a stream position and is indexed under it; a local user's
    /// visible change, or a forced one, is queued for every server sharing
    /// a room with them. Returns whether the change was visible.
    fn update(
        &self,
        peers: Peers<'_>,
        user_id: &str,
        now: u64,
        change: impl FnOnce(Option<&Row>) -> Option<(Row, bool)>,
    ) -> Result<bool, StoreError> {
        let (row, visible, federate) = {
            let _writer = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
            let old = self.read_row(user_id)?;
            let Some((mut row, force)) = change(old.as_ref()) else {
                return Ok(false);
            };
            let visible = old
                .as_ref()
                .is_none_or(|old| old.visible(now) != row.visible(now));
            let federate =
                self.is_local(user_id) && peers.federation.enabled() && (visible || force);
            if federate {
                row.updated_ms = now;
            }
            if visible {
                // Held until the rows are written: a sync must not be handed
                // a token past this position before the index row exists.
                let stream_write = peers.rooms.reserve_stream_id();
                row.position = stream_write.id();
                self.commit(user_id, &row, Some(row.position))?;
                drop(stream_write);
                if let Some(stale) = old.as_ref().map(|old| old.position)
                    && stale != 0
                    && stale != row.position
                {
                    // Outside the batch because the store has no batched
                    // delete; a crash in between leaves a row `changes`
                    // already knows to skip.
                    Store::delete(self.store.as_ref(), &keys::presence_stream(stale, user_id))?;
                }
            } else if old.as_ref() != Some(&row) {
                self.commit(user_id, &row, None)?;
            }
            let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
            if row.state() == State::Offline {
                live.remove(user_id);
            } else {
                live.insert(user_id.to_owned());
            }
            (row, visible, federate)
        };
        if federate {
            fan_out(peers, user_id, &row.status(now));
        }
        Ok(visible)
    }

    /// Write a row, and its index entry when it took a position.
    ///
    /// Relaxed durability: presence is a claim about the present, and one a
    /// crash loses is restated by the user's next sync or the peer's next
    /// update, where an fsync on every state change would put a disk
    /// barrier on the sync path.
    fn commit(&self, user_id: &str, row: &Row, position: Option<u64>) -> Result<(), StoreError> {
        let encoded = serde_json::to_vec(row).unwrap_or_default();
        let mut writes = vec![(keys::presence(user_id), encoded)];
        if let Some(position) = position {
            writes.push((keys::presence_stream(position, user_id), Vec::new()));
        }
        Store::commit(self.store.as_ref(), &writes, Durability::Relaxed)
    }
}

/// Held for the length of one `/sync` that speaks for its user's presence.
pub struct SyncGuard {
    presence: Arc<Presence>,
    user_id: String,
}

impl SyncGuard {
    fn start(presence: &Arc<Presence>, user_id: &str, now: u64) -> Self {
        let mut syncing = presence
            .syncing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mark = syncing.entry(user_id.to_owned()).or_default();
        mark.in_flight += 1;
        mark.last_ms = Some(now);
        Self {
            presence: Arc::clone(presence),
            user_id: user_id.to_owned(),
        }
    }
}

impl Drop for SyncGuard {
    fn drop(&mut self) {
        let mut syncing = self
            .presence
            .syncing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(mark) = syncing.get_mut(&self.user_id) {
            mark.in_flight = mark.in_flight.saturating_sub(1);
            mark.last_ms = Some(now_ms());
        }
    }
}

/// What the clock does to a row: the state it should now be in, if any.
fn timed_out(row: &Row, local: bool, sync: SyncMark, now: u64) -> Option<State> {
    let state = row.state();
    if state == State::Offline {
        return None;
    }
    if !local {
        return (now.saturating_sub(row.updated_ms) > FEDERATION_TIMEOUT_MS)
            .then_some(State::Offline);
    }
    // Activity counts as much as a sync does: a user who set themselves
    // online through the API a moment ago is not offline for not syncing.
    if sync.in_flight == 0 {
        let latest = sync.last_ms.unwrap_or(0).max(row.at_ms);
        if now.saturating_sub(latest) > SYNC_ONLINE_TIMEOUT_MS {
            return Some(State::Offline);
        }
    }
    (state == State::Online && now.saturating_sub(row.at_ms) > IDLE_TIMEOUT_MS)
        .then_some(State::Unavailable)
}

/// Queue `status` as an `m.presence` EDU for every server sharing a room
/// with `user_id`, once each.
fn fan_out(peers: Peers<'_>, user_id: &str, status: &Status) {
    let Ok(rooms) = peers.rooms.joined(user_id) else {
        return;
    };
    let mut destinations = BTreeSet::new();
    for room_id in rooms {
        if let Ok(domains) = peers.rooms.remote_domains(&room_id) {
            destinations.extend(domains);
        }
    }
    if destinations.is_empty() {
        return;
    }
    let edu = json!({
        "edu_type": "m.presence",
        "content": { "push": [status.push_entry(user_id)] },
    });
    for destination in destinations {
        peers.federation.queue_edu(&destination, edu.clone());
    }
}

/// Whether `user_id` is joined to a room some user of `server_name` is
/// joined to.
fn shares_room_with_local(rooms: &Rooms, user_id: &str, server_name: &str) -> bool {
    let Ok(joined) = rooms.joined(user_id) else {
        return false;
    };
    joined.iter().any(|room_id| {
        rooms.joined_member_ids(room_id).is_ok_and(|members| {
            members
                .iter()
                .any(|member| domain(member) == Some(server_name))
        })
    })
}

fn domain(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, domain)| domain)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Apply the clock every `interval`, for the life of the server.
///
/// Holds everything weakly and upgrades for one pass at a time, as the
/// other background loops do (`lib.rs` says why), and awaits nothing while
/// upgraded, so a cancellation never drops the last reference mid-pass.
pub async fn sweep_loop(
    presence: Weak<Presence>,
    rooms: Weak<Rooms>,
    federation: Weak<Federation>,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        let (Some(presence), Some(rooms), Some(federation)) =
            (presence.upgrade(), rooms.upgrade(), federation.upgrade())
        else {
            return;
        };
        presence.sweep(
            Peers {
                rooms: &rooms,
                federation: &federation,
            },
            now_ms(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: State, at_ms: u64, updated_ms: u64) -> Row {
        Row {
            state: state.as_str().to_owned(),
            at_ms,
            updated_ms,
            ..Row::default()
        }
    }

    const NOW: u64 = 10 * 60 * 60 * 1000;

    #[test]
    fn online_goes_idle_after_five_minutes_without_activity() {
        let syncing = SyncMark {
            in_flight: 1,
            last_ms: Some(NOW),
        };
        let active = row(State::Online, NOW - IDLE_TIMEOUT_MS + 1, 0);
        assert_eq!(timed_out(&active, true, syncing, NOW), None);
        let idle = row(State::Online, NOW - IDLE_TIMEOUT_MS - 1, 0);
        assert_eq!(
            timed_out(&idle, true, syncing, NOW),
            Some(State::Unavailable)
        );
    }

    #[test]
    fn a_local_user_whose_syncs_stopped_goes_offline() {
        let stale = row(State::Online, NOW - 60_000, 0);
        let stopped = SyncMark {
            in_flight: 0,
            last_ms: Some(NOW - SYNC_ONLINE_TIMEOUT_MS - 1),
        };
        assert_eq!(timed_out(&stale, true, stopped, NOW), Some(State::Offline));
        // A sync in flight, however long its long-poll, keeps them on.
        let polling = SyncMark {
            in_flight: 1,
            last_ms: Some(NOW - SYNC_ONLINE_TIMEOUT_MS - 1),
        };
        assert_eq!(timed_out(&stale, true, polling, NOW), None);
        // And so does a sync that ended a moment ago.
        let recent = SyncMark {
            in_flight: 0,
            last_ms: Some(NOW - 1_000),
        };
        assert_eq!(timed_out(&stale, true, recent, NOW), None);
        // Offline stays offline: nothing to time out.
        let gone = row(State::Offline, 0, 0);
        assert_eq!(timed_out(&gone, true, stopped, NOW), None);
    }

    #[test]
    fn a_remote_user_nobody_has_heard_about_goes_offline() {
        let quiet = row(State::Online, NOW, NOW - FEDERATION_TIMEOUT_MS - 1);
        assert_eq!(
            timed_out(&quiet, false, SyncMark::default(), NOW),
            Some(State::Offline)
        );
        let heard = row(State::Online, 0, NOW - FEDERATION_TIMEOUT_MS + 1);
        assert_eq!(timed_out(&heard, false, SyncMark::default(), NOW), None);
    }

    #[test]
    fn last_active_alone_is_not_a_visible_change() {
        let earlier = row(State::Online, NOW - 1_000, 0);
        let later = row(State::Online, NOW, 0);
        assert_eq!(earlier.visible(NOW), later.visible(NOW));
        let idle = row(State::Online, NOW - CURRENTLY_ACTIVE_MS - 1, 0);
        assert_ne!(idle.visible(NOW), later.visible(NOW));
    }

    #[test]
    fn a_row_from_before_the_stream_still_reads() {
        let old: Row =
            serde_json::from_str(r#"{"state":"online","status_msg":"hi","at_ms":5}"#).unwrap();
        assert_eq!(old.state(), State::Online);
        assert_eq!(old.position, 0);
        assert_eq!(old.status_msg.as_deref(), Some("hi"));
    }
}
