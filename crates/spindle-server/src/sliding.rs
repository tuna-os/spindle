//! Simplified Sliding Sync (MSC4186) — the surface Element X speaks.
//!
//! The idea the MSC exists for: a client with a thousand rooms wants the
//! *visible window* of its room list, not all thousand — so the request names
//! ranges over a sorted list, and the response carries only the rooms in
//! view plus whatever changed.
//!
//! **Connections.** A client's requests form a connection, named by the
//! user, the device and the request's `conn_id`, and each response's `pos`
//! names a position in it. Behind each position the server keeps what the
//! client was told: the parameters it asked with, which are sticky (a
//! request that leaves out its lists, a field of a list, its subscriptions
//! or an extension's config keeps the previous ones), and for each room the
//! stream position the client holds it at and the room config it was sent
//! with. That is what lets a room the client already holds be sent as only
//! what changed since, instead of in full every time it moves; a room that
//! comes back into a window after an absence be caught up from where the
//! client left it, not from the previous request; and a room whose
//! `required_state` or `timeline_limit` grows be sent the difference.
//!
//! The table lives in memory, with an idle expiry, and that is a choice
//! rather than a shortcut. A `pos` the server does not hold — after a
//! restart, after [`CONNECTION_IDLE_EXPIRY`] without a request, or one never
//! issued to this device and connection — is answered `M_UNKNOWN_POS`,
//! which every MSC4186 client handles by starting the connection over, at
//! the price of one initial response for its visible window. To-device
//! messages are acknowledged by the extension's own `since`, not by `pos`,
//! so a lost connection loses no keys. Persisting the table would cost a
//! write on every request to save that one window.
//!
//! The sort is by each room's last activity, newest first. The linear index
//! cannot order rooms against each other — it is per-room by design — so the
//! sort key is the head event's timestamp, one point read per room.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Map, Value, json};

/// `(type, state_key)` pairs, as `required_state` names them.
pub type RequiredState = Vec<(String, String)>;

/// One list, after the sticky merge: which slice of the sorted rooms, and
/// what to send for each room in it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListRequest {
    pub ranges: Vec<(usize, usize)>,
    pub required_state: RequiredState,
    pub timeline_limit: usize,
}

/// A direct subscription to one room, window position notwithstanding,
/// after the sticky merge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomSubscription {
    pub required_state: RequiredState,
    pub timeline_limit: usize,
}

/// A list or a subscription as one request sends it. Every field is
/// optional, because a field left out keeps the value the connection last
/// had; a subscription has no `ranges`, and one it sends anyway is unused.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Sent {
    ranges: Option<Vec<(usize, usize)>>,
    required_state: Option<RequiredState>,
    timeline_limit: Option<usize>,
}

/// The whole request body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SlidingRequest {
    /// Which of the device's connections this request belongs to. Absent is
    /// the device's default connection, a connection like any other.
    pub conn_id: Option<String>,
    /// Echoed in the response: a client that changed its parameters
    /// mid-poll tells the answer to its new request from a late answer to
    /// the old one by this.
    pub txn_id: Option<String>,
    /// MSC4186 lists `pos` among the body's fields; the query parameter,
    /// which is what clients send, wins when both are present.
    pub pos: Option<String>,
    pub lists: Option<Map<String, Value>>,
    pub room_subscriptions: Option<Map<String, Value>>,
    /// MSC3575's way to end a subscription without restating the others.
    pub unsubscribe_rooms: Vec<String>,
    /// Milliseconds to long-poll when nothing has changed.
    pub timeout: Option<u64>,
    pub extensions: Extensions,
}

/// What a connection asks for: the lists, subscriptions and extension
/// configs of its latest request, over its earlier ones where that request
/// is silent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub lists: BTreeMap<String, ListRequest>,
    pub subscriptions: BTreeMap<String, RoomSubscription>,
    /// The extension configs. `to_device.since` is never kept here: it is a
    /// token the request carries, not a parameter of the connection.
    pub extensions: Extensions,
}

impl SlidingRequest {
    /// The parameters this request runs with: each one it sends, and for
    /// each one it leaves out, the connection's previous one.
    ///
    /// `lists` and `room_subscriptions` merge alike. Left out altogether,
    /// the previous set stands: MSC3575's sticky parameters, which let a
    /// client send its lists once. Sent, the set is the one sent, so a list
    /// or subscription the client stopped naming ends -- a client that
    /// restates everything on every request, as matrix-rust-sdk does, is
    /// answered exactly as it asked -- and within each one named, a field
    /// left out keeps its previous value. Extension configs merge field by
    /// field.
    ///
    /// # Errors
    ///
    /// Names the list or subscription that does not decode.
    pub fn params(&self, previous: Option<&Params>) -> Result<Params, String> {
        let empty = Params::default();
        let previous = previous.unwrap_or(&empty);
        let lists = match &self.lists {
            None => previous.lists.clone(),
            Some(lists) => {
                let mut merged = BTreeMap::new();
                for (name, value) in lists {
                    let sent = Sent::deserialize(value)
                        .map_err(|error| format!("list {name:?}: {error}"))?;
                    let before = previous.lists.get(name);
                    let list = ListRequest {
                        ranges: sent
                            .ranges
                            .or_else(|| before.map(|list| list.ranges.clone()))
                            .unwrap_or_default(),
                        required_state: sent
                            .required_state
                            .or_else(|| before.map(|list| list.required_state.clone()))
                            .unwrap_or_default(),
                        timeline_limit: sent
                            .timeline_limit
                            .or_else(|| before.map(|list| list.timeline_limit))
                            .unwrap_or_default(),
                    };
                    merged.insert(name.clone(), list);
                }
                merged
            }
        };
        let mut subscriptions = match &self.room_subscriptions {
            None => previous.subscriptions.clone(),
            Some(subscriptions) => {
                let mut merged = BTreeMap::new();
                for (room_id, value) in subscriptions {
                    let sent = Sent::deserialize(value)
                        .map_err(|error| format!("subscription {room_id:?}: {error}"))?;
                    let before = previous.subscriptions.get(room_id);
                    let subscription = RoomSubscription {
                        required_state: sent
                            .required_state
                            .or_else(|| before.map(|room| room.required_state.clone()))
                            .unwrap_or_default(),
                        timeline_limit: sent
                            .timeline_limit
                            .or_else(|| before.map(|room| room.timeline_limit))
                            .unwrap_or_default(),
                    };
                    merged.insert(room_id.clone(), subscription);
                }
                merged
            }
        };
        for room_id in &self.unsubscribe_rooms {
            subscriptions.remove(room_id);
        }
        Ok(Params {
            lists,
            subscriptions,
            extensions: self.extensions.merged(&previous.extensions),
        })
    }
}

/// The extensions (MSC4186 §extensions): the parts of a client's world that
/// are not a room's timeline, each switched on by name. Element X reads
/// *all* of its E2EE and to-device traffic through these rather than
/// through classic sync, so serving them on `/sync` v3 alone leaves the
/// flagship client unable to decrypt anything.
///
/// Sticky like the rest of a connection's parameters, field by field.
/// `to_device` carries its own `since`, because to-device messages are
/// acknowledged by the token that delivered them rather than by `pos`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Extensions {
    pub to_device: ToDeviceExtension,
    pub e2ee: Toggle,
    pub account_data: RoomExtension,
    pub receipts: RoomExtension,
    pub typing: RoomExtension,
}

/// One extension's switch. Absent is off.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Toggle {
    pub enabled: Option<bool>,
}

impl Toggle {
    #[must_use]
    pub fn on(&self) -> bool {
        self.enabled == Some(true)
    }
}

/// A room extension's switch and its scope (MSC3575's extension `lists` and
/// `rooms`): the lists whose windows it speaks about and the subscriptions.
/// `"*"` in either is all of them, and a field left out is `["*"]`, which
/// is how Synapse reads it too -- an extension that names no scope applies
/// to every room in view.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RoomExtension {
    pub enabled: Option<bool>,
    pub lists: Option<Vec<String>>,
    pub rooms: Option<Vec<String>>,
}

impl RoomExtension {
    #[must_use]
    pub fn on(&self) -> bool {
        self.enabled == Some(true)
    }

    fn merged(&self, previous: &Self) -> Self {
        Self {
            enabled: self.enabled.or(previous.enabled),
            lists: self.lists.clone().or_else(|| previous.lists.clone()),
            rooms: self.rooms.clone().or_else(|| previous.rooms.clone()),
        }
    }

    /// The rooms this extension speaks about, out of the rooms in each
    /// list's window and the subscribed ones.
    #[must_use]
    pub fn scope<'a>(
        &self,
        windows: &'a BTreeMap<String, Vec<String>>,
        subscribed: &'a [String],
    ) -> BTreeSet<&'a str> {
        let mut scope = BTreeSet::new();
        let every_list = self
            .lists
            .as_ref()
            .is_none_or(|names| names.iter().any(|name| name == "*"));
        for (name, rooms) in windows {
            let named = || {
                self.lists
                    .as_ref()
                    .is_some_and(|names| names.contains(name))
            };
            if every_list || named() {
                scope.extend(rooms.iter().map(String::as_str));
            }
        }
        let every_room = self
            .rooms
            .as_ref()
            .is_none_or(|rooms| rooms.iter().any(|room| room == "*"));
        for room_id in subscribed {
            let named = || {
                self.rooms
                    .as_ref()
                    .is_some_and(|rooms| rooms.contains(room_id))
            };
            if every_room || named() {
                scope.insert(room_id.as_str());
            }
        }
        scope
    }
}

/// The to-device extension: enabled, and the token of the last batch the
/// client has, which is what acknowledges everything before it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ToDeviceExtension {
    pub enabled: Option<bool>,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

impl ToDeviceExtension {
    #[must_use]
    pub fn on(&self) -> bool {
        self.enabled == Some(true)
    }
}

impl Extensions {
    /// Whether any extension is on, so a response can stay `{}` when none
    /// is.
    #[must_use]
    pub fn any(&self) -> bool {
        self.to_device.on()
            || self.e2ee.on()
            || self.account_data.on()
            || self.receipts.on()
            || self.typing.on()
    }

    /// The request's configs over the connection's previous ones. The
    /// to-device `since` is left behind: see [`Params::extensions`].
    fn merged(&self, previous: &Self) -> Self {
        Self {
            to_device: ToDeviceExtension {
                enabled: self.to_device.enabled.or(previous.to_device.enabled),
                since: None,
                limit: self.to_device.limit.or(previous.to_device.limit),
            },
            e2ee: Toggle {
                enabled: self.e2ee.enabled.or(previous.e2ee.enabled),
            },
            account_data: self.account_data.merged(&previous.account_data),
            receipts: self.receipts.merged(&previous.receipts),
            typing: self.typing.merged(&previous.typing),
        }
    }
}

/// What a room is sent with: MSC4186's "room config".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomConfig {
    pub required_state: RequiredState,
    pub timeline_limit: usize,
}

impl RoomConfig {
    /// Fold in one more list or subscription that names the room: MSC4186
    /// combines them into a superset, the larger timeline and the union of
    /// the state.
    fn absorb(&mut self, required_state: &[(String, String)], timeline_limit: usize) {
        for pair in required_state {
            if !self.required_state.contains(pair) {
                self.required_state.push(pair.clone());
            }
        }
        self.timeline_limit = self.timeline_limit.max(timeline_limit);
    }
}

/// The rooms one response is about.
pub struct Selection {
    /// The rooms in each list's window, by list name.
    pub windows: BTreeMap<String, Vec<String>>,
    /// The subscribed rooms the user may see.
    pub subscribed: Vec<String>,
    /// Every room a window or a subscription names, with its combined
    /// config. Rooms sharing a config share one allocation, which is what
    /// keeps a connection's per-room record small.
    pub wanted: HashMap<String, Arc<RoomConfig>>,
}

/// Which rooms `params` names, out of `ordered` -- the user's rooms sorted
/// newest first -- and of the subscriptions, the ones in `visible`.
///
/// A subscription is an arbitrary room id lifted out of the request body,
/// so only the ones the user may see count; one they may not is dropped
/// silently, as MSC4186 says. A client fishing for a room it was never in
/// learns nothing from the difference between "no such room" and "not
/// yours", which is the same reason the room directory does not
/// distinguish them.
#[must_use]
pub fn select<S: std::hash::BuildHasher>(
    params: &Params,
    ordered: &[(String, i64)],
    visible: &HashSet<&str, S>,
) -> Selection {
    let mut combined: HashMap<String, RoomConfig> = HashMap::new();
    let mut windows = BTreeMap::new();
    for (name, list) in &params.lists {
        let rooms: Vec<String> = indices_in_view(&list.ranges, ordered.len())
            .into_iter()
            .map(|index| ordered[index].0.clone())
            .collect();
        for room_id in &rooms {
            combined
                .entry(room_id.clone())
                .or_default()
                .absorb(&list.required_state, list.timeline_limit);
        }
        windows.insert(name.clone(), rooms);
    }
    let mut subscribed = Vec::new();
    for (room_id, subscription) in &params.subscriptions {
        if !visible.contains(room_id.as_str()) {
            continue;
        }
        combined
            .entry(room_id.clone())
            .or_default()
            .absorb(&subscription.required_state, subscription.timeline_limit);
        subscribed.push(room_id.clone());
    }
    let mut interned: Vec<Arc<RoomConfig>> = Vec::new();
    let wanted = combined
        .into_iter()
        .map(|(room_id, config)| {
            let shared = if let Some(shared) = interned.iter().find(|known| ***known == config) {
                Arc::clone(shared)
            } else {
                let shared = Arc::new(config);
                interned.push(Arc::clone(&shared));
                shared
            };
            (room_id, shared)
        })
        .collect();
    Selection {
        windows,
        subscribed,
        wanted,
    }
}

/// What the client holds of one room on a connection.
#[derive(Clone, Debug)]
pub struct SentRoom {
    /// The stream position the client is current to for this room: the
    /// last response that either sent it or was silent about it because
    /// nothing had changed.
    pub at: u64,
    /// The config it was last answered for.
    pub config: Arc<RoomConfig>,
    /// Whether it was sent as an invite: stripped state only.
    pub invite: bool,
}

/// What a connection holds at one `pos`.
#[derive(Clone, Debug, Default)]
pub struct Connection {
    /// The stream position that response answered at.
    pub stream: u64,
    pub params: Params,
    /// Each room the client holds, by room id. A room the user can no
    /// longer see is dropped, so seeing it again starts it over in full.
    pub rooms: HashMap<String, SentRoom>,
    /// For each room whose receipts the client holds, the stream position
    /// it holds them as of. Apart from [`Self::rooms`] because the receipts
    /// extension has its own scope.
    pub receipts: HashMap<String, u64>,
}

/// How one room in a response is to be answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Need {
    /// The client does not hold it -- never sent on this connection, or
    /// sent as an invite and joined since, or the reverse -- so it goes in
    /// full, `initial: true`.
    Initial,
    /// The client holds it as of `since`: what changed after that, and
    /// nothing if nothing did.
    Since {
        since: u64,
        /// The timeline limit grew: MSC4186 sends the newest events up to
        /// the new limit, already-sent ones included, and says so.
        expanded_timeline: bool,
        /// The `required_state` entries the client did not ask for before.
        widened: RequiredState,
    },
}

impl Need {
    /// Judge a room from what the client holds of it.
    #[must_use]
    pub fn of(held: Option<&SentRoom>, config: &RoomConfig, invite: bool) -> Self {
        match held {
            Some(held) if held.invite == invite => Self::Since {
                since: held.at,
                expanded_timeline: config.timeline_limit > held.config.timeline_limit,
                widened: widened(&held.config.required_state, &config.required_state),
            },
            _ => Self::Initial,
        }
    }

    /// Whether the room must be sent even if nothing in it changed: MSC4186
    /// wants an expanded timeline sent at once, and a client that widens
    /// its `required_state` is asking for state it does not have.
    #[must_use]
    pub fn forced(&self) -> bool {
        match self {
            Self::Initial => true,
            Self::Since {
                expanded_timeline,
                widened,
                ..
            } => *expanded_timeline || !widened.is_empty(),
        }
    }
}

/// The entries of `new` that `old` did not already ask for. An entry is
/// covered by an old one naming the same type or `*`, and the same key or
/// `*`; `$ME` and `$LAZY` are keys like any other here, so only a wildcard
/// or the same placeholder covers them.
#[must_use]
pub fn widened(old: &[(String, String)], new: &[(String, String)]) -> RequiredState {
    new.iter()
        .filter(|(event_type, state_key)| {
            !old.iter().any(|(old_type, old_key)| {
                (old_type == "*" || old_type == event_type)
                    && (old_key == "*" || old_key == state_key)
            })
        })
        .cloned()
        .collect()
}

/// How long a connection survives without a request. Element X polls with
/// a timeout of seconds while it is open; a connection idle this long
/// belongs to a client that will be answered `M_UNKNOWN_POS` and start over
/// with one window's worth of rooms, which costs it less than holding every
/// abandoned connection's room record costs the server.
pub const CONNECTION_IDLE_EXPIRY: Duration = Duration::from_secs(60 * 60);

/// The connections one device may hold at once. `conn_id` is the client's
/// to choose, so without a bound one device could grow the table without
/// end; Element X uses two. Past the bound the least recently used goes.
const CONNECTIONS_PER_DEVICE: usize = 16;

/// The positions one connection keeps. A request with `pos` acknowledges
/// that position and retires the rest, so normally two remain: the one the
/// client holds, which it may retry, and the answer in flight. Overlapping
/// requests (MSC4186 forbids them, but a cancelled one may still be
/// finishing) can add more until the client picks one.
const POSITIONS_PER_CONNECTION: usize = 4;

/// How often an access sweeps the table for idle connections.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Whose connection: the user, the device, and the request's `conn_id`.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub user_id: String,
    pub device_id: String,
    pub conn_id: String,
}

/// Every live connection's positions, in memory.
pub struct Connections {
    table: Mutex<Table>,
}

struct Table {
    connections: HashMap<ConnectionKey, Positions>,
    /// The next position number. One counter for the whole table, so a
    /// `pos` never names a position of another connection's numbering.
    next: u64,
    swept: Instant,
}

struct Positions {
    held: Vec<(u64, Arc<Connection>)>,
    used: Instant,
}

impl Default for Connections {
    fn default() -> Self {
        Self::new()
    }
}

impl Connections {
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: Mutex::new(Table {
                connections: HashMap::new(),
                next: 1,
                swept: Instant::now(),
            }),
        }
    }

    /// What connection `key` held at `pos`, retiring every other position
    /// of it: the client has processed the response that carried `pos`, so
    /// an older one is behind it, and a newer one answered a request whose
    /// response it never processed. `None` is `M_UNKNOWN_POS`: a `pos`
    /// this connection does not hold, never held, or held before it expired.
    pub fn resume(&self, key: &ConnectionKey, pos: &str, now: Instant) -> Option<Arc<Connection>> {
        let (stream, number) = parse_pos(pos)?;
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.sweep(now);
        let positions = table.connections.get_mut(key)?;
        if now.saturating_duration_since(positions.used) > CONNECTION_IDLE_EXPIRY {
            table.connections.remove(key);
            return None;
        }
        let state = positions
            .held
            .iter()
            .find(|(held, state)| *held == number && state.stream == stream)
            .map(|(_, state)| Arc::clone(state))?;
        positions.held.retain(|(held, _)| *held == number);
        positions.used = now;
        Some(state)
    }

    /// Keep `state` as a new position of connection `key`, and return the
    /// `pos` that names it. `fresh` -- a request without `pos` -- starts the
    /// connection over, dropping whatever it held.
    pub fn record(
        &self,
        key: ConnectionKey,
        state: Connection,
        fresh: bool,
        now: Instant,
    ) -> String {
        let stream = state.stream;
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        table.sweep(now);
        let number = table.next;
        table.next += 1;
        if !table.connections.contains_key(&key) {
            table.make_room_for(&key);
        }
        let positions = table.connections.entry(key).or_insert_with(|| Positions {
            held: Vec::new(),
            used: now,
        });
        if fresh {
            positions.held.clear();
        }
        positions.held.push((number, Arc::new(state)));
        if positions.held.len() > POSITIONS_PER_CONNECTION {
            positions.held.remove(0);
        }
        positions.used = now;
        format_pos(stream, number)
    }
}

impl Table {
    fn sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.swept) < SWEEP_INTERVAL {
            return;
        }
        self.connections.retain(|_, positions| {
            now.saturating_duration_since(positions.used) <= CONNECTION_IDLE_EXPIRY
        });
        self.swept = now;
    }

    /// Evict the device's least recently used connection if `key` would be
    /// one too many.
    fn make_room_for(&mut self, key: &ConnectionKey) {
        let same_device = |other: &ConnectionKey| {
            other.user_id == key.user_id && other.device_id == key.device_id
        };
        let held = self
            .connections
            .keys()
            .filter(|other| same_device(other))
            .count();
        if held < CONNECTIONS_PER_DEVICE {
            return;
        }
        if let Some(oldest) = self
            .connections
            .iter()
            .filter(|(other, _)| same_device(other))
            .min_by_key(|(_, positions)| positions.used)
            .map(|(other, _)| other.clone())
        {
            self.connections.remove(&oldest);
        }
    }
}

/// `s{stream}.{position}`: the stream position the response answered at,
/// then the connection position. Only the second identifies anything; the
/// first is checked against it, so a position number reused after a
/// restart cannot pass for the old one, and it makes the token readable in
/// a log.
fn format_pos(stream: u64, number: u64) -> String {
    format!("{}.{number}", crate::tokens::Sync(stream))
}

fn parse_pos(pos: &str) -> Option<(u64, u64)> {
    let (stream, number) = pos.split_once('.')?;
    let crate::tokens::Sync(stream) = stream.parse().ok()?;
    Some((stream, number.parse().ok()?))
}

/// Whether `required_state` asks for this `(type, state_key)`.
///
/// `["*", "*"]` is everything; `["m.room.member", "*"]` is every member;
/// `["m.room.member", "$ME"]` is the asking user's own membership, which is
/// how Element X asks for exactly the memberships it can render. `$LAZY`
/// (the senders in the timeline window) is expanded to concrete keys by
/// the caller before this is asked. An empty list is *nothing*, not
/// everything — a client that wants no state says so by saying nothing,
/// and the timeline is unaffected either way.
#[must_use]
pub fn wants_state(
    required: &[(String, String)],
    viewer: &str,
    event_type: &str,
    state_key: &str,
) -> bool {
    required.iter().any(|(wanted_type, wanted_key)| {
        let type_matches = wanted_type == "*" || wanted_type == event_type;
        let key = if wanted_key == "$ME" {
            viewer
        } else {
            wanted_key
        };
        type_matches && (key == "*" || key == state_key)
    })
}

/// MSC4186 `heroes`: up to five members other than `viewer`, each as
/// `{user_id, name?, avatar?}` from their own member event. Six candidates
/// come in so that leaving the viewer out still leaves five.
#[must_use]
pub fn heroes(candidates: &[crate::rooms::Hero], viewer: &str) -> Vec<Value> {
    candidates
        .iter()
        .filter(|hero| hero.user_id != viewer)
        .take(5)
        .map(|hero| {
            let mut entry = Map::new();
            entry.insert("user_id".to_owned(), json!(hero.user_id));
            if let Some(name) = &hero.displayname {
                entry.insert("name".to_owned(), json!(name));
            }
            if let Some(avatar) = &hero.avatar_url {
                entry.insert("avatar".to_owned(), json!(avatar));
            }
            Value::Object(entry)
        })
        .collect()
}

/// Clip `ranges` to a list of `len` rooms, yielding the indices in view.
///
/// Ranges are inclusive on both ends, as the MSC writes them. Out-of-bounds
/// ends are clipped rather than refused: the client's window is sized by its
/// screen, not by how many rooms exist, and a request for rooms 0–19 of a
/// 3-room account means the 3 rooms.
#[must_use]
pub fn indices_in_view(ranges: &[(usize, usize)], len: usize) -> Vec<usize> {
    let mut indices = Vec::new();
    for &(start, end) in ranges {
        for index in start..=end.min(len.saturating_sub(1)) {
            if index < len && !indices.contains(&index) {
                indices.push(index);
            }
        }
        if len == 0 {
            break;
        }
    }
    indices
}

/// A room's badge for the reader: unread events that notify, and the
/// highlights among them.
#[derive(Clone, Copy)]
pub struct Counts {
    pub notification_count: usize,
    pub highlight_count: usize,
}

/// One room's timeline window, as the caller fetched it.
pub struct Timeline {
    pub events: Vec<Value>,
    pub limited: bool,
    /// Where the window begins, as a `/messages` token (#331); `None` for an
    /// empty window.
    pub prev_batch: Option<String>,
    /// The window reaches back past what the connection already sent,
    /// because the timeline limit grew (MSC4186 `expanded_timeline`).
    pub expanded: bool,
}

/// What a room-list row is drawn from when the room has no name: the
/// members' own names and avatars, the room's avatar, and who is invited.
/// MSC4186 sends these beside the counts so a client need not ask for every
/// member's state to label a direct chat.
pub struct Summary {
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub joined_count: usize,
    pub invited_count: usize,
    /// Up to five members other than the viewer, joined first.
    pub heroes: Vec<Value>,
    /// The room's recency, comparable across rooms: the timestamp of its
    /// newest event. A client sorts its list by this without a timeline.
    pub bump_stamp: i64,
}

/// The `rooms` entry for one room, from the pieces the caller fetched.
#[must_use]
pub fn room_entry(
    summary: Summary,
    required_state: Vec<Value>,
    timeline: Timeline,
    unread: Counts,
    initial: bool,
) -> Value {
    let mut entry = Map::new();
    if let Some(name) = summary.name {
        entry.insert("name".to_owned(), json!(name));
    }
    if let Some(avatar) = summary.avatar {
        entry.insert("avatar".to_owned(), json!(avatar));
    }
    entry.insert("heroes".to_owned(), Value::Array(summary.heroes));
    entry.insert("invited_count".to_owned(), json!(summary.invited_count));
    entry.insert("bump_stamp".to_owned(), json!(summary.bump_stamp));
    entry.insert("required_state".to_owned(), Value::Array(required_state));
    entry.insert("timeline".to_owned(), Value::Array(timeline.events));
    entry.insert("limited".to_owned(), json!(timeline.limited));
    if let Some(prev_batch) = timeline.prev_batch {
        entry.insert("prev_batch".to_owned(), json!(prev_batch));
    }
    if timeline.expanded {
        // Synapse's spelling, which matrix-rust-sdk reads, and the MSC's.
        entry.insert("unstable_expanded_timeline".to_owned(), json!(true));
        entry.insert("expanded_timeline".to_owned(), json!(true));
    }
    entry.insert("joined_count".to_owned(), json!(summary.joined_count));
    entry.insert(
        "notification_count".to_owned(),
        json!(unread.notification_count),
    );
    entry.insert("highlight_count".to_owned(), json!(unread.highlight_count));
    // `initial: true` marks a room sent in full, so a client knows to replace
    // its copy rather than apply a delta: a room the connection never sent,
    // or one it sent as an invite. The caller decides, this records it.
    entry.insert("initial".to_owned(), json!(initial));
    Value::Object(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_inclusive_and_clipped() {
        assert_eq!(indices_in_view(&[(0, 2)], 10), vec![0, 1, 2]);
        assert_eq!(indices_in_view(&[(0, 19)], 3), vec![0, 1, 2]);
        assert_eq!(indices_in_view(&[(0, 0)], 0), Vec::<usize>::new());
        // Two ranges, overlapping: each index once.
        assert_eq!(indices_in_view(&[(0, 2), (2, 4)], 10), vec![0, 1, 2, 3, 4]);
    }

    fn request(body: Value) -> SlidingRequest {
        serde_json::from_value(body).unwrap()
    }

    fn pairs(pairs: &[(&str, &str)]) -> RequiredState {
        pairs
            .iter()
            .map(|(event_type, state_key)| ((*event_type).to_owned(), (*state_key).to_owned()))
            .collect()
    }

    #[test]
    fn parameters_left_out_keep_their_previous_values() {
        let first = request(json!({
            "lists": { "all": { "ranges": [[0, 9]], "required_state": [["m.room.name", ""]], "timeline_limit": 1 } },
            "room_subscriptions": { "!a:x": { "timeline_limit": 20 } },
            "extensions": { "typing": { "enabled": true, "lists": ["all"] }, "to_device": { "enabled": true, "since": "s4" } },
        }))
        .params(None)
        .unwrap();
        assert_eq!(
            first.extensions.to_device.since, None,
            "a token is not a parameter"
        );

        // No lists, no subscriptions, no extensions: all of them stand.
        let silent = request(json!({})).params(Some(&first)).unwrap();
        assert_eq!(silent, first);

        // A list named again with one field: the others stand.
        let grown = request(json!({ "lists": { "all": { "ranges": [[0, 99]] } } }))
            .params(Some(&first))
            .unwrap();
        assert_eq!(grown.lists["all"].ranges, vec![(0, 99)]);
        assert_eq!(
            grown.lists["all"].required_state,
            pairs(&[("m.room.name", "")])
        );
        assert_eq!(grown.lists["all"].timeline_limit, 1);
        assert_eq!(grown.subscriptions, first.subscriptions);

        // Lists sent: a list not named is gone.
        let other = request(json!({ "lists": { "dms": { "ranges": [[0, 0]] } } }))
            .params(Some(&first))
            .unwrap();
        assert_eq!(other.lists.keys().collect::<Vec<_>>(), vec!["dms"]);

        // An extension field sent overrides that field alone.
        let off = request(json!({ "extensions": { "typing": { "enabled": false } } }))
            .params(Some(&first))
            .unwrap();
        assert!(!off.extensions.typing.on());
        assert_eq!(off.extensions.typing.lists, Some(vec!["all".to_owned()]));
        assert!(off.extensions.to_device.on());

        let gone = request(json!({ "unsubscribe_rooms": ["!a:x"] }))
            .params(Some(&first))
            .unwrap();
        assert!(gone.subscriptions.is_empty());
    }

    #[test]
    fn an_extension_speaks_about_the_lists_and_rooms_it_names() {
        let windows: BTreeMap<String, Vec<String>> = [
            ("all".to_owned(), vec!["!a:x".to_owned(), "!b:x".to_owned()]),
            ("dms".to_owned(), vec!["!c:x".to_owned()]),
        ]
        .into();
        let subscribed = vec!["!d:x".to_owned(), "!e:x".to_owned()];
        let scope = |extension: Value| -> Vec<String> {
            let extension: RoomExtension = serde_json::from_value(extension).unwrap();
            extension
                .scope(&windows, &subscribed)
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(
            scope(json!({})),
            vec!["!a:x", "!b:x", "!c:x", "!d:x", "!e:x"],
            "unscoped is everything in view"
        );
        assert_eq!(
            scope(json!({ "lists": ["dms"], "rooms": [] })),
            vec!["!c:x"]
        );
        assert_eq!(
            scope(json!({ "lists": [], "rooms": ["!e:x", "!nowhere:x"] })),
            vec!["!e:x"],
            "a room no subscription names is not in scope"
        );
        assert_eq!(
            scope(json!({ "lists": ["*"], "rooms": [] })),
            vec!["!a:x", "!b:x", "!c:x"]
        );
    }

    #[test]
    fn a_room_is_judged_by_what_the_client_holds() {
        let held = SentRoom {
            at: 7,
            config: Arc::new(RoomConfig {
                required_state: pairs(&[("m.room.name", ""), ("m.room.member", "*")]),
                timeline_limit: 1,
            }),
            invite: false,
        };
        let config = |required: &[(&str, &str)], limit| RoomConfig {
            required_state: pairs(required),
            timeline_limit: limit,
        };
        assert_eq!(
            Need::of(None, &config(&[], 1), false),
            Need::Initial,
            "never sent"
        );
        assert_eq!(
            Need::of(
                Some(&SentRoom {
                    invite: true,
                    ..held.clone()
                }),
                &config(&[], 1),
                false
            ),
            Need::Initial,
            "sent as an invite, joined since"
        );
        let same = Need::of(Some(&held), &held.config, false);
        assert_eq!(
            same,
            Need::Since {
                since: 7,
                expanded_timeline: false,
                widened: Vec::new()
            }
        );
        assert!(!same.forced());
        // Narrower is not wider; a member key is covered by the wildcard.
        assert!(!Need::of(Some(&held), &config(&[("m.room.member", "$ME")], 1), false).forced());
        let wider = Need::of(
            Some(&held),
            &config(&[("m.room.name", ""), ("m.room.topic", "")], 1),
            false,
        );
        assert_eq!(
            wider,
            Need::Since {
                since: 7,
                expanded_timeline: false,
                widened: pairs(&[("m.room.topic", "")])
            }
        );
        assert!(wider.forced());
        let longer = Need::of(Some(&held), &config(&[("m.room.name", "")], 20), false);
        assert!(matches!(
            longer,
            Need::Since {
                expanded_timeline: true,
                ..
            }
        ));
        assert!(longer.forced());
    }

    fn key(conn_id: &str) -> ConnectionKey {
        ConnectionKey {
            user_id: "@a:x".to_owned(),
            device_id: "DEV".to_owned(),
            conn_id: conn_id.to_owned(),
        }
    }

    fn at(stream: u64) -> Connection {
        Connection {
            stream,
            ..Connection::default()
        }
    }

    #[test]
    fn a_pos_names_one_position_of_one_connection() {
        let connections = Connections::new();
        let now = Instant::now();
        let first = connections.record(key("list"), at(3), true, now);
        assert!(first.starts_with("s3."), "{first}");
        assert_eq!(
            connections
                .resume(&key("list"), &first, now)
                .unwrap()
                .stream,
            3
        );

        // Another connection of the same device, another device, a forged
        // stream position, garbage and a pos from before connections: unknown.
        assert!(connections.resume(&key("other"), &first, now).is_none());
        let elsewhere = ConnectionKey {
            device_id: "OTHER".to_owned(),
            ..key("list")
        };
        assert!(connections.resume(&elsewhere, &first, now).is_none());
        let number = first.split_once('.').unwrap().1;
        assert!(
            connections
                .resume(&key("list"), &format!("s4.{number}"), now)
                .is_none()
        );
        assert!(connections.resume(&key("list"), "s3", now).is_none());
        assert!(connections.resume(&key("list"), "s3.7b7d", now).is_none());

        // The answer to `first` is not processed until the client sends it;
        // retrying `first` still works, and then the unprocessed answer is
        // retired.
        let second = connections.record(key("list"), at(5), false, now);
        assert!(connections.resume(&key("list"), &first, now).is_some());
        assert!(connections.resume(&key("list"), &second, now).is_none());

        // Acknowledging a newer position retires the older one.
        let third = connections.record(key("list"), at(6), false, now);
        assert!(connections.resume(&key("list"), &third, now).is_some());
        assert!(connections.resume(&key("list"), &first, now).is_none());

        // Starting over without `pos` forgets everything held.
        connections.record(key("list"), at(7), true, now);
        assert!(connections.resume(&key("list"), &third, now).is_none());
    }

    #[test]
    fn an_idle_connection_expires() {
        let connections = Connections::new();
        let start = Instant::now();
        let pos = connections.record(key("list"), at(3), true, start);
        let soon = start + CONNECTION_IDLE_EXPIRY / 2;
        assert!(connections.resume(&key("list"), &pos, soon).is_some());
        // Idle is counted from the last use, not from creation.
        let later = soon + CONNECTION_IDLE_EXPIRY;
        assert!(connections.resume(&key("list"), &pos, later).is_some());
        let too_late = later + CONNECTION_IDLE_EXPIRY + Duration::from_secs(1);
        assert!(connections.resume(&key("list"), &pos, too_late).is_none());
    }

    #[test]
    fn a_device_holds_a_bounded_number_of_connections() {
        let connections = Connections::new();
        let start = Instant::now();
        let mut tokens = Vec::new();
        for index in 0..=CONNECTIONS_PER_DEVICE {
            let now = start + Duration::from_secs(u64::try_from(index).unwrap());
            tokens.push(connections.record(key(&index.to_string()), at(1), true, now));
        }
        let now = start + Duration::from_secs(100);
        assert!(
            connections.resume(&key("0"), &tokens[0], now).is_none(),
            "the least recently used went"
        );
        assert!(connections.resume(&key("1"), &tokens[1], now).is_some());
        let newest = CONNECTIONS_PER_DEVICE;
        assert!(
            connections
                .resume(&key(&newest.to_string()), &tokens[newest], now)
                .is_some()
        );
    }

    #[test]
    fn required_state_wildcards() {
        let all = vec![("*".to_owned(), "*".to_owned())];
        assert!(wants_state(&all, "@a:x", "m.room.name", ""));
        assert!(wants_state(&all, "@a:x", "m.room.member", "@b:x"));

        let members = vec![("m.room.member".to_owned(), "*".to_owned())];
        assert!(wants_state(&members, "@a:x", "m.room.member", "@b:x"));
        assert!(!wants_state(&members, "@a:x", "m.room.name", ""));

        let me = vec![("m.room.member".to_owned(), "$ME".to_owned())];
        assert!(wants_state(&me, "@a:x", "m.room.member", "@a:x"));
        assert!(!wants_state(&me, "@a:x", "m.room.member", "@b:x"));

        // Empty means nothing, not everything.
        assert!(!wants_state(&[], "@a:x", "m.room.name", ""));
    }
}
