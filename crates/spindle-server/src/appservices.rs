//! Application services: bridges and bots with a skeleton key.
//!
//! An appservice is a client whose token authenticates *a namespace of
//! users* rather than one account. The registration file (YAML, by spec)
//! is the whole contract: the `as_token` the service presents to us, the
//! `hs_token` we will present to it, the localpart it acts as by default,
//! and the regex namespaces inside which it may masquerade as anyone.
//!
//! Registrations load once at startup and a bad file is startup-fatal —
//! a bridge that silently failed to register would look exactly like a
//! bridge receiving nothing, which is the failure mode worth the loudest
//! possible error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use spindle_store::{FjallStore, ReadView, Store};

use crate::rooms::Rooms;

/// One namespace claim: a regex over full IDs, and whether the claim is
/// exclusive to this service.
#[derive(Debug, Clone, Deserialize)]
pub struct Namespace {
    #[serde(default)]
    pub exclusive: bool,
    pub regex: String,
    #[serde(skip)]
    compiled: Option<Regex>,
}

impl Namespace {
    fn compile(&mut self) -> Result<(), AppserviceError> {
        // Anchored per spec: a namespace regex matches the whole ID, and
        // an unanchored one would quietly claim every user whose name
        // merely *contains* the pattern.
        let anchored = format!("^(?:{})$", self.regex);
        self.compiled =
            Some(Regex::new(&anchored).map_err(|error| {
                AppserviceError::BadRegex(self.regex.clone(), error.to_string())
            })?);
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, id: &str) -> bool {
        self.compiled
            .as_ref()
            .is_some_and(|regex| regex.is_match(id))
    }
}

/// The three namespace families a registration may claim.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Namespaces {
    #[serde(default)]
    pub users: Vec<Namespace>,
    #[serde(default)]
    pub aliases: Vec<Namespace>,
    #[serde(default)]
    pub rooms: Vec<Namespace>,
}

/// One appservice, as its registration file declares it.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags mirror the registration file's wire format, one per MSC"
)]
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub id: String,
    /// Where transactions get pushed; `None` (or explicit null) means the
    /// service only ever acts through the CS API and receives nothing.
    #[serde(default)]
    pub url: Option<String>,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: Namespaces,
    /// `false` exempts the service from rate limits; the default is the
    /// spec's: limited like anyone else.
    #[serde(default = "default_rate_limited")]
    pub rate_limited: bool,
    /// MSC2409, stable in the spec: whether transactions also carry
    /// ephemeral data (typing, for now) for the service's rooms. Opt-in
    /// because a bridge that never asked would have to parse and discard
    /// a stream of second-by-second presence noise. The unstable names
    /// are what shipping bridge registrations still write.
    #[serde(
        default,
        alias = "de.sorunome.msc2409.push_ephemeral",
        alias = "push_ephemeral"
    )]
    pub receive_ephemeral: bool,
    /// MSC4190: the service manages devices itself. Registration mints
    /// no session (the `as_token` is the only credential), and the
    /// service creates and deletes devices through `PUT`/`DELETE
    /// /devices/{deviceId}` under masquerade. The unstable name is
    /// accepted because that is what shipping bridges still write.
    #[serde(default, alias = "io.element.msc4190")]
    pub device_management: bool,
    /// MSC3202: transactions also carry device-list changes for users
    /// the service is interested in, and one-time-key counts for its own
    /// ghosts' devices — the signal an encrypting bridge replenishes
    /// keys on. The unstable name is what shipping bridges write.
    #[serde(default, alias = "org.matrix.msc3202")]
    pub receive_device_lists: bool,
}

fn default_rate_limited() -> bool {
    true
}

impl Registration {
    /// The user the service acts as when it does not masquerade.
    #[must_use]
    pub fn sender_user(&self, server_name: &str) -> String {
        format!("@{}:{server_name}", self.sender_localpart)
    }

    /// Whether the service may act as `user_id`: its own sender, or
    /// anyone inside its user namespaces.
    #[must_use]
    pub fn may_masquerade_as(&self, user_id: &str, server_name: &str) -> bool {
        user_id == self.sender_user(server_name)
            || self
                .namespaces
                .users
                .iter()
                .any(|namespace| namespace.matches(user_id))
    }

    /// Whether this registration *exclusively* claims `user_id`. The
    /// to-device push runs behind this rather than plain namespace
    /// membership: delivered rows are deleted on acknowledgement, and
    /// only a user who exists solely through the service has no syncing
    /// client whose mail we would be eating.
    #[must_use]
    pub fn exclusively_claims(&self, user_id: &str) -> bool {
        self.namespaces
            .users
            .iter()
            .any(|namespace| namespace.exclusive && namespace.matches(user_id))
    }

    /// Whether the service hears about an event: its sender or any joined
    /// member inside the user namespaces (the sender user included), or
    /// the room itself inside the room namespaces.
    ///
    /// Alias namespaces deliberately do not gate the push — deciding
    /// interest by alias would mean resolving every event's room against
    /// the directory on the hot path, and a service that cares about a
    /// room it aliased is in that room through a namespace user anyway.
    #[must_use]
    pub fn wants_event(
        &self,
        room_id: &str,
        sender: &str,
        members: &[String],
        server_name: &str,
    ) -> bool {
        self.may_masquerade_as(sender, server_name)
            || self
                .namespaces
                .rooms
                .iter()
                .any(|namespace| namespace.matches(room_id))
            || members
                .iter()
                .any(|member| self.may_masquerade_as(member, server_name))
    }
}

/// Why registrations could not be loaded. All startup-fatal.
#[derive(Debug)]
pub enum AppserviceError {
    Unreadable(String, String),
    Invalid(String, String),
    BadRegex(String, String),
    /// Two registrations share an `id` or an `as_token` — either would
    /// make "which service is this?" ambiguous at auth time.
    Duplicate(String),
}

impl std::fmt::Display for AppserviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(path, error) => write!(f, "{path}: {error}"),
            Self::Invalid(path, error) => write!(f, "{path} does not parse: {error}"),
            Self::BadRegex(regex, error) => write!(f, "namespace regex {regex:?}: {error}"),
            Self::Duplicate(what) => write!(f, "duplicate registration {what}"),
        }
    }
}

/// Every registered appservice, indexed for the auth path.
#[derive(Default)]
pub struct Appservices {
    list: Vec<Arc<Registration>>,
}

impl Appservices {
    /// Load and validate every registration file named in the config.
    ///
    /// # Errors
    ///
    /// Returns [`AppserviceError`] on the first unreadable, unparseable or
    /// ambiguous registration — startup-fatal by design.
    pub fn load(paths: &[String]) -> Result<Self, AppserviceError> {
        let mut list: Vec<Arc<Registration>> = Vec::new();
        for path in paths {
            let raw = std::fs::read_to_string(path)
                .map_err(|error| AppserviceError::Unreadable(path.clone(), error.to_string()))?;
            let mut registration: Registration = serde_yaml::from_str(&raw)
                .map_err(|error| AppserviceError::Invalid(path.clone(), error.to_string()))?;
            for namespace in registration
                .namespaces
                .users
                .iter_mut()
                .chain(registration.namespaces.aliases.iter_mut())
                .chain(registration.namespaces.rooms.iter_mut())
            {
                namespace.compile()?;
            }
            if list.iter().any(|existing| {
                existing.id == registration.id || existing.as_token == registration.as_token
            }) {
                return Err(AppserviceError::Duplicate(registration.id));
            }
            list.push(Arc::new(registration));
        }
        Ok(Self { list })
    }

    /// The registration presenting `as_token`, if any.
    #[must_use]
    pub fn by_token(&self, token: &str) -> Option<&Arc<Registration>> {
        self.list
            .iter()
            .find(|registration| registration.as_token == token)
    }

    /// Every registration, for iteration by the transaction push.
    #[must_use]
    pub fn all(&self) -> &[Arc<Registration>] {
        &self.list
    }

    /// Whether any service holds an *exclusive* users-namespace claim on
    /// `user_id`. Exclusivity is a reservation against everyone else:
    /// ordinary registration must refuse the name, or the service arrives
    /// to find its namespace squatted.
    #[must_use]
    pub fn exclusively_claims(&self, user_id: &str) -> bool {
        self.list
            .iter()
            .any(|registration| registration.exclusively_claims(user_id))
    }

    /// The service (with a URL) that *exclusively* claims `user_id`, if
    /// any — the gate MSC3983/3984 key proxying runs behind. Exclusive,
    /// because that is the claim "these accounts exist only through me",
    /// which is exactly when the homeserver's own key tables can be
    /// empty while the service's are not.
    #[must_use]
    pub fn exclusive_claimant(&self, user_id: &str) -> Option<&Arc<Registration>> {
        self.list.iter().find(|registration| {
            registration.url.is_some() && registration.exclusively_claims(user_id)
        })
    }

    /// The classic user query: ask the services claiming `user_id`
    /// whether it exists (`GET {url}/_matrix/app/v1/users/{userId}`).
    ///
    /// A 200 is the service saying "it does now" — the expected
    /// implementation provisions the ghost through the register endpoint
    /// before answering. Returns whether any claimant said yes; when no
    /// service claims the ID this returns false without a request, so
    /// the common path costs nothing.
    pub async fn query_user(&self, user_id: &str, server_name: &str) -> bool {
        let client = reqwest::Client::new();
        for registration in &self.list {
            let Some(url) = &registration.url else {
                continue;
            };
            if !registration.may_masquerade_as(user_id, server_name) {
                continue;
            }
            if query_existence(&client, url, &registration.hs_token, "users", user_id).await {
                return true;
            }
        }
        false
    }

    /// The room-alias twin (`GET {url}/_matrix/app/v1/rooms/{roomAlias}`):
    /// a 200 means the service has created the room and mapped the alias,
    /// so a re-resolution will find it.
    pub async fn query_alias(&self, alias: &str) -> bool {
        let client = reqwest::Client::new();
        for registration in &self.list {
            let Some(url) = &registration.url else {
                continue;
            };
            if !registration
                .namespaces
                .aliases
                .iter()
                .any(|namespace| namespace.matches(alias))
            {
                continue;
            }
            if query_existence(&client, url, &registration.hs_token, "rooms", alias).await {
                return true;
            }
        }
        false
    }
}

/// One MSC3983/3984 proxy call: POST `body` to the service's unstable
/// `endpoint`, answering `{}` on any failure — the callers' own
/// absence-handling (fallback keys, "unknown device") already covers an
/// empty answer, so a broken bridge degrades to exactly the behaviour
/// the server had before these MSCs existed.
async fn proxy_post(registration: &Registration, endpoint: &str, body: &Value) -> Value {
    let Some(url) = &registration.url else {
        return serde_json::json!({});
    };
    let target = format!(
        "{}/_matrix/app/v1/unstable/{endpoint}",
        url.trim_end_matches('/')
    );
    let response = reqwest::Client::new()
        .post(target)
        .header("authorization", format!("Bearer {}", registration.hs_token))
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(10))
        .body(body.to_string())
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_else(|| serde_json::json!({})),
        _ => serde_json::json!({}),
    }
}

/// MSC3983: ask the claiming service for one-time keys the homeserver
/// does not hold. `wanted` maps device to a *list* of algorithms, per
/// the MSC; the answer is the claim response's `one_time_keys` shape.
pub async fn proxy_otk_claim(registration: &Registration, wanted: &Value) -> Value {
    let answer = proxy_post(registration, "org.matrix.msc3983/keys/claim", wanted).await;
    // Tolerate both the bare map and a wrapped `one_time_keys` — the MSC
    // says bare, some implementations echo the claim response.
    if answer.get("one_time_keys").is_some() {
        answer["one_time_keys"].clone()
    } else {
        answer
    }
}

/// MSC3984: ask the claiming service to answer a `/keys/query` for its
/// own users. The request and the useful part of the response are the
/// endpoint's own `device_keys` shape.
pub async fn proxy_key_query(registration: &Registration, device_keys: &Value) -> Value {
    let answer = proxy_post(
        registration,
        "org.matrix.msc3984/keys/query",
        &serde_json::json!({ "device_keys": device_keys }),
    )
    .await;
    answer["device_keys"].clone()
}

/// One existence probe. `id` is percent-encoded for the path — an alias
/// starts with `#`, which unencoded would become a URL fragment and the
/// service would see a request for nothing.
async fn query_existence(
    client: &reqwest::Client,
    url: &str,
    hs_token: &str,
    kind: &str,
    id: &str,
) -> bool {
    let encoded = id
        .replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F");
    let target = format!(
        "{}/_matrix/app/v1/{kind}/{encoded}",
        url.trim_end_matches('/')
    );
    client
        .get(target)
        .header("authorization", format!("Bearer {hs_token}"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

/// At most this many events ride one transaction; the rest wait for the
/// next pass. The cap bounds the request the receiving bridge has to
/// swallow, not our scan — `stream_events` stops reading at the cap too.
const TRANSACTION_LIMIT: usize = 100;

/// One computed-but-unacknowledged transaction: its ID, its events, and
/// the stream position an acknowledgement advances the cursor to.
///
/// Held in memory until delivered so that every retry re-sends *this*
/// batch under *this* ID — recomputing on retry would fold newly arrived
/// events into the batch and change the ID, and the service's replay
/// table can only absorb a duplicate that is actually a duplicate. A
/// crash loses the struct and recomputes from the durable cursor, which
/// re-delivers under a fresh ID: at-least-once, exactly as promised.
struct PendingPush {
    txn_id: String,
    events: Vec<Value>,
    /// MSC2409 ephemeral riders, pinned with the batch: a transaction is
    /// immutable once its ID is assigned, retries included.
    ephemeral: Vec<Value>,
    /// MSC3202: users whose device lists changed in the batch's range.
    /// Cursor-advancing like events — a missed change means encrypting
    /// to a stale device set, so it gets at-least-once, not fire-once.
    device_lists_changed: Vec<String>,
    /// MSC3202: `{user: {device: {algorithm: count}}}` for the service's
    /// key-holding ghost devices in the batch's rooms.
    otk_counts: Value,
    /// MSC3202: the same shape over unused fallback key algorithms.
    fallback_keys: Value,
    /// MSC2409: to-device messages for the service's exclusive users,
    /// pinned with the batch like events. The rows behind them are
    /// deleted only on acknowledgement — for session-establishment
    /// ciphertext, redelivery is the correct side to err on.
    to_device: Vec<Value>,
    /// The store keys of those rows, for the acknowledgement delete.
    to_device_keys: Vec<Vec<u8>>,
    advance_to: u64,
}

/// The acknowledged stream position for one service, 0 for never-pushed.
fn read_cursor(store: &FjallStore, appservice_id: &str) -> u64 {
    ReadView::get(store, &spindle_core::keys::appservice_cursor(appservice_id))
        .ok()
        .flatten()
        .and_then(|raw| raw.get(..8).and_then(|bytes| bytes.try_into().ok()))
        .map_or(0, u64::from_be_bytes)
}

fn write_cursor(store: &FjallStore, appservice_id: &str, position: u64) {
    let _ = Store::put(
        store,
        &spindle_core::keys::appservice_cursor(appservice_id),
        &position.to_be_bytes(),
    );
}

/// The next batch for one service: interested events in
/// `(cursor, position]`, the rooms they came from, and the stream
/// position the batch covers.
fn collect_batch(
    rooms: &Rooms,
    registration: &Registration,
    server_name: &str,
    cursor: u64,
    position: u64,
) -> Result<(Vec<Value>, std::collections::BTreeSet<String>, u64), crate::rooms::RoomError> {
    let (records, advance_to) = rooms.stream_events(cursor, position, TRANSACTION_LIMIT)?;
    // Membership is asked once per room per batch, not once per event —
    // a busy room would otherwise pay a full member scan per message.
    let mut members_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut events = Vec::new();
    let mut batch_rooms = std::collections::BTreeSet::new();
    for (room_id, event) in records {
        let members = match members_of.entry(room_id.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                rooms
                    .joined_members(&room_id)
                    .map(|members| members.keys().cloned().collect())
                    .unwrap_or_default(),
            ),
        };
        let sender = event["sender"].as_str().unwrap_or_default();
        // A membership event *about* an interesting user is interesting,
        // whatever the sender: the invite that summons the service's bot
        // into a room is sent by a human, to a bot that is not a joined
        // member yet — the two checks below both miss it, and a bridge
        // that never hears its own invites can never join anything.
        // matrix-hookshot, invited and waiting forever, found this.
        let about_ours = event["type"] == "m.room.member"
            && event["state_key"]
                .as_str()
                .is_some_and(|user| registration.may_masquerade_as(user, server_name));
        if about_ours || registration.wants_event(&room_id, sender, members, server_name) {
            batch_rooms.insert(room_id);
            events.push(event);
        }
    }
    Ok((events, batch_rooms, advance_to))
}

/// Whether the service cares about `user_id`'s devices: its own
/// namespaces, or any room they share with the service's interest.
fn interesting_user(
    rooms: &Rooms,
    registration: &Registration,
    server_name: &str,
    user_id: &str,
) -> bool {
    if registration.may_masquerade_as(user_id, server_name) {
        return true;
    }
    let Ok(joined) = rooms.joined(user_id) else {
        return false;
    };
    joined.iter().any(|room_id| {
        let members: Vec<String> = rooms
            .joined_members(room_id)
            .map(|members| members.keys().cloned().collect())
            .unwrap_or_default();
        registration.wants_event(room_id, "", &members, server_name)
    })
}

/// MSC3202's key-count payloads for the service's ghost devices in the
/// batch's rooms: `{user: {device: {algorithm: count}}}` for one-time
/// keys, and the same shape over unused fallback algorithms.
///
/// Only devices that uploaded identity keys are reported — a device
/// without them has no E2E to replenish, and reporting zeros for every
/// ghost would drown the one zero that matters.
fn key_counts(
    store: &FjallStore,
    devices: &crate::devices::Devices,
    rooms: &Rooms,
    registration: &Registration,
    server_name: &str,
    batch_rooms: &std::collections::BTreeSet<String>,
) -> (Value, Value) {
    let accounts = crate::accounts::Accounts::new(store, server_name);
    let mut otk = serde_json::Map::new();
    let mut fallback = serde_json::Map::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for room_id in batch_rooms {
        let members: Vec<String> = rooms
            .joined_members(room_id)
            .map(|members| members.keys().cloned().collect())
            .unwrap_or_default();
        for user_id in members {
            if !registration.may_masquerade_as(&user_id, server_name)
                || !seen.insert(user_id.clone())
            {
                continue;
            }
            let Some(localpart) = user_id
                .strip_prefix('@')
                .and_then(|rest| rest.split(':').next())
            else {
                continue;
            };
            let Ok(user_devices) = accounts.devices_of(localpart) else {
                continue;
            };
            let mut user_otk = serde_json::Map::new();
            let mut user_fallback = serde_json::Map::new();
            for device in user_devices {
                if devices
                    .device_keys(&user_id, &device.device_id)
                    .ok()
                    .flatten()
                    .is_none()
                {
                    continue;
                }
                if let Ok(counts) = devices.one_time_key_counts(&user_id, &device.device_id) {
                    user_otk.insert(device.device_id.clone(), Value::Object(counts));
                }
                if let Ok(algorithms) =
                    devices.unused_fallback_algorithms(&user_id, &device.device_id)
                {
                    user_fallback.insert(device.device_id.clone(), serde_json::json!(algorithms));
                }
            }
            if !user_otk.is_empty() {
                otk.insert(user_id.clone(), Value::Object(user_otk));
            }
            if !user_fallback.is_empty() {
                fallback.insert(user_id.clone(), Value::Object(user_fallback));
            }
        }
    }
    (Value::Object(otk), Value::Object(fallback))
}

/// The typing changes a service has not yet been told about, as MSC2409
/// ephemeral events (`m.typing` with a `room_id`, `/sync`-shaped).
///
/// `last_sent` is what the service currently believes, per room; the
/// delta is every interested room where reality differs, including "the
/// last typist stopped" — announced exactly once, as an empty
/// `user_ids`, by removing the room from the map rather than storing an
/// empty entry that would never stop comparing equal.
fn typing_delta(
    typing: &crate::typing::Typing,
    rooms: &Rooms,
    registration: &Registration,
    server_name: &str,
    last_sent: &mut HashMap<String, Vec<String>>,
) -> Vec<Value> {
    let mut current: HashMap<String, Vec<String>> = HashMap::new();
    for (room_id, users) in typing.rooms_active() {
        let members: Vec<String> = rooms
            .joined_members(&room_id)
            .map(|members| members.keys().cloned().collect())
            .unwrap_or_default();
        // Sender "" matches nothing, so this is the membership and
        // room-namespace half of interest — exactly what an EDU has.
        if registration.wants_event(&room_id, "", &members, server_name) {
            current.insert(room_id, users);
        }
    }
    let mut out = Vec::new();
    let known: Vec<String> = last_sent.keys().cloned().collect();
    for room_id in current
        .keys()
        .cloned()
        .chain(known)
        .collect::<std::collections::BTreeSet<_>>()
    {
        let now = current.get(&room_id).cloned().unwrap_or_default();
        if last_sent.get(&room_id).cloned().unwrap_or_default() == now {
            continue;
        }
        out.push(serde_json::json!({
            "type": "m.typing",
            "room_id": room_id,
            "content": { "user_ids": now },
        }));
        if now.is_empty() {
            last_sent.remove(&room_id);
        } else {
            last_sent.insert(room_id, now);
        }
    }
    out
}

/// Deliver one transaction to the service's push URL.
async fn deliver(
    client: &reqwest::Client,
    url: &str,
    hs_token: &str,
    push: &PendingPush,
) -> Result<(), String> {
    let target = format!(
        "{}/_matrix/app/v1/transactions/{}",
        url.trim_end_matches('/'),
        push.txn_id
    );
    let mut body = serde_json::json!({ "events": push.events });
    // Only for services that opted in, and only when there is something
    // to say — MSC2409 has non-opted services never see the key at all,
    // and the MSC3202 payloads follow the same rule under their unstable
    // names, which are what shipping bridges parse.
    if !push.ephemeral.is_empty() {
        body["ephemeral"] = Value::Array(push.ephemeral.clone());
    }
    if !push.device_lists_changed.is_empty() {
        body["org.matrix.msc3202.device_lists"] = serde_json::json!({
            "changed": push.device_lists_changed,
            "left": [],
        });
    }
    if push
        .otk_counts
        .as_object()
        .is_some_and(|map| !map.is_empty())
    {
        body["org.matrix.msc3202.device_one_time_keys_count"] = push.otk_counts.clone();
    }
    if push
        .fallback_keys
        .as_object()
        .is_some_and(|map| !map.is_empty())
    {
        body["org.matrix.msc3202.device_unused_fallback_key_types"] = push.fallback_keys.clone();
    }
    if !push.to_device.is_empty() {
        body["to_device"] = Value::Array(push.to_device.clone());
    }
    let response = client
        .put(target)
        .header("authorization", format!("Bearer {hs_token}"))
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(30))
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("answered {}", response.status()));
    }
    Ok(())
}

/// Everything [`compute_pending`] reads, bundled so the loop body stays
/// a loop body.
struct PushSources<'a> {
    store: &'a FjallStore,
    devices: &'a crate::devices::Devices,
    rooms: &'a Rooms,
    typing: &'a crate::typing::Typing,
    server_name: &'a str,
}

/// The next transaction one service is owed, if any. Advances the cursor
/// durably past a range nothing in which interested the service — a
/// service whose rooms went quiet must not re-scan the same dead range
/// every pass, forever.
fn compute_pending(
    sources: &PushSources<'_>,
    registration: &Registration,
    typing_sent: &mut HashMap<String, Vec<String>>,
    ephemeral_txn: &mut u64,
) -> Option<PendingPush> {
    let cursor = read_cursor(sources.store, &registration.id);
    let position = sources.rooms.stream_position();
    let (events, batch_rooms, advance_to) = if position > cursor {
        collect_batch(
            sources.rooms,
            registration,
            sources.server_name,
            cursor,
            position,
        )
        .ok()?
    } else {
        (Vec::new(), std::collections::BTreeSet::new(), cursor)
    };
    let device_lists_changed: Vec<String> =
        if registration.receive_device_lists && advance_to > cursor {
            sources
                .devices
                .device_lists_changed(cursor, Some(advance_to))
                .unwrap_or_default()
                .into_iter()
                .filter(|user_id| {
                    interesting_user(sources.rooms, registration, sources.server_name, user_id)
                })
                .collect()
        } else {
            Vec::new()
        };
    if events.is_empty() && device_lists_changed.is_empty() && advance_to > cursor {
        write_cursor(sources.store, &registration.id, advance_to);
    }
    let (otk_counts, fallback_keys) =
        if registration.receive_device_lists && !batch_rooms.is_empty() {
            key_counts(
                sources.store,
                sources.devices,
                sources.rooms,
                registration,
                sources.server_name,
                &batch_rooms,
            )
        } else {
            (serde_json::json!({}), serde_json::json!({}))
        };
    let ephemeral = if registration.receive_ephemeral {
        typing_delta(
            sources.typing,
            sources.rooms,
            registration,
            sources.server_name,
            typing_sent,
        )
    } else {
        Vec::new()
    };
    // MSC2409's other half: queued to-device messages for users who exist
    // only through this service, shaped like sync's plus the MSC's
    // `to_user_id`/`to_device_id` so the bridge knows which ghost's inbox
    // each one is. Exclusive users only — these rows are deleted on
    // acknowledgement, and only a user with no syncing client has no
    // mail we could be eating.
    let mut to_device = Vec::new();
    let mut to_device_keys = Vec::new();
    if registration.receive_ephemeral && advance_to > cursor {
        for row in sources
            .devices
            .pending_to_device_in(cursor, advance_to)
            .unwrap_or_default()
        {
            if !registration.exclusively_claims(&row.user_id) {
                continue;
            }
            let mut message = row.message;
            message["to_user_id"] = Value::String(row.user_id);
            message["to_device_id"] = Value::String(row.device_id);
            to_device.push(message);
            to_device_keys.push(row.key);
        }
    }
    // A batch advances the cursor when it carries anything at-least-once:
    // events, a device-list change a bridge must not miss (encrypting to
    // a stale device set is the failure mode), or to-device ciphertext.
    // Typing alone stays fire-once.
    let advancing = !events.is_empty() || !device_lists_changed.is_empty() || !to_device.is_empty();
    if !advancing && ephemeral.is_empty() {
        return None;
    }
    let txn_id = if advancing {
        // Deterministic by range, not by attempt: the range is pinned
        // until acknowledged, so a retry reuses the ID and redelivery is
        // a no-op on the service.
        format!("s{}-{advance_to}", cursor + 1)
    } else {
        *ephemeral_txn += 1;
        format!("e{ephemeral_txn}")
    };
    Some(PendingPush {
        txn_id,
        advance_to: if advancing { advance_to } else { cursor },
        events,
        ephemeral,
        device_lists_changed,
        otk_counts,
        fallback_keys,
        to_device,
        to_device_keys,
    })
}

/// Push transactions to every service with a URL, forever.
///
/// The same polling shape as the federation outbox drain, and for the
/// same reason: the empty-case scan is a bounded read, and the poll
/// interval doubles as the floor of the retry backoff. The cursor row
/// advances only on acknowledgement; a batch nothing in which interested
/// the service still advances the cursor durably — otherwise a service
/// whose rooms went quiet would re-scan the same dead range every pass,
/// forever.
pub async fn push_loop(
    store: Arc<FjallStore>,
    appservices: Arc<Appservices>,
    rooms: Arc<Rooms>,
    typing: Arc<crate::typing::Typing>,
    devices: Arc<crate::devices::Devices>,
    server_name: String,
    retry_base: Duration,
) {
    let client = reqwest::Client::new();
    let sources = PushSources {
        store: &store,
        devices: &devices,
        rooms: &rooms,
        typing: &typing,
        server_name: &server_name,
    };
    let mut pending: HashMap<String, PendingPush> = HashMap::new();
    let mut backoff: HashMap<String, (u32, std::time::Instant)> = HashMap::new();
    // What each opted-in service believes about who is typing where.
    let mut typing_sent: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    // Ephemeral-only transactions are fire-once, so their IDs only owe
    // anyone uniqueness — same rule as the federation outbox's EDU IDs.
    let mut ephemeral_txn = 0_u64;
    loop {
        tokio::time::sleep(
            retry_base
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
        )
        .await;
        for registration in appservices.all() {
            let Some(url) = &registration.url else {
                continue;
            };
            if let Some((_, until)) = backoff.get(&registration.id)
                && *until > std::time::Instant::now()
            {
                continue;
            }
            if !pending.contains_key(&registration.id)
                && let Some(push) = compute_pending(
                    &sources,
                    registration,
                    typing_sent.entry(registration.id.clone()).or_default(),
                    &mut ephemeral_txn,
                )
            {
                pending.insert(registration.id.clone(), push);
            }
            let Some(push) = pending.get(&registration.id) else {
                continue;
            };
            match deliver(&client, url, &registration.hs_token, push).await {
                Ok(()) => {
                    // The delivered to-device rows are consumed, deleted
                    // before the cursor moves: the reverse order could
                    // strand rows below the cursor forever, while this
                    // order at worst deletes what the 200 already proved
                    // received.
                    for key in &push.to_device_keys {
                        let _ = devices.delete_queued(key);
                    }
                    write_cursor(&store, &registration.id, push.advance_to);
                    pending.remove(&registration.id);
                    backoff.remove(&registration.id);
                }
                Err(error) => {
                    tracing::debug!("appservice push to {}: {error}", registration.id);
                    // An ephemeral-only transaction is dropped, never
                    // retried: a typing notification redelivered after a
                    // backoff is a lie about the present, exactly the
                    // federation outbox's rule for its EDUs. The next
                    // real change produces a fresh delta anyway.
                    if push.events.is_empty()
                        && push.device_lists_changed.is_empty()
                        && push.to_device.is_empty()
                    {
                        pending.remove(&registration.id);
                    }
                    let failures = backoff.get(&registration.id).map_or(0, |(count, _)| *count) + 1;
                    let delay = retry_base * 2_u32.saturating_pow(failures.min(6));
                    backoff.insert(
                        registration.id.clone(),
                        (failures, std::time::Instant::now() + delay),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_regexes_match_the_whole_id_not_a_substring() {
        let mut namespace = Namespace {
            exclusive: true,
            regex: "@bot:server".to_owned(),
            compiled: None,
        };
        namespace.compile().unwrap();
        assert!(namespace.matches("@bot:server"));
        // Unanchored, both of these would match by containment — and a
        // namespace that matches by containment is a claim over IDs the
        // registration never wrote down.
        assert!(!namespace.matches("@bot:serverextra"));
        assert!(!namespace.matches("x@bot:server"));
    }
}
