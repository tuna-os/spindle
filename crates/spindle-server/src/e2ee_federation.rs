//! End-to-end encryption across federation: the key directory, one-time
//! key claims, to-device messages and device-list changes, in both
//! directions.
//!
//! A room's encryption is the clients' business; what the server owes them
//! is a way to find each other's keys and to pass Olm and Megolm material
//! around, and across a federation seam that means four things: a peer
//! can ask this server for its users' device keys and claim their one-time
//! keys, this server asks the peer the same for the peer's users, a
//! to-device message for a user elsewhere goes out in a transaction and one
//! for a user here is delivered from one, and a device that appears or
//! disappears is announced to every server sharing a room with its user.
//!
//! Nothing here reads plaintext. Keys and messages are stored and relayed
//! as the clients uploaded them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::AppState;
use crate::errors::MatrixError;
use crate::inbound::federation_origin;

/// The server a user ID lives on, or `None` for something that is not one.
fn domain_of(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, domain)| domain)
}

fn is_local(state: &AppState, user_id: &str) -> bool {
    domain_of(user_id) == Some(state.config.server.name.as_str())
}

/// `POST /_matrix/federation/v1/user/keys/query`: the device directory as
/// a peer sees it, for this server's users only. Same body as the
/// client endpoint; the user-signing key is never sent, since it exists
/// to sign other people and is nobody else's business.
pub(crate) async fn keys_query(
    state: AppState,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let (uri, body) = read(request).await?;
    federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;
    let requested = body["device_keys"].as_object().cloned().unwrap_or_default();
    let mut device_keys = serde_json::Map::new();
    let mut master_keys = serde_json::Map::new();
    let mut self_signing_keys = serde_json::Map::new();
    for (user_id, wanted) in &requested {
        if !is_local(&state, user_id) {
            continue;
        }
        let all = state
            .devices
            .all_device_keys(user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        let narrowed: serde_json::Map<String, Value> = match wanted.as_array() {
            Some(list) if !list.is_empty() => {
                let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
                all.into_iter()
                    .filter(|(device_id, _)| names.contains(&device_id.as_str()))
                    .collect()
            }
            _ => all,
        };
        device_keys.insert(user_id.clone(), Value::Object(narrowed));
        let fetch = |key_type: &str| {
            state
                .devices
                .cross_signing_key(user_id, key_type)
                .map_err(|error| MatrixError::internal(&error.to_string()))
        };
        if let Some(key) = fetch("master")? {
            master_keys.insert(user_id.clone(), key);
        }
        if let Some(key) = fetch("self_signing")? {
            self_signing_keys.insert(user_id.clone(), key);
        }
    }
    Ok(Json(json!({
        "device_keys": device_keys,
        "master_keys": master_keys,
        "self_signing_keys": self_signing_keys,
    })))
}

/// `POST /_matrix/federation/v1/user/keys/claim`: one one-time key per
/// requested device of this server's users, each handed out once.
pub(crate) async fn keys_claim(
    state: AppState,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let (uri, body) = read(request).await?;
    federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;
    let requested = body["one_time_keys"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let claimed = claim_local(&state, &requested)?;
    Ok(Json(json!({ "one_time_keys": claimed })))
}

/// Claim one-time keys for local users, the way both the client and the
/// federation endpoint do it.
pub(crate) fn claim_local(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>, MatrixError> {
    let mut claimed = serde_json::Map::new();
    for (user_id, devices) in requested {
        if !is_local(state, user_id) {
            continue;
        }
        let Some(devices) = devices.as_object() else {
            continue;
        };
        let mut per_user = serde_json::Map::new();
        for (device_id, algorithm) in devices {
            let Some(algorithm) = algorithm.as_str() else {
                continue;
            };
            if let Some((key_id, key)) = state
                .devices
                .claim_key(user_id, device_id, algorithm)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
            {
                per_user.insert(device_id.clone(), json!({ key_id: key }));
            }
        }
        if !per_user.is_empty() {
            claimed.insert(user_id.clone(), Value::Object(per_user));
        }
    }
    Ok(claimed)
}

/// `GET /_matrix/federation/v1/user/devices/{userId}`: every device of one
/// of this server's users, with the cross-signing keys, for a peer that
/// has fallen behind on updates and wants the whole list. Its `stream_id`
/// is the head of the user's device-list chain, the id the next update
/// names as `prev_id`, so the peer knows that update follows this snapshot.
pub(crate) async fn user_devices(
    state: AppState,
    headers: axum::http::HeaderMap,
    user_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    if !is_local(&state, &user_id) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "the user does not live on this server".to_owned(),
        ));
    }
    // The head is read before the devices: a change writes its keys before
    // it extends the chain, so a snapshot read after the head holds at least
    // what the head names. Read the other way round, a change landing in
    // between would be named by the served id yet missing from the list,
    // and the peer would skip its update as already covered.
    let stream_id = state
        .devices
        .device_list_stream_id(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let devices: Vec<Value> = state
        .devices
        .all_device_keys(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .into_iter()
        .map(|(device_id, keys)| json!({ "device_id": device_id, "keys": keys }))
        .collect();
    let mut response = json!({
        "user_id": user_id,
        "stream_id": stream_id,
        "devices": devices,
    });
    for (name, key_type) in [
        ("master_key", "master"),
        ("self_signing_key", "self_signing"),
    ] {
        if let Some(key) = state
            .devices
            .cross_signing_key(&user_id, key_type)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
        {
            response[name] = key;
        }
    }
    Ok(Json(response))
}

/// Apply one EDU from a transaction `origin` signed. The origin is the
/// whole authority for what is inside: a to-device message is delivered
/// only from a sender on the origin, and a device-list change is believed
/// only about the origin's own users.
pub(crate) async fn apply_edu(state: &AppState, origin: &str, edu: &Value) {
    let content = &edu["content"];
    match edu["edu_type"].as_str() {
        Some("m.direct_to_device") => deliver_to_device(state, origin, content),
        Some("m.device_list_update") => apply_device_list_update(state, origin, content).await,
        Some("m.signing_key_update" | "org.matrix.signing_key_update") => {
            apply_signing_key_update(state, origin, content);
        }
        _ => {}
    }
}

fn deliver_to_device(state: &AppState, origin: &str, content: &Value) {
    let Some(sender) = content["sender"].as_str() else {
        return;
    };
    if domain_of(sender) != Some(origin) {
        tracing::debug!(
            origin,
            sender,
            "to-device EDU names a sender not on the origin"
        );
        return;
    }
    let Some(event_type) = content["type"].as_str() else {
        return;
    };
    // Redelivery is not an error: a peer whose response was lost sends the
    // same `message_id` again, and the recipient must not see it twice.
    let replay = content["message_id"]
        .as_str()
        .map(|id| spindle_core::keys::transaction(origin, "edu", id));
    if let Some(key) = &replay
        && let Ok(Some(_)) = spindle_store::ReadView::get(state.store.as_ref(), key)
    {
        return;
    }
    let Some(messages) = content["messages"].as_object() else {
        return;
    };
    let mut delivered = false;
    let mut batch_write = None;
    for (target_user, per_device) in messages {
        if !is_local(state, target_user) {
            continue;
        }
        let Some(per_device) = per_device.as_object() else {
            continue;
        };
        for (target_device, body) in per_device {
            let devices: Vec<String> = if target_device == "*" {
                state
                    .devices
                    .all_device_keys(target_user)
                    .map(|keys| keys.keys().cloned().collect())
                    .unwrap_or_default()
            } else {
                vec![target_device.clone()]
            };
            for device_id in devices {
                batch_write.get_or_insert_with(|| state.rooms.reserve_stream_id());
                let stream_write = state.rooms.reserve_stream_id();
                let seq = stream_write.id();
                let message = json!({ "type": event_type, "sender": sender, "content": body });
                if let Err(error) =
                    state
                        .devices
                        .queue_to_device(target_user, &device_id, seq, &message)
                {
                    tracing::warn!(%error, "cannot queue a federated to-device message");
                }
                delivered = true;
            }
        }
    }
    if let Some(key) = replay {
        let _ = spindle_store::Store::put(state.store.as_ref(), &key, b"");
    }
    if delivered {
        state.rooms.wake_sync_waiters();
    }
}

/// Where an inbound device-list update sits against what this server has
/// accounted for about its user.
#[derive(Debug, PartialEq, Eq)]
enum Link {
    /// At or below what is accounted for: a redelivery, or an update the
    /// last snapshot already held. Applying it could put back a key the
    /// snapshot had replaced.
    Covered,
    /// Follows what is accounted for, and applies as it stands.
    Follows,
    /// Names a predecessor this server never saw: an update was lost, and
    /// only the user's whole list is a safe base for what comes next.
    Gap,
}

/// Place an update after `known`, the newest id accounted for. A sender's
/// ids rise per user, so a predecessor at or below `known` was applied or
/// folded into the snapshot that set it. That is also why `prev_id` is
/// compared rather than matched: a snapshot's `stream_id` need not be an id
/// any update carried.
fn place(known: Option<u64>, stream_id: u64, prev_id: &[u64]) -> Link {
    match known {
        Some(known) if stream_id <= known => Link::Covered,
        Some(known) if prev_id.iter().all(|prev| *prev <= known) => Link::Follows,
        // Never tracked: the start of a chain applies as it stands; anything
        // later had predecessors this copy does not hold.
        None if prev_id.is_empty() => Link::Follows,
        _ => Link::Gap,
    }
}

/// Apply an `m.device_list_update`: inline when it follows the last one
/// accounted for, by refetching the user's whole list when it reveals a
/// gap (spec, Server-Server API, "Device Management"). Updates about one
/// user are applied one at a time, so a burst arriving behind a gap waits
/// for the one refetch and is then covered by it.
async fn apply_device_list_update(state: &AppState, origin: &str, content: &Value) {
    let Some(user_id) = content["user_id"].as_str() else {
        return;
    };
    if domain_of(user_id) != Some(origin) {
        tracing::debug!(
            origin,
            user_id,
            "device-list update for a user not on the origin"
        );
        return;
    }
    let Some(device_id) = content["device_id"].as_str() else {
        return;
    };
    let _turn = state.devices.device_list_turn(user_id).await;
    let known = match state.devices.remote_device_list_stream_id(user_id) {
        Ok(known) => known,
        Err(error) => {
            tracing::warn!(%error, user_id, "cannot read a peer's device-list position");
            return;
        }
    };
    let stream_id = content["stream_id"].as_u64();
    let prev_id: Vec<u64> = content["prev_id"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect();
    // Without a `stream_id` an update cannot be placed at all, and is
    // treated as the gap it might be.
    let link = stream_id.map_or(Link::Gap, |id| place(known, id, &prev_id));
    let carries_change =
        content["deleted"].as_bool().unwrap_or(false) || content["keys"].is_object();
    let outcome = match (link, stream_id) {
        (Link::Covered, _) => return,
        (Link::Follows, Some(stream_id)) if carries_change => {
            apply_device_change(state, user_id, device_id, content).and_then(|()| {
                state
                    .devices
                    .set_remote_device_list_stream_id(user_id, stream_id)
            })
        }
        // An update without the keys is a notice to fetch, wherever it
        // sits in the chain.
        _ => {
            let floor = stream_id.max(known).unwrap_or(0);
            resync_device_list(state, origin, user_id, device_id, floor, content).await
        }
    };
    if let Err(error) = outcome {
        tracing::warn!(%error, user_id, "cannot apply a device-list update");
        return;
    }
    note_remote_change(state, user_id);
}

/// One device's change, as an update carries it.
fn apply_device_change(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    content: &Value,
) -> Result<(), spindle_store::StoreError> {
    if content["deleted"].as_bool().unwrap_or(false) {
        state.devices.remove_device_material(user_id, device_id)
    } else if content["keys"].is_object() {
        state
            .devices
            .upload_device_keys(user_id, device_id, &content["keys"])
    } else {
        Ok(())
    }
}

/// Replace this server's copy of a remote user's devices with the peer's
/// whole list, and account for it up to the snapshot's `stream_id` -- or
/// `floor`, the update that prompted it, if that is higher: the peer sent
/// the update before it was asked, so the snapshot holds it whatever scale
/// its `stream_id` is on.
///
/// A peer that cannot be reached leaves the user stale: the update's own
/// change is still applied, being the newest word on that device, but
/// nothing is accounted for, so the next update still sees the gap and
/// refetches rather than building on a copy known to be incomplete.
async fn resync_device_list(
    state: &AppState,
    origin: &str,
    user_id: &str,
    device_id: &str,
    floor: u64,
    content: &Value,
) -> Result<(), spindle_store::StoreError> {
    match state.federation.remote_user_devices(origin, user_id).await {
        Ok(listing) => {
            store_remote_devices(state, user_id, &listing)?;
            let served = listing["stream_id"].as_u64().unwrap_or(0);
            state
                .devices
                .set_remote_device_list_stream_id(user_id, served.max(floor))
        }
        Err(error) => {
            tracing::debug!(%error, user_id, "cannot refresh a peer's device list");
            apply_device_change(state, user_id, device_id, content)
        }
    }
}

fn apply_signing_key_update(state: &AppState, origin: &str, content: &Value) {
    let Some(user_id) = content["user_id"].as_str() else {
        return;
    };
    if domain_of(user_id) != Some(origin) {
        return;
    }
    for (name, key_type) in [
        ("master_key", "master"),
        ("self_signing_key", "self_signing"),
    ] {
        if content[name].is_object()
            && let Err(error) =
                state
                    .devices
                    .upload_cross_signing(user_id, key_type, &content[name])
        {
            tracing::warn!(%error, user_id, "cannot store a peer's cross-signing key");
        }
    }
    note_remote_change(state, user_id);
}

/// Record that a remote user's device list moved, so local clients that
/// share a room with them hear it under `device_lists.changed`.
fn note_remote_change(state: &AppState, user_id: &str) {
    let stream_write = state.rooms.reserve_stream_id();
    let seq = stream_write.id();
    if let Err(error) = state.devices.mark_device_list_changed(user_id, seq) {
        tracing::warn!(%error, user_id, "cannot record a device-list change");
    }
    state.rooms.wake_sync_waiters();
}

/// Keep a peer's `/user/devices` answer as this server's copy of that
/// user's keys: what `/keys/query` falls back to when the peer is dark, and
/// what a `*` to-device fan-out needs to know.
fn store_remote_devices(
    state: &AppState,
    user_id: &str,
    listing: &Value,
) -> Result<(), spindle_store::StoreError> {
    let known: Vec<String> = state
        .devices
        .all_device_keys(user_id)?
        .keys()
        .cloned()
        .collect();
    let mut seen = Vec::new();
    for device in listing["devices"].as_array().into_iter().flatten() {
        let Some(device_id) = device["device_id"].as_str() else {
            continue;
        };
        if device["keys"].is_object() {
            state
                .devices
                .upload_device_keys(user_id, device_id, &device["keys"])?;
        }
        seen.push(device_id.to_owned());
    }
    for gone in known.into_iter().filter(|id| !seen.contains(id)) {
        state.devices.remove_device_material(user_id, &gone)?;
    }
    for (name, key_type) in [
        ("master_key", "master"),
        ("self_signing_key", "self_signing"),
    ] {
        if listing[name].is_object() {
            state
                .devices
                .upload_cross_signing(user_id, key_type, &listing[name])?;
        }
    }
    Ok(())
}

/// Every remote server that shares a room with `user_id`: the audience for
/// that user's device-list changes.
fn servers_sharing_rooms(state: &AppState, user_id: &str) -> Vec<String> {
    let mut servers = std::collections::BTreeSet::new();
    for room_id in state.rooms.joined(user_id).unwrap_or_default() {
        servers.extend(state.rooms.remote_domains(&room_id).unwrap_or_default());
    }
    servers.into_iter().collect()
}

/// Tell every server sharing a room with `user_id` that one of their
/// devices changed: `keys` for a new or re-keyed device, `deleted` for one
/// that is gone.
///
/// Each update is a link in the user's chain: a fresh `stream_id`, and the
/// previous one as `prev_id`. The previous link is the user's, not the last
/// one this destination was sent: a server that stopped sharing a room
/// for a while missed the updates in between, and naming the newest one
/// is what lets it see that and refetch, where naming the last it got
/// would pass the gap off as continuous. The chain moves even when nobody
/// is told, so the next server to hear of the user refetches the list it
/// never had.
pub(crate) fn announce_device_change(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    keys: Option<&Value>,
    seq: u64,
) {
    let servers = servers_sharing_rooms(state, user_id);
    let queued = state
        .devices
        .extend_device_list_chain(user_id, seq, |stream_id, prev| {
            let mut content = json!({
                "user_id": user_id,
                "device_id": device_id,
                "stream_id": stream_id,
                "prev_id": prev.into_iter().collect::<Vec<u64>>(),
                "deleted": keys.is_none(),
            });
            if let Some(keys) = keys {
                content["keys"] = keys.clone();
            }
            let edu = json!({ "edu_type": "m.device_list_update", "content": content });
            for server in &servers {
                state.federation.queue_edu(server, edu.clone());
            }
        });
    if let Err(error) = queued {
        tracing::warn!(%error, user_id, "cannot extend a device-list chain");
    }
}

/// Tell every server sharing a room with `user_id` about new cross-signing
/// keys.
pub(crate) fn announce_signing_keys(state: &AppState, user_id: &str) {
    let mut content = json!({ "user_id": user_id });
    for (name, key_type) in [
        ("master_key", "master"),
        ("self_signing_key", "self_signing"),
    ] {
        if let Ok(Some(key)) = state.devices.cross_signing_key(user_id, key_type) {
            content[name] = key;
        }
    }
    let edu = json!({ "edu_type": "m.signing_key_update", "content": content });
    for server in servers_sharing_rooms(state, user_id) {
        state.federation.queue_edu(&server, edu.clone());
    }
}

/// Queue to-device messages for users on other servers: one EDU per
/// destination, carrying only that server's recipients, named by the
/// client's transaction so a retry does not deliver twice.
pub(crate) fn queue_remote_to_device(
    state: &AppState,
    sender: &str,
    event_type: &str,
    txn_id: &str,
    messages: &serde_json::Map<String, Value>,
) {
    let mut by_server: std::collections::BTreeMap<String, serde_json::Map<String, Value>> =
        std::collections::BTreeMap::new();
    for (target_user, per_device) in messages {
        let Some(domain) = domain_of(target_user) else {
            continue;
        };
        if domain == state.config.server.name {
            continue;
        }
        by_server
            .entry(domain.to_owned())
            .or_default()
            .insert(target_user.clone(), per_device.clone());
    }
    for (server, recipients) in by_server {
        state.federation.queue_edu(
            &server,
            json!({
                "edu_type": "m.direct_to_device",
                "content": {
                    "sender": sender,
                    "type": event_type,
                    "message_id": format!("{sender}/{txn_id}"),
                    "messages": recipients,
                },
            }),
        );
    }
}

/// How long `/keys/query` and `/keys/claim` wait for other servers when
/// the client does not say: the spec's default `timeout`.
const DEFAULT_REMOTE_KEYS_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest `timeout` a client can ask for. Each request to a peer
/// gives up after 30 s on its own, so a longer wait buys nothing; the cap
/// also keeps `now + timeout` from overflowing an `Instant`.
const MAX_REMOTE_KEYS_TIMEOUT: Duration = Duration::from_secs(60);

/// How many peers one client request asks at the same time: enough that
/// a query naming every server in a large room waits about one round
/// trip, few enough that one request cannot open an unbounded number of
/// connections.
const REMOTE_KEYS_CONCURRENCY: usize = 64;

/// When a `/keys/query` or `/keys/claim` stops waiting for other servers:
/// the client's `timeout` in milliseconds from now, or the spec's 10 s.
/// A value that is not a non-negative integer counts as absent: the field
/// was ignored until #723, and a client that sent something odd must not
/// start to get errors for it.
pub(crate) fn remote_keys_deadline(timeout: Option<&Value>) -> Instant {
    let wait = timeout
        .and_then(Value::as_u64)
        .map_or(DEFAULT_REMOTE_KEYS_TIMEOUT, Duration::from_millis)
        .min(MAX_REMOTE_KEYS_TIMEOUT);
    Instant::now() + wait
}

/// Which `user/keys/*` request a client's request becomes for each peer.
#[derive(Clone, Copy)]
enum KeysRequest {
    Query,
    Claim,
}

impl KeysRequest {
    fn name(self) -> &'static str {
        match self {
            Self::Query => "keys/query",
            Self::Claim => "keys/claim",
        }
    }
}

/// One server's part of a client's request, and what came of it.
struct PeerAnswer {
    server: String,
    users: Arc<serde_json::Map<String, Value>>,
    answer: Result<Value, String>,
}

/// A client's request for users on other servers, one part per server.
fn by_remote_server(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
) -> BTreeMap<String, serde_json::Map<String, Value>> {
    let mut by_server: BTreeMap<String, serde_json::Map<String, Value>> = BTreeMap::new();
    for (user_id, wanted) in requested {
        if let Some(domain) = domain_of(user_id)
            && domain != state.config.server.name
        {
            by_server
                .entry(domain.to_owned())
                .or_default()
                .insert(user_id.clone(), wanted.clone());
        }
    }
    by_server
}

/// Ask every server in `by_server` its part, all at once (up to
/// [`REMOTE_KEYS_CONCURRENCY`]), and stop waiting at `deadline`.
///
/// One after another, the client waited for the sum of every peer's
/// latency, and each dead peer added its whole 30 s request timeout
/// (#723). Asked together, the wait is the slowest answer, cut off at the
/// client's deadline; a peer still silent then is a failure like any
/// other. A peer the outbox is backing off from because it gave no
/// answer at all is not asked: it would most likely spend the whole
/// deadline saying nothing.
async fn ask_peers(
    state: &AppState,
    kind: KeysRequest,
    by_server: BTreeMap<String, serde_json::Map<String, Value>>,
    deadline: Instant,
) -> Vec<PeerAnswer> {
    let mut answers = Vec::with_capacity(by_server.len());
    let mut waiting = by_server.into_iter();
    // What each request in flight is for, by task: a task that panicked
    // still has to be reported as that server's failure.
    let mut asking: HashMap<tokio::task::Id, (String, Arc<serde_json::Map<String, Value>>)> =
        HashMap::new();
    let mut requests = tokio::task::JoinSet::new();
    loop {
        while requests.len() < REMOTE_KEYS_CONCURRENCY
            && let Some((server, users)) = waiting.next()
        {
            let users = Arc::new(users);
            if state.federation.unreachable_backing_off(&server) {
                answers.push(PeerAnswer {
                    server,
                    users,
                    answer: Err("not asked: the server did not answer recently".to_owned()),
                });
                continue;
            }
            if Instant::now() >= deadline {
                answers.push(PeerAnswer {
                    server,
                    users,
                    answer: Err("not asked before the request's timeout".to_owned()),
                });
                continue;
            }
            let federation = Arc::clone(&state.federation);
            let destination = server.clone();
            let ask = Arc::clone(&users);
            let task = requests.spawn(async move {
                let started = Instant::now();
                let request = async {
                    match kind {
                        KeysRequest::Query => {
                            federation.remote_keys_query(&destination, &ask).await
                        }
                        KeysRequest::Claim => {
                            federation.remote_keys_claim(&destination, &ask).await
                        }
                    }
                };
                let answer = match tokio::time::timeout_at(deadline, request).await {
                    Ok(Ok(answer)) => Ok(answer),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("no answer within the request's timeout".to_owned()),
                };
                // Per peer, so a slow request can be traced to the server
                // that made it slow.
                tracing::debug!(
                    server = destination,
                    elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    answered = answer.is_ok(),
                    "{}: peer asked",
                    kind.name(),
                );
                answer
            });
            asking.insert(task.id(), (server, users));
        }
        let Some(joined) = requests.join_next_with_id().await else {
            break;
        };
        let (id, answer) = match joined {
            Ok((id, answer)) => (id, answer),
            Err(error) => (error.id(), Err(format!("the request failed: {error}"))),
        };
        if let Some((server, users)) = asking.remove(&id) {
            answers.push(PeerAnswer {
                server,
                users,
                answer,
            });
        }
    }
    answers
}

/// Ask each remote server for its users' device keys, merging the answers
/// into the client's response. A server that does not answer by
/// `deadline` is listed under `failures`, and its users' keys come from
/// this server's last copy of them if there is one.
pub(crate) async fn query_remote_keys(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
    deadline: Instant,
    response: &mut serde_json::Map<String, Value>,
) {
    let by_server = by_remote_server(state, requested);
    for PeerAnswer {
        server,
        users,
        answer,
    } in ask_peers(state, KeysRequest::Query, by_server, deadline).await
    {
        match answer {
            Ok(answer) => {
                for section in ["device_keys", "master_keys", "self_signing_keys"] {
                    if let Some(theirs) = answer[section].as_object() {
                        let ours = response
                            .entry(section)
                            .or_insert_with(|| Value::Object(serde_json::Map::new()));
                        if let Some(ours) = ours.as_object_mut() {
                            ours.extend(theirs.clone());
                        }
                    }
                }
                // What the peer said is now this server's copy.
                if let Some(device_keys) = answer["device_keys"].as_object() {
                    for (user_id, devices) in device_keys {
                        for (device_id, keys) in devices.as_object().into_iter().flatten() {
                            let _ = state.devices.upload_device_keys(user_id, device_id, keys);
                        }
                    }
                }
            }
            Err(error) => {
                tracing::debug!(error, server, "keys/query: peer did not answer");
                let failures = response
                    .entry("failures")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(failures) = failures.as_object_mut() {
                    failures.insert(server, json!({ "errcode": "M_UNKNOWN", "error": error }));
                }
                for user_id in users.keys() {
                    if let Ok(cached) = state.devices.all_device_keys(user_id)
                        && !cached.is_empty()
                        && let Some(device_keys) = response
                            .entry("device_keys")
                            .or_insert_with(|| Value::Object(serde_json::Map::new()))
                            .as_object_mut()
                    {
                        device_keys.insert(user_id.clone(), Value::Object(cached));
                    }
                }
            }
        }
    }
}

/// Claim one-time keys from each remote server for its users, merging
/// the answers into the client's response. A server that does not answer
/// by `deadline` is listed under `failures`.
pub(crate) async fn claim_remote_keys(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
    deadline: Instant,
    claimed: &mut serde_json::Map<String, Value>,
    failures: &mut serde_json::Map<String, Value>,
) {
    let by_server = by_remote_server(state, requested);
    for PeerAnswer { server, answer, .. } in
        ask_peers(state, KeysRequest::Claim, by_server, deadline).await
    {
        match answer {
            Ok(answer) => {
                if let Some(theirs) = answer["one_time_keys"].as_object() {
                    claimed.extend(theirs.clone());
                }
            }
            Err(error) => {
                tracing::debug!(error, server, "keys/claim: peer did not answer");
                failures.insert(server, json!({ "errcode": "M_UNKNOWN", "error": error }));
            }
        }
    }
}

async fn read(
    request: axum::http::Request<axum::body::Body>,
) -> Result<(String, Value), MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    Ok((uri, body))
}

#[cfg(test)]
mod tests {
    use super::{Link, place};

    #[test]
    fn an_update_is_placed_against_what_is_accounted_for() {
        // Never tracked: only the start of a chain stands on its own.
        assert_eq!(place(None, 5, &[]), Link::Follows);
        assert_eq!(place(None, 5, &[4]), Link::Gap);
        // Tracked: the next link follows, a skipped one is a gap.
        assert_eq!(place(Some(4), 5, &[4]), Link::Follows);
        assert_eq!(place(Some(4), 6, &[5]), Link::Gap);
        assert_eq!(place(Some(4), 6, &[4, 5]), Link::Gap);
        // A predecessor at or below a snapshot's id was folded into it.
        assert_eq!(place(Some(9), 12, &[7]), Link::Follows);
        // Anything at or below what is accounted for is old news.
        assert_eq!(place(Some(9), 9, &[8]), Link::Covered);
        assert_eq!(place(Some(9), 3, &[]), Link::Covered);
    }
}
