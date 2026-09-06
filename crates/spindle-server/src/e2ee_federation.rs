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

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

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
/// has fallen behind on updates and wants the whole list.
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
    let devices: Vec<Value> = state
        .devices
        .all_device_keys(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .into_iter()
        .map(|(device_id, keys)| json!({ "device_id": device_id, "keys": keys }))
        .collect();
    let mut response = json!({
        "user_id": user_id,
        "stream_id": state.rooms.stream_position(),
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
                let seq = state.rooms.allocate_stream_id();
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
    let outcome = if content["deleted"].as_bool().unwrap_or(false) {
        state.devices.remove_device_material(user_id, device_id)
    } else if content["keys"].is_object() {
        state
            .devices
            .upload_device_keys(user_id, device_id, &content["keys"])
    } else {
        // An update without the keys is a notice to fetch: the peer's
        // whole list, which also catches any update that was lost.
        match state.federation.remote_user_devices(origin, user_id).await {
            Ok(listing) => store_remote_devices(state, user_id, &listing),
            Err(error) => {
                tracing::debug!(%error, user_id, "cannot refresh a peer's device list");
                Ok(())
            }
        }
    };
    if let Err(error) = outcome {
        tracing::warn!(%error, user_id, "cannot apply a device-list update");
        return;
    }
    note_remote_change(state, user_id);
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
    let seq = state.rooms.allocate_stream_id();
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
/// that is gone. Rides the durable outbox, so a peer that is dark hears it
/// when it comes back.
pub(crate) fn announce_device_change(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    keys: Option<&Value>,
    seq: u64,
) {
    let mut content = json!({
        "user_id": user_id,
        "device_id": device_id,
        "stream_id": seq,
        "prev_id": [],
        "deleted": keys.is_none(),
    });
    if let Some(keys) = keys {
        content["keys"] = keys.clone();
    }
    let edu = json!({ "edu_type": "m.device_list_update", "content": content });
    for server in servers_sharing_rooms(state, user_id) {
        state.federation.queue_edu(&server, edu.clone());
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

/// Ask each remote server for its users' device keys, merging the answers
/// into the client's response. A server that does not answer is listed
/// under `failures`, and its users' keys come from this server's last copy
/// of them if there is one.
pub(crate) async fn query_remote_keys(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
    response: &mut serde_json::Map<String, Value>,
) {
    let mut by_server: std::collections::BTreeMap<String, serde_json::Map<String, Value>> =
        std::collections::BTreeMap::new();
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
    for (server, ask) in by_server {
        match state.federation.remote_keys_query(&server, &ask).await {
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
                tracing::debug!(%error, server, "keys/query: peer did not answer");
                let failures = response
                    .entry("failures")
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(failures) = failures.as_object_mut() {
                    failures.insert(
                        server.clone(),
                        json!({ "errcode": "M_UNKNOWN", "error": error.to_string() }),
                    );
                }
                for user_id in ask.keys() {
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
/// the answers into the client's response.
pub(crate) async fn claim_remote_keys(
    state: &AppState,
    requested: &serde_json::Map<String, Value>,
    claimed: &mut serde_json::Map<String, Value>,
    failures: &mut serde_json::Map<String, Value>,
) {
    let mut by_server: std::collections::BTreeMap<String, serde_json::Map<String, Value>> =
        std::collections::BTreeMap::new();
    for (user_id, devices) in requested {
        if let Some(domain) = domain_of(user_id)
            && domain != state.config.server.name
        {
            by_server
                .entry(domain.to_owned())
                .or_default()
                .insert(user_id.clone(), devices.clone());
        }
    }
    for (server, ask) in by_server {
        match state.federation.remote_keys_claim(&server, &ask).await {
            Ok(answer) => {
                if let Some(theirs) = answer["one_time_keys"].as_object() {
                    claimed.extend(theirs.clone());
                }
            }
            Err(error) => {
                tracing::debug!(%error, server, "keys/claim: peer did not answer");
                failures.insert(
                    server,
                    json!({ "errcode": "M_UNKNOWN", "error": error.to_string() }),
                );
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
