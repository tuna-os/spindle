//! End-to-end encryption endpoints: device and cross-signing keys, key
//! backups, and send-to-device messages.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{limit_exceeded, visible_device_changes};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

/// Keys, key backups and send-to-device.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/keys/upload", post(upload_keys))
        .route("/_matrix/client/v3/keys/query", post(query_keys))
        .route("/_matrix/client/v3/keys/claim", post(claim_keys))
        .route("/_matrix/client/v3/keys/changes", get(key_changes))
        .route(
            "/_matrix/client/v3/keys/device_signing/upload",
            post(upload_cross_signing),
        )
        .route(
            "/_matrix/client/v3/keys/signatures/upload",
            post(upload_signatures),
        )
        .route(
            "/_matrix/client/v3/room_keys/version",
            post(create_backup_version).get(latest_backup_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/version/{version}",
            get(get_backup_version)
                .put(update_backup_version)
                .delete(delete_backup_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys",
            axum::routing::put(put_backup_keys)
                .get(get_backup_keys)
                .delete(delete_backup_keys),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}",
            axum::routing::put(put_backup_room)
                .get(get_backup_room)
                .delete(delete_backup_room),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}",
            axum::routing::put(put_backup_session)
                .get(get_backup_session)
                .delete(delete_backup_session),
        )
        .route(
            "/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}",
            axum::routing::put(send_to_device),
        )
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
// The postfix repetition is the spec's: these are `/keys/upload`'s three
// wire field names, verbatim.
#[allow(clippy::struct_field_names)]
struct UploadKeysRequest {
    device_keys: Option<Value>,
    one_time_keys: Option<serde_json::Map<String, Value>>,
    fallback_keys: Option<serde_json::Map<String, Value>>,
}

/// `POST /_matrix/client/v3/keys/upload`
async fn upload_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<UploadKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(device_keys) = &request.device_keys {
        // The claim inside must match the authenticated caller. Accepting a
        // body that names another user or device would let any account plant
        // keys on another's identity, and verification downstream trusts
        // exactly this mapping.
        let claimed_user = device_keys["user_id"].as_str();
        let claimed_device = device_keys["device_id"].as_str();
        if claimed_user != Some(identity.user_id.as_str())
            || claimed_device != Some(identity.device_id.as_str())
        {
            return Err(MatrixError::forbidden(
                "device_keys must belong to the uploading device",
            ));
        }
        state
            .devices
            .upload_device_keys(&identity.user_id, &identity.device_id, device_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // Identity keys changing is what "device list changed" means — other
        // users must re-query before encrypting to this user again. One-time
        // and fallback keys are consumables and do not move the watermark.
        let stream_write = state.rooms.reserve_stream_id();
        let seq = stream_write.id();
        state
            .devices
            .mark_device_list_changed(&identity.user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // Anyone long-polling `/sync` should hear about it now, not at the
        // timeout: encrypting to a stale device set is the failure mode.
        state.rooms.wake_sync_waiters();
        // And every server sharing a room with this user, through the
        // outbox, so a peer's clients re-query before encrypting.
        crate::e2ee_federation::announce_device_change(
            &state,
            &identity.user_id,
            &identity.device_id,
            Some(device_keys),
            seq,
        );
    }
    if let Some(fallback_keys) = &request.fallback_keys {
        state
            .devices
            .upload_fallback_keys(&identity.user_id, &identity.device_id, fallback_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let counts = match &request.one_time_keys {
        Some(one_time_keys) => {
            // Counted before the write, against what the device already
            // holds plus what it is sending. A key that re-uses an id it
            // already uploaded is counted twice here; that errs toward
            // refusing at the cap, and a client at the cap has no business
            // uploading more.
            let cap = state.config.limits.one_time_keys_per_device;
            let held = state
                .devices
                .one_time_key_total(&identity.user_id, &identity.device_id)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            if held.saturating_add(one_time_keys.len()) > cap {
                return Err(limit_exceeded("one-time keys per device", cap));
            }
            state
                .devices
                .upload_one_time_keys(&identity.user_id, &identity.device_id, one_time_keys)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
        }
        None => state
            .devices
            .one_time_key_counts(&identity.user_id, &identity.device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?,
    };
    Ok(Json(json!({ "one_time_key_counts": counts })))
}

#[derive(Debug, Deserialize)]
struct QueryKeysRequest {
    device_keys: serde_json::Map<String, Value>,
}

/// `POST /_matrix/client/v3/keys/query`
async fn query_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<QueryKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut device_keys = serde_json::Map::new();
    let local = |user_id: &str| {
        user_id.split_once(':').map(|(_, domain)| domain) == Some(state.config.server.name.as_str())
    };
    for (user_id, wanted) in &request.device_keys {
        if !local(user_id) {
            continue;
        }
        let all = state
            .devices
            .all_device_keys(user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // An empty list means every device; a non-empty one narrows.
        let mut narrowed: serde_json::Map<String, Value> = match wanted.as_array() {
            Some(list) if !list.is_empty() => {
                let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
                all.into_iter()
                    .filter(|(device_id, _)| names.contains(&device_id.as_str()))
                    .collect()
            }
            _ => all,
        };
        // A user the store knows nothing about, who exists only through
        // an appservice, gets MSC3984's second chance: the service
        // answers for its own users' keys. Local keys win when present —
        // the store is what this server vouched for.
        if narrowed.is_empty()
            && let Some(registration) = state.appservices.exclusive_claimant(user_id)
        {
            let answer =
                crate::appservices::proxy_key_query(registration, &json!({ user_id: wanted }))
                    .await;
            if let Some(theirs) = answer[user_id].as_object() {
                narrowed.clone_from(theirs);
            }
        }
        device_keys.insert(user_id.clone(), Value::Object(narrowed));
    }
    // Cross-signing keys ride along for every queried user. The
    // user-signing key is the exception: it exists to sign *other people*,
    // which is nobody else's business — only its owner gets it back.
    let mut master_keys = serde_json::Map::new();
    let mut self_signing_keys = serde_json::Map::new();
    let mut user_signing_keys = serde_json::Map::new();
    for user_id in request.device_keys.keys().filter(|user_id| local(user_id)) {
        let fetch = |key_type: &str| {
            state
                .devices
                .cross_signing_key(user_id, key_type)
                .map_err(|error| MatrixError::internal(&error.to_string()))
        };
        if let Some(key) = fetch("master")? {
            master_keys.insert(
                user_id.clone(),
                signatures_visible_to(key, user_id, &identity.user_id),
            );
        }
        if let Some(key) = fetch("self_signing")? {
            self_signing_keys.insert(
                user_id.clone(),
                signatures_visible_to(key, user_id, &identity.user_id),
            );
        }
        if user_id == &identity.user_id
            && let Some(key) = fetch("user_signing")?
        {
            user_signing_keys.insert(user_id.clone(), key);
        }
    }
    let mut response = serde_json::Map::new();
    response.insert("device_keys".to_owned(), Value::Object(device_keys));
    response.insert("master_keys".to_owned(), Value::Object(master_keys));
    response.insert(
        "self_signing_keys".to_owned(),
        Value::Object(self_signing_keys),
    );
    response.insert(
        "user_signing_keys".to_owned(),
        Value::Object(user_signing_keys),
    );
    response.insert("failures".to_owned(), json!({}));
    // Users elsewhere are asked of their servers, one request per server.
    crate::e2ee_federation::query_remote_keys(&state, &request.device_keys, &mut response).await;
    Ok(Json(Value::Object(response)))
}

#[derive(Debug, Deserialize)]
struct ClaimKeysRequest {
    one_time_keys: serde_json::Map<String, Value>,
}

/// `POST /_matrix/client/v3/keys/claim`
async fn claim_keys(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    Json(request): Json<ClaimKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut claimed = serde_json::Map::new();
    let mut failures = serde_json::Map::new();
    crate::e2ee_federation::claim_remote_keys(
        &state,
        &request.one_time_keys,
        &mut claimed,
        &mut failures,
    )
    .await;
    for (user_id, devices) in &request.one_time_keys {
        if user_id.split_once(':').map(|(_, domain)| domain)
            != Some(state.config.server.name.as_str())
        {
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
                continue;
            }
            // A device with none left is simply absent from the response,
            // which is the spec's shape: absence says "no key", and the
            // caller falls back to the fallback key or fails the session.
            // Unless the user exists only through an appservice — then
            // MSC3983 gives that service the chance to hand over a key
            // directly, because its key store is the real one.
            if let Some(registration) = state.appservices.exclusive_claimant(user_id) {
                let answer = crate::appservices::proxy_otk_claim(
                    registration,
                    &json!({ user_id: { device_id: [algorithm] } }),
                )
                .await;
                if let Some(keys) = answer[user_id][device_id].as_object()
                    && !keys.is_empty()
                {
                    per_user.insert(device_id.clone(), Value::Object(keys.clone()));
                }
            }
        }
        if !per_user.is_empty() {
            claimed.insert(user_id.clone(), Value::Object(per_user));
        }
    }
    Ok(Json(
        json!({ "one_time_keys": claimed, "failures": failures }),
    ))
}

#[derive(Debug, Deserialize)]
struct KeyChangesQuery {
    from: String,
    to: String,
}

/// `GET /_matrix/client/v3/keys/changes`
///
/// The catch-up form of `device_lists.changed`: a client that was offline
/// asks for the window between the token it went to sleep on and the token
/// its first sync just returned. Same computation, same visibility rule —
/// only the window is caller-chosen.
async fn key_changes(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<KeyChangesQuery>,
) -> Result<Json<Value>, MatrixError> {
    // A Synapse token from before the migration is a point this server
    // cannot place: as `from` it widens the window to everything, which
    // costs the client a few key downloads and loses no change; as `to` it
    // is now (#568).
    let resume = |token: &str| {
        crate::tokens::Sync::resume(Some(token))
            .map_err(|error| MatrixError::bad_json(error.to_string()))
    };
    let from = resume(&query.from)?.position().unwrap_or(0);
    let to = resume(&query.to)?
        .position()
        .unwrap_or_else(|| state.rooms.stream_position());
    let changed = visible_device_changes(&state, &identity, from, to)?;
    Ok(Json(json!({ "changed": changed, "left": [] })))
}

// The postfix repetition is the spec's: these are the endpoint's three wire
// field names, verbatim.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CrossSigningUpload {
    master_key: Option<Value>,
    self_signing_key: Option<Value>,
    user_signing_key: Option<Value>,
}

/// `POST /_matrix/client/v3/keys/device_signing/upload`
async fn upload_cross_signing(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CrossSigningUpload>,
) -> Result<Json<Value>, MatrixError> {
    let uploads = [
        ("master", &request.master_key),
        ("self_signing", &request.self_signing_key),
        ("user_signing", &request.user_signing_key),
    ];
    for (key_type, key) in uploads {
        let Some(key) = key else { continue };
        // The same rule as /keys/upload: the body's claim must match the
        // authenticated caller, or any account could plant a master key on
        // another's identity and own every verification derived from it.
        if key["user_id"].as_str() != Some(identity.user_id.as_str()) {
            return Err(MatrixError::forbidden(
                "cross-signing keys must belong to the uploading user",
            ));
        }
        state
            .devices
            .upload_cross_signing(&identity.user_id, key_type, key)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    // New cross-signing keys are a device-list change: peers must re-query
    // before they can trust (or distrust) the new signing tree.
    let stream_write = state.rooms.reserve_stream_id();
    let seq = stream_write.id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    crate::e2ee_federation::announce_signing_keys(&state, &identity.user_id);
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/keys/signatures/upload`
async fn upload_signatures(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<serde_json::Map<String, Value>>,
) -> Result<Json<Value>, MatrixError> {
    let mut failures = serde_json::Map::new();
    let mut signed_users = std::collections::BTreeSet::new();
    for (user_id, targets) in &request {
        let Some(targets) = targets.as_object() else {
            continue;
        };
        for (target, signed) in targets {
            let added = state
                .devices
                .add_signatures(user_id, target, signed)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            if added {
                signed_users.insert(user_id.clone());
            }
            if !added {
                // The spec's failure shape: per-target errors, not a failed
                // request — the other signatures in the batch still landed.
                failures
                    .entry(user_id.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()))
                    .as_object_mut()
                    .expect("just inserted an object")
                    .insert(
                        target.clone(),
                        json!({ "errcode": "M_NOT_FOUND", "error": "no such key" }),
                    );
            }
        }
    }
    // A new signature is a device-list change for the user whose key
    // carries it. Without this the signer's own client never hears that
    // its signature landed: it re-queries a user's keys only when a sync
    // names them in `device_lists.changed`, and until it does the identity
    // it just verified stays unverified in its own store.
    for user_id in &signed_users {
        let stream_write = state.rooms.reserve_stream_id();
        let seq = stream_write.id();
        state
            .devices
            .mark_device_list_changed(user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        if user_id == &identity.user_id {
            crate::e2ee_federation::announce_signing_keys(&state, user_id);
        }
    }
    if !signed_users.is_empty() {
        state.rooms.wake_sync_waiters();
    }
    Ok(Json(json!({ "failures": failures })))
}

/// A key as `viewer` may see it: signatures by anyone other than the
/// key's owner or the viewer are dropped. A user-signing signature is the
/// signer's private opinion of who they have verified; the spec has the
/// server return it to the signer alone.
fn signatures_visible_to(mut key: Value, owner: &str, viewer: &str) -> Value {
    if let Some(signatures) = key["signatures"].as_object_mut() {
        signatures.retain(|signer, _| signer == owner || signer == viewer);
    }
    key
}

/// The API's version is a string; storage counts. Anything non-numeric can
/// name no stored version, and "no such version" is 404 territory.
fn parse_backup_version(version: &str) -> Result<u64, MatrixError> {
    version.parse::<u64>().map_err(|_| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        )
    })
}

fn backup_version_body(info: &crate::backups::VersionInfo) -> Value {
    json!({
        "algorithm": info.algorithm,
        "auth_data": info.auth_data,
        "count": info.count,
        "etag": info.etag.to_string(),
        "version": info.version.to_string(),
    })
}

fn backup_error(error: &spindle_store::StoreError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

#[derive(Debug, Deserialize)]
struct CreateBackupRequest {
    algorithm: String,
    auth_data: Value,
}

/// `POST /_matrix/client/v3/room_keys/version`
async fn create_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CreateBackupRequest>,
) -> Result<Json<Value>, MatrixError> {
    let version = state
        .backups
        .create_version(&identity.user_id, &request.algorithm, &request.auth_data)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({ "version": version.to_string() })))
}

/// `GET /_matrix/client/v3/room_keys/version`
async fn latest_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let Some(info) = state
        .backups
        .latest_version(&identity.user_id)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no backup exists".to_owned(),
        ));
    };
    Ok(Json(backup_version_body(&info)))
}

/// `GET /_matrix/client/v3/room_keys/version/{version}`
async fn get_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    let Some(info) = state
        .backups
        .version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        ));
    };
    Ok(Json(backup_version_body(&info)))
}

/// `PUT /_matrix/client/v3/room_keys/version/{version}`
async fn update_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
    Json(request): Json<CreateBackupRequest>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    let Some(info) = state
        .backups
        .version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        ));
    };
    // Same algorithm only: changing the algorithm mid-version would leave a
    // backup whose entries no one recipe decrypts. A new algorithm is a new
    // version.
    if request.algorithm != info.algorithm {
        return Err(MatrixError::bad_json(
            "the algorithm of an existing backup cannot change".to_owned(),
        ));
    }
    state
        .backups
        .update_version(
            &identity.user_id,
            version,
            &request.algorithm,
            &request.auth_data,
        )
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/room_keys/version/{version}`
async fn delete_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    state
        .backups
        .delete_version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    // Deleting the already-deleted succeeds quietly: the state the caller
    // asked for is the state that holds.
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct BackupQuery {
    version: String,
}

/// Reads may name any *live* version; a deleted or never-created one is 404.
///
/// Returning an empty backup instead would be worse than the error: a
/// restoring client would conclude its history is simply gone.
fn require_live_version(
    state: &AppState,
    user_id: &str,
    requested: &str,
) -> Result<u64, MatrixError> {
    let version = parse_backup_version(requested)?;
    state
        .backups
        .version(user_id, version)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no backup version {version}"),
            )
        })?;
    Ok(version)
}

/// The version every write must name: the *current* one.
///
/// A client writing to an old version is a client that missed a reset —
/// its recovery key no longer opens the live backup, and accepting the
/// write would strand those keys where no restore will look. 403 with the
/// current version is the spec's way of saying "re-fetch and re-encrypt".
fn require_current_version(
    state: &AppState,
    user_id: &str,
    requested: &str,
) -> Result<u64, MatrixError> {
    let requested = parse_backup_version(requested)?;
    let current = state
        .backups
        .latest_version(user_id)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "no backup exists".to_owned(),
            )
        })?;
    if requested != current.version {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_WRONG_ROOM_KEYS_VERSION",
            format!("the current backup version is {}", current.version),
        ));
    }
    Ok(requested)
}

fn backup_summary(state: &AppState, user_id: &str, version: u64) -> Result<Value, MatrixError> {
    let info = state
        .backups
        .version(user_id, version)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| MatrixError::internal("backup vanished mid-request"))?;
    Ok(json!({ "etag": info.etag.to_string(), "count": info.count }))
}

/// `PUT /_matrix/client/v3/room_keys/keys`
async fn put_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    if let Some(rooms) = request["rooms"].as_object() {
        for (room_id, room) in rooms {
            store_backup_room(&state, &identity.user_id, version, room_id, room)?;
        }
    }
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

fn store_backup_room(
    state: &AppState,
    user_id: &str,
    version: u64,
    room_id: &str,
    room: &Value,
) -> Result<(), MatrixError> {
    if let Some(sessions) = room["sessions"].as_object() {
        for (session_id, data) in sessions {
            state
                .backups
                .put_key(user_id, version, room_id, session_id, data)
                .map_err(|error| backup_error(&error))?;
        }
    }
    Ok(())
}

/// `GET /_matrix/client/v3/room_keys/keys`
async fn get_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({ "rooms": rooms })))
}

/// `PUT /_matrix/client/v3/room_keys/keys/{room_id}`
async fn put_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    store_backup_room(&state, &identity.user_id, version, &room_id, &request)?;
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

/// `GET /_matrix/client/v3/room_keys/keys/{room_id}`
async fn get_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    let sessions = rooms
        .get(&room_id)
        .cloned()
        .unwrap_or_else(|| json!({ "sessions": {} }));
    Ok(Json(sessions))
}

/// `PUT /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn put_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(data): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    state
        .backups
        .put_key(&identity.user_id, version, &room_id, &session_id, &data)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

/// The shared body of the three DELETE granularities.
///
/// Deletes go through the current-version rule like writes do: a client
/// deleting from a superseded version thinks it is trimming the live
/// backup, and quietly deleting somewhere else would let it believe it did.
fn delete_backup(
    state: &AppState,
    user_id: &str,
    requested: &str,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(state, user_id, requested)?;
    state
        .backups
        .delete_keys(user_id, version, room_id, session_id)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(backup_summary(state, user_id, version)?))
}

/// `DELETE /_matrix/client/v3/room_keys/keys`
async fn delete_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(&state, &identity.user_id, &query.version, None, None)
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{room_id}`
async fn delete_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(
        &state,
        &identity.user_id,
        &query.version,
        Some(&room_id),
        None,
    )
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn delete_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(
        &state,
        &identity.user_id,
        &query.version,
        Some(&room_id),
        Some(&session_id),
    )
}

/// `GET /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn get_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    let Some(data) = rooms
        .get(&room_id)
        .and_then(|room| room["sessions"].get(&session_id))
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such session in the backup".to_owned(),
        ));
    };
    Ok(Json(data.clone()))
}

#[derive(Debug, Deserialize)]
struct SendToDeviceRequest {
    messages: serde_json::Map<String, Value>,
}

/// `PUT /_matrix/client/v3/sendToDevice/{event_type}/{txn_id}`
async fn send_to_device(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((event_type, txn_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<SendToDeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Same replay table as /send: a retried batch must not deliver twice.
    // The stored value is unused here — presence is the answer.
    let txn_key = spindle_core::keys::transaction(
        &identity.user_id,
        &identity.device_id,
        &format!("to-device/{txn_id}"),
    );
    if let Ok(Some(_)) = spindle_store::ReadView::get(state.store.as_ref(), &txn_key) {
        return Ok(Json(json!({})));
    }

    // Recipients on other servers go out as one EDU per server.
    crate::e2ee_federation::queue_remote_to_device(
        &state,
        &identity.user_id,
        &event_type,
        &txn_id,
        &request.messages,
    );
    // Hold publication through the batch, so its N recipients need one
    // sync wake rather than N complete response assemblies. Each message
    // still has its own id, including wildcard/explicit-device overlaps.
    let mut batch_write = None;
    for (target_user, per_device) in &request.messages {
        if target_user.split_once(':').map(|(_, domain)| domain)
            != Some(state.config.server.name.as_str())
        {
            continue;
        }
        let Some(per_device) = per_device.as_object() else {
            continue;
        };
        for (target_device, content) in per_device {
            let devices: Vec<String> = if target_device == "*" {
                state
                    .devices
                    .all_device_keys(target_user)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?
                    .keys()
                    .cloned()
                    .collect()
            } else {
                vec![target_device.clone()]
            };
            for device_id in devices {
                batch_write.get_or_insert_with(|| state.rooms.reserve_stream_id());
                let stream_write = state.rooms.reserve_stream_id();
                let seq = stream_write.id();
                let message = json!({
                    "type": event_type,
                    "sender": identity.user_id,
                    "content": content,
                });
                state
                    .devices
                    .queue_to_device(target_user, &device_id, seq, &message)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?;
            }
        }
    }
    spindle_store::Store::put(state.store.as_ref(), &txn_key, b"")
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // A recipient may be blocked in a long-poll right now, and a to-device
    // message lands in no room, so nothing else would wake them.
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}
