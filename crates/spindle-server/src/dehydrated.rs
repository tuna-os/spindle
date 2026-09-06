//! MSC3814 dehydrated devices: a device a client parks on the server so that
//! the room keys sent to it while every real device is gone are still
//! there when the user comes back. Element X creates one after cross-signing
//! and rehydrates it on a fresh login, which is how E2EE history survives
//! the last device being lost.
//!
//! The server's side is small, and that is the design: the dehydrated
//! device is an ordinary device as far as keys go -- its identity keys are
//! answered by `/keys/query`, its one-time keys claimed like any other, its
//! to-device queue filled by `/sendToDevice` like any other -- plus one
//! record per user naming which device is the dehydrated one and carrying
//! the encrypted `device_data` the client needs to rehydrate it. What is
//! *not* ordinary is how the queue is read: `/events` hands the messages
//! over in batches that stay queued until the next call names the token
//! that delivered them, because a rehydrating client that crashes halfway
//! must be able to start over.
//!
//! One dehydrated device per user. Putting another replaces the first
//! outright: its keys, its queue, and its place in the device list.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use spindle_core::keys::{self, Keyspace};
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;

/// The routes, spelled out in full: the dashboard generator reads them
/// from source and cannot expand a prefix.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            get(get_device).put(put_device).delete(delete_device),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device_id}/events",
            post(events),
        )
}

/// The one record: which device is dehydrated, and what the client needs
/// to bring it back.
#[derive(Debug, Deserialize)]
struct Record {
    device_id: String,
    device_data: Value,
}

fn record_key(user_id: &str) -> Vec<u8> {
    keys::user_prefix(Keyspace::DehydratedDevice, user_id)
}

fn read_record(state: &AppState, user_id: &str) -> Result<Option<Record>, MatrixError> {
    let Some(bytes) = ReadView::get(state.store.as_ref(), &record_key(user_id))
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

fn none() -> MatrixError {
    MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no dehydrated device")
}

/// Forget a dehydrated device entirely: its keys, its queued messages, and
/// the record. The device list moves so that peers stop encrypting to it.
fn discard(state: &AppState, user_id: &str, device_id: &str) -> Result<(), MatrixError> {
    state
        .devices
        .remove_device_material(user_id, device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // Everything still queued for it: read without acknowledging, then
    // acknowledge everything by naming the newest position.
    let _ = state
        .devices
        .take_pending(user_id, device_id, Some(u64::MAX))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Store::delete(state.store.as_ref(), &record_key(user_id))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let seq = state.rooms.allocate_stream_id();
    state
        .devices
        .mark_device_list_changed(user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    crate::e2ee_federation::announce_device_change(state, user_id, device_id, None, seq);
    state.rooms.wake_sync_waiters();
    Ok(())
}

/// `GET /dehydrated_device`
async fn get_device(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let record = read_record(&state, &identity.user_id)?.ok_or_else(none)?;
    Ok(Json(json!({
        "device_id": record.device_id,
        "device_data": record.device_data,
    })))
}

#[derive(Debug, Deserialize)]
struct PutRequest {
    device_id: String,
    device_data: Value,
    #[serde(default)]
    initial_device_display_name: Option<String>,
    #[serde(default)]
    device_keys: Option<Value>,
    #[serde(default)]
    one_time_keys: Option<Map<String, Value>>,
    #[serde(default)]
    fallback_keys: Option<Map<String, Value>>,
}

/// `PUT /dehydrated_device`
async fn put_device(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<PutRequest>,
) -> Result<Json<Value>, MatrixError> {
    if request.device_id.is_empty() || request.device_id.contains(['/', '\0']) {
        return Err(MatrixError::bad_json("device_id must be a device ID"));
    }
    if !request.device_data.is_object()
        || request
            .device_data
            .get("algorithm")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(MatrixError::bad_json(
            "device_data must be an object naming its algorithm",
        ));
    }
    // The keys, if any, must be the dehydrated device's own: the same
    // rule `/keys/upload` applies to a session, for the same reason.
    if let Some(device_keys) = &request.device_keys
        && (device_keys["user_id"].as_str() != Some(identity.user_id.as_str())
            || device_keys["device_id"].as_str() != Some(request.device_id.as_str()))
    {
        return Err(MatrixError::bad_json(
            "device_keys must belong to the dehydrated device",
        ));
    }
    // A device that already has a session is somebody's live device;
    // dehydrating over it would hand its queue to whoever rehydrates.
    if identity.device_id == request.device_id {
        return Err(MatrixError::bad_json(
            "the dehydrated device cannot be the requesting device",
        ));
    }

    if let Some(previous) = read_record(&state, &identity.user_id)? {
        discard(&state, &identity.user_id, &previous.device_id)?;
    }

    let user_id = identity.user_id.as_str();
    let device_id = request.device_id.as_str();
    Store::put(
        state.store.as_ref(),
        &record_key(user_id),
        json!({
            "device_id": device_id,
            "device_data": request.device_data,
            "display_name": request.initial_device_display_name,
        })
        .to_string()
        .as_bytes(),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;

    if let Some(device_keys) = &request.device_keys {
        state
            .devices
            .upload_device_keys(user_id, device_id, device_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if let Some(fallback_keys) = &request.fallback_keys {
        state
            .devices
            .upload_fallback_keys(user_id, device_id, fallback_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if let Some(one_time_keys) = &request.one_time_keys {
        let cap = state.config.limits.one_time_keys_per_device;
        if one_time_keys.len() > cap {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_LIMIT_EXCEEDED",
                format!("at most {cap} one-time keys per device"),
            ));
        }
        state
            .devices
            .upload_one_time_keys(user_id, device_id, one_time_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }

    // A new device with keys is a device-list change, to every local
    // client and every peer sharing a room, exactly as a session's upload
    // is: a peer that does not re-query will not encrypt to it, and the
    // whole point is that it be encrypted to.
    let seq = state.rooms.allocate_stream_id();
    state
        .devices
        .mark_device_list_changed(user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    crate::e2ee_federation::announce_device_change(
        &state,
        user_id,
        device_id,
        request.device_keys.as_ref(),
        seq,
    );
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({ "device_id": device_id })))
}

/// `DELETE /dehydrated_device`
async fn delete_device(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let record = read_record(&state, &identity.user_id)?.ok_or_else(none)?;
    discard(&state, &identity.user_id, &record.device_id)?;
    Ok(Json(json!({ "device_id": record.device_id })))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EventsRequest {
    next_batch: Option<String>,
}

/// `POST /dehydrated_device/{device_id}/events`
///
/// The queue, in batches that stay queued until acknowledged: a call with
/// no `next_batch` gets everything pending; one naming the token a
/// previous call answered with drops what that call delivered and gets
/// the rest. The token is a position in the server's stream, the same
/// shape sliding sync's to-device extension uses.
async fn events(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path(device_id): Path<String>,
    Json(request): Json<EventsRequest>,
) -> Result<Json<Value>, MatrixError> {
    let record = read_record(&state, &identity.user_id)?.ok_or_else(none)?;
    if record.device_id != device_id {
        return Err(none());
    }
    let acknowledged = match request.next_batch.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Sync>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let position = state.rooms.stream_position();
    let events = state
        .devices
        .take_pending(&identity.user_id, &device_id, acknowledged)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({
        "events": events,
        "next_batch": crate::tokens::Sync(position).to_string(),
    })))
}
