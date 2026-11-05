//! Device management: listing, renaming and deleting a user's devices.

use crate::AppState;
use crate::accounts::Accounts;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{appservice_of, internal, localpart_of, optional_body, password_uia};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

/// Device management: listing, renaming, deletion — and MSC4190's
/// appservice half, where PUT mints a device with no session behind it.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/devices", get(list_devices))
        .route("/_matrix/client/v3/delete_devices", post(delete_devices))
        .route(
            "/_matrix/client/v3/devices/{device_id}",
            get(get_device).put(put_device).delete(delete_device),
        )
}

/// A device as the spec's `Device` object. Spindle does not track
/// last-seen data, and the spec has those fields optional, so they are
/// absent rather than present-and-wrong; a device never named has no
/// `display_name` for the same reason, since the spec's field is a string
/// and a null is neither absent nor one.
fn device_body(device: &crate::accounts::Device) -> Value {
    let mut body = json!({ "device_id": device.device_id });
    if let Some(name) = &device.display_name {
        body["display_name"] = json!(name);
    }
    body
}

/// `GET /_matrix/client/v3/devices`
async fn list_devices(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let devices = accounts
        .devices_of(&localpart_of(&identity.user_id))
        .map_err(|error| internal(&error))?;
    Ok(Json(json!({
        "devices": devices.iter().map(device_body).collect::<Vec<_>>(),
    })))
}

/// `GET /_matrix/client/v3/devices/{deviceId}`
async fn get_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .device(&localpart_of(&identity.user_id), &device_id)
        .map_err(|error| internal(&error))?
        .map(|device| Json(device_body(&device)))
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such device"))
}

/// `PUT /_matrix/client/v3/devices/{deviceId}`
///
/// For everyone, this renames an existing device. For a service whose
/// registration declares MSC4190 device management, a PUT on a device
/// that does not exist *creates* it — the deviceless registration's way
/// of minting the device its encryption keys will hang off, with no
/// access token behind it because the `as_token` is the only credential.
async fn put_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Authenticated(identity): Authenticated,
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&identity.user_id);
    let named = body
        .as_ref()
        .and_then(|Json(body)| body.get("display_name").cloned());
    let display_of = |named: Option<Value>, unchanged: Option<String>| match named {
        None => Ok(unchanged),
        Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => Ok(Some(name)),
        Some(_) => Err(MatrixError::bad_json("display_name must be a string")),
    };
    if let Some(existing) = accounts
        .device(&localpart, &device_id)
        .map_err(|error| internal(&error))?
    {
        let display_name = display_of(named, existing.display_name)?;
        accounts
            .put_device(&localpart, &device_id, display_name)
            .map_err(|error| internal(&error))?;
        return Ok((StatusCode::OK, Json(json!({}))));
    }
    if !appservice_of(&state, &headers).is_some_and(|registration| registration.device_management) {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such device",
        ));
    }
    let display_name = display_of(named, None)?;
    accounts
        .put_device(&localpart, &device_id, display_name)
        .map_err(|error| internal(&error))?;
    let stream_write = state.rooms.reserve_stream_id();
    let seq = stream_write.id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    Ok((StatusCode::CREATED, Json(json!({}))))
}

/// `DELETE /_matrix/client/v3/devices/{deviceId}`
///
/// A person re-proves their password (single-stage UIA); a service with
/// MSC4190 device management deletes outright — its `as_token` outranks a
/// password that, for a ghost, nobody holds. Deletion takes the sessions
/// and the E2E material with it, and marks the device list changed so
/// peers stop encrypting to the dead device.
///
/// Under MSC3861 delegation there is no UIA either: a delegated user's
/// local password is unguessable by construction, so the challenge would
/// be one nobody can answer — and the caller's identity was proven
/// moments ago by the provider vouching for their live token, which is
/// a stronger statement than re-typing a password. Synapse makes the
/// same call in its delegated mode.
async fn delete_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Authenticated(identity): Authenticated,
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&identity.user_id);
    if accounts
        .device(&localpart, &device_id)
        .map_err(|error| internal(&error))?
        .is_none()
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such device",
        ));
    }
    let auth = body
        .as_ref()
        .and_then(|Json(body)| body.get("auth").cloned());
    if let Some(challenge) =
        password_uia(&state, &localpart, &headers, auth.as_ref(), "delete_device")?
    {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    accounts
        .delete_device(&localpart, &device_id)
        .map_err(|error| internal(&error))?;
    state
        .devices
        .remove_device_material(&identity.user_id, &device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let stream_write = state.rooms.reserve_stream_id();
    let seq = stream_write.id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    crate::e2ee_federation::announce_device_change(
        &state,
        &identity.user_id,
        &device_id,
        None,
        seq,
    );
    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Debug, Default, Deserialize)]
struct DeleteDevicesRequest {
    #[serde(default)]
    devices: Vec<String>,
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/delete_devices`
///
/// The bulk form of `DELETE /devices/{deviceId}`, and it shares that
/// endpoint's password stage. A device that does not exist is not an error:
/// the request asks for it to be gone, and it is.
async fn delete_devices(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: DeleteDevicesRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "delete_devices",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    for device_id in &request.devices {
        accounts
            .delete_device(&localpart, device_id)
            .map_err(|error| internal(&error))?;
        state
            .devices
            .remove_device_material(&identity.user_id, device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if !request.devices.is_empty() {
        let stream_write = state.rooms.reserve_stream_id();
        let seq = stream_write.id();
        state
            .devices
            .mark_device_list_changed(&identity.user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        state.rooms.wake_sync_waiters();
        for device_id in &request.devices {
            crate::e2ee_federation::announce_device_change(
                &state,
                &identity.user_id,
                device_id,
                None,
                seq,
            );
        }
    }
    Ok((StatusCode::OK, Json(json!({}))))
}
