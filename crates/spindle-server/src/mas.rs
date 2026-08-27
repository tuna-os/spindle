//! The provisioning surface a delegated auth provider drives.
//!
//! Under MSC3861 the provider owns accounts, which means account
//! *lifecycle* — creation, deactivation, devices, display names — is
//! decided over there and executed here. The Matrix Authentication
//! Service speaks one concrete dialect for that: the `/_synapse/mas/*`
//! API it uses to drive Synapse. Implementing the same dialect is what
//! lets an unmodified MAS run this server; inventing a nicer one would
//! only mean nobody's provider speaks it.
//!
//! The whole surface is guarded by one bearer secret
//! (`auth.delegated.homeserver_secret` here, `matrix.secret` in MAS's
//! config), and does not exist at all — 404, like every other
//! unconfigured feature — until delegation with that secret is
//! configured. The check is a hash comparison for the same reason token
//! lookups are: a byte-by-byte equality over a secret is a timing oracle.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::accounts::{AccountError, Accounts, unguessable_password};
use crate::errors::MatrixError;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_synapse/mas/query_user", get(query_user))
        .route(
            "/_synapse/mas/is_localpart_available",
            get(is_localpart_available),
        )
        .route("/_synapse/mas/provision_user", post(provision_user))
        .route("/_synapse/mas/upsert_device", post(upsert_device))
        .route("/_synapse/mas/delete_device", post(delete_device))
        .route(
            "/_synapse/mas/update_device_display_name",
            post(update_device_display_name),
        )
        .route("/_synapse/mas/sync_devices", post(sync_devices))
        .route("/_synapse/mas/delete_user", post(delete_user))
        .route("/_synapse/mas/reactivate_user", post(reactivate_user))
        .route("/_synapse/mas/set_displayname", post(set_displayname))
        .route("/_synapse/mas/unset_displayname", post(unset_displayname))
        .route(
            "/_synapse/mas/allow_cross_signing_reset",
            post(allow_cross_signing_reset),
        )
}

/// Admit only the configured provider, or explain why not.
///
/// Unconfigured is `M_UNRECOGNIZED`, exactly what an unknown endpoint
/// answers: a deployment without delegation does not have this surface,
/// and should not reveal that it *could*. A wrong secret is plain 403.
fn admit(state: &AppState, headers: &HeaderMap) -> Result<(), MatrixError> {
    let Some(secret) = state
        .config
        .auth
        .delegated
        .as_ref()
        .and_then(|delegated| delegated.homeserver_secret.as_deref())
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "no delegated auth provider manages this server",
        ));
    };
    let presented = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if blake3::hash(presented.as_bytes()) != blake3::hash(secret.as_bytes()) {
        return Err(MatrixError::forbidden("that is not the provider's secret"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ByLocalpart {
    localpart: String,
}

/// `GET /_synapse/mas/query_user?localpart=…`
async fn query_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ByLocalpart>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let Some(account) = accounts
        .account(&query.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such user",
        ));
    };
    let user_id = accounts.user_id(&account.localpart);
    let profile = state
        .profiles
        .get(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({
        "user_id": user_id,
        "display_name": profile.displayname,
        "avatar_url": profile.avatar_url,
        // Suspension (locked-but-not-deactivated) is a state this server
        // does not have; a suspended-in-MAS user is simply active here
        // until MAS deactivates them for real.
        "is_suspended": false,
        "is_deactivated": account.deactivated,
    })))
}

/// `GET /_synapse/mas/is_localpart_available?localpart=…`
///
/// 200 means yes; the refusals are the same Matrix errors registration
/// would give, which is exactly what MAS's client matches on.
async fn is_localpart_available(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ByLocalpart>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    match accounts.availability(&query.localpart) {
        Ok(()) => {}
        Err(AccountError::UserInUse) => return Err(MatrixError::user_in_use()),
        Err(AccountError::InvalidUsername) => return Err(MatrixError::invalid_username()),
        Err(other) => return Err(MatrixError::internal(&other.to_string())),
    }
    // Exclusive appservice namespaces reserve names against everyone,
    // the auth provider included — the bridge got there first.
    let user_id = accounts.user_id(&query.localpart);
    if state.appservices.exclusively_claims(&user_id) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_EXCLUSIVE",
            "this localpart is reserved by an application service",
        ));
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct ProvisionRequest {
    localpart: String,
    set_displayname: Option<String>,
    #[serde(default)]
    unset_displayname: bool,
    set_avatar_url: Option<String>,
    #[serde(default)]
    unset_avatar_url: bool,
    // MAS also sends `set_emails`/`unset_emails` and `locked`; this
    // server stores no email addresses and has no lock state, so those
    // fields are accepted and deliberately unread — refusing them would
    // fail every provision for data there is nowhere to put.
}

/// `POST /_synapse/mas/provision_user` — 201 created it, 200 updated it.
async fn provision_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProvisionRequest>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let known = accounts
        .account(&request.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if !known {
        accounts
            .register(&request.localpart, &unguessable_password())
            .map_err(|error| match error {
                AccountError::InvalidUsername => MatrixError::invalid_username(),
                other => MatrixError::internal(&other.to_string()),
            })?;
    }
    let displayname = match (&request.set_displayname, request.unset_displayname) {
        (Some(name), _) => Some(Some(name.clone())),
        (None, true) => Some(None),
        (None, false) => None,
    };
    let avatar_url = match (&request.set_avatar_url, request.unset_avatar_url) {
        (Some(url), _) => Some(Some(url.clone())),
        (None, true) => Some(None),
        (None, false) => None,
    };
    if displayname.is_some() || avatar_url.is_some() {
        let user_id = accounts.user_id(&request.localpart);
        state
            .profiles
            .set(&user_id, displayname, avatar_url)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let status = if known {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(json!({}))))
}

#[derive(Deserialize)]
struct DeviceRequest {
    localpart: String,
    device_id: String,
    display_name: Option<String>,
}

/// `POST /_synapse/mas/upsert_device`
async fn upsert_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    // An upsert without a display name keeps the one the device has —
    // MAS names a device once at creation, then never re-sends it.
    let display_name = match request.display_name {
        Some(name) => Some(name),
        None => accounts
            .device(&request.localpart, &request.device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .and_then(|device| device.display_name),
    };
    accounts
        .put_device(&request.localpart, &request.device_id, display_name)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    device_list_changed(&state, &accounts.user_id(&request.localpart));
    Ok(Json(json!({})))
}

/// `POST /_synapse/mas/delete_device`
///
/// Idempotent on purpose: MAS retries its jobs, and re-deleting a
/// device that is already gone succeeded the first time.
async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    remove_device(&state, &accounts, &request.localpart, &request.device_id)?;
    device_list_changed(&state, &accounts.user_id(&request.localpart));
    Ok(Json(json!({})))
}

/// `POST /_synapse/mas/update_device_display_name`
async fn update_device_display_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    if accounts
        .device(&request.localpart, &request.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_none()
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such device",
        ));
    }
    accounts
        .put_device(&request.localpart, &request.device_id, request.display_name)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct SyncDevicesRequest {
    localpart: String,
    devices: std::collections::HashSet<String>,
}

/// `POST /_synapse/mas/sync_devices` — make ours match the provider's
/// set exactly. This is MAS's recovery path when it suspects drift.
async fn sync_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncDevicesRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let ours = accounts
        .devices_of(&request.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let mut changed = false;
    for device in &ours {
        if !request.devices.contains(&device.device_id) {
            remove_device(&state, &accounts, &request.localpart, &device.device_id)?;
            changed = true;
        }
    }
    let known: std::collections::HashSet<&str> = ours
        .iter()
        .map(|device| device.device_id.as_str())
        .collect();
    for device_id in &request.devices {
        if !known.contains(device_id.as_str()) {
            accounts
                .put_device(&request.localpart, device_id, None)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            changed = true;
        }
    }
    if changed {
        device_list_changed(&state, &accounts.user_id(&request.localpart));
    }
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct DeleteUserRequest {
    localpart: String,
    #[serde(default)]
    erase: bool,
}

/// `POST /_synapse/mas/delete_user` — deactivation, the provider's way.
///
/// The account row stays: the localpart is reserved forever, because a
/// released name would hand the old user's identity to whoever registers
/// it next. Sessions and devices go, which is what "logged out
/// everywhere" means. `erase` additionally clears the profile.
async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeleteUserRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let devices = accounts
        .devices_of(&request.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for device in devices {
        remove_device(&state, &accounts, &request.localpart, &device.device_id)?;
    }
    accounts
        .set_deactivated(&request.localpart, true)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let user_id = accounts.user_id(&request.localpart);
    if request.erase {
        state
            .profiles
            .set(&user_id, Some(None), Some(None))
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    device_list_changed(&state, &user_id);
    Ok(Json(json!({})))
}

/// `POST /_synapse/mas/reactivate_user`
async fn reactivate_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ByLocalpart>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_deactivated(&request.localpart, false)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct DisplaynameRequest {
    localpart: String,
    displayname: String,
}

/// `POST /_synapse/mas/set_displayname`
async fn set_displayname(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DisplaynameRequest>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    state
        .profiles
        .set(
            &accounts.user_id(&request.localpart),
            Some(Some(request.displayname)),
            None,
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

/// `POST /_synapse/mas/unset_displayname`
async fn unset_displayname(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ByLocalpart>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    state
        .profiles
        .set(&accounts.user_id(&request.localpart), Some(None), None)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

/// `POST /_synapse/mas/allow_cross_signing_reset`
///
/// Synapse uses this to open a UIA-free window for replacing
/// cross-signing keys. This server does not (yet) demand UIA for that
/// upload, so the window is always open and the call has nothing to do —
/// acknowledged rather than refused, because MAS treats an error here as
/// a failed job and retries it forever.
async fn allow_cross_signing_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_request): Json<ByLocalpart>,
) -> Result<Json<Value>, MatrixError> {
    admit(&state, &headers)?;
    Ok(Json(json!({})))
}

/// One device, gone whole: the row, its sessions, its E2E material.
fn remove_device(
    state: &AppState,
    accounts: &Accounts<'_, spindle_store::FjallStore>,
    localpart: &str,
    device_id: &str,
) -> Result<(), MatrixError> {
    accounts
        .delete_device(localpart, device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state
        .devices
        .remove_device_material(&accounts.user_id(localpart), device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(())
}

/// Mark the user's device list changed and wake `/sync`, so peers stop
/// (or start) encrypting to the right set of devices.
fn device_list_changed(state: &AppState, user_id: &str) {
    let seq = state.rooms.allocate_stream_id();
    if let Err(error) = state.devices.mark_device_list_changed(user_id, seq) {
        tracing::warn!(user_id, %error, "device-list change mark failed");
    }
    state.rooms.wake_sync_waiters();
}
