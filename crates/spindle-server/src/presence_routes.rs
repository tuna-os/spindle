//! User presence endpoints.
//!
//! Handles presence status updates and queries per the Matrix Client-Server
//! specification (§ Presence). Presence is stored in [`crate::presence::State`]
//! and exposed as read-only to users who share a room or are querying their
//! own presence (to prevent privacy leakage via presence patterns).

use axum::{
    Json, Router,
    extract::State,
    routing::{get, put},
};
use serde_json::{json, Value};

use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::AppState;

/// `PUT /_matrix/client/v3/presence/{user_id}/status`
///
/// Set your own presence. The spec is explicit that this sets *the caller's*
/// presence, and a server that let one user mark another offline would be
/// handing out a small denial-of-service against every client that renders
/// an online indicator.
///
/// **Authentication**: Required.
/// **Spec**: [§ 9.2](https://spec.matrix.org/v1.11/client-server-api/#put_matrixclientv3presenceuser_idstatus)
async fn put_presence(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<PresenceRequest>,
) -> Result<Json<Value>, MatrixError> {
    if user_id != identity.user_id {
        return Err(MatrixError::forbidden(
            "you cannot set another user's presence",
        ));
    }
    let presence = crate::presence::State::parse(&request.presence).ok_or_else(|| {
        MatrixError::bad_json(format!(
            "presence must be 'online', 'offline' or 'unavailable', not {:?}",
            request.presence
        ))
    })?;
    state
        .presence
        .set(&identity.user_id, presence, request.status_msg.as_deref())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/presence/{user_id}/status`
///
/// Query a user's presence. Only returns presence for your own user, or for
/// users you share a room with. The spec defines a 403 here for exactly this,
/// and it is worth having rather than serving presence to anyone who asks:
/// presence is a continuous signal about when a person is at their computer,
/// and an unauthenticated-in-practice one would let any account on this server
/// watch any other.
///
/// **Authentication**: Required.
/// **Spec**: [§ 9.1](https://spec.matrix.org/v1.11/client-server-api/#get_matrixclientv3presenceuser_idstatus)
async fn get_presence(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if user_id != identity.user_id && !shares_a_room(&state, &identity.user_id, &user_id)? {
        return Err(MatrixError::forbidden(
            "you are not allowed to see this user's presence status",
        ));
    }
    let status = state
        .presence
        .get(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let mut body = json!({
        "presence": status.state.as_str(),
        "last_active_ago": status.last_active_ago,
        "currently_active": status.currently_active,
    });
    if let Some(message) = status.status_msg {
        body["status_msg"] = Value::String(message);
    }
    Ok(Json(body))
}

/// Mount all presence-related routes.
///
/// This is called from [`crate::routes::profile_routes()`].
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/_matrix/client/v3/presence/{user_id}/status",
        get(get_presence).put(put_presence),
    )
}

// ---- Helpers ----

/// Check if two users share a room.
///
/// Used to determine if one user can view another's presence.
fn shares_a_room(
    state: &AppState,
    asker: &str,
    about: &str,
) -> Result<bool, MatrixError> {
    let rooms = state
        .rooms
        .joined(asker)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for room in rooms {
        if state
            .rooms
            .is_joined(about, &room)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Request body for setting presence.
#[derive(serde::Deserialize)]
struct PresenceRequest {
    presence: String,
    #[serde(default)]
    status_msg: Option<String>,
}
