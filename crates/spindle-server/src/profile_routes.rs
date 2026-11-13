//! Global profile endpoints: read anyone's profile, write your own.

use crate::AppState;
use crate::accounts::Accounts;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{internal, room_error};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Deserialize;
use serde_json::{Value, json};

/// Registration, login, and the per-user data that is not in any room.
/// The global-profile surface: read anyone's, write your own.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/profile/{user_id}", get(get_profile))
        .route(
            "/_matrix/client/v3/profile/{user_id}/displayname",
            get(get_profile_displayname).put(put_profile_displayname),
        )
        .route(
            "/_matrix/client/v3/profile/{user_id}/avatar_url",
            get(get_profile_avatar).put(put_profile_avatar),
        )
        .route(
            "/_matrix/client/v3/profile/{user_id}/{key}",
            get(get_profile_field)
                .put(put_profile_field)
                .delete(delete_profile_field),
        )
}

/// Read a profile, wherever the user lives.
///
/// A local user's profile is the stored row. A remote user's is their
/// server's to answer, over `query/profile` — which is how a client here
/// renders the name of someone it has never shared a room with.
pub(crate) async fn profile_of(state: &AppState, user_id: &str) -> Result<Value, MatrixError> {
    let domain = user_id.split_once(':').map(|(_, domain)| domain);
    if domain == Some(state.config.server.name.as_str()) {
        let localpart = user_id.strip_prefix('@').map_or(user_id, |rest| {
            rest.split_once(':')
                .map_or(rest, |(localpart, _)| localpart)
        });
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        let known = accounts
            .account(localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_some();
        // The classic appservice user query: a namespace ghost may exist
        // the moment its service is asked, so an unknown local user gets
        // one chance to be provisioned before the 404 stands.
        let known = known
            || (state
                .appservices
                .query_user(user_id, &state.config.server.name)
                .await
                && accounts
                    .account(localpart)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?
                    .is_some());
        if !known {
            return Err(MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("{user_id} is not here"),
            ));
        }
        let profile = state
            .profiles
            .get(user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        return serde_json::to_value(profile)
            .map_err(|error| MatrixError::internal(&error.to_string()));
    }
    let Some(domain) = domain else {
        return Err(MatrixError::bad_json(format!("{user_id} is not a user ID")));
    };
    state
        .federation
        .remote_query_profile(domain, user_id)
        .await
        .map_err(|error| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("{domain} did not answer for {user_id}: {error}"),
            )
        })
}

/// `GET /_matrix/client/v3/profile/{userId}`
async fn get_profile(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    Ok(Json(profile_of(&state, &user_id).await?))
}

/// `GET /_matrix/client/v3/profile/{userId}/displayname`
async fn get_profile_displayname(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let profile = profile_of(&state, &user_id).await?;
    let mut body = serde_json::Map::new();
    if let Some(name) = profile.get("displayname").filter(|v| !v.is_null()) {
        body.insert("displayname".to_owned(), name.clone());
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/profile/{userId}/avatar_url`
async fn get_profile_avatar(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let profile = profile_of(&state, &user_id).await?;
    let mut body = serde_json::Map::new();
    if let Some(url) = profile.get("avatar_url").filter(|v| !v.is_null()) {
        body.insert("avatar_url".to_owned(), url.clone());
    }
    Ok(Json(Value::Object(body)))
}

#[derive(Debug, Deserialize)]
struct DisplaynameRequest {
    displayname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AvatarRequest {
    avatar_url: Option<String>,
}

/// `GET /_matrix/client/v3/profile/{userId}/{keyName}` (spec v1.16)
///
/// One field of a profile, `displayname` and `avatar_url` included; the
/// literal routes for those two still answer first. A field that is not
/// set is a 404, which is the spec's answer and the one a client can act
/// on.
async fn get_profile_field(
    State(state): State<AppState>,
    axum::extract::Path((user_id, key)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let profile = profile_of(&state, &user_id).await?;
    match profile.get(&key).filter(|value| !value.is_null()) {
        Some(value) => Ok(Json(json!({ key: value }))),
        None => Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{user_id} has no {key}"),
        )),
    }
}

/// The user's own profile, or a server admin acting for them.
fn may_edit_profile(state: &AppState, actor: &str, user_id: &str) -> Result<(), MatrixError> {
    if actor == user_id
        || crate::admin::is_server_admin(state, actor).map_err(|error| internal(&error))?
    {
        Ok(())
    } else {
        Err(MatrixError::forbidden("a profile belongs to its user"))
    }
}

fn field_refusal(refusal: crate::profiles::FieldRefusal) -> MatrixError {
    match refusal {
        crate::profiles::FieldRefusal::KeyTooLarge => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_KEY_TOO_LARGE",
            format!(
                "a profile key is at most {} bytes",
                crate::profiles::MAX_KEY_BYTES
            ),
        ),
        crate::profiles::FieldRefusal::ProfileTooLarge => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_PROFILE_TOO_LARGE",
            format!(
                "a profile is at most {} bytes",
                crate::profiles::MAX_PROFILE_BYTES
            ),
        ),
        crate::profiles::FieldRefusal::NotAString => {
            MatrixError::bad_json("displayname and avatar_url are strings")
        }
    }
}

/// `PUT /_matrix/client/v3/profile/{userId}/{keyName}` (spec v1.16)
///
/// The body names the key again, as the spec has it; a body that names
/// a different key is a request that does not agree with itself.
async fn put_profile_field(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, key)): axum::extract::Path<(String, String)>,
    Json(mut request): Json<serde_json::Map<String, Value>>,
) -> Result<Json<Value>, MatrixError> {
    may_edit_profile(&state, &identity.user_id, &user_id)?;
    let Some(value) = request.remove(&key) else {
        return Err(MatrixError::bad_json(format!("the body must carry {key}")));
    };
    state
        .profiles
        .set_field(&user_id, &key, Some(value))
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .map_err(field_refusal)?;
    if key == "displayname" || key == "avatar_url" {
        propagate_profile(&state, &user_id).await?;
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/profile/{userId}/{keyName}` (spec v1.16)
async fn delete_profile_field(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, key)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    may_edit_profile(&state, &identity.user_id, &user_id)?;
    state
        .profiles
        .set_field(&user_id, &key, None)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .map_err(field_refusal)?;
    if key == "displayname" || key == "avatar_url" {
        propagate_profile(&state, &user_id).await?;
    }
    Ok(Json(json!({})))
}

/// Store one profile field and copy it into every joined room's member
/// event — the propagation the spec asks for, and the step that carries a
/// renamed user across federation, because member events fan out and
/// profile rows do not.
pub(crate) async fn propagate_profile(state: &AppState, user_id: &str) -> Result<(), MatrixError> {
    let profile = state
        .profiles
        .get(user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let rooms = state
        .rooms
        .joined(user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for room_id in rooms {
        let mut content = json!({ "membership": "join" });
        if let Some(name) = &profile.displayname {
            content["displayname"] = json!(name);
        }
        if let Some(url) = &profile.avatar_url {
            content["avatar_url"] = json!(url);
        }
        state
            .rooms
            .set_state_checked(
                &room_id,
                user_id,
                state.key.pair(),
                "m.room.member",
                user_id,
                &content,
            )
            .await
            .map_err(room_error)?;
    }
    state.rooms.wake_sync_waiters();
    Ok(())
}

/// `PUT /_matrix/client/v3/profile/{userId}/displayname`
async fn put_profile_displayname(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<DisplaynameRequest>,
) -> Result<Json<Value>, MatrixError> {
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden("a profile belongs to its user"));
    }
    state
        .profiles
        .set(&user_id, Some(request.displayname), None)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    propagate_profile(&state, &user_id).await?;
    Ok(Json(json!({})))
}

/// `PUT /_matrix/client/v3/profile/{userId}/avatar_url`
async fn put_profile_avatar(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<AvatarRequest>,
) -> Result<Json<Value>, MatrixError> {
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden("a profile belongs to its user"));
    }
    state
        .profiles
        .set(&user_id, None, Some(request.avatar_url))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    propagate_profile(&state, &user_id).await?;
    Ok(Json(json!({})))
}
