//! Per-user data that is not in any room's log: account data, room tags and
//! sync filters.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{account_data_error, limit_exceeded};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde_json::{Value, json};

/// Account data, tags and filters.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/user/{user_id}/account_data/{event_type}",
            get(get_account_data).put(set_account_data),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}",
            get(get_room_account_data).put(set_room_account_data),
        )
        // Tags are not their own storage: the spec models them as the `m.tag`
        // room account-data event, and these endpoints are views over it.
        // That is what makes them appear in /sync's per-room account data
        // with no extra wiring -- there is only one value to keep true.
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags",
            get(get_tags),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}",
            axum::routing::put(set_tag).delete(delete_tag),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/filter",
            post(create_filter),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/filter/{filter_id}",
            get(get_filter),
        )
}

/// `GET /_matrix/client/v3/user/{user_id}/account_data/{event_type}`
async fn get_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, event_type)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    read_account_data(&state, &identity, &user_id, "", &event_type)
}

/// `PUT /_matrix/client/v3/user/{user_id}/account_data/{event_type}`
async fn set_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, event_type)): axum::extract::Path<(String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    write_account_data(&state, &identity, &user_id, "", &event_type, &content)
}

/// `GET /_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}`
async fn get_room_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, event_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Value>, MatrixError> {
    read_account_data(&state, &identity, &user_id, &room_id, &event_type)
}

/// `PUT /_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}`
async fn set_room_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, event_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    write_account_data(&state, &identity, &user_id, &room_id, &event_type, &content)
}

/// Account data is per-user and private, so the `user_id` in the path has to
/// be the caller's.
///
/// The spec says `M_FORBIDDEN` for someone else's, and that is the right code
/// even though the data may not exist: answering `M_NOT_FOUND` for a user who
/// has set nothing and `M_FORBIDDEN` for one who has would turn this endpoint
/// into an oracle for what other people have configured.
fn own_account(identity: &crate::accounts::Identity, user_id: &str) -> Result<(), MatrixError> {
    if identity.user_id == user_id {
        return Ok(());
    }
    Err(MatrixError::forbidden(
        "account data belongs to the user who set it",
    ))
}

fn read_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    user_id: &str,
    room_id: &str,
    event_type: &str,
) -> Result<Json<Value>, MatrixError> {
    own_account(identity, user_id)?;
    state
        .account_data
        .get(user_id, room_id, event_type)
        .map_err(|error| account_data_error(&error))?
        .map(Json)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no {event_type} for {user_id}"),
            )
        })
}

/// Account-data types this endpoint must not write.
///
/// Both have an endpoint of their own that does more than store bytes:
/// `m.push_rules` is edited a rule at a time through `/pushrules/`, and
/// `m.fully_read` moves a receipt through `/read_markers`. Letting a client
/// `PUT` them here would put a second writer on a value the server also
/// maintains, and the two would drift.
const RESERVED_ACCOUNT_DATA: [&str; 2] = ["m.push_rules", "m.fully_read"];

fn write_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    user_id: &str,
    room_id: &str,
    event_type: &str,
    content: &Value,
) -> Result<Json<Value>, MatrixError> {
    own_account(identity, user_id)?;
    if RESERVED_ACCOUNT_DATA.contains(&event_type) {
        return Err(MatrixError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "M_BAD_JSON",
            format!("{event_type} has its own endpoint and cannot be set here"),
        ));
    }
    // The server keeps the bytes and has no opinion about them, so there is no
    // validation of `content` beyond it being JSON -- which the extractor has
    // already established. A client inventing a new `event_type` has to work
    // on a server that has never heard of it.
    //
    // What it may not do is invent them without end. A replacement never
    // counts: the cap is on how much is held, not on how often it changes.
    let cap = state.config.limits.account_data_per_user;
    let is_new = state
        .account_data
        .get(user_id, room_id, event_type)
        .map_err(|error| account_data_error(&error))?
        .is_none();
    if is_new
        && state
            .account_data
            .count(user_id)
            .map_err(|error| account_data_error(&error))?
            >= cap
    {
        return Err(limit_exceeded("account data entries", cap));
    }
    let stream_write = state.rooms.reserve_stream_id();
    let position = stream_write.id();
    state
        .account_data
        .put(user_id, room_id, event_type, content, position)
        .map_err(|error| account_data_error(&error))?;
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/user/{user_id}/filter`
///
/// The filter is parsed here rather than stored as opaque bytes, so a
/// malformed one is refused at upload instead of on every sync that quotes it.
async fn create_filter(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(filter): Json<crate::filters::Filter>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    // Every upload mints a new id, so every upload is growth; a client that
    // wants the same filter back is expected to keep the id it was given.
    let cap = state.config.limits.filters_per_user;
    if state
        .filters
        .count(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        >= cap
    {
        return Err(limit_exceeded("filters", cap));
    }
    let filter_id = state
        .filters
        .put(&user_id, &filter)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "filter_id": filter_id })))
}

/// `GET /_matrix/client/v3/user/{user_id}/filter/{filter_id}`
async fn get_filter(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, filter_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let filter = state
        .filters
        .get(&user_id, &filter_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no filter {filter_id}"),
            )
        })?;
    Ok(Json(
        serde_json::to_value(filter).unwrap_or_else(|_| json!({})),
    ))
}

/// `GET /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags`
async fn get_tags(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    // A user who never tagged anything gets an empty map, not a 404: "no
    // tags" is an ordinary answer here, where for general account data an
    // unset type is a 404. The difference is that this endpoint's shape is
    // fixed by the spec and a client iterates the map unconditionally.
    Ok(Json(tags))
}

/// `PUT /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}`
async fn set_tag(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, tag)): axum::extract::Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let mut tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    if !tags["tags"].is_object() {
        tags["tags"] = json!({});
    }
    // The body is the tag's content -- `order` and whatever else the client
    // keeps there. Stored as given: the server has no opinion about tag
    // content for the same reason it has none about account data generally.
    tags["tags"][&tag] = content;
    let stream_write = state.rooms.reserve_stream_id();
    let position = stream_write.id();
    state
        .account_data
        .put(&user_id, &room_id, "m.tag", &tags, position)
        .map_err(|error| account_data_error(&error))?;
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}`
async fn delete_tag(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, tag)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let mut tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    let removed = tags["tags"]
        .as_object_mut()
        .is_some_and(|map| map.remove(&tag).is_some());
    if !removed {
        // The spec's own answer for deleting a tag that is not there. Quietly
        // returning {} would be defensible; 404 is what Synapse does and what
        // clients therefore already handle.
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{room_id} is not tagged {tag}"),
        ));
    }
    let stream_write = state.rooms.reserve_stream_id();
    let position = stream_write.id();
    state
        .account_data
        .put(&user_id, &room_id, "m.tag", &tags, position)
        .map_err(|error| account_data_error(&error))?;
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}
