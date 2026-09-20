//! Server notices: a message from the operator to one user, in a room
//! this server opens for the two of them (`POST /send_server_notice`).
//!
//! The notice is an ordinary event from an ordinary account, sent through
//! the same append path as everything else: the notices account is a
//! local user created on first use, the room is a private room it
//! creates with the recipient invited, and the recipient's client files
//! it under the `m.server_notice` tag the way Element expects. Nothing
//! here is surgery on the log.

use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::{Accounts, unguessable_password};
use crate::errors::MatrixError;
use crate::routes::room_error;

/// What an admin asked to send.
pub struct Notice<'a> {
    pub user_id: &'a str,
    pub content: &'a Value,
    pub event_type: &'a str,
}

/// Send `notice`, opening the recipient's notices room first if there is
/// none. Returns the event id.
///
/// # Errors
///
/// 400 when `[server_notices]` is not configured, 404 for a recipient this
/// server does not hold, and the room layer's refusals otherwise.
pub fn send(state: &AppState, notice: &Notice<'_>) -> Result<String, MatrixError> {
    let Some(config) = &state.config.server_notices else {
        return Err(MatrixError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "server notices are not configured: set [server_notices] in the config",
        ));
    };
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let Some(localpart) = crate::admin::local_localpart(state, notice.user_id) else {
        return Err(MatrixError::new(
            axum::http::StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "not a user of this server",
        ));
    };
    if accounts
        .account(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_none()
    {
        return Err(MatrixError::new(
            axum::http::StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such user here",
        ));
    }

    // The notices account, born on first use with a password nobody holds.
    let sender = accounts.user_id(&config.localpart);
    if accounts
        .account(&config.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_none()
    {
        accounts
            .register(&config.localpart, &unguessable_password())
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        state
            .profiles
            .set(&sender, Some(Some(config.display_name.clone())), None)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }

    let room_id = notices_room(state, &sender, notice.user_id, &config.room_name)?;
    let event_id = state
        .rooms
        .send(
            &room_id,
            &sender,
            state.key.pair(),
            notice.event_type,
            notice.content,
        )
        .map_err(room_error)?;
    Ok(event_id)
}

/// The room this server talks to `user_id` in: the one on record if it
/// still stands, with the user asked back in when they left; otherwise a
/// fresh private room with them invited, tagged `m.server_notice` for
/// them.
fn notices_room(
    state: &AppState,
    sender: &str,
    user_id: &str,
    room_name: &str,
) -> Result<String, MatrixError> {
    let internal = |error: spindle_store::StoreError| MatrixError::internal(&error.to_string());
    let recorded = ReadView::get(state.store.as_ref(), &keys::server_notice_room(user_id))
        .map_err(internal)?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|room_id| state.rooms.summary(room_id).is_ok());
    if let Some(room_id) = recorded {
        let membership = state
            .rooms
            .state(&room_id)
            .map_err(room_error)?
            .into_iter()
            .find(|event| event["type"] == "m.room.member" && event["state_key"] == user_id)
            .and_then(|event| event["content"]["membership"].as_str().map(str::to_owned));
        if !matches!(membership.as_deref(), Some("join" | "invite")) {
            state
                .rooms
                .set_membership(&room_id, sender, user_id, "invite", None, state.key.pair())
                .map_err(room_error)?;
        }
        return Ok(room_id);
    }
    let profile = state.profiles.get(sender).map_err(internal)?;
    let mut creator_profile = serde_json::Map::new();
    if let Some(name) = profile.displayname {
        creator_profile.insert("displayname".to_owned(), json!(name));
    }
    let room_id = state
        .rooms
        .create(
            sender,
            state.key.pair(),
            Some(room_name),
            None,
            Some("private_chat"),
            &[],
            &[],
            None,
            None,
            None,
            &creator_profile,
        )
        .map_err(room_error)?;
    // A local user, so the invite is one membership event; nothing crosses
    // federation here.
    state
        .rooms
        .set_membership(&room_id, sender, user_id, "invite", None, state.key.pair())
        .map_err(room_error)?;
    Store::put(
        state.store.as_ref(),
        &keys::server_notice_room(user_id),
        room_id.as_bytes(),
    )
    .map_err(internal)?;
    let mut tags = state
        .account_data
        .get(user_id, &room_id, "m.tag")
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    if !tags["tags"].is_object() {
        tags["tags"] = json!({});
    }
    tags["tags"]["m.server_notice"] = json!({});
    state
        .account_data
        .put(user_id, &room_id, "m.tag", &tags)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(room_id)
}
