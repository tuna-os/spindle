//! Moderation and reporting endpoints.
//!
//! User-facing report endpoints for rooms, users, and events.
//! Reports are filed for operator review via the admin API.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::rooms::may_read_room;
use crate::{AppState, accounts::Accounts};
use spindle_core::localpart_of;

/// `POST /_matrix/client/v3/rooms/{room_id}/report`
///
/// A user tells the server's operators that a room is a problem.
/// The report is filed for operator review via the admin API.
async fn report_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path(room_id): Path<String>,
    Json(request): Json<ReasonOnly>,
) -> Result<Json<Value>, MatrixError> {
    // Deliberately open to strangers. A report is how somebody *outside*
    // a room tells the admins about it (spec v1.13 says a reporter need
    // not be joined), so the caller's own view of the room is not the
    // gate here. What is checked is that the room exists at all: a
    // member already knows that, and a stranger learns nothing more from
    // the 404 than they would from a join attempt.
    if may_read_room(&state, &identity.user_id, &room_id).is_err() {
        // A stranger: still allowed to report, but only a room that exists.
        if state.rooms.summary(&room_id).is_err() {
            return Err(MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "no such room",
            ));
        }
    }
    let report_id = crate::admin::file_report(
        &state,
        &identity.user_id,
        Some(&room_id),
        None,
        None,
        request.reason.as_deref(),
        None,
    )?;
    crate::admin::audit(
        &state,
        &identity.user_id,
        "report",
        &room_id,
        &json!({ "room_id": room_id, "reason": request.reason, "report_id": report_id }),
    )?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/users/{userId}/report` (spec v1.14)
///
/// A report about a user. Only a local user can be reported here: a
/// report about somebody else's user belongs to their server, and this
/// one has nothing to act on. An unknown local user is a 404.
async fn report_user(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path(user_id): Path<String>,
    Json(request): Json<ReasonOnly>,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let local = user_id.ends_with(&format!(":{}", state.config.server.name))
        && accounts
            .account(&localpart_of(&user_id))
            .map_err(|error| {
                let err_string = error.to_string();
                MatrixError::new(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", &err_string)
            })?
            .is_some();
    if !local {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such user here",
        ));
    }
    let report_id = crate::admin::file_report(
        &state,
        &identity.user_id,
        None,
        None,
        Some(&user_id),
        request.reason.as_deref(),
        None,
    )?;
    crate::admin::audit(
        &state,
        &identity.user_id,
        "report",
        &user_id,
        &json!({ "user_id": user_id, "reason": request.reason, "report_id": report_id }),
    )?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/report/{event_id}`
///
/// A user tells the server's operators that an event is a problem. The
/// report is filed where the admin API's `/event_reports` reads it, by
/// an id an operator can quote, and a line goes into the audit log too,
/// which is the feed an operator already reads -- a report stored
/// somewhere nobody looks is not a moderation feature, it is the
/// appearance of one.
///
/// **404 covers both "no such event" and "you cannot see it", deliberately
/// and per the spec.** Distinguishing them would turn this endpoint into an
/// oracle for whether a given event ID exists in a room the caller is not
/// in, which is exactly the thing a reporting endpoint must not become.
async fn report_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(request): Json<ReportRequest>,
) -> Result<Json<Value>, MatrixError> {
    // The spec's range, and it is signed: a "score" here runs from -100
    // (worst) to 0, so a positive number is a caller who has misread the
    // API rather than one paying a compliment.
    if let Some(score) = request.score
        && !(-100..=0).contains(&score)
    {
        return Err(MatrixError::bad_json(format!(
            "score must be between -100 and 0, not {score}"
        )));
    }
    let not_found = || MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such event");
    if may_read_room(&state, &identity.user_id, &room_id).is_err() {
        return Err(not_found());
    }
    let event = state
        .rooms
        .event(&room_id, &event_id)
        .map_err(|_| not_found())?;

    let report_id = crate::admin::file_event_report(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        event["sender"].as_str(),
        request.reason.as_deref(),
        request.score,
    )?;
    crate::admin::audit(
        &state,
        &identity.user_id,
        "report",
        &event_id,
        &json!({
            "room_id": room_id,
            "reason": request.reason,
            "score": request.score,
            "report_id": report_id,
        }),
    )?;
    Ok(Json(json!({})))
}

/// Moderation reporting routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/rooms/{room_id}/report",
            post(report_room),
        )
        .route(
            "/_matrix/client/v3/users/{user_id}/report",
            post(report_user),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/report/{event_id}",
            post(report_event),
        )
}

#[derive(Debug, Deserialize, Serialize)]
struct ReasonOnly {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReportRequest {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    score: Option<i64>,
}
