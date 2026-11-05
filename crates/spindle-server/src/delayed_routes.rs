//! MSC4140 delayed events: scheduling, lookup and management.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{DelayQuery, delay_error, delay_error_as, room_error};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

/// MSC4140's delayed events: scheduling, lookup and management, under the
/// stable paths the merged MSC names and the unstable ones shipping clients
/// call.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
            get(delayed_events),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
            post(delayed_event_action).get(delayed_event_lookup),
        )
        // MSC4140 as merged: scheduling through an endpoint of its own, and
        // the stable management and lookup paths, beside the unstable ones
        // shipping clients call.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
            axum::routing::put(delayed_event_put_unstable),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
            axum::routing::put(delayed_event_put_stable),
        )
        .route(
            "/_matrix/client/v1/delayed_events/{delay_id}",
            get(delayed_event_lookup),
        )
        .route(
            "/_matrix/client/v1/delayed_events/{delay_id}/{action}",
            post(delayed_event_action_stable),
        )
        // The current MSC4140 shape: the action in the path and no access
        // token, so a delegate (lk-jwt-service) can keep a leave event
        // pending, or send it, for a client that has gone away.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}",
            post(delayed_event_action_by_id),
        )
}

/// One delay as MSC4140's lookup reports it, pending or finished.
fn delay_info(event: &crate::delayed::DelayedEvent) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("delay_id".to_owned(), json!(event.delay_id));
    entry.insert("room_id".to_owned(), json!(event.room_id));
    entry.insert("type".to_owned(), json!(event.event_type));
    if let Some(state_key) = &event.state_key {
        entry.insert("state_key".to_owned(), json!(state_key));
    }
    let since = event.fire_at_ms.saturating_sub(event.delay_ms);
    entry.insert("delay_ms".to_owned(), json!(event.delay_ms));
    entry.insert("delayed_since_ts".to_owned(), json!(since));
    // The names the list endpoint has always used, kept beside the merged
    // ones: they are what Synapse sends and what shipping clients read.
    entry.insert("delay".to_owned(), json!(event.delay_ms));
    entry.insert("running_since".to_owned(), json!(since));
    entry.insert("content".to_owned(), event.content.clone());
    Value::Object(entry)
}

/// The same for a delay that has finished, with how it finished.
fn finalised_info(record: &crate::delayed::FinalisedDelay) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("delay_id".to_owned(), json!(record.delay_id));
    entry.insert("room_id".to_owned(), json!(record.room_id));
    entry.insert("type".to_owned(), json!(record.event_type));
    if let Some(state_key) = &record.state_key {
        entry.insert("state_key".to_owned(), json!(state_key));
    }
    entry.insert("delay_ms".to_owned(), json!(record.delay_ms));
    entry.insert(
        "delayed_since_ts".to_owned(),
        json!(record.delayed_since_ts),
    );
    entry.insert("content".to_owned(), record.content.clone());
    let mut finalised = serde_json::Map::new();
    if let Some(event_id) = &record.event_id {
        finalised.insert("event_id".to_owned(), json!(event_id));
    }
    if let Some(error) = &record.error {
        finalised.insert(
            "error".to_owned(),
            json!({
                "errcode": record.errcode.as_deref().unwrap_or("M_UNKNOWN"),
                "error": error,
            }),
        );
    }
    finalised.insert("finalised_ts".to_owned(), json!(record.finalised_ts));
    entry.insert("finalised".to_owned(), Value::Object(finalised));
    Value::Object(entry)
}

/// `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events`
///
/// What this caller is still waiting on. Scoped to the caller: a delay is a
/// pending action taken in their name, and whose it is is the only sensible
/// unit here. Not in MSC4140 as merged (MSC4486 takes it on), and kept
/// because Synapse serves it and clients call it.
async fn delayed_events(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let pending = state.delayed.list(&identity.user_id).map_err(delay_error)?;
    let chunk: Vec<Value> = pending.iter().map(delay_info).collect();
    Ok(Json(json!({ "delayed_events": chunk })))
}

/// `GET /_matrix/client/v1/delayed_events/{delay_id}`, and its unstable
/// alias.
///
/// One delay of the caller's, pending or finished: MSC4140's way for a
/// client that was away to learn whether its delay was sent, cancelled or
/// refused, and why. Another user's delay is not found, exactly as one that
/// never existed.
async fn delayed_event_lookup(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(delay_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    match state.delayed.get(&delay_id, &identity.user_id) {
        Ok(event) => Ok(Json(delay_info(&event))),
        Err(crate::delayed::DelayError::NotFound) => {
            match state.delayed.outcome(&delay_id).map_err(delay_error)? {
                Some((owner, record)) if owner == identity.user_id => {
                    Ok(Json(finalised_info(&record)))
                }
                _ => Err(delay_error(crate::delayed::DelayError::NotFound)),
            }
        }
        Err(error) => Err(delay_error(error)),
    }
}

#[derive(Debug, Deserialize)]
struct DelayActionRequest {
    action: String,
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}`
///
/// The earliest shape of the management endpoint, with the action in the
/// body; matrix-js-sdk still falls back to it. `restart` is the one that
/// matters: it is the heartbeat a live client sends to say "not yet", and
/// it re-applies the *original* delay rather than what remained.
async fn delayed_event_action(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(delay_id): axum::extract::Path<String>,
    Json(request): Json<DelayActionRequest>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&request.action).ok_or_else(|| {
        MatrixError::bad_json(format!(
            "action must be 'send', 'cancel' or 'restart', not {:?}",
            request.action
        ))
    })?;
    act_on_delay(&state, &delay_id, Some(&identity.user_id), action, false).await
}

/// Apply `action` to a delay -- the caller's when `owner` names them, the
/// holder of the id's otherwise -- and do what follows from it: send the
/// event for `send`, record the outcome for `cancel`.
///
/// `stable` picks how an action that contradicts a finished delay is
/// refused. MSC4140 as merged says 409, and the stable endpoint says so.
/// The unstable endpoints keep the 404 they have always given, because the
/// clients calling them were built against it: matrix-js-sdk before October
/// 2026 treats a 409 on `restart` or `cancel` as unrecoverable and ends the
/// call, and lk-jwt-service before 0.7 retries a 409 until its deadline
/// where a 404 tells it the delay is gone. Synapse answers 404 there too.
async fn act_on_delay(
    state: &AppState,
    delay_id: &str,
    owner: Option<&str>,
    action: crate::delayed::Action,
    stable: bool,
) -> Result<Json<Value>, MatrixError> {
    let pending = state
        .delayed
        .pending(delay_id)
        .filter(|event| owner.is_none_or(|owner| event.sender == owner));
    let acted = match owner {
        Some(owner) => state.delayed.act(delay_id, owner, action),
        None => state.delayed.act_by_id(delay_id, action),
    }
    .map_err(|error| match error {
        crate::delayed::DelayError::Conflict if !stable => {
            delay_error(crate::delayed::DelayError::NotFound)
        }
        other => delay_error(other),
    })?;
    if let Some(event) = acted {
        send_delayed_now(state, &event).await?;
    } else if action == crate::delayed::Action::Cancel {
        // A cancel is kept as an outcome like any other, so a lookup can
        // report it and a repeated cancel is the success it should be. Not
        // when the delay had already finished: that cancel changed nothing.
        if let Some(event) = pending {
            record_cancel(state, &event);
        }
    }
    Ok(Json(json!({})))
}

/// Keep a cancellation as the delay's outcome.
fn record_cancel(state: &AppState, event: &crate::delayed::DelayedEvent) {
    let record = crate::delayed::FinalisedDelay::cancelled(event);
    if let Err(error) =
        state
            .delayed
            .finalise(&event.sender, state.rooms.stream_position(), &record)
    {
        tracing::warn!(
            delay_id = %event.delay_id,
            "a delayed event was cancelled but its outcome was not recorded: {error}"
        );
    }
}

/// Send a delayed event now, on its owner's behalf, and record the outcome
/// for MSC4309 -- the `send` action, from either route.
///
/// Sticky if it was scheduled sticky: `MatrixRTC` 2.0's leave is a sticky
/// delayed event, and a delegate that sends it early (lk-jwt-service, when
/// the participant drops off the SFU) must deliver the same event the fire
/// loop would have, or clients that track membership through the sticky
/// map never see the participant go.
///
/// A send that is refused leaves the delay scheduled and answers with the
/// refusal, as MSC4140 asks: whatever refused it may have changed by its
/// deadline, and the client may retry until then.
async fn send_delayed_now(
    state: &AppState,
    event: &crate::delayed::DelayedEvent,
) -> Result<(), MatrixError> {
    let sent = match &event.state_key {
        Some(state_key) => {
            state
                .rooms
                .set_state_sticky_checked(
                    &event.room_id,
                    &event.sender,
                    state.key.pair(),
                    &event.event_type,
                    state_key,
                    &event.content,
                    event.sticky_ms,
                )
                .await
        }
        None => {
            state
                .rooms
                .send_sticky_checked(
                    &event.room_id,
                    &event.sender,
                    state.key.pair(),
                    &event.event_type,
                    &event.content,
                    event.sticky_ms,
                )
                .await
        }
    };
    let event_id = match sent {
        Ok(event_id) => event_id,
        Err(error) => {
            if let Err(store) = state.delayed.reinstate(event) {
                tracing::warn!(
                    delay_id = %event.delay_id,
                    "a refused delayed send could not be put back: {store}"
                );
            }
            return Err(room_error(error));
        }
    };
    // MSC4309, for the same reason the fire loop records its outcome:
    // this device learns the result from the response, but the user's
    // *other* devices are exactly as uninformed as if the delay had
    // fired on its own. A failure to record must not fail the send that
    // already happened, so it is logged rather than returned.
    let record = crate::delayed::FinalisedDelay::of(event, Ok(event_id));
    if let Err(error) =
        state
            .delayed
            .finalise(&event.sender, state.rooms.stream_position(), &record)
    {
        tracing::warn!(
            delay_id = %event.delay_id,
            "a delayed event was sent but its outcome was not recorded: {error}"
        );
    }
    Ok(())
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}`
///
/// An access token is optional here. With one, the delay must be the
/// caller's, as on the stable endpoint -- which is how lk-jwt-service 0.8
/// calls it, as the user, through its application service. Without one the
/// delay ID is the capability (see [`crate::delayed::Delayed::act_by_id`]),
/// which is how earlier releases call it to restart a delegated leave while
/// the participant is still on the SFU and send it when they are not;
/// answering that 404 makes the service drop the delegation, and the leave
/// fires while the caller is still in the call.
async fn delayed_event_action_by_id(
    State(state): State<AppState>,
    crate::auth::MaybeAuthenticated(identity): crate::auth::MaybeAuthenticated,
    axum::extract::Path((delay_id, action)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&action).ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            format!("no delayed-event action {action:?}"),
        )
    })?;
    act_on_delay(
        &state,
        &delay_id,
        identity.as_ref().map(|identity| identity.user_id.as_str()),
        action,
        false,
    )
    .await
}

/// `POST /_matrix/client/v1/delayed_events/{delay_id}/{action}`
///
/// MSC4140 as merged: authenticated, and scoped to the delay's owner.
async fn delayed_event_action_stable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((delay_id, action)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&action).ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            format!("no delayed-event action {action:?}"),
        )
    })?;
    act_on_delay(&state, &delay_id, Some(&identity.user_id), action, true).await
}

/// The body of MSC4140's scheduling endpoint.
#[derive(Debug, Deserialize)]
struct DelayedEventBody {
    delay_ms: Value,
    content: Option<Value>,
    state_key: Option<Value>,
    /// MSC4354's sticky duration, accepted in the body as well as the query,
    /// as Synapse does until the MSCs settle on one.
    #[serde(rename = "org.matrix.msc4354.sticky_duration_ms")]
    sticky: Option<u64>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/delayed_event/{event_type}/{txn_id}`,
/// and its unstable alias under `org.matrix.msc4140`.
///
/// MSC4140 as merged schedules through an endpoint of its own, with the
/// delay, the content and (for a state event) the state key in the body,
/// rather than through a query parameter on `/send` and `/state` -- which
/// stay served, because that is what shipping clients call. It is a
/// transaction like `/send`: a retried request returns the delay it made
/// the first time, rather than scheduling a second one, which for a
/// participant's leave would be a second leave nobody restarts.
fn schedule_delayed_event(
    state: &AppState,
    identity: &crate::accounts::Identity,
    (room_id, event_type, txn_id): (String, String, String),
    query: &DelayQuery,
    body: DelayedEventBody,
    stable: bool,
) -> Result<Json<Value>, MatrixError> {
    let delay_ms = body
        .delay_ms
        .as_u64()
        .filter(|delay| *delay > 0)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "delay_ms must be a whole number of milliseconds greater than zero",
            )
        })?;
    let content = match body.content {
        Some(Value::Object(content)) => Value::Object(content),
        Some(_) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "content must be an object",
            ));
        }
        None => return Err(MatrixError::missing_param("content is required")),
    };
    let state_key = match body.state_key {
        None => None,
        Some(Value::String(state_key)) => Some(state_key),
        Some(_) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "state_key must be a string",
            ));
        }
    };
    let sticky = match (query.sticky, body.sticky) {
        (Some(query), Some(body)) if query != body => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "conflicting values given for org.matrix.msc4354.sticky_duration_ms",
            ));
        }
        (query, body) => query.or(body),
    };
    let key = delayed_transaction_key(identity, &txn_id);
    if let Ok(Some(stored)) = spindle_store::ReadView::get(state.store.as_ref(), &key)
        && let Ok(delay_id) = String::from_utf8(stored)
    {
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    if !state
        .rooms
        .is_joined(&identity.user_id, &room_id)
        .unwrap_or(false)
    {
        return Err(MatrixError::forbidden(format!(
            "{} is not in {room_id}",
            identity.user_id
        )));
    }
    let delay_id = state
        .delayed
        .schedule(
            &room_id,
            &identity.user_id,
            &event_type,
            state_key.as_deref(),
            &content,
            delay_ms,
            sticky,
        )
        .map_err(|error| delay_error_as(error, stable))?;
    spindle_store::Store::put(state.store.as_ref(), &key, delay_id.as_bytes())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "delay_id": delay_id })))
}

/// Where a scheduling transaction is remembered: the device's transaction
/// row, in a namespace of its own. The spec scopes a transaction ID to one
/// device and one endpoint, so the same ID on `/send` is a different
/// transaction and must not answer with a delay.
fn delayed_transaction_key(identity: &crate::accounts::Identity, txn_id: &str) -> Vec<u8> {
    spindle_core::keys::transaction(
        &identity.user_id,
        &identity.device_id,
        &format!("\u{0}msc4140/{txn_id}"),
    )
}

async fn delayed_event_put_unstable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(path): axum::extract::Path<(String, String, String)>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(body): Json<DelayedEventBody>,
) -> Result<Json<Value>, MatrixError> {
    schedule_delayed_event(&state, &identity, path, &query, body, false)
}

async fn delayed_event_put_stable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(path): axum::extract::Path<(String, String, String)>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(body): Json<DelayedEventBody>,
) -> Result<Json<Value>, MatrixError> {
    schedule_delayed_event(&state, &identity, path, &query, body, true)
}
