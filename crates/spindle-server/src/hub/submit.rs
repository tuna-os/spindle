//! Placing events through the hub, and handing the hub over (#22, SPEC
//! section 12.6).
//!
//! Both directions of one exchange: the participant's send ([`try_send`],
//! [`try_handoff`]) and the hub's answer ([`submit`], [`handoff`]). The
//! hub's side is compare-and-append: it appends a submitted event only if
//! the event names its head, under the room lock its own appends take.

use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ruma::CanonicalJsonValue;
use serde_json::{Value, json};

use super::attest::{self, encode};
use super::epoch::{Designation, claim_failover, designation};
use super::metrics::Counter;
use super::{
    EPOCH_KEY, FAILOVER_KEY, NOT_HUB_ERRCODE, PREV_FINAL_KEY, PREV_HUB_KEY, STALE_ERRCODE,
    UNSTABLE_PREFIX, WRONG_FINAL_ERRCODE, after_local_send, is_capable, lock, server_of,
};
use crate::AppState;
use crate::errors::MatrixError;
use crate::federation::FederationError;
use crate::rooms::{ChainEntry, HUB_EVENT_TYPE, Sequenced};
use crate::routes::room_error;

/// Events handed back with a stale answer. The spec's own window for
/// `/get_missing_events` is about this size; a participant further behind
/// than this falls back to the ordinary send and ordinary catch-up.
const MISSING_LIMIT: usize = 50;

/// The largest submission body read: an event is at most 64 KiB.
const MAX_SUBMISSION_BYTES: usize = 256 * 1024;

/// A request body as JSON, with the URI it was signed over.
async fn read_body(
    request: axum::http::Request<axum::body::Body>,
) -> Result<(String, Value), MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), MAX_SUBMISSION_BYTES)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    Ok((uri, body))
}

fn not_hub(state: &AppState, room_id: &str) -> MatrixError {
    MatrixError::new(
        StatusCode::FORBIDDEN,
        NOT_HUB_ERRCODE,
        format!("{} does not hub {room_id}", state.config.server.name),
    )
}

/// The checks every event handed to the hub passes before it is looked at
/// as an event: this server hubs the room, the event is in it, its sender
/// lives on the origin, and the origin is in the room. Returns the room's
/// designation and the event's ID once its signature and hash verify.
async fn admit(
    state: &AppState,
    origin: &str,
    room_id: &str,
    pdu: &Value,
) -> Result<(Designation, String), MatrixError> {
    let current = designation(state, room_id)
        .await
        .filter(|current| current.server == state.config.server.name)
        .ok_or_else(|| not_hub(state, room_id))?;
    if !pdu.is_object() || pdu["room_id"].as_str() != Some(room_id) {
        return Err(MatrixError::bad_json("pdu must be an event in this room"));
    }
    if pdu["sender"].as_str().and_then(server_of) != Some(origin) {
        return Err(MatrixError::forbidden(
            "the sender does not live on the origin",
        ));
    }
    if !state
        .rooms
        .server_in_room(room_id, origin)
        .map_err(room_error)?
    {
        return Err(MatrixError::forbidden(format!(
            "{origin} is not in {room_id}"
        )));
    }
    let event_id = verify_submission(state, origin, room_id, pdu).await?;
    Ok((current, event_id))
}

/// The 409 for an event that did not name the head: the head, and what
/// the participant is missing of it.
fn stale(state: &AppState, room_id: &str, pdu: &Value, head: &[String]) -> Response {
    state.metrics.hub().bump(Counter::SequencedStale);
    let named = crate::rooms::edge_ids(&pdu["prev_events"]);
    let missing = state
        .rooms
        .hub_events_after(room_id, &named, MISSING_LIMIT)
        .unwrap_or_default();
    (
        StatusCode::CONFLICT,
        Json(json!({
            "errcode": STALE_ERRCODE,
            "error": "the event does not name the hub's head; catch up and build again",
            "head": head,
            "missing": missing,
        })),
    )
        .into_response()
}

/// `POST .../org.spindle.msc3995/submit/{roomId}`, body `{"pdu": ...}`:
/// sequence a participant's event.
///
/// Answers `200 {"event_id", "li", "attestation"}` once appended,
/// `409 ORG.SPINDLE.MSC3995_STALE_HEAD {"head", "missing"}` when the event
/// does not name the head, `403 ORG.SPINDLE.MSC3995_NOT_HUB` when this
/// server does not hub the room, and the ordinary refusals otherwise.
pub(crate) async fn submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, MatrixError> {
    let (uri, body) = read_body(request).await?;
    let origin =
        crate::inbound::federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;
    let pdu = body["pdu"].clone();
    if pdu["type"].as_str() == Some(HUB_EVENT_TYPE) {
        return Err(MatrixError::bad_json(
            "a hub change is a handoff, not a submission",
        ));
    }
    let (current, event_id) = admit(&state, &origin, &room_id, &pdu).await?;
    let sequenced = {
        let state = state.clone();
        let room_id = room_id.clone();
        let event_id = event_id.clone();
        let pdu = pdu.clone();
        crate::blocking::offload(
            std::sync::Arc::clone(&state.metrics),
            crate::metrics::BlockingTask::FederationSend,
            move || {
                state
                    .rooms
                    .hub_sequence(&room_id, &event_id, &pdu, None)
                    .map_err(room_error)
            },
        )
        .await
    };
    let sequenced = match sequenced {
        Ok(sequenced) => sequenced,
        Err(error) => {
            state.metrics.hub().bump(Counter::SequencedRefused);
            return Err(error);
        }
    };
    match sequenced {
        Sequenced::Appended { li, chain } => {
            state.metrics.hub().bump(Counter::SequencedAppended);
            let attestation = match chain {
                Some(chain) => Some(attest::sign(
                    &state,
                    &room_id,
                    current.epoch,
                    &ChainEntry {
                        li,
                        event_id: event_id.clone(),
                        chain,
                        state_root: [0; 32],
                    },
                    false,
                )?),
                None => None,
            };
            attest::spawn_attestations(&state, &room_id);
            state.rooms.wake_sync_waiters();
            Ok(Json(json!({
                "event_id": event_id,
                "li": li,
                "attestation": attestation,
            }))
            .into_response())
        }
        Sequenced::Stale { head } => Ok(stale(&state, &room_id, &pdu, &head)),
        Sequenced::WrongFinal { .. } => Err(MatrixError::internal("no final was asked about")),
    }
}

/// Whether a handoff's stated final entry is `last`, the last entry the
/// outgoing hub sequenced -- or `null` when it sequenced none.
fn names_final(stated: &Value, last: Option<&ChainEntry>) -> bool {
    match last {
        None => stated.is_null(),
        Some(entry) => {
            stated["li"].as_i64() == Some(entry.li)
                && stated["event_id"].as_str() == Some(entry.event_id.as_str())
                && stated["chain"].as_str() == Some(encode(&entry.chain).as_str())
        }
    }
}

fn final_of(entry: Option<&ChainEntry>) -> Value {
    entry.map_or(Value::Null, |entry| {
        json!({ "li": entry.li, "event_id": entry.event_id, "chain": encode(&entry.chain) })
    })
}

/// `POST .../org.spindle.msc3995/handoff/{roomId}`, body `{"pdu": ...}`:
/// co-sign and sequence the `m.room.hub` event that moves this room's hub
/// to its sender's server.
///
/// MSC3995's rule is that the current hub signs a hub change; this is
/// where it does. The event must open the next epoch, name the current
/// `m.room.hub`, name this server's head (as any submission must) and state
/// as the outgoing epoch's final entry exactly the last entry this server
/// sequenced -- which, attested first, is the last entry it ever attests
/// in the epoch. Checked under the room lock with the head, so nothing can
/// be appended in between. Answers `200 {"event_id", "pdu"}` with the
/// co-signed event, `409` stale-head or `409
/// ORG.SPINDLE.MSC3995_WRONG_FINAL {"final"}` to build again.
pub(crate) async fn handoff(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, MatrixError> {
    let (uri, body) = read_body(request).await?;
    let origin =
        crate::inbound::federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;
    let pdu = body["pdu"].clone();
    let (current, event_id) = admit(&state, &origin, &room_id, &pdu).await?;
    let content = &pdu["content"];
    if pdu["type"].as_str() != Some(HUB_EVENT_TYPE)
        || pdu["state_key"].as_str() != Some("")
        || content[EPOCH_KEY].as_u64() != Some(current.epoch + 1)
        || content[PREV_HUB_KEY].as_str() != Some(current.event_id.as_str())
        || content[FAILOVER_KEY] == json!(true)
    {
        state.metrics.hub().bump(Counter::HandoffRefused);
        return Err(MatrixError::forbidden(
            "a handoff opens the next epoch and names the current m.room.hub",
        ));
    }
    // Everything up to the head is attested before the epoch can close on
    // it, so the final entry is the last one this server ever attests.
    attest::send_attestations(&state, &room_id).await;
    let version = state.rooms.room_version(&room_id).map_err(room_error)?;
    let cosigned = crate::inbound::countersign(&state, &pdu, &version)?;
    let stated = content[PREV_FINAL_KEY].clone();
    let guard = |last: Option<&ChainEntry>| names_final(&stated, last);
    match state
        .rooms
        .hub_sequence(&room_id, &event_id, &cosigned, Some(&guard))
        .map_err(room_error)?
    {
        Sequenced::Appended { .. } => {
            state.metrics.hub().bump(Counter::HandoffCosigned);
            tracing::info!(
                room = room_id,
                to = origin,
                epoch = current.epoch + 1,
                "handed the hub over"
            );
            Ok(Json(json!({ "event_id": event_id, "pdu": cosigned })).into_response())
        }
        Sequenced::Stale { head } => Ok(stale(&state, &room_id, &pdu, &head)),
        Sequenced::WrongFinal { last } => Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "errcode": WRONG_FINAL_ERRCODE,
                "error": "the handoff must close the epoch on the hub's last entry",
                "final": final_of(last.as_ref()),
            })),
        )
            .into_response()),
    }
}

/// Name and verify a submitted event under the room's version: signature
/// and content hash both, with no redaction fallback. A transaction keeps a
/// tampered event redacted because its position is authentic; a submission
/// has no position yet, so a bad hash is simply a refusal.
async fn verify_submission(
    state: &AppState,
    origin: &str,
    room_id: &str,
    pdu: &Value,
) -> Result<String, MatrixError> {
    let version = state.rooms.room_version(room_id).map_err(room_error)?;
    let Ok(CanonicalJsonValue::Object(canonical)) = CanonicalJsonValue::try_from(pdu.clone())
    else {
        return Err(MatrixError::bad_json("pdu is not canonical JSON"));
    };
    let parsed = spindle_core::Pdu::from_remote(version.clone(), canonical.clone())
        .map_err(|error| MatrixError::bad_json(format!("{error:?}")))?;
    let keys = state.federation.peer_keys(origin).await.map_err(|error| {
        tracing::debug!("cannot fetch {origin} keys for a hub submission: {error}");
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "the origin's keys cannot be verified".to_owned(),
        )
    })?;
    let enforce = spindle_core::rules_of(&version).is_some_and(|rules| rules.enforce_key_validity);
    let key_map = keys.map_for(pdu["origin_server_ts"].as_u64(), enforce);
    match spindle_core::version::verify(&key_map, &canonical, &version) {
        Ok(ruma::signatures::Verified::All) => Ok(parsed.event_id().as_str().to_owned()),
        Ok(ruma::signatures::Verified::Signatures) => Err(MatrixError::forbidden(
            "the content hash does not match the event",
        )),
        Err(error) => Err(MatrixError::forbidden(format!("signature: {error}"))),
    }
}

/// [`try_send`] behind the client transaction: a retried transaction is
/// left to the ordinary path, which answers it from what it recorded.
///
/// # Errors
///
/// As [`try_send`].
pub(crate) async fn send_with_transaction(
    state: &AppState,
    identity: &crate::accounts::Identity,
    txn_id: &str,
    room_id: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
) -> Result<Option<Json<Value>>, MatrixError> {
    let key = spindle_core::keys::transaction(&identity.user_id, &identity.device_id, txn_id);
    if let Ok(Some(_)) = spindle_store::ReadView::get(state.store.as_ref(), &key) {
        return Ok(None);
    }
    match Box::pin(try_send(
        state,
        &identity.user_id,
        room_id,
        event_type,
        state_key,
        content,
    ))
    .await?
    {
        Some(event_id) => {
            crate::routes::record_transaction(state, identity, txn_id, &event_id).map(Some)
        }
        None => Ok(None),
    }
}

/// The hub answered at all: whatever it said, it is up.
fn heard_from(state: &AppState, room_id: &str) {
    lock(&state.hub.unreachable).remove(room_id);
}

/// Send one local event through the room's hub, when there is one to use.
///
/// `Ok(None)` means nothing was built: hub mode is off, the room has no
/// usable hub, this server is the hub (its own appends are already the
/// order), or the hub does not answer the probe. The caller then sends the
/// ordinary way. `Ok(Some(event_id))` means the event is committed here and
/// on its way to the room -- placed by the hub, or, when the hub could not
/// place it, committed as an ordinary event: once built, the same event is
/// what gets sent, so a submission whose answer was lost can never become
/// two copies of one message.
///
/// A hub that has not answered for `failover_after_ms` is replaced, if this
/// server is its first backup: see `epoch::claim_failover`.
///
/// # Errors
///
/// The ordinary send's: the room is unknown or the auth rules refuse the
/// event.
pub(crate) async fn try_send(
    state: &AppState,
    sender: &str,
    room_id: &str,
    event_type: &str,
    state_key: Option<&str>,
    content: &Value,
) -> Result<Option<String>, MatrixError> {
    let config = &state.config.federation.hub;
    if !config.enabled
        || matches!(
            event_type,
            "m.room.member" | "m.room.create" | HUB_EVENT_TYPE
        )
    {
        return Ok(None);
    }
    let Some(current) = designation(state, room_id).await else {
        return Ok(None);
    };
    if current.server == state.config.server.name || !is_capable(state, &current.server).await {
        return Ok(None);
    }
    let metrics = state.metrics.hub();
    let hub = current.server.as_str();
    let uri = format!(
        "{UNSTABLE_PREFIX}/submit/{}",
        crate::federation::path_segment(room_id)
    );
    let mut attempt = 0;
    loop {
        attempt += 1;
        let (event_id, json) = state
            .rooms
            .build_for_hub(
                room_id,
                sender,
                state.key.pair(),
                event_type,
                state_key,
                content,
            )
            .map_err(room_error)?;
        // `unsigned` is this server's annotation (`replaces_state`), not
        // part of the event; the hub gets the event.
        let mut wire = json.clone();
        if let Some(object) = wire.as_object_mut() {
            object.remove("unsigned");
        }
        let answer = tokio::time::timeout(
            Duration::from_millis(config.submit_timeout_ms),
            state
                .federation
                .hub_request(hub, &uri, Some(&json!({ "pdu": wire }))),
        )
        .await;
        match answer {
            Ok(Ok(placed)) if placed["event_id"].as_str() == Some(event_id.as_str()) => {
                heard_from(state, room_id);
                state
                    .rooms
                    .commit_placed(room_id, &event_id, &json)
                    .map_err(room_error)?;
                metrics.bump(Counter::SubmissionPlaced);
                if placed["attestation"].is_object() {
                    attest::record_from(
                        state,
                        hub,
                        room_id,
                        &current,
                        &[],
                        &[placed["attestation"].clone()],
                    )
                    .await;
                }
                return Ok(Some(event_id));
            }
            Ok(Err(FederationError::Answered { status: 409, body }))
                if body["errcode"].as_str() == Some(STALE_ERRCODE)
                    && attempt < config.submit_attempts =>
            {
                heard_from(state, room_id);
                metrics.bump(Counter::SubmissionStaleRetry);
                catch_up(state, hub, room_id, &body).await;
            }
            outcome => {
                Box::pin(fall_back(
                    state, sender, room_id, &current, &event_id, &json, &outcome,
                ))
                .await?;
                return Ok(Some(event_id));
            }
        }
    }
}

/// The hub could not place the event: unreachable, too slow, stale too
/// often, or refusing. The event is valid here, so it is sent the way any
/// server sends its own events, hub included; a hub that did take it
/// absorbs the redelivery. A hub silent for `failover_after_ms` is then
/// replaced, if this server is its first backup.
#[allow(
    clippy::too_many_arguments,
    reason = "one event, and what became of it"
)]
async fn fall_back(
    state: &AppState,
    sender: &str,
    room_id: &str,
    current: &Designation,
    event_id: &str,
    json: &Value,
    outcome: &Result<Result<Value, FederationError>, tokio::time::error::Elapsed>,
) -> Result<(), MatrixError> {
    let config = &state.config.federation.hub;
    let unreachable = matches!(outcome, Err(_) | Ok(Err(FederationError::Refused(_))));
    let why = match outcome {
        Ok(Ok(_)) => "the hub placed a different event".to_owned(),
        Ok(Err(error)) => error.to_string(),
        Err(_) => "timed out".to_owned(),
    };
    tracing::info!(
        room = room_id,
        hub = current.server,
        event = event_id,
        "hub could not sequence the event, sending it the ordinary way: {why}"
    );
    state.metrics.hub().bump(Counter::SubmissionFallback);
    state
        .rooms
        .commit_placed(room_id, event_id, json)
        .map_err(room_error)?;
    if !unreachable {
        heard_from(state, room_id);
        return Ok(());
    }
    let since = *lock(&state.hub.unreachable)
        .entry(room_id.to_owned())
        .or_insert_with(Instant::now);
    if since.elapsed() >= Duration::from_millis(config.failover_after_ms)
        && current.backups.first() == Some(&state.config.server.name)
    {
        Box::pin(claim_failover(state, sender, room_id, current)).await;
    }
    Ok(())
}

/// Take what a stale answer handed back through the ordinary receive path.
async fn catch_up(state: &AppState, hub: &str, room_id: &str, body: &Value) {
    for pdu in body["missing"].as_array().into_iter().flatten() {
        let (missing_id, outcome) = crate::inbound::receive_from_hub(state, hub, pdu).await;
        if let Err(reason) = outcome {
            tracing::debug!(
                room = room_id,
                event = missing_id,
                "hub handed back an event that did not apply: {reason}"
            );
        }
    }
}

/// A client's `m.room.hub` in a room that already has a hub: a planned
/// handoff to this server.
///
/// This server opens the next epoch: it adds the epoch, the current
/// `m.room.hub` and the outgoing epoch's final entry to the client's
/// content, builds the event, and has the current hub co-sign and sequence
/// it -- itself, when it is already the hub (a handoff to itself, to change
/// the backups). The current hub corrects the final entry and the head if
/// either moved, and the event is built again.
///
/// `Ok(None)` leaves the event to the ordinary path: hub mode is off, the
/// room has no hub yet (this is its first `m.room.hub`), or the client set
/// the epoch itself, which is a client's own business.
///
/// # Errors
///
/// The ordinary send's, and a `502` when the current hub will not co-sign:
/// an `m.room.hub` it has not signed would only make the room ordinary.
pub(crate) async fn try_handoff(
    state: &AppState,
    sender: &str,
    room_id: &str,
    content: &Value,
) -> Result<Option<String>, MatrixError> {
    let config = &state.config.federation.hub;
    if !config.enabled || !content.is_object() || content.get(EPOCH_KEY).is_some() {
        return Ok(None);
    }
    let Some(current) = designation(state, room_id).await else {
        return Ok(None);
    };
    let ours = current.server == state.config.server.name;
    let mut stated = attest::highest_proven(state, room_id, &current)
        .and_then(|value| attest::Parsed::read(&value))
        .map_or(Value::Null, |held| {
            json!({ "li": held.li, "event_id": held.event_id, "chain": encode(&held.chain) })
        });
    let uri = format!(
        "{UNSTABLE_PREFIX}/handoff/{}",
        crate::federation::path_segment(room_id)
    );
    for _ in 0..config.submit_attempts.max(2) {
        let mut opening = content.clone();
        if let Some(object) = opening.as_object_mut() {
            object.insert(EPOCH_KEY.to_owned(), json!(current.epoch + 1));
            object.insert(PREV_HUB_KEY.to_owned(), json!(current.event_id));
            object.insert(PREV_FINAL_KEY.to_owned(), stated.clone());
        }
        let (event_id, json) = state
            .rooms
            .build_for_hub(
                room_id,
                sender,
                state.key.pair(),
                HUB_EVENT_TYPE,
                Some(""),
                &opening,
            )
            .map_err(room_error)?;
        if ours {
            attest::send_attestations(state, room_id).await;
            let guard = |last: Option<&ChainEntry>| names_final(&stated, last);
            match state
                .rooms
                .hub_sequence(room_id, &event_id, &json, Some(&guard))
                .map_err(room_error)?
            {
                Sequenced::Appended { .. } => {
                    return finish_handoff(state, room_id, &event_id, &json).map(Some);
                }
                Sequenced::Stale { .. } => {}
                Sequenced::WrongFinal { last } => stated = final_of(last.as_ref()),
            }
            continue;
        }
        let mut wire = json.clone();
        if let Some(object) = wire.as_object_mut() {
            object.remove("unsigned");
        }
        let answer = tokio::time::timeout(
            Duration::from_millis(config.submit_timeout_ms),
            state
                .federation
                .hub_request(&current.server, &uri, Some(&json!({ "pdu": wire }))),
        )
        .await;
        match answer {
            Ok(Ok(cosigned)) if cosigned["event_id"].as_str() == Some(event_id.as_str()) => {
                return finish_handoff(state, room_id, &event_id, &cosigned["pdu"]).map(Some);
            }
            Ok(Err(FederationError::Answered { status: 409, body })) => {
                if body["errcode"].as_str() == Some(WRONG_FINAL_ERRCODE) {
                    stated = body["final"].clone();
                } else {
                    catch_up(state, &current.server, room_id, &body).await;
                }
            }
            outcome => {
                state.metrics.hub().bump(Counter::HandoffRefused);
                let why = match outcome {
                    Ok(Ok(_)) => "the hub co-signed a different event".to_owned(),
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "timed out".to_owned(),
                };
                return Err(MatrixError::new(
                    StatusCode::BAD_GATEWAY,
                    "M_UNKNOWN",
                    format!("the room's hub did not co-sign the handoff: {why}"),
                ));
            }
        }
    }
    state.metrics.hub().bump(Counter::HandoffRefused);
    Err(MatrixError::new(
        StatusCode::CONFLICT,
        "M_UNKNOWN",
        "the hub's head kept moving; try the handoff again",
    ))
}

fn finish_handoff(
    state: &AppState,
    room_id: &str,
    event_id: &str,
    json: &Value,
) -> Result<String, MatrixError> {
    state
        .rooms
        .commit_placed(room_id, event_id, json)
        .map_err(room_error)?;
    state.metrics.hub().bump(Counter::HandoffCompleted);
    after_local_send(state, room_id);
    Ok(event_id.to_owned())
}
