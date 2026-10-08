//! MSC3995 linearized hub mode between Spindle peers: the first slice (#22).
//!
//! Compiled only with the `hub-mode` cargo feature, and dormant even then
//! until `[federation.hub] enabled = true`. SPEC section 12.6 is the design;
//! this is the summary a reader of the code needs.
//!
//! **What a hub room is.** An ordinary room -- any room version, every peer
//! an ordinary homeserver to every other -- in which the room creator's
//! server has sent an `m.room.hub` state event naming itself (MSC3995: the
//! hub is the server of that event's sender). Hub mode is an overlay on
//! that room among the servers that speak it, never a property of the room
//! that a server which does not speak it has to know about.
//!
//! **Ordering.** A participant builds its event exactly as it would anyway
//! -- on its own head, signed by itself, hashes and all -- and submits it
//! to the hub before anyone else sees it. The hub appends it if, and only
//! if, it names the hub's current head (`Rooms::hub_sequence`, under the
//! room lock its own appends take); otherwise it answers 409 with the events
//! the participant is missing, and the participant catches up and builds
//! again. Every event the hub accepts therefore extends one chain, so hub
//! mode makes the participants' events fork-free without changing a byte of
//! what they look like.
//!
//! **Dual ordinary-PDU projection.** Because the submitted event already is
//! the ordinary PDU, there is nothing to project: once the hub has placed
//! it, its origin commits it and fans it out to every server in the room the
//! ordinary way. A server that knows nothing of hub mode -- Synapse, a build
//! without the feature -- receives ordinary events from their own origins,
//! each naming one parent, and sees an ordinary room. MSC3995's star
//! *delivery* (the hub relays everyone's events) needs the MSC's own room
//! version and is designed-only (SPEC section 12.4).
//!
//! **Attestations.** The hub signs `(room_id, hub, epoch, li, event_id,
//! chain[li])` for every entry it sequences -- the chain value the log
//! already computes (SPEC section 5.3) -- and sends the attestations to
//! hub-speaking participants only, in an `org.spindle.msc3995.attestations`
//! EDU. A participant keeps them, checks that consecutive ones chain, and
//! turns two that cannot both be true into a stored, portable proof.
//!
//! **Failure.** A hub that cannot be reached, or that keeps answering
//! stale, costs the participant nothing but the hub's guarantee: the event
//! it built is committed and fanned out as an ordinary event, and the room
//! heals the ordinary way (a fork, merged by the next event). Liveness is
//! never traded for the ordering, which is the right trade in an ordinary
//! room version and the opposite of the MSC's (SPEC section 13.1).
//!
//! Designed-only, with TODOs where they would go: hub handoff and failover
//! (epochs, SPEC section 13.2), checkpoints, relayed (star) delivery, the
//! MSC room version, and metrics on `/metrics`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ruma::CanonicalJsonValue;
use serde_json::{Value, json};
use spindle_core::{ChainHash, EventId};

use crate::AppState;
use crate::errors::MatrixError;
use crate::federation::{FederationError, PeerKeys};
use crate::metrics::EduResult;
use crate::rooms::{HUB_EVENT_TYPE, HubDesignation, Sequenced};
use crate::routes::room_error;

/// Where every hub endpoint lives. Spindle's namespace, not the MSC's: the
/// MSC defines none of these endpoints, so none may squat its prefix.
pub const UNSTABLE_PREFIX: &str = "/_matrix/federation/unstable/org.spindle.msc3995";

/// The key the capability answer is under, and the EDU type's stem.
pub const CAPABILITY_KEY: &str = "org.spindle.msc3995";

/// The EDU a hub sends its attestations in.
pub const ATTESTATION_EDU: &str = "org.spindle.msc3995.attestations";

/// The hub's answer to an event that does not name its head.
pub const STALE_ERRCODE: &str = "ORG.SPINDLE.MSC3995_STALE_HEAD";

/// The answer of a server asked to sequence a room it does not hub.
pub const NOT_HUB_ERRCODE: &str = "ORG.SPINDLE.MSC3995_NOT_HUB";

/// What a proof of equivocation says it is.
pub const EQUIVOCATION_KIND: &str = "org.spindle.msc3995.equivocation";

/// Events handed back with a stale answer. The spec's own window for
/// `/get_missing_events` is about this size; a participant further behind
/// than this falls back to the ordinary send and ordinary catch-up.
const MISSING_LIMIT: usize = 50;

/// Attestations per EDU, and per pass of the hub's attestation loop.
const ATTESTATION_BATCH: usize = 100;

/// How far back a hub with no memory of a room's attestations starts: a
/// restart re-signs at most this many, and Ed25519 signatures are
/// deterministic, so a participant reads them as duplicates.
const ATTESTATION_BACKLOG: i64 = 100;

/// How long "the probe got no answer" is believed: briefly, because it is
/// a fact about the network, not about the peer.
const UNANSWERED_TTL: Duration = Duration::from_secs(10);

/// The largest submission body read: an event is at most 64 KiB.
const MAX_SUBMISSION_BYTES: usize = 256 * 1024;

/// Hub mode's process state.
#[derive(Default)]
pub struct Hub {
    /// Peer -> (speaks hub mode, when that was learned).
    capable: Mutex<HashMap<String, (bool, Instant, Duration)>>,
    /// Hubbed room -> the last position attested to participants.
    attested: Mutex<HashMap<String, i64>>,
    counters: Counters,
}

#[derive(Default)]
struct Counters {
    sequenced: AtomicU64,
    stale_answers: AtomicU64,
    submitted: AtomicU64,
    stale_retries: AtomicU64,
    fallbacks: AtomicU64,
    attestations_accepted: AtomicU64,
    attestations_rejected: AtomicU64,
    equivocations: AtomicU64,
}

/// A snapshot of hub mode's counters. Not yet on `/metrics`
/// (TODO(#22)); tests and the admin surface read them from here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HubCounts {
    /// As hub: participant events appended.
    pub sequenced: u64,
    /// As hub: submissions answered "stale head".
    pub stale_answers: u64,
    /// As participant: events the hub placed.
    pub submitted: u64,
    /// As participant: rebuilds after a stale answer.
    pub stale_retries: u64,
    /// As participant: events sent the ordinary way because the hub could
    /// not place them.
    pub fallbacks: u64,
    /// As participant: attestations verified and kept.
    pub attestations_accepted: u64,
    /// As participant: attestations refused (bad signature or shape).
    pub attestations_rejected: u64,
    /// As participant: equivocation proofs recorded.
    pub equivocations: u64,
}

impl Hub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters, now.
    #[must_use]
    pub fn counts(&self) -> HubCounts {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let counters = &self.counters;
        HubCounts {
            sequenced: read(&counters.sequenced),
            stale_answers: read(&counters.stale_answers),
            submitted: read(&counters.submitted),
            stale_retries: read(&counters.stale_retries),
            fallbacks: read(&counters.fallbacks),
            attestations_accepted: read(&counters.attestations_accepted),
            attestations_rejected: read(&counters.attestations_rejected),
            equivocations: read(&counters.equivocations),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The hub endpoints. Mounted only with `[federation.hub] enabled`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/capabilities",
            get(capabilities),
        )
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/submit/{room_id}",
            post(submit),
        )
}

/// `GET .../org.spindle.msc3995/capabilities`: "this server speaks hub
/// mode". Unauthenticated, like `/federation/v1/version`: it says what the
/// server is, nothing about any room.
///
/// MSC3995's own advertisement, `"m.linearized": true` on the key document,
/// means "not DAG-capable" -- the opposite of what Spindle is -- so it is
/// not used; and the MSC's interim "a join carrying `hub_server`" is a
/// field an ordinary room version's event cannot carry.
async fn capabilities() -> Json<Value> {
    Json(json!({
        CAPABILITY_KEY: {
            "hub": true,
            "participant": true,
            "ordering": "compare-and-append",
            "attestations": 1,
        }
    }))
}

/// `POST .../org.spindle.msc3995/submit/{roomId}`, body `{"pdu": ...}`:
/// sequence a participant's event.
///
/// Answers `200 {"event_id", "li", "attestation"}` once appended,
/// `409 ORG.SPINDLE.MSC3995_STALE_HEAD {"head", "missing"}` when the event
/// does not name the head, `403 ORG.SPINDLE.MSC3995_NOT_HUB` when this
/// server does not hub the room, and the ordinary refusals otherwise.
async fn submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Response, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), MAX_SUBMISSION_BYTES)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let origin =
        crate::inbound::federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;

    let designation = state.rooms.hub_designation(&room_id).map_err(room_error)?;
    let Some(designation) = designation.filter(|hub| hub.server == state.config.server.name) else {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            NOT_HUB_ERRCODE,
            format!("{} does not hub {room_id}", state.config.server.name),
        ));
    };
    let pdu = body["pdu"].clone();
    if !pdu.is_object() || pdu["room_id"].as_str() != Some(room_id.as_str()) {
        return Err(MatrixError::bad_json("pdu must be an event in this room"));
    }
    // A participant submits its own users' events: the same rule a
    // transaction's origin is held to.
    let sender_server = pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .map(|(_, domain)| domain);
    if sender_server != Some(origin.as_str()) {
        return Err(MatrixError::forbidden(
            "the sender does not live on the origin",
        ));
    }
    if !state
        .rooms
        .server_in_room(&room_id, &origin)
        .map_err(room_error)?
    {
        return Err(MatrixError::forbidden(format!(
            "{origin} is not in {room_id}"
        )));
    }
    let event_id = verify_submission(&state, &origin, &room_id, &pdu).await?;

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
                    .hub_sequence(&room_id, &event_id, &pdu)
                    .map_err(room_error)
            },
        )
        .await?
    };
    match sequenced {
        Sequenced::Appended { li, chain } => {
            bump(&state.hub.counters.sequenced);
            let attestation = chain
                .map(|chain| attest(&state, &designation, &room_id, li, &event_id, &chain))
                .transpose()?;
            spawn_attestations(&state, &room_id);
            state.rooms.wake_sync_waiters();
            Ok(Json(json!({
                "event_id": event_id,
                "li": li,
                "attestation": attestation,
            }))
            .into_response())
        }
        Sequenced::Stale { head } => {
            bump(&state.hub.counters.stale_answers);
            let named = crate::rooms::edge_ids(&pdu["prev_events"]);
            let missing = state
                .rooms
                .hub_events_after(&room_id, &named, MISSING_LIMIT)
                .unwrap_or_default();
            Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "errcode": STALE_ERRCODE,
                    "error": "the event does not name the hub's head; catch up and build again",
                    "head": head,
                    "missing": missing,
                })),
            )
                .into_response())
        }
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

/// The unsigned body of one attestation.
fn attestation_body(
    room_id: &str,
    designation: &HubDesignation,
    li: i64,
    event_id: &str,
    chain: &[u8; 32],
) -> Value {
    let encoded: ruma::serde::Base64 = ruma::serde::Base64::new(chain.to_vec());
    json!({
        "room_id": room_id,
        "hub": designation.server,
        "epoch": designation.epoch,
        "li": li,
        "event_id": event_id,
        "chain": encoded.encode(),
    })
}

/// Sign one attestation with this server's key.
fn attest(
    state: &AppState,
    designation: &HubDesignation,
    room_id: &str,
    li: i64,
    event_id: &str,
    chain: &[u8; 32],
) -> Result<Value, MatrixError> {
    let body = attestation_body(room_id, designation, li, event_id, chain);
    let Ok(CanonicalJsonValue::Object(mut object)) = CanonicalJsonValue::try_from(body) else {
        return Err(MatrixError::internal(
            "an attestation is not canonical JSON",
        ));
    };
    ruma::signatures::sign_json(&state.config.server.name, state.key.pair(), &mut object)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    serde_json::to_value(&object).map_err(|error| MatrixError::internal(&error.to_string()))
}

/// Attest whatever this hub has sequenced in `room_id` since it last did,
/// to every hub-speaking server in the room, in the background.
pub(crate) fn after_local_send(state: &AppState, room_id: &str) {
    if state.config.federation.hub.enabled {
        spawn_attestations(state, room_id);
    }
}

fn spawn_attestations(state: &AppState, room_id: &str) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let state = state.clone();
    let room_id = room_id.to_owned();
    tokio::spawn(async move { send_attestations(&state, &room_id).await });
}

/// One pass of the hub's attestation stream for a room.
///
/// Positions are claimed under a lock before signing, so two passes racing
/// never sign the same range twice, though they may queue out of order --
/// which a participant tolerates, checking each attestation against both
/// neighbours as it arrives. Entries from servers that do not speak hub
/// mode are attested too: the hub vouches for its order, whoever authored
/// the event, and that is what keeps a participant's chain unbroken in a
/// mixed room.
async fn send_attestations(state: &AppState, room_id: &str) {
    let Ok(Some(designation)) = state.rooms.hub_designation(room_id) else {
        return;
    };
    if designation.server != state.config.server.name {
        return;
    }
    let Ok(destinations) = state.rooms.remote_domains(room_id) else {
        return;
    };
    let mut audience = Vec::new();
    for destination in destinations {
        if is_capable(state, &destination).await {
            audience.push(destination);
        }
    }
    if audience.is_empty() {
        return;
    }
    loop {
        let entries = {
            let mut attested = state
                .hub
                .attested
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let start = match attested.get(room_id) {
                Some(last) => *last,
                None => state
                    .rooms
                    .hub_last_position(room_id)
                    .unwrap_or(0)
                    .saturating_sub(ATTESTATION_BACKLOG),
            };
            let Ok(entries) = state
                .rooms
                .hub_chain_since(room_id, start, ATTESTATION_BATCH)
            else {
                return;
            };
            if let Some((last, _, _)) = entries.last() {
                attested.insert(room_id.to_owned(), *last);
            }
            entries
        };
        if entries.is_empty() {
            return;
        }
        let attestations: Vec<Value> = entries
            .iter()
            .filter_map(|(li, event_id, chain)| {
                attest(state, &designation, room_id, *li, event_id, chain).ok()
            })
            .collect();
        let edu = json!({
            "edu_type": ATTESTATION_EDU,
            "content": { "room_id": room_id, "attestations": attestations },
        });
        for destination in &audience {
            state.federation.queue_edu(destination, edu.clone());
        }
        if entries.len() < ATTESTATION_BATCH {
            return;
        }
    }
}

/// Whether `server` speaks hub mode, from the cache or by asking it.
///
/// A definite answer -- the capability document, or a refusal such as
/// Synapse's `404 M_UNRECOGNIZED` -- is believed for
/// `capability_ttl_ms`. No answer at all is believed for a few seconds,
/// as "no", so a peer that is down costs one probe per window rather than
/// one per event.
async fn is_capable(state: &AppState, server: &str) -> bool {
    if server == state.config.server.name {
        return true;
    }
    if let Some((capable, learned, ttl)) = state
        .hub
        .capable
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(server)
        && learned.elapsed() < *ttl
    {
        return *capable;
    }
    let config = &state.config.federation.hub;
    let probe = tokio::time::timeout(
        Duration::from_millis(config.submit_timeout_ms),
        state
            .federation
            .hub_request(server, &format!("{UNSTABLE_PREFIX}/capabilities"), None),
    )
    .await;
    let (capable, ttl) = match probe {
        Ok(Ok(answer)) => (
            answer[CAPABILITY_KEY]["hub"] == json!(true),
            Duration::from_millis(config.capability_ttl_ms),
        ),
        Ok(Err(FederationError::Answered { .. })) => {
            (false, Duration::from_millis(config.capability_ttl_ms))
        }
        _ => (false, UNANSWERED_TTL),
    };
    state
        .hub
        .capable
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(server.to_owned(), (capable, Instant::now(), ttl));
    capable
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
    match try_send(
        state,
        &identity.user_id,
        room_id,
        event_type,
        state_key,
        content,
    )
    .await?
    {
        Some(event_id) => {
            crate::routes::record_transaction(state, identity, txn_id, &event_id).map(Some)
        }
        None => Ok(None),
    }
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
    let Ok(Some(designation)) = state.rooms.hub_designation(room_id) else {
        return Ok(None);
    };
    if designation.server == state.config.server.name
        || !is_capable(state, &designation.server).await
    {
        return Ok(None);
    }
    let hub = designation.server.as_str();
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
                state
                    .rooms
                    .commit_placed(room_id, &event_id, &json)
                    .map_err(room_error)?;
                bump(&state.hub.counters.submitted);
                if placed["attestation"].is_object() {
                    record_from_hub(state, hub, room_id, &[placed["attestation"].clone()]).await;
                }
                return Ok(Some(event_id));
            }
            Ok(Err(FederationError::Answered { status: 409, body }))
                if body["errcode"].as_str() == Some(STALE_ERRCODE)
                    && attempt < config.submit_attempts =>
            {
                bump(&state.hub.counters.stale_retries);
                for pdu in body["missing"].as_array().into_iter().flatten() {
                    let (missing_id, outcome) =
                        crate::inbound::receive_from_hub(state, hub, pdu).await;
                    if let Err(reason) = outcome {
                        tracing::debug!(
                            room = room_id,
                            event = missing_id,
                            "hub handed back an event that did not apply: {reason}"
                        );
                    }
                }
            }
            outcome => {
                // The hub could not place it: unreachable, too slow, stale
                // too often, or refusing. The event is valid here, so it is
                // sent the way any server sends its own events, hub
                // included; a hub that did take it absorbs the redelivery.
                let why = match &outcome {
                    Ok(Ok(_)) => "the hub placed a different event".to_owned(),
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "timed out".to_owned(),
                };
                tracing::info!(
                    room = room_id,
                    hub,
                    event = event_id,
                    "hub could not sequence the event, sending it the ordinary way: {why}"
                );
                bump(&state.hub.counters.fallbacks);
                state
                    .rooms
                    .commit_placed(room_id, &event_id, &json)
                    .map_err(room_error)?;
                return Ok(Some(event_id));
            }
        }
    }
}

/// Whether an inbound EDU is hub mode's, and if so apply and count it.
pub(crate) async fn takes_edu(state: &AppState, origin: &str, edu: &Value) -> bool {
    if !state.config.federation.hub.enabled || edu["edu_type"].as_str() != Some(ATTESTATION_EDU) {
        return false;
    }
    let result = apply_attestation_edu(state, origin, &edu["content"]).await;
    state
        .metrics
        .record_edu_received(crate::metrics::EduType::Other, result);
    true
}

/// Apply an inbound `org.spindle.msc3995.attestations` EDU.
///
/// Only the room's hub may attest to its order, so an EDU from anyone else
/// is ignored whole; each attestation must then verify against the hub's
/// own key.
pub(crate) async fn apply_attestation_edu(
    state: &AppState,
    origin: &str,
    content: &Value,
) -> EduResult {
    let (Some(room_id), Some(attestations)) = (
        content["room_id"].as_str(),
        content["attestations"].as_array(),
    ) else {
        return EduResult::Malformed;
    };
    match state.rooms.hub_designation(room_id) {
        Ok(Some(designation)) if designation.server == origin => {}
        _ => return EduResult::Ignored,
    }
    let attestations: Vec<Value> = attestations
        .iter()
        .take(ATTESTATION_BATCH)
        .cloned()
        .collect();
    if record_from_hub(state, origin, room_id, &attestations).await > 0 {
        EduResult::Accepted
    } else {
        EduResult::Ignored
    }
}

/// Verify and keep attestations from `hub`; how many verified.
async fn record_from_hub(state: &AppState, hub: &str, room_id: &str, list: &[Value]) -> usize {
    let keys = match state.federation.peer_keys(hub).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::debug!("cannot fetch {hub} keys to check its attestations: {error}");
            return 0;
        }
    };
    let mut verified = 0;
    for attestation in list {
        match record(state, &keys, hub, room_id, attestation) {
            Recorded::Invalid => bump(&state.hub.counters.attestations_rejected),
            Recorded::Equivocation => {
                verified += 1;
                bump(&state.hub.counters.equivocations);
            }
            Recorded::New => {
                verified += 1;
                bump(&state.hub.counters.attestations_accepted);
            }
            Recorded::Duplicate => verified += 1,
        }
    }
    verified
}

/// What became of one attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    New,
    Duplicate,
    /// Kept, or refused, with a proof recorded against the hub.
    Equivocation,
    Invalid,
}

/// The parts of an attestation a participant checks.
struct Parsed {
    li: i64,
    event_id: String,
    chain: [u8; 32],
}

fn parse(attestation: &Value, hub: &str, room_id: &str) -> Option<Parsed> {
    if attestation["hub"].as_str() != Some(hub) || attestation["room_id"].as_str() != Some(room_id)
    {
        return None;
    }
    let chain: ruma::serde::Base64 =
        ruma::serde::Base64::parse(attestation["chain"].as_str()?).ok()?;
    Some(Parsed {
        li: attestation["li"].as_i64()?,
        event_id: attestation["event_id"].as_str()?.to_owned(),
        chain: chain.as_bytes().try_into().ok()?,
    })
}

fn verifies(keys: &PeerKeys, attestation: &Value) -> bool {
    let Ok(CanonicalJsonValue::Object(object)) = CanonicalJsonValue::try_from(attestation.clone())
    else {
        return false;
    };
    ruma::signatures::verify_json(&keys.map_for(None, false), &object).is_ok()
}

/// Whether `later` is the chain step after `earlier`.
fn chains(earlier: &Parsed, later: &Parsed) -> bool {
    ChainHash::from_bytes(earlier.chain).extend(&EventId::new(later.event_id.as_str()))
        == ChainHash::from_bytes(later.chain)
}

fn stored(state: &AppState, room_id: &str, li: i64) -> Option<Value> {
    spindle_store::ReadView::get(
        state.store.as_ref(),
        &spindle_core::keys::hub_attestation(room_id, li),
    )
    .ok()
    .flatten()
    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Record a proof that `hub` signed two things that cannot both be true.
/// Self-contained: both attestations carry the hub's signature, and either
/// they name different events at one position, or recomputing the chain
/// step between them shows it broken.
fn prove(state: &AppState, hub: &str, room_id: &str, li: i64, reason: &str, pair: [&Value; 2]) {
    let proof = json!({
        "kind": EQUIVOCATION_KIND,
        "reason": reason,
        "room_id": room_id,
        "hub": hub,
        "li": li,
        "attestations": pair,
    });
    tracing::warn!(
        room = room_id,
        hub,
        li,
        reason,
        "the hub equivocated; proof recorded"
    );
    if let Err(error) = spindle_store::Store::put(
        state.store.as_ref(),
        &spindle_core::keys::hub_equivocation(room_id, li),
        proof.to_string().as_bytes(),
    ) {
        tracing::warn!("cannot store an equivocation proof: {error}");
    }
}

/// Check one attestation and keep it.
///
/// A second, different attestation for a position already held is never
/// stored over the first: the first is what this server was told, and the
/// pair is the proof. One that does not chain from its predecessor, or to
/// its successor, is kept (it is what the hub signed) and the broken step
/// recorded as a proof.
fn record(
    state: &AppState,
    keys: &PeerKeys,
    hub: &str,
    room_id: &str,
    attestation: &Value,
) -> Recorded {
    let Some(parsed) = parse(attestation, hub, room_id) else {
        return Recorded::Invalid;
    };
    if !verifies(keys, attestation) {
        return Recorded::Invalid;
    }
    if let Some(existing) = stored(state, room_id, parsed.li) {
        let Some(held) = parse(&existing, hub, room_id) else {
            return Recorded::Invalid;
        };
        if held.event_id == parsed.event_id && held.chain == parsed.chain {
            return Recorded::Duplicate;
        }
        prove(
            state,
            hub,
            room_id,
            parsed.li,
            "conflicting_entries",
            [&existing, attestation],
        );
        return Recorded::Equivocation;
    }
    let mut equivocated = false;
    if let Some(previous) = stored(state, room_id, parsed.li - 1)
        && let Some(earlier) = parse(&previous, hub, room_id)
        && !chains(&earlier, &parsed)
    {
        prove(
            state,
            hub,
            room_id,
            parsed.li,
            "broken_chain",
            [&previous, attestation],
        );
        equivocated = true;
    }
    if let Some(next) = stored(state, room_id, parsed.li + 1)
        && let Some(later) = parse(&next, hub, room_id)
        && !chains(&parsed, &later)
    {
        prove(
            state,
            hub,
            room_id,
            parsed.li + 1,
            "broken_chain",
            [attestation, &next],
        );
        equivocated = true;
    }
    if let Err(error) = spindle_store::Store::put(
        state.store.as_ref(),
        &spindle_core::keys::hub_attestation(room_id, parsed.li),
        attestation.to_string().as_bytes(),
    ) {
        tracing::warn!("cannot store a hub attestation: {error}");
        return Recorded::Invalid;
    }
    if equivocated {
        Recorded::Equivocation
    } else {
        Recorded::New
    }
}

/// Every attestation this server holds for `room_id`, in position order.
///
/// # Errors
///
/// Returns the store's error if the scan fails.
pub fn attestations(
    store: &spindle_store::FjallStore,
    room_id: &str,
) -> Result<Vec<Value>, spindle_store::StoreError> {
    scan(store, spindle_core::keys::Keyspace::HubAttestation, room_id)
}

/// Every equivocation proof this server holds for `room_id`.
///
/// # Errors
///
/// Returns the store's error if the scan fails.
pub fn equivocation_proofs(
    store: &spindle_store::FjallStore,
    room_id: &str,
) -> Result<Vec<Value>, spindle_store::StoreError> {
    scan(
        store,
        spindle_core::keys::Keyspace::HubEquivocation,
        room_id,
    )
}

fn scan(
    store: &spindle_store::FjallStore,
    keyspace: spindle_core::keys::Keyspace,
    room_id: &str,
) -> Result<Vec<Value>, spindle_store::StoreError> {
    let prefix = spindle_core::keys::room_prefix(keyspace, room_id);
    Ok(spindle_store::ReadView::scan_prefix(store, &prefix)?
        .into_iter()
        .filter_map(|(_, value)| serde_json::from_slice(&value).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(li: i64, event_id: &str, chain: ChainHash) -> Parsed {
        Parsed {
            li,
            event_id: event_id.to_owned(),
            chain: *chain.as_bytes(),
        }
    }

    #[test]
    fn consecutive_attestations_chain_only_in_order() {
        let first = ChainHash::seed().extend(&EventId::new("$a"));
        let second = first.extend(&EventId::new("$b"));
        assert!(chains(&parsed(1, "$a", first), &parsed(2, "$b", second)));
        // The same events the other way round, or a different successor,
        // break the step: the chain commits to order, not membership.
        let swapped = ChainHash::seed()
            .extend(&EventId::new("$b"))
            .extend(&EventId::new("$a"));
        assert!(!chains(&parsed(1, "$a", first), &parsed(2, "$a", swapped)));
        assert!(!chains(&parsed(1, "$a", first), &parsed(2, "$c", second)));
    }

    #[test]
    fn an_attestation_parses_only_for_its_own_room_and_hub() {
        let designation = HubDesignation {
            server: "hub.example".to_owned(),
            epoch: 0,
            event_id: "$hub".to_owned(),
        };
        let chain = *ChainHash::seed().as_bytes();
        let body = attestation_body("!r:hub.example", &designation, 7, "$e", &chain);
        let parsed = parse(&body, "hub.example", "!r:hub.example").expect("parses");
        assert_eq!((parsed.li, parsed.event_id.as_str()), (7, "$e"));
        assert_eq!(parsed.chain, chain);
        assert!(parse(&body, "other.example", "!r:hub.example").is_none());
        assert!(parse(&body, "hub.example", "!other:hub.example").is_none());
    }
}
