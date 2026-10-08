//! Recover a pushed PDU's dependencies before the ordinary room receipt checks.
//! No room or store lock crosses an outbound request. Fetched bodies are
//! individually named and verified; the peer's response is not a verdict.
//!
//! Recovery is bounded, and a server back from a long outage can be further
//! behind than any bound: a busy room gains thousands of events a day. So
//! when recovery cannot finish -- the gap is wider than the budget, the
//! peer will not answer, or time runs out -- the event is accepted across
//! the gap on a participating server's `/state_ids` instead ([`super::gap`]),
//! as Synapse does, rather than refused forever. Recovery that succeeds
//! keeps the full history and never takes that path.
//!
//! One room recovers one PDU at a time ([`RecoveryGate`]): a transaction of
//! fifty PDUs naming the same unknown history otherwise asks the peer the
//! same `get_missing_events` question fifty times, and the peer answers the
//! duplicates 429 (production saw exactly this, `M_LIMIT_EXCEEDED: Too many
//! duplicate requests`). A later PDU waits for the recovery in flight, then
//! tries the ordinary path first, which is usually enough: the event before
//! it was just placed.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};

use crate::AppState;
use crate::federation::{Federation, FederationError, PeerKeys};
use crate::metrics::{FetchKind, GapResult, Metrics, PduOutcome, RecoveryResult};
use crate::rooms::{RoomError, Rooms};
use crate::signing::ServerKey;

const MAX_RECOVERED_EVENTS: usize = 512;
const MAX_RECOVERED_BYTES: usize = 16 * 1024 * 1024;
/// One predecessor recovery attempt against one peer.
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole of a gap acceptance: `/state_ids`, the missing bodies, and the
/// append. Longer than a recovery, because its walk is wider and it is the
/// last resort before refusing.
const GAP_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a PDU waits for another recovery in the same room to finish
/// before it is refused as missing its dependencies, to be retried with the
/// transaction.
const RECOVERY_WAIT: Duration = Duration::from_secs(60);
/// How long a peer that answered 429 is left alone for one room and one
/// kind of request, when it does not say. Clamped to a sane range when it
/// does, so a peer cannot switch recovery off for a day or ask to be
/// hammered again at once.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(60);
const MIN_COOLDOWN: Duration = Duration::from_secs(5);
pub(super) const MAX_COOLDOWN: Duration = Duration::from_secs(600);

/// The requests a 429 cools down, separately: a peer limiting duplicate
/// `get_missing_events` calls has said nothing about `/state_ids`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Endpoint {
    /// `get_missing_events` and the `/event` walk behind it.
    Recovery,
    /// `/state_ids` and the `/event` fetches for its bodies.
    StateIds,
    /// `/backfill` for a recorded gap (`super::backfill`).
    Backfill,
}

/// What talking to peers about a room needs, borrowed: a request handler
/// lends it from its [`AppState`], and the backfill loop from the sources
/// it upgraded for one pass -- which is why this is not `AppState` itself:
/// the loop holds those weakly (#292) and has no `AppState` to lend.
pub(super) struct Peers<'a> {
    pub(super) rooms: &'a Rooms,
    pub(super) federation: &'a Arc<Federation>,
    pub(super) key: &'a ServerKey,
    pub(super) server_name: &'a str,
    pub(super) metrics: &'a Metrics,
    pub(super) recovery: &'a RecoveryGate,
}

impl<'a> Peers<'a> {
    pub(super) fn of(state: &'a AppState) -> Self {
        Self {
            rooms: &state.rooms,
            federation: &state.federation,
            key: &state.key,
            server_name: &state.config.server.name,
            metrics: &state.metrics,
            recovery: &state.recovery,
        }
    }
}

/// The amplification guard on gap acceptances (#620): how many one room,
/// and one origin across rooms, may make per window.
#[derive(Clone, Copy, Debug)]
pub(super) struct GapCaps {
    pub(super) per_room: usize,
    pub(super) per_origin: usize,
    pub(super) window: Duration,
}

impl GapCaps {
    pub(super) fn of(config: &crate::config::FederationConfig) -> Self {
        Self {
            per_room: config.gap_acceptances_per_room,
            per_origin: config.gap_acceptances_per_origin,
            window: Duration::from_secs(config.gap_acceptance_window_secs),
        }
    }
}

/// Whose gap acceptances a window counts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum GapScope {
    Room(String),
    Origin(String),
}

type CooldownKey = (String, String, Endpoint);

/// Per-room single flight for dependency recovery, and the peers this
/// server is leaving alone after they answered 429.
///
/// Process-local on purpose: both are about requests in flight right now.
/// A restart forgets them, which costs at most one more request per peer.
#[derive(Debug, Default)]
pub struct RecoveryGate {
    /// One async lock per room with a recovery in flight. Weak, so a room
    /// nobody is recovering holds nothing; dead entries are swept on entry.
    rooms: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
    /// `(room, peer, endpoint)` -> not before.
    cooldowns: Mutex<HashMap<CooldownKey, Instant>>,
    /// When each room and each origin was last admitted to a gap
    /// acceptance, within the cap's window.
    gap_admissions: Mutex<HashMap<GapScope, VecDeque<Instant>>>,
}

impl RecoveryGate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait for this room's turn to recover. The guard is the turn.
    async fn enter(&self, room_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut rooms = self
                .rooms
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            rooms.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = rooms.get(room_id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                rooms.insert(room_id.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }

    /// Whether `peer` asked to be left alone for this room and endpoint.
    pub(super) fn cooling(&self, room_id: &str, peer: &str, endpoint: Endpoint) -> bool {
        let now = Instant::now();
        self.cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(room_id.to_owned(), peer.to_owned(), endpoint))
            .is_some_and(|until| *until > now)
    }

    /// Leave `peer` alone for this room and endpoint for `wait`, clamped.
    pub(super) fn cool(&self, room_id: &str, peer: &str, endpoint: Endpoint, wait: Duration) {
        let now = Instant::now();
        let mut cooldowns = self
            .cooldowns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cooldowns.retain(|_, until| *until > now);
        cooldowns.insert(
            (room_id.to_owned(), peer.to_owned(), endpoint),
            now + wait.clamp(MIN_COOLDOWN, MAX_COOLDOWN),
        );
    }

    /// Leave a peer that said it is not in the room (403) alone for this
    /// room, for every kind of request, for the longest cooldown: it has
    /// nothing to give, and asking again is a wasted round trip on the
    /// path that is supposed to unfreeze the room (#620).
    pub(super) fn shun(&self, room_id: &str, peer: &str) {
        for endpoint in [Endpoint::Recovery, Endpoint::StateIds, Endpoint::Backfill] {
            self.cool(room_id, peer, endpoint, MAX_COOLDOWN);
        }
    }

    /// Admit one gap acceptance for `room_id` from `origin`, or say which
    /// cap refuses it. Admission is counted only when both caps allow it,
    /// so a refusal by one does not use up the other.
    pub(super) fn admit_gap(
        &self,
        room_id: &str,
        origin: &str,
        caps: GapCaps,
    ) -> Result<(), GapResult> {
        let now = Instant::now();
        let mut admissions = self
            .gap_admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        admissions.retain(|_, times| {
            while times
                .front()
                .is_some_and(|at| now.saturating_duration_since(*at) >= caps.window)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let room = GapScope::Room(room_id.to_owned());
        let from = GapScope::Origin(origin.to_owned());
        if admissions.get(&room).map_or(0, VecDeque::len) >= caps.per_room {
            return Err(GapResult::CappedRoom);
        }
        if admissions.get(&from).map_or(0, VecDeque::len) >= caps.per_origin {
            return Err(GapResult::CappedOrigin);
        }
        admissions.entry(room).or_default().push_back(now);
        admissions.entry(from).or_default().push_back(now);
        Ok(())
    }
}

/// Why a recovery or gap attempt stopped short.
#[derive(Debug)]
pub(super) enum Failure {
    /// The gap is wider than the budget. Another peer has the same gap.
    Budget(String),
    /// The peer did not answer usefully; `rate_limited` carries its
    /// requested wait when it answered 429. Another peer may do better.
    Peer {
        message: String,
        rate_limited: Option<Duration>,
        /// It answered 403: it is not in the room, and has nothing to give.
        forbidden: bool,
    },
    /// What a peer sent failed verification or authorization. Fail closed.
    Invalid(String),
    /// The event itself was judged by the receipt checks and refused.
    Verdict(RoomError),
}

impl Failure {
    pub(super) fn from_peer(error: &FederationError) -> Self {
        let rate_limited = match error {
            FederationError::Answered { status: 429, body } => Some(
                body["retry_after_ms"]
                    .as_u64()
                    .map_or(RATE_LIMIT_COOLDOWN, Duration::from_millis),
            ),
            _ => None,
        };
        Self::Peer {
            message: error.to_string(),
            rate_limited,
            forbidden: matches!(error, FederationError::Answered { status: 403, .. }),
        }
    }

    /// A peer failure for a reason of this server's own, not an answer.
    pub(super) fn peer(message: impl Into<String>) -> Self {
        Self::Peer {
            message: message.into(),
            rate_limited: None,
            forbidden: false,
        }
    }

    pub(super) fn message(&self) -> String {
        match self {
            Self::Budget(why) | Self::Invalid(why) | Self::Peer { message: why, .. } => why.clone(),
            Self::Verdict(error) => error.to_string(),
        }
    }
}

impl From<RoomError> for Failure {
    fn from(error: RoomError) -> Self {
        Self::Invalid(error.to_string())
    }
}

/// What a refusal from the room says about the PDU, for the outcome metric.
fn classify(error: &RoomError) -> PduOutcome {
    match error {
        RoomError::Forbidden(why) if why.contains("soft-failed") => PduOutcome::SoftFailed,
        RoomError::Forbidden(_) => PduOutcome::Rejected,
        RoomError::Append(_) | RoomError::MissingBody(_) => PduOutcome::RefusedMissingDeps,
        _ => PduOutcome::Refused,
    }
}

pub(super) struct VerifiedPdu {
    pub(super) id: String,
    pub(super) body: Value,
}
/// Gather precisely the signers the room version requires, including a
/// restricted join's authorizer and a v1/v2 event ID's server.
pub(super) async fn verify(
    peers: &Peers<'_>,
    room_id: &str,
    version: &RoomVersionId,
    body: &Value,
    expected: Option<&str>,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<VerifiedPdu, String> {
    let CanonicalJsonValue::Object(canonical) =
        CanonicalJsonValue::try_from(body.clone()).map_err(|error| error.to_string())?
    else {
        return Err("event is not a canonical object".to_owned());
    };
    let pdu = spindle_core::Pdu::from_remote(version.clone(), canonical.clone())
        .map_err(|error| format!("event: {error:?}"))?;
    if expected.is_some_and(|expected| pdu.event_id().as_str() != expected) {
        return Err("recovered event ID does not match the requested event".to_owned());
    }
    if body["room_id"]
        .as_str()
        .is_some_and(|named| named != room_id)
    {
        return Err("recovered event belongs to another room".to_owned());
    }
    let rules = spindle_core::rules_of(version).ok_or_else(|| "unknown room version".to_owned())?;
    let required =
        ruma::signatures::required_server_signatures_to_verify_event(&canonical, &rules.signatures)
            .map_err(|error| error.to_string())?;
    let mut public_keys = ruma::signatures::PublicKeyMap::new();
    for server in required {
        let server = server.as_str();
        if server == peers.server_name {
            public_keys.insert(
                server.to_owned(),
                BTreeMap::from([(
                    peers.key.key_id(),
                    ruma::serde::Base64::parse(peers.key.public_key_base64())
                        .map_err(|error| error.to_string())?,
                )]),
            );
            continue;
        }
        // The keys the server signed this event with, valid when it says
        // it signed it: from what is held, or looked for further -- the
        // server itself, then the notaries -- when it is not.
        let at = body["origin_server_ts"].as_u64();
        let fetched = peers
            .federation
            .event_keys(
                server,
                keys.get(server),
                &crate::federation::signing_key_ids(body, server),
                at,
                rules.enforce_key_validity,
            )
            .await
            .map_err(|error| {
                signature_refusal(peers.metrics, None, None, body, version, &error.to_string())
            })?;
        public_keys.extend(fetched.map_for(at, rules.enforce_key_validity));
        keys.insert(server.to_owned(), fetched);
    }
    let verdict =
        spindle_core::version::verify(&public_keys, &canonical, version).map_err(|error| {
            let error = error.to_string();
            // Name the failing server for the classification: the first
            // required one whose keys are held, which is the one ruma
            // reports on when only one is required.
            let server = keys.keys().find(|server| error.contains(server.as_str()));
            let held = server.and_then(|server| keys.get(server));
            signature_refusal(
                peers.metrics,
                held,
                server.map(String::as_str),
                body,
                version,
                &error,
            )
        })?;
    let body = match verdict {
        ruma::signatures::Verified::All => body.clone(),
        ruma::signatures::Verified::Signatures => {
            let redacted = spindle_core::version::redact(&canonical, version)
                .map_err(|error| error.to_string())?;
            serde_json::to_value(redacted).map_err(|error| error.to_string())?
        }
    };
    crate::authorize::StoredEvent::parse_in(pdu.event_id().as_str(), room_id, &body)?;
    Ok(VerifiedPdu {
        id: pdu.event_id().as_str().to_owned(),
        body,
    })
}

/// Count a signature refusal by reason, and say why in the refusal: the
/// reason, the room version it was judged under, the key IDs it was signed
/// with, and ruma's error -- what a refused event in production otherwise
/// leaves no trace of. A signature that does not match the bytes also logs
/// those bytes: the redacted form, which is all a signature covers and
/// holds no message content, so the disagreement can be found.
fn signature_refusal(
    metrics: &Metrics,
    keys: Option<&PeerKeys>,
    server: Option<&str>,
    body: &Value,
    version: &RoomVersionId,
    error: &str,
) -> String {
    let reason =
        crate::federation::Federation::classify_signature_failure(keys, server, body, error);
    metrics.record_signature_failure(reason);
    if reason == crate::metrics::SignatureFailure::BadSignature
        && let Ok(CanonicalJsonValue::Object(canonical)) =
            CanonicalJsonValue::try_from(body.clone())
        && let Ok(redacted) = spindle_core::version::redact(&canonical, version)
    {
        let mut signed = serde_json::to_string(&redacted).unwrap_or_default();
        if signed.len() > 4096 {
            let mut end = 4096;
            while !signed.is_char_boundary(end) {
                end -= 1;
            }
            signed.truncate(end);
        }
        tracing::warn!(
            room_version = %version,
            room_id = body["room_id"].as_str().unwrap_or("?"),
            "an event's signature does not match the bytes judged; redacted form: {signed}"
        );
    }
    let signed_with: Vec<String> = body["signatures"]
        .as_object()
        .map(|signatures| {
            signatures
                .iter()
                .take(4)
                .flat_map(|(server, keys)| {
                    keys.as_object()
                        .into_iter()
                        .flat_map(|keys| keys.keys().take(4))
                        .map(move |key_id| format!("{server}/{key_id}"))
                })
                .collect()
        })
        .unwrap_or_default();
    format!(
        "signature: {}: {error} (room v{version}, signed with [{}])",
        reason.label(),
        signed_with.join(", ")
    )
}

/// Judge one pushed PDU, recovering or bridging its dependencies when it
/// names history this server lacks, and count what became of it.
pub(super) async fn receive(
    state: &AppState,
    origin: &str,
    signer: &str,
    provided_keys: Option<&PeerKeys>,
    pdu: &Value,
) -> (String, Result<(), String>) {
    let (id, outcome, result) = Box::pin(judge(state, origin, signer, provided_keys, pdu)).await;
    state.metrics.record_pdu(outcome);
    (id, result)
}

async fn judge(
    state: &AppState,
    origin: &str,
    signer: &str,
    provided_keys: Option<&PeerKeys>,
    pdu: &Value,
) -> (String, PduOutcome, Result<(), String>) {
    if pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .map(|(_, domain)| domain)
        != Some(signer)
    {
        return (
            "$foreign-sender".to_owned(),
            PduOutcome::Refused,
            Err("the sender does not live on the origin".to_owned()),
        );
    }
    let Some(room_id) = pdu["room_id"].as_str() else {
        return (
            "$malformed".to_owned(),
            PduOutcome::Refused,
            Err("no room_id".to_owned()),
        );
    };
    let version = state
        .rooms
        .room_version(room_id)
        .unwrap_or_else(|_| super::room_version_of(state, pdu));
    let mut keys = HashMap::new();
    if let Some(provided) = provided_keys {
        keys.insert(signer.to_owned(), provided.clone());
    }
    let event = match verify(&Peers::of(state), room_id, &version, pdu, None, &mut keys).await {
        Ok(event) => event,
        Err(error) => {
            let id = CanonicalJsonValue::try_from(pdu.clone())
                .ok()
                .and_then(|value| {
                    let CanonicalJsonValue::Object(canonical) = value else {
                        return None;
                    };
                    spindle_core::Pdu::from_remote(version.clone(), canonical)
                        .ok()
                        .map(|event| event.event_id().as_str().to_owned())
                })
                .unwrap_or_else(|| "$malformed".to_owned());
            return (id, PduOutcome::Refused, Err(error));
        }
    };
    let error = match state.rooms.receive_remote(room_id, &event.id, &event.body) {
        Ok(()) => return (event.id, PduOutcome::Accepted, Ok(())),
        Err(error) => error,
    };
    // A rejection is already a verdict. Recovery fills an absent dependency;
    // it must not reconsider a stored historical or native rejection.
    if !matches!(error, RoomError::Append(_) | RoomError::MissingBody(_)) {
        return (event.id, classify(&error), Err(error.to_string()));
    }
    if !has_missing(state, room_id, &event.body) {
        return (event.id, PduOutcome::Refused, Err(error.to_string()));
    }
    // Recovery asks a participating peer about a room we hold; no unsigned
    // third-party name can trigger an arbitrary dependency fetch.
    if !state.rooms.server_in_room(room_id, origin).unwrap_or(false) {
        return (
            event.id,
            PduOutcome::RefusedMissingDeps,
            Err(error.to_string()),
        );
    }

    // The rest runs as its own task, so a sending server that gives up on
    // the transaction does not cancel a recovery halfway: the work finishes,
    // and the transaction's retry finds the event already placed. It holds
    // the room's turn for as long as it runs.
    let id = event.id.clone();
    let task = {
        let state = state.clone();
        let origin = origin.to_owned();
        let room_id = room_id.to_owned();
        async move {
            let Ok(turn) =
                tokio::time::timeout(RECOVERY_WAIT, state.recovery.enter(&room_id)).await
            else {
                return (
                    PduOutcome::RefusedMissingDeps,
                    Err("another dependency recovery for this room is still running".to_owned()),
                );
            };
            let outcome = resolve(&state, &origin, &room_id, &version, &event, &mut keys).await;
            drop(turn);
            outcome
        }
    };
    match tokio::spawn(task).await {
        Ok((outcome, result)) => (id, outcome, result),
        Err(error) => (
            id,
            PduOutcome::RefusedMissingDeps,
            Err(format!("dependency recovery failed: {error}")),
        ),
    }
}

/// Whether the event names a predecessor or auth event this room lacks.
fn has_missing(state: &AppState, room_id: &str, body: &Value) -> bool {
    state
        .rooms
        .missing_remote_dependencies(room_id, body)
        .is_ok_and(|(predecessors, auth)| !predecessors.is_empty() || !auth.is_empty())
}

/// With the room's turn held: try the ordinary path again, then recovery
/// against the origin and one other participant, then a gap acceptance.
#[allow(
    clippy::too_many_lines,
    reason = "the fallback ladder for one PDU, read top to bottom"
)]
async fn resolve(
    state: &AppState,
    origin: &str,
    room_id: &str,
    version: &RoomVersionId,
    event: &VerifiedPdu,
    keys: &mut HashMap<String, PeerKeys>,
) -> (PduOutcome, Result<(), String>) {
    // A recovery that held the turn before this one may have placed exactly
    // what this event needs -- usually the event before it.
    let error = match state.rooms.receive_remote(room_id, &event.id, &event.body) {
        Ok(()) => return (PduOutcome::Accepted, Ok(())),
        Err(error) => error,
    };
    if !matches!(error, RoomError::Append(_) | RoomError::MissingBody(_)) {
        return (classify(&error), Err(error.to_string()));
    }
    let missing = match state
        .rooms
        .missing_remote_dependencies(room_id, &event.body)
    {
        Ok(missing) if !missing.0.is_empty() || !missing.1.is_empty() => missing,
        _ => return (PduOutcome::Refused, Err(error.to_string())),
    };

    let mut last = error.to_string();
    for peer in recovery_peers(state, origin, room_id) {
        let started = Instant::now();
        let attempt = tokio::time::timeout(
            RECOVERY_TIMEOUT,
            recover(state, &peer, room_id, version, event, missing.clone(), keys),
        )
        .await;
        let elapsed = started.elapsed();
        match attempt {
            Ok(Ok(())) => {
                state
                    .metrics
                    .record_recovery(RecoveryResult::Recovered, elapsed);
                return match state.rooms.receive_remote(room_id, &event.id, &event.body) {
                    Ok(()) => (PduOutcome::Accepted, Ok(())),
                    Err(error) => (classify(&error), Err(error.to_string())),
                };
            }
            Ok(Err(Failure::Peer {
                message,
                rate_limited,
                forbidden,
            })) => {
                if forbidden {
                    state.recovery.shun(room_id, &peer);
                }
                if let Some(wait) = rate_limited {
                    state
                        .recovery
                        .cool(room_id, &peer, Endpoint::Recovery, wait);
                    state
                        .metrics
                        .record_recovery(RecoveryResult::RateLimited, elapsed);
                } else {
                    state
                        .metrics
                        .record_recovery(RecoveryResult::PeerError, elapsed);
                }
                tracing::info!(
                    room = room_id,
                    event_id = %event.id,
                    peer = %peer,
                    "dependency recovery failed against a peer: {message}"
                );
                last = message;
            }
            Ok(Err(Failure::Budget(why))) => {
                // Every peer has the same gap; asking another is pointless.
                state
                    .metrics
                    .record_recovery(RecoveryResult::BudgetExceeded, elapsed);
                last = why;
                break;
            }
            Ok(Err(failure @ (Failure::Invalid(_) | Failure::Verdict(_)))) => {
                // A peer that sends forged or unauthorized history is not
                // bridged around: refuse, as recovery always has.
                state
                    .metrics
                    .record_recovery(RecoveryResult::Invalid, elapsed);
                return (PduOutcome::RefusedMissingDeps, Err(failure.message()));
            }
            Err(_) => {
                state
                    .metrics
                    .record_recovery(RecoveryResult::Timeout, elapsed);
                "dependency recovery timed out".clone_into(&mut last);
                break;
            }
        }
    }

    // The amplification guard (#620): one gap acceptance can fetch tens of
    // thousands of events, so a room, and an origin across rooms, get only
    // so many per window. Past the cap the PDU is refused as before gap
    // acceptance existed, and the sender's retry is judged again later.
    if let Err(capped) =
        state
            .recovery
            .admit_gap(room_id, origin, GapCaps::of(&state.config.federation))
    {
        state.metrics.record_gap(capped);
        tracing::warn!(
            room = room_id,
            event_id = %event.id,
            origin = %origin,
            cap = ?capped,
            "refused a gap acceptance: the cap for this window is reached"
        );
        return (
            PduOutcome::RefusedMissingDeps,
            Err(format!(
                "dependency recovery failed ({last}); gap acceptance is capped for now"
            )),
        );
    }
    let attempt = tokio::time::timeout(
        GAP_TIMEOUT,
        super::gap::accept(state, origin, room_id, version, event, keys),
    )
    .await;
    let failure = match attempt {
        Ok(Ok(Some(missing))) => {
            state.metrics.record_gap(GapResult::Accepted);
            tracing::info!(
                room = room_id,
                event_id = %event.id,
                origin = %origin,
                missing_prev_events = ?missing,
                "accepted a PDU across a federation gap after recovery failed ({last}); \
                 the history between is missing until backfilled"
            );
            return (PduOutcome::GapAccepted, Ok(()));
        }
        // Its parents arrived while the state was fetched: an ordinary append.
        Ok(Ok(None)) => {
            state.metrics.record_gap(GapResult::Accepted);
            return (PduOutcome::Accepted, Ok(()));
        }
        Ok(Err(failure)) => failure,
        Err(_) => {
            state.metrics.record_gap(GapResult::Timeout);
            return (
                PduOutcome::RefusedMissingDeps,
                Err(format!(
                    "dependency recovery failed ({last}) and gap acceptance timed out"
                )),
            );
        }
    };
    let (result, outcome) = match &failure {
        Failure::Budget(_) => (GapResult::BudgetExceeded, PduOutcome::RefusedMissingDeps),
        Failure::Peer {
            rate_limited: Some(_),
            ..
        } => (GapResult::RateLimited, PduOutcome::RefusedMissingDeps),
        Failure::Peer { .. } => (GapResult::PeerError, PduOutcome::RefusedMissingDeps),
        Failure::Invalid(_) => (GapResult::Invalid, PduOutcome::RefusedMissingDeps),
        Failure::Verdict(error) => (GapResult::Invalid, classify(error)),
    };
    state.metrics.record_gap(result);
    (
        outcome,
        Err(format!(
            "dependency recovery failed ({last}); gap acceptance failed: {}",
            failure.message()
        )),
    )
}

/// The peers to ask for missing predecessors: the origin, then the server
/// with the most members joined to the room (#620: a server whose users
/// have all left answers 403, and alphabetical order once picked exactly
/// that one), leaving out any still cooling down from a 429 or a 403.
fn recovery_peers(state: &AppState, origin: &str, room_id: &str) -> Vec<String> {
    let mut peers = Vec::with_capacity(2);
    if state.recovery.cooling(room_id, origin, Endpoint::Recovery) {
        state
            .metrics
            .record_recovery(RecoveryResult::RateLimited, Duration::ZERO);
    } else {
        peers.push(origin.to_owned());
    }
    if let Some(other) = state
        .rooms
        .participating_servers(room_id)
        .unwrap_or_default()
        .into_iter()
        .find(|domain| {
            domain != origin
                && *domain != state.config.server.name
                && !state.recovery.cooling(room_id, domain, Endpoint::Recovery)
        })
    {
        peers.push(other);
    }
    peers
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one verified event and its bounded predecessor recovery"
)]
async fn recover(
    state: &AppState,
    peer: &str,
    room_id: &str,
    version: &RoomVersionId,
    latest: &VerifiedPdu,
    missing: (Vec<String>, Vec<String>),
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<(), Failure> {
    let mut offered = BTreeMap::new();
    if !missing.0.is_empty() {
        let heads = state.rooms.remote_recovery_heads(room_id)?;
        let events = state
            .federation
            .remote_missing_events(peer, room_id, &heads, std::slice::from_ref(&latest.id), 100)
            .await
            .map_err(|error| Failure::from_peer(&error))?;
        for event in events {
            // Name the response before selecting the ancestors actually cited
            // by this event. Unrelated response events never reach storage.
            let CanonicalJsonValue::Object(canonical) = CanonicalJsonValue::try_from(event.clone())
                .map_err(|error| Failure::Invalid(error.to_string()))?
            else {
                return Err(Failure::Invalid(
                    "missing-events response contains a non-object".to_owned(),
                ));
            };
            let parsed = spindle_core::Pdu::from_remote(version.clone(), canonical)
                .map_err(|error| Failure::Invalid(format!("missing event: {error:?}")))?;
            offered.insert(parsed.event_id().as_str().to_owned(), event);
        }
    }
    let mut pending: BTreeSet<String> = missing.0.into_iter().collect();
    let mut predecessors = BTreeMap::new();
    let mut bytes = 0;
    while let Some(id) = pending.pop_first() {
        if predecessors.contains_key(&id) || !predecessor_missing(state, room_id, &id)? {
            continue;
        }
        if predecessors.len() >= MAX_RECOVERED_EVENTS {
            state
                .metrics
                .record_fetched(FetchKind::Predecessor, count(predecessors.len()));
            return Err(Failure::Budget(
                "dependency recovery event budget exceeded".to_owned(),
            ));
        }
        let body = match offered.remove(&id) {
            Some(body) => body,
            None => state
                .federation
                .remote_event(peer, &id)
                .await
                .map_err(|error| Failure::from_peer(&error))?,
        };
        charge(&body, &mut bytes, MAX_RECOVERED_BYTES)?;
        let event = verify(&Peers::of(state), room_id, version, &body, Some(&id), keys)
            .await
            .map_err(Failure::Invalid)?;
        if event.id != id {
            return Err(Failure::Invalid(
                "recovered predecessor ID does not match the requested event".to_owned(),
            ));
        }
        let (parents, _) = state
            .rooms
            .missing_remote_dependencies(room_id, &event.body)?;
        pending.extend(parents);
        predecessors.insert(id, event.body);
    }
    state
        .metrics
        .record_fetched(FetchKind::Predecessor, count(predecessors.len()));
    recover_auth(
        state,
        peer,
        room_id,
        version,
        latest,
        &predecessors,
        &mut bytes,
        keys,
    )
    .await?;
    // Pushed events must have real predecessor state. Never seed their state
    // from a peer's claimed current snapshot when its predecessors are absent.
    while !predecessors.is_empty() {
        let mut ready = Vec::new();
        for (id, body) in &predecessors {
            if state
                .rooms
                .missing_remote_dependencies(room_id, body)?
                .0
                .is_empty()
            {
                ready.push(id.clone());
            }
        }
        if ready.is_empty() {
            return Err(Failure::Invalid(
                "recovered predecessor graph is incomplete or cyclic".to_owned(),
            ));
        }
        for id in ready {
            let body = predecessors
                .remove(&id)
                .expect("ready predecessor is pending");
            if let Err(error) = state.rooms.receive_remote(room_id, &id, &body)
                && predecessor_missing(state, room_id, &id)?
            {
                return Err(Failure::Invalid(format!(
                    "recovered predecessor refused: {error}"
                )));
            }
        }
    }
    Ok(())
}

fn predecessor_missing(state: &AppState, room_id: &str, id: &str) -> Result<bool, Failure> {
    Ok(!state
        .rooms
        .missing_remote_dependencies(room_id, &json!({"prev_events":[id]}))?
        .0
        .is_empty())
}

#[allow(
    clippy::too_many_arguments,
    reason = "auth closure shares the verified event's recovery context"
)]
async fn recover_auth(
    state: &AppState,
    peer: &str,
    room_id: &str,
    version: &RoomVersionId,
    latest: &VerifiedPdu,
    predecessors: &BTreeMap<String, Value>,
    bytes: &mut usize,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<(), Failure> {
    let mut pending = BTreeSet::new();
    for body in predecessors.values().chain(std::iter::once(&latest.body)) {
        pending.extend(state.rooms.missing_remote_dependencies(room_id, body)?.1);
    }
    let mut auth = BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if auth.contains_key(&id) {
            continue;
        }
        match state.rooms.pdu(room_id, &id) {
            Ok(_) => continue,
            Err(RoomError::MissingBody(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if auth.len() + predecessors.len() >= MAX_RECOVERED_EVENTS {
            return Err(Failure::Budget(
                "dependency recovery event budget exceeded".to_owned(),
            ));
        }
        let body = match predecessors.get(&id) {
            Some(body) => body.clone(),
            None => state
                .federation
                .remote_event(peer, &id)
                .await
                .map_err(|error| Failure::from_peer(&error))?,
        };
        charge(&body, bytes, MAX_RECOVERED_BYTES)?;
        let event = verify(&Peers::of(state), room_id, version, &body, Some(&id), keys)
            .await
            .map_err(Failure::Invalid)?;
        if event.id != id {
            return Err(Failure::Invalid(
                "recovered auth ID does not match the requested event".to_owned(),
            ));
        }
        pending.extend(
            state
                .rooms
                .missing_remote_dependencies(room_id, &event.body)?
                .1,
        );
        auth.insert(id, event.body);
    }
    state
        .metrics
        .record_fetched(FetchKind::Auth, count(auth.len()));
    if !auth.is_empty() {
        state
            .rooms
            .retain_remote_auth(room_id, &auth.into_iter().collect::<Vec<_>>())?;
    }
    Ok(())
}

/// Charge one fetched body against a byte budget.
pub(super) fn charge(body: &Value, bytes: &mut usize, limit: usize) -> Result<(), Failure> {
    let length = serde_json::to_vec(body)
        .map_err(|error| Failure::Invalid(error.to_string()))?
        .len();
    if length > limit.saturating_sub(*bytes) {
        return Err(Failure::Budget(
            "dependency recovery byte budget exceeded".to_owned(),
        ));
    }
    *bytes += length;
    Ok(())
}

/// A collection's length as a counter increment.
pub(super) fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}
