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
use crate::blocking::spawn_detached;
use crate::federation::{Federation, FederationError, PeerKeys};
use crate::metrics::{BlockingTask, FetchKind, GapResult, Metrics, PduOutcome, RecoveryResult};
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

/// Dependencies held as failed at once, across rooms (#725). Past it the
/// entry nearest its expiry gives way: forgetting one costs one repeat of
/// the work the entry saved, and a peer serving bad bodies for many event
/// IDs cannot grow the cache past this.
const MAX_FAILED_DEPENDENCIES: usize = 4096;
/// The longest `dependency_failure_ttl_secs` holds an entry. Also what
/// keeps `Instant + ttl` clear of overflow for any configured value.
const MAX_FAILURE_TTL: Duration = Duration::from_secs(86_400);

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

/// An event that failed verification: its ID, and the peer that served the
/// body which failed, or `None` for a dependency of a pushed PDU whose
/// recovery and gap acceptance failed, whoever was asked.
type FailedKey = (String, Option<String>);

/// Per-room single flight for dependency recovery, the peers this server
/// is leaving alone after they answered 429, the dependencies that
/// failed verification lately, and the turns inbound transactions take at
/// room work.
///
/// Process-local on purpose: all of it is about requests made right now.
/// A restart forgets them, which costs at most one more request per peer.
#[derive(Debug)]
pub struct RecoveryGate {
    /// One async lock per room with a recovery in flight. Weak, so a room
    /// nobody is recovering holds nothing; dead entries are swept on entry.
    rooms: Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
    /// `(room, peer, endpoint)` -> not before.
    cooldowns: Mutex<HashMap<CooldownKey, Instant>>,
    /// When each room and each origin was last admitted to a gap
    /// acceptance, within the cap's window.
    gap_admissions: Mutex<HashMap<GapScope, VecDeque<Instant>>>,
    /// `room` -> what failed verification there -> held until (#725).
    /// Keyed by room first, so the check that every PDU with a missing
    /// dependency makes costs one lookup in a room with no failures.
    failed: Mutex<HashMap<String, HashMap<FailedKey, Instant>>>,
    /// How long an entry of `failed` holds. Zero turns the cache off.
    failure_ttl: Duration,
    /// [`super::INGEST_SLOTS`] turns at room work (`blocking` says why).
    ingest: tokio::sync::Semaphore,
}

impl RecoveryGate {
    /// A gate that holds a failed dependency for `failure_ttl`, at most
    /// [`MAX_FAILURE_TTL`].
    #[must_use]
    pub fn new(failure_ttl: Duration) -> Self {
        Self {
            rooms: Mutex::default(),
            cooldowns: Mutex::default(),
            gap_admissions: Mutex::default(),
            failed: Mutex::default(),
            failure_ttl: failure_ttl.min(MAX_FAILURE_TTL),
            ingest: tokio::sync::Semaphore::new(super::INGEST_SLOTS),
        }
    }

    /// Wait for a turn at inbound room work. The wait is a task waiting,
    /// not a thread, and the semaphore is fair, so a backlog drains in
    /// arrival order. The permit is the turn.
    pub(super) async fn ingest_turn(
        &self,
    ) -> Result<tokio::sync::SemaphorePermit<'_>, tokio::sync::AcquireError> {
        self.ingest.acquire().await
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

    /// Hold `events` of `room_id` as failed for the TTL (#725): served by
    /// `peer` in a body that failed verification, or, with no peer, named
    /// by a pushed PDU whose recovery and gap acceptance failed.
    pub(super) fn distrust<'e>(
        &self,
        room_id: &str,
        peer: Option<&str>,
        events: impl IntoIterator<Item = &'e str>,
    ) {
        self.distrust_at(Instant::now(), room_id, peer, events);
    }

    fn distrust_at<'e>(
        &self,
        now: Instant,
        room_id: &str,
        peer: Option<&str>,
        events: impl IntoIterator<Item = &'e str>,
    ) {
        if self.failure_ttl.is_zero() {
            return;
        }
        let until = now + self.failure_ttl;
        let mut failed = self
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        failed.retain(|_, held| {
            held.retain(|_, until| *until > now);
            !held.is_empty()
        });
        let mut count: usize = failed.values().map(HashMap::len).sum();
        for event in events {
            let key = (event.to_owned(), peer.map(str::to_owned));
            let known = failed
                .get(room_id)
                .is_some_and(|held| held.contains_key(&key));
            if !known {
                if count >= MAX_FAILED_DEPENDENCIES {
                    evict_nearest_expiry(&mut failed);
                } else {
                    count += 1;
                }
            }
            failed
                .entry(room_id.to_owned())
                .or_default()
                .insert(key, until);
        }
    }

    /// The first of `events` held as failed in `room_id` for `peer` (or,
    /// with none, as a pushed PDU's dependency), if any.
    pub(super) fn failed<'e>(
        &self,
        room_id: &str,
        peer: Option<&str>,
        events: impl IntoIterator<Item = &'e str>,
    ) -> Option<&'e str> {
        self.failed_at(Instant::now(), room_id, peer, events)
    }

    fn failed_at<'e>(
        &self,
        now: Instant,
        room_id: &str,
        peer: Option<&str>,
        events: impl IntoIterator<Item = &'e str>,
    ) -> Option<&'e str> {
        let failed = self
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = failed.get(room_id)?;
        let peer = peer.map(str::to_owned);
        events.into_iter().find(|event| {
            held.get(&((*event).to_owned(), peer.clone()))
                .is_some_and(|until| *until > now)
        })
    }

    /// Forget what failed in `room_id`: a recovery or gap acceptance there
    /// just succeeded, so the room's history and the keys this server holds
    /// have changed, and what failed before may verify now.
    pub(super) fn forgive(&self, room_id: &str) {
        self.failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(room_id);
    }
}

/// Drop the entry of `failed` that expires first. Every entry holds for the
/// same TTL, so that is also the oldest. A scan, but only when the cache is
/// full, on a path that just failed a verification.
fn evict_nearest_expiry(failed: &mut HashMap<String, HashMap<FailedKey, Instant>>) {
    let Some((room, key)) = failed
        .iter()
        .flat_map(|(room, held)| held.iter().map(move |(key, until)| (*until, room, key)))
        .min_by_key(|(until, ..)| *until)
        .map(|(_, room, key)| (room.clone(), key.clone()))
    else {
        return;
    };
    if let Some(held) = failed.get_mut(&room) {
        held.remove(&key);
        if held.is_empty() {
            failed.remove(&room);
        }
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

    /// [`Self::from_peer`], naming the request that failed, so a log line
    /// says which endpoint and which event a peer refused rather than only
    /// what it said.
    pub(super) fn from_peer_doing(what: &str, error: &FederationError) -> Self {
        let mut failure = Self::from_peer(error);
        if let Self::Peer { message, .. } = &mut failure {
            *message = format!("{what}: {message}");
        }
        failure
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
    let (id, canonical) = identify(version, body)?;
    if expected.is_some_and(|expected| id != expected) {
        return Err("recovered event ID does not match the requested event".to_owned());
    }
    if body["room_id"]
        .as_str()
        .is_some_and(|named| named != room_id)
    {
        return Err("recovered event belongs to another room".to_owned());
    }
    let public_keys = signing_keys(peers, version, &canonical, body, keys).await?;
    let body = check_signed(room_id, version, &canonical, &id, body, &public_keys)
        .map_err(|refusal| refusal.explain(peers, keys, body, version))?;
    Ok(VerifiedPdu { id, body })
}

/// The canonical form of a body read off the wire and the ID it hashes to
/// under `version`. The reference hash is the costly part of reading an
/// event, so a caller that must know the ID before deciding to verify
/// (`resync`) computes it here once and hands both to [`check_signed`].
pub(super) fn identify(
    version: &RoomVersionId,
    body: &Value,
) -> Result<(String, ruma::CanonicalJsonObject), String> {
    let CanonicalJsonValue::Object(canonical) =
        CanonicalJsonValue::try_from(body.clone()).map_err(|error| error.to_string())?
    else {
        return Err("event is not a canonical object".to_owned());
    };
    let pdu = spindle_core::Pdu::from_remote(version.clone(), canonical.clone())
        .map_err(|error| format!("event: {error:?}"))?;
    Ok((pdu.event_id().as_str().to_owned(), canonical))
}

/// The public keys of every server whose signature the room version
/// requires on this event: our own, held keys, or keys looked for further
/// -- the server itself, then the notaries -- when they are not held.
/// `keys` accumulates what was fetched, so a batch from one server fetches
/// once.
pub(super) async fn signing_keys(
    peers: &Peers<'_>,
    version: &RoomVersionId,
    canonical: &ruma::CanonicalJsonObject,
    body: &Value,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<ruma::signatures::PublicKeyMap, String> {
    let rules = spindle_core::rules_of(version).ok_or_else(|| "unknown room version".to_owned())?;
    let required =
        ruma::signatures::required_server_signatures_to_verify_event(canonical, &rules.signatures)
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
        // it signed it.
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
    Ok(public_keys)
}

/// Why [`check_signed`] refused an event: its signatures, which are
/// classified and explained against the keys held, or anything else.
pub(super) enum Refusal {
    Signature(String),
    Other(String),
}

impl Refusal {
    /// The refusal as [`verify`] words it, counting a signature failure
    /// by reason.
    pub(super) fn explain(
        self,
        peers: &Peers<'_>,
        keys: &HashMap<String, PeerKeys>,
        body: &Value,
        version: &RoomVersionId,
    ) -> String {
        match self {
            Self::Other(why) => why,
            Self::Signature(error) => {
                // Name the failing server for the classification: the
                // first required one whose keys are held, which is the one
                // ruma reports on when only one is required.
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
            }
        }
    }
}

/// The CPU half of [`verify`]: check the signatures against keys already
/// gathered, redact a body whose content hash does not match, and parse
/// the result as an event of `room_id`. Synchronous and free of shared
/// state, so a batch can run on several threads.
pub(super) fn check_signed(
    room_id: &str,
    version: &RoomVersionId,
    canonical: &ruma::CanonicalJsonObject,
    id: &str,
    body: &Value,
    public_keys: &ruma::signatures::PublicKeyMap,
) -> Result<Value, Refusal> {
    let verdict = spindle_core::version::verify(public_keys, canonical, version)
        .map_err(|error| Refusal::Signature(error.to_string()))?;
    let body = match verdict {
        ruma::signatures::Verified::All => body.clone(),
        ruma::signatures::Verified::Signatures => {
            let redacted = spindle_core::version::redact(canonical, version)
                .map_err(|error| Refusal::Other(error.to_string()))?;
            serde_json::to_value(redacted).map_err(|error| Refusal::Other(error.to_string()))?
        }
    };
    crate::authorize::StoredEvent::parse_in(id, room_id, &body).map_err(Refusal::Other)?;
    Ok(body)
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
///
/// `origin_keys` are the origin's keys. The PDU can come from a user on
/// any server: the origin can relay the events of other servers (#631).
/// The signatures in the PDU, not the origin, identify the sender's
/// server: `verify` gets the keys of each server that the room version
/// requires.
pub(super) async fn receive(
    state: &AppState,
    origin: &str,
    origin_keys: Option<&PeerKeys>,
    pdu: &Value,
) -> (String, Result<(), String>) {
    let relayed = pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .is_some_and(|(_, domain)| domain != origin);
    let (id, outcome, result) = Box::pin(judge(state, origin, origin_keys, pdu)).await;
    state.metrics.record_pdu(outcome, relayed);
    (id, result)
}

/// The version to judge an event for a room this server does not hold
/// under, if it is one this server should judge at all: a leave or ban of
/// one of our users whose invite there is still pending
/// (`Rooms::receive_remote` clears it). The version is the one the invite's
/// stripped `m.room.create` names, or else read off the event's shape.
fn unheld_room_version(state: &AppState, room_id: &str, pdu: &Value) -> Option<RoomVersionId> {
    if pdu["type"].as_str() != Some("m.room.member")
        || !matches!(pdu["content"]["membership"].as_str(), Some("leave" | "ban"))
    {
        return None;
    }
    let target = pdu["state_key"].as_str()?;
    if target.split_once(':').map(|(_, domain)| domain) != Some(state.config.server.name.as_str()) {
        return None;
    }
    let pending = state.rooms.pending_invite(target, room_id).ok()??;
    let stated = pending["invite_state"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find(|event| event["type"].as_str() == Some("m.room.create"))
        })
        .filter(|create| create["content"]["room_version"].is_string())
        .and_then(|create| crate::rooms::version_in(&create["content"]).ok());
    Some(stated.unwrap_or_else(|| super::room_version_of(state, pdu)))
}

#[allow(
    clippy::too_many_lines,
    reason = "the receipt checks for one PDU, read top to bottom"
)]
async fn judge(
    state: &AppState,
    origin: &str,
    origin_keys: Option<&PeerKeys>,
    pdu: &Value,
) -> (String, PduOutcome, Result<(), String>) {
    let Some(room_id) = pdu["room_id"].as_str() else {
        return (
            "$malformed".to_owned(),
            PduOutcome::Refused,
            Err("no room_id".to_owned()),
        );
    };
    let version = match state.rooms.room_version(room_id) {
        Ok(version) => version,
        // A room this server does not hold has no version to judge the
        // event under, and judging it under a guess turns a version
        // mismatch into "bad signature" -- what production logged for
        // zoft.chat's events in a room it was never in. The one thing such
        // an event may say is that our user's pending invite there ended;
        // anything else is refused here, before a key is fetched.
        Err(RoomError::UnknownRoom(_)) => match unheld_room_version(state, room_id, pdu) {
            Some(version) => version,
            None => {
                return (
                    "$unknown-room".to_owned(),
                    PduOutcome::Refused,
                    Err(format!("unknown room: this server does not hold {room_id}")),
                );
            }
        },
        Err(_) => super::room_version_of(state, pdu),
    };
    if let Err(refusal) = server_acl_admits(state, room_id, origin) {
        return (
            pdu_id_or_malformed(&version, pdu),
            PduOutcome::Refused,
            Err(refusal),
        );
    }
    // The room is known before any key is fetched. Thus a relayed PDU
    // cannot cause key fetches for a room this server does not hold.
    let mut keys = HashMap::new();
    if let Some(provided) = origin_keys {
        keys.insert(origin.to_owned(), provided.clone());
    }
    let mut event = match verify(&Peers::of(state), room_id, &version, pdu, None, &mut keys).await {
        Ok(event) => event,
        Err(error) => {
            return (
                pdu_id_or_malformed(&version, pdu),
                PduOutcome::Refused,
                Err(error),
            );
        }
    };
    if let Err(error) = state.rooms.authorize_policy(room_id, &mut event.body).await {
        if !matches!(error, RoomError::Forbidden(_) | RoomError::Policy(_)) {
            return (event.id, PduOutcome::Refused, Err(error.to_string()));
        }
        // Ordinary auth is still checked before the event is soft-failed.
        tracing::debug!(
            room_id,
            event_id = event.id,
            "policy approval failed: {error}"
        );
    }
    let error = match state.rooms.receive_live(room_id, &event.id, &event.body) {
        Ok(()) => return (event.id, PduOutcome::Accepted, Ok(())),
        Err(error) => error,
    };
    // A rejection is already a verdict. Recovery fills an absent dependency;
    // it must not reconsider a stored historical or native rejection.
    if !matches!(error, RoomError::Append(_) | RoomError::MissingBody(_)) {
        return (event.id, classify(&error), Err(error.to_string()));
    }
    let Some(missing) = missing_dependencies(state, room_id, &event.body) else {
        return (event.id, PduOutcome::Refused, Err(error.to_string()));
    };
    // Recovery asks a participating peer about a room we hold; no unsigned
    // third-party name can trigger an arbitrary dependency fetch.
    if !state.rooms.server_in_room(room_id, origin).unwrap_or(false) {
        return (
            event.id,
            PduOutcome::RefusedMissingDeps,
            Err(error.to_string()),
        );
    }
    // Before the room's turn: a PDU whose dependency failed a moment ago is
    // refused at once, not after the recovery in flight ahead of it.
    if let Some((outcome, result)) = failed_recently(state, room_id, &missing) {
        return (event.id, outcome, result);
    }

    // The rest runs as its own task, so a sending server that gives up on
    // the transaction does not cancel a recovery halfway: the work finishes,
    // and the transaction's retry finds the event already placed. It holds
    // the room's turn for as long as it runs. A blocking-pool task rather
    // than a spawned one: it ingests what it fetched and resolves state
    // over it, which on a worker held that worker for as long (#614).
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
    let metrics = Arc::clone(&state.metrics);
    match spawn_detached(metrics, BlockingTask::FederationCatchUp, task).await {
        Ok((outcome, result)) => (id, outcome, result),
        Err(error) => (
            id,
            PduOutcome::RefusedMissingDeps,
            Err(format!("dependency recovery failed: {error}")),
        ),
    }
}

/// The predecessors and auth events the event names that this room lacks,
/// if there are any.
fn missing_dependencies(
    state: &AppState,
    room_id: &str,
    body: &Value,
) -> Option<(Vec<String>, Vec<String>)> {
    state
        .rooms
        .missing_remote_dependencies(room_id, body)
        .ok()
        .filter(|(predecessors, auth)| !predecessors.is_empty() || !auth.is_empty())
}

/// Every ID in a [`missing_dependencies`] answer.
fn dependencies(missing: &(Vec<String>, Vec<String>)) -> impl Iterator<Item = &str> {
    missing.0.iter().chain(&missing.1).map(String::as_str)
}

/// The refusal of an event that names a dependency which failed
/// verification within the TTL (#725), if it does. The recovery and gap
/// acceptance it would start ended in that failure moments ago; asking
/// again costs every peer the same fetches for the same answer, once per
/// PDU that names it. The sender retries the transaction, so the event is
/// judged again once the entry expires.
fn failed_recently(
    state: &AppState,
    room_id: &str,
    missing: &(Vec<String>, Vec<String>),
) -> Option<(PduOutcome, Result<(), String>)> {
    let dependency = state
        .recovery
        .failed(room_id, None, dependencies(missing))?;
    state
        .metrics
        .record_recovery(RecoveryResult::NegativeCached, Duration::ZERO);
    Some((
        PduOutcome::RefusedMissingDeps,
        Err(format!(
            "dependency {dependency} failed verification recently; \
             it is not fetched again until that expires"
        )),
    ))
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
    let error = match state.rooms.receive_live(room_id, &event.id, &event.body) {
        Ok(()) => return (PduOutcome::Accepted, Ok(())),
        Err(error) => error,
    };
    if !matches!(error, RoomError::Append(_) | RoomError::MissingBody(_)) {
        return (classify(&error), Err(error.to_string()));
    }
    let Some(missing) = missing_dependencies(state, room_id, &event.body) else {
        return (PduOutcome::Refused, Err(error.to_string()));
    };
    // Again with the turn held: the recovery this PDU waited for may have
    // failed on the same dependency.
    if let Some(refusal) = failed_recently(state, room_id, &missing) {
        return refusal;
    }

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
                state.recovery.forgive(room_id);
                return match state.rooms.receive_live(room_id, &event.id, &event.body) {
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
                if matches!(failure, Failure::Invalid(_)) {
                    state
                        .recovery
                        .distrust(room_id, None, dependencies(&missing));
                }
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
            state.recovery.forgive(room_id);
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
            state.recovery.forgive(room_id);
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
        Failure::Invalid(_) => {
            // Nothing a peer can serve for these verifies now: refuse the
            // next PDU that names them at once (#725).
            state
                .recovery
                .distrust(room_id, None, dependencies(&missing));
            (GapResult::Invalid, PduOutcome::RefusedMissingDeps)
        }
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

/// The event's ID if the body parses as a PDU of `version`, else
/// `$malformed`: the name a refusal is filed under before verification.
fn pdu_id_or_malformed(version: &RoomVersionId, pdu: &Value) -> String {
    CanonicalJsonValue::try_from(pdu.clone())
        .ok()
        .and_then(|value| {
            let CanonicalJsonValue::Object(canonical) = value else {
                return None;
            };
            spindle_core::Pdu::from_remote(version.clone(), canonical)
                .ok()
                .map(|event| event.event_id().as_str().to_owned())
        })
        .unwrap_or_else(|| "$malformed".to_owned())
}

/// The room's `m.room.server_acl` judges the origin before a key is
/// fetched or a signature checked: a denied server gets no work done on
/// its behalf. A room this server does not hold has no ACL to consult,
/// and the one event such a room may deliver (`unheld_room_version`) is
/// about our own user's invite, which no ACL is for. A store error fails
/// closed.
fn server_acl_admits(state: &AppState, room_id: &str, origin: &str) -> Result<(), String> {
    match state.rooms.server_acl_permits(room_id, origin) {
        Ok(true) | Err(RoomError::UnknownRoom(_)) => Ok(()),
        Ok(false) => Err(format!("{origin} is denied by the room's server ACL")),
        Err(error) => Err(format!("the room's server ACL cannot be read: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(gate: &RecoveryGate) -> usize {
        gate.failed.lock().unwrap().values().map(HashMap::len).sum()
    }

    /// A dependency is held for the TTL, in its room, for whoever served it,
    /// and a success in the room forgets it.
    #[test]
    fn a_failed_dependency_is_held_for_the_ttl_and_forgiven_on_success() {
        let gate = RecoveryGate::new(Duration::from_secs(60));
        let now = Instant::now();
        gate.distrust_at(now, "!room", None, ["$named"]);
        gate.distrust_at(now, "!room", Some("bad.example"), ["$served"]);

        assert_eq!(
            gate.failed_at(now, "!room", None, ["$other", "$named"]),
            Some("$named")
        );
        assert_eq!(gate.failed_at(now, "!elsewhere", None, ["$named"]), None);
        assert_eq!(
            gate.failed_at(now, "!room", Some("bad.example"), ["$served"]),
            Some("$served")
        );
        assert_eq!(
            gate.failed_at(now, "!room", Some("good.example"), ["$served"]),
            None,
            "another peer's body may verify"
        );
        assert_eq!(gate.failed_at(now, "!room", None, ["$served"]), None);

        let expired = now + Duration::from_secs(60);
        assert_eq!(gate.failed_at(expired, "!room", None, ["$named"]), None);

        gate.forgive("!room");
        assert_eq!(gate.failed_at(now, "!room", None, ["$named"]), None);
        assert_eq!(held(&gate), 0);
    }

    /// Past the cap the oldest entry gives way, so the cache never grows
    /// past [`MAX_FAILED_DEPENDENCIES`] however many IDs a peer names.
    #[test]
    fn the_cache_is_bounded_and_drops_the_oldest_entry() {
        let gate = RecoveryGate::new(Duration::from_secs(600));
        let start = Instant::now();
        for index in 0..=MAX_FAILED_DEPENDENCIES {
            let at = start + Duration::from_millis(u64::try_from(index).unwrap());
            gate.distrust_at(at, "!room", None, [format!("${index}").as_str()]);
        }
        assert_eq!(held(&gate), MAX_FAILED_DEPENDENCIES);
        let last = format!("${MAX_FAILED_DEPENDENCIES}");
        assert_eq!(gate.failed_at(start, "!room", None, ["$0"]), None);
        assert_eq!(gate.failed_at(start, "!room", None, ["$1"]), Some("$1"));
        assert_eq!(
            gate.failed_at(start, "!room", None, [last.as_str()]),
            Some(last.as_str())
        );
    }

    /// A TTL of zero turns the cache off.
    #[test]
    fn a_zero_ttl_holds_nothing() {
        let gate = RecoveryGate::new(Duration::ZERO);
        let now = Instant::now();
        gate.distrust_at(now, "!room", None, ["$named"]);
        assert_eq!(gate.failed_at(now, "!room", None, ["$named"]), None);
        assert_eq!(held(&gate), 0);
    }
}
