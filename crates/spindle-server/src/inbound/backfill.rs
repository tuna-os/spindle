//! Fill recorded federation gaps in the background (#619).
//!
//! A PDU accepted across a gap ([`super::gap`]) leaves a marker naming the
//! predecessors this server lacks. This loop reads the markers and, one
//! chunk at a time, walks that missing history backwards from them with
//! `/backfill`, until every branch of the walk meets history this server
//! holds:
//!
//! 1. ask a participating server for up to `gap_backfill_chunk` events
//!    before the walk's frontier, and keep only the ones the walk asked for
//!    -- the frontier's own events and, transitively, their `prev_events`.
//!    Event IDs are reference hashes, so every event kept is pinned by the
//!    signed gap event above it: a peer cannot slip anything else in;
//! 2. verify every one (hash, signatures, ID) and fetch any auth event this
//!    server lacks, verified and authorized the same way
//!    ([`crate::rooms::Rooms::retain_remote_auth`]);
//! 3. ask for `/state_ids` once, at the chunk's oldest event (SPEC §6.5),
//!    and fetch and authorize whatever of that state this server lacks;
//! 4. hand the chunk to [`crate::rooms::Rooms::commit_gap_chunk`], which
//!    judges each event against its auth events and the state folded
//!    forward from that `/state_ids`, stores the ones that pass as the
//!    gap's segment of the timeline, and records the walk's new frontier
//!    in the marker -- one atomic write, so a restart resumes exactly where
//!    the last chunk stopped and a refused chunk changes nothing.
//!
//! Backfilled events take no stream position, so `/sync` never fans them
//! out and push never sees them; they are not in the room's log, so they
//! never move its current state or its forward extremities.
//!
//! **Pacing.** One chunk at a time, server-wide, with
//! `gap_backfill_interval_ms` between chunks: a 10k-event gap fills over a
//! few minutes rather than competing with request handling. A peer that
//! answers 429 is left alone for the room (the same cooldowns recovery
//! keeps), one that answers 403 is not asked again for a while, and a gap
//! whose chunk failed waits `gap_backfill_retry_ms`, doubling per failure,
//! before it is tried again. A client paging into a gap wakes the loop and
//! puts that room first ([`GapBackfill::poke`]).
//!
//! **Ownership.** Like the delivery loops (#292), this holds what it reads
//! weakly and ends once the router is gone; a pass upgrades for one chunk.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::Value;

use super::recovery::{Endpoint, Failure, Peers, RecoveryGate, verify};
use crate::federation::{Federation, PeerKeys};
use crate::metrics::{BackfillChunk, BackfillEvent, Metrics};
use crate::rooms::{GapChunk, GapChunkOutcome, GapProgress, RoomError, Rooms};
use crate::signing::ServerKey;

/// Frontier events named in one `/backfill` request.
const MAX_FROM: usize = 20;
/// Frontier events fetched one by one when `/backfill` served none of them.
const FALLBACK_EVENTS: usize = 4;
/// Servers tried for one chunk.
const MAX_PEERS: usize = 3;
/// The whole of one chunk: the page, its auth events, its state and the
/// write.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);
/// IDs a `/state_ids` answer may name before it is not read at all.
const MAX_STATE_IDS: usize = 200_000;
/// Longest wait between attempts at a gap whose chunks keep failing.
const MAX_RETRY: Duration = Duration::from_secs(3600);
/// Consecutive chunks refused as invalid before a gap is given up on.
const MAX_INVALID_ATTEMPTS: u32 = 10;
/// How long a room's ranked participants are reused between chunks.
const PARTICIPANTS_TTL: Duration = Duration::from_secs(300);
/// Verifications between two yields to the runtime.
const VERIFY_BATCH: usize = 16;
/// The longest an idle loop sleeps before checking its router is alive.
const IDLE_TICK: Duration = Duration::from_secs(1);

/// The backfill loop's handle: what wakes it, and the rooms a client is
/// waiting on.
#[derive(Debug, Default)]
pub struct GapBackfill {
    wake: tokio::sync::Notify,
    /// Rooms whose gap a client paged into, served first.
    wanted: Mutex<BTreeSet<String>>,
    /// Ranked participants per room, reused for a few minutes: ranking
    /// reads every member event of the room.
    participants: Mutex<HashMap<String, (Instant, Vec<String>)>>,
}

impl GapBackfill {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A client paged into `room_id`'s gap: fill it next, and now.
    pub fn poke(&self, room_id: &str) {
        self.wanted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned());
        self.wake.notify_one();
    }
}

/// How the loop paces itself, from `[federation]`.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub chunk: usize,
    pub interval: Duration,
    pub idle: Duration,
    pub retry: Duration,
    pub max_events: u64,
}

impl Settings {
    #[must_use]
    pub fn of(config: &crate::config::FederationConfig) -> Self {
        Self {
            chunk: config.gap_backfill_chunk.clamp(1, 100),
            interval: Duration::from_millis(config.gap_backfill_interval_ms),
            idle: Duration::from_millis(config.gap_backfill_idle_ms.max(1)),
            retry: Duration::from_millis(config.gap_backfill_retry_ms),
            max_events: u64::try_from(config.gap_backfill_max_events).unwrap_or(u64::MAX),
        }
    }
}

/// What the loop reads, held weakly.
pub struct Sources {
    pub rooms: Weak<Rooms>,
    pub federation: Weak<Federation>,
    pub key: Weak<ServerKey>,
    pub metrics: Weak<Metrics>,
    pub recovery: Weak<RecoveryGate>,
    pub backfill: Weak<GapBackfill>,
    pub server_name: String,
}

/// The sources, upgraded for one chunk.
struct Live {
    rooms: Arc<Rooms>,
    federation: Arc<Federation>,
    key: Arc<ServerKey>,
    metrics: Arc<Metrics>,
    recovery: Arc<RecoveryGate>,
    backfill: Arc<GapBackfill>,
}

impl Sources {
    fn upgrade(&self) -> Option<Live> {
        Some(Live {
            rooms: self.rooms.upgrade()?,
            federation: self.federation.upgrade()?,
            key: self.key.upgrade()?,
            metrics: self.metrics.upgrade()?,
            recovery: self.recovery.upgrade()?,
            backfill: self.backfill.upgrade()?,
        })
    }
}

/// One gap due for a chunk.
struct Due {
    room_id: String,
    marker: Value,
}

/// Run until the router is gone: wait to be woken or for the idle tick,
/// then fill due gaps a chunk at a time, pausing between chunks.
pub async fn run(sources: Sources, settings: Settings) {
    let mut wait = settings.interval;
    loop {
        // Idle in ticks of at most a second, re-upgrading each time, so a
        // loop whose router is gone returns within a second as the other
        // loops do, however long `gap_backfill_idle_ms` is.
        let until = Instant::now() + wait;
        loop {
            let Some(backfill) = sources.backfill.upgrade() else {
                return;
            };
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let woken = tokio::select! {
                () = backfill.wake.notified() => true,
                () = tokio::time::sleep(left.min(IDLE_TICK)) => false,
            };
            if woken {
                break;
            }
        }
        wait = settings.idle;
        loop {
            let Some(live) = sources.upgrade() else {
                return;
            };
            let Some(due) = next_due(&live) else {
                break;
            };
            let peers = Peers {
                rooms: &live.rooms,
                federation: &live.federation,
                key: &live.key,
                server_name: &sources.server_name,
                metrics: &live.metrics,
                recovery: &live.recovery,
            };
            Box::pin(step(&peers, &live.backfill, &due, settings)).await;
            drop(live);
            tokio::time::sleep(settings.interval).await;
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The next gap to fill: a room a client is waiting on first, then the
/// oldest gap. Also counts the open gaps for the gauge, and clears markers
/// a finished chunk left behind if a crash came between its write and the
/// marker's delete.
fn next_due(live: &Live) -> Option<Due> {
    let markers = match live.rooms.all_federation_gaps() {
        Ok(markers) => markers,
        Err(error) => {
            tracing::warn!("cannot read the federation gap markers: {error}");
            return None;
        }
    };
    let now = now_ms();
    let mut open = 0_u64;
    let mut due = Vec::new();
    for (room_id, marker) in markers {
        let progress = GapProgress::of(&marker);
        match progress.status.as_str() {
            "open" => {
                open += 1;
                if progress.next_attempt_ms <= now {
                    due.push(Due { room_id, marker });
                }
            }
            "complete" => {
                if let Some(event_id) = marker["event_id"].as_str() {
                    let _ = live.rooms.delete_federation_gap(&room_id, event_id);
                }
            }
            _ => {}
        }
    }
    live.metrics.set_gaps_remaining(open);
    let mut wanted = live
        .backfill
        .wanted
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    wanted.retain(|room| due.iter().any(|gap| &gap.room_id == room));
    due.sort_by_key(|gap| {
        (
            !wanted.contains(&gap.room_id),
            gap.marker["accepted_ts"].as_u64().unwrap_or(0),
        )
    });
    due.into_iter().next()
}

/// Set the open-gaps gauge from the markers as they stand now.
fn refresh_gaps_remaining(peers: &Peers<'_>) {
    if let Ok(markers) = peers.rooms.all_federation_gaps() {
        let open = markers
            .iter()
            .filter(|(_, marker)| GapProgress::of(marker).status == "open")
            .count();
        peers
            .metrics
            .set_gaps_remaining(u64::try_from(open).unwrap_or(u64::MAX));
    }
}

/// Fill one chunk of one gap and record how it went.
async fn step(peers: &Peers<'_>, backfill: &GapBackfill, due: &Due, settings: Settings) {
    let started = Instant::now();
    let Some(event_id) = due.marker["event_id"].as_str() else {
        return;
    };
    let room_id = due.room_id.as_str();
    let attempt = tokio::time::timeout(
        CHUNK_TIMEOUT,
        Box::pin(fill(peers, backfill, due, settings)),
    )
    .await;
    let failure = match attempt {
        Ok(Ok(outcome)) => {
            if outcome.complete {
                // The gap just closed: the gauge says so before the chunk is
                // counted, not one idle interval later at the next scan, so
                // whoever sees the completion sees the gauge agree with it.
                refresh_gaps_remaining(peers);
            }
            let result = if outcome.complete {
                BackfillChunk::Completed
            } else {
                BackfillChunk::Filled
            };
            peers.metrics.record_backfill_events(
                BackfillEvent::Inserted,
                u64::try_from(outcome.inserted).unwrap_or(u64::MAX),
            );
            peers.metrics.record_backfill_events(
                BackfillEvent::Rejected,
                u64::try_from(outcome.rejected).unwrap_or(u64::MAX),
            );
            peers
                .metrics
                .record_backfill_chunk(result, started.elapsed());
            if outcome.complete {
                tracing::info!(
                    room = room_id,
                    event_id,
                    "backfilled a federation gap to history this server holds"
                );
            } else {
                tracing::debug!(
                    room = room_id,
                    event_id,
                    inserted = outcome.inserted,
                    rejected = outcome.rejected,
                    "backfilled one chunk of a federation gap"
                );
            }
            return;
        }
        Ok(Err(failure)) => failure,
        Err(_) => Failure::peer("the chunk timed out"),
    };
    let result = match &failure {
        Failure::Peer {
            rate_limited: Some(_),
            ..
        } => BackfillChunk::RateLimited,
        Failure::Peer { .. } => BackfillChunk::PeerError,
        Failure::Budget(_) => BackfillChunk::Truncated,
        Failure::Invalid(_) | Failure::Verdict(_) => BackfillChunk::Invalid,
    };
    peers
        .metrics
        .record_backfill_chunk(result, started.elapsed());
    record_failure(peers, due, event_id, &failure, result, settings);
}

/// Back a gap off after a failed chunk: count the attempt, set when it may
/// be tried again, and settle a gap that cannot be filled as truncated or
/// failed so the loop stops asking.
fn record_failure(
    peers: &Peers<'_>,
    due: &Due,
    event_id: &str,
    failure: &Failure,
    result: BackfillChunk,
    settings: Settings,
) {
    let room_id = due.room_id.as_str();
    // Re-read rather than reuse `due.marker`: a chunk that failed wrote
    // nothing, but the marker may still have moved underneath.
    let marker = peers
        .rooms
        .federation_gaps(room_id)
        .ok()
        .and_then(|markers| {
            markers
                .into_iter()
                .find(|marker| marker["event_id"].as_str() == Some(event_id))
        })
        .unwrap_or_else(|| due.marker.clone());
    let mut progress = GapProgress::of(&marker);
    progress.attempts = progress.attempts.saturating_add(1);
    let wait = settings
        .retry
        .saturating_mul(2_u32.saturating_pow(progress.attempts.saturating_sub(1).min(16)))
        .min(MAX_RETRY);
    progress.next_attempt_ms =
        now_ms().saturating_add(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX));
    progress.last_error = Some(failure.message().chars().take(500).collect());
    match result {
        BackfillChunk::Truncated => "truncated".clone_into(&mut progress.status),
        BackfillChunk::Invalid if progress.attempts >= MAX_INVALID_ATTEMPTS => {
            "failed".clone_into(&mut progress.status);
        }
        _ => {}
    }
    tracing::warn!(
        room = room_id,
        event_id,
        attempts = progress.attempts,
        status = %progress.status,
        "a federation gap backfill chunk failed: {}",
        failure.message()
    );
    if let Err(error) =
        peers
            .rooms
            .put_federation_gap(room_id, event_id, &progress.into_marker(marker))
    {
        tracing::warn!(
            room = room_id,
            event_id,
            "cannot record backfill progress: {error}"
        );
    }
}

/// Fetch, verify and store the next chunk of one gap.
async fn fill(
    peers: &Peers<'_>,
    backfill: &GapBackfill,
    due: &Due,
    settings: Settings,
) -> Result<GapChunkOutcome, Failure> {
    let room_id = due.room_id.as_str();
    let anchor_event = due.marker["event_id"]
        .as_str()
        .ok_or_else(|| Failure::Invalid("the gap marker names no event".to_owned()))?;
    let progress = GapProgress::of(&due.marker);
    let version = peers.rooms.room_version(room_id)?;
    if spindle_core::is_state_dag(&version) {
        return Err(Failure::Budget(
            "a state-DAG room's history cannot be folded from /state_ids".to_owned(),
        ));
    }
    let frontier = peers.rooms.gap_unheld(room_id, &progress.frontier)?;
    if frontier.is_empty() {
        // Every branch already met held history: close the gap.
        return commit(
            peers,
            room_id,
            &GapChunk {
                anchor_event,
                events: &[],
                state_before: &[],
                frontier: Vec::new(),
            },
        );
    }
    let room_left = u64::from(progress.next_seq).saturating_add(1);
    if progress.filled >= settings.max_events
        || room_left < u64::try_from(settings.chunk).unwrap_or(u64::MAX)
    {
        return Err(Failure::Budget(format!(
            "the gap has backfilled {} events, its limit",
            progress.filled
        )));
    }

    let candidates = candidates(peers, backfill, room_id, &due.marker, anchor_event);
    if candidates.is_empty() {
        return Err(Failure::Peer {
            message: "every participating server is cooling down".to_owned(),
            rate_limited: Some(Duration::ZERO),
            forbidden: false,
        });
    }
    let mut keys = HashMap::new();
    let mut last = None;
    for peer in candidates {
        match Box::pin(fetch_chunk(
            peers, &peer, room_id, &version, &frontier, settings, &mut keys,
        ))
        .await
        {
            Ok(fetched) => {
                tokio::task::yield_now().await;
                let outcome = commit(
                    peers,
                    room_id,
                    &GapChunk {
                        anchor_event,
                        events: &fetched.events,
                        state_before: &fetched.state_before,
                        frontier: fetched.frontier,
                    },
                );
                tokio::task::yield_now().await;
                return outcome;
            }
            Err(failure) => {
                match &failure {
                    Failure::Peer {
                        rate_limited: Some(wait),
                        ..
                    } => peers
                        .recovery
                        .cool(room_id, &peer, Endpoint::Backfill, *wait),
                    Failure::Peer {
                        forbidden: true, ..
                    } => peers.recovery.shun(room_id, &peer),
                    Failure::Budget(_) => return Err(failure),
                    _ => {}
                }
                tracing::info!(
                    room = room_id,
                    event_id = anchor_event,
                    peer = %peer,
                    "a gap backfill chunk failed against a peer: {}",
                    failure.message()
                );
                last = Some(failure);
            }
        }
    }
    Err(last.unwrap_or_else(|| Failure::peer("no participating server could be asked")))
}

/// Store a checked chunk. A refusal by the room is a refusal of what the
/// peer sent: fail closed, nothing of the chunk is kept.
fn commit(
    peers: &Peers<'_>,
    room_id: &str,
    chunk: &GapChunk<'_>,
) -> Result<GapChunkOutcome, Failure> {
    peers
        .rooms
        .commit_gap_chunk(room_id, chunk)
        .map_err(|error| Failure::Invalid(format!("the chunk was refused: {error}")))
}

/// The servers to ask, in order: whoever served the gap event's state,
/// the gap event's own server, then the servers with the most members
/// joined (#620), leaving out this server and any peer still cooling down
/// from a 429 or a 403 for this room.
fn candidates(
    peers: &Peers<'_>,
    backfill: &GapBackfill,
    room_id: &str,
    marker: &Value,
    anchor_event: &str,
) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::new();
    if let Some(from) = marker["state_from"].as_str() {
        ordered.push(from.to_owned());
    }
    if let Ok(event) = peers.rooms.pdu(room_id, anchor_event)
        && let Some((_, domain)) = event["sender"].as_str().and_then(|s| s.split_once(':'))
    {
        ordered.push(domain.to_owned());
    }
    ordered.extend(participants(peers.rooms, backfill, room_id));
    let mut seen = HashSet::new();
    ordered
        .into_iter()
        .filter(|peer| {
            peer != peers.server_name
                && seen.insert(peer.clone())
                && !peers.recovery.cooling(room_id, peer, Endpoint::Backfill)
                && !peers.recovery.cooling(room_id, peer, Endpoint::StateIds)
        })
        .take(MAX_PEERS)
        .collect()
}

/// The room's participating servers, ranked, from a short-lived cache.
fn participants(rooms: &Rooms, backfill: &GapBackfill, room_id: &str) -> Vec<String> {
    let mut cache = backfill
        .participants
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.retain(|_, (at, _)| at.elapsed() < PARTICIPANTS_TTL);
    if let Some((_, ranked)) = cache.get(room_id) {
        return ranked.clone();
    }
    let ranked = rooms.participating_servers(room_id).unwrap_or_default();
    cache.insert(room_id.to_owned(), (Instant::now(), ranked.clone()));
    ranked
}

/// A chunk fetched from one peer and verified, ready to be committed.
struct Fetched {
    /// Newest first, every event before its predecessors.
    events: Vec<(String, Value)>,
    state_before: Vec<String>,
    frontier: Vec<String>,
}

/// The walk over one peer's answer: which events it asked for, and which
/// it took.
struct Walk {
    wanted: BTreeSet<String>,
    taken: Vec<(String, Value)>,
    seen: HashSet<String>,
}

impl Walk {
    fn new(frontier: &[String]) -> Self {
        Self {
            wanted: frontier.iter().cloned().collect(),
            taken: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Take every offered event the walk wants, following each one's
    /// `prev_events` to what it wants next, until nothing offered is
    /// wanted or the chunk is full. A predecessor this server holds is
    /// where that branch of the walk ends.
    fn take(
        &mut self,
        rooms: &Rooms,
        room_id: &str,
        offered: &mut HashMap<String, Value>,
        limit: usize,
    ) -> Result<(), RoomError> {
        loop {
            let mut found = Vec::new();
            for id in &self.wanted {
                if self.taken.len() + found.len() >= limit {
                    break;
                }
                if let Some(body) = offered.remove(id) {
                    found.push((id.clone(), body));
                }
            }
            if found.is_empty() {
                return Ok(());
            }
            let mut parents = Vec::new();
            for (id, body) in found {
                self.wanted.remove(&id);
                self.seen.insert(id.clone());
                parents.extend(
                    crate::rooms::edge_ids(&body["prev_events"])
                        .into_iter()
                        .filter(|parent| !self.seen.contains(parent)),
                );
                self.taken.push((id, body));
            }
            parents.sort();
            parents.dedup();
            for parent in rooms.gap_unheld(room_id, &parents)? {
                if !self.seen.contains(&parent) {
                    self.wanted.insert(parent);
                }
            }
        }
    }
}

/// Index a peer's PDUs by the ID each one's content names, under the
/// room's version. A PDU that does not parse is not one the walk can want.
fn by_id(version: &RoomVersionId, pdus: Vec<Value>) -> HashMap<String, Value> {
    let mut out = HashMap::with_capacity(pdus.len());
    for pdu in pdus {
        let Ok(CanonicalJsonValue::Object(canonical)) = CanonicalJsonValue::try_from(pdu.clone())
        else {
            continue;
        };
        if let Ok(parsed) = spindle_core::Pdu::from_remote(version.clone(), canonical) {
            out.insert(parsed.event_id().as_str().to_owned(), pdu);
        }
    }
    out
}

/// One chunk from one peer: the page, verified, with its auth events and
/// the state before its oldest event retained.
#[allow(
    clippy::too_many_lines,
    reason = "one chunk's fetch, verification and state, in the order SPEC §6.5 gives"
)]
async fn fetch_chunk(
    peers: &Peers<'_>,
    peer: &str,
    room_id: &str,
    version: &RoomVersionId,
    frontier: &[String],
    settings: Settings,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<Fetched, Failure> {
    let from: Vec<String> = frontier.iter().take(MAX_FROM).cloned().collect();
    let pdus = peers
        .federation
        .remote_backfill(peer, room_id, &from, settings.chunk)
        .await
        .map_err(|error| Failure::from_peer(&error))?;
    peers.metrics.record_backfill_events(
        BackfillEvent::Fetched,
        u64::try_from(pdus.len()).unwrap_or(u64::MAX),
    );
    let mut offered = by_id(version, pdus);
    let mut walk = Walk::new(frontier);
    walk.take(peers.rooms, room_id, &mut offered, settings.chunk)?;
    if walk.taken.is_empty() {
        // A peer whose `/backfill` served nothing the walk asked for --
        // some answer only from their own extremities -- may still serve
        // the events themselves.
        for id in frontier.iter().take(FALLBACK_EVENTS) {
            let body = peers
                .federation
                .remote_event(peer, id)
                .await
                .map_err(|error| Failure::from_peer(&error))?;
            peers
                .metrics
                .record_backfill_events(BackfillEvent::Fetched, 1);
            offered.insert(id.clone(), body);
        }
        walk.take(peers.rooms, room_id, &mut offered, settings.chunk)?;
    }
    if walk.taken.is_empty() {
        return Err(Failure::peer(format!(
            "{peer} served none of the gap's missing history"
        )));
    }

    // Every event the walk took: hash, signatures, and that the body is
    // the event it was asked for. One forged event refuses the chunk.
    let mut events = Vec::with_capacity(walk.taken.len());
    for (index, (id, body)) in walk.taken.into_iter().enumerate() {
        let verified = verify(peers, room_id, version, &body, Some(&id), keys)
            .await
            .map_err(|why| Failure::Invalid(format!("backfilled event {id}: {why}")))?;
        if verified.id != id {
            return Err(Failure::Invalid(format!(
                "backfilled event {id} does not match the body served for it"
            )));
        }
        events.push((id, verified.body));
        if index % VERIFY_BATCH == VERIFY_BATCH - 1 {
            tokio::task::yield_now().await;
        }
    }
    let events = newest_first(events);

    // Auth events the chunk cites and this server lacks, outside the chunk
    // itself: fetched, verified and authorized before anything is judged.
    let in_chunk: HashSet<&str> = events.iter().map(|(id, _)| id.as_str()).collect();
    let mut auth = BTreeSet::new();
    for (_, body) in &events {
        for id in peers.rooms.missing_remote_dependencies(room_id, body)?.1 {
            if !in_chunk.contains(id.as_str()) {
                auth.insert(id);
            }
        }
    }
    if !auth.is_empty() {
        let fetched = Box::pin(super::gap::fetch_state(
            peers, peer, room_id, version, auth, "", keys,
        ))
        .await?;
        retain(peers, room_id, fetched)?;
    }

    // SPEC §6.5: the state once per chunk, at its oldest event.
    let oldest = events
        .last()
        .map(|(id, _)| id.clone())
        .ok_or_else(|| Failure::peer("an empty chunk"))?;
    let started = Instant::now();
    let response = match peers
        .federation
        .remote_state_ids(peer, room_id, &oldest)
        .await
    {
        Ok(response) => {
            peers.metrics.observe_state_ids("ok", started.elapsed());
            response
        }
        Err(error) => {
            let failure = Failure::from_peer(&error);
            if let Failure::Peer {
                rate_limited: Some(wait),
                ..
            } = &failure
            {
                peers
                    .recovery
                    .cool(room_id, peer, Endpoint::StateIds, *wait);
                peers
                    .metrics
                    .observe_state_ids("rate_limited", started.elapsed());
            } else {
                peers.metrics.observe_state_ids("error", started.elapsed());
            }
            return Err(failure);
        }
    };
    let ids = |field: &str| -> Vec<String> {
        response[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let state_before = ids("pdu_ids");
    let auth_chain = ids("auth_chain_ids");
    if state_before.len().saturating_add(auth_chain.len()) > MAX_STATE_IDS {
        return Err(Failure::Budget(format!(
            "/state_ids from {peer} names more than {MAX_STATE_IDS} events"
        )));
    }
    if state_before.is_empty() {
        return Err(Failure::Invalid(format!(
            "/state_ids from {peer} names no state"
        )));
    }
    let roots: BTreeSet<String> = state_before.iter().chain(&auth_chain).cloned().collect();
    let fetched = Box::pin(super::gap::fetch_state(
        peers, peer, room_id, version, roots, &oldest, keys,
    ))
    .await?;
    retain(peers, room_id, fetched)?;

    Ok(Fetched {
        events,
        state_before,
        frontier: walk.wanted.into_iter().collect(),
    })
}

/// Retain verified auth and state bodies, each authorized against its own
/// auth events; one that is not refuses the chunk.
fn retain(
    peers: &Peers<'_>,
    room_id: &str,
    fetched: std::collections::BTreeMap<String, Value>,
) -> Result<(), Failure> {
    if fetched.is_empty() {
        return Ok(());
    }
    peers
        .rooms
        .retain_remote_auth(room_id, &fetched.into_iter().collect::<Vec<_>>())
        .map_err(|error| Failure::Invalid(format!("the chunk's state or auth events: {error}")))
}

/// Order a chunk newest first, every event before its predecessors: a
/// topological order over the edges inside the chunk, ties broken by
/// depth, then timestamp, then ID, newest first.
fn newest_first(events: Vec<(String, Value)>) -> Vec<(String, Value)> {
    let index: HashMap<String, usize> = events
        .iter()
        .enumerate()
        .map(|(at, (id, _))| (id.clone(), at))
        .collect();
    let parents: Vec<Vec<usize>> = events
        .iter()
        .map(|(_, body)| {
            let mut parents: Vec<usize> = crate::rooms::edge_ids(&body["prev_events"])
                .iter()
                .filter_map(|parent| index.get(parent).copied())
                .collect();
            parents.sort_unstable();
            parents.dedup();
            parents
        })
        .collect();
    let mut children = vec![0_usize; events.len()];
    for each in &parents {
        for &parent in each {
            children[parent] += 1;
        }
    }
    let key = |at: usize| {
        let body = &events[at].1;
        (
            std::cmp::Reverse(body["depth"].as_i64().unwrap_or(0)),
            std::cmp::Reverse(body["origin_server_ts"].as_i64().unwrap_or(0)),
            events[at].0.clone(),
            at,
        )
    };
    let mut ready: BTreeSet<_> = (0..events.len())
        .filter(|&at| children[at] == 0)
        .map(key)
        .collect();
    let mut order = Vec::with_capacity(events.len());
    let mut placed = vec![false; events.len()];
    while let Some(next) = ready.pop_first() {
        let at = next.3;
        order.push(at);
        placed[at] = true;
        for &parent in &parents[at] {
            children[parent] -= 1;
            if children[parent] == 0 {
                ready.insert(key(parent));
            }
        }
    }
    // A cycle cannot be signed into existence with reference-hash IDs; if
    // one arrives anyway, what is left goes last, deepest first.
    let mut rest: Vec<usize> = (0..events.len()).filter(|&at| !placed[at]).collect();
    rest.sort_by_key(|&at| key(at));
    order.extend(rest);
    let mut slots: Vec<Option<(String, Value)>> = events.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|at| slots.get_mut(at).and_then(Option::take))
        .collect()
}
