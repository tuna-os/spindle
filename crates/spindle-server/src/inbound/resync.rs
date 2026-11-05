//! Resync partial-state rooms in the background (MSC3706 faster joins,
//! #746).
//!
//! A join answered with `members_omitted` returns to the client at once
//! and leaves a record (`crate::rooms::PartialState`). This loop reads the
//! records and, for each room, asks a server for the full state at the
//! join -- the server the join went through first, then the resident's
//! `servers_in_room`:
//!
//! 1. one `/state` at the join carries the state before it and its auth
//!    chain. Synapse asks `/state_ids` first and then `/state` when a
//!    tenth or more is missing; a partial-state room always lacks its
//!    omitted roster, so that test always passes and the first request
//!    is a round trip saved (#766);
//! 2. the bodies this server lacks are each named by their own hash,
//!    signature-checked on every core, then authorized against their auth
//!    events and retained ([`crate::rooms::Rooms::retain_remote_auth`]);
//!    auth events they cite that are still missing come by `/event`;
//! 3. [`crate::rooms::Rooms::complete_partial_state`] folds the member
//!    events into every snapshot from the join on and ends the room's
//!    partial state.
//!
//! A peer that cannot answer, or answers with something that does not
//! verify, gives way to the next; a room no peer could resync waits
//! `retry_base_ms`, doubling per failure up to ten minutes, and is tried
//! again for as long as it is partial. The record outlives a restart, so a
//! resync cut short by one starts over when the server comes back.
//!
//! **Ownership.** Like the backfill loop (#292), this holds what it reads
//! weakly and ends once the router is gone; a pass upgrades for one room.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use ruma::RoomVersionId;
use serde_json::Value;

use super::gap::fetch_state;
use super::recovery::{
    Endpoint, Failure, Peers, RecoveryGate, check_signed, identify, signing_keys,
};
use crate::federation::{Federation, PeerKeys};
use crate::metrics::Metrics;
use crate::rooms::{PartialState, RoomError, Rooms};
use crate::signing::ServerKey;

/// Servers asked in one pass for one room.
const MAX_PEERS: usize = 4;
/// IDs a `/state_ids` answer may name before it is not read at all.
const MAX_STATE_IDS: usize = 500_000;
/// The largest `/state` answer read: a room of a hundred thousand members
/// is tens of megabytes of member events.
const MAX_STATE_BYTES: usize = 256 * 1024 * 1024;
/// The longest a room waits between attempts.
const MAX_RETRY: Duration = Duration::from_secs(600);
/// How often an idle loop checks that its router still exists.
const IDLE_TICK: Duration = Duration::from_secs(1);

/// When each room whose last attempt failed is due again, and how many
/// attempts in a row have failed. Local to the loop: nothing else asks.
#[derive(Default)]
struct Retry(HashMap<String, (Instant, u32)>);

impl Retry {
    fn due(&self, room_id: &str) -> bool {
        self.0
            .get(room_id)
            .is_none_or(|(due, _)| *due <= Instant::now())
    }

    fn failed(&mut self, room_id: &str, base: Duration) {
        let failures = self.0.get(room_id).map_or(0, |(_, failures)| *failures);
        let wait = base
            .saturating_mul(2u32.saturating_pow(failures.min(16)))
            .min(MAX_RETRY);
        self.0.insert(
            room_id.to_owned(),
            (Instant::now() + wait, failures.saturating_add(1)),
        );
    }

    fn succeeded(&mut self, room_id: &str) {
        self.0.remove(room_id);
    }
}

/// What the loop reads, held weakly.
pub struct Sources {
    pub rooms: Weak<Rooms>,
    pub federation: Weak<Federation>,
    pub key: Weak<ServerKey>,
    pub metrics: Weak<Metrics>,
    pub recovery: Weak<RecoveryGate>,
    /// Rung by every partial join ([`Rooms::partial_state_wake`]).
    pub wake: Arc<tokio::sync::Notify>,
    pub server_name: String,
    /// The first wait after a failed attempt (`retry_base_ms`).
    pub retry: Duration,
}

/// The sources, upgraded for one room.
struct Live {
    rooms: Arc<Rooms>,
    federation: Arc<Federation>,
    key: Arc<ServerKey>,
    metrics: Arc<Metrics>,
    recovery: Arc<RecoveryGate>,
}

impl Sources {
    fn upgrade(&self) -> Option<Live> {
        Some(Live {
            rooms: self.rooms.upgrade()?,
            federation: self.federation.upgrade()?,
            key: self.key.upgrade()?,
            metrics: self.metrics.upgrade()?,
            recovery: self.recovery.upgrade()?,
        })
    }
}

/// Run until the router is gone: resync every due partial-state room,
/// then wait to be woken or for the next tick.
pub async fn run(sources: Sources) {
    let mut retry = Retry::default();
    loop {
        let rooms = match sources.upgrade() {
            Some(live) => live.rooms.partial_state_rooms(),
            None => return,
        };
        for record in rooms {
            let Some(live) = sources.upgrade() else {
                return;
            };
            if !retry.due(&record.room_id) {
                continue;
            }
            // One room's resync on the blocking pool: it folds the whole
            // state at the join into the room and resolves it, which for a
            // big room is seconds of synchronous work that on a worker
            // held the worker for as long (#614).
            let server_name = sources.server_name.clone();
            let metrics = Arc::clone(&live.metrics);
            let room = record.clone();
            let attempt = crate::blocking::offload_async(
                metrics,
                crate::metrics::BlockingTask::FederationCatchUp,
                move || async move {
                    let peers = Peers {
                        rooms: &live.rooms,
                        federation: &live.federation,
                        key: &live.key,
                        server_name: &server_name,
                        metrics: &live.metrics,
                        recovery: &live.recovery,
                    };
                    Box::pin(resync(&peers, &room)).await
                },
            )
            .await
            .unwrap_or_else(|_| Err(Failure::peer("the resync panicked")));
            match attempt {
                Ok(filled) => {
                    retry.succeeded(&record.room_id);
                    tracing::info!(
                        room = %record.room_id,
                        filled,
                        "partial-state room resynced"
                    );
                }
                Err(failure) => {
                    retry.failed(&record.room_id, sources.retry);
                    tracing::info!(
                        room = %record.room_id,
                        "cannot resync a partial-state room yet: {}",
                        failure.message()
                    );
                }
            }
        }
        // A tick at most, so a loop whose router is gone returns within one
        // and a room whose retry came due is not left waiting for a join.
        let tick = sources.retry.clamp(Duration::from_millis(1), IDLE_TICK);
        tokio::select! {
            () = sources.wake.notified() => {}
            () = tokio::time::sleep(tick) => {}
        }
    }
}

/// One attempt at one room, from each candidate server in turn.
async fn resync(peers: &Peers<'_>, record: &PartialState) -> Result<usize, Failure> {
    let room_id = record.room_id.as_str();
    let version = match peers.rooms.room_version(room_id) {
        Ok(version) => version,
        // The record outlived its room: the seeding it was written before
        // never finished. Nothing to resync.
        Err(RoomError::UnknownRoom(_)) => {
            peers.rooms.abandon_partial_state(room_id)?;
            return Ok(0);
        }
        Err(error) => return Err(error.into()),
    };
    let mut candidates = vec![record.via.clone()];
    for server in &record.servers_in_room {
        if !candidates.contains(server) {
            candidates.push(server.clone());
        }
    }
    // Collected before the first request rather than filtered lazily: an
    // iterator of borrowing closures held across an await is not `Send`
    // for every lifetime, and the loop runs on a spawned task.
    let candidates: Vec<String> = candidates
        .into_iter()
        .filter(|peer| peer != peers.server_name)
        .filter(|peer| !peers.recovery.cooling(room_id, peer, Endpoint::StateIds))
        .take(MAX_PEERS)
        .collect();
    let mut keys = HashMap::new();
    let mut last = None;
    for peer in candidates {
        match resync_from(peers, &peer, record, &version, &mut keys).await {
            Ok(filled) => return Ok(filled),
            Err(failure) => {
                if let Failure::Peer {
                    rate_limited: Some(wait),
                    ..
                } = &failure
                {
                    peers
                        .recovery
                        .cool(room_id, &peer, Endpoint::StateIds, *wait);
                }
                tracing::debug!(
                    room = room_id,
                    %peer,
                    "resync from this peer failed: {}",
                    failure.message()
                );
                // Another server may answer, and answer honestly: a peer's
                // invalid state fails only that peer.
                last = Some(failure);
            }
        }
    }
    Err(last
        .unwrap_or_else(|| Failure::peer("no server in the room can be asked for its state yet")))
}

/// Fetch, verify and retain the state at the join from `peer`, then fold
/// it into the room.
async fn resync_from(
    peers: &Peers<'_>,
    peer: &str,
    record: &PartialState,
    version: &RoomVersionId,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<usize, Failure> {
    let room_id = record.room_id.as_str();
    let join_id = record.join_event_id.as_str();
    let State {
        state_ids,
        mut fetched,
    } = state_at_join(peers, peer, record, version, keys).await?;
    // Every auth event the fetched bodies cite that is neither among them
    // nor held here: one `/event` each. Gathered over the whole batch, so
    // the create event, power levels and join rules every member cites
    // are looked up once rather than once per member.
    let mut cited = BTreeSet::new();
    for body in fetched.values() {
        cited.extend(auth_event_ids(body).filter(|id| !fetched.contains_key(*id)));
    }
    let mut rest = BTreeSet::new();
    for id in cited {
        if !holds(peers, room_id, id)? {
            rest.insert(id.to_owned());
        }
    }
    if !rest.is_empty() {
        fetched.extend(fetch_state(peers, peer, room_id, version, rest, join_id, keys).await?);
    }
    if !fetched.is_empty() {
        peers
            .rooms
            .retain_remote_auth(room_id, &fetched.into_iter().collect::<Vec<_>>())
            .map_err(|error| Failure::Invalid(format!("the state at the join: {error}")))?;
    }
    peers
        .rooms
        .complete_partial_state(room_id, &state_ids)
        .map_err(|error| Failure::Invalid(format!("the state at the join: {error}")))
}

/// The state at the join as one peer answers it.
struct State {
    /// The IDs of the state before the join, in the order `/state` gave.
    state_ids: Vec<String>,
    /// The bodies of state and auth chain this server lacked, verified.
    fetched: BTreeMap<String, Value>,
}

/// One `/state` at the join, rather than `/state_ids` and then `/state`:
/// a partial-state room lacks the omitted roster, which is nearly all of a
/// large room's state, so the bodies are wanted anyway and the IDs are
/// theirs to compute. The resident saves computing the state twice and
/// the resync a round trip. Each body is named once by its own hash;
/// bodies this server already holds are skipped before the signature
/// check, since their identity is all that is read of them. Hashing and
/// signature checks both run on every core ([`on_every_core`]).
async fn state_at_join(
    peers: &Peers<'_>,
    peer: &str,
    record: &PartialState,
    version: &RoomVersionId,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<State, Failure> {
    let room_id = record.room_id.as_str();
    let mut response = peers
        .federation
        .remote_state(peer, room_id, &record.join_event_id, MAX_STATE_BYTES)
        .await
        .map_err(|error| Failure::from_peer_doing("/state", &error))?;
    let mut field = |name: &str| -> Vec<Value> {
        match response[name].take() {
            Value::Array(events) => events,
            _ => Vec::new(),
        }
    };
    let (pdus, auth_chain) = (field("pdus"), field("auth_chain"));
    if pdus.len().saturating_add(auth_chain.len()) > MAX_STATE_IDS {
        return Err(Failure::Budget(format!(
            "/state from {peer} carries more than {MAX_STATE_IDS} events"
        )));
    }
    if pdus.is_empty() {
        return Err(Failure::Invalid(format!(
            "/state from {peer} names no state"
        )));
    }
    let state_len = pdus.len();
    let named = {
        let version = version.clone();
        on_every_core(pdus.into_iter().chain(auth_chain).collect(), move |body| {
            (identify(&version, &body), body)
        })
        .await?
    };
    let mut state_ids = Vec::with_capacity(state_len);
    let mut wanted = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, (identified, body)) in named.into_iter().enumerate() {
        let (id, canonical) =
            identified.map_err(|why| Failure::Invalid(format!("/state: {why}")))?;
        if index < state_len {
            state_ids.push(id.clone());
        }
        if !seen.insert(id.clone()) || holds(peers, room_id, &id)? {
            continue;
        }
        // v12's create event names no room: only a stated other room
        // disqualifies, as in `verify`.
        if body["room_id"]
            .as_str()
            .is_some_and(|named| named != room_id)
        {
            return Err(Failure::Invalid(format!(
                "state event {id} belongs to another room"
            )));
        }
        let public_keys = signing_keys(peers, version, &canonical, &body, keys)
            .await
            .map_err(|why| Failure::Invalid(format!("state event {id}: {why}")))?;
        wanted.push(Unchecked {
            id,
            canonical,
            body,
            public_keys,
        });
    }
    let checked = {
        let (room_id, version) = (room_id.to_owned(), version.clone());
        on_every_core(wanted, move |unchecked| {
            let verdict = check_signed(
                &room_id,
                &version,
                &unchecked.canonical,
                &unchecked.id,
                &unchecked.body,
                &unchecked.public_keys,
            );
            (unchecked, verdict)
        })
        .await?
    };
    let mut fetched = BTreeMap::new();
    for (unchecked, verdict) in checked {
        let body = verdict.map_err(|refusal| {
            let why = refusal.explain(peers, keys, &unchecked.body, version);
            Failure::Invalid(format!("state event {}: {why}", unchecked.id))
        })?;
        fetched.insert(unchecked.id, body);
    }
    Ok(State { state_ids, fetched })
}

/// A body named and with its signers' keys gathered, not yet checked.
struct Unchecked {
    id: String,
    canonical: ruma::CanonicalJsonObject,
    body: Value,
    public_keys: ruma::signatures::PublicKeyMap,
}

/// `work` over every item, off the async workers and split across the
/// machine's cores, in the items' order. A 10,000-member resync hashes and
/// signature-checks ten thousand events over canonical JSON; on one thread
/// that was most of the resync (#766). Each item is judged alone, so the
/// split changes nothing but the wall time.
async fn on_every_core<T, U, F>(items: Vec<T>, work: F) -> Result<Vec<U>, Failure>
where
    T: Send + 'static,
    U: Send + 'static,
    F: Fn(T) -> U + Send + Sync + 'static,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }
    tokio::task::spawn_blocking(move || {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let chunk = items.len().div_ceil(threads).max(1);
        let mut items = items;
        let mut chunks = Vec::new();
        while items.len() > chunk {
            let tail = items.split_off(chunk);
            chunks.push(std::mem::replace(&mut items, tail));
        }
        chunks.push(items);
        let work = &work;
        std::thread::scope(|scope| {
            let workers: Vec<_> = chunks
                .into_iter()
                .map(|chunk| scope.spawn(move || chunk.into_iter().map(work).collect::<Vec<_>>()))
                .collect();
            // A worker that panicked judged nothing: the whole batch is
            // refused rather than missing its share.
            let mut done = Vec::new();
            for worker in workers {
                done.extend(
                    worker
                        .join()
                        .map_err(|_| Failure::Invalid("a parallel check panicked".to_owned()))?,
                );
            }
            Ok(done)
        })
    })
    .await
    .map_err(|error| Failure::Invalid(format!("parallel checks stopped: {error}")))?
}

/// Whether this server holds `id`'s body in the room.
fn holds(peers: &Peers<'_>, room_id: &str, id: &str) -> Result<bool, Failure> {
    match peers.rooms.pdu(room_id, id) {
        Ok(_) => Ok(true),
        Err(RoomError::MissingBody(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The auth event IDs a body cites: plain IDs from room version 3, and
/// `[id, hashes]` pairs before it.
fn auth_event_ids(body: &Value) -> impl Iterator<Item = &str> {
    body["auth_events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str().or_else(|| entry[0].as_str()))
}
