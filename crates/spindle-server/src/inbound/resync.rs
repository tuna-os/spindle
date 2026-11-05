//! Resync partial-state rooms in the background (MSC3706 faster joins,
//! #746).
//!
//! A join answered with `members_omitted` returns to the client at once
//! and leaves a record (`crate::rooms::PartialState`). This loop reads the
//! records and, for each room, asks a server for the full state at the
//! join -- the server the join went through first, then the resident's
//! `servers_in_room` -- the way Synapse's `_sync_partial_state_room` does:
//!
//! 1. `/state_ids` at the join names the state before it and its auth
//!    chain;
//! 2. the bodies this server lacks are fetched -- with one `/state` when
//!    they are a tenth or more of what was named, which for a large room's
//!    omitted roster is nearly all of it, and an `/event` each otherwise,
//!    the same split Synapse makes -- each named by its own hash and
//!    signature-checked, then authorized against its auth events and
//!    retained ([`crate::rooms::Rooms::retain_remote_auth`]);
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

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::Value;

use super::gap::fetch_state;
use super::recovery::{Endpoint, Failure, Peers, RecoveryGate, verify};
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
            let peers = Peers {
                rooms: &live.rooms,
                federation: &live.federation,
                key: &live.key,
                server_name: &sources.server_name,
                metrics: &live.metrics,
                recovery: &live.recovery,
            };
            match Box::pin(resync(&peers, &record)).await {
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
    let response = peers
        .federation
        .remote_state_ids(peer, room_id, join_id)
        .await
        .map_err(|error| Failure::from_peer_doing("/state_ids", &error))?;
    let ids = |field: &str| -> Vec<String> {
        response[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let state_ids = ids("pdu_ids");
    let auth_ids = ids("auth_chain_ids");
    if state_ids.len().saturating_add(auth_ids.len()) > MAX_STATE_IDS {
        return Err(Failure::Budget(format!(
            "/state_ids from {peer} names more than {MAX_STATE_IDS} events"
        )));
    }
    if state_ids.is_empty() {
        return Err(Failure::Invalid(format!(
            "/state_ids from {peer} names no state"
        )));
    }

    let named: BTreeSet<String> = state_ids.iter().chain(&auth_ids).cloned().collect();
    let mut missing = BTreeSet::new();
    for id in &named {
        match peers.rooms.pdu(room_id, id) {
            Ok(_) => {}
            Err(RoomError::MissingBody(_)) => {
                missing.insert(id.clone());
            }
            Err(error) => return Err(error.into()),
        }
    }

    let mut fetched = BTreeMap::new();
    if missing.len().saturating_mul(10) >= named.len() {
        fetched = state_bodies(peers, peer, record, version, &missing, keys).await?;
    }
    // Whatever `/state` did not carry, or all of it when little is
    // missing, and every auth event the fetched bodies cite that this
    // server lacks: one `/event` each.
    let mut rest: BTreeSet<String> = missing
        .iter()
        .filter(|id| !fetched.contains_key(*id))
        .cloned()
        .collect();
    for body in fetched.values() {
        rest.extend(
            peers
                .rooms
                .missing_remote_dependencies(room_id, body)?
                .1
                .into_iter()
                .filter(|id| !fetched.contains_key(id)),
        );
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

/// The bodies of `/state` at the join that this server lacks, each named
/// by its own hash and signature-checked. Bodies it already holds are
/// skipped before the signature check: their identity is all that is
/// read of them.
async fn state_bodies(
    peers: &Peers<'_>,
    peer: &str,
    record: &PartialState,
    version: &RoomVersionId,
    missing: &BTreeSet<String>,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<BTreeMap<String, Value>, Failure> {
    let room_id = record.room_id.as_str();
    let response = peers
        .federation
        .remote_state(peer, room_id, &record.join_event_id, MAX_STATE_BYTES)
        .await
        .map_err(|error| Failure::from_peer_doing("/state", &error))?;
    let bodies: Vec<&Value> = ["pdus", "auth_chain"]
        .iter()
        .filter_map(|field| response[*field].as_array())
        .flatten()
        .collect();
    let mut fetched = BTreeMap::new();
    for body in bodies {
        let Some(id) = reference_id(version, body) else {
            continue;
        };
        if !missing.contains(&id) || fetched.contains_key(&id) {
            continue;
        }
        let verified = verify(peers, room_id, version, body, Some(&id), keys)
            .await
            .map_err(|why| Failure::Invalid(format!("state event {id}: {why}")))?;
        fetched.insert(verified.id, verified.body);
    }
    Ok(fetched)
}

/// The ID a body hashes to under `version`, or `None` for one that is not
/// an event; `verify` judges it properly once it is known to be wanted.
fn reference_id(version: &RoomVersionId, body: &Value) -> Option<String> {
    let CanonicalJsonValue::Object(canonical) = CanonicalJsonValue::try_from(body.clone()).ok()?
    else {
        return None;
    };
    spindle_core::Pdu::from_remote(version.clone(), canonical)
        .ok()
        .map(|pdu| pdu.event_id().as_str().to_owned())
}
