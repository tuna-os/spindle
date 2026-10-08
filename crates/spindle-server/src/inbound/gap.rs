//! Accept a pushed PDU across a gap in a room's history, on the state a
//! participating server says it was sent in.
//!
//! The last resort of [`super::recovery`]: its predecessors could not be
//! recovered -- more of them than the budget, a peer that will not answer,
//! or no time left -- and refusing it would freeze the room, because every
//! later event descends from it. This is what Synapse does in the same
//! place (`_get_state_ids_after_missing_prev_event`): ask a server in the
//! room for `/state_ids` at the event, which is the state *before* it and
//! that state's auth chain, fetch and check whatever of that this server
//! lacks, and append the event on that state.
//!
//! Nothing a peer says is taken on its word. Every body fetched is named
//! by its own hash, signature-checked like any recovered event, and
//! authorized against its own auth events before it is stored
//! ([`crate::rooms::Rooms::retain_remote_auth`]); the event itself then
//! passes the full receipt checks against that state and against the
//! room's current state. Anything that fails fails the whole acceptance:
//! fail closed, and the event stays refused.
//!
//! What it does not do is fill the gap. The history between the event's
//! unknown predecessors and what this server holds stays missing; the room
//! records a marker for it (`Rooms::federation_gaps`), and the background
//! backfill ([`super::backfill`]) reads the markers and fills them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ruma::RoomVersionId;
use serde_json::Value;

use super::recovery::{Endpoint, Failure, Peers, VerifiedPdu, charge, count, verify};
use crate::AppState;
use crate::federation::PeerKeys;
use crate::metrics::FetchKind;
use crate::rooms::RoomError;

/// Event bodies one gap acceptance may fetch. A room's state and its auth
/// chain are what is fetched, not its history, so this is sized for a
/// large room's membership rather than for a day of messages; past it the
/// acceptance fails closed rather than hold a room's worth of bodies.
const MAX_GAP_EVENTS: usize = 20_000;
/// Bytes those bodies may total.
const MAX_GAP_BYTES: usize = 64 * 1024 * 1024;
/// IDs a `/state_ids` answer may name before it is not read at all. The
/// response is already capped at 16 MiB on the wire; this bounds the walk.
const MAX_STATE_IDS: usize = 200_000;
/// Servers asked for `/state_ids`, the origin first.
const MAX_STATE_PEERS: usize = 4;
/// `/event` requests in flight at once for one acceptance.
const FETCH_CONCURRENCY: usize = 16;

/// Accept `event` across the gap its unknown predecessors leave, on the
/// state before it from the first participating server that can say what it
/// is: the origin, then the others in the room.
///
/// Returns the predecessors the event named that this server lacks, or
/// `None` when they turned up meanwhile and the event took the ordinary
/// path.
///
/// # Errors
///
/// A [`Failure`]: budget exceeded and invalid answers stop at once (fail
/// closed); a peer that cannot answer gives way to the next one, and the
/// last peer's failure is returned.
pub(super) async fn accept(
    state: &AppState,
    origin: &str,
    room_id: &str,
    version: &RoomVersionId,
    event: &VerifiedPdu,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<Option<Vec<String>>, Failure> {
    if spindle_core::is_state_dag(version) {
        return Err(Failure::Invalid(
            "a state-DAG room's state cannot be taken from /state_ids".to_owned(),
        ));
    }
    // The origin, then the servers with the most joined members first: a
    // server whose users all left answers 403 and has no state to give.
    let mut candidates = vec![origin.to_owned()];
    candidates.extend(
        state
            .rooms
            .participating_servers(room_id)?
            .into_iter()
            .filter(|domain| domain != origin && *domain != state.config.server.name),
    );
    let mut last = None;
    for peer in candidates
        .into_iter()
        .filter(|peer| !state.recovery.cooling(room_id, peer, Endpoint::StateIds))
        .take(MAX_STATE_PEERS)
    {
        let started = Instant::now();
        let answer = state
            .federation
            .remote_state_ids(&peer, room_id, &event.id)
            .await;
        let response = match answer {
            Ok(response) => {
                state.metrics.observe_state_ids("ok", started.elapsed());
                response
            }
            Err(error) => {
                let failure = Failure::from_peer(&error);
                if matches!(
                    failure,
                    Failure::Peer {
                        forbidden: true,
                        ..
                    }
                ) {
                    state.recovery.shun(room_id, &peer);
                }
                let result = if cool(state, room_id, &peer, &failure) {
                    "rate_limited"
                } else {
                    "error"
                };
                state.metrics.observe_state_ids(result, started.elapsed());
                tracing::info!(
                    room = room_id,
                    event_id = %event.id,
                    peer = %peer,
                    "cannot fetch the state at an event across a gap: {error}"
                );
                last = Some(failure);
                continue;
            }
        };
        match bridge(state, &peer, room_id, version, event, &response, keys).await {
            Ok(missing) => return Ok(missing),
            // The peer named the state but would not serve its bodies;
            // another server in the room may.
            Err(failure @ Failure::Peer { .. }) => {
                cool(state, room_id, &peer, &failure);
                last = Some(failure);
            }
            Err(failure) => return Err(failure),
        }
    }
    Err(last.unwrap_or_else(|| Failure::Peer {
        message: "no participating server can be asked for the state at the event".to_owned(),
        rate_limited: Some(Duration::ZERO),
        forbidden: false,
    }))
}

/// Leave a peer that answered 429 alone for this room's `/state_ids`.
/// Whether it did.
fn cool(state: &AppState, room_id: &str, peer: &str, failure: &Failure) -> bool {
    if let Failure::Peer {
        rate_limited: Some(wait),
        ..
    } = failure
    {
        state
            .recovery
            .cool(room_id, peer, Endpoint::StateIds, *wait);
        return true;
    }
    false
}

/// Fetch, check and retain whatever of `peer`'s state at the event this
/// server lacks, then append the event on it.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded walk, then one retention and one append"
)]
async fn bridge(
    state: &AppState,
    peer: &str,
    room_id: &str,
    version: &RoomVersionId,
    event: &VerifiedPdu,
    response: &Value,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<Option<Vec<String>>, Failure> {
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

    // Everything the state, its auth chain and the event's own auth events
    // cite, walked through each fetched body's auth events in turn: the
    // retention below authorizes every body against its auth events, so
    // all of them must be here or already held.
    let mut roots: BTreeSet<String> = state_before.iter().chain(&auth_chain).cloned().collect();
    roots.extend(
        state
            .rooms
            .missing_remote_dependencies(room_id, &event.body)?
            .1,
    );
    let fetched = fetch_state(
        &Peers::of(state),
        peer,
        room_id,
        version,
        roots,
        &event.id,
        keys,
    )
    .await?;

    if !fetched.is_empty() {
        state
            .rooms
            .retain_remote_auth(room_id, &fetched.into_iter().collect::<Vec<_>>())
            .map_err(|error| Failure::Invalid(format!("the state at the event: {error}")))?;
    }
    state
        .rooms
        .accept_across_gap(room_id, &event.id, &event.body, &state_before, peer)
        .map_err(|error| match error {
            // The receipt checks judged the event itself.
            RoomError::Forbidden(why)
                if why.starts_with("rejected") || why.starts_with("soft-failed") =>
            {
                Failure::Verdict(RoomError::Forbidden(why))
            }
            // The peer's state could not be a state of this room.
            other => Failure::Invalid(other.to_string()),
        })
}

/// Fetch, verify and return every body named in `roots` -- and every auth
/// event those cite, transitively -- that this server lacks, from `peer`.
/// `skip` is the event the state is *for*, never part of it.
///
/// Bounded to [`MAX_GAP_EVENTS`] bodies and [`MAX_GAP_BYTES`]; past either
/// it fails closed. Each body is named by its own hash and signature-
/// checked; authorization is the caller's, through
/// [`crate::rooms::Rooms::retain_remote_auth`], which needs every auth
/// event in hand -- hence the walk.
///
/// # Errors
///
/// A [`Failure`]: the peer would not serve a body, a body failed
/// verification, or the walk outgrew its budget.
pub(super) async fn fetch_state(
    peers: &Peers<'_>,
    peer: &str,
    room_id: &str,
    version: &RoomVersionId,
    mut pending: BTreeSet<String>,
    skip: &str,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<BTreeMap<String, Value>, Failure> {
    pending.remove(skip);
    let mut fetched: BTreeMap<String, Value> = BTreeMap::new();
    let mut bytes = 0;
    loop {
        let mut wave = Vec::with_capacity(FETCH_CONCURRENCY);
        while wave.len() < FETCH_CONCURRENCY {
            let Some(id) = pending.pop_first() else {
                break;
            };
            if id == skip || fetched.contains_key(&id) {
                continue;
            }
            match peers.rooms.pdu(room_id, &id) {
                Ok(_) => {}
                Err(RoomError::MissingBody(_)) => wave.push(id),
                Err(error) => return Err(error.into()),
            }
        }
        if wave.is_empty() {
            break;
        }
        if fetched.len().saturating_add(wave.len()) > MAX_GAP_EVENTS {
            peers
                .metrics
                .record_fetched(FetchKind::GapState, count(fetched.len()));
            return Err(Failure::Budget(format!(
                "the state at the event needs more than {MAX_GAP_EVENTS} events this server lacks"
            )));
        }
        let mut requests = tokio::task::JoinSet::new();
        for id in wave {
            let federation = Arc::clone(peers.federation);
            let peer = peer.to_owned();
            requests.spawn(async move {
                let body = federation.remote_event(&peer, &id).await;
                (id, body)
            });
        }
        let mut bodies = Vec::with_capacity(FETCH_CONCURRENCY);
        while let Some(joined) = requests.join_next().await {
            let (id, body) =
                joined.map_err(|error| Failure::peer(format!("event fetch failed: {error}")))?;
            bodies.push((id, body.map_err(|error| Failure::from_peer(&error))?));
        }
        // Deterministic order for verification, whatever order they landed in.
        bodies.sort_by(|left, right| left.0.cmp(&right.0));
        for (id, body) in bodies {
            charge(&body, &mut bytes, MAX_GAP_BYTES)?;
            let verified = verify(peers, room_id, version, &body, Some(&id), keys)
                .await
                .map_err(|why| Failure::Invalid(format!("state event {id}: {why}")))?;
            if verified.id != id {
                return Err(Failure::Invalid(format!(
                    "state event {id} does not match the body served for it"
                )));
            }
            pending.extend(
                peers
                    .rooms
                    .missing_remote_dependencies(room_id, &verified.body)?
                    .1,
            );
            fetched.insert(id, verified.body);
        }
    }
    peers
        .metrics
        .record_fetched(FetchKind::GapState, count(fetched.len()));
    Ok(fetched)
}
