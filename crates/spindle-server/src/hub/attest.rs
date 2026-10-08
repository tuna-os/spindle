//! Attestations, checkpoints and proofs (#22, SPEC sections 12.6, 13.3).
//!
//! The hub signs, for every entry it sequences in an epoch, `{room_id, hub,
//! epoch, li, event_id, chain}` -- `chain` being the value the log computed
//! when the entry was appended (SPEC section 5.3), so nothing is hashed
//! twice -- and every `checkpoint_interval` entries a checkpoint, the same
//! fields plus the state root after the entry. Both travel to hub-mode
//! servers only, in one EDU.
//!
//! A participant keeps them by `(room, epoch, li)` and checks each against
//! its neighbours: consecutive positions must chain. Two signed statements
//! that cannot both be true are kept together as a proof any holder of the
//! hub's public key can check. A participant with nothing for the current
//! epoch first asks the hub for a fresh checkpoint and anchors on it, so it
//! can check every attestation after it without replaying the room.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use ruma::CanonicalJsonValue;
use serde_json::{Value, json};
use spindle_core::keys::Keyspace;
use spindle_core::{ChainHash, EventId};

use super::epoch::{Designation, designation};
use super::metrics::Counter;
use super::{ATTESTATION_EDU, UNSTABLE_PREFIX, is_capable, lock};
use crate::AppState;
use crate::errors::MatrixError;
use crate::federation::PeerKeys;
use crate::metrics::EduResult;
use crate::rooms::ChainEntry;

/// Attestations per EDU, and per pass of the hub's attestation loop.
const ATTESTATION_BATCH: usize = 100;

/// How far back a hub with no memory of a room's attestations starts: a
/// restart re-signs at most this many, and Ed25519 signatures are
/// deterministic, so a participant reads them as duplicates.
const ATTESTATION_BACKLOG: i64 = 100;

/// What a proof says it is.
pub const PROOF_KIND: &str = "org.spindle.msc3995.equivocation";
/// What a refused epoch's proof says it is.
pub const TRUNCATION_KIND: &str = "org.spindle.msc3995.truncation";

/// Unpadded standard base64, the encoding Matrix uses for hashes.
pub(crate) fn encode(bytes: &[u8; 32]) -> String {
    let encoded: ruma::serde::Base64 = ruma::serde::Base64::new(bytes.to_vec());
    encoded.encode()
}

fn decode(value: &Value) -> Option<[u8; 32]> {
    let decoded: ruma::serde::Base64 = ruma::serde::Base64::parse(value.as_str()?).ok()?;
    decoded.as_bytes().try_into().ok()
}

/// The fields of an attestation or checkpoint a server checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parsed {
    pub room_id: String,
    pub hub: String,
    pub epoch: u64,
    pub li: i64,
    pub event_id: String,
    pub chain: [u8; 32],
    /// Present on a checkpoint.
    pub state_root: Option<[u8; 32]>,
}

impl Parsed {
    pub(crate) fn read(value: &Value) -> Option<Self> {
        Some(Self {
            room_id: value["room_id"].as_str()?.to_owned(),
            hub: value["hub"].as_str()?.to_owned(),
            epoch: value["epoch"].as_u64()?,
            li: value["li"].as_i64()?,
            event_id: value["event_id"].as_str()?.to_owned(),
            chain: decode(&value["chain"])?,
            state_root: decode(&value["state_root"]),
        })
    }
}

/// Whether the attested `chain` after `event_id` follows from `earlier`:
/// `chain = BLAKE3(domain || earlier || event_id)`. Public so a proof can
/// be checked by anyone holding it.
#[must_use]
pub fn chain_step_holds(earlier: &str, event_id: &str, chain: &str) -> bool {
    match (decode(&json!(earlier)), decode(&json!(chain))) {
        (Some(earlier), Some(chain)) => {
            ChainHash::from_bytes(earlier).extend(&EventId::new(event_id))
                == ChainHash::from_bytes(chain)
        }
        _ => false,
    }
}

fn chains(earlier: &Parsed, later: &Parsed) -> bool {
    ChainHash::from_bytes(earlier.chain).extend(&EventId::new(later.event_id.as_str()))
        == ChainHash::from_bytes(later.chain)
}

/// Sign `entry` as an attestation, or as a checkpoint with its state root.
pub(crate) fn sign(
    state: &AppState,
    room_id: &str,
    epoch: u64,
    entry: &ChainEntry,
    checkpoint: bool,
) -> Result<Value, MatrixError> {
    let mut body = json!({
        "room_id": room_id,
        "hub": state.config.server.name,
        "epoch": epoch,
        "li": entry.li,
        "event_id": entry.event_id,
        "chain": encode(&entry.chain),
    });
    if checkpoint {
        body["state_root"] = json!(encode(&entry.state_root));
    }
    let Ok(CanonicalJsonValue::Object(mut object)) = CanonicalJsonValue::try_from(body) else {
        return Err(MatrixError::internal(
            "an attestation is not canonical JSON",
        ));
    };
    ruma::signatures::sign_json(&state.config.server.name, state.key.pair(), &mut object)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    serde_json::to_value(&object).map_err(|error| MatrixError::internal(&error.to_string()))
}

pub(crate) fn verifies(keys: &PeerKeys, value: &Value) -> bool {
    let Ok(CanonicalJsonValue::Object(object)) = CanonicalJsonValue::try_from(value.clone()) else {
        return false;
    };
    ruma::signatures::verify_json(&keys.map_for(None, false), &object).is_ok()
}

pub(crate) fn spawn_attestations(state: &AppState, room_id: &str) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let state = state.clone();
    let room_id = room_id.to_owned();
    tokio::spawn(async move { send_attestations(&state, &room_id).await });
}

/// One pass of the hub's attestation stream for a room: everything
/// sequenced since the last pass, in this epoch, to every hub-mode server.
///
/// An epoch's stream starts at its own `m.room.hub` event: what came
/// before was ordered by the outgoing hub, and this one does not vouch for
/// that order. Positions are claimed under a lock before signing, so two
/// passes racing never sign the same range twice, though they may queue
/// out of order -- which a participant tolerates, checking each against
/// both neighbours. Entries from servers that do not speak hub mode are
/// attested too: the hub vouches for its order, whoever wrote the event.
pub(crate) async fn send_attestations(state: &AppState, room_id: &str) {
    let Some(current) = designation(state, room_id).await else {
        return;
    };
    if current.server != state.config.server.name {
        return;
    }
    let mut audience = Vec::new();
    for destination in state.rooms.remote_domains(room_id).unwrap_or_default() {
        if is_capable(state, &destination).await {
            audience.push(destination);
        }
    }
    let interval = i64::try_from(state.config.federation.hub.checkpoint_interval).unwrap_or(1);
    let key = (room_id.to_owned(), current.epoch);
    loop {
        let entries = {
            let mut attested = lock(&state.hub.attested);
            let start = attested.get(&key).copied().unwrap_or_else(|| {
                let last = state.rooms.hub_last_position(room_id).unwrap_or(0);
                let opened = state
                    .rooms
                    .hub_position(room_id, &current.event_id)
                    .ok()
                    .flatten()
                    .map_or(i64::MIN, |li| li - 1);
                opened.max(last.saturating_sub(ATTESTATION_BACKLOG))
            });
            let Ok(mut entries) = state
                .rooms
                .hub_chain_since(room_id, start, ATTESTATION_BATCH)
            else {
                return;
            };
            // The epoch ends where the next `m.room.hub` was appended: read
            // after the entries, so one appended before them is seen here
            // and one appended after them is not among them.
            if let Ok(Some(now)) = state.rooms.hub_event(room_id)
                && now["event_id"].as_str() != Some(current.event_id.as_str())
            {
                let next = now["event_id"]
                    .as_str()
                    .and_then(|id| state.rooms.hub_position(room_id, id).ok().flatten());
                entries.retain(|entry| next.is_some_and(|next| entry.li < next));
                if entries.is_empty() {
                    return;
                }
            }
            if let Some(entry) = entries.last() {
                attested.insert(key.clone(), entry.li);
            }
            entries
        };
        if entries.is_empty() {
            return;
        }
        let attestations: Vec<Value> = entries
            .iter()
            .filter_map(|entry| sign(state, room_id, current.epoch, entry, false).ok())
            .collect();
        let checkpoints: Vec<Value> = entries
            .iter()
            .filter(|entry| entry.li.rem_euclid(interval) == 0)
            .filter_map(|entry| sign(state, room_id, current.epoch, entry, true).ok())
            .collect();
        for _ in &checkpoints {
            state.metrics.hub().bump(Counter::CheckpointSigned);
        }
        let edu = json!({
            "edu_type": ATTESTATION_EDU,
            "content": {
                "room_id": room_id,
                "attestations": attestations,
                "checkpoints": checkpoints,
            },
        });
        for destination in &audience {
            state.federation.queue_edu(destination, edu.clone());
        }
        if entries.len() < ATTESTATION_BATCH {
            return;
        }
    }
}

/// Whether an inbound EDU is hub mode's, and if so apply and count it.
pub(crate) async fn takes_edu(state: &AppState, origin: &str, edu: &Value) -> bool {
    if !state.config.federation.hub.enabled || edu["edu_type"].as_str() != Some(ATTESTATION_EDU) {
        return false;
    }
    let result = apply_edu(state, origin, &edu["content"]).await;
    state
        .metrics
        .record_edu_received(crate::metrics::EduType::Other, result);
    true
}

/// Apply an inbound attestation EDU. Each attestation must be from the
/// hub of its own epoch, which must be the EDU's origin, and verify
/// against that hub's key.
async fn apply_edu(state: &AppState, origin: &str, content: &Value) -> EduResult {
    let Some(room_id) = content["room_id"].as_str() else {
        return EduResult::Malformed;
    };
    let Some(current) = designation(state, room_id).await else {
        return EduResult::Ignored;
    };
    if !current.history.iter().any(|hub| hub == origin) {
        return EduResult::Ignored;
    }
    let take = |field: &str| -> Vec<Value> {
        content[field]
            .as_array()
            .into_iter()
            .flatten()
            .take(ATTESTATION_BATCH)
            .cloned()
            .collect()
    };
    let checkpoints = take("checkpoints");
    let attestations = take("attestations");
    if record_from(
        state,
        origin,
        room_id,
        &current,
        &checkpoints,
        &attestations,
    )
    .await
        > 0
    {
        EduResult::Accepted
    } else {
        EduResult::Ignored
    }
}

/// Verify and keep checkpoints, then attestations, from `hub`; how many
/// verified. A server holding nothing yet for the hub's current epoch
/// anchors on a fresh checkpoint from it first.
pub(crate) async fn record_from(
    state: &AppState,
    hub: &str,
    room_id: &str,
    current: &Designation,
    checkpoints: &[Value],
    attestations: &[Value],
) -> usize {
    let keys = match state.federation.peer_keys(hub).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::debug!("cannot fetch {hub} keys to check its attestations: {error}");
            return 0;
        }
    };
    let mut checkpoints = checkpoints.to_vec();
    if current.server == hub
        && highest(state, room_id, current.epoch).is_none()
        && lock(&state.hub.anchored).insert((room_id.to_owned(), current.epoch))
        && let Some(anchor) = fetch_checkpoint(state, hub, room_id).await
    {
        checkpoints.insert(0, anchor);
    }
    let mut verified = 0;
    for value in checkpoints.iter().chain(attestations) {
        let checkpoint = value.get("state_root").is_some();
        match record(state, &keys, current, room_id, value, checkpoint) {
            Recorded::Invalid => state.metrics.hub().bump(if checkpoint {
                Counter::CheckpointRejected
            } else {
                Counter::AttestationRejected
            }),
            Recorded::Duplicate => {
                verified += 1;
                if !checkpoint {
                    state.metrics.hub().bump(Counter::AttestationDuplicate);
                }
            }
            Recorded::New | Recorded::Equivocation => {
                verified += 1;
                state.metrics.hub().bump(if checkpoint {
                    Counter::CheckpointVerified
                } else {
                    Counter::AttestationAccepted
                });
            }
        }
    }
    verified
}

/// Ask `hub` for a checkpoint of its head now.
async fn fetch_checkpoint(state: &AppState, hub: &str, room_id: &str) -> Option<Value> {
    let uri = format!(
        "{UNSTABLE_PREFIX}/checkpoint/{}",
        crate::federation::path_segment(room_id)
    );
    let answer = tokio::time::timeout(
        Duration::from_millis(state.config.federation.hub.submit_timeout_ms),
        state.federation.hub_request(hub, &uri, None),
    )
    .await
    .ok()?
    .ok()?;
    answer["checkpoint"]
        .is_object()
        .then(|| answer["checkpoint"].clone())
}

/// What became of one attestation or checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    New,
    Duplicate,
    /// Kept, or refused, with a proof recorded against the hub.
    Equivocation,
    Invalid,
}

fn read_row(
    state: &AppState,
    keyspace: Keyspace,
    room_id: &str,
    epoch: u64,
    li: i64,
) -> Option<Value> {
    spindle_store::ReadView::get(
        state.store.as_ref(),
        &spindle_core::keys::hub_row(keyspace, room_id, epoch, li),
    )
    .ok()
    .flatten()
    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn write_row(
    state: &AppState,
    keyspace: Keyspace,
    room_id: &str,
    epoch: u64,
    li: i64,
    value: &Value,
) {
    if let Err(error) = spindle_store::Store::put(
        state.store.as_ref(),
        &spindle_core::keys::hub_row(keyspace, room_id, epoch, li),
        value.to_string().as_bytes(),
    ) {
        tracing::warn!("cannot store a hub record: {error}");
    }
}

/// Record a proof, once per position: two signed statements by `hub` that
/// cannot both be true.
fn prove(state: &AppState, room_id: &str, epoch: u64, li: i64, reason: &str, pair: [&Value; 2]) {
    if read_row(state, Keyspace::HubEquivocation, room_id, epoch, li).is_some() {
        return;
    }
    let hub = pair[0]["hub"].clone();
    tracing::warn!(
        room = room_id,
        epoch,
        li,
        reason,
        "the hub equivocated; proof recorded"
    );
    let proof = json!({
        "kind": PROOF_KIND,
        "reason": reason,
        "room_id": room_id,
        "hub": hub,
        "epoch": epoch,
        "li": li,
        "attestations": pair,
    });
    write_row(state, Keyspace::HubEquivocation, room_id, epoch, li, &proof);
    state.metrics.hub().bump(if reason == "broken_chain" {
        Counter::ProofBrokenChain
    } else {
        Counter::ProofConflictingEntries
    });
}

/// Record that the epoch opened by `claim` drops an entry `outgoing`'s hub
/// attested: the claim, signed by its sender's server, and the attestation
/// it contradicts, signed by the outgoing hub. Kept once per position.
pub(crate) fn prove_truncation(
    state: &AppState,
    room_id: &str,
    outgoing: &Designation,
    claim: &Value,
    attestation: &Value,
) {
    let Some(held) = Parsed::read(attestation) else {
        return;
    };
    if read_row(
        state,
        Keyspace::HubEquivocation,
        room_id,
        outgoing.epoch,
        held.li,
    )
    .is_some()
    {
        return;
    }
    tracing::warn!(
        room = room_id,
        epoch = outgoing.epoch + 1,
        claimed_by = claim["sender"].as_str().unwrap_or("?"),
        attested = held.li,
        "refused a new hub epoch that drops an attested entry; proof recorded"
    );
    let mut claim = claim.clone();
    if let Some(object) = claim.as_object_mut() {
        object.remove("unsigned");
    }
    let proof = json!({
        "kind": TRUNCATION_KIND,
        "room_id": room_id,
        "hub": outgoing.server,
        "epoch": outgoing.epoch,
        "li": held.li,
        "claim": claim,
        "attestation": attestation,
    });
    write_row(
        state,
        Keyspace::HubEquivocation,
        room_id,
        outgoing.epoch,
        held.li,
        &proof,
    );
    state.metrics.hub().bump(Counter::ProofTruncation);
}

/// Check one attestation or checkpoint and keep it.
///
/// A second, different statement for a position already held is never
/// stored over the first: the first is what this server was told, and the
/// pair is the proof. One that does not chain from its predecessor, or to
/// its successor, is kept (it is what the hub signed) and the broken step
/// recorded as a proof. A checkpoint is also held against the attestation
/// at its position, and its state root against this server's own.
fn record(
    state: &AppState,
    keys: &PeerKeys,
    current: &Designation,
    room_id: &str,
    value: &Value,
    checkpoint: bool,
) -> Recorded {
    let Some(parsed) = Parsed::read(value) else {
        return Recorded::Invalid;
    };
    if parsed.room_id != room_id
        || current.hub_of(parsed.epoch) != Some(parsed.hub.as_str())
        || checkpoint != parsed.state_root.is_some()
        || !verifies(keys, value)
    {
        return Recorded::Invalid;
    }
    let (epoch, li) = (parsed.epoch, parsed.li);
    let own = if checkpoint {
        Keyspace::HubCheckpoint
    } else {
        Keyspace::HubAttestation
    };
    let same_place =
        |other: &Parsed| other.event_id == parsed.event_id && other.chain == parsed.chain;
    if let Some(existing) = read_row(state, own, room_id, epoch, li) {
        if Parsed::read(&existing)
            .is_some_and(|held| same_place(&held) && held.state_root == parsed.state_root)
        {
            return Recorded::Duplicate;
        }
        prove(
            state,
            room_id,
            epoch,
            li,
            "conflicting_entries",
            [&existing, value],
        );
        return Recorded::Equivocation;
    }
    let mut equivocated = false;
    // A checkpoint and an attestation at one position must agree.
    let other = if checkpoint {
        Keyspace::HubAttestation
    } else {
        Keyspace::HubCheckpoint
    };
    if let Some(twin) = read_row(state, other, room_id, epoch, li)
        && Parsed::read(&twin).is_some_and(|held| !same_place(&held))
    {
        prove(
            state,
            room_id,
            epoch,
            li,
            "conflicting_entries",
            [&twin, value],
        );
        equivocated = true;
    }
    equivocated |= !chains_with_neighbours(state, room_id, &parsed, value);
    write_row(state, own, room_id, epoch, li, value);
    if checkpoint {
        compare_state_root(state, room_id, &parsed);
    } else {
        note_highest(state, room_id, epoch, value);
    }
    if equivocated {
        Recorded::Equivocation
    } else {
        Recorded::New
    }
}

/// Whether `value` chains from the statement before it and to the one
/// after it, where this server holds them; each broken step is proven.
fn chains_with_neighbours(state: &AppState, room_id: &str, parsed: &Parsed, value: &Value) -> bool {
    let (epoch, li) = (parsed.epoch, parsed.li);
    let neighbour = |li: i64| {
        read_row(state, Keyspace::HubAttestation, room_id, epoch, li)
            .or_else(|| read_row(state, Keyspace::HubCheckpoint, room_id, epoch, li))
    };
    let mut holds = true;
    if let Some(previous) = neighbour(li - 1)
        && let Some(earlier) = Parsed::read(&previous)
        && !chains(&earlier, parsed)
    {
        prove(
            state,
            room_id,
            epoch,
            li,
            "broken_chain",
            [&previous, value],
        );
        holds = false;
    }
    if let Some(next) = neighbour(li + 1)
        && let Some(later) = Parsed::read(&next)
        && !chains(parsed, &later)
    {
        prove(
            state,
            room_id,
            epoch,
            li + 1,
            "broken_chain",
            [value, &next],
        );
        holds = false;
    }
    holds
}

/// The state root is the one thing a checkpoint adds: where this server
/// sequenced the same entry itself, it computed the same state, or the two
/// disagree about the room.
fn compare_state_root(state: &AppState, room_id: &str, parsed: &Parsed) {
    if let (Some(root), Ok(Some(mine))) = (
        parsed.state_root,
        state.rooms.hub_entry(room_id, None, Some(&parsed.event_id)),
    ) {
        if mine.state_root == root {
            state.metrics.hub().bump(Counter::CheckpointStateMatched);
        } else {
            tracing::warn!(
                room = room_id,
                li = parsed.li,
                "a hub checkpoint's state root differs from ours"
            );
            state.metrics.hub().bump(Counter::CheckpointStateMismatch);
        }
    }
}

/// Keep the highest attestation per epoch in memory, seeded from the
/// store first so a restart does not forget a higher one.
fn note_highest(state: &AppState, room_id: &str, epoch: u64, value: &Value) {
    let _ = highest(state, room_id, epoch);
    let mut highest = lock(&state.hub.highest);
    let known = highest
        .entry((room_id.to_owned(), epoch))
        .or_insert_with(|| value.clone());
    if known["li"].as_i64().unwrap_or(i64::MIN) < value["li"].as_i64().unwrap_or(i64::MIN) {
        *known = value.clone();
    }
}

/// The highest attestation this server holds for `(room, epoch)`.
pub(crate) fn highest(state: &AppState, room_id: &str, epoch: u64) -> Option<Value> {
    let key = (room_id.to_owned(), epoch);
    if let Some(known) = lock(&state.hub.highest).get(&key) {
        return Some(known.clone());
    }
    let prefix = spindle_core::keys::hub_epoch_prefix(Keyspace::HubAttestation, room_id, epoch);
    let found = spindle_store::ReadView::scan_prefix(state.store.as_ref(), &prefix)
        .ok()?
        .into_iter()
        .filter_map(|(_, value)| serde_json::from_slice::<Value>(&value).ok())
        .max_by_key(|value| value["li"].as_i64().unwrap_or(i64::MIN))?;
    lock(&state.hub.highest).insert(key, found.clone());
    Some(found)
}

/// The highest entry of `outgoing`'s epoch this server can prove was
/// attested: the attestation it holds, or, when it was that epoch's hub,
/// its own attestation of the last entry it attested.
pub(crate) fn highest_proven(
    state: &AppState,
    room_id: &str,
    outgoing: &Designation,
) -> Option<Value> {
    if outgoing.server == state.config.server.name {
        let last = lock(&state.hub.attested)
            .get(&(room_id.to_owned(), outgoing.epoch))
            .copied()?;
        let entry = state.rooms.hub_entry(room_id, Some(last), None).ok()??;
        return sign(state, room_id, outgoing.epoch, &entry, false).ok();
    }
    highest(state, room_id, outgoing.epoch)
}

#[derive(serde::Deserialize)]
pub(crate) struct EpochQuery {
    epoch: u64,
}

/// `GET .../org.spindle.msc3995/attested/{roomId}?epoch=N`: the highest
/// attestation of epoch `N` this server can show. Asked by a backup
/// claiming the next epoch, so it starts from what anyone in the room
/// heard, not from what it heard itself.
pub(crate) async fn attested(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<EpochQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    crate::inbound::federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let Some(current) = designation(&state, &room_id).await else {
        return Ok(Json(json!({ "attestation": null })));
    };
    let Some(server) = current.hub_of(query.epoch) else {
        return Ok(Json(json!({ "attestation": null })));
    };
    let outgoing = Designation {
        server: server.to_owned(),
        epoch: query.epoch,
        ..current.clone()
    };
    Ok(Json(json!({
        "attestation": highest_proven(&state, &room_id, &outgoing),
    })))
}

/// `GET .../org.spindle.msc3995/checkpoint/{roomId}`: a checkpoint of the
/// hub's head, signed now. What a participant with no history in the
/// current epoch anchors on.
pub(crate) async fn checkpoint(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    crate::inbound::federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let current = designation(&state, &room_id)
        .await
        .filter(|current| current.server == state.config.server.name)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::FORBIDDEN,
                super::NOT_HUB_ERRCODE,
                format!("{} does not hub {room_id}", state.config.server.name),
            )
        })?;
    let entry = state
        .rooms
        .hub_entry(&room_id, None, None)
        .map_err(crate::routes::room_error)?
        .ok_or_else(|| {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "nothing sequenced")
        })?;
    let signed = sign(&state, &room_id, current.epoch, &entry, true)?;
    state.metrics.hub().bump(Counter::CheckpointSigned);
    Ok(Json(json!({ "checkpoint": signed })))
}

fn scan(store: &spindle_store::FjallStore, keyspace: Keyspace, room_id: &str) -> Vec<Value> {
    let prefix = spindle_core::keys::room_prefix(keyspace, room_id);
    spindle_store::ReadView::scan_prefix(store, &prefix)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, value)| serde_json::from_slice(&value).ok())
        .collect()
}

/// Every attestation this server holds for `room_id`, by epoch then
/// position.
#[must_use]
pub fn attestations(store: &spindle_store::FjallStore, room_id: &str) -> Vec<Value> {
    scan(store, Keyspace::HubAttestation, room_id)
}

/// Every checkpoint this server holds for `room_id`, by epoch then
/// position.
#[must_use]
pub fn checkpoints(store: &spindle_store::FjallStore, room_id: &str) -> Vec<Value> {
    scan(store, Keyspace::HubCheckpoint, room_id)
}

/// Every proof this server holds against a hub of `room_id`.
#[must_use]
pub fn proofs(store: &spindle_store::FjallStore, room_id: &str) -> Vec<Value> {
    scan(store, Keyspace::HubEquivocation, room_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_step_holds_only_in_order() {
        let first = ChainHash::seed().extend(&EventId::new("$a"));
        let second = first.extend(&EventId::new("$b"));
        let b64 = |chain: ChainHash| encode(chain.as_bytes());
        assert!(chain_step_holds(&b64(first), "$b", &b64(second)));
        // The chain commits to order, not membership.
        assert!(!chain_step_holds(&b64(first), "$c", &b64(second)));
        assert!(!chain_step_holds(&b64(second), "$b", &b64(first)));
        assert!(!chain_step_holds("not base64!", "$b", &b64(second)));
    }

    #[test]
    fn an_attestation_parses_and_a_checkpoint_carries_its_state_root() {
        let chain = encode(ChainHash::seed().as_bytes());
        let attestation = json!({
            "room_id": "!r:hub", "hub": "hub", "epoch": 2, "li": 7,
            "event_id": "$e", "chain": chain,
        });
        let parsed = Parsed::read(&attestation).expect("parses");
        assert_eq!(
            (parsed.epoch, parsed.li, parsed.event_id.as_str()),
            (2, 7, "$e")
        );
        assert!(parsed.state_root.is_none());
        let mut checkpoint = attestation.clone();
        checkpoint["state_root"] = json!(chain);
        assert!(Parsed::read(&checkpoint).unwrap().state_root.is_some());
        assert!(Parsed::read(&json!({ "li": 1 })).is_none());
    }
}
