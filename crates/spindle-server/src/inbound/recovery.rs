//! Recover a pushed PDU's dependencies before the ordinary room receipt checks.
//! No room or store lock crosses an outbound request. Fetched bodies are
//! individually named and verified; the peer's response is not a verdict.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};

use crate::AppState;
use crate::federation::PeerKeys;

const MAX_RECOVERED_EVENTS: usize = 512;
const MAX_RECOVERED_BYTES: usize = 16 * 1024 * 1024;

struct VerifiedPdu {
    id: String,
    body: Value,
}

/// Gather precisely the signers the room version requires, including a
/// restricted join's authorizer and a v1/v2 event ID's server.
async fn verify(
    state: &AppState,
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
        if server == state.config.server.name {
            public_keys.insert(
                server.to_owned(),
                BTreeMap::from([(
                    state.key.key_id(),
                    ruma::serde::Base64::parse(state.key.public_key_base64())
                        .map_err(|error| error.to_string())?,
                )]),
            );
            continue;
        }
        if !keys.contains_key(server) {
            let fetched = state
                .federation
                .peer_keys(server)
                .await
                .map_err(|error| error.to_string())?;
            keys.insert(server.to_owned(), fetched);
        }
        public_keys.extend(keys[server].map_for(
            body["origin_server_ts"].as_u64(),
            rules.enforce_key_validity,
        ));
    }
    let body = match spindle_core::version::verify(&public_keys, &canonical, version)
        .map_err(|error| format!("signature: {error}"))?
    {
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

pub(super) async fn receive(
    state: &AppState,
    origin: &str,
    signer: &str,
    provided_keys: Option<&PeerKeys>,
    pdu: &Value,
) -> (String, Result<(), String>) {
    if pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .map(|(_, domain)| domain)
        != Some(signer)
    {
        return (
            "$foreign-sender".to_owned(),
            Err("the sender does not live on the origin".to_owned()),
        );
    }
    let Some(room_id) = pdu["room_id"].as_str() else {
        return ("$malformed".to_owned(), Err("no room_id".to_owned()));
    };
    let version = state
        .rooms
        .room_version(room_id)
        .unwrap_or_else(|_| super::room_version_of(state, pdu));
    let mut keys = HashMap::new();
    if let Some(provided) = provided_keys {
        keys.insert(signer.to_owned(), provided.clone());
    }
    let event = match verify(state, room_id, &version, pdu, None, &mut keys).await {
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
            return (id, Err(error));
        }
    };
    let first = state.rooms.receive_remote(room_id, &event.id, &event.body);
    let Err(error) = first else {
        return (event.id, Ok(()));
    };
    // A rejection is already a verdict. Recovery fills an absent dependency;
    // it must not reconsider a stored historical or native rejection.
    if !matches!(
        error,
        crate::rooms::RoomError::Append(_) | crate::rooms::RoomError::MissingBody(_)
    ) {
        return (event.id, Err(error.to_string()));
    }
    let missing = match state
        .rooms
        .missing_remote_dependencies(room_id, &event.body)
    {
        Ok(missing) if !missing.0.is_empty() || !missing.1.is_empty() => missing,
        _ => return (event.id, Err(error.to_string())),
    };
    // Recovery asks a participating peer about a room we hold; no unsigned
    // third-party name can trigger an arbitrary dependency fetch.
    if !state.rooms.server_in_room(room_id, origin).unwrap_or(false) {
        return (event.id, Err(error.to_string()));
    }
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        recover(state, origin, room_id, &version, &event, missing, &mut keys),
    )
    .await;
    let outcome = match result {
        Ok(Ok(())) => state
            .rooms
            .receive_remote(room_id, &event.id, &event.body)
            .map_err(|error| error.to_string()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("dependency recovery timed out".to_owned()),
    };
    (event.id, outcome)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one verified event and its bounded predecessor recovery"
)]
async fn recover(
    state: &AppState,
    origin: &str,
    room_id: &str,
    version: &RoomVersionId,
    latest: &VerifiedPdu,
    missing: (Vec<String>, Vec<String>),
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<(), String> {
    let mut offered = BTreeMap::new();
    if !missing.0.is_empty() {
        let heads = state
            .rooms
            .remote_recovery_heads(room_id)
            .map_err(|error| error.to_string())?;
        let events = state
            .federation
            .remote_missing_events(
                origin,
                room_id,
                &heads,
                std::slice::from_ref(&latest.id),
                100,
            )
            .await
            .map_err(|error| error.to_string())?;
        for event in events {
            // Name the response before selecting the ancestors actually cited
            // by this event. Unrelated response events never reach storage.
            let CanonicalJsonValue::Object(canonical) =
                CanonicalJsonValue::try_from(event.clone()).map_err(|error| error.to_string())?
            else {
                return Err("missing-events response contains a non-object".to_owned());
            };
            let parsed = spindle_core::Pdu::from_remote(version.clone(), canonical)
                .map_err(|error| format!("missing event: {error:?}"))?;
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
            return Err("dependency recovery event budget exceeded".to_owned());
        }
        let body = match offered.remove(&id) {
            Some(body) => body,
            None => state
                .federation
                .remote_event(origin, &id)
                .await
                .map_err(|error| error.to_string())?,
        };
        charge(&body, &mut bytes)?;
        let event = verify(state, room_id, version, &body, Some(&id), keys).await?;
        if event.id != id {
            return Err("recovered predecessor ID does not match the requested event".to_owned());
        }
        let (parents, _) = state
            .rooms
            .missing_remote_dependencies(room_id, &event.body)
            .map_err(|error| error.to_string())?;
        pending.extend(parents);
        predecessors.insert(id, event.body);
    }
    recover_auth(
        state,
        origin,
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
                .missing_remote_dependencies(room_id, body)
                .map_err(|error| error.to_string())?
                .0
                .is_empty()
            {
                ready.push(id.clone());
            }
        }
        if ready.is_empty() {
            return Err("recovered predecessor graph is incomplete or cyclic".to_owned());
        }
        for id in ready {
            let body = predecessors
                .remove(&id)
                .expect("ready predecessor is pending");
            if let Err(error) = state.rooms.receive_remote(room_id, &id, &body)
                && predecessor_missing(state, room_id, &id)?
            {
                return Err(format!("recovered predecessor refused: {error}"));
            }
        }
    }
    Ok(())
}

fn predecessor_missing(state: &AppState, room_id: &str, id: &str) -> Result<bool, String> {
    state
        .rooms
        .missing_remote_dependencies(room_id, &json!({"prev_events":[id]}))
        .map(|missing| !missing.0.is_empty())
        .map_err(|error| error.to_string())
}

#[allow(
    clippy::too_many_arguments,
    reason = "auth closure shares the verified event's recovery context"
)]
async fn recover_auth(
    state: &AppState,
    origin: &str,
    room_id: &str,
    version: &RoomVersionId,
    latest: &VerifiedPdu,
    predecessors: &BTreeMap<String, Value>,
    bytes: &mut usize,
    keys: &mut HashMap<String, PeerKeys>,
) -> Result<(), String> {
    let mut pending = BTreeSet::new();
    for body in predecessors.values().chain(std::iter::once(&latest.body)) {
        pending.extend(
            state
                .rooms
                .missing_remote_dependencies(room_id, body)
                .map_err(|error| error.to_string())?
                .1,
        );
    }
    let mut auth = BTreeMap::new();
    while let Some(id) = pending.pop_first() {
        if auth.contains_key(&id) {
            continue;
        }
        match state.rooms.pdu(room_id, &id) {
            Ok(_) => continue,
            Err(crate::rooms::RoomError::MissingBody(_)) => {}
            Err(error) => return Err(error.to_string()),
        }
        if auth.len() + predecessors.len() >= MAX_RECOVERED_EVENTS {
            return Err("dependency recovery event budget exceeded".to_owned());
        }
        let body = match predecessors.get(&id) {
            Some(body) => body.clone(),
            None => state
                .federation
                .remote_event(origin, &id)
                .await
                .map_err(|error| error.to_string())?,
        };
        charge(&body, bytes)?;
        let event = verify(state, room_id, version, &body, Some(&id), keys).await?;
        if event.id != id {
            return Err("recovered auth ID does not match the requested event".to_owned());
        }
        pending.extend(
            state
                .rooms
                .missing_remote_dependencies(room_id, &event.body)
                .map_err(|error| error.to_string())?
                .1,
        );
        auth.insert(id, event.body);
    }
    if !auth.is_empty() {
        state
            .rooms
            .retain_remote_auth(room_id, &auth.into_iter().collect::<Vec<_>>())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn charge(body: &Value, bytes: &mut usize) -> Result<(), String> {
    let length = serde_json::to_vec(body)
        .map_err(|error| error.to_string())?
        .len();
    if length > MAX_RECOVERED_BYTES.saturating_sub(*bytes) {
        return Err("dependency recovery byte budget exceeded".to_owned());
    }
    *bytes += length;
    Ok(())
}
