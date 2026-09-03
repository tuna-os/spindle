//! The server-to-server protocol as it arrives, and the membership
//! handshakes this server walks with a resident: what a peer's PDU has to
//! satisfy to be accepted, how a refusal is reported, how a `make_join` or
//! `make_leave` template is finished and signed, how a resident's
//! signatures are taken on, and which servers are asked to broker a join.
//!
//! It sat in the route table (#309), so every claim about it was proven
//! through a socket -- a real peer, a key pair, a served key document -- to
//! assert things one function call deep. The policy functions at the top
//! take no HTTP type; the handlers below them take the unwrapped request
//! (state, headers, path parts, the raw body) and `routes.rs` keeps only the
//! axum extractor shells, so the route table stays the one list the
//! dashboard and `surface.rs` check against. The outbound client
//! (`federation.rs`) is the other half of the same protocol.

use std::collections::HashMap;

use axum::Json;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;
use crate::routes::{MAX_TXN_ID_LEN, record_invite, room_error};

/// Say that a peer's event was refused, and name what it was refused over.
///
/// Otherwise this is silent. The transaction still answers 200 -- one bad
/// event must not poison a batch of fifty -- and the rejection lives only
/// in the per-event result the sending server reads and usually discards.
/// So the moment two servers start disagreeing about a room is the one
/// moment neither one's logs mention, which is exactly backwards.
///
/// The two user IDs are here because they are the only ones a signature
/// check parses, so they are the only ones "could not parse user ID" can
/// be about -- and without them that sentence has no subject.
pub(crate) fn report_refused_pdu(origin: &str, event_id: &str, pdu: &Value, reason: &str) {
    tracing::warn!(
        origin = %origin,
        room_id = pdu["room_id"].as_str().unwrap_or("?"),
        event_id = %event_id,
        event_type = pdu["type"].as_str().unwrap_or("?"),
        sender = pdu["sender"].as_str().unwrap_or("?"),
        state_key = pdu["state_key"].as_str().unwrap_or("-"),
        authorised_via = pdu["content"]["join_authorised_via_users_server"]
            .as_str()
            .unwrap_or("-"),
        "refused a PDU from a peer: {reason}"
    );
}

///
/// `signer` is the server whose `keys` these are, and the sender has to live
/// there: the transaction's origin for its own users' events, or, for a
/// membership event the origin relays on behalf of a user elsewhere (a join,
/// knock or leave it brokered), that user's own server -- see
/// [`relayed_membership_signer`].
pub(crate) fn receive_one_pdu(
    state: &AppState,
    signer: &str,
    keys: Option<&crate::federation::PeerKeys>,
    pdu: &Value,
    delivery: Delivery,
) -> (String, Result<(), String>) {
    use ruma::CanonicalJsonValue;

    // The same acceptance either way; only who fans the event out differs.
    let receive = |room_id: &str, event_id: &str, json: &Value| match delivery {
        Delivery::Transaction => state.rooms.receive_remote(room_id, event_id, json),
        Delivery::Brokered => state.rooms.receive_brokered(room_id, event_id, json),
    };

    let Ok(CanonicalJsonValue::Object(canonical)) = CanonicalJsonValue::try_from(pdu.clone())
    else {
        return (
            "$malformed".to_owned(),
            Err("not canonicalizable".to_owned()),
        );
    };

    // The sender must live on the signer: a transaction is a server
    // speaking for its own users, and accepting someone else's would let
    // any peer forge any server's events into our rooms. The signature
    // check below is against the signer's keys, so this is what ties the
    // event to the server that can answer for it.
    let sender_domain = pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .map(|(_, domain)| domain);
    if sender_domain != Some(signer) {
        return (
            "$foreign-sender".to_owned(),
            Err("the sender does not live on the origin".to_owned()),
        );
    }

    let pdu_parsed = match spindle_core::Pdu::from_remote(
        ruma::RoomVersionId::try_from(crate::rooms::ROOM_VERSION)
            .expect("the supported room version parses"),
        canonical.clone(),
    ) {
        Ok(parsed) => parsed,
        Err(error) => return ("$malformed".to_owned(), Err(format!("{error:?}"))),
    };
    let event_id = pdu_parsed.event_id().as_str().to_owned();

    if let Some(keys) = keys {
        let rules = ruma::RoomVersionId::try_from(crate::rooms::ROOM_VERSION)
            .expect("the supported room version parses")
            .rules()
            .expect("the supported room version has rules");
        // Which of the peer's keys may answer for this event depends on
        // when the peer says it signed it: a key retired at `expired_ts`
        // verifies nothing claimed after that moment (#296).
        let key_map = keys.map_for(pdu["origin_server_ts"].as_u64());
        match ruma::signatures::verify_event(&key_map, &canonical, &rules) {
            Ok(ruma::signatures::Verified::All) => {}
            // The signature holds but the content hash does not: someone
            // altered the body after signing. The spec's answer is redact,
            // not drop — the event's *position* is authentic (its ID is the
            // reference hash over the redacted form, which is what peers
            // agree on), only its content is not, so the room keeps the
            // event and loses the tampering.
            Ok(ruma::signatures::Verified::Signatures) => {
                let redacted =
                    match ruma::canonical_json::redact(canonical.clone(), &rules.redaction, None) {
                        Ok(redacted) => redacted,
                        Err(error) => return (event_id, Err(format!("redaction: {error}"))),
                    };
                let json = serde_json::to_value(&redacted).unwrap_or(Value::Null);
                return match receive(
                    pdu["room_id"].as_str().unwrap_or_default(),
                    &event_id,
                    &json,
                ) {
                    Ok(()) => (event_id, Ok(())),
                    Err(error) => (event_id, Err(error.to_string())),
                };
            }
            Err(error) => return (event_id, Err(format!("signature: {error}"))),
        }
    }

    let Some(room_id) = pdu["room_id"].as_str() else {
        return (event_id, Err("no room_id".to_owned()));
    };
    match receive(room_id, &event_id, pdu) {
        Ok(()) => (event_id, Ok(())),
        Err(error) => (event_id, Err(error.to_string())),
    }
}

/// Judge and apply each PDU of one transaction, keyed by the event ID this
/// server computed for it.
///
/// A membership event the origin relays for a user elsewhere verifies
/// against that user's server, fetched once per server per batch. A fetch
/// that fails refuses that PDU alone, not the transaction: the origin's own
/// events are still its to deliver.
async fn receive_pdus(
    state: &AppState,
    origin: &str,
    key_map: Option<&crate::federation::PeerKeys>,
    pdus: &[Value],
) -> serde_json::Map<String, Value> {
    let mut relayed_keys: HashMap<String, Option<crate::federation::PeerKeys>> = HashMap::new();
    let mut results = serde_json::Map::new();
    for pdu in pdus {
        let relayed = relayed_membership_signer(origin, pdu);
        if let Some(domain) = &relayed
            && !relayed_keys.contains_key(domain)
        {
            let fetched = state.federation.peer_keys(domain).await;
            if let Err(error) = &fetched {
                tracing::debug!("cannot fetch {domain} keys for a relayed membership: {error}");
            }
            relayed_keys.insert(domain.clone(), fetched.ok());
        }
        let (event_id, outcome) = match &relayed {
            Some(domain) => match relayed_keys.get(domain).and_then(Option::as_ref) {
                Some(keys) => {
                    receive_one_pdu(state, domain, Some(keys), pdu, Delivery::Transaction)
                }
                None => (
                    "$unverifiable".to_owned(),
                    Err(format!(
                        "{domain}'s keys cannot be fetched to verify its user's membership"
                    )),
                ),
            },
            None => receive_one_pdu(state, origin, key_map, pdu, Delivery::Transaction),
        };
        let result = match outcome {
            Ok(()) => json!({}),
            Err(reason) => {
                report_refused_pdu(origin, &event_id, pdu, &reason);
                json!({ "error": reason })
            }
        };
        results.insert(event_id, result);
    }
    results
}

/// The server whose keys verify `pdu` when `origin` is relaying it: the
/// sender's own, for a membership event about the sender from a server
/// other than the origin. `None` when the origin speaks for itself.
///
/// This is the one shape a server legitimately sends on another's behalf.
/// A join, knock or leave brokered through `send_join`/`send_knock`/
/// `send_leave` is signed by the user's server, which is not in the room
/// and cannot deliver it, so the resident that admitted it does
/// (`Rooms::receive_brokered`) -- and every other server in the room then
/// receives a PDU whose sender is not on the transaction's origin. Refusing
/// those, as this server did, meant no remote user's federated join, knock
/// or leave ever reached a room this server was merely in. Nothing else is
/// relayed: a message claiming a sender elsewhere is still the forgery the
/// origin rule exists to refuse, and it is refused without a key fetch.
fn relayed_membership_signer(origin: &str, pdu: &Value) -> Option<String> {
    let sender = pdu["sender"].as_str()?;
    if pdu["type"].as_str() != Some("m.room.member") || pdu["state_key"].as_str() != Some(sender) {
        return None;
    }
    let (_, domain) = sender.split_once(':')?;
    (domain != origin).then(|| domain.to_owned())
}

/// How a PDU reached this server, which decides who fans it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// In a `/send` transaction from a server in the room: the origin fans
    /// its own events out, and forwarding it again would deliver everything
    /// twice.
    Transaction,
    /// Handed back through a `send_join`/`send_knock`/`send_leave`
    /// handshake by a server that is not in the room and cannot reach the
    /// servers that are, so this one does it for them
    /// (`Rooms::receive_brokered`).
    Brokered,
}

/// Finish a membership template: stamp a timestamp if the resident server
/// left it out, content-hash and sign it as ours, and name it by its
/// reference hash — exactly what the resident's `send_join`/`send_leave`
/// will verify.
///
/// `version` is the room's, as the resident named it in the `make_join` or
/// `make_leave` response — not this build's default. The two agree only
/// when the room happens to be the default version, and the hash the
/// resident checks is computed under the room's rules, so signing under
/// ours would produce an event nobody could name.
pub(crate) fn sign_membership_template(
    state: &AppState,
    template: &Value,
    version: &ruma::RoomVersionId,
) -> Result<(String, Value), String> {
    let Ok(ruma::CanonicalJsonValue::Object(mut canonical)) =
        ruma::CanonicalJsonValue::try_from(template.clone())
    else {
        return Err("the template does not canonicalize".to_owned());
    };
    if !canonical.contains_key("origin_server_ts") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        canonical.insert(
            "origin_server_ts".to_owned(),
            ruma::CanonicalJsonValue::Integer(ruma::Int::try_from(now).unwrap_or_default()),
        );
    }
    let rules = version
        .rules()
        .ok_or_else(|| "the room version rules are unavailable".to_owned())?;
    ruma::signatures::hash_and_sign_event(
        &state.config.server.name,
        state.key.pair(),
        &mut canonical,
        &rules.redaction,
    )
    .map_err(|error| format!("the template cannot be signed: {error}"))?;
    let hash = ruma::signatures::reference_hash(&canonical, &rules)
        .map_err(|error| format!("the signed event cannot be hashed: {error}"))?;
    let event = serde_json::to_value(&canonical)
        .map_err(|error| format!("the signed event cannot be serialized: {error}"))?;
    Ok((format!("${hash}"), event))
}

/// Add this server's signature to an event another server built.
///
/// Used where this server has something to attest that the builder could
/// not: that an invited user's server was told (`federation_invite`), or
/// that the authorising user of a restricted join really is a member here
/// who could have invited the joiner (`send_join`). In both cases the
/// signature is the attestation -- peers verify it, they do not take the
/// field's presence as proof.
///
/// Signing does not disturb the event ID: the reference hash is taken over
/// the redacted form, from which `signatures` is stripped.
pub(crate) fn countersign(
    state: &AppState,
    event: &Value,
    version: &ruma::RoomVersionId,
) -> Result<Value, MatrixError> {
    let Ok(ruma::CanonicalJsonValue::Object(mut canonical)) =
        ruma::CanonicalJsonValue::try_from(event.clone())
    else {
        return Err(MatrixError::bad_json(
            "the event does not canonicalize".to_owned(),
        ));
    };
    let rules = version
        .rules()
        .ok_or_else(|| MatrixError::internal("the room version rules are unavailable"))?;
    ruma::signatures::hash_and_sign_event(
        &state.config.server.name,
        state.key.pair(),
        &mut canonical,
        &rules.redaction,
    )
    .map_err(|error| MatrixError::internal(&format!("the event cannot be co-signed: {error}")))?;
    serde_json::to_value(&canonical).map_err(|error| MatrixError::internal(&error.to_string()))
}

/// Take on the signatures a resident server added to our own join event.
///
/// MSC3083's `send_join` response returns the event the resident accepted,
/// and for a restricted join that copy carries *its* signature as well as
/// ours -- the attestation that the authorising user really is a member
/// there. Keeping only our singly-signed copy would leave this server
/// relaying an event the next peer rejects.
///
/// Signatures are merged rather than the event adopted wholesale, and the
/// merge happens only if the two bodies are identical once signatures are
/// set aside. A resident that returns a *different* event is not to be
/// believed about it: what we signed is what we signed, and the event ID
/// everyone else computes is the hash of that.
pub(crate) fn merge_returned_signatures(join: &mut Value, returned: &Value) {
    let without_signatures = |event: &Value| -> Value {
        let mut copy = event.clone();
        if let Some(object) = copy.as_object_mut() {
            object.remove("signatures");
        }
        copy
    };
    if !returned.is_object() || without_signatures(returned) != without_signatures(join) {
        return;
    }
    let Some(theirs) = returned["signatures"].as_object().cloned() else {
        return;
    };
    if !join["signatures"].is_object() {
        join["signatures"] = json!({});
    }
    let Some(ours) = join["signatures"].as_object_mut() else {
        return;
    };
    for (server, keys) in theirs {
        // Never overwrite: our own entry is the one we can vouch for, and a
        // resident replacing it would be substituting a signature we did
        // not make for one we did.
        ours.entry(server).or_insert(keys);
    }
}

/// Every server worth asking to broker a join, most-specific first.
///
/// The client's own `server_name`/`via` hints lead; the domain in the room
/// ID follows; and a pending invite's origin closes the list — an invited
/// user accepting knows one server that certainly holds the room, the one
/// that sent the invite, and clients do not pass `via` when accepting.
/// This server itself is never a candidate: a room it held would not have
/// reached this path.
pub(crate) fn join_candidates(
    own_server: &str,
    room_id: &str,
    servers: &[String],
    invite_origin: Option<&str>,
) -> Vec<String> {
    let mut candidates: Vec<String> = servers.to_vec();
    let push = |domain: &str, candidates: &mut Vec<String>| {
        if !candidates.iter().any(|server| server == domain) && domain != own_server {
            candidates.push(domain.to_owned());
        }
    };
    if let Some((_, domain)) = room_id.split_once(':') {
        push(domain, &mut candidates);
    }
    if let Some(origin) = invite_origin {
        push(origin, &mut candidates);
    }
    candidates
}

/// `PUT /_matrix/federation/v1/send/{txnId}`
///
/// One transaction from one peer: up to fifty PDUs and some EDUs. Each PDU
/// is judged alone — hash and signature against the origin's published
/// keys, then the same authorization predicate local events pass — and a
/// refusal soft-fails into the per-PDU results without poisoning the
/// batch. Of the EDUs, `m.typing` is applied — for the origin's own
/// joined users only, so no server can put words in another's hands —
/// and the rest are still accepted and dropped (receipts, presence and
/// device lists arrive with later slices).
pub(crate) async fn send_transaction(
    state: AppState,
    headers: axum::http::HeaderMap,
    txn_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    // The replay row is keyed by `(origin, txn_id)` behind a two-byte
    // length, so a peer choosing anything longer than the key can hold
    // would see its own transactions answer for one another. No real
    // implementation sends more than a few dozen bytes; the bound sits
    // far above that and far below the key's.
    if txn_id.len() > MAX_TXN_ID_LEN {
        return Err(MatrixError::bad_json(format!(
            "a transaction id is at most {MAX_TXN_ID_LEN} bytes"
        )));
    }
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;

    let origin = federation_origin(&state, &headers, "PUT", &uri, Some(&body)).await?;

    // The replay table answers a retried transaction with its first answer:
    // the peer's retry loop is at-least-once, and this row is what makes
    // redelivery idempotent on our side.
    let txn_key = spindle_core::keys::federation_txn(&origin, &txn_id);
    if let Ok(Some(stored)) = spindle_store::ReadView::get(state.store.as_ref(), &txn_key)
        && let Ok(response) = serde_json::from_slice::<Value>(&stored)
    {
        return Ok(Json(response));
    }

    let pdus = body["pdus"].as_array().cloned().unwrap_or_default();
    if pdus.len() > 50 {
        return Err(MatrixError::bad_json(
            "a transaction carries at most 50 PDUs".to_owned(),
        ));
    }

    let key_map = if pdus.is_empty() {
        None
    } else {
        Some(state.federation.peer_keys(&origin).await.map_err(|error| {
            tracing::debug!("cannot fetch {origin} keys: {error}");
            MatrixError::new(
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "the origin's keys cannot be verified".to_owned(),
            )
        })?)
    };

    let results = receive_pdus(&state, &origin, key_map.as_ref(), &pdus).await;

    // EDUs after PDUs, so a join and the typing that follows it land in
    // order within one transaction. `m.typing` only, and only about the
    // origin's own joined users: an EDU is unsigned content inside a
    // signed envelope, so the envelope's origin is the whole authority.
    for edu in body["edus"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .take(100)
    {
        if edu["edu_type"].as_str() != Some("m.typing") {
            continue;
        }
        let content = &edu["content"];
        let (Some(room_id), Some(user_id), Some(typing)) = (
            content["room_id"].as_str(),
            content["user_id"].as_str(),
            content["typing"].as_bool(),
        ) else {
            continue;
        };
        if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin.as_str()) {
            continue;
        }
        if !state.rooms.is_joined(user_id, room_id).unwrap_or(false) {
            continue;
        }
        state
            .typing
            .set(room_id, user_id, typing, crate::typing::DEFAULT_TIMEOUT);
    }

    let response = json!({ "pdus": results });
    spindle_store::Store::put(
        state.store.as_ref(),
        &txn_key,
        response.to_string().as_bytes(),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    Ok(Json(response))
}

/// `GET /_matrix/federation/v1/state/{roomId}?event_id=`
pub(crate) async fn room_state(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    query: FederationStateQuery,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let (pdus, auth_chain) = state
        .rooms
        .federation_state(&room_id, &query.event_id)
        .map_err(room_error)?;
    let bodies = |events: Vec<crate::rooms::IdentifiedEvent>| -> Vec<Value> {
        events.into_iter().map(|(_, event)| event).collect()
    };
    Ok(Json(json!({
        "pdus": bodies(pdus),
        "auth_chain": bodies(auth_chain),
    })))
}

/// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=`
///
/// The IDs-only form: same computation, smaller wire — a peer that
/// already holds most events asks for this one.
pub(crate) async fn room_state_ids(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    query: FederationStateQuery,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let (pdus, auth_chain) = state
        .rooms
        .federation_state(&room_id, &query.event_id)
        .map_err(room_error)?;
    let ids = |events: Vec<crate::rooms::IdentifiedEvent>| -> Vec<String> {
        events.into_iter().map(|(id, _)| id).collect()
    };
    Ok(Json(json!({
        "pdu_ids": ids(pdus),
        "auth_chain_ids": ids(auth_chain),
    })))
}

/// `GET /_matrix/federation/v1/event/{eventId}`
pub(crate) async fn event(
    state: AppState,
    headers: axum::http::HeaderMap,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    // Resolve the room first: the in-room check needs it, and an event we
    // do not hold gets the same 404 whether or not the asker could have
    // seen it — nothing leaks through the error shape.
    let Some(room_id) = state.rooms.room_of_event(&event_id).map_err(room_error)? else {
        federation_origin(&state, &headers, "GET", &uri, None).await?;
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such event".to_owned(),
        ));
    };
    federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let event = state.rooms.event(&room_id, &event_id).map_err(room_error)?;
    Ok(Json(json!({
        "origin": state.config.server.name,
        "origin_server_ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0),
        "pdus": [event],
    })))
}

/// `GET /_matrix/federation/v1/backfill/{roomId}?v=&limit=`
///
/// History walking backwards from the named events. On a DAG server this
/// is a traversal; on the linear log it is a bounded range read, newest
/// first, starting events included.
pub(crate) async fn backfill(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    // `v` repeats; serde's map-shaped Query cannot carry that, so the pairs
    // are read directly.
    let mut from = Vec::new();
    let mut limit = 100_usize;
    for (key, value) in form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
    {
        match key.as_ref() {
            "v" => from.push(value.into_owned()),
            "limit" => limit = value.parse().unwrap_or(limit),
            _ => {}
        }
    }
    // The cap is ours: a peer that asks for the whole room gets a page.
    let limit = limit.clamp(1, 100);
    let pdus = state
        .rooms
        .backfill(&room_id, &from, limit)
        .map_err(room_error)?;
    Ok(Json(json!({
        "origin": state.config.server.name,
        "origin_server_ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0),
        "pdus": pdus,
    })))
}

/// `POST /_matrix/federation/v1/get_missing_events/{roomId}`
///
/// The catch-up call a server makes when a received event cites parents it
/// does not hold: fill the gap between what they have and what they got.
pub(crate) async fn missing_events(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    federation_room_origin(&state, &headers, "POST", &uri, Some(&body), &room_id).await?;
    let ids = |key: &str| -> Vec<String> {
        body[key]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let limit = usize::try_from(body["limit"].as_u64().unwrap_or(10))
        .unwrap_or(10)
        .clamp(1, 100);
    let min_depth = body["min_depth"].as_u64().unwrap_or(0);
    let events = state
        .rooms
        .missing_events(
            &room_id,
            &ids("earliest_events"),
            &ids("latest_events"),
            limit,
            min_depth,
        )
        .map_err(room_error)?;
    Ok(Json(json!({ "events": events })))
}

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`
pub(crate) async fn make_join(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    user_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let origin = federation_origin(&state, &headers, "GET", &uri, None).await?;
    // A server makes joins for its own users only: a template for someone
    // else's user would be a forgery kit.
    if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden(
            "the user does not live on the requesting server",
        ));
    }
    // What version this room actually is, rather than what this build's
    // default happens to be. The old check compared the peer's list against
    // a literal `ver=11` and, on a mismatch, told them "this room is version
    // 11" — a sentence it had no basis for, since it had never looked at the
    // room. For a room of any other version that answer is simply false.
    let version = state.rooms.room_version(&room_id).map_err(room_error)?;
    let version = version.as_str();

    // The `ver` list is the peer telling us what *they* can speak. If this
    // room's version is not in it, no template we produce will parse on
    // their side, so the refusal is correct — but it has to name the version
    // they would have needed.
    let offered = request.uri().query().is_some_and(|query| {
        query
            .split('&')
            .filter_map(|pair| pair.strip_prefix("ver="))
            .any(|ver| ver == version)
    });
    if !offered {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INCOMPATIBLE_ROOM_VERSION",
            format!("this room is version {version}"),
        ));
    }
    let event = state
        .rooms
        .make_join_template(&room_id, &user_id)
        .map_err(room_error)?;
    Ok(Json(json!({
        "room_version": version,
        "event": event,
    })))
}

/// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`
///
/// The mirror of `make_join`, and how an invited user's server rejects an
/// invite to a room it holds no log for: it fetches this template, signs
/// it, and brings it back through `send_leave`.
pub(crate) async fn make_leave(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    user_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let origin = federation_origin(&state, &headers, "GET", &uri, None).await?;
    // A server makes leaves for its own users only, same as joins: a
    // template for someone else's user would be a forgery kit.
    if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden(
            "the user does not live on the requesting server",
        ));
    }
    let version = state.rooms.room_version(&room_id).map_err(room_error)?;
    let event = state
        .rooms
        .make_leave_template(&room_id, &user_id)
        .map_err(room_error)?;
    Ok(Json(json!({
        "room_version": version.as_str(),
        "event": event,
    })))
}

/// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}`
///
/// A knock template, for a room whose join rule invites them: the same
/// preview-then-verify shape as `make_join`, and the same auth rules judge
/// the signed event on the way back through `send_knock`.
pub(crate) async fn make_knock(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    user_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let origin = federation_origin(&state, &headers, "GET", &uri, None).await?;
    if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden(
            "the user does not live on the requesting server",
        ));
    }
    let version = state.rooms.room_version(&room_id).map_err(room_error)?;
    let event = state
        .rooms
        .make_knock_template(&room_id, &user_id)
        .map_err(room_error)?;
    Ok(Json(json!({
        "room_version": version.as_str(),
        "event": event,
    })))
}

/// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`
pub(crate) async fn send_knock(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let knock: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let origin = federation_origin(&state, &headers, "PUT", &uri, Some(&knock)).await?;

    // Same smuggling rule as send_join and send_leave: this door admits
    // exactly one kind of event.
    let is_knock = knock["type"] == json!("m.room.member")
        && knock["content"]["membership"] == json!("knock")
        && knock["state_key"] == knock["sender"]
        && knock["room_id"].as_str() == Some(room_id.as_str());
    if !is_knock {
        return Err(MatrixError::bad_json(
            "send_knock carries exactly a knock event for this room".to_owned(),
        ));
    }
    let Some(knocker) = knock["sender"].as_str().map(str::to_owned) else {
        return Err(MatrixError::bad_json("the knock has no sender".to_owned()));
    };

    let key_map = state.federation.peer_keys(&origin).await.map_err(|error| {
        tracing::debug!("cannot fetch {origin} keys: {error}");
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "the origin's keys cannot be verified".to_owned(),
        )
    })?;
    let (computed_id, outcome) =
        receive_one_pdu(&state, &origin, Some(&key_map), &knock, Delivery::Brokered);
    if computed_id != event_id {
        return Err(MatrixError::bad_json(format!(
            "the event hashes to {computed_id}, not {event_id}"
        )));
    }
    if let Err(reason) = outcome {
        return Err(MatrixError::forbidden(&reason));
    }
    state.rooms.wake_sync_waiters();
    // The stripped state a knocker may see: what room they knocked on and
    // how it admits — the same subset an invitee gets.
    let events = state
        .rooms
        .stripped_state(&room_id, &knocker)
        .unwrap_or_default();
    Ok(Json(json!({ "knock_room_state": events })))
}

/// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`
pub(crate) async fn send_leave(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    send_leave_common(state, headers, room_id, event_id, request)
        .await
        .map(Json)
}

/// `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}`
///
/// The v1 `[200, {}]` envelope, same fossil rule as `send_join` v1.
pub(crate) async fn send_leave_v1(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    send_leave_common(state, headers, room_id, event_id, request)
        .await
        .map(|answer| Json(json!([200, answer])))
}

/// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
pub(crate) async fn send_join(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    send_join_common(state, headers, room_id, event_id, request)
        .await
        .map(Json)
}

/// `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}`
///
/// The v1 shape: the same answer inside a `[200, {...}]` envelope — a
/// fossil the spec keeps for servers that predate v2, and cheap to serve
/// since the body is the v2 body.
pub(crate) async fn send_join_v1(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    send_join_common(state, headers, room_id, event_id, request)
        .await
        .map(|answer| Json(json!([200, answer])))
}

/// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`
///
/// A remote server invites one of this server's users. The event arrives
/// signed by the inviter; this server checks it names a local user, adds its
/// own signature — the co-signature is what the rest of the room will accept
/// as proof the invitee's server was told — and records the invite so the
/// user's next `/sync` shows it, room history or not.
pub(crate) async fn invite(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let origin = federation_origin(&state, &headers, "PUT", &uri, Some(&body)).await?;

    // The version check comes first: an event from a room version this
    // server does not speak cannot be reasoned about, let alone signed.
    //
    // The question here is *can we speak this*, not *is this our default*,
    // and the difference is not pedantry. An invite is for a remote room
    // this server has no state for, so there is nothing to look the version
    // up from -- the body's `room_version` is the only statement of it, and
    // the spec puts it there for exactly that reason. Comparing it against
    // one hardcoded version happened to behave identically only because the
    // supported list has one entry, and would start silently refusing
    // invites the moment it had two.
    let offered = body["room_version"].as_str().unwrap_or_default();
    if !crate::surface::supports_room_version(offered) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INCOMPATIBLE_ROOM_VERSION",
            format!(
                "this server speaks room versions {}",
                crate::surface::ROOM_VERSIONS.join(", ")
            ),
        ));
    }
    let event = body["event"].clone();
    let is_invite = event["type"] == json!("m.room.member")
        && event["content"]["membership"] == json!("invite")
        && event["room_id"].as_str() == Some(room_id.as_str());
    if !is_invite {
        return Err(MatrixError::bad_json(
            "invite carries exactly an invite event for this room".to_owned(),
        ));
    }
    // The signature this endpoint adds vouches for the *invitee*: their
    // server was told. It vouches for nothing about the sender — but the
    // sender must at least belong to the server that signed the request,
    // or any server could originate invites in another's name.
    let sender_domain = event["sender"].as_str().and_then(|u| u.split_once(':'));
    if sender_domain.map(|(_, domain)| domain) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden(
            "the invite's sender does not belong to the requesting server",
        ));
    }
    let Some(target) = event["state_key"].as_str() else {
        return Err(MatrixError::bad_json("the invite names no one".to_owned()));
    };
    let target_domain = target.split_once(':').map(|(_, domain)| domain);
    if target_domain != Some(state.config.server.name.as_str()) {
        return Err(MatrixError::forbidden(
            "the invited user is not on this server",
        ));
    }
    // Right domain, no such account: co-signing would vouch that a user
    // was told about an invite when there is no user to tell.
    let localpart = target.strip_prefix('@').map_or(target, |rest| {
        rest.split_once(':')
            .map_or(rest, |(localpart, _)| localpart)
    });
    let known = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if !known {
        return Err(MatrixError::forbidden("no such user on this server"));
    }
    let target = target.to_owned();

    let Ok(ruma::CanonicalJsonValue::Object(mut canonical)) =
        ruma::CanonicalJsonValue::try_from(event)
    else {
        return Err(MatrixError::bad_json(
            "the invite event does not canonicalize".to_owned(),
        ));
    };
    let rules = ruma::RoomVersionId::try_from(crate::rooms::ROOM_VERSION)
        .ok()
        .and_then(|version| version.rules())
        .ok_or_else(|| MatrixError::internal("the room version rules are unavailable"))?;
    // The path names the event the inviter computed; disagreement means the
    // two servers are not looking at the same event.
    let hash = ruma::signatures::reference_hash(&canonical, &rules)
        .map_err(|error| MatrixError::bad_json(format!("the invite cannot be hashed: {error}")))?;
    if format!("${hash}") != event_id {
        return Err(MatrixError::bad_json(format!(
            "the event hashes to ${hash}, not {event_id}"
        )));
    }
    if ruma::signatures::hash_and_sign_event(
        &state.config.server.name,
        state.key.pair(),
        &mut canonical,
        &rules.redaction,
    )
    .is_err()
    {
        return Err(MatrixError::internal("the invite cannot be co-signed"));
    }
    let signed = serde_json::to_value(&canonical)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;

    // An invite for a room this server already holds is not a notification
    // about somewhere else -- it is an event in a log we have, and it has to
    // go in. It arrives out of band precisely because the invitee's server
    // is usually *not* in the room, so the inviter cannot reach it through
    // an ordinary transaction; when we are in the room, that reasoning does
    // not apply and skipping the append leaves our copy saying the user is
    // still gone. Their own join is then refused by the rules reading our
    // state, while the inviting server believes it told us. Synapse and
    // Continuwuity both add the invite to a room they hold, for this reason.
    //
    // Idempotent against the copy that may also arrive in a transaction:
    // `ingest` returns early for an event already in the log.
    record_invite(
        &state, &origin, &room_id, &event_id, &target, &body, &signed,
    )?;

    Ok(Json(json!({ "event": signed })))
}

/// Authenticate a federation request, or answer 401 with no gradient.
///
/// Every X-Matrix failure — missing header, bad signature, unfetchable
/// keys, wrong destination — collapses to the same `M_UNAUTHORIZED`, so a
/// probing peer learns nothing about which check refused it. The detail
/// lives in our logs, not in their response.
pub(crate) async fn federation_origin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &str,
    content: Option<&Value>,
) -> Result<String, MatrixError> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    state
        .federation
        .verify_request(authorization, method, uri, content)
        .await
        .map_err(|error| {
            tracing::debug!("federation auth refused: {error}");
            MatrixError::new(
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "the request signature is not valid".to_owned(),
            )
        })
}

/// Authenticate a federation request AND require the origin in the room.
///
/// The two checks always travel together on room-data reads: an
/// authenticated stranger is still a stranger, and room state belongs to
/// the servers in the room.
pub(crate) async fn federation_room_origin(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    uri: &str,
    content: Option<&Value>,
    room_id: &str,
) -> Result<String, MatrixError> {
    let origin = federation_origin(state, headers, method, uri, content).await?;
    let joined = state
        .rooms
        .server_in_room(room_id, &origin)
        .unwrap_or(false);
    if !joined {
        return Err(MatrixError::forbidden(
            "your server has no joined member in that room",
        ));
    }
    Ok(origin)
}

pub(crate) async fn send_leave_common(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Value, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let leave: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let origin = federation_origin(&state, &headers, "PUT", &uri, Some(&leave)).await?;

    // Shape first, same reasoning as send_join: this door admits exactly
    // one kind of event, and anything else through it is smuggling.
    let is_leave = leave["type"] == json!("m.room.member")
        && leave["content"]["membership"] == json!("leave")
        && leave["state_key"] == leave["sender"]
        && leave["room_id"].as_str() == Some(room_id.as_str());
    if !is_leave {
        return Err(MatrixError::bad_json(
            "send_leave carries exactly a leave event for this room".to_owned(),
        ));
    }

    let key_map = state.federation.peer_keys(&origin).await.map_err(|error| {
        tracing::debug!("cannot fetch {origin} keys: {error}");
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "the origin's keys cannot be verified".to_owned(),
        )
    })?;
    let (computed_id, outcome) =
        receive_one_pdu(&state, &origin, Some(&key_map), &leave, Delivery::Brokered);
    if computed_id != event_id {
        return Err(MatrixError::bad_json(format!(
            "the event hashes to {computed_id}, not {event_id}"
        )));
    }
    if let Err(reason) = outcome {
        return Err(MatrixError::forbidden(&reason));
    }
    state.rooms.wake_sync_waiters();
    Ok(json!({}))
}

pub(crate) async fn send_join_common(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    event_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Value, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let join: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let origin = federation_origin(&state, &headers, "PUT", &uri, Some(&join)).await?;

    // The shape is checked before the machinery runs: send_join admits one
    // kind of event, and anything else through this door — however well
    // signed — is a peer using the join handshake to smuggle.
    let is_join = join["type"] == json!("m.room.member")
        && join["content"]["membership"] == json!("join")
        && join["state_key"] == join["sender"]
        && join["room_id"].as_str() == Some(room_id.as_str());
    if !is_join {
        return Err(MatrixError::bad_json(
            "send_join carries exactly a join event for this room".to_owned(),
        ));
    }

    let mut key_map = state.federation.peer_keys(&origin).await.map_err(|error| {
        tracing::debug!("cannot fetch {origin} keys: {error}");
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "the origin's keys cannot be verified".to_owned(),
        )
    })?;

    // A restricted join is signed by two servers, and this is the second.
    // The joiner's server signs the event as its sender; the *authorising*
    // user's server signs it as the one making the claim, because the
    // nomination is a statement about a room only that server can see into
    // (MSC3083, and `required_server_signatures_to_verify_event` enforces
    // it from v8). We put the nomination in the template, so the signature
    // it needs is ours -- and without it the event we handed out fails
    // verification here, on our own doorstep, before any peer sees it.
    let join = match join["content"]["join_authorised_via_users_server"].as_str() {
        Some(nominee)
            if nominee.split_once(':').map(|(_, domain)| domain)
                == Some(state.config.server.name.as_str()) =>
        {
            key_map.vouch(
                state.config.server.name.clone(),
                state.key.key_id(),
                ruma::serde::Base64::parse(state.key.public_key_base64())
                    .map_err(|error| MatrixError::internal(&error.to_string()))?,
            );
            let version = state.rooms.room_version(&room_id).map_err(room_error)?;
            countersign(&state, &join, &version)?
        }
        // Someone else's user, or nobody's: not ours to vouch for. The
        // signature check below will ask for that server's key and fail if
        // the joining server did not collect it, which is the right answer
        // -- a nomination this server did not make is not one it endorses.
        _ => join,
    };
    let (computed_id, outcome) =
        receive_one_pdu(&state, &origin, Some(&key_map), &join, Delivery::Brokered);
    // The path names the event the peer computed; disagreement means one
    // side hashed a different event than the other signed.
    if computed_id != event_id {
        return Err(MatrixError::bad_json(format!(
            "the event hashes to {computed_id}, not {event_id}"
        )));
    }
    if let Err(reason) = outcome {
        return Err(MatrixError::forbidden(&reason));
    }

    // The state *before* the join, with its auth chain: everything the new
    // server needs to participate from this event onward.
    let (state_pairs, auth_pairs) = state
        .rooms
        .federation_state(&room_id, &event_id)
        .map_err(room_error)?;
    let bodies = |events: Vec<crate::rooms::IdentifiedEvent>| -> Vec<Value> {
        events.into_iter().map(|(_, event)| event).collect()
    };
    state.rooms.wake_sync_waiters();
    Ok(json!({
        "origin": state.config.server.name,
        "event": join,
        "state": bodies(state_pairs),
        "auth_chain": bodies(auth_pairs),
    }))
}

/// Judge and, if it holds up, apply one received PDU.
///
/// Returns the event ID this server *computed* (never one the peer
/// claimed) with the outcome. A PDU too malformed to even hash is keyed by
/// a placeholder, because the response shape needs a key and inventing a
/// plausible-looking ID for garbage would be worse.
#[derive(Debug, Deserialize)]
pub(crate) struct FederationStateQuery {
    pub(crate) event_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(servers: &[&str]) -> Vec<String> {
        servers.iter().map(|server| (*server).to_owned()).collect()
    }

    #[test]
    fn hints_lead_the_room_domain_follows_and_the_invite_origin_closes() {
        let candidates = join_candidates(
            "us.example",
            "!room:home.example",
            &owned(&["via.example"]),
            Some("inviter.example"),
        );
        assert_eq!(
            candidates,
            owned(&["via.example", "home.example", "inviter.example"])
        );
    }

    #[test]
    fn a_server_is_named_once_and_this_server_never() {
        let candidates = join_candidates(
            "us.example",
            "!room:via.example",
            &owned(&["via.example", "us.example"]),
            Some("via.example"),
        );
        // The hint list is the client's and is kept as given; what follows
        // is added only if new, and never this server.
        assert_eq!(candidates, owned(&["via.example", "us.example"]));
        assert_eq!(
            join_candidates("us.example", "!room:us.example", &[], Some("us.example")),
            Vec::<String>::new()
        );
    }

    fn signed(body: &str, signatures: &Value) -> Value {
        json!({ "type": "m.room.member", "content": { "membership": "join", "body": body }, "signatures": signatures })
    }

    #[test]
    fn a_resident_signature_on_the_identical_event_is_taken_on() {
        let mut join = signed("same", &json!({ "us.example": { "ed25519:a": "ours" } }));
        let returned = signed(
            "same",
            &json!({ "us.example": { "ed25519:a": "theirs-for-us" }, "home.example": { "ed25519:b": "theirs" } }),
        );
        merge_returned_signatures(&mut join, &returned);
        assert_eq!(
            join["signatures"],
            json!({ "us.example": { "ed25519:a": "ours" }, "home.example": { "ed25519:b": "theirs" } }),
            "theirs is added, ours is never replaced"
        );
    }

    #[test]
    fn a_resident_that_returns_a_different_event_is_not_believed() {
        let mut join = signed(
            "what we signed",
            &json!({ "us.example": { "ed25519:a": "ours" } }),
        );
        let before = join.clone();
        let returned = signed(
            "something else",
            &json!({ "home.example": { "ed25519:b": "theirs" } }),
        );
        merge_returned_signatures(&mut join, &returned);
        assert_eq!(join, before);
        merge_returned_signatures(&mut join, &json!("not an event"));
        assert_eq!(join, before);
    }

    #[test]
    fn a_join_without_a_signatures_block_gains_one() {
        let mut join = json!({ "type": "m.room.member", "content": { "membership": "join" } });
        let returned = json!({ "type": "m.room.member", "content": { "membership": "join" }, "signatures": { "home.example": { "ed25519:b": "theirs" } } });
        merge_returned_signatures(&mut join, &returned);
        assert_eq!(
            join["signatures"],
            json!({ "home.example": { "ed25519:b": "theirs" } })
        );
    }
}
