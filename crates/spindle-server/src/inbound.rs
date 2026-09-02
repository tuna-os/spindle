//! The server-to-server protocol as it arrives, and the membership
//! handshakes this server walks with a resident: what a peer's PDU has to
//! satisfy to be accepted, how a refusal is reported, how a `make_join` or
//! `make_leave` template is finished and signed, how a resident's
//! signatures are taken on, and which servers are asked to broker a join.
//!
//! None of this takes an HTTP type. It sat in the route table (#309), so
//! every claim about it was proven through a socket -- a real peer, a key
//! pair, a served key document -- to assert things one function call deep.
//! The outbound client (`federation.rs`) is the other half of the same
//! protocol; this is the policy the handlers in `routes.rs` apply.

use serde_json::{Value, json};

use crate::AppState;
use crate::errors::MatrixError;

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

pub(crate) fn receive_one_pdu(
    state: &AppState,
    origin: &str,
    keys: Option<&crate::federation::PeerKeys>,
    pdu: &Value,
) -> (String, Result<(), String>) {
    use ruma::CanonicalJsonValue;

    let Ok(CanonicalJsonValue::Object(canonical)) = CanonicalJsonValue::try_from(pdu.clone())
    else {
        return (
            "$malformed".to_owned(),
            Err("not canonicalizable".to_owned()),
        );
    };

    // The sender must live on the origin: a transaction is a server
    // speaking for its own users, and accepting someone else's would let
    // any peer forge any server's events into our rooms.
    let sender_domain = pdu["sender"]
        .as_str()
        .and_then(|sender| sender.split_once(':'))
        .map(|(_, domain)| domain);
    if sender_domain != Some(origin) {
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
                return match state.rooms.receive_remote(
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
    match state.rooms.receive_remote(room_id, &event_id, pdu) {
        Ok(()) => (event_id, Ok(())),
        Err(error) => (event_id, Err(error.to_string())),
    }
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
