//! Epochs: who hubs a room now, by what right, and failover (#22, SPEC
//! sections 12.1, 12.6 and 13.2).
//!
//! A room's hub is read off its `m.room.hub` events, oldest first. The
//! first (epoch 0) must come from the room creator's server. Each later
//! one opens the next epoch, names the one before (`org.spindle.
//! prev_hub_event`) and states the outgoing hub's last attested entry
//! (`org.spindle.prev_epoch_final`). It is valid when either
//!
//! - **handoff:** the outgoing hub co-signed it -- MSC3995's own rule,
//!   that the current hub signs a hub change; or
//! - **failover:** it says so (`org.spindle.failover`) and comes from the
//!   first backup the outgoing epoch listed (`org.spindle.backups`). The
//!   outgoing hub cannot sign anything while it is down, so who may claim
//!   is fixed in advance instead, by whoever set the outgoing hub.
//!
//! and, in both cases, it does not drop an attested entry: a server that
//! holds an attestation from the outgoing hub for a later position than
//! the stated final -- or a different entry at it -- refuses the epoch and
//! keeps the claim and that attestation as a proof. A refused epoch leaves
//! the room ordinary on that server: never a hub it cannot trust.
//!
//! Power is the room's ordinary business: an `m.room.hub` is a state event,
//! and only a user the power levels allow can send one.

use std::time::Duration;

use ruma::CanonicalJsonValue;
use serde_json::{Value, json};

use super::metrics::Counter;
use super::{
    BACKUPS_KEY, EPOCH_KEY, FAILOVER_KEY, PREV_FINAL_KEY, PREV_HUB_KEY, UNSTABLE_PREFIX, attest,
    is_capable, lock, server_of,
};
use crate::AppState;
use crate::rooms::HUB_EVENT_TYPE;

/// How many epochs back a designation is read before it is given up on.
const MAX_EPOCHS: usize = 1024;

/// Who hubs a room, and by what chain of hub events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Designation {
    /// The hub: the server of the current `m.room.hub` sender.
    pub server: String,
    /// The epoch the current `m.room.hub` opened.
    pub epoch: u64,
    /// The current `m.room.hub` event.
    pub event_id: String,
    /// Who may claim the next epoch if this hub fails, in order.
    pub backups: Vec<String>,
    /// Every epoch's hub, by epoch, back to the first.
    pub history: Vec<String>,
}

impl Designation {
    /// The hub of `epoch`, if the room has had that epoch.
    #[must_use]
    pub fn hub_of(&self, epoch: u64) -> Option<&str> {
        usize::try_from(epoch)
            .ok()
            .and_then(|epoch| self.history.get(epoch))
            .map(String::as_str)
    }
}

fn epoch_of(event: &Value) -> u64 {
    event["content"][EPOCH_KEY].as_u64().unwrap_or(0)
}

fn backups_of(event: &Value) -> Vec<String> {
    event["content"][BACKUPS_KEY]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// The room's hub, if hub mode is in force in it and every epoch to the
/// current one is valid on this server's evidence.
///
/// A room with no `m.room.hub` is ordinary: unlike in the MSC's own room
/// version, the creator is not the hub by default.
pub async fn designation(state: &AppState, room_id: &str) -> Option<Designation> {
    designation_explained(state, room_id).await.ok()
}

/// [`designation`], saying why when there is none: for logs, the admin
/// surface and tests.
///
/// # Errors
///
/// Why the room has no hub this server trusts.
pub async fn designation_explained(state: &AppState, room_id: &str) -> Result<Designation, String> {
    let current = state
        .rooms
        .hub_event(room_id)
        .map_err(|error| error.to_string())?
        .ok_or("the room has no m.room.hub")?;
    // Back to the first epoch, from the store: no keys needed for this.
    let mut chain = vec![current];
    while let Some(last) = chain.last() {
        let epoch = epoch_of(last);
        if epoch == 0 {
            break;
        }
        if chain.len() > MAX_EPOCHS {
            return Err("too many epochs".to_owned());
        }
        let previous_id = last["content"][PREV_HUB_KEY]
            .as_str()
            .ok_or(format!("epoch {epoch} names no previous m.room.hub"))?
            .to_owned();
        let mut previous = state
            .rooms
            .pdu(room_id, &previous_id)
            .map_err(|error| format!("epoch {epoch}'s previous m.room.hub: {error}"))?;
        if previous["type"].as_str() != Some(HUB_EVENT_TYPE)
            || previous["state_key"].as_str() != Some("")
            || epoch_of(&previous) + 1 != epoch
        {
            return Err(format!("epoch {epoch} does not follow {previous_id}"));
        }
        previous["event_id"] = json!(previous_id);
        chain.push(previous);
    }
    chain.reverse();
    let genesis = chain.first().ok_or("no epoch 0")?;
    let creator = state
        .rooms
        .creator_server(room_id)
        .map_err(|error| error.to_string())?
        .ok_or("the room has no creator")?;
    if genesis["sender"].as_str().and_then(server_of) != Some(creator.as_str()) {
        return Err("epoch 0 is not the room creator's server's".to_owned());
    }
    let mut designation = Designation {
        server: creator.clone(),
        epoch: 0,
        event_id: genesis["event_id"].as_str().unwrap_or_default().to_owned(),
        backups: backups_of(genesis),
        history: vec![creator],
    };
    for event in &chain[1..] {
        designation = Box::pin(next_epoch(state, room_id, &designation, event)).await?;
    }
    Ok(designation)
}

/// Whether `event` validly opens the epoch after `outgoing`'s.
async fn next_epoch(
    state: &AppState,
    room_id: &str,
    outgoing: &Designation,
    event: &Value,
) -> Result<Designation, String> {
    let epoch = outgoing.epoch + 1;
    let server = event["sender"]
        .as_str()
        .and_then(server_of)
        .ok_or(format!("epoch {epoch} has no sender"))?
        .to_owned();
    let event_id = event["event_id"].as_str().unwrap_or_default().to_owned();
    if event["content"][FAILOVER_KEY] == json!(true) {
        if outgoing.backups.first() != Some(&server) || server == outgoing.server {
            return Err(format!(
                "epoch {epoch} is a failover claim by {server}, not the first backup"
            ));
        }
    } else if !cosigned_by(state, room_id, &event_id, event, &outgoing.server).await {
        return Err(format!(
            "epoch {epoch} is a handoff {} did not co-sign",
            outgoing.server
        ));
    }
    if !keeps_attested_prefix(state, room_id, outgoing, event) {
        return Err(format!("epoch {epoch} drops an attested entry"));
    }
    let mut history = outgoing.history.clone();
    history.push(server.clone());
    Ok(Designation {
        server,
        epoch,
        event_id,
        backups: backups_of(event),
        history,
    })
}

/// Whether `signer` signed `event`: the outgoing hub's co-signature on a
/// handoff. Verified over the redacted event, the way every event
/// signature is, so it covers the content through the content hash.
async fn cosigned_by(
    state: &AppState,
    room_id: &str,
    event_id: &str,
    event: &Value,
    signer: &str,
) -> bool {
    if let Some(known) = lock(&state.hub.cosigned).get(event_id) {
        return *known;
    }
    let Ok(version) = state.rooms.room_version(room_id) else {
        return false;
    };
    let mut body = event.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("event_id");
        object.remove("unsigned");
    }
    let Ok(CanonicalJsonValue::Object(canonical)) = CanonicalJsonValue::try_from(body) else {
        return false;
    };
    let Ok(mut redacted) = spindle_core::version::redact(&canonical, &version) else {
        return false;
    };
    // `verify_json` checks every entity that signed, and this asks about
    // one: keep only its signatures. (The sender's own signature was
    // checked when the event was received.)
    let Some(CanonicalJsonValue::Object(only)) = redacted
        .get("signatures")
        .and_then(|signatures| match signatures {
            CanonicalJsonValue::Object(all) => all.get(signer).cloned(),
            _ => None,
        })
        .map(|mine| {
            let mut only = ruma::CanonicalJsonObject::new();
            only.insert(signer.to_owned(), mine);
            CanonicalJsonValue::Object(only)
        })
    else {
        lock(&state.hub.cosigned).insert(event_id.to_owned(), false);
        return false;
    };
    redacted.insert("signatures".to_owned(), CanonicalJsonValue::Object(only));
    let key_map = if signer == state.config.server.name {
        let mut map = ruma::signatures::PublicKeyMap::new();
        map.entry(signer.to_owned()).or_default().insert(
            state.key.key_id(),
            ruma::serde::Base64::new(state.key.pair().public_key().to_vec()),
        );
        map
    } else {
        match state.federation.peer_keys(signer).await {
            Ok(keys) => keys.map_for(None, false),
            // Unknown, not false: a key fetch can succeed later.
            Err(_) => return false,
        }
    };
    let verified = ruma::signatures::verify_json(&key_map, &redacted).is_ok();
    lock(&state.hub.cosigned).insert(event_id.to_owned(), verified);
    verified
}

/// The invariant: a new epoch never drops an entry the outgoing hub
/// attested, on the evidence this server holds. On a violation the claim
/// and the attestation it contradicts are kept as a proof.
fn keeps_attested_prefix(
    state: &AppState,
    room_id: &str,
    outgoing: &Designation,
    event: &Value,
) -> bool {
    let Some(known) = attest::highest_proven(state, room_id, outgoing) else {
        return true;
    };
    let Some(held) = attest::Parsed::read(&known) else {
        return true;
    };
    let stated = &event["content"][PREV_FINAL_KEY];
    let truncates = match (
        stated["li"].as_i64(),
        stated["event_id"].as_str(),
        stated["chain"].as_str(),
    ) {
        (Some(li), Some(event_id), Some(chain)) => {
            li < held.li
                || (li == held.li
                    && (event_id != held.event_id || chain != attest::encode(&held.chain)))
        }
        _ => true,
    };
    if truncates {
        attest::prove_truncation(state, room_id, outgoing, event, &known);
    }
    !truncates
}

/// Claim the next epoch for this server, because the room's hub has not
/// answered for `failover_after_ms` and this server is the first backup it
/// listed. Returns whether a claim was sent.
///
/// The claim starts the new epoch from the highest attestation of the
/// outgoing epoch that any hub-mode server in the room can show -- its own
/// and every other participant's, asked for and verified -- so a
/// participant that heard more from the old hub than this server did does
/// not lose it. The entry that attestation names is fetched first if this
/// server lacks it. The claim is an ordinary state event, sent by `sender`,
/// so the room's power levels decide whether it may be sent at all.
pub(crate) async fn claim_failover(
    state: &AppState,
    sender: &str,
    room_id: &str,
    outgoing: &Designation,
) -> bool {
    let metrics = state.metrics.hub();
    let (best, provider) = best_attested(state, room_id, outgoing).await;
    let final_entry = best.as_ref().and_then(attest::Parsed::read);
    if let Some(entry) = &final_entry
        && !super::holds(state, room_id, &entry.event_id)
    {
        let fetched = match &provider {
            Some(provider) => state
                .federation
                .remote_event(provider, &entry.event_id)
                .await
                .ok(),
            None => None,
        };
        if let (Some(provider), Some(pdu)) = (&provider, fetched) {
            let _ = crate::inbound::receive_from_hub(state, provider, &pdu).await;
        }
        if !super::holds(state, room_id, &entry.event_id) {
            tracing::warn!(
                room = room_id,
                event = entry.event_id,
                "cannot claim the hub: the last attested entry cannot be fetched"
            );
            metrics.bump(Counter::FailoverAbandoned);
            return false;
        }
    }
    let mut backups: Vec<String> = outgoing
        .backups
        .iter()
        .filter(|server| **server != state.config.server.name)
        .cloned()
        .collect();
    backups.push(outgoing.server.clone());
    let content = json!({
        EPOCH_KEY: outgoing.epoch + 1,
        PREV_HUB_KEY: outgoing.event_id,
        FAILOVER_KEY: true,
        PREV_FINAL_KEY: final_entry.as_ref().map(|entry| json!({
            "li": entry.li,
            "event_id": entry.event_id,
            "chain": attest::encode(&entry.chain),
            "attestation": best,
        })),
        BACKUPS_KEY: backups,
    });
    match state.rooms.set_state(
        room_id,
        sender,
        state.key.pair(),
        HUB_EVENT_TYPE,
        "",
        &content,
    ) {
        Ok(event_id) => {
            tracing::warn!(
                room = room_id,
                old_hub = outgoing.server,
                event = event_id,
                epoch = outgoing.epoch + 1,
                "the hub stopped answering; claimed the next epoch"
            );
            metrics.bump(Counter::FailoverClaimed);
            lock(&state.hub.unreachable).remove(room_id);
            super::after_local_send(state, room_id);
            true
        }
        Err(error) => {
            tracing::warn!(room = room_id, "cannot claim the hub: {error}");
            metrics.bump(Counter::FailoverAbandoned);
            false
        }
    }
}

/// The highest attestation of `outgoing`'s epoch that any hub-mode server
/// in the room can show -- this one's, and each other participant's,
/// asked for and verified against the outgoing hub's key -- and who
/// showed it, when it was not this server.
async fn best_attested(
    state: &AppState,
    room_id: &str,
    outgoing: &Designation,
) -> (Option<Value>, Option<String>) {
    let mut best = attest::highest_proven(state, room_id, outgoing);
    let mut provider: Option<String> = None;
    let keys = state.federation.peer_keys(&outgoing.server).await.ok();
    for server in state.rooms.remote_domains(room_id).unwrap_or_default() {
        if server == outgoing.server || !is_capable(state, &server).await {
            continue;
        }
        let uri = format!(
            "{UNSTABLE_PREFIX}/attested/{}?epoch={}",
            crate::federation::path_segment(room_id),
            outgoing.epoch
        );
        let Ok(Ok(answer)) = tokio::time::timeout(
            Duration::from_millis(state.config.federation.hub.submit_timeout_ms),
            state.federation.hub_request(&server, &uri, None),
        )
        .await
        else {
            continue;
        };
        let offered = &answer["attestation"];
        let (Some(keys), Some(parsed)) = (&keys, attest::Parsed::read(offered)) else {
            continue;
        };
        let better = best
            .as_ref()
            .and_then(attest::Parsed::read)
            .is_none_or(|best| parsed.li > best.li);
        if better
            && parsed.hub == outgoing.server
            && parsed.epoch == outgoing.epoch
            && attest::verifies(keys, offered)
        {
            best = Some(offered.clone());
            provider = Some(server);
        }
    }
    (best, provider)
}
