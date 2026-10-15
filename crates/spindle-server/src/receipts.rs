//! Read receipts across federation (#624), and the `m.receipt` event local
//! clients are shown.
//!
//! A receipt is stored once, under one key shape, whoever set it: a local
//! client through `/receipt` or `/read_markers`, or a peer through an
//! `m.receipt` EDU. Classic `/sync` and the sliding-sync receipts extension
//! read that store and never ask where a row came from.
//!
//! **Inbound** (<https://spec.matrix.org/v1.16/server-server-api/#receipts>):
//! the content is `room -> receipt type -> user -> {event_ids, data}`. An
//! EDU is unsigned content inside a signed envelope, so the envelope's
//! origin is the only authority: a receipt is accepted for a user on the
//! origin who is joined to the room, and for nobody else. Only `m.read`
//! federates -- `m.read.private` is never sent by a conforming server, and
//! one that arrives anyway is refused, never stored as public.
//!
//! **Outbound**: a local user's public `m.read` receipt is queued for every
//! other server in the room, coalesced per destination by
//! [`crate::federation::Federation::queue_receipt`]. Private receipts and
//! `m.fully_read` stay home.
//!
//! **Presence is not federated** (#624 asked whether it was cheap): this
//! server has no `/sync` presence block for an inbound `m.presence` to land
//! in -- a peer's update would be readable only by polling
//! `GET /presence/{user}/status` -- and the outbound half is a fan-out of
//! every local user's every state change to every server they share a room
//! with, which is the load other homeservers ship presence switched off to
//! avoid. Inbound `m.presence` is counted as `unsupported` in
//! `spindle_federation_edus_received_total` so its volume is visible before
//! anyone builds it.

use serde_json::Value;

use crate::AppState;
use crate::federation::OutboundReceipt;
use crate::metrics::{EduResult, ReceiptResult};
use crate::rooms::RoomError;

/// Receipts read out of one inbound EDU; the rest are counted and dropped.
pub const MAX_RECEIPTS_PER_EDU: usize = 500;

/// Event IDs considered per receipt. The spec allows a list; every real
/// server sends one.
const MAX_EVENT_IDS: usize = 10;

/// The longest room, user, event or thread ID accepted (the spec's 255).
const MAX_ID_LEN: usize = 255;

/// Whether `viewer` may see a receipt of `receipt_type` that `owner` set.
///
/// `m.read` is public. Everything else -- `m.read.private`, and the
/// `m.fully_read` marker `/read_markers` stores alongside -- is its owner's
/// business only.
#[must_use]
pub fn visible_to(receipt_type: &str, owner: &str, viewer: &str) -> bool {
    receipt_type == "m.read" || owner == viewer
}

/// One receipt row as the store hands it back: `(user, type, event, ts,
/// thread)`.
pub type ReceiptRow = (String, String, String, u64, Option<String>);

/// Other readers' receipts a room's first `m.receipt` carries at most; the
/// viewer's own are always included on top.
pub const MAX_INITIAL_RECEIPTS: usize = 100;

/// `viewer`'s own rows, and the newest `cap` of everyone else's by `ts`.
#[must_use]
pub fn newest(
    rows: impl IntoIterator<Item = ReceiptRow>,
    viewer: &str,
    cap: usize,
) -> Vec<ReceiptRow> {
    let (mut kept, mut others): (Vec<ReceiptRow>, Vec<ReceiptRow>) =
        rows.into_iter().partition(|row| row.0 == viewer);
    others.sort_unstable_by(|a, b| b.3.cmp(&a.3));
    others.truncate(cap);
    kept.extend(others);
    kept
}

/// The content of an `m.receipt` ephemeral event for `viewer`:
/// `event -> type -> user -> {ts, thread_id?}`, as the client-server spec
/// shapes it. Rows `viewer` may not see are left out.
#[must_use]
pub fn event_content(
    rows: impl IntoIterator<Item = ReceiptRow>,
    viewer: &str,
) -> serde_json::Map<String, Value> {
    let mut content: serde_json::Map<String, Value> = serde_json::Map::new();
    for (user, receipt_type, event_id, ts, thread) in rows {
        if !visible_to(&receipt_type, &user, viewer) {
            continue;
        }
        let mut data = serde_json::json!({ "ts": ts });
        if let Some(thread) = thread {
            data["thread_id"] = Value::String(thread);
        }
        let by_type = content
            .entry(event_id)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        let Some(by_type) = by_type.as_object_mut() else {
            continue;
        };
        let by_user = by_type
            .entry(receipt_type)
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(by_user) = by_user.as_object_mut() {
            by_user.insert(user, data);
        }
    }
    content
}

/// Queue a local user's receipt for the room's other servers, if it is one
/// that federates: `m.read` only.
pub fn federate(
    state: &AppState,
    room_id: &str,
    user_id: &str,
    receipt_type: &str,
    event_id: &str,
    thread_id: Option<&str>,
) {
    if receipt_type != "m.read" {
        return;
    }
    let Ok(destinations) = state.rooms.remote_domains(room_id) else {
        return;
    };
    let receipt = OutboundReceipt {
        room_id,
        user_id,
        event_id,
        thread_id,
        ts: now_ms(),
    };
    for destination in destinations {
        state.federation.queue_receipt(&destination, &receipt);
    }
}

/// Apply one inbound `m.receipt` EDU from `origin`, counting what became of
/// every receipt in it, and return what became of the EDU as a whole.
///
/// Synchronous room work -- a receipt for a cold room loads it -- so the
/// caller runs it off the async workers.
#[must_use]
pub fn apply_edu(state: &AppState, origin: &str, content: &Value) -> EduResult {
    let Some(rooms) = content.as_object() else {
        return EduResult::Malformed;
    };
    let metrics = &state.metrics;
    let mut seen = 0_usize;
    let mut accepted = 0_usize;
    for (room_id, by_type) in rooms {
        let Some(by_type) = by_type.as_object() else {
            metrics.record_receipt_received(ReceiptResult::Malformed);
            continue;
        };
        for (receipt_type, by_user) in by_type {
            let Some(by_user) = by_user.as_object() else {
                metrics.record_receipt_received(ReceiptResult::Malformed);
                continue;
            };
            for (user_id, receipt) in by_user {
                seen += 1;
                let result = if seen > MAX_RECEIPTS_PER_EDU {
                    ReceiptResult::OverLimit
                } else {
                    apply_one(state, origin, room_id, receipt_type, user_id, receipt)
                };
                if result == ReceiptResult::Accepted {
                    accepted += 1;
                }
                metrics.record_receipt_received(result);
            }
        }
    }
    if accepted > 0 {
        EduResult::Accepted
    } else {
        EduResult::Ignored
    }
}

fn apply_one(
    state: &AppState,
    origin: &str,
    room_id: &str,
    receipt_type: &str,
    user_id: &str,
    receipt: &Value,
) -> ReceiptResult {
    if receipt_type != "m.read" {
        return ReceiptResult::UnsupportedType;
    }
    if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin) {
        return ReceiptResult::ForeignUser;
    }
    let event_ids: Vec<&str> = receipt["event_ids"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .take(MAX_EVENT_IDS)
        .filter_map(Value::as_str)
        .filter(|id| id.len() <= MAX_ID_LEN)
        .collect();
    let thread_id = match &receipt["data"]["thread_id"] {
        Value::Null => None,
        Value::String(thread) if thread.len() <= MAX_ID_LEN => Some(thread.as_str()),
        _ => return ReceiptResult::Malformed,
    };
    if event_ids.is_empty() || room_id.len() > MAX_ID_LEN || user_id.len() > MAX_ID_LEN {
        return ReceiptResult::Malformed;
    }
    let ts = receipt["data"]["ts"].as_u64().unwrap_or_else(now_ms);
    match state
        .rooms
        .set_remote_receipt(room_id, user_id, receipt_type, &event_ids, thread_id, ts)
    {
        Ok(_) => ReceiptResult::Accepted,
        Err(RoomError::MissingBody(_)) => ReceiptResult::UnknownEvent,
        Err(RoomError::Forbidden(_) | RoomError::UnknownRoom(_)) => ReceiptResult::NotJoined,
        Err(error) => {
            tracing::debug!(room_id, user_id, "remote receipt not stored: {error}");
            ReceiptResult::NotJoined
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_receipts_and_markers_are_their_owners_alone() {
        let rows = vec![
            (
                "@a:x".to_owned(),
                "m.read".to_owned(),
                "$1".to_owned(),
                1,
                None,
            ),
            (
                "@a:x".to_owned(),
                "m.read.private".to_owned(),
                "$2".to_owned(),
                2,
                None,
            ),
            (
                "@a:x".to_owned(),
                "m.fully_read".to_owned(),
                "$2".to_owned(),
                2,
                None,
            ),
            (
                "@b:x".to_owned(),
                "m.read".to_owned(),
                "$1".to_owned(),
                3,
                Some("$root".to_owned()),
            ),
        ];
        let seen_by_b = event_content(rows.clone(), "@b:x");
        assert!(seen_by_b.get("$2").is_none(), "{seen_by_b:?}");
        assert_eq!(seen_by_b["$1"]["m.read"]["@b:x"]["thread_id"], "$root");
        assert_eq!(seen_by_b["$1"]["m.read"]["@a:x"]["ts"], 1);
        let seen_by_a = event_content(rows, "@a:x");
        assert_eq!(seen_by_a["$2"]["m.read.private"]["@a:x"]["ts"], 2);
    }

    #[test]
    fn a_first_look_keeps_the_viewers_own_and_the_newest_of_the_rest() {
        let row = |user: &str, ts: u64| -> ReceiptRow {
            (
                user.to_owned(),
                "m.read".to_owned(),
                "$e".to_owned(),
                ts,
                None,
            )
        };
        let kept = newest(
            vec![
                row("@me:x", 1),
                row("@a:x", 5),
                row("@b:x", 9),
                row("@c:x", 7),
            ],
            "@me:x",
            2,
        );
        let users: Vec<&str> = kept.iter().map(|row| row.0.as_str()).collect();
        assert_eq!(users, ["@me:x", "@b:x", "@c:x"]);
    }
}
