//! A rejected invite's leave is fanned out to the invitee's server by the
//! resident server, after the rejecting server has already answered its
//! user. A second invite can be recorded before that leave lands, and the
//! old leave must not take the new invite with it (CI run 34041725907,
//! `a_rejected_invite_leaves_both_sides_clean`).

use std::sync::Arc;

use serde_json::json;
use spindle_server::rooms::Rooms;
use spindle_store::FjallStore;
use tempfile::TempDir;

const BOB: &str = "@bob:example.org";
const ROOM: &str = "!elsewhere:remote.test";

fn leave_after(invite_id: &str) -> serde_json::Value {
    json!({
        "type": "m.room.member",
        "room_id": ROOM,
        "sender": BOB,
        "state_key": BOB,
        "content": { "membership": "leave" },
        "auth_events": ["$create", "$power", invite_id],
        "prev_events": [invite_id],
        "origin_server_ts": 1,
    })
}

#[test]
fn a_leave_for_an_earlier_invite_leaves_the_new_invite_standing() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let rooms = Rooms::new(Arc::clone(&store), "example.org");

    rooms
        .record_pending_invite(BOB, ROOM, "remote.test", "$second", &[])
        .unwrap();

    // The leave that rejected the first invite arrives late.
    rooms
        .receive_remote(ROOM, "$stale-leave", &leave_after("$first"))
        .unwrap();
    assert!(
        rooms.pending_invite(BOB, ROOM).unwrap().is_some(),
        "the stale leave does not end the new invite"
    );

    // A leave about the standing invite ends it.
    rooms
        .receive_remote(ROOM, "$fresh-leave", &leave_after("$second"))
        .unwrap();
    assert!(
        rooms.pending_invite(BOB, ROOM).unwrap().is_none(),
        "the leave for this invite ends it"
    );
}

#[test]
fn a_record_without_an_invite_id_still_yields_to_any_leave() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let rooms = Rooms::new(Arc::clone(&store), "example.org");

    // The shape a row had before the invite's id was kept beside it.
    spindle_store::Store::put(
        store.as_ref(),
        &spindle_core::keys::user_room(spindle_core::keys::Keyspace::PendingInvite, BOB, ROOM),
        json!({ "origin": "remote.test", "invite_state": [] })
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    rooms
        .receive_remote(ROOM, "$leave", &leave_after("$whatever"))
        .unwrap();
    assert!(rooms.pending_invite(BOB, ROOM).unwrap().is_none());
}
