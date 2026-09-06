//! #84 §4: everything an event needs lands in the entry's batch, or nothing
//! does.
//!
//! The body used to be written with a separate `put` before the entry was
//! committed, and survived a crash only because fjall keeps a single
//! journal that the entry's sync happened to flush. Nothing stated that
//! ordering and nothing tested it; its failure would have been a durable
//! entry pointing at a body that was lost, surfacing as `MissingBody` on a
//! read far from the cause. This test is the statement: an append moves
//! the batch count by exactly one and the unbatched-row count by nothing.

use std::sync::Arc;

use serde_json::json;
use spindle_store::FjallStore;
use tempfile::TempDir;

#[test]
fn an_append_writes_nothing_outside_its_batch() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), "example.org");
    let room = rooms
        .create(
            "@alice:example.org",
            key.pair(),
            None,
            None,
            None,
            &[],
            &[],
            None,
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap();

    let unbatched = store.unbatched();
    let journalled = store.journalled();

    let event_id = rooms
        .send(
            &room,
            "@alice:example.org",
            key.pair(),
            "m.room.message",
            &json!({ "msgtype": "m.text", "body": "one batch" }),
        )
        .unwrap();

    assert_eq!(
        store.journalled() - journalled,
        1,
        "one event is one batch: the entry, its body, its stream row and its indexes together"
    );
    assert_eq!(
        store.unbatched() - unbatched,
        0,
        "no row of an event may be written outside its batch; a crash could keep it without the entry, or the entry without it"
    );

    // And the body is there to read back, through the batch.
    let event = rooms.event(&room, &event_id).unwrap();
    assert_eq!(event["content"]["body"], "one batch");
}
