//! #817: truncating a room's log below a watermark.
//!
//! Chain integrity is the risk. Each test truncates a real room and then
//! asks the question a different reader would: a reload, an exhaustive
//! verification, a new append, a backup, a gc run, a `/messages` walk and a
//! crash between the checkpoint and the deletes. None of them sleeps; the
//! row counts are what is asserted.

use std::sync::Arc;

use serde_json::json;
use spindle_core::keys::{Keyspace, keyspace_prefix, room_prefix};
use spindle_core::{ChainHash, EventId, RoomLog};
use spindle_server::rooms::Rooms;
use spindle_server::signing::ServerKey;
use spindle_store::{FjallStore, ReadView, RoomStore};
use tempfile::TempDir;

const SERVER: &str = "example.org";
const ALICE: &str = "@alice:example.org";
const BOB: &str = "@bob:example.org";

struct Fixture {
    dir: TempDir,
    store: Arc<FjallStore>,
    rooms: Rooms,
    key: ServerKey,
    room: String,
    first_message: String,
}

/// A room of messages, reactions to the first one, and a topic change every
/// third event, so old state roots own nodes of their own.
fn fixture(rounds: usize) -> Fixture {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = Rooms::new(Arc::clone(&store), SERVER);
    let room = rooms
        .create(
            ALICE,
            key.pair(),
            Some("retained"),
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
    let first_message = rooms
        .send(
            &room,
            ALICE,
            key.pair(),
            "m.room.message",
            &json!({ "msgtype": "m.text", "body": "first" }),
        )
        .unwrap();
    // A ban early on, so a user's current membership event sits below any
    // floor the tests choose.
    rooms
        .set_state(
            &room,
            ALICE,
            key.pair(),
            "m.room.member",
            BOB,
            &json!({ "membership": "ban" }),
        )
        .unwrap();
    for n in 0..rounds {
        rooms
            .send(
                &room,
                ALICE,
                key.pair(),
                "m.room.message",
                &json!({ "msgtype": "m.text", "body": format!("{n}") }),
            )
            .unwrap();
        rooms
            .send(
                &room,
                ALICE,
                key.pair(),
                "m.reaction",
                &json!({ "m.relates_to": {
                    "rel_type": "m.annotation", "event_id": first_message, "key": format!("{n}")
                }}),
            )
            .unwrap();
        rooms
            .set_state(
                &room,
                ALICE,
                key.pair(),
                "m.room.topic",
                "",
                &json!({ "topic": format!("topic {n}") }),
            )
            .unwrap();
    }
    Fixture {
        dir,
        store,
        rooms,
        key,
        room,
        first_message,
    }
}

impl Fixture {
    fn log(&self) -> RoomLog {
        RoomStore::new(self.store.as_ref(), self.room.as_str())
            .load_exhaustive()
            .unwrap()
            .unwrap()
            .log
    }

    /// The position `fraction` of the way up the room's log.
    fn watermark(&self, numerator: usize, denominator: usize) -> i64 {
        let log = self.log();
        let at = log.len() * numerator / denominator;
        log.entries().nth(at).unwrap().li.get()
    }

    fn state_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .rooms
            .state(&self.room)
            .unwrap()
            .iter()
            .map(|event| event["event_id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    }

    fn rows(&self, keyspace: Keyspace) -> usize {
        ReadView::scan_prefix(self.store.as_ref(), &room_prefix(keyspace, &self.room))
            .unwrap()
            .len()
    }

    fn send(&self, body: &str) -> String {
        self.rooms
            .send(
                &self.room,
                ALICE,
                self.key.pair(),
                "m.room.message",
                &json!({ "msgtype": "m.text", "body": body }),
            )
            .unwrap()
    }
}

/// Recompute the chain from the checkpoint over the entries that carry one.
fn recomputed_head(log: &RoomLog) -> ChainHash {
    let mut chain = log
        .chain_checkpoint()
        .map_or_else(ChainHash::seed, |p| p.chain);
    for entry in log.entries().filter(|entry| entry.chain.is_some()) {
        chain = chain.extend(&entry.event_id);
        assert_eq!(
            entry.chain,
            Some(chain),
            "stored chain at {}",
            entry.li.get()
        );
    }
    chain
}

#[test]
fn a_truncated_room_reloads_with_the_same_state_head_and_counters() {
    let fixture = fixture(12);
    let before = fixture.log();
    let state = fixture.state_ids();
    let floor = fixture.watermark(2, 3);

    let report = fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    assert_eq!(report.refused, None);
    assert_eq!(report.floor, floor);
    assert!(report.entries > 0 && report.bodies > 0 && report.index_rows > 0);

    let after = fixture.log();
    assert_eq!(after.next_forward(), before.next_forward());
    assert_eq!(after.next_backward(), before.next_backward());
    assert_eq!(after.head_chain(), before.head_chain());
    assert_eq!(after.forward_extremities(), before.forward_extremities());
    assert_eq!(fixture.state_ids(), state);
    assert_eq!(
        after.current_state().unwrap().root(),
        before.current_state().unwrap().root()
    );
    // What is left below the floor is only what the room still needs.
    assert!(after.len() < before.len());
    assert!(after.entries().filter(|e| e.li.get() >= floor).count() > 0);
    assert_eq!(
        after.entries().filter(|e| e.li.get() >= floor).count(),
        before.entries().filter(|e| e.li.get() >= floor).count()
    );

    // A restart rebuilds the registry from the rows.
    drop(fixture.rooms);
    let rooms = Rooms::new(Arc::clone(&fixture.store), SERVER);
    let mut ids: Vec<String> = rooms
        .state(&fixture.room)
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    assert_eq!(ids, state);
}

#[test]
fn exhaustive_load_verify_and_a_new_append_work_from_the_checkpoint() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();

    let report = spindle_store::verify::verify_store(fixture.store.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    let log = fixture.log();
    let checkpoint = log.chain_checkpoint().expect("a checkpoint was recorded");
    assert_eq!(checkpoint.floor, floor);
    assert_eq!(recomputed_head(&log), log.head_chain());

    let appended = fixture.send("after the truncation");
    let log = fixture.log();
    let entry = log.get(&EventId::new(appended.as_str())).unwrap();
    assert!(entry.chain.is_some());
    assert_eq!(recomputed_head(&log), log.head_chain());
    assert_eq!(
        log.head_chain(),
        entry.chain.unwrap(),
        "the new event extends the old head"
    );
    let report = spindle_store::verify::verify_store(fixture.store.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
}

#[test]
fn rows_below_the_floor_are_gone_and_the_rest_are_not() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    let log = fixture.log();
    let below: Vec<_> = log.entries().filter(|e| e.li.get() < floor).collect();
    let above = log.len() - below.len();
    let (log_rows, stream_rows, relation_rows, global_stream) = (
        fixture.rows(Keyspace::Log),
        fixture.rows(Keyspace::RoomStream),
        fixture.rows(Keyspace::Relation),
        ReadView::scan_prefix(fixture.store.as_ref(), &keyspace_prefix(Keyspace::Stream))
            .unwrap()
            .len(),
    );
    assert_eq!(log_rows, log.len());

    let report = fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    let kept_below = fixture
        .log()
        .entries()
        .filter(|e| e.li.get() < floor)
        .count();
    assert_eq!(fixture.rows(Keyspace::Log), above + kept_below);
    assert_eq!(report.entries, (below.len() - kept_below) as u64);
    // Every removed stream row left both indexes, and none above the floor did.
    let removed_streams = stream_rows - fixture.rows(Keyspace::RoomStream);
    assert!(removed_streams > 0);
    assert_eq!(
        global_stream - removed_streams,
        ReadView::scan_prefix(fixture.store.as_ref(), &keyspace_prefix(Keyspace::Stream))
            .unwrap()
            .len()
    );
    assert!(fixture.rows(Keyspace::Relation) < relation_rows);
    // The reactions above the floor still point at the first message.
    assert!(fixture.rows(Keyspace::Relation) > 0);
    assert!(fixture.rooms.messages(&fixture.room, None, 1000).is_ok());

    // A second call finds nothing to do, and reads next to nothing to say so.
    let scanned = fixture.store.scanned();
    let again = fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    assert_eq!((again.entries, again.bodies, again.index_rows), (0, 0, 0));
    assert!(
        fixture.store.scanned() - scanned < (log.len() / 2) as u64,
        "an idempotent run must not walk the room"
    );
    let _ = (&fixture.first_message, &fixture.dir);
}

#[test]
fn gc_frees_the_state_only_the_removed_roots_used() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    let before = spindle_store::gc::collect_state_nodes(fixture.store.as_ref(), true).unwrap();
    assert_eq!(before.swept, 0, "nothing is dead while every root is held");

    fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    let dry = spindle_store::gc::collect_state_nodes(fixture.store.as_ref(), true).unwrap();
    assert!(dry.swept > 0, "the removed topics' tries are collectable");
    assert!(dry.holders < before.holders);
    let swept = spindle_store::gc::collect_state_nodes(fixture.store.as_ref(), false).unwrap();
    assert_eq!(swept.swept, dry.swept);

    // The room is whole afterwards.
    let report = spindle_store::verify::verify_store(fixture.store.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    fixture.send("still writable");
}

#[test]
fn a_backup_of_a_truncated_room_restores_and_verifies() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    let head = fixture.log().head_chain();
    let state = fixture.state_ids();

    let mut bytes = Vec::new();
    spindle_store::backup::write_backup(fixture.store.as_ref(), &mut bytes).unwrap();
    let target = TempDir::new().unwrap();
    let restored = Arc::new(FjallStore::open(target.path()).unwrap());
    spindle_store::backup::read_backup(&mut bytes.as_slice(), restored.as_ref()).unwrap();

    let report = spindle_store::verify::verify_store(restored.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    let log = RoomStore::new(restored.as_ref(), fixture.room.as_str())
        .load_exhaustive()
        .unwrap()
        .unwrap()
        .log;
    assert_eq!(log.head_chain(), head);
    let rooms = Rooms::new(Arc::clone(&restored), SERVER);
    let mut ids: Vec<String> = rooms
        .state(&fixture.room)
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    assert_eq!(ids, state);
}

#[test]
fn paging_back_stops_cleanly_at_the_watermark() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    let kept = fixture.log();

    let mut seen = Vec::new();
    let mut from = None;
    loop {
        let (page, next) = fixture.rooms.messages(&fixture.room, from, 5).unwrap();
        assert!(
            page.iter()
                .all(|event| event.json["type"] != "m.room.redaction"),
            "no purge markers: every entry that is left has its body"
        );
        seen.extend(page.iter().map(|event| event.li));
        match next {
            Some(next) => from = Some(next),
            None => break,
        }
    }
    assert_eq!(seen.len(), kept.len());
    let oldest_unpinned = kept
        .entries()
        .filter(|e| e.chain.is_some())
        .map(|e| e.li.get())
        .min()
        .unwrap();
    assert!(oldest_unpinned >= floor);
}

#[test]
fn a_crash_after_the_checkpoint_leaves_a_consistent_room_that_finishes_later() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    let state = fixture.state_ids();
    let head = fixture.log().head_chain();
    let rows_before = fixture.rows(Keyspace::Log);

    // The checkpoint batch lands; its sync fails, as the machine dies.
    fixture.store.inject_fault(spindle_store::Fault::AtNextSync);
    assert!(
        fixture
            .rooms
            .truncate_room_log(&fixture.room, floor)
            .is_err()
    );
    let path = fixture.dir.path().to_path_buf();
    let room = fixture.room.clone();
    let (dir, first) = (fixture.dir, fixture.first_message);
    drop(fixture.rooms);
    drop(fixture.store);
    let store = Arc::new(FjallStore::open(&path).unwrap());

    let roomstore = RoomStore::new(store.as_ref(), room.as_str());
    let checkpoint = roomstore.chain_checkpoint().unwrap();
    assert_eq!(checkpoint.map(|point| point.floor), Some(floor));
    // Nothing was deleted yet, but the room already reads as truncated and verifies.
    assert_eq!(
        ReadView::scan_prefix(store.as_ref(), &room_prefix(Keyspace::Log, &room))
            .unwrap()
            .len(),
        rows_before
    );
    let report = spindle_store::verify::verify_store(store.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    let loaded = roomstore.load_exhaustive().unwrap().unwrap().log;
    assert_eq!(loaded.head_chain(), head);
    assert!(
        loaded.len() < rows_before,
        "leftovers below the floor are ignored"
    );

    // The next run finishes the deletes.
    let rooms = Rooms::new(Arc::clone(&store), SERVER);
    let report = rooms.truncate_room_log(&room, floor).unwrap();
    assert!(report.entries > 0 && report.bodies > 0);
    assert_eq!(
        ReadView::scan_prefix(store.as_ref(), &room_prefix(Keyspace::Log, &room))
            .unwrap()
            .len(),
        loaded.len()
    );
    let mut ids: Vec<String> = rooms
        .state(&room)
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    assert_eq!(ids, state);
    let report = spindle_store::verify::verify_store(store.as_ref()).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    let _ = (dir, first);
}

#[test]
fn the_floor_never_passes_an_extremity_or_the_head() {
    let fixture = fixture(4);
    let head = fixture.log().entries().next_back().unwrap().li.get();
    let report = fixture
        .rooms
        .truncate_room_log(&fixture.room, i64::MAX)
        .unwrap();
    assert_eq!(report.floor, head);
    let log = fixture.log();
    assert!(
        log.get(log.forward_extremities().iter().next().unwrap())
            .is_some()
    );
    fixture.send("the head is still there to extend");
}

/// Readers find the current state's events by ID. Their entries must
/// survive, or a banned user's departure point vanishes with the log row.
#[test]
fn the_entries_of_the_current_state_outlive_the_floor() {
    let fixture = fixture(12);
    let floor = fixture.watermark(2, 3);
    let departure = fixture.rooms.departure(&fixture.room, BOB).unwrap();
    assert!(
        departure.is_some_and(|li| li < floor),
        "the ban is below the floor"
    );

    fixture
        .rooms
        .truncate_room_log(&fixture.room, floor)
        .unwrap();
    assert_eq!(
        fixture.rooms.departure(&fixture.room, BOB).unwrap(),
        departure
    );
    let intervals = fixture
        .rooms
        .membership_intervals(&fixture.room, ALICE, false)
        .unwrap();
    assert_eq!(
        intervals.len(),
        1,
        "alice's open stint survives: {intervals:?}"
    );
    assert!(intervals[0].0 < floor && intervals[0].1 == i64::MAX);
}
