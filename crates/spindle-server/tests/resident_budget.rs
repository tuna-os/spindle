//! #816: open rooms are bounded by `[storage] max_resident_rooms`.
//!
//! Each assertion counts rooms, loads and linear indexes; none depends on
//! timing. A room dropped from memory must come back from the store exactly
//! as a restart would bring it back.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::metrics::Metrics;
use spindle_server::rooms::Rooms;
use spindle_store::FjallStore;
use tempfile::TempDir;

const SERVER: &str = "example.org";
const ALICE: &str = "@alice:example.org";
const ROOMS: usize = 10;
const BUDGET: usize = 3;

fn store() -> (TempDir, Arc<FjallStore>) {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    (dir, store)
}

fn message(n: usize) -> Value {
    json!({ "msgtype": "m.text", "body": format!("message {n}") })
}

/// Everything a client or a peer could tell apart about a room.
#[derive(Debug, PartialEq)]
struct Fingerprint {
    state: Vec<String>,
    messages: Vec<(String, i64)>,
    next_forward: i64,
    head_chain: String,
    extremities: Vec<String>,
}

/// Reads a room through the API, which loads it if need be. The room's lock
/// is not kept past the call.
fn fingerprint(rooms: &Rooms, room_id: &str) -> Fingerprint {
    let mut state: Vec<String> = rooms
        .state(room_id)
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect();
    state.sort();
    let (events, _) = rooms.messages(room_id, None, 10_000).unwrap();
    let lock = rooms.lock_for_test(room_id).unwrap();
    let log = lock.read().unwrap();
    Fingerprint {
        state,
        messages: events
            .into_iter()
            .map(|event| (event.event_id, event.li))
            .collect(),
        next_forward: log.next_forward(),
        head_chain: format!("{:?}", log.head_chain()),
        extremities: log
            .forward_extremities()
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect(),
    }
}

/// `ROOMS` rooms written with no limit, and what each looked like.
fn seed(
    store: &Arc<FjallStore>,
) -> (
    spindle_server::signing::ServerKey,
    Vec<String>,
    Vec<Fingerprint>,
) {
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = Rooms::new(Arc::clone(store), SERVER);
    let mut ids = Vec::new();
    for index in 0..ROOMS {
        let room = create(&rooms, &key, index);
        for n in 0..6 {
            rooms
                .send(&room, ALICE, key.pair(), "m.room.message", &message(n))
                .unwrap();
        }
        ids.push(room);
    }
    let prints = ids.iter().map(|room| fingerprint(&rooms, room)).collect();
    (key, ids, prints)
}

fn create(rooms: &Rooms, key: &spindle_server::signing::ServerKey, index: usize) -> String {
    rooms
        .create(
            ALICE,
            key.pair(),
            Some(&format!("room {index}")),
            None,
            None,
            &[],
            &[],
            None,
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap()
}

fn limited(store: &Arc<FjallStore>, limit: usize) -> (Rooms, Arc<Metrics>) {
    let metrics = Arc::new(Metrics::new());
    let rooms = Rooms::with_metrics(Arc::clone(store), SERVER, Arc::clone(&metrics));
    rooms.set_max_resident_rooms(limit);
    (rooms, metrics)
}

/// The next send lands on the very next index, with the old head still
/// directly below it: no fork, no index issued twice.
fn assert_next_send_is_consecutive(
    rooms: &Rooms,
    key: &spindle_server::signing::ServerKey,
    room: &str,
    before: &Fingerprint,
) {
    let sent = rooms
        .send(room, ALICE, key.pair(), "m.room.message", &message(99))
        .unwrap();
    let after = fingerprint(rooms, room);
    assert_eq!(after.messages[0], (sent, before.next_forward), "{room}");
    assert_eq!(after.messages[1], before.messages[0], "{room}");
    assert_eq!(after.next_forward, before.next_forward + 1, "{room}");
    assert_eq!(after.extremities.len(), 1, "{room}: the room forked");
}

#[test]
fn resident_rooms_stay_within_the_budget_and_each_reloads_exactly() {
    let (_dir, store) = store();
    let (key, ids, before) = seed(&store);
    let (rooms, metrics) = limited(&store, BUDGET);

    for (room, expected) in ids.iter().zip(&before) {
        assert_eq!(&fingerprint(&rooms, room), expected, "{room}");
        assert!(rooms.resident_count().unwrap() <= BUDGET as u64);
    }
    assert_eq!(metrics.cold_loads_total(), ROOMS as u64);
    assert_eq!(metrics.rooms_evicted(), (ROOMS - BUDGET) as u64);
    assert!(
        metrics
            .render()
            .contains(&format!("spindle_rooms_evicted_total {}", ROOMS - BUDGET))
    );

    // Every room, evicted or not, again and in the other order: each load
    // is identical, and the budget holds throughout.
    for (room, expected) in ids.iter().zip(&before).rev() {
        assert_eq!(&fingerprint(&rooms, room), expected, "{room} (second pass)");
        assert!(rooms.resident_count().unwrap() <= BUDGET as u64);
    }
    for (room, expected) in ids.iter().zip(&before) {
        assert_next_send_is_consecutive(&rooms, &key, room, expected);
        assert!(rooms.resident_count().unwrap() <= BUDGET as u64);
    }
}

#[test]
fn evicted_rooms_keep_their_indexes_across_a_restart() {
    let (_dir, store) = store();
    let (key, ids, before) = seed(&store);
    {
        let (rooms, _) = limited(&store, BUDGET);
        // Write through a room that has been evicted and reloaded.
        for room in &ids {
            fingerprint(&rooms, room);
            assert!(rooms.resident_count().unwrap() <= BUDGET as u64);
        }
        for (room, expected) in ids.iter().zip(&before) {
            assert_next_send_is_consecutive(&rooms, &key, room, expected);
        }
    }
    let (restarted, _) = limited(&store, BUDGET);
    for (room, expected) in ids.iter().zip(&before) {
        let now = fingerprint(&restarted, room);
        assert_eq!(now.next_forward, expected.next_forward + 1, "{room}");
        assert_eq!(now.messages.len(), expected.messages.len() + 1, "{room}");
        let again = restarted
            .send(room, ALICE, key.pair(), "m.room.message", &message(100))
            .unwrap();
        let after = fingerprint(&restarted, room);
        assert_eq!(after.messages[0], (again, now.next_forward), "{room}");
        assert_eq!(after.extremities.len(), 1, "{room}: the room forked");
    }
}

#[test]
fn a_room_in_use_is_never_evicted() {
    let (_dir, store) = store();
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let (rooms, metrics) = limited(&store, 1);
    let busy = create(&rooms, &key, 0);
    // An in-flight reader or federation task holds the room's lock `Arc`.
    let held = rooms.lock_for_test(&busy).unwrap();
    for index in 1..5 {
        create(&rooms, &key, index);
        assert!(rooms.is_resident(&busy), "evicted while held");
        assert!(rooms.resident_count().unwrap() <= 2);
    }
    assert_eq!(metrics.rooms_evicted(), 4);
    drop(held);

    // Once released, it is the room idle the longest, and the next room
    // opened past the budget takes it out.
    create(&rooms, &key, 5);
    assert!(!rooms.is_resident(&busy));
    assert_eq!(rooms.resident_count(), Some(1));
}

#[test]
fn eviction_leaves_no_cache_for_the_room() {
    let (_dir, store) = store();
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let (rooms, _) = limited(&store, 1);
    let first = create(&rooms, &key, 0);
    rooms
        .send(&first, ALICE, key.pair(), "m.room.message", &message(0))
        .unwrap();
    rooms.last_activity(&first).unwrap();
    rooms.state(&first).unwrap();
    assert!(rooms.holds_caches_for(&first), "nothing was cached to drop");

    let second = create(&rooms, &key, 1);
    assert!(!rooms.is_resident(&first));
    assert!(!rooms.holds_caches_for(&first), "a cache outlived the room");
    assert!(rooms.holds_caches_for(&second));
}
