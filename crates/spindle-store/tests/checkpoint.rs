//! #6: a room can be read while it is being written, and never comes back torn.
//!
//! Rebuilding a room takes two reads — the metadata, then the log. A commit
//! landing between them produces a room whose counters and log disagree, and
//! one direction of that disagreement is not merely wrong but unsafe: metadata
//! trailing the log means `next_forward` names an index the log already holds,
//! so the next append reissues it. That is the fork storage ordering exists to
//! make impossible, arrived at through a backup rather than through a crash.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use spindle_core::RoomLog;
use spindle_store::{Durability, FjallStore, ReadView, RoomStore, Store};
use tempfile::TempDir;

const ROOM: &str = "!checkpoint:example.org";

/// Every read through one checkpoint sees the same moment, whatever lands after.
#[test]
fn a_checkpoint_does_not_see_writes_that_land_after_it() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let room_store = RoomStore::new(&store, ROOM);

    let mut log = RoomLog::new();
    for number in 0..10 {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }

    let checkpoint = store.snapshot().expect("fjall provides snapshot isolation");
    let prefix = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Log, ROOM);
    let before = checkpoint.scan_prefix(&prefix).unwrap().len();
    assert_eq!(before, 10);

    for number in 10..30 {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }

    assert_eq!(
        checkpoint.scan_prefix(&prefix).unwrap().len(),
        before,
        "the checkpoint moved after later commits landed"
    );
    // ...while a live read does see them, so the test is not passing because
    // nothing was written.
    assert_eq!(store.scan_prefix(&prefix).unwrap().len(), 30);
}

/// The property that matters, under real concurrency: a load taken while
/// another thread is appending must return a room that is internally
/// consistent, not merely one that parses.
#[test]
fn a_room_read_during_concurrent_appends_is_never_torn() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());

    // Seed, so the reader has something to find immediately.
    {
        let room_store = RoomStore::new(store.as_ref(), ROOM);
        let mut log = RoomLog::new();
        let entry = log.append_local("$seed", None).unwrap().clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let room_store = RoomStore::new(store.as_ref(), ROOM);
            let mut log = room_store.load().unwrap().unwrap().log;
            let mut number = 0_u32;
            // Bounded: every read rebuilds the whole room, so an unbounded
            // writer makes the test quadratic in wall time and tells us nothing
            // extra -- the race either exists in the first hundred commits or
            // it does not.
            while number < 400 && !stop.load(Ordering::Relaxed) {
                let entry = log
                    .append_local(format!("$concurrent-{number}"), None)
                    .unwrap()
                    .clone();
                room_store
                    .commit_entry(&entry, &log, Durability::Relaxed)
                    .unwrap();
                number += 1;
            }
            number
        })
    };

    let room_store = RoomStore::new(store.as_ref(), ROOM);
    let mut reads = 0;
    for _ in 0..60 {
        let restored = room_store.load().unwrap().expect("the room exists");
        let log = &restored.log;
        let head = log.entries().next_back().expect("a seeded room has a head");

        // Counters must agree with the log they were committed alongside.
        assert_eq!(
            log.next_forward(),
            head.li.get() + 1,
            "next_forward disagrees with the log: the next append would reissue \
             an index the log already holds"
        );
        // And the extremity set must name the head, not some earlier event.
        assert_eq!(
            log.forward_extremities().len(),
            1,
            "a linear room has exactly one extremity"
        );
        assert!(
            log.forward_extremities().contains(&head.event_id),
            "the recorded extremity is not the head of the log it came with"
        );
        assert!(
            restored.broken_chain.is_empty(),
            "the chain must verify on a consistent read: {:?}",
            restored.broken_chain
        );
        reads += 1;
    }

    stop.store(true, Ordering::Relaxed);
    let appended = writer.join().unwrap();

    assert_eq!(reads, 60);
    assert!(
        appended > 0,
        "the writer never committed, so nothing was read concurrently"
    );
}
