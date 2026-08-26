//! Part of #6: a crash may lose a suffix of the log. It may never reorder it,
//! fork it, or leave a half-written commit visible.

use std::{cell::RefCell, collections::BTreeMap};

use spindle_core::RoomLog;
use spindle_store::{Durability, Record, RoomStore, Store, StoreError};

/// An in-memory store that stops accepting commits after a set number, the way
/// a machine losing power stops accepting them: abruptly, mid-workload.
///
/// Commits are all-or-nothing, mirroring the engine's batch semantics — that is
/// the property under test, so the fake must not be more forgiving than the
/// real thing.
struct FaultyStore {
    data: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
    commits_before_failure: RefCell<usize>,
    writes_seen: RefCell<usize>,
}

impl FaultyStore {
    fn new(commits_before_failure: usize) -> Self {
        Self {
            data: RefCell::new(BTreeMap::new()),
            commits_before_failure: RefCell::new(commits_before_failure),
            writes_seen: RefCell::new(0),
        }
    }
}

impl Store for FaultyStore {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.data.borrow_mut().insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.data.borrow().get(key).cloned())
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        Ok(self
            .data
            .borrow()
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn commit(&self, writes: &[Record], _durability: Durability) -> Result<(), StoreError> {
        let mut remaining = self.commits_before_failure.borrow_mut();
        if *remaining == 0 {
            // The power went out. Nothing from this batch lands.
            return Err(StoreError::Backend("injected fault".to_owned()));
        }
        *remaining -= 1;
        *self.writes_seen.borrow_mut() += writes.len();
        let mut data = self.data.borrow_mut();
        for (key, value) in writes {
            data.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

const ROOM: &str = "!room:example.org";

#[test]
fn a_crash_loses_only_a_suffix_and_never_reorders_or_forks() {
    let store = FaultyStore::new(37);
    let room_store = RoomStore::new(&store, ROOM);
    let mut log = RoomLog::new();

    let mut committed = 0_usize;
    for number in 0..100 {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        match room_store.commit_entry(&entry, &log, Durability::Strict) {
            Ok(()) => committed += 1,
            Err(_) => break,
        }
    }
    assert_eq!(committed, 37, "the fault should land where it was injected");

    let restored = room_store.load().unwrap().unwrap();

    // A prefix: exactly what was acknowledged, nothing more.
    assert_eq!(restored.log.len(), 37);
    assert!(restored.unverified.is_empty());

    // In order, contiguous, no holes and no duplicates -- the log did not
    // reorder or fork, it merely stopped.
    let indices: Vec<i64> = restored.log.entries().map(|entry| entry.li.get()).collect();
    assert_eq!(indices, (1..=37).collect::<Vec<_>>());

    let names: Vec<&str> = restored
        .log
        .entries()
        .map(|entry| entry.event_id.as_str())
        .collect();
    assert_eq!(names.first(), Some(&"$event-0"));
    assert_eq!(names.last(), Some(&"$event-36"));

    // The counters agree with the surviving log, so the next append takes the
    // next index rather than reissuing one already used.
    assert_eq!(restored.log.next_forward(), 38);
    assert_eq!(restored.log.forward_extremities().len(), 1);
}

#[test]
fn a_failed_commit_lands_nothing_at_all() {
    let store = FaultyStore::new(1);
    let room_store = RoomStore::new(&store, ROOM);
    let mut log = RoomLog::new();

    let first = log.append_local("$first", None).unwrap().clone();
    room_store
        .commit_entry(&first, &log, Durability::Strict)
        .unwrap();

    let second = log.append_local("$second", None).unwrap().clone();
    assert!(
        room_store
            .commit_entry(&second, &log, Durability::Strict)
            .is_err()
    );

    // The failed batch carried both the entry and the updated metadata. Neither
    // may be visible: a room whose metadata says two events but whose log holds
    // one is a forked read.
    let restored = room_store.load().unwrap().unwrap();
    assert_eq!(restored.log.len(), 1);
    assert_eq!(restored.log.next_forward(), 2);
}

#[test]
fn an_append_costs_a_fixed_number_of_writes() {
    // Guards the regression this path exists to fix: the previous full-rewrite
    // save was O(room) per append, which made a large room quadratic to fill.
    let store = FaultyStore::new(usize::MAX);
    let room_store = RoomStore::new(&store, ROOM);
    let mut log = RoomLog::new();

    for number in 0..50 {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, Durability::Group)
            .unwrap();
    }

    // Two writes per append: the entry, and the room metadata.
    assert_eq!(*store.writes_seen.borrow(), 100);
}

#[test]
fn every_durability_mode_commits() {
    for mode in [Durability::Strict, Durability::Group, Durability::Relaxed] {
        let store = FaultyStore::new(usize::MAX);
        let room_store = RoomStore::new(&store, ROOM);
        let mut log = RoomLog::new();
        let entry = log.append_local("$only", None).unwrap().clone();
        room_store.commit_entry(&entry, &log, mode).unwrap();
        assert_eq!(room_store.load().unwrap().unwrap().log.len(), 1, "{mode:?}");
    }
}
