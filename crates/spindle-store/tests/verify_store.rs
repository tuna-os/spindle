//! #818: `spindle verify` answers "is this store intact?" for every room, and
//! a failed read is an error, not a missing node.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use spindle_core::keys::{Keyspace, keyspace_prefix};
use spindle_core::{RoomLog, StateKey, StateKeyTable};
use spindle_store::verify::verify_store;
use spindle_store::{Durability, FjallStore, ReadView, Record, RoomStore, Store, StoreError};
use tempfile::TempDir;

fn seed(store: &impl Store, room: &str, entries: usize) {
    let room_store = RoomStore::new(store, room);
    let mut log = RoomLog::new(store.key_table());
    for index in 0..entries {
        let key = StateKey::new("m.room.member", format!("@u{index}:example.org"));
        let entry = log
            .append_local(format!("${room}-{index}"), Some(key))
            .unwrap()
            .clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }
}

/// A store whose state-node reads fail on demand, as a disk fault does.
struct FlakyReads {
    inner: FjallStore,
    failing: AtomicBool,
}

const FAULT: &str = "injected read fault";

impl ReadView for FlakyReads {
    fn key_table(&self) -> Arc<dyn StateKeyTable> {
        self.inner.key_table()
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if self.failing.load(Ordering::Relaxed)
            && key.starts_with(&keyspace_prefix(Keyspace::StateNode))
        {
            return Err(StoreError::Backend(FAULT.to_owned()));
        }
        self.inner.get(key)
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        self.inner.scan_prefix(prefix)
    }

    fn scan_from(&self, prefix: &[u8], start: &[u8]) -> Result<Vec<Record>, StoreError> {
        self.inner.scan_from(prefix, start)
    }

    fn scan_until(
        &self,
        prefix: &[u8],
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Record>, StoreError> {
        self.inner.scan_until(prefix, start, end)
    }
}

impl Store for FlakyReads {
    fn accepts_writes(&self) -> bool {
        self.inner.accepts_writes()
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.inner.put(key, value)
    }

    fn delete(&self, key: &[u8]) -> Result<(), StoreError> {
        self.inner.delete(key)
    }

    fn commit(&self, writes: &[Record], durability: Durability) -> Result<(), StoreError> {
        self.inner.commit(writes, durability)
    }

    fn commit_deferred(&self, writes: &[Record]) -> Result<(), StoreError> {
        self.inner.commit_deferred(writes)
    }

    fn commit_ops_deferred(&self, ops: &[spindle_store::BatchOp]) -> Result<(), StoreError> {
        self.inner.commit_ops_deferred(ops)
    }

    fn sync(&self, durability: Durability) -> Result<(), StoreError> {
        self.inner.sync(durability)
    }

    fn flush(&self) -> Result<(), StoreError> {
        self.inner.flush()
    }
}

#[test]
fn an_intact_store_verifies_and_a_missing_node_is_named() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store, "!a:example.org", 20);
    seed(&store, "!b:example.org", 20);
    let report = verify_store(&store).unwrap();
    assert!(report.is_intact(), "{:?}", report.problems);
    assert_eq!((report.rooms, report.entries), (2, 40));

    // Damage a node only a deep check reads: one under an early root.
    let (key, _) = store
        .scan_prefix(&keyspace_prefix(Keyspace::StateNode))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    Store::delete(&store, &key).unwrap();
    let report = verify_store(&store).unwrap();
    assert!(!report.is_intact(), "a missing node must fail verify");
}

/// A read error reaches the operator as itself. Before, the node lookup
/// turned it into "missing", so the report blamed the room's data for a
/// fault in the disk.
#[test]
fn a_read_error_is_reported_as_an_error_not_a_missing_node() {
    let dir = TempDir::new().unwrap();
    let store = FlakyReads {
        inner: FjallStore::open(dir.path()).unwrap(),
        failing: AtomicBool::new(false),
    };
    seed(&store, "!a:example.org", 20);
    assert!(verify_store(&store).unwrap().is_intact());

    store.failing.store(true, Ordering::Relaxed);
    let report = verify_store(&store).unwrap();
    assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
    let (room, error) = &report.problems[0];
    assert_eq!(room, "!a:example.org");
    assert!(error.to_string().contains(FAULT), "{error}");

    // The serving paths must not swallow it either.
    let error = RoomStore::new(&store, "!a:example.org")
        .load_runtime()
        .unwrap_err();
    assert!(error.to_string().contains(FAULT), "{error}");
}
