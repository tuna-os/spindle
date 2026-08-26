//! #6: a store this binary cannot read is refused, not silently read as empty.
//!
//! Every key carries the key-schema version in its first byte, which stops two
//! layouts being confused for one another. What it does *not* do is let a
//! binary notice a version it does not speak: a scan is a prefix scan, so
//! looking under version 1 for a store written at version 2 finds no keys at
//! all. An empty store is a plausible thing to find, so nothing is reported,
//! and the server starts serving a room whose history it cannot see.
//!
//! The first test below demonstrates that silence directly. The rest are the
//! marker that replaces it with a refusal.

use spindle_core::{RoomLog, keys};
use spindle_store::{Durability, FjallStore, ReadView, RoomStore, SchemaMarker, Store, StoreError};
use tempfile::TempDir;

const ROOM: &str = "!schema:example.org";

fn seed(store: &FjallStore) {
    let room_store = RoomStore::new(store, ROOM);
    let mut log = RoomLog::new();
    for number in 0..5 {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, Durability::Strict)
            .unwrap();
    }
}

/// The failure the marker exists to prevent, shown rather than asserted about.
///
/// A version bump rewrites every key under a different schema byte. Without a
/// marker the room does not come back wrong — it does not come back at all, and
/// the store reports that as "no such room".
#[test]
fn without_the_marker_a_newer_store_is_indistinguishable_from_an_empty_one() {
    let source = TempDir::new().unwrap();
    let store = FjallStore::open(source.path()).unwrap();
    seed(&store);
    let rows: Vec<_> = store.scan_prefix(&[keys::KEY_SCHEMA_VERSION]).unwrap();
    assert!(
        !rows.is_empty(),
        "the room is there before the schema moves"
    );

    // Build what a version-2 binary would have written: the same rows, every
    // key under schema byte 2, and nothing under byte 1.
    let future_dir = TempDir::new().unwrap();
    let future_store = FjallStore::open(future_dir.path()).unwrap();
    for (key, value) in &rows {
        let mut moved = key.clone();
        moved[0] = 2;
        future_store.put(&moved, value).unwrap();
    }
    future_store.flush().unwrap();

    // A version-1 reader finds nothing in it. Not an error, not a warning: the
    // room reads exactly like one that never existed.
    let missing = RoomStore::new(&future_store, ROOM).load().unwrap();
    let never_existed = RoomStore::new(&future_store, "!never-existed:example.org")
        .load()
        .unwrap();
    assert!(missing.is_none(), "the whole room is invisible");
    assert!(never_existed.is_none());
    // Identical outcomes for "your history is unreadable" and "no such room",
    // which is the entire problem the marker solves.

    // With the marker moved too — as a real version-2 writer would move it —
    // the same store refuses to open instead of reading as empty.
    let future = SchemaMarker {
        key_schema: 2,
        record: 1,
    };
    future_store
        .put(&keys::store_marker(), &future.encode())
        .unwrap();
    future_store.flush().unwrap();
    drop(future_store);
    assert!(
        matches!(
            FjallStore::open(future_dir.path()),
            Err(StoreError::UnsupportedSchema { .. })
        ),
        "a marked version-2 store must refuse rather than read as empty"
    );
}

#[test]
fn opening_a_fresh_store_stamps_the_current_schema() {
    let dir = TempDir::new().unwrap();
    {
        let store = FjallStore::open(dir.path()).unwrap();
        let raw = store
            .get(&keys::store_marker())
            .unwrap()
            .expect("open must stamp an unmarked store");
        assert_eq!(SchemaMarker::decode(&raw).unwrap(), SchemaMarker::current());
    }

    // And reopening a store it already stamped is not an error.
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store);
    drop(store);
    FjallStore::open(dir.path()).expect("a matching marker reopens cleanly");
}

/// The refusal. A store from a future binary must not open at all.
#[test]
fn a_store_from_a_newer_schema_is_refused_with_both_versions_named() {
    let dir = TempDir::new().unwrap();
    {
        let store = FjallStore::open(dir.path()).unwrap();
        seed(&store);
        // Stamp it as though a newer binary had written it.
        let future = SchemaMarker {
            key_schema: keys::KEY_SCHEMA_VERSION + 1,
            record: 7,
        };
        store.put(&keys::store_marker(), &future.encode()).unwrap();
        store.flush().unwrap();
    }

    let Err(error) = FjallStore::open(dir.path()) else {
        panic!("a newer store must be refused");
    };
    match error {
        StoreError::UnsupportedSchema { found, supported } => {
            assert_eq!(found.key_schema, keys::KEY_SCHEMA_VERSION + 1);
            assert_eq!(found.record, 7);
            assert_eq!(supported, SchemaMarker::current());
            // The message has to name both, or an operator cannot tell which
            // binary to reach for.
            let rendered = error_text(&StoreError::UnsupportedSchema { found, supported });
            assert!(rendered.contains(&found.key_schema.to_string()));
            assert!(rendered.contains(&supported.key_schema.to_string()));
        }
        other => panic!("expected a schema refusal, got {other:?}"),
    }
}

/// A marker whose own encoding this binary does not know is also a refusal,
/// not a decode that happens to line up.
#[test]
fn a_marker_from_an_unknown_marker_version_is_refused() {
    let dir = TempDir::new().unwrap();
    {
        let store = FjallStore::open(dir.path()).unwrap();
        store.put(&keys::store_marker(), &[99, 1, 1]).unwrap();
        store.flush().unwrap();
    }
    assert!(
        FjallStore::open(dir.path()).is_err(),
        "an unreadable marker must refuse, not fall through to the room keys"
    );
}

fn error_text(error: &StoreError) -> String {
    format!("{error}")
}
