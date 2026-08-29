//! `scan_from` reads the tail of a prefix, and nothing else.
//!
//! The point of the primitive is what it does *not* read. A prefix scan with
//! a filter would return the same rows and cost the whole prefix, which is
//! the shape every "narrow question answered with a whole read" fix in this
//! repository has been about — so the assertions here are about the rows that
//! come back, and `scanned` is what proves the rest were never touched.

use spindle_store::{FjallStore, ReadView, Store};
use tempfile::TempDir;

/// Two neighbouring prefixes, `n` rows each, keys ending in a big-endian
/// counter so they sort the way the caller expects to seek into them.
fn seeded() -> (TempDir, FjallStore) {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    for prefix in [1u8, 2] {
        for index in 0u64..10 {
            let mut key = vec![prefix];
            key.extend_from_slice(&index.to_be_bytes());
            store.put(&key, &[u8::try_from(index).unwrap()]).unwrap();
        }
    }
    (dir, store)
}

fn key(prefix: u8, index: u64) -> Vec<u8> {
    let mut key = vec![prefix];
    key.extend_from_slice(&index.to_be_bytes());
    key
}

#[test]
fn a_scan_starts_where_it_is_told_and_stops_at_the_prefix() {
    let (_dir, store) = seeded();
    let rows = store.scan_from(&[1], &key(1, 7)).unwrap();
    let found: Vec<u64> = rows
        .iter()
        .map(|(key, _)| u64::from_be_bytes(key[1..].try_into().unwrap()))
        .collect();
    assert_eq!(
        found,
        vec![7, 8, 9],
        "the scan must begin at the start key and end at the prefix, not run \
         on into the neighbouring one"
    );
}

/// The cost is the tail, not the prefix.
///
/// This is the whole reason the method exists rather than a filter over
/// `scan_prefix`, and a counter is the only way to tell the two apart: both
/// return the same three rows.
#[test]
fn a_scan_does_not_touch_the_rows_before_its_start() {
    let (_dir, store) = seeded();
    let before = store.scanned();
    store.scan_from(&[1], &key(1, 7)).unwrap();
    assert_eq!(
        store.scanned() - before,
        3,
        "three rows were wanted; anything more means the rows before the \
         start key were read and discarded"
    );
}

#[test]
fn a_start_below_the_prefix_yields_the_whole_prefix() {
    let (_dir, store) = seeded();
    assert_eq!(store.scan_from(&[2], &[2]).unwrap().len(), 10);
}

#[test]
fn a_start_past_the_prefix_yields_nothing() {
    let (_dir, store) = seeded();
    assert!(store.scan_from(&[1], &key(1, 10)).unwrap().is_empty());
}

/// An empty prefix range is empty, not the rest of the store.
#[test]
fn a_prefix_with_no_rows_yields_nothing() {
    let (_dir, store) = seeded();
    assert!(store.scan_from(&[3], &[3]).unwrap().is_empty());
}
