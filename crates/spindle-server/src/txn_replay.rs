//! The replay table for inbound `/send` transactions (#814).
//!
//! A peer's retry loop is at-least-once, so the first answer to a
//! transaction is stored and served again if the same transaction arrives.
//! Peers retry within minutes. The table used to keep every row forever: one
//! row for each transaction, EDU-only ones included, each with a result for
//! every PDU, and the transaction IDs are the peer's to choose.
//!
//! A row is now `received_ms` (8 bytes, big-endian) then the response JSON,
//! and each origin's rows older than [`REPLAY_TTL_MS`] are deleted by a
//! sweep that its own `/send` triggers, at most once in [`SWEEP_EVERY_MS`].
//! The time is in the value, not the key, so no key moves: a row written
//! before this change is plain JSON (it starts with `{`, and a millisecond
//! clock does not), reads as before, and is swept on the origin's next sweep.
//! A row that a sweep removes early only means that a very late retry is
//! processed again, which the duplicate handling of every PDU already allows.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use spindle_core::keys;
use spindle_store::{Store, StoreError};

/// How long an answer is kept. Far past any retry interval a peer uses.
pub(crate) const REPLAY_TTL_MS: u64 = 60 * 60 * 1000;

/// The least time between two sweeps for one origin. A sweep reads that
/// origin's rows, so it must not run on every transaction of a busy one.
const SWEEP_EVERY_MS: u64 = 60 * 1000;

/// The most rows one sweep removes, so that a first sweep over a long
/// backlog is spread over several transactions instead of stalling one.
const SWEEP_BATCH: usize = 5_000;

/// The origins that have a sweep time, so the map is bounded: past this it
/// is emptied, which only makes the next sweeps early.
const TRACKED_ORIGINS: usize = 4_096;

/// A stored row: the time it was written, then the response.
pub(crate) fn encode(received_ms: u64, response: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(8 + response.len());
    row.extend_from_slice(&received_ms.to_be_bytes());
    row.extend_from_slice(response);
    row
}

/// The write time of a row and its response. A row from before the time was
/// stored has no time and is all response.
pub(crate) fn decode(row: &[u8]) -> (Option<u64>, &[u8]) {
    if row.first() == Some(&b'{') || row.len() < 8 {
        return (None, row);
    }
    let (time, response) = row.split_at(8);
    (
        <[u8; 8]>::try_from(time).ok().map(u64::from_be_bytes),
        response,
    )
}

/// Delete `origin`'s rows older than the TTL, up to [`SWEEP_BATCH`] of them.
/// Rows with no time (written before this change) are older than any TTL.
///
/// Returns how many rows were removed.
///
/// # Errors
///
/// Returns a storage error if the scan or a delete fails.
pub(crate) fn sweep_origin(
    store: &dyn Store,
    origin: &str,
    now_ms: u64,
) -> Result<usize, StoreError> {
    let mut expired = Vec::new();
    store
        .visit_prefix(&keys::federation_txn_origin(origin), &mut |key, row| {
            let (received, _) = decode(row);
            if received.is_none_or(|at| now_ms.saturating_sub(at) > REPLAY_TTL_MS) {
                expired.push(key.to_vec());
                if expired.len() >= SWEEP_BATCH {
                    // Stops the scan; the rows found so far are the batch.
                    return Err(StoreError::Backend("sweep batch full".to_owned()));
                }
            }
            Ok(())
        })
        .or_else(|error| {
            if expired.len() >= SWEEP_BATCH {
                Ok(())
            } else {
                Err(error)
            }
        })?;
    for key in &expired {
        store.delete(key)?;
    }
    Ok(expired.len())
}

/// Whether `origin` is due a sweep at `now_ms`; and if so, record that it
/// has had one.
pub(crate) fn sweep_due(origin: &str, now_ms: u64) -> bool {
    static LAST: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    let mut last = LAST
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if last.len() >= TRACKED_ORIGINS {
        last.clear();
    }
    match last.get(origin) {
        Some(&at) if now_ms.saturating_sub(at) < SWEEP_EVERY_MS => false,
        _ => {
            last.insert(origin.to_owned(), now_ms);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_store::{FjallStore, ReadView};

    fn put(store: &FjallStore, origin: &str, txn: &str, row: &[u8]) {
        store.put(&keys::federation_txn(origin, txn), row).unwrap();
    }

    fn held(store: &FjallStore, origin: &str, txn: &str) -> bool {
        store
            .get(&keys::federation_txn(origin, txn))
            .unwrap()
            .is_some()
    }

    #[test]
    fn a_row_keeps_its_time_and_its_response() {
        let row = encode(1_700_000_000_000, br#"{"pdus":{}}"#);
        let (at, response) = decode(&row);
        assert_eq!(at, Some(1_700_000_000_000));
        assert_eq!(response, br#"{"pdus":{}}"#);
        // A row from before the time was stored is all response.
        assert_eq!(
            decode(br#"{"pdus":{}}"#),
            (None, br#"{"pdus":{}}"# as &[u8])
        );
    }

    #[test]
    fn a_sweep_removes_old_and_untimed_rows_of_one_origin_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let now = 10 * REPLAY_TTL_MS;
        put(
            &store,
            "a.example",
            "old",
            &encode(now - REPLAY_TTL_MS - 1, b"{}"),
        );
        put(&store, "a.example", "fresh", &encode(now - 1_000, b"{}"));
        put(&store, "a.example", "legacy", b"{\"pdus\":{}}");
        // Another origin, and one whose name this one is a prefix of.
        put(&store, "b.example", "old", &encode(0, b"{}"));
        put(&store, "a.example.org", "old", &encode(0, b"{}"));

        let removed = sweep_origin(&store, "a.example", now).unwrap();

        assert_eq!(removed, 2);
        assert!(!held(&store, "a.example", "old"));
        assert!(!held(&store, "a.example", "legacy"));
        assert!(
            held(&store, "a.example", "fresh"),
            "a fresh row is the point"
        );
        assert!(
            held(&store, "b.example", "old"),
            "another origin is untouched"
        );
        assert!(
            held(&store, "a.example.org", "old"),
            "a longer name is not this origin"
        );
    }

    #[test]
    fn rows_do_not_pile_up_while_one_origin_keeps_sending() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        // A transaction a minute for two days, with the sweep the handler
        // runs: the table holds about an hour of them, not two days.
        for minute in 0..(48 * 60_u64) {
            let now = minute * 60_000;
            put(
                &store,
                "busy.example",
                &format!("t{minute}"),
                &encode(now, b"{}"),
            );
            if sweep_due("busy.example", now) {
                sweep_origin(&store, "busy.example", now).unwrap();
            }
        }
        let rows = store
            .scan_prefix(&keys::federation_txn_origin("busy.example"))
            .unwrap()
            .len();
        assert!(rows <= 62, "{rows} rows are held; an hour is about 60");
    }
}
