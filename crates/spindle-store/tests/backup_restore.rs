//! #20: a backup an operator can trust, and a restore that refuses what it
//! cannot read.
//!
//! The exit criterion is "automated backup/restore produces an independently
//! verified equivalent server". Each test below is one way that fails, and
//! every one of them fails *quietly* without a check: a backup nobody can
//! restore looks exactly like a backup nobody has needed yet.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use spindle_core::RoomLog;
use spindle_store::backup::{BackupError, read_backup, write_backup};
use spindle_store::{Durability, FjallStore, ReadView, RoomStore, SchemaMarker, Store};
use tempfile::TempDir;

const ROOM: &str = "!backup:example.org";

fn seed(store: &FjallStore, events: usize) {
    let room_store = RoomStore::new(store, ROOM);
    let mut log = RoomLog::new();
    for number in 0..events {
        let entry = log.append_local(format!("$event-{number}"), None).unwrap();
        let entry = entry.clone();
        room_store
            .commit_entry(&entry, &log, Durability::Strict)
            .unwrap();
    }
}

fn backup_of(store: &FjallStore) -> Vec<u8> {
    let mut out = Vec::new();
    let snapshot = store.snapshot();
    let view: &dyn ReadView = snapshot.as_deref().unwrap_or(store);
    write_backup(view, &mut out).expect("a backup is written");
    out
}

/// Restoring a backup reproduces every row the source held.
#[test]
fn a_restored_store_holds_what_the_backup_held() {
    let source_dir = TempDir::new().unwrap();
    let source = FjallStore::open(source_dir.path()).unwrap();
    seed(&source, 12);
    let expected = source.scan_prefix(&[]).unwrap();
    assert!(!expected.is_empty(), "the source has rows to back up");

    let bytes = backup_of(&source);

    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    let restored = read_backup(&mut bytes.as_slice(), &target).expect("the backup restores");

    let actual = target.scan_prefix(&[]).unwrap();
    assert_eq!(
        actual, expected,
        "the restored store is not row-for-row the source"
    );
    assert_eq!(restored, expected.len() as u64);

    // And the room reads back through the ordinary path, not just as bytes.
    let rebuilt = RoomStore::new(&target, ROOM)
        .load()
        .unwrap()
        .expect("the room is there after a restore");
    assert!(
        rebuilt.broken_chain.is_empty(),
        "the restored room's chain does not verify: {:?}",
        rebuilt.broken_chain,
    );
}

/// A truncated backup is refused, not restored as far as it goes.
///
/// This is the failure an operator meets at the worst possible moment: a
/// restore that reports success and silently drops the tail. Half a store is
/// worse than a refusal, because a refusal sends them to the other backup.
///
/// Caught by the *framing* rather than the digest — a cut stream runs out of
/// bytes before the trailer is reached — so this test passes even with the
/// digest check removed. `an_altered_backup_is_refused` is what proves the
/// digest; the two cover different corruptions and neither substitutes for
/// the other.
#[test]
fn a_truncated_backup_is_refused() {
    let source_dir = TempDir::new().unwrap();
    let source = FjallStore::open(source_dir.path()).unwrap();
    seed(&source, 12);
    let bytes = backup_of(&source);

    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    let cut = &bytes[..bytes.len() - 40];
    let error = read_backup(&mut &cut[..], &target).expect_err("a truncated backup is refused");
    assert!(
        matches!(
            error,
            BackupError::Io(_) | BackupError::DigestMismatch | BackupError::CountMismatch { .. }
        ),
        "unexpected error for a truncated backup: {error}",
    );
}

/// A backup whose bytes were altered is refused.
#[test]
fn an_altered_backup_is_refused() {
    let source_dir = TempDir::new().unwrap();
    let source = FjallStore::open(source_dir.path()).unwrap();
    seed(&source, 8);
    let mut bytes = backup_of(&source);

    // Flip a byte in the middle: a row's payload, not the framing.
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;

    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    match read_backup(&mut bytes.as_slice(), &target) {
        Err(BackupError::DigestMismatch) => {}
        // A flip inside a length field can derail the framing first. Either
        // way it must not be reported as a successful restore.
        Err(other) => assert!(
            !matches!(other, BackupError::Store(_)),
            "unexpected error for an altered backup: {other}",
        ),
        Ok(rows) => panic!("an altered backup restored {rows} rows as though it were sound"),
    }
}

/// Something that is not a backup is named as such.
#[test]
fn a_file_that_is_not_a_backup_is_named_as_such() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let error = read_backup(&mut &b"this is a config file, not a backup"[..], &store)
        .expect_err("a non-backup is refused");
    assert!(matches!(error, BackupError::NotABackup), "{error}");
    assert!(error.to_string().contains("not a Spindle backup"));
}

/// A backup written under a schema this binary does not speak is refused.
///
/// The same rule that governs opening a store (#78), applied one directory
/// further out. Restoring it would put rows this binary cannot interpret into
/// a store that then opens cleanly — the silent wrongness the marker exists to
/// prevent, arrived at through a restore.
#[test]
fn a_backup_from_another_schema_is_refused() {
    let source_dir = TempDir::new().unwrap();
    let source = FjallStore::open(source_dir.path()).unwrap();
    seed(&source, 4);
    let bytes = backup_of(&source);

    // Rewrite the marker inside the stream as a newer binary would have
    // written it. The digest no longer matches either; the schema check comes
    // first, and that ordering is the point — the operator is told *why* the
    // backup is unreadable, not merely that it is.
    let marker = SchemaMarker::current().encode();
    let future = SchemaMarker {
        record: SchemaMarker::current().record + 1,
        ..SchemaMarker::current()
    }
    .encode();
    let at = bytes
        .windows(marker.len())
        .position(|window| window == marker.as_slice())
        .expect("the stream carries the marker");
    let mut altered = bytes.clone();
    altered[at..at + marker.len()].copy_from_slice(&future);

    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    let error =
        read_backup(&mut altered.as_slice(), &target).expect_err("another schema is refused");
    match error {
        BackupError::UnsupportedSchema { found, supported } => {
            assert_eq!(found.record, supported.record + 1);
            assert_eq!(supported, SchemaMarker::current());
        }
        other => panic!("expected UnsupportedSchema, got {other}"),
    }
}

/// A backup taken while the store is being written is of one moment.
///
/// This is why the backup goes through a snapshot rather than the live store.
/// Row-by-row against a moving store, a commit landing mid-scan yields a
/// backup whose metadata trails its log — and the first append after that
/// restore reissues an index the log already holds, which is the fork the
/// storage ordering exists to make impossible.
#[test]
fn a_backup_taken_under_writes_is_of_one_moment() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    seed(&store, 10);

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let room_store = RoomStore::new(store.as_ref(), ROOM);
            // Rebuild the log the committed rows describe, then keep going.
            let mut log = room_store.load().unwrap().expect("the room is there").log;
            let mut number = 1000;
            while !stop.load(Ordering::SeqCst) {
                let Ok(entry) = log.append_local(format!("$late-{number}"), None) else {
                    break;
                };
                let entry = entry.clone();
                room_store
                    .commit_entry(&entry, &log, Durability::Relaxed)
                    .unwrap();
                number += 1;
            }
        })
    };

    let bytes = backup_of(&store);
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();

    // The backup restores, and what it restores is internally consistent: the
    // room rebuilds, which is exactly what a torn backup would fail to do.
    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    read_backup(&mut bytes.as_slice(), &target).expect("a backup taken under load restores");
    let rebuilt = RoomStore::new(&target, ROOM)
        .load()
        .expect("the restored room loads")
        .expect("the room is present");
    assert!(
        rebuilt.broken_chain.is_empty(),
        "the restored room has a broken chain, which is what a torn backup \
         produces: {:?}",
        rebuilt.broken_chain,
    );
}
