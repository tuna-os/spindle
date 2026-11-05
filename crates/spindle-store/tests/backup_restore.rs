//! #20: a backup an operator can trust, and a restore that refuses what it
//! cannot read.
//!
//! The exit criterion is "automated backup/restore produces an independently
//! verified equivalent server". Each test below is one way that fails, and
//! every one of them fails *quietly* without a check: a backup nobody can
//! restore looks exactly like a backup nobody has needed yet.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use spindle_core::{MemStateKeyTable, RoomLog, StateKey, StateKeyTable};
use spindle_store::backup::{BackupError, read_backup, write_backup};
use spindle_store::{
    Durability, FjallStore, ReadView, Record, RoomStore, RowVisitor, SchemaMarker, Store,
    StoreError,
};
use tempfile::TempDir;

const ROOM: &str = "!backup:example.org";

fn seed(store: &FjallStore, events: usize) {
    let room_store = RoomStore::new(store, ROOM);
    let mut log = RoomLog::new(store.key_table());
    for number in 0..events {
        let entry = log
            .append_local(
                format!("$event-{number}"),
                Some(StateKey::new("m.room.topic", "")),
            )
            .unwrap();
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

    let key = StateKey::new("m.room.topic", "");
    assert!(target.key_table().id_of("m.room.topic", "").is_some());

    // And the room reads back through the ordinary path, not just as bytes.
    let rebuilt = RoomStore::new(&target, ROOM)
        .load()
        .unwrap()
        .expect("the room is there after a restore");
    assert_eq!(
        rebuilt.log.current_state().unwrap().get(&key),
        Some("$event-11")
    );
    assert!(rebuilt.unverified.is_empty());
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

/// The stream exactly as #20 first wrote it: every row collected through
/// `scan_prefix`, then framed. Kept here, spelled out byte by byte, as the
/// definition the streaming writer (#743) must keep matching -- a backup
/// taken by one binary has to restore under the next.
fn reference_backup(view: &dyn ReadView) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend_from_slice(b"SPINDLE-BACKUP\x00\x01");
    stream.push(1);
    let marker = SchemaMarker::current().encode();
    stream.push(u8::try_from(marker.len()).unwrap());
    stream.extend_from_slice(&marker);
    let rows = view.scan_prefix(&[]).unwrap();
    for (key, value) in &rows {
        stream.extend_from_slice(&u32::try_from(key.len()).unwrap().to_be_bytes());
        stream.extend_from_slice(key);
        stream.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        stream.extend_from_slice(value);
    }
    stream.extend_from_slice(&u32::MAX.to_be_bytes());
    stream.extend_from_slice(&(rows.len() as u64).to_be_bytes());
    let digest = blake3::hash(&stream);
    stream.extend_from_slice(digest.as_bytes());
    stream
}

/// Streaming the rows changed how they are read, not one byte of what is
/// written: for a store with state, intern rows and a room's metadata, the
/// stream is the collected-then-framed one, and it restores.
#[test]
fn the_streamed_backup_is_byte_for_byte_the_original_format() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store, 40);
    let streamed = backup_of(&store);
    let snapshot = store.snapshot();
    let view: &dyn ReadView = snapshot.as_deref().unwrap_or(&store);
    assert_eq!(streamed, reference_backup(view));

    let target_dir = TempDir::new().unwrap();
    let target = FjallStore::open(target_dir.path()).unwrap();
    read_backup(&mut streamed.as_slice(), &target).unwrap();
    assert_eq!(
        target.scan_prefix(&[]).unwrap(),
        store.scan_prefix(&[]).unwrap()
    );
}

const ROWS: u32 = 2_000;
const VALUE: usize = 1_024;
/// `row-00000000`: twelve bytes.
const KEY: usize = 12;
const FRAME: u64 = (4 + KEY + 4 + VALUE) as u64;

/// A backend that makes its rows up, and records how far the backup's
/// output had got each time it handed one out.
///
/// From that, `max_in_flight` is the most rows the backup held at once:
/// rows handed out whose frame had not yet reached the writer. A writer
/// that streams holds one; one that collects first holds all of them.
struct Generated {
    /// Bytes the writer has received, shared with [`Received`].
    received: Rc<Cell<u64>>,
    /// `received` at the moment each row was produced.
    at_production: RefCell<Vec<u64>>,
}

impl Generated {
    fn row(&self, index: u32) -> (Vec<u8>, Vec<u8>) {
        self.at_production.borrow_mut().push(self.received.get());
        let key = format!("row-{index:08}").into_bytes();
        assert_eq!(key.len(), KEY);
        (key, vec![u8::try_from(index % 251).unwrap(); VALUE])
    }

    fn max_in_flight(&self) -> u64 {
        let produced = self.at_production.borrow();
        // The header is written before the scan starts, so the first row's
        // reading is where row frames begin.
        let header = produced[0];
        produced
            .iter()
            .zip(0_u64..)
            .map(|(received, index)| index + 1 - (received - header) / FRAME)
            .max()
            .unwrap()
    }
}

impl ReadView for Generated {
    fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(None)
    }

    /// What a backend's collecting scan does: every row, then return.
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        assert!(prefix.is_empty());
        Ok((0..ROWS).map(|index| self.row(index)).collect())
    }

    fn visit_prefix(&self, prefix: &[u8], visit: &mut RowVisitor<'_>) -> Result<(), StoreError> {
        assert!(prefix.is_empty());
        for index in 0..ROWS {
            let (key, value) = self.row(index);
            visit(&key, &value)?;
        }
        Ok(())
    }

    fn scan_from(&self, _: &[u8], _: &[u8]) -> Result<Vec<Record>, StoreError> {
        unreachable!("a backup reads the whole store")
    }

    fn key_table(&self) -> Arc<dyn StateKeyTable> {
        MemStateKeyTable::shared()
    }

    fn scan_until(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<Record>, StoreError> {
        unreachable!("a backup reads the whole store")
    }
}

/// A writer that counts what reaches it and keeps none of it.
struct Received(Rc<Cell<u64>>);

impl std::io::Write for Received {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.set(self.0.get() + bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The backup holds one row at a time (#743), however many the store has.
///
/// Before, `write_backup` collected `scan_prefix(&[])` and framed the Vec:
/// all 2,000 rows -- two megabytes here, the whole store in production --
/// were in memory before the first frame was written.
#[test]
fn a_backup_holds_one_row_at_a_time() {
    let received = Rc::new(Cell::new(0));
    let view = Generated {
        received: Rc::clone(&received),
        at_production: RefCell::new(Vec::new()),
    };
    let rows = write_backup(&view, &mut Received(Rc::clone(&received))).unwrap();
    assert_eq!(rows, u64::from(ROWS));
    assert_eq!(view.at_production.borrow().len(), ROWS as usize);
    assert_eq!(view.max_in_flight(), 1, "rows held at once");
}
