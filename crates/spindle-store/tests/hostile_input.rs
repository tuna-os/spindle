//! Part of #267, target 3: feed the record codecs and the backup reader
//! bytes nobody sane wrote.
//!
//! `format_compatibility.rs` proves the happy path round-trips. Nothing
//! proved what happens to the unhappy one, and these decoders read two
//! things this server does not control: rows off a disk that may be
//! corrupt, and a file `spindle restore` was pointed at.
//!
//! The property that matters is not only "does not panic". Every framed
//! field in both formats is introduced by a length, and a decoder that
//! believes a length before it has seen the bytes behind it sizes an
//! allocation from a number the file chose. That failure does not return
//! an error a caller could refuse: a failed allocation aborts the process.
//!
//! Which is exactly what a test cannot watch from the inside -- an abort
//! takes the harness with it, and an allocation the kernel overcommits
//! leaves no trace in any value this code can read. So each measurement
//! runs in a child process. The parent reads the child's exit status, so
//! an abort is a failed assertion rather than a dead test binary, and its
//! peak address space, so an allocation is visible whether or not the
//! kernel made it hurt.

use std::process::Command;

use proptest::prelude::*;
use spindle_store::{
    FjallStore, ReadView, SchemaMarker, Store,
    backup::{read_backup, write_backup},
    codec::{EntryRecord, RoomRecord},
};

/// The environment variable that turns this test binary into the child.
const CASE: &str = "SPINDLE_HOSTILE_CASE";

/// Generous enough that no honest decode of a few dozen bytes comes near
/// it, and far below the gibibytes a length-believing decoder reserves.
const SANE_MIB: u64 = 256;

// -- hostile inputs -------------------------------------------------------

/// An `EntryRecord` well-formed up to its parent count, which then claims
/// more parents than the rest of the record has bytes to frame.
fn entry_claiming(parents: u32) -> Vec<u8> {
    let mut bytes = vec![1_u8];
    bytes.extend_from_slice(&[0; 8]); // li
    bytes.extend_from_slice(&[0; 8]); // depth
    bytes.extend_from_slice(&[0; 32]); // state_root
    bytes.extend_from_slice(&0_u32.to_be_bytes()); // event_id, empty
    bytes.extend_from_slice(&parents.to_be_bytes());
    bytes
}

/// The same trick one record over: a `RoomRecord` claiming extremities.
fn room_claiming(extremities: u32) -> Vec<u8> {
    let mut bytes = vec![1_u8];
    bytes.extend_from_slice(&[0; 8]); // next_forward
    bytes.extend_from_slice(&[0; 8]); // next_backward
    bytes.extend_from_slice(&extremities.to_be_bytes());
    bytes
}

/// A backup whose header is genuine and whose first row claims `key_len`.
fn backup_claiming(key_len: u32) -> Vec<u8> {
    let marker = SchemaMarker::current().encode();
    let mut file = b"SPINDLE-BACKUP\x00\x01".to_vec();
    file.push(1); // format version
    file.push(u8::try_from(marker.len()).expect("the marker is a handful of bytes"));
    file.extend_from_slice(&marker);
    file.extend_from_slice(&key_len.to_be_bytes());
    file
}

// -- the instrument -------------------------------------------------------

/// Peak virtual size of this process, in MiB.
///
/// Linux-only, which is where this is measured; `None` elsewhere makes the
/// assertions skip rather than lie about a number they could not read.
fn peak_mib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmPeak:"))?;
    Some(line.split_whitespace().nth(1)?.parse::<u64>().ok()? / 1024)
}

/// What a child reported about one hostile input.
struct Reading {
    /// The child returned rather than aborting.
    survived: bool,
    /// How much address space the decode added, in MiB.
    grew_mib: u64,
}

/// Run one named case in a child and read back what it cost.
fn measure(case: &str) -> Reading {
    let output = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["decodes_one_hostile_input", "--exact", "--nocapture"])
        .env(CASE, case)
        .output()
        .expect("to run the child");

    let reported = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("grew ").map(str::to_owned))
        .and_then(|value| value.trim().parse().ok());

    Reading {
        survived: output.status.success(),
        grew_mib: reported.unwrap_or(0),
    }
}

/// The child. A no-op in the ordinary run; the whole point when the parent
/// sets [`CASE`].
#[test]
fn decodes_one_hostile_input() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };

    // Everything the case needs is built before the reading is taken, so
    // the number below is what the decode cost and not what opening a
    // store or building an input did.
    let decode: Box<dyn FnOnce()> = match case.as_str() {
        "entry" => {
            let record = entry_claiming(u32::MAX);
            Box::new(move || assert!(EntryRecord::decode(&record).is_err()))
        }
        "room" => {
            let record = room_claiming(u32::MAX);
            Box::new(move || assert!(RoomRecord::decode(&record).is_err()))
        }
        "backup" => {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let store = FjallStore::open(directory.path()).expect("a fresh store");
            let file = backup_claiming(u32::MAX - 1);
            Box::new(move || {
                assert!(read_backup(&mut file.as_slice(), &store).is_err());
                drop(directory);
            })
        }
        other => panic!("no such case: {other}"),
    };

    let before = peak_mib();
    decode();

    let grew = before
        .zip(peak_mib())
        .map_or(0, |(before, after)| after.saturating_sub(before));
    println!("grew {grew}");
}

#[test]
fn an_entry_record_allocates_for_the_bytes_it_has_not_the_ones_it_claims() {
    // 57 bytes, claiming 4_294_967_295 parents. Before the bound, that is a
    // `Vec::<String>::with_capacity` of 103 GiB -- a request large enough to
    // fail outright, and a failed allocation aborts.
    let reading = measure("entry");
    assert!(
        reading.survived,
        "a 57-byte record claiming u32::MAX parents took the process down"
    );
    assert!(
        reading.grew_mib < SANE_MIB,
        "it grew the process by {} MiB",
        reading.grew_mib
    );
}

#[test]
fn a_room_record_allocates_for_the_bytes_it_has_not_the_ones_it_claims() {
    let reading = measure("room");
    assert!(
        reading.survived,
        "a 21-byte record claiming u32::MAX extremities took the process down"
    );
    assert!(
        reading.grew_mib < SANE_MIB,
        "it grew the process by {} MiB",
        reading.grew_mib
    );
}

#[test]
fn a_backup_allocates_for_the_bytes_it_has_not_the_ones_it_claims() {
    // 26 bytes, claiming a key one byte below `END_OF_ROWS`. Before the
    // bound this reserves four gibibytes and then reads nothing into them:
    // it survives only because Linux overcommits pages it never touches,
    // which is the kernel's decision and not this crate's.
    let reading = measure("backup");
    assert!(
        reading.survived,
        "a 26-byte backup claiming a 4 GiB key took the process down"
    );
    assert!(
        reading.grew_mib < SANE_MIB,
        "it grew the process by {} MiB",
        reading.grew_mib
    );
}

/// The other half of the bound: honest lengths must still be believed. A
/// decoder that refused every length would pass every test above.
#[test]
fn an_honest_backup_still_round_trips() {
    let source_dir = tempfile::tempdir().expect("a temporary directory");
    let source = FjallStore::open(source_dir.path()).expect("a fresh store");
    // Values larger than any chunked read would use, so a fix that reads in
    // steps is exercised across more than one step.
    for index in 0_u32..64 {
        source
            .put(&index.to_be_bytes(), &vec![b'v'; 200_000])
            .expect("a write");
    }
    source.flush().expect("a flush");

    let mut file = Vec::new();
    let snapshot = source.snapshot().expect("fjall has snapshots");
    // Every row the store holds, which is the 64 written above plus the
    // schema marker the store stamps for itself.
    let written = write_backup(snapshot.as_ref(), &mut file).expect("a backup");
    assert!(written >= 64, "the backup holds {written} rows");

    let target_dir = tempfile::tempdir().expect("a temporary directory");
    let target = FjallStore::open(target_dir.path()).expect("a fresh store");
    assert_eq!(
        read_backup(&mut file.as_slice(), &target).expect("a restore"),
        written
    );
    for index in 0_u32..64 {
        assert_eq!(
            target.get(&index.to_be_bytes()).expect("a read"),
            Some(vec![b'v'; 200_000])
        );
    }
}

// -- fuzzing --------------------------------------------------------------

proptest! {
    /// Bytes off the floor into every decoder.
    #[test]
    fn arbitrary_bytes_decode_or_refuse(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let _ = std::hint::black_box(EntryRecord::decode(&bytes));
        let _ = std::hint::black_box(RoomRecord::decode(&bytes));
        let _ = std::hint::black_box(SchemaMarker::decode(&bytes));
    }

    /// A row that lost its tail: every prefix of a real record, and the
    /// round trip alongside so the arm cannot pass on a decoder that
    /// refuses everything.
    #[test]
    fn truncated_records_decode_or_refuse(
        event_id in "\\PC{0,32}",
        parents in prop::collection::vec("\\PC{0,16}", 0..4),
        li: i64,
        depth: u64,
        state_key in prop::option::of(("\\PC{0,16}", "\\PC{0,16}")),
    ) {
        let record = EntryRecord {
            li,
            event_id,
            prev_events: parents,
            depth,
            state_key,
            state_root: [7; 32],
            chain: None,
        };
        let encoded = record.encode();
        let decoded = EntryRecord::decode(&encoded);
        prop_assert_eq!(decoded.as_ref(), Ok(&record));
        for cut in 0..encoded.len() {
            let _ = std::hint::black_box(EntryRecord::decode(&encoded[..cut]));
        }
    }

    /// A row whose length prefixes lie. Every four-byte window overwritten
    /// with an arbitrary `u32`, because every framed field in this format
    /// is introduced by exactly one of them.
    #[test]
    fn lying_lengths_decode_or_refuse(
        next_forward: i64,
        next_backward: i64,
        extremities in prop::collection::vec("\\PC{0,16}", 0..4),
        claimed: u32,
    ) {
        let record = RoomRecord {
            next_forward,
            next_backward,
            forward_extremities: extremities,
        };
        let encoded = record.encode();
        let decoded = RoomRecord::decode(&encoded);
        prop_assert_eq!(decoded.as_ref(), Ok(&record));
        for at in 0..encoded.len().saturating_sub(4) {
            let mut corrupt = encoded.clone();
            corrupt[at..at + 4].copy_from_slice(&claimed.to_be_bytes());
            let _ = std::hint::black_box(RoomRecord::decode(&corrupt));
        }
    }

    /// A file that is not a backup, and a real one that has been chewed.
    #[test]
    fn arbitrary_backups_restore_or_refuse(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        at in 0_usize..64,
        claimed in 0_u32..1 << 20,
    ) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = FjallStore::open(directory.path()).expect("a fresh store");

        let _ = std::hint::black_box(read_backup(&mut bytes.as_slice(), &store));

        // A real header, then noise, then a length written over it.
        let mut file = backup_claiming(0);
        file.extend_from_slice(&bytes);
        if at + 4 <= file.len() {
            file[at..at + 4].copy_from_slice(&claimed.to_be_bytes());
        }
        let _ = std::hint::black_box(read_backup(&mut file.as_slice(), &store));
    }
}
