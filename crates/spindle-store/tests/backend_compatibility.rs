//! #187: a store written by one `fjall` version must open under the next.
//!
//! [`format_compatibility`] already freezes *our* bytes — the record and key
//! encodings, as checked-in fixtures. It says nothing about the bytes
//! underneath them. `fjall` has its own on-disk format (a `version` file, a
//! partition manifest, a level listing, a config, and a journal), and a major
//! version of it can change any of those.
//!
//! Nothing here noticed, because every other test in this crate opens a fresh
//! [`TempDir`] and writes it with the same build that reads it. That proves
//! the encoder agrees with itself, which is exactly the failure mode the
//! `format_compatibility` module warns about, one layer down: a `fjall` bump
//! would go green in CI and then fail to open a real deployment's store.
//!
//! So the directory under `tests/fixtures/fjall2/` was written by `fjall`
//! 2.11.2 and checked in. **Do not regenerate it.** If a `fjall` upgrade makes
//! this test fail, that failure is the finding: existing stores need a
//! migration, or the upgrade needs to be declined. Refreshing the fixture
//! converts "operators lose their data" into a green tick.
//!
//! ## Two fixtures, because there are two formats
//!
//! `fixtures/fjall2/` holds its rows in the **journal**: at that size `fjall`
//! had not rotated a memtable, so it gates the `version` file, the partition
//! manifest, the level listing, the partition config, and journal replay.
//!
//! `fixtures/fjall2-segments/` holds its rows in a **segment**, forced there
//! by `Store::flush_to_segments`. That is the format a major version of an
//! LSM engine is most likely to change, and until the hook existed nothing
//! here could produce one — which is precisely why the `fjall` 3 upgrade
//! could not be judged safe in #193.
//!
//! Both are kept. The journal one is not redundant: a store that has just
//! taken writes and not yet rotated is the ordinary state of a running
//! server, and journal replay is what opens it.
//!
//! [`format_compatibility`]: ./format_compatibility.rs
//! [`TempDir`]: tempfile::TempDir

use spindle_store::{FjallStore, ReadView};
use tempfile::TempDir;

/// The rows in `fixtures/fjall2/`, by the version that wrote them.
const ROWS: &[(&[u8], &[u8])] = &[
    (b"\x01alpha", b"one"),
    (b"\x01beta", b"two"),
    (b"\x01gamma", b"three"),
];

/// How many rows `fixtures/fjall2-segments/` holds.
const SEGMENT_ROWS: usize = 64;

/// Copy the fixture somewhere writable.
///
/// Opening a `fjall` keyspace replays and may rewrite its journal, so opening
/// the checked-in directory in place would mutate the fixture — and a fixture
/// the test edits is not a fixture.
fn fixture() -> TempDir {
    copy_fixture("fjall2")
}

/// The same, for the segment-bearing fixture.
fn segment_fixture() -> TempDir {
    copy_fixture("fjall2-segments")
}

fn copy_fixture(name: &str) -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}"));
    copy_dir(&source, dir.path());
    dir
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).expect("create");
    for entry in std::fs::read_dir(from).expect("read fixture") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// A store written by the pinned `fjall` opens, and still holds its rows.
#[test]
fn a_store_written_by_fjall_2_still_opens_and_reads() {
    let dir = fixture();
    let store = FjallStore::open(dir.path()).expect(
        "a store written by an earlier fjall must open -- if this fails after a \
         fjall upgrade, existing deployments cannot be opened either",
    );

    for (key, want) in ROWS {
        let got = store
            .get(key)
            .expect("read")
            .unwrap_or_else(|| panic!("{} is missing", String::from_utf8_lossy(key)));
        assert_eq!(
            got.as_slice(),
            *want,
            "{} came back changed",
            String::from_utf8_lossy(key),
        );
    }
}

/// The fixture is not empty, and the emptiness would otherwise pass silently.
///
/// If a future `fjall` opened the directory, found a format it did not
/// understand, and started fresh rather than failing, every `get` above would
/// return `None` — and a test that only checked "no error" would agree that
/// all was well. This is the assertion that catches a silent reset.
#[test]
fn the_fixture_is_not_silently_empty() {
    let dir = fixture();
    let store = FjallStore::open(dir.path()).expect("open");
    let rows = store.scan_prefix(&[1]).expect("scan");
    assert_eq!(
        rows.len(),
        ROWS.len(),
        "the fixture holds {} rows; finding {} means the store was reset rather \
         than read",
        ROWS.len(),
        rows.len(),
    );
}

/// A store whose rows live in a **segment** opens and reads.
///
/// This is the half `fixtures/fjall2/` could not reach. Its rows were in the
/// journal, so a `fjall` upgrade that changed only the segment format would
/// have passed that test and still failed to open a real deployment — where
/// most rows are in segments, because that is where an LSM engine puts them.
#[test]
fn a_store_whose_rows_are_in_a_segment_still_opens_and_reads() {
    let dir = segment_fixture();
    let store = FjallStore::open(dir.path()).expect(
        "a segment written by an earlier fjall must open -- if this fails after \
         an upgrade, so does every store that has ever compacted",
    );

    for n in 0..SEGMENT_ROWS {
        let key = format!("\x01row-{n:04}");
        let got = store
            .get(key.as_bytes())
            .expect("read")
            .unwrap_or_else(|| panic!("{key} is missing"));
        assert_eq!(
            got.as_slice(),
            format!("value-{n}").as_bytes(),
            "{key} came back changed",
        );
    }
}

/// The segment fixture really does carry a segment.
///
/// Without this the test above could pass on a fixture whose rows had
/// silently stayed in the journal — proving the same thing twice and leaving
/// the segment format uncovered while appearing to cover it.
#[test]
fn the_segment_fixture_actually_contains_a_segment() {
    let segments = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fjall2-segments/partitions/spindle/segments");
    let count = std::fs::read_dir(&segments)
        .unwrap_or_else(|error| panic!("no segments directory at {}: {error}", segments.display()))
        .count();
    assert!(
        count > 0,
        "the fixture has a segments directory but no segments"
    );
}
