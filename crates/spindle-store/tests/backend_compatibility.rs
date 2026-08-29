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
//! these tests fail, that failure is the finding: existing stores need a
//! migration, or the upgrade needs to be declined. Refreshing the fixture
//! converts "operators lose their data" into a green tick.
//!
//! ## That already happened, and this is what it looks like
//!
//! Taking `fjall` 3 (#193) made these fail with `InvalidVersion(Some(V2))`.
//! `fjall` 3 changed the on-disk format and has no in-process upgrade: it
//! refuses a v2 directory and points at a separate tool. The fixtures were
//! **kept and the assertions inverted** — they now prove the refusal is
//! clean and explains itself, which is the property an operator has left
//! once the data cannot be read. Regenerating them under `fjall` 3 would
//! have been the green tick this file exists to refuse.
//!
//! The break was accepted deliberately because Spindle has no deployments
//! and therefore no data to migrate. That is a fact with an expiry date, and
//! these fixtures are what will notice when it expires.
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

/// A store written by fjall 2 is **refused**, and says what to do.
///
/// This test used to assert the opposite, and the change is the finding. The
/// module doc above said: *"If a fjall upgrade makes this test fail, that
/// failure is the finding: existing stores need a migration, or the upgrade
/// needs to be declined. Refreshing the fixture converts 'operators lose
/// their data' into a green tick."*
///
/// Taking fjall 3 made it fail, with `InvalidVersion(Some(V2))`. fjall 3
/// changed the on-disk format and has **no in-process upgrade path** — it
/// refuses the directory and points at a separate migration tool. So the
/// fixture was not refreshed: it is kept, and the assertion inverted to the
/// property that now matters. An operator with a v2 directory must get a
/// comprehensible refusal rather than corruption or a silently empty store.
///
/// Taking the break was a deliberate decision (#193): Spindle has no
/// deployments, so there is no data to migrate. The day that stops being
/// true, this fixture is the thing that says so.
#[test]
fn a_store_written_by_fjall_2_is_refused_with_an_explanation() {
    let dir = fixture();
    let error = FjallStore::open(dir.path())
        .err()
        .expect("a fjall 2 store must not open under fjall 3");
    let message = error.to_string();

    // The three things an operator needs: which engine wrote it, that there
    // is no automatic upgrade, and where the tool is.
    assert!(message.contains("fjall 2"), "{message}");
    assert!(message.contains("no automatic upgrade"), "{message}");
    assert!(message.contains("migrate-v2-v3"), "{message}");
}

/// The segment-bearing fixture is refused too, and for the same reason.
///
/// Kept separate because the two fixtures fail at different layers — one has
/// its rows in the journal, the other in a segment — and a version gate that
/// caught only one of them would leave the other to fail later and worse.
#[test]
fn a_segment_written_by_fjall_2_is_refused_too() {
    let dir = segment_fixture();
    let error = FjallStore::open(dir.path())
        .err()
        .expect("a fjall 2 segment store must not open under fjall 3");
    assert!(error.to_string().contains("migrate-v2-v3"), "{error}");
}

/// A store this build wrote reopens, with its rows intact.
///
/// The fjall 2 fixtures can no longer carry this claim, and it is the claim
/// that matters day to day: the two tests above prove the *refusal* is clean,
/// and this one proves that reading a store back still works — which a
/// refusal would otherwise mask. Written and reopened in one test rather than
/// checked in as a fixture, because a checked-in fjall 3 fixture is the next
/// major version's tripwire and this is about the engine in use now.
#[test]
fn a_store_this_build_wrote_reopens_with_its_rows() {
    let dir = TempDir::new().expect("temp dir");
    {
        let store = FjallStore::open(dir.path()).expect("create");
        for (key, value) in ROWS {
            spindle_store::Store::put(&store, key, value).expect("write");
        }
        // Through a segment as well as the journal, so this covers the same
        // two layers the fixtures did.
        spindle_store::Store::flush_to_segments(&store).expect("rotate");
        spindle_store::Store::sync(&store, spindle_store::Durability::Strict).expect("sync");
    }

    let store = FjallStore::open(dir.path()).expect("reopen");
    for (key, want) in ROWS {
        let got = store
            .get(key)
            .expect("read")
            .unwrap_or_else(|| panic!("{} is missing", String::from_utf8_lossy(key)));
        assert_eq!(got.as_slice(), *want);
    }
    assert_eq!(store.scan_prefix(&[1]).expect("scan").len(), ROWS.len());
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
