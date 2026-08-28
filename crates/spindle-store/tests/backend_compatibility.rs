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
//! ## What this does and does not cover
//!
//! The fixture's rows live in the journal — `fjall` had not rotated a memtable
//! into a segment at this size, and the store exposes no way to force one.
//! So this gates the `version` file, the partition manifest, the level
//! listing, the partition config, and **journal replay**. It does not gate the
//! segment format. A fuller fixture wants a store large enough to have
//! compacted, which is worth doing when there is a reason to carry the bytes.
//!
//! [`format_compatibility`]: ./format_compatibility.rs
//! [`TempDir`]: tempfile::TempDir

use spindle_store::{FjallStore, ReadView};
use tempfile::TempDir;

/// The rows written into the fixture, by the version that wrote it.
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
    let dir = TempDir::new().expect("temp dir");
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fjall2");
    copy_dir(source.as_ref(), dir.path());
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
