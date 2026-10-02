//! #21's disk-full drill, store half: a store whose disk fills refuses the
//! write that does not fit, says so from then on, and loses nothing it
//! acknowledged.
//!
//! The disk is filled for real. A fake `Store` that fails on cue would
//! only prove the fake; what is under test is how the engine meets
//! `ENOSPC` from `write(2)` and `fsync(2)` part way through its journal.
//! That needs a filesystem small enough to fill, which a test cannot make
//! without root, so the drill is `#[ignore]`d and takes one from
//! `SPINDLE_DISK_FULL_DIR`: `just drill-disk-full` mounts a small tmpfs
//! there, and CI runs that recipe on every pull request.
//!
//! The drill never fills a disk it was not pointed at. It refuses a
//! directory with more room than [`MAX_FREE_BYTES`].
//!
//! "Free some space and restart" is the operator's remedy, so the drill
//! keeps a ballast file on the filesystem, deletes it once the store is
//! full, and reopens the same directory.

use std::path::{Path, PathBuf};

use spindle_store::{Durability, FjallStore, ReadView, Store};

/// The directory on a small filesystem, from `just drill-disk-full`.
const DIR_VAR: &str = "SPINDLE_DISK_FULL_DIR";

/// Refuse a filesystem that would take longer than this to fill: 256 MiB.
/// The drill writes until the disk is full, and pointed at a real disk
/// that is a way to fill the machine.
const MAX_FREE_BYTES: u64 = 256 * 1024 * 1024;

/// Each commit's value. Big enough to fill the filesystem in a few
/// thousand commits.
const VALUE_BYTES: usize = 16 * 1024;

/// Twice [`MAX_FREE_BYTES`] in commits, so a store that never
/// refuses one fails the drill rather than finishing it.
const ATTEMPTS: usize = 2 * 256 * 1024 * 1024 / VALUE_BYTES;

fn key(n: usize) -> Vec<u8> {
    format!("disk-full/{n:06}").into_bytes()
}

/// Commit `n`'s value: xorshift noise seeded by `n`, so the engine's
/// compression cannot shrink it and the bytes written are the bytes that
/// fill the disk.
fn value(n: usize) -> Vec<u8> {
    let mut state = (n as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (0..VALUE_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// The directory to fill, checked to be on a small filesystem.
///
/// "Small" is measured the only way the standard library allows: write
/// zeroes until the filesystem refuses, then delete them.
/// `own` is this drill's subdirectory, cleared first.
fn small_filesystem(own: &str) -> (PathBuf, u64) {
    let root = PathBuf::from(
        std::env::var_os(DIR_VAR)
            .unwrap_or_else(|| panic!("{DIR_VAR} names a directory on a small filesystem")),
    );
    // A run that failed part way leaves its directory, and its ballast,
    // filling the space this one is about to measure.
    let _ = std::fs::remove_dir_all(root.join(own));
    let _ = std::fs::remove_file(root.join("ballast"));
    let probe = root.join("probe");
    let free = fill(&probe);
    std::fs::remove_file(&probe).unwrap();
    assert!(
        free < MAX_FREE_BYTES,
        "{} has {free} bytes free; the drill fills it, so it wants under {MAX_FREE_BYTES}",
        root.display(),
    );
    (root, free)
}

/// Write zeroes to `path` until the filesystem refuses, capped at
/// [`MAX_FREE_BYTES`] so a large disk is not filled finding out.
fn fill(path: &Path) -> u64 {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path).unwrap();
    let chunk = vec![0_u8; 1024 * 1024];
    let mut written = 0_u64;
    while written < MAX_FREE_BYTES {
        match file.write(&chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => written += n as u64,
        }
    }
    written
}

#[test]
#[ignore = "fills a filesystem: run it through `just drill-disk-full`"]
fn a_full_disk_refuses_writes_and_loses_nothing_acknowledged() {
    let (root, free) = small_filesystem("store");
    // A quarter of the filesystem held back for the restart. Freeing only
    // a sliver is not a remedy: a reopened store has to flush what it
    // recovered before it can take a write, and a flush needs room.
    let ballast = root.join("ballast");
    let ballast_bytes = usize::try_from(free / 4).unwrap();
    std::fs::write(&ballast, vec![1_u8; ballast_bytes]).expect("the ballast fits");
    let dir = root.join("store");

    let acknowledged = {
        let store = FjallStore::open(&dir).expect("the store opens on the empty filesystem");
        assert!(store.accepts_writes(), "a fresh store accepts writes");

        let mut acknowledged = 0;
        let mut refused = None;
        for n in 0..ATTEMPTS {
            match store.commit(&[(key(n), value(n))], Durability::Strict) {
                Ok(()) => acknowledged += 1,
                Err(error) => {
                    refused = Some(error);
                    break;
                }
            }
        }
        let refused = refused.expect("the filesystem refuses a commit before the attempts run out");
        assert!(
            acknowledged > 0,
            "the filesystem is meant to fill a working store"
        );
        assert!(
            !store.accepts_writes(),
            "a refused commit ({refused:?}) leaves the store reporting it cannot write",
        );

        // The latch does not flap back, even once there is room again:
        // the engine refuses every write after a failed one until the
        // directory is reopened. A readiness probe that turned green here
        // would route clients to a server whose next write fails.
        std::fs::remove_file(&ballast).unwrap();
        let again = store.commit(&[(b"after".to_vec(), b"x".to_vec())], Durability::Strict);
        assert!(
            again.is_err(),
            "the engine refuses writes after a failed one"
        );
        assert!(!store.accepts_writes(), "and the store still says so");

        // Reads keep working: a full disk is a write outage, not a read one.
        assert_eq!(
            store.get(&key(0)).unwrap(),
            Some(value(0)),
            "an acknowledged row is still readable on the full disk",
        );
        acknowledged
    };

    // The operator's remedy: the space is free (the ballast went above),
    // and the process restarts onto the same directory.
    let store = FjallStore::open(&dir).expect("the store reopens once there is space");
    for n in 0..acknowledged {
        assert_eq!(
            store.get(&key(n)).unwrap(),
            Some(value(n)),
            "commit {n} of {acknowledged} was acknowledged and must survive",
        );
    }
    // The refused commit may or may not have landed -- it was never
    // acknowledged -- but nothing after it can have.
    assert_eq!(
        store.get(&key(acknowledged + 1)).unwrap(),
        None,
        "nothing after the refused commit landed",
    );
    assert_eq!(store.get(b"after").unwrap(), None);

    assert!(store.accepts_writes(), "the reopened store accepts writes");
    store
        .commit(&[(b"after".to_vec(), b"x".to_vec())], Durability::Strict)
        .expect("and takes one");
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}
