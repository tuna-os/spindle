//! Part of #6: the million-event append/reopen test, and the shape check that
//! keeps it honest between runs.
//!
//! The full-size run is `#[ignore]`d — it is a resource-envelope measurement,
//! not a per-commit gate:
//!
//! ```text
//! cargo test -p spindle-store --release --test scale -- --ignored --nocapture
//! ```
//!
//! The smaller run below executes on every commit. Its job is not to be fast
//! but to assert the *shape*: that appending stays proportional to the event
//! rather than to the room. A regression to an O(room) write path shows up
//! there long before anyone runs the million.

use std::time::Instant;

use spindle_core::RoomLog;
use spindle_store::{Durability, FjallStore, RoomStore};
use tempfile::TempDir;

const ROOM: &str = "!scale:example.org";

struct Measured {
    appended: usize,
    first_decile: f64,
    last_decile: f64,
    reopen_seconds: f64,
}

/// Append `count` events one atomic commit at a time, then reopen from a fresh
/// handle and check the log came back whole.
fn append_and_reopen(count: usize, durability: Durability) -> Measured {
    let dir = TempDir::new().unwrap();
    let decile = (count / 10).max(1);
    let mut first_decile = 0.0_f64;
    let last_decile;

    {
        let store = FjallStore::open(dir.path()).unwrap();
        let room_store = RoomStore::new(&store, ROOM);
        let mut log = RoomLog::new();
        let mut window = Instant::now();

        for number in 0..count {
            let entry = log.append_local(format!("$event-{number}"), None).unwrap();
            let entry = entry.clone();
            room_store.commit_entry(&entry, &log, durability).unwrap();

            if number + 1 == decile {
                first_decile = window.elapsed().as_secs_f64();
            } else if number + 1 == count.saturating_sub(decile) {
                // Start timing the final decile.
                window = Instant::now();
            }
        }
        last_decile = window.elapsed().as_secs_f64();
    }

    let started = Instant::now();
    let store = FjallStore::open(dir.path()).unwrap();
    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();
    let reopen_seconds = started.elapsed().as_secs_f64();

    assert_eq!(restored.log.len(), count);
    assert!(restored.unverified.is_empty());
    assert_eq!(
        restored.log.next_forward(),
        i64::try_from(count).unwrap() + 1
    );
    assert_eq!(restored.log.forward_extremities().len(), 1);

    let head = restored.log.entries().next_back().unwrap();
    assert_eq!(head.event_id.as_str(), format!("$event-{}", count - 1));
    assert_eq!(head.li.get(), i64::try_from(count).unwrap());

    Measured {
        appended: count,
        first_decile,
        last_decile,
        reopen_seconds,
    }
}

fn report(label: &str, measured: &Measured) {
    let Measured {
        appended,
        first_decile,
        last_decile,
        reopen_seconds,
    } = measured;
    let decile = (appended / 10).max(1);
    println!(
        "{label}: {appended} events | first {decile} in {first_decile:.3}s | \
         last {decile} in {last_decile:.3}s | reopen {reopen_seconds:.3}s"
    );
}

#[test]
fn appending_stays_proportional_to_the_event_not_the_room() {
    let measured = append_and_reopen(20_000, Durability::Relaxed);
    report("scale/20k", &measured);

    // The shape assertion. An O(room) write path makes the last decile
    // dramatically slower than the first; an O(1) one keeps them comparable.
    // The bound is deliberately loose because this runs on shared CI hardware
    // where a factor of a few is ordinary noise -- it is a tripwire for a
    // change in complexity class, not a performance budget.
    assert!(
        measured.last_decile < measured.first_decile * 8.0 + 0.5,
        "append cost grew with room size: first decile {:.3}s, last decile {:.3}s",
        measured.first_decile,
        measured.last_decile
    );
}

#[test]
#[ignore = "resource-envelope measurement; run explicitly with --ignored --release"]
fn a_million_events_append_and_reopen() {
    let measured = append_and_reopen(1_000_000, Durability::Relaxed);
    report("scale/1M", &measured);

    assert!(
        measured.last_decile < measured.first_decile * 8.0 + 0.5,
        "append cost grew with room size across a million events: \
         first decile {:.3}s, last decile {:.3}s",
        measured.first_decile,
        measured.last_decile
    );
}

#[test]
fn strict_durability_costs_an_fsync_per_commit() {
    // Reported next to the relaxed numbers deliberately. A scale figure quoted
    // without its durability mode is close to meaningless, and publishing only
    // the favourable mode is the kind of benchmark hygiene #34 rules out.
    let relaxed = append_and_reopen(2_000, Durability::Relaxed);
    let strict = append_and_reopen(2_000, Durability::Strict);
    report("durability/relaxed", &relaxed);
    report("durability/strict", &strict);

    let relaxed_total = relaxed.first_decile + relaxed.last_decile;
    let strict_total = strict.first_decile + strict.last_decile;
    println!(
        "durability: strict/relaxed cost ratio {:.1}x",
        strict_total / relaxed_total.max(f64::MIN_POSITIVE)
    );

    // No assertion on the ratio: it is dominated by the host's fsync latency,
    // which varies by orders of magnitude between an NVMe workstation and a
    // shared CI runner. The number is here to be read, not to gate.
    assert_eq!(strict.appended, 2_000);
}
