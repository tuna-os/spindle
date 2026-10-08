//! Cold load of a very large room: where the time goes, and that the fast
//! path still restores exactly what the exhaustive one does.
//!
//! The profile is `#[ignore]`d -- it writes a store of a million log rows and
//! is a measurement, not a gate:
//!
//! ```text
//! SPINDLE_COLD_EVENTS=1000000 cargo test -p spindle-store --release \
//!     --test cold_load -- --ignored --nocapture
//! ```
//!
//! The shape of the synthetic room follows the production room that made
//! this worth measuring: about a million timeline rows, a few thousand of
//! them backfilled below zero (and so carrying no chain attestation), and a
//! handful of state slots. Event IDs are room-v4+ shaped -- a `$` and 43
//! characters of URL-safe base64 -- because the size of the ID is most of
//! the size of a row.

use std::time::Instant;

use spindle_core::keys::{Keyspace, content_addressed, room_li, room_prefix};
use spindle_core::{
    ChainHash, EventId, LinearIndex, RestoredEntry, RoomLog, StateKey, StateRoot, StateSnapshot,
};
use spindle_store::codec::{EntryRecord, RoomRecord};
use spindle_store::{Durability, FjallStore, ReadView, RoomStore, Store};

const ROOM: &str = "!cold:example.org";

/// A deterministic, room-v4-shaped event ID for one position.
fn event_id(n: i64) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = blake3::hash(&n.to_be_bytes());
    let mut id = String::with_capacity(44);
    id.push('$');
    for byte in digest.as_bytes().iter().chain(digest.as_bytes()).take(43) {
        id.push(char::from(ALPHABET[usize::from(byte & 63)]));
    }
    id
}

struct Shape {
    forward: i64,
    backfilled: i64,
    state_slots: usize,
}

/// Write a room straight into the store's record format, the way an import
/// or years of appends leave it, without paying for a million appends.
fn build(store: &FjallStore, shape: &Shape) {
    // The state: a few slots, all set before the first backfilled event.
    let mut state = StateSnapshot::new();
    for slot in 0..shape.state_slots {
        state = state.apply(
            StateKey::new(format!("m.room.slot{slot}"), ""),
            event_id(-1_000_000_000 - i64::try_from(slot).unwrap()),
        );
    }
    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = state
        .delta_nodes(None)
        .into_iter()
        .map(|(address, node)| {
            (
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            )
        })
        .collect();
    let root = *state.root().as_bytes();
    let flush = |batch: &mut Vec<(Vec<u8>, Vec<u8>)>| {
        store.commit(batch, Durability::Relaxed).unwrap();
        batch.clear();
    };

    // Backfilled history: li 0, -1, ... each naming the next older event,
    // the oldest naming one nobody holds (a backfill frontier).
    for n in 0..shape.backfilled {
        let li = -n;
        let record = EntryRecord {
            li,
            event_id: event_id(li),
            prev_events: vec![event_id(li - 1)],
            depth: u64::try_from(shape.backfilled - n).unwrap(),
            state_key: None,
            state_root: root,
            chain: None,
        };
        batch.push((
            room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(li)),
            record.encode(),
        ));
        if batch.len() >= 20_000 {
            flush(&mut batch);
        }
    }

    // Forward history, chained.
    let mut chain = ChainHash::seed();
    for li in 1..=shape.forward {
        let id = EventId::new(event_id(li));
        chain = chain.extend(&id);
        let record = EntryRecord {
            li,
            event_id: id.as_str().to_owned(),
            prev_events: vec![event_id(li - 1)],
            depth: u64::try_from(shape.backfilled + li).unwrap(),
            state_key: None,
            state_root: root,
            chain: Some(*chain.as_bytes()),
        };
        batch.push((
            room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(li)),
            record.encode(),
        ));
        if batch.len() >= 20_000 {
            flush(&mut batch);
        }
    }
    batch.push((
        room_prefix(Keyspace::RoomMeta, ROOM),
        RoomRecord {
            next_forward: shape.forward + 1,
            next_backward: -shape.backfilled,
            forward_extremities: vec![event_id(shape.forward)],
        }
        .encode(),
    ));
    flush(&mut batch);
    store.flush_to_segments().unwrap();
    store.flush().unwrap();
}

/// This process's resident and peak resident set, in MiB.
fn rss() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// Reset the peak so each phase reports its own.
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

fn timed<T>(label: &str, work: impl FnOnce() -> T) -> T {
    reset_peak();
    let (before, _) = rss();
    let started = Instant::now();
    let out = work();
    let elapsed = started.elapsed();
    let (after, peak) = rss();
    println!(
        "  {label:<42} {:>8.3}s  rss {before:>5} -> {after:>5} MiB  peak {peak:>5} MiB",
        elapsed.as_secs_f64()
    );
    out
}

#[test]
#[ignore = "resource-envelope measurement; run explicitly with --ignored --release"]
fn profile_cold_load_of_a_huge_room() {
    let total: i64 = std::env::var("SPINDLE_COLD_EVENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let shape = Shape {
        backfilled: (total / 110).max(1),
        forward: total - (total / 110).max(1),
        state_slots: 14,
    };
    let dir = tempfile::tempdir().unwrap();
    {
        let store = FjallStore::open(dir.path()).unwrap();
        let started = Instant::now();
        build(&store, &shape);
        println!(
            "built {} forward + {} backfilled rows in {:.1}s",
            shape.forward,
            shape.backfilled,
            started.elapsed().as_secs_f64()
        );
    }
    let store = FjallStore::open(dir.path()).unwrap();
    let prefix = room_prefix(Keyspace::Log, ROOM);

    println!("phases (warm page cache):");
    let records = timed("scan_prefix (copy every key and value)", || {
        store.scan_prefix(&prefix).unwrap()
    });
    let bytes: usize = records.iter().map(|(k, v)| k.len() + v.len()).sum();
    println!(
        "    {} rows, {} MiB of keys+values",
        records.len(),
        bytes >> 20
    );
    let decoded = timed("EntryRecord::decode every row", || {
        records
            .iter()
            .map(|(_, value)| EntryRecord::decode(value).unwrap())
            .collect::<Vec<_>>()
    });
    drop(records);
    timed("chain recompute only", || {
        let mut chain = ChainHash::seed();
        for record in &decoded {
            if record.chain.is_some() {
                chain = chain.extend(&EventId::new(record.event_id.as_str()));
            }
        }
        chain
    });
    let restored: Vec<RestoredEntry> = timed("RestoredEntry from every record", || {
        decoded
            .iter()
            .map(|record| RestoredEntry {
                li: record.linear_index(),
                event_id: record.event(),
                prev_events: record.parents(),
                depth: record.depth,
                state_key: record.slot(),
                expected_state_root: record.state_root,
                chain: record.chain,
            })
            .collect()
    });
    drop(decoded);
    let mut load_node = |address: &StateRoot| {
        store
            .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))
            .unwrap()
    };
    let log = timed("RoomLog::restore_runtime (core only)", || {
        RoomLog::restore_runtime(
            restored,
            shape.forward + 1,
            -shape.backfilled,
            [EventId::new(event_id(shape.forward))],
            &mut load_node,
        )
        .unwrap()
        .log
    });
    timed("drop the restored log", || drop(log));

    // Memory is measured in a fresh process: this one's allocator holds
    // on to everything the phases above freed, so its resident set says
    // nothing about what a load costs a server that has just started.
    drop(store);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "cold_load_in_a_fresh_process",
            "--nocapture",
        ])
        .env("SPINDLE_COLD_STORE", dir.path())
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&child.stdout));
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let store = FjallStore::open(dir.path()).unwrap();

    let room = RoomStore::new(&store, ROOM);
    for run in 0..2 {
        let log = timed(&format!("load_runtime (run {run})"), || {
            room.load_runtime().unwrap().unwrap().log
        });
        assert_eq!(log.len(), usize::try_from(total).unwrap());
        timed("drop the restored log", || drop(log));
    }
}

/// The child half of [`profile_cold_load_of_a_huge_room`]: one load, in a
/// process that has done nothing else, so its resident set is the load's.
#[test]
#[ignore = "run by profile_cold_load_of_a_huge_room"]
fn cold_load_in_a_fresh_process() {
    let Some(path) = std::env::var_os("SPINDLE_COLD_STORE") else {
        return;
    };
    let store = FjallStore::open(path).unwrap();
    let (before, _) = rss();
    reset_peak();
    let started = Instant::now();
    let log = RoomStore::new(&store, ROOM)
        .load_runtime()
        .unwrap()
        .unwrap()
        .log;
    let elapsed = started.elapsed();
    let (after, peak) = rss();
    println!(
        "  {:<42} {:>8.3}s  rss {before:>5} -> {after:>5} MiB  peak {peak:>5} MiB  ({} entries)",
        "load_runtime, fresh process",
        elapsed.as_secs_f64(),
        log.len()
    );
}
