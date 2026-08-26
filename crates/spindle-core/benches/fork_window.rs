//! Comparative benchmark: bounded fork-window search vs. the exhaustive walk it
//! replaces, across room sizes.
//!
//! The claim under test is SPEC §9: handling a fork costs what the fork costs,
//! not what the room's history costs. The exhaustive implementation here is the
//! shape the code had before #30 — and the shape a DAG homeserver is forced
//! into, since without a linear index there is no cheap reverse-topological
//! order to walk in.
//!
//! Run with `cargo bench -p spindle-core`.

use std::collections::{BTreeSet, HashMap};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use spindle_core::{EventId, EventInput, LogEntry, RoomLog};

/// The pre-#30 walk: every ancestor of every tip, back to the room's first
/// event, then intersect.
fn exhaustive(room: &RoomLog, tips: &[EventId]) -> usize {
    let by_id: HashMap<&str, &LogEntry> = room
        .entries()
        .map(|entry| (entry.event_id.as_str(), entry))
        .collect();

    let mut ancestries = Vec::new();
    for tip in tips {
        let mut seen = BTreeSet::new();
        let mut pending = vec![tip.clone()];
        while let Some(id) = pending.pop() {
            let Some(entry) = by_id.get(id.as_str()) else {
                continue;
            };
            if !seen.insert(entry.li.get()) {
                continue;
            }
            pending.extend(entry.prev_events.iter().cloned());
        }
        ancestries.push(seen);
    }

    let mut common = ancestries[0].clone();
    for ancestry in &ancestries[1..] {
        common.retain(|li| ancestry.contains(li));
    }
    ancestries
        .into_iter()
        .flatten()
        .filter(|li| !common.contains(li))
        .collect::<BTreeSet<_>>()
        .len()
}

/// A linear room of `history` events with a two-event fork at the tip — the
/// shape a concurrent send from a legacy peer actually produces.
fn room_with_tip_fork(history: usize) -> (RoomLog, Vec<EventId>) {
    let mut room = RoomLog::new();
    room.append_local("$genesis", None).unwrap();
    for number in 0..history {
        room.append_local(format!("$live-{number}"), None).unwrap();
    }
    let head = room.forward_extremities().iter().next().unwrap().clone();
    room.append_remote(EventInput::new("$stale", vec![head]))
        .unwrap();
    room.append_local("$after", None).unwrap();

    (room, vec![EventId::new("$stale"), EventId::new("$after")])
}

fn fork_window(c: &mut Criterion) {
    let mut group = c.benchmark_group("fork_window/two_event_fork");

    for history in [100_usize, 1_000, 10_000] {
        let (room, tips) = room_with_tip_fork(history);

        // Throughput is room size: flat ns/iter as this grows is the claim.
        group.throughput(Throughput::Elements(history as u64));

        group.bench_with_input(BenchmarkId::new("bounded", history), &history, |b, _| {
            b.iter(|| {
                let window = room.fork_window(&tips, 512).unwrap();
                std::hint::black_box(window.events.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("exhaustive", history), &history, |b, _| {
            b.iter(|| std::hint::black_box(exhaustive(&room, &tips)));
        });
    }

    group.finish();
}

criterion_group!(benches, fork_window);
criterion_main!(benches);
