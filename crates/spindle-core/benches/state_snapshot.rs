//! Comparative benchmark: the persistent state trie against the alternatives it
//! was chosen over.
//!
//! The claim under test is SPEC §6.1: room state is a persistent structure with
//! structural sharing, so keeping a snapshot per event costs `O(log n)` nodes
//! per change rather than a copy of the whole state. That is only worth the
//! hand-rolled HAMT if it actually beats the two obvious alternatives — cloning
//! a `HashMap` per event, and an off-the-shelf persistent map.
//!
//! A log keeps every intermediate snapshot, so each benchmark below retains all
//! of them. Measuring only the final state would flatter the naive version by
//! letting each clone be dropped immediately, which is not how the log uses it.
//!
//! Run with `cargo bench -p spindle-core --bench state_snapshot`.

use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use spindle_core::{StateKey, StateSnapshot};

fn slots(count: usize) -> Vec<(StateKey, String)> {
    (0..count)
        .map(|number| {
            (
                StateKey::new("m.room.member", format!("@user{number}:example.org")),
                format!("$event-{number}"),
            )
        })
        .collect()
}

fn seeded_trie(entries: &[(StateKey, String)]) -> StateSnapshot {
    let mut state = StateSnapshot::new();
    for (key, event_id) in entries {
        state = state.apply(key.clone(), event_id.as_str());
    }
    state
}

/// Applying updates while retaining every intermediate snapshot, as the log does.
fn retained_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/retained_updates");

    for size in [100_usize, 1_000, 10_000] {
        // Sizes span two orders of magnitude so the shape, not one number, shows.
        let entries = slots(size);

        group.bench_with_input(BenchmarkId::new("hamt", size), &entries, |b, entries| {
            b.iter(|| {
                let mut history = Vec::with_capacity(entries.len());
                let mut state = StateSnapshot::new();
                for (key, event_id) in entries {
                    state = state.apply(key.clone(), event_id.as_str());
                    history.push(state.clone());
                }
                std::hint::black_box(history.len())
            });
        });

        group.bench_with_input(BenchmarkId::new("imbl", size), &entries, |b, entries| {
            b.iter(|| {
                let mut history = Vec::with_capacity(entries.len());
                let mut state: imbl::HashMap<String, String> = imbl::HashMap::new();
                for (key, event_id) in entries {
                    state.insert(key.state_key().to_owned(), event_id.clone());
                    history.push(state.clone());
                }
                std::hint::black_box(history.len())
            });
        });

        // Cloning the whole map per event is quadratic in the number of state
        // events, so it is only measured where it finishes. At 10,000 it does
        // not: ~50M entry copies per iteration. That omission is the result,
        // not a gap in the data -- it is why the trie exists.
        if size <= 1_000 {
            group.bench_with_input(
                BenchmarkId::new("clone_per_event", size),
                &entries,
                |b, entries| {
                    b.iter(|| {
                        let mut history = Vec::with_capacity(entries.len());
                        let mut state: HashMap<String, String> = HashMap::new();
                        for (key, event_id) in entries {
                            state.insert(key.state_key().to_owned(), event_id.clone());
                            history.push(state.clone());
                        }
                        std::hint::black_box(history.len())
                    });
                },
            );
        }
    }

    group.finish();
}

/// A single lookup against a warm state, which is the auth hot path (§7.1).
fn lookups(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/lookup");

    for size in [1_000_usize, 50_000] {
        let entries = slots(size);
        let trie = seeded_trie(&entries);
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(key, id)| (key.state_key().to_owned(), id.clone()))
            .collect();
        let probe = &entries[size / 2];

        group.bench_with_input(BenchmarkId::new("hamt", size), &probe.0, |b, key| {
            b.iter(|| std::hint::black_box(trie.get(key)));
        });
        group.bench_with_input(BenchmarkId::new("hashmap", size), &probe.0, |b, key| {
            b.iter(|| std::hint::black_box(map.get(key.state_key())));
        });
    }

    group.finish();
}

criterion_group!(benches, retained_updates, lookups);
criterion_main!(benches);
