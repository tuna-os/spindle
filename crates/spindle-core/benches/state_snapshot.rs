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
//! The first two groups measure what the trie *costs* against those
//! alternatives, and it loses some of them (#80 records which). The last two
//! measure what it *buys*, which neither alternative can do at all: `im` has
//! no stable node addresses, so persisting one of its snapshots means
//! serialising everything reachable, and a `HashMap` is not persistent, so a
//! past state is either a copy kept or a replay performed. Both sides of the
//! trade are in this file so a reader can weigh it rather than half of it.
//!
//! Run with `cargo bench -p spindle-core --bench state_snapshot`.

use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use spindle_core::{RoomLog, StateKey, StateRoot, StateSnapshot};

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

/// The bytes a state change has to put on disk.
///
/// Ours is [`StateSnapshot::delta_nodes`]: the nodes on the copied path and
/// nothing else, because every unchanged subtree keeps its content address
/// and the walk stops there. That is the property SPEC §6.1 claims and the
/// reason the trie is content-addressed rather than merely persistent.
///
/// The comparison is an `im` map, which shares structure in memory exactly as
/// well but has no address for a node, so writing a snapshot means writing
/// every entry reachable from it. It is encoded here as length-framed
/// key/value pairs -- the floor of any serialisation, with no format overhead
/// charged to it -- so the gap measured is the gap in *what* must be written,
/// not in how cleverly.
fn persist(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/persist");

    for size in [100_usize, 1_000, 10_000] {
        let entries = slots(size);
        let trie = seeded_trie(&entries);
        let map: imbl::HashMap<String, String> = entries
            .iter()
            .map(|(key, id)| (key.state_key().to_owned(), id.clone()))
            .collect();
        let update = (StateKey::new("m.room.topic", ""), "$topic".to_owned());

        let delta_bytes: usize = trie
            .apply(update.0.clone(), update.1.as_str())
            .delta_nodes(Some(&trie))
            .iter()
            .map(|(_, node)| node.len())
            .sum();
        group.throughput(Throughput::Bytes(delta_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("hamt_delta", size),
            &(&trie, &update),
            |b, (trie, (key, id))| {
                b.iter(|| {
                    let after = trie.apply(key.clone(), id.as_str());
                    let nodes = after.delta_nodes(Some(trie));
                    std::hint::black_box(nodes.iter().map(|(_, node)| node.len()).sum::<usize>())
                });
            },
        );

        let mut serialised = map.clone();
        serialised.insert(update.0.state_key().to_owned(), update.1.clone());
        group.throughput(Throughput::Bytes(encode_map(&serialised).len() as u64));
        group.bench_with_input(
            BenchmarkId::new("im_serialise", size),
            &(&map, &update),
            |b, (map, (key, id))| {
                b.iter(|| {
                    let mut after = (*map).clone();
                    after.insert(key.state_key().to_owned(), id.clone());
                    std::hint::black_box(encode_map(&after).len())
                });
            },
        );
    }

    group.finish();
}

/// Length-framed key/value pairs: what an `im` snapshot costs to write with
/// no format overhead at all.
fn encode_map(map: &imbl::HashMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in map {
        out.extend_from_slice(&u32::try_from(key.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// The state as it stood at some earlier point in the log.
///
/// This is what `/context` on an old event, an authorization check on a
/// late-arriving federated event, and a rejoin all ask for. Three ways to
/// answer it, all measured:
///
/// - `resident`: the point is inside the window the log keeps in memory
///   (`DEFAULT_RESIDENT_WINDOW`, 512 snapshots); the answer is a clone of an
///   `Arc`, whatever the state size.
/// - `rehydrate`: the point is older than the window, so the snapshot is
///   rebuilt from the node store by content address, every node verified.
///   This is proportional to the state, and it is the row this file expects
///   to *lose* -- a DAG server's delta walk does not read the whole state.
/// - `delta_replay_100`: what a state-groups server does when the point is
///   not itself a stored snapshot: take the nearest full state and replay
///   the deltas up to the point. Synapse caps that chain at 100 hops
///   (`_MAX_STATE_DELTA_HOPS`), so 100 is the worst case it allows itself.
///   Modelled on an `im` map, which is the most charitable substrate for it.
///
/// The honest reading is the pair: inside the window the linear log answers
/// in constant time where a delta walk pays per hop; outside it, it pays for
/// the whole state where a delta walk still pays per hop. Where the window
/// ends is therefore a real tuning question, not a detail.
fn history_at(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/history_at");

    for size in [100_usize, 1_000, 10_000] {
        let entries = slots(size);

        // A log whose every entry is a state event, so the state at li is
        // the first li entries applied. Snapshots beyond the window are
        // written to a node store the way `RoomStore` writes them.
        let mut log = RoomLog::new();
        let mut nodes: HashMap<StateRoot, Vec<u8>> = HashMap::new();
        let mut previous: Option<StateSnapshot> = None;
        for (index, (key, _)) in entries.iter().enumerate() {
            let li = log
                .append_local(format!("$event-{index}"), Some(key.clone()))
                .expect("a fresh chain never conflicts")
                .li;
            // The log's own apply happens on append; the bench stores what
            // that produced, exactly as the store does.
            let state = log
                .state_after(li)
                .expect("just appended, so resident")
                .clone();
            for (address, bytes) in state.delta_nodes(previous.as_ref()) {
                nodes.insert(address, bytes);
            }
            previous = Some(state);
        }
        let entries_in_log: Vec<_> = log
            .entries()
            .map(|entry| (entry.li, entry.state_root))
            .collect();
        // The point asked for: the middle of the room. Resident when the
        // room fits in the window, rehydrated otherwise -- both are measured
        // regardless, since the window is a setting.
        let root = entries_in_log[size / 2].1;
        let resident_li = entries_in_log[entries_in_log.len() - 1].0;

        group.bench_with_input(BenchmarkId::new("resident", size), &resident_li, |b, li| {
            b.iter(|| std::hint::black_box(log.state_after(*li).cloned()));
        });

        group.bench_with_input(BenchmarkId::new("rehydrate", size), &root, |b, root| {
            b.iter(|| {
                let mut load = |address: &StateRoot| nodes.get(address).cloned();
                std::hint::black_box(
                    StateSnapshot::rehydrate(*root, &mut load).map(|state| state.len()),
                )
            });
        });

        let map: imbl::HashMap<String, String> = entries[..size.saturating_sub(100)]
            .iter()
            .map(|(key, id)| (key.state_key().to_owned(), id.clone()))
            .collect();
        let hops: Vec<_> = entries[size.saturating_sub(100)..].to_vec();
        group.bench_with_input(
            BenchmarkId::new("delta_replay_100", size),
            &(&map, &hops),
            |b, (map, hops)| {
                b.iter(|| {
                    let mut state = (*map).clone();
                    for (key, id) in *hops {
                        state.insert(key.state_key().to_owned(), id.clone());
                    }
                    std::hint::black_box(state.len())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, retained_updates, lookups, persist, history_at);
criterion_main!(benches);
