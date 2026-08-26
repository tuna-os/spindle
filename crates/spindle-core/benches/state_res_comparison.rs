//! The comparison SPEC §18.1 rests on: resolving a fork our way versus running
//! Matrix state resolution v2 over the same fork.
//!
//! `ruma-state-res` is the implementation Conduit, Continuwuity and Tuwunel
//! actually run, so this is the closest thing to a like-for-like measurement
//! against another homeserver without standing one up. #42 is the real thing;
//! this is the algorithmic core of the claim it will test.
//!
//! **What is and is not being compared.** Both sides answer the same question —
//! *given two forked heads, what is the resolved room state?* — but they start
//! from what each design actually has in hand at that moment. Ours starts from
//! two materialized state snapshots, because Spindle paid for materialization
//! at append time. Theirs starts from state maps and auth chains, because that
//! is what a DAG homeserver holds. That asymmetry is the design difference, not
//! a thumb on the scale; the append-side cost it moves is measured separately
//! in `state_snapshot.rs`. Quoting this figure without that sentence would be
//! quoting it dishonestly.
//!
//! Run with `cargo bench -p spindle-core --bench state_res_comparison`.

#[path = "../tests/oracle/mod.rs"]
mod oracle;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oracle::{ALICE, RoomBuilder, auth_chains, reference_resolve_with_chains};
use ruma::state_res::StateMap;
use ruma::{OwnedEventId, events::TimelineEventType};
use serde_json::json;
use spindle_core::{EventId, EventInput, RoomLog, StateKey};

/// Build a fork with `per_side` divergent state writes on each branch.
///
/// Every write lands on its own state slot, so the fork stays in SPEC §9.2's
/// case 2 — the case Spindle claims to resolve without state resolution, and
/// therefore the only case where the comparison says anything.
struct Fork {
    base: RoomBuilder,
    /// Both branches' events in one graph, which is what the resolver needs to
    /// walk auth chains across the fork.
    graph: RoomBuilder,
    states: Vec<StateMap<OwnedEventId>>,
    writes: Vec<Vec<(StateKey, String)>>,
}

fn build(per_side: usize) -> Fork {
    let base = RoomBuilder::new();
    let mut branches = Vec::new();
    let mut writes = Vec::new();

    for (label, prefix) in [("-l", "left"), ("-r", "right")] {
        let mut branch = base.fork(label);
        let mut branch_writes = Vec::new();
        for index in 0..per_side {
            let state_key = format!("{prefix}{index}");
            let id = branch.add(
                ALICE,
                TimelineEventType::RoomTopic,
                Some(state_key.clone()),
                &json!({ "topic": state_key }),
            );
            branch_writes.push((
                StateKey::new("m.room.topic", state_key),
                id.as_str().to_owned(),
            ));
        }
        writes.push(branch_writes);
        branches.push(branch);
    }

    let states = branches.iter().map(RoomBuilder::state_map).collect();
    let mut graph = branches[0].fork("-g");
    graph.absorb(&branches[1]);

    Fork {
        base,
        graph,
        states,
        writes,
    }
}

/// Replay the shared ancestry and both branches into a log, returning the tips.
fn spindle_log(
    base: &RoomBuilder,
    branches: &[Vec<(StateKey, String)>],
) -> (RoomLog, Vec<EventId>) {
    let mut log = RoomLog::new();
    let shared = base.state_map();
    let mut ordered: Vec<_> = shared.iter().collect();
    ordered.sort_by_key(|(_, id)| id.as_str().to_owned());

    let mut head: Option<String> = None;
    for ((event_type, key), id) in ordered {
        head = Some(append(
            &mut log,
            head.as_deref(),
            &StateKey::new(event_type.to_string(), key.clone()),
            id.as_str(),
        ));
    }
    let ancestor = head.expect("the base room is not empty");

    let mut tips = Vec::new();
    for writes in branches {
        let mut branch_head = ancestor.clone();
        for (key, id) in writes {
            branch_head = append(&mut log, Some(&branch_head), key, id);
        }
        tips.push(EventId::new(branch_head));
    }
    (log, tips)
}

fn append(log: &mut RoomLog, parent: Option<&str>, key: &StateKey, event_id: &str) -> String {
    let prev = parent
        .map(|id| vec![EventId::new(id.to_owned())])
        .unwrap_or_default();
    log.append_remote(EventInput::new(event_id.to_owned(), prev).with_state_key(key.clone()))
        .expect("a generated append is valid");
    event_id.to_owned()
}

fn compare(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fork resolution");

    for per_side in [1_usize, 4, 16, 64] {
        let fork = build(per_side);
        // Hoisted: a homeserver stores auth chains rather than rebuilding them
        // per resolution, so charging the reference resolver for that walk on
        // every iteration would be measuring our harness, not their algorithm.
        let chains = auth_chains(&fork.graph, &fork.states[0], &fork.states[1]);
        group.throughput(Throughput::Elements(per_side as u64 * 2));

        group.bench_with_input(
            BenchmarkId::new("ruma-state-res", per_side),
            &per_side,
            |bencher, _| {
                bencher.iter(|| {
                    reference_resolve_with_chains(
                        &fork.graph,
                        &fork.states[0],
                        &fork.states[1],
                        chains.clone(),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("spindle window merge", per_side),
            &per_side,
            |bencher, _| {
                bencher.iter_batched(
                    || spindle_log(&fork.base, &fork.writes),
                    |(mut log, tips)| {
                        let window = log
                            .fork_window(&tips, 512)
                            .expect("the fork is within the window");
                        let merged = log
                            .append_local("$merge", None)
                            .expect("a disjoint fork merges")
                            .li;
                        // Touch both results so neither is optimized away.
                        (window.visited, log.state_after(merged).map(|_| ()))
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, compare);
criterion_main!(benches);
