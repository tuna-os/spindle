//! What a delayed event costs, at the sizes a call actually reaches.
//!
//! #36 asks for these because delayed-event handling is a performance
//! claim, and the claim is specifically about `restart`: `MatrixRTC`
//! refreshes the pending departure of every participant in every live
//! call, continuously, so `restart` runs far more often than schedule or
//! cancel and was built not to touch storage. A benchmark is how that
//! stops being an assertion.
//!
//! Per #34's policy the interesting output is the **shape across sizes**,
//! not the absolute times: these numbers are only comparable against each
//! other, on one machine, in one run.
//!
//! Sizes are chosen to mean something rather than to be round. A delay per
//! participant is what `MatrixRTC` keeps, so 10 / 100 / 1,000 live delays in
//! a room is a small call, a large call, and a call larger than any client
//! renders. The pending counts for the scan go to 10,000 because that is a
//! server holding many calls at once, which is where a scan proportional
//! to everything pending would start to hurt.
//!
//! Run with `cargo bench -p spindle-server --bench delayed_events`.

use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use spindle_server::delayed::{Action, Delayed};
use spindle_store::FjallStore;

/// A `Delayed` over a fresh store, with caps lifted out of the way.
///
/// The count cap exists to stop one sender hoarding rows; here it would
/// only stop the benchmark reaching the sizes #36 names, and the thing
/// under test is unrelated to it.
fn delayed(tmp: &tempfile::TempDir) -> Delayed {
    let store = Arc::new(FjallStore::open(tmp.path()).expect("the store opens"));
    Delayed::with_limits(store, 24 * 60 * 60 * 1000, usize::MAX)
}

/// One delay per participant, which is what a live call holds.
///
/// Returns `(delay_id, sender)` pairs: the sender is carried rather than
/// looked up, so the measured loop does no bookkeeping of its own.
fn a_call_of(delayed: &Delayed, participants: usize, delay_ms: u64) -> Vec<(String, String)> {
    (0..participants)
        .map(|number| {
            let sender = format!("@participant{number}:example.org");
            let id = delayed
                .schedule(
                    "!call:example.org",
                    &sender,
                    "m.rtc.member",
                    Some(&sender),
                    &serde_json::json!({ "memberships": [] }),
                    delay_ms,
                )
                .expect("the delay is scheduled");
            (id, sender)
        })
        .collect()
}

/// The hot path: one heartbeat from one participant.
///
/// Measured per call rather than per call-round, so the number to compare
/// across sizes is "what one participant's heartbeat costs when N of them
/// are live". If that is flat, the in-memory deadline is doing its job; if
/// it climbs, something is walking the other participants.
fn restart_throughput(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("delayed/restart");
    for participants in [10_usize, 100, 1_000] {
        let tmp = tempfile::TempDir::new().expect("a temporary directory");
        let delayed = delayed(&tmp);
        let ids = a_call_of(&delayed, participants, 60_000);
        let mut next = 0_usize;
        group.bench_with_input(
            BenchmarkId::from_parameter(participants),
            &participants,
            |bencher, _| {
                bencher.iter(|| {
                    // Round-robin so no single row is kept artificially warm.
                    let (id, sender) = &ids[next % ids.len()];
                    next += 1;
                    delayed
                        .act(id, sender, Action::Restart)
                        .expect("the restart succeeds");
                });
            },
        );
    }
    group.finish();
}

/// The reload: what the fire loop pays on a tick when nothing is due.
///
/// #36 anticipated a heap to rebuild on room open, and asked what 10,000
/// pending delays cost to reload. This implementation has no heap to
/// rebuild -- the queue is an ordered keyspace -- so the question becomes
/// what an idle tick costs with that much pending behind it.
///
/// **This is the one that came out wrong, and finding it is what the
/// benchmark was for.** `due` breaks out of its loop at the first row
/// that is not due yet, but the scan underneath it (`ReadView::scan_from`)
/// returned a `Vec`, so every pending row was read and collected before
/// the first deadline was looked at: the break saved the JSON parse, not
/// the read. Measured on one machine: 23 us at 100 pending, 284 us at
/// 1,000, 3.1 ms at 10,000 -- linear in what is *pending*, on a tick that
/// runs every 100 ms whether or not anything is due. Filed as #348.
///
/// Fixed in #350: the deadline is the leading part of the key, so
/// "everything due" is exactly a range ending at now, and `due` asks for
/// that range through `ReadView::scan_until` instead of for the whole
/// prefix. It is flat across these sizes now -- the numbers are in
/// `docs/benchmarks.md` -- so what this benchmark measures today is that
/// it stays that way. The cheap guard is the row count rather than the
/// clock: `delayed::restart_hot_path_tests` fails on the regression in
/// CI, and this reports what it costs.
fn idle_tick(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("delayed/idle_tick");
    for pending in [100_usize, 1_000, 10_000] {
        let tmp = tempfile::TempDir::new().expect("a temporary directory");
        let delayed = delayed(&tmp);
        // Far enough out that none of them is due while the benchmark runs.
        let _ids = a_call_of(&delayed, pending, 60 * 60 * 1000);
        group.bench_with_input(
            BenchmarkId::from_parameter(pending),
            &pending,
            |bencher, _| {
                bencher.iter(|| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
                        .unwrap_or(0);
                    let due = delayed.due(now).expect("the scan succeeds");
                    assert!(due.is_empty(), "nothing is due yet at this size");
                });
            },
        );
    }
    group.finish();
}

/// The other half of the same question: a tick where everything *is* due.
///
/// This one is expected to climb, and should -- the work is proportional
/// to what fires, which is the cost the design accepts. Reported beside
/// the idle tick so the two shapes can be read together: flat when
/// nothing is due, linear in what does.
fn firing_tick(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("delayed/firing_tick");
    // Each sample rebuilds a store and schedules the whole batch, so the
    // default sample count would spend hours writing setup rows.
    group.sample_size(10);
    for due_now in [100_usize, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(due_now),
            &due_now,
            |bencher, _| {
                bencher.iter_batched(
                    || {
                        let tmp = tempfile::TempDir::new().expect("a temporary directory");
                        let delayed = delayed(&tmp);
                        // Due immediately: scheduled with no delay at all.
                        let _ids = a_call_of(&delayed, due_now, 0);
                        (tmp, delayed)
                    },
                    |(_tmp, delayed)| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
                            .unwrap_or(0);
                        let due = delayed
                            .due(now.saturating_add(1))
                            .expect("the scan succeeds");
                        assert_eq!(due.len(), due_now, "all of them are due");
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, restart_throughput, idle_tick, firing_tick);
criterion_main!(benches);
