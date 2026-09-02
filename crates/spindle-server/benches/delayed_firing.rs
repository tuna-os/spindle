//! Firing jitter: how late a delayed event is, against the deadline it was
//! given.
//!
//! The third measurement #36 asks for, and the one criterion cannot
//! express. Criterion times a function; this is a question about wall
//! clocks — an event due at T is appended at T + something, and what
//! matters to `MatrixRTC` is the distribution of that something under load,
//! because it is how long a crashed participant lingers in a call after
//! their departure was supposed to fire.
//!
//! What is measured is `deadline -> the tick that surfaced it`, not the
//! append that follows: the append is the ordinary send path, measured
//! elsewhere, and mixing them would hide which half moved. Two components
//! make up what is measured, and they behave differently, which is the
//! point of reporting a distribution rather than a mean:
//!
//! - the tick interval, which sets a floor and a ceiling: an event due
//!   just after a tick waits nearly a whole one, an event due just before
//!   waits almost nothing, so p50 should sit near half a tick however many
//!   delays are pending;
//! - the scan, which is what could make it worse at scale.
//!
//! So the shape to read is p99 against size. If it tracks the tick and not
//! the count, a call getting larger does not make anybody's departure
//! later.
//!
//! Deliberately not a criterion benchmark and deliberately not run in CI:
//! it sleeps in real time, so it is a measurement to take and record, not
//! a gate. Per #34 the output is the shape across sizes, not the absolute
//! milliseconds, which belong to whatever machine ran it.
//!
//! Run with `cargo bench -p spindle-server --bench delayed_firing`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use spindle_server::delayed::Delayed;
use spindle_store::FjallStore;

/// The fire loop's tick in the server (`lib.rs`), so the numbers here are
/// the ones a deployment would see rather than a figure chosen to flatter.
const TICK: Duration = Duration::from_millis(100);

/// The spread of deadlines across the window, so the sample sees the whole
/// floor-to-ceiling range a tick produces rather than one point of it.
const WINDOW_MS: u64 = 1_000;

/// Headroom added to every deadline so that scheduling finishes before the
/// earliest one falls due.
///
/// Without it this measures the wrong thing, and did on the first run: a
/// deadline is fixed when its delay is scheduled, so with a thousand rows
/// to write the early ones were already overdue by the time the last was
/// stored, and the "jitter" reported at 1,000 was mostly the harness's own
/// setup. `lateness` asserts the headroom held rather than trusting it.
const SETUP_HEADROOM_MS: u64 = 4_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Schedule `participants` delays spread across the window, then run the
/// fire loop's scan until they have all been surfaced, recording how late
/// each one was.
fn lateness(participants: usize) -> Vec<i64> {
    let tmp = tempfile::TempDir::new().expect("a temporary directory");
    let store = Arc::new(FjallStore::open(tmp.path()).expect("the store opens"));
    let delayed = Delayed::with_limits(store, 24 * 60 * 60 * 1000, usize::MAX);

    // Spread across the window rather than all on one deadline: a single
    // deadline would measure one tick's scan repeatedly and hide the
    // floor-and-ceiling behaviour the tick interval produces.
    let mut deadlines = std::collections::HashMap::new();
    let mut earliest = u64::MAX;
    for number in 0..participants {
        let sender = format!("@participant{number}:example.org");
        // Spread proportionally, so every size samples the same window and
        // the rows are comparable: `number % WINDOW_MS` would give ten
        // participants a ten-millisecond band and a thousand the whole
        // second, which is a difference in sampling rather than in the
        // system.
        // ...plus a phase offset inside one tick. Spreading alone is not
        // enough: ten deadlines across a second land exactly 100 ms apart,
        // which is the tick, so every one of them falls at the same point
        // in a tick and the row reports a jitter far below the truth. The
        // offset decorrelates the sample from the tick at every size. 37 is
        // coprime with the tick, so the ten phases it produces are
        // distinct.
        let index = u64::try_from(number).unwrap_or(0);
        let delay_ms = SETUP_HEADROOM_MS
            + (index * WINDOW_MS / u64::try_from(participants.max(1)).unwrap_or(1))
            + (index * 37) % 100;
        let scheduled_at = now_ms();
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
        let deadline = scheduled_at.saturating_add(delay_ms);
        earliest = earliest.min(deadline);
        deadlines.insert(id, deadline);
    }
    // The measurement is only about the fire loop if every deadline is
    // still ahead of us now. If setup overran the headroom, say so instead
    // of reporting the overrun as jitter.
    assert!(
        now_ms() < earliest,
        "setup took longer than the {SETUP_HEADROOM_MS} ms headroom at {participants} delays: \
         raise it rather than reading the numbers"
    );

    let mut late = Vec::with_capacity(participants);
    let deadline_for_giving_up = now_ms().saturating_add(SETUP_HEADROOM_MS + WINDOW_MS * 4);
    while late.len() < participants && now_ms() < deadline_for_giving_up {
        std::thread::sleep(TICK);
        let observed = now_ms();
        for event in delayed.due(observed).expect("the scan succeeds") {
            let Some(deadline) = deadlines.get(&event.delay_id) else {
                continue;
            };
            // Signed: a delay surfaced before its deadline would be a bug
            // worth seeing rather than a zero worth hiding.
            late.push(
                i64::try_from(observed).unwrap_or(i64::MAX)
                    - i64::try_from(*deadline).unwrap_or(i64::MAX),
            );
            delayed.take(&event).expect("the row is taken");
        }
    }
    late
}

/// The value at `percentile` of a sorted sample, nearest-rank.
///
/// Integer arithmetic throughout: the rank is `ceil(p * n / 100)`, which
/// needs no floats and so cannot round a boundary the wrong way on a
/// small sample.
fn at(sorted: &[i64], percentile: usize) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (percentile * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn main() {
    println!("delayed-event firing jitter (tick = {TICK:?})");
    println!();
    println!("| live delays | fired | p50 late | p99 late | max late |");
    println!("|---|---|---|---|---|");
    for participants in [10_usize, 100, 1_000] {
        let mut late = lateness(participants);
        late.sort_unstable();
        println!(
            "| {participants} | {} | {} ms | {} ms | {} ms |",
            late.len(),
            at(&late, 50),
            at(&late, 99),
            late.last().copied().unwrap_or(0),
        );
    }
    println!();
    println!("Read the p99 column against the tick, not against the sizes:");
    println!("jitter that tracks the tick means a larger call does not make");
    println!("anybody's departure land later.");
}
