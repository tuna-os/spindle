//! The counters SPEC §17.2 names, in the Prometheus text format (#166).
//!
//! The one that matters is the fork-case split from §9.2. §18.3 states the
//! design's falsifiable target — *case-3 fork resolutions as a fraction of
//! federated events, below 0.1%* — and a target nobody counts is a slogan.
//! This module is where that number comes from, which is also what #16
//! needs to assert that a test took the cheap path rather than silently
//! taking an expensive one.
//!
//! **No metrics crate.** Three counters and a text format that has not
//! changed in a decade did not justify a dependency, and the exposition
//! format is the contract either way — the tests here assert it directly.
//! Slice 2's histograms are where a library starts earning its keep; that
//! is the point to reconsider, and reconsidering costs one module.
//!
//! The registry is process-global, as metrics registries conventionally
//! are: threading a handle through every constructor to reach two call
//! sites deep in the append path buys nothing. The consequence for tests
//! is that counters accumulate across them, so assertions here are on
//! *deltas* rather than absolute values — which is what a scrape does
//! anyway.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

/// Which of §9.2's three cases an append took.
///
/// The classification is exactly the spec's, decided by what the event is
/// rather than by what the code did, so the counter cannot drift from the
/// argument it exists to test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkCase {
    /// Case 1 — a non-state event. Cannot conflict; no resolution.
    NonState,
    /// Case 2 — a state event whose key nothing in the window touched.
    /// One `apply()`; no resolution.
    StateUncontested,
    /// Case 3 — a state event contested inside the window. The expensive
    /// path, and the one §18.3 says must stay under 0.1% of federated
    /// events.
    StateContested,
}

/// Where an event entered from. The denominator of §18.3's target is
/// federated events specifically, so the two are counted apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Local,
    Federated,
}

// Relaxed throughout: these are counters read by a scrape, never used to
// order anything. Paying for stronger ordering on the append hot path to
// make a number that is sampled every 15 seconds marginally fresher would
// be a poor trade.
static FORK_CASES: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static EVENTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// `[exclusive, shared]` acquisitions of one room's lock.
static ROOM_LOCKS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// `[exclusive, shared]` acquisitions of the registry that finds rooms.
static REGISTRY_LOCKS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

impl ForkCase {
    fn index(self) -> usize {
        match self {
            Self::NonState => 0,
            Self::StateUncontested => 1,
            Self::StateContested => 2,
        }
    }

    /// The label value, which is the spec's case number.
    fn label(self) -> &'static str {
        match self {
            Self::NonState => "1",
            Self::StateUncontested => "2",
            Self::StateContested => "3",
        }
    }
}

impl Origin {
    fn index(self) -> usize {
        match self {
            Self::Local => 0,
            Self::Federated => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Federated => "federated",
        }
    }
}

/// Record one acquisition of a *room's* lock, and how it was taken.
///
/// Contention here is confined to that room: two requests for different
/// rooms do not meet. Exclusive is what an append takes, and what makes
/// concurrent writers to the same room queue -- which is the ordering the
/// log rests on, not a defect.
pub fn record_room_lock(exclusive: bool) {
    ROOM_LOCKS[usize::from(!exclusive)].fetch_add(1, Ordering::Relaxed);
}

/// Record one acquisition of the registry that maps room ids to their locks.
///
/// This one *is* server-wide, so an exclusive acquisition stalls every
/// request for every room. It should be rare: the registry is taken
/// exclusively only to admit a room this process has not opened yet, and
/// shared for every lookup after. A rising exclusive count on a server that
/// is not opening new rooms means something is taking it that should not.
pub fn record_registry_lock(exclusive: bool) {
    REGISTRY_LOCKS[usize::from(!exclusive)].fetch_add(1, Ordering::Relaxed);
}

/// Record one event reaching the log, and which case carried it.
pub fn record_append(origin: Origin, case: ForkCase) {
    EVENTS[origin.index()].fetch_add(1, Ordering::Relaxed);
    FORK_CASES[case.index()].fetch_add(1, Ordering::Relaxed);
}

/// Record a fork that needed state resolution — case 3.
///
/// Not an append, so not [`record_append`]: nothing enters the log when
/// this is recorded. Bounded resolution exists in `spindle-core` but is not
/// yet wired into ingest (#16), so a contested fork is *deferred* rather
/// than resolved. A federated event naming the contesting tips is refused;
/// a local send sets the contesting tip aside and is authored without it
/// (#225), and that send is then counted by [`record_append`] as the case
/// it took. Counting an event here as well would count that send twice.
/// The counter goes where the decision is made, so it keeps counting the
/// same thing when the resolver lands and the deferral becomes a
/// resolution.
pub fn record_contested_state() {
    FORK_CASES[ForkCase::StateContested.index()].fetch_add(1, Ordering::Relaxed);
}

/// The exposition, in the Prometheus text format.
#[must_use]
pub fn render() -> String {
    let mut out = String::with_capacity(2048);
    render_build_info(&mut out);
    render_appends(&mut out);
    render_room_locks(&mut out);
    render_http(&mut out);
    render_federation(&mut out);
    render_sync(&mut out);
    out
}

fn render_build_info(out: &mut String) {
    out.push_str(
        "# HELP spindle_build_info The version this process is running.\n\
         # TYPE spindle_build_info gauge\n",
    );
    let _ = writeln!(
        out,
        "spindle_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
}

/// The §9.2 case split, the federated-event denominator §18.3 needs, and
/// the commit histogram those targets are stated against.
fn render_appends(out: &mut String) {
    out.push_str(
        "# HELP spindle_events_appended_total Events appended to a room log.\n\
         # TYPE spindle_events_appended_total counter\n",
    );
    for origin in [Origin::Local, Origin::Federated] {
        let _ = writeln!(
            out,
            "spindle_events_appended_total{{origin=\"{}\"}} {}",
            origin.label(),
            EVENTS[origin.index()].load(Ordering::Relaxed)
        );
    }

    out.push_str(
        "# HELP spindle_fork_resolutions_total Appends by SPEC 9.2 case; \
         case 3 is the expensive path and should stay near zero.\n\
         # TYPE spindle_fork_resolutions_total counter\n",
    );
    for case in [
        ForkCase::NonState,
        ForkCase::StateUncontested,
        ForkCase::StateContested,
    ] {
        let _ = writeln!(
            out,
            "spindle_fork_resolutions_total{{case=\"{}\"}} {}",
            case.label(),
            FORK_CASES[case.index()].load(Ordering::Relaxed)
        );
    }

    out.push_str(
        "# HELP spindle_append_duration_seconds Time to commit one event to a room log.\n\
         # TYPE spindle_append_duration_seconds histogram\n",
    );
    if let Ok(read) = APPEND_LATENCY.read() {
        for (durability, histogram) in read.iter() {
            histogram.render_into(
                out,
                "spindle_append_duration_seconds",
                &format!("durability=\"{}\"", escape(durability)),
            );
        }
    }
}

fn render_room_locks(out: &mut String) {
    out.push_str(
        "# HELP spindle_room_registry_acquisitions_total Room registry lock \
         acquisitions, by mode.\n\
         # TYPE spindle_room_registry_acquisitions_total counter\n",
    );
    for (index, mode) in ["exclusive", "shared"].into_iter().enumerate() {
        let _ = writeln!(
            out,
            "spindle_room_registry_acquisitions_total{{mode=\"{mode}\"}} {}",
            REGISTRY_LOCKS[index].load(Ordering::Relaxed)
        );
    }
    out.push_str(
        "# HELP spindle_room_lock_acquisitions_total One room's lock \
         acquisitions, by mode.\n\
         # TYPE spindle_room_lock_acquisitions_total counter\n",
    );
    for (index, mode) in ["exclusive", "shared"].into_iter().enumerate() {
        let _ = writeln!(
            out,
            "spindle_room_lock_acquisitions_total{{mode=\"{mode}\"}} {}",
            ROOM_LOCKS[index].load(Ordering::Relaxed)
        );
    }
}

fn render_http(out: &mut String) {
    out.push_str(
        "# HELP spindle_http_request_duration_seconds Time to serve one request, by matched route.\n\
         # TYPE spindle_http_request_duration_seconds histogram\n",
    );
    if let Ok(read) = HTTP_LATENCY.read() {
        for (route, histogram) in read.iter() {
            histogram.render_into(
                out,
                "spindle_http_request_duration_seconds",
                &format!("route=\"{}\"", escape(route)),
            );
        }
    }

    out.push_str(
        "# HELP spindle_http_requests_total Requests served, by matched route, method and status.\n\
         # TYPE spindle_http_requests_total counter\n",
    );
    if let Ok(read) = HTTP_REQUESTS.read() {
        for (key, counter) in read.iter() {
            let mut parts = key.split('\u{1}');
            let (Some(route), Some(method), Some(status)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let _ = writeln!(
                out,
                "spindle_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {}",
                escape(route),
                escape(method),
                escape(status),
                counter.load(Ordering::Relaxed)
            );
        }
    }
}

fn render_federation(out: &mut String) {
    out.push_str(
        "# HELP spindle_federation_queue_depth Events waiting to be delivered, by destination.\n\
         # TYPE spindle_federation_queue_depth gauge\n",
    );
    if let Ok(read) = FEDERATION_QUEUE.read() {
        for (destination, depth) in read.iter() {
            let _ = writeln!(
                out,
                "spindle_federation_queue_depth{{destination=\"{}\"}} {depth}",
                escape(destination)
            );
        }
    }
}

fn render_sync(out: &mut String) {
    out.push_str(
        "# HELP spindle_sync_subscribers Clients currently blocked in a long-polling /sync.\n\
         # TYPE spindle_sync_subscribers gauge\n",
    );
    let _ = writeln!(
        out,
        "spindle_sync_subscribers {}",
        SYNC_SUBSCRIBERS.load(Ordering::Relaxed)
    );

    out.push_str(
        "# HELP spindle_sync_lag_seconds Age of the newest event a /sync delivered.\n\
         # TYPE spindle_sync_lag_seconds histogram\n",
    );
    if let Ok(read) = SYNC_LAG.read() {
        for histogram in read.values() {
            histogram.render_into(out, "spindle_sync_lag_seconds", "");
        }
    }
}

/// Bucket bounds, in seconds.
///
/// Weighted to where SPEC §18.3 puts its targets — local send p50 under
/// 2 ms and p99 under 10 ms — because buckets that straddle the target
/// are the ones that can tell you whether you met it. The default set
/// most libraries ship starts at 5 ms, which would put every one of
/// those appends in the first bucket and answer nothing.
const BUCKETS: [f64; 12] = [
    0.000_5, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// A Prometheus histogram: per-bucket counts, a sum and a total.
///
/// Counts are per-bucket here and made cumulative at render, which is
/// what the exposition format wants; doing it the other way would mean
/// touching every bucket above the observation on the hot path.
#[derive(Debug)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS.len()],
    /// Microseconds, so the sum needs no float atomic. Rendered as
    /// seconds, which is the unit the metric name promises.
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self {
            buckets: [ZERO; BUCKETS.len()],
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// A [`Duration`] rather than seconds, so the microsecond sum is an
    /// integer conversion the type system checks rather than a float
    /// cast that has to be reasoned about.
    fn observe(&self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let slot = BUCKETS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(BUCKETS.len());
        if let Some(bucket) = self.buckets.get(slot) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        // Saturating: a duration past u64 microseconds is 584,000 years,
        // which is a clock fault rather than a measurement — and a
        // wrapped sum would misreport every observation after it.
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Render as `name{labels,le="..."}` triples plus `_sum` and `_count`.
    fn render_into(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0;
        let separator = if labels.is_empty() { "" } else { "," };
        for (index, bound) in BUCKETS.iter().enumerate() {
            cumulative += self.buckets[index].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{bound}\"}} {cumulative}"
            );
        }
        // The overflow slot lives past the named bounds, so +Inf is the
        // total rather than the last cumulative sum.
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}"
        );
        // Exact until the accumulated total passes f64's 52-bit
        // mantissa, which for microseconds is about 142 years of
        // measured time in one series.
        #[allow(clippy::cast_precision_loss)]
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "{name}_sum{{{labels}}} {sum}");
        let _ = writeln!(out, "{name}_count{{{labels}}} {count}");
    }
}

/// A histogram per label value.
///
/// Read-mostly: after the first request through a route the entry
/// exists, so the hot path takes a read lock and nothing else. The key
/// sets are bounded by code — the durability modes the store offers,
/// and the router's own matched paths — never by anything a caller
/// chooses, which is the cardinality rule #166 sets.
type Family = LazyLock<RwLock<HashMap<String, Histogram>>>;

static APPEND_LATENCY: Family = LazyLock::new(RwLock::default);
static HTTP_LATENCY: Family = LazyLock::new(RwLock::default);
static HTTP_REQUESTS: LazyLock<RwLock<HashMap<String, AtomicU64>>> = LazyLock::new(RwLock::default);

fn observe_in(family: &Family, key: &str, elapsed: Duration) {
    if let Ok(read) = family.read()
        && let Some(histogram) = read.get(key)
    {
        histogram.observe(elapsed);
        return;
    }
    if let Ok(mut write) = family.write() {
        write
            .entry(key.to_owned())
            .or_insert_with(Histogram::new)
            .observe(elapsed);
    }
}

/// Record how long a commit took, by the durability it was asked for.
///
/// SPEC §18.3's local-send targets are stated against `group`, so the
/// label is what makes the number comparable to the target rather than
/// an average over settings nobody runs together.
pub fn observe_append(durability: &str, elapsed: Duration) {
    observe_in(&APPEND_LATENCY, durability, elapsed);
}

/// Record one served request.
///
/// `route` must be the router's matched path (`/rooms/{room_id}/...`),
/// never the raw URI: the raw path carries room and user IDs, and a
/// label taking values from the request would let any caller mint
/// series until the scrape falls over.
pub fn observe_request(route: &str, method: &str, status: u16, elapsed: Duration) {
    observe_in(&HTTP_LATENCY, route, elapsed);
    let key = format!("{route}\u{1}{method}\u{1}{status}");
    if let Ok(read) = HTTP_REQUESTS.read()
        && let Some(counter) = read.get(&key)
    {
        counter.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Ok(mut write) = HTTP_REQUESTS.write() {
        write
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// How many destinations get their own series before the rest are
/// summed into `other`.
///
/// The label set must not be something a stranger can grow: a room full
/// of fabricated server names would otherwise mint a series each and
/// make the scrape the attack. Twenty is well past what a single-node
/// deployment federates with in anger, and the tail is not lost — it is
/// added up.
const DESTINATION_CAP: usize = 20;

static FEDERATION_QUEUE: LazyLock<RwLock<Vec<(String, u64)>>> = LazyLock::new(RwLock::default);
static SYNC_SUBSCRIBERS: AtomicU64 = AtomicU64::new(0);
static SYNC_LAG: Family = LazyLock::new(RwLock::default);

/// Replace the federation queue depths with a fresh reading.
///
/// A gauge, so it is *set* rather than added to: the delivery loop knows
/// the whole picture each pass, and carrying stale destinations forward
/// would report a backlog for a peer that has none. Deepest first, with
/// everything past the cap summed into `other`.
pub fn set_federation_queue(depths: &[(String, u64)]) {
    let mut sorted: Vec<(String, u64)> = depths.to_vec();
    sorted.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let mut capped: Vec<(String, u64)> = sorted.iter().take(DESTINATION_CAP).cloned().collect();
    let rest: u64 = sorted
        .iter()
        .skip(DESTINATION_CAP)
        .map(|(_, depth)| depth)
        .sum();
    if rest > 0 {
        capped.push(("other".to_owned(), rest));
    }
    if let Ok(mut write) = FEDERATION_QUEUE.write() {
        *write = capped;
    }
}

/// A `/sync` has started waiting.
pub fn sync_waiter_started() {
    SYNC_SUBSCRIBERS.fetch_add(1, Ordering::Relaxed);
}

/// A `/sync` has stopped waiting, woken or timed out.
pub fn sync_waiter_finished() {
    // Saturating: an unbalanced decrement would wrap to u64::MAX and
    // report every client on earth as connected to this server.
    let _ = SYNC_SUBSCRIBERS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

/// How far behind the newest event a sync response was.
///
/// "Watermark lag" is ambiguous, so this picks the definition an
/// operator can act on: the age of the newest event a `/sync` actually
/// delivered, measured when it is delivered. A client keeping up sees
/// milliseconds; a server falling behind sees it climb, which is the
/// symptom #19's exit criteria ask to alert on.
pub fn observe_sync_lag(elapsed: Duration) {
    observe_in(&SYNC_LAG, "", elapsed);
}

/// Read the subscriber gauge, for tests that assert it moved.
#[must_use]
pub fn sync_subscribers() -> u64 {
    SYNC_SUBSCRIBERS.load(Ordering::Relaxed)
}

/// Escape a label value per the exposition format.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Read one counter, for tests that assert a metric actually moved.
#[must_use]
pub fn fork_case_count(case: ForkCase) -> u64 {
    FORK_CASES[case.index()].load(Ordering::Relaxed)
}

/// Read one counter, for tests that assert a metric actually moved.
#[must_use]
pub fn event_count(origin: Origin) -> u64 {
    EVENTS[origin.index()].load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every counter moves when its case does, and the exposition says so.
    ///
    /// Deltas, not absolutes: the registry is global and the test binary
    /// shares it, which is the documented consequence of that choice.
    #[test]
    fn each_case_moves_its_own_counter() {
        let before = (
            fork_case_count(ForkCase::NonState),
            fork_case_count(ForkCase::StateUncontested),
            fork_case_count(ForkCase::StateContested),
            event_count(Origin::Local),
            event_count(Origin::Federated),
        );

        record_append(Origin::Local, ForkCase::NonState);
        record_append(Origin::Federated, ForkCase::StateUncontested);
        record_contested_state();

        assert_eq!(fork_case_count(ForkCase::NonState), before.0 + 1);
        assert_eq!(fork_case_count(ForkCase::StateUncontested), before.1 + 1);
        assert_eq!(fork_case_count(ForkCase::StateContested), before.2 + 1);
        assert_eq!(event_count(Origin::Local), before.3 + 1);
        // One federated event: a contested fork is a decision, not an
        // append, and the send that steps around it is counted on its own.
        assert_eq!(event_count(Origin::Federated), before.4 + 1);
    }

    /// The subscriber gauge is balanced: what goes up comes back down,
    /// and an unbalanced decrement cannot wrap it.
    ///
    /// Here rather than in the integration tests because this binary does
    /// not share the gauge with a concurrently running HTTP test, which
    /// makes it deterministic instead of merely usually right.
    #[test]
    fn the_subscriber_gauge_is_balanced() {
        let before = sync_subscribers();
        sync_waiter_started();
        assert_eq!(sync_subscribers(), before + 1);
        sync_waiter_finished();
        assert_eq!(sync_subscribers(), before);
        // One too many decrements must not wrap to u64::MAX and report
        // every client on earth as connected to this server.
        sync_waiter_finished();
        assert!(sync_subscribers() <= before);
    }

    /// The exposition is the contract, so it is asserted rather than eyeballed.
    #[test]
    fn the_exposition_is_well_formed() {
        let text = render();
        for name in [
            "spindle_build_info",
            "spindle_events_appended_total",
            "spindle_fork_resolutions_total",
        ] {
            assert!(text.contains(&format!("# HELP {name} ")), "{text}");
            assert!(text.contains(&format!("# TYPE {name} ")), "{text}");
        }
        // Every case and origin is present even at zero: a series that
        // appears only once it is non-zero makes a dashboard read "no
        // data" exactly when it should read "none happened".
        for case in ["1", "2", "3"] {
            assert!(
                text.contains(&format!(
                    "spindle_fork_resolutions_total{{case=\"{case}\"}} "
                )),
                "{text}"
            );
        }
        for origin in ["local", "federated"] {
            assert!(
                text.contains(&format!(
                    "spindle_events_appended_total{{origin=\"{origin}\"}} "
                )),
                "{text}"
            );
        }
        // Values parse as integers: a counter rendered as anything else is
        // silently dropped by a scraper.
        for line in text.lines().filter(|line| !line.starts_with('#')) {
            let value = line.rsplit(' ').next().expect("a value");
            assert!(value.parse::<u64>().is_ok(), "bad value in {line:?}");
        }
    }
}
