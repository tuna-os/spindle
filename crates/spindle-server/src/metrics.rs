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
//! The registry is a value, [`Metrics`], owned by the server that produces
//! it and handed to the few things that record into it. It was
//! process-global for a while, as metrics registries conventionally are,
//! and the cost showed up where #174 said it would: every integration
//! test in one binary shared the counters, so an assertion was a delta
//! across whatever the other tests were doing at that instant, and two of
//! them flaked on exactly that. A handle costs one field in three
//! constructors and buys tests that can say *equals*, and an exposition
//! that is provably a rendering of the counters it sits beside.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// What became of one PDU a peer pushed in a transaction.
///
/// Five outcomes are the receipt checks' own verdicts; `refused` is
/// everything refused before them -- a bad signature, a foreign sender, an
/// unknown room -- so the series add up to every PDU received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PduOutcome {
    /// Appended to the timeline through the ordinary receipt checks,
    /// directly or after its predecessors were recovered.
    Accepted,
    /// Appended across a gap on a peer's `/state_ids` (see `inbound::gap`).
    GapAccepted,
    /// Kept out of the timeline: fails only against the current state.
    SoftFailed,
    /// Kept out of the timeline: fails against its auth events or the
    /// state before it.
    Rejected,
    /// Its predecessors or auth events are missing and could neither be
    /// recovered nor bridged.
    RefusedMissingDeps,
    /// Refused before any receipt check.
    Refused,
}

impl PduOutcome {
    const ALL: [Self; 6] = [
        Self::Accepted,
        Self::GapAccepted,
        Self::SoftFailed,
        Self::Rejected,
        Self::RefusedMissingDeps,
        Self::Refused,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::GapAccepted => "gap_accepted",
            Self::SoftFailed => "soft_failed",
            Self::Rejected => "rejected",
            Self::RefusedMissingDeps => "refused_missing_deps",
            Self::Refused => "refused",
        }
    }
}

/// How one predecessor recovery attempt against one peer ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryResult {
    /// Every missing predecessor and auth event was recovered.
    Recovered,
    /// The gap is wider than the event or byte budget.
    BudgetExceeded,
    /// The peer failed to answer, or answered with an error.
    PeerError,
    /// The peer answered 429, or was still cooling down from one.
    RateLimited,
    /// The attempt ran out of time.
    Timeout,
    /// What the peer sent failed verification or authorization.
    Invalid,
}

impl RecoveryResult {
    const ALL: [Self; 6] = [
        Self::Recovered,
        Self::BudgetExceeded,
        Self::PeerError,
        Self::RateLimited,
        Self::Timeout,
        Self::Invalid,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Recovered => "recovered",
            Self::BudgetExceeded => "budget_exceeded",
            Self::PeerError => "peer_error",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Invalid => "invalid",
        }
    }
}

/// Why an event body was fetched from a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchKind {
    /// A missing predecessor (`get_missing_events` or `/event`).
    Predecessor,
    /// A missing auth event of a pushed or recovered event.
    Auth,
    /// A state or auth-chain event named by `/state_ids` for a gap.
    GapState,
}

impl FetchKind {
    const ALL: [Self; 3] = [Self::Predecessor, Self::Auth, Self::GapState];

    fn label(self) -> &'static str {
        match self {
            Self::Predecessor => "predecessor",
            Self::Auth => "auth",
            Self::GapState => "gap_state",
        }
    }
}

/// How one attempt to accept an event across a gap ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GapResult {
    /// The event was appended on the peer's state.
    Accepted,
    /// The state or its auth chain exceeded the gap budget.
    BudgetExceeded,
    /// No participating server answered `/state_ids` usefully.
    PeerError,
    /// Every candidate answered 429 or was cooling down from one.
    RateLimited,
    /// The attempt ran out of time.
    Timeout,
    /// The state, an event in it, or the event itself failed verification
    /// or authorization: refused, fail closed.
    Invalid,
    /// Not attempted: the room has had its window's worth of gap
    /// acceptances (the amplification guard, `[federation]
    /// gap_acceptances_per_room`).
    CappedRoom,
    /// Not attempted: the origin has had its window's worth of gap
    /// acceptances across all rooms (`gap_acceptances_per_origin`).
    CappedOrigin,
}

impl GapResult {
    const ALL: [Self; 8] = [
        Self::Accepted,
        Self::BudgetExceeded,
        Self::PeerError,
        Self::RateLimited,
        Self::Timeout,
        Self::Invalid,
        Self::CappedRoom,
        Self::CappedOrigin,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::BudgetExceeded => "budget_exceeded",
            Self::PeerError => "peer_error",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::Invalid => "invalid",
            Self::CappedRoom => "capped_room",
            Self::CappedOrigin => "capped_origin",
        }
    }
}

/// How one backfill chunk for a recorded federation gap ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillChunk {
    /// Events were verified, checked and stored below the gap event.
    Filled,
    /// The walk met history this server holds: the gap is closed and its
    /// marker removed.
    Completed,
    /// No participating server answered usefully.
    PeerError,
    /// Every candidate answered 429 or was cooling down from one.
    RateLimited,
    /// An event, its auth chain or the state the peer named failed
    /// verification or authorization: nothing from the chunk was stored.
    Invalid,
    /// The gap outgrew the backfill budget and was left truncated.
    Truncated,
}

impl BackfillChunk {
    const ALL: [Self; 6] = [
        Self::Filled,
        Self::Completed,
        Self::PeerError,
        Self::RateLimited,
        Self::Invalid,
        Self::Truncated,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Filled => "filled",
            Self::Completed => "completed",
            Self::PeerError => "peer_error",
            Self::RateLimited => "rate_limited",
            Self::Invalid => "invalid",
            Self::Truncated => "truncated",
        }
    }
}

/// What became of one event a gap backfill handled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackfillEvent {
    /// Fetched from a peer as part of a gap's history (before any check).
    Fetched,
    /// Stored into the gap's segment of the timeline.
    Inserted,
    /// Walked through but kept out of the timeline: it failed its auth
    /// events or the state before it.
    Rejected,
}

impl BackfillEvent {
    const ALL: [Self; 3] = [Self::Fetched, Self::Inserted, Self::Rejected];

    fn label(self) -> &'static str {
        match self {
            Self::Fetched => "fetched",
            Self::Inserted => "inserted",
            Self::Rejected => "rejected",
        }
    }
}

/// Position of a label value in its `ALL` table, which is the counter's
/// slot. A linear search over at most six values, and it cannot drift from
/// the table the renderer walks.
fn slot<T: PartialEq + Copy>(all: &[T], value: T) -> usize {
    all.iter().position(|each| *each == value).unwrap_or(0)
}

/// Every counter, gauge and histogram this server exposes.
///
/// One per server: `spindle_server::app` makes it and hands the same
/// `Arc` to the rooms, the federation client and the request middleware,
/// and `main` serves `render` from it. Relaxed ordering throughout: these
/// are counters read by a scrape, never used to order anything, and
/// paying for stronger ordering on the append hot path to make a number
/// that is sampled every 15 seconds marginally fresher would be a poor
/// trade.
#[derive(Debug, Default)]
pub struct Metrics {
    fork_cases: [AtomicU64; 3],
    events: [AtomicU64; 2],
    /// `[soft-failed, rejected]` PDUs kept out of the timeline.
    sidelined: [AtomicU64; 2],
    /// `[exclusive, shared]` acquisitions of one room's lock.
    room_locks: [AtomicU64; 2],
    /// `[exclusive, shared]` acquisitions of the registry that finds rooms.
    registry_locks: [AtomicU64; 2],
    append_latency: Family,
    http_latency: Family,
    http_requests: RwLock<HashMap<String, AtomicU64>>,
    federation_queue: RwLock<Vec<(String, u64)>>,
    sync_subscribers: AtomicU64,
    sync_lag: Family,
    /// Inbound PDUs by what became of them ([`PduOutcome`]).
    pdu_outcomes: [AtomicU64; PduOutcome::ALL.len()],
    /// Predecessor recovery attempts by result ([`RecoveryResult`]).
    recovery_attempts: [AtomicU64; RecoveryResult::ALL.len()],
    recovery_latency: Family,
    /// Bodies fetched from peers by recovery or gap acceptance ([`FetchKind`]).
    recovery_fetched: [AtomicU64; FetchKind::ALL.len()],
    /// Gap acceptance attempts by result ([`GapResult`]).
    gap_acceptances: [AtomicU64; GapResult::ALL.len()],
    state_ids_latency: Family,
    /// Gap backfill chunks by result ([`BackfillChunk`]).
    backfill_chunks: [AtomicU64; BackfillChunk::ALL.len()],
    backfill_latency: Family,
    /// Events a gap backfill handled, by what became of them.
    backfill_events: [AtomicU64; BackfillEvent::ALL.len()],
    /// Recorded federation gaps not yet filled (a gauge).
    gaps_remaining: AtomicU64,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

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

impl Metrics {
    /// Record one acquisition of a *room's* lock, and how it was taken.
    ///
    /// Contention here is confined to that room: two requests for different
    /// rooms do not meet. Exclusive is what an append takes, and what makes
    /// concurrent writers to the same room queue -- which is the ordering the
    /// log rests on, not a defect.
    pub fn record_room_lock(&self, exclusive: bool) {
        self.room_locks[usize::from(!exclusive)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record one acquisition of the registry that maps room ids to their locks.
    ///
    /// This one *is* server-wide, so an exclusive acquisition stalls every
    /// request for every room. It should be rare: the registry is taken
    /// exclusively only to admit a room this process has not opened yet, and
    /// shared for every lookup after. A rising exclusive count on a server that
    /// is not opening new rooms means something is taking it that should not.
    pub fn record_registry_lock(&self, exclusive: bool) {
        self.registry_locks[usize::from(!exclusive)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record one event reaching the log, and which case carried it.
    pub fn record_append(&self, origin: Origin, case: ForkCase) {
        self.events[origin.index()].fetch_add(1, Ordering::Relaxed);
        self.fork_cases[case.index()].fetch_add(1, Ordering::Relaxed);
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
    pub fn record_contested_state(&self) {
        self.fork_cases[ForkCase::StateContested.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a received PDU kept for the DAG but out of the timeline: one
    /// that failed the auth checks against its auth events or the state
    /// before it (`rejected`), or only against the room's current state
    /// (soft-failed). A peer whose events keep landing here disagrees with
    /// this server about the room's state, which is the thing to look at.
    pub fn record_sidelined(&self, rejected: bool) {
        self.sidelined[usize::from(rejected)].fetch_add(1, Ordering::Relaxed);
    }

    /// The exposition, in the Prometheus text format.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);
        render_build_info(&mut out);
        self.render_appends(&mut out);
        self.render_room_locks(&mut out);
        self.render_http(&mut out);
        self.render_federation(&mut out);
        self.render_inbound(&mut out);
        self.render_sync(&mut out);
        out
    }
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

impl Metrics {
    /// The §9.2 case split, the federated-event denominator §18.3 needs, and
    /// the commit histogram those targets are stated against.
    fn render_appends(&self, out: &mut String) {
        out.push_str(
            "# HELP spindle_events_appended_total Events appended to a room log.\n\
         # TYPE spindle_events_appended_total counter\n",
        );
        for origin in [Origin::Local, Origin::Federated] {
            let _ = writeln!(
                out,
                "spindle_events_appended_total{{origin=\"{}\"}} {}",
                origin.label(),
                self.events[origin.index()].load(Ordering::Relaxed)
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
                self.fork_cases[case.index()].load(Ordering::Relaxed)
            );
        }

        out.push_str(
            "# HELP spindle_pdus_sidelined_total Received events kept out of the timeline \
         by the checks on receipt of a PDU.\n\
         # TYPE spindle_pdus_sidelined_total counter\n",
        );
        for (verdict, index) in [("soft_failed", 0), ("rejected", 1)] {
            let _ = writeln!(
                out,
                "spindle_pdus_sidelined_total{{verdict=\"{verdict}\"}} {}",
                self.sidelined[index].load(Ordering::Relaxed)
            );
        }

        out.push_str(
            "# HELP spindle_append_duration_seconds Time to commit one event to a room log.\n\
         # TYPE spindle_append_duration_seconds histogram\n",
        );
        if let Ok(read) = self.append_latency.read() {
            for (durability, histogram) in read.iter() {
                histogram.render_into(
                    out,
                    "spindle_append_duration_seconds",
                    &format!("durability=\"{}\"", escape(durability)),
                );
            }
        }
    }

    fn render_room_locks(&self, out: &mut String) {
        out.push_str(
            "# HELP spindle_room_registry_acquisitions_total Room registry lock \
         acquisitions, by mode.\n\
         # TYPE spindle_room_registry_acquisitions_total counter\n",
        );
        for (index, mode) in ["exclusive", "shared"].into_iter().enumerate() {
            let _ = writeln!(
                out,
                "spindle_room_registry_acquisitions_total{{mode=\"{mode}\"}} {}",
                self.registry_locks[index].load(Ordering::Relaxed)
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
                self.room_locks[index].load(Ordering::Relaxed)
            );
        }
    }

    fn render_http(&self, out: &mut String) {
        out.push_str(
        "# HELP spindle_http_request_duration_seconds Time to serve one request, by matched route.\n\
         # TYPE spindle_http_request_duration_seconds histogram\n",
    );
        if let Ok(read) = self.http_latency.read() {
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
        if let Ok(read) = self.http_requests.read() {
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

    fn render_federation(&self, out: &mut String) {
        out.push_str(
        "# HELP spindle_federation_queue_depth Events waiting to be delivered, by destination.\n\
         # TYPE spindle_federation_queue_depth gauge\n",
    );
        if let Ok(read) = self.federation_queue.read() {
            for (destination, depth) in read.iter() {
                let _ = writeln!(
                    out,
                    "spindle_federation_queue_depth{{destination=\"{}\"}} {depth}",
                    escape(destination)
                );
            }
        }
    }

    fn render_sync(&self, out: &mut String) {
        out.push_str(
            "# HELP spindle_sync_subscribers Clients currently blocked in a long-polling /sync.\n\
         # TYPE spindle_sync_subscribers gauge\n",
        );
        let _ = writeln!(
            out,
            "spindle_sync_subscribers {}",
            self.sync_subscribers.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP spindle_sync_lag_seconds Age of the newest event a /sync delivered.\n\
         # TYPE spindle_sync_lag_seconds histogram\n",
        );
        if let Ok(read) = self.sync_lag.read() {
            for histogram in read.values() {
                histogram.render_into(out, "spindle_sync_lag_seconds", "");
            }
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

/// Bucket bounds for the federation recovery paths, in seconds.
///
/// Those are network round trips and walks over many of them, bounded by
/// timeouts of tens of seconds; the append buckets above would put every
/// one of them in `+Inf` and answer nothing.
const SLOW_BUCKETS: [f64; 11] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0];

/// A Prometheus histogram: per-bucket counts, a sum and a total.
///
/// Counts are per-bucket here and made cumulative at render, which is
/// what the exposition format wants; doing it the other way would mean
/// touching every bucket above the observation on the hot path.
#[derive(Debug)]
struct Histogram {
    bounds: &'static [f64],
    buckets: Box<[AtomicU64]>,
    /// Microseconds, so the sum needs no float atomic. Rendered as
    /// seconds, which is the unit the metric name promises.
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// A [`Duration`] rather than seconds, so the microsecond sum is an
    /// integer conversion the type system checks rather than a float
    /// cast that has to be reasoned about.
    fn observe(&self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let slot = self
            .bounds
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(self.bounds.len());
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
        for (bound, bucket) in self.bounds.iter().zip(self.buckets.iter()) {
            cumulative += bucket.load(Ordering::Relaxed);
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
type Family = RwLock<HashMap<String, Histogram>>;

fn observe_in(family: &Family, key: &str, elapsed: Duration) {
    observe_in_buckets(family, key, elapsed, &BUCKETS);
}

fn observe_in_buckets(family: &Family, key: &str, elapsed: Duration, bounds: &'static [f64]) {
    if let Ok(read) = family.read()
        && let Some(histogram) = read.get(key)
    {
        histogram.observe(elapsed);
        return;
    }
    if let Ok(mut write) = family.write() {
        write
            .entry(key.to_owned())
            .or_insert_with(|| Histogram::new(bounds))
            .observe(elapsed);
    }
}

impl Metrics {
    /// Record how long a commit took, by the durability it was asked for.
    ///
    /// SPEC §18.3's local-send targets are stated against `group`, so the
    /// label is what makes the number comparable to the target rather than
    /// an average over settings nobody runs together.
    pub fn observe_append(&self, durability: &str, elapsed: Duration) {
        observe_in(&self.append_latency, durability, elapsed);
    }

    /// Record one served request.
    ///
    /// `route` must be the router's matched path (`/rooms/{room_id}/...`),
    /// never the raw URI: the raw path carries room and user IDs, and a
    /// label taking values from the request would let any caller mint
    /// series until the scrape falls over.
    pub fn observe_request(&self, route: &str, method: &str, status: u16, elapsed: Duration) {
        observe_in(&self.http_latency, route, elapsed);
        let key = format!("{route}\u{1}{method}\u{1}{status}");
        if let Ok(read) = self.http_requests.read()
            && let Some(counter) = read.get(&key)
        {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Ok(mut write) = self.http_requests.write() {
            write
                .entry(key)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
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

impl Metrics {
    /// Replace the federation queue depths with a fresh reading.
    ///
    /// A gauge, so it is *set* rather than added to: the delivery loop knows
    /// the whole picture each pass, and carrying stale destinations forward
    /// would report a backlog for a peer that has none. Deepest first, with
    /// everything past the cap summed into `other`.
    pub fn set_federation_queue(&self, depths: &[(String, u64)]) {
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
        if let Ok(mut write) = self.federation_queue.write() {
            *write = capped;
        }
    }

    /// A `/sync` has started waiting.
    pub fn sync_waiter_started(&self) {
        self.sync_subscribers.fetch_add(1, Ordering::Relaxed);
    }

    /// A `/sync` has stopped waiting, woken or timed out.
    pub fn sync_waiter_finished(&self) {
        // Saturating: an unbalanced decrement would wrap to u64::MAX and
        // report every client on earth as connected to this server.
        let _ =
            self.sync_subscribers
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
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
    pub fn observe_sync_lag(&self, elapsed: Duration) {
        observe_in(&self.sync_lag, "", elapsed);
    }

    /// Read the subscriber gauge, for tests that assert it moved.
    #[must_use]
    pub fn sync_subscribers(&self) -> u64 {
        self.sync_subscribers.load(Ordering::Relaxed)
    }
}

impl Metrics {
    /// Record what became of one PDU a peer pushed.
    pub fn record_pdu(&self, outcome: PduOutcome) {
        self.pdu_outcomes[slot(&PduOutcome::ALL, outcome)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record one predecessor recovery attempt against one peer, and how
    /// long it took.
    pub fn record_recovery(&self, result: RecoveryResult, elapsed: Duration) {
        self.recovery_attempts[slot(&RecoveryResult::ALL, result)].fetch_add(1, Ordering::Relaxed);
        observe_in_buckets(
            &self.recovery_latency,
            result.label(),
            elapsed,
            &SLOW_BUCKETS,
        );
    }

    /// Record event bodies fetched from a peer by recovery or a gap.
    pub fn record_fetched(&self, kind: FetchKind, count: u64) {
        self.recovery_fetched[slot(&FetchKind::ALL, kind)].fetch_add(count, Ordering::Relaxed);
    }

    /// Record one attempt to accept an event across a gap.
    pub fn record_gap(&self, result: GapResult) {
        self.gap_acceptances[slot(&GapResult::ALL, result)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record one `/state_ids` request, by `ok`, `rate_limited` or `error`.
    pub fn observe_state_ids(&self, result: &'static str, elapsed: Duration) {
        observe_in_buckets(&self.state_ids_latency, result, elapsed, &SLOW_BUCKETS);
    }

    /// Record one gap backfill chunk, and how long it took.
    pub fn record_backfill_chunk(&self, result: BackfillChunk, elapsed: Duration) {
        self.backfill_chunks[slot(&BackfillChunk::ALL, result)].fetch_add(1, Ordering::Relaxed);
        observe_in_buckets(
            &self.backfill_latency,
            result.label(),
            elapsed,
            &SLOW_BUCKETS,
        );
    }

    /// Record events a gap backfill fetched, inserted or kept out.
    pub fn record_backfill_events(&self, kind: BackfillEvent, count: u64) {
        self.backfill_events[slot(&BackfillEvent::ALL, kind)].fetch_add(count, Ordering::Relaxed);
    }

    /// Set the number of recorded gaps not yet filled. A gauge: the
    /// backfill loop counts the markers and says how many there are.
    pub fn set_gaps_remaining(&self, gaps: u64) {
        self.gaps_remaining.store(gaps, Ordering::Relaxed);
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn backfill_chunk_count(&self, result: BackfillChunk) -> u64 {
        self.backfill_chunks[slot(&BackfillChunk::ALL, result)].load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn backfill_event_count(&self, kind: BackfillEvent) -> u64 {
        self.backfill_events[slot(&BackfillEvent::ALL, kind)].load(Ordering::Relaxed)
    }

    /// Read the gauge, for tests that assert it moved.
    #[must_use]
    pub fn gaps_remaining(&self) -> u64 {
        self.gaps_remaining.load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn pdu_count(&self, outcome: PduOutcome) -> u64 {
        self.pdu_outcomes[slot(&PduOutcome::ALL, outcome)].load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn recovery_count(&self, result: RecoveryResult) -> u64 {
        self.recovery_attempts[slot(&RecoveryResult::ALL, result)].load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn fetched_count(&self, kind: FetchKind) -> u64 {
        self.recovery_fetched[slot(&FetchKind::ALL, kind)].load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn gap_count(&self, result: GapResult) -> u64 {
        self.gap_acceptances[slot(&GapResult::ALL, result)].load(Ordering::Relaxed)
    }

    /// Inbound federation: PDU outcomes, dependency recovery, gaps.
    ///
    /// Every label is a fixed enum value: no room, event or server name,
    /// so a peer cannot mint series by sending us things.
    fn render_inbound(&self, out: &mut String) {
        out.push_str(
            "# HELP spindle_federation_pdus_received_total PDUs peers pushed, by outcome.\n\
         # TYPE spindle_federation_pdus_received_total counter\n",
        );
        for outcome in PduOutcome::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_pdus_received_total{{result=\"{}\"}} {}",
                outcome.label(),
                self.pdu_count(outcome)
            );
        }
        out.push_str(
            "# HELP spindle_federation_recovery_attempts_total Missing-dependency \
         recovery attempts against one peer, by result.\n\
         # TYPE spindle_federation_recovery_attempts_total counter\n",
        );
        for result in RecoveryResult::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_recovery_attempts_total{{result=\"{}\"}} {}",
                result.label(),
                self.recovery_count(result)
            );
        }
        out.push_str(
            "# HELP spindle_federation_recovery_duration_seconds Time one recovery \
         attempt took, by result.\n\
         # TYPE spindle_federation_recovery_duration_seconds histogram\n",
        );
        if let Ok(read) = self.recovery_latency.read() {
            for (result, histogram) in read.iter() {
                histogram.render_into(
                    out,
                    "spindle_federation_recovery_duration_seconds",
                    &format!("result=\"{}\"", escape(result)),
                );
            }
        }
        out.push_str(
            "# HELP spindle_federation_recovery_events_fetched_total Event bodies \
         fetched from peers to fill missing dependencies, by kind.\n\
         # TYPE spindle_federation_recovery_events_fetched_total counter\n",
        );
        for kind in FetchKind::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_recovery_events_fetched_total{{kind=\"{}\"}} {}",
                kind.label(),
                self.fetched_count(kind)
            );
        }
        out.push_str(
            "# HELP spindle_federation_gap_acceptances_total Attempts to accept a PDU \
         across a history gap on a peer's state, by result.\n\
         # TYPE spindle_federation_gap_acceptances_total counter\n",
        );
        for result in GapResult::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_gap_acceptances_total{{result=\"{}\"}} {}",
                result.label(),
                self.gap_count(result)
            );
        }
        out.push_str(
            "# HELP spindle_federation_state_ids_duration_seconds Time one /state_ids \
         request took, by result.\n\
         # TYPE spindle_federation_state_ids_duration_seconds histogram\n",
        );
        if let Ok(read) = self.state_ids_latency.read() {
            for (result, histogram) in read.iter() {
                histogram.render_into(
                    out,
                    "spindle_federation_state_ids_duration_seconds",
                    &format!("result=\"{}\"", escape(result)),
                );
            }
        }
        self.render_backfill(out);
    }

    /// Gap backfill: chunks, events, the gaps still open, chunk duration.
    fn render_backfill(&self, out: &mut String) {
        out.push_str(
            "# HELP spindle_federation_backfill_chunks_total Gap backfill chunks, \
         by result.\n\
         # TYPE spindle_federation_backfill_chunks_total counter\n",
        );
        for result in BackfillChunk::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_backfill_chunks_total{{result=\"{}\"}} {}",
                result.label(),
                self.backfill_chunk_count(result)
            );
        }
        out.push_str(
            "# HELP spindle_federation_backfill_events_total Events a gap backfill \
         fetched, inserted, or kept out of the timeline.\n\
         # TYPE spindle_federation_backfill_events_total counter\n",
        );
        for kind in BackfillEvent::ALL {
            let _ = writeln!(
                out,
                "spindle_federation_backfill_events_total{{result=\"{}\"}} {}",
                kind.label(),
                self.backfill_event_count(kind)
            );
        }
        out.push_str(
            "# HELP spindle_federation_gaps_remaining Recorded federation gaps \
         whose history is not yet backfilled.\n\
         # TYPE spindle_federation_gaps_remaining gauge\n",
        );
        let _ = writeln!(
            out,
            "spindle_federation_gaps_remaining {}",
            self.gaps_remaining()
        );
        out.push_str(
            "# HELP spindle_federation_backfill_duration_seconds Time one gap \
         backfill chunk took, by result.\n\
         # TYPE spindle_federation_backfill_duration_seconds histogram\n",
        );
        if let Ok(read) = self.backfill_latency.read() {
            for (result, histogram) in read.iter() {
                histogram.render_into(
                    out,
                    "spindle_federation_backfill_duration_seconds",
                    &format!("result=\"{}\"", escape(result)),
                );
            }
        }
    }
}

/// Escape a label value per the exposition format.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Metrics {
    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn fork_case_count(&self, case: ForkCase) -> u64 {
        self.fork_cases[case.index()].load(Ordering::Relaxed)
    }

    /// Read one counter, for tests that assert a metric actually moved.
    #[must_use]
    pub fn event_count(&self, origin: Origin) -> u64 {
        self.events[origin.index()].load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every counter moves when its case does, and the exposition says so.
    #[test]
    fn each_case_moves_its_own_counter() {
        let metrics = Metrics::new();
        metrics.record_append(Origin::Local, ForkCase::NonState);
        metrics.record_append(Origin::Federated, ForkCase::StateUncontested);
        metrics.record_contested_state();

        assert_eq!(metrics.fork_case_count(ForkCase::NonState), 1);
        assert_eq!(metrics.fork_case_count(ForkCase::StateUncontested), 1);
        assert_eq!(metrics.fork_case_count(ForkCase::StateContested), 1);
        assert_eq!(metrics.event_count(Origin::Local), 1);
        // One federated event: a contested fork is a decision, not an
        // append, and the send that steps around it is counted on its own.
        assert_eq!(metrics.event_count(Origin::Federated), 1);
    }

    /// The subscriber gauge is balanced: what goes up comes back down,
    /// and an unbalanced decrement cannot wrap it.
    #[test]
    fn the_subscriber_gauge_is_balanced() {
        let metrics = Metrics::new();
        metrics.sync_waiter_started();
        assert_eq!(metrics.sync_subscribers(), 1);
        metrics.sync_waiter_finished();
        assert_eq!(metrics.sync_subscribers(), 0);
        // One too many decrements must not wrap to u64::MAX and report
        // every client on earth as connected to this server.
        metrics.sync_waiter_finished();
        assert_eq!(metrics.sync_subscribers(), 0);
    }

    /// Each inbound federation counter moves on its own label, and the
    /// exposition renders every label even at zero.
    #[test]
    fn inbound_federation_counters_move_and_render() {
        let metrics = Metrics::new();
        let text = metrics.render();
        for outcome in PduOutcome::ALL {
            assert!(
                text.contains(&format!(
                    "spindle_federation_pdus_received_total{{result=\"{}\"}} 0",
                    outcome.label()
                )),
                "{text}"
            );
        }
        for result in GapResult::ALL {
            assert!(
                text.contains(&format!(
                    "spindle_federation_gap_acceptances_total{{result=\"{}\"}} 0",
                    result.label()
                )),
                "{text}"
            );
        }

        metrics.record_pdu(PduOutcome::GapAccepted);
        metrics.record_pdu(PduOutcome::GapAccepted);
        metrics.record_pdu(PduOutcome::RefusedMissingDeps);
        metrics.record_recovery(RecoveryResult::RateLimited, Duration::from_millis(30));
        metrics.record_recovery(RecoveryResult::BudgetExceeded, Duration::from_secs(12));
        metrics.record_fetched(FetchKind::GapState, 7);
        metrics.record_fetched(FetchKind::Predecessor, 2);
        metrics.record_gap(GapResult::Accepted);
        metrics.observe_state_ids("ok", Duration::from_millis(400));

        assert_eq!(metrics.pdu_count(PduOutcome::GapAccepted), 2);
        assert_eq!(metrics.pdu_count(PduOutcome::RefusedMissingDeps), 1);
        assert_eq!(metrics.pdu_count(PduOutcome::Accepted), 0);
        assert_eq!(metrics.recovery_count(RecoveryResult::RateLimited), 1);
        assert_eq!(metrics.recovery_count(RecoveryResult::BudgetExceeded), 1);
        assert_eq!(metrics.recovery_count(RecoveryResult::Recovered), 0);
        assert_eq!(metrics.fetched_count(FetchKind::GapState), 7);
        assert_eq!(metrics.fetched_count(FetchKind::Predecessor), 2);
        assert_eq!(metrics.fetched_count(FetchKind::Auth), 0);
        assert_eq!(metrics.gap_count(GapResult::Accepted), 1);

        let text = metrics.render();
        for line in [
            "spindle_federation_pdus_received_total{result=\"gap_accepted\"} 2",
            "spindle_federation_recovery_attempts_total{result=\"rate_limited\"} 1",
            "spindle_federation_recovery_events_fetched_total{kind=\"gap_state\"} 7",
            "spindle_federation_gap_acceptances_total{result=\"accepted\"} 1",
            // Twelve seconds lands in the ten-to-thirty bucket, which the
            // append buckets could not have told apart from an hour.
            "spindle_federation_recovery_duration_seconds_bucket{result=\"budget_exceeded\",le=\"10\"} 0",
            "spindle_federation_recovery_duration_seconds_bucket{result=\"budget_exceeded\",le=\"30\"} 1",
            "spindle_federation_state_ids_duration_seconds_count{result=\"ok\"} 1",
        ] {
            assert!(text.contains(line), "missing {line:?} in {text}");
        }
    }

    /// The exposition is the contract, so it is asserted rather than eyeballed.
    #[test]
    fn the_exposition_is_well_formed() {
        let text = Metrics::new().render();
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
                    "spindle_fork_resolutions_total{{case=\"{case}\"}} 0"
                )),
                "{text}"
            );
        }
        for origin in ["local", "federated"] {
            assert!(
                text.contains(&format!(
                    "spindle_events_appended_total{{origin=\"{origin}\"}} 0"
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
