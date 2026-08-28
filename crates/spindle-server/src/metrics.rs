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

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Record one event reaching the log, and which case carried it.
pub fn record_append(origin: Origin, case: ForkCase) {
    EVENTS[origin.index()].fetch_add(1, Ordering::Relaxed);
    FORK_CASES[case.index()].fetch_add(1, Ordering::Relaxed);
}

/// Record an append that needed state resolution — case 3.
///
/// Separate from [`record_append`] because today this is a path the ingest
/// code *refuses* rather than resolves: bounded resolution exists in
/// `spindle-core` but is not yet wired into ingest (#16). The counter goes
/// where the decision is made, so it keeps counting the same thing when
/// that lands and the refusal becomes a resolution.
pub fn record_contested_state(origin: Origin) {
    record_append(origin, ForkCase::StateContested);
}

/// The exposition, in the Prometheus text format.
#[must_use]
pub fn render() -> String {
    let mut out = String::with_capacity(1024);

    out.push_str(
        "# HELP spindle_build_info The version this process is running.\n\
         # TYPE spindle_build_info gauge\n",
    );
    let _ = writeln!(
        out,
        "spindle_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

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

    out
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
        record_contested_state(Origin::Federated);

        assert_eq!(fork_case_count(ForkCase::NonState), before.0 + 1);
        assert_eq!(fork_case_count(ForkCase::StateUncontested), before.1 + 1);
        assert_eq!(fork_case_count(ForkCase::StateContested), before.2 + 1);
        assert_eq!(event_count(Origin::Local), before.3 + 1);
        // Two federated events: the uncontested one and the contested one.
        assert_eq!(event_count(Origin::Federated), before.4 + 2);
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
