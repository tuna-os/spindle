//! How the outbox waits on a destination that keeps failing, and what it
//! still owes one that has been down a long time (#801).
//!
//! The outbox used to retry every failing destination at least once a
//! minute, forever, and keep every row queued for it. On a server in
//! thousands of rooms that is thousands of dead hosts, each holding a
//! delivery slot for a 30 s timeout once a minute, and queues that only
//! grow. Synapse does two things this module copies:
//!
//! - **The wait grows with the outage.** For its first minutes a failing
//!   destination is retried as before, doubling from `retry_base_ms` to
//!   64× of it -- a peer restarting is back within a minute. Once it has
//!   failed for [`LONG_AFTER`]× `retry_base_ms` (ten minutes at the
//!   default) it waits as long again as it has been down, so the wait
//!   doubles from ten minutes up to [`MAX_BACKOFF`], a day. Any request
//!   the destination itself sends this server ends the wait at once
//!   (`Federation::reset_delivery`): a server that talks to us is up.
//!   A peer with `[federation] peers.max_backoff_ms` keeps its own cap,
//!   which bounds this schedule as it bounded the old one.
//! - **A server back from a long outage is caught up, not replayed.**
//!   Its queue is cut to the newest [`CATCH_UP_PER_ROOM`] PDUs of each
//!   room; the peer fetches whatever it still wants through the
//!   `prev_events` of what it receives (`get_missing_events`, backfill).
//!   Weeks of PDUs sent fifty at a time would hold its rooms in the past
//!   for hours. Only PDUs: to-device messages and device-list and
//!   cross-signing updates wait in their own outbox, kept until the peer
//!   acknowledges them, because a peer cannot ask for those again. A peer
//!   given `max_backoff_ms` is never cut either: the operator said to
//!   wait for it, and its rows wait whole.
//!
//! The state is kept in the store ([`keys::destination_retry`]), one row
//! per failing destination, written once per failed attempt and deleted at
//! the first success. Without it a restart would retry every dead server at
//! once and start each one's schedule over, so a server that restarts more
//! often than every ten minutes would never reach the long waits at all.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store};

use super::OutboxRow;

/// The longest an ordinary destination waits between attempts: a day,
/// Synapse's cap for a destination that keeps failing.
pub(super) const MAX_BACKOFF: Duration = Duration::from_secs(24 * 60 * 60);

/// The cap of the first, fast phase, in multiples of `retry_base_ms`:
/// about a minute at the default.
const FAST_CAP: u32 = 64;

/// How long a destination fails, in multiples of `retry_base_ms`, before
/// its wait grows with the outage and it is caught up rather than sent its
/// backlog: ten minutes at the default, Synapse's first retry interval.
pub(super) const LONG_AFTER: u32 = 600;

/// The PDUs per room kept for a destination that is catching up: about
/// what one `get_missing_events` brings, so the peer holds the recent
/// conversation without asking and fetches the rest only if it wants it.
pub(super) const CATCH_UP_PER_ROOM: usize = 10;

/// How the outbox stands with one destination whose last attempt failed.
/// Times are milliseconds since the epoch, so the row means the same thing
/// after a restart.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Backoff {
    /// Failed attempts in a row since the run began or the last reset.
    pub failures: u32,
    /// When the run of failures began; `None` after a reset, until the
    /// next failure begins a new run.
    pub since: Option<u64>,
    /// When the last attempt failed.
    pub last: u64,
    /// How long after `last` the next attempt is due; 0 once reset.
    pub interval: u64,
    /// The last attempt got no HTTP answer at all.
    pub unreachable: bool,
    /// The destination failed for longer than [`LONG_AFTER`]. Kept through
    /// a reset and cleared only by an acknowledged transaction: a server
    /// that comes back after hours is caught up whether the outbox found
    /// it or it found us.
    pub long: bool,
}

impl Backoff {
    /// The entry after one more failed attempt at `now`, following
    /// `previous` (`None` for a destination that was healthy).
    pub(super) fn after_failure(
        previous: Option<&Self>,
        now: u64,
        retry_base: Duration,
        patient: Option<Duration>,
        unreachable: bool,
    ) -> Self {
        let failures = previous.map_or(0, |entry| entry.failures).saturating_add(1);
        let since = previous.and_then(|entry| entry.since).unwrap_or(now);
        let down_for = Duration::from_millis(now.saturating_sub(since));
        let wait = delay(retry_base, failures, down_for, patient);
        Self {
            failures,
            since: Some(since),
            last: now,
            interval: u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
            unreachable,
            long: previous.is_some_and(|entry| entry.long) || long_down(retry_base, down_for),
        }
    }

    /// Whether the next attempt is due at `now`.
    pub(super) fn due(&self, now: u64) -> bool {
        self.last.saturating_add(self.interval) <= now
    }

    /// The entry after a reset: due now, and the next failure starts a new
    /// run. `None` when nothing is left worth keeping -- a destination that
    /// is not catching up is simply healthy again.
    pub(super) fn reset(&self) -> Option<Self> {
        self.long.then(|| Self {
            failures: 0,
            since: None,
            interval: 0,
            unreachable: false,
            ..self.clone()
        })
    }
}

/// How long to wait before the next attempt at a destination that has
/// failed `failures` times in a row over `down_for`.
///
/// Doubling from the base, capped at 64× -- about a minute at the default
/// base -- while the outage is young, so a peer that restarts is noticed
/// within a minute. Once it has lasted [`LONG_AFTER`]× the base, as long
/// again as it has lasted, up to [`MAX_BACKOFF`]: the wait doubles with
/// every attempt, the way Synapse's does from ten minutes to a day. A peer
/// the operator has marked patient (`[federation] peers` with
/// `max_backoff_ms`) keeps doubling from the base up to its own cap, which
/// bounds both phases.
pub(super) fn delay(
    retry_base: Duration,
    failures: u32,
    down_for: Duration,
    patient: Option<Duration>,
) -> Duration {
    let doubling = retry_base.saturating_mul(2_u32.saturating_pow(failures.min(31)));
    let (fast, cap) = match patient {
        Some(cap) => (doubling, cap),
        None => (
            doubling.min(retry_base.saturating_mul(FAST_CAP)),
            MAX_BACKOFF,
        ),
    };
    let grown = if long_down(retry_base, down_for) {
        down_for
    } else {
        Duration::ZERO
    };
    fast.max(grown).min(cap)
}

/// Whether an outage of `down_for` is a long one.
fn long_down(retry_base: Duration, down_for: Duration) -> bool {
    down_for >= retry_base.saturating_mul(LONG_AFTER)
}

/// Whether `entry`'s wait is past the fast phase: the `long` series of
/// `spindle_federation_destinations_backing_off`.
pub(super) fn is_long(entry: &Backoff, retry_base: Duration) -> bool {
    entry.long || Duration::from_millis(entry.interval) > retry_base.saturating_mul(FAST_CAP)
}

/// Every destination's stored entry. A row that does not parse is skipped:
/// the destination is then tried at once, as it was before rows existed.
pub(super) fn load(store: &FjallStore) -> HashMap<String, Backoff> {
    ReadView::scan_prefix(store, &keys::destination_retry_all())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(key, value)| {
            Some((
                keys::destination_retry_name(&key)?,
                serde_json::from_slice(&value).ok()?,
            ))
        })
        .collect()
}

/// Store `destination`'s entry. A refused write is logged and otherwise
/// ignored: the entry in memory still governs this process.
pub(super) fn save(store: &FjallStore, destination: &str, entry: &Backoff) {
    let written = serde_json::to_vec(entry)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            Store::put(store, &keys::destination_retry(destination), &bytes)
                .map_err(|error| error.to_string())
        });
    if let Err(error) = written {
        tracing::warn!(destination, "cannot store the outbox backoff: {error}");
    }
}

/// Delete `destination`'s entry: it is healthy again.
pub(super) fn forget(store: &FjallStore, destination: &str) {
    if let Err(error) = Store::delete(store, &keys::destination_retry(destination)) {
        tracing::warn!(destination, "cannot delete the outbox backoff: {error}");
    }
}

/// Split one destination's queued rows, oldest first, into the ones a
/// catch-up still sends -- the newest [`CATCH_UP_PER_ROOM`] of each room,
/// in their order -- and the keys of the rest. A row whose room cannot be
/// read is kept: nothing is dropped that is not understood.
pub(super) fn catch_up(rows: Vec<OutboxRow>) -> (Vec<OutboxRow>, Vec<Vec<u8>>) {
    let mut per_room: BTreeMap<String, usize> = BTreeMap::new();
    let mut keep = vec![true; rows.len()];
    for (index, (_, value)) in rows.iter().enumerate().rev() {
        let Some(room) = super::outbox::room_of(value) else {
            continue;
        };
        let seen = per_room.entry(room).or_default();
        *seen += 1;
        keep[index] = *seen <= CATCH_UP_PER_ROOM;
    }
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for ((key, value), keep) in rows.into_iter().zip(keep) {
        if keep {
            kept.push((key, value));
        } else {
            dropped.push(key);
        }
    }
    (kept, dropped)
}

/// What the store has queued for `destination`, oldest first.
pub(super) fn queued(store: &FjallStore, destination: &str) -> Vec<OutboxRow> {
    ReadView::scan_prefix(store, &keys::federation_outbox_prefix(destination)).unwrap_or_default()
}

/// Cut `rows`, `destination`'s queue, for a catch-up: delete what it will
/// not be sent and count it. Returns what is left.
pub(super) fn cut(
    store: &FjallStore,
    metrics: &crate::metrics::Metrics,
    outbox: &super::outbox::OutboxIndex,
    destination: &str,
    rows: Vec<OutboxRow>,
) -> Vec<OutboxRow> {
    let (kept, dropped) = catch_up(rows);
    if !dropped.is_empty() {
        tracing::info!(
            destination,
            dropped = dropped.len(),
            "catching a long-unreachable server up: older queued events dropped"
        );
        for key in &dropped {
            let _ = Store::delete(store, key);
        }
        outbox.release(destination, dropped.len() as u64);
        metrics.record_catch_up_dropped(dropped.len() as u64);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The room a PDU outbox row is for.
    fn room_of(value: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(value).ok()?["room_id"]
            .as_str()
            .map(str::to_owned)
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn a_young_outage_is_retried_within_a_minute_and_a_patient_peer_within_its_cap() {
        let young = Duration::from_secs(5 * 60);
        assert_eq!(delay(SECOND, 1, Duration::ZERO, None), 2 * SECOND);
        assert_eq!(delay(SECOND, 6, young, None), 64 * SECOND);
        assert_eq!(delay(SECOND, 40, young, None), 64 * SECOND);
        let hour = Duration::from_secs(3600);
        assert_eq!(delay(SECOND, 6, young, Some(hour)), 64 * SECOND);
        assert_eq!(delay(SECOND, 11, young, Some(hour)), 2048 * SECOND);
        assert_eq!(delay(SECOND, 12, young, Some(hour)), hour);
        // A patient peer's cap bounds the long phase too, and a huge
        // failure count cannot overflow.
        assert_eq!(delay(SECOND, 13, 5 * hour, Some(hour)), hour);
        assert_eq!(delay(SECOND, u32::MAX, 5 * hour, Some(hour)), hour);
    }

    #[test]
    fn a_long_outage_waits_as_long_again_up_to_a_day() {
        let ten_minutes = Duration::from_secs(600);
        assert_eq!(delay(SECOND, 15, ten_minutes, None), ten_minutes);
        assert_eq!(delay(SECOND, 16, 3 * ten_minutes, None), 3 * ten_minutes);
        assert_eq!(
            delay(SECOND, 30, Duration::from_secs(5 * 86_400), None),
            MAX_BACKOFF
        );
    }

    /// The whole schedule on a fake clock: every attempt fails, each one
    /// made exactly when the last one's wait ran out.
    #[test]
    fn a_destination_that_keeps_failing_reaches_the_day_cap_and_stays_there() {
        let mut now = 1_000_000_u64;
        let mut entry: Option<Backoff> = None;
        let mut waits = Vec::new();
        for _ in 0..40 {
            let next = Backoff::after_failure(entry.as_ref(), now, SECOND, None, true);
            waits.push(next.interval);
            now += next.interval;
            entry = Some(next);
        }
        let day = u64::try_from(MAX_BACKOFF.as_millis()).unwrap();
        // The fast phase is unchanged: 2 s doubling to 64 s.
        assert_eq!(&waits[..6], &[2_000, 4_000, 8_000, 16_000, 32_000, 64_000]);
        assert!(waits.windows(2).all(|pair| pair[0] <= pair[1]), "{waits:?}");
        let first_day = waits.iter().position(|wait| *wait == day).unwrap();
        assert!(first_day < 25, "the day cap took {first_day} failures");
        assert!(waits[first_day..].iter().all(|wait| *wait == day));
        // Ten minutes in, the outage is long: each wait is as long as the
        // outage so far, so it doubles until the cap.
        let first_long = waits.iter().position(|wait| *wait >= 600_000).unwrap();
        for index in first_long..first_day {
            assert_eq!(waits[index + 1], (2 * waits[index]).min(day), "{waits:?}");
        }
        assert!(entry.unwrap().long);
    }

    #[test]
    fn a_reset_is_due_at_once_and_keeps_a_long_outage_catching_up() {
        let short = Backoff::after_failure(None, 1_000, SECOND, None, true);
        assert_eq!(short.reset(), None);
        let long = Backoff {
            failures: 20,
            since: Some(0),
            last: 10_000_000,
            interval: 10_000_000,
            unreachable: true,
            long: true,
        };
        let reset = long.reset().unwrap();
        assert!(reset.due(10_000_000));
        assert!(reset.long);
        // The next failure starts a fresh run, short waits first.
        let again = Backoff::after_failure(Some(&reset), 10_000_001, SECOND, None, true);
        assert_eq!(again.interval, 2_000);
        assert!(again.long);
    }

    #[test]
    fn a_patient_peer_is_never_caught_up_by_its_own_schedule() {
        // `long` records the outage; the outbox decides not to cut a
        // patient peer's queue, and its wait stays within its cap.
        let hour = Duration::from_secs(3600);
        let first = Backoff::after_failure(None, 0, SECOND, Some(hour), true);
        let later = Backoff::after_failure(Some(&first), 7_200_000, SECOND, Some(hour), true);
        assert_eq!(later.interval, 3_600_000);
    }

    fn row(seq: u64, room: &str) -> OutboxRow {
        (
            keys::federation_outbox("peer.example", seq),
            serde_json::json!({ "room_id": room, "depth": seq })
                .to_string()
                .into_bytes(),
        )
    }

    #[test]
    fn a_catch_up_keeps_the_newest_of_each_room_in_order() {
        let mut rows: Vec<OutboxRow> = (0..25).map(|seq| row(seq, "!busy:x")).collect();
        rows.insert(3, row(100, "!quiet:x"));
        rows.push((
            keys::federation_outbox("peer.example", 200),
            b"not json".to_vec(),
        ));
        let (kept, dropped) = catch_up(rows);
        assert_eq!(dropped.len(), 15);
        let busy: Vec<u64> = kept
            .iter()
            .filter(|(_, value)| room_of(value).as_deref() == Some("!busy:x"))
            .map(|(_, value)| {
                serde_json::from_slice::<Value>(value).unwrap()["depth"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(busy, (15..25).collect::<Vec<_>>());
        assert!(
            kept.iter()
                .any(|(_, value)| room_of(value).as_deref() == Some("!quiet:x"))
        );
        assert_eq!(kept.last().unwrap().1, b"not json");
    }

    #[test]
    fn an_entry_survives_the_store() {
        let directory = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(directory.path()).unwrap();
        let entry = Backoff::after_failure(None, 5, SECOND, None, false);
        save(&store, "dead.example", &entry);
        assert_eq!(load(&store).get("dead.example"), Some(&entry));
        forget(&store, "dead.example");
        assert!(load(&store).is_empty());
    }
}
