//! Which destinations have PDUs queued, and how many (#821).
//!
//! The delivery loop used to read the whole outbox on every pass -- twice a
//! second, and after every delivery -- and copy every queued body, to find
//! the few destinations it could send to. With thousands of dead peers
//! that is the whole backlog, read again and again. This index is kept in
//! memory instead: built from one scan when the server starts, raised by
//! each enqueue and lowered by each delivery or drop. A pass reads rows
//! only for the destinations it is about to send to, and only the first
//! page of each ([`head`]).
//!
//! The index is a hint about where rows are, never the rows themselves:
//! every row stays in the store, so a restart loses nothing. It can be a
//! little high (a row put after the count) but never low for a row written
//! through [`OutboxIndex::enqueue`], because the count is raised before the
//! row is put. A row written any other way (an import, a test) is found by
//! the rescan ([`OutboxIndex::rescan`]) the loop runs when the index is
//! empty and every [`RESCAN_EVERY`].
//!
//! A row holds a reference to the event, not a copy of it ([`reference`]):
//! the room already stores the body once, with the event, and a pass reads
//! it from there when it builds a transaction ([`resolve`]). One message
//! into a room of thousands of servers writes thousands of small rows in
//! one batch. Rows from before that hold the whole PDU and are sent as
//! they are.
//!
//! It also bounds the queue of a destination that has been down a long
//! time. [`super::retry`] cuts such a queue once, when the outage turns
//! long, but the rows queued after that grew without limit until the next
//! attempt, up to a day away. Past [`MAX_QUEUED_PER_DESTINATION`] the
//! oldest are dropped as new ones arrive; the peer fetches what it misses
//! through `prev_events` and backfill when it returns, as it does after a
//! catch-up.

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use spindle_core::keys;
use spindle_store::{BatchOp, Durability, FjallStore, ReadView, Store, StoreError};

use super::OutboxRow;
use crate::metrics::Metrics;

/// The most PDUs queued for a destination that is in a long backoff and
/// has no patience setting. Past it the oldest are dropped.
pub const MAX_QUEUED_PER_DESTINATION: usize = 5_000;

/// How often the loop looks for rows the index was not told about, on top
/// of looking whenever the index is empty.
pub(super) const RESCAN_EVERY: Duration = Duration::from_secs(300);

/// The two lists a pass picks destinations from, each with its own place
/// to start so that neither favours the names that sort first.
#[derive(Clone, Copy)]
pub(super) enum Turn {
    /// Destinations that answered last time.
    Healthy,
    /// Destinations due a retry.
    Retry,
}

/// What the index knows of one destination's queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Queue {
    /// Rows queued, as far as the index knows.
    pub rows: u64,
    /// Changes whenever a row is queued, so a pass that found nothing can
    /// tell that nothing has been queued since it looked.
    pub generation: u64,
}

#[derive(Default)]
struct State {
    queues: BTreeMap<String, Queue>,
    /// Destinations whose queue is bounded: down a long time, and not
    /// marked patient by the operator.
    shedding: HashSet<String>,
    /// Where the last pass stopped, per [`Turn`].
    cursors: [Option<String>; 2],
}

/// See the module documentation.
pub struct OutboxIndex {
    state: Mutex<State>,
    cap: usize,
}

/// Stops a [`ReadView::visit_prefix`] once a page is read.
const PAGE_FULL: &str = "outbox page full";

/// The first `limit` rows queued for `destination`, oldest first. Reads
/// only those: the scan stops at the page, however long the queue is.
pub(super) fn head(store: &FjallStore, destination: &str, limit: usize) -> Vec<OutboxRow> {
    let mut rows = Vec::new();
    if limit == 0 {
        return rows;
    }
    let read = ReadView::visit_prefix(
        store,
        &keys::federation_outbox_prefix(destination),
        &mut |key, value| {
            rows.push((key.to_vec(), value.to_vec()));
            if rows.len() >= limit {
                return Err(StoreError::Backend(PAGE_FULL.to_owned()));
            }
            Ok(())
        },
    );
    match read {
        Ok(()) => {}
        Err(StoreError::Backend(reason)) if reason == PAGE_FULL => {}
        Err(error) => tracing::warn!(destination, "cannot read the outbox: {error}"),
    }
    rows
}

/// The first byte of a row that refers to a stored event. A row from
/// before #821 holds the whole PDU, a JSON object, which starts with `{`
/// (0x7b); no JSON document starts with 0x00, so the two shapes cannot be
/// mistaken for one another.
const REFERENCE: u8 = 0x00;

/// The value of a row that names an event the room already stores: the tag,
/// the room ID's length as two bytes, the room ID, then the event ID. The
/// event body is stored once with the event; every destination's row is
/// this small.
#[must_use]
pub fn reference(room_id: &str, event_id: &str) -> Vec<u8> {
    let room = room_id.as_bytes();
    let length = u16::try_from(room.len()).unwrap_or(u16::MAX);
    let mut row = Vec::with_capacity(3 + room.len() + event_id.len());
    row.push(REFERENCE);
    row.extend_from_slice(&length.to_be_bytes());
    row.extend_from_slice(&room[..usize::from(length)]);
    row.extend_from_slice(event_id.as_bytes());
    row
}

/// The room and event a [`reference`] row names; `None` for a row that
/// holds a whole PDU.
fn parse_reference(value: &[u8]) -> Option<(&str, &str)> {
    let rest = value.strip_prefix(&[REFERENCE])?;
    let length = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
    let room = std::str::from_utf8(rest.get(2..2 + length)?).ok()?;
    let event = std::str::from_utf8(rest.get(2 + length..)?).ok()?;
    Some((room, event))
}

/// The room a queued row is for, in either shape.
pub(super) fn room_of(value: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Room<'a> {
        #[serde(borrow)]
        room_id: Option<std::borrow::Cow<'a, str>>,
    }
    if let Some((room, _)) = parse_reference(value) {
        return Some(room.to_owned());
    }
    serde_json::from_slice::<Room<'_>>(value)
        .ok()?
        .room_id
        .map(std::borrow::Cow::into_owned)
}

/// `rows` with each [`reference`] replaced by the body it names, as the
/// room stores it now -- the redacted form for a redacted event, which is
/// what federation sends. A row that holds a whole PDU passes through.
///
/// A row whose body is gone (an admin purge) can never be sent: it is
/// deleted and counted, and the second return value says how many were. A
/// body that cannot be read for another reason leaves its row for the next
/// pass.
pub(super) fn resolve(
    store: &FjallStore,
    index: &OutboxIndex,
    metrics: &Metrics,
    destination: &str,
    rows: Vec<OutboxRow>,
) -> (Vec<OutboxRow>, u64) {
    let mut sendable = Vec::with_capacity(rows.len());
    let mut purged = 0_u64;
    for (key, value) in rows {
        let Some((room, event)) = parse_reference(&value) else {
            sendable.push((key, value));
            continue;
        };
        match ReadView::get(store, &keys::event_body(room, event)) {
            Ok(Some(body)) => sendable.push((key, body)),
            Ok(None) => {
                if Store::delete(store, &key).is_ok() {
                    purged += 1;
                }
            }
            Err(error) => tracing::warn!(destination, "cannot read a queued event: {error}"),
        }
    }
    if purged > 0 {
        index.release(destination, purged);
        metrics.record_outbox_body_missing(purged);
        tracing::warn!(
            destination,
            purged,
            "queued events whose bodies were purged were dropped from the queue"
        );
    }
    (sendable, purged)
}

impl OutboxIndex {
    /// An index of what `store` holds now, bounding queues at
    /// [`MAX_QUEUED_PER_DESTINATION`].
    #[must_use]
    pub fn load(store: &FjallStore) -> Self {
        Self::with_cap(store, MAX_QUEUED_PER_DESTINATION)
    }

    /// As [`Self::load`] with another bound.
    #[must_use]
    pub fn with_cap(store: &FjallStore, cap: usize) -> Self {
        let index = Self {
            state: Mutex::new(State::default()),
            cap,
        };
        index.rescan(store);
        index
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count the rows in the store and raise the index to match. Never
    /// lowers a count: one that is too high corrects itself when its
    /// destination is next read and found empty, and lowering here could
    /// race an enqueue.
    pub(super) fn rescan(&self, store: &FjallStore) {
        let mut found: BTreeMap<String, u64> = BTreeMap::new();
        let read = ReadView::visit_prefix(store, &keys::federation_outbox_all(), &mut |key, _| {
            if let Some(destination) = keys::federation_outbox_destination(key) {
                *found.entry(destination).or_default() += 1;
            }
            Ok(())
        });
        if let Err(error) = read {
            tracing::warn!("cannot scan the outbox: {error}");
            return;
        }
        let mut state = self.lock();
        for (destination, rows) in found {
            let queue = state.queues.entry(destination).or_insert(Queue {
                rows: 0,
                generation: 0,
            });
            if rows > queue.rows {
                queue.rows = rows;
                queue.generation += 1;
            }
        }
    }

    /// Whether no destination has rows.
    pub(super) fn is_empty(&self) -> bool {
        self.lock().queues.is_empty()
    }

    /// Queue one event for each of `queued` -- `(destination, seq)` pairs --
    /// as a reference to the room's stored body ([`reference`]), in one
    /// batch: a crash leaves every destination with the event or none.
    ///
    /// The counts are raised before the rows are put, so a pass that runs
    /// between the two finds the destination and not a hole. When a
    /// destination's queue is bounded and now past the bound, the oldest
    /// rows go, down to a tenth under the bound so that the cost of finding
    /// them is paid once for many enqueues.
    ///
    /// # Errors
    ///
    /// Returns the store's error if the rows cannot be written; the counts
    /// are undone.
    pub fn enqueue(
        &self,
        store: &FjallStore,
        metrics: &Metrics,
        queued: &[(&str, u64)],
        row: &[u8],
    ) -> Result<(), StoreError> {
        let excess: Vec<(&str, usize)> = {
            let mut state = self.lock();
            let mut excess = Vec::new();
            for (destination, _) in queued {
                let bounded = state.shedding.contains(*destination);
                let queue = state
                    .queues
                    .entry((*destination).to_owned())
                    .or_insert(Queue {
                        rows: 0,
                        generation: 0,
                    });
                queue.rows += 1;
                queue.generation += 1;
                let rows = usize::try_from(queue.rows).unwrap_or(usize::MAX);
                if bounded && rows > self.cap {
                    excess.push((*destination, rows - self.cap + self.cap / 10));
                }
            }
            excess
        };
        let ops: Vec<BatchOp> = queued
            .iter()
            .map(|(destination, seq)| {
                BatchOp::Put(keys::federation_outbox(destination, *seq), row.to_vec())
            })
            .collect();
        if let Err(error) = Store::commit_ops(store, &ops, Durability::Group) {
            for (destination, _) in queued {
                self.release(destination, 1);
            }
            return Err(error);
        }
        for (destination, excess) in excess {
            self.shed(store, metrics, destination, excess);
        }
        Ok(())
    }

    /// Drop the oldest `excess` rows of `destination`'s queue and count
    /// them.
    fn shed(&self, store: &FjallStore, metrics: &Metrics, destination: &str, excess: usize) {
        let mut dropped = 0_u64;
        for (key, _) in head(store, destination, excess) {
            if Store::delete(store, &key).is_ok() {
                dropped += 1;
            }
        }
        if dropped == 0 {
            return;
        }
        self.release(destination, dropped);
        metrics.record_outbox_capped(dropped);
        tracing::warn!(
            destination,
            dropped,
            cap = self.cap,
            "the queue for a long-unreachable server is full: oldest queued events dropped"
        );
    }

    /// `rows` rows of `destination` are gone: delivered or dropped.
    pub(super) fn release(&self, destination: &str, rows: u64) {
        let mut state = self.lock();
        let Some(queue) = state.queues.get_mut(destination) else {
            return;
        };
        queue.rows = queue.rows.saturating_sub(rows);
        if queue.rows == 0 {
            state.queues.remove(destination);
        }
    }

    /// A read of `destination` found no rows. Forget it, unless a row was
    /// queued since `seen` was taken.
    pub(super) fn found_empty(&self, destination: &str, seen: Queue) {
        let mut state = self.lock();
        if state.queues.get(destination) == Some(&seen) {
            state.queues.remove(destination);
        }
    }

    /// Every destination with rows, and its queue.
    pub(super) fn snapshot(&self) -> BTreeMap<String, Queue> {
        self.lock().queues.clone()
    }

    /// Bound the queues of exactly these destinations.
    pub(super) fn set_shedding(&self, destinations: impl IntoIterator<Item = String>) {
        self.lock().shedding = destinations.into_iter().collect();
    }

    /// `destinations`, sorted, starting after where the last pass for
    /// `turn` stopped and wrapping around.
    pub(super) fn rotate(&self, turn: Turn, destinations: Vec<String>) -> Vec<String> {
        let state = self.lock();
        rotated(destinations, state.cursors[turn as usize].as_deref())
    }

    /// The last pass for `turn` ended at `last`.
    pub(super) fn stopped_at(&self, turn: Turn, last: &str) {
        self.lock().cursors[turn as usize] = Some(last.to_owned());
    }

    /// Rows queued for `destination`, for tests.
    #[must_use]
    pub fn queued(&self, destination: &str) -> u64 {
        self.lock()
            .queues
            .get(destination)
            .map_or(0, |queue| queue.rows)
    }
}

/// `sorted` turned so that it starts with the first name after `after`.
fn rotated(sorted: Vec<String>, after: Option<&str>) -> Vec<String> {
    let start = after.map_or(0, |after| {
        sorted.partition_point(|name| name.as_str() <= after)
    });
    let mut out = sorted;
    let start = start.min(out.len());
    out.rotate_left(start);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FjallStore) {
        let directory = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(directory.path()).unwrap();
        (directory, store)
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_two_row_shapes_cannot_be_mistaken_for_each_other() {
        let new = reference("!room:x", "$event");
        assert_eq!(parse_reference(&new), Some(("!room:x", "$event")));
        assert_eq!(room_of(&new).as_deref(), Some("!room:x"));
        let old = br#"{"room_id":"!room:x","type":"m.room.message"}"#;
        assert_eq!(parse_reference(old), None);
        assert_eq!(room_of(old).as_deref(), Some("!room:x"));
        assert_eq!(parse_reference(&[REFERENCE, 0xff]), None);
    }

    #[test]
    fn rotation_starts_after_the_cursor_and_wraps() {
        let all = names(&["a", "b", "c", "d"]);
        assert_eq!(rotated(all.clone(), None), all);
        assert_eq!(
            rotated(all.clone(), Some("b")),
            names(&["c", "d", "a", "b"])
        );
        assert_eq!(rotated(all.clone(), Some("d")), all);
        // A cursor that is no longer in the list still marks a place.
        assert_eq!(rotated(all, Some("bb")), names(&["c", "d", "a", "b"]));
    }

    #[test]
    fn the_index_is_rebuilt_from_the_store() {
        let (_dir, store) = store();
        for seq in 1..=3 {
            Store::put(&store, &keys::federation_outbox("a.example", seq), b"{}").unwrap();
        }
        Store::put(&store, &keys::federation_outbox("b.example", 4), b"{}").unwrap();
        let index = OutboxIndex::load(&store);
        assert_eq!(index.queued("a.example"), 3);
        assert_eq!(index.queued("b.example"), 1);
        assert_eq!(index.queued("c.example"), 0);
    }

    #[test]
    fn a_row_written_outside_the_index_is_found_by_a_rescan() {
        let (_dir, store) = store();
        let index = OutboxIndex::load(&store);
        assert!(index.is_empty());
        Store::put(&store, &keys::federation_outbox("late.example", 1), b"{}").unwrap();
        index.rescan(&store);
        assert_eq!(index.queued("late.example"), 1);
    }

    #[test]
    fn a_page_reads_only_its_own_rows() {
        let (_dir, store) = store();
        for seq in 1..=200 {
            Store::put(&store, &keys::federation_outbox("a.example", seq), b"{}").unwrap();
        }
        Store::put(&store, &keys::federation_outbox("b.example", 1), b"{}").unwrap();
        let before = store.scanned();
        let page = head(&store, "a.example", 50);
        assert_eq!(page.len(), 50);
        assert_eq!(store.scanned() - before, 50);
        assert_eq!(
            keys::federation_outbox("a.example", 1),
            page.first().unwrap().0
        );
    }

    #[test]
    fn a_count_that_ran_ahead_of_the_store_is_forgotten_unless_something_was_queued() {
        let (_dir, store) = store();
        let metrics = Metrics::default();
        let index = OutboxIndex::load(&store);
        index
            .enqueue(&store, &metrics, &[("a.example", 1)], b"{}")
            .unwrap();
        let seen = index.snapshot()["a.example"];
        // The row is gone behind the index's back.
        Store::delete(&store, &keys::federation_outbox("a.example", 1)).unwrap();
        index
            .enqueue(&store, &metrics, &[("a.example", 2)], b"{}")
            .unwrap();
        index.found_empty("a.example", seen);
        assert_eq!(index.queued("a.example"), 2, "a newer enqueue keeps it");
        let seen = index.snapshot()["a.example"];
        index.found_empty("a.example", seen);
        assert_eq!(index.queued("a.example"), 0);
    }

    #[test]
    fn a_full_queue_drops_the_oldest_and_counts_them() {
        let (_dir, store) = store();
        let metrics = Metrics::default();
        let index = OutboxIndex::with_cap(&store, 20);
        index.set_shedding(["dead.example".to_owned()]);
        for seq in 1..=25 {
            index
                .enqueue(&store, &metrics, &[("dead.example", seq)], b"{}")
                .unwrap();
        }
        let left = head(&store, "dead.example", 100);
        assert!(left.len() <= 20, "{} rows left", left.len());
        assert_eq!(left.len() as u64, index.queued("dead.example"));
        assert_eq!(
            left.last().unwrap().0,
            keys::federation_outbox("dead.example", 25),
            "the newest is kept"
        );
        assert!(
            !left
                .iter()
                .any(|(key, _)| *key == keys::federation_outbox("dead.example", 1)),
            "the oldest is dropped"
        );
        assert_eq!(metrics.outbox_capped(), 25 - left.len() as u64);
    }

    #[test]
    fn a_destination_that_is_not_down_long_is_not_bounded() {
        let (_dir, store) = store();
        let metrics = Metrics::default();
        let index = OutboxIndex::with_cap(&store, 5);
        for seq in 1..=30 {
            index
                .enqueue(&store, &metrics, &[("busy.example", seq)], b"{}")
                .unwrap();
        }
        assert_eq!(index.queued("busy.example"), 30);
        assert_eq!(metrics.outbox_capped(), 0);
    }
}
