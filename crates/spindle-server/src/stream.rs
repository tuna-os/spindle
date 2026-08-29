//! The server-global stream position, and the watermark that makes it safe
//! to publish (SPEC §10.2).
//!
//! `/sync` needs a total order across rooms; the linear index only orders
//! events within one. So every committed event takes an id from a global
//! counter, and a sync token is a position in that sequence.
//!
//! **The subtle part is not the counter, it is when an id may be shown to a
//! client.** Today every append holds the same lock, so ids are allocated
//! and committed in the same order and the newest id is always safe. The
//! moment appends to different rooms proceed at once that stops being true:
//! a writer can take id 7, and a writer that took id 8 can finish first. A
//! `/sync` that then hands out a token of 8 has told the client "you have
//! seen everything up to 8" — and when 7 lands, no future sync will ever
//! mention it, because the client's token is already past it. The event is
//! not lost from the log; it is lost from that client's view, permanently
//! and silently.
//!
//! SPEC §10.2's answer, and the standard one: an id is publishable only when
//! every lower id has committed, so the visible position is the **highest
//! contiguous committed id** and ids that finish early wait in an interval
//! set until their predecessors arrive.
//!
//! This is written and proven before the lock it exists for is touched. It
//! is correct under the current single lock too — allocate and commit in
//! order and the watermark is exactly the counter — so it can land, and be
//! exercised, ahead of the change that needs it.

use std::collections::BTreeSet;
use std::sync::Mutex;

/// The global stream counter, and the boundary of what may be published.
#[derive(Debug)]
pub struct Stream {
    state: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// The next id [`Stream::allocate`] will hand out.
    next: u64,
    /// The highest id for which every id at or below it has committed.
    watermark: u64,
    /// Committed ids *above* the watermark, waiting on their predecessors.
    ///
    /// A set rather than a range list: the gaps are at most as many as
    /// there are appends in flight, which is bounded by the number of
    /// writers, so the tidier representation would be optimising a
    /// structure that holds single digits.
    ahead: BTreeSet<u64>,
}

impl Stream {
    /// A stream whose highest committed id is `resumed_at`.
    ///
    /// Restart is the one place the watermark starts non-zero: everything in
    /// the store committed, by definition, or it would not be in the store.
    #[must_use]
    pub fn resuming_at(resumed_at: u64) -> Self {
        Self {
            state: Mutex::new(Inner {
                next: resumed_at + 1,
                watermark: resumed_at,
                ahead: BTreeSet::new(),
            }),
        }
    }

    /// Take the next id. It is **not** publishable until [`Self::commit`].
    pub fn allocate(&self) -> u64 {
        let mut state = self.lock();
        let id = state.next;
        state.next += 1;
        id
    }

    /// Mark `id` durable, advancing the watermark over any run it completes.
    ///
    /// Committing out of order is the case this exists for: an id above the
    /// watermark waits, and the watermark jumps when the gap below it fills.
    pub fn commit(&self, id: u64) {
        let mut state = self.lock();
        if id <= state.watermark {
            // Already published, or committed twice. Either way, nothing to
            // do -- and specifically not a panic: a retry that double-commits
            // must not take the server down.
            return;
        }
        state.ahead.insert(id);
        let mut watermark = state.watermark;
        while state.ahead.remove(&(watermark + 1)) {
            watermark += 1;
        }
        state.watermark = watermark;
    }

    /// Release `id` without an event behind it.
    ///
    /// For an append that allocated an id and then failed. The id must stop
    /// holding the watermark either way: an id abandoned in silence stalls
    /// the visible position *forever*, which does not lose one event, it
    /// makes every event after it invisible to every client. Advancing over
    /// it is safe because the stream scan already skips absent ids -- there
    /// is no event there to miss.
    ///
    /// Distinct from [`Self::commit`] only in what it says. Keeping the two
    /// spellings apart is the difference between a call site that means
    /// "this landed" and one that means "this did not, and must not wedge
    /// the server".
    pub fn abandon(&self, id: u64) {
        self.commit(id);
    }

    /// The highest id every client may be told about.
    ///
    /// Never a value with an uncommitted id below it, which is the whole
    /// point: a token past an in-flight id would skip that event forever.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.lock().watermark
    }

    /// Ids taken but not yet committed.
    ///
    /// Zero whenever nothing is in flight, so a test can assert the stream
    /// settles rather than sampling it and hoping.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        let state = self.lock();
        state.next - 1 - state.watermark - state.ahead.len() as u64
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::Stream;

    /// A deterministic shuffle, so a failure reproduces exactly.
    ///
    /// No `rand` here on purpose: a property test whose counterexample
    /// cannot be replayed is a flake generator, and the point of this
    /// module is to be believed.
    fn shuffled(count: usize, seed: u64) -> Vec<u64> {
        let mut order: Vec<u64> = (1..=count as u64).collect();
        let mut state = seed | 1;
        for index in (1..order.len()).rev() {
            // xorshift64: small, deterministic, and adequate for shuffling.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pick = usize::try_from(state % (index as u64 + 1))
                .expect("a modulus below the length fits the length's type");
            order.swap(index, pick);
        }
        order
    }

    #[test]
    fn sequential_use_makes_the_watermark_the_counter() {
        // The behaviour under today's single lock: allocate, commit, in
        // order. This is what makes the structure safe to land before the
        // change that needs it -- it cannot alter what the server does now.
        let stream = Stream::resuming_at(0);
        for expected in 1..=100 {
            let id = stream.allocate();
            assert_eq!(id, expected);
            stream.commit(id);
            assert_eq!(stream.position(), expected);
        }
        assert_eq!(stream.in_flight(), 0);
    }

    #[test]
    fn a_restart_resumes_above_what_the_store_holds() {
        let stream = Stream::resuming_at(42);
        assert_eq!(stream.position(), 42);
        assert_eq!(stream.allocate(), 43);
    }

    /// **The property this module exists for.**
    ///
    /// At every moment, whatever order commits arrive in, the position must
    /// never be at or above an id that has not committed. A position past an
    /// in-flight id is a client told it has seen an event that has not
    /// happened, and no later sync will mention it.
    #[test]
    fn the_position_never_passes_an_uncommitted_id() {
        for seed in 1..=200 {
            let count = 32usize;
            let stream = Stream::resuming_at(0);
            let ids: Vec<u64> = (0..count).map(|_| stream.allocate()).collect();
            assert_eq!(stream.in_flight(), count as u64);

            let mut committed = vec![false; count + 1];
            for id in shuffled(count, seed) {
                stream.commit(id);
                committed[usize::try_from(id).expect("an id at or below count")] = true;

                let position =
                    usize::try_from(stream.position()).expect("a position at or below count");
                // Everything at or below the position must have committed.
                for (lower, landed) in committed.iter().enumerate().take(position + 1).skip(1) {
                    assert!(
                        landed,
                        "seed {seed}: position {position} passed uncommitted id {lower}"
                    );
                }
                // And the position must be the *highest* such id, or the
                // structure is correct but useless -- it would stall.
                let contiguous = (1..=count).take_while(|id| committed[*id]).count();
                assert_eq!(
                    position, contiguous,
                    "seed {seed}: position {position} lags the contiguous run {contiguous}"
                );
            }
            assert_eq!(stream.position(), count as u64);
            assert_eq!(stream.in_flight(), 0);
            assert_eq!(ids.last(), Some(&(count as u64)));
        }
    }

    #[test]
    fn the_position_only_ever_moves_forward() {
        for seed in 1..=50 {
            let stream = Stream::resuming_at(0);
            for _ in 0..16 {
                stream.allocate();
            }
            let mut highest = 0;
            for id in shuffled(16usize, seed) {
                stream.commit(id);
                let position = stream.position();
                assert!(position >= highest, "seed {seed}: position went backwards");
                highest = position;
            }
        }
    }

    #[test]
    fn committing_twice_is_not_fatal() {
        // A retry that re-commits must not panic or rewind: the append path
        // has error branches, and a server that dies on a double commit is
        // worse than one that ignores it.
        let stream = Stream::resuming_at(0);
        let id = stream.allocate();
        stream.commit(id);
        stream.commit(id);
        assert_eq!(stream.position(), 1);
        // And it must not leave the id behind in `ahead`, where nothing will
        // ever remove it: the watermark is already past it, so the run that
        // drains the set will never reach it again. A stale entry is a slow
        // leak and makes `in_flight` count backwards.
        assert_eq!(stream.in_flight(), 0, "a re-commit was left in the set");

        let second = stream.allocate();
        stream.commit(second);
        stream.commit(1);
        assert_eq!(stream.position(), 2);
        assert_eq!(stream.in_flight(), 0);
    }

    #[test]
    fn an_abandoned_id_does_not_wedge_the_stream() {
        // An append that allocates an id and then fails must not stall the
        // visible position: that would not lose one event, it would make
        // every later event invisible to every client.
        let stream = Stream::resuming_at(0);
        let doomed = stream.allocate();
        stream.abandon(doomed);
        for _ in 0..4 {
            let id = stream.allocate();
            stream.commit(id);
        }
        assert_eq!(stream.position(), 5);
        assert_eq!(stream.in_flight(), 0);
    }

    #[test]
    fn an_id_that_never_commits_holds_the_line() {
        // The other half of the guarantee: a writer that dies mid-append
        // must stall the *visible* position rather than let later ids past
        // it. Losing throughput here is correct; losing an event is not.
        let stream = Stream::resuming_at(0);
        let stalled = stream.allocate();
        for _ in 0..8 {
            let id = stream.allocate();
            stream.commit(id);
        }
        assert_eq!(
            stream.position(),
            0,
            "later ids were published over an id still in flight"
        );
        stream.commit(stalled);
        assert_eq!(stream.position(), 9, "the run did not complete on arrival");
    }
}
