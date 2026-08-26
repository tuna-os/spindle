use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{StateKey, StateRoot, StateSnapshot};

/// Matrix caps `prev_events` at 20 references per event.
const MAX_PREV_EVENTS: usize = 20;

/// One bit per tip tracks which tips reach a node, so the tip set must fit a
/// `u64`. Matrix caps `prev_events` at 20, so a real fork is far below this.
const MAX_TIPS: usize = u64::BITS as usize;

/// A Matrix event ID, treated as an opaque value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(Box<str>);

impl EventId {
    #[must_use]
    pub fn new(value: impl Into<Box<str>>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Spindle's durable, per-room storage order.
///
/// Signed, because backfill needs somewhere to put history that arrives later
/// but belongs earlier. Live events ascend from `1`; backfilled history
/// descends from `0`. Backfill always proceeds strictly backwards from the
/// earliest event we hold, so an insertion *between* two stored events is never
/// required and a plain integer suffices — no fractional indexing, no
/// rebalancing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinearIndex(i64);

impl LinearIndex {
    #[must_use]
    pub fn get(self) -> i64 {
        self.0
    }

    /// Build an index from a raw value.
    ///
    /// The log allocates indices itself; this exists for storage round-trips
    /// and for tests that need to probe the encoding at the extremes.
    #[must_use]
    pub fn from_raw(value: i64) -> Self {
        Self(value)
    }
}

/// An already authenticated event ready to enter the room log.
#[derive(Clone, Debug)]
pub struct EventInput {
    pub event_id: EventId,
    /// The event's real signed Matrix DAG parents. These are never rewritten.
    pub prev_events: Vec<EventId>,
    /// Present when this event replaces a room-state slot.
    pub state_key: Option<StateKey>,
}

impl EventInput {
    #[must_use]
    pub fn new(event_id: impl Into<Box<str>>, prev_events: Vec<EventId>) -> Self {
        Self {
            event_id: EventId::new(event_id),
            prev_events,
            state_key: None,
        }
    }

    #[must_use]
    pub fn with_state_key(mut self, state_key: StateKey) -> Self {
        self.state_key = Some(state_key);
        self
    }
}

/// One event in storage order, with its Matrix DAG relationship intact.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub li: LinearIndex,
    pub event_id: EventId,
    pub prev_events: Vec<EventId>,
    pub depth: u64,
    /// The state slot this entry wrote, if it wrote one.
    ///
    /// Retained so the log is self-describing: a reader with only the log can
    /// rebuild room state by folding forward, without a separate state index.
    pub state_key: Option<StateKey>,
    pub state_after: StateSnapshot,
}

/// The ancestry that differs between a set of forward extremities.
///
/// Events are returned in Spindle's topological storage order. The nearest
/// common ancestor is a diagnostic anchor; all history common to every tip is
/// excluded from `events`, including DAGs with more than one maximal common
/// ancestor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkWindow {
    pub nearest_common_ancestor: EventId,
    pub events: Vec<EventId>,
    /// Entries the search touched. Proportional to the window, not to room
    /// history — assert on this to catch a regression back to a full scan, and
    /// report it as the fork-cost metric.
    pub visited: usize,
}

/// A per-room log in linear-index order, plus the minimal DAG overlay
/// federation requires.
///
/// Entries are keyed by [`LinearIndex`] rather than held in arrival order: this
/// is the in-memory analogue of the ordered key-value store the events are
/// destined for, so backfill lands in the right place without renumbering.
#[derive(Clone, Debug)]
pub struct RoomLog {
    entries: BTreeMap<i64, LogEntry>,
    positions: HashMap<EventId, i64>,
    forward_extremities: BTreeSet<EventId>,
    next_forward: i64,
    next_backward: i64,
}

impl Default for RoomLog {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            positions: HashMap::new(),
            forward_extremities: BTreeSet::new(),
            next_forward: 1,
            next_backward: 0,
        }
    }
}

impl RoomLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every entry in linear-index order, oldest first.
    #[must_use]
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &LogEntry> + ExactSizeIterator {
        self.entries.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look one entry up by event ID.
    #[must_use]
    pub fn get(&self, event_id: &EventId) -> Option<&LogEntry> {
        self.positions
            .get(event_id)
            .and_then(|li| self.entries.get(li))
    }

    #[must_use]
    pub fn forward_extremities(&self) -> &BTreeSet<EventId> {
        &self.forward_extremities
    }

    /// Next index a live append will take. Durable state; a reopen must
    /// restore it or the log will reissue indices it has already used.
    #[must_use]
    pub fn next_forward(&self) -> i64 {
        self.next_forward
    }

    /// Next index a backfill prepend will take.
    #[must_use]
    pub fn next_backward(&self) -> i64 {
        self.next_backward
    }

    /// Find the bounded divergent ancestry behind a set of event tips.
    ///
    /// This walks signed `prev_events`; linear-index proximity is never used to
    /// decide ancestry. The index supplies only the order the walk runs in.
    ///
    /// The search is bounded by the fork, not by room history. Every event's
    /// `li` is strictly greater than each of its parents' — appends allocate
    /// above everything held and backfill below it — so descending `li` is a
    /// valid reverse-topological order. Visiting in that order means a node's
    /// set of reaching tips is final when it is popped, so the walk can stop
    /// the moment every frontier entry is reachable from every tip: everything
    /// below that is common ancestry by definition and cannot affect the
    /// answer.
    ///
    /// Work is therefore `O(window x MAX_PREV_EVENTS)`. Each entry visited is
    /// either divergent, and so charged against `max_events`, or one of the
    /// bounded frontier that ends the walk.
    ///
    /// # Errors
    ///
    /// Returns [`ForkWindowError`] for an empty or oversized tip set, an
    /// unknown tip, a DAG without common history, or a divergent window larger
    /// than `max_events`.
    pub fn fork_window(
        &self,
        tips: &[EventId],
        max_events: usize,
    ) -> Result<ForkWindow, ForkWindowError> {
        if tips.is_empty() {
            return Err(ForkWindowError::EmptyTips);
        }
        if tips.len() > MAX_TIPS {
            return Err(ForkWindowError::TooManyTips(tips.len()));
        }

        // One bit per tip; a node reachable from all of them is common ancestry.
        let full = if tips.len() == u64::BITS as usize {
            u64::MAX
        } else {
            (1_u64 << tips.len()) - 1
        };

        let mut reached: HashMap<i64, u64> = HashMap::new();
        let mut frontier: BTreeSet<i64> = BTreeSet::new();
        for (index, tip) in tips.iter().enumerate() {
            let Some(li) = self.positions.get(tip) else {
                return Err(ForkWindowError::UnknownTip(tip.clone()));
            };
            *reached.entry(*li).or_default() |= 1_u64 << index;
            frontier.insert(*li);
        }

        let mut divergent: BTreeSet<i64> = BTreeSet::new();
        let mut visited = 0_usize;

        // Reach is propagated all the way down, including through entries
        // already known common: an entry can also be reachable by a longer path
        // that has not been walked yet, and truncating there would leave its
        // reach understated and mis-report it as divergent.
        //
        // Popping by descending `li` is a reverse-topological order, so an
        // entry's reach is final when it is popped, and the first entry popped
        // that every tip reaches has the greatest `li` of any such entry — the
        // nearest common ancestor.
        let mut nearest: Option<i64> = None;

        while let Some(li) = frontier.iter().next_back().copied() {
            // Once every frontier entry is reachable from every tip, all
            // remaining history is common ancestry and cannot affect the
            // answer. This is what keeps an ordinary tip fork from walking the
            // room: it fires one pop after the fork closes.
            if frontier.iter().all(|entry| reached[entry] == full) {
                nearest = nearest.or(Some(li));
                break;
            }

            frontier.remove(&li);
            visited += 1;

            let mask = reached[&li];
            if mask == full {
                nearest = nearest.or(Some(li));
            } else {
                divergent.insert(li);
                if divergent.len() > max_events {
                    return Err(ForkWindowError::TooLarge {
                        limit: max_events,
                        event_count: divergent.len(),
                    });
                }
            }

            // A backfill frontier names parents older than anything we hold.
            // Those are outside our history, not a corrupt index.
            for parent in &self.entries[&li].prev_events {
                if let Some(parent_li) = self.positions.get(parent).copied() {
                    *reached.entry(parent_li).or_default() |= mask;
                    frontier.insert(parent_li);
                }
            }
        }

        let Some(nearest) = nearest else {
            return Err(ForkWindowError::NoCommonAncestor);
        };

        Ok(ForkWindow {
            nearest_common_ancestor: self.entries[&nearest].event_id.clone(),
            events: divergent
                .into_iter()
                .map(|li| self.entries[&li].event_id.clone())
                .collect(),
            visited,
        })
    }

    /// Append a received event without changing its signed `prev_events`.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the event is duplicated, has invalid or
    /// unknown predecessors, exceeds the Matrix parent limit, or needs full
    /// state resolution.
    pub fn append_remote(&mut self, input: EventInput) -> Result<&LogEntry, AppendError> {
        self.append(input)
    }

    /// Author an event on every current extremity.
    ///
    /// In a linear room this is exactly one parent. After a stale class-D PDU it
    /// is a bounded set of parents, which collapses the federation DAG back to
    /// one extremity while the event still receives one linear storage index.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the new event is duplicated, the room has
    /// invalid predecessor state, or competing parent states need the Matrix
    /// room-version resolver.
    pub fn append_local(
        &mut self,
        event_id: impl Into<Box<str>>,
        state_key: Option<StateKey>,
    ) -> Result<&LogEntry, AppendError> {
        let input = EventInput {
            event_id: EventId::new(event_id),
            prev_events: self.forward_extremities.iter().cloned().collect(),
            state_key,
        };
        self.append(input)
    }

    fn append(&mut self, input: EventInput) -> Result<&LogEntry, AppendError> {
        if self.positions.contains_key(&input.event_id) {
            return Err(AppendError::DuplicateEvent(input.event_id));
        }
        if input.prev_events.len() > MAX_PREV_EVENTS {
            return Err(AppendError::TooManyPredecessors(input.prev_events.len()));
        }
        if self.entries.is_empty() && !input.prev_events.is_empty() {
            return Err(AppendError::UnknownPredecessor(
                input.prev_events[0].clone(),
            ));
        }
        if !self.entries.is_empty() && input.prev_events.is_empty() {
            return Err(AppendError::MissingPredecessor);
        }

        let mut parent_entries = Vec::with_capacity(input.prev_events.len());
        for parent in &input.prev_events {
            let Some(entry) = self.get(parent) else {
                return Err(AppendError::UnknownPredecessor(parent.clone()));
            };
            parent_entries.push(entry);
        }

        let mut state_after = merge_states(&parent_entries)?;
        let state_key = input.state_key;
        if let Some(state_key) = state_key.clone() {
            state_after = state_after.apply(state_key, input.event_id.as_str());
        }
        let depth = parent_entries
            .iter()
            .map(|entry| entry.depth)
            .max()
            .map_or(0, |depth| depth.saturating_add(1));

        let li = self.next_forward;
        self.next_forward = self
            .next_forward
            .checked_add(1)
            .ok_or(AppendError::IndexSpaceExhausted)?;

        let entry = LogEntry {
            li: LinearIndex(li),
            event_id: input.event_id,
            prev_events: input.prev_events,
            depth,
            state_key,
            state_after,
        };

        for parent in &entry.prev_events {
            self.forward_extremities.remove(parent);
        }
        self.forward_extremities.insert(entry.event_id.clone());
        self.positions.insert(entry.event_id.clone(), li);
        Ok(self.entries.entry(li).or_insert(entry))
    }

    /// Place one backfilled event before everything currently held.
    ///
    /// Backfill walks strictly backwards from the earliest event we have, so
    /// these take descending non-positive indices and never collide with live
    /// history. Two things are supplied by the caller rather than derived:
    ///
    /// - `state_after`, because the state of backfilled history is established
    ///   per chunk from one `/state_ids` call folded forward (SPEC §6.5), not
    ///   by walking parents we may not hold.
    /// - `depth`, because a backfilled PDU carries its own signed depth.
    ///
    /// The event's `prev_events` may name events older than anything we hold;
    /// that is ordinary at a backfill frontier, not an error.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the event is already present, exceeds the
    /// Matrix parent limit, the room is empty, or the index space is exhausted.
    pub fn prepend_remote(
        &mut self,
        input: EventInput,
        state_after: StateSnapshot,
        depth: u64,
    ) -> Result<&LogEntry, AppendError> {
        if self.positions.contains_key(&input.event_id) {
            return Err(AppendError::DuplicateEvent(input.event_id));
        }
        if input.prev_events.len() > MAX_PREV_EVENTS {
            return Err(AppendError::TooManyPredecessors(input.prev_events.len()));
        }
        if self.entries.is_empty() {
            return Err(AppendError::EmptyRoom);
        }

        let li = self.next_backward;
        self.next_backward = self
            .next_backward
            .checked_sub(1)
            .ok_or(AppendError::IndexSpaceExhausted)?;

        let entry = LogEntry {
            li: LinearIndex(li),
            event_id: input.event_id,
            prev_events: input.prev_events,
            depth,
            state_key: input.state_key,
            state_after,
        };

        // Backfilled history is never a forward extremity: it is, by
        // construction, behind everything we already hold.
        self.positions.insert(entry.event_id.clone(), li);
        Ok(self.entries.entry(li).or_insert(entry))
    }
}

/// Loads a stored state-trie node by its content address.
pub type NodeLoader<'a> = &'a mut dyn FnMut(&StateRoot) -> Option<Vec<u8>>;

/// One entry read back from storage, ready to be replayed.
#[derive(Clone, Debug)]
pub struct RestoredEntry {
    pub li: LinearIndex,
    pub event_id: EventId,
    pub prev_events: Vec<EventId>,
    pub depth: u64,
    pub state_key: Option<StateKey>,
    /// The state root recorded when this entry was first written.
    pub expected_state_root: [u8; 32],
}

/// A log rebuilt from storage, plus whichever entries could not be verified.
#[derive(Clone, Debug)]
pub struct RestoredLog {
    pub log: RoomLog,
    /// Entries whose refolded state disagrees with the root recorded at write
    /// time.
    ///
    /// Expected for backfilled ranges, whose state was supplied by the caller
    /// from `/state_ids` (SPEC §6.5) rather than derived from parents this log
    /// holds — re-establishing it is a fetch, not a replay. Anything else in
    /// here is corruption, and the caller must treat it as such rather than
    /// serving state it could not reproduce.
    pub unverified: Vec<LinearIndex>,
}

/// Why a log could not be rebuilt from storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreError {
    /// Entries were not supplied in ascending linear-index order.
    OutOfOrder { expected_after: i64, found: i64 },
    /// Two entries claim the same index.
    DuplicateIndex(i64),
}

impl RoomLog {
    /// Rebuild a log from durable records, supplied in ascending `li` order.
    ///
    /// State is refolded rather than stored per entry, then checked against the
    /// root recorded at write time. A disagreement is reported, never silently
    /// accepted: serving state we could not reproduce is worse than admitting
    /// we could not.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError`] if the records are out of order or duplicated.
    pub fn restore(
        entries: impl IntoIterator<Item = RestoredEntry>,
        next_forward: i64,
        next_backward: i64,
        forward_extremities: impl IntoIterator<Item = EventId>,
    ) -> Result<RestoredLog, RestoreError> {
        Self::rebuild(
            entries,
            next_forward,
            next_backward,
            forward_extremities,
            None,
        )
    }

    /// Rebuild a log, loading each entry's state from stored trie nodes rather
    /// than refolding it.
    ///
    /// This is the path a server uses. Refolding is `O(room)` — the state of
    /// the head is derived by replaying every state event before it — whereas
    /// loading a persisted root is `O(log n)` in the size of the state. It also
    /// restores backfilled ranges, whose state came from `/state_ids` and which
    /// a refold cannot reproduce by construction.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError`] if the records are out of order or duplicated.
    pub fn restore_with_state(
        entries: impl IntoIterator<Item = RestoredEntry>,
        next_forward: i64,
        next_backward: i64,
        forward_extremities: impl IntoIterator<Item = EventId>,
        load_node: NodeLoader<'_>,
    ) -> Result<RestoredLog, RestoreError> {
        Self::rebuild(
            entries,
            next_forward,
            next_backward,
            forward_extremities,
            Some(load_node),
        )
    }

    fn rebuild(
        entries: impl IntoIterator<Item = RestoredEntry>,
        next_forward: i64,
        next_backward: i64,
        forward_extremities: impl IntoIterator<Item = EventId>,
        mut load_node: Option<NodeLoader<'_>>,
    ) -> Result<RestoredLog, RestoreError> {
        let mut log = Self {
            entries: BTreeMap::new(),
            positions: HashMap::new(),
            forward_extremities: forward_extremities.into_iter().collect(),
            next_forward,
            next_backward,
        };
        let mut unverified = Vec::new();
        let mut previous: Option<i64> = None;

        for restored in entries {
            let li = restored.li.get();
            if let Some(previous) = previous {
                if li == previous {
                    return Err(RestoreError::DuplicateIndex(li));
                }
                if li < previous {
                    return Err(RestoreError::OutOfOrder {
                        expected_after: previous,
                        found: li,
                    });
                }
            }
            previous = Some(li);

            // Refold first. It is O(1) per entry given the parent's state,
            // which is already in hand from the previous iteration, whereas
            // rebuilding an entry's trie from stored nodes is O(state) — doing
            // that for every entry would make a reopen quadratic. The stored
            // trie is the fallback for the entries a refold cannot reproduce,
            // not the primary path.
            let parents: Vec<&LogEntry> = restored
                .prev_events
                .iter()
                .filter_map(|parent| log.get(parent))
                .collect();
            let mut folded = match merge_states(&parents) {
                Ok(state) => state,
                // A conflict means the fold cannot be reproduced; fall through
                // to the stored trie rather than refusing to open the room.
                Err(_) => StateSnapshot::new(),
            };
            if let Some(state_key) = restored.state_key.clone() {
                folded = folded.apply(state_key, restored.event_id.as_str());
            }

            let state_after = if *folded.root().as_bytes() == restored.expected_state_root {
                folded
            } else {
                // Backfilled ranges land here: their state came from
                // `/state_ids`, not from parents this log holds, so only the
                // stored trie can supply it.
                let stored = StateRoot::from_bytes(restored.expected_state_root);
                if let Some(state) = load_node
                    .as_mut()
                    .and_then(|load| StateSnapshot::rehydrate(stored, load).ok())
                {
                    state
                } else {
                    unverified.push(restored.li);
                    folded
                }
            };

            let entry = LogEntry {
                li: restored.li,
                event_id: restored.event_id,
                prev_events: restored.prev_events,
                depth: restored.depth,
                state_key: restored.state_key,
                state_after,
            };
            log.positions.insert(entry.event_id.clone(), li);
            log.entries.insert(li, entry);
        }

        Ok(RestoredLog { log, unverified })
    }
}

fn merge_states(parents: &[&LogEntry]) -> Result<StateSnapshot, AppendError> {
    let Some(first) = parents.first() else {
        return Ok(StateSnapshot::new());
    };
    if parents.len() == 1 {
        return Ok(first.state_after.clone());
    }

    let mut values: BTreeMap<StateKey, BTreeSet<Box<str>>> = BTreeMap::new();
    for parent in parents {
        parent.state_after.for_each(|key, event_id| {
            values
                .entry(key.clone())
                .or_default()
                .insert(event_id.into());
        });
    }

    let mut merged = StateSnapshot::new();
    for (key, candidates) in values {
        if candidates.len() > 1 {
            return Err(AppendError::NeedsStateResolution {
                key,
                candidates: candidates.into_iter().map(EventId).collect(),
            });
        }
        let event_id = candidates
            .into_iter()
            .next()
            .expect("a collected state key has a value");
        merged = merged.apply(key, event_id);
    }
    Ok(merged)
}

/// A violation of the executable room-log invariants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppendError {
    DuplicateEvent(EventId),
    MissingPredecessor,
    UnknownPredecessor(EventId),
    TooManyPredecessors(usize),
    /// Backfill needs an existing room to walk backwards from.
    EmptyRoom,
    /// The room exhausted its 64-bit linear index space.
    IndexSpaceExhausted,
    /// Competing state events require the room-version-specific Matrix resolver.
    NeedsStateResolution {
        key: StateKey,
        candidates: Vec<EventId>,
    },
}

/// Why a bounded divergent-ancestry window could not be produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkWindowError {
    EmptyTips,
    /// More tips than the reachability bitmap can track.
    TooManyTips(usize),
    UnknownTip(EventId),
    NoCommonAncestor,
    TooLarge {
        limit: usize,
        event_count: usize,
    },
}
