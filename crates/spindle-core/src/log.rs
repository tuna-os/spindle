use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{StateKey, StateSnapshot};

/// Matrix caps `prev_events` at 20 references per event.
const MAX_PREV_EVENTS: usize = 20;

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

    /// Find the bounded divergent ancestry behind a set of event tips.
    ///
    /// This walks signed `prev_events`; linear-index proximity is never used to
    /// decide ancestry. The index is used only to return a deterministic,
    /// topological order and to break ties between common ancestors.
    ///
    /// # Errors
    ///
    /// Returns [`ForkWindowError`] for an empty tip set, an unknown tip, a DAG
    /// without common history, or a divergent window larger than `max_events`.
    pub fn fork_window(
        &self,
        tips: &[EventId],
        max_events: usize,
    ) -> Result<ForkWindow, ForkWindowError> {
        if tips.is_empty() {
            return Err(ForkWindowError::EmptyTips);
        }

        let mut ancestries = Vec::with_capacity(tips.len());
        for tip in tips {
            let Some(li) = self.positions.get(tip) else {
                return Err(ForkWindowError::UnknownTip(tip.clone()));
            };
            ancestries.push(self.ancestor_positions(*li));
        }

        let mut common = ancestries[0].clone();
        for ancestry in &ancestries[1..] {
            common.retain(|position| ancestry.contains(position));
        }
        let Some(nearest) = common
            .iter()
            .copied()
            .max_by_key(|li| (self.entries[li].depth, *li))
        else {
            return Err(ForkWindowError::NoCommonAncestor);
        };

        let divergent: BTreeSet<i64> = ancestries
            .into_iter()
            .flatten()
            .filter(|li| !common.contains(li))
            .collect();
        if divergent.len() > max_events {
            return Err(ForkWindowError::TooLarge {
                limit: max_events,
                event_count: divergent.len(),
            });
        }

        Ok(ForkWindow {
            nearest_common_ancestor: self.entries[&nearest].event_id.clone(),
            events: divergent
                .into_iter()
                .map(|li| self.entries[&li].event_id.clone())
                .collect(),
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
        if let Some(state_key) = input.state_key {
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
            state_after,
        };

        // Backfilled history is never a forward extremity: it is, by
        // construction, behind everything we already hold.
        self.positions.insert(entry.event_id.clone(), li);
        Ok(self.entries.entry(li).or_insert(entry))
    }

    fn ancestor_positions(&self, tip: i64) -> BTreeSet<i64> {
        let mut ancestors = BTreeSet::new();
        let mut pending = vec![tip];
        while let Some(li) = pending.pop() {
            if !ancestors.insert(li) {
                continue;
            }
            // A backfilled event may name parents older than anything we hold.
            // Those are outside our history, not a corrupt index.
            pending.extend(
                self.entries[&li]
                    .prev_events
                    .iter()
                    .filter_map(|parent| self.positions.get(parent).copied()),
            );
        }
        ancestors
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
    UnknownTip(EventId),
    NoCommonAncestor,
    TooLarge { limit: usize, event_count: usize },
}
