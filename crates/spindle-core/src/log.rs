use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{StateKey, StateSnapshot};

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinearIndex(u64);

impl LinearIndex {
    #[must_use]
    pub fn get(self) -> u64 {
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

/// A per-room append-only log plus the minimal DAG overlay federation requires.
#[derive(Clone, Debug, Default)]
pub struct RoomLog {
    entries: Vec<LogEntry>,
    positions: HashMap<EventId, usize>,
    forward_extremities: BTreeSet<EventId>,
}

impl RoomLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
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
            let Some(position) = self.positions.get(tip) else {
                return Err(ForkWindowError::UnknownTip(tip.clone()));
            };
            ancestries.push(self.ancestor_positions(*position));
        }

        let mut common = ancestries[0].clone();
        for ancestry in &ancestries[1..] {
            common.retain(|position| ancestry.contains(position));
        }
        let Some(nearest_position) = common
            .iter()
            .copied()
            .max_by_key(|position| (self.entries[*position].depth, self.entries[*position].li))
        else {
            return Err(ForkWindowError::NoCommonAncestor);
        };

        let divergent: BTreeSet<usize> = ancestries
            .into_iter()
            .flatten()
            .filter(|position| !common.contains(position))
            .collect();
        if divergent.len() > max_events {
            return Err(ForkWindowError::TooLarge {
                limit: max_events,
                event_count: divergent.len(),
            });
        }

        Ok(ForkWindow {
            nearest_common_ancestor: self.entries[nearest_position].event_id.clone(),
            events: divergent
                .into_iter()
                .map(|position| self.entries[position].event_id.clone())
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
        if input.prev_events.len() > 20 {
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
            let Some(position) = self.positions.get(parent) else {
                return Err(AppendError::UnknownPredecessor(parent.clone()));
            };
            parent_entries.push(&self.entries[*position]);
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
        let li = LinearIndex(
            u64::try_from(self.entries.len())
                .expect("room event count fits in u64")
                .saturating_add(1),
        );
        let entry = LogEntry {
            li,
            event_id: input.event_id,
            prev_events: input.prev_events,
            depth,
            state_after,
        };

        for parent in &entry.prev_events {
            self.forward_extremities.remove(parent);
        }
        self.forward_extremities.insert(entry.event_id.clone());
        self.positions
            .insert(entry.event_id.clone(), self.entries.len());
        self.entries.push(entry);
        Ok(self.entries.last().expect("entry was just pushed"))
    }

    fn ancestor_positions(&self, tip: usize) -> BTreeSet<usize> {
        let mut ancestors = BTreeSet::new();
        let mut pending = vec![tip];
        while let Some(position) = pending.pop() {
            if !ancestors.insert(position) {
                continue;
            }
            pending.extend(
                self.entries[position]
                    .prev_events
                    .iter()
                    .map(|parent| self.positions[parent]),
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
