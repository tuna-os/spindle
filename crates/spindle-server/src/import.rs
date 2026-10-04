//! Turning a Synapse room into a Spindle log (#20).
//!
//! Synapse stores a room as a DAG; Spindle stores it as a log. The conversion
//! is not a rewrite. Every event keeps its own event ID and its own signed
//! `prev_events`, and the only thing the importer chooses is the *order* they
//! are offered in. That is precisely why an import can preserve identifiers,
//! hashes and signatures: nothing it does is visible inside an event.
//!
//! Three things here carry judgement, and each is a way an import goes wrong
//! quietly rather than loudly:
//!
//! 1. **Which events are part of the room at all.** Synapse's `events` table
//!    holds more than a room's timeline — outliers fetched only to check
//!    somebody's auth chain, and events it rejected. Importing either would
//!    put history into a room that was never in it.
//! 2. **What order puts every parent before its children.** Neither of the
//!    orderings Synapse already has is safe to reuse; see [`plan`].
//! 3. **Whether the result is the same room.** After the replay, the state
//!    Spindle folded forward is compared against the state Synapse says the
//!    room is in, key by key. That is #20's exit criterion, and it is a real
//!    test rather than a formality: Spindle's fork merge (SPEC §9.2) and
//!    Synapse's state resolution are different algorithms, so a room with a
//!    contested fork can legitimately produce two answers. Finding that is
//!    the point of running it.
//!
//! This module reads a [`SourceRoom`] rather than a database. Keeping the two
//! apart is what lets the part with the judgement in it be tested exhaustively
//! with no database at all, and it is also what keeps a `SQLite` fixture and a
//! production `PostgreSQL` deployment behind one interface rather than two
//! copies of this logic. The reader that fills a `SourceRoom` from Synapse's
//! own tables lands separately.

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};

/// Reading a `SourceRoom` out of a Synapse database.
///
/// Behind a non-default feature: it pulls in a bundled SQLite, and a one-shot
/// migration path is not a reason for the server binary or the hot CI gate to
/// pay a C compile.
#[cfg(feature = "synapse-import")]
pub mod synapse;

use spindle_core::{AppendError, EventId, EventInput, RoomLog, StateKey, StateSnapshot};

/// Room state as Synapse holds it: `(type, state_key)` to event ID.
pub type StateMap = BTreeMap<(String, String), String>;

/// One event as Synapse stores it, reduced to what ordering needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEvent {
    pub event_id: String,
    pub event_type: String,
    /// `None` for a message, `Some` — possibly empty — for a state event.
    pub state_key: Option<String>,
    /// The event's real signed parents. Never rewritten, only ordered.
    pub prev_events: Vec<String>,
    /// The signed depth. A tie-break for determinism, never the ordering.
    pub depth: u64,
    /// Synapse's arrival order. Also only ever a tie-break; see [`plan`].
    pub stream_ordering: i64,
    /// Held for somebody else's auth chain, not part of this room's timeline.
    pub outlier: bool,
    /// Synapse refused it. It never entered the room's state.
    pub rejected: bool,
}

/// A room as Synapse holds it.
#[derive(Clone, Debug)]
pub struct SourceRoom {
    pub room_id: String,
    pub events: Vec<SourceEvent>,
    /// Synapse's `current_state_events`: what it says the room's state is.
    pub current_state: StateMap,
    /// State after the root of the imported subgraph, from Synapse's state
    /// groups.
    ///
    /// Needed only when the import starts at a backfill horizon rather than at
    /// `m.room.create` — a room Synapse joined over federation has no history
    /// before the join, so there is nothing to fold forward from. Supplying it
    /// makes the import possible and the divergence check *weaker*, because
    /// the state it ends up comparing was seeded from the same source it is
    /// compared against. [`Outcome::seeded_from_source`] records which of the
    /// two happened, so a report can say so.
    pub state_after_root: Option<StateMap>,
    /// Synapse's forward extremities (`event_forward_extremities`): the
    /// events whose resolved states make the room's current state. Empty
    /// means "the planned events no other planned event names as a parent".
    pub forward_extremities: Vec<String>,
}

/// An event the plan leaves out, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Excluded {
    /// Held only to check somebody's auth chain.
    Outlier(String),
    /// Synapse refused it; it never entered the room's state.
    Rejected(String),
    /// A non-root event naming a parent the import does not have.
    ///
    /// Appending it would mean either rewriting its signed `prev_events` —
    /// which destroys the signature this whole exercise exists to preserve —
    /// or claiming a parent we cannot show. Neither is available, so it is
    /// left out and said so.
    Frayed { event_id: String, missing: String },
    /// Reachable only through an event that was itself left out.
    Orphaned { event_id: String, behind: String },
}

impl Excluded {
    #[must_use]
    pub fn event_id(&self) -> &str {
        match self {
            Self::Outlier(id) | Self::Rejected(id) => id,
            Self::Frayed { event_id, .. } | Self::Orphaned { event_id, .. } => event_id,
        }
    }
}

/// One event in the order the log will be offered it.
#[derive(Clone, Debug)]
pub struct Step {
    pub input: EventInput,
    pub depth: u64,
    /// The first step, which the log is seeded with rather than appended to.
    pub seed: bool,
    /// The event names a parent the import does not hold. Only
    /// [`plan_resolving`] keeps such an event; its state comes from the
    /// source rather than from folding parents.
    pub gap: bool,
    /// The last step, seeded with the source's current state; see
    /// [`mark_head_from_source`].
    pub head: bool,
}

/// An ordering the log can replay, plus everything it left behind.
#[derive(Clone, Debug)]
pub struct Plan {
    pub room_id: String,
    pub steps: Vec<Step>,
    pub excluded: Vec<Excluded>,
    /// True when the root is a backfill horizon rather than `m.room.create`.
    pub seeded_from_source: bool,
}

/// Why a room could not be ordered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// Nothing to import: every event was an outlier or rejected.
    NoEvents { room_id: String },
    /// The imported subgraph has more than one root.
    ///
    /// Only one can seed the log — [`RoomLog::append_seeded`] makes its event
    /// the sole forward extremity — and the others would then name parents the
    /// log does not hold. This is refused rather than resolved by dropping the
    /// smaller roots: silently importing part of a room is exactly the partial
    /// cutover #20 says must never happen, and it looks like a success.
    MultipleRoots { room_id: String, roots: Vec<String> },
    /// A cycle. Not reachable through honest Matrix events, which are
    /// hash-linked, but reachable through a corrupt or hand-edited database,
    /// and the wrong outcome is an importer that never returns.
    Cycle {
        room_id: String,
        events: Vec<String>,
    },
    /// The root is a horizon and the caller supplied no state for it.
    NoRootState { room_id: String, root: String },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEvents { room_id } => write!(
                formatter,
                "{room_id}: nothing to import; every event is an outlier or was rejected"
            ),
            Self::MultipleRoots { room_id, roots } => write!(
                formatter,
                "{room_id}: the history to import has {} disconnected starting points \
                 ({}); only one can seed a log, and importing part of a room is worse \
                 than importing none of it",
                roots.len(),
                roots.join(", ")
            ),
            Self::Cycle { room_id, events } => write!(
                formatter,
                "{room_id}: {} events form a cycle through their prev_events \
                 (from {}); this cannot come from signed Matrix events, so the \
                 source database is damaged",
                events.len(),
                events.first().map_or("?", String::as_str)
            ),
            Self::NoRootState { room_id, root } => write!(
                formatter,
                "{room_id}: the history starts at {root} rather than m.room.create, \
                 so there is nothing to fold state forward from; supply the state \
                 Synapse holds for that event"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// A state slot the two servers do not agree on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Divergence {
    pub key: StateKey,
    /// What Spindle folded forward. `None` when Spindle has no such slot.
    pub spindle: Option<String>,
    /// What Synapse says. `None` when Synapse has no such slot.
    pub synapse: Option<String>,
}

/// What a replay produced.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub room_id: String,
    pub imported: usize,
    pub excluded: Vec<Excluded>,
    /// Empty is the exit criterion: zero room-state divergence.
    pub divergence: Vec<Divergence>,
    /// The state comparison was seeded from the source it is compared against.
    ///
    /// A clean import folds every state event forward from `m.room.create`, so
    /// agreeing with Synapse at the end means the two independently reached the
    /// same answer. An import starting at a backfill horizon begins from
    /// Synapse's own state, and agreement then only covers the events after
    /// that point. Both are legitimate imports; they are not equally strong
    /// evidence, and a report that does not distinguish them overstates one.
    pub seeded_from_source: bool,
}

impl Outcome {
    /// Whether this import may be cut over to.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.divergence.is_empty()
    }
}

/// Why a replay failed.
#[derive(Clone, Debug)]
pub enum ImportError {
    Plan(PlanError),
    /// The log refused an event the plan offered it.
    Append {
        room_id: String,
        event_id: String,
        error: AppendError,
    },
    /// The log accepted everything and then had no state for its own head.
    NoHeadState {
        room_id: String,
    },
    /// An event needed the source's state and the source had none.
    NoSourceState {
        room_id: String,
        event_id: String,
        why: String,
    },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "{error}"),
            Self::Append {
                room_id,
                event_id,
                error,
            } => write!(
                formatter,
                "{room_id}: the log refused {event_id}: {error:?}"
            ),
            Self::NoHeadState { room_id } => {
                write!(formatter, "{room_id}: no state for the log's own head")
            }
            Self::NoSourceState {
                room_id,
                event_id,
                why,
            } => write!(
                formatter,
                "{room_id}: {event_id} needs Synapse's state and there is none: {why}"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<PlanError> for ImportError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

fn state_key_of(event: &SourceEvent) -> Option<StateKey> {
    event
        .state_key
        .as_ref()
        .map(|key| StateKey::new(event.event_type.clone(), key.clone()))
}

/// An event waiting in the topological sort, ordered by its tie-break.
///
/// [`BinaryHeap`] is a max-heap and the smallest tie-break has to come out
/// first, so the comparison is written the other way round rather than wrapped
/// in `Reverse` -- the reversal is the whole reason this type exists, and
/// hiding it behind a wrapper puts it a type parameter away from the reader.
struct Ready<'a>(&'a SourceEvent);

impl Ord for Ready<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            other.0.depth,
            other.0.stream_ordering,
            other.0.event_id.as_str(),
        )
            .cmp(&(
                self.0.depth,
                self.0.stream_ordering,
                self.0.event_id.as_str(),
            ))
    }
}

impl PartialOrd for Ready<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ready<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for Ready<'_> {}

/// Separate the room's timeline from what Synapse keeps beside it.
fn timeline<'a>(
    room: &'a SourceRoom,
    excluded: &mut Vec<Excluded>,
) -> HashMap<&'a str, &'a SourceEvent> {
    let mut included = HashMap::with_capacity(room.events.len());
    for event in &room.events {
        if event.outlier {
            excluded.push(Excluded::Outlier(event.event_id.clone()));
        } else if event.rejected {
            excluded.push(Excluded::Rejected(event.event_id.clone()));
        } else {
            included.insert(event.event_id.as_str(), event);
        }
    }
    included
}

/// Drop what cannot be appended, and return the starting points that remain.
///
/// An event whose parents are all outside the import is a starting point. One
/// whose parents are only *partly* outside cannot be appended at all: the log
/// will refuse a parent it does not hold, and the alternative -- dropping that
/// parent from `prev_events` -- would change the bytes the signature covers.
/// Dropping such an event orphans everything below it, and those in turn.
fn prune_frayed<'a>(
    included: &mut HashMap<&'a str, &'a SourceEvent>,
    excluded: &mut Vec<Excluded>,
) -> Vec<&'a SourceEvent> {
    let mut origins: Vec<&'a SourceEvent> = Vec::new();
    let mut dropped: HashSet<&'a str> = HashSet::new();
    let mut children: HashMap<&'a str, Vec<&'a str>> = HashMap::new();

    for event in included.values() {
        for parent in event
            .prev_events
            .iter()
            .filter(|parent| included.contains_key(parent.as_str()))
        {
            children
                .entry(parent)
                .or_default()
                .push(event.event_id.as_str());
        }
        let known = event
            .prev_events
            .iter()
            .filter(|parent| included.contains_key(parent.as_str()))
            .count();
        if known == 0 {
            origins.push(event);
        } else if known < event.prev_events.len() {
            let missing = event
                .prev_events
                .iter()
                .find(|parent| !included.contains_key(parent.as_str()))
                .cloned()
                .unwrap_or_default();
            dropped.insert(event.event_id.as_str());
            excluded.push(Excluded::Frayed {
                event_id: event.event_id.clone(),
                missing,
            });
        }
    }

    if dropped.is_empty() {
        return origins;
    }

    // Walk the reverse edges once. The previous whole-map fixed-point scan was
    // correct but quadratic for a long history behind one frayed event -- a
    // very ordinary shape in a large federated room with a retention gap.
    let mut first_dropped: Vec<&str> = dropped.iter().copied().collect();
    first_dropped.sort_unstable();
    for descendants in children.values_mut() {
        descendants.sort_unstable();
    }
    let mut pending: VecDeque<&str> = first_dropped.into();
    while let Some(behind) = pending.pop_front() {
        for event_id in children.get(behind).into_iter().flatten().copied() {
            if dropped.insert(event_id) {
                excluded.push(Excluded::Orphaned {
                    event_id: event_id.to_owned(),
                    behind: behind.to_owned(),
                });
                pending.push_back(event_id);
            }
        }
    }

    included.retain(|event_id, _| !dropped.contains(event_id));
    origins.retain(|event| !dropped.contains(event.event_id.as_str()));
    origins
}

/// Kahn's algorithm over `prev_events`, restricted to the import.
///
/// `pending` counts parents inside the import that have not been emitted yet;
/// `children` is the reverse edge set. Both carry the events themselves rather
/// than keys to look up again, so the walk cannot reach for something that is
/// not there. Short of the whole set means a cycle, which the caller reports.
fn toposort(included: &HashMap<&str, &SourceEvent>) -> Vec<Step> {
    let mut pending: HashMap<&str, usize> = HashMap::with_capacity(included.len());
    let mut children: HashMap<&str, Vec<&SourceEvent>> = HashMap::with_capacity(included.len());
    for event in included.values() {
        let parents: Vec<&str> = event
            .prev_events
            .iter()
            .filter(|parent| included.contains_key(parent.as_str()))
            .map(String::as_str)
            .collect();
        pending.insert(event.event_id.as_str(), parents.len());
        for parent in parents {
            children.entry(parent).or_default().push(event);
        }
    }

    let mut ready: BinaryHeap<Ready<'_>> = included
        .values()
        .filter(|event| pending.get(event.event_id.as_str()) == Some(&0))
        .map(|event| Ready(event))
        .collect();

    let mut steps = Vec::with_capacity(included.len());
    while let Some(Ready(event)) = ready.pop() {
        let gap = event
            .prev_events
            .iter()
            .any(|parent| !included.contains_key(parent.as_str()));
        steps.push(Step {
            input: EventInput {
                event_id: EventId::new(event.event_id.clone()),
                prev_events: event
                    .prev_events
                    .iter()
                    .map(|parent| EventId::new(parent.clone()))
                    .collect(),
                state_key: state_key_of(event),
            },
            depth: event.depth,
            seed: false,
            gap,
            head: false,
        });
        for child in children
            .get(event.event_id.as_str())
            .into_iter()
            .flatten()
            .copied()
        {
            if let Some(count) = pending.get_mut(child.event_id.as_str()) {
                *count -= 1;
                if *count == 0 {
                    ready.push(Ready(child));
                }
            }
        }
    }
    steps
}

fn cycle_error(room_id: &str, held: &HashMap<&str, &SourceEvent>, steps: &[Step]) -> PlanError {
    let emitted: HashSet<&str> = steps
        .iter()
        .map(|step| step.input.event_id.as_str())
        .collect();
    let mut events: Vec<String> = held
        .keys()
        .filter(|id| !emitted.contains(*id))
        .map(|id| (*id).to_owned())
        .collect();
    events.sort();
    PlanError::Cycle {
        room_id: room_id.to_owned(),
        events,
    }
}

/// Order a room's events so that every parent precedes its children.
///
/// **Neither ordering Synapse already has is safe to reuse.**
/// `stream_ordering` is arrival order, and a backfilled event arrives long
/// after the children that sent us looking for it. `depth` is closer -- it is
/// defined as one more than the deepest parent -- but it is a *signed field
/// chosen by whoever sent the event*, so a remote server can set it to
/// anything, and a homeserver that never had to trust it for ordering has
/// never had a reason to reject a bad one. Sorting by either produces an
/// import that fails on some rooms and, worse, succeeds on others in the wrong
/// order. So this is a real topological sort over `prev_events`, with
/// `(depth, stream_ordering, event_id)` used only to break ties between events
/// that are genuinely unordered with respect to each other -- which keeps the
/// output deterministic, so two runs over one database produce the same log
/// rather than two logs differing by nothing that matters.
///
/// # Errors
///
/// Returns [`PlanError`] when the room has nothing importable, more than one
/// starting point, a cycle, or a horizon start with no state supplied for it.
pub fn plan(room: &SourceRoom) -> Result<Plan, PlanError> {
    let mut excluded = Vec::new();
    let mut included = timeline(room, &mut excluded);
    let nothing_to_import = || PlanError::NoEvents {
        room_id: room.room_id.clone(),
    };
    if included.is_empty() {
        return Err(nothing_to_import());
    }

    let mut origins = prune_frayed(&mut included, &mut excluded);
    if included.is_empty() {
        return Err(nothing_to_import());
    }

    origins.sort_unstable_by(|left, right| left.event_id.cmp(&right.event_id));
    if origins.len() > 1 {
        return Err(PlanError::MultipleRoots {
            room_id: room.room_id.clone(),
            roots: origins.iter().map(|event| event.event_id.clone()).collect(),
        });
    }
    let Some(origin) = origins.first().copied() else {
        // No starting point and a non-empty set means every event has a parent
        // inside the set, which for a finite set means a cycle.
        return Err(cycle_error(&room.room_id, &included, &[]));
    };

    let seeded_from_source =
        !(origin.event_type == "m.room.create" && origin.prev_events.is_empty());
    if seeded_from_source && room.state_after_root.is_none() {
        return Err(PlanError::NoRootState {
            room_id: room.room_id.clone(),
            root: origin.event_id.clone(),
        });
    }

    let mut steps = toposort(&included);
    if steps.len() != included.len() {
        return Err(cycle_error(&room.room_id, &included, &steps));
    }

    // The first step is the starting point by construction: it is the only
    // event with no pending parents when the heap is built, so nothing can be
    // emitted before it.
    if let Some(first) = steps.first_mut() {
        first.seed = true;
    }
    excluded.sort_by(|left, right| left.event_id().cmp(right.event_id()));

    Ok(Plan {
        room_id: room.room_id.clone(),
        steps,
        excluded,
        seeded_from_source,
    })
}

/// Where an import gets the state a log cannot fold for itself.
///
/// [`replay_resolving`] asks for it, and the full importer answers from
/// Synapse's state groups and the room version's resolver.
pub trait SourceState {
    /// The state after `event_id`, as the source resolved it.
    ///
    /// # Errors
    ///
    /// A description of why the source has no state for the event.
    fn state_after(&mut self, event_id: &str) -> Result<StateMap, String>;

    /// The source's state after `event_id` on the named slots only.
    ///
    /// # Errors
    ///
    /// As [`Self::state_after`].
    fn state_after_keys(
        &mut self,
        event_id: &str,
        keys: &[(String, String)],
    ) -> Result<StateMap, String> {
        let mut state = self.state_after(event_id)?;
        state.retain(|key, _| keys.contains(key));
        Ok(state)
    }

    /// The room version's resolution of `sets` (the states after an event's
    /// parents, or after the room's forward extremities). `None` when this
    /// source has no resolver, and the log's own fold is used instead.
    fn resolve(&mut self, _sets: &[&StateSnapshot]) -> Option<Result<Resolution, String>> {
        None
    }

    /// How the source arrived at the state of `event_id`: from its
    /// parents, or from somewhere else. A source that cannot tell says
    /// [`Continuity::Derived`], and the import trusts the derivation.
    fn continuity(&mut self, _event_id: &str, _parents: &[EventId], _is_state: bool) -> Continuity {
        Continuity::Derived
    }
}

/// How Synapse arrived at an event's state, read from its state groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Continuity {
    /// The state before the event is a parent's state group.
    Derived,
    /// The state before the event is a delta on a parent's group: Synapse
    /// resolved the parents.
    Resolved,
    /// The state before the event is neither: Synapse took it from
    /// elsewhere (a peer's `/state_ids` when the event arrived before its
    /// parents did). The import compares in full.
    Elsewhere,
    /// The group is a full snapshot with no edge, so the derivation cannot
    /// be read from the graph. The import compares in full.
    Unknown,
}

/// What the room version's resolver settled for a set of states.
#[derive(Clone, Debug, Default)]
pub struct Resolution {
    /// Every slot the sets disagreed on.
    pub contested: Vec<StateKey>,
    /// The slots whose resolved value differs from the first set's: the
    /// value, or `None` when the resolved state has no such slot.
    pub slots: Vec<(StateKey, Option<String>)>,
}

/// The state an event is written with, when it is not the log's own fold.
#[derive(Clone, Debug)]
pub struct Settled {
    pub state: StateSnapshot,
    /// The slots to persist beside the seed (bodies to store, memberships
    /// to index): the full state for Synapse's state, only the changed
    /// slots for a resolver's answer.
    pub slots: StateMap,
    pub reason: String,
}

/// The room version's resolver against Synapse at one fork.
#[derive(Clone, Debug)]
pub struct ForkCheck {
    pub event_id: String,
    pub contested: usize,
    /// Slots where the resolver and Synapse disagree. Empty: they agree.
    pub disagreements: Vec<Divergence>,
}

/// Order a room for an import that takes the source's state where Spindle
/// cannot derive it.
///
/// [`plan`] refuses a room with more than one starting point and leaves out
/// every event that names a parent the import does not hold. Both are gaps
/// in the history Synapse retained: a backfill that stopped, or events
/// fetched one at a time. Synapse still resolved the state at each of those
/// events, and it keeps that state in its state groups. This plan keeps
/// every such event and marks it `gap`, and the replay seeds it with the
/// source's state instead of refusing it. Only outliers and rejected events
/// are left out.
///
/// The seed is `m.room.create` when the import holds it, and otherwise the
/// earliest starting point, which needs `state_after_root` as in [`plan`].
///
/// # Errors
///
/// Returns [`PlanError`] when the room has nothing importable, a cycle, or a
/// horizon start with no state supplied for it.
pub fn plan_resolving(room: &SourceRoom) -> Result<Plan, PlanError> {
    let mut excluded = Vec::new();
    let included = timeline(room, &mut excluded);
    if included.is_empty() {
        return Err(PlanError::NoEvents {
            room_id: room.room_id.clone(),
        });
    }
    let origin = included
        .values()
        .filter(|event| {
            !event
                .prev_events
                .iter()
                .any(|parent| included.contains_key(parent.as_str()))
        })
        .min_by_key(|event| {
            (
                !(event.event_type == "m.room.create" && event.prev_events.is_empty()),
                event.depth,
                event.stream_ordering,
                event.event_id.as_str(),
            )
        })
        .copied();
    let Some(origin) = origin else {
        return Err(cycle_error(&room.room_id, &included, &[]));
    };
    let seeded_from_source =
        !(origin.event_type == "m.room.create" && origin.prev_events.is_empty());
    if seeded_from_source && room.state_after_root.is_none() {
        return Err(PlanError::NoRootState {
            room_id: room.room_id.clone(),
            root: origin.event_id.clone(),
        });
    }

    let mut steps = toposort(&included);
    if steps.len() != included.len() {
        return Err(cycle_error(&room.room_id, &included, &steps));
    }
    // The seed has no parent inside the import, so moving it to the front
    // keeps every parent before its children.
    if let Some(index) = steps
        .iter()
        .position(|step| step.input.event_id.as_str() == origin.event_id)
    {
        let mut seed = steps.remove(index);
        seed.seed = true;
        seed.gap = false;
        steps.insert(0, seed);
    }
    excluded.sort_by(|left, right| left.event_id().cmp(right.event_id()));
    Ok(Plan {
        room_id: room.room_id.clone(),
        steps,
        excluded,
        seeded_from_source,
    })
}

/// Why a head step takes the source's current state.
pub const HEAD_REASON: &str =
    "head: Synapse's current state, resolved over its forward extremities";

/// Why a step took the room version's resolution of its parents.
pub const RESOLVED_REASON: &str = "resolved: the room version's resolver over the parents' states";

/// Why the head took the room version's resolution of the extremities.
pub const HEAD_RESOLVED_REASON: &str =
    "head: the room version's resolver over the forward extremities";

/// Why a step took Synapse's state where the resolver disagreed.
pub const DISAGREED_REASON: &str =
    "resolver disagrees with Synapse: Synapse's state taken on the disagreeing slots";

/// Why a step took Synapse's state where Synapse did not derive it from
/// the event's parents.
pub const ELSEWHERE_REASON: &str = "Synapse's state here is not derived from the event's parents (taken from a peer): Synapse's state";

/// Why a step names a parent the import does not hold.
pub const GAP_REASON: &str = "a parent is outside the retained history";

/// Make the last step of a plan take the source's current state.
///
/// Spindle's current state is the state after the last entry of its log.
/// Synapse's is the resolution of every forward extremity. Without a
/// resolver, the import seeds the last event with Synapse's current state
/// when the two differ, and says so in the report.
pub fn mark_head_from_source(step: &mut Step) {
    step.head = true;
}

/// Whether an append the log refused can take a supplied state instead.
///
/// A contested fork needs the Matrix state resolver, which Spindle's log
/// does not carry (SPEC §9.2); a parent outside the import or outside the
/// resident window has no state to fold.
#[must_use]
pub fn takes_source_state(error: &AppendError) -> bool {
    matches!(
        error,
        AppendError::NeedsStateResolution { .. }
            | AppendError::StateNotResident { .. }
            | AppendError::UnknownPredecessor(_)
    )
}

/// What [`replay_resolving`] produced.
#[derive(Clone, Debug)]
pub struct ResolvedOutcome {
    pub outcome: Outcome,
    /// Events written with a supplied state rather than the log's own
    /// fold, and why.
    pub from_source: Vec<(String, String)>,
    /// The state each of those events is written with, for the write that
    /// follows (only when the source has a resolver).
    pub settled: HashMap<String, Settled>,
    /// Every fork the resolver settled, checked against Synapse.
    pub forks: Vec<ForkCheck>,
    /// How many replay passes it took until the log's fold agreed with the
    /// derived state on every event it was left to fold.
    pub passes: usize,
    /// Events whose derived state was compared in full with Synapse's,
    /// because Synapse's state graph did not show it derived from the
    /// parents.
    pub full_checks: usize,
}

/// [`replay`] over [`plan_resolving`]: the import derives each event's
/// state, and the final state is compared with the source's current state.
///
/// With a resolver ([`SourceState::resolve`]) an event whose parents'
/// states differ takes the room version's resolution of them, checked
/// against Synapse's state for the same event, and the room's head takes
/// the resolution of Synapse's forward extremities. The log folds every
/// other event; where its fold is not the derived state, or it refuses the
/// fork, the event is written with the derived state instead. Only an
/// event with a parent outside the retained history takes Synapse's state,
/// because nothing else knows the state there.
///
/// Without a resolver the log folds what it can and Synapse's state fills
/// the rest.
///
/// # Errors
///
/// Returns [`ImportError`] when the room cannot be ordered, the log refuses
/// an event for a reason the source cannot answer, or the source has no
/// state for an event that needs it.
pub fn replay_resolving(
    room: &SourceRoom,
    source: &mut dyn SourceState,
    head_from_source: bool,
) -> Result<ResolvedOutcome, ImportError> {
    let mut plan = plan_resolving(room)?;
    if head_from_source && let Some(last) = plan.steps.last_mut() {
        mark_head_from_source(last);
    }
    let mut marks: HashSet<String> = HashSet::new();
    let mut passes = 0;
    loop {
        passes += 1;
        let (mut result, new_marks) = replay_pass(room, &plan, source, &marks)?;
        // A fold that disagreed downstream of a fold that was already wrong
        // may be a knock-on effect, so a pass is repeated with every mark so
        // far until no new one appears.
        if new_marks.is_empty() {
            result.passes = passes;
            return Ok(result);
        }
        if passes >= 8 {
            return Err(ImportError::NoSourceState {
                room_id: room.room_id.clone(),
                event_id: new_marks.into_iter().next().unwrap_or_default(),
                why: "the log's fold did not settle in 8 passes".to_owned(),
            });
        }
        marks.extend(new_marks);
    }
}

/// The derived state for one step, before it is appended.
struct Want {
    state: Option<StateSnapshot>,
    /// Set when the state is not what the log would fold.
    reason: Option<&'static str>,
    slots: Option<StateMap>,
}

fn key_pair(key: &StateKey) -> (String, String) {
    (
        key.event_type().as_str().to_owned(),
        key.state_key().to_owned(),
    )
}

/// One pass of [`replay_resolving`]. `marks` are the events to write with
/// the derived state; the second value is the events the log folded
/// wrongly (or refused) in this pass.
#[allow(clippy::too_many_lines)]
fn replay_pass(
    room: &SourceRoom,
    plan: &Plan,
    source: &mut dyn SourceState,
    marks: &HashSet<String>,
) -> Result<(ResolvedOutcome, HashSet<String>), ImportError> {
    let room_id = room.room_id.as_str();
    let mut log = RoomLog::new();
    let mut head: Option<EventId> = None;
    let mut from_source = Vec::new();
    let mut settled: HashMap<String, Settled> = HashMap::new();
    let mut forks = Vec::new();
    let mut new_marks = HashSet::new();
    let refused = |event_id: &str, error: AppendError| ImportError::Append {
        room_id: room_id.to_owned(),
        event_id: event_id.to_owned(),
        error,
    };
    let no_state = |event_id: &str, why: String| ImportError::NoSourceState {
        room_id: room_id.to_owned(),
        event_id: event_id.to_owned(),
        why,
    };

    // The state after each event, derived independently of the log, kept
    // while a later step still names the event as a parent, or while it is
    // a forward extremity (which the head resolves).
    let index: HashMap<&str, usize> = plan
        .steps
        .iter()
        .enumerate()
        .map(|(position, step)| (step.input.event_id.as_str(), position))
        .collect();
    let mut last_use: HashMap<&str, usize> = HashMap::new();
    for (position, step) in plan.steps.iter().enumerate() {
        for parent in &step.input.prev_events {
            if index.contains_key(parent.as_str()) {
                let slot = last_use.entry(parent.as_str()).or_insert(position);
                *slot = (*slot).max(position);
            }
        }
    }
    let extremities: Vec<&str> = if room.forward_extremities.is_empty() {
        plan.steps
            .iter()
            .map(|step| step.input.event_id.as_str())
            .filter(|id| !last_use.contains_key(id))
            .collect()
    } else {
        room.forward_extremities
            .iter()
            .map(String::as_str)
            .filter(|id| index.contains_key(id))
            .collect()
    };
    let keep: HashSet<&str> = extremities.iter().copied().collect();
    let mut derived: HashMap<&str, StateSnapshot> = HashMap::new();
    // The state after the step before, which a seed shares structure with.
    let mut previous: Option<StateSnapshot> = None;
    let mut resolver_present = true;
    let mut full_checks = 0;
    let last_position = plan.steps.len().saturating_sub(1);

    for (position, step) in plan.steps.iter().enumerate() {
        let event_id = step.input.event_id.as_str();
        let apply_own = |state: StateSnapshot| match step.input.state_key.clone() {
            Some(key) => state.apply(key, event_id.to_owned()),
            None => state,
        };

        // 1. The state this event should have, derived where possible.
        let mut want = if step.seed {
            Want {
                state: Some(match &room.state_after_root {
                    Some(map) => snapshot_from(map),
                    None => apply_own(StateSnapshot::new()),
                }),
                reason: None,
                slots: None,
            }
        } else if step.gap {
            let map = source
                .state_after(event_id)
                .map_err(|why| no_state(event_id, why))?;
            let base = step
                .input
                .prev_events
                .iter()
                .find_map(|parent| derived.get(parent.as_str()))
                .or(previous.as_ref());
            let (state, slots) = snapshot_over(base, &map);
            Want {
                state: Some(state),
                reason: Some(GAP_REASON),
                slots: Some(slots),
            }
        } else {
            let parents: Vec<&StateSnapshot> = step
                .input
                .prev_events
                .iter()
                .filter_map(|parent| derived.get(parent.as_str()))
                .collect();
            let first = parents.first().copied();
            match first {
                _ if parents.len() != step.input.prev_events.len() => Want {
                    state: None,
                    reason: None,
                    slots: None,
                },
                None => Want {
                    state: None,
                    reason: None,
                    slots: None,
                },
                Some(first) if parents.iter().all(|state| state.root() == first.root()) => Want {
                    state: Some(apply_own(first.clone())),
                    reason: None,
                    slots: None,
                },
                Some(first) => match source.resolve(&parents) {
                    None => {
                        resolver_present = false;
                        Want {
                            state: None,
                            reason: None,
                            slots: None,
                        }
                    }
                    Some(Err(why)) => {
                        return Err(no_state(event_id, format!("resolver: {why}")));
                    }
                    Some(Ok(resolution)) => {
                        if std::env::var("SPINDLE_IMPORT_DEBUG_EVENT")
                            .is_ok_and(|id| id == event_id)
                        {
                            debug_fork(source, step, &parents, &resolution);
                        }
                        let mut state = apply_own(apply_slots(first, &resolution.slots));
                        // Check the resolver against Synapse on every slot
                        // the parents contested, and the event's own.
                        let mut keys: Vec<(String, String)> =
                            resolution.contested.iter().map(key_pair).collect();
                        if let Some(own) = &step.input.state_key {
                            keys.push(key_pair(own));
                        }
                        keys.sort_unstable();
                        keys.dedup();
                        let synapse = source
                            .state_after_keys(event_id, &keys)
                            .map_err(|why| no_state(event_id, why))?;
                        let disagreements: Vec<Divergence> = keys
                            .iter()
                            .filter_map(|slot| {
                                let key = StateKey::new(slot.0.clone(), slot.1.clone());
                                let ours = state.get(&key).map(str::to_owned);
                                let theirs = synapse.get(slot).cloned();
                                (ours != theirs).then_some(Divergence {
                                    key,
                                    spindle: ours,
                                    synapse: theirs,
                                })
                            })
                            .collect();
                        let mut reason = RESOLVED_REASON;
                        if !disagreements.is_empty() {
                            // Synapse's answer is what the room's peers and
                            // clients hold; the disagreement is reported.
                            let fixes: Vec<(StateKey, Option<String>)> = disagreements
                                .iter()
                                .map(|slot| (slot.key.clone(), slot.synapse.clone()))
                                .collect();
                            state = apply_slots(&state, &fixes);
                            reason = DISAGREED_REASON;
                        }
                        let mut changed = StateMap::new();
                        for (key, _, value) in first.diff(&state) {
                            if let Some(value) = value {
                                changed.insert(key_pair(key), value.to_owned());
                            }
                        }
                        forks.push(ForkCheck {
                            event_id: event_id.to_owned(),
                            contested: resolution.contested.len(),
                            disagreements,
                        });
                        Want {
                            state: Some(state),
                            reason: Some(reason),
                            slots: Some(changed),
                        }
                    }
                },
            }
        };

        // 1b. Where Synapse's state graph does not show this event's state
        // derived from its parents, compare in full; where they differ,
        // Synapse's state is the one the room's peers hold.
        if !step.seed
            && !step.gap
            && let Some(state) = &want.state
        {
            let continuity = source.continuity(
                event_id,
                &step.input.prev_events,
                step.input.state_key.is_some(),
            );
            if matches!(continuity, Continuity::Elsewhere | Continuity::Unknown) {
                full_checks += 1;
                let map = source
                    .state_after(event_id)
                    .map_err(|why| no_state(event_id, why))?;
                if !same_state(state, &map) {
                    let (state, slots) = snapshot_over(Some(state), &map);
                    want = Want {
                        state: Some(state),
                        reason: Some(ELSEWHERE_REASON),
                        slots: Some(slots),
                    };
                }
            }
        }

        // 2. The head: the resolution of every forward extremity.
        if position == last_position && !step.seed && resolver_present {
            let mut sets: Vec<&StateSnapshot> = Vec::new();
            for extremity in &extremities {
                if *extremity == event_id {
                    if let Some(state) = &want.state {
                        sets.push(state);
                    }
                } else if let Some(state) = derived.get(extremity) {
                    sets.push(state);
                }
            }
            let head_state = match sets.as_slice() {
                [] => None,
                [only] => Some((*only).clone()),
                [first, ..] => match source.resolve(&sets) {
                    Some(Ok(resolution)) => Some(apply_slots(first, &resolution.slots)),
                    Some(Err(why)) => {
                        return Err(no_state(event_id, format!("resolver at the head: {why}")));
                    }
                    None => None,
                },
            };
            if let Some(head_state) = head_state
                && want
                    .state
                    .as_ref()
                    .is_none_or(|natural| natural.root() != head_state.root())
            {
                let mut slots = StateMap::new();
                let base = want
                    .state
                    .clone()
                    .or_else(|| previous.clone())
                    .unwrap_or_default();
                for (key, _, value) in base.diff(&head_state) {
                    if let Some(value) = value {
                        slots.insert(key_pair(key), value.to_owned());
                    }
                }
                want = Want {
                    state: Some(head_state),
                    reason: Some(HEAD_RESOLVED_REASON),
                    slots: Some(slots),
                };
            }
        }

        // 3. Append: seeded where the state is supplied, folded otherwise.
        let seed_with = |log: &mut RoomLog, state: StateSnapshot| {
            log.append_seeded(step.input.clone(), state, step.depth)
                .map(|entry| entry.event_id.clone())
                .map_err(|error| refused(event_id, error))
        };
        let seeded = !step.seed
            && want.state.is_some()
            && (want.reason.is_some_and(|reason| reason != RESOLVED_REASON)
                || marks.contains(event_id));
        let entry = if step.seed {
            seed_with(&mut log, want.state.clone().unwrap_or_default())?
        } else if seeded {
            let state = want.state.clone().unwrap_or_default();
            let reason = want.reason.unwrap_or(RESOLVED_REASON);
            from_source.push((event_id.to_owned(), reason.to_owned()));
            settled.insert(
                event_id.to_owned(),
                Settled {
                    state: state.clone(),
                    slots: want.slots.clone().unwrap_or_default(),
                    reason: reason.to_owned(),
                },
            );
            seed_with(&mut log, state)?
        } else if let Some(state) = want.state.clone() {
            // The log may fold this event itself; check that it reaches the
            // derived state, and mark it to be seeded when it does not.
            match log.append_remote(step.input.clone()) {
                Ok(entry) => {
                    let id = entry.event_id.clone();
                    if log
                        .state_after_event(&id)
                        .is_none_or(|folded| folded.root() != state.root())
                    {
                        new_marks.insert(event_id.to_owned());
                    }
                    id
                }
                Err(error) if takes_source_state(&error) => {
                    new_marks.insert(event_id.to_owned());
                    seed_with(&mut log, state)?
                }
                Err(error) => return Err(refused(event_id, error)),
            }
        } else if step.head {
            // No resolver: Synapse's current state.
            from_source.push((event_id.to_owned(), HEAD_REASON.to_owned()));
            seed_with(&mut log, snapshot_from(&room.current_state))?
        } else {
            match log.append_remote(step.input.clone()) {
                Ok(entry) => entry.event_id.clone(),
                Err(error) if takes_source_state(&error) => {
                    let map = source
                        .state_after(event_id)
                        .map_err(|why| no_state(event_id, why))?;
                    from_source.push((event_id.to_owned(), format!("{error:?}")));
                    seed_with(&mut log, snapshot_from(&map))?
                }
                Err(error) => return Err(refused(event_id, error)),
            }
        };

        // 4. Keep the derived state while it is still needed.
        let actual = match want.state {
            Some(state) => Some(state),
            None => log.state_after_event(&entry).cloned(),
        };
        if let Some(state) = &actual
            && (last_use.contains_key(event_id) || keep.contains(event_id))
        {
            derived.insert(event_id, state.clone());
        }
        previous = actual;
        for parent in &step.input.prev_events {
            let parent = parent.as_str();
            if last_use.get(parent) == Some(&position) && !keep.contains(parent) {
                derived.remove(parent);
            }
        }
        head = Some(entry);
    }

    let head = head.ok_or_else(|| ImportError::NoHeadState {
        room_id: room_id.to_owned(),
    })?;
    let state = log
        .state_after_event(&head)
        .ok_or_else(|| ImportError::NoHeadState {
            room_id: room_id.to_owned(),
        })?;
    Ok((
        ResolvedOutcome {
            outcome: Outcome {
                room_id: room_id.to_owned(),
                imported: plan.steps.len(),
                divergence: compare(state, &room.current_state),
                excluded: plan.excluded.clone(),
                seeded_from_source: plan.seeded_from_source,
            },
            from_source,
            settled,
            forks,
            passes: 0,
            full_checks,
        },
        new_marks,
    ))
}

/// Print, for one fork, how each parent's derived state differs from the
/// source's state for that parent, and what the resolver contested. Set
/// `SPINDLE_IMPORT_DEBUG_EVENT` to the event ID to investigate a
/// disagreement.
fn debug_fork(
    source: &mut dyn SourceState,
    step: &Step,
    parents: &[&StateSnapshot],
    resolution: &Resolution,
) {
    eprintln!(
        "debug {}: contested {:?}",
        step.input.event_id.as_str(),
        resolution
            .contested
            .iter()
            .map(|key| format!("{}|{}", key.event_type().as_str(), key.state_key()))
            .collect::<Vec<_>>()
    );
    for (parent, state) in step.input.prev_events.iter().zip(parents) {
        match source.state_after(parent.as_str()) {
            Ok(map) => {
                let theirs = snapshot_from(&map);
                let diff = state.diff(&theirs);
                eprintln!(
                    "debug   parent {}: {} slots differ from the source",
                    parent.as_str(),
                    diff.len()
                );
                for (key, ours, theirs) in diff.iter().take(10) {
                    eprintln!(
                        "debug     {}|{} ours={ours:?} source={theirs:?}",
                        key.event_type().as_str(),
                        key.state_key()
                    );
                }
            }
            Err(why) => eprintln!("debug   parent {}: no source state: {why}", parent.as_str()),
        }
    }
    if let Some(Ok(theirs)) = {
        let maps: Vec<StateSnapshot> = step
            .input
            .prev_events
            .iter()
            .filter_map(|parent| source.state_after(parent.as_str()).ok())
            .map(|map| snapshot_from(&map))
            .collect();
        let refs: Vec<&StateSnapshot> = maps.iter().collect();
        source.resolve(&refs)
    } {
        eprintln!(
            "debug   resolver over the source's parent states changes {:?}",
            theirs
                .slots
                .iter()
                .map(|(key, value)| format!(
                    "{}|{} -> {value:?}",
                    key.event_type().as_str(),
                    key.state_key()
                ))
                .collect::<Vec<_>>()
        );
    }
}

/// `map` as a snapshot that shares structure with `base`, and the slots
/// where it differs from `base` (the ones a seed has to persist).
///
/// Building each seed's state from nothing gave every gap in a room of
/// tens of thousands of members a trie of its own, and the import held
/// all of them.
fn snapshot_over(base: Option<&StateSnapshot>, map: &StateMap) -> (StateSnapshot, StateMap) {
    let Some(base) = base else {
        return (snapshot_from(map), map.clone());
    };
    let mut changed = StateMap::new();
    let mut added = 0_usize;
    for ((kind, state_key), value) in map {
        match base.get(&StateKey::new(kind.clone(), state_key.clone())) {
            Some(held) if held == value => {}
            Some(_) => {
                changed.insert((kind.clone(), state_key.clone()), value.clone());
            }
            None => {
                added += 1;
                changed.insert((kind.clone(), state_key.clone()), value.clone());
            }
        }
    }
    let mut state = base.clone();
    if base.len() + added != map.len() {
        // Drop missing slots along their trie paths, retaining all shared
        // nodes. Rebuilding each seed retained a full trie at every gap.
        let mut missing = Vec::new();
        base.for_each(|key, _| {
            if !map.contains_key(&key_pair(key)) {
                missing.push(key.clone());
            }
        });
        for key in missing {
            state = state.remove(&key);
        }
    }
    for ((kind, state_key), value) in &changed {
        state = state.apply(
            StateKey::new(kind.clone(), state_key.clone()),
            value.clone(),
        );
    }
    (state, changed)
}

/// Whether a snapshot holds exactly `map`.
fn same_state(state: &StateSnapshot, map: &StateMap) -> bool {
    state.len() == map.len()
        && map.iter().all(|((kind, key), value)| {
            state.get(&StateKey::new(kind.clone(), key.clone())) == Some(value.as_str())
        })
}

/// `state` with `slots` applied; a `None` value removes the slot.
#[must_use]
pub fn apply_slots(state: &StateSnapshot, slots: &[(StateKey, Option<String>)]) -> StateSnapshot {
    let mut next = state.clone();
    for (key, value) in slots {
        next = match value {
            Some(value) => next.apply(key.clone(), value.clone()),
            None => next.remove(key),
        };
    }
    next
}

pub(crate) fn snapshot_from(map: &StateMap) -> StateSnapshot {
    let mut snapshot = StateSnapshot::new();
    for ((event_type, state_key), event_id) in map {
        snapshot = snapshot.apply(
            StateKey::new(event_type.clone(), state_key.clone()),
            event_id.clone(),
        );
    }
    snapshot
}

/// Why a validated rehearsal could not be persisted.
#[cfg(feature = "synapse-import")]
#[derive(Debug)]
pub enum PersistError {
    Replay(ImportError),
    Divergent { room_id: String, slots: usize },
    MissingBody(String),
    BodyMismatch(String),
    Room(crate::rooms::RoomError),
}

#[cfg(feature = "synapse-import")]
impl std::fmt::Display for PersistError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay(error) => write!(formatter, "{error}"),
            Self::Divergent { room_id, slots } => {
                write!(formatter, "{room_id}: {slots} state slots diverge")
            }
            Self::MissingBody(event_id) => write!(formatter, "missing JSON body for {event_id}"),
            Self::BodyMismatch(event_id) => {
                write!(
                    formatter,
                    "Synapse metadata and JSON disagree for {event_id}"
                )
            }
            Self::Room(error) => write!(formatter, "persisting rehearsal: {error}"),
        }
    }
}

#[cfg(feature = "synapse-import")]
impl std::error::Error for PersistError {}

/// Validate every source row, then persist one room into an isolated store.
///
/// This is intentionally a rehearsal path, not yet the production cutover
/// writer: storage failures can leave a prefix behind until resumable room
/// checkpoints land. Call it only with an empty disposable store.
///
/// # Errors
///
/// Returns [`PersistError`] if replay diverges, source JSON disagrees with
/// normalized metadata, or the target store cannot persist the validated log.
#[cfg(feature = "synapse-import")]
pub fn persist_rehearsal(
    rooms: &crate::rooms::Rooms,
    source: &SourceRoom,
    bodies: &BTreeMap<String, serde_json::Value>,
) -> Result<Outcome, PersistError> {
    let outcome = replay(source).map_err(PersistError::Replay)?;
    if !outcome.clean() {
        return Err(PersistError::Divergent {
            room_id: source.room_id.clone(),
            slots: outcome.divergence.len(),
        });
    }
    let plan = plan(source).map_err(|error| PersistError::Replay(error.into()))?;
    let events: HashMap<&str, &SourceEvent> = source
        .events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect();
    for step in &plan.steps {
        let event_id = step.input.event_id.as_str();
        let body = bodies
            .get(event_id)
            .ok_or_else(|| PersistError::MissingBody(event_id.to_owned()))?;
        let Some(event) = events.get(event_id) else {
            return Err(PersistError::BodyMismatch(event_id.to_owned()));
        };
        check_body(event, body)?;
    }

    rooms
        .persist_synapse_plan(&plan, source.state_after_root.as_ref(), bodies)
        .map_err(PersistError::Room)?;
    Ok(outcome)
}

/// Event bodies and resolved state from the source, for the room writer.
#[cfg(feature = "synapse-import")]
pub trait SynapseSource: SourceState {
    /// The signed JSON of `event_id`, as the source stored it.
    fn body(&mut self, event_id: &str) -> Option<serde_json::Value>;

    /// The state the replay settled for `event_id`, when it is to be
    /// written with a supplied state rather than the log's fold.
    fn settled(&mut self, _event_id: &str) -> Option<Settled> {
        None
    }
}

/// A source held in memory: what a test, or a caller that already read
/// everything, hands the room writer.
#[cfg(feature = "synapse-import")]
#[derive(Default)]
pub struct MemorySource {
    pub bodies: HashMap<String, serde_json::Value>,
    pub states: HashMap<String, StateMap>,
}

#[cfg(feature = "synapse-import")]
impl SourceState for MemorySource {
    fn state_after(&mut self, event_id: &str) -> Result<StateMap, String> {
        self.states
            .get(event_id)
            .cloned()
            .ok_or_else(|| format!("no state for {event_id}"))
    }
}

#[cfg(feature = "synapse-import")]
impl SynapseSource for MemorySource {
    fn body(&mut self, event_id: &str) -> Option<serde_json::Value> {
        self.bodies.get(event_id).cloned()
    }
}

/// Append one chunk of a validated plan to the target, resuming if the room
/// already holds some of it. See `Rooms::persist_synapse_steps`.
///
/// Returns how many events were appended, and which took the source's state.
///
/// # Errors
///
/// Returns [`PersistError::Room`] if a body is missing or the write fails.
#[cfg(feature = "synapse-import")]
pub fn persist_chunk(
    rooms: &crate::rooms::Rooms,
    room_id: &str,
    steps: &[Step],
    state_after_root: Option<&StateMap>,
    source: &mut dyn SynapseSource,
) -> Result<(usize, Vec<(String, String)>), PersistError> {
    rooms
        .persist_synapse_steps(room_id, steps, state_after_root, source)
        .map_err(PersistError::Room)
}

/// Apply a room's imported redactions and sync it. See
/// `Rooms::finish_synapse_room`.
///
/// # Errors
///
/// Returns [`PersistError::Room`] if a target cannot be rewritten.
#[cfg(feature = "synapse-import")]
pub fn finish_room(
    rooms: &crate::rooms::Rooms,
    room_id: &str,
    redactions: &[(String, String)],
) -> Result<usize, PersistError> {
    rooms
        .finish_synapse_room(room_id, redactions)
        .map_err(PersistError::Room)
}

/// Check that an event's signed JSON says what Synapse's normalized rows say.
///
/// The plan is built from `events` and `event_edges`; the log stores the
/// JSON. If the two disagree about the type, the state key or the parents,
/// the order the plan chose is not the order the stored events describe.
///
/// # Errors
///
/// Returns [`PersistError::BodyMismatch`] when they disagree.
#[cfg(feature = "synapse-import")]
pub fn check_body(event: &SourceEvent, body: &serde_json::Value) -> Result<(), PersistError> {
    let body_state_key = body.get("state_key").and_then(serde_json::Value::as_str);
    // Compared as sets: `event_edges` has no order column, so the rows come
    // back in whatever order the database chooses.
    let mut body_parents: Vec<&str> = body
        .get("prev_events")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parent| {
            // Room versions 1 and 2 name a parent as `[event_id, hashes]`.
            parent
                .as_str()
                .or_else(|| parent.get(0).and_then(serde_json::Value::as_str))
        })
        .collect();
    body_parents.sort_unstable();
    let mut row_parents: Vec<&str> = event.prev_events.iter().map(String::as_str).collect();
    row_parents.sort_unstable();
    if body.get("type").and_then(serde_json::Value::as_str) != Some(event.event_type.as_str())
        || body_state_key != event.state_key.as_deref()
        || body_parents != row_parents
    {
        return Err(PersistError::BodyMismatch(event.event_id.clone()));
    }
    Ok(())
}

/// Every `(target, redaction)` pair among the planned events.
///
/// A redaction names its target in `content.redacts` from room version 11
/// and in the top-level `redacts` before that.
#[cfg(feature = "synapse-import")]
#[must_use]
pub fn redactions_in<'v>(
    steps: &[Step],
    body_of: &dyn Fn(&str) -> Option<&'v serde_json::Value>,
) -> Vec<(String, String)> {
    steps
        .iter()
        .filter_map(|step| {
            let event_id = step.input.event_id.as_str();
            redaction_target(body_of(event_id)?)
                .map(|target| (target.to_owned(), event_id.to_owned()))
        })
        .collect()
}

/// The event a redaction removes, or `None` for any other event.
#[cfg(feature = "synapse-import")]
#[must_use]
pub fn redaction_target(body: &serde_json::Value) -> Option<&str> {
    if body["type"].as_str() != Some("m.room.redaction") {
        return None;
    }
    body["content"]["redacts"]
        .as_str()
        .or_else(|| body["redacts"].as_str())
}

/// Compare the state Spindle folded forward with the state Synapse reports.
///
/// Returned in key order and including slots only one side has, because "the
/// room lost its join rules" and "the room gained a join rules nobody sent"
/// are both divergence and neither shows up in a comparison that only walks
/// the keys they share.
#[must_use]
pub fn compare(state: &StateSnapshot, current_state: &StateMap) -> Vec<Divergence> {
    let mut ours: BTreeMap<(String, String), String> = BTreeMap::new();
    state.for_each(|key, event_id| {
        ours.insert(
            (
                key.event_type().as_str().to_owned(),
                key.state_key().to_owned(),
            ),
            event_id.to_owned(),
        );
    });

    let keys: BTreeSet<&(String, String)> = ours.keys().chain(current_state.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let spindle = ours.get(key);
            let synapse = current_state.get(key);
            if spindle == synapse {
                return None;
            }
            Some(Divergence {
                key: StateKey::new(key.0.clone(), key.1.clone()),
                spindle: spindle.cloned(),
                synapse: synapse.cloned(),
            })
        })
        .collect()
}

/// Replay a room into a fresh log and compare the result with the source.
///
/// The log is built and thrown away: this establishes whether the room *can*
/// be imported and whether doing so preserves its state, which is what a dry
/// run has to answer before anything is written. Persisting the log is the
/// caller's job, and is deliberately not done here — a function that both
/// decides and commits has no dry run.
///
/// # Errors
///
/// Returns [`ImportError`] when the room cannot be ordered or the log refuses
/// an event the plan offered it.
pub fn replay(room: &SourceRoom) -> Result<Outcome, ImportError> {
    let plan = plan(room)?;
    let mut log = RoomLog::new();
    let mut head: Option<EventId> = None;

    for step in &plan.steps {
        let event_id = step.input.event_id.clone();
        let result = if step.seed {
            let state_after = match &room.state_after_root {
                Some(map) => snapshot_from(map),
                // A create-rooted import folds forward from nothing, so the
                // root's own state is just the root, and only when it is a
                // state event.
                None => step
                    .input
                    .state_key
                    .clone()
                    .map_or_else(StateSnapshot::new, |key| {
                        StateSnapshot::new().apply(key, event_id.as_str().to_owned())
                    }),
            };
            log.append_seeded(step.input.clone(), state_after, step.depth)
        } else {
            log.append_remote(step.input.clone())
        };
        match result {
            Ok(entry) => head = Some(entry.event_id.clone()),
            Err(error) => {
                return Err(ImportError::Append {
                    room_id: room.room_id.clone(),
                    event_id: event_id.as_str().to_owned(),
                    error,
                });
            }
        }
    }

    let head = head.ok_or_else(|| ImportError::NoHeadState {
        room_id: room.room_id.clone(),
    })?;
    let state = log
        .state_after_event(&head)
        .ok_or_else(|| ImportError::NoHeadState {
            room_id: room.room_id.clone(),
        })?;

    Ok(Outcome {
        room_id: room.room_id.clone(),
        imported: plan.steps.len(),
        divergence: compare(state, &room.current_state),
        excluded: plan.excluded,
        seeded_from_source: plan.seeded_from_source,
    })
}

#[cfg(test)]
mod seed_sharing_tests {
    use super::*;

    #[test]
    fn a_gap_removing_one_member_shares_the_existing_room_trie() {
        let mut map = StateMap::new();
        for index in 0..10_000 {
            map.insert(
                ("m.room.member".to_owned(), format!("@u{index}:example.org")),
                format!("$e{index}"),
            );
        }
        let base = snapshot_from(&map);
        map.remove(&("m.room.member".to_owned(), "@u3000:example.org".to_owned()));
        let (seed, changed) = snapshot_over(Some(&base), &map);
        assert_eq!(seed.root(), snapshot_from(&map).root());
        assert!(
            changed.is_empty(),
            "removal needs no replacement event bodies"
        );
        assert!(seed.delta_nodes(Some(&base)).len() <= 52);
    }
}
