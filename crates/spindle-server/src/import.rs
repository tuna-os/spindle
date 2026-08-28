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

use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};

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

    for event in included.values() {
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

    let mut changed = true;
    while changed {
        changed = false;
        for event in included.values() {
            if dropped.contains(event.event_id.as_str()) {
                continue;
            }
            if let Some(behind) = event
                .prev_events
                .iter()
                .find(|parent| dropped.contains(parent.as_str()))
            {
                dropped.insert(event.event_id.as_str());
                excluded.push(Excluded::Orphaned {
                    event_id: event.event_id.clone(),
                    behind: behind.clone(),
                });
                changed = true;
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

fn snapshot_from(map: &StateMap) -> StateSnapshot {
    let mut snapshot = StateSnapshot::new();
    for ((event_type, state_key), event_id) in map {
        snapshot = snapshot.apply(
            StateKey::new(event_type.clone(), state_key.clone()),
            event_id.clone(),
        );
    }
    snapshot
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
