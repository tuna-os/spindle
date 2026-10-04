use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{StateKey, StateRoot, StateSnapshot};

/// Matrix caps `prev_events` at 20 references per event.
const MAX_PREV_EVENTS: usize = 20;

/// Domain separator for the log chain, matching the convention the state trie
/// uses so no two hash inputs in this codebase can ever collide by accident.
const CHAIN_DOMAIN: &[u8] = b"spindle-log-chain-v1\0";

/// One bit per tip tracks which tips reach a node, so the tip set must fit a
/// `u64`. Matrix caps `prev_events` at 20, so a real fork is far below this.
const MAX_TIPS: usize = u64::BITS as usize;

/// How many recent entries keep their materialized state resident, by default.
///
/// Matched to SPEC §9.1's `max_fork_window`, and that coupling is the whole
/// argument: a fork deeper than the window already falls back to full state
/// resolution, which reads the trie from the store. So a window this size holds
/// every snapshot the fast path can ask for, and nothing that only the slow
/// path can.
pub const DEFAULT_RESIDENT_WINDOW: usize = 512;

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

/// A running hash over everything this server has sequenced in a room.
///
/// `chain[li] = H(CHAIN_DOMAIN || chain[li-1] || event_id[li])`, seeded from the
/// domain separator alone. Each value therefore commits to the entire ordered
/// history before it, so a server cannot restate what it once served without
/// producing a different chain — which is what turns "trust the serializer for
/// ordering" into "detect the serializer changing its mind" (SPEC §13.3).
///
/// Only forward-appended entries carry one. Backfilled history was sequenced by
/// somebody else and arrives with its own provenance; attesting to an order we
/// did not choose would be a claim we cannot back.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainHash([u8; 32]);

impl ChainHash {
    /// The value the chain starts from, before any event is sequenced.
    #[must_use]
    pub fn seed() -> Self {
        Self(*blake3::hash(CHAIN_DOMAIN).as_bytes())
    }

    /// Extend the chain with one event.
    #[must_use]
    pub fn extend(self, event_id: &EventId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CHAIN_DOMAIN);
        hasher.update(&self.0);
        hasher.update(event_id.as_str().as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
    /// This server's attestation to the order, for entries it sequenced.
    ///
    /// `None` for backfilled history, which it did not.
    pub chain: Option<ChainHash>,
    /// Content address of the room state after this entry applied.
    ///
    /// The address, not the state. A 32-byte root is what every entry can
    /// afford to keep forever; the materialized [`StateSnapshot`] it names is
    /// held only while it is recent enough to be reachable by a fork, and is
    /// otherwise rehydrated from the store (SPEC §6.4).
    pub state_root: StateRoot,
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

/// Why an event that is part of the room's DAG is kept out of its timeline.
///
/// The spec's checks on receipt of a PDU have three outcomes, and only one
/// of them is "append to the room". The other two still keep the event:
/// a later event may name it in `prev_events`, and the state at that later
/// event is computed from it like any other parent's.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Sideline {
    /// Allowed by the state before it, refused by the room's current state.
    /// Its state is the state before it with it applied, but it is not a
    /// forward extremity and no client is shown it.
    SoftFailed,
    /// Refused by its auth events or by the state before it. It changes no
    /// state: the state after it is the state before it.
    Rejected,
}

/// An event held for the DAG but not in the timeline: soft-failed or
/// rejected (see [`Sideline`]).
///
/// Kept outside the linear log on purpose. Nothing that walks the log --
/// pagination, sync, search, the stream -- can show it to a client by
/// mistake, because nothing that walks the log sees it.
#[derive(Clone, Debug)]
pub struct SidelinedEntry {
    pub event_id: EventId,
    pub prev_events: Vec<EventId>,
    pub depth: u64,
    pub state_key: Option<StateKey>,
    pub kind: Sideline,
    /// The state after it: the state before it, plus the event itself when
    /// it soft-failed.
    pub state_root: StateRoot,
}

/// The room version's state resolution algorithm, supplied from above.
///
/// The core holds the states; what to do when they disagree is the room
/// version's call, and the rules, the event bodies and the auth DAG that
/// call reads live above the core (ADR 0002). [`RoomLog`] asks only when it
/// must: never for a single parent, and never when every parent holds the
/// same state.
pub trait StateResolver {
    /// Resolve two or more pairwise-different states into one.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the states cannot be resolved -- an
    /// event a candidate needs cannot be read, or this resolver declines
    /// to resolve a conflict at all ([`Strict`]).
    fn resolve(&mut self, states: &[StateSnapshot]) -> Result<StateSnapshot, AppendError>;
}

/// The resolver that resolves nothing: parents that disagree are refused
/// with [`AppendError::NeedsStateResolution`], naming the first slot they
/// disagree on.
///
/// For callers with no room version behind them -- the log's own
/// restore-time refold and tests -- and for the importer, whose answer to a
/// contested fork is the state its source already resolved.
#[derive(Clone, Copy, Debug, Default)]
pub struct Strict;

impl StateResolver for Strict {
    fn resolve(&mut self, states: &[StateSnapshot]) -> Result<StateSnapshot, AppendError> {
        let Some((first, rest)) = states.split_first() else {
            return Ok(StateSnapshot::new());
        };
        for other in rest {
            if let Some((key, _, _)) = first.diff(other).into_iter().next() {
                let candidates = states
                    .iter()
                    .filter_map(|state| state.get(key))
                    .map(EventId::new)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                return Err(AppendError::NeedsStateResolution {
                    key: key.clone(),
                    candidates,
                });
            }
        }
        Ok(first.clone())
    }
}

/// How many forward extremities a locally authored event names, newest
/// first. Synapse's figure: enough to collapse an ordinary fork in one
/// event, few enough that a peer flooding stale extremities cannot make
/// every local event resolve twenty states.
pub const MAX_AUTHORED_PREV_EVENTS: usize = 10;

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
    /// Soft-failed and rejected events: in the DAG, out of the timeline.
    sidelined: HashMap<EventId, SidelinedEntry>,
    /// Their states, held resident: they are few, and a child naming one
    /// needs its state at once.
    sidelined_state: HashMap<EventId, StateSnapshot>,
    /// The room's current state when it has several forward extremities:
    /// their states resolved by the room version's algorithm. With one
    /// extremity it is that extremity's state, and this is `None`. Set by
    /// whoever holds the resolver ([`RoomLog::set_current`]); see
    /// [`RoomLog::current_state`].
    current: Option<StateSnapshot>,
    next_forward: i64,
    next_backward: i64,
    head_chain: ChainHash,
    /// Materialized state for the entries that can still be asked for it.
    ///
    /// Bounded, because the alternative is not: a snapshot per entry retains
    /// every version of every path the trie ever copied, so a long-lived room
    /// grows without limit even though the trie shares structure perfectly.
    resident: BTreeMap<i64, StateSnapshot>,
    resident_window: usize,
}

impl Default for RoomLog {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            positions: HashMap::new(),
            forward_extremities: BTreeSet::new(),
            sidelined: HashMap::new(),
            sidelined_state: HashMap::new(),
            current: None,
            next_forward: 1,
            next_backward: 0,
            head_chain: ChainHash::seed(),
            resident: BTreeMap::new(),
            resident_window: DEFAULT_RESIDENT_WINDOW,
        }
    }
}

impl RoomLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A log that keeps `window` recent snapshots resident instead of the
    /// default [`DEFAULT_RESIDENT_WINDOW`].
    ///
    /// Set this to at least the `max_events` passed to [`RoomLog::fork_window`]
    /// — below that, a fork the design says is cheap has to reach the store for
    /// state the design says should be in hand.
    #[must_use]
    pub fn with_resident_window(window: usize) -> Self {
        Self {
            resident_window: window,
            ..Self::default()
        }
    }

    /// Materialized state after the entry at `li`, if it is still resident.
    ///
    /// `None` means evicted, not absent: the state exists, addressed by that
    /// entry's `state_root`, and is rehydrated from the store. Callers on the
    /// fast path never see `None`, because everything a fork can reach is
    /// pinned.
    #[must_use]
    pub fn state_after(&self, li: LinearIndex) -> Option<&StateSnapshot> {
        self.resident.get(&li.get())
    }

    /// Materialized state after `event_id`, if it is still resident.
    #[must_use]
    pub fn state_after_event(&self, event_id: &EventId) -> Option<&StateSnapshot> {
        self.positions
            .get(event_id)
            .and_then(|li| self.resident.get(li))
    }

    /// The state before `event_id`: its parents' states resolved by the
    /// room version's algorithm, which is what the event was authorized
    /// against and what federation's `/state` and `/state_ids` answer for it.
    ///
    /// Not the state after the entry before it in this server's order. The
    /// two agree in a linear room and part after a fork: the entry before
    /// the event that merges two branches belongs to one of them, while the
    /// merge event was authorized against the resolution of both (#16).
    ///
    /// Resident snapshots serve where the window still holds them; older
    /// ones are rehydrated through `load`, the store's content-addressed
    /// read, because a peer may ask about an event older than the window.
    ///
    /// Parents this server does not hold are outside its history, not a
    /// corrupt index -- the frontier of a backfill names them -- and are
    /// left out. An event none of whose parents is held answers the state
    /// after the entry before it in linear order, which for backfilled
    /// history is the older event.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError::UnknownPredecessor`] for an event the log does
    /// not hold, [`AppendError::StateNotResident`] for a parent whose state
    /// is neither resident nor rehydratable, and whatever `resolver` returns
    /// for parents it cannot resolve.
    pub fn state_before(
        &self,
        event_id: &EventId,
        resolver: &mut dyn StateResolver,
        load: &mut dyn FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<StateSnapshot, AppendError> {
        let (prev_events, li) = if let Some(entry) = self.get(event_id) {
            (&entry.prev_events, Some(entry.li))
        } else if let Some(sidelined) = self.sidelined.get(event_id) {
            (&sidelined.prev_events, None)
        } else {
            return Err(AppendError::UnknownPredecessor(event_id.clone()));
        };
        let held: Vec<EventId> = prev_events
            .iter()
            .filter(|parent| self.holds(parent))
            .cloned()
            .collect();
        if held.is_empty() {
            let Some(li) = li else {
                return Ok(StateSnapshot::new());
            };
            return match self
                .entry_at_or_before(li.get().saturating_sub(1))
                .filter(|previous| previous.li < li)
            {
                Some(previous) => self.state_after_any(&previous.event_id, load),
                None => Ok(StateSnapshot::new()),
            };
        }
        self.resolve_parents(&held, resolver, load)
    }

    /// The state an event naming `prev_events` sits on: their states,
    /// resolved when they differ.
    ///
    /// This is the only place state resolution is entered from. One parent,
    /// or several holding the same state, is answered without it -- the
    /// one case where SPEC 9.2's fork merge provably equals every room
    /// version's algorithm, since states that do not differ have nothing to
    /// resolve and both algorithms return them unchanged. Anything else goes
    /// to `resolver`, which is the room version's algorithm (ADR 0005).
    ///
    /// # Errors
    ///
    /// Returns [`AppendError::UnknownPredecessor`] for a parent this log does
    /// not hold (as an entry or sidelined), [`AppendError::StateNotResident`]
    /// for a parent whose state cannot be read, and the resolver's error.
    pub fn resolve_parents(
        &self,
        prev_events: &[EventId],
        resolver: &mut dyn StateResolver,
        load: &mut dyn FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<StateSnapshot, AppendError> {
        let mut states: Vec<StateSnapshot> = Vec::with_capacity(prev_events.len());
        for parent in prev_events {
            let state = self.state_after_any(parent, load)?;
            if !states.iter().any(|held| held.root() == state.root()) {
                states.push(state);
            }
        }
        match states.len() {
            0 => Ok(StateSnapshot::new()),
            1 => Ok(states.pop().unwrap_or_default()),
            _ => resolver.resolve(&states),
        }
    }

    /// The state after `event_id`, an entry or a sidelined event: from the
    /// window if it is still there and from the store through `load` if not.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError::UnknownPredecessor`] for an event this log does
    /// not hold and [`AppendError::StateNotResident`] for state that cannot
    /// be rehydrated.
    pub fn state_after_any(
        &self,
        event_id: &EventId,
        load: &mut dyn FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<StateSnapshot, AppendError> {
        if let Some(entry) = self.get(event_id) {
            if let Some(state) = self.resident.get(&entry.li.get()) {
                return Ok(state.clone());
            }
            return StateSnapshot::rehydrate(entry.state_root, &mut |root: &StateRoot| load(root))
                .map_err(|_| AppendError::StateNotResident {
                    li: entry.li,
                    event_id: event_id.clone(),
                });
        }
        if let Some(sidelined) = self.sidelined.get(event_id) {
            if let Some(state) = self.sidelined_state.get(event_id) {
                return Ok(state.clone());
            }
            return StateSnapshot::rehydrate(sidelined.state_root, &mut |root: &StateRoot| {
                load(root)
            })
            .map_err(|_| AppendError::StateNotResident {
                li: LinearIndex(0),
                event_id: event_id.clone(),
            });
        }
        Err(AppendError::UnknownPredecessor(event_id.clone()))
    }

    /// Whether this log holds `event_id`, in the timeline or sidelined.
    #[must_use]
    pub fn holds(&self, event_id: &EventId) -> bool {
        self.positions.contains_key(event_id) || self.sidelined.contains_key(event_id)
    }

    /// A soft-failed or rejected event this log holds, if `event_id` is one.
    #[must_use]
    pub fn sidelined(&self, event_id: &EventId) -> Option<&SidelinedEntry> {
        self.sidelined.get(event_id)
    }

    /// Every soft-failed or rejected event this log holds.
    pub fn sidelined_entries(&self) -> impl Iterator<Item = &SidelinedEntry> {
        self.sidelined.values()
    }

    /// The room's current state: the state of its one forward extremity,
    /// or -- with several -- their states resolved, as last set by
    /// [`Self::set_current`].
    ///
    /// This, not the state after the newest entry, is what local events
    /// are authorized against, what soft-fail checks read, and what a
    /// client is told the room's state is. The two agree whenever the room
    /// has one extremity, which is the linear case and almost always the
    /// real one; after a fork the newest entry belongs to one branch.
    ///
    /// `None` only for an empty room, or when a fork is open and no
    /// resolution has been recorded; readers that need an answer then fall
    /// back to the newest entry's state, which is what this returned before
    /// the resolver existed.
    #[must_use]
    pub fn current_state(&self) -> Option<&StateSnapshot> {
        if self.forward_extremities.len() == 1 {
            let tip = self.forward_extremities.first()?;
            return self.state_after_event(tip);
        }
        self.current.as_ref().or_else(|| {
            self.entries
                .keys()
                .next_back()
                .and_then(|li| self.resident.get(li))
        })
    }

    /// Whether [`Self::current_state`] is a recorded resolution, or the
    /// single extremity's state. `false` means a fork is open and nobody
    /// has resolved it yet.
    #[must_use]
    pub fn current_is_settled(&self) -> bool {
        self.forward_extremities.len() <= 1 || self.current.is_some()
    }

    /// Resolve the forward extremities' states into the room's current
    /// state. Pure: record the answer with [`Self::set_current`].
    ///
    /// # Errors
    ///
    /// As [`Self::resolve_parents`].
    pub fn resolve_current(
        &self,
        resolver: &mut dyn StateResolver,
        load: &mut dyn FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<StateSnapshot, AppendError> {
        let tips: Vec<EventId> = self.forward_extremities.iter().cloned().collect();
        self.resolve_parents(&tips, resolver, load)
    }

    /// Record the room's current state, as [`Self::resolve_current`]
    /// computed it. Ignored while the room has one extremity, whose own
    /// state is the current state by definition.
    pub fn set_current(&mut self, state: StateSnapshot) {
        if self.forward_extremities.len() > 1 {
            self.current = Some(state);
        } else {
            self.current = None;
        }
    }

    /// How many snapshots are currently held in memory.
    ///
    /// Exposed so a test can assert the bound holds rather than assume it. A
    /// room whose resident count tracks its length has lost the bound, which is
    /// the regression this whole mechanism exists to prevent.
    #[must_use]
    pub fn resident_len(&self) -> usize {
        self.resident.len()
    }

    /// Record a snapshot and drop whatever the window no longer covers.
    ///
    /// The entry just written always survives this call, whatever its index.
    /// That is what lets a backfill prepend — which takes an index far below
    /// the window floor — hand its `/state_ids` state to the caller for
    /// persistence before it is dropped again on the next append.
    fn make_resident(&mut self, li: i64, state: StateSnapshot) {
        self.resident.insert(li, state);
        self.evict(li);
    }

    /// Retain the window, `keep`, and every forward extremity at any age.
    ///
    /// The extremity rule is the one that is not obvious and is load-bearing:
    /// a class-D stale peer event can leave an extremity arbitrarily far back
    /// (ADR 0001), and the next local event has to merge that extremity's state
    /// with the head's. Evicting it by age would turn an ordinary federation
    /// append into a store read at best, and an unresolvable merge at worst.
    ///
    /// The floor comes from the highest resident index rather than from `keep`,
    /// so a backfill prepend cannot drag the window down and resurrect the
    /// whole room.
    fn evict(&mut self, keep: i64) {
        let Some(&newest) = self.resident.keys().next_back() else {
            return;
        };
        let floor = newest.saturating_sub_unsigned(self.resident_window as u64);
        if self
            .resident
            .first_key_value()
            .is_none_or(|(&li, _)| li >= floor)
        {
            return;
        }
        let pinned: BTreeSet<i64> = self
            .forward_extremities
            .iter()
            .filter_map(|id| self.positions.get(id).copied())
            .collect();
        self.resident
            .retain(|&li, _| li >= floor || li == keep || pinned.contains(&li));
    }

    /// Every entry in linear-index order, oldest first.
    #[must_use]
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &LogEntry> + ExactSizeIterator {
        self.entries.values()
    }

    /// The entries whose linear index falls in `range`, oldest first.
    ///
    /// A `BTreeMap` range probe, so a page that starts deep in a room's
    /// history does not first walk past everything on the other side of
    /// it: `entries().filter(..)` reads the same rows and drops most.
    pub fn entries_in(
        &self,
        range: impl std::ops::RangeBounds<i64>,
    ) -> impl DoubleEndedIterator<Item = &LogEntry> {
        self.entries.range(range).map(|(_, entry)| entry)
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

    /// The entry at exactly `li`, if the log still holds it.
    ///
    /// `entries` is a `BTreeMap`, so this is a probe rather than a walk.
    /// Worth its own method because the alternative reads naturally and is
    /// not: `entries().find(|e| e.li.get() == li)` is a linear scan of the
    /// room, and on a path that runs per event it makes the whole read
    /// quadratic in the room's length.
    #[must_use]
    pub fn entry_at(&self, li: i64) -> Option<&LogEntry> {
        self.entries.get(&li)
    }

    /// The newest entry at or before `li` — the seek behind "what did
    /// this room look like at that point" (SPEC §17.4). One `BTreeMap`
    /// range probe; `None` means the log starts after that point.
    #[must_use]
    pub fn entry_at_or_before(&self, li: i64) -> Option<&LogEntry> {
        self.entries
            .range(..=li)
            .next_back()
            .map(|(_, entry)| entry)
    }

    /// Every tip of the federation DAG, including any set aside.
    ///
    /// This is what a peer would compute from the same events, and what
    /// the store persists. It is not what a local event names -- that is
    /// [`Self::authoring_extremities`].
    #[must_use]
    pub fn forward_extremities(&self) -> &BTreeSet<EventId> {
        &self.forward_extremities
    }

    /// The forward extremities a locally authored event names: the newest
    /// [`MAX_AUTHORED_PREV_EVENTS`] tips, in linear order.
    ///
    /// In a linear room this is exactly one entry, the head. After a fork
    /// it is both tips, and the event that names them is the merge.
    pub fn authoring_extremities(&self) -> impl Iterator<Item = &EventId> {
        let mut tips: Vec<(i64, &EventId)> = self
            .forward_extremities
            .iter()
            .map(|tip| (self.positions.get(tip).copied().unwrap_or(i64::MIN), tip))
            .collect();
        tips.sort_unstable_by(|left, right| right.cmp(left));
        tips.truncate(MAX_AUTHORED_PREV_EVENTS);
        tips.sort_unstable();
        tips.into_iter().map(|(_, tip)| tip)
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

    /// The chain value covering everything this server has sequenced so far.
    ///
    /// This is what a server signs and publishes to attest to its ordering.
    #[must_use]
    pub fn head_chain(&self) -> ChainHash {
        self.head_chain
    }

    /// The entry at a position this log issued.
    ///
    /// Every `li` that reaches this came from this log: read out of
    /// `positions`, or inserted a few lines above the call. The lookup
    /// cannot miss, and an index says so more plainly than an error nobody
    /// could give a reason for. `expect` rather than `allow`, so this stops
    /// compiling the day the lookup can be written without indexing instead
    /// of quietly outliving its reason. No parsed byte reaches this; it is
    /// the one indexed lookup the crate keeps, kept in one place.
    #[expect(
        clippy::indexing_slicing,
        reason = "`li` was issued by this log; see the doc comment"
    )]
    fn issued_entry(&self, li: i64) -> &LogEntry {
        &self.entries[&li]
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
            // A miss cannot happen -- every entry joins `frontier` and
            // `reached` in the same statement -- and reading one as "not yet
            // fully reached" keeps walking, which is the safe direction.
            if frontier
                .iter()
                .all(|entry| reached.get(entry).is_some_and(|mask| *mask == full))
            {
                nearest = nearest.or(Some(li));
                break;
            }

            frontier.remove(&li);
            visited += 1;

            let mask = reached.get(&li).copied().unwrap_or(0);
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
            for parent in &self.issued_entry(li).prev_events {
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
            nearest_common_ancestor: self.issued_entry(nearest).event_id.clone(),
            events: divergent
                .into_iter()
                .map(|li| self.issued_entry(li).event_id.clone())
                .collect(),
            visited,
        })
    }

    /// Append a received event without changing its signed `prev_events`.
    ///
    /// Parents that disagree are refused ([`Strict`]): this is the form for
    /// callers with no resolver. The server appends through
    /// [`Self::resolve_parents`] and [`Self::append_resolved`].
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the event is duplicated, has invalid or
    /// unknown predecessors, exceeds the Matrix parent limit, or its parents'
    /// states differ.
    pub fn append_remote(&mut self, input: EventInput) -> Result<&LogEntry, AppendError> {
        self.append(input)
    }

    /// Author an event on the current extremities ([`Self::authoring_extremities`]).
    ///
    /// In a linear room this is exactly one parent. After a stale class-D PDU it
    /// is a bounded set of parents, which collapses the federation DAG back to
    /// one extremity while the event still receives one linear storage index.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the new event is duplicated, the room has
    /// invalid predecessor state, or the parents' states differ ([`Strict`]).
    pub fn append_local(
        &mut self,
        event_id: impl Into<Box<str>>,
        state_key: Option<StateKey>,
    ) -> Result<&LogEntry, AppendError> {
        let input = EventInput {
            event_id: EventId::new(event_id),
            prev_events: self.authoring_extremities().cloned().collect(),
            state_key,
        };
        self.append(input)
    }

    /// Validate an event's parents and compute its depth.
    fn check_parents(&self, input: &EventInput) -> Result<u64, AppendError> {
        if self.holds(&input.event_id) {
            return Err(AppendError::DuplicateEvent(input.event_id.clone()));
        }
        if input.prev_events.len() > MAX_PREV_EVENTS {
            return Err(AppendError::TooManyPredecessors(input.prev_events.len()));
        }
        if let Some(first) = input.prev_events.first()
            && self.entries.is_empty()
            && self.sidelined.is_empty()
        {
            return Err(AppendError::UnknownPredecessor(first.clone()));
        }
        if !self.entries.is_empty() && input.prev_events.is_empty() {
            return Err(AppendError::MissingPredecessor);
        }
        let mut depth = 0_u64;
        for parent in &input.prev_events {
            let parent_depth = if let Some(entry) = self.get(parent) {
                entry.depth
            } else if let Some(sidelined) = self.sidelined.get(parent) {
                sidelined.depth
            } else {
                return Err(AppendError::UnknownPredecessor(parent.clone()));
            };
            depth = depth.max(parent_depth.saturating_add(1));
        }
        Ok(depth)
    }

    fn append(&mut self, input: EventInput) -> Result<&LogEntry, AppendError> {
        self.check_parents(&input)?;
        let state_before =
            self.resolve_parents(&input.prev_events, &mut Strict, &mut |_: &StateRoot| None)?;
        self.append_resolved(input, state_before)
    }

    /// Append an accepted event whose state before it the caller resolved
    /// ([`Self::resolve_parents`]).
    ///
    /// The event becomes a forward extremity and its parents stop being
    /// ones. With one extremity left, the room's current state is that
    /// event's; with several, the caller records their resolution with
    /// [`Self::set_current`].
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the event is duplicated, names too many
    /// or unknown parents, or the index space is exhausted.
    pub fn append_resolved(
        &mut self,
        input: EventInput,
        state_before: StateSnapshot,
    ) -> Result<&LogEntry, AppendError> {
        let depth = self.check_parents(&input)?;
        let mut state_after = state_before;
        let state_key = input.state_key;
        if let Some(state_key) = state_key.clone() {
            state_after = state_after.apply(state_key, input.event_id.as_str());
        }

        let li = self.next_forward;
        self.next_forward = self
            .next_forward
            .checked_add(1)
            .ok_or(AppendError::IndexSpaceExhausted)?;

        let chain = self.head_chain.extend(&input.event_id);
        let entry = LogEntry {
            li: LinearIndex(li),
            event_id: input.event_id,
            prev_events: input.prev_events,
            depth,
            state_key,
            chain: Some(chain),
            state_root: state_after.root(),
        };
        self.head_chain = chain;

        for parent in &entry.prev_events {
            self.forward_extremities.remove(parent);
        }
        self.forward_extremities.insert(entry.event_id.clone());
        if self.forward_extremities.len() == 1 {
            self.current = None;
        }
        self.positions.insert(entry.event_id.clone(), li);
        self.entries.insert(li, entry);
        // After the extremity set is updated, so a parent that just stopped
        // being an extremity stops being pinned by it.
        self.make_resident(li, state_after);
        Ok(self.issued_entry(li))
    }

    /// Hold a soft-failed or rejected event for the DAG, outside the
    /// timeline ([`Sideline`]).
    ///
    /// A rejected event's state is the state before it; a soft-failed
    /// event's is that state with the event applied, because the spec only
    /// keeps a soft-failed event from clients and extremities, not from
    /// the state of whatever later names it. Neither changes the forward
    /// extremities: the event is not one, and its parents stay what they
    /// were.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError`] when the event is duplicated or names too many
    /// or unknown parents.
    pub fn sideline(
        &mut self,
        input: EventInput,
        state_before: StateSnapshot,
        kind: Sideline,
    ) -> Result<&SidelinedEntry, AppendError> {
        let depth = self.check_parents(&input)?;
        let state_after = match (&input.state_key, kind) {
            (Some(key), Sideline::SoftFailed) => {
                state_before.apply(key.clone(), input.event_id.as_str())
            }
            _ => state_before,
        };
        let entry = SidelinedEntry {
            event_id: input.event_id.clone(),
            prev_events: input.prev_events,
            depth,
            state_key: input.state_key,
            kind,
            state_root: state_after.root(),
        };
        self.restore_sidelined(entry, state_after);
        self.sidelined
            .get(&input.event_id)
            .ok_or(AppendError::UnknownPredecessor(input.event_id))
    }

    /// Put back a sidelined event read from storage, with its state.
    pub fn restore_sidelined(&mut self, entry: SidelinedEntry, state: StateSnapshot) {
        self.sidelined_state.insert(entry.event_id.clone(), state);
        self.sidelined.insert(entry.event_id.clone(), entry);
    }

    /// The sidelined event's state, when it is resident.
    #[must_use]
    pub fn sidelined_state(&self, event_id: &EventId) -> Option<&StateSnapshot> {
        self.sidelined_state.get(event_id)
    }

    /// Append an event whose state is supplied rather than derived — the
    /// seeding path for a room joined over federation.
    ///
    /// A remote join hands this server a state set and a join event with no
    /// shared history behind them: the parents the events name live on the
    /// resident server, not here. Deriving state by folding parents is
    /// therefore impossible, and the caller supplies each event's
    /// state-after instead, built by replaying the remote state in
    /// dependency order. `chain` stays `None` for the same reason it does
    /// on backfill: this history was sequenced by somebody else.
    ///
    /// The appended event becomes the sole forward extremity, so seeding a
    /// room is a run of these calls ending with the join, after which
    /// ordinary appends continue from it.
    ///
    /// # Errors
    ///
    /// Returns [`AppendError::DuplicateEvent`] for an event already held,
    /// or [`AppendError::IndexSpaceExhausted`].
    pub fn append_seeded(
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
            state_key: input.state_key,
            chain: None,
            state_root: state_after.root(),
        };

        self.forward_extremities.clear();
        self.current = None;
        self.forward_extremities.insert(entry.event_id.clone());
        self.positions.insert(entry.event_id.clone(), li);
        self.entries.insert(li, entry);
        self.make_resident(li, state_after);
        Ok(self.issued_entry(li))
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
            // Backfilled history was sequenced by somebody else.
            chain: None,
            state_root: state_after.root(),
        };

        // Backfilled history is never a forward extremity: it is, by
        // construction, behind everything we already hold.
        self.positions.insert(entry.event_id.clone(), li);
        self.entries.insert(li, entry);
        // Backfill takes descending indices, so it is always below the window
        // floor and this snapshot is dropped again immediately. That is correct
        // and deliberate: backfilled state came from `/state_ids`, is persisted
        // by the commit, and is rehydrated rather than refolded on reopen.
        self.make_resident(li, state_after);
        Ok(self.issued_entry(li))
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
    /// The chain value recorded when this entry was sequenced, if this server
    /// sequenced it.
    pub chain: Option<[u8; 32]>,
}

/// A log rebuilt from storage, plus whichever entries could not be verified.
#[derive(Clone, Debug)]
pub struct RestoredLog {
    pub log: RoomLog,
    /// Entries whose recorded chain value does not match the one recomputed
    /// from the entries before them.
    ///
    /// The chain commits to the whole ordered history, so a break here means
    /// the log was altered after it was sequenced — an event edited, removed,
    /// or reordered. Unlike `unverified`, there is no benign explanation: this
    /// is the tamper signal (SPEC §13.3), and the first broken index is where
    /// the history stopped matching what was attested.
    pub broken_chain: Vec<LinearIndex>,

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
            sidelined: HashMap::new(),
            sidelined_state: HashMap::new(),
            current: None,
            next_forward,
            next_backward,
            head_chain: ChainHash::seed(),
            resident: BTreeMap::new(),
            resident_window: DEFAULT_RESIDENT_WINDOW,
        };
        let mut unverified = Vec::new();
        let mut broken_chain = Vec::new();
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
            let parents: Vec<&StateSnapshot> = restored
                .prev_events
                .iter()
                .filter_map(|parent| log.state_after_event(parent))
                .collect();
            // No merge base here, and none is needed: a reopen that cannot
            // reproduce a fold falls through to the stored trie below, which
            // is the authority for exactly these entries. Computing an
            // ancestor mid-rebuild would also be asking a half-built log
            // about ancestry it does not yet hold.
            // A conflict means the fold cannot be reproduced; fall through
            // to the stored trie rather than refusing to open the room.
            let mut folded = restored_fold(&parents).unwrap_or_default();
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

            // Recompute the chain rather than trusting what was stored: a
            // stored value that agrees with itself proves nothing. Backfilled
            // entries are skipped because they carry no attestation from us.
            let chain = match restored.chain {
                Some(stored) => {
                    let recomputed = log.head_chain.extend(&restored.event_id);
                    if *recomputed.as_bytes() != stored {
                        broken_chain.push(restored.li);
                    }
                    log.head_chain = recomputed;
                    Some(recomputed)
                }
                None => None,
            };

            let entry = LogEntry {
                li: restored.li,
                event_id: restored.event_id,
                prev_events: restored.prev_events,
                depth: restored.depth,
                state_key: restored.state_key,
                chain,
                // The root of the state we actually have, which is not always
                // the root that was stored: an entry we could neither refold
                // nor rehydrate is reported in `unverified`, and giving it the
                // stored root anyway would leave the log advertising an address
                // its own snapshot does not hash to.
                state_root: state_after.root(),
            };
            log.positions.insert(entry.event_id.clone(), li);
            log.entries.insert(li, entry);
            // Bounded here too. A reopen that materialized every entry's state
            // would exhaust memory on exactly the rooms this bound exists for,
            // and would do it before the server finished starting.
            log.make_resident(li, state_after);
        }

        Ok(RestoredLog {
            log,
            broken_chain,
            unverified,
        })
    }
}

/// Fold a restored entry's parents: their state when they agree, `None`
/// when they do not -- the stored trie is then the authority, because only
/// the room version's resolver could have produced it.
fn restored_fold(parents: &[&StateSnapshot]) -> Option<StateSnapshot> {
    let (first, rest) = parents.split_first()?;
    rest.iter()
        .all(|other| other.root() == first.root())
        .then(|| (*first).clone())
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
    /// The room version's resolver could not resolve the parents' states.
    ResolutionFailed(String),
    /// A named predecessor's state has been evicted from memory.
    ///
    /// Unreachable on the append path, which can only name recent entries or
    /// pinned extremities. It exists so that a future change which breaks that
    /// invariant fails loudly instead of silently appending onto empty state.
    StateNotResident {
        li: LinearIndex,
        event_id: EventId,
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
