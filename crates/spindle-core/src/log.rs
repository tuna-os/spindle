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

    /// The chain value covering everything this server has sequenced so far.
    ///
    /// This is what a server signs and publishes to attest to its ordering.
    #[must_use]
    pub fn head_chain(&self) -> ChainHash {
        self.head_chain
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

        let mut parent_states = Vec::with_capacity(input.prev_events.len());
        let mut depth = 0_u64;
        for parent in &input.prev_events {
            let Some(entry) = self.get(parent) else {
                return Err(AppendError::UnknownPredecessor(parent.clone()));
            };
            let entry_li = entry.li;
            let entry_depth = entry.depth;
            let Some(state) = self.resident.get(&entry_li.get()) else {
                // Every parent an append can name is either recent or a pinned
                // extremity, so this is unreachable by construction. It is an
                // error rather than a panic because "unreachable by
                // construction" is a claim about code that can be changed.
                return Err(AppendError::StateNotResident {
                    li: entry_li,
                    event_id: parent.clone(),
                });
            };
            parent_states.push(state);
            depth = depth.max(entry_depth.saturating_add(1));
        }

        let mut state_after = merge_states(&parent_states)?;
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
        self.positions.insert(entry.event_id.clone(), li);
        self.entries.insert(li, entry);
        // After the extremity set is updated, so a parent that just stopped
        // being an extremity stops being pinned by it.
        self.make_resident(li, state_after);
        Ok(&self.entries[&li])
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
        Ok(&self.entries[&li])
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

fn merge_states(parents: &[&StateSnapshot]) -> Result<StateSnapshot, AppendError> {
    let Some(first) = parents.first() else {
        return Ok(StateSnapshot::new());
    };
    if parents.len() == 1 {
        return Ok((*first).clone());
    }

    let mut values: BTreeMap<StateKey, BTreeSet<Box<str>>> = BTreeMap::new();
    for parent in parents {
        parent.for_each(|key, event_id| {
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
