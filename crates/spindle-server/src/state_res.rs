//! Matrix state resolution on the live path (ADR 0005).
//!
//! The core log holds a state per event and asks for a resolver whenever an
//! event's parents -- or the room's forward extremities -- hold different
//! states (`spindle_core::StateResolver`). This module is that resolver:
//! the room version's own algorithm, and nothing else.
//!
//! - Room version 1: the original algorithm, `crate::state_res_v1`.
//! - Room versions 2 and up: ruma-state-res's `resolve`, which carries state
//!   resolution v2 (rooms 2-11) and v2.1 (room 12 and its MSC4242 variant).
//!
//! What is ours is the inputs ruma needs, computed so that a resolution in a
//! room of a million events costs the fork rather than the room:
//!
//! - **The auth difference** (`AuthGraph::auth_difference`). ruma takes it as
//!   a list of full auth chains and diffs them, which would mean
//!   materializing every chain in full. It is computed here instead by
//!   Synapse's walk: every event of every state set is seeded with the sets
//!   it is in, sets flow down `auth_events` edges in reverse topological
//!   order, and the walk stops as soon as everything left to visit is
//!   reachable from every set. The answer is handed to ruma as one chain
//!   holding exactly the difference beside empty ones, which ruma's
//!   `union - intersection` returns unchanged.
//! - **The conflicted state subgraph** for v2.1, from the same graph.
//! - **The auth DAG itself**, per room, built lazily from stored bodies and
//!   kept: each node is a state event with its auth edges and its rank (one
//!   more than its highest auth event's). Available bodies are read once
//!   per graph build; unavailable bodies are rechecked before cache reuse.
//! - **A cache of resolutions** keyed by input state roots, room identity,
//!   rejection policy and auth graph generation, least recently used out
//!   first. A recovered auth body changes the question even when all input
//!   state roots stay identical.
//!
//! Every "is this event allowed" question inside resolution is ruma's
//! `check_state_dependent_auth_rules`, exactly as on the send path
//! (`authorize`).

use std::cell::RefCell;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use ruma::OwnedEventId;
use ruma::room_version_rules::{RoomVersionRules, StateResolutionVersion};
use ruma::state_res::StateMap;
use ruma::state_res::utils::event_id_set::EventIdSet;
use serde_json::Value;
use spindle_core::{
    AppendError, EventId, RoomLog, Sideline, StateKey, StateResolver, StateSnapshot,
};

use crate::authorize::StoredEvent;

/// One state event in a room's auth DAG.
#[derive(Debug)]
struct Node {
    id: Box<str>,
    /// Indices of its `auth_events`.
    auth: Vec<u32>,
    /// One more than the highest rank among its auth events; zero for an
    /// event with none, or one whose body this server does not hold. Strictly
    /// decreasing along every auth edge, which is what makes it a valid
    /// order for the difference walk.
    rank: u32,
    /// Whether `auth` and `rank` have been read from the body yet.
    loaded: bool,
}

/// A room's auth DAG over the state events resolution has touched.
///
/// Built on demand from stored bodies, one read per event per build, and then
/// kept while the room is open. Signed auth edges never change, but a body
/// absent during an earlier resolution can arrive later. Such arrivals rebuild
/// ranks and give subsequent resolutions a new cache generation.
#[derive(Debug, Default)]
pub struct AuthGraph {
    index: HashMap<Box<str>, u32>,
    nodes: Vec<Node>,
    missing: HashSet<Box<str>>,
    generation: u64,
}

impl AuthGraph {
    /// How many events the graph holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph holds nothing yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Recheck only bodies that were unavailable, not every cached auth edge.
    /// A recovered ancestor can change ranks throughout the graph, so rebuild
    /// all ranks together instead of repairing just that ancestor's node.
    fn refresh_missing(&mut self, body_exists: &dyn Fn(&str) -> bool) {
        if self.missing.iter().any(|id| body_exists(id)) {
            self.index.clear();
            self.nodes.clear();
            self.missing.clear();
            self.generation = self.generation.wrapping_add(1);
        }
    }

    fn intern(&mut self, id: &str) -> u32 {
        if let Some(index) = self.index.get(id) {
            return *index;
        }
        let index = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
        self.nodes.push(Node {
            id: id.into(),
            auth: Vec::new(),
            rank: 0,
            loaded: false,
        });
        self.index.insert(id.into(), index);
        index
    }

    fn node(&self, index: u32) -> Option<&Node> {
        self.nodes.get(index as usize)
    }

    /// Make sure `id` and its whole auth ancestry are loaded and ranked.
    ///
    /// Iterative, because an auth chain can be thousands deep (every power
    /// levels event names the one before it) and recursion that deep is a
    /// stack overflow, not an error.
    fn ensure(&mut self, id: &str, auth_of: &dyn Fn(&str) -> Option<Vec<String>>) -> u32 {
        let root = self.intern(id);
        let mut stack = vec![(root, false)];
        while let Some((index, expanded)) = stack.pop() {
            let Some(node) = self.nodes.get(index as usize) else {
                continue;
            };
            if node.loaded && !expanded {
                continue;
            }
            if expanded {
                let rank = self.nodes.get(index as usize).map_or(0, |node| {
                    node.auth
                        .iter()
                        .filter_map(|auth| self.nodes.get(*auth as usize))
                        .map(|auth| auth.rank.saturating_add(1))
                        .max()
                        .unwrap_or(0)
                });
                if let Some(node) = self.nodes.get_mut(index as usize) {
                    node.rank = rank;
                    node.loaded = true;
                }
                continue;
            }
            let node_id = node.id.clone();
            let edges = auth_of(&node_id);
            if edges.is_none() {
                self.missing.insert(node_id.clone());
            }
            let auth: Vec<u32> = edges
                .unwrap_or_default()
                .iter()
                .map(|auth| self.intern(auth))
                .filter(|auth| *auth != index)
                .collect();
            stack.push((index, true));
            for child in &auth {
                if self
                    .nodes
                    .get(*child as usize)
                    .is_some_and(|node| !node.loaded)
                {
                    stack.push((*child, false));
                }
            }
            if let Some(node) = self.nodes.get_mut(index as usize) {
                node.auth = auth;
            }
        }
        root
    }

    /// The auth difference of `sets`, inclusive of the sets' own events:
    /// every event in the auth chain of some set and not of every set.
    ///
    /// Synapse's walk (`_get_auth_chain_difference_txn`): each event is
    /// marked with the sets that reach it, marks flow from an event to its
    /// auth events, and events are visited highest rank first, so an
    /// event's mark is final when it is visited. The walk ends when nothing
    /// left to visit is unreached by some set.
    fn auth_difference(&self, sets: &[Vec<u32>]) -> Vec<u32> {
        // Parent counts are bounded, but forward extremities can exceed
        // a machine word after a long partition. Every branch must count.
        if sets.len() > 64 {
            let mut counts: HashMap<u32, usize> = HashMap::new();
            for set in sets {
                let mut seen = HashSet::new();
                let mut pending = set.clone();
                while let Some(index) = pending.pop() {
                    if !seen.insert(index) {
                        continue;
                    }
                    *counts.entry(index).or_default() += 1;
                    if let Some(node) = self.node(index) {
                        pending.extend(&node.auth);
                    }
                }
            }
            return counts
                .into_iter()
                .filter_map(|(index, count)| (count != sets.len()).then_some(index))
                .collect();
        }
        let count = sets.len();
        let full: u64 = if count == 64 {
            u64::MAX
        } else {
            (1_u64 << count) - 1
        };
        let mut marks: HashMap<u32, u64> = HashMap::new();
        for (bit, set) in sets.iter().take(count).enumerate() {
            for index in set {
                *marks.entry(*index).or_default() |= 1_u64 << bit;
            }
        }
        let mut heap: BinaryHeap<(u32, u32)> = BinaryHeap::new();
        let mut queued: HashSet<u32> = HashSet::new();
        let mut unreached = 0_usize;
        for (index, mark) in &marks {
            let rank = self.node(*index).map_or(0, |node| node.rank);
            heap.push((rank, *index));
            queued.insert(*index);
            if *mark != full {
                unreached += 1;
            }
        }
        let mut difference = Vec::new();
        while unreached > 0 {
            let Some((_, index)) = heap.pop() else {
                break;
            };
            let mark = marks.get(&index).copied().unwrap_or(0);
            if mark != full {
                unreached -= 1;
                difference.push(index);
            }
            let Some(node) = self.node(index) else {
                continue;
            };
            for auth in &node.auth {
                let before = marks.get(auth).copied();
                let after = before.unwrap_or(0) | mark;
                marks.insert(*auth, after);
                if queued.insert(*auth) {
                    let rank = self.node(*auth).map_or(0, |node| node.rank);
                    heap.push((rank, *auth));
                    if after != full {
                        unreached += 1;
                    }
                } else if before.is_some_and(|before| before != full) && after == full {
                    unreached -= 1;
                }
            }
        }
        difference
    }

    /// Room version 12's conflicted state subgraph: the events on some auth
    /// path from one conflicted event down to another -- ancestors of a
    /// conflicted event that are also descendants of one.
    fn conflicted_subgraph(&self, conflicted: &HashSet<u32>) -> Vec<u32> {
        // Every auth ancestor of a conflicted event.
        let mut ancestors: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = conflicted.iter().copied().collect();
        while let Some(index) = queue.pop_front() {
            let Some(node) = self.node(index) else {
                continue;
            };
            for auth in &node.auth {
                if ancestors.insert(*auth) {
                    queue.push_back(*auth);
                }
            }
        }
        // Lowest rank first, so each event's auth events are decided
        // before it: an ancestor is in the subgraph when its auth chain
        // reaches a conflicted event.
        let mut ordered: Vec<u32> = ancestors.iter().copied().collect();
        ordered.sort_by_key(|index| self.node(*index).map_or(0, |node| node.rank));
        let mut reaches: HashSet<u32> = HashSet::new();
        for index in &ordered {
            let Some(node) = self.node(*index) else {
                continue;
            };
            if node
                .auth
                .iter()
                .any(|auth| conflicted.contains(auth) || reaches.contains(auth))
            {
                reaches.insert(*index);
            }
        }
        let mut subgraph: Vec<u32> = reaches.into_iter().collect();
        subgraph.extend(conflicted.iter().copied());
        subgraph
    }
}

/// Resolutions already computed, keyed by the sorted roots of the states
/// they resolved.
///
/// A root is the content address of a whole state (`StateSnapshot::root`),
/// a BLAKE3 hash over every `(type, state_key) -> event ID` slot. Every input
/// a resolution reads is fixed by those states: the events they name, whose
/// IDs are reference hashes from room version 3 on and, before that, name
/// the one body this store kept; the auth chains those bodies cite; and the
/// room version, through the create event. Three inputs are not in signed
/// PDUs, so they are in the key too: the room, the rejection policy, and the
/// auth graph's generation, which changes when a missing auth body arrives.
/// Two calls with the same key are therefore the same call.
///
/// Least recently used entries go first. The cache is shared by every room,
/// and a room whose current state sits on a fork that does not merge asks
/// the same question on every message it receives (#626). The old
/// first-in-first-out order evicted such an entry after 512 newer misses
/// anywhere on the server, however often it was hit.
#[derive(Debug, Default)]
pub struct ResolutionCache {
    entries: Mutex<CacheEntries>,
}

/// The cached resolutions with the tick each was last used at, and the
/// clock that issues ticks.
#[derive(Debug, Default)]
struct CacheEntries {
    map: HashMap<Vec<[u8; 32]>, (StateSnapshot, u64)>,
    clock: u64,
}

/// Resolutions kept. Each is a state root and a snapshot sharing nearly all
/// of its structure with its inputs, so this bounds bookkeeping, not memory
/// proportional to state.
const RESOLUTION_CACHE_CAPACITY: usize = 512;

impl ResolutionCache {
    fn key(states: &[StateSnapshot], policy: [u8; 32]) -> Vec<[u8; 32]> {
        let mut key: Vec<[u8; 32]> = states
            .iter()
            .map(|state| *state.root().as_bytes())
            .collect();
        key.sort_unstable();
        key.dedup();
        key.insert(0, policy);
        key
    }

    fn get(&self, key: &[[u8; 32]]) -> Option<StateSnapshot> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.clock = entries.clock.wrapping_add(1);
        let now = entries.clock;
        entries.map.get_mut(key).map(|(state, used)| {
            *used = now;
            state.clone()
        })
    }

    fn put(&self, key: Vec<[u8; 32]>, state: StateSnapshot) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.clock = entries.clock.wrapping_add(1);
        let now = entries.clock;
        entries.map.insert(key, (state, now));
        // One scan per insertion, and an insertion follows a resolution,
        // which costs far more than 512 comparisons.
        while entries.map.len() > RESOLUTION_CACHE_CAPACITY {
            let Some(oldest) = entries
                .map
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.map.remove(&oldest);
        }
    }

    /// How many resolutions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map
            .len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a resolution cost, for the metrics and the log line.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolutionStats {
    pub resolutions: u64,
    pub cache_hits: u64,
    /// Candidates the iterative auth checks refused. Expected, not a fault:
    /// weighing such events is what resolution is for.
    pub rejections: u64,
}

/// The room version's resolver over one room's log and bodies.
pub struct RoomResolver<'a> {
    rules: &'a RoomVersionRules,
    room_id: &'a str,
    log: &'a RoomLog,
    body: &'a dyn Fn(&str) -> Option<Value>,
    graph: &'a Mutex<AuthGraph>,
    cache: &'a ResolutionCache,
    pub stats: ResolutionStats,
}

impl<'a> RoomResolver<'a> {
    #[must_use]
    pub fn new(
        rules: &'a RoomVersionRules,
        room_id: &'a str,
        log: &'a RoomLog,
        body: &'a dyn Fn(&str) -> Option<Value>,
        graph: &'a Mutex<AuthGraph>,
        cache: &'a ResolutionCache,
    ) -> Self {
        Self {
            rules,
            room_id,
            log,
            body,
            graph,
            cache,
            stats: ResolutionStats::default(),
        }
    }

    /// A stored event as ruma reads it, rejected or not as this log says.
    fn stored(&self, id: &str) -> Option<StoredEvent> {
        let body = (self.body)(id)?;
        let rejected = self
            .log
            .sidelined(&EventId::new(id))
            .is_some_and(|entry| entry.kind == Sideline::Rejected);
        // A freshly refused malformed event must not acquire legacy
        // compatibility merely because resolution revisits its stored body.
        let event = if rejected {
            StoredEvent::parse_in(id, self.room_id, &body)
        } else {
            StoredEvent::parse_auth_in(id, self.room_id, &body)
        }
        .ok()?;
        Some(
            event
                .with_rejected(rejected)
                .with_preserved_rejection(self.log.historically_rejected(&EventId::new(id))),
        )
    }

    fn resolve_maps(
        &self,
        maps: &[StateMap<OwnedEventId>],
    ) -> Result<StateMap<OwnedEventId>, String> {
        let cache: RefCell<HashMap<OwnedEventId, Option<StoredEvent>>> =
            RefCell::new(HashMap::new());
        let fetch = |id: &ruma::EventId| -> Option<StoredEvent> {
            if let Some(hit) = cache.borrow().get(id) {
                return hit.clone();
            }
            let event = self.stored(id.as_str());
            cache.borrow_mut().insert(id.to_owned(), event.clone());
            event
        };

        match &self.rules.state_res {
            StateResolutionVersion::V1 => {
                crate::state_res_v1::resolve(&self.rules.authorization, maps, |id| fetch(id))
            }
            StateResolutionVersion::V2(v2) => {
                let (difference, subgraph) =
                    self.difference_and_subgraph(maps, v2.consider_conflicted_state_subgraph);
                let mut chains: Vec<EventIdSet<OwnedEventId>> =
                    vec![difference.into_iter().collect()];
                chains.extend((1..maps.len()).map(|_| EventIdSet::new()));
                ruma::state_res::resolve_with_candidate_policy(
                    &self.rules.authorization,
                    v2,
                    maps.iter(),
                    chains,
                    fetch,
                    |_| Some(subgraph.iter().cloned().collect()),
                    |event| !event.preserved_rejection(),
                )
                .map_err(|error| error.to_string())
            }
            other => Err(format!("unknown state resolution algorithm {other:?}")),
        }
    }

    /// The auth difference of `maps`, and -- when the version asks for it --
    /// the conflicted state subgraph, both as event IDs.
    fn difference_and_subgraph(
        &self,
        maps: &[StateMap<OwnedEventId>],
        subgraph: bool,
    ) -> (Vec<OwnedEventId>, Vec<OwnedEventId>) {
        let auth_of = |id: &str| -> Option<Vec<String>> {
            let body = (self.body)(id)?;
            Some(crate::rooms::edge_ids(&body["auth_events"]))
        };
        let mut graph = self
            .graph
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sets: Vec<Vec<u32>> = maps
            .iter()
            .map(|map| {
                map.values()
                    .map(|id| graph.ensure(id.as_str(), &auth_of))
                    .collect()
            })
            .collect();
        let to_ids = |graph: &AuthGraph, indices: Vec<u32>| -> Vec<OwnedEventId> {
            indices
                .into_iter()
                .filter_map(|index| graph.node(index))
                .filter_map(|node| OwnedEventId::try_from(node.id.as_ref()).ok())
                .collect()
        };
        let difference = graph.auth_difference(&sets);
        let difference = to_ids(&graph, difference);
        if !subgraph {
            return (difference, Vec::new());
        }
        // The conflicted state set: every value of a key the maps do not
        // all agree on.
        let mut conflicted: HashSet<u32> = HashSet::new();
        let mut keys: HashSet<&(ruma::events::StateEventType, String)> = HashSet::new();
        for map in maps {
            keys.extend(map.keys());
        }
        for key in keys {
            let values: Vec<Option<&OwnedEventId>> = maps.iter().map(|map| map.get(key)).collect();
            if values.windows(2).any(|pair| pair.first() != pair.get(1)) {
                for value in values.into_iter().flatten() {
                    if let Some(index) = graph.index.get(value.as_str()) {
                        conflicted.insert(*index);
                    }
                }
            }
        }
        let subgraph = graph.conflicted_subgraph(&conflicted);
        (difference, to_ids(&graph, subgraph))
    }
}

/// A snapshot as ruma's state map, and the slots it could not carry: an
/// event ID ruma cannot parse names no event the resolver can fetch, so it
/// cannot take part, and its slot is left exactly as the base holds it.
fn to_map(state: &StateSnapshot, unparsed: &mut HashSet<StateKey>) -> StateMap<OwnedEventId> {
    let mut map = StateMap::new();
    state.for_each(|key, id| {
        if let Ok(id) = OwnedEventId::try_from(id) {
            map.insert(
                (
                    ruma::events::StateEventType::from(key.event_type().as_str()),
                    key.state_key().to_owned(),
                ),
                id,
            );
        } else {
            unparsed.insert(key.clone());
        }
    });
    map
}

/// `resolved` as a snapshot, built on `base` so that it shares every
/// subtree the two have in common: only the slots that differ are written.
fn to_snapshot(
    base: &StateSnapshot,
    resolved: &StateMap<OwnedEventId>,
    unparsed: HashSet<StateKey>,
) -> StateSnapshot {
    let mut state = base.clone();
    let mut kept: HashSet<StateKey> = unparsed;
    for ((event_type, state_key), id) in resolved {
        let key = StateKey::new(event_type.to_string(), state_key.as_str());
        if state.get(&key) != Some(id.as_str()) {
            state = state.apply(key.clone(), id.as_str());
        }
        kept.insert(key);
    }
    let mut dropped = Vec::new();
    base.for_each(|key, _| {
        if !kept.contains(key) {
            dropped.push(key.clone());
        }
    });
    for key in dropped {
        state = state.remove(&key);
    }
    state
}

impl StateResolver for RoomResolver<'_> {
    fn resolve(&mut self, states: &[StateSnapshot]) -> Result<StateSnapshot, AppendError> {
        let generation = {
            let mut graph = self
                .graph
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            graph.refresh_missing(&|id| (self.body)(id).is_some());
            graph.generation
        };
        // Roots and rejection policy can stay identical when a missing auth
        // body arrives. The old answer must not survive that new evidence.
        let mut policy = blake3::Hasher::new();
        policy.update(&self.log.resolution_policy_id());
        policy.update(self.room_id.as_bytes());
        policy.update(&generation.to_be_bytes());
        let key = ResolutionCache::key(states, *policy.finalize().as_bytes());
        if let Some(hit) = self.cache.get(&key) {
            self.stats.cache_hits += 1;
            return Ok(hit);
        }
        let Some(base) = states.first() else {
            return Ok(StateSnapshot::new());
        };
        let mut unparsed = HashSet::new();
        let maps: Vec<StateMap<OwnedEventId>> = states
            .iter()
            .map(|state| to_map(state, &mut unparsed))
            .collect();
        if !unparsed.is_empty() {
            tracing::warn!(
                room = self.room_id,
                slots = unparsed.len(),
                "state names event IDs that do not parse; those slots keep their value"
            );
        }
        // Whatever an earlier resolution on this thread left uncounted is
        // not this one's.
        let _ = ruma::state_res::take_auth_rejections();
        let resolved = self.resolve_maps(&maps);
        self.stats.rejections += ruma::state_res::take_auth_rejections();
        let resolved = resolved.map_err(AppendError::ResolutionFailed)?;
        let state = to_snapshot(base, &resolved, unparsed);
        self.stats.resolutions += 1;
        self.cache.put(key, state.clone());
        Ok(state)
    }
}

#[cfg(test)]
#[path = "state_res_tests.rs"]
mod tests;
