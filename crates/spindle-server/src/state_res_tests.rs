//! The live resolver against ruma's reference resolution, on generated
//! contested forks in every room-version family.
//!
//! `RoomResolver` computes two of ruma's inputs itself -- the auth difference
//! (by Synapse's walk over a ranked auth DAG, instead of full chains) and
//! room 12's conflicted subgraph -- and builds the answer back into a trie on
//! top of the first parent's. Every one of those is a place to be subtly
//! wrong, so the reference here does it the slow, obvious way: full
//! inclusive auth chains for every state set, the subgraph by brute force,
//! and the result compared slot by slot.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use ruma::room_version_rules::{RoomVersionRules, StateResolutionVersion};
use ruma::state_res::StateMap;
use ruma::state_res::utils::event_id_set::EventIdSet;
use ruma::{OwnedEventId, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::{EventId, RoomLog, StateKey, StateResolver, StateSnapshot};

use super::{AuthGraph, ResolutionCache, RoomResolver};
use crate::authorize::StoredEvent;

const ALICE: &str = "@alice:example.org";
const BOB: &str = "@bob:example.org";
const CAROL: &str = "@carol:example.org";

/// A tiny deterministic generator: the fixtures must be reproducible from a
/// seed, and a property-testing shrinker would shrink toward forks too small
/// to contest anything.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

type Key = (String, String);

/// One room's events, and the state along one branch of it.
#[derive(Clone)]
struct Room {
    version: RoomVersionId,
    id: String,
    bodies: HashMap<String, Value>,
    depth: HashMap<String, u64>,
    state: BTreeMap<Key, String>,
    head: Option<String>,
    counter: u64,
    label: String,
}

impl Room {
    fn new(version: RoomVersionId) -> Self {
        let mut room = Self {
            version,
            id: String::new(),
            bodies: HashMap::new(),
            depth: HashMap::new(),
            state: BTreeMap::new(),
            head: None,
            counter: 0,
            label: String::new(),
        };
        let v12 = room.rules().authorization.room_create_event_id_as_room_id;
        room.id = if v12 {
            "!create".to_owned()
        } else {
            "!room:example.org".to_owned()
        };
        let mut create = json!({ "room_version": room.version.as_str() });
        if !v12 {
            create["creator"] = json!(ALICE);
        }
        room.add(ALICE, "m.room.create", Some(""), &create, 1);
        room.add(
            ALICE,
            "m.room.member",
            Some(ALICE),
            &json!({ "membership": "join" }),
            2,
        );
        let mut users = json!({ BOB: 50 });
        if !v12 {
            users[ALICE] = json!(100);
        }
        room.add(
            ALICE,
            "m.room.power_levels",
            Some(""),
            &json!({
                "users": users,
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
            }),
            3,
        );
        room.add(
            ALICE,
            "m.room.join_rules",
            Some(""),
            &json!({ "join_rule": "public" }),
            4,
        );
        room.add(
            BOB,
            "m.room.member",
            Some(BOB),
            &json!({ "membership": "join" }),
            5,
        );
        room.add(
            CAROL,
            "m.room.member",
            Some(CAROL),
            &json!({ "membership": "join" }),
            6,
        );
        room.add(
            ALICE,
            "m.room.topic",
            Some(""),
            &json!({ "topic": "base" }),
            7,
        );
        room
    }

    fn rules(&self) -> RoomVersionRules {
        spindle_core::rules_of(&self.version).expect("a known version")
    }

    fn names_by_origin(&self) -> bool {
        !spindle_core::version::names_events_by_hash(&self.version)
    }

    fn fork(&self, label: &str) -> Self {
        let mut fork = self.clone();
        label.clone_into(&mut fork.label);
        fork
    }

    fn reference(&self, id: &str) -> Value {
        if self.names_by_origin() {
            json!([id, { "sha256": "unchecked" }])
        } else {
            json!(id)
        }
    }

    /// The v1-v12 auth event selection, from this branch's state.
    fn auth_for(
        &self,
        sender: &str,
        kind: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Vec<String> {
        if kind == "m.room.create" {
            return Vec::new();
        }
        let v12 = self.rules().authorization.room_create_event_id_as_room_id;
        let mut keys: Vec<Key> = Vec::new();
        if !v12 {
            keys.push(("m.room.create".to_owned(), String::new()));
        }
        keys.push(("m.room.power_levels".to_owned(), String::new()));
        keys.push(("m.room.member".to_owned(), sender.to_owned()));
        if kind == "m.room.member" {
            if matches!(
                content["membership"].as_str(),
                Some("join" | "invite" | "knock")
            ) {
                keys.push(("m.room.join_rules".to_owned(), String::new()));
            }
            if let Some(target) = state_key.filter(|target| *target != sender) {
                keys.push(("m.room.member".to_owned(), target.to_owned()));
            }
        }
        keys.iter()
            .filter_map(|key| self.state.get(key).cloned())
            .collect()
    }

    fn add(
        &mut self,
        sender: &str,
        kind: &str,
        state_key: Option<&str>,
        content: &Value,
        ts: u64,
    ) -> String {
        self.counter += 1;
        let id = if kind == "m.room.create" && self.id == "!create" {
            "$create".to_owned()
        } else if self.names_by_origin() {
            format!("$e{}{}:example.org", self.counter, self.label)
        } else {
            format!("$e{}{}", self.counter, self.label)
        };
        let auth = self.auth_for(sender, kind, state_key, content);
        let prev: Vec<String> = self.head.iter().cloned().collect();
        let depth = prev
            .iter()
            .filter_map(|parent| self.depth.get(parent))
            .max()
            .map_or(0, |depth| depth + 1);
        let mut body = json!({
            "type": kind,
            "sender": sender,
            "content": content,
            "origin_server_ts": ts,
            "depth": depth,
            "prev_events": prev.iter().map(|id| self.reference(id)).collect::<Vec<_>>(),
            "auth_events": auth.iter().map(|id| self.reference(id)).collect::<Vec<_>>(),
        });
        if !(kind == "m.room.create" && self.id == "!create") {
            body["room_id"] = json!(self.id);
        }
        if let Some(state_key) = state_key {
            body["state_key"] = json!(state_key);
            self.state
                .insert((kind.to_owned(), state_key.to_owned()), id.clone());
        }
        if self.names_by_origin() {
            body["event_id"] = json!(id);
        }
        self.bodies.insert(id.clone(), body);
        self.depth.insert(id.clone(), depth);
        self.head = Some(id.clone());
        id
    }

    fn absorb(&mut self, other: &Self) {
        for (id, body) in &other.bodies {
            self.bodies
                .entry(id.clone())
                .or_insert_with(|| body.clone());
        }
    }

    fn snapshot(&self) -> StateSnapshot {
        let mut out = StateSnapshot::new();
        for ((kind, key), id) in &self.state {
            out = out.apply(StateKey::new(kind.as_str(), key.as_str()), id.as_str());
        }
        out
    }

    fn map(&self) -> StateMap<OwnedEventId> {
        self.state
            .iter()
            .map(|((kind, key), id)| {
                (
                    (kind.as_str().into(), key.clone()),
                    OwnedEventId::try_from(id.as_str()).expect("fixture IDs parse"),
                )
            })
            .collect()
    }

    fn stored(&self, id: &str) -> Option<StoredEvent> {
        StoredEvent::parse_in(id, &self.id, self.bodies.get(id)?).ok()
    }

    fn auth_of(&self, id: &str) -> Vec<String> {
        self.bodies
            .get(id)
            .map(|body| crate::rooms::edge_ids(&body["auth_events"]))
            .unwrap_or_default()
    }

    /// Every auth ancestor of `id`, not including it.
    fn ancestors(&self, id: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut frontier = self.auth_of(id);
        while let Some(next) = frontier.pop() {
            if out.insert(next.clone()) {
                frontier.extend(self.auth_of(&next));
            }
        }
        out
    }
}

/// One random operation on a branch: a state change some member makes,
/// authorized or not -- resolution has to cope with both.
fn operate(branch: &mut Room, rng: &mut Rng, clock: &mut u64) {
    // Clocks are deliberately not monotonic across branches: a branch's
    // server may be ahead of or behind the others.
    *clock = clock
        .saturating_add(rng.below(40))
        .saturating_sub(15)
        .max(10);
    let ts = *clock;
    let pick = |rng: &mut Rng| [ALICE, BOB, CAROL][usize::try_from(rng.below(3)).unwrap_or(0)];
    match rng.below(8) {
        0 | 1 => {
            let sender = pick(rng);
            branch.add(
                sender,
                "m.room.topic",
                Some(""),
                &json!({ "topic": format!("t{ts}") }),
                ts,
            );
        }
        2 => {
            let target = [BOB, CAROL][usize::try_from(rng.below(2)).unwrap_or(0)];
            let sender = pick(rng);
            let membership = ["ban", "leave"][usize::try_from(rng.below(2)).unwrap_or(0)];
            branch.add(
                sender,
                "m.room.member",
                Some(target),
                &json!({ "membership": membership }),
                ts,
            );
        }
        3 => {
            let level = [0, 50, 100][usize::try_from(rng.below(3)).unwrap_or(0)];
            let sender = [ALICE, BOB][usize::try_from(rng.below(2)).unwrap_or(0)];
            let v12 = branch.rules().authorization.room_create_event_id_as_room_id;
            let mut users = json!({ BOB: level, CAROL: 0 });
            if !v12 {
                users[ALICE] = json!(100);
            }
            branch.add(
                sender,
                "m.room.power_levels",
                Some(""),
                &json!({
                    "users": users,
                    "users_default": 0,
                    "events_default": 0,
                    "state_default": 50,
                    "ban": 50,
                    "kick": 50,
                }),
                ts,
            );
        }
        4 => {
            let rule = ["public", "invite"][usize::try_from(rng.below(2)).unwrap_or(0)];
            branch.add(
                ALICE,
                "m.room.join_rules",
                Some(""),
                &json!({ "join_rule": rule }),
                ts,
            );
        }
        5 => {
            let joiner = [BOB, CAROL][usize::try_from(rng.below(2)).unwrap_or(0)];
            branch.add(
                joiner,
                "m.room.member",
                Some(joiner),
                &json!({ "membership": "join" }),
                ts,
            );
        }
        6 => {
            let sender = pick(rng);
            branch.add(
                sender,
                "m.room.name",
                Some(""),
                &json!({ "name": format!("n{ts}") }),
                ts,
            );
        }
        _ => {
            let sender = pick(rng);
            branch.add(sender, "m.room.message", None, &json!({ "body": "hi" }), ts);
        }
    }
}

/// ruma's resolution, the slow obvious way: full inclusive auth chains and a
/// brute-force conflicted subgraph.
fn reference(graph: &Room, branches: &[Room]) -> BTreeMap<Key, String> {
    let rules = graph.rules();
    let maps: Vec<StateMap<OwnedEventId>> = branches.iter().map(Room::map).collect();
    let fetch = |id: &ruma::EventId| graph.stored(id.as_str());
    let resolved = match &rules.state_res {
        StateResolutionVersion::V1 => {
            crate::state_res_v1::resolve(&rules.authorization, &maps, |id| {
                graph.stored(id.as_str())
            })
            .expect("v1 resolves")
        }
        StateResolutionVersion::V2(v2) => {
            let chains: Vec<EventIdSet<OwnedEventId>> = maps
                .iter()
                .map(|map| {
                    let mut chain: BTreeSet<String> = BTreeSet::new();
                    for id in map.values() {
                        chain.insert(id.as_str().to_owned());
                        chain.extend(graph.ancestors(id.as_str()));
                    }
                    chain
                        .into_iter()
                        .map(|id| OwnedEventId::try_from(id.as_str()).expect("parses"))
                        .collect()
                })
                .collect();
            let subgraph = |conflicted: &StateMap<Vec<OwnedEventId>>| {
                let conflicted: HashSet<String> = conflicted
                    .values()
                    .flatten()
                    .map(|id| id.as_str().to_owned())
                    .collect();
                let mut out = EventIdSet::new();
                for id in graph.bodies.keys() {
                    let below = conflicted.iter().any(|c| graph.ancestors(c).contains(id));
                    let above = graph
                        .ancestors(id)
                        .iter()
                        .any(|ancestor| conflicted.contains(ancestor));
                    if (below && above) || conflicted.contains(id) {
                        out.insert(OwnedEventId::try_from(id.as_str()).expect("parses"));
                    }
                }
                Some(out)
            };
            ruma::state_res::resolve(
                &rules.authorization,
                v2,
                maps.iter(),
                chains,
                fetch,
                subgraph,
            )
            .expect("the reference resolves")
        }
        other => panic!("no reference for {other:?}"),
    };
    resolved
        .into_iter()
        .map(|((kind, key), id)| ((kind.to_string(), key), id.as_str().to_owned()))
        .collect()
}

fn ours(state: &StateSnapshot) -> BTreeMap<Key, String> {
    let mut out = BTreeMap::new();
    state.for_each(|key, id| {
        out.insert(
            (
                key.event_type().as_str().to_owned(),
                key.state_key().to_owned(),
            ),
            id.to_owned(),
        );
    });
    out
}

/// Build a contested fork from `seed` and resolve it both ways.
fn check(version: &RoomVersionId, seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let base = Room::new(version.clone());
    let branch_count = 2 + rng.below(2);
    let mut branches = Vec::new();
    let mut clock = 100;
    for index in 0..branch_count {
        let mut branch = base.fork(&format!("b{index}"));
        let mut branch_clock = clock + rng.below(30);
        for _ in 0..=rng.below(4) {
            operate(&mut branch, &mut rng, &mut branch_clock);
        }
        clock += 5;
        branches.push(branch);
    }
    let mut graph = base.fork("g");
    for branch in &branches {
        graph.absorb(branch);
    }

    let expected = reference(&graph, &branches);

    let rules = graph.rules();
    let log = RoomLog::new();
    let bodies = graph.bodies.clone();
    let body = move |id: &str| bodies.get(id).cloned();
    let auth_graph = Mutex::new(AuthGraph::default());
    let cache = ResolutionCache::default();
    let snapshots: Vec<StateSnapshot> = branches.iter().map(Room::snapshot).collect();
    let mut distinct: Vec<StateSnapshot> = Vec::new();
    for snapshot in snapshots {
        if !distinct.iter().any(|held| held.root() == snapshot.root()) {
            distinct.push(snapshot);
        }
    }
    if distinct.len() < 2 {
        return;
    }
    let mut resolver = RoomResolver::new(&rules, &graph.id, &log, &body, &auth_graph, &cache);
    let actual = resolver.resolve(&distinct).expect("our resolver resolves");
    assert_eq!(
        ours(&actual),
        expected,
        "room v{version}, seed {seed}: the live resolver disagrees with the reference"
    );
    // A second ask is a cache hit, and the same answer.
    let again = resolver.resolve(&distinct).expect("resolves again");
    assert_eq!(again.root(), actual.root());
    assert_eq!(resolver.stats.cache_hits, 1);
}

fn sweep(version: &RoomVersionId) {
    for seed in 1..=150 {
        check(version, seed);
    }
}

#[test]
fn room_version_1_agrees_with_the_reference() {
    sweep(&RoomVersionId::V1);
}

#[test]
fn room_version_2_agrees_with_the_reference() {
    sweep(&RoomVersionId::V2);
}

#[test]
fn room_version_6_agrees_with_the_reference() {
    sweep(&RoomVersionId::V6);
}

#[test]
fn room_version_9_agrees_with_the_reference() {
    sweep(&RoomVersionId::V9);
}

#[test]
fn room_version_10_agrees_with_the_reference() {
    sweep(&RoomVersionId::V10);
}

#[test]
fn room_version_11_agrees_with_the_reference() {
    sweep(&RoomVersionId::V11);
}

#[test]
fn room_version_12_agrees_with_the_reference() {
    sweep(&RoomVersionId::V12);
}

/// The walk's answer is the full chains' difference, on the generated forks.
#[test]
fn the_auth_difference_walk_equals_full_chains() {
    for version in [RoomVersionId::V6, RoomVersionId::V11, RoomVersionId::V12] {
        for seed in 1..=60 {
            let mut rng = Rng(seed * 7 + 3);
            let base = Room::new(version.clone());
            let mut branches = Vec::new();
            let mut clock = 100;
            for index in 0..2 {
                let mut branch = base.fork(&format!("b{index}"));
                for _ in 0..=rng.below(4) {
                    operate(&mut branch, &mut rng, &mut clock);
                }
                branches.push(branch);
            }
            let mut graph = base.fork("g");
            for branch in &branches {
                graph.absorb(branch);
            }
            let chains: Vec<BTreeSet<String>> = branches
                .iter()
                .map(|branch| {
                    let mut chain = BTreeSet::new();
                    for id in branch.state.values() {
                        chain.insert(id.clone());
                        chain.extend(graph.ancestors(id));
                    }
                    chain
                })
                .collect();
            let union: BTreeSet<String> = chains.iter().flatten().cloned().collect();
            let expected: BTreeSet<String> = union
                .into_iter()
                .filter(|id| !chains.iter().all(|chain| chain.contains(id)))
                .collect();

            let mut auth_graph = AuthGraph::default();
            let auth_of = |id: &str| Some(graph.auth_of(id));
            let sets: Vec<Vec<u32>> = branches
                .iter()
                .map(|branch| {
                    branch
                        .state
                        .values()
                        .map(|id| auth_graph.ensure(id, &auth_of))
                        .collect()
                })
                .collect();
            let walked: BTreeSet<String> = auth_graph
                .auth_difference(&sets)
                .into_iter()
                .filter_map(|index| auth_graph.node(index).map(|node| node.id.to_string()))
                .collect();
            assert_eq!(walked, expected, "room v{version}, seed {seed}");
        }
    }
}

/// A slot that resolves to nothing is removed, and the trie that results is
/// the one inserting the remaining slots alone would build.
#[test]
fn a_slot_resolved_away_is_removed_canonically() {
    let base = StateSnapshot::new()
        .apply(StateKey::new("m.room.create", ""), "$c")
        .apply(StateKey::new("m.room.topic", ""), "$t");
    let mut resolved = StateMap::new();
    resolved.insert(
        ("m.room.create".into(), String::new()),
        OwnedEventId::try_from("$c").expect("parses"),
    );
    let out = super::to_snapshot(&base, &resolved, HashSet::new());
    assert_eq!(out.len(), 1);
    assert_eq!(
        out.root(),
        StateSnapshot::new()
            .apply(StateKey::new("m.room.create", ""), "$c")
            .root()
    );
}

#[test]
fn auth_difference_includes_extremities_beyond_one_machine_word() {
    let mut graph = AuthGraph::default();
    let auth = |id: &str| {
        Some(if id == "$root" {
            Vec::new()
        } else {
            vec!["$root".to_owned()]
        })
    };
    let common = graph.ensure("$common", &auth);
    let last = graph.ensure("$last", &auth);
    let mut sets = vec![vec![common]; 64];
    sets.push(vec![last]);
    let found: std::collections::BTreeSet<_> = graph.auth_difference(&sets).into_iter().collect();
    assert_eq!(found, [common, last].into_iter().collect());
}

#[test]
fn changing_imported_rejection_policy_cannot_reuse_a_cached_resolution() {
    let cache = ResolutionCache::default();
    let states = [StateSnapshot::new()];
    let mut log = RoomLog::new();
    let original = ResolutionCache::key(&states, log.resolution_policy_id());
    cache.put(original.clone(), StateSnapshot::new());
    log.preserve_historical_rejection(EventId::new("$historical-ban"));
    let changed = ResolutionCache::key(&states, log.resolution_policy_id());
    assert_ne!(changed, original);
    assert!(cache.get(&changed).is_none());
    log.preserve_historical_rejection(EventId::new("$historical-ban"));
    assert_eq!(
        ResolutionCache::key(&states, log.resolution_policy_id()),
        changed
    );
}

#[test]
fn a_live_rejected_malformed_power_event_cannot_be_reconsidered() {
    let base = Room::new(RoomVersionId::V10);
    let power_key = ("m.room.power_levels".to_owned(), String::new());
    let original_power = base.state[&power_key].clone();
    let mut left = base.fork("left");
    let mut content = base.bodies[&original_power]["content"].clone();
    content["users"]["@bridge:*"] = json!(50);
    let malformed = left.add(ALICE, "m.room.power_levels", Some(""), &content, 100);
    left.add(
        ALICE,
        "m.room.topic",
        Some(""),
        &json!({"topic": "left"}),
        101,
    );
    // The peer's branch references the refused PDU in its auth chain. It
    // stays outside our accepted state but appears in the auth difference.
    left.state.insert(power_key.clone(), original_power.clone());
    let mut right = base.fork("right");
    let mut valid_content = base.bodies[&original_power]["content"].clone();
    valid_content["users"][BOB] = json!(45);
    let valid_power = right.add(ALICE, "m.room.power_levels", Some(""), &valid_content, 90);
    right.add(
        ALICE,
        "m.room.topic",
        Some(""),
        &json!({"topic": "right"}),
        102,
    );
    let mut room = base.clone();
    room.absorb(&left);
    room.absorb(&right);
    let mut log = RoomLog::new();
    let previous_policy = log.resolution_policy_id();
    log.restore_sidelined(
        spindle_core::SidelinedEntry {
            event_id: EventId::new(malformed.as_str()),
            prev_events: Vec::new(),
            depth: left.depth[&malformed],
            state_key: Some(StateKey::new("m.room.power_levels", "")),
            kind: spindle_core::Sideline::Rejected,
            state_root: StateSnapshot::new().root(),
        },
        StateSnapshot::new(),
    );
    assert_ne!(log.resolution_policy_id(), previous_policy);
    let rules = room.rules();
    let body = |id: &str| room.bodies.get(id).cloned();
    let graph = Mutex::new(AuthGraph::default());
    let cache = ResolutionCache::default();
    let mut resolver = RoomResolver::new(&rules, &room.id, &log, &body, &graph, &cache);
    let actual = resolver
        .resolve(&[left.snapshot(), right.snapshot()])
        .unwrap();
    assert_eq!(
        actual.get(&StateKey::new("m.room.power_levels", "")),
        Some(valid_power.as_str())
    );
}

#[test]
fn recovered_auth_body_rebuilds_ancestor_ranks_and_auth_difference() {
    let bodies = std::cell::RefCell::new(HashMap::from([
        ("$left", vec!["$late".to_owned()]),
        ("$right", vec!["$common".to_owned()]),
        ("$common", vec![]),
    ]));
    let auth = |id: &str| bodies.borrow().get(id).cloned();
    let mut graph = AuthGraph::default();
    graph.ensure("$left", &auth);
    graph.ensure("$right", &auth);
    assert!(graph.missing.contains("$late"));
    assert_eq!(graph.nodes[graph.index["$left"] as usize].rank, 1);
    let checked = std::cell::RefCell::new(Vec::new());
    graph.refresh_missing(&|id| {
        checked.borrow_mut().push(id.to_owned());
        bodies.borrow().contains_key(id)
    });
    assert_eq!(*checked.borrow(), ["$late"]);
    assert_eq!(
        graph.generation, 0,
        "an absent body does not invalidate a graph"
    );
    bodies
        .borrow_mut()
        .insert("$late", vec!["$common".to_owned()]);
    graph.refresh_missing(&|id| bodies.borrow().contains_key(id));
    assert_eq!(graph.generation, 1);
    let left = graph.ensure("$left", &auth);
    let right = graph.ensure("$right", &auth);
    assert_eq!(graph.nodes[left as usize].rank, 2);
    let difference: BTreeSet<_> = graph
        .auth_difference(&[vec![left], vec![right]])
        .into_iter()
        .map(|index| graph.nodes[index as usize].id.to_string())
        .collect();
    assert_eq!(
        difference,
        BTreeSet::from(["$left".to_owned(), "$right".to_owned(), "$late".to_owned()])
    );
    assert!(graph.missing.is_empty());
}

#[test]
fn a_recovered_auth_body_cannot_reuse_a_resolution_from_before_its_arrival() {
    let room = Room::new(RoomVersionId::V11);
    let rules = room.rules();
    let bodies = std::cell::RefCell::new(room.bodies.clone());
    let body = |id: &str| bodies.borrow().get(id).cloned();
    let graph = Mutex::new(AuthGraph::default());
    // A previous fork touched this unavailable auth ancestor.
    graph.lock().unwrap().ensure("$late", &|_| None);
    let cache = ResolutionCache::default();
    let log = RoomLog::new();
    let state = room.snapshot();
    let mut resolver = RoomResolver::new(&rules, &room.id, &log, &body, &graph, &cache);
    let first = resolver.resolve(&[state.clone(), state.clone()]).unwrap();
    resolver.resolve(&[state.clone(), state.clone()]).unwrap();
    assert_eq!(resolver.stats.cache_hits, 1);
    bodies
        .borrow_mut()
        .insert("$late".to_owned(), json!({"auth_events": []}));
    let recovered = resolver.resolve(&[state.clone(), state]).unwrap();
    assert_eq!(first.root(), recovered.root());
    assert_eq!(
        resolver.stats.resolutions, 2,
        "new auth evidence must force resolution"
    );
    assert_eq!(
        resolver.stats.cache_hits, 1,
        "the pre-recovery cache cannot answer"
    );
    assert_eq!(graph.lock().unwrap().generation, 1);
}
