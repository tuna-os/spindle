//! A spec-valid synthetic room, and ruma's reference resolver run over it.
//!
//! SPEC §19.2 makes `ruma-state-res` the correctness oracle for §9.3's
//! equivalence claim. Using it needs three things ruma does not hand out: an
//! [`Event`] implementation, a room whose auth chain actually satisfies the
//! v11 authorization rules, and the auth chains themselves. `ruma-state-res`
//! has helpers for all of this, but they are gated behind a private
//! `__criterion` feature and cannot be used from outside the crate, so this
//! module builds them.
//!
//! Everything here is deliberately built with ruma types. Our side of the
//! comparison is not (ADR 0002), which is what stops the comparison being
//! circular.
//!
//! Shared by the equivalence test and the comparison benchmark, each of which
//! uses a different part of it — hence the blanket `dead_code` allow, which is
//! about the two consumers rather than about anything here being unused.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ruma::state_res::{StateMap, events::Event, utils::event_id_set::EventIdSet};
use ruma::{
    EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UInt,
    UserId,
    events::{StateEventType, TimelineEventType},
    room_version_rules::RoomVersionRules,
};
use serde_json::{json, value::RawValue as RawJsonValue};

pub const ROOM: &str = "!oracle:example.org";
pub const ALICE: &str = "@alice:example.org";
pub const BOB: &str = "@bob:example.org";

/// A minimal PDU: exactly the fields `ruma-state-res` reads, and no others.
#[derive(Clone, Debug)]
pub struct TestPdu {
    pub event_id: OwnedEventId,
    pub room_id: OwnedRoomId,
    pub sender: OwnedUserId,
    pub origin_server_ts: MilliSecondsSinceUnixEpoch,
    pub event_type: TimelineEventType,
    pub content: Box<RawJsonValue>,
    pub state_key: Option<String>,
    pub prev_events: Vec<OwnedEventId>,
    pub auth_events: Vec<OwnedEventId>,
}

impl Event for TestPdu {
    type Id = OwnedEventId;

    fn event_id(&self) -> &Self::Id {
        &self.event_id
    }

    fn room_id(&self) -> Option<&RoomId> {
        Some(&self.room_id)
    }

    fn sender(&self) -> &UserId {
        &self.sender
    }

    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        self.origin_server_ts
    }

    fn event_type(&self) -> &TimelineEventType {
        &self.event_type
    }

    fn content(&self) -> &RawJsonValue {
        &self.content
    }

    fn state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }

    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.prev_events.iter())
    }

    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.auth_events.iter())
    }

    fn redacts(&self) -> Option<&Self::Id> {
        None
    }

    fn rejected(&self) -> bool {
        false
    }
}

/// Accumulates a room whose events satisfy the v11 authorization rules.
///
/// The auth-event selection is not decoration: `resolve()` walks auth chains to
/// build its conflicted subgraph, and a room whose events name the wrong auth
/// events produces a resolution that is wrong in ways that look like a bug in
/// whatever is being compared against it.
pub struct RoomBuilder {
    events: HashMap<OwnedEventId, TestPdu>,
    /// Current state by `(type, state_key)`, used to pick auth events.
    state: BTreeMap<(TimelineEventType, String), OwnedEventId>,
    /// The most recent event, which is this branch's single `prev_event`.
    head: Option<OwnedEventId>,
    /// Distinguishes IDs generated after a fork, so two branches that both
    /// descend from the same ancestor cannot mint the same event ID.
    branch: String,
    counter: u64,
    timestamp: u64,
}

impl RoomBuilder {
    /// A room with a creator, a join, power levels and join rules — the
    /// smallest graph that authorizes anything else.
    pub fn new() -> Self {
        let mut builder = Self {
            events: HashMap::new(),
            state: BTreeMap::new(),
            head: None,
            branch: String::new(),
            counter: 0,
            timestamp: 1,
        };

        builder.add(
            ALICE,
            TimelineEventType::RoomCreate,
            Some(String::new()),
            &json!({ "room_version": "11" }),
        );
        builder.add(
            ALICE,
            TimelineEventType::RoomMember,
            Some(ALICE.to_owned()),
            &json!({ "membership": "join" }),
        );
        builder.add(
            ALICE,
            TimelineEventType::RoomPowerLevels,
            Some(String::new()),
            &json!({
                "users": { ALICE: 100 },
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
            }),
        );
        builder.add(
            ALICE,
            TimelineEventType::RoomJoinRules,
            Some(String::new()),
            &json!({ "join_rule": "public" }),
        );
        builder
    }

    /// Append one event, wiring its auth events per the v11 selection rules.
    pub fn add(
        &mut self,
        sender: &str,
        event_type: TimelineEventType,
        state_key: Option<String>,
        content: &serde_json::Value,
    ) -> OwnedEventId {
        self.counter += 1;
        self.timestamp += 1;
        let event_id = EventId::parse(format!("$event{}{}:example.org", self.counter, self.branch))
            .expect("a generated event ID is valid");

        let auth_events = self.auth_events_for(sender, &event_type, state_key.as_deref());
        let prev_events = self.heads();

        let pdu = TestPdu {
            event_id: event_id.clone(),
            room_id: RoomId::parse(ROOM).expect("a constant room ID is valid"),
            sender: UserId::parse(sender).expect("a constant user ID is valid"),
            origin_server_ts: MilliSecondsSinceUnixEpoch(
                UInt::new(self.timestamp).expect("a small timestamp fits"),
            ),
            event_type: event_type.clone(),
            content: serde_json::value::to_raw_value(content).expect("content serializes"),
            state_key: state_key.clone(),
            prev_events,
            auth_events,
        };

        if let Some(key) = state_key {
            self.state.insert((event_type, key), event_id.clone());
        }
        self.events.insert(event_id.clone(), pdu);
        self.head = Some(event_id.clone());
        event_id
    }

    /// The v11 auth-event selection: create, the sender's membership, power
    /// levels, and — for a join or leave — join rules.
    fn auth_events_for(
        &self,
        sender: &str,
        event_type: &TimelineEventType,
        state_key: Option<&str>,
    ) -> Vec<OwnedEventId> {
        if *event_type == TimelineEventType::RoomCreate {
            return Vec::new();
        }

        let mut auth = Vec::new();
        let mut push = |key: (TimelineEventType, String)| {
            if let Some(id) = self.state.get(&key) {
                auth.push(id.clone());
            }
        };
        push((TimelineEventType::RoomCreate, String::new()));
        push((TimelineEventType::RoomPowerLevels, String::new()));
        push((TimelineEventType::RoomMember, sender.to_owned()));

        if *event_type == TimelineEventType::RoomMember {
            push((TimelineEventType::RoomJoinRules, String::new()));
            // The target's current membership, when it differs from the sender's.
            if let Some(target) = state_key.filter(|target| *target != sender) {
                push((TimelineEventType::RoomMember, target.to_owned()));
            }
        }
        auth
    }

    fn heads(&self) -> Vec<OwnedEventId> {
        // Each branch is linear by construction; the fork is between branches.
        self.head.iter().cloned().collect()
    }

    /// The state map as ruma wants it: `(type, state_key) -> event_id`.
    pub fn state_map(&self) -> StateMap<OwnedEventId> {
        self.state
            .iter()
            .map(|((event_type, key), id)| {
                ((state_event_type(event_type), key.clone()), id.clone())
            })
            .collect()
    }

    /// The full auth chain of every event in a state map, transitively.
    pub fn auth_chain(&self, state: &StateMap<OwnedEventId>) -> BTreeSet<OwnedEventId> {
        let mut chain = BTreeSet::new();
        let mut frontier: Vec<OwnedEventId> = state.values().cloned().collect();
        while let Some(id) = frontier.pop() {
            if !chain.insert(id.clone()) {
                continue;
            }
            if let Some(event) = self.events.get(&id) {
                frontier.extend(event.auth_events.iter().cloned());
            }
        }
        chain
    }

    pub fn get(&self, id: &EventId) -> Option<TestPdu> {
        self.events.get(id).cloned()
    }

    /// A snapshot of the builder, so two forks can diverge from one ancestor.
    ///
    /// `label` distinguishes the IDs each branch mints from here on. Without
    /// it both branches number from the same counter and collide, which looks
    /// exactly like a duplicate-event bug in whatever is consuming the graph.
    pub fn fork(&self, label: &str) -> Self {
        Self {
            events: self.events.clone(),
            state: self.state.clone(),
            head: self.head.clone(),
            branch: label.to_owned(),
            counter: self.counter,
            timestamp: self.timestamp,
        }
    }

    /// Merge another fork's events into this one, so the resolver can see both
    /// sides of the graph.
    pub fn absorb(&mut self, other: &Self) {
        for (id, event) in &other.events {
            self.events
                .entry(id.clone())
                .or_insert_with(|| event.clone());
        }
    }
}

/// `StateMap` is keyed by `StateEventType`; the builder tracks
/// `TimelineEventType` because that is what an `Event` reports.
pub fn state_event_type(event_type: &TimelineEventType) -> StateEventType {
    StateEventType::from(event_type.to_string())
}

/// Run ruma's reference resolver over two state maps.
///
/// This is the oracle. Everything it returns is the specification's answer by
/// definition; disagreement is our bug until proven otherwise.
pub fn reference_resolve(
    graph: &RoomBuilder,
    left: &StateMap<OwnedEventId>,
    right: &StateMap<OwnedEventId>,
) -> StateMap<OwnedEventId> {
    let chains = auth_chains(graph, left, right);
    reference_resolve_with_chains(graph, left, right, chains)
}

/// Auth chains for a pair of state maps, computed once.
///
/// A homeserver stores auth chains; it does not walk the graph to rebuild them
/// on every resolution. Computing them inside a timed loop would charge the
/// reference resolver for work a real deployment has already done, so the
/// benchmark hoists this out and only `reference_resolve_with_chains` is timed.
pub fn auth_chains(
    graph: &RoomBuilder,
    left: &StateMap<OwnedEventId>,
    right: &StateMap<OwnedEventId>,
) -> Vec<EventIdSet<OwnedEventId>> {
    vec![
        graph.auth_chain(left).into_iter().collect(),
        graph.auth_chain(right).into_iter().collect(),
    ]
}

/// As [`reference_resolve`], but with the auth chains supplied.
pub fn reference_resolve_with_chains(
    graph: &RoomBuilder,
    left: &StateMap<OwnedEventId>,
    right: &StateMap<OwnedEventId>,
    chains: Vec<EventIdSet<OwnedEventId>>,
) -> StateMap<OwnedEventId> {
    let rules = RoomVersionRules::V11;
    let state_res_rules = match rules.state_res {
        ruma::room_version_rules::StateResolutionVersion::V2(rules) => rules,
        other => panic!("room version 11 must use state resolution v2, got {other:?}"),
    };

    ruma::state_res::resolve(
        &rules.authorization,
        &state_res_rules,
        [left, right],
        chains,
        |id| graph.get(id),
        |_conflicted| None,
    )
    .expect("the reference resolver must succeed on a spec-valid room")
}
