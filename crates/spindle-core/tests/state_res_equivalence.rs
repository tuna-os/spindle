//! #34 / SPEC §19.2, revisited by ADR 0005: the fork merge against ruma's
//! reference state resolver.
//!
//! SPEC §9.3 used to claim that SPEC §9.2's fork merge -- take a slot only
//! one branch moved, refuse a slot both moved -- produces exactly what state
//! resolution would. The tests here used to check that claim on forks built
//! to satisfy it, and on those it held. It does not hold in general, and the
//! counterexamples below are why the merge is gone from the live path:
//!
//! - **A ban voids the other branch's write.** State resolution re-checks
//!   every conflicted event against the resolved power events, so a topic
//!   set on one branch by a user the other branch banned is dropped. The
//!   merge took it, because only one branch moved the topic.
//! - **Clocks decide ties.** Two values for one slot are ordered by their
//!   power level's mainline and then by `origin_server_ts`, not by which
//!   one descends from the other. A branch whose server's clock runs behind
//!   loses a slot it moved, to the value it moved it from.
//!
//! Each would leave Spindle and every Synapse in the room holding different
//! current state, with nothing that ever converges them. So the log no
//! longer decides any fork whose tips' states differ: it asks the room
//! version's resolver (`spindle_server::state_res`), and the last test here
//! checks that what it does with the answer is exactly the answer.

mod oracle;

use std::collections::BTreeMap;

use oracle::{ALICE, BOB, RoomBuilder, reference_resolve};
use ruma::state_res::StateMap;
use ruma::{OwnedEventId, events::TimelineEventType};
use serde_json::json;
use spindle_core::{
    AppendError, EventId, EventInput, RoomLog, StateKey, StateResolver, StateSnapshot,
};

fn normalize(state: &StateMap<OwnedEventId>) -> BTreeMap<(String, String), String> {
    state
        .iter()
        .map(|((event_type, key), id)| {
            (
                (event_type.to_string(), key.clone()),
                id.as_str().to_owned(),
            )
        })
        .collect()
}

fn normalize_ours(state: &StateSnapshot) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    state.for_each(|key, event_id| {
        out.insert(
            (
                key.event_type().as_str().to_owned(),
                key.state_key().to_owned(),
            ),
            event_id.to_owned(),
        );
    });
    out
}

/// SPEC §9.2's retired fork merge, kept here as the thing the counterexamples
/// are counterexamples to: per slot, a value only one branch moved away from
/// the base wins; a slot both moved is a conflict (`None`).
fn retired_merge(
    base: &StateMap<OwnedEventId>,
    left: &StateMap<OwnedEventId>,
    right: &StateMap<OwnedEventId>,
) -> Option<BTreeMap<(String, String), String>> {
    let (base, left, right) = (normalize(base), normalize(left), normalize(right));
    let mut keys: Vec<&(String, String)> = left.keys().chain(right.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = BTreeMap::new();
    for key in keys {
        let inherited = base.get(key);
        let claims: Vec<&String> = [left.get(key), right.get(key)]
            .into_iter()
            .flatten()
            .filter(|value| Some(*value) != inherited)
            .collect();
        let value = match claims.as_slice() {
            [] => inherited?,
            [only] => *only,
            [first, second] if first == second => *first,
            _ => return None,
        };
        out.insert(key.clone(), value.clone());
    }
    Some(out)
}

/// A room where Bob is joined with the power to set the topic.
fn room_with_bob() -> RoomBuilder {
    let mut base = RoomBuilder::new();
    base.add(
        ALICE,
        TimelineEventType::RoomPowerLevels,
        Some(String::new()),
        &json!({
            "users": { ALICE: 100, BOB: 50 },
            "users_default": 0,
            "events_default": 0,
            "state_default": 50,
        }),
    );
    base.add(
        BOB,
        TimelineEventType::RoomMember,
        Some(BOB.to_owned()),
        &json!({ "membership": "join" }),
    );
    base
}

#[test]
fn a_ban_on_one_branch_voids_the_other_branchs_write() {
    let base = room_with_bob();

    let mut left = base.fork("-l");
    let topic = left.add(
        BOB,
        TimelineEventType::RoomTopic,
        Some(String::new()),
        &json!({ "topic": "set by bob" }),
    );
    let mut right = base.fork("-r");
    let ban = right.add(
        ALICE,
        TimelineEventType::RoomMember,
        Some(BOB.to_owned()),
        &json!({ "membership": "ban" }),
    );

    let mut graph = left.fork("-g");
    graph.absorb(&right);
    let reference = normalize(&reference_resolve(
        &graph,
        &left.state_map(),
        &right.state_map(),
    ));
    let merged = retired_merge(&base.state_map(), &left.state_map(), &right.state_map())
        .expect("the branches moved different slots, which the merge took as no conflict");

    let topic_key = ("m.room.topic".to_owned(), String::new());
    let bob_key = ("m.room.member".to_owned(), BOB.to_owned());
    assert_eq!(reference.get(&bob_key), Some(&ban.as_str().to_owned()));
    assert_eq!(
        reference.get(&topic_key),
        None,
        "state resolution drops a write by a user the other branch banned"
    );
    assert_eq!(merged.get(&topic_key), Some(&topic.as_str().to_owned()));
    assert_ne!(merged, reference, "the retired merge and state resolution disagree");
}

#[test]
fn a_clock_that_runs_behind_loses_a_slot_only_its_branch_moved() {
    let mut base = RoomBuilder::new();
    base.set_clock(1_000);
    let first = base.add(
        ALICE,
        TimelineEventType::RoomTopic,
        Some(String::new()),
        &json!({ "topic": "before the fork" }),
    );

    // The left branch's server runs behind: its topic is causally after the
    // base topic and stamped before it.
    let mut left = base.fork("-l");
    left.set_clock(500);
    let behind = left.add(
        ALICE,
        TimelineEventType::RoomTopic,
        Some(String::new()),
        &json!({ "topic": "from a slow clock" }),
    );
    let mut right = base.fork("-r");
    right.add(
        ALICE,
        TimelineEventType::RoomName,
        Some(String::new()),
        &json!({ "name": "elsewhere" }),
    );

    let mut graph = left.fork("-g");
    graph.absorb(&right);
    let reference = normalize(&reference_resolve(
        &graph,
        &left.state_map(),
        &right.state_map(),
    ));
    let merged = retired_merge(&base.state_map(), &left.state_map(), &right.state_map())
        .expect("only the left branch moved the topic");

    let topic_key = ("m.room.topic".to_owned(), String::new());
    assert_eq!(merged.get(&topic_key), Some(&behind.as_str().to_owned()));
    assert_eq!(
        reference.get(&topic_key),
        Some(&first.as_str().to_owned()),
        "state resolution orders the two topics by timestamp, and the older one is stamped later"
    );
}

/// A resolver that asks ruma, over one fixture graph.
struct Oracle<'a> {
    graph: &'a RoomBuilder,
    calls: usize,
}

impl StateResolver for Oracle<'_> {
    fn resolve(&mut self, states: &[StateSnapshot]) -> Result<StateSnapshot, AppendError> {
        self.calls += 1;
        let maps: Vec<StateMap<OwnedEventId>> = states
            .iter()
            .map(|state| {
                let mut map = StateMap::new();
                state.for_each(|key, id| {
                    map.insert(
                        (
                            key.event_type().as_str().into(),
                            key.state_key().to_owned(),
                        ),
                        OwnedEventId::try_from(id).expect("fixture IDs parse"),
                    );
                });
                map
            })
            .collect();
        let [left, right] = maps.as_slice() else {
            panic!("the fixture forks two ways");
        };
        let resolved = reference_resolve(self.graph, left, right);
        let mut out = StateSnapshot::new();
        for ((event_type, key), id) in resolved {
            out = out.apply(StateKey::new(event_type.to_string(), key), id.as_str());
        }
        Ok(out)
    }
}

/// Replay a branch's state events into the log as a chain from `parent`.
fn replay(log: &mut RoomLog, branch: &RoomBuilder, base: &RoomBuilder, parent: &str) -> String {
    let base_ids: std::collections::BTreeSet<String> = base
        .state_map()
        .values()
        .map(|id| id.as_str().to_owned())
        .collect();
    let mut head = parent.to_owned();
    let mut writes: Vec<(String, (String, String))> = branch
        .state_map()
        .into_iter()
        .filter(|(_, id)| !base_ids.contains(id.as_str()))
        .map(|((event_type, key), id)| (id.as_str().to_owned(), (event_type.to_string(), key)))
        .collect();
    writes.sort();
    for (id, (event_type, key)) in writes {
        log.append_remote(
            EventInput::new(id.clone(), vec![EventId::new(head)])
                .with_state_key(StateKey::new(event_type, key)),
        )
        .unwrap();
        head = id;
    }
    head
}

#[test]
fn the_log_takes_the_resolvers_answer_and_nothing_else() {
    let base = room_with_bob();
    let mut left = base.fork("-l");
    left.add(
        BOB,
        TimelineEventType::RoomTopic,
        Some(String::new()),
        &json!({ "topic": "set by bob" }),
    );
    let mut right = base.fork("-r");
    right.add(
        ALICE,
        TimelineEventType::RoomMember,
        Some(BOB.to_owned()),
        &json!({ "membership": "ban" }),
    );
    let mut graph = left.fork("-g");
    graph.absorb(&right);

    let mut log = RoomLog::new();
    let mut shared: Vec<(String, (String, String))> = base
        .state_map()
        .into_iter()
        .map(|((event_type, key), id)| (id.as_str().to_owned(), (event_type.to_string(), key)))
        .collect();
    shared.sort();
    let mut head: Option<String> = None;
    for (id, (event_type, key)) in shared {
        let prev = head.iter().map(|id| EventId::new(id.as_str())).collect();
        log.append_remote(EventInput::new(id.clone(), prev).with_state_key(StateKey::new(event_type, key)))
            .unwrap();
        head = Some(id);
    }
    let ancestor = head.unwrap();
    let left_head = replay(&mut log, &left, &base, &ancestor);
    let right_head = replay(&mut log, &right, &base, &ancestor);
    assert_eq!(log.forward_extremities().len(), 2);

    let prev = vec![EventId::new(left_head), EventId::new(right_head)];
    let mut oracle = Oracle {
        graph: &graph,
        calls: 0,
    };
    let mut no_store = |_: &spindle_core::StateRoot| -> Option<Vec<u8>> {
        panic!("the tips' states are resident")
    };
    let before = log.resolve_parents(&prev, &mut oracle, &mut no_store).unwrap();
    let merged = log
        .append_resolved(EventInput::new("$merge", prev), before)
        .unwrap()
        .li;
    assert_eq!(oracle.calls, 1);
    assert_eq!(
        normalize_ours(log.state_after(merged).unwrap()),
        normalize(&reference_resolve(&graph, &left.state_map(), &right.state_map())),
    );
}

/// A fork whose tips hold different states is never merged by the log
/// itself: the strict form refuses and names the slot, whatever the slot.
#[test]
fn a_fork_whose_states_differ_is_never_merged_without_a_resolver() {
    let mut log = RoomLog::new();
    let root = log
        .append_local("$root", Some(StateKey::new("m.room.create", "")))
        .unwrap()
        .event_id
        .clone();

    log.append_remote(
        EventInput::new("$left", vec![root.clone()]).with_state_key(StateKey::new("m.room.topic", "")),
    )
    .unwrap();
    log.append_remote(
        EventInput::new("$right", vec![root]).with_state_key(StateKey::new("m.room.name", "")),
    )
    .unwrap();

    match log.append_local("$merge", None).unwrap_err() {
        AppendError::NeedsStateResolution { key, candidates } => {
            assert!(
                key == StateKey::new("m.room.topic", "") || key == StateKey::new("m.room.name", ""),
                "{key:?}"
            );
            assert_eq!(candidates.len(), 1);
        }
        other => panic!("differing tips must reach a resolver, got {other:?}"),
    }
}
