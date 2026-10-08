use std::collections::BTreeMap;

use proptest::prelude::*;
use spindle_core::{
    AppendError, EventId, EventInput, ForkWindowError, RoomLog, Sideline, StateKey, StateResolver,
    StateSnapshot,
};

#[test]
fn stale_remote_event_is_joined_by_the_next_local_event() {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$one", None).unwrap();
    room.append_local("$two", None).unwrap();

    room.append_remote(EventInput::new("$remote", vec![EventId::new("$one")]))
        .unwrap();
    assert_eq!(room.forward_extremities().len(), 2);

    let merge = room.append_local("$merge", None).unwrap();
    assert_eq!(merge.prev_events.len(), 2);
    assert!(merge.prev_events.contains(&EventId::new("$two")));
    assert!(merge.prev_events.contains(&EventId::new("$remote")));
    assert_eq!(room.forward_extremities().len(), 1);
}

#[test]
fn conflicting_state_fork_requires_the_matrix_resolver() {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic-a", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    room.append_remote(
        EventInput::new("$topic-b", vec![EventId::new("$create")])
            .with_state_key(StateKey::new("m.room.topic", "")),
    )
    .unwrap();

    assert!(matches!(
        room.append_local("$merge", None),
        Err(AppendError::NeedsStateResolution { .. })
    ));
}

/// A resolver for the log's own tests: counts its calls and answers with
/// the union of the states, later ones winning. Not any room version's
/// algorithm -- the core does not know one -- which is the point: these
/// tests are about *when* the log asks and what it does with the answer.
#[derive(Default)]
struct Recording {
    calls: usize,
}

impl StateResolver for Recording {
    fn resolve(&mut self, states: &[StateSnapshot]) -> Result<StateSnapshot, AppendError> {
        self.calls += 1;
        let mut out = states.first().cloned().unwrap_or_default();
        for other in states.iter().skip(1) {
            for (key, _, theirs) in out.clone().diff(other) {
                if let Some(theirs) = theirs {
                    out = out.apply(key.clone(), theirs);
                }
            }
        }
        Ok(out)
    }
}

fn no_store(_: &spindle_core::StateRoot) -> Option<Vec<u8>> {
    panic!("the state of a recent event is resident")
}

/// Append through the server's path: resolve the parents, then append.
fn append_resolved(
    room: &mut RoomLog,
    resolver: &mut Recording,
    input: EventInput,
) -> Result<(), AppendError> {
    let before = room.resolve_parents(&input.prev_events, resolver, &mut no_store)?;
    room.append_resolved(input, before)?;
    if room.forward_extremities().len() > 1 {
        let current = room.resolve_current(resolver, &mut no_store)?;
        room.set_current(current);
    }
    Ok(())
}

/// Parents that disagree on any slot are the resolver's, whether or not
/// the slot held a value at the fork.
///
/// SPEC 9.2 used to merge a fork whose branches moved different slots
/// without asking (#225), on the claim that it equals state resolution.
/// It does not in general -- a branch that banned the sender of the other
/// branch's write, or clocks that order two writes against their causal
/// order, both change the answer (ADR 0005) -- so the log no longer
/// decides: the strict form refuses, and a resolver is asked.
#[test]
fn a_disjoint_fork_is_the_resolvers_whether_or_not_the_slots_were_already_set() {
    for preset in [false, true] {
        let mut room = RoomLog::new();
        room.append_local("$create", Some(StateKey::new("m.room.create", "")))
            .unwrap();
        if preset {
            room.append_local("$topic0", Some(StateKey::new("m.room.topic", "")))
                .unwrap();
            room.append_local("$name0", Some(StateKey::new("m.room.name", "")))
                .unwrap();
        }
        let base = room.forward_extremities().iter().next().unwrap().clone();

        room.append_local("$topic-ours", Some(StateKey::new("m.room.topic", "")))
            .unwrap();
        room.append_remote(
            EventInput::new("$name-theirs", vec![base])
                .with_state_key(StateKey::new("m.room.name", "")),
        )
        .unwrap();
        assert_eq!(room.forward_extremities().len(), 2);

        assert!(
            matches!(
                room.clone().append_local("$merge", None),
                Err(AppendError::NeedsStateResolution { .. })
            ),
            "preset={preset}: the strict form must not merge differing states"
        );

        let mut resolver = Recording::default();
        let prev: Vec<EventId> = room.authoring_extremities().cloned().collect();
        let tips: Vec<StateSnapshot> = prev
            .iter()
            .map(|tip| room.state_after_event(tip).unwrap().clone())
            .collect();
        append_resolved(&mut room, &mut resolver, EventInput::new("$merge", prev)).unwrap();
        assert!(resolver.calls >= 1, "preset={preset}");
        // Whatever the resolver said is the merge's state, exactly.
        let expected = Recording::default().resolve(&tips).unwrap();
        let state = room.state_after_event(&EventId::new("$merge")).unwrap();
        assert_eq!(state.root(), expected.root(), "preset={preset}");
        assert_eq!(
            state.get(&StateKey::new("m.room.name", "")),
            Some("$name-theirs"),
            "preset={preset}"
        );
    }
}

/// Parents holding the same state are never resolved: the one case the
/// old fork merge provably shares with every room version's algorithm.
#[test]
fn parents_that_agree_cost_no_resolution() {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();
    room.append_local("$ours", None).unwrap();
    room.append_remote(EventInput::new("$theirs", vec![base]))
        .unwrap();
    assert_eq!(room.forward_extremities().len(), 2);

    let mut resolver = Recording::default();
    let prev: Vec<EventId> = room.authoring_extremities().cloned().collect();
    append_resolved(&mut room, &mut resolver, EventInput::new("$merge", prev)).unwrap();
    assert_eq!(resolver.calls, 0, "two messages on one state need nothing");
    assert_eq!(room.forward_extremities().len(), 1);
}

/// The state before an event is its parents' states resolved, not the
/// state after whichever entry happens to precede it in linear order.
///
/// The two are the same thing in a linear room. After a fork they part:
/// the entry before the merge event belongs to one branch, while the merge
/// event was authorized against the resolution of both.
#[test]
fn the_state_before_a_merge_event_is_the_resolution_of_both_branches() {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();
    room.append_local("$topic-ours", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    room.append_remote(
        EventInput::new("$name-theirs", vec![base.clone()])
            .with_state_key(StateKey::new("m.room.name", "")),
    )
    .unwrap();
    let mut resolver = Recording::default();
    let prev: Vec<EventId> = room.authoring_extremities().cloned().collect();
    append_resolved(&mut room, &mut resolver, EventInput::new("$merge", prev)).unwrap();

    let before = room
        .state_before(&EventId::new("$merge"), &mut resolver, &mut no_store)
        .unwrap();
    assert_eq!(
        before.get(&StateKey::new("m.room.topic", "")),
        Some("$topic-ours"),
        "our branch's write is missing from the state before the merge"
    );
    assert_eq!(
        before.get(&StateKey::new("m.room.name", "")),
        Some("$name-theirs"),
        "their branch's write is missing from the state before the merge"
    );
    assert_eq!(
        before.root(),
        room.state_after_event(&EventId::new("$merge"))
            .unwrap()
            .root(),
        "a message changes nothing, so before and after it agree"
    );

    // In the linear stretch the state before is the one parent's.
    let calls = resolver.calls;
    let before = room
        .state_before(&EventId::new("$topic-ours"), &mut resolver, &mut no_store)
        .unwrap();
    assert_eq!(resolver.calls, calls, "one parent is never resolved");
    assert_eq!(before.get(&StateKey::new("m.room.topic", "")), None);
    assert_eq!(before.root(), room.state_after_event(&base).unwrap().root());

    // And before the create event there is no state at all.
    let before = room
        .state_before(&EventId::new("$create"), &mut resolver, &mut no_store)
        .unwrap();
    assert!(before.is_empty());

    assert_eq!(
        room.state_before(&EventId::new("$nowhere"), &mut resolver, &mut no_store)
            .unwrap_err(),
        AppendError::UnknownPredecessor(EventId::new("$nowhere"))
    );
}

/// The same slot on both branches is refused by the strict form, preset
/// or not.
#[test]
fn a_same_slot_fork_still_needs_the_resolver_when_the_slot_was_already_set() {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic0", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();

    room.append_local("$topic-a", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    room.append_remote(
        EventInput::new("$topic-b", vec![base]).with_state_key(StateKey::new("m.room.topic", "")),
    )
    .unwrap();

    assert!(matches!(
        room.append_local("$merge", None),
        Err(AppendError::NeedsStateResolution { .. })
    ));
}

/// The room's current state is the one extremity's state, or -- with a
/// fork open -- the resolution recorded for the extremities, never simply
/// the newest entry's.
#[test]
fn the_current_state_is_the_resolution_of_the_forward_extremities() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();
    room.append_local("$topic-ours", Some(topic.clone()))
        .unwrap();
    assert!(room.current_is_settled());
    assert_eq!(
        room.current_state().unwrap().get(&topic),
        Some("$topic-ours")
    );

    let mut resolver = Recording::default();
    append_resolved(
        &mut room,
        &mut resolver,
        EventInput::new("$name-theirs", vec![base])
            .with_state_key(StateKey::new("m.room.name", "")),
    )
    .unwrap();
    assert_eq!(room.forward_extremities().len(), 2);
    assert!(room.current_is_settled());
    let current = room.current_state().unwrap();
    assert_eq!(
        current.get(&topic),
        Some("$topic-ours"),
        "the newest entry is their branch, which never set a topic"
    );
    assert_eq!(
        current.get(&StateKey::new("m.room.name", "")),
        Some("$name-theirs")
    );
}

/// A rejected event is held for the DAG and changes nothing: no state, no
/// extremity, no place in the timeline. A child that names it sits on the
/// state before it.
#[test]
fn a_rejected_event_changes_no_state_and_no_extremity() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    let head = room.forward_extremities().iter().next().unwrap().clone();
    let before = room
        .resolve_parents(
            std::slice::from_ref(&head),
            &mut Recording::default(),
            &mut no_store,
        )
        .unwrap();
    room.sideline(
        EventInput::new("$bad", vec![head.clone()]).with_state_key(topic.clone()),
        before.clone(),
        Sideline::Rejected,
    )
    .unwrap();

    assert!(room.holds(&EventId::new("$bad")));
    assert!(
        room.get(&EventId::new("$bad")).is_none(),
        "not in the timeline"
    );
    assert_eq!(room.len(), 1);
    assert_eq!(
        room.forward_extremities().iter().collect::<Vec<_>>(),
        vec![&head]
    );
    let after = room
        .state_after_any(&EventId::new("$bad"), &mut no_store)
        .unwrap();
    assert_eq!(
        after.root(),
        before.root(),
        "a rejected event moves no state"
    );

    // A child naming it sits on the state before it.
    let mut resolver = Recording::default();
    append_resolved(
        &mut room,
        &mut resolver,
        EventInput::new("$child", vec![EventId::new("$bad")]),
    )
    .unwrap();
    assert_eq!(
        room.state_after_event(&EventId::new("$child"))
            .unwrap()
            .get(&topic),
        None
    );
    // The child is a new tip; the rejected event never was one, so the
    // create event stays a tip beside it.
    assert_eq!(room.forward_extremities().len(), 2);
}

/// A soft-failed event is kept from the timeline and the extremities, but
/// its state is real: a child that names it inherits its write.
#[test]
fn a_soft_failed_event_keeps_its_state_for_its_children() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    let head = room.forward_extremities().iter().next().unwrap().clone();
    let before = room
        .resolve_parents(
            std::slice::from_ref(&head),
            &mut Recording::default(),
            &mut no_store,
        )
        .unwrap();
    let sidelined = room
        .sideline(
            EventInput::new("$soft", vec![head.clone()]).with_state_key(topic.clone()),
            before,
            Sideline::SoftFailed,
        )
        .unwrap()
        .clone();
    assert_eq!(sidelined.kind, Sideline::SoftFailed);
    assert_eq!(
        room.forward_extremities().iter().collect::<Vec<_>>(),
        vec![&head]
    );
    assert_eq!(
        room.current_state().unwrap().get(&topic),
        None,
        "the room's current state does not take a soft-failed write"
    );

    let mut resolver = Recording::default();
    append_resolved(
        &mut room,
        &mut resolver,
        EventInput::new("$child", vec![EventId::new("$soft")]),
    )
    .unwrap();
    assert_eq!(
        room.state_after_event(&EventId::new("$child"))
            .unwrap()
            .get(&topic),
        Some("$soft")
    );
}

#[test]
fn fork_window_uses_ancestry_not_nearby_linear_indices() {
    let mut room = RoomLog::new();
    room.append_local("$root", None).unwrap();
    room.append_local("$a1", None).unwrap();
    room.append_remote(EventInput::new("$b1", vec![EventId::new("$root")]))
        .unwrap();
    room.append_remote(EventInput::new("$a2", vec![EventId::new("$a1")]))
        .unwrap();
    room.append_remote(EventInput::new("$b2", vec![EventId::new("$b1")]))
        .unwrap();

    let window = room
        .fork_window(&[EventId::new("$a2"), EventId::new("$b2")], 4)
        .unwrap();
    assert_eq!(window.nearest_common_ancestor, EventId::new("$root"));
    assert_eq!(
        window.events,
        vec![
            EventId::new("$a1"),
            EventId::new("$b1"),
            EventId::new("$a2"),
            EventId::new("$b2")
        ]
    );
}

#[test]
fn fork_window_excludes_all_common_history_after_a_prior_merge() {
    let mut room = RoomLog::new();
    room.append_local("$root", None).unwrap();
    room.append_local("$left", None).unwrap();
    room.append_remote(EventInput::new("$right", vec![EventId::new("$root")]))
        .unwrap();
    room.append_local("$joined", None).unwrap();
    room.append_local("$new-left", None).unwrap();
    room.append_remote(EventInput::new("$new-right", vec![EventId::new("$joined")]))
        .unwrap();

    let window = room
        .fork_window(&[EventId::new("$new-left"), EventId::new("$new-right")], 2)
        .unwrap();
    assert_eq!(window.nearest_common_ancestor, EventId::new("$joined"));
    assert_eq!(
        window.events,
        vec![EventId::new("$new-left"), EventId::new("$new-right")]
    );
}

#[test]
fn fork_window_enforces_its_event_budget() {
    let mut room = RoomLog::new();
    room.append_local("$root", None).unwrap();
    room.append_local("$left", None).unwrap();
    room.append_remote(EventInput::new("$right", vec![EventId::new("$root")]))
        .unwrap();

    assert_eq!(
        room.fork_window(&[EventId::new("$left"), EventId::new("$right")], 1),
        Err(ForkWindowError::TooLarge {
            limit: 1,
            event_count: 2
        })
    );
}

proptest! {
    #[test]
    fn hamt_matches_a_btree_map(
        operations in prop::collection::vec(("[a-z]{1,12}", "[a-z]{0,12}", "\\$[a-z0-9]{1,16}"), 0..500)
    ) {
        let mut state = StateSnapshot::new();
        let mut model = BTreeMap::new();

        for (event_type, state_key, event_id) in operations {
            let key = StateKey::new(event_type, state_key);
            state = state.apply(key.clone(), event_id.clone());
            model.insert(key, event_id);
        }

        prop_assert_eq!(state.len(), model.len());
        for (key, event_id) in &model {
            prop_assert_eq!(state.get(key), Some(event_id.as_str()));
        }
    }

    #[test]
    fn every_linear_index_is_a_valid_topological_order(stale_parent_choices in prop::collection::vec(any::<usize>(), 0..200)) {
        let mut room = RoomLog::new();
        room.append_local("$genesis", None).unwrap();

        for (number, choice) in stale_parent_choices.into_iter().enumerate() {
            let known = room.len();
            let parent = room.entries().nth(choice % known).unwrap().event_id.clone();
            room.append_remote(EventInput::new(format!("$remote-{number}"), vec![parent])).unwrap();
            room.append_local(format!("$local-{number}"), None).unwrap();
        }

        let positions: BTreeMap<_, _> = room
            .entries()
            .map(|entry| (entry.event_id.clone(), entry.li))
            .collect();
        for entry in room.entries() {
            for parent in &entry.prev_events {
                prop_assert!(positions[parent] < entry.li);
            }
        }
        prop_assert_eq!(room.forward_extremities().len(), 1);
    }
}

#[test]
fn backfill_takes_descending_indices_below_live_history() {
    let mut room = RoomLog::new();
    room.append_local("$join", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$live", None).unwrap();

    // Two chunks of history walked strictly backwards from the join point.
    let older = room
        .prepend_remote(
            EventInput::new("$older", vec![EventId::new("$oldest")]),
            StateSnapshot::new(),
            41,
        )
        .unwrap()
        .li;
    let oldest = room
        .prepend_remote(EventInput::new("$oldest", vec![]), StateSnapshot::new(), 40)
        .unwrap()
        .li;

    assert_eq!(older.get(), 0);
    assert_eq!(oldest.get(), -1);

    // Live history is untouched and still ascends from 1.
    let live: Vec<_> = room
        .entries()
        .map(|entry| (entry.event_id.as_str().to_owned(), entry.li.get()))
        .collect();
    assert_eq!(
        live,
        vec![
            ("$oldest".to_owned(), -1),
            ("$older".to_owned(), 0),
            ("$join".to_owned(), 1),
            ("$live".to_owned(), 2),
        ]
    );
}

#[test]
fn backfilled_history_sorts_before_the_join_point_it_precedes() {
    let mut room = RoomLog::new();
    room.append_local("$join", None).unwrap();
    room.prepend_remote(
        EventInput::new("$ancestor", vec![]),
        StateSnapshot::new(),
        7,
    )
    .unwrap();

    let ancestor = room.get(&EventId::new("$ancestor")).unwrap().li;
    let join = room.get(&EventId::new("$join")).unwrap().li;
    assert!(ancestor < join);
    // Backfill is behind everything held, so it is never an extremity.
    assert_eq!(room.forward_extremities().len(), 1);
    assert!(room.forward_extremities().contains(&EventId::new("$join")));
}

#[test]
fn backfill_requires_a_room_to_walk_backwards_from() {
    let mut room = RoomLog::new();
    assert_eq!(
        room.prepend_remote(
            EventInput::new("$ancestor", vec![]),
            StateSnapshot::new(),
            0
        )
        .err(),
        Some(AppendError::EmptyRoom)
    );
}
