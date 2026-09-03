use std::collections::BTreeMap;

use proptest::prelude::*;
use spindle_core::{
    AppendError, EventId, EventInput, ForkWindowError, RoomLog, SetAside, StateKey, StateSnapshot,
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

/// A fork on disjoint slots merges even when both slots already had a value.
///
/// The regression behind #225. A parent's snapshot describes all of that
/// branch's state, not the part it changed, so for a key one branch wrote and
/// the other left alone the two parents disagree on paper — one carries the
/// new event, the other the value both inherited. Reading that as a conflict
/// refused a merge with an empty conflicted set, and since every later local
/// append names all forward extremities, refused it permanently.
///
/// The distinction lives entirely in whether the slots held a value at the
/// fork point, so both arrangements are asserted here together; testing only
/// the unset one is what let the bug stand.
#[test]
fn a_disjoint_fork_merges_whether_or_not_the_slots_were_already_set() {
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

        room.append_local("$merge", None)
            .unwrap_or_else(|error| panic!("preset={preset}: {error:?}"));

        // Both branches' writes survive. Taking either parent wholesale keeps
        // one and drops the other, which is the mistake a merge that merely
        // stopped erroring would make.
        let state = room.state_after_event(&EventId::new("$merge")).unwrap();
        assert_eq!(
            state.get(&StateKey::new("m.room.topic", "")),
            Some("$topic-ours"),
            "preset={preset}"
        );
        assert_eq!(
            state.get(&StateKey::new("m.room.name", "")),
            Some("$name-theirs"),
            "preset={preset}"
        );
    }
}

/// The state before an event is the fold of its parents, not the state
/// after whichever entry happens to precede it in linear order.
///
/// The two are the same thing in a linear room, which is how the
/// federation `/state_ids` read got away with the second for as long as it
/// did. After a fork they part: the entry before the merge event belongs
/// to one branch, and its state has that branch's write and not the
/// other's, while the merge event was authorized against both. Asked at
/// the merge event, a peer was told a state this server never held there.
#[test]
fn the_state_before_a_merge_event_is_the_fold_of_both_branches() {
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
    room.append_local("$merge", None).unwrap();

    // Nothing is evicted in a room this small, so the loader must never be
    // asked; a snapshot rehydrated here would be one the window still held.
    let mut load = |_: &spindle_core::StateRoot| -> Option<Vec<u8>> {
        panic!("the state before a recent event is resident")
    };
    let before = room
        .state_before(&EventId::new("$merge"), &mut load)
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

    // In the linear stretch the fold is the one parent: the state before
    // the topic write is the base, without the topic.
    let before = room
        .state_before(&EventId::new("$topic-ours"), &mut load)
        .unwrap();
    assert_eq!(before.get(&StateKey::new("m.room.topic", "")), None);
    assert_eq!(before.root(), room.state_after_event(&base).unwrap().root());

    // And before the create event there is no state at all.
    let before = room
        .state_before(&EventId::new("$create"), &mut load)
        .unwrap();
    assert!(before.is_empty());

    assert_eq!(
        room.state_before(&EventId::new("$nowhere"), &mut load)
            .unwrap_err(),
        AppendError::UnknownPredecessor(EventId::new("$nowhere"))
    );
}

/// The same slot on both branches stays case 3, preset or not.
///
/// The counterpart to the test above, and the reason the fix is a rule about
/// the *base* rather than a loosening: a key both branches moved away from
/// what they inherited is a real conflict and must still reach the resolver.
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

/// A contested fork is stepped around, not tripped over: the room keeps
/// taking local appends on its linear head (#225).
///
/// What is set aside is the tip that claims the contested key other than
/// the head, the head being the entry the linear order puts last, whichever
/// branch it belongs to. The tip set aside stays a forward extremity -- the
/// resolver will want it -- but no local append names it, and a second call
/// finds nothing left to set aside, which is what keeps one open fork from
/// being counted on every send.
#[test]
fn a_contested_fork_is_set_aside_and_local_appends_continue_on_the_head() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic0", Some(topic.clone())).unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();

    room.append_local("$topic-ours", Some(topic.clone()))
        .unwrap();
    // Theirs lands last, so it is the linear head.
    room.append_remote(EventInput::new("$topic-theirs", vec![base]).with_state_key(topic.clone()))
        .unwrap();
    assert!(matches!(
        room.append_local("$merge", None),
        Err(AppendError::NeedsStateResolution { .. })
    ));

    let set_aside = room.set_aside_contested().unwrap();
    assert_eq!(
        set_aside,
        vec![SetAside {
            extremity: EventId::new("$topic-ours"),
            key: topic.clone(),
        }]
    );
    assert!(
        room.set_aside_contested().unwrap().is_empty(),
        "one fork is set aside once"
    );

    let merge = room.append_local("$merge", None).unwrap();
    assert_eq!(merge.prev_events, vec![EventId::new("$topic-theirs")]);
    let state = room.state_after_event(&EventId::new("$merge")).unwrap();
    assert_eq!(state.get(&topic), Some("$topic-theirs"));

    // Still a tip of the DAG, still resident, just not authored on.
    let ours = EventId::new("$topic-ours");
    assert!(room.forward_extremities().contains(&ours));
    assert!(room.set_aside_extremities().contains(&ours));
    assert!(room.state_after_event(&ours).is_some());
    assert_eq!(room.authoring_extremities().count(), 1);
}

/// A three-way fork loses only the branch that disagrees.
///
/// A tip that merely inherited the contested key made no claim on it, and
/// setting it aside would drop a branch that would have merged for free.
#[test]
fn set_aside_keeps_a_tip_that_only_inherited_the_contested_key() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic0", Some(topic.clone())).unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();

    room.append_remote(EventInput::new("$message", vec![base.clone()]))
        .unwrap();
    room.append_remote(
        EventInput::new("$topic-a", vec![base.clone()]).with_state_key(topic.clone()),
    )
    .unwrap();
    room.append_remote(EventInput::new("$topic-b", vec![base]).with_state_key(topic.clone()))
        .unwrap();
    assert_eq!(room.forward_extremities().len(), 3);

    let set_aside = room.set_aside_contested().unwrap();
    assert_eq!(set_aside.len(), 1, "{set_aside:?}");
    assert_eq!(set_aside[0].extremity, EventId::new("$topic-a"));

    let merge = room.append_local("$merge", None).unwrap();
    assert_eq!(merge.prev_events.len(), 2, "{:?}", merge.prev_events);
    assert!(merge.prev_events.contains(&EventId::new("$message")));
    assert!(merge.prev_events.contains(&EventId::new("$topic-b")));
    let state = room.state_after_event(&EventId::new("$merge")).unwrap();
    assert_eq!(state.get(&topic), Some("$topic-b"));
}

/// Whatever builds on a set-aside tip is a fresh tip, judged afresh.
///
/// The set-aside mark is about a tip, not a branch. A peer that extends the
/// branch this server stepped around produces a new extremity, which the
/// next local append considers on its own merits -- and, since it still
/// contests the key, sets aside in turn. That second decision is a second
/// fork for the counter, which is right: the peer produced a second tip
/// this server cannot fold.
#[test]
fn a_tip_built_on_a_set_aside_tip_is_judged_afresh() {
    let topic = StateKey::new("m.room.topic", "");
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic0", Some(topic.clone())).unwrap();
    let base = room.forward_extremities().iter().next().unwrap().clone();
    room.append_local("$topic-ours", Some(topic.clone()))
        .unwrap();
    room.append_remote(EventInput::new("$topic-theirs", vec![base]).with_state_key(topic.clone()))
        .unwrap();
    assert_eq!(room.set_aside_contested().unwrap().len(), 1);
    room.append_local("$merge", None).unwrap();

    room.append_remote(EventInput::new("$more", vec![EventId::new("$topic-ours")]))
        .unwrap();
    assert!(
        room.set_aside_extremities().is_empty(),
        "the tip built on is no tip, and no longer set aside"
    );
    assert_eq!(room.authoring_extremities().count(), 2);

    let set_aside = room.set_aside_contested().unwrap();
    assert_eq!(set_aside.len(), 1, "{set_aside:?}");
    // `$more` is the linear head now, so it is `$merge` that steps aside.
    assert_eq!(set_aside[0].extremity, EventId::new("$merge"));
    let next = room.append_local("$next", None).unwrap();
    assert_eq!(next.prev_events, vec![EventId::new("$more")]);
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
