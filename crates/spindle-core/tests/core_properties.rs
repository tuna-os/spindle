use std::collections::BTreeMap;

use proptest::prelude::*;
use spindle_core::{
    AppendError, EventId, EventInput, ForkWindowError, RoomLog, StateKey, StateSnapshot,
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
    room.append_remote(EventInput::new(
        "$new-right",
        vec![EventId::new("$joined")],
    ))
    .unwrap();

    let window = room
        .fork_window(
            &[EventId::new("$new-left"), EventId::new("$new-right")],
            2,
        )
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
            let known = room.entries().len();
            let parent = room.entries()[choice % known].event_id.clone();
            room.append_remote(EventInput::new(format!("$remote-{number}"), vec![parent])).unwrap();
            room.append_local(format!("$local-{number}"), None).unwrap();
        }

        let positions: BTreeMap<_, _> = room
            .entries()
            .iter()
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
