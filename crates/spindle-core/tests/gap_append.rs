//! A forward event accepted across a federation gap keeps the room's own
//! head as an extremity, survives a cold reopen, and lets ordinary appends
//! continue on top of it.
use std::collections::HashMap;

use spindle_core::{
    AppendError, EventId, EventInput, RestoredEntry, RoomLog, StateKey, StateRoot, StateSnapshot,
};

fn member(user: &str) -> StateKey {
    StateKey::new("m.room.member", user)
}

fn records(log: &RoomLog) -> Vec<RestoredEntry> {
    log.entries()
        .map(|entry| RestoredEntry {
            li: entry.li,
            event_id: entry.event_id.clone(),
            prev_events: entry.prev_events.clone(),
            depth: entry.depth,
            state_key: entry.state_key.clone(),
            expected_state_root: *entry.state_root.as_bytes(),
            chain: entry.chain.map(|chain| *chain.as_bytes()),
        })
        .collect()
}

#[test]
fn a_gap_event_is_an_extra_extremity_on_the_state_it_was_given() {
    let mut log = RoomLog::new();
    log.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    log.append_local("$alice", Some(member("@alice:here")))
        .unwrap();
    let head = EventId::new("$alice");

    // The remote state names a member this log has never seen.
    let mut remote = StateSnapshot::new();
    remote = remote.apply(StateKey::new("m.room.create", ""), "$create");
    remote = remote.apply(member("@alice:here"), "$alice");
    remote = remote.apply(member("@carol:there"), "$carol");

    let entry = log
        .append_across_gap(
            EventInput::new("$latest", vec![EventId::new("$unknown")]),
            remote.clone(),
            9_000,
        )
        .unwrap()
        .clone();
    assert_eq!(entry.depth, 9_000, "the signed depth stands");
    assert!(entry.chain.is_some(), "sequenced here, so attested");
    assert_eq!(entry.prev_events, vec![EventId::new("$unknown")]);
    assert!(log.forward_extremities().contains(&head));
    assert!(log.forward_extremities().contains(&EventId::new("$latest")));
    assert_eq!(
        log.state_after_event(&EventId::new("$latest"))
            .unwrap()
            .root(),
        remote.root(),
        "a non-state event's state after is the state it was given"
    );

    // A redelivery is a duplicate, not a second entry.
    assert_eq!(
        log.append_across_gap(
            EventInput::new("$latest", vec![EventId::new("$unknown")]),
            remote.clone(),
            1,
        )
        .unwrap_err(),
        AppendError::DuplicateEvent(EventId::new("$latest"))
    );

    // Ordinary appends continue from the gap event as from any other.
    log.append_resolved(
        EventInput::new("$next", vec![EventId::new("$latest")]),
        remote.clone(),
    )
    .unwrap();
    assert!(log.forward_extremities().contains(&head));
    assert!(log.forward_extremities().contains(&EventId::new("$next")));
    assert_eq!(log.get(&EventId::new("$next")).unwrap().depth, 9_001);

    // And the whole thing reopens to the same log.
    let mut stored: HashMap<StateRoot, Vec<u8>> = HashMap::new();
    for entry in log.entries() {
        stored.extend(log.state_after(entry.li).unwrap().delta_nodes(None));
    }
    let restored = RoomLog::restore_with_state(
        records(&log),
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |root| stored.get(root).cloned(),
    )
    .unwrap();
    assert!(restored.unverified.is_empty(), "{:?}", restored.unverified);
    assert!(restored.broken_chain.is_empty());
    assert_eq!(
        restored.log.forward_extremities(),
        log.forward_extremities()
    );
    assert_eq!(
        restored
            .log
            .state_after_event(&EventId::new("$latest"))
            .unwrap()
            .root(),
        remote.root()
    );
}

#[test]
fn a_held_parent_stops_being_an_extremity_and_raises_the_depth() {
    let mut log = RoomLog::new();
    log.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    log.append_local("$a", None).unwrap();
    let state = log.current_state().unwrap().clone();
    let entry = log
        .append_across_gap(
            EventInput::new(
                "$merge",
                vec![EventId::new("$a"), EventId::new("$elsewhere")],
            ),
            state,
            0,
        )
        .unwrap()
        .clone();
    assert_eq!(entry.depth, 2, "above the held parent, whatever was signed");
    assert_eq!(
        log.forward_extremities().iter().collect::<Vec<_>>(),
        vec![&EventId::new("$merge")]
    );
}

#[test]
fn a_gap_needs_history_and_parents() {
    let mut empty = RoomLog::new();
    assert_eq!(
        empty
            .append_across_gap(
                EventInput::new("$x", vec![EventId::new("$y")]),
                StateSnapshot::new(),
                1,
            )
            .unwrap_err(),
        AppendError::EmptyRoom
    );
    let mut log = RoomLog::new();
    log.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    assert_eq!(
        log.append_across_gap(EventInput::new("$x", Vec::new()), StateSnapshot::new(), 1)
            .unwrap_err(),
        AppendError::MissingPredecessor
    );
}
