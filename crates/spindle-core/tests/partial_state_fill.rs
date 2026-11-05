//! A partial-state join (MSC3706) leaves member slots empty in every
//! snapshot from the join on; [`RoomLog::fill_partial_state`] fills them
//! from the full state fetched later, in place, without moving an event.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use spindle_core::{
    EventId, EventInput, LinearIndex, MemStateKeyTable, RoomLog, StateKey, StateKeyTable,
    StateRoot, StateSnapshot,
};

fn table() -> Arc<dyn StateKeyTable> {
    MemStateKeyTable::shared()
}

fn member(user: &str) -> StateKey {
    StateKey::new("m.room.member", user)
}

/// A room seeded from a partial `send_join` answer -- create, power
/// levels and the joiner -- then carrying on: a message, a member the
/// resident left out changing their membership after the join, a topic.
fn partial_room(window: usize) -> (RoomLog, LinearIndex) {
    let mut log = RoomLog::with_resident_window(window, table());
    let mut state = StateSnapshot::new(log.table().clone());
    for (id, key) in [
        ("$create", StateKey::new("m.room.create", "")),
        ("$power", StateKey::new("m.room.power_levels", "")),
    ] {
        state = state.apply(&key, id);
        log.append_seeded(
            EventInput::new(id, Vec::new()).with_state_key(key),
            state.clone(),
            1,
        )
        .unwrap();
    }
    state = state.apply(&member("@joiner:here"), "$join");
    let join = log
        .append_seeded(
            EventInput::new("$join", vec![EventId::new("$power")])
                .with_state_key(member("@joiner:here")),
            state,
            3,
        )
        .unwrap()
        .li;
    log.append_local("$message", None).unwrap();
    log.append_local("$carol-leaves", Some(member("@carol:there")))
        .unwrap();
    log.append_local("$topic", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    (log, join)
}

/// The full state before the join names two members the resident left
/// out: bob, untouched since, and carol, whose leave after the join is
/// newer than the join she had before it.
fn full_state_fill() -> BTreeMap<StateKey, EventId> {
    BTreeMap::from([
        (member("@bob:there"), EventId::new("$bob-join")),
        (member("@carol:there"), EventId::new("$carol-join")),
    ])
}

#[test]
fn every_snapshot_from_the_join_gains_the_omitted_members_and_keeps_newer_slots() {
    let (mut log, join) = partial_room(64);
    let chain_before = log.head_chain();
    let order_before: Vec<EventId> = log.entries().map(|entry| entry.event_id.clone()).collect();
    let create_root = log.state_after(LinearIndex::from_raw(1)).unwrap().root();

    let filled = log
        .fill_partial_state(join, &full_state_fill(), &mut |_| None)
        .unwrap();
    assert_eq!(
        filled.entries.len(),
        4,
        "the join and the three entries after it, nothing before"
    );

    let bob = member("@bob:there");
    let carol = member("@carol:there");
    for (event, carol_is) in [
        ("$join", "$carol-join"),
        ("$message", "$carol-join"),
        ("$carol-leaves", "$carol-leaves"),
        ("$topic", "$carol-leaves"),
    ] {
        let state = log.state_after_event(&EventId::new(event)).unwrap();
        assert_eq!(state.get(&bob), Some("$bob-join"), "{event}");
        assert_eq!(state.get(&carol), Some(carol_is), "{event}");
        assert_eq!(
            log.get(&EventId::new(event)).unwrap().state_root,
            state.root(),
            "{event}: the entry names the state it now has"
        );
    }
    assert_eq!(
        log.current_state().unwrap().get(&bob),
        Some("$bob-join"),
        "the room's current state is the filled one"
    );
    assert_eq!(
        log.state_after(LinearIndex::from_raw(1)).unwrap().root(),
        create_root,
        "seeded history before the join is left as it was"
    );
    assert_eq!(log.head_chain(), chain_before, "no event moved");
    let order_after: Vec<EventId> = log.entries().map(|entry| entry.event_id.clone()).collect();
    assert_eq!(order_after, order_before);

    // Filling again is a no-op: every slot the fill names is held now,
    // which is what lets a resync interrupted after the fill run again.
    let again = log
        .fill_partial_state(join, &full_state_fill(), &mut |_| None)
        .unwrap();
    assert!(again.entries.is_empty() && again.sidelined.is_empty());
}

#[test]
fn snapshots_outside_the_window_are_read_back_and_filled_alike() {
    // A window of one keeps only the head resident: every other snapshot
    // the fill touches has to come back through `load`.
    let (mut log, join) = partial_room(1);
    let (mut reference, _) = partial_room(64);
    let mut nodes: HashMap<StateRoot, Vec<u8>> = HashMap::new();
    for entry in reference.entries() {
        let state = reference.state_after(entry.li).unwrap();
        for (address, node) in state.delta_nodes(None) {
            nodes.insert(address, node);
        }
    }
    // The two logs intern alike, so the reference's nodes are this log's.
    let filled = log
        .fill_partial_state(join, &full_state_fill(), &mut |root| {
            nodes.get(root).cloned()
        })
        .unwrap();
    let expected = reference
        .fill_partial_state(join, &full_state_fill(), &mut |_| None)
        .unwrap();
    let roots = |filled: &spindle_core::FilledStates| -> Vec<StateRoot> {
        filled
            .entries
            .iter()
            .map(|entry| entry.state.root())
            .collect()
    };
    assert_eq!(roots(&filled), roots(&expected));
}
