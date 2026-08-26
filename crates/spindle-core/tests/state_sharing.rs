//! SPEC §6.1: updating one state slot must copy a path, not a state.
//!
//! The timing benchmark in `benches/state_snapshot.rs` cannot show this
//! cleanly — allocation cost is buried in wall clock and varies by allocator.
//! Node count is exact, and it is the property the design actually rests on.

use spindle_core::{StateKey, StateSnapshot};

fn seeded(count: usize) -> StateSnapshot {
    let mut state = StateSnapshot::new();
    for number in 0..count {
        state = state.apply(
            StateKey::new("m.room.member", format!("@user{number}:example.org")),
            format!("$event-{number}"),
        );
    }
    state
}

#[test]
fn one_update_creates_a_path_not_a_copy() {
    // Across two orders of magnitude of state, the number of nodes a single
    // update creates should stay flat. If it tracks state size, path copying
    // has been lost and every state event is writing the whole room.
    let mut counts = Vec::new();

    for size in [100_usize, 1_000, 10_000] {
        let before = seeded(size);
        let after = before.apply(StateKey::new("m.room.topic", ""), "$topic");

        let created = after.delta_nodes(Some(&before)).len();
        counts.push((size, created));

        assert!(
            created <= 8,
            "updating one slot in a {size}-entry state created {created} nodes"
        );
    }

    // Flat, not growing: the 10,000-entry case must not cost meaningfully more
    // than the 100-entry one.
    let smallest = counts.first().unwrap().1;
    let largest = counts.last().unwrap().1;
    assert!(
        largest <= smallest + 3,
        "nodes per update grew with state size: {counts:?}"
    );
}

#[test]
fn an_unchanged_state_creates_nothing() {
    let state = seeded(500);
    assert!(
        state.delta_nodes(Some(&state)).is_empty(),
        "a snapshot compared against itself shares every node"
    );
}

#[test]
fn rewriting_a_slot_to_the_same_value_still_shares_the_rest() {
    let before = seeded(1_000);
    let after = before.apply(
        StateKey::new("m.room.member", "@user0:example.org"),
        "$event-0",
    );

    // Identical content means identical content addresses, so nothing is new.
    assert_eq!(after.root(), before.root());
    assert!(after.delta_nodes(Some(&before)).is_empty());
}
