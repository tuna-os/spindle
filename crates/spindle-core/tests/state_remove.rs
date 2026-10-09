//! Removing a state slot preserves canonical roots and shares untouched trie nodes.

use std::collections::BTreeMap;

use proptest::prelude::*;
use spindle_core::{StateKey, StateSnapshot};

fn key(slot: u16) -> StateKey {
    StateKey::new("m.room.member", format!("@user{slot}:example.org"))
}

proptest! {
    #[test]
    fn removing_slots_matches_rebuilding_the_remaining_map(
        writes in prop::collection::vec((any::<u16>(), any::<u16>()), 0..100),
        removed in prop::collection::vec(any::<u16>(), 0..30),
    ) {
        let mut map = BTreeMap::new();
        let mut state = StateSnapshot::new();
        for (slot, value) in writes {
            let value = format!("$e{value}");
            state = state.apply(key(slot), value.clone());
            map.insert(slot, value);
        }
        for slot in removed.into_iter().chain(map.keys().copied().take(10).collect::<Vec<_>>()) {
            state = state.remove(&key(slot));
            map.remove(&slot);
            let mut rebuilt = StateSnapshot::new();
            for (slot, value) in &map {
                rebuilt = rebuilt.apply(key(*slot), value.clone());
            }
            prop_assert_eq!(state.root(), rebuilt.root());
            prop_assert_eq!(state.len(), map.len());
        }
    }
}

#[test]
fn deleting_from_a_large_room_persists_only_the_changed_path() {
    let mut state = StateSnapshot::new();
    for slot in 0..20_000 {
        state = state.apply(key(slot), format!("$e{slot}"));
    }
    let removed = state.remove(&key(9000));
    assert_eq!(removed.len(), 19_999);
    assert_eq!(
        state.get(&key(9000)),
        Some("$e9000"),
        "old snapshots are immutable"
    );
    assert_eq!(removed.get(&key(9000)), None);
    assert!(
        removed.delta_nodes(Some(&state)).len() <= 52,
        "one trie path, never a fresh room trie"
    );
    assert_eq!(removed.remove(&key(9000)).root(), removed.root());
    assert_eq!(removed.apply(key(9000), "$e9000").root(), state.root());
}
