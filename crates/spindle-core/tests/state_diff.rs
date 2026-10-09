//! `StateSnapshot::diff`: the slots two states disagree on, and only those.
//!
//! The property is checked against the obvious implementation (walk both
//! states in full and compare), over random histories that share a base and
//! then diverge, which is the shape a fork merge diffs.

use std::collections::BTreeMap;

use proptest::prelude::*;
use spindle_core::{StateKey, StateSnapshot};

fn key(slot: u16) -> StateKey {
    if slot.is_multiple_of(7) {
        StateKey::new("m.room.topic", format!("{slot}"))
    } else {
        StateKey::new("m.room.member", format!("@user{slot}:example.org"))
    }
}

fn build(base: &StateSnapshot, writes: &[(u16, u16)]) -> StateSnapshot {
    let mut state = base.clone();
    for (slot, value) in writes {
        state = state.apply(key(*slot), format!("$e{value}"));
    }
    state
}

fn as_map(state: &StateSnapshot) -> BTreeMap<StateKey, String> {
    let mut map = BTreeMap::new();
    state.for_each(|key, event_id| {
        map.insert(key.clone(), event_id.to_owned());
    });
    map
}

fn naive(
    left: &StateSnapshot,
    right: &StateSnapshot,
) -> Vec<(StateKey, Option<String>, Option<String>)> {
    let (left, right) = (as_map(left), as_map(right));
    let mut keys: Vec<&StateKey> = left.keys().chain(right.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|key| left.get(*key) != right.get(*key))
        .map(|key| {
            (
                (*key).clone(),
                left.get(key).cloned(),
                right.get(key).cloned(),
            )
        })
        .collect()
}

fn owned(
    diff: Vec<(&StateKey, Option<&str>, Option<&str>)>,
) -> Vec<(StateKey, Option<String>, Option<String>)> {
    diff.into_iter()
        .map(|(key, ours, theirs)| {
            (
                key.clone(),
                ours.map(str::to_owned),
                theirs.map(str::to_owned),
            )
        })
        .collect()
}

proptest! {
    #[test]
    fn diff_matches_a_full_comparison(
        base in prop::collection::vec((0_u16..2_000, 0_u16..50), 0..600),
        left in prop::collection::vec((0_u16..2_500, 50_u16..100), 0..40),
        right in prop::collection::vec((0_u16..2_500, 50_u16..100), 0..40),
    ) {
        let base = build(&StateSnapshot::new(), &base);
        let left = build(&base, &left);
        let right = build(&base, &right);
        prop_assert_eq!(owned(left.diff(&right)), naive(&left, &right));
        prop_assert_eq!(owned(right.diff(&left)), naive(&right, &left));
        prop_assert!(left.diff(&left).is_empty());
    }
}

#[test]
fn unrelated_states_diff_in_full() {
    let left = build(&StateSnapshot::new(), &[(1, 1), (2, 2), (3, 3)]);
    let right = build(&StateSnapshot::new(), &[(2, 2), (3, 4), (5, 5)]);
    assert_eq!(owned(left.diff(&right)), naive(&left, &right));
    assert_eq!(left.diff(&right).len(), 3);
    assert!(StateSnapshot::new().diff(&StateSnapshot::new()).is_empty());
    assert_eq!(StateSnapshot::new().diff(&left).len(), 3);
}

#[test]
fn a_large_shared_state_diffs_only_the_changed_slots() {
    let base = build(
        &StateSnapshot::new(),
        &(0..20_000).map(|slot| (slot, 0)).collect::<Vec<_>>(),
    );
    let left = base.apply(key(17), "$left");
    let right = base.apply(key(17), "$right").apply(key(30_000), "$new");
    let diff = owned(left.diff(&right));
    assert_eq!(
        diff,
        vec![
            (key(17), Some("$left".to_owned()), Some("$right".to_owned())),
            (key(30_000), None, Some("$new".to_owned())),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
}
