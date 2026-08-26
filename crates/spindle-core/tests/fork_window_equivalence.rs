//! #30: the bounded fork-window search must agree with an exhaustive walk.
//!
//! The exhaustive implementation lives here rather than in the library: it is
//! the oracle, deliberately written the slow obvious way, and the point of the
//! library version is that it reaches the same answer without touching history
//! it cannot affect.

use std::collections::{BTreeSet, HashMap};

use proptest::prelude::*;
use spindle_core::{EventId, EventInput, LogEntry, RoomLog};

/// Divergent ancestry by brute force: every ancestor of every tip, minus the
/// ancestors common to all of them. O(room history), which is the cost the
/// library version exists to avoid.
fn exhaustive_window(room: &RoomLog, tips: &[EventId]) -> Option<(EventId, Vec<EventId>)> {
    let by_id: HashMap<&str, &LogEntry> = room
        .entries()
        .map(|entry| (entry.event_id.as_str(), entry))
        .collect();

    let ancestors = |tip: &EventId| -> BTreeSet<i64> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![tip.clone()];
        while let Some(id) = pending.pop() {
            let Some(entry) = by_id.get(id.as_str()) else {
                continue;
            };
            if !seen.insert(entry.li.get()) {
                continue;
            }
            pending.extend(entry.prev_events.iter().cloned());
        }
        seen
    };

    let ancestries: Vec<_> = tips.iter().map(ancestors).collect();
    let mut common = ancestries[0].clone();
    for ancestry in &ancestries[1..] {
        common.retain(|li| ancestry.contains(li));
    }
    let nearest = common.iter().copied().max()?;

    let divergent: BTreeSet<i64> = ancestries
        .into_iter()
        .flatten()
        .filter(|li| !common.contains(li))
        .collect();

    let li_to_id = |li: i64| {
        room.entries()
            .find(|entry| entry.li.get() == li)
            .map(|entry| entry.event_id.clone())
            .unwrap()
    };
    Some((
        li_to_id(nearest),
        divergent.into_iter().map(li_to_id).collect(),
    ))
}

/// A room whose forks are driven by the generated stale-parent choices.
fn forked_room(choices: &[usize]) -> RoomLog {
    let mut room = RoomLog::new();
    room.append_local("$genesis", None).unwrap();
    for (number, choice) in choices.iter().enumerate() {
        let known = room.len();
        let parent = room.entries().nth(choice % known).unwrap().event_id.clone();
        room.append_remote(EventInput::new(format!("$stale-{number}"), vec![parent]))
            .unwrap();
        if number % 3 == 0 {
            room.append_local(format!("$merge-{number}"), None).unwrap();
        }
    }
    room
}

proptest! {
    #[test]
    fn bounded_search_agrees_with_an_exhaustive_walk(
        choices in prop::collection::vec(any::<usize>(), 1..40),
        tip_choices in prop::collection::vec(any::<usize>(), 2..5),
    ) {
        let room = forked_room(&choices);
        let all: Vec<_> = room.entries().map(|entry| entry.event_id.clone()).collect();

        let mut tips: Vec<EventId> = tip_choices
            .iter()
            .map(|choice| all[choice % all.len()].clone())
            .collect();
        tips.dedup();

        let bounded = room.fork_window(&tips, usize::MAX).unwrap();
        let (nearest, events) = exhaustive_window(&room, &tips).unwrap();

        prop_assert_eq!(bounded.nearest_common_ancestor, nearest);
        prop_assert_eq!(bounded.events, events);
    }
}

#[test]
fn a_small_fork_in_a_large_room_does_not_scan_history() {
    let mut room = RoomLog::new();
    room.append_local("$genesis", None).unwrap();
    for number in 0..5_000 {
        room.append_local(format!("$live-{number}"), None).unwrap();
    }
    // A stale PDU naming the head's *predecessor*, which is what a concurrent
    // send from a legacy peer produces: two extremities, two divergent events.
    let stale_parent = room.entries().nth(room.len() - 2).unwrap().event_id.clone();
    let head = room.forward_extremities().iter().next().unwrap().clone();
    room.append_remote(EventInput::new("$stale", vec![stale_parent]))
        .unwrap();

    let window = room
        .fork_window(&[head.clone(), EventId::new("$stale")], 512)
        .unwrap();

    assert_eq!(window.events, vec![head, EventId::new("$stale")]);
    assert_eq!(window.nearest_common_ancestor, EventId::new("$live-4998"));
    // The room holds 5,003 entries. An exhaustive walk would touch all of them.
    assert!(
        window.visited <= 8,
        "bounded search touched {} entries in a {}-entry room",
        window.visited,
        room.len()
    );
}
