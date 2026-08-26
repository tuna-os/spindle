//! #49: materialized state is bounded by the fork window, not by room length.
//!
//! The log keeps a 32-byte content address on every entry forever, and the
//! materialized [`StateSnapshot`] only while a fork could still reach it. These
//! tests assert the bound holds and, more importantly, that the two exceptions
//! to it are honoured: the entry just written, and every forward extremity at
//! any age.

use spindle_core::{
    AppendError, DEFAULT_RESIDENT_WINDOW, EventId, EventInput, RoomLog, StateKey, StateSnapshot,
};

/// A room whose resident count tracks its length has lost the bound, and that
/// is the regression this whole mechanism exists to prevent.
#[test]
fn resident_state_is_bounded_by_the_window_not_by_the_room() {
    let window = 64;
    let events = 5_000;
    let mut log = RoomLog::with_resident_window(window);

    for number in 0..events {
        log.append_local(
            format!("$event-{number}"),
            Some(StateKey::new(
                "m.room.member",
                format!("@user{number}:example.org"),
            )),
        )
        .unwrap();
    }

    assert_eq!(log.len(), events);
    // The head is an extremity and so pinned, which is the one entry that can
    // sit outside the window; everything else is inside it.
    assert!(
        log.resident_len() <= window + 1,
        "{} snapshots resident for a window of {window}",
        log.resident_len()
    );
    // The bound is the point: 5,000 events, at most 65 snapshots.
    assert!(log.resident_len() < events / 10);
}

/// Eviction loses the materialization, never the address.
#[test]
fn an_evicted_entry_still_carries_its_state_root() {
    let mut log = RoomLog::with_resident_window(8);
    for number in 0..200 {
        log.append_local(format!("$event-{number}"), None).unwrap();
    }

    let oldest = log.entries().next().unwrap();
    assert!(
        log.state_after(oldest.li).is_none(),
        "the oldest entry should be long evicted"
    );
    // Still addressable, which is what makes rehydration from the store
    // possible: the log remains self-describing after eviction.
    let head = log.entries().next_back().unwrap();
    assert_eq!(
        oldest.state_root, head.state_root,
        "no state events, so every root is the empty root"
    );
    assert!(log.state_after(head.li).is_some());
}

/// The load-bearing exception. A class-D stale peer event leaves an extremity
/// arbitrarily far back (ADR 0001), and the next local event has to merge that
/// extremity's state with the head's. Evicting it by age would break an
/// ordinary federation append.
#[test]
fn a_stale_forward_extremity_keeps_its_state_however_old_it_gets() {
    let window = 16;
    let mut log = RoomLog::with_resident_window(window);

    let root = log
        .append_local("$root", Some(StateKey::new("m.room.create", "")))
        .unwrap()
        .event_id
        .clone();

    // A peer event on a stale parent: it does not name the head, so the room
    // now has two forward extremities.
    let stale = log
        .append_remote(
            EventInput::new("$stale", vec![root.clone()])
                .with_state_key(StateKey::new("m.room.topic", "")),
        )
        .unwrap()
        .event_id
        .clone();
    let stale_li = log.get(&stale).unwrap().li;

    // Advance the head far past the window, always naming only the head so the
    // stale extremity stays dangling.
    let mut head = root;
    for number in 0..(window * 10) {
        head = log
            .append_remote(EventInput::new(
                format!("$live-{number}"),
                vec![head.clone()],
            ))
            .unwrap()
            .event_id
            .clone();
    }

    assert_eq!(log.forward_extremities().len(), 2);
    assert!(
        log.state_after(stale_li).is_some(),
        "an extremity {} entries back was evicted; the next local append would \
         have nothing to merge",
        log.len() - 1
    );

    // And the merge it exists for actually works: one local event collapses the
    // fork, because the two sides touched disjoint state slots.
    let merged = log.append_local("$merge", None).unwrap().li;
    assert_eq!(log.forward_extremities().len(), 1);
    let merged_state = log.state_after(merged).unwrap();
    assert_eq!(
        merged_state.get(&StateKey::new("m.room.create", "")),
        Some("$root")
    );
    assert_eq!(
        merged_state.get(&StateKey::new("m.room.topic", "")),
        Some("$stale"),
        "the stale side's state survived into the merge"
    );

    // Once it is no longer an extremity, it is no longer pinned.
    for number in 0..window {
        log.append_local(format!("$after-{number}"), None).unwrap();
    }
    assert!(
        log.state_after(stale_li).is_none(),
        "a collapsed extremity should stop being pinned"
    );
}

/// Backfill takes indices far below the window floor. Its state came from
/// `/state_ids` and cannot be refolded, so it has to survive long enough to be
/// handed to the store.
#[test]
fn a_backfilled_entry_is_resident_until_the_next_append() {
    let mut log = RoomLog::with_resident_window(4);
    for number in 0..100 {
        log.append_local(format!("$event-{number}"), None).unwrap();
    }

    let supplied = StateSnapshot::new().apply(StateKey::new("m.room.name", ""), "$name");
    let backfilled = log
        .prepend_remote(EventInput::new("$older", vec![]), supplied, 40)
        .unwrap()
        .li;

    assert_eq!(
        log.state_after(backfilled)
            .expect("backfilled state must survive its own prepend")
            .get(&StateKey::new("m.room.name", "")),
        Some("$name")
    );

    // ...and is dropped once the caller has had its chance to persist it.
    log.append_local("$next", None).unwrap();
    assert!(log.state_after(backfilled).is_none());
}

/// A room shorter than the window keeps everything, so nothing about the common
/// case changes.
#[test]
fn a_short_room_keeps_every_snapshot() {
    let mut log = RoomLog::new();
    for number in 0..64 {
        log.append_local(format!("$event-{number}"), None).unwrap();
    }
    assert_eq!(log.resident_len(), log.len());
    assert!(log.len() < DEFAULT_RESIDENT_WINDOW);
}

/// The invariant that makes `StateNotResident` unreachable on the append path
/// is a claim about code, so it is worth stating that the error exists and what
/// it would mean. An append can only name entries the log holds, and every one
/// of those is either inside the window or a pinned extremity.
#[test]
fn every_predecessor_an_append_can_name_has_resident_state() {
    let window = 8;
    let mut log = RoomLog::with_resident_window(window);
    for number in 0..500 {
        log.append_local(format!("$event-{number}"), None).unwrap();
    }

    // Naming an evicted, non-extremity parent is the one way to reach the
    // error, and it is not something the append API can be driven into by a
    // caller that uses `append_local`.
    let evicted: EventId = log.entries().next().unwrap().event_id.clone();
    let error = log
        .append_remote(EventInput::new("$onto-evicted", vec![evicted.clone()]))
        .unwrap_err();
    assert_eq!(
        error,
        AppendError::StateNotResident {
            li: log.get(&evicted).unwrap().li,
            event_id: evicted,
        },
        "reaching past the window must fail loudly, not append onto empty state"
    );
}
