use std::time::{Duration, Instant};

use spindle_core::{EventId, EventInput, RoomLog, StateKey, StateSnapshot};

fn assert_budget(name: &str, elapsed: Duration, budget: Duration) {
    eprintln!(
        "benchmark={name} elapsed_ms={} budget_ms={}",
        elapsed.as_millis(),
        budget.as_millis()
    );
    assert!(elapsed <= budget, "{name} exceeded its regression budget");
}

#[test]
#[ignore = "release-mode CI performance gate"]
fn hamt_applies_twenty_thousand_unique_state_updates_within_budget() {
    let started = Instant::now();
    let mut state = StateSnapshot::new();
    for number in 0..20_000 {
        state = state.apply(
            StateKey::new("m.room.member", format!("@user-{number}:example.org")),
            format!("$event-{number}"),
        );
    }
    let elapsed = started.elapsed();

    assert_eq!(state.len(), 20_000);
    assert_budget("hamt_unique_updates_20k", elapsed, Duration::from_secs(10));
}

#[test]
#[ignore = "release-mode CI performance gate"]
fn fork_window_walks_four_thousand_divergent_events_within_budget() {
    let mut room = RoomLog::new();
    room.append_local("$root", None).unwrap();
    let mut left = EventId::new("$root");
    let mut right = EventId::new("$root");
    for number in 0..2_000 {
        let next_left = EventId::new(format!("$left-{number}"));
        room.append_remote(EventInput::new(
            next_left.as_str(),
            vec![left.clone()],
        ))
        .unwrap();
        left = next_left;

        let next_right = EventId::new(format!("$right-{number}"));
        room.append_remote(EventInput::new(
            next_right.as_str(),
            vec![right.clone()],
        ))
        .unwrap();
        right = next_right;
    }

    let started = Instant::now();
    let window = room.fork_window(&[left, right], 4_000).unwrap();
    let elapsed = started.elapsed();

    assert_eq!(window.events.len(), 4_000);
    assert_budget("fork_window_4k", elapsed, Duration::from_secs(5));
}
