//! Cold reopen must reuse immutable historical subtrees without changing any
//! stored root, timeline cursor, extremity, or following ordinary append.
use spindle_core::{
    EventId, EventInput, RestoredEntry, RoomLog, StateKey, StateRoot, StateSnapshot,
};
use std::collections::HashMap;

#[test]
fn many_seeded_historical_roots_reopen_equivalently_with_changed_path_reads() {
    let mut expected = RoomLog::new();
    let mut state = StateSnapshot::new();
    for index in 0..512 {
        state = state.apply(
            StateKey::new("m.room.member", format!("@u{index}:test")),
            format!("$member{index}"),
        );
    }
    let updated_key = StateKey::new("m.room.member", "@u0:test");
    let mut stored: HashMap<StateRoot, Vec<u8>> = state.delta_nodes(None).into_iter().collect();
    let mut previous: Option<EventId> = None;
    for index in 0..100 {
        let before = state.clone();
        state = state.apply(updated_key.clone(), format!("$current-only{index}"));
        stored.extend(state.delta_nodes(Some(&before)));
        let id = EventId::new(format!("$timeline{index}"));
        expected
            .append_seeded(
                EventInput::new(id.as_str(), previous.iter().cloned().collect()),
                state.clone(),
                index + 1,
            )
            .unwrap();
        previous = Some(id);
    }
    let entries: Vec<RestoredEntry> = expected
        .entries()
        .map(|entry| RestoredEntry {
            li: entry.li,
            event_id: entry.event_id.clone(),
            prev_events: entry.prev_events.clone(),
            depth: entry.depth,
            state_key: entry.state_key.clone(),
            expected_state_root: *entry.state_root.as_bytes(),
            chain: entry.chain.map(|chain| *chain.as_bytes()),
        })
        .collect();
    let mut reads = 0;
    let mut restored = RoomLog::restore_with_state(
        entries,
        expected.next_forward(),
        expected.next_backward(),
        expected.forward_extremities().iter().cloned(),
        &mut |root| {
            reads += 1;
            stored.get(root).cloned()
        },
    )
    .unwrap();
    assert!(restored.unverified.is_empty());
    assert!(restored.broken_chain.is_empty());
    assert!(
        reads <= stored.len(),
        "{reads} node reads for {} distinct immutable nodes",
        stored.len()
    );
    assert_eq!(restored.log.next_forward(), expected.next_forward());
    assert_eq!(restored.log.next_backward(), expected.next_backward());
    assert_eq!(
        restored.log.forward_extremities(),
        expected.forward_extremities()
    );
    for (original, reopened) in expected.entries().zip(restored.log.entries()) {
        assert_eq!(original.li, reopened.li);
        assert_eq!(original.event_id, reopened.event_id);
        assert_eq!(original.prev_events, reopened.prev_events);
        assert_eq!(original.state_root, reopened.state_root);
        assert_eq!(original.chain, reopened.chain);
        assert_eq!(
            expected.state_after(original.li).unwrap().root(),
            restored.log.state_after(reopened.li).unwrap().root()
        );
    }
    assert_eq!(
        restored.log.current_state().unwrap().get(&updated_key),
        Some("$current-only99")
    );
    restored.log.append_local("$next-message", None).unwrap();
    expected.append_local("$next-message", None).unwrap();
    assert_eq!(
        restored.log.current_state().unwrap().root(),
        expected.current_state().unwrap().root()
    );
    assert_eq!(
        restored.log.current_state().unwrap().get(&updated_key),
        Some("$current-only99")
    );
}

#[test]
fn each_independent_cold_rebuild_rechecks_missing_and_corrupt_nodes() {
    let mut log = RoomLog::new();
    let state = StateSnapshot::new().apply(
        StateKey::new("m.room.member", "@a:test"),
        "$accepted-outlier",
    );
    log.append_seeded(EventInput::new("$seed", Vec::new()), state.clone(), 1)
        .unwrap();
    let entry = log.entries().next().unwrap();
    let records = vec![RestoredEntry {
        li: entry.li,
        event_id: entry.event_id.clone(),
        prev_events: entry.prev_events.clone(),
        depth: entry.depth,
        state_key: entry.state_key.clone(),
        expected_state_root: *entry.state_root.as_bytes(),
        chain: None,
    }];
    let stored: HashMap<StateRoot, Vec<u8>> = state.delta_nodes(None).into_iter().collect();
    let verified = RoomLog::restore_with_state(
        records.clone(),
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |root| stored.get(root).cloned(),
    )
    .unwrap();
    assert!(verified.unverified.is_empty());
    let missing = RoomLog::restore_with_state(
        records.clone(),
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |_| None,
    )
    .unwrap();
    assert_eq!(missing.unverified, vec![entry.li]);
    let corrupt = RoomLog::restore_with_state(
        records,
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |root| {
            stored.get(root).cloned().map(|mut bytes| {
                bytes[1] ^= 1;
                bytes
            })
        },
    )
    .unwrap();
    assert_eq!(corrupt.unverified, vec![entry.li]);
    assert_ne!(
        corrupt.log.entries().next().unwrap().state_root,
        entry.state_root
    );
}

/// Mirrors the measured hard-room state cardinality and seeded-root count,
/// while varying keys and update widths. This is synthetic scaling evidence;
/// the migrated store still needs its independent cold-read proof.
#[test]
#[ignore = "production-sized scaling probe; run explicitly with --ignored --nocapture"]
fn production_shaped_varied_roots_cold_rebuild() {
    use std::time::Instant;
    const SLOTS: usize = 51_395;
    const ROOTS: usize = 8_957;
    let started = Instant::now();
    let mut state = StateSnapshot::new();
    for slot in 0..SLOTS {
        state = state.apply(
            StateKey::new("m.room.member", format!("@member{slot}:synthetic.test")),
            format!("$original-member-{slot}-synthetic"),
        );
    }
    let initial_nodes = state.delta_nodes(None).len();
    let mut stored: HashMap<StateRoot, Vec<u8>> = state.delta_nodes(None).into_iter().collect();
    let mut log = RoomLog::new();
    let mut previous: Option<EventId> = None;
    let mut baseline = Vec::new();
    let mut random = 17_u64;
    for root in 0..ROOTS {
        let before = state.clone();
        for change in 0..(1 + root % 16) {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let slot = random % u64::try_from(SLOTS).unwrap();
            state = state.apply(
                StateKey::new("m.room.member", format!("@member{slot}:synthetic.test")),
                format!("$changed-{root}-{change}-synthetic"),
            );
        }
        stored.extend(state.delta_nodes(Some(&before)));
        if baseline.len() < 64 {
            baseline.push(state.root());
        }
        let id = EventId::new(format!("$timeline-{root}"));
        log.append_seeded(
            EventInput::new(id.as_str(), previous.iter().cloned().collect()),
            state.clone(),
            u64::try_from(root + 1).unwrap(),
        )
        .unwrap();
        previous = Some(id);
    }
    let generation_seconds = started.elapsed().as_secs_f64();
    let baseline_started = Instant::now();
    let mut baseline_reads = 0;
    for root in &baseline {
        let restored = StateSnapshot::rehydrate(*root, &mut |address| {
            baseline_reads += 1;
            stored.get(address).cloned()
        })
        .unwrap();
        assert_eq!(restored.root(), *root);
        assert_eq!(restored.len(), SLOTS);
    }
    let baseline_seconds = baseline_started.elapsed().as_secs_f64();
    let records = log.entries().map(|entry| RestoredEntry {
        li: entry.li,
        event_id: entry.event_id.clone(),
        prev_events: entry.prev_events.clone(),
        depth: entry.depth,
        state_key: entry.state_key.clone(),
        expected_state_root: *entry.state_root.as_bytes(),
        chain: entry.chain.map(|chain| *chain.as_bytes()),
    });
    let cached_started = Instant::now();
    let mut cached_reads = 0;
    let restored = RoomLog::restore_with_state(
        records,
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |root| {
            cached_reads += 1;
            stored.get(root).cloned()
        },
    )
    .unwrap();
    let cached_seconds = cached_started.elapsed().as_secs_f64();
    assert!(restored.unverified.is_empty());
    assert!(restored.broken_chain.is_empty());
    assert_eq!(restored.log.current_state().unwrap().root(), state.root());
    assert_eq!(restored.log.next_forward(), log.next_forward());
    assert!(cached_reads < initial_nodes * ROOTS / 10);
    println!(
        "{}",
        serde_json::json!({
            "fixture": "synthetic-varied-membership-roots", "slots": SLOTS, "roots": ROOTS,
            "initial_nodes": initial_nodes, "distinct_stored_nodes": stored.len(),
            "generation_seconds": generation_seconds, "uncached_roots": baseline.len(),
            "uncached_node_reads": baseline_reads, "uncached_seconds": baseline_seconds,
            "cached_node_reads": cached_reads, "cached_seconds": cached_seconds,
        })
    );
}
