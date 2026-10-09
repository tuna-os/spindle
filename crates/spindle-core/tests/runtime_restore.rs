use spindle_core::{
    EventId, EventInput, RestoreError, RestoredEntry, RoomLog, StateKey, StateRoot, StateSnapshot,
};
use std::collections::{HashMap, HashSet};

fn seeded() -> (RoomLog, Vec<RestoredEntry>, HashMap<StateRoot, Vec<u8>>) {
    let mut log = RoomLog::new();
    let mut state = StateSnapshot::new();
    for i in 0..128 {
        state = state.apply(
            StateKey::new("m.room.member", format!("@u{i}:test")),
            format!("$m{i}"),
        );
    }
    let mut nodes: HashMap<_, _> = state.delta_nodes(None).into_iter().collect();
    for i in 0..600 {
        let previous = state.clone();
        state = state.apply(
            StateKey::new("m.room.topic", ""),
            format!("$outlier-state{i}"),
        );
        nodes.extend(state.delta_nodes(Some(&previous)));
        let parents = if i == 0 {
            vec![]
        } else {
            vec![EventId::new(format!("$e{}", i - 1))]
        };
        log.append_seeded(
            EventInput::new(format!("$e{i}"), parents),
            state.clone(),
            i + 1,
        )
        .unwrap();
    }
    let entries = log
        .entries()
        .map(|e| RestoredEntry {
            li: e.li,
            event_id: e.event_id.clone(),
            prev_events: e.prev_events.clone(),
            depth: e.depth,
            state_key: e.state_key.clone(),
            expected_state_root: *e.state_root.as_bytes(),
            chain: e.chain.map(|c| *c.as_bytes()),
        })
        .collect();
    (log, entries, nodes)
}

#[test]
fn runtime_preserves_history_cursors_seed_roots_and_following_append() {
    let (mut original, entries, nodes) = seeded();
    let oldest = entries[0].expected_state_root;
    let mut reads = HashSet::new();
    let mut restored = RoomLog::restore_runtime(
        entries,
        original.next_forward(),
        original.next_backward(),
        original.forward_extremities().iter().cloned(),
        &mut |root| {
            reads.insert(*root);
            nodes.get(root).cloned()
        },
    )
    .unwrap()
    .log;
    assert!(!reads.contains(&StateRoot::from_bytes(oldest)));
    assert!(restored.state_after_event(&EventId::new("$e0")).is_none());
    assert_eq!(restored.resident_len(), 512);
    for (a, b) in original.entries().zip(restored.entries()) {
        assert_eq!(
            (
                a.li,
                &a.event_id,
                &a.prev_events,
                a.depth,
                &a.state_key,
                a.chain,
                a.state_root
            ),
            (
                b.li,
                &b.event_id,
                &b.prev_events,
                b.depth,
                &b.state_key,
                b.chain,
                b.state_root
            )
        );
    }
    assert_eq!(original.next_forward(), restored.next_forward());
    assert_eq!(original.next_backward(), restored.next_backward());
    assert_eq!(
        original.forward_extremities(),
        restored.forward_extremities()
    );
    assert_eq!(
        restored
            .current_state()
            .unwrap()
            .get(&StateKey::new("m.room.topic", "")),
        Some("$outlier-state599")
    );
    let old = restored
        .state_after_any(&EventId::new("$e0"), &mut |r| nodes.get(r).cloned())
        .unwrap();
    assert_eq!(
        old.get(&StateKey::new("m.room.topic", "")),
        Some("$outlier-state0")
    );
    assert_eq!(*old.root().as_bytes(), oldest);
    restored.append_local("$next", None).unwrap();
    original.append_local("$next", None).unwrap();
    assert_eq!(
        restored.current_state().unwrap().root(),
        original.current_state().unwrap().root()
    );
    assert_eq!(
        restored.entries().next_back().unwrap().li,
        original.entries().next_back().unwrap().li
    );
}

#[test]
fn historical_corruption_is_deferred_only_in_runtime_and_exhaustive_detects_it() {
    let (original, entries, mut nodes) = seeded();
    nodes.remove(&StateRoot::from_bytes(entries[0].expected_state_root));
    let restored = RoomLog::restore_runtime(
        entries.clone(),
        original.next_forward(),
        original.next_backward(),
        original.forward_extremities().iter().cloned(),
        &mut |r| nodes.get(r).cloned(),
    )
    .unwrap()
    .log;
    assert!(
        restored
            .state_after_any(&EventId::new("$e0"), &mut |r| nodes.get(r).cloned())
            .is_err()
    );
    assert_eq!(
        RoomLog::restore_exhaustive(
            entries,
            original.next_forward(),
            original.next_backward(),
            original.forward_extremities().iter().cloned(),
            &mut |r| nodes.get(r).cloned()
        )
        .unwrap_err(),
        RestoreError::UnreadableState(1)
    );
}

#[test]
fn selected_roots_and_old_forward_extremities_are_verified_before_serving() {
    let (original, entries, nodes) = seeded();
    let tips = vec![EventId::new("$e0"), EventId::new("$e599")];
    let restored = RoomLog::restore_runtime(
        entries.clone(),
        original.next_forward(),
        original.next_backward(),
        tips.clone(),
        &mut |r| nodes.get(r).cloned(),
    )
    .unwrap()
    .log;
    assert_eq!(restored.resident_len(), 513);
    assert!(restored.state_after_event(&tips[0]).is_some());
    for bad in [0, 599] {
        for corrupt in [false, true] {
            let mut altered = nodes.clone();
            let root = StateRoot::from_bytes(entries[bad].expected_state_root);
            if corrupt {
                altered.insert(root, b"corrupt node".to_vec());
            } else {
                altered.remove(&root);
            }
            assert_eq!(
                RoomLog::restore_runtime(
                    entries.clone(),
                    original.next_forward(),
                    original.next_backward(),
                    tips.clone(),
                    &mut |r| altered.get(r).cloned()
                )
                .unwrap_err(),
                RestoreError::UnreadableState(i64::try_from(bad).unwrap() + 1)
            );
        }
    }
}

#[test]
fn full_chain_is_checked_even_for_nonresident_old_history() {
    let mut original = RoomLog::new();
    original.append_local("$a", None).unwrap();
    original.append_local("$b", None).unwrap();
    let mut records: Vec<_> = original
        .entries()
        .map(|e| RestoredEntry {
            li: e.li,
            event_id: e.event_id.clone(),
            prev_events: e.prev_events.clone(),
            depth: e.depth,
            state_key: e.state_key.clone(),
            expected_state_root: *e.state_root.as_bytes(),
            chain: e.chain.map(|c| *c.as_bytes()),
        })
        .collect();
    records[0].chain = Some([9; 32]);
    assert_eq!(
        RoomLog::restore_runtime(
            records,
            original.next_forward(),
            original.next_backward(),
            original.forward_extremities().iter().cloned(),
            &mut |_| None
        )
        .unwrap_err(),
        RestoreError::BrokenChain(1)
    );
}

#[test]
fn exhaustive_rolling_owners_keep_distributed_seed_node_reads_bounded() {
    let (original, entries, nodes) = seeded();
    let mut reads = 0;
    let restored = RoomLog::restore_exhaustive(
        entries,
        original.next_forward(),
        original.next_backward(),
        original.forward_extremities().iter().cloned(),
        &mut |r| {
            reads += 1;
            nodes.get(r).cloned()
        },
    )
    .unwrap();
    assert!(
        reads <= nodes.len(),
        "{reads} reads for {} distinct nodes",
        nodes.len()
    );
    assert!(restored.unverified.is_empty());
    assert!(restored.broken_chain.is_empty());
    assert_eq!(restored.log.resident_len(), 512);
}

#[test]
fn exhaustive_repeated_nonresident_root_is_loaded_once() {
    let mut log = RoomLog::new();
    let mut state = StateSnapshot::new();
    for i in 0..1024 {
        state = state.apply(
            StateKey::new("m.room.member", format!("@u{i}:test")),
            format!("$m{i}"),
        );
    }
    let nodes: HashMap<_, _> = state.delta_nodes(None).into_iter().collect();
    for i in 0..2048 {
        log.append_seeded(
            EventInput::new(format!("$repeat{i}"), vec![]),
            state.clone(),
            i + 1,
        )
        .unwrap();
    }
    let records: Vec<_> = log
        .entries()
        .map(|e| RestoredEntry {
            li: e.li,
            event_id: e.event_id.clone(),
            prev_events: e.prev_events.clone(),
            depth: e.depth,
            state_key: e.state_key.clone(),
            expected_state_root: *e.state_root.as_bytes(),
            chain: None,
        })
        .collect();
    let mut reads = 0;
    let reopened = RoomLog::restore_exhaustive(
        records,
        log.next_forward(),
        log.next_backward(),
        log.forward_extremities().iter().cloned(),
        &mut |r| {
            reads += 1;
            nodes.get(r).cloned()
        },
    )
    .unwrap();
    assert_eq!(reads, nodes.len());
    assert_eq!(reopened.log.len(), 2048);
    assert_eq!(reopened.log.resident_len(), 512);
}

#[test]
fn duplicate_ids_and_colliding_counters_fail_before_state_reads() {
    let (original, mut entries, nodes) = seeded();
    entries[1].event_id = entries[0].event_id.clone();
    assert!(matches!(
        RoomLog::restore_runtime(
            entries,
            original.next_forward(),
            original.next_backward(),
            original.forward_extremities().iter().cloned(),
            &mut |_| panic!("metadata failure must precede state I/O")
        ),
        Err(RestoreError::DuplicateEvent(_))
    ));
    let (_, entries, _) = seeded();
    assert!(matches!(
        RoomLog::restore_runtime(
            entries,
            600,
            original.next_backward(),
            original.forward_extremities().iter().cloned(),
            &mut |r| nodes.get(r).cloned()
        ),
        Err(RestoreError::InvalidCounters { .. })
    ));
}
