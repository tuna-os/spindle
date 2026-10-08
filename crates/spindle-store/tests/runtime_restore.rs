use spindle_core::keys::{Keyspace, content_addressed};
use spindle_core::{EventInput, RestoreError, RoomLog, StateKey, StateSnapshot};
use spindle_store::{Durability, FjallStore, RoomStore, Store, StoreError};

#[test]
fn runtime_deferred_old_root_cannot_pass_explicit_exhaustive_store_validation() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let mut log = RoomLog::new();
    let mut first = None;
    for i in 0..600 {
        let state = StateSnapshot::new().apply(
            StateKey::new("m.room.topic", ""),
            format!("$source-outlier{i}"),
        );
        let entry = log
            .append_seeded(EventInput::new(format!("$e{i}"), vec![]), state, i + 1)
            .unwrap()
            .clone();
        if i == 0 {
            first = Some(entry.state_root);
        }
        RoomStore::new(&store, "!r:test")
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }
    let room = RoomStore::new(&store, "!r:test");
    assert!(room.load_exhaustive().unwrap().is_some());
    store
        .delete(&content_addressed(
            Keyspace::StateNode,
            first.unwrap().as_bytes(),
        ))
        .unwrap();
    let runtime = room.load_runtime().unwrap().unwrap();
    assert_eq!(runtime.log.len(), 600);
    assert_eq!(
        runtime
            .log
            .current_state()
            .unwrap()
            .get(&StateKey::new("m.room.topic", "")),
        Some("$source-outlier599")
    );
    assert!(matches!(
        room.load_exhaustive(),
        Err(StoreError::Restore(RestoreError::UnreadableState(1)))
    ));
    let head = runtime.log.entries().next_back().unwrap().state_root;
    store
        .put(
            &content_addressed(Keyspace::StateNode, head.as_bytes()),
            b"corrupt node",
        )
        .unwrap();
    assert!(matches!(
        room.load_runtime(),
        Err(StoreError::Restore(RestoreError::UnreadableState(600)))
    ));
}

// -- the streamed restore -------------------------------------------------

use spindle_core::keys::{room_li, room_prefix};
use spindle_core::{EventId, LinearIndex, RoomLog as Log, Sideline};
use spindle_store::ReadView;
use spindle_store::codec::{CodecError, EntryRecord, RoomRecord};

const ROOM: &str = "!stream:test";

/// A room with everything a restore has to carry: more history than the
/// resident window, state changes inside and outside it, backfilled history
/// below zero (no chain), an open fork whose older tip is far behind the
/// head, a sidelined event and an imported historical rejection.
fn varied_room(store: &FjallStore) -> Log {
    let room = RoomStore::new(store, ROOM);
    let mut log = Log::new();
    let commit = |log: &Log, entry: &spindle_core::LogEntry| {
        room.commit_entry(entry, log, Durability::Relaxed).unwrap();
    };
    for i in 0..40 {
        let entry = log
            .append_local(
                format!("$state{i}"),
                Some(StateKey::new("m.room.member", format!("@u{i}:test"))),
            )
            .unwrap()
            .clone();
        commit(&log, &entry);
    }
    // The fork's stale tip: a sibling of the head as it is now, which
    // nothing later names, so it stays an extremity hundreds of entries
    // behind the head.
    let parent = log.entries().next_back().unwrap().event_id.clone();
    let stale = log
        .append_remote(EventInput::new("$stale-tip", vec![parent.clone()]))
        .unwrap()
        .clone();
    commit(&log, &stale);
    let main = log
        .append_remote(EventInput::new("$main", vec![parent]))
        .unwrap()
        .clone();
    commit(&log, &main);
    for i in 0..700 {
        let parents = vec![log.entries().next_back().unwrap().event_id.clone()];
        let mut input = EventInput::new(format!("$m{i}"), parents);
        if i % 97 == 0 {
            input = input.with_state_key(StateKey::new("m.room.topic", ""));
        }
        let entry = log.append_remote(input).unwrap().clone();
        commit(&log, &entry);
    }
    // Backfilled history, with state supplied from outside.
    for i in 0..30 {
        let supplied =
            StateSnapshot::new().apply(StateKey::new("m.room.name", ""), format!("$name{i}"));
        let entry = log
            .prepend_remote(
                EventInput::new(
                    format!("$old{i}"),
                    vec![EventId::new(format!("$old{}", i + 1))],
                ),
                supplied,
                30 - i,
            )
            .unwrap()
            .clone();
        commit(&log, &entry);
    }
    // A soft-failed event on the head.
    let head = log.entries().next_back().unwrap().event_id.clone();
    let head_state = log.state_after_event(&head).unwrap().clone();
    let sidelined = log
        .sideline(
            EventInput::new("$soft", vec![head]).with_state_key(StateKey::new("m.room.topic", "")),
            head_state.clone(),
            Sideline::SoftFailed,
        )
        .unwrap()
        .clone();
    let after = log.sidelined_state(&sidelined.event_id).unwrap().clone();
    room.journal_sidelined(&sidelined, &after, Some(&head_state), &log, &[])
        .unwrap();
    room.commit_historical_rejections(
        &mut log,
        &[EventId::new("$rejected-elsewhere")],
        &[],
        Durability::Relaxed,
    )
    .unwrap();
    store.flush().unwrap();
    assert!(log.forward_extremities().len() > 1, "the fork is open");
    log
}

type EntryView = (
    i64,
    String,
    Vec<String>,
    u64,
    Option<StateKey>,
    Option<[u8; 32]>,
    [u8; 32],
);

fn entries_of<'a>(entries: impl Iterator<Item = &'a spindle_core::LogEntry>) -> Vec<EntryView> {
    entries
        .map(|e| {
            (
                e.li.get(),
                e.event_id.as_str().to_owned(),
                e.prev_events
                    .iter()
                    .map(|p| p.as_str().to_owned())
                    .collect(),
                e.depth,
                e.state_key.clone(),
                e.chain.map(|c| *c.as_bytes()),
                *e.state_root.as_bytes(),
            )
        })
        .collect()
}

/// Everything a reader of the log can observe, as one comparable value.
fn assert_same_room(expected: &Log, actual: &Log, label: &str) {
    assert_eq!(
        entries_of(expected.entries()),
        entries_of(actual.entries()),
        "{label}: entries"
    );
    assert_eq!(expected.len(), actual.len(), "{label}: length");
    assert_eq!(expected.next_forward(), actual.next_forward(), "{label}");
    assert_eq!(expected.next_backward(), actual.next_backward(), "{label}");
    assert_eq!(
        expected.forward_extremities(),
        actual.forward_extremities(),
        "{label}: extremities"
    );
    assert_eq!(
        expected.authoring_extremities().collect::<Vec<_>>(),
        actual.authoring_extremities().collect::<Vec<_>>(),
        "{label}: authoring extremities"
    );
    assert_eq!(expected.head_chain(), actual.head_chain(), "{label}: chain");
    assert_eq!(
        expected.current_state().map(StateSnapshot::root),
        actual.current_state().map(StateSnapshot::root),
        "{label}: current state"
    );
    for tip in expected.forward_extremities() {
        assert_eq!(
            expected.state_after_event(tip).map(StateSnapshot::root),
            actual.state_after_event(tip).map(StateSnapshot::root),
            "{label}: every tip's state is resident"
        );
    }
    let resident = |log: &Log| {
        log.entries()
            .filter_map(|e| log.state_after(e.li).map(|s| (e.li.get(), s.root())))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        resident(expected),
        resident(actual),
        "{label}: resident window"
    );
    // Pagination: pages from the head, from inside the backfill, and seeks.
    for (from, to) in [(i64::MIN, -20), (-25, 5), (100, 140), (700, i64::MAX)] {
        assert_eq!(
            entries_of(expected.entries_in(from..to).rev()),
            entries_of(actual.entries_in(from..to).rev()),
            "{label}: page {from}..{to}"
        );
    }
    for at in [-100, -29, 0, 1, 41, 500, 10_000] {
        assert_eq!(
            expected.entry_at_or_before(at).map(|e| e.li),
            actual.entry_at_or_before(at).map(|e| e.li),
            "{label}: seek {at}"
        );
    }
    let ids = |log: &Log| {
        let mut ids: Vec<_> = log
            .sidelined_entries()
            .map(|s| (s.event_id.as_str().to_owned(), s.state_root))
            .collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        ids
    };
    assert_eq!(ids(expected), ids(actual), "{label}: sidelined");
    assert_eq!(
        expected.historical_rejections().collect::<Vec<_>>(),
        actual.historical_rejections().collect::<Vec<_>>(),
        "{label}: historical rejections"
    );
    assert_eq!(
        expected.resolution_policy_id(),
        actual.resolution_policy_id(),
        "{label}: resolution policy"
    );
}

#[test]
fn the_streamed_runtime_restore_is_the_room_the_exhaustive_one_and_the_writer_hold() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let written = varied_room(&store);
    drop(store);
    let store = FjallStore::open(dir.path()).unwrap();
    let room = RoomStore::new(&store, ROOM);
    let runtime = room.load_runtime().unwrap().unwrap().log;
    let exhaustive = room.load_exhaustive().unwrap().unwrap().log;
    let (profiled, profile) = room.load_runtime_profiled().unwrap().unwrap();
    assert_eq!(profile.rows, written.len());
    assert!(profile.row_bytes > 0);

    // The writer's own log has the head window resident too; its
    // sidelined state and tips are what a restore must reproduce.
    assert_same_room(&exhaustive, &runtime, "runtime vs exhaustive");
    assert_same_room(&runtime, &profiled.log, "profiled vs runtime");
    assert_eq!(
        entries_of(written.entries()),
        entries_of(runtime.entries()),
        "runtime vs the log that wrote the store"
    );
    assert_eq!(written.head_chain(), runtime.head_chain());
    assert_eq!(written.forward_extremities(), runtime.forward_extremities());

    // And the restored room carries on exactly as the original does.
    let mut original = written;
    let mut restored = runtime;
    let head = original.entries().next_back().unwrap().event_id.clone();
    original
        .append_remote(EventInput::new("$next", vec![head.clone()]))
        .unwrap();
    restored
        .append_remote(EventInput::new("$next", vec![head]))
        .unwrap();
    assert_eq!(original.head_chain(), restored.head_chain());
    assert_eq!(
        original.forward_extremities(),
        restored.forward_extremities()
    );
    assert_eq!(
        original
            .state_after_event(&EventId::new("$next"))
            .map(StateSnapshot::root),
        restored
            .state_after_event(&EventId::new("$next"))
            .map(StateSnapshot::root)
    );
}

/// Rewrite one stored log row through `edit`.
fn edit_row(store: &FjallStore, li: i64, edit: impl FnOnce(&mut EntryRecord)) {
    let key = room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(li));
    let mut record = EntryRecord::decode(&store.get(&key).unwrap().unwrap()).unwrap();
    edit(&mut record);
    store.put(&key, &record.encode()).unwrap();
}

fn edit_meta(store: &FjallStore, edit: impl FnOnce(&mut RoomRecord)) {
    let key = room_prefix(Keyspace::RoomMeta, ROOM);
    let mut record = RoomRecord::decode(&store.get(&key).unwrap().unwrap()).unwrap();
    edit(&mut record);
    store.put(&key, &record.encode()).unwrap();
}

/// How to damage a stored room, and the refusal that damage must meet.
type Corruption = (
    &'static str,
    Box<dyn Fn(&FjallStore, &Log)>,
    Box<dyn Fn(&StoreError) -> bool>,
);

fn corruptions() -> Vec<Corruption> {
    vec![
        (
            "an edited event id in sequenced history",
            Box::new(|store, _| edit_row(store, 300, |r| "$edited".clone_into(&mut r.event_id))),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::BrokenChain(300)))),
        ),
        (
            "an edited chain value",
            Box::new(|store, _| edit_row(store, 5, |r| r.chain = Some([9; 32]))),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::BrokenChain(5)))),
        ),
        (
            "a sequenced row stripped of its attestation",
            Box::new(|store, _| edit_row(store, 600, |r| r.chain = None)),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::BrokenChain(601)))),
        ),
        (
            "a truncated row",
            Box::new(|store, _| {
                let key = room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(17));
                let mut value = store.get(&key).unwrap().unwrap();
                value.truncate(value.len() / 2);
                store.put(&key, &value).unwrap();
            }),
            Box::new(|e| matches!(e, StoreError::Codec(CodecError::Truncated))),
        ),
        (
            "a row from an unknown record version",
            Box::new(|store, _| {
                let key = room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(-3));
                let mut value = store.get(&key).unwrap().unwrap();
                value[0] = 99;
                store.put(&key, &value).unwrap();
            }),
            Box::new(|e| matches!(e, StoreError::Codec(CodecError::UnsupportedVersion(99)))),
        ),
        (
            "one event at two positions",
            Box::new(|store, _| edit_row(store, -4, |r| "$state3".clone_into(&mut r.event_id))),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::DuplicateEvent(_)))),
        ),
        (
            "a row filed under the wrong position",
            Box::new(|store, _| edit_row(store, 2, |r| r.li = 1)),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::DuplicateIndex(1)))),
        ),
        (
            "counters that would reissue a held position",
            Box::new(|store, _| edit_meta(store, |m| m.next_forward -= 1)),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::InvalidCounters { .. }))),
        ),
        (
            "a tip the log does not hold",
            Box::new(|store, _| {
                edit_meta(store, |m| m.forward_extremities.push("$nowhere".to_owned()));
            }),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::MissingExtremity(_)))),
        ),
        (
            "the stale tip's state, far outside the window, unreadable",
            Box::new(|store, log| {
                let tip = log.get(&EventId::new("$stale-tip")).unwrap();
                store
                    .put(
                        &content_addressed(Keyspace::StateNode, tip.state_root.as_bytes()),
                        b"not a node",
                    )
                    .unwrap();
            }),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::UnreadableState(_)))),
        ),
        (
            "the head's state unreadable",
            Box::new(|store, log| {
                let head = log.entries().next_back().unwrap();
                store
                    .delete(&content_addressed(
                        Keyspace::StateNode,
                        head.state_root.as_bytes(),
                    ))
                    .unwrap();
            }),
            Box::new(|e| matches!(e, StoreError::Restore(RestoreError::UnreadableState(_)))),
        ),
    ]
}

/// Every corruption the batch restore refused, the streamed one refuses
/// too -- in the runtime and the exhaustive form alike. Nothing is served
/// from a log that fails a check, whichever row the check fails on.
#[test]
fn the_streamed_restore_fails_closed_on_every_corruption() {
    let cases = corruptions();
    for (label, corrupt, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let log = varied_room(&store);
        assert!(
            RoomStore::new(&store, ROOM).load_runtime().is_ok(),
            "{label}"
        );
        corrupt(&store, &log);
        let room = RoomStore::new(&store, ROOM);
        match room.load_runtime() {
            Err(error) => assert!(expected(&error), "{label}: runtime refused with {error}"),
            Ok(_) => panic!("{label}: the runtime restore accepted it"),
        }
        match room.load_exhaustive() {
            Err(error) => assert!(expected(&error), "{label}: exhaustive refused with {error}"),
            Ok(_) => panic!("{label}: the exhaustive restore accepted it"),
        }
    }
}

/// The decoder the restore streams through reads exactly what the record
/// decoder reads, and refuses exactly what it refuses.
#[test]
fn decode_restored_agrees_with_decode_on_every_stored_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    varied_room(&store);
    let rows = store
        .scan_prefix(&room_prefix(Keyspace::Log, ROOM))
        .unwrap();
    assert!(rows.len() > 700);
    for (_, value) in rows {
        let record = EntryRecord::decode(&value).unwrap();
        let restored = EntryRecord::decode_restored(&value).unwrap();
        assert_eq!(restored.li, record.linear_index());
        assert_eq!(restored.event_id, record.event());
        assert_eq!(restored.prev_events, record.parents());
        assert_eq!(restored.depth, record.depth);
        assert_eq!(restored.state_key, record.slot());
        assert_eq!(restored.expected_state_root, record.state_root);
        assert_eq!(restored.chain, record.chain);
        for cut in 0..value.len() {
            assert_eq!(
                EntryRecord::decode(&value[..cut]).err(),
                EntryRecord::decode_restored(&value[..cut]).err(),
                "a row cut at {cut}"
            );
        }
    }
}

// -- the pipelined restore of a large room --------------------------------

const LARGE: &str = "!large:test";

/// A room large enough to be restored on two threads, written straight in
/// the record format: backfilled history with no chain, then sequenced
/// history with one.
fn large_room(store: &FjallStore, forward: i64, backfilled: i64) {
    let state = StateSnapshot::new().apply(StateKey::new("m.room.create", ""), "$create");
    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = state
        .delta_nodes(None)
        .into_iter()
        .map(|(address, node)| {
            (
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            )
        })
        .collect();
    let root = *state.root().as_bytes();
    let row = |li: i64, chain: Option<[u8; 32]>| {
        (
            room_li(Keyspace::Log, LARGE, LinearIndex::from_raw(li)),
            EntryRecord {
                li,
                event_id: format!("$e{li}"),
                prev_events: vec![format!("$e{}", li - 1)],
                depth: u64::try_from(li + backfilled).unwrap(),
                state_key: None,
                state_root: root,
                chain,
            }
            .encode(),
        )
    };
    for li in (1 - backfilled)..=0 {
        batch.push(row(li, None));
    }
    let mut chain = spindle_core::ChainHash::seed();
    for li in 1..=forward {
        chain = chain.extend(&EventId::new(format!("$e{li}")));
        batch.push(row(li, Some(*chain.as_bytes())));
    }
    batch.push((
        room_prefix(Keyspace::RoomMeta, LARGE),
        RoomRecord {
            next_forward: forward + 1,
            next_backward: -backfilled,
            forward_extremities: vec![format!("$e{forward}")],
        }
        .encode(),
    ));
    store.commit(&batch, Durability::Relaxed).unwrap();
}

fn edit_large(store: &FjallStore, li: i64, edit: impl FnOnce(&mut Vec<u8>)) {
    let key = room_li(Keyspace::Log, LARGE, LinearIndex::from_raw(li));
    let mut value = store.get(&key).unwrap().unwrap();
    edit(&mut value);
    store.put(&key, &value).unwrap();
}

#[test]
fn the_pipelined_restore_is_the_sequential_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    large_room(&store, 40_000, 500);
    let room = RoomStore::new(&store, LARGE);
    let (runtime, profile) = room.load_runtime_profiled().unwrap().unwrap();
    assert_eq!(profile.rows, 40_500);
    let exhaustive = room.load_exhaustive().unwrap().unwrap().log;
    // The batch form, fed every row on one thread.
    let rows: Vec<_> = store
        .scan_prefix(&room_prefix(Keyspace::Log, LARGE))
        .unwrap()
        .into_iter()
        .map(|(_, value)| EntryRecord::decode_restored(&value).unwrap())
        .collect();
    let mut load_node = |address: &spindle_core::StateRoot| {
        store
            .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))
            .unwrap()
    };
    let sequential = Log::restore_runtime(
        rows,
        40_001,
        -500,
        [EventId::new("$e40000")],
        &mut load_node,
    )
    .unwrap()
    .log;
    for (label, log) in [("runtime", &runtime.log), ("exhaustive", &exhaustive)] {
        assert_eq!(
            entries_of(sequential.entries()),
            entries_of(log.entries()),
            "{label}"
        );
        assert_eq!(sequential.head_chain(), log.head_chain(), "{label}");
        assert_eq!(sequential.resident_len(), log.resident_len(), "{label}");
        assert_eq!(
            sequential.forward_extremities(),
            log.forward_extremities(),
            "{label}"
        );
    }
}

/// Two corruptions in one large room: whichever comes first in the log is
/// the one reported, exactly as a restore on one thread reports it, though
/// the decode of the later row may run ahead of the check of the earlier.
#[test]
fn the_pipelined_restore_reports_the_first_corruption_in_log_order() {
    let truncate = |value: &mut Vec<u8>| value.truncate(20);
    let break_chain = |value: &mut Vec<u8>| {
        let mut record = EntryRecord::decode(value).unwrap();
        record.chain = Some([1; 32]);
        *value = record.encode();
    };
    for (chain_at, truncated_at, expect_chain) in [
        (1_000, 30_000, true),
        (30_000, 1_000, false),
        (39_999, 40_000, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        large_room(&store, 40_000, 500);
        edit_large(&store, chain_at, break_chain);
        edit_large(&store, truncated_at, truncate);
        let room = RoomStore::new(&store, LARGE);
        for result in [
            room.load_runtime().map(|_| ()),
            room.load_exhaustive().map(|_| ()),
        ] {
            let error = result.unwrap_err();
            if expect_chain {
                assert!(
                    matches!(error, StoreError::Restore(RestoreError::BrokenChain(li)) if li == chain_at),
                    "chain at {chain_at}, truncated at {truncated_at}: {error}"
                );
            } else {
                assert!(
                    matches!(error, StoreError::Codec(CodecError::Truncated)),
                    "chain at {chain_at}, truncated at {truncated_at}: {error}"
                );
            }
        }
    }
    // And each on its own, in the backfilled range too.
    for (li, edit) in [(-499, 0_u8), (-1, 1), (20_000, 1)] {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        large_room(&store, 40_000, 500);
        if edit == 0 {
            edit_large(&store, li, |value| value[0] = 7);
        } else {
            edit_large(&store, li, |value| {
                let mut record = EntryRecord::decode(value).unwrap();
                "$e5".clone_into(&mut record.event_id);
                *value = record.encode();
            });
        }
        let error = RoomStore::new(&store, LARGE).load_runtime().unwrap_err();
        let expected = match (li, edit) {
            (_, 0) => matches!(error, StoreError::Codec(CodecError::UnsupportedVersion(7))),
            // Backfilled history carries no attestation, so a repeated ID
            // there is caught when its original turns up at li 5...
            (-1, _) => matches!(error, StoreError::Restore(RestoreError::DuplicateEvent(_))),
            // ...while in sequenced history the chain catches it first.
            _ => matches!(
                error,
                StoreError::Restore(RestoreError::BrokenChain(20_000))
            ),
        };
        assert!(expected, "row {li}: {error}");
    }
}
