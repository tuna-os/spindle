//! Part of #6: what a reopen must reproduce, and what it must admit it cannot.

use proptest::prelude::*;
use spindle_core::{EventInput, RoomLog, StateKey, StateSnapshot};
use spindle_store::{
    FjallStore, ReadView, RoomStore, Store, StoreError,
    codec::{CodecError, EntryRecord, RECORD_VERSION, RoomRecord},
};
use tempfile::TempDir;

const ROOM: &str = "!room:example.org";

fn live_room() -> RoomLog {
    let mut room = RoomLog::new();
    room.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    room.append_local("$topic", Some(StateKey::new("m.room.topic", "")))
        .unwrap();
    room.append_local("$message", None).unwrap();
    room
}

#[test]
fn a_reopen_reproduces_head_extremities_counters_and_state() {
    let dir = TempDir::new().unwrap();
    let original = live_room();

    {
        let store = FjallStore::open(dir.path()).unwrap();
        RoomStore::new(&store, ROOM).save(&original).unwrap();
    }

    // A genuinely separate open, not a reused handle.
    let store = FjallStore::open(dir.path()).unwrap();
    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();

    assert!(
        restored.unverified.is_empty(),
        "live history must refold exactly; unverified: {:?}",
        restored.unverified
    );
    assert_eq!(restored.log.len(), original.len());
    assert_eq!(restored.log.next_forward(), original.next_forward());
    assert_eq!(restored.log.next_backward(), original.next_backward());
    assert_eq!(
        restored.log.forward_extremities(),
        original.forward_extremities()
    );

    // The state root is the real test: it proves the fold was reproduced, not
    // merely that bytes survived.
    let restored_head = restored.log.entries().next_back().unwrap();
    let original_head = original.entries().next_back().unwrap();
    assert_eq!(restored_head.event_id, original_head.event_id);
    assert_eq!(
        restored_head.state_root.as_bytes(),
        original_head.state_root.as_bytes()
    );

    // And the state itself is queryable, not just hash-equal.
    assert_eq!(
        restored
            .log
            .state_after(restored_head.li)
            .unwrap()
            .get(&StateKey::new("m.room.topic", "")),
        Some("$topic")
    );
}

#[test]
fn history_scans_back_in_log_order_after_a_reopen() {
    let dir = TempDir::new().unwrap();
    let mut room = live_room();
    room.prepend_remote(EventInput::new("$older", vec![]), StateSnapshot::new(), 40)
        .unwrap();

    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&room).unwrap();
    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();

    let order: Vec<&str> = restored
        .log
        .entries()
        .map(|entry| entry.event_id.as_str())
        .collect();
    // Backfilled history sorts first purely on key bytes -- nothing re-sorts.
    assert_eq!(order, vec!["$older", "$create", "$topic", "$message"]);
}

#[test]
fn backfilled_state_survives_a_reopen_now_that_the_trie_is_persisted() {
    let dir = TempDir::new().unwrap();
    let mut room = live_room();

    // Backfilled state comes from /state_ids (SPEC 6.5), not from parents this
    // log holds, so a refold cannot reproduce it.
    let supplied = StateSnapshot::new().apply(StateKey::new("m.room.name", ""), "$name");
    room.prepend_remote(EventInput::new("$older", vec![]), supplied, 40)
        .unwrap();

    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&room).unwrap();
    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();

    // Before the trie was persisted this could only be refolded, and a refold
    // cannot reproduce it: the state came from /state_ids, not from parents
    // this log holds. Loading the stored nodes restores it exactly.
    assert!(
        restored.unverified.is_empty(),
        "persisted state should restore exactly; unverified: {:?}",
        restored.unverified
    );
    let backfilled = restored
        .log
        .entries()
        .find(|entry| entry.li.get() == 0)
        .unwrap();
    assert_eq!(
        restored
            .log
            .state_after(backfilled.li)
            .unwrap()
            .get(&StateKey::new("m.room.name", "")),
        Some("$name"),
        "the externally supplied state came back"
    );
}

#[test]
fn a_corrupted_state_node_is_detected_rather_than_served() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&live_room()).unwrap();

    // Flip a byte in a stored trie node. Content addressing exists precisely so
    // this is caught; the alternative is serving state that silently is not
    // what was written.
    let prefix = [
        spindle_core::keys::KEY_SCHEMA_VERSION,
        spindle_core::keys::Keyspace::StateNode as u8,
    ];
    let (key, mut value) = store
        .scan_prefix(&prefix)
        .unwrap()
        .into_iter()
        .next()
        .expect("state nodes were persisted");
    let last = value.len() - 1;
    value[last] ^= 0xff;
    store.put(&key, &value).unwrap();

    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();

    // Rehydration rejects the tampered node on its hash, and the load falls
    // back to refolding from the log -- which is the authoritative record. The
    // state trie is derived data, so corrupting it costs time on the next open,
    // not correctness.
    assert!(
        restored.unverified.is_empty(),
        "a refold from the log should still reproduce the recorded roots"
    );
    let head_li = restored.log.entries().next_back().unwrap().li;
    assert_eq!(
        restored
            .log
            .state_after(head_li)
            .unwrap()
            .get(&StateKey::new("m.room.topic", "")),
        Some("$topic"),
        "the room's state survived a corrupted trie node"
    );
    assert_eq!(
        restored.log.entries().next_back().unwrap().state_root,
        live_room().entries().next_back().unwrap().state_root,
    );
}

#[test]
fn an_unknown_room_is_distinguishable_from_an_empty_one() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    assert!(RoomStore::new(&store, ROOM).load().unwrap().is_none());

    RoomStore::new(&store, ROOM).save(&RoomLog::new()).unwrap();
    let empty = RoomStore::new(&store, ROOM).load().unwrap();
    assert!(empty.is_some());
    assert_eq!(empty.unwrap().log.len(), 0);
}

#[test]
fn a_truncated_record_is_an_error_not_a_panic() {
    let entry = EntryRecord {
        li: 7,
        event_id: "$abc".to_owned(),
        prev_events: vec!["$def".to_owned()],
        depth: 3,
        state_key: Some(("m.room.topic".to_owned(), String::new())),
        state_root: [9_u8; 32],
        chain: Some([7_u8; 32]),
    };
    let encoded = entry.encode();
    assert_eq!(EntryRecord::decode(&encoded).unwrap(), entry);

    for cut in 0..encoded.len() {
        match EntryRecord::decode(&encoded[..cut]) {
            Err(CodecError::Truncated | CodecError::UnsupportedVersion(_)) => {}
            other => panic!("truncating to {cut} bytes should not yield {other:?}"),
        }
    }
}

#[test]
fn a_record_from_another_schema_version_is_refused() {
    let mut encoded = RoomRecord {
        next_forward: 4,
        next_backward: -2,
        forward_extremities: vec!["$head".to_owned()],
    }
    .encode();
    encoded[0] = RECORD_VERSION.wrapping_add(1);

    assert!(matches!(
        RoomRecord::decode(&encoded),
        Err(CodecError::UnsupportedVersion(_))
    ));
}

#[test]
fn a_corrupt_stored_record_surfaces_as_a_store_error() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&live_room()).unwrap();

    // Overwrite one log record with rubbish, as a bad disk would.
    let prefix = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Log, ROOM);
    let (key, _) = store
        .scan_prefix(&prefix)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    store.put(&key, b"not a record").unwrap();

    assert!(matches!(
        RoomStore::new(&store, ROOM).load(),
        Err(StoreError::Codec(_))
    ));
}

proptest! {
    #[test]
    fn entry_records_round_trip(
        li: i64,
        depth: u64,
        event_id in "\\$[a-zA-Z0-9]{1,24}",
        parents in prop::collection::vec("\\$[a-zA-Z0-9]{1,24}", 0..5),
        slot in prop::option::of(("[a-z.]{1,20}", "[a-z:@.]{0,20}")),
        chain: bool,
    ) {
        let record = EntryRecord {
            li,
            event_id,
            prev_events: parents,
            depth,
            state_key: slot,
            state_root: [0_u8; 32],
            chain: chain.then_some([3_u8; 32]),
        };
        prop_assert_eq!(EntryRecord::decode(&record.encode()).unwrap(), record);
    }
}

#[test]
fn tampering_with_stored_history_breaks_the_chain_on_reopen() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&live_room()).unwrap();

    // A clean reopen attests to itself.
    let clean = RoomStore::new(&store, ROOM).load().unwrap().unwrap();
    assert!(clean.broken_chain.is_empty());

    // Rewrite the middle entry's record so it names a different event, exactly
    // as an operator quietly editing history would have to. The record stays
    // structurally valid -- only the content changes.
    let prefix = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Log, ROOM);
    let records = store.scan_prefix(&prefix).unwrap();
    let (key, value) = &records[1];
    let mut record = EntryRecord::decode(value).unwrap();
    let original = record.li;
    record.event_id = "$substituted".to_owned();
    store.put(key, &record.encode()).unwrap();

    let tampered = RoomStore::new(&store, ROOM).load().unwrap().unwrap();

    // The chain recomputed from the entries no longer matches what was
    // recorded, and it stays broken for every entry after -- the edit cannot be
    // contained.
    assert!(
        !tampered.broken_chain.is_empty(),
        "an edited history must not reopen silently"
    );
    assert_eq!(tampered.broken_chain[0].get(), original);
    assert_eq!(
        tampered.broken_chain.len(),
        2,
        "the substituted entry and everything sequenced after it"
    );
}

/// An entry's `state_root` must be the address of the state the log actually
/// holds, even for an entry the restore could not reproduce.
///
/// Backfilled state comes from `/state_ids`, so a refold cannot rebuild it. A
/// restore with no node loader therefore has nothing to rehydrate from and
/// reports the entry in `unverified` — and the tempting thing to do is store
/// the root that was recorded anyway. That would leave the log advertising an
/// address its own snapshot does not hash to, and every rehydration downstream
/// trusts that address.
#[test]
fn an_unverified_entry_advertises_the_state_it_has_not_the_one_it_wanted() {
    let dir = TempDir::new().unwrap();
    let mut room = live_room();
    let supplied = StateSnapshot::new().apply(StateKey::new("m.room.name", ""), "$name");
    let recorded = room
        .prepend_remote(EventInput::new("$older", vec![]), supplied, 40)
        .unwrap()
        .state_root;

    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&room).unwrap();
    // `load_refolding` deliberately ignores the stored trie, so the backfilled
    // entry cannot come back.
    let restored = RoomStore::new(&store, ROOM)
        .load_refolding()
        .unwrap()
        .unwrap();

    let backfilled = restored
        .log
        .entries()
        .find(|entry| entry.li.get() == 0)
        .unwrap();
    assert!(
        restored.unverified.contains(&backfilled.li),
        "a backfilled entry cannot be refolded and must be reported"
    );
    assert_ne!(
        backfilled.state_root, recorded,
        "the refold could not reproduce the recorded state, and must not claim to"
    );

    // The invariant that matters: root and state agree, for every entry.
    for entry in restored.log.entries() {
        if let Some(state) = restored.log.state_after(entry.li) {
            assert_eq!(
                state.root(),
                entry.state_root,
                "li {} advertises a root its own snapshot does not hash to",
                entry.li.get()
            );
        }
    }
}
