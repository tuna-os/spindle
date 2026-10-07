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
