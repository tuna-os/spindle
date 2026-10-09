//! Imported rejection decisions survive every room recovery path.
use spindle_core::{EventId, RoomLog, StateKey, keys};
use spindle_store::{Durability, FjallStore, RoomStore, Store};

const ROOM: &str = "!room:example.org";
fn room() -> RoomLog {
    let mut log = RoomLog::new();
    log.append_local("$create", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    log
}

#[test]
fn imported_rejections_survive_reopen_and_refolding_without_entering_the_timeline() {
    let dir = tempfile::tempdir().unwrap();
    let id = EventId::new("$historical-ban");
    {
        let store = FjallStore::open(dir.path()).unwrap();
        let mut log = room();
        let rooms = RoomStore::new(&store, ROOM);
        rooms.save(&log).unwrap();
        rooms
            .commit_historical_rejections(
                &mut log,
                std::slice::from_ref(&id),
                &[],
                Durability::Strict,
            )
            .unwrap();
        assert!(log.historically_rejected(&id));
        assert_eq!(log.len(), 1);
        assert!(log.get(&id).is_none());
        rooms.save(&log).unwrap();
    }
    let store = FjallStore::open(dir.path()).unwrap();
    for log in [
        RoomStore::new(&store, ROOM).load().unwrap().unwrap().log,
        RoomStore::new(&store, ROOM)
            .load_refolding()
            .unwrap()
            .unwrap()
            .log,
    ] {
        assert!(log.historically_rejected(&id));
        assert_eq!(log.len(), 1);
        assert!(log.get(&id).is_none());
    }
}

#[test]
fn an_accepted_id_cannot_be_relabelled_as_a_historical_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let mut log = room();
    RoomStore::new(&store, ROOM).save(&log).unwrap();
    let accepted = EventId::new("$create");
    assert!(
        RoomStore::new(&store, ROOM)
            .commit_historical_rejections(
                &mut log,
                std::slice::from_ref(&accepted),
                &[],
                Durability::Strict
            )
            .is_err()
    );
    assert!(!log.historically_rejected(&accepted));
}

#[test]
fn a_corrupt_marker_refuses_recovery_instead_of_dropping_the_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    RoomStore::new(&store, ROOM).save(&room()).unwrap();
    store
        .put(&keys::historical_rejection(ROOM, "$old"), &[0])
        .unwrap();
    assert!(RoomStore::new(&store, ROOM).load().is_err());
}
