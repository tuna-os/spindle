//! #810: the configured durability reaches the commit, `relaxed` really
//! syncs on a timer, security writes never fall below `group`, and a batch
//! can delete atomically.

use spindle_store::{BatchOp, Durability, FjallStore, ReadView, Store};
use tempfile::TempDir;

const N: u64 = 5;

fn open(mode: Durability) -> (TempDir, FjallStore) {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    store.set_durability(mode);
    (dir, store)
}

/// What a room commit does: ask for the configured durability.
fn room_commits(store: &FjallStore) {
    for i in 0..N {
        store
            .commit(
                &[(vec![9, u8::try_from(i).unwrap()], vec![1])],
                store.durability(),
            )
            .unwrap();
    }
}

#[test]
fn the_configured_mode_decides_how_many_barriers_n_commits_pay() {
    let (_d, strict) = open(Durability::Strict);
    room_commits(&strict);
    assert_eq!(strict.barriers(), N, "strict: one fsync per commit");
    assert_eq!(strict.group_commits().0, 0, "strict is not grouped");

    let (_d, group) = open(Durability::Group);
    room_commits(&group);
    assert_eq!(
        group.barriers(),
        N,
        "sequential group commits each lead one"
    );
    assert_eq!(group.group_commits().0, N, "group goes through the group");

    let (_d, relaxed) = open(Durability::Relaxed);
    room_commits(&relaxed);
    assert_eq!(relaxed.barriers(), 0, "relaxed pays none at commit");
}

#[test]
fn relaxed_is_persisted_by_the_periodic_tick_and_only_when_dirty() {
    let (_d, store) = open(Durability::Relaxed);
    assert!(
        !store.relaxed_tick().unwrap(),
        "nothing written, nothing synced"
    );
    room_commits(&store);
    assert_eq!(store.barriers(), 0);
    assert!(store.relaxed_tick().unwrap(), "dirty journal is synced");
    assert_eq!(store.barriers(), 1, "one fsync covers all N commits");
    assert!(
        !store.relaxed_tick().unwrap(),
        "clean journal is not re-synced"
    );
    assert_eq!(store.barriers(), 1);
}

#[test]
fn the_periodic_thread_stops_on_drop_and_syncs_once_more() {
    let dir = TempDir::new().unwrap();
    let store = std::sync::Arc::new(FjallStore::open(dir.path()).unwrap());
    store.set_durability(Durability::Relaxed);
    // An hour: the timer cannot fire during the test, so any barrier below
    // comes from the guard's final tick on drop.
    let guard = store.spawn_periodic_sync(std::time::Duration::from_secs(3600));
    room_commits(&store);
    assert_eq!(store.barriers(), 0);
    drop(guard);
    assert_eq!(store.barriers(), 1, "drop joined the thread and synced");
}

#[test]
fn security_writes_are_never_weaker_than_group() {
    // A security call site asks for `Group`, whatever the operator chose.
    let (_d, relaxed) = open(Durability::Relaxed);
    relaxed
        .commit(&[(vec![1], vec![1])], Durability::Group)
        .unwrap();
    assert_eq!(
        relaxed.barriers(),
        1,
        "relaxed config does not weaken Group"
    );
    assert_eq!(relaxed.group_commits().0, 1);

    let (_d, group) = open(Durability::Group);
    group
        .commit(&[(vec![1], vec![1])], Durability::Group)
        .unwrap();
    assert_eq!(group.group_commits().0, 1);

    // Under `strict` the same request is raised to a strict fsync.
    let (_d, strict) = open(Durability::Strict);
    strict
        .commit(&[(vec![1], vec![1])], Durability::Group)
        .unwrap();
    assert_eq!(strict.barriers(), 1);
    assert_eq!(strict.group_commits().0, 0, "raised to strict, not grouped");
}

#[test]
fn a_batch_with_deletes_is_atomic_and_one_write_batch() {
    let (_d, store) = open(Durability::Group);
    store
        .commit(
            &[
                (vec![1], b"a".to_vec()),
                (vec![2], b"b".to_vec()),
                (vec![3], b"c".to_vec()),
            ],
            Durability::Group,
        )
        .unwrap();
    let before = store.snapshot().expect("fjall provides snapshots");
    let (batches, rows, unbatched, barriers) = (
        store.journalled(),
        store.written(),
        store.unbatched(),
        store.barriers(),
    );

    store
        .commit_ops(
            &[
                BatchOp::Delete(vec![1]),
                BatchOp::Delete(vec![2]),
                BatchOp::Put(vec![4], b"d".to_vec()),
                BatchOp::Delete(vec![99]),
            ],
            Durability::Group,
        )
        .unwrap();

    assert_eq!(store.journalled() - batches, 1, "one write batch");
    assert_eq!(store.written() - rows, 4, "every operation is a row");
    assert_eq!(store.unbatched(), unbatched, "none outside the batch");
    assert_eq!(store.barriers() - barriers, 1, "synced once");

    // All of it or none of it: the snapshot taken first sees none of the
    // batch, the store now sees all of it.
    assert_eq!(before.get(&[1]).unwrap().as_deref(), Some(&b"a"[..]));
    assert_eq!(before.get(&[2]).unwrap().as_deref(), Some(&b"b"[..]));
    assert_eq!(before.get(&[4]).unwrap(), None);
    assert_eq!(store.get(&[1]).unwrap(), None);
    assert_eq!(store.get(&[2]).unwrap(), None);
    assert_eq!(store.get(&[3]).unwrap().as_deref(), Some(&b"c"[..]));
    assert_eq!(store.get(&[4]).unwrap().as_deref(), Some(&b"d"[..]));
}
