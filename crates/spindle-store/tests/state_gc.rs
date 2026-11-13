//! #742: the state trie's mark-and-sweep.
//!
//! State nodes are content-addressed and shared across entries and rooms,
//! so a node is dead only when *no* stored root reaches it. Each test below
//! is one way a collector gets that wrong: sweeping a node another room
//! still shares, sweeping a root held outside the log, walking a shared
//! subtree once per root, or sweeping on a mark it could not complete.

use spindle_core::keys::{Keyspace, content_addressed, keyspace_prefix, room_prefix};
use spindle_core::{
    EventId, RoomLog, Sideline, SidelinedEntry, StateKey, StateRoot, StateSnapshot,
};
use spindle_store::gc::{
    GcError, GcOptions, GcReport, collect_state_nodes, collect_state_nodes_with,
};
use spindle_store::{Durability, FjallStore, ReadView, RoomStore, Store};
use tempfile::TempDir;

const SHARED: usize = 60;

fn member(index: usize) -> StateKey {
    StateKey::new("m.room.member", format!("@u{index}:example.org"))
}

/// A room whose first [`SHARED`] entries set the same slots to the same
/// events as every other room seeded here -- so their tries are the same
/// nodes -- followed by `own` entries of its own.
fn seed(store: &FjallStore, room: &str, own: usize) -> RoomLog {
    let room_store = RoomStore::new(store, room);
    let mut log = RoomLog::new(store.key_table());
    for index in 0..SHARED {
        let entry = log
            .append_local(format!("$shared-{index}"), Some(member(index)))
            .unwrap()
            .clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }
    for index in 0..own {
        // Every third one a message: an entry whose root is its parent's,
        // the commonest case and the one a per-root walk pays for most.
        let key = (index % 3 != 0).then(|| member(SHARED + index));
        let entry = log
            .append_local(format!("${room}-{index}"), key)
            .unwrap()
            .clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }
    log
}

/// Every row a room's records occupy, deleted: the store as it would be
/// if the room were removed outright. Its trie nodes are left behind,
/// which is what the collector is for.
fn delete_room_records(store: &FjallStore, room: &str) {
    for keyspace in [
        Keyspace::Log,
        Keyspace::RoomMeta,
        Keyspace::Sidelined,
        Keyspace::FederationGapEvent,
    ] {
        for (key, _) in store.scan_prefix(&room_prefix(keyspace, room)).unwrap() {
            Store::delete(store, &key).unwrap();
        }
    }
}

fn node_count(store: &FjallStore) -> u64 {
    store
        .scan_prefix(&keyspace_prefix(Keyspace::StateNode))
        .unwrap()
        .len() as u64
}

fn has_node(store: &FjallStore, root: StateRoot) -> bool {
    store
        .get(&content_addressed(Keyspace::StateNode, root.as_bytes()))
        .unwrap()
        .is_some()
}

/// Nodes of a state nothing names: what an interrupted write leaves.
fn plant_garbage(store: &FjallStore, tag: &str) -> u64 {
    let mut state = StateSnapshot::new(store.key_table());
    for index in 0..40 {
        state = state.apply(
            &StateKey::new("m.room.member", format!("@{tag}{index}:example.org")),
            format!("${tag}-{index}"),
        );
    }
    let nodes = state.delta_nodes(None);
    let planted = nodes.len() as u64;
    let writes: Vec<_> = nodes
        .into_iter()
        .map(|(address, bytes)| {
            (
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                bytes,
            )
        })
        .collect();
    store
        .commit_state_deferred(&writes, &store.key_table())
        .unwrap();
    store.sync(Durability::Strict).unwrap();
    planted
}

/// A room's state at `li` read back from the store alone, through its
/// stored root.
fn state_at(store: &FjallStore, log: &RoomLog, li: i64) -> StateSnapshot {
    let entry = log.entry_at_or_before(li).expect("an entry at that point");
    StateSnapshot::rehydrate(
        entry.state_root,
        &mut |address: &StateRoot| {
            store
                .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))
                .unwrap()
        },
        store.key_table(),
    )
    .expect("the state reads back")
}

/// Deleting one room's records leaves its exclusive nodes unreachable, and
/// the collector removes exactly those: the subtree both rooms share
/// survives, every point of the remaining room's state still reads back,
/// and a second run finds nothing to do.
#[test]
fn a_node_shared_by_two_rooms_survives_deleting_one() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let kept = seed(&store, "!kept:example.org", 90);
    let gone = seed(&store, "!gone:example.org", 90);
    let shared_root = kept
        .entry_at_or_before(i64::try_from(SHARED).unwrap())
        .unwrap()
        .state_root;
    assert_eq!(
        shared_root,
        gone.entry_at_or_before(i64::try_from(SHARED).unwrap())
            .unwrap()
            .state_root,
        "the fixture's rooms share a trie up to the fork"
    );

    let clean = collect_state_nodes(&store, true).unwrap();
    assert_eq!(clean.swept, 0, "nothing is unreachable yet: {clean:?}");
    let before = node_count(&store);
    assert_eq!(clean.marked, before);

    delete_room_records(&store, "!gone:example.org");
    let dry = collect_state_nodes(&store, true).unwrap();
    assert!(dry.swept > 0, "the deleted room left nodes behind: {dry:?}");
    assert_eq!(node_count(&store), before, "a dry run deletes nothing");

    let swept = collect_state_nodes(&store, false).unwrap();
    assert_eq!(swept, dry, "the run does what the dry run said");
    assert_eq!(node_count(&store), before - swept.swept);
    assert!(has_node(&store, shared_root), "the shared subtree survives");

    let restored = RoomStore::new(&store, "!kept:example.org")
        .load_exhaustive()
        .unwrap()
        .expect("the remaining room is there");
    assert!(restored.unverified.is_empty());
    for (li, slot, expected) in [
        (1, 0, Some("$shared-0")),
        (40, 39, Some("$shared-39")),
        (40, 41, None),
        (100, SHARED + 2, Some("$!kept:example.org-2")),
        (150, SHARED + 89, Some("$!kept:example.org-89")),
    ] {
        assert_eq!(
            state_at(&store, &kept, li).get(&member(slot)),
            expected,
            "slot {slot} at li {li}"
        );
    }
    assert_eq!(
        restored.log.current_state().map(StateSnapshot::root),
        kept.current_state().map(StateSnapshot::root)
    );

    let again = collect_state_nodes(&store, false).unwrap();
    assert_eq!(again.swept, 0, "a rerun is a no-op: {again:?}");
    assert_eq!(again.marked, swept.marked);
    assert_eq!(node_count(&store), again.marked);
}

/// The mark reads each reachable node once, however many roots reach it.
///
/// The fixture has 300 entries over states of up to 150 slots, so a walk
/// per root would read tens of thousands of nodes; the visited set holds it
/// to the number of distinct nodes.
#[test]
fn the_mark_reads_each_shared_node_once() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    for room in ["!a:example.org", "!b:example.org", "!c:example.org"] {
        seed(&store, room, 40);
    }
    let report = collect_state_nodes(&store, true).unwrap();
    assert_eq!(report.holders, 3 * (SHARED as u64 + 40));
    assert_eq!(report.node_reads, report.marked, "{report:?}");
    assert_eq!(report.marked, node_count(&store));
    assert!(report.marked_bytes > 0);
}

/// Roots held outside the log keep their nodes: a sidelined event's state
/// and a backfilled gap event's state are both read through those roots,
/// and neither is any log entry's.
#[test]
fn sidelined_and_gap_roots_are_marked_and_garbage_beside_them_is_not() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let room = "!holders:example.org";
    let log = seed(&store, room, 3);
    let base = log.current_state().unwrap().clone();

    let soft_failed = base.apply(&member(900), "$soft-failed");
    let entry = SidelinedEntry {
        event_id: EventId::new("$soft-failed"),
        prev_events: log.forward_extremities().iter().cloned().collect(),
        depth: 99,
        state_key: Some(member(900)),
        kind: Sideline::SoftFailed,
        state_root: soft_failed.root(),
    };
    RoomStore::new(&store, room)
        .journal_sidelined(&entry, &soft_failed, Some(&base), &log, &[])
        .unwrap();

    let gap_state = base.apply(&member(901), "$backfilled");
    let mut writes: Vec<_> = gap_state
        .delta_nodes(Some(&base))
        .into_iter()
        .map(|(address, bytes)| {
            (
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                bytes,
            )
        })
        .collect();
    let mut row = gap_state.root().as_bytes().to_vec();
    row.extend_from_slice(b"$backfilled");
    writes.push((spindle_core::keys::federation_gap_event(room, -5), row));
    store
        .commit_state_deferred(&writes, &store.key_table())
        .unwrap();
    store.sync(Durability::Strict).unwrap();

    let planted = plant_garbage(&store, "stray");
    let report = collect_state_nodes(&store, false).unwrap();
    assert_eq!(report.swept, planted, "exactly the garbage: {report:?}");
    assert!(report.swept_bytes > planted * 34, "{report:?}");
    for root in [soft_failed.root(), gap_state.root()] {
        assert!(has_node(&store, root));
        StateSnapshot::rehydrate(
            root,
            &mut |address: &StateRoot| {
                store
                    .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))
                    .unwrap()
            },
            store.key_table(),
        )
        .expect("a held-outside-the-log state still reads back");
    }
    RoomStore::new(&store, room)
        .load_exhaustive()
        .unwrap()
        .expect("the room, sidelined event and all, still restores");
}

/// A reachable node that is already missing stops the run before anything
/// is deleted: the mark below it is unknowable, and a sweep from a partial
/// mark deletes whatever that subtree held.
#[test]
fn a_missing_reachable_node_refuses_the_sweep() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let log = seed(&store, "!damaged:example.org", 10);
    let planted = plant_garbage(&store, "stray");
    let root = log.current_state().unwrap().root();
    Store::delete(
        &store,
        &content_addressed(Keyspace::StateNode, root.as_bytes()),
    )
    .unwrap();
    let before = node_count(&store);

    let error = collect_state_nodes(&store, false).unwrap_err();
    assert!(
        matches!(error, GcError::MissingNode(missing) if missing == root),
        "{error}"
    );
    assert_eq!(node_count(&store), before, "nothing was deleted");
    assert!(planted > 0);
}

/// Unrelated rows, the empty state's root and rows of an unexpected shape
/// in the node keyspace are all left alone.
#[test]
fn an_empty_store_and_a_messages_only_room_collect_nothing() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    assert_eq!(
        collect_state_nodes(&store, false).unwrap(),
        GcReport::default()
    );

    let room_store = RoomStore::new(&store, "!quiet:example.org");
    let mut log = RoomLog::new(store.key_table());
    for index in 0..5 {
        let entry = log
            .append_local(format!("$quiet-{index}"), None)
            .unwrap()
            .clone();
        room_store
            .commit_entry(&entry, &log, Durability::Relaxed)
            .unwrap();
    }
    let mut odd = keyspace_prefix(Keyspace::StateNode);
    odd.extend_from_slice(b"short");
    store.put(&odd, b"not a node").unwrap();
    let report = collect_state_nodes(&store, false).unwrap();
    assert_eq!(report.holders, 5);
    assert_eq!(report.marked, 0);
    assert_eq!(report.swept, 0);
    assert!(store.get(&odd).unwrap().is_some());
}

/// A `CurrentState` row that does not decode is a stale cache: a room load
/// ignores it, so gc drops it instead of refusing forever.
#[test]
fn an_undecodable_cache_row_is_dropped_not_fatal() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store, "!room:example.org", 10);
    let planted = plant_garbage(&store, "stray");
    let cache = room_prefix(Keyspace::CurrentState, "!room:example.org");
    store.put(&cache, b"not a record").unwrap();

    let dry = collect_state_nodes(&store, true).unwrap();
    assert_eq!(dry.dropped_cache_rows, 1);
    assert!(store.get(&cache).unwrap().is_some(), "a dry run keeps it");

    let report = collect_state_nodes(&store, false).unwrap();
    assert_eq!(report.dropped_cache_rows, 1);
    assert_eq!(report.swept, planted, "the garbage went too: {report:?}");
    assert!(store.get(&cache).unwrap().is_none());
    RoomStore::new(&store, "!room:example.org")
        .load_exhaustive()
        .unwrap()
        .expect("the room loads without its cache row");
    assert_eq!(collect_state_nodes(&store, false).unwrap().swept, 0);
}

/// The sweep deletes in batches and never holds all the dead addresses.
///
/// Counted, not timed: `unbatched` is the rows written outside a batch and
/// must not move; `written` moves by exactly the nodes swept; and the most
/// addresses held at once stays below the number swept.
#[test]
fn the_sweep_batches_its_deletes_and_holds_one_batch() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store, "!room:example.org", 10);
    let mut planted = 0;
    for tag in 0..160 {
        planted += plant_garbage(&store, &format!("t{tag}x"));
    }
    let (unbatched, written) = (store.unbatched(), store.written());

    let report = collect_state_nodes(&store, false).unwrap();
    assert_eq!(report.swept, planted, "{report:?}");
    assert!(report.swept > 2 * report.peak_pending, "{report:?}");
    assert_eq!(
        report.delete_batches,
        report.swept.div_ceil(report.peak_pending),
        "{report:?}"
    );
    assert_eq!(store.unbatched(), unbatched, "no delete went unbatched");
    assert_eq!(store.written() - written, planted);
    assert_eq!(node_count(&store), report.marked);
}

fn node_keys(store: &FjallStore) -> Vec<Vec<u8>> {
    store
        .scan_prefix(&keyspace_prefix(Keyspace::StateNode))
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

/// A store with live rooms, one deleted room and planted garbage.
fn store_with_garbage(dir: &TempDir) -> FjallStore {
    let store = FjallStore::open(dir.path()).unwrap();
    seed(&store, "!kept:example.org", 90);
    seed(&store, "!gone:example.org", 90);
    delete_room_records(&store, "!gone:example.org");
    for tag in 0..6 {
        plant_garbage(&store, &format!("g{tag}x"));
    }
    store
}

/// The mark set is bounded and exact: with room for 16 addresses it holds
/// at most 16 however many nodes are live, and deletes exactly the nodes an
/// unbounded run deletes.
#[test]
fn a_bounded_mark_set_sweeps_exactly_what_an_unbounded_one_does() {
    let (dir_a, dir_b) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let (unbounded, bounded) = (store_with_garbage(&dir_a), store_with_garbage(&dir_b));
    assert_eq!(node_keys(&unbounded), node_keys(&bounded));
    let scratch = TempDir::new().unwrap();
    let scratch_path = scratch.path().join("marks");

    let wide = collect_state_nodes(&unbounded, false).unwrap();
    let narrow = collect_state_nodes_with(
        &bounded,
        false,
        &GcOptions {
            max_marks: 16,
            scratch: Some(scratch_path.clone()),
        },
    )
    .unwrap();

    assert!(wide.swept > 0 && wide.marked > 200, "{wide:?}");
    assert_eq!(wide.peak_marked, wide.marked, "unbounded holds every mark");
    assert_eq!(wide.spilled, 0);
    assert!(narrow.peak_marked <= 16, "{narrow:?}");
    assert_eq!(narrow.spilled, narrow.marked - narrow.marked % 16);
    assert_eq!((narrow.marked, narrow.swept), (wide.marked, wide.swept));
    assert_eq!(
        node_keys(&unbounded),
        node_keys(&bounded),
        "same nodes deleted"
    );
    assert!(!scratch_path.exists(), "the scratch database is removed");
    for store in [&unbounded, &bounded] {
        RoomStore::new(store, "!kept:example.org")
            .load_exhaustive()
            .unwrap()
            .expect("the kept room loads");
    }
}

/// A scratch database a crashed run left behind is cleared, not read: here
/// it claims every node is live, which would sweep nothing.
#[test]
fn a_leftover_scratch_set_is_cleared_unread() {
    let dir = TempDir::new().unwrap();
    let store = store_with_garbage(&dir);
    let scratch = TempDir::new().unwrap();
    let scratch_path = scratch.path().join("marks");
    {
        let db = fjall::Database::open(fjall::Config::new(&scratch_path)).unwrap();
        let marks = db
            .keyspace("marks", fjall::KeyspaceCreateOptions::default)
            .unwrap();
        let prefix = keyspace_prefix(Keyspace::StateNode).len();
        for key in node_keys(&store) {
            marks.insert(&key[prefix..], []).unwrap();
        }
    }
    let report = collect_state_nodes_with(
        &store,
        false,
        &GcOptions {
            max_marks: 16,
            scratch: Some(scratch_path.clone()),
        },
    )
    .unwrap();
    assert!(report.swept > 0, "stale marks were not trusted: {report:?}");
    assert!(!scratch_path.exists());
}
