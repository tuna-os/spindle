//! The first real migration (#79): a version-2 store opens, migrates, and
//! reads back with the ordinary open.
//!
//! The fixture is hand-built version-2 bytes, not a store the current code
//! wrote: nothing in this binary writes version 2 any more, so there is no
//! other way to obtain one. The encoding below repeats exactly what the old
//! binary wrote (tag, digest, count, framed strings; verified under the old
//! tags) — a constant that updates itself is not a record of anything, so
//! the fixture states the old format plainly rather than deriving it.
//!
//! The room under migration is mixed on purpose: one entry already
//! version-3 (a previous partial run's work, which the migration must keep
//! rather than reconvert) and one entry plus a sidelined record still
//! version-2. What the test asserts after `migrate::run`:
//!
//! - the ordinary `open` accepts the store and the marker is current;
//! - every slot from both tries resolves to the event that set it;
//! - the version-2 node rows are gone and the intern rows are present;
//! - a second run reports nothing to do.

use spindle_core::keys::{Keyspace, content_addressed, room_li, room_prefix, store_marker};
use spindle_core::{
    EventId, LinearIndex, RehydrateError, RoomLog, StateKey, rehydrate_v2,
    rehydrate_v2_with_addresses,
};
use spindle_store::codec::{EntryRecord, RoomRecord, SidelinedRecord};
use spindle_store::migrate::{MIGRATIONS, run};
use spindle_store::{FjallStore, ReadView, RoomStore, SchemaMarker, Store};
use tempfile::TempDir;

const ROOM: &str = "!migrated:example.org";

/// Version-2 domain tags. Repeated, not derived: see the module docs.
const V2_STATE_KEY_TAG: &[u8] = b"spsk-v2\0";
const V2_LEAF_TAG: &[u8] = b"spindle-hamt-leaf-v2\0";
const V2_BRANCH_TAG: &[u8] = b"spindle-hamt-branch-v2\0";

fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&len_u32(value.len()).to_be_bytes());
    out.extend_from_slice(value);
}

/// A `usize` count as the `u32` the version-2 framing stores, saturating
/// rather than truncating: the fixture counts single digits, and a
/// truncation here would encode a different trie than the test asserts.
fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// Length-framed bytes fed to a hasher: the same framing `frame` writes.
fn hframe(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&len_u32(value.len()).to_be_bytes());
    hasher.update(value);
}

fn placement(event_type: &str, state_key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(V2_STATE_KEY_TAG);
    hframe(&mut hasher, event_type.as_bytes());
    hframe(&mut hasher, state_key.as_bytes());
    *hasher.finalize().as_bytes()
}

/// One version-2 leaf node holding `entries`, with its address.
fn v2_leaf(entries: &[(&str, &str, &str)]) -> (Vec<u8>, [u8; 32]) {
    let (first_type, first_key, _) = entries[0];
    let digest = placement(first_type, first_key);
    let mut out = vec![0_u8];
    out.extend_from_slice(&digest);
    out.extend_from_slice(&len_u32(entries.len()).to_be_bytes());
    for (event_type, state_key, event_id) in entries {
        frame(&mut out, event_type.as_bytes());
        frame(&mut out, state_key.as_bytes());
        frame(&mut out, event_id.as_bytes());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(V2_LEAF_TAG);
    hasher.update(&digest);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for (event_type, state_key, event_id) in entries {
        hframe(&mut hasher, event_type.as_bytes());
        hframe(&mut hasher, state_key.as_bytes());
        hframe(&mut hasher, event_id.as_bytes());
    }
    (out, *hasher.finalize().as_bytes())
}

/// A version-2 branch over `children` (addresses in slot order) with its address.
fn v2_branch(slots: &[u32], children: &[[u8; 32]]) -> (Vec<u8>, [u8; 32]) {
    let mut bitmap = 0_u32;
    for slot in slots {
        bitmap |= 1_u32 << slot;
    }
    let mut out = vec![1_u8];
    out.extend_from_slice(&bitmap.to_be_bytes());
    out.extend_from_slice(&len_u32(children.len()).to_be_bytes());
    for child in children {
        out.extend_from_slice(child);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(V2_BRANCH_TAG);
    hasher.update(&bitmap.to_be_bytes());
    for child in children {
        hasher.update(child);
    }
    (out, *hasher.finalize().as_bytes())
}

/// The top five bits of a digest at a trie level: the branch slot.
fn slot(digest: &[u8; 32], depth: usize) -> u32 {
    let bit_offset = depth * 5;
    let byte = bit_offset / 8;
    let shift = bit_offset % 8;
    let at = usize::from(digest.get(byte).copied().unwrap_or(0));
    let mut window = at >> shift;
    if shift > 3 && byte + 1 < digest.len() {
        window |= usize::from(digest[byte + 1]) << (8 - shift);
    }
    u32::try_from(window & 31).unwrap_or(u32::MAX)
}

/// Old node addresses the assertions check for deletion, and which slots
/// the first leaf holds (the fallback below may regroup them).
struct V2Fixture {
    root: [u8; 32],
    addr_one: [u8; 32],
    addr_two: [u8; 32],
    first: Vec<(&'static str, &'static str, &'static str)>,
}

/// One entry the current code wrote into the unchecked store: a previous
/// partial run's work, which the migration must recognise and keep rather
/// than reconvert.
fn seed_v3_entry(unchecked: &FjallStore) {
    let mut log = RoomLog::new(unchecked.key_table());
    log.append_local("$c1", Some(StateKey::new("m.room.create", "")))
        .unwrap();
    RoomStore::new(unchecked, ROOM).save(&log).unwrap();
}

/// The version-2 remainder: two leaves under one branch, three slots, plus
/// an entry naming the old root chained after the version-3 one, a sidelined
/// record naming an old subtree root, and the old binary's marker.
fn write_v2_fixture(unchecked: &FjallStore) -> V2Fixture {
    let mut first = vec![("m.room.create", "", "$c1"), ("m.room.topic", "", "$t")];
    let mut second = vec![("m.room.name", "", "$n")];
    if slot(&placement(first[0].0, first[0].1), 0) == slot(&placement(second[0].0, second[0].1), 0)
    {
        first.pop();
        second.push(("m.room.topic", "", "$t"));
    }
    let (leaf_one, addr_one) = v2_leaf(&first);
    let (leaf_two, addr_two) = v2_leaf(&second);
    let slot_one = slot(&placement(first[0].0, first[0].1), 0);
    let slot_two = slot(&placement(second[0].0, second[0].1), 0);
    assert_ne!(slot_one, slot_two, "the fixture needs two leaves");
    let (ordered, branch_children) = if slot_one < slot_two {
        ([slot_one, slot_two], [addr_one, addr_two])
    } else {
        ([slot_two, slot_one], [addr_two, addr_one])
    };
    let (branch, root) = v2_branch(&ordered, &branch_children);
    for (address, node) in [(addr_one, leaf_one), (addr_two, leaf_two), (root, branch)] {
        Store::put(
            unchecked,
            &content_addressed(Keyspace::StateNode, &address),
            &node,
        )
        .unwrap();
    }

    // An entry naming the old root, chained after the version-3 one.
    let chain = spindle_core::ChainHash::seed()
        .extend(&EventId::new("$c1"))
        .extend(&EventId::new("$c2"));
    let entry = EntryRecord {
        li: 2,
        event_id: "$c2".to_owned(),
        prev_events: vec!["$c1".to_owned()],
        depth: 2,
        state_key: None,
        state_root: root,
        chain: Some(*chain.as_bytes()),
    };
    Store::put(
        unchecked,
        &room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(2)),
        &entry.encode(),
    )
    .unwrap();
    let meta_key = room_prefix(Keyspace::RoomMeta, ROOM);
    let meta_bytes = ReadView::get(unchecked, &meta_key).unwrap().unwrap();
    let mut meta = RoomRecord::decode(&meta_bytes).unwrap();
    meta.next_forward = 3;
    meta.forward_extremities = vec!["$c2".to_owned()];
    Store::put(unchecked, &meta_key, &meta.encode()).unwrap();

    // A sidelined record naming an old subtree root: migration covers it too.
    let sidelined = SidelinedRecord {
        event_id: "$s1".to_owned(),
        prev_events: vec![],
        depth: 2,
        state_key: None,
        kind: 1,
        state_root: addr_one,
    };
    Store::put(
        unchecked,
        &spindle_core::keys::sidelined(ROOM, "$s1"),
        &sidelined.encode(),
    )
    .unwrap();

    // Gap history stores state roots outside log and sidelined records.
    let mut gap_row = addr_two.to_vec();
    gap_row.extend_from_slice(b"$gap");
    Store::put(
        unchecked,
        &spindle_core::keys::federation_gap_event(ROOM, 1),
        &gap_row,
    )
    .unwrap();

    // Stamped as the old binary left it.
    Store::put(
        unchecked,
        &store_marker(),
        &SchemaMarker {
            key_schema: 1,
            record: 1,
            content_digest: 2,
        }
        .encode(),
    )
    .unwrap();
    V2Fixture {
        root,
        addr_one,
        addr_two,
        first,
    }
}

#[test]
fn a_version_two_store_migrates_and_reads_back() {
    let dir = TempDir::new().unwrap();
    let unchecked = FjallStore::open_unchecked(dir.path()).unwrap();
    seed_v3_entry(&unchecked);
    let fixture = write_v2_fixture(&unchecked);

    let report = run(&unchecked, MIGRATIONS, false).unwrap();
    assert_eq!(report.steps.len(), 1, "one step carries 2 to 3");
    assert_eq!(report.from.content_digest, 2);
    assert_eq!(report.to, SchemaMarker::current());
    assert!(report.irreversible(), "old rows are deleted");
    drop(unchecked);

    // The ordinary open accepts the migrated store...
    let store = FjallStore::open(dir.path()).unwrap();
    let restored = RoomStore::new(&store, ROOM).load().unwrap().unwrap();
    assert!(
        restored.unverified.is_empty(),
        "migrated state restores exactly: {:?}",
        restored.unverified
    );
    // ...with every slot from both tries resolving to the event that set it.
    let head = restored.log.state_after(LinearIndex::from_raw(2)).unwrap();
    assert_eq!(
        head.get(&StateKey::new("m.room.create", "")),
        Some("$c1"),
        "the version-3 entry survived"
    );
    assert_eq!(head.get(&StateKey::new("m.room.topic", "")), Some("$t"));
    assert_eq!(head.get(&StateKey::new("m.room.name", "")), Some("$n"));
    let sidelined = restored.log.sidelined(&EventId::new("$s1")).unwrap();
    assert_eq!(sidelined.kind, spindle_core::Sideline::SoftFailed);
    let sidelined_state = restored.log.sidelined_state(&EventId::new("$s1")).unwrap();
    assert_eq!(
        sidelined_state.get(&StateKey::new("m.room.create", "")),
        Some("$c1")
    );
    // The sidelined root is the first leaf, whose other slot is wherever
    // the fixture's fallback put it.
    if fixture.first.iter().any(|slot| slot.0 == "m.room.topic") {
        assert_eq!(
            sidelined_state.get(&StateKey::new("m.room.topic", "")),
            Some("$t")
        );
    }
    // The version-2 rows are gone and the intern rows are present.
    for address in [fixture.addr_one, fixture.addr_two, fixture.root] {
        assert!(
            ReadView::get(&store, &content_addressed(Keyspace::StateNode, &address))
                .unwrap()
                .is_none(),
            "old node row was not deleted"
        );
    }
    let interned: Vec<(Vec<u8>, Vec<u8>)> =
        ReadView::scan_prefix(&store, &spindle_core::keys::state_key_intern_prefix()).unwrap();
    assert!(
        interned.len() >= 3,
        "create, topic and name rows persisted: {}",
        interned.len()
    );
    let row = ReadView::get(&store, &spindle_core::keys::federation_gap_event(ROOM, 1))
        .unwrap()
        .unwrap();
    assert_eq!(&row[32..], b"$gap", "the gap event id is preserved");
    let root = spindle_core::StateRoot::from_bytes(row[..32].try_into().unwrap());
    let gap_state = spindle_core::StateSnapshot::rehydrate(
        root,
        &mut |address| {
            ReadView::get(
                &store,
                &content_addressed(Keyspace::StateNode, address.as_bytes()),
            )
            .unwrap()
        },
        store.key_table(),
    )
    .unwrap();
    assert_eq!(gap_state.get(&StateKey::new("m.room.name", "")), Some("$n"));

    // And a second run reports nothing to do.
    let again = run(&store, MIGRATIONS, false).unwrap();
    assert!(again.steps.is_empty(), "migration converges");
}

#[test]
fn a_staged_root_revisited_from_sidelined_history_does_not_read_before_flush() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    seed_v3_entry(&store);
    let fixture = write_v2_fixture(&store);

    // Add a second distinct old root after the first one. The later sidelined
    // row then revisits the first root while both conversions are still below
    // the batch commit threshold.
    let (leaf, second_root) = v2_leaf(&[("m.room.history_visibility", "", "$h")]);
    Store::put(
        &store,
        &content_addressed(Keyspace::StateNode, &second_root),
        &leaf,
    )
    .unwrap();
    let second_entry = EntryRecord {
        li: 3,
        event_id: "$c3".to_owned(),
        prev_events: vec!["$c2".to_owned()],
        depth: 3,
        state_key: None,
        state_root: second_root,
        chain: None,
    };
    Store::put(
        &store,
        &room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(3)),
        &second_entry.encode(),
    )
    .unwrap();

    let sideline_key = spindle_core::keys::sidelined(ROOM, "$s1");
    let sideline_bytes = ReadView::get(&store, &sideline_key).unwrap().unwrap();
    let mut sideline = SidelinedRecord::decode(&sideline_bytes).unwrap();
    sideline.state_root = fixture.root;
    Store::put(&store, &sideline_key, &sideline.encode()).unwrap();

    let report = run(&store, MIGRATIONS, false).unwrap();
    assert_eq!(report.steps.len(), 1);
    assert_eq!(report.to, SchemaMarker::current());
}

/// The version-2 reader fails closed: version-3 bytes and corruption are
/// both refused, never mistaken for convertible state.
///
/// The migration tells "already migrated" from "corrupt" by attempting the
/// new derivation first and keeping what verifies. If the old reader
/// accepted new bytes, a rerun would reconvert migrated tries into garbage;
/// if it accepted corrupt bytes, corruption would migrate silently.
#[test]
fn the_version_two_reader_refuses_new_bytes_and_corruption() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let table = store.key_table();
    let mut load = |address: &spindle_core::StateRoot| {
        ReadView::get(
            &store,
            &content_addressed(Keyspace::StateNode, address.as_bytes()),
        )
        .ok()
        .flatten()
    };

    // A version-2 leaf the old binary could have written.
    let (leaf, address) = v2_leaf(&[("m.room.topic", "", "$t")]);
    Store::put(
        &store,
        &content_addressed(Keyspace::StateNode, &address),
        &leaf,
    )
    .unwrap();
    let (state, old_addresses) = rehydrate_v2_with_addresses(
        spindle_core::StateRoot::from_bytes(address),
        &mut load,
        &table,
    )
    .unwrap();
    assert_eq!(old_addresses.len(), 1);
    assert_eq!(old_addresses[0].as_bytes(), &address);
    assert_eq!(
        state.get(&StateKey::new("m.room.topic", "")),
        Some("$t"),
        "a genuine version-2 trie converts"
    );

    // Its migrated form: the new derivation reads it, and the old one must
    // fail rather than convert it again. The failure kind is shape-dependent
    // (a short leaf misparses before it ever hashes); what the migration
    // depends on is only that it fails, because the new-derivation check
    // runs first and keeps what verifies.
    let batch: Vec<_> = state
        .delta_nodes(None)
        .into_iter()
        .map(|(address, node)| {
            (
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            )
        })
        .collect();
    Store::commit_state_deferred(&store, &batch, state.table()).unwrap();
    let migrated = *state.root().as_bytes();
    assert!(
        rehydrate_v2(
            spindle_core::StateRoot::from_bytes(migrated),
            &mut load,
            &table
        )
        .is_err(),
        "migrated bytes fail instead of converting again"
    );

    // Corruption the other way: a byte flipped inside a string still parses
    // (it stays valid UTF-8) but breaks the old hash, so verification --
    // not parsing -- is what refuses it.
    let mut corrupt = leaf.clone();
    // The type string starts after tag, digest and count: 1 + 32 + 4.
    corrupt[1 + 32 + 4 + 4] ^= 0x01;
    Store::put(
        &store,
        &content_addressed(Keyspace::StateNode, &address),
        &corrupt,
    )
    .unwrap();
    assert!(
        matches!(
            rehydrate_v2(
                spindle_core::StateRoot::from_bytes(address),
                &mut load,
                &table
            ),
            Err(RehydrateError::HashMismatch)
        ),
        "corruption fails verification instead of converting"
    );
}

/// Content addresses are global: two rooms can reference the same old subtree.
#[test]
fn migration_preserves_old_nodes_until_every_room_has_converted() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    seed_v3_entry(&store);
    write_v2_fixture(&store);
    let other = "!second:example.org";
    for space in [
        Keyspace::RoomMeta,
        Keyspace::Log,
        Keyspace::Sidelined,
        Keyspace::FederationGapEvent,
    ] {
        let prefix = room_prefix(space, ROOM);
        for (key, value) in ReadView::scan_prefix(&store, &prefix).unwrap() {
            let mut copied = room_prefix(space, other);
            copied.extend_from_slice(&key[prefix.len()..]);
            Store::put(&store, &copied, &value).unwrap();
        }
    }
    run(&store, MIGRATIONS, false).unwrap();
    drop(store);
    let store = FjallStore::open(dir.path()).unwrap();
    for room in [ROOM, other] {
        let restored = RoomStore::new(&store, room).load().unwrap().unwrap();
        assert!(restored.unverified.is_empty());
        assert_eq!(
            restored
                .log
                .state_after(LinearIndex::from_raw(2))
                .unwrap()
                .get(&StateKey::new("m.room.topic", "")),
            Some("$t")
        );
    }
}

/// A real v2 path-copy trie, built from the old placement and wire format.
fn v2_tree(
    entries: &[(String, String, String)],
    depth: usize,
    nodes: &mut std::collections::HashMap<spindle_core::StateRoot, Vec<u8>>,
) -> spindle_core::StateRoot {
    use spindle_core::StateRoot;
    if entries.is_empty() {
        return StateRoot::from_bytes(*blake3::hash(b"spindle-empty-state-v2").as_bytes());
    }
    let (bytes, address) = if entries.len() == 1 {
        let (kind, key, event) = &entries[0];
        v2_leaf(&[(kind, key, event)])
    } else {
        let mut groups = std::collections::BTreeMap::<u32, Vec<_>>::new();
        for entry in entries {
            groups
                .entry(slot(&placement(&entry.0, &entry.1), depth))
                .or_default()
                .push(entry.clone());
        }
        let slots: Vec<_> = groups.keys().copied().collect();
        let children: Vec<_> = groups
            .values()
            .map(|entries| *v2_tree(entries, depth + 1, nodes).as_bytes())
            .collect();
        v2_branch(&slots, &children)
    };
    let root = StateRoot::from_bytes(address);
    nodes.insert(root, bytes);
    root
}

#[test]
fn incremental_history_matches_full_conversion_with_changed_path_reads() {
    use spindle_core::{MemStateKeyTable, StateRoot, rehydrate_v2_incremental};
    let table = MemStateKeyTable::shared();
    let mut entries: Vec<_> = (0..2048)
        .map(|i| {
            (
                "m.room.member".to_owned(),
                format!("@member{i}:example.org"),
                format!("$member{i}"),
            )
        })
        .collect();
    let mut nodes = std::collections::HashMap::new();
    let mut previous_root = v2_tree(&entries, 0, &mut nodes);
    let mut previous =
        rehydrate_v2(previous_root, &mut |root| nodes.get(root).cloned(), &table).unwrap();
    let mut incremental_reads = 0;
    let mut full_reads = 0;
    let mut v3_nodes = std::collections::HashMap::new();
    for (address, bytes) in previous.delta_nodes(None) {
        v3_nodes.insert(address, bytes);
    }
    let started = std::time::Instant::now();
    for revision in 0..64 {
        // Includes replacement, insertion, deletion and changes in trie shape.
        match revision % 4 {
            0 => entries[revision].2 = format!("$changed{revision}"),
            1 => entries.push((
                "m.room.member".to_owned(),
                format!("@new{revision}:example.org"),
                format!("$new{revision}"),
            )),
            2 => {
                entries.remove(revision);
            }
            _ => entries[revision].2 = format!("$other{revision}"),
        }
        let root = v2_tree(&entries, 0, &mut nodes);
        let (state, addresses) =
            rehydrate_v2_incremental(root, previous_root, &previous, &mut |address| {
                incremental_reads += 1;
                nodes.get(address).cloned()
            })
            .unwrap();
        let full = rehydrate_v2(
            root,
            &mut |address| {
                full_reads += 1;
                nodes.get(address).cloned()
            },
            &table,
        )
        .unwrap();
        assert_eq!(state.root(), full.root(), "revision {revision}");
        assert!(
            addresses.len() < 32,
            "only changed old paths need deletion tracking"
        );
        let delta = state.delta_nodes(Some(&previous));
        assert!(delta.len() < 32, "only changed new paths are persisted");
        for (address, bytes) in delta {
            v3_nodes.insert(address, bytes);
        }
        let restored = spindle_core::StateSnapshot::rehydrate(
            state.root(),
            &mut |address| v3_nodes.get(address).cloned(),
            table.clone(),
        )
        .unwrap();
        assert_eq!(restored.root(), full.root());
        previous_root = root;
        previous = state;
    }
    eprintln!(
        "2048-slot/64-revision history: full={full_reads} node reads, incremental={incremental_reads}, elapsed={:?}",
        started.elapsed()
    );
    assert!(
        incremental_reads * 100 < full_reads,
        "reads must scale with changed paths"
    );
    // Root/leaf/branch/empty transitions and a nonadjacent history jump.
    for subset in [&entries[..1], &entries[..2], &entries[..], &entries[..0]] {
        let root = v2_tree(subset, 0, &mut nodes);
        let (state, _) = rehydrate_v2_incremental(root, previous_root, &previous, &mut |address| {
            nodes.get(address).cloned()
        })
        .unwrap();
        let full = rehydrate_v2(root, &mut |address| nodes.get(address).cloned(), &table).unwrap();
        assert_eq!(state.root(), full.root());
        previous_root = root;
        previous = state;
    }
    assert_eq!(
        previous_root,
        StateRoot::from_bytes(*blake3::hash(b"spindle-empty-state-v2").as_bytes())
    );
}

#[test]
fn incremental_conversion_rejects_corruption_and_missing_changed_nodes() {
    use spindle_core::{MemStateKeyTable, rehydrate_v2_incremental};
    let table = MemStateKeyTable::shared();
    let entries = vec![("m.room.name".to_owned(), String::new(), "$name".to_owned())];
    let mut nodes = std::collections::HashMap::new();
    let previous_root = v2_tree(&entries, 0, &mut nodes);
    let previous =
        rehydrate_v2(previous_root, &mut |root| nodes.get(root).cloned(), &table).unwrap();
    let changed = vec![("m.room.name".to_owned(), String::new(), "$next".to_owned())];
    let root = v2_tree(&changed, 0, &mut nodes);
    let mut corrupt = nodes[&root].clone();
    *corrupt.last_mut().unwrap() ^= 1;
    nodes.insert(root, corrupt);
    assert!(matches!(
        rehydrate_v2_incremental(root, previous_root, &previous, &mut |address| nodes
            .get(address)
            .cloned()),
        Err(RehydrateError::HashMismatch)
    ));
    nodes.remove(&root);
    assert!(matches!(
        rehydrate_v2_incremental(root, previous_root, &previous, &mut |address| nodes
            .get(address)
            .cloned()),
        Err(RehydrateError::MissingNode)
    ));
}

#[test]
fn migrated_history_verification_skips_shared_nodes_without_retaining_snapshots() {
    use spindle_core::{MemStateKeyTable, MigrationStateVerifier, StateSnapshot};
    let table = MemStateKeyTable::shared();
    let mut state = StateSnapshot::new(table.clone());
    for i in 0..2048 {
        state = state.apply(
            &StateKey::new("m.room.member", format!("@member{i}:example.org")),
            format!("$member{i}"),
        );
    }
    let mut nodes: std::collections::HashMap<_, _> = state.delta_nodes(None).into_iter().collect();
    let mut verifier = MigrationStateVerifier::new(table.clone(), 100_000);
    verifier
        .verify(state.root(), &mut |root| nodes.get(root).cloned())
        .unwrap();
    let mut cached_reads = 0;
    let mut full_reads = 0;
    for i in 0..64 {
        let next = state.apply(
            &StateKey::new("m.room.member", format!("@member{i}:example.org")),
            format!("$changed{i}"),
        );
        nodes.extend(next.delta_nodes(Some(&state)));
        let root = next.root();
        state = next;
        verifier
            .verify(root, &mut |address| {
                cached_reads += 1;
                nodes.get(address).cloned()
            })
            .unwrap();
        StateSnapshot::rehydrate(
            root,
            &mut |address| {
                full_reads += 1;
                nodes.get(address).cloned()
            },
            table.clone(),
        )
        .unwrap();
    }
    eprintln!("v3 retry history: full={full_reads} node reads, verification memo={cached_reads}");
    assert!(cached_reads * 100 < full_reads);
    // Bounded eviction sacrifices performance, never validity.
    let mut bounded = MigrationStateVerifier::new(table.clone(), 8);
    bounded
        .verify(state.root(), &mut |address| nodes.get(address).cloned())
        .unwrap();
    let changed = state.apply(&StateKey::new("m.room.name", ""), "$new");
    nodes.extend(changed.delta_nodes(Some(&state)));
    nodes.remove(&changed.root());
    assert!(matches!(
        verifier.verify(changed.root(), &mut |address| nodes.get(address).cloned()),
        Err(RehydrateError::MissingNode)
    ));
    let mut fresh = MigrationStateVerifier::new(table, 100_000);
    let mut corrupt = nodes[&state.root()].clone();
    *corrupt.last_mut().unwrap() ^= 1;
    nodes.insert(state.root(), corrupt);
    assert!(
        fresh
            .verify(state.root(), &mut |address| nodes.get(address).cloned())
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One failure/reopen/retry scenario.
fn incremental_migration_resumes_after_a_committed_chunk_and_keeps_all_history() {
    use spindle_core::{StateRoot, StateSnapshot};
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    seed_v3_entry(&store);
    write_v2_fixture(&store);
    let mut entries: Vec<_> = (0..2048)
        .map(|i| {
            (
                "m.room.member".to_owned(),
                format!("@member{i}:example.org"),
                format!("$member{i}"),
            )
        })
        .collect();
    let mut nodes = std::collections::HashMap::new();
    let first = v2_tree(&entries, 0, &mut nodes);
    let mut history = vec![(first, entries.clone())];
    for revision in 0..16 {
        entries[revision].2 = format!("$changed{revision}");
        let root = v2_tree(&entries, 0, &mut nodes);
        history.push((root, entries.clone()));
    }
    for (address, bytes) in &nodes {
        Store::put(
            &store,
            &content_addressed(Keyspace::StateNode, address.as_bytes()),
            bytes,
        )
        .unwrap();
    }
    let template_key = room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(2));
    let template =
        EntryRecord::decode(&ReadView::get(&store, &template_key).unwrap().unwrap()).unwrap();
    for (index, (root, _)) in history.iter().enumerate() {
        let mut record = template.clone();
        record.li = i64::try_from(index).unwrap() + 2;
        record.state_root = *root.as_bytes();
        Store::put(
            &store,
            &room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(record.li)),
            &record.encode(),
        )
        .unwrap();
    }
    // The first conversion exceeds the 2,000-row commit chunk. Fail only
    // afterwards, then reopen so retry uses persisted intern ids and v3 nodes.
    let missing = history[1].0;
    Store::delete(
        &store,
        &content_addressed(Keyspace::StateNode, missing.as_bytes()),
    )
    .unwrap();
    assert!(run(&store, MIGRATIONS, false).is_err());
    let committed =
        EntryRecord::decode(&ReadView::get(&store, &template_key).unwrap().unwrap()).unwrap();
    assert_ne!(
        committed.state_root,
        *first.as_bytes(),
        "a chunk really committed"
    );
    Store::put(
        &store,
        &content_addressed(Keyspace::StateNode, missing.as_bytes()),
        &nodes[&missing],
    )
    .unwrap();
    drop(store);
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    run(&store, MIGRATIONS, false).unwrap();
    drop(store);
    let store = FjallStore::open(dir.path()).unwrap();
    for (index, (_, expected)) in history.iter().enumerate() {
        let key = room_li(
            Keyspace::Log,
            ROOM,
            LinearIndex::from_raw(i64::try_from(index).unwrap() + 2),
        );
        let record = EntryRecord::decode(&ReadView::get(&store, &key).unwrap().unwrap()).unwrap();
        let state = StateSnapshot::rehydrate(
            StateRoot::from_bytes(record.state_root),
            &mut |root| {
                ReadView::get(
                    &store,
                    &content_addressed(Keyspace::StateNode, root.as_bytes()),
                )
                .unwrap()
            },
            store.key_table(),
        )
        .unwrap();
        assert_eq!(state.len(), expected.len());
        for (kind, key, event) in expected {
            assert_eq!(
                state.get(&StateKey::new(kind.as_str(), key.as_str())),
                Some(event.as_str())
            );
        }
    }
    // Retry can only collect v2 nodes reachable from records still naming v2.
    // The first committed record no longer references its old root; its
    // unreachable old nodes are harmless orphans under the existing contract.
    let mut retry_nodes = std::collections::HashSet::new();
    for (root, _) in &history[1..] {
        retry_nodes.extend(
            spindle_core::v2_node_addresses(*root, &mut |address| nodes.get(address).cloned())
                .unwrap(),
        );
    }
    for address in retry_nodes {
        assert!(
            ReadView::get(
                &store,
                &content_addressed(Keyspace::StateNode, address.as_bytes())
            )
            .unwrap()
            .is_none()
        );
    }
    assert!(
        ReadView::get(
            &store,
            &content_addressed(Keyspace::StateNode, first.as_bytes())
        )
        .unwrap()
        .is_some()
    );
    assert!(run(&store, MIGRATIONS, false).unwrap().steps.is_empty());
}

#[test]
fn migration_verifier_checks_descendants_intern_ids_and_depth_after_cache_hits() {
    use spindle_core::{MemStateKeyTable, MigrationStateVerifier, StateRoot, StateSnapshot};
    let table = MemStateKeyTable::shared();
    let state = StateSnapshot::new(table.clone()).apply(&StateKey::new("m.room.name", ""), "$name");
    let mut nodes: std::collections::HashMap<_, _> = state.delta_nodes(None).into_iter().collect();
    let mut verifier = MigrationStateVerifier::new(table, 1000);
    verifier
        .verify(state.root(), &mut |address| nodes.get(address).cloned())
        .unwrap();
    // A separately scoped table must refuse the same leaf's unknown intern id.
    let mut foreign = MigrationStateVerifier::new(MemStateKeyTable::shared(), 1000);
    assert!(matches!(
        foreign.verify(state.root(), &mut |address| nodes.get(address).cloned()),
        Err(RehydrateError::Malformed)
    ));
    let branch = |child: StateRoot| {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(child.as_bytes());
        let mut hash = blake3::Hasher::new();
        hash.update(b"spindle-hamt-branch-v3\0");
        hash.update(&1_u32.to_be_bytes());
        hash.update(child.as_bytes());
        (StateRoot::from_bytes(*hash.finalize().as_bytes()), bytes)
    };
    let (root, bytes) = branch(state.root());
    nodes.insert(root, bytes);
    let mut independent = MigrationStateVerifier::new(state.table().clone(), 1000);
    assert!(matches!(
        independent.verify(root, &mut |address| {
            if *address == state.root() {
                None
            } else {
                nodes.get(address).cloned()
            }
        }),
        Err(RehydrateError::MissingNode)
    ));
    // Hash-valid branch wrappers reach the already cached leaf at depth 53,
    // beyond the decoder's 52-level limit. Cached depth zero cannot bypass it.
    let mut root = state.root();
    for _ in 0..53 {
        let (next, bytes) = branch(root);
        nodes.insert(next, bytes);
        root = next;
    }
    assert!(matches!(
        verifier.verify(root, &mut |address| nodes.get(address).cloned()),
        Err(RehydrateError::Malformed)
    ));
}
