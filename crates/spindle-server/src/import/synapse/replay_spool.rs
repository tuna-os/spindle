//! Temporary supplied states for a room's replay. The destination store is
//! untouched until replay settles; losing this spool means replaying the room.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use spindle_core::{StateKey, StateRoot, StateSnapshot};
use spindle_store::{Durability, FjallStore, ReadView, Store};

use crate::import::{Settled, StateMap};

#[derive(Serialize, Deserialize)]
struct Record {
    event_id: String,
    root: [u8; 32],
    slots: Vec<(String, String, String)>,
    reason: String,
}

/// The engine bounds its write buffers; this owner keeps at most one saved
/// and one read snapshot, independent of how many events need supplied state.
pub(super) struct ReplaySpool {
    path: PathBuf,
    store: Option<FjallStore>,
    pass: u64,
    saved: Option<StateSnapshot>,
    read: Option<StateSnapshot>,
}

impl ReplaySpool {
    pub(super) fn new(parent: &Path) -> Result<Self, String> {
        let path = parent.join(format!(
            ".spindle-replay-{}-{:032x}",
            std::process::id(),
            rand::random::<u128>()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|error| error.to_string())?;
        let store = match FjallStore::open(&path) {
            Ok(store) => store,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&path);
                return Err(error.to_string());
            }
        };
        Ok(Self {
            path,
            store: Some(store),
            pass: 0,
            saved: None,
            read: None,
        })
    }

    fn store(&self) -> Result<&FjallStore, String> {
        self.store
            .as_ref()
            .ok_or_else(|| "replay spool is closed".to_owned())
    }

    pub(super) fn begin_pass(&mut self) -> Result<(), String> {
        self.pass = self.pass.checked_add(1).ok_or("replay pass overflow")?;
        // A record from an earlier pass must never seed this pass's write.
        // Content-addressed nodes remain reusable, but the record key changes.
        self.saved = None;
        self.read = None;
        Ok(())
    }

    fn node_key(root: StateRoot) -> Vec<u8> {
        let mut key = vec![b'n'];
        key.extend_from_slice(root.as_bytes());
        key
    }

    fn record_key(&self, event_id: &str) -> Vec<u8> {
        let mut key = vec![b's'];
        key.extend_from_slice(&self.pass.to_be_bytes());
        key.extend_from_slice(blake3::hash(event_id.as_bytes()).as_bytes());
        key
    }

    pub(super) fn save(&mut self, event_id: &str, state: &Settled) -> Result<(), String> {
        let record = Record {
            event_id: event_id.to_owned(),
            root: *state.state.root().as_bytes(),
            slots: state
                .slots
                .iter()
                .map(|((kind, key), id)| (kind.clone(), key.clone(), id.clone()))
                .collect(),
            reason: state.reason.clone(),
        };
        let mut writes: Vec<_> = state
            .state
            .delta_nodes(self.saved.as_ref())
            .into_iter()
            .map(|(root, bytes)| (Self::node_key(root), bytes))
            .collect();
        writes.push((
            self.record_key(event_id),
            serde_json::to_vec(&record).map_err(|error| error.to_string())?,
        ));
        // Atomic nodes + record, buffered because the spool is disposable.
        // No checkpoint refers to it, and each process makes a fresh directory.
        self.store()?
            .commit(&writes, Durability::Relaxed)
            .map_err(|error| error.to_string())?;
        self.saved = Some(state.state.clone());
        Ok(())
    }

    pub(super) fn load(&mut self, event_id: &str) -> Result<Option<Settled>, String> {
        let Some(bytes) = self
            .store()?
            .get(&self.record_key(event_id))
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let record: Record = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if record.event_id != event_id {
            return Err("replay record event ID mismatch".to_owned());
        }
        let root = StateRoot::from_bytes(record.root);
        let state = if let Some(previous) = self
            .read
            .as_ref()
            .filter(|previous| previous.root() == root)
        {
            previous.clone()
        } else {
            let store = self.store()?;
            let mut read_error = None;
            let loaded = StateSnapshot::rehydrate(root, &mut |address| match store
                .get(&Self::node_key(*address))
            {
                Ok(value) => value,
                Err(error) => {
                    read_error = Some(error.to_string());
                    None
                }
            })
            .map_err(|error| {
                read_error.unwrap_or_else(|| format!("invalid replay state: {error:?}"))
            })?;
            // Rehydration creates new Arcs. Keep the shared paths from the
            // preceding read so the destination's resident window does not
            // retain hundreds of independent full member tries.
            match &self.read {
                None => loaded,
                Some(previous) => {
                    let mut shared = previous.clone();
                    for (key, _, value) in previous.diff(&loaded) {
                        shared = match value {
                            Some(value) => shared.apply(key.clone(), value.to_owned()),
                            None => shared.remove(key),
                        };
                    }
                    if shared.root() != root {
                        return Err("replay state sharing changed its root".to_owned());
                    }
                    shared
                }
            }
        };
        self.read = Some(state.clone());
        let slots: StateMap = record
            .slots
            .into_iter()
            .map(|(kind, key, id)| ((kind, key), id))
            .collect();
        for ((kind, key), id) in &slots {
            if state.get(&StateKey::new(kind.clone(), key.clone())) != Some(id.as_str()) {
                return Err("replay slot does not match its state".to_owned());
            }
        }
        Ok(Some(Settled {
            state,
            slots,
            reason: record.reason,
        }))
    }
}

impl Drop for ReplaySpool {
    fn drop(&mut self) {
        drop(self.store.take());
        if let Err(error) = std::fs::remove_dir_all(&self.path) {
            tracing::warn!(error = %error, "could not remove temporary replay state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{
        MemorySource, SourceEvent, SourceRoom, SourceState, SynapseSource, finish_room,
        persist_chunk, plan_resolving, replay_resolving,
    };
    use crate::rooms::Rooms;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn supplied(state: StateSnapshot, key: &str, event: &str) -> Settled {
        Settled {
            state,
            slots: StateMap::from([(
                ("m.room.member".to_owned(), key.to_owned()),
                event.to_owned(),
            )]),
            reason: "source state differs from derivation".to_owned(),
        }
    }

    #[test]
    fn disk_records_keep_only_two_snapshots_and_restore_every_state() {
        let parent = tempfile::tempdir().expect("parent");
        let mut spool = ReplaySpool::new(parent.path()).expect("spool");
        spool.begin_pass().expect("pass");
        let mut state = StateSnapshot::new();
        for member in 0..1_000 {
            state = state.apply(
                StateKey::new("m.room.member", format!("@member{member}:test")),
                format!("$old{member}"),
            );
        }
        let mut roots = Vec::new();
        for event in 0..100 {
            let id = format!("$update{event}");
            let key = format!("@member{event}:test");
            state = state.apply(StateKey::new("m.room.member", key.clone()), id.clone());
            roots.push(state.root());
            spool
                .save(&id, &supplied(state.clone(), &key, &id))
                .expect("save");
            // The original outcome held a snapshot per supplied event. This
            // source holds exactly one while saving, regardless of count.
            assert!(spool.saved.is_some());
            assert!(spool.read.is_none());
        }
        for (event, root) in roots.into_iter().enumerate() {
            let id = format!("$update{event}");
            let loaded = spool.load(&id).expect("load").expect("record");
            assert_eq!(loaded.state.root(), root);
            assert_eq!(loaded.state.len(), 1_000);
            assert_eq!(loaded.slots.len(), 1);
            if event > 0 {
                // Consecutive reads share the unchanged trie paths. Rebuilding
                // a full independent member trie here would multiply RAM by
                // the destination's 512-snapshot resident window.
                let previous = spool
                    .load(&format!("$update{}", event - 1))
                    .expect("previous")
                    .expect("record");
                assert!(loaded.state.delta_nodes(Some(&previous.state)).len() < 10);
            }
        }
        let path = spool.path.clone();
        drop(spool);
        assert!(!path.exists());
    }

    #[test]
    fn new_pass_cannot_read_old_supplied_states() {
        let parent = tempfile::tempdir().expect("parent");
        let mut spool = ReplaySpool::new(parent.path()).expect("spool");
        spool.begin_pass().expect("first");
        let state = StateSnapshot::new().apply(StateKey::new("m.room.member", "@a:test"), "$a");
        spool
            .save("$a", &supplied(state.clone(), "@a:test", "$a"))
            .expect("save");
        assert!(spool.load("$a").expect("first load").is_some());
        spool.begin_pass().expect("second");
        assert!(spool.load("$a").expect("second load").is_none());
        spool
            .save("$a", &supplied(state, "@a:test", "$a"))
            .expect("save again");
        assert!(spool.load("$a").expect("current load").is_some());
    }

    #[test]
    fn corrupt_or_missing_state_refuses_read_instead_of_folding() {
        let parent = tempfile::tempdir().expect("parent");
        let mut spool = ReplaySpool::new(parent.path()).expect("spool");
        spool.begin_pass().expect("pass");
        let state = StateSnapshot::new().apply(StateKey::new("m.room.member", "@a:test"), "$a");
        spool
            .save("$a", &supplied(state.clone(), "@a:test", "$a"))
            .expect("save");
        spool
            .store()
            .expect("store")
            .put(&ReplaySpool::node_key(state.root()), b"bad node")
            .expect("corrupt");
        assert!(spool.load("$a").is_err());
        spool
            .store()
            .expect("store")
            .delete(&ReplaySpool::node_key(state.root()))
            .expect("delete");
        assert!(spool.load("$a").is_err());
    }

    #[test]
    fn absent_event_and_empty_state_are_distinct() {
        let parent = tempfile::tempdir().expect("parent");
        let mut spool = ReplaySpool::new(parent.path()).expect("spool");
        spool.begin_pass().expect("pass");
        let empty = Settled {
            state: StateSnapshot::new(),
            slots: StateMap::new(),
            reason: "empty".to_owned(),
        };
        spool.save("$empty", &empty).expect("save");
        assert!(spool.load("$absent").expect("absent").is_none());
        assert!(
            spool
                .load("$empty")
                .expect("empty")
                .expect("record")
                .state
                .is_empty()
        );
    }

    struct DiskSource {
        source: MemorySource,
        spool: ReplaySpool,
        resolve_first_parent: bool,
    }

    impl SourceState for DiskSource {
        fn state_after(&mut self, id: &str) -> Result<StateMap, String> {
            self.source.state_after(id)
        }
        fn begin_replay_pass(&mut self) -> Result<(), String> {
            self.spool.begin_pass()
        }
        fn retain_settled(&mut self, id: &str, state: &Settled) -> Result<bool, String> {
            self.spool.save(id, state)?;
            Ok(false)
        }
        fn resolve(
            &mut self,
            _states: &[&StateSnapshot],
        ) -> Option<Result<crate::import::Resolution, String>> {
            self.resolve_first_parent
                .then(|| Ok(crate::import::Resolution::default()))
        }
    }

    impl SynapseSource for DiskSource {
        fn body(&mut self, id: &str) -> Option<Value> {
            self.source.body(id)
        }
        fn read_settled(&mut self, id: &str) -> Result<Option<Settled>, String> {
            self.spool.load(id)
        }
    }

    fn gapped_room() -> (SourceRoom, MemorySource) {
        let room_id = "!spool:example.org";
        let alice = "@alice:example.org";
        let rows = [
            ("$create", "m.room.create", Some(""), vec![]),
            ("$alice", "m.room.member", Some(alice), vec!["$create"]),
            ("$a", "m.room.topic", Some(""), vec!["$alice"]),
            ("$b", "m.room.topic", Some(""), vec!["$alice"]),
            ("$merge", "m.room.message", None, vec!["$a", "$b"]),
            ("$island", "m.room.message", None, vec!["$outside"]),
            ("$rejoin", "m.room.message", None, vec!["$merge", "$island"]),
        ];
        let mut events = Vec::new();
        let mut bodies = HashMap::new();
        for (id, kind, key, parents) in rows {
            let content = match kind {
                "m.room.create" => json!({"creator":alice,"room_version":"10"}),
                "m.room.member" => json!({"membership":"join"}),
                "m.room.topic" => json!({"topic":id}),
                _ => json!({"msgtype":"m.text","body":id}),
            };
            let mut body = json!({"room_id":room_id,"type":kind,"sender":alice,"origin_server_ts":1_700_000_000_000_u64,"prev_events":parents,"auth_events":[],"depth":1,"hashes":{"sha256":"unchecked"},"signatures":{},"content":content});
            if let Some(key) = key {
                body["state_key"] = json!(key);
            }
            bodies.insert(id.to_owned(), body);
            events.push(SourceEvent {
                event_id: id.to_owned(),
                event_type: kind.to_owned(),
                state_key: key.map(str::to_owned),
                prev_events: parents.into_iter().map(str::to_owned).collect(),
                depth: 0,
                stream_ordering: 0,
                outlier: false,
                rejected: false,
            });
        }
        let current: StateMap = [
            (
                ("m.room.create".to_owned(), String::new()),
                "$create".to_owned(),
            ),
            (
                ("m.room.member".to_owned(), alice.to_owned()),
                "$alice".to_owned(),
            ),
            (("m.room.topic".to_owned(), String::new()), "$b".to_owned()),
        ]
        .into_iter()
        .collect();
        let states = ["$merge", "$island", "$rejoin"]
            .into_iter()
            .map(|id| (id.to_owned(), current.clone()))
            .collect();
        (
            SourceRoom {
                room_id: room_id.to_owned(),
                events,
                current_state: current,
                state_after_root: None,
                forward_extremities: Vec::new(),
            },
            MemorySource { bodies, states },
        )
    }

    #[test]
    fn replay_offloads_supplied_states_and_disk_writer_matches_memory() {
        let parent = tempfile::tempdir().expect("parent");
        let (room, mut memory) = gapped_room();
        let expected = replay_resolving(&room, &mut memory, false).expect("memory replay");
        assert!(!expected.settled.is_empty());
        let (_, source) = gapped_room();
        let mut disk = DiskSource {
            source,
            spool: ReplaySpool::new(parent.path()).expect("spool"),
            resolve_first_parent: false,
        };
        let actual = replay_resolving(&room, &mut disk, false).expect("disk replay");
        assert!(
            actual.settled.is_empty(),
            "no per-event snapshots retained in the outcome"
        );
        assert_eq!(actual.outcome.divergence, expected.outcome.divergence);
        assert_eq!(actual.from_source, expected.from_source);
        assert_eq!(actual.passes, expected.passes);
        for (id, state) in &expected.settled {
            let loaded = disk.read_settled(id).expect("read").expect("supplied");
            assert_eq!(loaded.state.root(), state.state.root());
            assert_eq!(loaded.slots, state.slots);
            assert_eq!(loaded.reason, state.reason);
        }
        let memory_store =
            Arc::new(FjallStore::open(parent.path().join("memory-target")).expect("store"));
        let disk_store =
            Arc::new(FjallStore::open(parent.path().join("disk-target")).expect("store"));
        let memory_rooms = Rooms::new(memory_store, "example.org");
        let disk_rooms = Rooms::new(disk_store, "example.org");
        let plan = plan_resolving(&room).expect("plan");
        let expected_write =
            persist_chunk(&memory_rooms, &room.room_id, &plan.steps, None, &mut memory)
                .expect("memory write");
        let actual_write = persist_chunk(&disk_rooms, &room.room_id, &plan.steps, None, &mut disk)
            .expect("disk write");
        assert_eq!(actual_write, expected_write);
        finish_room(&memory_rooms, &room.room_id, &[]).expect("finish");
        finish_room(&disk_rooms, &room.room_id, &[]).expect("finish");
        assert_eq!(
            disk_rooms.state(&room.room_id).expect("disk state"),
            memory_rooms.state(&room.room_id).expect("memory state")
        );
    }

    #[test]
    fn writer_propagates_spool_corruption_when_source_state_is_available() {
        let parent = tempfile::tempdir().expect("parent");
        let (room, source) = gapped_room();
        let mut disk = DiskSource {
            source,
            spool: ReplaySpool::new(parent.path()).expect("spool"),
            resolve_first_parent: false,
        };
        let replay = replay_resolving(&room, &mut disk, false).expect("replay");
        assert!(replay.outcome.clean());
        disk.spool
            .store()
            .expect("store")
            .put(&disk.spool.record_key("$island"), b"bad record")
            .expect("corrupt");
        let rooms = Rooms::new(
            Arc::new(FjallStore::open(parent.path().join("target")).expect("store")),
            "example.org",
        );
        let plan = plan_resolving(&room).expect("plan");
        let error = persist_chunk(&rooms, &room.room_id, &plan.steps, None, &mut disk)
            .expect_err("refuse rather than use source fallback");
        assert!(error.to_string().contains("cannot read replayed state"));
    }

    struct FirstParentSource(MemorySource);

    impl SourceState for FirstParentSource {
        fn state_after(&mut self, id: &str) -> Result<StateMap, String> {
            self.0.state_after(id)
        }
        fn resolve(
            &mut self,
            _states: &[&StateSnapshot],
        ) -> Option<Result<crate::import::Resolution, String>> {
            // A controlled resolver answer that Strict cannot fold at $merge.
            // The replay must mark it and start a second fixed-point pass.
            Some(Ok(crate::import::Resolution::default()))
        }
    }

    #[test]
    fn fixed_point_second_pass_writes_only_its_own_supplied_states() {
        let parent = tempfile::tempdir().expect("parent");
        let (mut room, mut memory) = gapped_room();
        let topic = ("m.room.topic".to_owned(), String::new());
        room.current_state.insert(topic.clone(), "$a".to_owned());
        for state in memory.states.values_mut() {
            state.insert(topic.clone(), "$a".to_owned());
        }
        let disk_memory = MemorySource {
            bodies: memory.bodies.clone(),
            states: memory.states.clone(),
        };
        let expected =
            replay_resolving(&room, &mut FirstParentSource(memory), false).expect("memory replay");
        assert!(expected.passes >= 2);
        assert!(expected.outcome.clean());
        let mut disk = DiskSource {
            source: disk_memory,
            spool: ReplaySpool::new(parent.path()).expect("spool"),
            resolve_first_parent: true,
        };
        disk.spool.begin_pass().expect("old pass");
        let state = StateSnapshot::new().apply(StateKey::new("m.room.member", "@old:test"), "$old");
        disk.spool
            .save("$old-pass-only", &supplied(state, "@old:test", "$old"))
            .expect("old record");
        let actual = replay_resolving(&room, &mut disk, false).expect("disk replay");
        assert_eq!(actual.passes, expected.passes);
        assert_eq!(disk.spool.pass, 1 + actual.passes as u64);
        assert!(actual.settled.is_empty());
        assert_eq!(actual.from_source, expected.from_source);
        assert!(
            disk.read_settled("$old-pass-only")
                .expect("old record read")
                .is_none()
        );
        for (id, expected) in expected.settled {
            let actual = disk
                .read_settled(&id)
                .expect("load")
                .expect("current record");
            assert_eq!(actual.state.root(), expected.state.root());
            assert_eq!(actual.slots, expected.slots);
            assert_eq!(actual.reason, expected.reason);
        }
    }
}
