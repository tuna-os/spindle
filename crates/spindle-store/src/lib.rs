//! Durable storage for the Spindle linear log.
//!
//! Kept in its own crate so `spindle-core` stays free of a storage dependency,
//! per ADR 0002: the linear log and the state trie are the parts that are
//! actually ours, and they remain independently testable and benchmarkable.

pub mod codec;

use std::path::Path;

use fjall::{
    Config, Keyspace as FjallKeyspace, PartitionCreateOptions, PartitionHandle, PersistMode,
};
use spindle_core::{
    EventId, RestoreError, RestoredEntry, RestoredLog, RoomLog, StateRoot,
    keys::{Keyspace, content_addressed, room_li, room_prefix},
};

use crate::codec::{CodecError, EntryRecord, RoomRecord};

/// How hard a commit tries to be on disk before it is acknowledged.
///
/// Maps SPEC §8.3's three modes onto the engine. Ordering is decided before
/// durability in every mode, so a crash can only ever lose a *suffix* of the
/// log — never reorder it, never fork it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Durability {
    /// `strict`: data and metadata are fsynced before the commit returns.
    Strict,
    /// `group`: data is fsynced before the commit returns; file metadata is
    /// left to the OS.
    ///
    /// Note this is not yet the batched fsync SPEC §8.3 describes — commits are
    /// not currently coalesced across a time window, so this is "one data
    /// fsync per commit" rather than "one fsync per batch of commits". The
    /// coalescing needs the per-room executor and lands with it.
    #[default]
    Group,
    /// `relaxed`: the write reaches the OS page cache and is fsynced later.
    Relaxed,
}

impl Durability {
    fn persist_mode(self) -> PersistMode {
        match self {
            Self::Strict => PersistMode::SyncAll,
            Self::Group => PersistMode::SyncData,
            Self::Relaxed => PersistMode::Buffer,
        }
    }
}

/// One key and its value, as read back from a scan.
pub type Record = (Vec<u8>, Vec<u8>);

/// The ordered key-value operations the log needs.
///
/// Narrow on purpose: every hot operation is a point lookup or a sorted range
/// scan, so nothing here needs a query planner and a second backend has little
/// to implement.
pub trait Store {
    /// # Errors
    ///
    /// Returns a backend error if the write fails.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError>;

    /// # Errors
    ///
    /// Returns a backend error if the read fails.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;

    /// Entries whose key starts with `prefix`, in key order.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the scan fails.
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError>;

    /// Apply every write together, or none of them.
    ///
    /// Atomicity is the point: an appended event, its room metadata and its
    /// extremities describe one state of the room, and a reader must never see
    /// half of them.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the commit fails.
    fn commit(&self, writes: &[Record], durability: Durability) -> Result<(), StoreError>;

    /// # Errors
    ///
    /// Returns a backend error if the flush fails.
    fn flush(&self) -> Result<(), StoreError>;
}

/// A Fjall-backed store.
pub struct FjallStore {
    keyspace: FjallKeyspace,
    partition: PartitionHandle,
}

impl FjallStore {
    /// Open or create a store at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the keyspace cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let keyspace = Config::new(path).open()?;
        let partition = keyspace.open_partition("spindle", PartitionCreateOptions::default())?;
        Ok(Self {
            keyspace,
            partition,
        })
    }
}

impl Store for FjallStore {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.partition.insert(key, value)?;
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.partition.get(key)?.map(|slice| slice.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.partition.prefix(prefix) {
            let (key, value) = pair?;
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }

    fn commit(&self, writes: &[Record], durability: Durability) -> Result<(), StoreError> {
        let mut batch = self.keyspace.batch();
        for (key, value) in writes {
            batch.insert(&self.partition, key.as_slice(), value.as_slice());
        }
        batch.durability(Some(durability.persist_mode())).commit()?;
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        self.keyspace.persist(PersistMode::SyncAll)?;
        Ok(())
    }
}

/// Persist a room's log, and read it back.
pub struct RoomStore<'a, S: Store> {
    store: &'a S,
    room_id: String,
}

impl<'a, S: Store> RoomStore<'a, S> {
    pub fn new(store: &'a S, room_id: impl Into<String>) -> Self {
        Self {
            store,
            room_id: room_id.into(),
        }
    }

    /// Commit one newly appended entry together with the room's metadata.
    ///
    /// This is the write path a server uses: a single atomic batch per event,
    /// proportional to the event rather than to the room. The entry, the
    /// counters and the extremity set move together, so a reader never sees a
    /// room whose head disagrees with its log.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the commit fails.
    pub fn commit_entry(
        &self,
        entry: &spindle_core::LogEntry,
        log: &RoomLog,
        durability: Durability,
    ) -> Result<(), StoreError> {
        // Only the nodes this entry actually created. Path copying means an
        // unchanged subtree keeps its content address, so the walk stops as
        // soon as it reaches something the previous state already held --
        // O(log n) nodes per state change rather than O(state).
        let previous = log
            .entries()
            .rev()
            .find(|candidate| candidate.li < entry.li)
            .map(|candidate| &candidate.state_after);

        let mut writes = vec![
            (
                room_li(Keyspace::Log, &self.room_id, entry.li),
                EntryRecord::from_entry(entry).encode(),
            ),
            (
                room_prefix(Keyspace::RoomMeta, &self.room_id),
                Self::meta(log).encode(),
            ),
        ];
        for (address, node) in entry.state_after.delta_nodes(previous) {
            writes.push((
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            ));
        }

        self.store.commit(&writes, durability)
    }

    fn meta(log: &RoomLog) -> RoomRecord {
        RoomRecord {
            next_forward: log.next_forward(),
            next_backward: log.next_backward(),
            forward_extremities: log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        }
    }

    /// Write every entry and the room's metadata.
    ///
    /// Rewrites the whole room, so it is for seeding and tests rather than the
    /// serving path; use [`RoomStore::commit_entry`] for an append.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if any write fails.
    pub fn save(&self, log: &RoomLog) -> Result<(), StoreError> {
        let mut previous = None;
        for entry in log.entries() {
            let key = room_li(Keyspace::Log, &self.room_id, entry.li);
            self.store
                .put(&key, &EntryRecord::from_entry(entry).encode())?;
            // Persist the state trie here too, so both write paths restore
            // identically. A seeding path that produced a differently
            // restorable room would be a trap for whoever hit it first.
            for (address, node) in entry.state_after.delta_nodes(previous) {
                self.store.put(
                    &content_addressed(Keyspace::StateNode, address.as_bytes()),
                    &node,
                )?;
            }
            previous = Some(&entry.state_after);
        }
        self.store.put(
            &room_prefix(Keyspace::RoomMeta, &self.room_id),
            &Self::meta(log).encode(),
        )?;
        self.store.flush()
    }

    /// Rebuild the log by refolding state from the log alone, ignoring the
    /// stored state trie.
    ///
    /// The log is the authoritative record and the trie is derived from it, so
    /// this is the recovery path when the trie is lost or unreadable — and the
    /// baseline for judging whether persisting the trie earns its cost.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on a backend failure or an unreadable record.
    pub fn load_refolding(&self) -> Result<Option<RestoredLog>, StoreError> {
        let Some((meta, entries)) = self.read_records()? else {
            return Ok(None);
        };
        Ok(Some(RoomLog::restore(
            entries,
            meta.next_forward,
            meta.next_backward,
            meta.forward_extremities
                .into_iter()
                .map(|id| EventId::new(id.as_str())),
        )?))
    }

    fn read_records(&self) -> Result<Option<(RoomRecord, Vec<RestoredEntry>)>, StoreError> {
        let Some(raw_meta) = self
            .store
            .get(&room_prefix(Keyspace::RoomMeta, &self.room_id))?
        else {
            return Ok(None);
        };
        let meta = RoomRecord::decode(&raw_meta)?;

        // The scan is already in `li` order because the key encoding is
        // order-preserving across the sign boundary; backfilled history sorts
        // first without any sorting here.
        let prefix = room_prefix(Keyspace::Log, &self.room_id);
        let mut entries = Vec::new();
        for (_, value) in self.store.scan_prefix(&prefix)? {
            let record = EntryRecord::decode(&value)?;
            entries.push(RestoredEntry {
                li: record.linear_index(),
                event_id: record.event(),
                prev_events: record.parents(),
                depth: record.depth,
                state_key: record.slot(),
                expected_state_root: record.state_root,
            });
        }
        Ok(Some((meta, entries)))
    }

    /// Rebuild the log from storage.
    ///
    /// Returns `Ok(None)` when the room has no metadata, which is how an unknown
    /// room is distinguished from an empty one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on a backend failure, an unreadable record, or
    /// records that cannot be replayed in order.
    pub fn load(&self) -> Result<Option<RestoredLog>, StoreError> {
        let Some((meta, entries)) = self.read_records()? else {
            return Ok(None);
        };

        let mut load_node = |address: &StateRoot| {
            self.store
                .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))
                .ok()
                .flatten()
        };

        let restored = RoomLog::restore_with_state(
            entries,
            meta.next_forward,
            meta.next_backward,
            meta.forward_extremities
                .into_iter()
                .map(|id| EventId::new(id.as_str())),
            &mut load_node,
        )?;
        Ok(Some(restored))
    }
}

/// A storage failure.
#[derive(Debug)]
pub enum StoreError {
    /// The backend failed.
    Backend(String),
    /// A record could not be read.
    Codec(CodecError),
    /// Records could not be replayed into a log.
    Restore(RestoreError),
}

impl From<fjall::Error> for StoreError {
    fn from(error: fjall::Error) -> Self {
        Self::Backend(error.to_string())
    }
}

impl From<CodecError> for StoreError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<RestoreError> for StoreError {
    fn from(error: RestoreError) -> Self {
        Self::Restore(error)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(message) => write!(formatter, "storage backend failed: {message}"),
            Self::Codec(error) => write!(formatter, "unreadable record: {error:?}"),
            Self::Restore(error) => write!(formatter, "could not replay log: {error:?}"),
        }
    }
}

impl std::error::Error for StoreError {}
