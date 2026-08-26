//! Durable storage for the Spindle linear log.
//!
//! Kept in its own crate so `spindle-core` stays free of a storage dependency,
//! per ADR 0002: the linear log and the state trie are the parts that are
//! actually ours, and they remain independently testable and benchmarkable.

pub mod codec;

use std::path::Path;

use fjall::{Config, Keyspace as FjallKeyspace, PartitionCreateOptions, PartitionHandle};
use spindle_core::{
    EventId, RestoreError, RestoredEntry, RestoredLog, RoomLog,
    keys::{Keyspace, room_li, room_prefix},
};

use crate::codec::{CodecError, EntryRecord, RoomRecord};

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

    fn flush(&self) -> Result<(), StoreError> {
        self.keyspace.persist(fjall::PersistMode::SyncAll)?;
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

    /// Write every entry and the room's metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if any write fails.
    pub fn save(&self, log: &RoomLog) -> Result<(), StoreError> {
        for entry in log.entries() {
            let key = room_li(Keyspace::Log, &self.room_id, entry.li);
            self.store
                .put(&key, &EntryRecord::from_entry(entry).encode())?;
        }
        let meta = RoomRecord {
            next_forward: log.next_forward(),
            next_backward: log.next_backward(),
            forward_extremities: log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        };
        self.store.put(
            &room_prefix(Keyspace::RoomMeta, &self.room_id),
            &meta.encode(),
        )?;
        self.store.flush()
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

        let restored = RoomLog::restore(
            entries,
            meta.next_forward,
            meta.next_backward,
            meta.forward_extremities
                .into_iter()
                .map(|id| EventId::new(id.as_str())),
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
