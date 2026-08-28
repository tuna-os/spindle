//! Durable storage for the Spindle linear log.
//!
//! Kept in its own crate so `spindle-core` stays free of a storage dependency,
//! per ADR 0002: the linear log and the state trie are the parts that are
//! actually ours, and they remain independently testable and benchmarkable.

pub mod backup;
pub mod codec;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fjall::{
    Config, Keyspace as FjallKeyspace, PartitionCreateOptions, PartitionHandle, PersistMode,
};
use spindle_core::{
    CONTENT_DIGEST_VERSION, EventId, RestoreError, RestoredEntry, RestoredLog, RoomLog, StateRoot,
    keys::{KEY_SCHEMA_VERSION, Keyspace, content_addressed, room_li, room_prefix, store_marker},
};

use crate::codec::{CodecError, EntryRecord, RECORD_VERSION, RoomRecord};

/// How hard a commit tries to be on disk before it is acknowledged.
///
/// Maps SPEC §8.3's three modes onto the engine. Ordering is decided before
/// durability in every mode, so a crash can only ever lose a *suffix* of the
/// log — never reorder it, never fork it.
///
/// # Is `Strict` actually stronger than `Group`?
///
/// Yes, and #84 was right to ask, because measurement alone said otherwise.
/// Timing 400 commits found `Strict` at 223.5 µs and `Group` at 226.3 µs —
/// `Strict` marginally *faster*, i.e. indistinguishable — and observed that
/// "a mode that claims stronger durability and costs nothing is either free
/// or not doing what its documentation says, and we currently cannot tell
/// which."
///
/// The two candidate explanations were that this filesystem collapses the
/// modes, or that `fjall` does. **`fjall` does not.** Its journal writer
/// dispatches to genuinely different syscalls:
///
/// ```text
/// PersistMode::SyncAll  => file.sync_all()    // fsync(2):     data + metadata
/// PersistMode::SyncData => file.sync_data()   // fdatasync(2): data, and only
///                                             // the metadata needed to
///                                             // retrieve it
/// ```
///
/// So the request really is different, and the equal timings are a property
/// of the workload rather than of the mode. The journal is **append-only**,
/// and appending changes the file's size — which `fdatasync` is obliged to
/// flush anyway, because without the new size the data cannot be found.
/// For a growing file the two calls therefore do nearly the same work, which
/// is exactly the shape of the measurement.
///
/// The conclusion is that `Strict` is a real request that happens to be
/// almost free *here*, not a mode that quietly does nothing. That distinction
/// matters for the "regulated deployments" row in SPEC §8.3: an operator
/// choosing `strict` gets `fsync`, and on a filesystem or workload where the
/// two diverge they will pay for it and receive it.
///
/// `durability_modes_map_to_distinct_syscalls`, below, pins the mapping so
/// it cannot drift back into ambiguity silently.
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

#[cfg(test)]
mod durability_tests {
    use super::{Durability, PersistMode};

    /// Each mode asks the engine for a different syscall.
    ///
    /// This is the assertion #84 wanted and could not get from a stopwatch:
    /// `Strict` and `Group` time identically on an append-only journal, so
    /// timing cannot distinguish "stronger" from "a no-op that happens to be
    /// spelled differently". The mapping can be asserted; the timing cannot.
    ///
    /// If a future change collapses two modes onto one `PersistMode`, this
    /// fails — which is the point. Silently serving `fdatasync` to an
    /// operator who configured `strict` is the failure mode worth a test,
    /// because nothing about the running system would look wrong.
    #[test]
    fn durability_modes_map_to_distinct_syscalls() {
        assert_eq!(Durability::Strict.persist_mode(), PersistMode::SyncAll);
        assert_eq!(Durability::Group.persist_mode(), PersistMode::SyncData);
        assert_eq!(Durability::Relaxed.persist_mode(), PersistMode::Buffer);

        // And they are three modes, not two wearing three names.
        let modes = [
            Durability::Strict.persist_mode(),
            Durability::Group.persist_mode(),
            Durability::Relaxed.persist_mode(),
        ];
        for (i, left) in modes.iter().enumerate() {
            for right in &modes[i + 1..] {
                assert_ne!(left, right, "two durability modes collapsed onto {left:?}");
            }
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
pub trait ReadView {
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
}

pub trait Store: ReadView {
    /// # Errors
    ///
    /// Returns a backend error if the write fails.
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError>;

    /// A read view frozen at this moment, if the backend can provide one.
    ///
    /// Rebuilding a room takes two reads — the metadata, then the log — and a
    /// commit landing between them yields a room whose head and counters
    /// disagree. Metadata that trails the log is the dangerous direction: the
    /// next append reissues an index the log already holds, which is precisely
    /// the fork that ordering is supposed to make impossible.
    ///
    /// `None` means the backend has no snapshot isolation and reads are live.
    /// That is honest rather than silently unsafe: a backend without this
    /// cannot be backed up under concurrent writes, and callers can tell.
    /// Remove one key, if it is there.
    ///
    /// Deleting a key that does not exist is not an error: the caller wanted it
    /// gone, and it is gone. Logging out twice is the ordinary case, not a
    /// fault.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the delete fails.
    fn delete(&self, key: &[u8]) -> Result<(), StoreError>;

    fn snapshot(&self) -> Option<Box<dyn ReadView + '_>> {
        None
    }

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
    /// Point reads and scanned rows served since this store was opened.
    ///
    /// Here so that "how much work does this request do" can be *asserted*
    /// rather than timed. Every performance defect this project has actually
    /// shipped was algorithmic -- a read per member where a point lookup
    /// would do -- and a count catches that deterministically, on any
    /// machine, in a unit test, where a wall clock on a shared CI runner
    /// could not tell the regression from the runner's mood.
    ///
    /// Two relaxed atomics on the read path. They are always compiled in
    /// rather than hidden behind a feature, because a counter that only
    /// exists in test builds cannot be read from a running server, and the
    /// increment is far cheaper than the read it is counting.
    reads: AtomicU64,
    scanned: AtomicU64,
}

impl FjallStore {
    /// Point reads served since this store was opened.
    ///
    /// Monotonic and never reset: a caller measures a span by subtracting
    /// two readings, which composes under concurrency in a way a resettable
    /// counter does not.
    #[must_use]
    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Rows returned by prefix scans since this store was opened.
    ///
    /// Counted as rows rather than scans because that is the cost: one scan
    /// returning ten thousand rows is not one unit of work.
    #[must_use]
    pub fn scanned(&self) -> u64 {
        self.scanned.load(Ordering::Relaxed)
    }

    /// Open or create a store at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the keyspace cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let keyspace = Config::new(path).open()?;
        let partition = keyspace.open_partition("spindle", PartitionCreateOptions::default())?;
        let store = Self {
            reads: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            keyspace,
            partition,
        };
        store.check_schema()?;
        Ok(store)
    }

    /// Refuse a store this binary cannot read, and stamp one that has no mark.
    ///
    /// This is the whole reason the marker exists. Every other key carries the
    /// key-schema version in its first byte, which means a binary reading a
    /// store written under a different one scans a prefix that holds nothing
    /// and concludes the store is empty. An empty store is a plausible thing to
    /// find, so nothing about that is reported as an error, and the deployment
    /// starts serving a room whose entire history it simply cannot see. The
    /// marker turns that silence into a refusal.
    fn check_schema(&self) -> Result<(), StoreError> {
        let key = store_marker();
        match self.get(&key)? {
            Some(raw) => {
                let found = SchemaMarker::decode(&raw)?;
                let supported = SchemaMarker::current();
                if found != supported {
                    return Err(StoreError::UnsupportedSchema { found, supported });
                }
                Ok(())
            }
            // No mark: either a fresh store, or one written before the marker
            // existed. Both are version 1 by construction -- there has never
            // been another -- so stamping is correct rather than a guess. Once
            // a second version exists this arm needs to distinguish them, and
            // an unmarked non-empty store becomes a migration, not a stamp.
            None => self.put(&key, &SchemaMarker::current().encode()),
        }
    }
}

/// The schema versions a store was written under.
///
/// Read before anything else, so it cannot use the record encoding it
/// describes: a fixed few bytes, and those bytes are frozen forever.
///
/// Three versions, because there are three independent ways the stored bytes
/// can change meaning:
///
/// | field | what moving it means |
/// |---|---|
/// | `key_schema` | keys are laid out differently |
/// | `record` | records are encoded differently |
/// | `content_digest` | content addresses are *derived* differently |
///
/// The third was missing until #78. A digest change leaves the key layout and
/// the record encoding untouched, so the marker matched, the store opened, and
/// every node address was wrong — `state_nodes` lookups missing and each
/// entry's recorded `state_root` disagreeing with what recomputing produces,
/// both surfacing far from the cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaMarker {
    pub key_schema: u8,
    pub record: u8,
    pub content_digest: u8,
}

impl SchemaMarker {
    #[must_use]
    pub fn current() -> Self {
        Self {
            key_schema: KEY_SCHEMA_VERSION,
            record: RECORD_VERSION,
            content_digest: CONTENT_DIGEST_VERSION,
        }
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        // A marker version of its own, so even this can change shape -- which
        // is exactly what it was for: adding `content_digest` moved it to 2.
        vec![
            MARKER_VERSION,
            self.key_schema,
            self.record,
            self.content_digest,
        ]
    }

    /// # Errors
    ///
    /// Returns [`CodecError`] if the marker is truncated or of an unknown
    /// marker version.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        match bytes {
            [MARKER_VERSION, key_schema, record, content_digest] => Ok(Self {
                key_schema: *key_schema,
                record: *record,
                content_digest: *content_digest,
            }),
            // A marker written before `content_digest` existed. It is read,
            // not refused, because refusing would make this change reject
            // every store already on disk -- the precise outcome the marker
            // exists to prevent, inflicted by the fix for it.
            //
            // Reading it as digest version 1 is sound for the same reason
            // the unmarked arm below stamps rather than guesses: there has
            // only ever been one derivation, so a store written under the
            // old marker was written under that one. The moment a second
            // exists, `current()` names it, this decodes to 1, and the
            // comparison in `check_schema` refuses -- which is the whole
            // point, and it works without rewriting anyone's marker.
            [MARKER_V1, key_schema, record] => Ok(Self {
                key_schema: *key_schema,
                record: *record,
                content_digest: 1,
            }),
            [version, ..] => Err(CodecError::UnsupportedVersion(*version)),
            [] => Err(CodecError::Truncated),
        }
    }
}

/// Version of the marker's own encoding.
///
/// 2 since #78 added `content_digest`. A binary older than that reads a
/// four-byte marker, sees a marker version it does not know, and refuses --
/// which is correct: it cannot check a derivation it has no field for.
const MARKER_VERSION: u8 = 2;

/// The three-byte marker, still readable. See [`SchemaMarker::decode`].
const MARKER_V1: u8 = 1;

impl ReadView for FjallStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.partition.get(key)?.map(|slice| slice.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.partition.prefix(prefix) {
            let (key, value) = pair?;
            out.push((key.to_vec(), value.to_vec()));
        }
        self.scanned.fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(out)
    }
}

/// A Fjall read snapshot: every read sees the partition as of the sequence
/// number current when it was taken, whatever lands afterwards.
pub struct FjallCheckpoint(fjall::Snapshot);

impl ReadView for FjallCheckpoint {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .0
            .get(key)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .map(|value| value.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.0.prefix(prefix) {
            let (key, value) = pair.map_err(|error| StoreError::Backend(error.to_string()))?;
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }
}

impl Store for FjallStore {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.partition.insert(key, value)?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), StoreError> {
        self.partition.remove(key)?;
        Ok(())
    }

    fn snapshot(&self) -> Option<Box<dyn ReadView + '_>> {
        // `Keyspace::instant`, not `Partition::snapshot`. The latter reads the
        // raw sequence counter, which a batch commit bumps *before* inserting
        // its items; a snapshot taken in that window sees the batch half
        // applied. `instant` returns `visible_seqno`, which is published only
        // once every item has landed, so a batch is all-or-nothing to a reader
        // exactly as it is to a crash.
        Some(Box::new(FjallCheckpoint(
            self.partition.snapshot_at(self.keyspace.instant()),
        )))
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
        self.commit_entry_with(entry, log, &[], durability)
    }

    /// As [`Self::commit_entry`], with extra records in the *same* batch.
    ///
    /// The caller's records land if and only if the entry does. That matters
    /// for anything derived from the entry existing -- the global stream index
    /// above all: a stream id written after the commit is lost to a crash in
    /// between, and the event becomes one `/sync` will never deliver, while a
    /// stream id written before points at an entry that may never arrive.
    /// Neither ordering is safe, so there is no ordering, only one batch.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the batch cannot be committed, or
    /// [`StoreError::StateNotResident`] if the entry's state has been evicted.
    pub fn commit_entry_with(
        &self,
        entry: &spindle_core::LogEntry,
        log: &RoomLog,
        extra: &[Record],
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
            .and_then(|candidate| log.state_after(candidate.li));
        let state = log
            .state_after(entry.li)
            .ok_or(StoreError::StateNotResident { li: entry.li.get() })?;

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
        for (address, node) in state.delta_nodes(previous) {
            writes.push((
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            ));
        }
        writes.extend_from_slice(extra);

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
        let mut previous: Option<&spindle_core::StateSnapshot> = None;
        for entry in log.entries() {
            let key = room_li(Keyspace::Log, &self.room_id, entry.li);
            self.store
                .put(&key, &EntryRecord::from_entry(entry).encode())?;
            // Persist the state trie here too, so both write paths restore
            // identically. A seeding path that produced a differently
            // restorable room would be a trap for whoever hit it first.
            // This is why `save` is a seeding path and not a serving one: it
            // needs every entry's materialized state at once, and a room long
            // enough to have evicted some cannot supply that. Such a room is
            // already persisted incrementally by `commit_entry`, which needs
            // only the entry in hand.
            let state = log
                .state_after(entry.li)
                .ok_or(StoreError::StateNotResident { li: entry.li.get() })?;
            for (address, node) in state.delta_nodes(previous) {
                self.store.put(
                    &content_addressed(Keyspace::StateNode, address.as_bytes()),
                    &node,
                )?;
            }
            previous = Some(state);
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
        // Read metadata and log through one frozen view. Rebuilding a room
        // takes two reads, and a commit landing between them yields a room
        // whose counters and log disagree -- metadata trailing the log being
        // the dangerous direction, because the next append then reissues an
        // index the log already holds. Backends without snapshot isolation fall
        // back to live reads and are correspondingly unsafe to read under
        // concurrent writes; that is a property of the backend, not something
        // this function can paper over.
        let snapshot = self.store.snapshot();
        let view: &dyn ReadView = snapshot.as_deref().unwrap_or(self.store);

        let Some(raw_meta) = view.get(&room_prefix(Keyspace::RoomMeta, &self.room_id))? else {
            return Ok(None);
        };
        let meta = RoomRecord::decode(&raw_meta)?;

        // The scan is already in `li` order because the key encoding is
        // order-preserving across the sign boundary; backfilled history sorts
        // first without any sorting here.
        let prefix = room_prefix(Keyspace::Log, &self.room_id);
        let mut entries = Vec::new();
        for (_, value) in view.scan_prefix(&prefix)? {
            let record = EntryRecord::decode(&value)?;
            entries.push(RestoredEntry {
                li: record.linear_index(),
                event_id: record.event(),
                prev_events: record.parents(),
                depth: record.depth,
                state_key: record.slot(),
                expected_state_root: record.state_root,
                chain: record.chain,
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
    /// The store was written under a schema this binary does not speak.
    ///
    /// Refusing is the point: the alternative is scanning a prefix that holds
    /// nothing and reporting an empty store.
    UnsupportedSchema {
        found: SchemaMarker,
        supported: SchemaMarker,
    },
    /// The entry's materialized state is no longer held in memory.
    ///
    /// Only [`RoomStore::save`] can raise this, and only for a room long enough
    /// to have evicted state it is being asked to rewrite wholesale. Use
    /// [`RoomStore::commit_entry`] per append instead, which is the serving
    /// path and never needs more than the entry it is writing.
    StateNotResident { li: i64 },
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
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "store was written at key schema {}/record {}, this binary speaks {}/{}",
                found.key_schema, found.record, supported.key_schema, supported.record
            ),
            Self::StateNotResident { li } => write!(
                formatter,
                "state for li {li} has been evicted; use commit_entry per append"
            ),
        }
    }
}

impl std::error::Error for StoreError {}
