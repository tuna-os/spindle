//! Durable storage for the Spindle linear log.
//!
//! Kept in its own crate so `spindle-core` stays free of a storage dependency,
//! per ADR 0002: the linear log and the state trie are the parts that are
//! actually ours, and they remain independently testable and benchmarkable.

pub mod backup;
pub mod codec;
pub mod migrate;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

// fjall 3 renamed the two levels: what was a `Keyspace` (the whole store) is
// now a `Database`, and what was a `PartitionHandle` (one namespace inside
// it) is now a `Keyspace`. The aliases below keep this file's own vocabulary
// -- `db` for the store, `partition` for the namespace -- so the rename does
// not read as a change of design.
use fjall::{
    Config, Database as FjallDatabase, Keyspace as FjallPartition,
    KeyspaceCreateOptions as PartitionCreateOptions, PersistMode, Readable,
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

    /// Entries whose key starts with `prefix` *and* sorts at or after
    /// `start`, in key order.
    ///
    /// [`Self::scan_prefix`] with a filter would read the same rows and throw
    /// most of them away; this reads only the tail. That is the whole point
    /// wherever a key ends in a position the caller already holds -- a client
    /// asking what happened since its sync token wants the rows after the
    /// token, and the number of rows before it is the size of the history it
    /// is not asking about.
    ///
    /// `start` need not itself be a stored key, and need not share `prefix`:
    /// a start below the prefix yields the whole prefix, and one above it
    /// yields nothing.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the scan fails.
    fn scan_from(&self, prefix: &[u8], start: &[u8]) -> Result<Vec<Record>, StoreError>;
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

    /// Move buffered writes into the backend's on-disk segments, if it has
    /// that distinction.
    ///
    /// Not [`Self::flush`], which makes writes *durable* by persisting the
    /// journal. This makes them *resident in the segment format* — a
    /// different file layout, written on the backend's own schedule and not
    /// otherwise reachable from here.
    ///
    /// It exists for compatibility fixtures. `tests/backend_compatibility.rs`
    /// checks that a store one `fjall` version wrote opens under the next,
    /// and could only cover the journal, because at fixture size `fjall` had
    /// never rotated a memtable and nothing here could make it. That left the
    /// segment format — the half a major version of an LSM engine is most
    /// likely to change — untested, which is exactly the gap that made the
    /// `fjall` 3 upgrade unanswerable in #193.
    ///
    /// Default no-op: a backend without segments has nothing to do, and
    /// saying so is better than pretending the concept is universal.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the flush fails.
    fn flush_to_segments(&self) -> Result<(), StoreError> {
        Ok(())
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

    /// [`Store::commit`]'s first half: journal `writes` atomically, without
    /// making them durable.
    ///
    /// Pairs with [`Store::sync`], and exists so a caller holding a lock can
    /// keep the *ordering* inside it and leave the *fsync* outside. Writing
    /// under a lock is microseconds of memory work; syncing under it is a
    /// disk barrier, and a lock that spans one serializes every writer behind
    /// the slowest thing a machine does.
    ///
    /// A caller that does not pair this with a sync has written to the page
    /// cache and told nobody, so a crash loses it silently. Every use should
    /// read as one unit with the sync that follows.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the write fails.
    fn commit_deferred(&self, writes: &[Record]) -> Result<(), StoreError>;

    /// [`Store::commit`]'s second half: make everything journalled so far
    /// durable, to the standard `durability` asks for.
    ///
    /// Cumulative rather than per-write, which is what makes it safe to call
    /// after releasing the lock that ordered the writes: a later writer's sync
    /// also covers an earlier writer's bytes, so durability cannot invert even
    /// though the syncs race.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the sync fails.
    fn sync(&self, durability: Durability) -> Result<(), StoreError>;

    /// # Errors
    ///
    /// Returns a backend error if the flush fails.
    fn flush(&self) -> Result<(), StoreError>;
}

/// A Fjall-backed store.
/// Coalesces [`Durability::Group`]'s fsyncs across concurrent commits.
///
/// SPEC §8.3 describes the batch as "flushed on whichever comes first of `N`
/// pending entries or `T` microseconds". This is the same coalescing with
/// **neither constant**, and the absence is the design rather than a
/// simplification of it: a timer buys throughput under load by adding latency
/// when there is none to trade, so a server that is quiet pays `T` for
/// nothing. Here the first writer to arrive syncs immediately and everyone
/// who piles up behind it rides that sync — so the window is exactly as long
/// as one fsync takes, which is the shortest it could correctly be, and there
/// is no number to tune per deployment.
///
/// The correctness argument is a ticket:
///
/// - A writer's bytes reach the journal *before* it asks for a sync, so any
///   sync that **starts** after that point covers it. `next` names that sync.
/// - The leader seals the ticket it is about to satisfy and bumps `next`, so
///   a writer arriving mid-sync claims the *following* one — never the sync
///   already in flight, which may have started before its bytes landed.
/// - `done` only moves on success. A failed sync therefore wakes its
///   followers without satisfying them, and each retries as its own leader:
///   a broken disk fsyncs per writer and reports the error to every one of
///   them, rather than one failure being silently ridden as a success.
#[derive(Debug, Default)]
struct GroupCommit {
    state: Mutex<GroupState>,
    woken: Condvar,
}

/// `next` starts at 1 and `done` at 0, which is the encoding of "no sync has
/// happened yet". Starting both at 0 makes the *first* commit after startup
/// find `done >= ticket` and return durable without ever having fsynced —
/// the one commit whose loss a reader would have no way to detect, since
/// there is no later entry to expose the gap.
#[derive(Debug)]
struct GroupState {
    /// The sync that will cover a writer arriving now.
    next: u64,
    /// The highest sync that has completed successfully.
    done: u64,
    /// Whether a sync is in flight.
    running: bool,
    /// Syncs actually performed.
    led: u64,
    /// Commits that returned on a sync somebody else performed.
    joined: u64,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            next: 1,
            done: 0,
            running: false,
            led: 0,
            joined: 0,
        }
    }
}

impl GroupCommit {
    /// Return once a sync covering the caller's already-journalled bytes has
    /// completed — leading that sync if nobody else is.
    fn sync(&self, db: &FjallDatabase, mode: PersistMode) -> Result<(), StoreError> {
        self.sync_with(|| db.persist(mode).map_err(StoreError::from))
    }

    /// [`Self::sync`] with the fsync itself supplied.
    ///
    /// Split out so the ticket protocol can be tested against a `persist`
    /// that blocks on command. The property that matters — a writer arriving
    /// mid-sync does not ride that sync — is unobservable against a real
    /// fsync, which is over before a test can arrange to be inside it.
    fn sync_with(
        &self,
        persist: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let ticket = state.next;
        let mut persist = Some(persist);
        loop {
            if state.done >= ticket {
                return Ok(());
            }
            if state.running {
                // Counted here, under the lock and before parking, so a
                // reader that observes the count knows the waiter is
                // committed to waiting rather than about to lead.
                state.joined += 1;
                state = self
                    .woken
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            // Nobody is syncing, so lead one. Everything buffered up to this
            // instant rides along, which is where the coalescing comes from:
            // the followers do no I/O at all.
            let sealed = state.next;
            state.running = true;
            state.next = sealed + 1;
            state.led += 1;
            drop(state);

            let result = persist
                .take()
                .expect("the leader runs the persist exactly once")();

            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.running = false;
            if result.is_ok() {
                state.done = state.done.max(sealed);
            }
            self.woken.notify_all();
            return result;
        }
    }

    /// `(syncs performed, commits that rode somebody else's)`.
    ///
    /// The second over the first is the coalescing factor, and it is the
    /// number that says whether group commit is doing anything on a given
    /// workload: it is 0 at concurrency 1, by design and not by failure.
    fn counters(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        (state.led, state.joined)
    }
}

pub struct FjallStore {
    db: FjallDatabase,
    partition: FjallPartition,
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
    written: AtomicU64,
    /// Batches journalled but not necessarily synced, ever, since open.
    ///
    /// Exists so a caller can ask "did anything get written while I held
    /// that lock?" by comparing two readings. It is deliberately *global*
    /// rather than per-caller: a reading that changed because some other
    /// thread wrote causes one extra sync, and a reading that changed
    /// because *this* thread wrote can never be missed. The failure mode is
    /// a wasted fsync, never a lost one, which is the only direction worth
    /// being wrong in.
    journalled: AtomicU64,
    /// Shared by every writer, which is what lets their fsyncs become one.
    group: GroupCommit,
}

impl FjallStore {
    /// `(fsyncs performed, commits that rode somebody else's fsync)` in
    /// `Durability::Group`.
    ///
    /// The second over the first is the coalescing factor. It is 0 whenever
    /// commits never overlap — which is a fact about the caller's
    /// concurrency, not about this store, and the only way to tell a server
    /// that cannot coalesce from a workload that has nothing to coalesce.
    #[must_use]
    pub fn group_commits(&self) -> (u64, u64) {
        self.group.counters()
    }

    /// Batches journalled since this store was opened.
    ///
    /// Monotonic. Two readings that differ mean a write landed in between,
    /// which is how an append path knows a sync is owed -- see the field.
    #[must_use]
    pub fn journalled(&self) -> u64 {
        self.journalled.load(Ordering::Relaxed)
    }

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

    /// Rows written since this store was opened, counting a delete as a
    /// write because that is what it is on an LSM tree: a tombstone is a
    /// row, and it is merged and compacted like any other.
    ///
    /// The counterpart to [`Self::reads`], and for the same reason -- a
    /// claim about how much a path writes is testable by subtracting two
    /// readings, where a claim about how long it takes is not (#33).
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Open or create a store at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the keyspace cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self::open_unchecked(path)?;
        store.check_schema()?;
        Ok(store)
    }

    /// Open without checking the schema marker.
    ///
    /// For `spindle migrate` and nothing else. Migration has to read a store
    /// this binary has just refused — that is the situation it exists for —
    /// so it cannot go through the door that does the refusing.
    ///
    /// Every other caller wants [`Self::open`]. Reading a store at an
    /// unknown schema through the ordinary keyspaces is the silent misread
    /// the marker was added to prevent (see [`Self::check_schema`]): a
    /// prefix scan under the wrong version finds nothing and reports an
    /// empty store.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the keyspace cannot be opened.
    pub fn open_unchecked(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        // `Database::open`, not `create_or_recover`: the latter is
        // `#[doc(hidden)]` and documented as fjall's own no-background-threads
        // variant for testing. It happens to be what `open` calls today, and
        // depending on that would make a patch release of the engine a
        // silent change to how this server runs.
        let db = FjallDatabase::open(Config::new(path.as_ref())).map_err(|error| {
            // fjall 3 refuses a store written by fjall 2 outright: the on-disk
            // format changed and there is no in-process upgrade. Its own error
            // says `InvalidVersion(Some(V2))`, which tells an operator that
            // something is wrong and nothing about what to do -- and the thing
            // to do exists, so it is said here.
            if matches!(
                error,
                fjall::Error::InvalidVersion(Some(fjall::FormatVersion::V2))
            ) {
                return StoreError::Backend(format!(
                    "this data directory was written by Spindle's previous \
                     storage engine (fjall 2) and cannot be opened by this \
                     build: the on-disk format changed in fjall 3 and there is \
                     no automatic upgrade. Migrate it with \
                     https://github.com/fjall-rs/migrate-v2-v3 first, or point \
                     [storage] path at an empty directory to start fresh. \
                     ({error})"
                ));
            }
            // fjall 3 also takes an exclusive lock on the directory, which
            // fjall 2 did not. `Locked` therefore has a meaning an operator
            // can act on -- something else already has this store open --
            // and saying so beats the bare word.
            if matches!(error, fjall::Error::Locked) {
                return StoreError::Backend(format!(
                    "this data directory is already open by another process: \
                     Spindle's storage engine allows one writer at a time, so \
                     a command that opens the store directly (backup, restore, \
                     verify-media) cannot run against a directory a server is \
                     serving from. Stop the server first. ({error})"
                ));
            }
            StoreError::from(error)
        })?;
        let partition = db.keyspace("spindle", PartitionCreateOptions::default)?;
        Ok(Self {
            reads: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            written: AtomicU64::new(0),
            journalled: AtomicU64::new(0),
            group: GroupCommit::default(),
            db,
            partition,
        })
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
            let (key, value) = pair.into_inner()?;
            out.push((key.to_vec(), value.to_vec()));
        }
        self.scanned.fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(out)
    }

    fn scan_from(&self, prefix: &[u8], start: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.partition.range(start.to_vec()..) {
            let (key, value) = pair.into_inner()?;
            // The range runs to the end of the keyspace, so leaving the
            // prefix is the terminator. Breaking rather than filtering is
            // what makes this cost the tail and not the partition.
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key.to_vec(), value.to_vec()));
        }
        self.scanned.fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(out)
    }
}

/// A Fjall read snapshot: every read sees the partition as of the sequence
/// number current when it was taken, whatever lands afterwards.
///
/// It carries the partition as well as the snapshot because in fjall 3 a
/// snapshot spans the whole database and each read names the namespace it is
/// reading -- where in fjall 2 the snapshot was taken *from* the partition
/// and remembered it.
pub struct FjallCheckpoint(fjall::Snapshot, FjallPartition);

impl ReadView for FjallCheckpoint {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .0
            .get(&self.1, key)
            .map_err(|error| StoreError::Backend(error.to_string()))?
            .map(|value| value.to_vec()))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.0.prefix(&self.1, prefix) {
            let (key, value) = pair
                .into_inner()
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }

    fn scan_from(&self, prefix: &[u8], start: &[u8]) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::new();
        for pair in self.0.range(&self.1, start.to_vec()..) {
            let (key, value) = pair
                .into_inner()
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }
}

impl Store for FjallStore {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.partition.insert(key, value)?;
        self.written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn flush_to_segments(&self) -> Result<(), StoreError> {
        // `_and_wait`: the point is that the segment exists when this
        // returns. The non-waiting variant queues the rotation, which for a
        // fixture generator means writing the directory before the segment
        // it is supposed to contain.
        self.partition.rotate_memtable_and_wait()?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), StoreError> {
        self.partition.remove(key)?;
        self.written.fetch_add(1, Ordering::Relaxed);
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
            self.db.snapshot(),
            self.partition.clone(),
        )))
    }

    fn commit(&self, writes: &[Record], durability: Durability) -> Result<(), StoreError> {
        self.commit_deferred(writes)?;
        self.sync(durability)
    }

    fn commit_deferred(&self, writes: &[Record]) -> Result<(), StoreError> {
        let mut batch = self.db.batch();
        for (key, value) in writes {
            batch.insert(&self.partition, key.as_slice(), value.as_slice());
        }
        // Always `Buffer`: the bytes reach the journal and nothing is synced.
        // Which sync they get -- if any -- is `sync`'s decision.
        batch.durability(Some(PersistMode::Buffer)).commit()?;
        // Rows, not batches: a batch of a hundred is a hundred rows to
        // merge and compact, and counting it as one would let a path claim
        // it writes less by bundling the same work.
        self.written
            .fetch_add(writes.len() as u64, Ordering::Relaxed);
        // After the write, so an observer that sees the count move knows the
        // bytes are already journalled and a sync will cover them.
        self.journalled.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn sync(&self, durability: Durability) -> Result<(), StoreError> {
        // Every arm takes its syscall from `persist_mode`, so that mapping
        // stays the one place the modes are defined and
        // `durability_modes_map_to_distinct_syscalls` keeps pinning
        // something real.
        let mode = durability.persist_mode();
        match durability {
            // `Buffer` is the absence of a barrier, and the bytes are already
            // in the journal. A promise not to sync now, kept.
            Durability::Relaxed => Ok(()),
            // Not coalesced: `strict` exists for deployments that want the
            // barrier they asked for, not the cheapest correct one.
            Durability::Strict => {
                self.db.persist(mode)?;
                Ok(())
            }
            // Take the next sync going -- ours to lead if nobody else is
            // already running one.
            Durability::Group => self.group.sync(&self.db, mode),
        }
    }

    fn flush(&self) -> Result<(), StoreError> {
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }
}

#[cfg(test)]
mod group_commit_tests {
    use std::sync::Arc;
    use std::sync::mpsc;

    use super::{GroupCommit, StoreError};

    /// At concurrency 1 there is nothing to coalesce, so the writer syncs on
    /// arrival. This is the property a timer-based window would destroy: it
    /// would make a quiet server wait `T` for company that never comes.
    #[test]
    fn a_lone_writer_syncs_immediately() {
        let group = GroupCommit::default();
        group.sync_with(|| Ok(())).unwrap();
        assert_eq!(group.counters(), (1, 0), "one sync led, nobody rode it");
    }

    /// Sequential writers each get their own sync: the second writer's bytes
    /// reached the journal after the first sync finished, so that sync cannot
    /// have covered them.
    #[test]
    fn sequential_writers_do_not_share_a_sync() {
        let group = GroupCommit::default();
        group.sync_with(|| Ok(())).unwrap();
        group.sync_with(|| Ok(())).unwrap();
        assert_eq!(group.counters(), (2, 0));
    }

    /// The win: writers that pile up during one sync are satisfied by a
    /// single sync between them, not one each.
    ///
    /// They cannot ride the sync already running -- it may have started
    /// before their bytes reached the journal -- so they share the *next*
    /// ticket, one of them leads it, and the rest return on that. Five
    /// writers therefore cost one fsync, and the ratio only improves as more
    /// arrive within a sync's duration. That is the whole mechanism: without
    /// it these six commits are six fsyncs.
    #[test]
    fn writers_piling_up_during_a_sync_share_one() {
        let group = Arc::new(GroupCommit::default());
        let (entered, inside) = mpsc::channel();
        let (release, held) = mpsc::channel::<()>();

        let leader = {
            let group = Arc::clone(&group);
            std::thread::spawn(move || {
                group
                    .sync_with(|| {
                        entered.send(()).unwrap();
                        held.recv().unwrap();
                        Ok(())
                    })
                    .unwrap();
            })
        };
        // The leader is now inside the fsync with `running` set.
        inside.recv().unwrap();

        let waiting: Vec<_> = (0..5)
            .map(|_| {
                let group = Arc::clone(&group);
                std::thread::spawn(move || group.sync_with(|| Ok(())).unwrap())
            })
            .collect();

        // `joined` is incremented under the lock immediately before parking,
        // and the waiter holds the lock until `wait` releases it -- so
        // observing 5 proves all five are parked rather than about to lead.
        while group.counters().1 < 5 {
            std::thread::yield_now();
        }
        release.send(()).unwrap();

        leader.join().unwrap();
        for writer in waiting {
            writer.join().unwrap();
        }
        assert_eq!(
            group.counters().0,
            2,
            "six commits cost two fsyncs: the leader's, and one shared by \
             the five that arrived while it ran"
        );
    }

    /// The safety property, and the reason `next` is bumped when the leader
    /// seals rather than when it finishes: a writer whose bytes landed
    /// *during* a sync must not be told that sync made them durable.
    ///
    /// Unobservable against a real fsync, which is over before a test can
    /// arrange to be inside it -- which is why `sync_with` exists.
    #[test]
    fn a_writer_arriving_mid_sync_waits_for_the_next_one() {
        let group = Arc::new(GroupCommit::default());
        let (entered, inside) = mpsc::channel();
        let (release, held) = mpsc::channel::<()>();

        let leader = {
            let group = Arc::clone(&group);
            std::thread::spawn(move || {
                group
                    .sync_with(|| {
                        entered.send(()).unwrap();
                        held.recv().unwrap();
                        Ok(())
                    })
                    .unwrap();
            })
        };
        inside.recv().unwrap();

        // A writer arriving now claims the *following* sync, so once the
        // leader's completes it still has to lead one of its own.
        let latecomer = {
            let group = Arc::clone(&group);
            std::thread::spawn(move || group.sync_with(|| Ok(())).unwrap())
        };
        while group.counters().1 < 1 {
            std::thread::yield_now();
        }
        release.send(()).unwrap();

        leader.join().unwrap();
        latecomer.join().unwrap();
        assert_eq!(
            group.counters().0,
            2,
            "the latecomer led its own sync rather than riding one that \
             started before its bytes were in the journal"
        );
    }

    /// A failed sync satisfies nobody. The next writer performs a real one
    /// rather than reading a success off the failure.
    #[test]
    fn a_failed_sync_does_not_count_as_done() {
        let group = GroupCommit::default();
        let failed = group.sync_with(|| Err(StoreError::Backend("disk".to_owned())));
        assert!(failed.is_err());

        let mut ran = false;
        group
            .sync_with(|| {
                ran = true;
                Ok(())
            })
            .unwrap();
        assert!(ran, "the next writer must fsync rather than inherit an Ok");
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

    /// [`Self::commit_entry_with`] without the fsync.
    ///
    /// The entry and its records are journalled atomically, exactly as the
    /// durable form does; only the sync is left to the caller, which must
    /// follow with [`Store::sync`] before telling anyone the write happened.
    /// Splitting them lets the append path hold its lock across the ordering
    /// and release it before the disk barrier -- see [`Store::commit_deferred`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the batch cannot be journalled, or
    /// [`StoreError::StateNotResident`] if the entry's state has been evicted.
    pub fn journal_entry_with(
        &self,
        entry: &spindle_core::LogEntry,
        log: &RoomLog,
        extra: &[Record],
    ) -> Result<(), StoreError> {
        self.write_entry(entry, log, extra, None)
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
        self.write_entry(entry, log, extra, Some(durability))
    }

    /// The batch both forms build. `durability` of `None` journals without
    /// syncing.
    fn write_entry(
        &self,
        entry: &spindle_core::LogEntry,
        log: &RoomLog,
        extra: &[Record],
        durability: Option<Durability>,
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

        match durability {
            Some(durability) => self.store.commit(&writes, durability),
            None => self.store.commit_deferred(&writes),
        }
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
            // All three versions, not two. A `content_digest`-only
            // mismatch printed through the old two-field message showed the
            // operator two identical-looking version pairs and no reason for
            // the refusal -- and that field is the one whose mismatch is
            // hardest to diagnose from anywhere else (#78).
            //
            // The remedy is named here rather than left to the reader: this
            // string is the entire interface between a store that will not
            // open and the person who has to decide what to do about it.
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "store was written at key schema {}/record {}/digest {}, \
                 this binary speaks {}/{}/{}; run `spindle migrate <config>` \
                 to move the store forward, after taking a backup",
                found.key_schema,
                found.record,
                found.content_digest,
                supported.key_schema,
                supported.record,
                supported.content_digest,
            ),
            Self::StateNotResident { li } => write!(
                formatter,
                "state for li {li} has been evicted; use commit_entry per append"
            ),
        }
    }
}

impl std::error::Error for StoreError {}
