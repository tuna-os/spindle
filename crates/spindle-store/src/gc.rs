//! Mark-and-sweep for the state trie (#742).
//!
//! [`Keyspace::StateNode`] rows are content-addressed and shared: a state
//! change path-copies O(log n) nodes and every unchanged subtree keeps its
//! address, so one node can sit under thousands of roots in many rooms. No
//! row records who refers to it, which is what makes a write cheap and a
//! delete impossible to decide locally. Nothing ever deleted one, so every
//! node that stopped being referenced -- the intermediate states a gap fill
//! walks through, the rows an interrupted import leaves, the trie of a room
//! whose records were removed -- stayed on disk for good.
//!
//! The collector decides globally instead. **Mark**: every row that names a
//! state root (a log entry, a sidelined event, a backfilled gap event, a
//! room's recorded fork resolution) has its trie walked, and every node
//! reached is live. A visited set of
//! addresses makes a shared subtree cost one read however many roots reach
//! it -- without it the walk is the sum of every state's size, which for a
//! room of a million events with an unchanged ten-thousand-member subtree is
//! ten billion reads. **Sweep**: every stored node the mark did not reach is
//! deleted.
//!
//! **Offline only.** A node's address is its content, so a writer that
//! re-derives a node the sweep has judged dead re-puts the same key, and
//! nothing distinguishes that put from the row the sweep is about to delete.
//! A sweep racing an append can therefore delete a node the append has just
//! made live again, and the room's next restore fails on a missing node.
//! Marking under a snapshot does not close that: the race is on a key the
//! snapshot already held. `spindle gc` opens the store directly, and the
//! engine's directory lock is what guarantees no server is writing.
//!
//! **Refuses rather than guesses.** A missing or corrupt reachable node, an
//! unreadable root-holding record (an undecodable `CurrentState` cache row
//! is the exception: it is dropped), or a row in a root-holding keyspace this
//! collector does not read stops the run before anything is deleted. Each
//! of those means the mark is not the whole truth, and a sweep from a partial
//! mark deletes live state.

use std::collections::HashSet;

use spindle_core::StateRoot;
use spindle_core::keys::{KEY_SCHEMA_VERSION, Keyspace, content_addressed, keyspace_prefix};

use crate::codec::{CurrentStateRecord, EntryRecord, SidelinedRecord};
use crate::{ReadView, Store, StoreError};

/// How many dead nodes the sweep holds before it deletes them.
///
/// The sweep used to collect every dead address first, which for a store
/// that is mostly garbage is as large as the mark set. The scan runs under a
/// snapshot and the mark is complete, so a delete cannot change what the scan
/// sees: it deletes as it goes, one batch at a time.
const SWEEP_BATCH: usize = 4096;

/// What one collection found, and what it removed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GcReport {
    /// Root-holding rows read: log entries, sidelined events, gap events,
    /// recorded fork resolutions.
    pub holders: u64,
    /// Distinct nodes reachable from those roots.
    pub marked: u64,
    /// Value bytes of the reachable nodes.
    pub marked_bytes: u64,
    /// Node rows loaded during the mark. Equal to [`Self::marked`]: a
    /// shared subtree is read once, not once per root that reaches it.
    pub node_reads: u64,
    /// Unreachable nodes: deleted, or on a dry run, the ones that would be.
    pub swept: u64,
    /// Key and value bytes of the unreachable nodes.
    pub swept_bytes: u64,
    /// The most dead addresses the sweep held at once: at most
    /// [`SWEEP_BATCH`], however many nodes were dead.
    pub peak_pending: u64,
    /// Batched deletes issued (or, on a dry run, that would be).
    pub delete_batches: u64,
    /// `CurrentState` rows that did not decode, deleted (or, on a dry run,
    /// that would be). The row is a cache, and a room load already ignores
    /// one it cannot read, so it is not a reason to refuse.
    pub dropped_cache_rows: u64,
}

/// Why a collection stopped before sweeping.
#[derive(Debug)]
pub enum GcError {
    /// The backend failed.
    Store(StoreError),
    /// A root-holding record could not be decoded, so the root it names is
    /// unknown.
    UnreadableHolder { keyspace: Keyspace, key: Vec<u8> },
    /// A reachable node is not in the store.
    MissingNode(StateRoot),
    /// A reachable node is malformed or does not hash to its address.
    CorruptNode {
        node: StateRoot,
        why: spindle_core::RehydrateError,
    },
    /// The store holds rows in a keyspace declared to hold state roots that
    /// this collector does not know how to read.
    UnknownRootHolder(Keyspace),
}

impl std::fmt::Display for GcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::UnreadableHolder { keyspace, key } => write!(
                formatter,
                "the {keyspace:?} record {} cannot be read, so the state it names \
                 is unknown; nothing was deleted",
                hex(key)
            ),
            Self::MissingNode(node) => write!(
                formatter,
                "reachable state node {} is missing: the store is already damaged, \
                 and nothing was deleted",
                hex(node.as_bytes())
            ),
            Self::CorruptNode { node, why } => write!(
                formatter,
                "reachable state node {} is unreadable ({why:?}); nothing was deleted",
                hex(node.as_bytes())
            ),
            Self::UnknownRootHolder(keyspace) => write!(
                formatter,
                "the store holds {keyspace:?} rows, which name state roots this \
                 binary does not read; nothing was deleted"
            ),
        }
    }
}

impl std::error::Error for GcError {}

impl From<StoreError> for GcError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Mark every node reachable from a stored root, then delete the rest.
///
/// With `dry_run` nothing is deleted and the report says what would be.
/// Running it twice is a no-op the second time: everything left is marked.
///
/// Offline only (see the module docs): the caller must hold the store
/// exclusively. The mark reads through a snapshot when the backend has one,
/// so roots and nodes are of one moment even so.
///
/// # Errors
///
/// [`GcError`] when anything the mark depends on cannot be read; the store
/// is untouched in that case.
pub fn collect_state_nodes<S: Store>(store: &S, dry_run: bool) -> Result<GcReport, GcError> {
    let snapshot = store.snapshot();
    let view: &dyn ReadView = snapshot.as_deref().unwrap_or(store);

    // A keyspace the enum declares as `(room_id, li) -> state root` that no
    // writer uses today. Rows there would name roots this mark never sees.
    let declared = keyspace_prefix(Keyspace::StateRoot);
    let past = [KEY_SCHEMA_VERSION, Keyspace::StateRoot as u8 + 1];
    if view.last_before(&declared, &past)?.is_some() {
        return Err(GcError::UnknownRootHolder(Keyspace::StateRoot));
    }

    let mut marker = Marker {
        view,
        empty: spindle_core::StateSnapshot::new(view.key_table()).root(),
        marked: HashSet::new(),
        stack: Vec::new(),
        report: GcReport::default(),
        dropped: Vec::new(),
    };
    marker.holders(Keyspace::Log, Unreadable::Refuse, |value| {
        EntryRecord::decode(value)
            .ok()
            .map(|record| record.state_root)
    })?;
    marker.holders(Keyspace::Sidelined, Unreadable::Refuse, |value| {
        SidelinedRecord::decode(value)
            .ok()
            .map(|record| record.state_root)
    })?;
    // A gap event's row is the root of the state after it, then its ID
    // (`rooms::gaps`, and the migration that rewrites these in place).
    marker.holders(Keyspace::FederationGapEvent, Unreadable::Refuse, |value| {
        value.get(..32).and_then(|root| root.try_into().ok())
    })?;
    // A cache, but one whose nodes a reopened room reads: sweeping them
    // would turn the next restart's cheap load back into a resolution. A row
    // that does not decode names no nodes and is dropped, as `RoomStore`
    // ignores it at load.
    marker.holders(Keyspace::CurrentState, Unreadable::Drop, |value| {
        CurrentStateRecord::decode(value)
            .ok()
            .map(|record| record.root)
    })?;
    let Marker {
        marked,
        mut report,
        dropped,
        ..
    } = marker;
    report.marked = marked.len() as u64;

    let prefix = keyspace_prefix(Keyspace::StateNode);
    let mut sweep = Sweep {
        store,
        dry_run,
        pending: Vec::new(),
    };
    let mut failure = None;
    view.visit_prefix(&prefix, &mut |key, value| {
        // A key of any other shape is not a node this collector wrote or
        // can judge, so it is left alone rather than counted dead.
        let Some(address) = key
            .get(prefix.len()..)
            .and_then(|suffix| <[u8; 32]>::try_from(suffix).ok())
        else {
            return Ok(());
        };
        if marked.contains(&StateRoot::from_bytes(address)) {
            return Ok(());
        }
        report.swept += 1;
        report.swept_bytes += (key.len() + value.len()) as u64;
        sweep.add(key.to_vec(), &mut report).map_err(|error| {
            failure = Some(error);
            // Only stops the scan; `failure` is what is reported.
            StoreError::Backend("state collection stopped".to_owned())
        })
    })
    .map_err(|error| failure.take().unwrap_or(error))?;
    drop(snapshot);
    sweep.drain(&mut report)?;
    report.dropped_cache_rows = dropped.len() as u64;
    if !dry_run {
        for chunk in dropped.chunks(SWEEP_BATCH) {
            store.delete_batch(chunk)?;
        }
        store.flush()?;
    }
    Ok(report)
}

/// The sweep's buffer of dead keys, deleted a batch at a time.
struct Sweep<'a, S: Store> {
    store: &'a S,
    dry_run: bool,
    pending: Vec<Vec<u8>>,
}

impl<S: Store> Sweep<'_, S> {
    fn add(&mut self, key: Vec<u8>, report: &mut GcReport) -> Result<(), StoreError> {
        self.pending.push(key);
        report.peak_pending = report.peak_pending.max(self.pending.len() as u64);
        if self.pending.len() >= SWEEP_BATCH {
            self.drain(report)?;
        }
        Ok(())
    }

    fn drain(&mut self, report: &mut GcReport) -> Result<(), StoreError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        report.delete_batches += 1;
        let keys = std::mem::take(&mut self.pending);
        if self.dry_run {
            return Ok(());
        }
        self.store.delete_batch(&keys)
    }
}

/// What a root-holding row that does not decode means.
#[derive(Clone, Copy)]
enum Unreadable {
    /// The root is unknown, so the mark is incomplete: stop.
    Refuse,
    /// The row is a cache that names nothing: delete it.
    Drop,
}

/// The mark phase's state: what has been reached, and what is still to
/// visit.
struct Marker<'a> {
    view: &'a dyn ReadView,
    /// The empty state's root, which names no stored node.
    empty: StateRoot,
    marked: HashSet<StateRoot>,
    stack: Vec<StateRoot>,
    report: GcReport,
    /// Keys of the [`Unreadable::Drop`] rows that did not decode.
    dropped: Vec<Vec<u8>>,
}

impl Marker<'_> {
    /// Mark from the root every row of `keyspace` names.
    fn holders(
        &mut self,
        keyspace: Keyspace,
        unreadable: Unreadable,
        root_of: impl Fn(&[u8]) -> Option<[u8; 32]>,
    ) -> Result<(), GcError> {
        let view = self.view;
        let mut failure = None;
        let scanned = view.visit_prefix(&keyspace_prefix(keyspace), &mut |key, value| {
            let marked = match root_of(value) {
                Some(root) => self.mark(StateRoot::from_bytes(root)),
                None => match unreadable {
                    Unreadable::Refuse => Err(GcError::UnreadableHolder {
                        keyspace,
                        key: key.to_vec(),
                    }),
                    Unreadable::Drop => {
                        self.dropped.push(key.to_vec());
                        Ok(())
                    }
                },
            };
            marked.map_err(|error| {
                failure = Some(error);
                // Only stops the scan; `failure` is what is reported.
                StoreError::Backend("state collection stopped".to_owned())
            })
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(scanned?),
        }
    }

    /// Mark `root` and everything under it not already marked.
    ///
    /// Stopping at a marked node is the whole cost model: whatever reached
    /// it first has already marked everything below it.
    fn mark(&mut self, root: StateRoot) -> Result<(), GcError> {
        self.report.holders += 1;
        if root == self.empty {
            return Ok(());
        }
        self.stack.push(root);
        while let Some(address) = self.stack.pop() {
            if !self.marked.insert(address) {
                continue;
            }
            let bytes = self
                .view
                .get(&content_addressed(Keyspace::StateNode, address.as_bytes()))?
                .ok_or(GcError::MissingNode(address))?;
            self.report.node_reads += 1;
            self.report.marked_bytes += bytes.len() as u64;
            spindle_core::stored_node_children(&address, &bytes, &mut self.stack)
                .map_err(|why| GcError::CorruptNode { node: address, why })?;
        }
        Ok(())
    }
}
