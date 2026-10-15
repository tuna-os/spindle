//! Moving a store from the schema it was written under to the one this
//! binary speaks (#20).
//!
//! [`crate::SchemaMarker`] already turns a mismatch into a refusal rather
//! than a silent misread — that is what it is for. But a refusal is only
//! half an answer. An operator holding a store one version behind needs a
//! way forward, and "restore last night's backup onto an older binary" is
//! not one: it discards a day.
//!
//! **Migration is a separate command, never something `open` does.** An
//! upgrade that rewrites the store the moment a new binary starts is the
//! shape of change an operator cannot back out of — by the time they know
//! it happened, the old bytes are gone. So `open` still refuses, naming
//! `spindle migrate`, and the rewrite happens when somebody asks for it,
//! having had the chance to take a backup first.
//!
//! **Rollback limits are per step, and declared.** A step that only adds
//! bytes an older binary ignores is reversible in practice; one that
//! rewrites what a key means is not, and no amount of care at the call site
//! changes that. [`Migration::reversible`] records which, `plan` reports it,
//! and the command prints it before doing anything — because the honest
//! statement is "this cannot be undone except from a backup", made *before*
//! the write rather than in a release note afterwards.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::codec::{EntryRecord, SidelinedRecord};
use crate::{Durability, FjallStore, ReadView, Record, SchemaMarker, Store, StoreError};
use spindle_core::keys::{
    Keyspace, content_addressed, keyspace_prefix, room_from_prefixed, room_prefix, store_marker,
};
use spindle_core::{StateKeyTable, StateRoot, StateSnapshot, rehydrate_v2, v2_node_addresses};

/// Whether a store that took this step can be handed back to the binary it
/// came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reversible {
    /// The older binary can still read the store afterwards. It is free to
    /// re-stamp the marker back on its own terms.
    Yes,
    /// It cannot. Going back means restoring the backup taken beforehand,
    /// and losing whatever was written since.
    No,
}

/// One step between two adjacent schema markers.
///
/// Adjacent on purpose: a table of pairwise "any version to any version"
/// jumps grows as the square of the versions and is tested as the diagonal.
/// Steps chain, so each one is written and tested once.
pub struct Migration {
    pub from: SchemaMarker,
    pub to: SchemaMarker,
    /// One line, printed to the operator before it runs.
    pub summary: &'static str,
    pub reversible: Reversible,
    /// Returns how many rows it rewrote, for the report.
    pub apply: fn(&FjallStore) -> Result<u64, StoreError>,
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Migration")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("summary", &self.summary)
            .field("reversible", &self.reversible)
            .finish_non_exhaustive()
    }
}

/// Every step this binary knows how to take.
///
/// The first real one is #79: version-2 state tries hold `(event_type,
/// state_key)` strings and version 3 holds interned ids, so every trie is
/// rewritten. The machinery below was proven with synthetic tables before
/// it ever carried real data (`tests/schema_migration.rs`); the step itself
/// is proven by `tests/state_migration.rs`, which migrates a version-2
/// store and reads it back with the ordinary open.
pub static MIGRATIONS: &[Migration] = &[Migration {
    from: SchemaMarker {
        key_schema: 1,
        record: 1,
        // This entire step is pinned: future key, record and digest
        // versions must not change the path from (1, 1, 2) to (1, 1, 3).
        content_digest: 2,
    },
    to: SchemaMarker {
        key_schema: 1,
        record: 1,
        content_digest: 3,
    },
    summary: "rewrite version-2 state tries with interned key ids (#79)",
    reversible: Reversible::No,
    apply: migrate_intern_state_keys,
}];

/// Why a store cannot be moved to the current schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrateError {
    /// No chain of steps reaches the current schema from what is on disk.
    ///
    /// Nearly always a binary older than the store, which is the one case
    /// no migration can fix: the steps that would be needed have not been
    /// written yet, because the version they lead to did not exist when
    /// this binary was built.
    NoPath {
        found: SchemaMarker,
        current: SchemaMarker,
    },
    Store(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPath { found, current } => write!(
                formatter,
                "no migration path from key schema {}/record {}/digest {} to {}/{}/{}; \
                 this binary is most likely older than the store",
                found.key_schema,
                found.record,
                found.content_digest,
                current.key_schema,
                current.record,
                current.content_digest,
            ),
            Self::Store(why) => write!(formatter, "store: {why}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<StoreError> for MigrateError {
    fn from(error: StoreError) -> Self {
        Self::Store(format!("{error:?}"))
    }
}

/// The steps that carry `found` to `current`, in the order to run them.
///
/// An empty plan means the store is already current — not an error, and
/// worth distinguishing from a plan that could not be built, because an
/// operator running `migrate` twice should be told "nothing to do" rather
/// than shown a failure.
///
/// # Errors
///
/// Returns [`MigrateError::NoPath`] when no chain of `table` reaches
/// `current`.
pub fn plan(
    found: SchemaMarker,
    current: SchemaMarker,
    table: &'static [Migration],
) -> Result<Vec<&'static Migration>, MigrateError> {
    let mut steps = Vec::new();
    let mut at = found;
    // Bounded by the table: every step must advance to a marker it has not
    // already visited, so a table with a cycle terminates here rather than
    // hanging, and reports NoPath.
    let mut seen = vec![found];
    while at != current {
        let Some(step) = table
            .iter()
            .find(|step| step.from == at && !seen.contains(&step.to))
        else {
            return Err(MigrateError::NoPath { found, current });
        };
        at = step.to;
        seen.push(at);
        steps.push(step);
    }
    Ok(steps)
}

/// What a migration did, or would do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub from: SchemaMarker,
    pub to: SchemaMarker,
    pub steps: Vec<(&'static str, Reversible, u64)>,
    /// True when nothing was written, either because the store was already
    /// current or because this was a dry run.
    pub unchanged: bool,
}

impl Report {
    /// Whether any step in the plan cannot be undone.
    #[must_use]
    pub fn irreversible(&self) -> bool {
        self.steps
            .iter()
            .any(|(_, reversible, _)| *reversible == Reversible::No)
    }
}

/// The marker a store carries, or the current one if it has none.
///
/// An unmarked store is a fresh one; `check_schema` stamps it on open, and
/// there is nothing to migrate.
///
/// # Errors
///
/// Returns [`MigrateError`] if the marker cannot be read or decoded.
pub fn marker_of(store: &FjallStore) -> Result<SchemaMarker, MigrateError> {
    match ReadView::get(store, &store_marker())? {
        Some(raw) => {
            SchemaMarker::decode(&raw).map_err(|error| MigrateError::Store(format!("{error:?}")))
        }
        None => Ok(SchemaMarker::current()),
    }
}

/// Plan the migration for `store`, and run it unless `dry_run`.
///
/// The marker is written last, and only after every step succeeded. A step
/// that fails leaves the marker where it was, so the store still describes
/// itself as the version it can still be read as — a half-migrated store
/// that *claimed* to be current would be refused by nothing and misread by
/// everything.
///
/// # Errors
///
/// Returns [`MigrateError`] if no path exists or a step fails.
pub fn run(
    store: &FjallStore,
    table: &'static [Migration],
    dry_run: bool,
) -> Result<Report, MigrateError> {
    let found = marker_of(store)?;
    let current = SchemaMarker::current();
    let plan = plan(found, current, table)?;

    let mut steps = Vec::with_capacity(plan.len());
    for step in &plan {
        let rows = if dry_run { 0 } else { (step.apply)(store)? };
        steps.push((step.summary, step.reversible, rows));
    }
    if !dry_run && !plan.is_empty() {
        Store::put(store, &store_marker(), &current.encode())?;
    }
    Ok(Report {
        from: found,
        to: current,
        steps,
        unchanged: dry_run || plan.is_empty(),
    })
}

/// How many record writes one commit carries.
///
/// A room's rewritten entries, new nodes and intern rows are staged in
/// memory per chunk, so an unbounded room would hold the whole migration
/// in RAM. Chunking bounds pending writes; conversion memoization is per room and
/// obsolete addresses are retained until all rooms have converted. A crash between
/// chunks reruns cleanly (see [`convert_root`]).
const MIGRATION_CHUNK: usize = 2_000;

/// Rewrite every version-2 state trie with interned key ids.
///
/// One room at a time: convert log, sidelined and gap-history records'
/// root, rewrite the records that named a changed root, write the new
/// nodes and intern rows beside them, and delete the old nodes only after
/// the records that referenced them are gone.
///
/// Crash order is the design: new rows land before rewritten records, and
/// deletions land after, so at every point the store is either a version-2
/// store with orphans or a version-3 store with orphans -- never a store
/// whose records name missing nodes. Rerunning converts what is left: a
/// root that already verifies under the new derivation is kept as is, and
/// record rewrites and node writes are idempotent puts.
///
/// Irreversible by declaration ([`Reversible::No`]): the old binary cannot
/// read interned nodes, and the old rows are deleted. The operator is told
/// before anything runs, and the backup they took beforehand is the way back.
fn migrate_intern_state_keys(store: &FjallStore) -> Result<u64, StoreError> {
    let table = ReadView::key_table(store);
    let rooms: Vec<String> = ReadView::scan_prefix(store, &keyspace_prefix(Keyspace::RoomMeta))?
        .into_iter()
        .filter_map(|(key, _)| room_from_prefixed(&key).map(str::to_owned))
        .collect();
    let mut rewritten = 0_u64;
    let mut old_nodes = Vec::new();
    for room_id in &rooms {
        // Per room, not per store: the converted-root memo and the
        // written-node set are bounded by the largest room, not by the
        // largest store. Old node deletion waits until every room has
        // converted, because content addresses can be shared across rooms.
        let mut converted: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        let mut written: HashSet<[u8; 32]> = HashSet::new();
        rewritten += migrate_room(
            store,
            room_id,
            &table,
            &mut converted,
            &mut written,
            &mut old_nodes,
        )?;
    }
    // Every record now names version-3 nodes. Version-2 tags use a
    // separate address domain, so these cannot be new nodes.
    old_nodes.sort_unstable();
    old_nodes.dedup();
    for address in old_nodes {
        Store::delete(store, &content_addressed(Keyspace::StateNode, &address))?;
        rewritten += 1;
    }
    Ok(rewritten)
}

fn migrate_room(
    store: &FjallStore,
    room_id: &str,
    table: &Arc<dyn StateKeyTable>,
    converted: &mut HashMap<[u8; 32], [u8; 32]>,
    written: &mut HashSet<[u8; 32]>,
    old_nodes: &mut Vec<[u8; 32]>,
) -> Result<u64, StoreError> {
    let mut load = |address: &StateRoot| {
        ReadView::get(
            store,
            &content_addressed(Keyspace::StateNode, address.as_bytes()),
        )
        .ok()
        .flatten()
    };
    let mut puts: Vec<Record> = Vec::new();
    let mut count = 0_u64;
    for (key, value) in ReadView::scan_prefix(store, &room_prefix(Keyspace::Log, room_id))? {
        let mut record = EntryRecord::decode(&value)?;
        let root = convert_root(
            record.state_root,
            table,
            &mut load,
            converted,
            written,
            &mut puts,
            old_nodes,
        )?;
        if root != record.state_root {
            record.state_root = root;
            puts.push((key, record.encode()));
        }
        count += commit_chunk(store, &mut puts)?;
    }
    for (key, value) in ReadView::scan_prefix(store, &room_prefix(Keyspace::Sidelined, room_id))? {
        let mut record = SidelinedRecord::decode(&value)?;
        let root = convert_root(
            record.state_root,
            table,
            &mut load,
            converted,
            written,
            &mut puts,
            old_nodes,
        )?;
        if root != record.state_root {
            record.state_root = root;
            puts.push((key, record.encode()));
        }
        count += commit_chunk(store, &mut puts)?;
    }
    // Gap history keeps roots outside the linear log: 32 address bytes
    // followed by the event id. These must move before old nodes go away.
    for (key, mut value) in
        ReadView::scan_prefix(store, &room_prefix(Keyspace::FederationGapEvent, room_id))?
    {
        let old: [u8; 32] = value
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(crate::codec::CodecError::Truncated)?;
        let root = convert_root(
            old, table, &mut load, converted, written, &mut puts, old_nodes,
        )?;
        if root != old {
            value
                .get_mut(..32)
                .ok_or(crate::codec::CodecError::Truncated)?
                .copy_from_slice(&root);
            puts.push((key, value));
        }
        count += commit_chunk(store, &mut puts)?;
    }
    // The tail below the chunk size: staged all along, committed here.
    if !puts.is_empty() {
        Store::commit_state_deferred(store, puts.as_slice(), &store.key_table())?;
        Store::sync(store, Durability::Strict)?;
        count += puts.len() as u64;
        puts.clear();
    }
    Ok(count)
}

fn commit_chunk(store: &FjallStore, puts: &mut Vec<Record>) -> Result<u64, StoreError> {
    if puts.len() < MIGRATION_CHUNK {
        return Ok(0);
    }
    Store::commit_state_deferred(store, puts.as_slice(), &store.key_table())?;
    Store::sync(store, Durability::Strict)?;
    let count = puts.len() as u64;
    puts.clear();
    Ok(count)
}

/// The version-3 root for a stored version-2 one, persisting what it adds.
///
/// A root that already verifies under the new derivation is returned
/// unchanged: that is a previous partial run's work, and keeping it makes
/// reruns converge instead of erroring. A version-2 root never verifies
/// that way -- its bytes were hashed under the old tags -- so the check
/// tells migrated from corrupt without a version flag on the row. Anything
/// that verifies under neither is corruption, and stops the migration
/// rather than being rewritten into something that looks migrated.
#[allow(clippy::too_many_arguments)]
fn convert_root(
    old: [u8; 32],
    table: &Arc<dyn StateKeyTable>,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    converted: &mut HashMap<[u8; 32], [u8; 32]>,
    written: &mut HashSet<[u8; 32]>,
    puts: &mut Vec<Record>,
    old_nodes: &mut Vec<[u8; 32]>,
) -> Result<[u8; 32], StoreError> {
    if let Some(root) = converted.get(&old) {
        return Ok(*root);
    }
    if StateSnapshot::rehydrate(StateRoot::from_bytes(old), load, Arc::clone(table)).is_ok() {
        converted.insert(old, old);
        return Ok(old);
    }
    let corrupt = |error: spindle_core::RehydrateError| {
        StoreError::Backend(format!("version-2 state trie is unreadable: {error:?}"))
    };
    let state = rehydrate_v2(StateRoot::from_bytes(old), load, table).map_err(corrupt)?;
    for (address, node) in state.delta_nodes(None) {
        if written.insert(*address.as_bytes()) {
            puts.push((
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            ));
        }
    }
    old_nodes.extend(
        v2_node_addresses(StateRoot::from_bytes(old), load)
            .map_err(corrupt)?
            .into_iter()
            .map(|root| *root.as_bytes()),
    );
    let root = *state.root().as_bytes();
    converted.insert(old, root);
    Ok(root)
}
