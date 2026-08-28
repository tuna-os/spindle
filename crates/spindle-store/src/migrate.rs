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

use crate::{FjallStore, ReadView, SchemaMarker, Store, StoreError};
use spindle_core::keys::store_marker;

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
/// **Empty, and that is the honest state of things.** No schema change has
/// yet needed a data rewrite. The nearest candidate was #78, which widened
/// the marker from three bytes to four when `content_digest` was added —
/// but the three-byte form decodes to the *same* [`SchemaMarker`], so a
/// store carrying it opens today with nothing to do. Registering it would
/// have been a step from a version to itself: ceremony that runs, reports
/// success, and changes nothing.
///
/// What this module is for is the next change, not that one. The machinery
/// is proven by `tests/schema_migration.rs`, which drives `plan` and `run`
/// with synthetic tables — every property that matters (chaining, the
/// no-path refusal, dry runs writing nothing, the marker landing only after
/// every step succeeded) is a property of the machinery rather than of any
/// particular step, so a fixture table tests them exactly as well as a real
/// one would, and does it before the first real one is written under
/// whatever pressure produced it.
pub static MIGRATIONS: &[Migration] = &[];

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
