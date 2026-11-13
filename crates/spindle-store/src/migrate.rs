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
//!
//! **Every step has a name, and the store remembers which ran (#661).** The
//! marker says where a store is; it cannot say how it got there, and with
//! more than one step a store two versions behind and a store whose first
//! step was interrupted look alike. So each step carries a stable
//! [`Migration::id`], a finished step is written to a ledger in the same
//! commit that moves the marker to its `to`, and `--list` shows the ledger
//! beside the table.
//!
//! **A long step says where it is, and resumes from there (#656).** A step
//! that rewrites every room runs for hours on a large store, and with no
//! output a healthy run and a hung one look the same. A step reports phases
//! with a done count, and a total where it knows one, through [`StepRun`];
//! the updates are rate-limited so a step can count every row without
//! flooding a log. A checkpoint the step writes is the same record a
//! restarted run resumes from, so an interruption costs the work since the
//! last checkpoint, not the whole step.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::codec::{CodecError, EntryRecord, SidelinedRecord};
use crate::{Durability, FjallStore, ReadView, Record, SchemaMarker, Store, StoreError};
use spindle_core::keys::{
    Keyspace, content_addressed, keyspace_prefix, migration_applied, migration_ledger_prefix,
    migration_progress, room_from_prefixed, room_prefix, store_marker,
};
use spindle_core::{
    MigrationStateVerifier, StateKeyTable, StateRoot, StateSnapshot, rehydrate_v2_incremental,
    rehydrate_v2_with_addresses,
};

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
///
/// A step must be safe to run again from the start and from any checkpoint
/// it wrote: a crash can land anywhere, and the rerun cannot know how much
/// of the work after the last checkpoint reached the disk.
pub struct Migration {
    /// The step's name in the ledger and in a progress record. Never renamed
    /// or reused: a store records the id it ran, and a different step under
    /// the same id would read as already applied.
    pub id: &'static str,
    pub from: SchemaMarker,
    pub to: SchemaMarker,
    /// One line, printed to the operator before it runs.
    pub summary: &'static str,
    pub reversible: Reversible,
    /// Returns how many rows it rewrote, for the report.
    pub apply: fn(&mut StepRun<'_>) -> Result<u64, StoreError>,
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Migration")
            .field("id", &self.id)
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
///
/// A new step needs a row in the step table of `docs/lifecycle.md`;
/// `tests/schema_migration.rs` fails until every id here is listed there.
pub static MIGRATIONS: &[Migration] = &[Migration {
    id: "intern-state-keys",
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
    /// The table itself is unusable: an id that is empty, repeated, or not
    /// plain enough to print and store. Refused before anything is written,
    /// because the ledger tells steps apart by id alone.
    Table(String),
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
            Self::Table(why) => write!(formatter, "migration table: {why}"),
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

impl From<CodecError> for MigrateError {
    fn from(error: CodecError) -> Self {
        Self::Store(format!("{error:?}"))
    }
}

/// Refuse a table the ledger could not keep apart.
///
/// Ids are lowercase ASCII letters, digits and `-`: they are printed to the
/// operator, written as key bytes, and quoted in release notes, and none of
/// those wants whitespace or case to tell two steps apart.
///
/// # Errors
///
/// Returns [`MigrateError::Table`] naming the first bad id.
pub fn validate(table: &[Migration]) -> Result<(), MigrateError> {
    let mut seen = HashSet::new();
    for step in table {
        let plain = !step.id.is_empty()
            && step
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !plain {
            return Err(MigrateError::Table(format!(
                "step id {:?} is not lowercase letters, digits and '-'",
                step.id
            )));
        }
        if !seen.insert(step.id) {
            return Err(MigrateError::Table(format!(
                "step id {:?} is used twice",
                step.id
            )));
        }
        if step.from == step.to {
            return Err(MigrateError::Table(format!(
                "step {:?} does not move the marker",
                step.id
            )));
        }
    }
    Ok(())
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

/// What one step of a migration did, or would do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub step: &'static Migration,
    /// Rows the step rewrote; zero on a dry run.
    pub rows: u64,
}

impl PartialEq for Migration {
    /// Steps are told apart by id, which [`validate`] keeps unique.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Migration {}

/// What a migration did, or would do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub from: SchemaMarker,
    pub to: SchemaMarker,
    pub steps: Vec<StepReport>,
    /// The checkpoint the first step resumed from, or on a dry run would
    /// resume from: a previous run of it was interrupted.
    pub resumed: Option<Checkpoint>,
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
            .any(|report| report.step.reversible == Reversible::No)
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
        Some(raw) => Ok(SchemaMarker::decode(&raw)?),
        None => Ok(SchemaMarker::current()),
    }
}

/// A ledger row: a step this store finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Applied {
    pub id: String,
    pub from: SchemaMarker,
    pub to: SchemaMarker,
    pub rows: u64,
    /// When the step finished, in seconds since the Unix epoch.
    pub at: u64,
}

/// The version of a ledger row's own encoding.
const LEDGER_VERSION: u8 = 1;

impl Applied {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![LEDGER_VERSION];
        frame(&mut out, &self.from.encode());
        frame(&mut out, &self.to.encode());
        out.extend_from_slice(&self.rows.to_be_bytes());
        out.extend_from_slice(&self.at.to_be_bytes());
        out
    }

    fn decode(id: String, bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes, LEDGER_VERSION)?;
        let from = SchemaMarker::decode(reader.framed()?)?;
        let to = SchemaMarker::decode(reader.framed()?)?;
        Ok(Self {
            id,
            from,
            to,
            rows: reader.u64()?,
            at: reader.u64()?,
        })
    }
}

/// Every step this store has finished, in id order.
///
/// # Errors
///
/// Returns [`MigrateError`] if a ledger row cannot be read or decoded.
pub fn ledger(store: &FjallStore) -> Result<Vec<Applied>, MigrateError> {
    let prefix = migration_ledger_prefix();
    let mut applied = Vec::new();
    for (key, value) in ReadView::scan_prefix(store, &prefix)? {
        let id = key.get(prefix.len()..).unwrap_or_default().to_vec();
        let id = String::from_utf8(id).map_err(|_| CodecError::Malformed(0))?;
        applied.push(Applied::decode(id, &value)?);
    }
    Ok(applied)
}

/// Where an interrupted step stopped: the progress record a step's last
/// [`StepRun::checkpoint`] wrote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub step: String,
    pub phase: String,
    pub unit: String,
    pub done: u64,
    pub total: Option<u64>,
    /// The step's own resume position. Opaque here: only the step that
    /// wrote it knows what it means.
    pub cursor: Vec<u8>,
    /// When it was written, in seconds since the Unix epoch.
    pub at: u64,
}

/// The version of a progress record's own encoding.
const CHECKPOINT_VERSION: u8 = 1;

impl Checkpoint {
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![CHECKPOINT_VERSION];
        frame(&mut out, self.step.as_bytes());
        frame(&mut out, self.phase.as_bytes());
        frame(&mut out, self.unit.as_bytes());
        out.extend_from_slice(&self.done.to_be_bytes());
        match self.total {
            Some(total) => {
                out.push(1);
                out.extend_from_slice(&total.to_be_bytes());
            }
            None => out.push(0),
        }
        frame(&mut out, &self.cursor);
        out.extend_from_slice(&self.at.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes, CHECKPOINT_VERSION)?;
        let step = reader.text()?;
        let phase = reader.text()?;
        let unit = reader.text()?;
        let done = reader.u64()?;
        let total = match reader.byte()? {
            0 => None,
            1 => Some(reader.u64()?),
            other => return Err(CodecError::Malformed(other)),
        };
        Ok(Self {
            step,
            phase,
            unit,
            done,
            total,
            cursor: reader.framed()?.to_vec(),
            at: reader.u64()?,
        })
    }
}

/// The progress record of an interrupted step, if there is one.
///
/// # Errors
///
/// Returns [`MigrateError`] if the record cannot be read or decoded.
pub fn checkpoint(store: &FjallStore) -> Result<Option<Checkpoint>, MigrateError> {
    match ReadView::get(store, &migration_progress())? {
        Some(raw) => Ok(Some(Checkpoint::decode(&raw)?)),
        None => Ok(None),
    }
}

fn frame(out: &mut Vec<u8>, bytes: &[u8]) {
    // Every framed field is an id, a short name, a four-byte marker or a
    // step's cursor; none comes near 4 GiB.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A bounds-checked reader over a ledger or progress record.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], version: u8) -> Result<Self, CodecError> {
        match bytes.split_first() {
            Some((&found, rest)) if found == version => Ok(Self { bytes: rest }),
            Some((&found, _)) => Err(CodecError::UnsupportedVersion(found)),
            None => Err(CodecError::Truncated),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        if self.bytes.len() < len {
            return Err(CodecError::Truncated);
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        self.take(1)?.first().copied().ok_or(CodecError::Truncated)
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| CodecError::Truncated)?,
        ))
    }

    fn framed(&mut self) -> Result<&'a [u8], CodecError> {
        let len = self.take(4)?;
        let len = u32::from_be_bytes(len.try_into().map_err(|_| CodecError::Truncated)?);
        self.take(usize::try_from(len).map_err(|_| CodecError::Truncated)?)
    }

    fn text(&mut self) -> Result<String, CodecError> {
        String::from_utf8(self.framed()?.to_vec()).map_err(|_| CodecError::Malformed(0))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Where a step's phase is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Started,
    Running,
    Finished,
}

/// One progress update from a running step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Progress {
    /// The step's [`Migration::id`].
    pub step: &'static str,
    pub phase: &'static str,
    /// What `done` and `total` count: rooms, records, nodes.
    pub unit: &'static str,
    pub done: u64,
    /// `None` when the step cannot know how much work there is. Then there
    /// is no percentage and no ETA, only a count that keeps moving.
    pub total: Option<u64>,
    /// The part of `done` an earlier, interrupted run did. Not this run's
    /// work, so not part of its rate.
    pub resumed: u64,
    /// Since this run started the phase.
    pub elapsed: Duration,
    pub stage: Stage,
}

/// How long a phase runs before its rate is reported. A rate from the first
/// few milliseconds measures caches and start-up, not the store, and an ETA
/// built on it is a number made up.
pub const RATE_WINDOW: Duration = Duration::from_secs(1);

impl Progress {
    /// Percent of `total` done, when there is a total.
    #[must_use]
    pub fn percent(&self) -> Option<f64> {
        let total = self.total?;
        if total == 0 {
            return Some(100.0);
        }
        Some((as_f64(self.done) * 100.0 / as_f64(total)).min(100.0))
    }

    /// Units per second this run has done in this phase, once the phase has
    /// run long enough to measure one.
    #[must_use]
    pub fn rate(&self) -> Option<f64> {
        let worked = self.done.saturating_sub(self.resumed);
        if self.elapsed < RATE_WINDOW || worked == 0 {
            return None;
        }
        Some(as_f64(worked) / self.elapsed.as_secs_f64())
    }

    /// Time left at the measured rate. Only with a total and a rate, and
    /// only while the phase is running.
    #[must_use]
    pub fn eta(&self) -> Option<Duration> {
        if self.stage == Stage::Finished {
            return None;
        }
        let left = self.total?.saturating_sub(self.done);
        let rate = self.rate()?;
        Some(Duration::from_secs_f64(as_f64(left) / rate))
    }
}

#[allow(clippy::cast_precision_loss)] // A count past 2^52 loses digits only in a display estimate.
fn as_f64(count: u64) -> f64 {
    count as f64
}

/// What `run` tells its caller while it works.
#[derive(Debug)]
pub enum Event<'a> {
    /// A step is about to run; `resumed` is the checkpoint it continues from.
    Started {
        step: &'static Migration,
        resumed: Option<&'a Checkpoint>,
    },
    Progress(&'a Progress),
    /// A step finished, and the ledger and marker now say so.
    Applied {
        step: &'static Migration,
        rows: u64,
        elapsed: Duration,
    },
}

/// How often a running phase reports by default. Often enough that a
/// stalled run is visible within seconds, rarely enough that an hour-long
/// step writes hundreds of lines, not millions.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// A running step's view of the store and of the operator.
///
/// The step names its phases and counts its work here; this decides when
/// the count is worth printing. Phase starts and ends always reach the
/// caller; updates in between are limited to one per interval, so a step
/// can call [`Self::advance`] per row.
pub struct StepRun<'a> {
    store: &'a FjallStore,
    step: &'static Migration,
    resume: Option<Checkpoint>,
    interval: Duration,
    events: &'a mut dyn FnMut(&Event<'_>),
    phase: Option<Phase>,
}

struct Phase {
    name: &'static str,
    unit: &'static str,
    total: Option<u64>,
    done: u64,
    resumed: u64,
    started: Instant,
    reported: Instant,
}

impl<'a> StepRun<'a> {
    /// The store being migrated.
    #[must_use]
    pub fn store(&self) -> &'a FjallStore {
        self.store
    }

    /// The checkpoint an earlier, interrupted run of this step wrote.
    #[must_use]
    pub fn resume(&self) -> Option<&Checkpoint> {
        self.resume.as_ref()
    }

    /// End the current phase and start `name`, counting `unit`. `resumed`
    /// is the work an earlier run did, taken from [`Self::resume`].
    pub fn phase(
        &mut self,
        name: &'static str,
        unit: &'static str,
        total: Option<u64>,
        resumed: u64,
    ) {
        self.end_phase();
        let now = Instant::now();
        self.phase = Some(Phase {
            name,
            unit,
            total,
            done: resumed,
            resumed,
            started: now,
            reported: now,
        });
        self.report(Stage::Started);
    }

    /// Count `count` more units of the current phase's work.
    pub fn advance(&mut self, count: u64) {
        let Some(phase) = self.phase.as_mut() else {
            return;
        };
        phase.done = phase.done.saturating_add(count);
        if phase.reported.elapsed() >= self.interval {
            phase.reported = Instant::now();
            self.report(Stage::Running);
        }
    }

    /// Record that everything up to `cursor` in the current phase is done
    /// and durable, so an interrupted run resumes after it.
    ///
    /// The step must have made that work durable first: a checkpoint ahead
    /// of its data would skip work on resume.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the record cannot be written.
    pub fn checkpoint(&mut self, cursor: &[u8]) -> Result<(), StoreError> {
        let (phase, unit, done, total) = self.phase.as_ref().map_or(("", "", 0, None), |phase| {
            (phase.name, phase.unit, phase.done, phase.total)
        });
        let record = Checkpoint {
            step: self.step.id.to_owned(),
            phase: phase.to_owned(),
            unit: unit.to_owned(),
            done,
            total,
            cursor: cursor.to_vec(),
            at: unix_now(),
        };
        Store::put(self.store, &migration_progress(), &record.encode())
    }

    fn end_phase(&mut self) {
        if self.phase.is_some() {
            self.report(Stage::Finished);
        }
        self.phase = None;
    }

    fn report(&mut self, stage: Stage) {
        let Some(phase) = self.phase.as_ref() else {
            return;
        };
        let progress = Progress {
            step: self.step.id,
            phase: phase.name,
            unit: phase.unit,
            done: phase.done,
            total: phase.total,
            resumed: phase.resumed,
            elapsed: phase.started.elapsed(),
            stage,
        };
        (self.events)(&Event::Progress(&progress));
    }
}

/// Plan the migration for `store`, and run it unless `dry_run`, telling
/// nobody how it goes. See [`run_reporting`].
///
/// # Errors
///
/// Returns [`MigrateError`] if no path exists or a step fails.
pub fn run(
    store: &FjallStore,
    table: &'static [Migration],
    dry_run: bool,
) -> Result<Report, MigrateError> {
    run_reporting(store, table, dry_run, PROGRESS_INTERVAL, &mut |_| {})
}

/// Plan the migration for `store`, and run it unless `dry_run`, passing
/// step starts, progress at most once per `interval`, and step ends to
/// `events`.
///
/// The marker moves at the end of each step, in one commit with that step's
/// ledger row, and never during one. A step that fails leaves the marker at
/// its `from`, so the store still describes itself as the version it can
/// still be read as — a half-migrated store that *claimed* to be further
/// along would be refused by nothing and misread by everything. Its
/// checkpoint stays, and the next run resumes from it.
///
/// A checkpoint is honoured only by the step that wrote it, and only when
/// that step is the next one the marker calls for. A record naming another
/// step is from a different binary's table or from a step whose ledger
/// commit landed and whose cleanup did not; resuming another step's cursor
/// would skip work, so it is dropped and the step starts from the beginning.
///
/// # Errors
///
/// Returns [`MigrateError`] if the table is malformed, no path exists, or a
/// step fails.
pub fn run_reporting(
    store: &FjallStore,
    table: &'static [Migration],
    dry_run: bool,
    interval: Duration,
    events: &mut dyn FnMut(&Event<'_>),
) -> Result<Report, MigrateError> {
    validate(table)?;
    let found = marker_of(store)?;
    let current = SchemaMarker::current();
    let plan = plan(found, current, table)?;
    let saved = checkpoint(store)?;
    let resumed = saved
        .clone()
        .filter(|saved| plan.first().is_some_and(|step| step.id == saved.step));
    let mut report = Report {
        from: found,
        to: current,
        steps: Vec::with_capacity(plan.len()),
        resumed: resumed.clone(),
        unchanged: dry_run || plan.is_empty(),
    };
    if dry_run {
        report.steps = plan
            .into_iter()
            .map(|step| StepReport { step, rows: 0 })
            .collect();
        return Ok(report);
    }
    if saved.is_some() && resumed.is_none() {
        Store::delete(store, &migration_progress())?;
    }
    let mut resume = resumed;
    for step in plan {
        let started = Instant::now();
        events(&Event::Started {
            step,
            resumed: resume.as_ref(),
        });
        let mut running = StepRun {
            store,
            step,
            resume: resume.take(),
            interval,
            events: &mut *events,
            phase: None,
        };
        let rows = (step.apply)(&mut running)?;
        running.end_phase();
        let applied = Applied {
            id: step.id.to_owned(),
            from: step.from,
            to: step.to,
            rows,
            at: unix_now(),
        };
        Store::commit(
            store,
            &[
                (store_marker(), step.to.encode()),
                (migration_applied(step.id), applied.encode()),
            ],
            Durability::Strict,
        )?;
        Store::delete(store, &migration_progress())?;
        events(&Event::Applied {
            step,
            rows,
            elapsed: started.elapsed(),
        });
        report.steps.push(StepReport { step, rows });
    }
    Ok(report)
}

/// Where one step of the table stands on a particular store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    /// The ledger records it.
    Applied(Applied),
    /// The next `migrate` runs it.
    Pending,
    /// The next `migrate` runs it, resuming from this checkpoint.
    Interrupted(Checkpoint),
    /// Neither: the store was created after this step's `to`, or its marker
    /// is on no path this table walks.
    NotNeeded,
}

/// Where a store stands against a table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listing {
    /// Every step of the table, in table order.
    pub steps: Vec<(&'static Migration, Status)>,
    /// Ledger rows that name no step in the table: steps a newer binary ran.
    pub foreign: Vec<Applied>,
}

/// Every step of `table` with its status on `store`.
///
/// # Errors
///
/// Returns [`MigrateError`] if the marker, the ledger or the progress record
/// cannot be read.
pub fn list(store: &FjallStore, table: &'static [Migration]) -> Result<Listing, MigrateError> {
    let mut applied = ledger(store)?;
    // No path is a status, not an error here: listing is how an operator
    // finds out what an unmigratable store has been through.
    let pending = plan(marker_of(store)?, SchemaMarker::current(), table).unwrap_or_default();
    let saved = checkpoint(store)?;
    let steps = table
        .iter()
        .map(|step| {
            let status = if let Some(index) = applied.iter().position(|row| row.id == step.id) {
                Status::Applied(applied.remove(index))
            } else if !pending.contains(&step) {
                Status::NotNeeded
            } else {
                // Only the next step resumes; `run_reporting` drops a record
                // naming any other, so listing it would promise a resume
                // that will not happen.
                match &saved {
                    Some(saved) if saved.step == step.id && pending.first() == Some(&step) => {
                        Status::Interrupted(saved.clone())
                    }
                    _ => Status::Pending,
                }
            };
            (step, status)
        })
        .collect();
    Ok(Listing {
        steps,
        foreign: applied,
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

/// The phases of [`migrate_intern_state_keys`], by the names its progress
/// and checkpoint carry.
const COUNT_PHASE: &str = "count";
const CONVERT_PHASE: &str = "convert";
const DELETE_PHASE: &str = "delete-v2-nodes";

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
/// A room's last commit is synced before its checkpoint names it, so a
/// resumed run skips only rooms whose every record is version 3. The
/// version-2 nodes of the rooms it skips are not collected again: they are
/// orphans, the same as after a rerun from scratch, and `spindle gc`
/// deletes them.
///
/// Irreversible by declaration ([`Reversible::No`]): the old binary cannot
/// read interned nodes, and the old rows are deleted. The operator is told
/// before anything runs, and the backup they took beforehand is the way back.
fn migrate_intern_state_keys(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    let store = run.store();
    let table = ReadView::key_table(store);
    let rooms: Vec<String> = ReadView::scan_prefix(store, &keyspace_prefix(Keyspace::RoomMeta))?
        .into_iter()
        .filter_map(|(key, _)| room_from_prefixed(&key).map(str::to_owned))
        .collect();
    // The cursor is the last room an earlier run finished. Rooms come back in
    // key order, and nothing writes while the store is offline, so the same
    // list puts the same rooms before it. A cursor naming no room here is
    // not this store's; starting over is the safe reading of it.
    let (skip, resumed) = run
        .resume()
        .filter(|saved| saved.phase == CONVERT_PHASE)
        .and_then(|saved| {
            rooms
                .iter()
                .position(|room| room.as_bytes() == saved.cursor.as_slice())
                .map(|index| (index + 1, saved.done))
        })
        .unwrap_or((0, 0));
    let remaining = rooms.get(skip..).unwrap_or_default();

    // Counting first is a read of the rows the conversion reads anyway, and
    // it is what turns "still running" into a percentage and an ETA.
    run.phase(COUNT_PHASE, "records", None, 0);
    let mut total = resumed;
    for room_id in remaining {
        for space in ROOT_HOLDERS {
            ReadView::visit_prefix(store, &room_prefix(space, room_id), &mut |_, _| {
                total += 1;
                run.advance(1);
                Ok(())
            })?;
        }
    }

    run.phase(CONVERT_PHASE, "records", Some(total), resumed);
    let mut rewritten = 0_u64;
    let mut old_nodes = HashSet::new();
    for room_id in remaining {
        // Keep room-local root and verified-node caches bounded by the
        // largest room. Old node deletion waits until every room converts,
        // because content addresses can be shared across rooms.
        let mut migration = RoomMigration::new(Arc::clone(&table));
        rewritten += migrate_room(
            store,
            room_id,
            &table,
            &mut migration,
            &mut old_nodes,
            &mut || run.advance(1),
        )?;
        run.checkpoint(room_id.as_bytes())?;
    }

    // Every record now names version-3 nodes. Version-2 tags use a
    // separate address domain, so these cannot be new nodes.
    run.phase(DELETE_PHASE, "nodes", Some(old_nodes.len() as u64), 0);
    for address in old_nodes {
        Store::delete(store, &content_addressed(Keyspace::StateNode, &address))?;
        rewritten += 1;
        run.advance(1);
    }
    Ok(rewritten)
}

struct RoomMigration {
    converted: HashMap<[u8; 32], [u8; 32]>,
    written: HashSet<[u8; 32]>,
    verified: MigrationStateVerifier,
    previous_v2: Option<(StateRoot, StateSnapshot)>,
}

impl RoomMigration {
    fn new(table: Arc<dyn StateKeyTable>) -> Self {
        Self {
            converted: HashMap::new(),
            written: HashSet::new(),
            verified: MigrationStateVerifier::new(table, 1_000_000),
            previous_v2: None,
        }
    }
}

/// The room records that hold a state root: the rows `migrate_room` rewrites,
/// and so the unit the step's progress counts.
const ROOT_HOLDERS: [Keyspace; 3] = [
    Keyspace::Log,
    Keyspace::Sidelined,
    Keyspace::FederationGapEvent,
];

#[allow(clippy::too_many_lines)] // Three record keyspaces share one bounded commit buffer.
fn migrate_room(
    store: &FjallStore,
    room_id: &str,
    table: &Arc<dyn StateKeyTable>,
    migration: &mut RoomMigration,
    old_nodes: &mut HashSet<[u8; 32]>,
    progress: &mut dyn FnMut(),
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
    ReadView::visit_prefix(
        store,
        &room_prefix(Keyspace::Log, room_id),
        &mut |key, value| {
            let mut record = EntryRecord::decode(value)?;
            let root = convert_root(
                record.state_root,
                table,
                &mut load,
                migration,
                &mut puts,
                old_nodes,
            )?;
            if root != record.state_root {
                record.state_root = root;
                puts.push((key.to_vec(), record.encode()));
            }
            count += commit_chunk(store, &mut puts)?;
            progress();
            Ok(())
        },
    )?;
    ReadView::visit_prefix(
        store,
        &room_prefix(Keyspace::Sidelined, room_id),
        &mut |key, value| {
            let mut record = SidelinedRecord::decode(value)?;
            let root = convert_root(
                record.state_root,
                table,
                &mut load,
                migration,
                &mut puts,
                old_nodes,
            )?;
            if root != record.state_root {
                record.state_root = root;
                puts.push((key.to_vec(), record.encode()));
            }
            count += commit_chunk(store, &mut puts)?;
            progress();
            Ok(())
        },
    )?;
    // Gap history keeps roots outside the linear log: 32 address bytes
    // followed by the event id. These must move before old nodes go away.
    ReadView::visit_prefix(
        store,
        &room_prefix(Keyspace::FederationGapEvent, room_id),
        &mut |key, value| {
            let mut value = value.to_vec();
            let old: [u8; 32] = value
                .get(..32)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(crate::codec::CodecError::Truncated)?;
            let root = convert_root(old, table, &mut load, migration, &mut puts, old_nodes)?;
            if root != old {
                value
                    .get_mut(..32)
                    .ok_or(crate::codec::CodecError::Truncated)?
                    .copy_from_slice(&root);
                puts.push((key.to_vec(), value));
            }
            count += commit_chunk(store, &mut puts)?;
            progress();
            Ok(())
        },
    )?;
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
    migration: &mut RoomMigration,
    puts: &mut Vec<Record>,
    old_nodes: &mut HashSet<[u8; 32]>,
) -> Result<[u8; 32], StoreError> {
    let corrupt = |error: spindle_core::RehydrateError| {
        StoreError::Backend(format!("version-2 state trie is unreadable: {error:?}"))
    };
    if let Some(root) = migration.converted.get(&old).copied() {
        if migration
            .previous_v2
            .as_ref()
            .map(|(old, _)| *old.as_bytes())
            != Some(old)
        {
            // A mapped root may still be staged. Keep only a baseline that
            // actually matches this record, without reading staged nodes.
            migration.previous_v2 = None;
        }
        return Ok(root);
    }
    let old_root = StateRoot::from_bytes(old);
    if migration.verified.verify(old_root, load).is_ok() {
        migration.converted.insert(old, old);
        migration.previous_v2 = None;
        return Ok(old);
    }
    let (state, old_addresses) = if let Some((previous_root, previous)) = &migration.previous_v2 {
        rehydrate_v2_incremental(old_root, *previous_root, previous, load).map_err(corrupt)?
    } else {
        rehydrate_v2_with_addresses(old_root, load, table).map_err(corrupt)?
    };
    let previous = migration.previous_v2.as_ref().map(|(_, state)| state);
    for (address, node) in state.delta_nodes(previous) {
        if migration.written.insert(*address.as_bytes()) {
            puts.push((
                content_addressed(Keyspace::StateNode, address.as_bytes()),
                node,
            ));
        }
    }
    old_nodes.extend(old_addresses.into_iter().map(|root| *root.as_bytes()));
    let root = *state.root().as_bytes();
    migration.previous_v2 = Some((old_root, state));
    migration.converted.insert(old, root);
    Ok(root)
}
