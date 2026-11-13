//! Moving a store between schema versions (#20), the ledger of steps a store
//! has taken (#661), and the progress a long step reports (#656).
//!
//! Every test here drives `plan` and `run` with a **synthetic** table. That
//! is not a weaker test than a real migration would be. The properties that
//! decide whether an operator loses a store are properties of the machinery,
//! not of any particular step: whether steps chain, whether an unreachable
//! version is refused rather than half-applied, whether a dry run writes,
//! whether an interrupted run resumes where it stopped, and above all
//! whether the marker can end up ahead of the data.
//!
//! The first real step (#79) is proven separately, in
//! `tests/state_migration.rs`, which migrates a version-2 store and reads
//! it back with the ordinary open.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use spindle_core::keys::store_marker;
use spindle_store::migrate::{
    Event, MIGRATIONS, MigrateError, Migration, Progress, Reversible, Stage, Status, StepRun,
    checkpoint, ledger, list, marker_of, plan, run, run_reporting, validate,
};
use spindle_store::{FjallStore, SchemaMarker, Store, StoreError};
use tempfile::TempDir;

/// A marker that differs from the current one only in `record`.
const fn at_record(record: u8) -> SchemaMarker {
    SchemaMarker {
        key_schema: 1,
        record,
        content_digest: spindle_core::CONTENT_DIGEST_VERSION,
    }
}

/// The current marker, as a constant the static tables can name.
const CURRENT: SchemaMarker = at_record(1);

fn count_rows(store: &FjallStore, key: &[u8]) -> Option<Vec<u8>> {
    spindle_store::ReadView::get(store, key).unwrap()
}

/// Marker keys the synthetic steps write, so a test can see what ran and in
/// what order without the steps needing to touch real records.
const TRACE: &[u8] = b"\x01\xfe\xfetrace";

fn append_trace(store: &FjallStore, label: u8) -> Result<u64, StoreError> {
    let mut trail = count_rows(store, TRACE).unwrap_or_default();
    trail.push(label);
    Store::put(store, TRACE, &trail)?;
    Ok(1)
}

fn step_a(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    append_trace(run.store(), b'a')
}

fn step_b(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    append_trace(run.store(), b'b')
}

fn always_fails(_: &mut StepRun<'_>) -> Result<u64, StoreError> {
    Err(StoreError::Backend("this step fails".to_owned()))
}

const fn step(
    id: &'static str,
    from: u8,
    to: u8,
    reversible: Reversible,
    apply: fn(&mut StepRun<'_>) -> Result<u64, StoreError>,
) -> Migration {
    Migration {
        id,
        from: at_record(from),
        to: at_record(to),
        summary: id,
        reversible,
        apply,
    }
}

/// Two steps that chain from `record: 8` up to the current marker, listed
/// backwards: `plan` follows `from`/`to`, not the table's order.
static CHAIN: &[Migration] = &[
    step("second", 9, 1, Reversible::No, step_b),
    step("first", 8, 9, Reversible::Yes, step_a),
];

/// One step whose body fails.
static FAILING: &[Migration] = &[step("fails", 8, 1, Reversible::No, always_fails)];

/// Open a store and stamp it as if written at `marker`.
fn store_at(marker: SchemaMarker) -> (TempDir, FjallStore) {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    Store::put(&store, &store_marker(), &marker.encode()).unwrap();
    (dir, store)
}

/// The real table takes a current store nowhere, and says so as success.
///
/// Running `migrate` on a store that needs nothing is the common case — an
/// operator who upgrades on a schedule runs it every time — so it has to be
/// a clean no-op rather than an error to be squinted at.
#[test]
fn a_current_store_needs_no_steps() {
    let (_dir, store) = store_at(SchemaMarker::current());
    let report = run(&store, MIGRATIONS, false).unwrap();
    assert!(report.steps.is_empty(), "{report:?}");
    assert!(report.unchanged);
    assert!(!report.irreversible());
}

/// Steps chain, in order, and each one runs exactly once.
#[test]
fn steps_chain_from_the_stored_marker_to_the_current_one() {
    let (_dir, store) = store_at(at_record(8));

    let report = run(&store, CHAIN, false).unwrap();

    assert_eq!(report.from, at_record(8));
    assert_eq!(report.to, SchemaMarker::current());
    let ids: Vec<&str> = report.steps.iter().map(|step| step.step.id).collect();
    assert_eq!(ids, ["first", "second"], "{report:?}");
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"ab");
    assert!(!report.unchanged);

    // The marker now says current, so the ordinary checked open accepts it.
    // This is the assertion that says the migration *finished*: a plan that
    // ran every step but left the marker behind would leave the store
    // refusing to open, which is a different kind of broken.
    assert_eq!(marker_of(&store).unwrap(), SchemaMarker::current());
}

/// A version nothing reaches is refused, not partly applied.
///
/// Nearly always a binary older than its store. Nothing can be done about
/// that at runtime — the steps have not been written — so the only correct
/// behaviour is to touch nothing and say why.
#[test]
fn a_version_with_no_path_is_refused_without_writing() {
    let (_dir, store) = store_at(at_record(200));

    let error = run(&store, CHAIN, false).unwrap_err();
    assert!(matches!(error, MigrateError::NoPath { .. }), "{error:?}");
    assert!(
        error.to_string().contains("older than the store"),
        "the refusal does not name the likely cause: {error}"
    );

    assert!(count_rows(&store, TRACE).is_none(), "a step ran anyway");
    assert_eq!(
        marker_of(&store).unwrap(),
        at_record(200),
        "the marker moved"
    );
    assert!(ledger(&store).unwrap().is_empty());
}

/// A dry run reports the whole plan and writes nothing.
#[test]
fn a_dry_run_writes_nothing() {
    let (_dir, store) = store_at(at_record(8));

    let report = run(&store, CHAIN, true).unwrap();

    assert_eq!(report.steps.len(), 2, "{report:?}");
    assert!(report.unchanged);
    assert!(
        report.irreversible(),
        "the plan contains an irreversible step and did not say so"
    );
    assert!(
        count_rows(&store, TRACE).is_none(),
        "a step ran on a dry run"
    );
    assert_eq!(
        marker_of(&store).unwrap(),
        at_record(8),
        "a dry run moved the marker"
    );
    assert!(
        ledger(&store).unwrap().is_empty(),
        "a dry run wrote a ledger"
    );
}

/// A failed step leaves the marker where it was.
///
/// The one that matters most. A store whose marker says "current" while its
/// data is half-rewritten is refused by nothing and misread by everything —
/// exactly the silent failure `SchemaMarker` exists to prevent, reintroduced
/// by the tool meant to move past it. So the marker moves only at the end
/// of a step that succeeded.
#[test]
fn a_failed_step_does_not_leave_the_marker_ahead_of_the_data() {
    let (dir, store) = store_at(at_record(8));

    let error = run(&store, FAILING, false).unwrap_err();
    assert!(matches!(error, MigrateError::Store(_)), "{error:?}");

    assert_eq!(
        marker_of(&store).unwrap(),
        at_record(8),
        "the marker moved past a step that failed"
    );
    assert!(
        ledger(&store).unwrap().is_empty(),
        "a failed step is in the ledger"
    );
    // And the store still opens as what it is, so the operator can retry
    // after fixing the cause rather than restoring a backup.
    assert!(
        FjallStore::open(dir.path()).is_err(),
        "the store opened as current after a failed migration"
    );
}

/// Reversibility is reported per step, and any irreversible step taints the
/// plan.
#[test]
fn one_irreversible_step_makes_the_whole_plan_irreversible() {
    let (_dir, store) = store_at(at_record(8));
    let report = run(&store, CHAIN, true).unwrap();

    let reversibility: Vec<Reversible> = report
        .steps
        .iter()
        .map(|step| step.step.reversible)
        .collect();
    assert_eq!(reversibility, vec![Reversible::Yes, Reversible::No]);
    assert!(report.irreversible());
}

/// An unmarked store is fresh, and fresh means current.
#[test]
fn an_unmarked_store_reads_as_current() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open_unchecked(dir.path()).unwrap();
    assert_eq!(marker_of(&store).unwrap(), SchemaMarker::current());
}

/// The refusal an operator actually sees names the command that fixes it.
///
/// This string is the entire interface between a store that will not open
/// and the person deciding what to do about it, so its content is a
/// contract rather than a nicety.
#[test]
fn the_schema_refusal_names_the_migrate_command() {
    let (dir, store) = store_at(at_record(8));
    drop(store);

    let Err(error) = FjallStore::open(dir.path()) else {
        panic!("a store at another schema opened without complaint");
    };
    let message = error.to_string();
    assert!(
        message.contains("spindle migrate"),
        "the refusal does not name the remedy: {message}"
    );
    assert!(
        message.contains("backup"),
        "the refusal does not mention taking a backup first: {message}"
    );
    // All three versions, so a digest-only mismatch is diagnosable rather
    // than printing two identical-looking pairs (#78).
    assert!(
        message.contains("digest"),
        "the refusal omits the content digest: {message}"
    );
}

/// A table whose steps loop terminates rather than hanging.
///
/// `plan` is public, and a table is written by hand, so a typo that points
/// a step back at a version already visited is a plausible mistake. The
/// wrong outcome is not "a bad plan" — it is a `migrate` that never returns,
/// on a store the operator is waiting to bring back up.
#[test]
fn a_table_that_loops_is_refused_rather_than_walked_forever() {
    static LOOP: &[Migration] = &[
        step("there", 8, 9, Reversible::Yes, step_a),
        step("and-back-again", 9, 8, Reversible::Yes, step_b),
    ];

    let error = plan(at_record(8), SchemaMarker::current(), LOOP).unwrap_err();
    assert!(matches!(error, MigrateError::NoPath { .. }), "{error:?}");
}

/// The table this binary ships is one the ledger can keep apart, every step
/// in it leads to the current schema, and every id is in the operator docs.
///
/// The docs check is the gate #661 asks for: a step a release adds is one
/// an operator has to plan around, so it cannot land without its row in the
/// step table of `docs/lifecycle.md`.
#[test]
fn the_shipped_table_is_valid_reaches_the_current_schema_and_is_documented() {
    validate(MIGRATIONS).unwrap();
    let docs = include_str!("../../../docs/lifecycle.md");
    for migration in MIGRATIONS {
        let path = plan(migration.from, SchemaMarker::current(), MIGRATIONS).unwrap();
        assert_eq!(path.first().map(|first| first.id), Some(migration.id));
        assert!(
            docs.contains(&format!("| `{}` |", migration.id)),
            "docs/lifecycle.md has no step-table row for `{}`",
            migration.id
        );
    }
}

/// An id the ledger could confuse is refused before any step runs.
#[test]
fn a_table_with_a_repeated_or_unprintable_id_is_refused_before_writing() {
    static REPEATED: &[Migration] = &[
        step("same", 8, 9, Reversible::Yes, step_a),
        step("same", 9, 1, Reversible::Yes, step_b),
    ];
    static UNPRINTABLE: &[Migration] = &[step("Not Plain", 8, 1, Reversible::Yes, step_a)];
    for table in [REPEATED, UNPRINTABLE] {
        let (_dir, store) = store_at(at_record(8));
        let error = run(&store, table, false).unwrap_err();
        assert!(matches!(error, MigrateError::Table(_)), "{error:?}");
        assert!(count_rows(&store, TRACE).is_none(), "a step ran anyway");
        assert_eq!(marker_of(&store).unwrap(), at_record(8));
    }
}

/// Set by a test to make `fails_once` fail the next time it runs. One flag
/// per test that uses it: tests in this file run in parallel.
static FAIL_SECOND_ONCE: AtomicBool = AtomicBool::new(false);

fn fails_once(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    if FAIL_SECOND_ONCE.swap(false, Ordering::SeqCst) {
        return Err(StoreError::Backend("interrupted".to_owned()));
    }
    append_trace(run.store(), b'b')
}

/// Each step that finishes is in the ledger and moves the marker, so a run
/// that dies in a later step does not repeat the earlier one.
#[test]
fn a_rerun_after_a_later_step_fails_skips_the_steps_already_applied() {
    static FLAKY: &[Migration] = &[
        step("first", 8, 9, Reversible::Yes, step_a),
        step("second", 9, 1, Reversible::No, fails_once),
    ];
    let (_dir, store) = store_at(at_record(8));
    FAIL_SECOND_ONCE.store(true, Ordering::SeqCst);

    assert!(run(&store, FLAKY, false).is_err());
    assert_eq!(
        marker_of(&store).unwrap(),
        at_record(9),
        "the finished step moved the marker to its own `to`, and no further"
    );
    let applied = ledger(&store).unwrap();
    assert_eq!(applied.len(), 1, "{applied:?}");
    assert_eq!(applied[0].id, "first");
    assert_eq!(
        (applied[0].from, applied[0].to, applied[0].rows),
        (at_record(8), at_record(9), 1)
    );
    let listing = list(&store, FLAKY).unwrap();
    assert!(
        matches!(listing.steps[0].1, Status::Applied(_)),
        "{listing:?}"
    );
    assert_eq!(listing.steps[1].1, Status::Pending);

    let report = run(&store, FLAKY, false).unwrap();
    let ids: Vec<&str> = report.steps.iter().map(|step| step.step.id).collect();
    assert_eq!(ids, ["second"], "the rerun repeated a finished step");
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"ab");
    assert_eq!(marker_of(&store).unwrap(), CURRENT);
    let ids: Vec<String> = ledger(&store)
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(ids, ["first", "second"]);
}

/// Set by a test to make `interruptible_items` stop after its fifth item.
static INTERRUPT_ITEMS: AtomicBool = AtomicBool::new(false);

/// Never set: `whole_items` is for a test that must not race the one above
/// for its flag.
static NEVER: AtomicBool = AtomicBool::new(false);

fn interruptible_items(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    ten_items(run, &INTERRUPT_ITEMS)
}

fn whole_items(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    ten_items(run, &NEVER)
}

/// Ten units of work, each traced and checkpointed, resuming after the
/// last checkpointed one.
fn ten_items(run: &mut StepRun<'_>, interrupt: &AtomicBool) -> Result<u64, StoreError> {
    let start = run
        .resume()
        .and_then(|saved| saved.cursor.first().copied())
        .map_or(0, |last| last + 1);
    run.phase("items", "items", Some(10), u64::from(start));
    for item in start..10 {
        append_trace(run.store(), b'0' + item)?;
        run.advance(1);
        run.checkpoint(&[item])?;
        if item == 4 && interrupt.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Backend("killed mid-step".to_owned()));
        }
    }
    Ok(10 - u64::from(start))
}

/// A step interrupted part way resumes from its last checkpoint: the work
/// before it is not redone, the work after it is not skipped, and the
/// progress the rerun reports starts where the first run stopped.
#[test]
fn an_interrupted_step_resumes_from_its_checkpoint() {
    static ITEMS: &[Migration] = &[step(
        "ten-items",
        8,
        1,
        Reversible::Yes,
        interruptible_items,
    )];
    let (_dir, store) = store_at(at_record(8));
    INTERRUPT_ITEMS.store(true, Ordering::SeqCst);

    assert!(run(&store, ITEMS, false).is_err());
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"01234");
    assert_eq!(marker_of(&store).unwrap(), at_record(8));
    let saved = checkpoint(&store).unwrap().expect("a progress record");
    assert_eq!(
        (
            saved.step.as_str(),
            saved.phase.as_str(),
            saved.unit.as_str()
        ),
        ("ten-items", "items", "items")
    );
    assert_eq!(
        (saved.done, saved.total, saved.cursor.as_slice()),
        (5, Some(10), &[4][..])
    );
    let listing = list(&store, ITEMS).unwrap();
    assert_eq!(listing.steps[0].1, Status::Interrupted(saved.clone()));

    // A dry run says where a run would resume, and moves nothing.
    let planned = run(&store, ITEMS, true).unwrap();
    assert_eq!(planned.resumed.as_ref(), Some(&saved));
    assert_eq!(checkpoint(&store).unwrap().as_ref(), Some(&saved));
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"01234");

    let mut started = Vec::new();
    let mut progress = Vec::new();
    let report = run_reporting(
        &store,
        ITEMS,
        false,
        Duration::ZERO,
        &mut |event| match event {
            Event::Started { step, resumed } => started.push((step.id, resumed.cloned())),
            Event::Progress(update) => progress.push((*update).clone()),
            Event::Applied { .. } => {}
        },
    )
    .unwrap();
    assert_eq!(report.resumed.as_ref(), Some(&saved));
    assert_eq!(started, [("ten-items", Some(saved))]);
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"0123456789");
    let first = &progress[0];
    assert_eq!(
        (first.stage, first.done, first.resumed, first.total),
        (Stage::Started, 5, 5, Some(10))
    );
    let last = progress.last().unwrap();
    assert_eq!((last.stage, last.done), (Stage::Finished, 10));
    assert!(
        checkpoint(&store).unwrap().is_none(),
        "a finished step left its progress record"
    );
    assert_eq!(marker_of(&store).unwrap(), CURRENT);
    assert_eq!(ledger(&store).unwrap()[0].rows, 5);
}

/// A progress record is honoured only by the step that wrote it. Another
/// step's cursor means nothing to this one, and resuming from it would skip
/// work, so it is dropped and the step runs from the beginning.
#[test]
fn a_checkpoint_from_another_step_is_dropped_not_resumed() {
    static ITEMS: &[Migration] = &[step("other-items", 8, 1, Reversible::Yes, whole_items)];
    let (_dir, store) = store_at(at_record(8));
    // A record as an interrupted run of a step this table does not have
    // would leave it.
    {
        static FOREIGN: &[Migration] = &[step("foreign", 8, 1, Reversible::Yes, |run| {
            run.phase("foreign", "things", None, 0);
            run.checkpoint(b"somewhere")?;
            Err(StoreError::Backend("stopped".to_owned()))
        })];
        assert!(run(&store, FOREIGN, false).is_err());
    }
    assert_eq!(checkpoint(&store).unwrap().unwrap().step, "foreign");
    assert!(run(&store, ITEMS, true).unwrap().resumed.is_none());

    let report = run(&store, ITEMS, false).unwrap();
    assert!(report.resumed.is_none());
    assert_eq!(count_rows(&store, TRACE).unwrap(), b"0123456789");
    assert!(checkpoint(&store).unwrap().is_none());
}

/// A phase that knows its total, then one that does not, each counting
/// every unit.
#[allow(clippy::unnecessary_wraps)] // The signature every step has.
fn counted(run: &mut StepRun<'_>) -> Result<u64, StoreError> {
    run.phase("known", "records", Some(1_000), 0);
    for _ in 0..1_000 {
        run.advance(1);
    }
    run.phase("unknown", "rooms", None, 0);
    for _ in 0..500 {
        run.advance(1);
    }
    Ok(0)
}

static COUNTED: &[Migration] = &[step("counted", 8, 1, Reversible::Yes, counted)];

fn progress_of(interval: Duration) -> Vec<Progress> {
    let (_dir, store) = store_at(at_record(8));
    let mut updates = Vec::new();
    run_reporting(&store, COUNTED, false, interval, &mut |event| {
        if let Event::Progress(update) = event {
            updates.push((*update).clone());
        }
    })
    .unwrap();
    updates
}

/// Every unit of work is counted, the counts reach the caller with the step
/// and phase they belong to, and a phase without a total says so instead
/// of inventing a percentage or an ETA.
#[test]
fn progress_counts_every_unit_and_marks_unknown_totals() {
    let updates = progress_of(Duration::ZERO);
    let known: Vec<&Progress> = updates
        .iter()
        .filter(|update| update.phase == "known")
        .collect();
    let unknown: Vec<&Progress> = updates
        .iter()
        .filter(|update| update.phase == "unknown")
        .collect();

    // With no interval every advance reports: a start, one per unit, an end.
    assert_eq!(known.len(), 1_002);
    assert_eq!(unknown.len(), 502);
    assert!(updates.iter().all(|update| update.step == "counted"));
    let (start, end) = (known[0], known[known.len() - 1]);
    assert_eq!(
        (start.stage, start.done, start.percent()),
        (Stage::Started, 0, Some(0.0))
    );
    assert_eq!(
        (end.stage, end.done, end.unit),
        (Stage::Finished, 1_000, "records")
    );
    assert_eq!(end.percent(), Some(100.0));
    assert!(
        known.windows(2).all(|pair| pair[0].done <= pair[1].done),
        "a count went backwards"
    );

    let end = unknown[unknown.len() - 1];
    assert_eq!(
        (end.stage, end.done, end.total, end.unit),
        (Stage::Finished, 500, None, "rooms")
    );
    assert!(
        unknown
            .iter()
            .all(|update| update.percent().is_none() && update.eta().is_none()),
        "an unknown total produced a percentage or an ETA"
    );
}

/// However often a step counts, the caller hears from it at most once per
/// interval between a phase's start and its end.
#[test]
fn progress_is_rate_limited_however_often_a_step_counts() {
    let updates = progress_of(Duration::from_secs(3_600));
    let stages: Vec<(&str, Stage, u64)> = updates
        .iter()
        .map(|update| (update.phase, update.stage, update.done))
        .collect();
    assert_eq!(
        stages,
        [
            ("known", Stage::Started, 0),
            ("known", Stage::Finished, 1_000),
            ("unknown", Stage::Started, 0),
            ("unknown", Stage::Finished, 500),
        ],
        "1,500 advances inside an hour-long interval reported more than starts and ends"
    );
}

/// The rate counts only this run's work, and only once there is enough of
/// it to measure; the ETA needs both a rate and a total, and a finished
/// phase has none.
#[test]
fn rate_and_eta_need_a_measured_rate_and_a_total() {
    let running = Progress {
        step: "s",
        phase: "p",
        unit: "records",
        done: 50,
        total: Some(100),
        resumed: 10,
        elapsed: Duration::from_secs(10),
        stage: Stage::Running,
    };
    assert_eq!(running.percent(), Some(50.0));
    assert_eq!(running.rate(), Some(4.0), "40 records this run over 10 s");
    assert_eq!(running.eta(), Some(Duration::from_secs_f64(12.5)));

    let early = Progress {
        elapsed: Duration::from_millis(200),
        ..running.clone()
    };
    assert_eq!((early.rate(), early.eta()), (None, None));
    let only_resumed = Progress {
        done: 10,
        ..running.clone()
    };
    assert_eq!((only_resumed.rate(), only_resumed.eta()), (None, None));
    let unknown = Progress {
        total: None,
        ..running.clone()
    };
    assert_eq!((unknown.percent(), unknown.eta()), (None, None));
    assert_eq!(unknown.rate(), Some(4.0));
    let finished = Progress {
        stage: Stage::Finished,
        ..running.clone()
    };
    assert_eq!(finished.eta(), None);
    let empty = Progress {
        done: 0,
        resumed: 0,
        total: Some(0),
        ..running
    };
    assert_eq!(empty.percent(), Some(100.0));
}

/// On a store that never needed a step, listing says so rather than
/// calling it pending or applied.
#[test]
fn a_store_created_after_a_step_lists_it_as_not_needed() {
    let (_dir, store) = store_at(SchemaMarker::current());
    let listing = list(&store, CHAIN).unwrap();
    assert!(
        listing
            .steps
            .iter()
            .all(|(_, status)| *status == Status::NotNeeded),
        "{listing:?}"
    );
    assert!(listing.foreign.is_empty());
}

/// The ledger travels with a backup: a store restored from one still says
/// which steps it went through, and a binary that lacks one of them lists
/// it as foreign rather than dropping it.
#[test]
fn a_backup_carries_the_ledger_to_the_restored_store() {
    static ONLY_FIRST: &[Migration] = &[step("first", 8, 9, Reversible::Yes, step_a)];
    let (_dir, store) = store_at(at_record(8));
    run(&store, CHAIN, false).unwrap();
    let mut bytes = Vec::new();
    spindle_store::backup::write_backup(&store, &mut bytes).unwrap();

    let restored_dir = TempDir::new().unwrap();
    let restored = FjallStore::open(restored_dir.path()).unwrap();
    spindle_store::backup::read_backup(&mut bytes.as_slice(), &restored).unwrap();
    assert_eq!(ledger(&restored).unwrap(), ledger(&store).unwrap());

    let listing = list(&restored, ONLY_FIRST).unwrap();
    let foreign: Vec<&str> = listing.foreign.iter().map(|row| row.id.as_str()).collect();
    assert_eq!(foreign, ["second"]);
}
