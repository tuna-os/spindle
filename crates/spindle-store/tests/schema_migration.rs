//! Moving a store between schema versions (#20).
//!
//! The real table is empty — no schema change has needed a data rewrite
//! yet — so every test here drives `plan` and `run` with a **synthetic**
//! table. That is not a weaker test than a real migration would be. The
//! properties that decide whether an operator loses a store are properties
//! of the machinery, not of any particular step: whether steps chain,
//! whether an unreachable version is refused rather than half-applied,
//! whether a dry run writes, and above all whether the marker can end up
//! ahead of the data.
//!
//! Getting those right *before* the first real migration is the point.
//! The first one will be written under whatever pressure produced the
//! schema change, and that is the worst moment to be discovering that a
//! failed step leaves the store claiming to be a version it is not.

use spindle_core::keys::store_marker;
use spindle_store::migrate::{
    MIGRATIONS, MigrateError, Migration, Reversible, marker_of, plan, run,
};
use spindle_store::{FjallStore, SchemaMarker, Store};
use tempfile::TempDir;

/// A marker that differs from the current one only in `record`.
fn at_record(record: u8) -> SchemaMarker {
    SchemaMarker {
        record,
        ..SchemaMarker::current()
    }
}

fn count_rows(store: &FjallStore, key: &[u8]) -> Option<Vec<u8>> {
    spindle_store::ReadView::get(store, key).unwrap()
}

/// Marker keys the synthetic steps write, so a test can see what ran and in
/// what order without the steps needing to touch real records.
const TRACE: &[u8] = b"\x01\xfe\xfetrace";

fn append_trace(store: &FjallStore, label: u8) -> Result<u64, spindle_store::StoreError> {
    let mut trail = count_rows(store, TRACE).unwrap_or_default();
    trail.push(label);
    Store::put(store, TRACE, &trail)?;
    Ok(1)
}

fn step_a(store: &FjallStore) -> Result<u64, spindle_store::StoreError> {
    append_trace(store, b'a')
}

fn step_b(store: &FjallStore) -> Result<u64, spindle_store::StoreError> {
    append_trace(store, b'b')
}

fn always_fails(_: &FjallStore) -> Result<u64, spindle_store::StoreError> {
    Err(spindle_store::StoreError::Backend(
        "this step fails".to_owned(),
    ))
}

/// Two steps that chain from `record: 8` up to the current marker.
static CHAIN: &[Migration] = &[
    Migration {
        from: SchemaMarker {
            key_schema: 1,
            record: 8,
            content_digest: 1,
        },
        to: SchemaMarker {
            key_schema: 1,
            record: 9,
            content_digest: 1,
        },
        summary: "first synthetic step",
        reversible: Reversible::Yes,
        apply: step_a,
    },
    Migration {
        from: SchemaMarker {
            key_schema: 1,
            record: 9,
            content_digest: 1,
        },
        to: SchemaMarker {
            key_schema: 1,
            record: 1,
            content_digest: 1,
        },
        summary: "second synthetic step",
        reversible: Reversible::No,
        apply: step_b,
    },
];

/// One step whose body fails.
static FAILING: &[Migration] = &[Migration {
    from: SchemaMarker {
        key_schema: 1,
        record: 8,
        content_digest: 1,
    },
    to: SchemaMarker {
        key_schema: 1,
        record: 1,
        content_digest: 1,
    },
    summary: "a step that does not survive contact with the store",
    reversible: Reversible::No,
    apply: always_fails,
}];

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
    assert_eq!(report.steps.len(), 2, "{report:?}");
    // Order matters and is not implied by the table's order alone: `plan`
    // follows `from`/`to`, so a table listed backwards must still produce
    // the right sequence.
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
}

/// A failed step leaves the marker where it was.
///
/// The one that matters most. A store whose marker says "current" while its
/// data is half-rewritten is refused by nothing and misread by everything —
/// exactly the silent failure `SchemaMarker` exists to prevent, reintroduced
/// by the tool meant to move past it. So the marker is written last, and
/// only after every step succeeded.
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
        .map(|(_, reversible, _)| *reversible)
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
        Migration {
            from: SchemaMarker {
                key_schema: 1,
                record: 8,
                content_digest: 1,
            },
            to: SchemaMarker {
                key_schema: 1,
                record: 9,
                content_digest: 1,
            },
            summary: "there",
            reversible: Reversible::Yes,
            apply: step_a,
        },
        Migration {
            from: SchemaMarker {
                key_schema: 1,
                record: 9,
                content_digest: 1,
            },
            to: SchemaMarker {
                key_schema: 1,
                record: 8,
                content_digest: 1,
            },
            summary: "and back again",
            reversible: Reversible::Yes,
            apply: step_b,
        },
    ];

    let error = plan(at_record(8), SchemaMarker::current(), LOOP).unwrap_err();
    assert!(matches!(error, MigrateError::NoPath { .. }), "{error:?}");
}
