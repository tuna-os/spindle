//! `spindle migrate`: move a store forward to the schema this binary speaks
//! (#20), list the steps that takes (#661), and say how far a long one has
//! got (#656).
//!
//! The report of what ran goes to stdout, as before. Progress goes to
//! stderr, as text or as one JSON object per line: a Kubernetes job's log
//! is where an operator looks while a migration runs, and a script can only
//! follow it if the lines parse.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{Value, json};
use spindle_server::Config;
use spindle_store::SchemaMarker;
use spindle_store::migrate::{
    Applied, Checkpoint, Event, MIGRATIONS, Migration, PROGRESS_INTERVAL, Progress, Reversible,
    Stage, Status,
};

const USAGE: &str = "usage: spindle migrate <config> [--dry-run] [--progress text|json]\n       \
                     spindle migrate --list [<config>]";

/// The arguments after `migrate`.
struct Arguments {
    config: Option<String>,
    dry_run: bool,
    list: bool,
    json: bool,
}

fn parse(arguments: &[String]) -> Result<Arguments, String> {
    let mut parsed = Arguments {
        config: None,
        dry_run: false,
        list: false,
        json: false,
    };
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let format = match argument.as_str() {
            "--dry-run" => {
                parsed.dry_run = true;
                continue;
            }
            "--list" => {
                parsed.list = true;
                continue;
            }
            "--progress" => rest.next().map(String::as_str),
            other => match other.strip_prefix("--progress=") {
                Some(format) => Some(format),
                None if other.starts_with("--") => return Err(format!("unknown flag {other}")),
                None if parsed.config.is_none() => {
                    parsed.config = Some(other.to_owned());
                    continue;
                }
                None => return Err(format!("unexpected argument {other}")),
            },
        };
        parsed.json = match format {
            Some("json") => true,
            Some("text") => false,
            _ => return Err("--progress takes text or json".to_owned()),
        };
    }
    if parsed.config.is_none() && !parsed.list {
        return Err("a config is required".to_owned());
    }
    Ok(parsed)
}

/// Run `spindle migrate` with the arguments that follow it.
pub fn migrate(arguments: &[String]) -> ExitCode {
    let arguments = match parse(arguments) {
        Ok(arguments) => arguments,
        Err(why) => {
            eprintln!("migrate: {why}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let store = match arguments.config.as_deref().map(open) {
        Some(Some(store)) => Some(store),
        Some(None) => return ExitCode::FAILURE,
        None => None,
    };
    if arguments.list {
        return list(store.as_ref());
    }
    let Some(store) = store else {
        // `parse` requires a config unless listing.
        return ExitCode::FAILURE;
    };
    run(&store, arguments.dry_run, arguments.json)
}

fn open(config_path: &str) -> Option<spindle_store::FjallStore> {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot read {config_path}: {error}");
            return None;
        }
    };
    // Unchecked on purpose: the store this is being run on is one the
    // ordinary open has already refused.
    match spindle_store::FjallStore::open_unchecked(&config.storage.path) {
        Ok(store) => Some(store),
        Err(error) => {
            eprintln!("cannot open store: {error}");
            None
        }
    }
}

fn run(store: &spindle_store::FjallStore, dry_run: bool, json: bool) -> ExitCode {
    let mut events = |event: &Event<'_>| {
        if json {
            eprintln!("{}", event_json(event));
        } else {
            eprintln!("{}", event_text(event));
        }
    };
    let report = match spindle_store::migrate::run_reporting(
        store,
        MIGRATIONS,
        dry_run,
        PROGRESS_INTERVAL,
        &mut events,
    ) {
        Ok(report) => report,
        Err(error) => {
            let saved = spindle_store::migrate::checkpoint(store).ok().flatten();
            if json {
                eprintln!(
                    "{}",
                    json!({
                        "event": "error",
                        "message": error.to_string(),
                        "checkpoint": saved.as_ref().map(checkpoint_json),
                    })
                );
            } else {
                eprintln!("migrate: {error}");
                if let Some(saved) = saved {
                    eprintln!(
                        "migrate: progress is saved; the next run resumes [{}] {}",
                        saved.step,
                        checkpoint_text(&saved)
                    );
                }
            }
            return ExitCode::FAILURE;
        }
    };
    if report.steps.is_empty() {
        println!("migrate: the store is already at this binary's schema");
        return ExitCode::SUCCESS;
    }
    // The irreversibility notice comes first, and on a dry run it is the
    // whole point of the exercise: the operator is being told what they
    // cannot undo while they can still choose not to do it.
    if report.irreversible() {
        println!(
            "migrate: this plan CANNOT be undone -- going back means restoring \
             a backup taken before it runs"
        );
    }
    if dry_run && let Some(saved) = &report.resumed {
        println!(
            "migrate: [{}] was interrupted; a run resumes it {}",
            saved.step,
            checkpoint_text(saved)
        );
    }
    for step in &report.steps {
        let note = reversibility(step.step);
        let (id, summary) = (step.step.id, step.step.summary);
        if dry_run {
            println!("migrate: would apply [{id}] [{note}] {summary}");
        } else {
            println!(
                "migrate: applied [{id}] [{note}] {summary} ({} rows)",
                step.rows
            );
        }
    }
    if dry_run {
        println!("migrate: dry run, nothing written");
    } else {
        println!("migrate: done, store is now at this binary's schema");
    }
    ExitCode::SUCCESS
}

/// Every step this binary carries and, given a store, where each stands on
/// it. Without a store it is the release's own list: which schema versions
/// it can move a store from, and through which steps.
fn list(store: Option<&spindle_store::FjallStore>) -> ExitCode {
    println!(
        "migrate: this binary writes schema {}",
        marker(SchemaMarker::current())
    );
    let (steps, foreign): (Vec<_>, _) = match store {
        Some(store) => match spindle_store::migrate::list(store, MIGRATIONS) {
            Ok(listing) => (
                listing
                    .steps
                    .into_iter()
                    .map(|(step, status)| (step, Some(status)))
                    .collect(),
                listing.foreign,
            ),
            Err(error) => {
                eprintln!("migrate: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => (
            MIGRATIONS.iter().map(|step| (step, None)).collect(),
            Vec::new(),
        ),
    };
    if let Some(store) = store {
        match spindle_store::migrate::marker_of(store) {
            Ok(found) => println!("migrate: this store is at schema {}", marker(found)),
            Err(error) => {
                eprintln!("migrate: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    for (step, status) in steps {
        let status = status.map_or_else(String::new, |status| match status {
            Status::Applied(applied) => format!(": {}", applied_text(&applied)),
            Status::Pending => ": pending".to_owned(),
            Status::Interrupted(saved) => {
                format!(": pending, interrupted {}", checkpoint_text(&saved))
            }
            Status::NotNeeded => ": not needed by this store".to_owned(),
        });
        println!(
            "migrate: [{}] {} -> {} [{}] {}{status}",
            step.id,
            marker(step.from),
            marker(step.to),
            reversibility(step),
            step.summary
        );
    }
    for applied in foreign {
        println!(
            "migrate: [{}] {} -> {}: {}, by a binary that has a step this one does not",
            applied.id,
            marker(applied.from),
            marker(applied.to),
            applied_text(&applied)
        );
    }
    ExitCode::SUCCESS
}

/// A marker as `key/record/digest`, the order the refusals print it in.
fn marker(marker: SchemaMarker) -> String {
    format!(
        "{}/{}/{}",
        marker.key_schema, marker.record, marker.content_digest
    )
}

fn reversibility(step: &Migration) -> &'static str {
    match step.reversible {
        Reversible::Yes => "reversible",
        Reversible::No => "IRREVERSIBLE",
    }
}

fn applied_text(applied: &Applied) -> String {
    format!(
        "applied at unix time {} ({} rows)",
        applied.at, applied.rows
    )
}

fn checkpoint_text(saved: &Checkpoint) -> String {
    let count = match saved.total {
        Some(total) => format!("{}/{total}", saved.done),
        None => saved.done.to_string(),
    };
    format!(
        "in phase {} at {count} {}, saved at unix time {}",
        saved.phase, saved.unit, saved.at
    )
}

fn checkpoint_json(saved: &Checkpoint) -> Value {
    json!({
        "step": saved.step,
        "phase": saved.phase,
        "unit": saved.unit,
        "done": saved.done,
        "total": saved.total,
        "saved_at": saved.at,
    })
}

fn event_text(event: &Event<'_>) -> String {
    match event {
        Event::Started { step, resumed } => {
            let resumed = resumed.map_or_else(String::new, |saved| {
                format!(", resuming {}", checkpoint_text(saved))
            });
            format!("migrate: [{}] started: {}{resumed}", step.id, step.summary)
        }
        Event::Progress(progress) => progress_text(progress),
        Event::Applied {
            step,
            rows,
            elapsed,
        } => format!(
            "migrate: [{}] applied: {rows} rows in {}",
            step.id,
            duration_text(*elapsed)
        ),
    }
}

fn progress_text(progress: &Progress) -> String {
    let stage = match progress.stage {
        Stage::Started => " started",
        Stage::Running => "",
        Stage::Finished => " done",
    };
    let (done, unit) = (progress.done, progress.unit);
    let mut line = format!("migrate: [{}] {}{stage}: ", progress.step, progress.phase);
    // Writing to a String cannot fail.
    let _ = match (progress.total, progress.percent()) {
        (Some(total), Some(percent)) => write!(line, "{done}/{total} {unit} ({percent:.1}%)"),
        (None, _) if progress.stage == Stage::Finished => write!(line, "{done} {unit}"),
        // No total: a count that keeps moving is the sign of life, and no
        // percentage is better than an invented one.
        _ => write!(line, "{done} {unit} so far, total unknown"),
    };
    if let Some(rate) = progress.rate() {
        let _ = write!(line, ", {rate:.1} {unit}/s");
    }
    if let Some(eta) = progress.eta() {
        let _ = write!(line, ", ETA {}", duration_text(eta));
    }
    let _ = write!(line, ", {} elapsed", duration_text(progress.elapsed));
    line
}

fn duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..60 => format!("{:.1}s", duration.as_secs_f64()),
        60..3600 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h{:02}m", seconds / 3600, seconds % 3600 / 60),
    }
}

fn event_json(event: &Event<'_>) -> Value {
    match event {
        Event::Started { step, resumed } => json!({
            "event": "started",
            "step": step.id,
            "summary": step.summary,
            "from": marker(step.from),
            "to": marker(step.to),
            "reversible": step.reversible == Reversible::Yes,
            "resumed": resumed.map(checkpoint_json),
        }),
        Event::Progress(progress) => json!({
            "event": "progress",
            "step": progress.step,
            "phase": progress.phase,
            "stage": match progress.stage {
                Stage::Started => "started",
                Stage::Running => "running",
                Stage::Finished => "finished",
            },
            "unit": progress.unit,
            "done": progress.done,
            "total": progress.total,
            "percent": progress.percent(),
            "resumed": progress.resumed,
            "elapsed_seconds": progress.elapsed.as_secs_f64(),
            "rate_per_second": progress.rate(),
            "eta_seconds": progress.eta().map(|eta| eta.as_secs()),
        }),
        Event::Applied {
            step,
            rows,
            elapsed,
        } => json!({
            "event": "applied",
            "step": step.id,
            "rows": rows,
            "elapsed_seconds": elapsed.as_secs_f64(),
        }),
    }
}
