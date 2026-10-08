//! The `spindle` binary.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use spindle_server::Config;
use spindle_store::FjallStore;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[tokio::main]
async fn main() -> ExitCode {
    // `spindle import-synapse <config> <postgres-config> [options]` -- the
    // full import (#240, #563). See `import_synapse` for the options.
    if std::env::args().nth(1).as_deref() == Some("import-synapse") {
        #[cfg(feature = "synapse-import")]
        {
            let arguments: Vec<String> = std::env::args().skip(2).collect();
            return if let Ok(code) = std::thread::spawn(move || import_synapse(&arguments)).join() {
                code
            } else {
                eprintln!("spindle: Synapse import worker panicked");
                ExitCode::FAILURE
            };
        }
        #[cfg(not(feature = "synapse-import"))]
        {
            eprintln!("spindle: rebuild with --features synapse-import to use this command");
            return ExitCode::FAILURE;
        }
    }

    if std::env::args().nth(1).as_deref() == Some("import-synapse-rehearsal") {
        #[cfg(feature = "synapse-import")]
        {
            let (Some(config_path), Some(postgres), Some(room_id), Some(user_id)) = (
                std::env::args().nth(2),
                std::env::args().nth(3),
                std::env::args().nth(4),
                std::env::args().nth(5),
            ) else {
                eprintln!(
                    "usage: spindle import-synapse-rehearsal \
                     <config> <postgres-config> <room-id>[,<room-id>...] \
                     <user-id>[,<user-id>...]"
                );
                return ExitCode::FAILURE;
            };
            return if let Ok(code) = std::thread::spawn(move || {
                import_synapse_rehearsal(&config_path, &postgres, &room_id, &user_id)
            })
            .join()
            {
                code
            } else {
                eprintln!("spindle: Synapse rehearsal worker panicked");
                ExitCode::FAILURE
            };
        }
        #[cfg(not(feature = "synapse-import"))]
        {
            eprintln!("spindle: rebuild with --features synapse-import to use this command");
            return ExitCode::FAILURE;
        }
    }

    // `spindle promote-admin <config> <localpart>` — the offline path
    // that mints the FIRST admin (#83). Every later admin is granted
    // through the API by an existing one, which keeps the grant in the
    // audit log; the first has no one to grant it, so it happens here,
    // against the store, with the server stopped.
    if std::env::args().nth(1).as_deref() == Some("promote-admin") {
        let (Some(config_path), Some(localpart)) =
            (std::env::args().nth(2), std::env::args().nth(3))
        else {
            eprintln!("usage: spindle promote-admin <config> <localpart>");
            return ExitCode::FAILURE;
        };
        return promote_admin(&config_path, &localpart);
    }

    // `spindle set-password-hash <config> [<localpart>]` — store Argon2
    // PHC hashes computed elsewhere (#611), read from stdin so they never
    // sit in a process listing or shell history. With a localpart, stdin
    // is that account's one hash; without, each line is
    // `<localpart> <hash>` — the bulk path a MAS migration takes.
    if std::env::args().nth(1).as_deref() == Some("set-password-hash") {
        let Some(config_path) = std::env::args().nth(2) else {
            eprintln!("usage: spindle set-password-hash <config> [<localpart>] < hashes");
            return ExitCode::FAILURE;
        };
        return set_password_hash(&config_path, std::env::args().nth(3).as_deref());
    }

    // `spindle backup <config> <file>` and `spindle restore <config> <file>`
    // — the offline lifecycle pair (#20). Offline because the store is
    // opened directly: fjall holds a lock, so these run with the server
    // stopped, which is also the only way a restore can be sure nothing is
    // writing behind it.
    if std::env::args().nth(1).as_deref() == Some("backup") {
        let (Some(config_path), Some(file)) = (std::env::args().nth(2), std::env::args().nth(3))
        else {
            eprintln!("usage: spindle backup <config> <file>");
            return ExitCode::FAILURE;
        };
        return backup(&config_path, &file);
    }
    if std::env::args().nth(1).as_deref() == Some("restore") {
        let (Some(config_path), Some(file)) = (std::env::args().nth(2), std::env::args().nth(3))
        else {
            eprintln!("usage: spindle restore <config> <file>");
            return ExitCode::FAILURE;
        };
        return restore(&config_path, &file).await;
    }
    // `spindle verify-media <config>` -- the same audit a restore prints,
    // available on its own. Blobs can go missing without a restore in
    // sight: a bucket lifecycle rule, a half-copied directory, a disk that
    // came back smaller. The store still holds every record, so the server
    // looks healthy right up to the moment someone opens the file.
    if std::env::args().nth(1).as_deref() == Some("verify-media") {
        let Some(config_path) = std::env::args().nth(2) else {
            eprintln!("usage: spindle verify-media <config>");
            return ExitCode::FAILURE;
        };
        return verify_media(&config_path).await;
    }
    // `spindle migrate <config> [--dry-run]` -- move a store forward to the
    // schema this binary speaks (#20).
    //
    // Its own command rather than something the server does on start. An
    // upgrade that rewrites the store the moment a new binary boots is the
    // change an operator cannot back out of: by the time they know it
    // happened, the old bytes are gone. So `open` refuses and names this,
    // and the rewrite waits for somebody to ask -- having had the chance to
    // take a backup first.
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let Some(config_path) = std::env::args().nth(2) else {
            eprintln!("usage: spindle migrate <config> [--dry-run]");
            return ExitCode::FAILURE;
        };
        let dry_run = std::env::args().any(|argument| argument == "--dry-run");
        return migrate(&config_path, dry_run);
    }

    serve().await
}

/// Split a comma-separated command-line list, dropping empty entries.
#[cfg(feature = "synapse-import")]
fn rehearsal_list(argument: &str) -> Vec<String> {
    let mut items: Vec<String> = argument
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect();
    items.sort_unstable();
    items.dedup();
    items
}

/// The disposable login password for one rehearsal user.
///
/// `SPINDLE_REHEARSAL_PASSWORD_DIR` names a directory holding one file per
/// localpart (a mounted Kubernetes Secret, say), so each user keeps a
/// distinct password. Without it, `SPINDLE_REHEARSAL_PASSWORD` is used for
/// every user.
#[cfg(feature = "synapse-import")]
fn rehearsal_password(localpart: &str) -> Result<String, String> {
    let password = if let Ok(dir) = std::env::var("SPINDLE_REHEARSAL_PASSWORD_DIR") {
        let path = std::path::Path::new(&dir).join(localpart);
        std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?
            .trim_end_matches(['\r', '\n'])
            .to_owned()
    } else {
        std::env::var("SPINDLE_REHEARSAL_PASSWORD").map_err(|_| {
            "set SPINDLE_REHEARSAL_PASSWORD or SPINDLE_REHEARSAL_PASSWORD_DIR \
             for the disposable local logins"
                .to_owned()
        })?
    };
    if password.is_empty() {
        return Err(format!("the rehearsal password for {localpart} is empty"));
    }
    Ok(password)
}

#[cfg(feature = "synapse-import")]
const IMPORT_USAGE: &str = "usage: spindle import-synapse <config> <postgres-config> \
    [--media <synapse media_store_path>] [--checkpoint <file>] [--dry-run] [--no-validate] \
    [--rooms <id>,...] [--users <id>,...] [--exclude-rooms <file>] [--allow-nonempty] \
    [--validate-only]";

/// The full Synapse import (#240, #563).
///
/// Options:
///
/// * `--media <dir>`: Synapse's `media_store_path`, read-only. Without it
///   media is skipped and the report says so.
/// * `--checkpoint <file>`: the restart checkpoint and final JSON report.
///   Defaults to `<storage.path>.synapse-import.json`. Running the same
///   command again resumes from it.
/// * `--dry-run`: read, plan and compare every room, and write nothing.
/// * `--no-validate`: skip the read-back check of the written store.
/// * `--rooms`, `--users`: import only these (comma-separated).
/// * `--exclude-rooms <file>`: one `<room_id> <reason>` per line.
/// * `--allow-nonempty`: import into a store that already holds data and
///   has no checkpoint of this run, such as a second, supplementary source.
/// * `--validate-only`: check a finished import against Synapse again.
///
/// Environment: `SPINDLE_SYNAPSE_PASSWORD` (database password),
/// `SPINDLE_SYNAPSE_SIGNING_KEY_FILE` (Synapse's signing key), and
/// `SPINDLE_REHEARSAL_PASSWORD_DIR` (a known login password per localpart,
/// for test users only; every other account gets an unguessable one).
#[cfg(feature = "synapse-import")]
#[allow(clippy::too_many_lines)]
fn import_synapse(arguments: &[String]) -> ExitCode {
    use spindle_server::import::synapse::full;

    let (Some(config_path), Some(postgres)) = (arguments.first(), arguments.get(1)) else {
        eprintln!("{IMPORT_USAGE}");
        return ExitCode::FAILURE;
    };
    let mut media_root = None;
    let mut checkpoint = None;
    let mut dry_run = false;
    let mut validate = true;
    let mut validate_only = false;
    let mut allow_nonempty = false;
    let mut only_rooms = None;
    let mut only_users = None;
    let mut exclude_rooms = std::collections::BTreeMap::new();
    let mut rest = arguments[2..].iter();
    while let Some(flag) = rest.next() {
        let mut value = || rest.next().cloned();
        match flag.as_str() {
            "--dry-run" => dry_run = true,
            "--no-validate" => validate = false,
            "--validate-only" => validate_only = true,
            "--allow-nonempty" => allow_nonempty = true,
            "--media" => media_root = value().map(std::path::PathBuf::from),
            "--checkpoint" => checkpoint = value().map(std::path::PathBuf::from),
            "--rooms" => {
                only_rooms = value().map(|list| rehearsal_list(&list).into_iter().collect());
            }
            "--users" => {
                only_users = value().map(|list| rehearsal_list(&list).into_iter().collect());
            }
            "--exclude-rooms" => {
                let Some(path) = value() else {
                    eprintln!("{IMPORT_USAGE}");
                    return ExitCode::FAILURE;
                };
                let text = match std::fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(error) => {
                        eprintln!("spindle: cannot read {path}: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                for line in text.lines().map(str::trim) {
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (room_id, reason) =
                        line.split_once(char::is_whitespace).unwrap_or((line, ""));
                    exclude_rooms.insert(room_id.to_owned(), reason.trim().to_owned());
                }
            }
            other => {
                eprintln!("spindle: unknown option {other}\n{IMPORT_USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: cannot read {config_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let checkpoint = checkpoint.unwrap_or_else(|| {
        let mut path = config.storage.path.clone().into_os_string();
        path.push(".synapse-import.json");
        std::path::PathBuf::from(path)
    });
    let previous = match full::load_checkpoint(&checkpoint) {
        Ok(previous) => previous,
        Err(error) => {
            eprintln!("spindle: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(previous) = &previous {
        eprintln!(
            "resuming from {}: {} phases and {} rooms done",
            checkpoint.display(),
            previous.phases_done.len(),
            previous.rooms.len()
        );
        if previous.dry_run != dry_run {
            eprintln!(
                "spindle: the checkpoint is from a {} run; remove it or match --dry-run",
                if previous.dry_run { "dry" } else { "writing" }
            );
            return ExitCode::FAILURE;
        }
    }
    let signing_key = match std::env::var("SPINDLE_SYNAPSE_SIGNING_KEY_FILE") {
        Ok(path) => match std::fs::read_to_string(&path) {
            Ok(source) => Some(source),
            Err(error) => {
                eprintln!("spindle: cannot read Synapse signing key file {path}: {error}");
                return ExitCode::FAILURE;
            }
        },
        Err(_) => None,
    };
    let password_dir = std::env::var("SPINDLE_REHEARSAL_PASSWORD_DIR").ok();

    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("spindle: cannot open the target store: {error}");
            return ExitCode::FAILURE;
        }
    };
    if previous.is_none() && !dry_run && !allow_nonempty {
        let marker = spindle_core::keys::store_marker();
        match spindle_store::ReadView::scan_prefix(store.as_ref(), &[]) {
            Ok(rows) if rows.iter().all(|(key, _)| *key == marker) => {}
            Ok(_) => {
                eprintln!(
                    "spindle: the target store holds data and there is no checkpoint at {}; \
                     use an empty store, or --allow-nonempty for a supplementary source",
                    checkpoint.display()
                );
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("spindle: cannot inspect the target store: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    let options = full::Options {
        server_name: config.server.name.clone(),
        checkpoint,
        media_root,
        only_rooms,
        only_users,
        exclude_rooms,
        dry_run,
        allow_nonempty,
        signing_key,
        password_for: Box::new(move |localpart| {
            let dir = password_dir.as_ref()?;
            let password = std::fs::read_to_string(std::path::Path::new(dir).join(localpart))
                .ok()?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            (!password.is_empty()).then_some(password)
        }),
    };

    let database_password = std::env::var("SPINDLE_SYNAPSE_PASSWORD").ok();
    let mut source = match spindle_server::import::synapse::postgres::Reader::connect_no_tls(
        postgres,
        database_password.as_deref(),
    ) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("spindle: cannot connect to Synapse PostgreSQL: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut snapshot = match source.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("spindle: cannot start Synapse snapshot: {error}");
            return ExitCode::FAILURE;
        }
    };
    let run = if validate_only {
        previous.ok_or_else(|| {
            full::Error::Checkpoint(
                "--validate-only needs the checkpoint of a finished import".to_owned(),
            )
        })
    } else {
        full::run(
            &options,
            &mut snapshot,
            &store,
            spindle_server::blobs_for(&config),
            previous,
        )
    };
    let mut report = match run {
        Ok(report) => report,
        Err(error) => {
            eprintln!(
                "spindle: import stopped: {error}\nrun the same command again to resume from {}",
                options.checkpoint.display()
            );
            return ExitCode::FAILURE;
        }
    };
    if validate
        && !dry_run
        && let Err(error) = full::validate(
            &options,
            &mut snapshot,
            &store,
            spindle_server::blobs_for(&config),
            &mut report,
        )
    {
        eprintln!("spindle: validation stopped: {error}");
        return ExitCode::FAILURE;
    }
    println!(
        "import {}: rooms={} excluded_rooms={} events={} seconds={:.0} report={}",
        if dry_run { "dry run" } else { "done" },
        report.rooms.len(),
        report.excluded_rooms.len(),
        report
            .rooms
            .values()
            .map(|room| room.imported_events)
            .sum::<u64>(),
        report.seconds,
        options.checkpoint.display()
    );
    for (name, domain) in &report.domains {
        println!(
            "  {name}: source={} imported={} skipped={:?}",
            domain.source, domain.imported, domain.skipped
        );
    }
    for (room_id, excluded) in &report.excluded_rooms {
        println!(
            "  excluded {room_id} (v{}): {}",
            excluded.version, excluded.reason
        );
    }
    let clean = report.validation.as_ref().is_none_or(|validation| {
        validation.rooms_divergent.is_empty()
            && validation.rooms_short.is_empty()
            && validation.sample_mismatches.is_empty()
            && validation
                .domains
                .values()
                .all(|(_, mismatches)| mismatches.is_empty())
    });
    if clean {
        ExitCode::SUCCESS
    } else {
        eprintln!("spindle: validation found mismatches; see the report");
        ExitCode::from(2)
    }
}

/// Build an isolated cutover rehearsal from live Synapse.
///
/// `room_ids` and `user_ids` are comma-separated lists. Every room is read
/// and validated, then persisted; every user gets their recovery material
/// (account data, device and cross-signing keys, signatures, key backup)
/// and a disposable local login. All reads come from one source snapshot,
/// and nothing is written until every read has succeeded.
#[cfg(feature = "synapse-import")]
#[allow(clippy::too_many_lines)]
fn import_synapse_rehearsal(
    config_path: &str,
    postgres: &str,
    room_ids: &str,
    user_ids: &str,
) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: cannot read {config_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let room_ids = rehearsal_list(room_ids);
    let user_ids = rehearsal_list(user_ids);
    if room_ids.is_empty() || user_ids.is_empty() {
        eprintln!("spindle: name at least one room and one user");
        return ExitCode::FAILURE;
    }
    let mut users = Vec::with_capacity(user_ids.len());
    for user_id in &user_ids {
        let Some((localpart, domain)) = user_id
            .strip_prefix('@')
            .and_then(|user| user.split_once(':'))
        else {
            eprintln!("spindle: {user_id:?} is not a Matrix user ID");
            return ExitCode::FAILURE;
        };
        if domain != config.server.name {
            eprintln!(
                "spindle: {user_id} does not belong to configured server {}",
                config.server.name
            );
            return ExitCode::FAILURE;
        }
        match rehearsal_password(localpart) {
            Ok(password) => users.push((user_id.clone(), localpart.to_owned(), password)),
            Err(error) => {
                eprintln!("spindle: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            eprintln!("spindle: cannot open rehearsal store: {error}");
            return ExitCode::FAILURE;
        }
    };
    let marker = spindle_core::keys::store_marker();
    match spindle_store::ReadView::scan_prefix(store.as_ref(), &[]) {
        Ok(rows) if rows.iter().all(|(key, _)| *key == marker) => {}
        Ok(rows) => {
            let existing = rows.iter().filter(|(key, _)| *key != marker).count();
            eprintln!("spindle: rehearsal target holds {existing} rows; use an empty storage path");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("spindle: cannot inspect rehearsal store: {error}");
            return ExitCode::FAILURE;
        }
    }

    let database_password = std::env::var("SPINDLE_SYNAPSE_PASSWORD").ok();
    let mut source = match spindle_server::import::synapse::postgres::Reader::connect_no_tls(
        postgres,
        database_password.as_deref(),
    ) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("spindle: cannot connect to Synapse PostgreSQL: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut snapshot = match source.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("spindle: cannot start Synapse snapshot: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Read everything first, so a bad room or user fails the run while the
    // target store is still empty and the run can simply be repeated.
    let mut sources = Vec::with_capacity(room_ids.len());
    for room_id in &room_ids {
        let source_room = match snapshot.read_room(room_id) {
            Ok(room) => room,
            Err(error) => {
                eprintln!("spindle: cannot read source room {room_id}: {error}");
                return ExitCode::FAILURE;
            }
        };
        let bodies = match snapshot.event_bodies(room_id) {
            Ok(bodies) => bodies,
            Err(error) => {
                eprintln!("spindle: cannot read event bodies of {room_id}: {error}");
                return ExitCode::FAILURE;
            }
        };
        sources.push((source_room, bodies));
    }
    let mut recoveries = Vec::with_capacity(users.len());
    for (user_id, _, _) in &users {
        match snapshot.recovery_data(user_id) {
            Ok(recovery) => recoveries.push(recovery),
            Err(error) => {
                eprintln!("spindle: cannot read recovery data of {user_id}: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Ok(path) = std::env::var("SPINDLE_SYNAPSE_SIGNING_KEY_FILE") {
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("spindle: cannot read Synapse signing key file {path}: {error}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(error) =
            spindle_server::signing::ServerKey::install_synapse(store.as_ref(), &source)
        {
            eprintln!("spindle: cannot install Synapse signing key: {error}");
            return ExitCode::FAILURE;
        }
    }

    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), &config.server.name);
    for (source_room, bodies) in &sources {
        match spindle_server::import::persist_rehearsal(&rooms, source_room, bodies) {
            Ok(outcome) => println!(
                "room {}: room_events={}",
                source_room.room_id, outcome.imported
            ),
            Err(error) => {
                eprintln!(
                    "spindle: room rehearsal failed for {}: {error}",
                    source_room.room_id
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let account_data = spindle_server::account_data::AccountData::new(Arc::clone(&store));
    let devices = spindle_server::devices::Devices::new(Arc::clone(&store));
    let backups = spindle_server::backups::Backups::new(Arc::clone(&store));
    let accounts = spindle_server::accounts::Accounts::new(store.as_ref(), &config.server.name);
    for (recovery, (user_id, localpart, password)) in recoveries.iter().zip(&users) {
        let recovered = match spindle_server::import::synapse::recovery::restore(
            recovery,
            &account_data,
            &devices,
            &backups,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("spindle: recovery-data rehearsal failed for {user_id}: {error}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(error) = accounts.register(localpart, password) {
            eprintln!("spindle: cannot create disposable login for {user_id}: {error}");
            return ExitCode::FAILURE;
        }
        println!(
            "user {user_id}: account_data={} device_keys={} cross_signing_keys={} \
             signatures={} skipped_signatures={} backup_versions={} backup_sessions={}",
            recovered.account_data,
            recovered.device_keys,
            recovered.cross_signing_keys,
            recovered.signatures,
            recovered.skipped_signatures,
            recovered.backup_versions,
            recovered.backup_sessions
        );
    }
    if let Err(error) =
        spindle_store::Store::sync(store.as_ref(), spindle_store::Durability::Strict)
    {
        eprintln!("spindle: cannot sync rehearsal store: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "rehearsal ready: rooms={} users={}",
        room_ids.len(),
        user_ids.len()
    );
    println!(
        "rehearsal only: no media, remote cached keys, receipts, pushers, or federation cutover"
    );
    ExitCode::SUCCESS
}

/// Move a store forward to the schema this binary speaks.
fn migrate(config_path: &str, dry_run: bool) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot read {config_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Unchecked on purpose: the store this is being run on is one the
    // ordinary open has already refused.
    let store = match spindle_store::FjallStore::open_unchecked(&config.storage.path) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("cannot open store: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report =
        match spindle_store::migrate::run(&store, spindle_store::migrate::MIGRATIONS, dry_run) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("migrate: {error}");
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
    for (summary, reversible, rows) in &report.steps {
        let note = match reversible {
            spindle_store::migrate::Reversible::Yes => "reversible",
            spindle_store::migrate::Reversible::No => "IRREVERSIBLE",
        };
        if dry_run {
            println!("migrate: would apply [{note}] {summary}");
        } else {
            println!("migrate: applied [{note}] {summary} ({rows} rows)");
        }
    }
    if dry_run {
        println!("migrate: dry run, nothing written");
    } else {
        println!("migrate: done, store is now at this binary's schema");
    }
    ExitCode::SUCCESS
}

/// Run the server itself, which is what every argument form above declines
/// to do.
async fn serve() -> ExitCode {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "spindle.toml".to_owned());

    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            // Before logging is configured, so this goes to stderr directly.
            eprintln!("spindle: {error}");
            return ExitCode::FAILURE;
        }
    };

    let filter = config
        .logging
        .filter
        .clone()
        .unwrap_or_else(|| "info".to_owned());
    let tracer_provider = match init_logging(&config, filter) {
        Ok(provider) => provider,
        Err(code) => return code,
    };

    // Listened for from here, before the store is opened or anything is
    // bound: a signal that arrives during startup is then kept and
    // answered by draining the moment the server is up, instead of taking
    // the default action and killing the process mid-open.
    let stop = shutdown();

    // Storage opens before the listener. A server that binds first and then
    // discovers it cannot read its own database has already accepted
    // connections it cannot answer.
    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            tracing::error!(
                "cannot open storage at {}: {error}",
                config.storage.path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let bind = config.server.bind.clone();
    let name = config.server.name.clone();
    let metrics_bind = config.metrics.bind.clone();
    let federation_bind = config.federation.bind.clone();
    let federation_tls = config
        .federation
        .tls_cert
        .clone()
        .zip(config.federation.tls_key.clone());
    let listener = match TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot bind {bind}: {error}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!("spindle listening on {bind} as {name}");
    // The key is established before the listener accepts anything. A server
    // that binds and then discovers it cannot sign has already told a client it
    // was ready to take events it cannot create.
    let metrics = Arc::new(spindle_server::metrics::Metrics::new());
    let Some(app) = build_app(config, Arc::clone(&store), Arc::clone(&metrics)) else {
        return ExitCode::FAILURE;
    };
    // into_make_service_with_connect_info, so the rate limiter can see peer
    // addresses. Without it every request looks like it came from nowhere and
    // the per-source limit collapses onto one key.
    let service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

    // The scrape surface (#166), on its own listener so it is not reachable
    // wherever the client API is. Failing to bind is fatal for the same
    // reason it is for federation: a server configured to be observable
    // that silently is not will be discovered during the incident it was
    // meant to explain. Bound before the federation listener, which holds
    // the router: a failure here exits with no task left holding the store.
    if let Some(metrics_bind) = metrics_bind
        && !serve_metrics(&metrics_bind, metrics).await
    {
        return ExitCode::FAILURE;
    }

    // The federation listener is the same router over TLS: peers speak https
    // to 8448 and check the certificate against our name, so this listener
    // exists exactly when there is TLS material to answer them with. Failing
    // to bind or to load the material is fatal, not a warning — a server
    // configured to federate that silently cannot is worse than one that
    // says so and exits.
    let federation = match federation_bind {
        Some(fed_bind) => {
            match serve_federation(&fed_bind, federation_tls, &name, service.clone()).await {
                Some(listener) => Some(listener),
                None => return ExitCode::FAILURE,
            }
        }
        None => None,
    };

    // One signal drains both listeners. The main one stops accepting and
    // waits for its connections itself; the federation one is told the
    // same and joined below, so that when the store closes no task still
    // holds a copy of the router.
    let federation_handle = federation.as_ref().map(|listener| listener.handle.clone());
    let stop = async move {
        stop.await;
        if let Some(handle) = federation_handle {
            handle.graceful_shutdown(Some(Duration::from_secs(30)));
        }
    };
    let served = axum::serve(listener, service)
        .with_graceful_shutdown(stop)
        .await;
    if let Some(listener) = federation {
        if served.is_err() {
            listener.handle.shutdown();
        }
        if let Err(error) = listener.task.await {
            tracing::error!("federation listener did not stop cleanly: {error}");
        }
    }
    close_store(store).await;
    flush_traces(tracer_provider);
    match served {
        Ok(()) => {
            tracing::info!("shut down cleanly");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!("server stopped: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Install the log subscriber, and the trace exporter beside it when the
/// config names one.
///
/// The exporter is built before the subscriber so a bad OTLP environment
/// is reported and fails the start, rather than being discovered as a
/// silent absence of traces. Nothing is wired unless the config names it:
/// `docs/telemetry-guidelines.md`. The provider comes back to the caller,
/// who shuts it down last so the shutdown itself is traced.
fn init_logging(
    config: &Config,
    filter: String,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>, ExitCode> {
    let tracer_provider = match config.logging.traces {
        Some(spindle_server::config::TraceExporter::Otlp) => {
            match spindle_server::telemetry::otlp_provider() {
                Ok(provider) => Some(provider),
                Err(error) => {
                    eprintln!("spindle: cannot set up the OTLP trace exporter: {error}");
                    return Err(ExitCode::FAILURE);
                }
            }
        }
        None => None,
    };
    let traces = tracer_provider.as_ref().map(|provider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer("spindle"))
    });
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(filter))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(traces)
        .init();
    if tracer_provider.is_some() {
        tracing::info!("exporting traces over OTLP");
    }
    Ok(tracer_provider)
}

/// Last, so the shutdown is traced too: flush what is queued and stop the
/// export thread. The error is logged and not returned -- a collector that
/// went away must not turn a clean stop into a failed one.
fn flush_traces(provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>) {
    if let Some(provider) = provider
        && let Err(error) = provider.shutdown()
    {
        tracing::warn!("trace exporter did not flush: {error}");
    }
}

/// Close the store here, on the thread that opened it, once nothing else
/// holds it.
///
/// Every listener has been joined by now, so what may still hold the
/// store is a delivery loop inside one pass. The loops hold it only from
/// an upgrade to the end of a read or a write, never across an await, so
/// that pass ends within milliseconds; waiting for it keeps the close out
/// of a task the runtime is about to tear down. fjall's close joins its
/// worker threads, and #292 caught it waiting forever inside exactly such
/// a task.
async fn close_store(mut store: Arc<FjallStore>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match Arc::try_unwrap(store) {
            Ok(store) => {
                drop(store);
                tracing::info!("storage closed");
                return;
            }
            Err(shared) if Instant::now() < deadline => {
                store = shared;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(shared) => {
                tracing::warn!("storage is still in use; it closes with its last holder");
                drop(shared);
                return;
            }
        }
    }
}

/// Set the admin flag on an existing account, offline.
///
/// Refuses an unknown localpart rather than creating it: an admin
/// account minted with a password nobody chose would be a credential
/// nobody can present, and a typo'd localpart silently created would be
/// an admin nobody meant to exist.
fn promote_admin(config_path: &str, localpart: &str) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: {error}");
            return ExitCode::FAILURE;
        }
    };
    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "spindle: cannot open storage at {}: {error}",
                config.storage.path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let accounts = spindle_server::accounts::Accounts::new(&store, &config.server.name);
    match accounts.set_admin(localpart, true) {
        Ok(true) => {
            println!("{localpart} is now a server admin");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("spindle: no account named {localpart} — register it first");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("spindle: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Store pre-computed password hashes, offline (#611).
///
/// Every line is validated and applied on its own; a refused line is
/// reported by line number and localpart — never with its hash — and
/// makes the command exit non-zero once the rest are done, so a bulk
/// import tells the operator exactly which accounts still need attention.
fn set_password_hash(config_path: &str, localpart: Option<&str>) -> ExitCode {
    use std::io::Read as _;
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("spindle: cannot read stdin: {error}");
        return ExitCode::FAILURE;
    }
    let entries: Vec<(usize, String, String)> = match localpart {
        Some(localpart) => vec![(1, localpart.to_owned(), input.trim().to_owned())],
        None => input
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .map(|(index, line)| {
                let mut fields = line.split_whitespace();
                (
                    index + 1,
                    fields.next().unwrap_or_default().to_owned(),
                    fields.next().unwrap_or_default().to_owned(),
                )
            })
            .collect(),
    };
    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "spindle: cannot open storage at {}: {error}",
                config.storage.path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let accounts = spindle_server::accounts::Accounts::new(&store, &config.server.name);
    let (mut stored, mut failed) = (0_usize, 0_usize);
    for (line, localpart, hash) in entries {
        // `@alice:server` is accepted as well as `alice`.
        let localpart = localpart
            .strip_prefix('@')
            .and_then(|rest| rest.split_once(':'))
            .map_or(localpart.as_str(), |(name, _)| name)
            .to_lowercase();
        match accounts.set_password_hash(&localpart, &hash) {
            Ok(true) => stored += 1,
            Ok(false) => {
                failed += 1;
                eprintln!("spindle: line {line}: no account named {localpart}");
            }
            Err(error) => {
                failed += 1;
                eprintln!("spindle: line {line}: {localpart}: {error}");
            }
        }
    }
    println!("stored {stored} password hash(es), {failed} refused");
    if failed == 0 && stored > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Write a consistent backup of the configured store.
///
/// Refuses to overwrite an existing file. A backup command that clobbers
/// is one keystroke away from replacing the good copy with a bad one, and
/// the operator finds out when they restore.
fn backup(config_path: &str, file: &str) -> ExitCode {
    let Some(store) = open_store(config_path) else {
        return ExitCode::FAILURE;
    };
    let path = std::path::Path::new(file);
    if path.exists() {
        eprintln!("spindle: {file} already exists — refusing to overwrite a backup");
        return ExitCode::FAILURE;
    }
    let mut out = match std::fs::File::create(path) {
        Ok(file) => std::io::BufWriter::new(file),
        Err(error) => {
            eprintln!("spindle: cannot write {file}: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Through a snapshot: every row from one moment, so the backup cannot
    // hold metadata that trails its own log.
    let snapshot = spindle_store::Store::snapshot(&store);
    let view: &dyn spindle_store::ReadView = snapshot.as_deref().unwrap_or(&store);
    match spindle_store::backup::write_backup(view, &mut out) {
        Ok(rows) => {
            println!("wrote {rows} rows to {file}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("spindle: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Restore a backup into the configured store.
///
/// Refuses a store that already holds rows. Writing a backup over a
/// populated store is a *merge*, not a restore: anything the target holds
/// and the backup does not survives, so the result matches neither the
/// backup nor what was there before. #20 asks that a failed import never
/// cut over partially, and the surest way to honour that is to require an
/// empty target and let the operator move the old directory aside
/// deliberately.
async fn restore(config_path: &str, file: &str) -> ExitCode {
    let Some((store, config)) = open_store_with_config(config_path) else {
        return ExitCode::FAILURE;
    };
    let store = std::sync::Arc::new(store);
    // "Empty" means no *data*, not no rows: opening a store stamps the schema
    // marker, so a store that has never held anything already has one row.
    // Counting that as content would refuse every restore, including the only
    // one that is supposed to work.
    let marker = spindle_core::keys::store_marker();
    match spindle_store::ReadView::scan_prefix(store.as_ref(), &[]) {
        Ok(rows) => {
            let existing = rows.iter().filter(|(key, _)| *key != marker).count();
            if existing > 0 {
                eprintln!(
                    "spindle: the store already holds {existing} rows — restore into \
                     an empty store, so the result is the backup rather than a merge \
                     of the two"
                );
                return ExitCode::FAILURE;
            }
        }
        Err(error) => {
            eprintln!("spindle: cannot read the store: {error}");
            return ExitCode::FAILURE;
        }
    }
    let mut source = match std::fs::File::open(file) {
        Ok(file) => std::io::BufReader::new(file),
        Err(error) => {
            eprintln!("spindle: cannot read {file}: {error}");
            return ExitCode::FAILURE;
        }
    };
    match spindle_store::backup::read_backup(&mut source, store.as_ref()) {
        Ok(rows) => {
            println!("restored {rows} rows from {file}");
            // A backup carries rows; media bytes live outside it. Saying
            // "restored" and stopping would be true about the rows and
            // false about the server, so the restore ends by reporting what
            // the rows still need. It is a report, not a failure: staging a
            // bucket or rsyncing a directory after the rows is a legitimate
            // order to do this in, and the operator is the one who knows.
            // The store this restore is holding, not a fresh open of the
            // same directory: fjall 3 takes an exclusive lock on a data
            // directory, so reopening it here fails with `Locked` -- and
            // `report_media` used to swallow that into silence, turning "you
            // are missing these blobs" into no output at all. The test that
            // caught it is `a_restore_says_which_media_the_rows_it_wrote_still_need`.
            report_media_with(&config, std::sync::Arc::clone(&store)).await;
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("spindle: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `spindle verify-media <config>` — audit the blob backend against the store.
async fn verify_media(config_path: &str) -> ExitCode {
    match audit_media(config_path).await {
        Some(audit) if audit.complete() => {
            println!("media: {} blobs, all present", audit.blobs);
            ExitCode::SUCCESS
        }
        Some(audit) => {
            print_missing(&audit);
            // Unlike the restore path this *is* a failure: nobody runs
            // `verify-media` in the middle of a copy, they run it to be told
            // whether the deployment is whole.
            ExitCode::FAILURE
        }
        None => ExitCode::FAILURE,
    }
}

/// Print the media audit as part of another command, never failing it.
///
/// Takes the store rather than a path, because the caller is mid-command and
/// already holds one -- and fjall 3 will not hand out a second handle to a
/// directory that is already open.
async fn report_media_with(config: &Config, store: std::sync::Arc<FjallStore>) {
    match audit_with(config, store).await {
        Some(audit) if audit.complete() => {
            println!("media: {} blobs, all present", audit.blobs);
        }
        Some(audit) => print_missing(&audit),
        None => {}
    }
}

fn print_missing(audit: &spindle_server::media::MediaAudit) {
    println!(
        "media: {} blobs, {} present, {} MISSING",
        audit.blobs,
        audit.present,
        audit.missing.len()
    );
    // Named, not counted: "some media is gone" is not something anyone can
    // act on, and the media IDs are what an operator searches their other
    // copy for.
    for blob in &audit.missing {
        println!("  {} <- {}", blob.hash, blob.media_ids.join(", "));
    }
}

/// The audit for the store a config names, or `None` once the reason has
/// been reported.
async fn audit_media(config_path: &str) -> Option<spindle_server::media::MediaAudit> {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: {error}");
            return None;
        }
    };
    let store = match FjallStore::open(&config.storage.path) {
        Ok(store) => std::sync::Arc::new(store),
        Err(error) => {
            eprintln!("spindle: cannot open storage: {error}");
            return None;
        }
    };
    audit_with(&config, store).await
}

/// The audit itself, over a store the caller already has open.
async fn audit_with(
    config: &Config,
    store: std::sync::Arc<FjallStore>,
) -> Option<spindle_server::media::MediaAudit> {
    let media = spindle_server::media::Media::new(
        store,
        spindle_server::blobs_for(config),
        config.server.name.clone(),
    );
    match media.audit().await {
        Ok(audit) => Some(audit),
        Err(error) => {
            eprintln!("spindle: cannot audit media: {error}");
            None
        }
    }
}

/// Open the store a config names, reporting why if it cannot be opened.
fn open_store(config_path: &str) -> Option<FjallStore> {
    open_store_with_config(config_path).map(|(store, _)| store)
}

/// The same, keeping the config the caller will need anyway.
///
/// A command that opens the store almost always needs the configuration too,
/// and re-loading it is cheap -- but re-*opening the store* is not merely
/// wasteful under fjall 3, it fails: the directory is locked by the handle
/// this function just returned.
fn open_store_with_config(config_path: &str) -> Option<(FjallStore, Config)> {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("spindle: {error}");
            return None;
        }
    };
    match FjallStore::open(&config.storage.path) {
        Ok(store) => Some((store, config)),
        Err(error) => {
            eprintln!(
                "spindle: cannot open storage at {}: {error}",
                config.storage.path.display()
            );
            None
        }
    }
}

/// The router, or `None` with the reason logged.
fn build_app(
    config: spindle_server::Config,
    store: Arc<FjallStore>,
    metrics: Arc<spindle_server::metrics::Metrics>,
) -> Option<axum::Router> {
    match spindle_server::app_warming(config, store, metrics) {
        Ok(app) => Some(app),
        Err(error) => {
            tracing::error!("cannot build the server: {error}");
            None
        }
    }
}

/// Serve `GET /metrics` on its own listener.
async fn serve_metrics(bind: &str, metrics: Arc<spindle_server::metrics::Metrics>) -> bool {
    let listener = match TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot bind the metrics listener {bind}: {error}");
            return false;
        }
    };
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let metrics = Arc::clone(&metrics);
            async move {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    metrics.render(),
                )
            }
        }),
    );
    tracing::info!("metrics listening on {bind}");
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            tracing::error!("metrics listener stopped: {error}");
        }
    });
    true
}

/// The federation listener while it serves: the handle that tells it to
/// drain, and the task to join once it has. Joined rather than abandoned
/// because the task holds a copy of the router, and through it the store,
/// and a task the runtime tears down at exit is the wrong place for the
/// store to close (#292).
struct FederationListener {
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<()>,
}

/// Bring up the TLS federation listener, spawned beside the main service.
///
/// Returns `None` when the configuration cannot be served — missing TLS
/// material, unloadable PEM, an unparseable bind — because each of those is
/// a server that was told to federate and cannot.
async fn serve_federation(
    bind: &str,
    tls_material: Option<(std::path::PathBuf, std::path::PathBuf)>,
    name: &str,
    service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<
        axum::Router,
        std::net::SocketAddr,
    >,
) -> Option<FederationListener> {
    let Some((cert, key)) = tls_material else {
        tracing::error!("[federation] bind is set without tls_cert and tls_key");
        return None;
    };
    // The ring provider, installed explicitly: the default provider is
    // aws-lc, whose C build both bloats the image build and links a newer
    // glibc than the runtime image carries. Everything else in the tree
    // (reqwest, ruma) already speaks ring.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already installed");
    }
    let tls = match axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await {
        Ok(tls) => tls,
        Err(error) => {
            tracing::error!(
                "cannot load federation TLS material from {} and {}: {error}",
                cert.display(),
                key.display()
            );
            return None;
        }
    };
    let address: std::net::SocketAddr = match bind.parse() {
        Ok(address) => address,
        Err(error) => {
            tracing::error!("cannot parse federation bind {bind}: {error}");
            return None;
        }
    };
    tracing::info!("federation listening on {bind} as {name}");
    let handle = axum_server::Handle::new();
    let task = tokio::spawn({
        let handle = handle.clone();
        async move {
            if let Err(error) = axum_server::bind_rustls(address, tls)
                .handle(handle)
                .serve(service)
                .await
            {
                tracing::error!("federation listener stopped: {error}");
            }
        }
    });
    Some(FederationListener { handle, task })
}

/// Resolve on the first shutdown signal.
///
/// Both signals matter: a container runtime sends SIGTERM and waits, and a
/// developer sends SIGINT. Handling only one means the other kills the process
/// where it stands, which is survivable given the log's durability guarantees
/// but discards in-flight requests for no reason.
///
/// The signals are listened for from the call, not from the first poll,
/// which is later than it looks: the server polls this from a task of its
/// own once it is accepting. A signal before that would take the default
/// action; from the call on it is kept until the future is polled.
fn shutdown() -> impl Future<Output = ()> {
    #[cfg(unix)]
    let listen = |kind: signal::unix::SignalKind, name: &str| match signal::unix::signal(kind) {
        Ok(stream) => Some(stream),
        Err(error) => {
            tracing::warn!("cannot listen for {name}: {error}");
            None
        }
    };
    #[cfg(unix)]
    let interrupt = listen(signal::unix::SignalKind::interrupt(), "SIGINT");
    #[cfg(unix)]
    let terminate = listen(signal::unix::SignalKind::terminate(), "SIGTERM");

    async move {
        #[cfg(unix)]
        {
            let interrupt = async move {
                match interrupt {
                    Some(mut stream) => stream.recv().await,
                    None => std::future::pending().await,
                }
            };
            let terminate = async move {
                match terminate {
                    Some(mut stream) => stream.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = interrupt => tracing::info!("interrupted, draining"),
                _ = terminate => tracing::info!("terminating, draining"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = signal::ctrl_c().await;
            tracing::info!("interrupted, draining");
        }
    }
}
