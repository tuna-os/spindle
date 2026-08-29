//! The `spindle` binary.

use std::process::ExitCode;
use std::sync::Arc;

use spindle_server::Config;
use spindle_store::FjallStore;
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> ExitCode {
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
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

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
    let app = match spindle_server::app(config, store) {
        Ok(app) => app,
        Err(error) => {
            tracing::error!("cannot build the server: {error}");
            return ExitCode::FAILURE;
        }
    };
    // into_make_service_with_connect_info, so the rate limiter can see peer
    // addresses. Without it every request looks like it came from nowhere and
    // the per-source limit collapses onto one key.
    let service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

    // The federation listener is the same router over TLS: peers speak https
    // to 8448 and check the certificate against our name, so this listener
    // exists exactly when there is TLS material to answer them with. Failing
    // to bind or to load the material is fatal, not a warning — a server
    // configured to federate that silently cannot is worse than one that
    // says so and exits.
    if let Some(fed_bind) = federation_bind
        && !serve_federation(&fed_bind, federation_tls, &name, service.clone()).await
    {
        return ExitCode::FAILURE;
    }

    // The scrape surface (#166), on its own listener so it is not reachable
    // wherever the client API is. Failing to bind is fatal for the same
    // reason it is for federation: a server configured to be observable
    // that silently is not will be discovered during the incident it was
    // meant to explain.
    if let Some(metrics_bind) = metrics_bind
        && !serve_metrics(&metrics_bind).await
    {
        return ExitCode::FAILURE;
    }

    if let Err(error) = axum::serve(listener, service)
        .with_graceful_shutdown(shutdown())
        .await
    {
        tracing::error!("server stopped: {error}");
        return ExitCode::FAILURE;
    }

    tracing::info!("shut down cleanly");
    ExitCode::SUCCESS
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

/// Bring up the TLS federation listener, spawned beside the main service.
///
/// Returns false when the configuration cannot be served — missing TLS
/// material, unloadable PEM, an unparseable bind — because each of those is
/// a server that was told to federate and cannot.
/// Serve `GET /metrics` on its own listener.
async fn serve_metrics(bind: &str) -> bool {
    let listener = match TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot bind the metrics listener {bind}: {error}");
            return false;
        }
    };
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(|| async {
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                spindle_server::metrics::render(),
            )
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

async fn serve_federation(
    bind: &str,
    tls_material: Option<(std::path::PathBuf, std::path::PathBuf)>,
    name: &str,
    service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<
        axum::Router,
        std::net::SocketAddr,
    >,
) -> bool {
    let Some((cert, key)) = tls_material else {
        tracing::error!("[federation] bind is set without tls_cert and tls_key");
        return false;
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
            return false;
        }
    };
    let address: std::net::SocketAddr = match bind.parse() {
        Ok(address) => address,
        Err(error) => {
            tracing::error!("cannot parse federation bind {bind}: {error}");
            return false;
        }
    };
    tracing::info!("federation listening on {bind} as {name}");
    tokio::spawn(async move {
        if let Err(error) = axum_server::bind_rustls(address, tls).serve(service).await {
            tracing::error!("federation listener stopped: {error}");
        }
    });
    true
}

/// Resolve on the first shutdown signal.
///
/// Both signals matter: a container runtime sends SIGTERM and waits, and a
/// developer sends SIGINT. Handling only one means the other kills the process
/// where it stands, which is survivable given the log's durability guarantees
/// but discards in-flight requests for no reason.
async fn shutdown() {
    let interrupt = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => tracing::warn!("cannot listen for SIGTERM: {error}"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::info!("interrupted, draining"),
        () = terminate => tracing::info!("terminating, draining"),
    }
}
