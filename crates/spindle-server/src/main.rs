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

/// Bring up the TLS federation listener, spawned beside the main service.
///
/// Returns false when the configuration cannot be served — missing TLS
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
