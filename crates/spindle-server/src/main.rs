//! The `spindle` binary.

use std::process::ExitCode;
use std::sync::Arc;

use spindle_server::Config;
use spindle_store::FjallStore;
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> ExitCode {
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
    let listener = match TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot bind {bind}: {error}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!("spindle listening on {bind} as {name}");
    let app = spindle_server::app(config, store);
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
    {
        tracing::error!("server stopped: {error}");
        return ExitCode::FAILURE;
    }

    tracing::info!("shut down cleanly");
    ExitCode::SUCCESS
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
