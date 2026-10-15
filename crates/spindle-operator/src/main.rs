//! `spindle-operator --config spindle-operator.toml`

use std::collections::BTreeMap;

use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let (Some("--config"), Some(path)) = (args.next().as_deref(), args.next()) else {
        eprintln!("usage: spindle-operator --config <spindle-operator.toml>");
        return std::process::ExitCode::from(2);
    };
    let config = match std::fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|text| spindle_operator::config::Config::parse(&text))
    {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{path}: {error}");
            return std::process::ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cannot start the runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let (_engine, router) = match spindle_operator::build(&config, BTreeMap::new()) {
            Ok(built) => built,
            Err(error) => {
                eprintln!(
                    "cannot open {}: {error}",
                    config.operator.data_dir.display()
                );
                return std::process::ExitCode::FAILURE;
            }
        };
        let listener = match tokio::net::TcpListener::bind(config.operator.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("cannot listen on {}: {error}", config.operator.listen);
                return std::process::ExitCode::FAILURE;
            }
        };
        tracing::info!(listen = %config.operator.listen, "spindle-operator ready");
        // No graceful drain is needed for correctness: every step is
        // checkpointed before it runs, so a stop at any instant resumes
        // cleanly. Ctrl-C ends the process; the journal is already synced.
        let serve = axum::serve(listener, router).with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        match serve.await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("server error: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    })
}
