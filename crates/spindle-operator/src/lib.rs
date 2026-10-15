//! `spindle-operator`: the standalone control plane for a Spindle
//! deployment (#455, #457).
//!
//! It runs as its own process, with its own state on its own disk, so it
//! stays up while the homeservers it manages are stopped — which is
//! exactly when an operator needs it most: during a migration's source
//! seal, a cutover, or a recovery.
//!
//! - [`engine`]: durable operations — checkpointed steps, leases,
//!   approvals, cancellation and compensation — over the append-only
//!   [`journal`].
//! - [`driver`]: the interface deployment-specific code implements.
//! - [`auth`]: OIDC-backed browser sessions, CSRF, and roles.
//! - [`api`]: `/_spindle/operator/v1`, shared by the console and the CLI.
//! - [`homeserver`]: read-only people, rooms and reports, fetched with a
//!   connection's admin credential so the browser never holds one.
//! - [`console`]: the browser console (#458), static files over the API.
//! - [`secret`]: secrets by reference, and the redaction on every exit.

pub mod api;
pub mod auth;
pub mod config;
pub mod console;
pub mod driver;
pub mod engine;
pub mod error;
pub mod homeserver;
pub mod journal;
pub mod model;
pub mod secret;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderValue, header};
use axum::response::Response;

use crate::auth::{AppState, Auth};
use crate::config::Config;
use crate::driver::{Driver, ExecDriver};
use crate::engine::Engine;

/// How often expired evidence is deleted.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Headers every response carries. The console is never framed, never
/// sniffed, never cached by an intermediary, and never leaks its URLs
/// (which carry operation ids) to another site.
async fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // The console's own pages set a policy that lets them load their
    // script and style from this origin; everything else gets none.
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'",
        ));
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Open the engine and build the router.
///
/// `extra` adds in-process drivers alongside the configured programs; a
/// name in both is an error rather than a silent override.
///
/// # Errors
///
/// When the journal cannot be opened, or a driver is misconfigured.
pub fn build(
    config: &Config,
    extra: BTreeMap<String, Arc<dyn Driver>>,
) -> std::io::Result<(Arc<Engine>, Router)> {
    let mut drivers: BTreeMap<String, Arc<dyn Driver>> = BTreeMap::new();
    for (name, driver) in &config.drivers {
        let driver = ExecDriver::new(driver.clone()).map_err(std::io::Error::other)?;
        drivers.insert(name.clone(), Arc::new(driver));
    }
    for (name, driver) in extra {
        if drivers.insert(name.clone(), driver).is_some() {
            return Err(std::io::Error::other(format!(
                "driver `{name}` is defined twice"
            )));
        }
    }
    let engine = Engine::open(
        config.operator.data_dir.clone(),
        drivers,
        Duration::from_secs(config.operator.artifact_ttl_secs),
        Duration::from_secs(config.operator.probe_timeout_secs),
    )?;
    let sweeper = Arc::downgrade(&engine);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            let Some(engine) = sweeper.upgrade() else {
                return;
            };
            engine.sweep_artifacts().await;
        }
    });
    let auth = Arc::new(Auth::new(
        config.oidc.clone(),
        config.operator.public_url.clone(),
        Duration::from_secs(config.operator.session_ttl_secs),
    ));
    let state = AppState {
        engine: Arc::clone(&engine),
        auth,
    };
    let router = Router::new()
        .merge(auth::routes())
        .merge(api::routes())
        .merge(homeserver::routes())
        .merge(console::routes())
        .fallback(api::fallback)
        .layer(axum::middleware::map_response(harden))
        .with_state(state);
    Ok((engine, router))
}
