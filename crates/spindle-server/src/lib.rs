//! The Spindle homeserver's HTTP surface.
//!
//! What this crate is careful about, beyond wiring: **it does not advertise
//! anything it has not implemented.** See [`surface`] — the list of spec
//! versions and features `/versions` reports is derived from the same route
//! table that builds the router, so claiming something unbuilt is a
//! compile-or-test failure rather than a documentation drift.

pub mod account_data;
pub mod accounts;
pub mod auth;
pub mod authorize;
pub mod backups;
pub mod blobs;
pub mod config;
pub mod devices;
pub mod directory;
pub mod errors;
pub mod federation;
pub mod filters;
pub mod media;
pub mod previews;
pub mod push_rules;
pub mod ratelimit;
pub mod rooms;
pub mod routes;
pub mod s3;
pub mod signing;
pub mod sliding;
pub mod surface;
pub mod tokens;
pub mod typing;

use std::sync::Arc;

use axum::Router;
use spindle_store::FjallStore;

pub use config::{Config, ConfigError};

/// Everything a handler needs.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<FjallStore>,
    pub limiter: Arc<ratelimit::RateLimiter>,
    pub key: Arc<signing::ServerKey>,
    pub rooms: Arc<rooms::Rooms>,
    pub typing: Arc<typing::Typing>,
    pub account_data: Arc<account_data::AccountData>,
    pub directory: Arc<directory::Directory>,
    pub filters: Arc<filters::Filters>,
    pub media: Arc<media::Media>,
    pub devices: Arc<devices::Devices>,
    pub backups: Arc<backups::Backups>,
    pub previews: Arc<previews::Previews>,
    pub federation: Arc<federation::Federation>,
}

/// Why the application cannot be built. Both are startup-fatal on purpose:
/// a server without a signing key cannot create a single valid event, and a
/// preview allow-list that failed to parse must not fail *open*.
#[derive(Debug)]
pub enum AppError {
    Signing(signing::SigningError),
    PreviewConfig(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signing(error) => write!(formatter, "signing key: {error}"),
            Self::PreviewConfig(why) => write!(formatter, "preview config: {why}"),
        }
    }
}

impl std::error::Error for AppError {}

/// Build the HTTP application.
///
/// # Errors
///
/// Returns [`AppError`] if the server's signing key can be neither loaded
/// nor created, or if the preview allow-list does not parse. Fatal rather
/// than degraded in both cases — see [`AppError`].
pub fn app(config: Config, store: Arc<FjallStore>) -> Result<Router, AppError> {
    let key =
        Arc::new(signing::ServerKey::load_or_create(store.as_ref()).map_err(AppError::Signing)?);
    let rooms = Arc::new(rooms::Rooms::new(
        Arc::clone(&store),
        config.server.name.clone(),
    ));
    let limiter = Arc::new(ratelimit::RateLimiter::with_enabled(
        config.ratelimit.enabled,
    ));
    let store_for_filters = Arc::clone(&store);
    let store_for_devices = Arc::clone(&store);
    let store_for_backups = Arc::clone(&store);
    let account_data = Arc::new(account_data::AccountData::new(Arc::clone(&store)));
    let blobs = match &config.storage.s3 {
        Some(s3) => blobs::Blobs::S3(s3::S3Client::new(
            s3.endpoint.clone(),
            s3.bucket.clone(),
            s3.region.clone(),
            s3.access_key_id.clone(),
            s3.secret_access_key.clone(),
        )),
        None => blobs::Blobs::Local {
            root: config.storage.path.join("media"),
        },
    };
    let media = Arc::new(media::Media::new(
        Arc::clone(&store),
        blobs,
        config.server.name.clone(),
    ));
    let directory = Arc::new(directory::Directory::new(
        Arc::clone(&store),
        config.server.name.clone(),
    ));
    let previews = Arc::new(
        previews::Previews::new(
            Arc::clone(&store),
            Arc::clone(&media),
            &config.previews.allow_private,
        )
        .map_err(|error| AppError::PreviewConfig(error.to_string()))?,
    );
    let federation = Arc::new(federation::Federation::new(
        Arc::clone(&store),
        config.server.name.clone(),
        Arc::clone(&key),
        config.federation.insecure_http,
    ));
    let state = AppState {
        config: Arc::new(config),
        store,
        limiter,
        key,
        rooms,
        typing: Arc::new(typing::Typing::new()),
        account_data,
        directory,
        filters: Arc::new(filters::Filters::new(Arc::clone(&store_for_filters))),
        media,
        devices: Arc::new(devices::Devices::new(store_for_devices)),
        backups: Arc::new(backups::Backups::new(store_for_backups)),
        previews,
        federation,
    };
    // The outbound drain runs for the life of the process. Spawned only
    // when a runtime is running — which is every real caller; a build
    // outside one gets a router that serves but never sends, and the
    // absence of a runtime is that caller's own statement of intent.
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(federation::drain_outbox(
            Arc::clone(&state.store),
            Arc::clone(&state.federation),
            std::time::Duration::from_millis(state.config.federation.retry_base_ms),
        ));
    }
    Ok(routes::router(state))
}
