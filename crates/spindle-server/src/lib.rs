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
pub mod config;
pub mod devices;
pub mod directory;
pub mod errors;
pub mod filters;
pub mod media;
pub mod push_rules;
pub mod ratelimit;
pub mod rooms;
pub mod routes;
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
}

/// Build the HTTP application.
///
/// # Errors
///
/// Returns [`signing::SigningError`] if the server's signing key can be neither
/// loaded nor created. Fatal rather than degraded: a server without a key
/// cannot create a single valid event, so starting anyway would mean accepting
/// writes it can only produce invalid results for.
pub fn app(config: Config, store: Arc<FjallStore>) -> Result<Router, signing::SigningError> {
    let key = Arc::new(signing::ServerKey::load_or_create(store.as_ref())?);
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
    let media = Arc::new(media::Media::new(
        Arc::clone(&store),
        config.storage.path.join("media"),
        config.server.name.clone(),
    ));
    let directory = Arc::new(directory::Directory::new(
        Arc::clone(&store),
        config.server.name.clone(),
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
    };
    Ok(routes::router(state))
}
