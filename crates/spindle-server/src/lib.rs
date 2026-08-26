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
pub mod config;
pub mod errors;
pub mod push_rules;
pub mod ratelimit;
pub mod rooms;
pub mod routes;
pub mod signing;
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
    let account_data = Arc::new(account_data::AccountData::new(Arc::clone(&store)));
    let state = AppState {
        config: Arc::new(config),
        store,
        limiter,
        key,
        rooms,
        typing: Arc::new(typing::Typing::new()),
        account_data,
    };
    Ok(routes::router(state))
}
