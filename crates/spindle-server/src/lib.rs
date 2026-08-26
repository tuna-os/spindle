//! The Spindle homeserver's HTTP surface.
//!
//! What this crate is careful about, beyond wiring: **it does not advertise
//! anything it has not implemented.** See [`surface`] — the list of spec
//! versions and features `/versions` reports is derived from the same route
//! table that builds the router, so claiming something unbuilt is a
//! compile-or-test failure rather than a documentation drift.

pub mod config;
pub mod routes;
pub mod surface;

use std::sync::Arc;

use axum::Router;

pub use config::{Config, ConfigError};

/// Everything a handler needs.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

/// Build the HTTP application.
pub fn app(config: Config) -> Router {
    let state = AppState {
        config: Arc::new(config),
    };
    routes::router(state)
}
