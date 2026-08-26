//! The route table, and the router built from it.
//!
//! One table, so [`surface`](crate::surface)'s claims can be checked against
//! what is actually mounted rather than against a second list that agrees with
//! the first only until someone edits one of them.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};

use crate::{AppState, surface};

/// Every path this server answers.
///
/// Exposed so a test can compare it against [`surface::required_routes`].
pub const MOUNTED: &[&str] = &[
    "/_matrix/client/versions",
    "/_matrix/client/v3/capabilities",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/health",
    "/ready",
];

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .with_state(state)
}

/// `GET /_matrix/client/versions`
async fn versions() -> Json<Value> {
    let mut unstable = serde_json::Map::new();
    for (feature, enabled) in surface::UNSTABLE_FEATURES {
        unstable.insert((*feature).to_owned(), json!(enabled));
    }
    Json(json!({
        "versions": surface::spec_version_names(),
        "unstable_features": Value::Object(unstable),
    }))
}

/// `GET /_matrix/client/v3/capabilities`
///
/// Room-version capability is omitted entirely rather than sent empty: the spec
/// treats a missing capability as "unknown, assume the default", whereas an
/// empty `available` map is a positive claim that no room version works. Until
/// rooms exist (#7) the honest thing is to say nothing, not to say none.
async fn capabilities() -> Json<Value> {
    let mut capabilities = serde_json::Map::new();
    if let Some(default) = surface::DEFAULT_ROOM_VERSION {
        let available: serde_json::Map<String, Value> = surface::ROOM_VERSIONS
            .iter()
            .map(|version| ((*version).to_owned(), json!("stable")))
            .collect();
        capabilities.insert(
            "m.room_versions".to_owned(),
            json!({ "default": default, "available": Value::Object(available) }),
        );
    }
    Json(json!({ "capabilities": Value::Object(capabilities) }))
}

/// `GET /.well-known/matrix/client`
async fn well_known_client(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "m.homeserver": { "base_url": state.config.client_base_url() },
    }))
}

/// `GET /.well-known/matrix/server`
///
/// Served so a peer resolving this server name finds the port it actually
/// listens on rather than assuming 8448.
async fn well_known_server(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "m.server": state.config.server.name }))
}

/// Liveness: the process is up.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Readiness: the process can serve.
///
/// Currently the same answer as liveness, which is honest only because nothing
/// is initialised asynchronously yet. When storage opens here, this has to stop
/// reporting ready before it is — a readiness probe that lies is worse than no
/// readiness probe, because it takes traffic on the strength of the lie.
async fn ready() -> StatusCode {
    StatusCode::OK
}
