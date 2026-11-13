//! Discovery: the well-known documents, versions, capabilities, auth
//! metadata, and the health and readiness probes.

use crate::errors::MatrixError;
use crate::routes::rtc_transports;
use crate::{AppState, surface};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/support", get(well_known_support))
        .route("/_matrix/client/v1/auth_metadata", get(auth_metadata))
        // The unstable alias is load-bearing: Element Web's js-sdk asks
        // here first, and a deployment serving only the stable path
        // looks to it like a server with no delegation at all.
        .route(
            "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
            get(auth_metadata),
        )
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/health", get(health))
        .route("/ready", get(ready))
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
async fn capabilities(State(state): State<AppState>) -> Json<Value> {
    let mut capabilities = serde_json::Map::new();
    // MSC4140: both limits, which the server must enforce and so must
    // state, under the stable name and the unstable one clients read today.
    let (max_delay_ms, max_scheduled) = state.delayed.limits();
    let delayed = json!({ "max_delay_ms": max_delay_ms, "max_scheduled": max_scheduled });
    capabilities.insert("m.delayed_events".to_owned(), delayed.clone());
    capabilities.insert("org.matrix.msc4140.delayed_events".to_owned(), delayed);
    if let Some(default) = surface::DEFAULT_ROOM_VERSION {
        let available: serde_json::Map<String, Value> = surface::ROOM_VERSIONS
            .iter()
            .map(|version| {
                let stability = if *version == spindle_core::STATE_DAG_V12 {
                    "unstable"
                } else {
                    "stable"
                };
                ((*version).to_owned(), json!(stability))
            })
            .collect();
        capabilities.insert(
            "m.room_versions".to_owned(),
            json!({ "default": default, "available": Value::Object(available) }),
        );
    }
    capabilities.insert("m.get_login_token".to_owned(), json!({ "enabled": true }));
    Json(json!({ "capabilities": Value::Object(capabilities) }))
}

/// How long a well-known document may be reused, in seconds.
///
/// Both documents are configuration this server publishes about itself,
/// and both are read by things that cache. Without a header the caching
/// is somebody else's default, and the defaults are long: the
/// server-server spec tells a peer with no header to assume **24 hours**
/// (capping at 48), and a browser is free to pick a heuristic of its own
/// for the client document. That is the shape of the problem #37 names --
/// an operator changes a setting, restarts, and the change is not visible
/// for a day, from a server that is already serving the new answer.
///
/// An hour is a deliberate trade rather than a spec value, because the
/// spec gives none for the client document and only a default for the
/// other. It bounds propagation to something an operator can wait out
/// while a fetch per peer per hour is nothing next to the traffic a peer
/// already sends. The spec explicitly says a peer should respect the
/// header when it is present, so this shortens the 24-hour default rather
/// than fighting it.
const WELL_KNOWN_MAX_AGE_SECONDS: u32 = 3600;

/// A well-known document, with the caching this server chose.
fn well_known(body: Value) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            format!("public, max-age={WELL_KNOWN_MAX_AGE_SECONDS}"),
        )],
        Json(body),
    )
}

/// `GET /.well-known/matrix/client`
async fn well_known_client(
    State(state): State<AppState>,
) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    let mut body = json!({
        "m.homeserver": { "base_url": state.config.client_base_url() },
    });
    // MSC2965: a delegated deployment names its issuer here, which is
    // how a client knows to speak OIDC before it ever hits /login.
    if let Some(delegated) = &state.delegated {
        body["org.matrix.msc2965.authentication"] = json!({
            "issuer": delegated.issuer(),
            "account": format!("{}/account", delegated.issuer().trim_end_matches('/')),
        });
    } else if state.oidc.is_some() {
        // The built-in provider is its own issuer, and serves its own
        // account pages (#607).
        body["org.matrix.msc2965.authentication"] = json!({
            "issuer": format!("{}/", crate::oidc::issuer(&state)),
            "account": crate::account::management_uri(&state),
        });
    }
    // MSC4143 (which absorbed MSC4158): the MatrixRTC backend, named here
    // as well as on `/rtc/transports` because a client discovers calls
    // before it has a token to ask with. Omitted entirely when nothing is
    // configured -- an empty array here would be a positive claim to have
    // no backend, where absence is "this server does not answer that".
    let foci = rtc_transports(&state);
    if !foci.is_empty() {
        body["org.matrix.msc4143.rtc_foci"] = Value::Array(foci);
    }
    well_known(body)
}

/// `GET /_matrix/client/v1/auth_metadata`
///
/// MSC2965's discovery endpoint: the provider's own `OpenID Connect`
/// metadata document, relayed. A non-delegated deployment answers 404
/// `M_UNRECOGNIZED` — the endpoint's absence is how a client learns this
/// server does its own auth.
async fn auth_metadata(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    if state.oidc.is_some() {
        return Ok(Json(crate::oidc::metadata(&state)));
    }
    let Some(delegated) = &state.delegated else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "authentication is not delegated",
        ));
    };
    Ok(Json(delegated.metadata().await?))
}

/// `GET /.well-known/matrix/server`
///
/// Served so a peer resolving this server name finds the port it actually
/// listens on rather than assuming 8448.
async fn well_known_server(
    State(state): State<AppState>,
) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    well_known(json!({ "m.server": state.config.server.name }))
}

/// Liveness: the process is up.
///
/// Takes no state and no lock -- not the room registry, not a room --
/// and must stay that way: it answers whenever a worker can poll it, and
/// #614 is about making sure one always can, by keeping room work off the
/// async workers. A liveness answer that waited on the work it is meant
/// to see past would get a busy server killed.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Readiness: the process can serve.
///
/// Storage is open, the stream counters resumed and the signing key loaded
/// before the listener accepts anything, so by the time this can answer at
/// all the server can serve every request. It does **not** wait for the
/// startup room warm-up (`spawn_room_warmup`): a room of a million events
/// takes minutes to load, and holding a single-replica deployment out of
/// rotation for that long is an outage bought to avoid a slow first
/// request. A room not yet warm is loaded by the request that needs it,
/// off the async workers.
///
/// What it does wait on is the store: once the engine refuses a write (a
/// full disk, a failing one) it refuses every write after it, and a server
/// that answers `/sync` but fails every `/send` with a 500 is not one to
/// route clients to. A readiness probe that lies is worse than none.
///
/// Liveness stays up on purpose. The process is fine and its disk is not;
/// restarting it onto the same full disk only adds a crash loop to the page.
/// The remedy is in `docs/lifecycle.md`, under "A full disk".
async fn ready(State(state): State<AppState>) -> StatusCode {
    if spindle_store::Store::accepts_writes(state.store.as_ref()) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `GET /.well-known/matrix/support` (spec v1.10)
///
/// Who to contact about this server. Unconfigured, it is a 404 rather
/// than an empty list: the spec reads an empty answer as "nobody", and
/// "not published" is the truer thing to say.
async fn well_known_support(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    let Some(support) = &state.config.server.support else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "this server publishes no support contacts",
        ));
    };
    let contacts: Vec<Value> = support
        .contacts
        .iter()
        .map(|contact| {
            let mut entry = serde_json::Map::new();
            if let Some(matrix_id) = &contact.matrix_id {
                entry.insert("matrix_id".to_owned(), json!(matrix_id));
            }
            if let Some(email) = &contact.email_address {
                entry.insert("email_address".to_owned(), json!(email));
            }
            entry.insert("role".to_owned(), json!(contact.role));
            Value::Object(entry)
        })
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("contacts".to_owned(), Value::Array(contacts));
    if let Some(page) = &support.support_page {
        body.insert("support_page".to_owned(), json!(page));
    }
    Ok(Json(Value::Object(body)))
}
