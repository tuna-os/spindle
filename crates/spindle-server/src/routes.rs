//! The route table, and the router built from it.
//!
//! One table, so [`surface`](crate::surface)'s claims can be checked against
//! what is actually mounted rather than against a second list that agrees with
//! the first only until someone edits one of them.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::accounts::{AccountError, Accounts};
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::{AppState, surface};

/// Every path this server answers.
///
/// Exposed so a test can compare it against [`surface::required_routes`].
pub const MOUNTED: &[&str] = &[
    "/_matrix/client/versions",
    "/_matrix/client/v3/capabilities",
    "/_matrix/client/v3/register",
    "/_matrix/client/v3/login",
    "/_matrix/client/v3/logout",
    "/_matrix/client/v3/account/whoami",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/health",
    "/ready",
];

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/_matrix/client/v3/register", post(register))
        .route("/_matrix/client/v3/login", get(login_flows).post(login))
        .route("/_matrix/client/v3/logout", post(logout))
        .route("/_matrix/client/v3/account/whoami", get(whoami))
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

/// The identifier half of a login request.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Identifier {
    #[serde(rename = "m.id.user")]
    User { user: String },
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(rename = "type")]
    kind: String,
    identifier: Option<Identifier>,
    /// The deprecated top-level form, still sent by older clients.
    user: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterRequest {
    username: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
    #[serde(default)]
    inhibit_login: bool,
    auth: Option<Value>,
}

/// `GET /_matrix/client/v3/login`
///
/// Only password login. SSO and token login are advertised by servers that
/// implement them; listing a flow we cannot complete would send a client down
/// a path that dead-ends.
async fn login_flows() -> Json<Value> {
    Json(json!({ "flows": [{ "type": "m.login.password" }] }))
}

/// `POST /_matrix/client/v3/login`
async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Value>, MatrixError> {
    if request.kind != "m.login.password" {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            format!("unsupported login type {:?}", request.kind),
        ));
    }

    let localpart = match (&request.identifier, &request.user) {
        (Some(Identifier::User { user }), _) | (None, Some(user)) => localpart_of(user),
        (None, None) => return Err(MatrixError::bad_json("no user identifier")),
    };
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no password"))?;

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    // One message for a wrong password and for an unknown user. The
    // verification cost is already equal (see `verify_password`); saying
    // "no such user" here would give the difference back for free.
    if !accounts
        .verify_password(&localpart, password)
        .map_err(|error| internal(&error))?
    {
        return Err(MatrixError::forbidden("invalid username or password"));
    }

    let (token, device) = accounts
        .create_session(
            &localpart,
            request.device_id,
            request.initial_device_display_name,
        )
        .map_err(|error| internal(&error))?;

    Ok(Json(json!({
        "user_id": accounts.user_id(&localpart),
        "access_token": token,
        "device_id": device.device_id,
    })))
}

/// `POST /_matrix/client/v3/register`
///
/// One UIA stage, `m.login.dummy`: the first request without `auth` gets a 401
/// carrying the flows, and the client repeats it with the stage completed. The
/// dance is not decoration — clients implement UIA generically and a server
/// that skips it for registration makes them special-case it.
async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<Value>, MatrixError> {
    if request.auth.is_none() {
        return Err(MatrixError {
            status: StatusCode::UNAUTHORIZED,
            errcode: "M_FORBIDDEN",
            error: serde_json::to_string(&json!({
                "flows": [{ "stages": ["m.login.dummy"] }],
                "params": {},
                "session": "register",
            }))
            .unwrap_or_default(),
        });
    }

    let username = request
        .username
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no username"))?;
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no password"))?;

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .register(username, password)
        .map_err(|error| match error {
            AccountError::UserInUse => MatrixError::user_in_use(),
            AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => MatrixError::internal(&other.to_string()),
        })?;

    let user_id = accounts.user_id(username);
    if request.inhibit_login {
        return Ok(Json(json!({ "user_id": user_id })));
    }

    let (token, device) = accounts
        .create_session(
            username,
            request.device_id,
            request.initial_device_display_name,
        )
        .map_err(|error| internal(&error))?;
    Ok(Json(json!({
        "user_id": user_id,
        "access_token": token,
        "device_id": device.device_id,
    })))
}

/// `POST /_matrix/client/v3/logout`
async fn logout(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts.logout(&token).map_err(|error| internal(&error))?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/account/whoami`
async fn whoami(Authenticated(identity): Authenticated) -> Json<Value> {
    Json(json!({
        "user_id": identity.user_id,
        "device_id": identity.device_id,
    }))
}

/// `@alice:example.org` and `alice` both mean the same localpart.
fn localpart_of(user: &str) -> String {
    user.strip_prefix('@')
        .and_then(|rest| rest.split(':').next())
        .unwrap_or(user)
        .to_owned()
}

fn internal(error: &AccountError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}
