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

use axum::extract::ConnectInfo;
use std::net::SocketAddr;

use crate::accounts::{AccountError, Accounts};
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::ratelimit::{FAILED_LOGIN_PER_ACCOUNT, FAILED_LOGIN_PER_SOURCE, REGISTER_PER_SOURCE};
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
    "/_matrix/client/v3/refresh",
    "/_matrix/client/v3/account/whoami",
    "/_matrix/client/v3/createRoom",
    "/_matrix/client/v3/joined_rooms",
    "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
    "/_matrix/client/v3/rooms/{room_id}/messages",
    "/_matrix/client/v3/rooms/{room_id}/invite",
    "/_matrix/client/v3/rooms/{room_id}/join",
    "/_matrix/client/v3/rooms/{room_id}/leave",
    "/_matrix/client/v3/join/{room_id_or_alias}",
    "/_matrix/key/v2/server",
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
        .route("/_matrix/client/v3/refresh", post(refresh))
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        .route("/_matrix/client/v3/createRoom", post(create_room))
        .route("/_matrix/client/v3/joined_rooms", get(joined_rooms))
        .route(
            "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
            axum::routing::put(send_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/messages",
            get(room_messages),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/invite",
            post(invite_to_room),
        )
        .route("/_matrix/client/v3/rooms/{room_id}/join", post(join_room))
        .route("/_matrix/client/v3/rooms/{room_id}/leave", post(leave_room))
        .route(
            "/_matrix/client/v3/join/{room_id_or_alias}",
            post(join_room_by_id_or_alias),
        )
        .route("/_matrix/key/v2/server", get(server_keys))
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
    #[serde(default)]
    refresh_token: bool,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterRequest {
    username: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
    #[serde(default)]
    inhibit_login: bool,
    #[serde(default)]
    refresh_token: bool,
    auth: Option<Value>,
}

/// The login/register/refresh response body.
///
/// `refresh_token` and `expires_in_ms` are omitted when the client did not ask
/// for refresh, rather than sent null: a client checks for the key's presence
/// to decide whether to schedule a renewal.
fn session_body(user_id: &str, session: &crate::accounts::Session) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("user_id".to_owned(), json!(user_id));
    body.insert("access_token".to_owned(), json!(session.access_token));
    body.insert("device_id".to_owned(), json!(session.device.device_id));
    if let Some(refresh) = &session.refresh_token {
        body.insert("refresh_token".to_owned(), json!(refresh));
    }
    if let Some(expires) = session.expires_in_ms {
        body.insert("expires_in_ms".to_owned(), json!(expires));
    }
    Value::Object(body)
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
    source: ClientAddr,
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

    // Both keys are checked before the password is, so a caller already over
    // the limit does not get a free Argon2 verification out of each attempt.
    let account_key = format!("login:account:{localpart}");
    let source_key = format!("login:source:{source}");
    for (key, limit) in [
        (&account_key, FAILED_LOGIN_PER_ACCOUNT),
        (&source_key, FAILED_LOGIN_PER_SOURCE),
    ] {
        if let Err(retry) = state.limiter.check(key, limit) {
            return Err(MatrixError::limit_exceeded(retry.as_millis()));
        }
    }

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

    // A correct login is not the traffic being defended against, and counting
    // it would lock out the legitimate users of a busy shared address first.
    state.limiter.forget(&account_key);
    state.limiter.forget(&source_key);

    let session = accounts
        .create_session(
            &localpart,
            request.device_id,
            request.initial_device_display_name,
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;

    Ok(Json(session_body(&accounts.user_id(&localpart), &session)))
}

/// `POST /_matrix/client/v3/refresh`
///
/// Unauthenticated by design: the refresh token *is* the credential, and a
/// client refreshing precisely because its access token expired has nothing
/// else to present.
async fn refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let session = accounts
        .refresh(&request.refresh_token)
        .map_err(|error| match error {
            AccountError::UnknownToken => MatrixError::unknown_token(),
            other => internal(&other),
        })?;
    let user_id = accounts.user_id(&session.device.localpart);
    Ok(Json(session_body(&user_id, &session)))
}

/// `POST /_matrix/client/v3/register`
///
/// One UIA stage, `m.login.dummy`: the first request without `auth` gets a 401
/// carrying the flows, and the client repeats it with the stage completed. The
/// dance is not decoration — clients implement UIA generically and a server
/// that skips it for registration makes them special-case it.
async fn register(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Counted after the UIA hand-shake, so the mandatory first 401 does not
    // spend a client's budget on the flow the server itself required.
    if request.auth.is_some()
        && let Err(retry) = state
            .limiter
            .check(&format!("register:source:{source}"), REGISTER_PER_SOURCE)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }

    if request.auth.is_none() {
        return Err(MatrixError {
            status: StatusCode::UNAUTHORIZED,
            errcode: "M_FORBIDDEN",
            retry_after_ms: None,
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

    let session = accounts
        .create_session(
            username,
            request.device_id,
            request.initial_device_display_name,
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;
    Ok(Json(session_body(&user_id, &session)))
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

/// The caller's address, as far as it can be known.
///
/// Behind a reverse proxy every request appears to come from the proxy, which
/// would collapse the per-source limit onto a single key and make it useless.
/// Reading a forwarding header instead is worse: any client can set it, so the
/// limit becomes opt-out. Until the deployment can say which proxies it trusts,
/// the peer address is the only value that is not attacker-controlled — and the
/// per-account limit is the one that still bites in that case, which is why
/// both exist.
pub struct ClientAddr(String);

impl std::fmt::Display for ClientAddr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map_or_else(|| "unknown".to_owned(), |info| info.0.ip().to_string()),
        ))
    }
}

/// `GET /_matrix/key/v2/server`
///
/// Publishes the *public* half of this server's signing key, so a peer can
/// verify events we signed.
///
/// `valid_until_ts` is a re-fetch hint, not an expiry the spec enforces. It is
/// deliberately short-ish: a peer that caches this for a long time keeps
/// trusting a key we may have had to rotate, and the cost of it being wrong is
/// borne by whoever has to explain why signatures stopped verifying.
async fn server_keys(State(state): State<AppState>) -> Json<Value> {
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis().saturating_add(24 * 60 * 60 * 1000))
        .unwrap_or_default();

    Json(json!({
        "server_name": state.config.server.name,
        "valid_until_ts": u64::try_from(valid_until).unwrap_or(u64::MAX),
        "verify_keys": {
            state.key.key_id(): { "key": state.key.public_key_base64() },
        },
        // No key has been retired, and saying so explicitly is not the same as
        // omitting it: a peer reads this to decide whether a signature made
        // with an old key should still be honoured.
        "old_verify_keys": {},
    }))
}

#[derive(Debug, Default, Deserialize)]
struct CreateRoomRequest {
    name: Option<String>,
    topic: Option<String>,
}

/// `POST /_matrix/client/v3/createRoom`
async fn create_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CreateRoomRequest>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = state
        .rooms
        .create(
            &identity.user_id,
            state.key.pair(),
            request.name.as_deref(),
            request.topic.as_deref(),
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "room_id": room_id })))
}

/// `GET /_matrix/client/v3/joined_rooms`
async fn joined_rooms(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let rooms = state
        .rooms
        .joined(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "joined_rooms": rooms })))
}

#[derive(Debug, Deserialize)]
struct InviteRequest {
    user_id: String,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/invite`
async fn invite_to_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<InviteRequest>,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_membership(
            &room_id,
            &identity.user_id,
            &request.user_id,
            "invite",
            state.key.pair(),
        )
        .map_err(membership_error)?;
    // The spec's response is an empty object, not the event ID. A client that
    // wanted the event reads it from the timeline.
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/join`
async fn join_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    join(&state, &identity.user_id, &room_id)
}

/// `POST /_matrix/client/v3/join/{room_id_or_alias}`
///
/// Aliases do not resolve yet, so this accepts room IDs only and says so
/// rather than pretending: an alias returns `M_NOT_FOUND` from the room lookup
/// below, which is the truthful answer for a name this server cannot resolve.
async fn join_room_by_id_or_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    join(&state, &identity.user_id, &room_id_or_alias)
}

fn join(state: &AppState, user_id: &str, room_id: &str) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_membership(room_id, user_id, user_id, "join", state.key.pair())
        .map_err(membership_error)?;
    Ok(Json(json!({ "room_id": room_id })))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/leave`
async fn leave_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_membership(
            &room_id,
            &identity.user_id,
            &identity.user_id,
            "leave",
            state.key.pair(),
        )
        .map_err(membership_error)?;
    Ok(Json(json!({})))
}

fn membership_error(error: crate::rooms::RoomError) -> MatrixError {
    match error {
        crate::rooms::RoomError::UnknownRoom(_) => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such room")
        }
        crate::rooms::RoomError::Forbidden(rule) => MatrixError::forbidden(rule),
        other => MatrixError::internal(&other.to_string()),
    }
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`
async fn send_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, _txn_id)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    // The transaction ID is accepted and ignored. Idempotent replay is real
    // work -- storing the response against the ID and returning it on a repeat
    // -- and claiming it by accepting the parameter would be worse than not
    // taking it at all: a client retrying after a timeout would silently
    // duplicate its message. Tracked as the remaining item on #11.
    let event_id = state
        .rooms
        .send(
            &room_id,
            &identity.user_id,
            state.key.pair(),
            &event_type,
            &content,
        )
        .map_err(|error| match error {
            crate::rooms::RoomError::UnknownRoom(_) => {
                MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such room")
            }
            // The message is ruma's own wording for the rule that refused,
            // which is the same explanation a federating peer would give. A
            // generic "forbidden" would make a client's bug report useless.
            crate::rooms::RoomError::Forbidden(rule) => MatrixError::forbidden(rule),
            other => MatrixError::internal(&other.to_string()),
        })?;
    Ok(Json(json!({ "event_id": event_id })))
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    from: Option<String>,
    limit: Option<usize>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/messages`
///
/// The pagination token is the linear index, which is what SPEC 10.2's
/// "tokens are opaque to clients" buys: the ordering already exists, so there
/// is nothing to sort at read time and nothing to maintain alongside.
async fn room_messages(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let from = match query.from.as_deref() {
        Some(token) => Some(
            token
                .parse::<i64>()
                .map_err(|_| MatrixError::bad_json("malformed pagination token"))?,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(10).clamp(1, 100);

    let (events, next) =
        state
            .rooms
            .messages(&room_id, from, limit)
            .map_err(|error| match error {
                crate::rooms::RoomError::UnknownRoom(_) => {
                    MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such room")
                }
                other => MatrixError::internal(&other.to_string()),
            })?;

    let chunk: Vec<Value> = events
        .iter()
        .map(|event| {
            let mut json = event.json.clone();
            if let Some(object) = json.as_object_mut() {
                object.insert("event_id".to_owned(), json!(event.event_id));
            }
            json
        })
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    body.insert(
        "start".to_owned(),
        json!(from.map_or_else(|| "end".to_owned(), |from| from.to_string())),
    );
    // Absent when there is nothing more, which is how a client knows to stop.
    if let Some(next) = next {
        body.insert("end".to_owned(), json!(next.to_string()));
    }
    Ok(Json(Value::Object(body)))
}
