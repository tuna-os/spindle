//! Account endpoints: registration, login, logout, token refresh, password
//! change, deactivation, and the admin holds on an account.

use crate::AppState;
use crate::accounts::{AccountError, Accounts};
use crate::auth::{AccountAuthenticated, Authenticated};
use crate::errors::MatrixError;
use crate::metrics::LoginResult;
use crate::ratelimit::{FAILED_LOGIN_PER_ACCOUNT, FAILED_LOGIN_PER_SOURCE, REGISTER_PER_SOURCE};
use crate::routes::{ClientAddr, internal, localpart_of, optional_body, password_uia};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/admin/whois/{user_id}", get(admin_whois))
        .route(
            "/_matrix/client/v1/admin/lock/{user_id}",
            get(admin_lock_get).put(admin_lock_put),
        )
        .route(
            "/_matrix/client/v1/admin/suspend/{user_id}",
            get(admin_suspend_get).put(admin_suspend_put),
        )
        .route("/_matrix/client/v3/register", post(register))
        .route("/_matrix/client/v3/login", get(login_flows).post(login))
        .route(
            "/_matrix/client/v3/register/available",
            get(register_available),
        )
        .route(
            "/_matrix/client/v1/register/m.login.registration_token/validity",
            get(registration_token_validity),
        )
        .route("/_matrix/client/v3/logout", post(logout))
        .route("/_matrix/client/v3/logout/all", post(logout_all))
        .route("/_matrix/client/v1/login/get_token", post(login_get_token))
        .route("/_matrix/client/v3/refresh", post(refresh))
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        .route("/_matrix/client/v3/account/password", post(change_password))
        .route(
            "/_matrix/client/v3/account/deactivate",
            post(deactivate_account),
        )
}

/// The 404 every legacy auth endpoint answers under MSC3861 delegation:
/// the provider owns login, and a working password path beside it would
/// be a second door with its own keys.
fn delegated_refusal() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "authentication is delegated to the OIDC provider",
    )
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
    /// `m.login.token`: a token from `POST /login/get_token`.
    token: Option<String>,
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
    /// `m.login.application_service` switches registration to the
    /// appservice path: no UIA, the `as_token` is the whole proof.
    #[serde(rename = "type")]
    login_type: Option<String>,
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
/// Password login, and token login for the tokens `POST /login/get_token`
/// mints (spec v1.7), which is what `get_login_token: true` tells an
/// unauthenticated client. SSO is advertised by servers that implement it;
/// listing a flow we cannot complete would send a client down a path that
/// dead-ends.
async fn login_flows(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(delegated_refusal());
    }
    Ok(Json(json!({ "flows": [
        { "type": "m.login.password" },
        { "type": "m.login.token", "get_login_token": true },
    ] })))
}

/// The `m.login.token` half of `POST /login`: one token, one session.
fn login_with_token(state: &AppState, request: LoginRequest) -> Result<Json<Value>, MatrixError> {
    let token = request
        .token
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no token"))?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = accounts
        .redeem_login_token(token)
        .map_err(|error| match error {
            AccountError::UnknownToken => MatrixError::forbidden("the login token is not valid"),
            other => internal(&other),
        })?;
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

#[derive(Debug, Default, Deserialize)]
struct GetLoginTokenRequest {
    auth: Option<Value>,
}

/// `POST /_matrix/client/v1/login/get_token` (spec v1.7)
///
/// Behind the password stage of UIA, as the spec asks: the token logs a
/// second client in as this user, so minting one is as strong as a login.
async fn login_get_token(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: GetLoginTokenRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "get_login_token",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let (login_token, expires_in_ms) = accounts
        .issue_login_token(&localpart)
        .map_err(|error| internal(&error))?;
    Ok((
        StatusCode::OK,
        Json(json!({ "login_token": login_token, "expires_in_ms": expires_in_ms })),
    ))
}

/// `POST /_matrix/client/v3/login`
async fn login(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(delegated_refusal());
    }
    if request.kind == "m.login.token" {
        return login_with_token(&state, request);
    }
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
            record_password_login(&state, LoginResult::RateLimited);
            return Err(MatrixError::limit_exceeded(retry.as_millis()));
        }
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    // One message for a wrong password and for an unknown user. The
    // verification cost is already equal (see `verify_password`); saying
    // "no such user" here would give the difference back for free.
    let verified = accounts
        .verify_password(&localpart, password)
        .map_err(|error| {
            let result = if matches!(error, AccountError::Busy) {
                LoginResult::RateLimited
            } else {
                LoginResult::Error
            };
            record_password_login(&state, result);
            internal(&error)
        })?;
    if !verified {
        record_password_login(&state, LoginResult::BadPassword);
        return Err(MatrixError::forbidden("invalid username or password"));
    }
    record_password_login(&state, LoginResult::Success);

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

fn record_password_login(state: &AppState, result: LoginResult) {
    state
        .metrics
        .record_login(crate::metrics::LoginMethod::Password, result);
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

#[derive(Debug, Deserialize)]
struct TokenValidityQuery {
    token: Option<String>,
}

/// `GET /_matrix/client/v1/register/m.login.registration_token/validity`
/// (spec v1.2)
///
/// Whether a token would be accepted now. Rate-limited with registration
/// itself: this is the endpoint a guesser would hammer.
async fn registration_token_validity(
    State(state): State<AppState>,
    source: ClientAddr,
    axum::extract::Query(query): axum::extract::Query<TokenValidityQuery>,
) -> Result<Json<Value>, MatrixError> {
    if let Err(retry) = state
        .limiter
        .check(&format!("register:source:{source}"), REGISTER_PER_SOURCE)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    let token = query
        .token
        .ok_or_else(|| MatrixError::missing_param("token is required"))?;
    let valid =
        crate::registration_tokens::RegistrationTokens::new(std::sync::Arc::clone(&state.store))
            .is_valid(&token)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "valid": valid })))
}

/// `Ok(token)` when the stage is complete, `Err(challenge)` to send back.
type StageOutcome = Result<Option<String>, (StatusCode, Json<Value>)>;

/// The one UIA stage registration asks for, and whether `auth` completes
/// it. `Ok(Err(challenge))` is the 401 to send back; `Ok(Ok(token))` is
/// the registration token to spend once the account exists, `None` on an
/// open server.
///
/// With `[registration] require_token` on, the stage is
/// `m.login.registration_token` (spec v1.2) and the token in the auth dict
/// has to be one an admin minted and not yet spent; it is spent by the
/// caller, once the account exists, so a flow that fails later costs
/// nothing.
fn registration_stage(state: &AppState, auth: Option<&Value>) -> Result<StageOutcome, MatrixError> {
    let require_token = state.config.registration.require_token;
    let uia_stage = if require_token {
        "m.login.registration_token"
    } else {
        "m.login.dummy"
    };
    let challenge = |error: Option<(&str, &str)>| {
        let mut body = json!({
            "flows": [{ "stages": [uia_stage] }],
            "params": {},
            "session": "register",
        });
        if let Some((errcode, message)) = error {
            body["errcode"] = json!(errcode);
            body["error"] = json!(message);
        }
        (StatusCode::UNAUTHORIZED, Json(body))
    };
    let stage_completed = if require_token {
        auth.is_some_and(|auth| auth["type"] == uia_stage && auth["token"].is_string())
    } else {
        auth.is_some_and(|auth| auth["session"].is_string() || auth["type"] == "m.login.dummy")
    };
    if !stage_completed {
        return Ok(Err(challenge(None)));
    }
    if !require_token {
        return Ok(Ok(None));
    }
    let token = auth
        .and_then(|auth| auth["token"].as_str())
        .unwrap_or_default()
        .to_owned();
    let valid =
        crate::registration_tokens::RegistrationTokens::new(std::sync::Arc::clone(&state.store))
            .is_valid(&token)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !valid {
        return Ok(Err(challenge(Some((
            "M_UNAUTHORIZED",
            "the registration token is not valid",
        )))));
    }
    Ok(Ok(Some(token)))
}

/// `GET /_matrix/client/v3/register/available`
///
/// The same verdicts registration itself would give, without spending a UIA
/// flow to hear them.
async fn register_available(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, MatrixError> {
    let username = query
        .get("username")
        .ok_or_else(|| MatrixError::bad_json("no username"))?
        .to_lowercase();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    match accounts.availability(&username) {
        Ok(()) => Ok(Json(json!({ "available": true }))),
        Err(AccountError::UserInUse) => Err(MatrixError::user_in_use()),
        Err(AccountError::InvalidUsername) => Err(MatrixError::invalid_username()),
        Err(other) => Err(MatrixError::internal(&other.to_string())),
    }
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
    headers: axum::http::HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    // Under MSC3861 delegation, humans register at the provider — but an
    // appservice still provisions its ghosts here, because the as_token
    // is an authority delegation never displaced.
    if state.delegated.is_some()
        && request.login_type.as_deref() != Some("m.login.application_service")
    {
        return Err(delegated_refusal());
    }
    // Counted after the UIA hand-shake, so the mandatory first 401 does not
    // spend a client's budget on the flow the server itself required.
    if request.auth.is_some()
        && let Err(retry) = state
            .limiter
            .check(&format!("register:source:{source}"), REGISTER_PER_SOURCE)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }

    // Username problems outrank the UIA dance (SPEC: a client should learn
    // M_INVALID_USERNAME or M_USER_IN_USE on its *first* request, before
    // being sent through auth it would complete for nothing), so the checks
    // run even when no auth has been presented yet. Capitals are folded
    // down rather than refused: the localpart grammar is lowercase, and a
    // client typing "Alice" means alice.
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let username = request.username.as_deref().map(str::to_lowercase);
    if let Some(name) = username.as_deref() {
        match accounts.availability(name) {
            Ok(()) => {}
            Err(AccountError::UserInUse) => return Err(MatrixError::user_in_use()),
            Err(AccountError::InvalidUsername) => {
                return Err(MatrixError::invalid_username());
            }
            Err(other) => return Err(MatrixError::internal(&other.to_string())),
        }
    }

    // SPEC (appservice §registration): `m.login.application_service` skips
    // UIA entirely — the as_token in the Authorization header is the whole
    // proof, so it branches before the challenge below.
    if request.login_type.as_deref() == Some("m.login.application_service") {
        return register_appservice_user(&state, &headers, username.as_deref(), &request);
    }

    // An exclusive namespace is a reservation: only its service may create
    // these accounts, through the branch above. Refused before the UIA
    // dance for the same reason the username checks are — a client should
    // not complete auth for a name it can never have.
    if let Some(name) = username.as_deref() {
        let user_id = format!("@{name}:{}", state.config.server.name);
        if state.appservices.exclusively_claims(&user_id) {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_EXCLUSIVE",
                "this localpart is reserved by an application service",
            ));
        }
    }

    // The challenge is the *body* of the 401, not an error wrapping it:
    // SPEC (client-server §UIA) has clients read `flows`/`params`/`session`
    // at the top level, and a challenge folded into an `error` string is
    // invisible to every generic UIA implementation. Complement's
    // RegisterUser is what caught this. An auth dict that names a session
    // completes the stage; so does one that names the dummy stage and no
    // session at all, which is how matrix-rust-sdk (and so Element X)
    // registers: the spec makes `session` optional in the auth dict, the
    // dummy stage carries no state a session would tie back to, and
    // Synapse accepts it. Its integration suite was refused here on every
    // test until this did.
    let registration_token = match registration_stage(&state, request.auth.as_ref())? {
        Ok(token) => token,
        Err(challenge) => return Ok(challenge),
    };

    let username = username.ok_or_else(|| MatrixError::bad_json("no username"))?;
    let username = username.as_str();
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no password"))?;

    accounts
        .register(username, password)
        .map_err(|error| match error {
            AccountError::UserInUse => MatrixError::user_in_use(),
            AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => internal(&other),
        })?;

    let user_id = accounts.user_id(username);
    if let Some(token) = registration_token {
        crate::registration_tokens::RegistrationTokens::new(std::sync::Arc::clone(&state.store))
            .consume(&token)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if request.inhibit_login {
        return Ok((StatusCode::OK, Json(json!({ "user_id": user_id }))));
    }

    let session = accounts
        .create_session(
            username,
            request.device_id,
            request.initial_device_display_name,
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;
    Ok((StatusCode::OK, Json(session_body(&user_id, &session))))
}

/// The `m.login.application_service` branch of registration.
///
/// The account is born with an unguessable password held by nobody,
/// exactly like a ghost provisioned on first masquerade — the appservice
/// door is the only door either kind of account should have. The session
/// returned (unless `inhibit_login`) is a real one; MSC4190's deviceless
/// registration comes later.
fn register_appservice_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    username: Option<&str>,
    request: &RegisterRequest,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    let registration = state
        .appservices
        .by_token(token)
        .ok_or_else(MatrixError::unknown_token)?;
    let username = username.ok_or_else(|| MatrixError::bad_json("no username"))?;
    let server_name = &state.config.server.name;
    let user_id = format!("@{username}:{server_name}");
    if !registration.may_masquerade_as(&user_id, server_name) {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_EXCLUSIVE",
            format!(
                "{user_id} is outside the {} appservice's namespaces",
                registration.id
            ),
        ));
    }
    let accounts = Accounts::new(state.store.as_ref(), server_name);
    accounts
        .register(username, &crate::accounts::unguessable_password())
        .map_err(|error| match error {
            AccountError::UserInUse => MatrixError::user_in_use(),
            AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => internal(&other),
        })?;
    // MSC4190: a device-managing service gets no session even when it did
    // not ask to inhibit one — the as_token is its only credential, and
    // devices are minted through PUT /devices/{deviceId} instead.
    if request.inhibit_login || registration.device_management {
        return Ok((StatusCode::OK, Json(json!({ "user_id": user_id }))));
    }
    let session = accounts
        .create_session(
            username,
            request.device_id.clone(),
            request.initial_device_display_name.clone(),
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;
    Ok((StatusCode::OK, Json(session_body(&user_id, &session))))
}

/// `POST /_matrix/client/v3/logout`
async fn logout(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, MatrixError> {
    let token = bearer_token(&headers);
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    if introspected(&state, &accounts, token)? {
        // The token is the provider's, and the provider may not hear of
        // this logout. Dropping only the cached verdict would let the next
        // introspection vouch for it again, so the logout ends the device,
        // as the spec says a logout does and as MAS's own logout does
        // through `delete_device` (#615).
        crate::mas::remove_device(
            &state,
            &accounts,
            &localpart_of(&identity.user_id),
            &identity.device_id,
            crate::mas::EndedBy::Server,
        )?;
        crate::mas::device_list_changed(&state, &identity.user_id);
    } else {
        accounts.logout(token).map_err(|error| internal(&error))?;
    }
    Ok(Json(json!({})))
}

/// The bearer token of a request the [`Authenticated`] extractor admitted.
fn bearer_token(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .trim()
}

/// Whether `token` authenticated through the delegated provider's
/// introspection rather than as a local session or an appservice.
fn introspected(
    state: &AppState,
    accounts: &Accounts<'_, spindle_store::FjallStore>,
    token: &str,
) -> Result<bool, MatrixError> {
    Ok(state.delegated.is_some()
        && !token.is_empty()
        && state.appservices.by_token(token).is_none()
        && accounts
            .identify(token)
            .map_err(|error| internal(&error))?
            .is_none())
}

/// `GET /_matrix/client/v3/account/whoami`
async fn whoami(AccountAuthenticated(identity): AccountAuthenticated) -> Json<Value> {
    let mut body = json!({"user_id": identity.user_id});
    if !identity.device_id.is_empty() {
        body["device_id"] = json!(identity.device_id);
    }
    Json(body)
}

/// `POST /_matrix/client/v3/logout/all`
///
/// Every session of the account, this one included: the answer to a lost
/// phone, which is why it is its own endpoint rather than a loop over
/// `/logout` from a device that may not be the one in hand.
async fn logout_all(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&identity.user_id);
    // Asked before the local sessions go, or a local token would look like
    // one only the provider knows.
    let provider_session = introspected(&state, &accounts, bearer_token(&headers))?;
    accounts
        .logout_everywhere(&localpart)
        .map_err(|error| internal(&error))?;
    if provider_session {
        // Provider-vouched sessions have no local token to delete: ending
        // their devices is what keeps the next introspection from vouching
        // for them again (#615).
        for device in accounts
            .devices_of(&localpart)
            .map_err(|error| internal(&error))?
        {
            crate::mas::remove_device(
                &state,
                &accounts,
                &localpart,
                &device.device_id,
                crate::mas::EndedBy::Server,
            )?;
        }
        crate::mas::device_list_changed(&state, &identity.user_id);
    }
    if let Some(delegated) = &state.delegated {
        delegated.forget_user(&identity.user_id);
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/admin/whois/{userId}`
///
/// The user's devices. The spec's shape carries the sessions and
/// connections behind each device; this server keeps no connection log,
/// so each device is listed with one session and no connections, which
/// is the shape with nothing invented in it. The user themself or a
/// server admin may ask.
async fn admin_whois(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if identity.user_id != user_id
        && !crate::admin::is_server_admin(&state, &identity.user_id)
            .map_err(|error| internal(&error))?
    {
        return Err(MatrixError::forbidden(
            "only the user or a server admin may ask",
        ));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&user_id);
    if accounts
        .account(&localpart)
        .map_err(|error| internal(&error))?
        .is_none()
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such user here",
        ));
    }
    let mut devices = serde_json::Map::new();
    for device in accounts
        .devices_of(&localpart)
        .map_err(|error| internal(&error))?
    {
        devices.insert(
            device.device_id,
            json!({ "sessions": [{ "connections": [] }] }),
        );
    }
    Ok(Json(json!({ "user_id": user_id, "devices": devices })))
}

/// The two v1.18 administrative holds share one shape: a flag on the
/// account, read and written by a server admin, audited, and refused for
/// a user this server does not hold.
fn admin_hold(
    state: &AppState,
    actor: &crate::accounts::Identity,
    user_id: &str,
    hold: &'static str,
    set: Option<bool>,
) -> Result<Json<Value>, MatrixError> {
    if !crate::admin::is_server_admin(state, &actor.user_id).map_err(|error| internal(&error))? {
        return Err(MatrixError::forbidden("not a server admin"));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(user_id);
    let Some(account) = accounts
        .account(&localpart)
        .map_err(|error| internal(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such user here",
        ));
    };
    let Some(wanted) = set else {
        let current = if hold == "locked" {
            account.locked
        } else {
            account.suspended
        };
        return Ok(Json(json!({ hold: current })));
    };
    let written = if hold == "locked" {
        accounts.set_locked(&localpart, wanted)
    } else {
        accounts.set_suspended(&localpart, wanted)
    }
    .map_err(|error| internal(&error))?;
    debug_assert!(written);
    crate::admin::audit(
        state,
        &actor.user_id,
        hold,
        user_id,
        &json!({ hold: wanted }),
    )?;
    Ok(Json(json!({ hold: wanted })))
}

#[derive(Debug, Deserialize)]
struct LockRequest {
    locked: bool,
}

#[derive(Debug, Deserialize)]
struct SuspendRequest {
    suspended: bool,
}

/// `GET /_matrix/client/v1/admin/lock/{userId}` (spec v1.18)
async fn admin_lock_get(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    admin_hold(&state, &identity, &user_id, "locked", None)
}

/// `PUT /_matrix/client/v1/admin/lock/{userId}` (spec v1.18)
async fn admin_lock_put(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<LockRequest>,
) -> Result<Json<Value>, MatrixError> {
    admin_hold(&state, &identity, &user_id, "locked", Some(request.locked))
}

/// `GET /_matrix/client/v1/admin/suspend/{userId}` (spec v1.18)
async fn admin_suspend_get(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    admin_hold(&state, &identity, &user_id, "suspended", None)
}

/// `PUT /_matrix/client/v1/admin/suspend/{userId}` (spec v1.18)
async fn admin_suspend_put(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<SuspendRequest>,
) -> Result<Json<Value>, MatrixError> {
    admin_hold(
        &state,
        &identity,
        &user_id,
        "suspended",
        Some(request.suspended),
    )
}

#[derive(Debug, Default, Deserialize)]
struct PasswordChangeRequest {
    new_password: Option<String>,
    /// Defaults to true, per the spec: changing a password because it leaked
    /// is the common case, and leaving the other sessions signed in would
    /// defeat the point.
    logout_devices: Option<bool>,
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/account/password`
async fn change_password(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: PasswordChangeRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "change_password",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    let new_password = request
        .new_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| MatrixError::bad_json("no new_password"))?;

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_password(&localpart, new_password)
        .map_err(|error| internal(&error))?;
    if request.logout_devices.unwrap_or(true) {
        accounts
            .logout_everywhere(&localpart)
            .map_err(|error| internal(&error))?;
    }
    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Debug, Default, Deserialize)]
struct DeactivateRequest {
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/account/deactivate`
///
/// Deactivation leaves every room the user is in, rather than only flipping
/// the flag. A deactivated account that is still joined shows up in member
/// lists, counts toward `num_joined_members`, and keeps appearing in other
/// people's user-directory results -- so the flag alone would make the
/// account unusable without making it *gone*, which is the thing the user
/// asked for.
///
/// A room that refuses the leave is recorded and reported rather than
/// aborting: the account is still deactivated, and the honest answer is which
/// rooms it could not be removed from.
async fn deactivate_account(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: DeactivateRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "deactivate",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }

    let rooms = state.rooms.joined(&identity.user_id).unwrap_or_default();
    for room_id in rooms {
        let _ = state
            .rooms
            .set_membership_checked(
                &room_id,
                &identity.user_id,
                &identity.user_id,
                "leave",
                Some("account deactivated"),
                state.key.pair(),
            )
            .await;
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_deactivated(&localpart, true)
        .map_err(|error| internal(&error))?;
    accounts
        .logout_everywhere(&localpart)
        .map_err(|error| internal(&error))?;
    if let Some(delegated) = &state.delegated {
        delegated.forget_user(&identity.user_id);
    }
    state.rooms.wake_sync_waiters();

    // No identity server is contacted, so no third-party binding is removed.
    // `no-support` is the spec's word for exactly that, and it is more honest
    // than `success`.
    Ok((
        StatusCode::OK,
        Json(json!({ "id_server_unbind_result": "no-support" })),
    ))
}
