//! The built-in OIDC provider (#159): modern auth from one binary.
//!
//! MSC3861 clients — Element X natively, Element Web behind a flag —
//! authenticate through an OAuth 2.0 provider or not at all. The
//! delegated path (`[auth.delegated]`, `delegated.rs`) hands that role
//! to a real MAS, which costs an operator a second service and the
//! `PostgreSQL` it requires. This module is the other answer: Spindle
//! itself speaks the small provider surface those clients need, over
//! the accounts, passwords and devices it already holds.
//!
//! The decisive simplification is that **the tokens this provider mints
//! are Spindle's native sessions**. There is no introspection hop, no
//! JWT machinery, no signing-key rotation surface: the token endpoint
//! calls `create_session`, and every later request resolves it exactly
//! the way a password login's token resolves. The OAuth layer is only
//! the front door — discovery, client registration, an authorization
//! page, PKCE — and the house behind it is unchanged.
//!
//! Around that front door sit the pages a user reaches from their client
//! (#607, `account.rs`): profile, password, sessions, deactivation — and
//! a browser session, so a second client's sign-in is "Continue as …"
//! rather than the password again. Upstream identity providers (#610)
//! are still absent; `docs/delegated-auth.md` describes where they hook in.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;
use crate::metrics::{GrantResult, LoginMethod, LoginResult, TokenGrant};
use crate::routes::ClientAddr;
use crate::web::{self, FormTargets, escape, hidden, urlencode};

/// An RFC 6749 error: `{"error": code, "error_description": …}` with
/// the right status. The callers of `/oauth2/*` are OAuth libraries
/// that branch on `error`, exactly as Matrix clients branch on
/// `errcode` — same argument, different spelling.
pub struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.code,
                "error_description": self.description,
            })),
        )
            .into_response()
    }
}

impl From<MatrixError> for OAuthError {
    fn from(error: MatrixError) -> Self {
        Self {
            status: error.status,
            code: if error.status == StatusCode::NOT_FOUND {
                "invalid_request"
            } else {
                "server_error"
            },
            description: error.error,
        }
    }
}

/// How long an authorization code may sit unredeemed. Five minutes is
/// the RFC 6749 recommendation's upper bound; a code is one redirect's
/// worth of lifetime, not a credential.
const CODE_LIFETIME: Duration = Duration::from_secs(300);

/// The scopes that grant the client API: the stable spelling Matrix
/// 1.15 settled on, and the MSC2967 draft spelling older clients still
/// send. Element Web's bundled js-sdk moved from the second to the
/// first mid-2025; a provider accepting only one strands the other.
const API_SCOPES: [&str; 2] = [
    "urn:matrix:client:api:*",
    "urn:matrix:org.matrix.msc2967.client:api:*",
];

/// The scope prefixes that bind the session to one device — stable and
/// draft spellings, same story as [`API_SCOPES`]. The device ID after
/// the prefix is chosen by the client, exactly as it is in a password
/// login's `device_id` field.
const DEVICE_SCOPES: [&str; 2] = [
    "urn:matrix:client:device:",
    "urn:matrix:org.matrix.msc2967.client:device:",
];

/// One authorization code, waiting to be redeemed.
struct PendingCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    localpart: String,
    device_id: String,
    expires: Instant,
}

/// The provider's in-flight state. Codes are memory-only on purpose: a
/// code that does not survive a restart costs the user one more login
/// page, while a durable code would be a credential at rest.
pub struct BuiltinOidc {
    codes: Mutex<HashMap<String, PendingCode>>,
}

impl BuiltinOidc {
    #[must_use]
    pub fn new() -> Self {
        Self {
            codes: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for BuiltinOidc {
    fn default() -> Self {
        Self::new()
    }
}

/// A dynamically registered client, as stored.
#[derive(Deserialize, Serialize)]
struct ClientRecord {
    client_id: String,
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/oauth2/registration", post(register_client))
        .route("/oauth2/authorize", get(authorize_page).post(authorize))
        .route("/oauth2/token", post(token))
        .route("/oauth2/revoke", post(revoke))
}

/// The provider, or the 404 an undelegated non-provider answers. The
/// same refusal shape as every other unconfigured feature: absence,
/// not a stub.
pub(crate) fn provider(state: &AppState) -> Result<&BuiltinOidc, MatrixError> {
    state.oidc.as_deref().ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "this server is not an OIDC provider",
        )
    })
}

/// Where this provider says it lives, without the trailing slash:
/// `auth.oidc_issuer` when configured (#609), the client-facing base URL
/// otherwise. Every URL the discovery document advertises is built on
/// this, so a deployment that moves the issuer to its own host moves
/// every endpoint with it.
#[must_use]
pub fn issuer(state: &AppState) -> String {
    state.config.oidc_issuer_base()
}

/// The discovery document, served at the well-known path and relayed
/// verbatim by `/_matrix/client/v1/auth_metadata` (MSC2965).
#[must_use]
pub fn metadata(state: &AppState) -> Value {
    let issuer = issuer(state);
    json!({
        "issuer": format!("{issuer}/"),
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "registration_endpoint": format!("{issuer}/oauth2/registration"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "prompt_values_supported": ["login"],
        // MSC4191: where a client sends its user to manage the account,
        // and which of the pages it may deep-link to with `?action=`.
        "account_management_uri": crate::account::management_uri(state),
        "account_management_actions_supported": crate::account::ACTIONS_SUPPORTED,
    })
}

async fn discovery(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    provider(&state)?;
    Ok(Json(metadata(&state)))
}

#[derive(Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    // Everything else a client sends (grant_types, response_types,
    // application_type, client_uri, logo_uri…) is accepted and unread:
    // this provider supports exactly one shape — public client, code +
    // PKCE — and registering is declaring redirect URIs for it.
}

/// `POST /oauth2/registration` — RFC 7591 dynamic registration.
///
/// Clients persist their `client_id` across restarts, so registrations
/// are durable rows rather than memory. Public clients only: there is
/// no secret to issue, PKCE is the proof of continuity.
async fn register_client(
    State(state): State<AppState>,
    Json(request): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<Value>), OAuthError> {
    provider(&state)?;
    if request.redirect_uris.is_empty() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        ));
    }
    let client_id = format!("oc_{}", random_hex(16));
    let record = ClientRecord {
        client_id: client_id.clone(),
        redirect_uris: request.redirect_uris.clone(),
        client_name: request.client_name.clone(),
    };
    Store::put(
        state.store.as_ref(),
        &keys::oidc_client(&client_id),
        serde_json::to_vec(&record)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .as_slice(),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "redirect_uris": request.redirect_uris,
            "client_name": request.client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })),
    ))
}

fn load_client(state: &AppState, client_id: &str) -> Result<Option<ClientRecord>, MatrixError> {
    ReadView::get(state.store.as_ref(), &keys::oidc_client(client_id))
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .map(|raw| {
            serde_json::from_slice(&raw).map_err(|error| MatrixError::internal(&error.to_string()))
        })
        .transpose()
}

/// The query parameters an authorization request carries, echoed
/// through the login form so the POST still knows them.
#[derive(Deserialize, Serialize)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    #[serde(default = "default_challenge_method")]
    code_challenge_method: String,
    #[serde(default = "default_response_mode")]
    response_mode: String,
    response_type: Option<String>,
    /// OIDC's `prompt`: `login` asks for the password even when a browser
    /// session could continue. Anything else is ignored.
    prompt: Option<String>,
}

impl AuthorizeParams {
    /// The authorization request as a query string, for a link back to
    /// the same request (the consent page's "use another account").
    fn query(&self, prompt: Option<&str>) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scope)
            .append_pair("code_challenge", &self.code_challenge)
            .append_pair("code_challenge_method", &self.code_challenge_method)
            .append_pair("response_mode", &self.response_mode)
            .append_pair("response_type", "code");
        if let Some(value) = &self.state {
            query.append_pair("state", value);
        }
        if let Some(prompt) = prompt {
            query.append_pair("prompt", prompt);
        }
        query.finish()
    }

    /// The authorization request as hidden form fields.
    fn hidden_fields(&self) -> String {
        let mut fields = String::new();
        fields.push_str(&hidden("client_id", &self.client_id));
        fields.push_str(&hidden("redirect_uri", &self.redirect_uri));
        fields.push_str(&hidden("scope", &self.scope));
        fields.push_str(&hidden("code_challenge", &self.code_challenge));
        fields.push_str(&hidden(
            "code_challenge_method",
            &self.code_challenge_method,
        ));
        fields.push_str(&hidden("response_mode", &self.response_mode));
        fields.push_str(&hidden("response_type", "code"));
        if let Some(value) = &self.state {
            fields.push_str(&hidden("state", value));
        }
        fields
    }
}

fn default_challenge_method() -> String {
    "plain".to_owned()
}

fn default_response_mode() -> String {
    "query".to_owned()
}

/// Validate everything about an authorization request that can be
/// validated before a human is involved. Errors here are pages, not
/// redirects: RFC 6749 §4.1.2.1 forbids redirecting to an unvalidated
/// `redirect_uri`, which is exactly what an open-redirect bug is.
fn check_authorize(state: &AppState, params: &AuthorizeParams) -> Result<(), OAuthError> {
    let client = load_client(state, &params.client_id)?.ok_or_else(|| {
        oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "unknown client_id — register first",
        )
    })?;
    if !client
        .redirect_uris
        .iter()
        .any(|registered| registered == &params.redirect_uri)
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is not one the client registered",
        ));
    }
    if params.response_type.as_deref() != Some("code") {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    // PKCE S256 is mandatory, not negotiable down to `plain`: a public
    // client without it is bearer-code auth, and `plain` exists only
    // for clients that cannot hash — none of ours.
    if params.code_challenge_method != "S256" || params.code_challenge.is_empty() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required",
        ));
    }
    if !params
        .scope
        .split(' ')
        .any(|part| API_SCOPES.contains(&part))
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "the MSC2967 client API scope is required",
        ));
    }
    if device_id_of(&params.scope).is_none() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "an MSC2967 device scope is required",
        ));
    }
    Ok(())
}

fn device_id_of(scope: &str) -> Option<String> {
    scope
        .split(' ')
        .find_map(|part| {
            DEVICE_SCOPES
                .iter()
                .find_map(|prefix| part.strip_prefix(prefix))
        })
        .filter(|device| !device.is_empty())
        .map(str::to_owned)
}

/// `GET /oauth2/authorize` — the login page, or "Continue as …".
///
/// Plain HTML, no scripts: the page's whole job is to carry the
/// authorization parameters through a password prompt. Values are
/// HTML-escaped on the way in; they came from a URL a stranger built.
/// A browser already signed in here (by an earlier authorization or the
/// account pages) is offered the account it is signed in as instead,
/// unless the client asked for `prompt=login`.
async fn authorize_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, OAuthError> {
    provider(&state)?;
    check_authorize(&state, &params)?;
    let client_name = client_name(&state, &params.client_id)?;
    if params.prompt.as_deref() != Some("login")
        && let Some(session) = web::browser_session(&state, &headers)?
    {
        return Ok(web::html(
            StatusCode::OK,
            FormTargets::Redirecting,
            consent_page(&state, &params, &client_name, &session),
        ));
    }
    Ok(login_response(
        &state,
        &headers,
        StatusCode::OK,
        &params,
        &client_name,
        None,
    ))
}

fn client_name(state: &AppState, client_id: &str) -> Result<String, MatrixError> {
    Ok(load_client(state, client_id)?
        .and_then(|client| client.client_name)
        .unwrap_or_else(|| "an application".to_owned()))
}

/// The host a code would be sent to, shown so the person can tell an
/// impostor's registration from the client they meant.
fn redirect_host(redirect_uri: &str) -> &str {
    redirect_uri
        .split_once("://")
        .map_or(redirect_uri, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
}

fn consent_page(
    state: &AppState,
    params: &AuthorizeParams,
    client_name: &str,
    session: &web::BrowserSession,
) -> String {
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&session.localpart);
    let body = format!(
        "<h1>Continue to {client}?</h1>\
         <p><strong>{client}</strong> (<code>{host}</code>) is asking to sign in as you.</p>\
         <p>You are signed in as <strong>{user}</strong>.</p>\
         <form method=\"post\" action=\"/oauth2/authorize\">{fields}{csrf}\
         <button type=\"submit\">Continue as {user}</button></form>\
         <p><a href=\"/oauth2/authorize?{other}\">Use a different account</a></p>",
        client = escape(client_name),
        host = escape(redirect_host(&params.redirect_uri)),
        user = escape(&user_id),
        fields = params.hidden_fields(),
        csrf = hidden("csrf", &session.csrf),
        other = escape(&params.query(Some("login"))),
    );
    web::page(state, "Continue", &body)
}

fn login_response(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    params: &AuthorizeParams,
    client_name: &str,
    error: Option<&str>,
) -> Response {
    let (csrf, set_csrf) = web::signed_out_csrf(state, headers);
    let response = web::html(
        status,
        FormTargets::Redirecting,
        login_page(state, params, client_name, error, &csrf),
    );
    match set_csrf {
        Some(cookie) => web::with_cookie(response, &cookie),
        None => response,
    }
}

fn login_page(
    state: &AppState,
    params: &AuthorizeParams,
    client_name: &str,
    error: Option<&str>,
    csrf: &str,
) -> String {
    let notice = error.map_or(String::new(), |message| {
        format!("<p class=\"error\">{}</p>", escape(message))
    });
    let forgot = if crate::email::configured(state) {
        "<p><a href=\"/account/password/forgot\">Forgot your password?</a></p>"
    } else {
        ""
    };
    let body = format!(
        "<form method=\"post\" action=\"/oauth2/authorize\">\
         <h1>Sign in to {server}</h1>\
         <p>{client} (<code>{host}</code>) is asking to sign in as you.</p>{notice}{fields}{csrf}\
         <input name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required>\
         <input name=\"password\" type=\"password\" placeholder=\"Password\" \
         autocomplete=\"current-password\" required>\
         <button type=\"submit\">Sign in</button></form>{forgot}",
        server = escape(&state.config.server.name),
        client = escape(client_name),
        host = escape(redirect_host(&params.redirect_uri)),
        notice = notice,
        fields = params.hidden_fields(),
        csrf = hidden("login_csrf", csrf),
    );
    web::page(state, "Sign in", &body)
}

/// The login form's fields — the authorization parameters spelled out
/// rather than `#[serde(flatten)]`, which form-urlencoded
/// deserialization does not reliably support. `username` and
/// `password` are absent on the "Continue as …" form, which carries the
/// browser session's `csrf` instead.
#[derive(Deserialize)]
struct AuthorizeForm {
    username: Option<String>,
    password: Option<String>,
    csrf: Option<String>,
    /// The double-submit token of the password form. Optional so that a
    /// client driving the form without cookies (the pre-#607 flow) still
    /// signs in: a login form is not a state change a third party can
    /// profit from forcing, since it needs the victim's own password.
    login_csrf: Option<String>,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    #[serde(default = "default_challenge_method")]
    code_challenge_method: String,
    #[serde(default = "default_response_mode")]
    response_mode: String,
    response_type: Option<String>,
}

impl AuthorizeForm {
    fn params(&self) -> AuthorizeParams {
        AuthorizeParams {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
            response_mode: self.response_mode.clone(),
            response_type: self.response_type.clone(),
            prompt: None,
        }
    }
}

/// `POST /oauth2/authorize` — check the password (or the browser
/// session), mint a code, redirect.
///
/// The password is counted against the same per-account and per-source
/// budgets as the client API's login, before the Argon2 work. A correct
/// password also starts a browser session, so the account pages and the
/// next client's authorization find the user signed in.
async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<AuthorizeForm>,
) -> Result<Response, OAuthError> {
    let oidc = provider(&state)?;
    let params = form.params();
    check_authorize(&state, &params)?;
    let client_name = client_name(&state, &params.client_id)?;
    let form_error = |status: StatusCode, message: &str| {
        login_response(
            &state,
            &headers,
            status,
            &params,
            &client_name,
            Some(message),
        )
    };

    let (localpart, new_session) = if let (None, Some(csrf)) = (&form.password, &form.csrf) {
        // "Continue as …": the browser session is the credential, and its
        // CSRF secret proves the form is the one this server rendered.
        let Some(session) = web::browser_session(&state, &headers)? else {
            return Ok(form_error(
                StatusCode::UNAUTHORIZED,
                "Your sign-in has expired. Please sign in again.",
            ));
        };
        if !session.csrf_ok(Some(csrf)) {
            return Ok(form_error(
                StatusCode::FORBIDDEN,
                "That form has expired. Please sign in again.",
            ));
        }
        state
            .metrics
            .record_login(LoginMethod::OidcSession, LoginResult::Success);
        (session.localpart, None)
    } else {
        match password_sign_in(&state, &headers, &source.to_string(), &form)? {
            Ok(localpart) => {
                let cookie = web::start_browser_session(&state, &localpart)?;
                (localpart, Some(cookie))
            }
            Err((status, message)) => return Ok(form_error(status, message)),
        }
    };

    let device_id = device_id_of(&params.scope)
        .ok_or_else(|| MatrixError::internal("checked scope lost its device"))?;
    let code = random_hex(32);
    oidc.codes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            code.clone(),
            PendingCode {
                client_id: params.client_id.clone(),
                redirect_uri: params.redirect_uri.clone(),
                code_challenge: params.code_challenge.clone(),
                scope: params.scope.clone(),
                localpart,
                device_id,
                expires: Instant::now() + CODE_LIFETIME,
            },
        );
    let mut fragment_or_query = format!("code={}", urlencode(&code));
    if let Some(value) = &params.state {
        let _ = write!(fragment_or_query, "&state={}", urlencode(value));
    }
    let separator = if params.response_mode == "fragment" {
        '#'
    } else if params.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let target = format!("{}{separator}{fragment_or_query}", params.redirect_uri);
    let response = Redirect::to(&target).into_response();
    Ok(match new_session {
        Some(cookie) => web::with_cookie(response, &cookie),
        None => response,
    })
}

/// The password half of the authorization form: the localpart it signs
/// in, or the status and message to re-render the form with. Counted
/// against the shared attempt budget before the Argon2 work.
fn password_sign_in(
    state: &AppState,
    headers: &HeaderMap,
    source: &str,
    form: &AuthorizeForm,
) -> Result<Result<String, (StatusCode, &'static str)>, OAuthError> {
    let (Some(username), Some(password)) = (&form.username, &form.password) else {
        return Ok(Err((
            StatusCode::BAD_REQUEST,
            "Enter your username and password.",
        )));
    };
    if form.login_csrf.is_some() && !web::signed_out_csrf_ok(headers, form.login_csrf.as_deref()) {
        return Ok(Err((
            StatusCode::FORBIDDEN,
            "That form has expired. Please try again.",
        )));
    }
    let localpart = web::localpart_of(username);
    if web::spend_password_attempt(state, &localpart, source).is_err() {
        state
            .metrics
            .record_login(LoginMethod::Oidc, LoginResult::RateLimited);
        return Ok(Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a minute and try again.",
        )));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let good = accounts
        .verify_password(&localpart, password)
        .map_err(|error| {
            state
                .metrics
                .record_login(LoginMethod::Oidc, LoginResult::Error);
            MatrixError::internal(&error.to_string())
        })?;
    if !good {
        // Back to the form, not an OAuth error: a typo'd password is the
        // human's business, and the flow is still alive.
        state
            .metrics
            .record_login(LoginMethod::Oidc, LoginResult::BadPassword);
        return Ok(Err((
            StatusCode::UNAUTHORIZED,
            "That username and password did not match.",
        )));
    }
    web::forget_password_attempts(state, &localpart, source);
    state
        .metrics
        .record_login(LoginMethod::Oidc, LoginResult::Success);
    Ok(Ok(localpart))
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// `POST /oauth2/token`
///
/// Redeems a code (or rotates a refresh token) into a **native Spindle
/// session** — the same `syt_`/`syr_` pair, device-bound and expiring,
/// that a password login with refresh mints. From here on the OAuth
/// layer is out of the picture.
async fn token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<Value>, OAuthError> {
    let oidc = provider(&state)?;
    let grant = match request.grant_type.as_str() {
        "authorization_code" => Some(TokenGrant::AuthorizationCode),
        "refresh_token" => Some(TokenGrant::RefreshToken),
        _ => None,
    };
    let outcome = grant_token(&state, oidc, &request);
    if let Some(grant) = grant {
        let result = match &outcome {
            Ok(_) => GrantResult::Success,
            Err(error) if error.code == "invalid_grant" => GrantResult::InvalidGrant,
            Err(error) if error.code == "invalid_request" => GrantResult::InvalidRequest,
            Err(_) => GrantResult::Error,
        };
        state.metrics.record_token_grant(grant, result);
    }
    outcome
}

fn grant_token(
    state: &AppState,
    oidc: &BuiltinOidc,
    request: &TokenRequest,
) -> Result<Json<Value>, OAuthError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    match request.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier)) = (&request.code, &request.code_verifier) else {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required",
                ));
            };
            // Taken, not read: a code redeems exactly once, and a replay
            // finds nothing whether the first redemption succeeded or not.
            let pending = oidc
                .codes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(code);
            let Some(pending) = pending.filter(|pending| pending.expires > Instant::now()) else {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "unknown, used, or expired code",
                ));
            };
            if request.client_id.as_deref() != Some(pending.client_id.as_str())
                || request.redirect_uri.as_deref() != Some(pending.redirect_uri.as_str())
            {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "client_id and redirect_uri must match the authorization",
                ));
            }
            let hashed = sha2::Sha256::digest(verifier.as_bytes());
            if base64url_unpadded(&hashed) != pending.code_challenge {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE verification failed",
                ));
            }
            let session = accounts
                .create_session(&pending.localpart, Some(pending.device_id), None, true)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            Ok(Json(session_json(&session, Some(&pending.scope))))
        }
        "refresh_token" => {
            let Some(refresh_token) = &request.refresh_token else {
                return Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                ));
            };
            let session = accounts.refresh(refresh_token).map_err(|_| {
                oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "that refresh token is not live",
                )
            })?;
            // The scope the code grant echoed is gone by now, and the
            // validator treats scope as optional — omitted beats
            // reconstructed in a spelling the client did not use.
            Ok(Json(session_json(&session, None)))
        }
        other => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("unsupported grant_type {other:?}"),
        )),
    }
}

/// RFC 6749 §5.1's response, shaped for matrix-js-sdk's validator: an
/// optional field that is absent must be *absent*, because a `null`
/// where a string may be fails its type guard and kills the login at
/// the last step.
fn session_json(session: &crate::accounts::Session, scope: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": session.access_token,
        "token_type": "Bearer",
        "expires_in": session.expires_in_ms.map_or(3600, |ms| ms / 1000),
    });
    if let Some(refresh) = &session.refresh_token {
        body["refresh_token"] = json!(refresh);
    }
    if let Some(scope) = scope {
        body["scope"] = json!(scope);
    }
    body
}

#[derive(Deserialize)]
struct RevokeRequest {
    token: String,
}

/// `POST /oauth2/revoke` — RFC 7009. Revoking either half of the pair
/// ends the session; per the RFC, an unknown token still answers 200,
/// because "already gone" is the state the caller asked for.
async fn revoke(
    State(state): State<AppState>,
    Form(request): Form<RevokeRequest>,
) -> Result<Json<Value>, OAuthError> {
    provider(&state)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .logout(&request.token)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

fn oauth_error(status: StatusCode, code: &'static str, description: &str) -> OAuthError {
    OAuthError {
        status,
        code,
        description: description.to_owned(),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    crate::secrets::fill(&mut raw);
    raw.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// RFC 7636's base64url without padding, for PKCE challenges -- and RFC
/// 7515's, which is the same alphabet, for the JWTs `livekit` mints.
pub(crate) fn base64url_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for slot in 0..=chunk.len() {
            let index = (triple >> (18 - 6 * slot)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}
