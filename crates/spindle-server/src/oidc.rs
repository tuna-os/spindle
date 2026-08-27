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
//! What is deliberately absent: upstream identity providers, SSO, email flows,
//! account management UI. Those are what a real MAS is for, and the
//! docs say so; this is the floor that makes a single-node deployment
//! whole, not a MAS replacement.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;

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
fn provider(state: &AppState) -> Result<&BuiltinOidc, MatrixError> {
    state.oidc.as_deref().ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "this server is not an OIDC provider",
        )
    })
}

/// Where this provider says it lives — the client-facing base URL.
#[must_use]
pub fn issuer(state: &AppState) -> String {
    state
        .config
        .client_base_url()
        .trim_end_matches('/')
        .to_owned()
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

/// `GET /oauth2/authorize` — the login page.
///
/// Plain HTML, no scripts: the page's whole job is to carry the
/// authorization parameters through a password prompt. Values are
/// HTML-escaped on the way in; they came from a URL a stranger built.
async fn authorize_page(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Html<String>, OAuthError> {
    provider(&state)?;
    check_authorize(&state, &params)?;
    let client_name = load_client(&state, &params.client_id)?
        .and_then(|client| client.client_name)
        .unwrap_or_else(|| "an application".to_owned());
    Ok(Html(login_page(&state, &params, &client_name, None)))
}

fn login_page(
    state: &AppState,
    params: &AuthorizeParams,
    client_name: &str,
    error: Option<&str>,
) -> String {
    let hidden = |name: &str, value: &str| {
        format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape(name),
            escape(value)
        )
    };
    let mut fields = String::new();
    fields.push_str(&hidden("client_id", &params.client_id));
    fields.push_str(&hidden("redirect_uri", &params.redirect_uri));
    fields.push_str(&hidden("scope", &params.scope));
    fields.push_str(&hidden("code_challenge", &params.code_challenge));
    fields.push_str(&hidden(
        "code_challenge_method",
        &params.code_challenge_method,
    ));
    fields.push_str(&hidden("response_mode", &params.response_mode));
    fields.push_str(&hidden("response_type", "code"));
    if let Some(value) = &params.state {
        fields.push_str(&hidden("state", value));
    }
    let notice = error.map_or(String::new(), |message| {
        format!("<p class=\"error\">{}</p>", escape(message))
    });
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Sign in — {server}</title>\
         <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;\
         min-height:100vh;margin:0;background:#f4f4f4}}form{{background:#fff;\
         padding:2rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);\
         display:flex;flex-direction:column;gap:.75rem;min-width:280px}}\
         input{{padding:.5rem;font-size:1rem}}button{{padding:.6rem;font-size:1rem}}\
         .error{{color:#b00;margin:0}}</style></head><body>\
         <form method=\"post\" action=\"/oauth2/authorize\">\
         <h1>Sign in to {server}</h1>\
         <p>{client} is asking to sign in as you.</p>{notice}{fields}\
         <input name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required>\
         <input name=\"password\" type=\"password\" placeholder=\"Password\" \
         autocomplete=\"current-password\" required>\
         <button type=\"submit\">Sign in</button></form></body></html>",
        server = escape(&state.config.server.name),
        client = escape(client_name),
        notice = notice,
        fields = fields,
    )
}

/// The login form's fields — the authorization parameters spelled out
/// rather than `#[serde(flatten)]`, which form-urlencoded
/// deserialization does not reliably support.
#[derive(Deserialize)]
struct AuthorizeForm {
    username: String,
    password: String,
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
        }
    }
}

/// `POST /oauth2/authorize` — check the password, mint a code, redirect.
async fn authorize(
    State(state): State<AppState>,
    Form(form): Form<AuthorizeForm>,
) -> Result<Response, OAuthError> {
    let oidc = provider(&state)?;
    let params = form.params();
    check_authorize(&state, &params)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = form.username.trim().to_lowercase();
    let localpart = localpart
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .map_or(localpart.as_str(), |(name, _)| name)
        .to_owned();
    let good = accounts
        .verify_password(&localpart, &form.password)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !good {
        // Back to the form, not an OAuth error: a typo'd password is the
        // human's business, and the flow is still alive.
        let client_name = load_client(&state, &params.client_id)?
            .and_then(|client| client.client_name)
            .unwrap_or_else(|| "an application".to_owned());
        return Ok((
            StatusCode::UNAUTHORIZED,
            Html(login_page(
                &state,
                &params,
                &client_name,
                Some("That username and password did not match."),
            )),
        )
            .into_response());
    }
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
    Ok(Redirect::to(&target).into_response())
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
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// RFC 7636's base64url without padding, for PKCE challenges.
fn base64url_unpadded(bytes: &[u8]) -> String {
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

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn urlencode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
