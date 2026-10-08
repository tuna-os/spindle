//! Browser sessions backed by an OIDC provider, and role checks.
//!
//! The flow is the authorization-code flow with PKCE. The operator never
//! sees a password and never holds a long-lived credential for anyone:
//!
//! 1. `GET …/session/login` remembers a `state`, `nonce` and PKCE verifier,
//!    binds them to this browser with a short-lived `SameSite=Lax` cookie
//!    (so a login started in one browser cannot be finished in another),
//!    and redirects to the provider.
//! 2. `GET …/session/callback` exchanges the code at the token endpoint and
//!    validates the ID token's `iss`, `aud`, `exp` and `nonce`. The token
//!    arrives directly from the token endpoint over TLS, so OIDC Core
//!    §3.1.3.7 lets TLS stand in for checking its signature; that keeps a
//!    JOSE stack out of this service.
//! 3. The person's claims map to roles; nobody without a role gets a
//!    session. The session id goes in an `HttpOnly; Secure;
//!    SameSite=Strict` `__Host-` cookie, and only its hash is recorded.
//!
//! Unsafe requests must also carry `X-CSRF-Token`, derived from the session
//! id so it needs no storage, and any `Origin` they carry must be the
//! operator's own. `SameSite=Strict` already stops a cross-site form; the
//! token is the second lock for browsers and proxies that get that wrong.
//!
//! The session is the only credential the browser holds. Matrix admin
//! tokens and every other secret stay server-side, behind references.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::OidcConfig;
use crate::engine::{Context, Engine, now, sha256_hex};
use crate::error::ApiError;
use crate::journal::Change;
use crate::model::{Principal, Role};

pub const SESSION_COOKIE: &str = "__Host-spindle-operator";
const LOGIN_COOKIE: &str = "__Host-spindle-operator-login";
pub const CSRF_HEADER: &str = "x-csrf-token";
/// How long a person has to finish signing in at the provider.
const LOGIN_WINDOW: Duration = Duration::from_secs(600);
/// Logins started and not yet finished, at most.
const MAX_PENDING_LOGINS: usize = 1024;
const PREFIX: &str = "/_spindle/operator/v1";

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

struct Pending {
    binding_hash: String,
    nonce: String,
    verifier: String,
    return_to: String,
    created: Instant,
}

pub struct Auth {
    oidc: OidcConfig,
    public_url: String,
    session_ttl: Duration,
    http: reqwest::Client,
    discovery: Mutex<Option<Discovery>>,
    pending: Mutex<HashMap<String, Pending>>,
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub auth: Arc<Auth>,
}

impl FromRef<AppState> for Arc<Engine> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.engine)
    }
}

fn random_token() -> String {
    use rand::TryRng as _;
    let mut bytes = [0_u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the OS entropy source must be readable to mint sessions");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The CSRF token for a session: derived, so nothing extra is stored, and
/// unguessable without the session id the cookie protects.
fn csrf_token(session_id: &str) -> String {
    sha256_hex(format!("spindle-operator csrf\0{session_id}").as_bytes())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

/// Only same-origin paths, so a crafted login link cannot bounce a fresh
/// session to someone else's site.
fn safe_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_-.?=&%:~".contains(&b)) =>
        {
            path.to_owned()
        }
        _ => "/".to_owned(),
    }
}

impl Auth {
    /// # Panics
    ///
    /// If an HTTP client with default TLS settings cannot be built, which
    /// only a broken system certificate store causes.
    #[must_use]
    pub fn new(oidc: OidcConfig, public_url: String, session_ttl: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a reqwest client with no custom TLS builds");
        Auth {
            oidc,
            public_url,
            session_ttl,
            http,
            discovery: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn redirect_uri(&self) -> String {
        format!("{}{PREFIX}/session/callback", self.public_url)
    }

    async fn discovery(&self) -> Result<Discovery, ApiError> {
        if let Some(found) = self.discovery.lock().ok().and_then(|d| d.clone()) {
            return Ok(found);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.oidc.issuer.trim_end_matches('/')
        );
        let unavailable =
            |detail: String| ApiError::new(StatusCode::BAD_GATEWAY, "oidc_unavailable", detail);
        let response =
            self.http.get(&url).send().await.map_err(|_| {
                unavailable("the OIDC provider did not answer discovery".to_owned())
            })?;
        let bytes = response
            .bytes()
            .await
            .map_err(|_| unavailable("the OIDC discovery document was cut short".to_owned()))?;
        let found: Discovery = serde_json::from_slice(&bytes).map_err(|error| {
            unavailable(format!("the OIDC discovery document is invalid: {error}"))
        })?;
        if found.issuer.trim_end_matches('/') != self.oidc.issuer.trim_end_matches('/') {
            return Err(unavailable(
                "the provider's discovery names a different issuer".to_owned(),
            ));
        }
        if let Ok(mut slot) = self.discovery.lock() {
            *slot = Some(found.clone());
        }
        Ok(found)
    }

    fn roles_for(&self, subject: &str, claims: &Value) -> BTreeSet<Role> {
        let groups: Vec<&str> = match claims.get(&self.oidc.roles_claim) {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            Some(Value::String(one)) => vec![one.as_str()],
            _ => Vec::new(),
        };
        let matches = |entries: &[String]| {
            entries.iter().any(|entry| {
                entry.strip_prefix("sub:") == Some(subject)
                    || entry
                        .strip_prefix("group:")
                        .is_some_and(|group| groups.contains(&group))
            })
        };
        let map = &self.oidc.roles;
        let mut roles = BTreeSet::new();
        for (role, entries) in [
            (Role::Viewer, &map.viewer),
            (Role::Operator, &map.operator),
            (Role::Approver, &map.approver),
        ] {
            if matches(entries) {
                roles.insert(role);
            }
        }
        roles
    }

    /// Trade the authorization code for tokens at the token endpoint.
    async fn exchange(
        &self,
        discovery: &Discovery,
        code: &str,
        verifier: &str,
    ) -> Result<TokenResponse, Response> {
        let secret = self.oidc.client_secret_ref.resolve().map_err(|error| {
            tracing::error!(%error, "the OIDC client secret is unavailable");
            refused(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the operator is misconfigured",
            )
        })?;
        let redirect_uri = self.redirect_uri();
        let exchange = self
            .http
            .post(&discovery.token_endpoint)
            .basic_auth(&self.oidc.client_id, Some(secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", verifier),
                ("client_id", self.oidc.client_id.as_str()),
            ])
            .send()
            .await;
        let token = match exchange {
            Ok(response) if response.status().is_success() => response
                .bytes()
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok()),
            _ => None,
        };
        token.ok_or_else(|| {
            refused(
                StatusCode::BAD_GATEWAY,
                "the identity provider did not issue a token",
            )
        })
    }

    fn validate_id_token(
        &self,
        issuer: &str,
        id_token: &str,
        nonce: &str,
    ) -> Result<Value, String> {
        let payload = id_token
            .split('.')
            .nth(1)
            .ok_or("the ID token is not a JWT")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .map_err(|_| "the ID token payload is not base64url")?;
        let claims: Value =
            serde_json::from_slice(&bytes).map_err(|_| "the ID token payload is not JSON")?;
        if claims["iss"].as_str() != Some(issuer) {
            return Err("the ID token was issued by someone else".to_owned());
        }
        let audience_ok = match &claims["aud"] {
            Value::String(one) => one == &self.oidc.client_id,
            Value::Array(many) => many
                .iter()
                .any(|a| a.as_str() == Some(&self.oidc.client_id)),
            _ => false,
        };
        if !audience_ok {
            return Err("the ID token is for a different client".to_owned());
        }
        let expires = claims["exp"].as_u64().ok_or("the ID token has no expiry")?;
        if expires.saturating_mul(1000) <= now() {
            return Err("the ID token has expired".to_owned());
        }
        if claims["nonce"].as_str() != Some(nonce) {
            return Err("the ID token's nonce does not match this login".to_owned());
        }
        if claims["sub"].as_str().is_none_or(str::is_empty) {
            return Err("the ID token names no subject".to_owned());
        }
        Ok(claims)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(&format!("{PREFIX}/session"), routing::get(session))
        .route(&format!("{PREFIX}/session/login"), routing::get(login))
        .route(
            &format!("{PREFIX}/session/callback"),
            routing::get(callback),
        )
        .route(&format!("{PREFIX}/session/logout"), routing::post(logout))
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

async fn login(State(app): State<AppState>, Query(query): Query<LoginQuery>) -> Response {
    let auth = &app.auth;
    let discovery = match auth.discovery().await {
        Ok(found) => found,
        Err(error) => return error.into_response(),
    };
    let state = random_token();
    let binding = random_token();
    let nonce = random_token();
    let verifier = random_token();
    let challenge =
        URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes()));
    if let Ok(mut pending) = auth.pending.lock() {
        pending.retain(|_, login| login.created.elapsed() < LOGIN_WINDOW);
        // Anyone can start a login, so the number in flight is capped: past
        // the cap the oldest is dropped (its browser just starts again)
        // rather than letting unauthenticated requests grow memory.
        while pending.len() >= MAX_PENDING_LOGINS {
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, login)| login.created)
                .map(|(state, _)| state.clone())
            else {
                break;
            };
            pending.remove(&oldest);
        }
        pending.insert(
            state.clone(),
            Pending {
                binding_hash: sha256_hex(binding.as_bytes()),
                nonce: nonce.clone(),
                verifier,
                return_to: safe_return_to(query.return_to.as_deref()),
                created: Instant::now(),
            },
        );
    }
    let scope = auth.oidc.scopes.join(" ");
    let redirect_uri = auth.redirect_uri();
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &auth.oidc.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let separator = if discovery.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{separator}{query}", discovery.authorization_endpoint);
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&location) {
        headers.insert(header::LOCATION, value);
    }
    // Lax, not Strict: the provider's redirect back is a cross-site
    // top-level navigation, and a Strict cookie would not ride on it.
    let login_cookie = format!(
        "{LOGIN_COOKIE}={binding}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        LOGIN_WINDOW.as_secs()
    );
    if let Ok(value) = HeaderValue::from_str(&login_cookie) {
        headers.insert(header::SET_COOKIE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

fn refused(status: StatusCode, message: &str) -> Response {
    let mut response = (
        status,
        Json(json!({"error": {"code": "login_failed", "message": message}})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn callback(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let auth = &app.auth;
    if let Some(error) = query.error {
        tracing::info!(%error, "the OIDC provider refused a login");
        return refused(
            StatusCode::UNAUTHORIZED,
            "the identity provider refused the login",
        );
    }
    let (Some(code), Some(state)) = (query.code, query.state) else {
        return refused(
            StatusCode::BAD_REQUEST,
            "the callback is missing its code or state",
        );
    };
    let pending = auth
        .pending
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&state));
    let Some(pending) = pending.filter(|p| p.created.elapsed() < LOGIN_WINDOW) else {
        return refused(
            StatusCode::BAD_REQUEST,
            "this login is unknown or has expired",
        );
    };
    let bound = cookie(&headers, LOGIN_COOKIE)
        .is_some_and(|binding| sha256_hex(binding.as_bytes()) == pending.binding_hash);
    if !bound {
        return refused(
            StatusCode::BAD_REQUEST,
            "this login was started in a different browser",
        );
    }
    let discovery = match auth.discovery().await {
        Ok(found) => found,
        Err(error) => return error.into_response(),
    };
    let token = match auth.exchange(&discovery, &code, &pending.verifier).await {
        Ok(token) => token,
        Err(response) => return response,
    };
    let claims = match auth.validate_id_token(&discovery.issuer, &token.id_token, &pending.nonce) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%error, "an ID token was rejected");
            return refused(StatusCode::UNAUTHORIZED, &error);
        }
    };
    let sub = claims["sub"].as_str().unwrap_or_default();
    let roles = auth.roles_for(sub, &claims);
    let principal = Principal {
        subject: format!("{}#{sub}", discovery.issuer.trim_end_matches('/')),
        name: claims["name"]
            .as_str()
            .or_else(|| claims["preferred_username"].as_str())
            .map(str::to_owned),
        roles,
    };
    if principal.roles.is_empty() {
        tracing::info!(subject = %principal.subject, "a login with no operator role was refused");
        return refused(StatusCode::FORBIDDEN, "your account holds no operator role");
    }
    let session_id = random_token();
    let ttl_ms = u64::try_from(auth.session_ttl.as_millis()).unwrap_or(u64::MAX);
    let context = Context::of(&principal, None);
    let opened = app.engine.transact(&context, None, |_| {
        Ok((
            vec![Change::SessionOpened {
                session_hash: sha256_hex(session_id.as_bytes()),
                principal: principal.clone(),
                expires_at: now().saturating_add(ttl_ms),
            }],
            (),
        ))
    });
    if let Err(error) = opened {
        return error.into_response();
    }
    signed_in(&pending.return_to, &session_id, auth.session_ttl)
}

/// The page that ends a login. A page rather than a redirect: the browser
/// arrived from the provider, cross-site, and a `SameSite=Strict` cookie is
/// withheld for the rest of that redirect chain. A same-site navigation
/// from this page carries it.
fn signed_in(return_to: &str, session_id: &str, ttl: Duration) -> Response {
    let target = return_to.replace('&', "&amp;");
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=\"0;url={target}\">\
         <title>Signed in</title><a href=\"{target}\">Continue</a>"
    );
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let session_cookie = format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        ttl.as_secs()
    );
    if let Ok(value) = HeaderValue::from_str(&session_cookie) {
        headers.append(header::SET_COOKIE, value);
    }
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-spindle-operator-login=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        ),
    );
    response
}

/// An authenticated request: who, and the request id the audit trail
/// records against their changes.
pub struct Authenticated {
    pub principal: Principal,
    pub session_hash: String,
    pub csrf_token: String,
    pub expires_at: u64,
    pub request: Option<String>,
}

impl Authenticated {
    #[must_use]
    pub fn context(&self) -> Context {
        Context::of(&self.principal, self.request.clone())
    }

    /// # Errors
    /// 403 when the principal lacks `role`.
    pub fn require(&self, role: Role) -> Result<(), ApiError> {
        if self.principal.has(role) {
            Ok(())
        } else {
            Err(ApiError::forbidden(format!(
                "this needs the {} role",
                format!("{role:?}").to_lowercase()
            )))
        }
    }
}

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, ApiError> {
        let unauthenticated =
            || ApiError::new(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in first");
        let session_id = cookie(&parts.headers, SESSION_COOKIE).ok_or_else(unauthenticated)?;
        let session_hash = sha256_hex(session_id.as_bytes());
        let session = app
            .engine
            .read(|state| state.sessions.get(&session_hash).cloned())
            .filter(|session| session.expires_at > now())
            .ok_or_else(unauthenticated)?;
        let csrf = csrf_token(&session_id);
        let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if !safe {
            let presented = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok());
            if presented != Some(csrf.as_str()) {
                return Err(ApiError::forbidden("missing or wrong X-CSRF-Token"));
            }
            if let Some(origin) = parts.headers.get(header::ORIGIN)
                && origin.to_str().ok() != Some(app.auth.public_url.as_str())
            {
                return Err(ApiError::forbidden("cross-origin request refused"));
            }
        }
        let request = parts
            .headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 128)
            .map(str::to_owned);
        Ok(Authenticated {
            principal: session.principal,
            session_hash,
            csrf_token: csrf,
            expires_at: session.expires_at,
            request,
        })
    }
}

async fn session(who: Authenticated) -> Response {
    let mut response = Json(json!({
        "principal": who.principal,
        "expires_at": who.expires_at,
        "csrf_token": who.csrf_token,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn logout(State(app): State<AppState>, who: Authenticated) -> Result<Response, ApiError> {
    let hash = who.session_hash.clone();
    app.engine.transact(&who.context(), None, |_| {
        Ok((vec![Change::SessionClosed { session_hash: hash }], ()))
    })?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
        ))
        .expect("a static cookie is a valid header"),
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_stay_on_this_origin() {
        assert_eq!(safe_return_to(Some("/changes?id=op_1")), "/changes?id=op_1");
        assert_eq!(safe_return_to(Some("//evil.example")), "/");
        assert_eq!(safe_return_to(Some("https://evil.example")), "/");
        assert_eq!(safe_return_to(Some("/\"><script>")), "/");
        assert_eq!(safe_return_to(None), "/");
    }

    #[test]
    fn cookies_are_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-spindle-operator=xyz"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(cookie(&headers, LOGIN_COOKIE), None);
    }
}
