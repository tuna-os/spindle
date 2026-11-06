//! Upstream OIDC identity providers (#610): sign-in delegated to Authelia,
//! Keycloak, Kanidm or any other OIDC provider, as MAS's `upstream_oauth2`
//! does it.
//!
//! The issuer clients know stays this server's; only the question "who is
//! this?" goes upstream. The answer is a localpart, and from there a sign-in
//! is exactly a password sign-in: the built-in provider's pages get a
//! browser session, and the client API's `m.login.sso` gets a login token.
//!
//! The flow is the authorization-code flow with PKCE, from this server as a
//! confidential (or public) client of the upstream:
//!
//! 1. `/upstream/authorize/{id}` (a button on the sign-in pages) or
//!    `/_matrix/client/v3/login/sso/redirect/{id}` (the client API) opens a
//!    flow: `state`, `nonce` and a PKCE verifier, all fresh, kept in memory
//!    for ten minutes, and a cookie that binds the flow to this browser.
//! 2. The upstream sends the browser back to `/upstream/callback/{id}`. The
//!    flow is taken (one use), the cookie checked (so nobody can finish a
//!    flow they started in someone else's browser), the code redeemed at
//!    the token endpoint, and the ID token verified: signature against the
//!    upstream's JWKS, `iss`, `aud`/`azp`, `exp`/`nbf` and the flow's `nonce`.
//! 3. `(provider id, sub)` is looked up in the link table. A first sign-in
//!    links to the account whose confirmed address is the upstream's
//!    verified one, only when the operator turned that on, and otherwise
//!    creates an account from the configured localpart claim, refusing a
//!    taken name rather than handing someone else's account over.
//!
//! Discovery and the JWKS are fetched on first use and cached, not at
//! startup: a server that cannot boot because an identity provider was
//! briefly down is an outage nobody asked for. Nothing here logs a token,
//! a code or a secret.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Digest;
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::{AccountError, Accounts};
use crate::config::{UpstreamClientAuth, UpstreamOidcConfig};
use crate::errors::MatrixError;
use crate::metrics::{LoginMethod, LoginResult};
use crate::ratelimit::FAILED_LOGIN_PER_SOURCE;
use crate::routes::ClientAddr;
use crate::web::{self, FormTargets, escape, urlencode};

/// How long a flow may take, from the button to the callback: long enough
/// for a person to type a password and pass a second factor upstream.
const FLOW_LIFETIME: Duration = Duration::from_secs(600);

/// The most flows held at once. Each is a few hundred bytes; the bound only
/// keeps a flood of unfinished flows from growing memory without limit.
const MAX_FLOWS: usize = 10_000;

/// How long a discovery document or key set is trusted before it is read
/// again.
const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60);

/// An ID token signed by a key this server does not hold triggers one
/// re-read of the key set (the upstream rotated), but not more often than
/// this, so a stream of forged tokens is not a stream of fetches.
const KEYS_REFRESH_FLOOR: Duration = Duration::from_secs(60);

/// Clock skew allowed on `exp` and `nbf`.
const CLOCK_LEEWAY_SECS: u64 = 60;

/// Every request to an upstream gives up after this.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The cookie that binds a flow to the browser that started it.
const BINDING_COOKIE: &str = "spindle_upstream";

/// The configured providers and the flows in progress.
pub struct Upstream {
    providers: Vec<Provider>,
    http: reqwest::Client,
    flows: Mutex<HashMap<String, Flow>>,
}

struct Provider {
    config: UpstreamOidcConfig,
    secret: String,
    metadata: Mutex<Option<(Instant, Arc<Metadata>)>>,
    keys: Mutex<Option<(Instant, Arc<Vec<Jwk>>)>>,
}

/// The parts of an OIDC provider's discovery document this client uses.
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// A JWKS, its keys left raw so one this server cannot read is skipped.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Value>,
}

/// One key of a JWKS (RFC 7517), with the members the algorithms here use.
#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

/// Where a finished sign-in goes.
#[derive(Clone, Debug)]
enum Target {
    /// The built-in provider's pages: a browser session, then this path on
    /// this server (an authorization request, or an account page).
    Page { next: String },
    /// The client API's SSO: a login token, handed to this client URL.
    Sso { redirect_url: String },
}

/// One flow, under its `state`.
struct Flow {
    provider: String,
    nonce: String,
    verifier: String,
    /// The BLAKE3 digest of the binding cookie's value.
    binding: [u8; 32],
    target: Target,
    expires: Instant,
}

/// The stored account link.
#[derive(Deserialize, Serialize)]
struct Link {
    localpart: String,
    linked_ms: u64,
}

/// Why a sign-in through an upstream failed: what the page tells the
/// person, and what the log tells the operator.
#[derive(Debug)]
struct Failure {
    status: StatusCode,
    shown: &'static str,
    logged: String,
}

impl Failure {
    fn upstream(logged: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            shown: "The identity provider could not be reached, or its answer could not be \
                    verified. Try again later.",
            logged: logged.into(),
        }
    }

    fn refused(status: StatusCode, shown: &'static str, logged: impl Into<String>) -> Self {
        Self {
            status,
            shown,
            logged: logged.into(),
        }
    }

    fn internal(error: &MatrixError) -> Self {
        Self::refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong on this server. Try again later.",
            error.error.clone(),
        )
    }
}

impl Upstream {
    /// The providers `[[auth.upstream_oidc]]` configures, or `None` when
    /// there are none.
    ///
    /// # Errors
    ///
    /// When a client secret file cannot be read, or the HTTP client cannot
    /// be built.
    pub fn new(configs: &[UpstreamOidcConfig]) -> Result<Option<Self>, String> {
        if configs.is_empty() {
            return Ok(None);
        }
        let providers = configs
            .iter()
            .map(|config| {
                Ok(Provider {
                    secret: config.resolve_secret()?,
                    config: config.clone(),
                    metadata: Mutex::new(None),
                    keys: Mutex::new(None),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        // No redirects: a token endpoint that redirects is misconfigured,
        // and following one would carry the client secret somewhere the
        // operator never named.
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("auth.upstream_oidc: {error}"))?;
        Ok(Some(Self {
            providers,
            http,
            flows: Mutex::new(HashMap::new()),
        }))
    }

    fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers
            .iter()
            .find(|provider| provider.config.id == id)
    }

    fn flows(&self) -> std::sync::MutexGuard<'_, HashMap<String, Flow>> {
        self.flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<T, Failure> {
        let mut request = self.http.get(url);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| Failure::upstream(format!("GET {url}: {error}")))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| Failure::upstream(format!("GET {url}: {error}")))?;
        if !status.is_success() {
            return Err(Failure::upstream(format!("GET {url}: HTTP {status}")));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| Failure::upstream(format!("GET {url}: {error}")))
    }

    /// The provider's discovery document, cached.
    async fn metadata(&self, provider: &Provider) -> Result<Arc<Metadata>, Failure> {
        let cached = lock(&provider.metadata).clone();
        if let Some((fetched, metadata)) = cached
            && fetched.elapsed() < DISCOVERY_TTL
        {
            return Ok(metadata);
        }
        let issuer = provider.config.issuer.trim_end_matches('/');
        let metadata: Metadata = self
            .get_json(&format!("{issuer}/.well-known/openid-configuration"), None)
            .await?;
        // OIDC Discovery §4.3: the document must name the issuer it was
        // fetched for, or it is someone else's.
        if metadata.issuer.trim_end_matches('/') != issuer {
            return Err(Failure::upstream(format!(
                "the discovery document of {issuer} names the issuer {:?}",
                metadata.issuer
            )));
        }
        let metadata = Arc::new(metadata);
        *lock(&provider.metadata) = Some((Instant::now(), Arc::clone(&metadata)));
        Ok(metadata)
    }

    /// The provider's signing keys, cached; `refresh` re-reads them unless
    /// that was done a moment ago.
    async fn keys(
        &self,
        provider: &Provider,
        metadata: &Metadata,
        refresh: bool,
    ) -> Result<Arc<Vec<Jwk>>, Failure> {
        let cached = lock(&provider.keys).clone();
        if let Some((fetched, keys)) = cached {
            let floor = if refresh {
                KEYS_REFRESH_FLOOR
            } else {
                DISCOVERY_TTL
            };
            if fetched.elapsed() < floor {
                return Ok(keys);
            }
        }
        let set: JwkSet = self.get_json(&metadata.jwks_uri, None).await?;
        // A key of a type this server cannot use is skipped, not fatal: a
        // set may carry encryption keys or newer algorithms beside the one
        // that signs.
        let keys: Arc<Vec<Jwk>> = Arc::new(
            set.keys
                .into_iter()
                .filter_map(|key| serde_json::from_value(key).ok())
                .collect(),
        );
        *lock(&provider.keys) = Some((Instant::now(), Arc::clone(&keys)));
        Ok(keys)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/upstream/authorize/{id}", get(authorize))
        .route("/upstream/callback/{id}", get(callback))
        .route("/_matrix/client/v3/login/sso/redirect", get(sso_redirect))
        .route(
            "/_matrix/client/v3/login/sso/redirect/{idp_id}",
            get(sso_redirect_to),
        )
}

fn not_configured() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "this server has no upstream identity providers",
    )
}

/// The client API's identity providers, for `GET /login`'s `m.login.sso`
/// flow; `None` when there are none, or sign-in is delegated.
pub(crate) fn identity_providers(state: &AppState) -> Option<Value> {
    if state.delegated.is_some() {
        return None;
    }
    let upstream = state.upstream.as_ref()?;
    Some(Value::Array(
        upstream
            .providers
            .iter()
            .map(|provider| json!({ "id": provider.config.id, "name": label(&provider.config) }))
            .collect(),
    ))
}

fn label(config: &UpstreamOidcConfig) -> &str {
    config.name.as_deref().unwrap_or(&config.id)
}

/// The "Sign in with …" buttons for a sign-in page whose sign-in should
/// end at `next`; empty without providers.
pub(crate) fn buttons(state: &AppState, next: &str) -> String {
    let Some(upstream) = &state.upstream else {
        return String::new();
    };
    let mut html = String::new();
    for provider in &upstream.providers {
        let _ = write!(
            html,
            "<p><a href=\"/upstream/authorize/{id}?next={next}\">Sign in with {name}</a></p>",
            id = escape(&urlencode(&provider.config.id)),
            next = escape(&urlencode(next)),
            name = escape(label(&provider.config)),
        );
    }
    html
}

/// Where a page sign-in may end: an authorization request of the built-in
/// provider, or an account page. Anything else is the account home, as
/// [`web::safe_next`] has it.
fn safe_next(next: Option<&str>) -> String {
    if let Some(next) = next
        && next.len() <= 4096
        && next.starts_with("/oauth2/authorize?")
        && !next.contains("//")
        && !next.contains('\\')
        && !next.chars().any(char::is_control)
    {
        return next.to_owned();
    }
    web::safe_next(next)
}

/// A page of this module: a message, and no link to pages that may not
/// exist (the client API's SSO works without the built-in provider).
fn notice(state: &AppState, status: StatusCode, title: &str, text: &str) -> Response {
    web::html(
        status,
        FormTargets::SelfOnly,
        web::page(
            state,
            title,
            &format!("<h1>{}</h1><p>{}</p>", escape(title), escape(text)),
        ),
    )
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
}

/// `GET /upstream/authorize/{id}` — a sign-in page's button.
async fn authorize(
    State(state): State<AppState>,
    Path(id): Path<String>,
    source: ClientAddr,
    Query(query): Query<NextQuery>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let next = safe_next(query.next.as_deref());
    begin(&state, &id, Target::Page { next }, &source.to_string()).await
}

#[derive(Deserialize)]
struct SsoQuery {
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
}

/// The client URL a login token may be handed to: an absolute URI with a
/// scheme (apps register custom ones), never a script-carrying one.
fn check_redirect_url(redirect_url: Option<String>) -> Result<String, MatrixError> {
    let invalid =
        |message: &str| MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message);
    let url = redirect_url.ok_or_else(|| MatrixError::missing_param("redirectUrl is required"))?;
    let scheme = url
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    let well_formed = scheme.as_deref().is_some_and(|scheme| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    if !well_formed || url.len() > 2048 || url.chars().any(char::is_control) {
        return Err(invalid("redirectUrl must be an absolute URI"));
    }
    if matches!(scheme.as_deref(), Some("javascript" | "data" | "vbscript")) {
        return Err(invalid("redirectUrl may not be a script"));
    }
    Ok(url)
}

/// `GET /_matrix/client/v3/login/sso/redirect` — with one provider, its
/// flow; with several, a page to choose.
async fn sso_redirect(
    State(state): State<AppState>,
    source: ClientAddr,
    Query(query): Query<SsoQuery>,
) -> Result<Response, MatrixError> {
    if state.delegated.is_some() {
        return Err(not_configured());
    }
    let upstream = state.upstream.clone().ok_or_else(not_configured)?;
    let redirect_url = check_redirect_url(query.redirect_url)?;
    if let [only] = upstream.providers.as_slice() {
        return begin(
            &state,
            &only.config.id,
            Target::Sso { redirect_url },
            &source.to_string(),
        )
        .await;
    }
    let mut list = String::new();
    for provider in &upstream.providers {
        let _ = write!(
            list,
            "<p><a href=\"/_matrix/client/v3/login/sso/redirect/{id}?redirectUrl={url}\">\
             Sign in with {name}</a></p>",
            id = escape(&urlencode(&provider.config.id)),
            url = escape(&urlencode(&redirect_url)),
            name = escape(label(&provider.config)),
        );
    }
    let body = format!(
        "<h1>Sign in to {server}</h1>{list}",
        server = escape(&state.config.server.name)
    );
    Ok(web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        web::page(&state, "Sign in", &body),
    ))
}

/// `GET /_matrix/client/v3/login/sso/redirect/{idpId}`
async fn sso_redirect_to(
    State(state): State<AppState>,
    Path(idp_id): Path<String>,
    source: ClientAddr,
    Query(query): Query<SsoQuery>,
) -> Result<Response, MatrixError> {
    if state.delegated.is_some() {
        return Err(not_configured());
    }
    let redirect_url = check_redirect_url(query.redirect_url)?;
    begin(
        &state,
        &idp_id,
        Target::Sso { redirect_url },
        &source.to_string(),
    )
    .await
}

/// Open a flow and send the browser upstream.
async fn begin(
    state: &AppState,
    id: &str,
    target: Target,
    source: &str,
) -> Result<Response, MatrixError> {
    let upstream = state.upstream.clone().ok_or_else(not_configured)?;
    let Some(provider) = upstream.provider(id) else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such identity provider",
        ));
    };
    // The login budget per source: each flow costs a fetch upstream and a
    // row in memory.
    if state
        .limiter
        .check(
            &format!("upstream:source:{source}"),
            FAILED_LOGIN_PER_SOURCE,
        )
        .is_err()
    {
        return Ok(notice(
            state,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-ins",
            "Wait a minute and try again.",
        ));
    }
    let metadata = match upstream.metadata(provider).await {
        Ok(metadata) => metadata,
        Err(failure) => {
            tracing::warn!(provider = id, reason = %failure.logged, "upstream sign-in could not start");
            return Ok(notice(
                state,
                failure.status,
                "Sign-in failed",
                failure.shown,
            ));
        }
    };
    let flow_state = web::random_secret();
    let nonce = web::random_secret();
    let verifier = web::random_secret();
    let binding = web::random_secret();
    let challenge = crate::oidc::base64url_unpadded(&sha2::Sha256::digest(verifier.as_bytes()));
    {
        let now = Instant::now();
        let mut flows = upstream.flows();
        flows.retain(|_, flow| flow.expires > now);
        if flows.len() >= MAX_FLOWS {
            return Ok(notice(
                state,
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many sign-ins",
                "Too many sign-ins are in progress. Try again in a few minutes.",
            ));
        }
        flows.insert(
            flow_state.clone(),
            Flow {
                provider: id.to_owned(),
                nonce: nonce.clone(),
                verifier,
                binding: web::digest(&binding),
                target,
                expires: now + FLOW_LIFETIME,
            },
        );
    }
    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.config.client_id)
        .append_pair("redirect_uri", &callback_url(state, id))
        .append_pair("scope", &provider.config.scopes.join(" "))
        .append_pair("state", &flow_state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let separator = if metadata.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!(
        "{}{separator}{}",
        metadata.authorization_endpoint,
        query.finish()
    );
    Ok(web::with_cookie(
        web::see_other(&location),
        &web::set_cookie(state, BINDING_COOKIE, &binding, FLOW_LIFETIME.as_secs()),
    ))
}

/// The redirect URI registered at the upstream: MAS's path shape, so a
/// provider moved from MAS keeps its registration.
fn callback_url(state: &AppState, id: &str) -> String {
    format!("{}/upstream/callback/{id}", crate::oidc::issuer(state))
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

/// `GET /upstream/callback/{id}`
async fn callback(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, MatrixError> {
    let upstream = state.upstream.clone().ok_or_else(not_configured)?;
    let (target, localpart) = match finish(&state, &upstream, &id, &headers, query).await {
        Ok(done) => done,
        Err(failure) => {
            state
                .metrics
                .record_login(LoginMethod::Upstream, LoginResult::Error);
            tracing::warn!(provider = %id, reason = %failure.logged, "upstream sign-in refused");
            return Ok(notice(
                &state,
                failure.status,
                "Sign-in failed",
                failure.shown,
            ));
        }
    };
    state
        .metrics
        .record_login(LoginMethod::Upstream, LoginResult::Success);
    let clear = web::set_cookie(&state, BINDING_COOKIE, "", 0);
    let response = match target {
        Target::Page { next } => {
            let session = web::start_browser_session(&state, &localpart)?;
            web::with_cookie(web::see_other(&next), &session)
        }
        Target::Sso { redirect_url } => {
            let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
            let (token, _) = accounts
                .issue_login_token(&localpart)
                .map_err(|error| crate::routes::internal(&error))?;
            sso_confirmation(&state, &redirect_url, &token, &accounts.user_id(&localpart))
        }
    };
    Ok(web::with_cookie(response, &clear))
}

/// The last page of a client API sign-in: a link back to the client, with
/// the login token. A page rather than a redirect, as Synapse has it, so a
/// sign-in somebody else started (with their own `redirectUrl`) shows the
/// person where their session is about to go before it goes.
fn sso_confirmation(state: &AppState, redirect_url: &str, token: &str, user_id: &str) -> Response {
    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    let target = format!("{redirect_url}{separator}loginToken={}", urlencode(token));
    let host = redirect_url
        .split_once("://")
        .map_or(redirect_url, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let body = format!(
        "<h1>Continue to your application?</h1>\
         <p>You are signed in as <strong>{user}</strong>. Continue only if you started this \
         sign-in yourself, in the application at <code>{host}</code>.</p>\
         <p><a href=\"{target}\">Continue to {host}</a></p>",
        user = escape(user_id),
        host = escape(host),
        target = escape(&target),
    );
    web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        web::page(state, "Continue", &body),
    )
}

/// Everything from the callback's query to a localpart.
async fn finish(
    state: &AppState,
    upstream: &Upstream,
    id: &str,
    headers: &HeaderMap,
    query: CallbackQuery,
) -> Result<(Target, String), Failure> {
    let expired = || {
        Failure::refused(
            StatusCode::BAD_REQUEST,
            "This sign-in has expired or was already used. Start again.",
            "unknown, spent or lapsed state",
        )
    };
    // Taken, not read: a flow finishes once, so a replayed callback (and
    // with it a replayed nonce) finds nothing.
    let flow = query
        .state
        .as_deref()
        .and_then(|flow_state| upstream.flows().remove(flow_state))
        .ok_or_else(expired)?;
    if flow.provider != id || flow.expires <= Instant::now() {
        return Err(expired());
    }
    let bound = web::cookie(headers, BINDING_COOKIE)
        .is_some_and(|value| web::ct_eq(&web::digest(&value), &flow.binding));
    if !bound {
        return Err(Failure::refused(
            StatusCode::FORBIDDEN,
            "This sign-in was started in another browser. Start again from this one.",
            "the binding cookie is missing or wrong",
        ));
    }
    if let Some(error) = query.error {
        return Err(Failure::refused(
            StatusCode::FORBIDDEN,
            "The identity provider did not sign you in.",
            format!("the provider answered error={error}"),
        ));
    }
    let code = query
        .code
        .ok_or_else(|| Failure::upstream("the callback carries no code"))?;
    let provider = upstream.provider(id).ok_or_else(expired)?;
    let metadata = upstream.metadata(provider).await?;
    let tokens = redeem(state, upstream, provider, &metadata, &code, &flow.verifier).await?;
    let expected = Expected {
        issuer: &metadata.issuer,
        client_id: &provider.config.client_id,
        nonce: &flow.nonce,
        now: web::now_ms() / 1000,
    };
    let keys = upstream.keys(provider, &metadata, false).await?;
    let verified = match verify_id_token(&tokens.id_token, &keys, &expected) {
        Err(IdTokenError::NoKey) => {
            let keys = upstream.keys(provider, &metadata, true).await?;
            verify_id_token(&tokens.id_token, &keys, &expected)
        }
        other => other,
    };
    let mut claims = verified
        .map_err(|error| Failure::upstream(format!("the ID token was refused: {error:?}")))?;
    if provider.config.fetch_userinfo {
        merge_userinfo(
            upstream,
            &metadata,
            tokens.access_token.as_deref(),
            &mut claims,
        )
        .await?;
    }
    let localpart = resolve_account(state, &provider.config, &claims)?;
    Ok((flow.target, localpart))
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    access_token: Option<String>,
}

/// Redeem the code at the token endpoint, with the PKCE verifier and the
/// client authentication the provider is configured for.
async fn redeem(
    state: &AppState,
    upstream: &Upstream,
    provider: &Provider,
    metadata: &Metadata,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse, Failure> {
    let config = &provider.config;
    let redirect_uri = callback_url(state, &config.id);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier),
    ];
    let mut request = upstream.http.post(&metadata.token_endpoint);
    match config.token_endpoint_auth_method {
        // RFC 6749 §2.3.1: both halves form-encoded before Basic encodes them.
        UpstreamClientAuth::ClientSecretBasic => {
            request = request.basic_auth(
                urlencode(&config.client_id),
                Some(urlencode(&provider.secret)),
            );
        }
        UpstreamClientAuth::ClientSecretPost => {
            form.push(("client_id", &config.client_id));
            form.push(("client_secret", &provider.secret));
        }
        UpstreamClientAuth::None => form.push(("client_id", &config.client_id)),
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|error| Failure::upstream(format!("token endpoint: {error}")))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| Failure::upstream(format!("token endpoint: {error}")))?;
    if !status.is_success() {
        // The body is an RFC 6749 error object; its `error` code is safe
        // to log, the rest may echo the request.
        let code = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|body| body["error"].as_str().map(str::to_owned))
            .unwrap_or_default();
        return Err(Failure::upstream(format!(
            "token endpoint: HTTP {status} {code}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| Failure::upstream(format!("token endpoint answer: {error}")))
}

/// Add the userinfo endpoint's claims to the ID token's, for a provider
/// that keeps them out of the token. The ID token's own claims win, and the
/// answer must be about the same subject (OIDC Core §5.3.2).
async fn merge_userinfo(
    upstream: &Upstream,
    metadata: &Metadata,
    access_token: Option<&str>,
    claims: &mut Map<String, Value>,
) -> Result<(), Failure> {
    let (Some(endpoint), Some(access_token)) = (&metadata.userinfo_endpoint, access_token) else {
        return Err(Failure::upstream(
            "fetch_userinfo is on, but there is no userinfo endpoint or access token",
        ));
    };
    let info: Map<String, Value> = upstream.get_json(endpoint, Some(access_token)).await?;
    if info.get("sub") != claims.get("sub") {
        return Err(Failure::upstream("userinfo is about another subject"));
    }
    for (name, value) in info {
        claims.entry(name).or_insert(value);
    }
    Ok(())
}

/// The account an upstream identity signs in as: its link, an account
/// found by verified address (when allowed), or a new one.
fn resolve_account(
    state: &AppState,
    config: &UpstreamOidcConfig,
    claims: &Map<String, Value>,
) -> Result<String, Failure> {
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = keys::upstream_link(&config.id, subject);
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let storage = |error: &dyn std::fmt::Display| {
        Failure::internal(&MatrixError::internal(&error.to_string()))
    };
    let linked = ReadView::get(state.store.as_ref(), &key)
        .map_err(|error| storage(&error))?
        .and_then(|raw| serde_json::from_slice::<Link>(&raw).ok());
    if let Some(link) = linked {
        let usable = accounts
            .account(&link.localpart)
            .map_err(|error| storage(&error))?
            .is_some_and(|account| !account.deactivated && !account.locked);
        if !usable {
            return Err(Failure::refused(
                StatusCode::FORBIDDEN,
                "The account this sign-in belongs to is deactivated or locked.",
                "the linked account cannot sign in",
            ));
        }
        return Ok(link.localpart);
    }

    let verified_address = (claims.get("email_verified") == Some(&Value::Bool(true)))
        .then(|| claims.get(&config.email_claim).and_then(Value::as_str))
        .flatten()
        .and_then(crate::email::normalize);
    if config.link_existing_by_email
        && let Some(address) = &verified_address
        && let Some(owner) =
            crate::email::owner_of(state, address).map_err(|e| Failure::internal(&e))?
    {
        let usable = accounts
            .account(&owner)
            .map_err(|error| storage(&error))?
            .is_some_and(|account| !account.deactivated && !account.locked);
        if usable {
            write_link(state, &key, &owner)?;
            return Ok(owner);
        }
    }

    let localpart = provision(state, config, claims)?;
    write_link(state, &key, &localpart)?;
    let user_id = accounts.user_id(&localpart);
    if let Some(name) = claims
        .get(&config.displayname_claim)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let name: String = name.chars().take(256).collect();
        state
            .profiles
            .set(&user_id, Some(Some(name)), None)
            .map_err(|error| storage(&error))?;
    }
    // The upstream vouched for the address; an address another account
    // already holds stays where it is.
    if let Some(address) = verified_address
        && crate::email::owner_of(state, &address)
            .map_err(|e| Failure::internal(&e))?
            .is_none()
    {
        crate::email::bind(state, &localpart, &address).map_err(|e| Failure::internal(&e))?;
    }
    Ok(localpart)
}

/// A new account for a first sign-in, named by the localpart claim.
fn provision(
    state: &AppState,
    config: &UpstreamOidcConfig,
    claims: &Map<String, Value>,
) -> Result<String, Failure> {
    let Some(wanted) = claims
        .get(&config.localpart_claim)
        .and_then(Value::as_str)
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
    else {
        return Err(Failure::refused(
            StatusCode::FORBIDDEN,
            "The identity provider did not say which username to use, so no account could be made.",
            format!("no {:?} claim", config.localpart_claim),
        ));
    };
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let taken = || {
        Failure::refused(
            StatusCode::CONFLICT,
            "An account with your username already exists here and is not linked to this \
             sign-in. Ask an administrator.",
            format!("the localpart {wanted:?} is taken"),
        )
    };
    if state
        .appservices
        .exclusively_claims(&accounts.user_id(&wanted))
    {
        return Err(taken());
    }
    match accounts.register(&wanted, &crate::accounts::unguessable_password()) {
        Ok(_) => Ok(wanted),
        Err(AccountError::UserInUse) => Err(taken()),
        Err(AccountError::InvalidUsername) => Err(Failure::refused(
            StatusCode::FORBIDDEN,
            "Your username at the identity provider cannot be used as a Matrix username here.",
            format!("the localpart {wanted:?} is not valid"),
        )),
        Err(other) => Err(Failure::internal(&MatrixError::internal(
            &other.to_string(),
        ))),
    }
}

fn write_link(state: &AppState, key: &[u8], localpart: &str) -> Result<(), Failure> {
    let row = serde_json::to_vec(&Link {
        localpart: localpart.to_owned(),
        linked_ms: web::now_ms(),
    })
    .map_err(|error| Failure::internal(&MatrixError::internal(&error.to_string())))?;
    Store::put(state.store.as_ref(), key, &row)
        .map_err(|error| Failure::internal(&MatrixError::internal(&error.to_string())))
}

/// What an ID token must say.
struct Expected<'a> {
    issuer: &'a str,
    client_id: &'a str,
    nonce: &'a str,
    /// Seconds since the epoch.
    now: u64,
}

/// Why an ID token was refused.
#[derive(Debug, Eq, PartialEq)]
enum IdTokenError {
    Malformed,
    /// `none`, the HMAC family, or something newer.
    UnsupportedAlgorithm(String),
    /// No key in the set fits the token's `kid` and algorithm.
    NoKey,
    BadSignature,
    Issuer,
    Audience,
    Expired,
    NotYetValid,
    Nonce,
    NoSubject,
}

/// The asymmetric JWS algorithms (RFC 7518 §3, RFC 8037) a provider may
/// sign ID tokens with. `none` and the HMAC family are refused: the first
/// is no signature, and the second would make the client secret a key
/// anyone holding it could mint tokens with.
#[derive(Clone, Copy)]
enum Algorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

impl Algorithm {
    fn of(name: &str) -> Option<Self> {
        Some(match name {
            "RS256" => Self::Rs256,
            "RS384" => Self::Rs384,
            "RS512" => Self::Rs512,
            "PS256" => Self::Ps256,
            "PS384" => Self::Ps384,
            "PS512" => Self::Ps512,
            "ES256" => Self::Es256,
            "ES384" => Self::Es384,
            "EdDSA" => Self::EdDsa,
            _ => return None,
        })
    }

    /// Whether `key` signed `message`; `None` when the key is not one this
    /// algorithm can use at all.
    fn verify(self, key: &Jwk, message: &[u8], signature: &[u8]) -> Option<bool> {
        use ring::signature as sig;
        let rsa: Option<&sig::RsaParameters> = match self {
            Self::Rs256 => Some(&sig::RSA_PKCS1_2048_8192_SHA256),
            Self::Rs384 => Some(&sig::RSA_PKCS1_2048_8192_SHA384),
            Self::Rs512 => Some(&sig::RSA_PKCS1_2048_8192_SHA512),
            Self::Ps256 => Some(&sig::RSA_PSS_2048_8192_SHA256),
            Self::Ps384 => Some(&sig::RSA_PSS_2048_8192_SHA384),
            Self::Ps512 => Some(&sig::RSA_PSS_2048_8192_SHA512),
            _ => None,
        };
        if let Some(parameters) = rsa {
            if key.kty != "RSA" {
                return None;
            }
            let components = sig::RsaPublicKeyComponents {
                n: b64(key.n.as_deref()?)?,
                e: b64(key.e.as_deref()?)?,
            };
            return Some(components.verify(parameters, message, signature).is_ok());
        }
        let (family, curve, algorithm, coordinate): (
            _,
            _,
            &'static dyn sig::VerificationAlgorithm,
            _,
        ) = match self {
            Self::Es256 => ("EC", "P-256", &sig::ECDSA_P256_SHA256_FIXED, 32),
            Self::Es384 => ("EC", "P-384", &sig::ECDSA_P384_SHA384_FIXED, 48),
            _ => ("OKP", "Ed25519", &sig::ED25519, 32),
        };
        if key.kty != family || key.crv.as_deref() != Some(curve) {
            return None;
        }
        let x = b64(key.x.as_deref()?)?;
        let public = if family == "EC" {
            // SEC 1's uncompressed point: 0x04, then x and y.
            let y = b64(key.y.as_deref()?)?;
            if x.len() != coordinate || y.len() != coordinate {
                return None;
            }
            [&[4_u8][..], &x, &y].concat()
        } else {
            x
        };
        Some(
            sig::UnparsedPublicKey::new(algorithm, public)
                .verify(message, signature)
                .is_ok(),
        )
    }
}

fn b64(text: &str) -> Option<Vec<u8>> {
    ruma::serde::Base64::<ruma::serde::base64::UrlSafe>::parse(text)
        .ok()
        .map(ruma::serde::Base64::into_inner)
}

/// Verify an ID token (OIDC Core §3.1.3.7) and return its claims.
fn verify_id_token(
    token: &str,
    keys: &[Jwk],
    expected: &Expected<'_>,
) -> Result<Map<String, Value>, IdTokenError> {
    let mut parts = token.split('.');
    let (Some(header_part), Some(payload_part), Some(signature_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(IdTokenError::Malformed);
    };
    let header: Value = b64(header_part)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(IdTokenError::Malformed)?;
    let name = header["alg"].as_str().ok_or(IdTokenError::Malformed)?;
    let algorithm =
        Algorithm::of(name).ok_or_else(|| IdTokenError::UnsupportedAlgorithm(name.to_owned()))?;
    let kid = header["kid"].as_str();
    let signature = b64(signature_part).ok_or(IdTokenError::Malformed)?;
    let message = &token.as_bytes()[..header_part.len() + 1 + payload_part.len()];
    let mut usable = false;
    let mut good = false;
    for key in keys.iter().filter(|key| {
        key.usage.as_deref() != Some("enc")
            && kid.is_none_or(|kid| key.kid.as_deref() == Some(kid))
            && key.alg.as_deref().is_none_or(|alg| alg == name)
    }) {
        match algorithm.verify(key, message, &signature) {
            Some(true) => {
                good = true;
                break;
            }
            Some(false) => usable = true,
            None => {}
        }
    }
    if !good {
        return Err(if usable {
            IdTokenError::BadSignature
        } else {
            IdTokenError::NoKey
        });
    }

    let claims = b64(payload_part)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|claims| match claims {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .ok_or(IdTokenError::Malformed)?;
    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(IdTokenError::Issuer);
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(audience)) => audience == expected.client_id,
        Some(Value::Array(audiences)) => {
            audiences.iter().any(|audience| audience == expected.client_id)
                // §3.1.3.7 items 4-5: with other audiences beside this
                // client, the party the token was issued to must be it.
                && (audiences.len() == 1
                    || claims
                        .get("azp")
                        .is_some_and(|azp| azp == expected.client_id))
        }
        _ => false,
    };
    if !audience_ok {
        return Err(IdTokenError::Audience);
    }
    let expires = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(IdTokenError::Malformed)?;
    if expires.saturating_add(CLOCK_LEEWAY_SECS) <= expected.now {
        return Err(IdTokenError::Expired);
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|not_before| not_before > expected.now.saturating_add(CLOCK_LEEWAY_SECS))
    {
        return Err(IdTokenError::NotYetValid);
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(expected.nonce) {
        return Err(IdTokenError::Nonce);
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(IdTokenError::NoSubject);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    fn key_pair() -> (EcdsaKeyPair, Jwk) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref();
        let jwk = Jwk {
            kty: "EC".to_owned(),
            kid: Some("k1".to_owned()),
            usage: Some("sig".to_owned()),
            alg: Some("ES256".to_owned()),
            crv: Some("P-256".to_owned()),
            n: None,
            e: None,
            x: Some(crate::oidc::base64url_unpadded(&point[1..33])),
            y: Some(crate::oidc::base64url_unpadded(&point[33..])),
        };
        (pair, jwk)
    }

    fn sign(pair: &EcdsaKeyPair, claims: &Value) -> String {
        let header = crate::oidc::base64url_unpadded(
            json!({ "alg": "ES256", "kid": "k1" })
                .to_string()
                .as_bytes(),
        );
        let payload = crate::oidc::base64url_unpadded(claims.to_string().as_bytes());
        let message = format!("{header}.{payload}");
        let signature = pair
            .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap();
        format!(
            "{message}.{}",
            crate::oidc::base64url_unpadded(signature.as_ref())
        )
    }

    const EXPECTED: Expected<'static> = Expected {
        issuer: "https://idp.example",
        client_id: "spindle",
        nonce: "nonce-1",
        now: 1_000_000,
    };

    fn claims() -> Value {
        json!({
            "iss": "https://idp.example", "aud": "spindle", "sub": "u1",
            "exp": 1_000_300, "iat": 1_000_000, "nonce": "nonce-1",
        })
    }

    #[test]
    fn a_good_token_verifies_and_each_check_bites() {
        let (pair, jwk) = key_pair();
        let keys = [jwk];
        assert!(verify_id_token(&sign(&pair, &claims()), &keys, &EXPECTED).is_ok());
        for (field, value, error) in [
            ("iss", json!("https://evil.example"), IdTokenError::Issuer),
            ("aud", json!("someone-else"), IdTokenError::Audience),
            ("aud", json!(["spindle", "other"]), IdTokenError::Audience),
            ("exp", json!(900_000), IdTokenError::Expired),
            ("nbf", json!(2_000_000), IdTokenError::NotYetValid),
            ("nonce", json!("replayed"), IdTokenError::Nonce),
            ("sub", json!(""), IdTokenError::NoSubject),
        ] {
            let mut altered = claims();
            altered[field] = value;
            assert_eq!(
                verify_id_token(&sign(&pair, &altered), &keys, &EXPECTED).unwrap_err(),
                error,
                "{field}"
            );
        }
        let mut with_azp = claims();
        with_azp["aud"] = json!(["spindle", "other"]);
        with_azp["azp"] = json!("spindle");
        assert!(verify_id_token(&sign(&pair, &with_azp), &keys, &EXPECTED).is_ok());
    }

    #[test]
    fn a_foreign_key_or_a_tampered_token_is_refused() {
        let (pair, _) = key_pair();
        let (_, other) = key_pair();
        assert_eq!(
            verify_id_token(&sign(&pair, &claims()), &[other], &EXPECTED).unwrap_err(),
            IdTokenError::BadSignature
        );
        let (pair, jwk) = key_pair();
        let token = sign(&pair, &claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = crate::oidc::base64url_unpadded(
            json!({ "iss": "https://idp.example", "aud": "spindle", "sub": "admin",
                    "exp": 1_000_300, "nonce": "nonce-1" })
            .to_string()
            .as_bytes(),
        );
        parts[1] = &forged;
        assert_eq!(
            verify_id_token(&parts.join("."), std::slice::from_ref(&jwk), &EXPECTED).unwrap_err(),
            IdTokenError::BadSignature
        );
        let unsigned = format!(
            "{}.{}.",
            crate::oidc::base64url_unpadded(br#"{"alg":"none"}"#),
            parts[1]
        );
        assert_eq!(
            verify_id_token(&unsigned, &[jwk], &EXPECTED).unwrap_err(),
            IdTokenError::UnsupportedAlgorithm("none".to_owned())
        );
    }

    #[test]
    fn only_paths_on_this_server_are_destinations() {
        assert_eq!(
            safe_next(Some("/oauth2/authorize?client_id=x")),
            "/oauth2/authorize?client_id=x"
        );
        assert_eq!(
            safe_next(Some("/account/?action=emails")),
            "/account/?action=emails"
        );
        assert_eq!(safe_next(Some("https://evil.example/")), "/account/");
        assert_eq!(safe_next(Some("/oauth2/authorize?x=//evil")), "/account/");
    }

    #[test]
    fn client_urls_must_be_absolute_and_not_scripts() {
        assert!(check_redirect_url(Some("https://app.example/cb".to_owned())).is_ok());
        assert!(check_redirect_url(Some("io.element.app:/callback".to_owned())).is_ok());
        assert!(check_redirect_url(Some("/relative".to_owned())).is_err());
        assert!(check_redirect_url(Some("javascript:alert(1)".to_owned())).is_err());
        assert!(check_redirect_url(None).is_err());
    }

    /// RFC 7515 Appendix A.2: an RS256 JWS and the public half of its key.
    /// Its claims carry no `aud`, so a token whose signature and `iss` pass
    /// stops at the audience check — the RSA path verifying a real token.
    #[test]
    fn the_rfc_7515_rs256_example_verifies() {
        // spellchecker:off
        let jwk = Jwk {
            kty: "RSA".to_owned(),
            kid: None,
            usage: None,
            alg: None,
            crv: None,
            n: Some(
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJ\
                 PMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0\
                 LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uD\
                 Zlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2\
                 PAcDTW9gb54h4FRWyuXpoQ"
                    .to_owned(),
            ),
            e: Some("AQAB".to_owned()),
            x: None,
            y: None,
        };
        let token = "eyJhbGciOiJSUzI1NiJ9.\
            eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
            cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W\
            2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkS\
            jtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnv\
            Wh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let expected = Expected {
            issuer: "joe",
            client_id: "spindle",
            nonce: "",
            now: 0,
        };
        assert_eq!(
            verify_id_token(token, std::slice::from_ref(&jwk), &expected).unwrap_err(),
            IdTokenError::Audience
        );
        let tampered = token.replacen("cC4h", "cC4i", 1);
        assert_eq!(
            verify_id_token(&tampered, &[jwk], &expected).unwrap_err(),
            IdTokenError::BadSignature
        );
        // spellchecker:on
    }
}
