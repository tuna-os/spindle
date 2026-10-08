//! What the built-in provider's server-rendered pages share (#607, #608):
//! the page shell, the security headers, cookies, CSRF, browser sessions
//! and the password-attempt budget.
//!
//! The pages are plain HTML forms with no script, like the authorization
//! page they grew from. Three rules hold for every one of them:
//!
//! - **Everything interpolated is escaped.** Values come from URLs and
//!   form fields a stranger can build.
//! - **Every state-changing POST carries a CSRF token**, compared in
//!   constant time: the browser session's own secret once signed in, a
//!   double-submit cookie before (the sign-in and forgot-password forms).
//! - **No page can be framed, cached or used to redirect off-site.**
//!   `frame-ancestors 'none'`, `no-store`, and every post-sign-in
//!   destination is a path on this server checked by [`safe_next`].
//!
//! Browser sessions are durable rows keyed by the BLAKE3 digest of the
//! cookie, the same treatment access tokens get: a copy of the store is
//! not a copy of anyone's session.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;
use crate::ratelimit::{FAILED_LOGIN_PER_ACCOUNT, FAILED_LOGIN_PER_SOURCE, RetryAfter};

/// The browser-session cookie.
pub(crate) const SESSION_COOKIE: &str = "spindle_session";

/// The double-submit CSRF cookie the signed-out forms use.
pub(crate) const CSRF_COOKIE: &str = "spindle_csrf";

/// How long a browser session lasts from sign-in. A week: long enough
/// that a second client's "Continue as …" finds it, short enough that a
/// forgotten shared computer stops being signed in. Everything that
/// changes a credential asks for the password again regardless.
pub(crate) const BROWSER_SESSION_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:0;background:#f4f4f4;\
color:#1b1d22}main{max-width:560px;margin:2rem auto;background:#fff;padding:2rem;\
border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15)}form{display:flex;\
flex-direction:column;gap:.75rem;margin:1rem 0}form.inline{display:inline;margin:0}\
input{padding:.5rem;font-size:1rem}button{padding:.6rem;font-size:1rem;cursor:pointer}\
button.danger{background:#b00;color:#fff;border:0;border-radius:4px}\
.error{color:#b00}.notice{color:#060}nav{display:flex;flex-wrap:wrap;gap:.75rem;\
margin-bottom:1rem;align-items:center}table{border-collapse:collapse;width:100%}\
td,th{text-align:left;padding:.4rem;border-bottom:1px solid #ddd}\
label.check{display:flex;gap:.5rem;align-items:center}code{word-break:break-all}";

/// A whole page: the shell every built-in page shares.
pub(crate) fn page(state: &AppState, title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>{title} — {server}</title><style>{STYLE}</style></head>\
         <body><main>{body}</main></body></html>",
        title = escape(title),
        server = escape(&state.config.server.name),
    )
}

/// Which `form-action` a page may declare. The authorization pages post
/// to themselves and are then redirected to the client's registered
/// redirect URI — another origin, often a custom scheme — and browsers
/// apply `form-action` to that redirect, so those pages cannot pin it.
#[derive(Clone, Copy)]
pub(crate) enum FormTargets {
    SelfOnly,
    Redirecting,
}

/// An HTML response with the headers every built-in page carries.
pub(crate) fn html(status: StatusCode, targets: FormTargets, body: String) -> Response {
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    secure_headers(headers, targets);
    response
}

/// `no-store`, no framing, no sniffing, no referrer, no script.
pub(crate) fn secure_headers(headers: &mut HeaderMap, targets: FormTargets) {
    let csp = match targets {
        FormTargets::SelfOnly => {
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'"
        }
        FormTargets::Redirecting => {
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; \
             base-uri 'none'"
        }
    };
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// A 303 to a path on this server, with the page headers.
pub(crate) fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    secure_headers(response.headers_mut(), FormTargets::SelfOnly);
    response
}

/// Escape for HTML text and double- or single-quoted attributes.
pub(crate) fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// `application/x-www-form-urlencoded` encoding of one value.
pub(crate) fn urlencode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// A hidden form field.
pub(crate) fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
        escape(name),
        escape(value)
    )
}

/// Where to go after signing in, if it is somewhere this server's
/// account pages live; the account home otherwise. The open-redirect
/// guard: anything absolute, scheme-relative (`//evil`), backslashed or
/// outside `/account` is replaced rather than followed.
pub(crate) fn safe_next(next: Option<&str>) -> String {
    const HOME: &str = "/account/";
    let Some(next) = next else {
        return HOME.to_owned();
    };
    let acceptable = next.len() <= 1024
        && (next == "/account" || next.starts_with("/account/") || next.starts_with("/account?"))
        && !next.contains("//")
        && !next.contains('\\')
        && !next.chars().any(char::is_control);
    if acceptable {
        next.to_owned()
    } else {
        HOME.to_owned()
    }
}

/// Constant-time equality for secrets: the time taken depends on the
/// lengths only, never on where the first difference is.
pub(crate) fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// 256 bits from the OS, hex-encoded.
pub(crate) fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    crate::secrets::fill(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The digest a secret is stored under.
pub(crate) fn digest(secret: &str) -> [u8; 32] {
    *blake3::hash(secret.as_bytes()).as_bytes()
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// One cookie's value from the request, if present.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// A `Set-Cookie` value: `HttpOnly`, `SameSite=Lax`, path `/`, and
/// `Secure` whenever the provider's issuer is https — always, in any
/// real deployment. Lax rather than Strict so that following the
/// account-management link out of a client still finds the session; the
/// forms are protected by their CSRF tokens, not by the cookie policy.
pub(crate) fn set_cookie(state: &AppState, name: &str, value: &str, max_age_secs: u64) -> String {
    let secure = if state.config.oidc_issuer_base().starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}{secure}")
}

/// Append a `Set-Cookie` header to a response.
pub(crate) fn with_cookie(mut response: Response, cookie: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The double-submit token for a signed-out form: the cookie's value if
/// the browser already has one, a fresh one (and the cookie to set)
/// otherwise.
pub(crate) fn signed_out_csrf(state: &AppState, headers: &HeaderMap) -> (String, Option<String>) {
    if let Some(existing) = cookie(headers, CSRF_COOKIE).filter(|value| value.len() == 64) {
        return (existing, None);
    }
    let fresh = random_secret();
    let set = set_cookie(state, CSRF_COOKIE, &fresh, 60 * 60);
    (fresh, Some(set))
}

/// Whether a signed-out form's token matches its cookie.
pub(crate) fn signed_out_csrf_ok(headers: &HeaderMap, presented: Option<&str>) -> bool {
    match (cookie(headers, CSRF_COOKIE), presented) {
        (Some(expected), Some(presented)) => ct_eq(expected.as_bytes(), presented.as_bytes()),
        _ => false,
    }
}

/// A signed-in browser.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BrowserSession {
    pub localpart: String,
    /// The CSRF secret every signed-in form carries.
    pub csrf: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// A digest of the account's password hash when the session began.
    /// Any password change — this server's pages, the client API, an
    /// admin's reset, an imported hash — changes the hash and so ends
    /// every browser session started before it, without each of those
    /// paths having to know browser sessions exist.
    pub credential: String,
}

impl BrowserSession {
    /// Whether a form's token is this session's.
    pub(crate) fn csrf_ok(&self, presented: Option<&str>) -> bool {
        presented.is_some_and(|presented| ct_eq(self.csrf.as_bytes(), presented.as_bytes()))
    }
}

fn storage(error: &impl std::fmt::Display) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

/// Start a browser session for `localpart`; returns the `Set-Cookie`
/// value. Lapsed sessions are swept on the way: the keyspace is bounded
/// by sign-ins in the last week.
pub(crate) fn start_browser_session(
    state: &AppState,
    localpart: &str,
) -> Result<String, MatrixError> {
    let now = now_ms();
    let store = state.store.as_ref();
    for (key, raw) in
        ReadView::scan_prefix(store, &keys::browser_session_prefix()).map_err(|e| storage(&e))?
    {
        let lapsed = serde_json::from_slice::<BrowserSession>(&raw)
            .ok()
            .is_none_or(|session| session.expires_ms <= now);
        if lapsed {
            Store::delete(store, &key).map_err(|e| storage(&e))?;
        }
    }
    let secret = random_secret();
    let session = BrowserSession {
        localpart: localpart.to_owned(),
        csrf: random_secret(),
        created_ms: now,
        expires_ms: now.saturating_add(BROWSER_SESSION_LIFETIME_MS),
        credential: credential_of(state, localpart)?.unwrap_or_default(),
    };
    Store::put(
        store,
        &keys::browser_session(&digest(&secret)),
        &serde_json::to_vec(&session).map_err(|e| storage(&e))?,
    )
    .map_err(|e| storage(&e))?;
    Ok(set_cookie(
        state,
        SESSION_COOKIE,
        &secret,
        BROWSER_SESSION_LIFETIME_MS / 1000,
    ))
}

/// The browser session a request carries, if it is live and its account
/// may still sign in (not deactivated, not locked).
pub(crate) fn browser_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<BrowserSession>, MatrixError> {
    let Some(secret) = cookie(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let key = keys::browser_session(&digest(&secret));
    let Some(raw) = ReadView::get(state.store.as_ref(), &key).map_err(|e| storage(&e))? else {
        return Ok(None);
    };
    let Ok(session) = serde_json::from_slice::<BrowserSession>(&raw) else {
        return Ok(None);
    };
    if session.expires_ms <= now_ms() {
        Store::delete(state.store.as_ref(), &key).map_err(|e| storage(&e))?;
        return Ok(None);
    }
    let account = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&session.localpart)
        .map_err(|e| storage(&e))?;
    let Some(account) = account.filter(|account| !account.deactivated && !account.locked) else {
        return Ok(None);
    };
    let current = credential_digest(&account.password_hash);
    if !ct_eq(current.as_bytes(), session.credential.as_bytes()) {
        Store::delete(state.store.as_ref(), &key).map_err(|e| storage(&e))?;
        return Ok(None);
    }
    Ok(Some(session))
}

fn credential_digest(password_hash: &str) -> String {
    blake3::hash(password_hash.as_bytes()).to_hex().to_string()
}

fn credential_of(state: &AppState, localpart: &str) -> Result<Option<String>, MatrixError> {
    Ok(
        Accounts::new(state.store.as_ref(), &state.config.server.name)
            .account(localpart)
            .map_err(|e| storage(&e))?
            .map(|account| credential_digest(&account.password_hash)),
    )
}

/// Carry the browser session this request holds across a password change
/// its own user just made, which would otherwise end it with the rest.
pub(crate) fn keep_browser_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), MatrixError> {
    let Some(secret) = cookie(headers, SESSION_COOKIE) else {
        return Ok(());
    };
    let key = keys::browser_session(&digest(&secret));
    let store = state.store.as_ref();
    let Some(mut session) = ReadView::get(store, &key)
        .map_err(|e| storage(&e))?
        .and_then(|raw| serde_json::from_slice::<BrowserSession>(&raw).ok())
    else {
        return Ok(());
    };
    session.credential = credential_of(state, &session.localpart)?.unwrap_or_default();
    Store::put(
        store,
        &key,
        &serde_json::to_vec(&session).map_err(|e| storage(&e))?,
    )
    .map_err(|e| storage(&e))
}

/// End the browser session this request carries; returns the cookie
/// that clears it in the browser.
pub(crate) fn end_browser_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, MatrixError> {
    if let Some(secret) = cookie(headers, SESSION_COOKIE) {
        Store::delete(
            state.store.as_ref(),
            &keys::browser_session(&digest(&secret)),
        )
        .map_err(|e| storage(&e))?;
    }
    Ok(set_cookie(state, SESSION_COOKIE, "", 0))
}

/// End every browser session of `localpart`, except the one this request
/// carries when `keep_current` — what a password change or reset does
/// to the other browsers that were signed in.
pub(crate) fn end_browser_sessions_of(
    state: &AppState,
    localpart: &str,
    keep: Option<&HeaderMap>,
) -> Result<(), MatrixError> {
    let current = keep
        .and_then(|headers| cookie(headers, SESSION_COOKIE))
        .map(|secret| keys::browser_session(&digest(&secret)));
    let store = state.store.as_ref();
    for (key, raw) in
        ReadView::scan_prefix(store, &keys::browser_session_prefix()).map_err(|e| storage(&e))?
    {
        if current.as_deref() == Some(key.as_slice()) {
            continue;
        }
        let theirs = serde_json::from_slice::<BrowserSession>(&raw)
            .ok()
            .is_none_or(|session| session.localpart == localpart);
        if theirs {
            Store::delete(store, &key).map_err(|e| storage(&e))?;
        }
    }
    Ok(())
}

/// The keys a password attempt is counted under: exactly the client
/// login's, so the API, the authorization page and the account pages
/// share one budget and a guesser gains nothing by switching doors.
fn budget_keys(localpart: &str, source: &str) -> [String; 2] {
    [
        format!("login:account:{localpart}"),
        format!("login:source:{source}"),
    ]
}

/// Spend one password attempt against both budgets, before the Argon2
/// work is done, or refuse.
pub(crate) fn spend_password_attempt(
    state: &AppState,
    localpart: &str,
    source: &str,
) -> Result<(), RetryAfter> {
    let [account, source] = budget_keys(localpart, source);
    state.limiter.check(&account, FAILED_LOGIN_PER_ACCOUNT)?;
    state.limiter.check(&source, FAILED_LOGIN_PER_SOURCE)
}

/// A correct password clears both budgets, as the client login does.
pub(crate) fn forget_password_attempts(state: &AppState, localpart: &str, source: &str) {
    for key in budget_keys(localpart, source) {
        state.limiter.forget(&key);
    }
}

/// `@alice:server`, `Alice` and `alice` all mean the same localpart.
pub(crate) fn localpart_of(user: &str) -> String {
    let user = user.trim();
    user.strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .map_or(user, |(name, _)| name)
        .to_lowercase()
}

/// The smallest password the pages accept. The client API's own floor
/// is the spec's (none); a page that asks a human to pick one can ask
/// for something that is not trivially guessed.
pub(crate) const MIN_PASSWORD_CHARS: usize = 8;

/// Check a new password and its confirmation; the message to show if not.
pub(crate) fn new_password_problem(password: &str, confirm: &str) -> Option<&'static str> {
    if password != confirm {
        Some("The two new passwords did not match.")
    } else if password.chars().count() < MIN_PASSWORD_CHARS {
        Some("Choose a password of at least 8 characters.")
    } else if password.len() > 1024 {
        Some("That password is too long.")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_account_paths_are_followed() {
        for good in [
            "/account/",
            "/account",
            "/account/?action=org.matrix.profile",
        ] {
            assert_eq!(safe_next(Some(good)), good);
        }
        for bad in [
            "https://evil.example/",
            "//evil.example/account/",
            "/account//evil.example",
            "/\\evil.example",
            "/account/\\\\evil",
            "/oauth2/authorize",
            "/accountant",
            "/account/\r\nSet-Cookie: x=y",
            "javascript:alert(1)",
        ] {
            assert_eq!(safe_next(Some(bad)), "/account/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/account/");
    }

    #[test]
    fn escaping_covers_both_quote_styles() {
        assert_eq!(
            escape("<a href='x' title=\"y\">&</a>"),
            "&lt;a href=&#39;x&#39; title=&quot;y&quot;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn constant_time_equality_is_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn cookies_are_found_among_others() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; spindle_session=s3cret; spindle_csrf=c"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("s3cret"));
        assert_eq!(cookie(&headers, CSRF_COOKIE).as_deref(), Some("c"));
        assert_eq!(cookie(&headers, "missing"), None);
    }

    #[test]
    fn localparts_fold_like_the_client_login() {
        assert_eq!(localpart_of("@Alice:example.org"), "alice");
        assert_eq!(localpart_of(" alice "), "alice");
    }

    #[test]
    fn new_passwords_must_match_and_be_long_enough() {
        assert!(new_password_problem("longenough", "longenough").is_none());
        assert!(new_password_problem("longenough", "different!").is_some());
        assert!(new_password_problem("short", "short").is_some());
    }
}
