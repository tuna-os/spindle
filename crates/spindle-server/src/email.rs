//! Email for the built-in provider (#608): addresses on accounts, their
//! verification, and resetting a forgotten password.
//!
//! Three properties decide the shape of everything here:
//!
//! - **Tokens are single-use, expiring, and stored as digests.** A link
//!   carries 256 bits from the OS; the store keeps its BLAKE3 digest, so a
//!   copy of the store resets nobody's password. Redeeming deletes the row
//!   before acting on it, and a lapsed row is as dead as a missing one.
//! - **The forgot-password page cannot be asked who has an account.** It
//!   answers the same page, with the same status, after the same work,
//!   for every address: the lookup, the token and the mail all happen
//!   after the response, in a task of their own. Rate limits are per
//!   source and per address, and neither depends on the address existing.
//! - **Mail goes through [`Mailer`]**, an object rather than a function, so
//!   a test (or a future transport) supplies its own: [`MemoryMailer`]
//!   keeps what it was given. [`SmtpMailer`] is the production one, over
//!   `lettre` and the same rustls stack as everything else here.
//!
//! Nothing here logs an address, a token or a link. A delivery failure is
//! logged by kind and failure class only.

use std::fmt::Write as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::accounts::Accounts;
use crate::auth::Authenticated;
use crate::config::{EmailConfig, EmailTls};
use crate::errors::MatrixError;
use crate::metrics::{AccountAction, EmailKind, PasswordRecoveryMethod, PasswordRecoveryResult};
use crate::ratelimit::{
    EMAIL_PER_USER, FAILED_LOGIN_PER_SOURCE, RESET_REQUEST_PER_ADDRESS, RESET_REQUEST_PER_SOURCE,
};
use crate::routes::ClientAddr;
use crate::web::{self, BrowserSession, FormTargets, escape, hidden};

/// How long a password-reset link works: an hour, the window in which
/// somebody who asked for one is reading their mail.
pub const RESET_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// How long an address-verification link works: a day, because adding an
/// address is not urgent and the mail may sit unread for a while.
pub const VERIFY_TOKEN_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

/// One message to send. The `From:` is the transport's own.
#[derive(Clone, Debug)]
pub struct OutgoingEmail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Why a message was not sent, in classes that are safe to log: an SMTP
/// error's text can quote the recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailFailure {
    /// The relay refused it for good (5xx).
    Permanent,
    /// The relay refused it for now (4xx).
    Transient,
    /// The relay could not be reached, or TLS failed, or it timed out.
    Connection,
    /// The message itself could not be built (a bad address).
    Message,
}

impl std::fmt::Display for MailFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Permanent => "permanent refusal",
            Self::Transient => "transient refusal",
            Self::Connection => "connection failure",
            Self::Message => "unbuildable message",
        })
    }
}

/// A boxed send, so [`Mailer`] stays object-safe.
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), MailFailure>> + Send + 'a>>;

/// Where outgoing mail goes.
pub trait Mailer: Send + Sync {
    fn send(&self, email: OutgoingEmail) -> SendFuture<'_>;
}

/// The SMTP transport `[email]` configures.
pub struct SmtpMailer {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl SmtpMailer {
    /// Build the transport from `[email]`. Nothing connects until the
    /// first message: a relay that is briefly down at startup is not a
    /// reason to refuse to serve.
    ///
    /// # Errors
    ///
    /// A description of what is wrong with the configuration — never the
    /// password.
    pub fn new(config: &EmailConfig, hello_name: &str) -> Result<Self, String> {
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::transport::smtp::extension::ClientId;
        type Transport = lettre::AsyncSmtpTransport<lettre::Tokio1Executor>;
        let from: lettre::message::Mailbox = config
            .from
            .parse()
            .map_err(|_| "email.from is not a mailbox".to_owned())?;
        let builder = match config.tls {
            EmailTls::Tls => Transport::relay(&config.smtp_host),
            EmailTls::Starttls => Transport::starttls_relay(&config.smtp_host),
            EmailTls::None => Ok(Transport::builder_dangerous(&config.smtp_host)),
        }
        .map_err(|_| "email.smtp_host cannot be used for TLS".to_owned())?;
        let mut builder = builder
            .port(config.port())
            .hello_name(ClientId::Domain(hello_name.to_owned()))
            .timeout(Some(Duration::from_secs(30)));
        if let Some(username) = &config.username {
            let password = config.resolve_password()?;
            builder = builder.credentials(Credentials::new(username.clone(), password));
        }
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
}

impl Mailer for SmtpMailer {
    fn send(&self, email: OutgoingEmail) -> SendFuture<'_> {
        Box::pin(async move {
            use lettre::AsyncTransport as _;
            let to: lettre::message::Mailbox =
                email.to.parse().map_err(|_| MailFailure::Message)?;
            let message = lettre::Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(email.subject)
                .header(lettre::message::header::ContentType::TEXT_PLAIN)
                .body(email.body)
                .map_err(|_| MailFailure::Message)?;
            self.transport
                .send(message)
                .await
                .map(|_| ())
                .map_err(|error| {
                    if error.is_permanent() {
                        MailFailure::Permanent
                    } else if error.is_transient() {
                        MailFailure::Transient
                    } else {
                        MailFailure::Connection
                    }
                })
        })
    }
}

/// A mailbox in memory: every message handed to it, in order. For tests,
/// and for anyone who wants to see what the server would have sent.
#[derive(Default)]
pub struct MemoryMailer {
    sent: Mutex<Vec<OutgoingEmail>>,
}

impl MemoryMailer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything sent so far.
    #[must_use]
    pub fn sent(&self) -> Vec<OutgoingEmail> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Mailer for MemoryMailer {
    fn send(&self, email: OutgoingEmail) -> SendFuture<'_> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(email);
        Box::pin(async { Ok(()) })
    }
}

/// Whether this server sends mail: the built-in provider with a mailer.
#[must_use]
pub fn configured(state: &AppState) -> bool {
    state.oidc.is_some() && state.mailer.is_some()
}

/// An address as this server stores and compares it: trimmed and
/// lowercased, and only if it parses as an address at all. The whole
/// address is folded, the local part included — strictly a mail server
/// may tell `Alice@` from `alice@`, but no person means two accounts by
/// it, and treating them as two would let one inbox own two identities.
#[must_use]
pub fn normalize(address: &str) -> Option<String> {
    let folded = address.trim().to_lowercase();
    (folded.len() <= 254 && folded.parse::<lettre::Address>().is_ok()).then_some(folded)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenKind {
    Verify,
    Reset,
}

/// One emailed link's row, under the digest of its token.
#[derive(Debug, Deserialize, Serialize)]
struct TokenRow {
    kind: TokenKind,
    localpart: String,
    email: String,
    expires_ms: u64,
}

/// A verified address on an account.
#[derive(Debug, Deserialize, Serialize)]
struct EmailRow {
    added_ms: u64,
}

fn storage(error: &impl std::fmt::Display) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

fn decode<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Option<T> {
    serde_json::from_slice(raw).ok()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MatrixError> {
    serde_json::to_vec(value).map_err(|e| storage(&e))
}

/// The verified addresses of one account, with when each was added.
fn addresses_of(state: &AppState, localpart: &str) -> Result<Vec<(String, u64)>, MatrixError> {
    let prefix = keys::user_email_prefix(localpart);
    let mut out = Vec::new();
    for (key, raw) in
        ReadView::scan_prefix(state.store.as_ref(), &prefix).map_err(|e| storage(&e))?
    {
        let Some(address) = key
            .get(prefix.len()..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            continue;
        };
        let added = decode::<EmailRow>(&raw).map_or(0, |row| row.added_ms);
        out.push((address.to_owned(), added));
    }
    Ok(out)
}

/// Who an address belongs to, if anyone.
fn owner_of(state: &AppState, address: &str) -> Result<Option<String>, MatrixError> {
    Ok(
        ReadView::get(state.store.as_ref(), &keys::email_owner(address))
            .map_err(|e| storage(&e))?
            .and_then(|raw| String::from_utf8(raw).ok()),
    )
}

fn bind(state: &AppState, localpart: &str, address: &str) -> Result<(), MatrixError> {
    state
        .store
        .commit(
            &[
                (keys::email_owner(address), localpart.as_bytes().to_vec()),
                (
                    keys::user_email(localpart, address),
                    encode(&EmailRow {
                        added_ms: web::now_ms(),
                    })?,
                ),
            ],
            spindle_store::Durability::Group,
        )
        .map_err(|e| storage(&e))
}

fn unbind(state: &AppState, localpart: &str, address: &str) -> Result<(), MatrixError> {
    let store = state.store.as_ref();
    if owner_of(state, address)?.as_deref() == Some(localpart) {
        Store::delete(store, &keys::email_owner(address)).map_err(|e| storage(&e))?;
    }
    Store::delete(store, &keys::user_email(localpart, address)).map_err(|e| storage(&e))
}

/// Release every address of an account, and every link outstanding for
/// it — what deactivation does, so a deactivated account's address can
/// be used again and its last reset link dies with it.
///
/// # Errors
///
/// A storage error.
pub(crate) fn forget_account(state: &AppState, localpart: &str) -> Result<(), MatrixError> {
    for (address, _) in addresses_of(state, localpart)? {
        unbind(state, localpart, &address)?;
    }
    drop_tokens(state.store.as_ref(), |row| row.localpart == localpart)
}

/// Drop every outstanding reset link of an account — what any other
/// successful recovery does, so an older link cannot undo it.
///
/// # Errors
///
/// A storage error.
pub(crate) fn drop_reset_links(
    store: &spindle_store::FjallStore,
    localpart: &str,
) -> Result<(), MatrixError> {
    drop_tokens(store, |row| {
        row.kind == TokenKind::Reset && row.localpart == localpart
    })
}

/// Delete every token row `doomed` picks, and every lapsed one.
fn drop_tokens(
    store: &spindle_store::FjallStore,
    doomed: impl Fn(&TokenRow) -> bool,
) -> Result<(), MatrixError> {
    let now = web::now_ms();
    for (key, raw) in
        ReadView::scan_prefix(store, &keys::email_token_prefix()).map_err(|e| storage(&e))?
    {
        let gone = decode::<TokenRow>(&raw).is_none_or(|row| row.expires_ms <= now || doomed(&row));
        if gone {
            Store::delete(store, &key).map_err(|e| storage(&e))?;
        }
    }
    Ok(())
}

/// Mint a link token. A new reset link supersedes the account's earlier
/// ones: only the newest mail in the inbox works.
fn issue_token(
    store: &spindle_store::FjallStore,
    kind: TokenKind,
    localpart: &str,
    address: &str,
    lifetime_ms: u64,
) -> Result<String, MatrixError> {
    drop_tokens(store, |row| {
        kind == TokenKind::Reset && row.kind == TokenKind::Reset && row.localpart == localpart
    })?;
    let token = web::random_secret();
    let row = TokenRow {
        kind,
        localpart: localpart.to_owned(),
        email: address.to_owned(),
        expires_ms: web::now_ms().saturating_add(lifetime_ms),
    };
    Store::put(
        store,
        &keys::email_token(&web::digest(&token)),
        &encode(&row)?,
    )
    .map_err(|e| storage(&e))?;
    Ok(token)
}

/// A live token's row, left in place (for rendering the form a link
/// opens) or taken (for acting on it). The lookup is by digest, so there
/// is no comparison of the secret to time.
fn token_row(
    state: &AppState,
    token: &str,
    kind: TokenKind,
    take: bool,
) -> Result<Option<TokenRow>, MatrixError> {
    if token.len() != 64 {
        return Ok(None);
    }
    let key = keys::email_token(&web::digest(token));
    let Some(raw) = ReadView::get(state.store.as_ref(), &key).map_err(|e| storage(&e))? else {
        return Ok(None);
    };
    if take {
        Store::delete(state.store.as_ref(), &key).map_err(|e| storage(&e))?;
    }
    Ok(decode::<TokenRow>(&raw).filter(|row| row.kind == kind && row.expires_ms > web::now_ms()))
}

/// The longest an administrator's reset link may live: a week.
pub const MAX_RESET_LINK_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The default lifetime of an administrator's reset link: a day, long
/// enough to reach the user by whatever channel the operator has.
pub const DEFAULT_RESET_LINK_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Parse a lifetime like `24h`, `30m`, `2d` or `900s` (a bare number is
/// seconds) into milliseconds, refusing zero and anything past a week.
///
/// # Errors
///
/// What is wrong with it.
pub fn parse_ttl(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let count: u64 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not a lifetime such as 24h, 30m or 2d"))?;
    let unit_ms = match unit {
        "" | "s" => 1000,
        "m" => 60 * 1000,
        "h" => 60 * 60 * 1000,
        "d" => 24 * 60 * 60 * 1000,
        _ => return Err(format!("{text:?} is not a lifetime such as 24h, 30m or 2d")),
    };
    let ttl = count.saturating_mul(unit_ms);
    if ttl == 0 || ttl > MAX_RESET_LINK_TTL_MS {
        return Err("a reset link lives more than nothing and at most 7d".to_owned());
    }
    Ok(ttl)
}

/// Mint a password-reset link for `localpart` on an administrator's say-so
/// — the recovery path that needs no mail. It is the same token as a mailed
/// reset (single-use, digest at rest, newest only: earlier links of the
/// account die) and opens the same page, which signs every device out.
/// Returns the URL, the only time the token exists in clear, and when it
/// lapses.
///
/// # Errors
///
/// When the account does not exist, is deactivated, or the store fails.
pub fn issue_reset_link(
    store: &spindle_store::FjallStore,
    config: &crate::Config,
    localpart: &str,
    ttl_ms: u64,
) -> Result<(String, u64), String> {
    let account = Accounts::new(store, &config.server.name)
        .account(localpart)
        .map_err(|error| error.to_string())?;
    match account {
        None => return Err(format!("no account named {localpart}")),
        Some(account) if account.deactivated => {
            return Err(format!("{localpart} is deactivated"));
        }
        Some(_) => {}
    }
    let token =
        issue_token(store, TokenKind::Reset, localpart, "", ttl_ms).map_err(|error| error.error)?;
    let expires = web::now_ms().saturating_add(ttl_ms);
    Ok((
        format!(
            "{}/account/password/reset?token={token}",
            config.oidc_issuer_base()
        ),
        expires,
    ))
}

/// Hand a message to the mailer in a task of its own, counting the
/// outcome. The caller's response never waits on, or varies with, it.
fn dispatch(state: &AppState, kind: EmailKind, email: OutgoingEmail) {
    let Some(mailer) = state.mailer.clone() else {
        return;
    };
    let metrics = Arc::clone(&state.metrics);
    tokio::spawn(async move {
        let result = mailer.send(email).await;
        metrics.record_email(kind, result.is_ok());
        if let Err(failure) = result {
            tracing::warn!(kind = ?kind, %failure, "email delivery failed");
        }
    });
}

fn link(state: &AppState, path: &str, token: &str) -> String {
    format!("{}{path}?token={token}", crate::oidc::issuer(state))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/account/emails/add", post(add_email))
        .route("/account/emails/remove", post(remove_email))
        .route("/account/emails/verify", get(verify_page).post(verify))
        .route("/account/password/forgot", get(forgot_page).post(forgot))
        .route("/account/password/reset", get(reset_page).post(reset))
        .route("/_matrix/client/v3/account/3pid", get(threepids))
}

/// The email page's body, for `account.rs`'s `?action=emails`.
pub(crate) fn emails_view(
    state: &AppState,
    session: &BrowserSession,
) -> Result<String, MatrixError> {
    let mut list = String::new();
    for (address, _) in addresses_of(state, &session.localpart)? {
        let _ = write!(
            list,
            "<tr><td>{shown}</td><td><form class=\"inline\" method=\"post\" \
             action=\"/account/emails/remove\">{csrf}{field}<button type=\"submit\">Remove\
             </button></form></td></tr>",
            shown = escape(&address),
            csrf = hidden("csrf", &session.csrf),
            field = hidden("email", &address),
        );
    }
    let list = if list.is_empty() {
        "<p>No email address is confirmed on this account. Add one so you can reset a \
         forgotten password.</p>"
            .to_owned()
    } else {
        format!("<table>{list}</table>")
    };
    Ok(format!(
        "{list}<h2>Add an address</h2>\
         <form method=\"post\" action=\"/account/emails/add\">{csrf}\
         <input name=\"email\" type=\"email\" placeholder=\"you@example.org\" required>\
         <input name=\"password\" type=\"password\" placeholder=\"Your password\" \
         autocomplete=\"current-password\" required>\
         <button type=\"submit\">Send a confirmation link</button></form>",
        csrf = hidden("csrf", &session.csrf),
    ))
}

fn signed_in_refusal(
    state: &AppState,
    session: &BrowserSession,
    status: StatusCode,
    problem: &str,
) -> Result<Response, MatrixError> {
    let body = emails_view(state, session)?;
    Ok(crate::account::refusal_page(
        state, session, status, "Email", problem, &body,
    ))
}

#[derive(Deserialize)]
struct AddForm {
    csrf: Option<String>,
    email: String,
    password: String,
}

/// `POST /account/emails/add` — mail a confirmation link. The address is
/// bound only when the link is followed: proving the inbox is the point.
async fn add_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<AddForm>,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    let session = match crate::account::session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    let Some(address) = normalize(&form.email) else {
        return signed_in_refusal(
            &state,
            &session,
            StatusCode::BAD_REQUEST,
            "That is not an email address.",
        );
    };
    if let Some((status, problem)) = crate::account::recheck_password(
        &state,
        &session.localpart,
        &source.to_string(),
        &form.password,
    )? {
        return signed_in_refusal(&state, &session, status, problem);
    }
    if state
        .limiter
        .check(&format!("email:user:{}", session.localpart), EMAIL_PER_USER)
        .is_err()
    {
        return signed_in_refusal(
            &state,
            &session,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many confirmation emails. Try again in an hour.",
        );
    }
    // An address another account holds gets no mail and no message that
    // says so: the page must not be a way to learn whose address it is.
    let owner = owner_of(&state, &address)?;
    if owner.is_none() {
        let token = issue_token(
            state.store.as_ref(),
            TokenKind::Verify,
            &session.localpart,
            &address,
            VERIFY_TOKEN_LIFETIME_MS,
        )?;
        let user_id = Accounts::new(state.store.as_ref(), &state.config.server.name)
            .user_id(&session.localpart);
        dispatch(
            &state,
            EmailKind::Verification,
            OutgoingEmail {
                to: address,
                subject: format!("Confirm your email address on {}", state.config.server.name),
                body: format!(
                    "Someone signed in as {user_id} asked to add this address to their \
                     account on {server}.\n\nTo confirm it, open this link within a day:\n\n\
                     {link}\n\nIf this wasn't you, ignore this email and nothing will change.\n",
                    server = state.config.server.name,
                    link = link(&state, "/account/emails/verify", &token),
                ),
            },
        );
    }
    state.metrics.record_account_action(AccountAction::EmailAdd);
    Ok(web::see_other("/account/?action=emails&notice=email_sent"))
}

#[derive(Deserialize)]
struct RemoveForm {
    csrf: Option<String>,
    email: String,
}

/// `POST /account/emails/remove`
async fn remove_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RemoveForm>,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    let session = match crate::account::session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    if let Some(address) = normalize(&form.email) {
        unbind(&state, &session.localpart, &address)?;
        state
            .metrics
            .record_account_action(AccountAction::EmailRemove);
    }
    Ok(web::see_other(
        "/account/?action=emails&notice=email_removed",
    ))
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

fn dead_link(state: &AppState) -> Response {
    crate::account::message_page(
        state,
        StatusCode::BAD_REQUEST,
        "That link has expired",
        "Reset and confirmation links work once, for a limited time. Ask for a new one.",
    )
}

/// `GET /account/emails/verify?token=…` — a button, not the change. Mail
/// scanners and link previews follow links; only a person presses
/// buttons, and the token must survive the scanner.
async fn verify_page(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    let token = query.token.unwrap_or_default();
    let Some(row) = token_row(&state, &token, TokenKind::Verify, false)? else {
        return Ok(dead_link(&state));
    };
    let body = format!(
        "<h1>Confirm your email address</h1><p>Add <strong>{address}</strong> to \
         <strong>{user}</strong>?</p><form method=\"post\" action=\"/account/emails/verify\">\
         {token}<button type=\"submit\">Confirm</button></form>",
        address = escape(&row.email),
        user = escape(
            &Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&row.localpart)
        ),
        token = hidden("token", &token),
    );
    Ok(web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        web::page(&state, "Confirm your email", &body),
    ))
}

#[derive(Deserialize)]
struct TokenForm {
    token: String,
}

/// `POST /account/emails/verify` — the token is the credential: it was
/// minted for one account and one address, behind that account's
/// password, and only the inbox ever saw it.
async fn verify(
    State(state): State<AppState>,
    Form(form): Form<TokenForm>,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    let Some(row) = token_row(&state, &form.token, TokenKind::Verify, true)? else {
        return Ok(dead_link(&state));
    };
    let active = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&row.localpart)
        .map_err(|e| storage(&e))?
        .is_some_and(|account| !account.deactivated);
    let taken = owner_of(&state, &row.email)?.is_some_and(|owner| owner != row.localpart);
    if !active || taken {
        return Ok(dead_link(&state));
    }
    bind(&state, &row.localpart, &row.email)?;
    state
        .metrics
        .record_account_action(AccountAction::EmailVerify);
    Ok(crate::account::message_page(
        &state,
        StatusCode::OK,
        "Email address confirmed",
        "You can use it to reset your password if you ever forget it.",
    ))
}

fn not_configured() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "this server does not send email",
    )
}

/// `GET /account/password/forgot`
async fn forgot_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    Ok(forgot_form(&state, &headers, StatusCode::OK, None))
}

fn forgot_form(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let (csrf, set_csrf) = web::signed_out_csrf(state, headers);
    let error = error.map_or(String::new(), |text| {
        format!("<p class=\"error\">{}</p>", escape(text))
    });
    let body = format!(
        "<h1>Forgot your password?</h1>{error}<p>Enter the email address confirmed on your \
         account and we will send you a link to choose a new password.</p>\
         <form method=\"post\" action=\"/account/password/forgot\">{csrf}\
         <input name=\"email\" type=\"email\" placeholder=\"you@example.org\" required>\
         <button type=\"submit\">Send me a link</button></form>",
        csrf = hidden("csrf", &csrf),
    );
    let response = web::html(
        status,
        FormTargets::SelfOnly,
        web::page(state, "Forgot password", &body),
    );
    match set_csrf {
        Some(cookie) => web::with_cookie(response, &cookie),
        None => response,
    }
}

#[derive(Deserialize)]
struct ForgotForm {
    csrf: Option<String>,
    email: String,
}

/// `POST /account/password/forgot` — the same answer for every address.
async fn forgot(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<ForgotForm>,
) -> Result<Response, MatrixError> {
    if !configured(&state) {
        return Err(not_configured());
    }
    if !web::signed_out_csrf_ok(&headers, form.csrf.as_deref()) {
        return Ok(forgot_form(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            Some("That form has expired. Please try again."),
        ));
    }
    let address = normalize(&form.email);
    // Keyed by the address's digest, so the limiter's memory is not a list
    // of the addresses people typed.
    let address_key = format!(
        "reset:address:{}",
        web::hex_digest(address.as_deref().unwrap_or(form.email.trim()))
    );
    let limited = state
        .limiter
        .check(&format!("reset:source:{source}"), RESET_REQUEST_PER_SOURCE)
        .is_err()
        || state
            .limiter
            .check(&address_key, RESET_REQUEST_PER_ADDRESS)
            .is_err();
    if limited {
        return Ok(forgot_form(
            &state,
            &headers,
            StatusCode::TOO_MANY_REQUESTS,
            Some("Too many requests. Try again later."),
        ));
    }
    state.metrics.record_password_reset_requested();
    if let Some(address) = address {
        let task_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = send_reset_link(&task_state, &address) {
                tracing::warn!(error = %error.error, "password reset request could not be processed");
            }
        });
    }
    Ok(crate::account::message_page(
        &state,
        StatusCode::OK,
        "Check your email",
        "If that address is confirmed on an account here, we have sent it a link to \
         choose a new password. The link works once, for an hour.",
    ))
}

/// The part of a forgot-password request that depends on the address.
fn send_reset_link(state: &AppState, address: &str) -> Result<(), MatrixError> {
    let Some(localpart) = owner_of(state, address)? else {
        return Ok(());
    };
    let active = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&localpart)
        .map_err(|e| storage(&e))?
        .is_some_and(|account| !account.deactivated && !account.locked);
    if !active {
        return Ok(());
    }
    let token = issue_token(
        state.store.as_ref(),
        TokenKind::Reset,
        &localpart,
        address,
        RESET_TOKEN_LIFETIME_MS,
    )?;
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&localpart);
    dispatch(
        state,
        EmailKind::PasswordReset,
        OutgoingEmail {
            to: address.to_owned(),
            subject: format!("Reset your password on {}", state.config.server.name),
            body: format!(
                "Someone asked to reset the password of {user_id} on {server}.\n\n\
                 To choose a new password, open this link within the hour:\n\n{link}\n\n\
                 If this wasn't you, ignore this email: your password has not changed.\n",
                server = state.config.server.name,
                link = link(state, "/account/password/reset", &token),
            ),
        },
    );
    Ok(())
}

fn reset_form(
    state: &AppState,
    status: StatusCode,
    token: &str,
    user_id: &str,
    error: Option<&str>,
) -> Response {
    let error = error.map_or(String::new(), |text| {
        format!("<p class=\"error\">{}</p>", escape(text))
    });
    let body = format!(
        "<h1>Choose a new password</h1>{error}<p>For <strong>{user}</strong>. Every device \
         will be signed out.</p><form method=\"post\" action=\"/account/password/reset\">{token}\
         <input name=\"new_password\" type=\"password\" placeholder=\"New password\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <input name=\"confirm_password\" type=\"password\" placeholder=\"New password, again\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <button type=\"submit\">Set password</button></form>",
        user = escape(user_id),
        token = hidden("token", token),
        min = web::MIN_PASSWORD_CHARS,
    );
    web::html(
        status,
        FormTargets::SelfOnly,
        web::page(state, "Choose a new password", &body),
    )
}

/// `GET /account/password/reset?token=…`
async fn reset_page(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let token = query.token.unwrap_or_default();
    let Some(row) = token_row(&state, &token, TokenKind::Reset, false)? else {
        return Ok(dead_link(&state));
    };
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&row.localpart);
    Ok(reset_form(&state, StatusCode::OK, &token, &user_id, None))
}

#[derive(Deserialize)]
struct ResetForm {
    token: String,
    new_password: String,
    confirm_password: String,
}

/// `POST /account/password/reset` — the new password is checked before
/// the token is spent, so a typo costs a retry rather than the link; then
/// the token is taken, the password set, every session and browser
/// signed out, and every other reset link of the account dropped.
async fn reset(
    State(state): State<AppState>,
    source: ClientAddr,
    Form(form): Form<ResetForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    if state
        .limiter
        .check(&format!("reset:redeem:{source}"), FAILED_LOGIN_PER_SOURCE)
        .is_err()
    {
        state.metrics.record_password_recovery(
            PasswordRecoveryMethod::ResetLink,
            PasswordRecoveryResult::RateLimited,
        );
        return Ok(crate::account::message_page(
            &state,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            "Wait a minute and try again.",
        ));
    }
    let Some(peeked) = token_row(&state, &form.token, TokenKind::Reset, false)? else {
        state.metrics.record_password_recovery(
            PasswordRecoveryMethod::ResetLink,
            PasswordRecoveryResult::Rejected,
        );
        return Ok(dead_link(&state));
    };
    let method = PasswordRecoveryMethod::ResetLink;
    // An admin-issued link carries no address; a mailed one names the
    // address it went to.
    let mailed = !peeked.email.is_empty();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    if let Some(problem) = web::new_password_problem(&form.new_password, &form.confirm_password) {
        let user_id = accounts.user_id(&peeked.localpart);
        return Ok(reset_form(
            &state,
            StatusCode::BAD_REQUEST,
            &form.token,
            &user_id,
            Some(problem),
        ));
    }
    let Some(row) = token_row(&state, &form.token, TokenKind::Reset, true)? else {
        return Ok(dead_link(&state));
    };
    // Still this address's account? An address removed, or moved, after
    // the mail went out takes its links with it.
    if !row.email.is_empty()
        && owner_of(&state, &row.email)?.as_deref() != Some(row.localpart.as_str())
    {
        state
            .metrics
            .record_password_recovery(method, PasswordRecoveryResult::Rejected);
        return Ok(dead_link(&state));
    }
    let changed = accounts
        .set_password(&row.localpart, &form.new_password)
        .map_err(|e| storage(&e))?;
    if !changed {
        return Ok(dead_link(&state));
    }
    accounts
        .logout_everywhere(&row.localpart)
        .map_err(|e| storage(&e))?;
    web::end_browser_sessions_of(&state, &row.localpart, None)?;
    drop_tokens(state.store.as_ref(), |other| {
        other.kind == TokenKind::Reset && other.localpart == row.localpart
    })?;
    if mailed {
        state.metrics.record_password_reset_completed();
    }
    state
        .metrics
        .record_password_recovery(method, PasswordRecoveryResult::Success);
    Ok(crate::account::message_page(
        &state,
        StatusCode::OK,
        "Your password has been changed",
        "Every device has been signed out. Sign in again with your new password.",
    ))
}

/// `GET /_matrix/client/v3/account/3pid` — the account's confirmed
/// addresses. Adding and removing them is the account pages' job (the
/// client API's `requestToken` flows are not served); this is the read
/// clients show in their settings. Under delegation the provider owns
/// identity, and this answers as the endpoint always did there: absent.
async fn threepids(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "third-party identifiers are the identity provider's",
        ));
    }
    let localpart = crate::admin::local_localpart(&state, &identity.user_id).unwrap_or_default();
    let threepids: Vec<Value> = addresses_of(&state, &localpart)?
        .into_iter()
        .map(|(address, added_ms)| {
            json!({
                "medium": "email",
                "address": address,
                "added_at": added_ms,
                "validated_at": added_ms,
            })
        })
        .collect();
    Ok(Json(json!({ "threepids": threepids })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};

    /// The smallest SMTP server that accepts one message: enough to see
    /// that what `[email]` builds speaks the protocol and carries the
    /// headers, without a real relay. A plain thread, so it needs nothing
    /// of the runtime the client runs on.
    fn fake_relay() -> (u16, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut write = socket.try_clone().unwrap();
            let lines = BufReader::new(socket).lines();
            write.write_all(b"220 fake ESMTP\r\n").unwrap();
            let mut data = String::new();
            let mut in_data = false;
            for line in lines {
                let Ok(line) = line else { break };
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").unwrap();
                    } else {
                        data.push_str(&line);
                        data.push('\n');
                    }
                    continue;
                }
                let verb = line.get(..4).unwrap_or_default().to_ascii_uppercase();
                let reply: &[u8] = match verb.as_str() {
                    "EHLO" | "HELO" => b"250 fake\r\n",
                    "DATA" => {
                        in_data = true;
                        b"354 go ahead\r\n"
                    }
                    "QUIT" => {
                        let _ = write.write_all(b"221 bye\r\n");
                        break;
                    }
                    _ => b"250 ok\r\n",
                };
                write.write_all(reply).unwrap();
            }
            data
        });
        (port, handle)
    }

    #[tokio::test]
    async fn the_smtp_transport_delivers_to_a_relay() {
        let (port, relay) = fake_relay();
        let config: EmailConfig = toml::from_str(&format!(
            "from = \"Example <noreply@example.org>\"\nsmtp_host = \"127.0.0.1\"\n\
             smtp_port = {port}\ntls = \"none\"\n"
        ))
        .unwrap();
        let mailer = SmtpMailer::new(&config, "example.org").unwrap();
        mailer
            .send(OutgoingEmail {
                to: "alice@example.org".to_owned(),
                subject: "Hello".to_owned(),
                body: "A link: https://example.org/x?token=abc\n".to_owned(),
            })
            .await
            .unwrap();
        let data = relay.join().unwrap();
        assert!(
            data.contains("From: Example <noreply@example.org>"),
            "{data}"
        );
        assert!(data.contains("To: alice@example.org"), "{data}");
        assert!(data.contains("Subject: Hello"), "{data}");
        assert!(data.contains("token=abc"), "{data}");
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_a_connection_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config: EmailConfig = toml::from_str(&format!(
            "from = \"noreply@example.org\"\nsmtp_host = \"127.0.0.1\"\n\
             smtp_port = {port}\ntls = \"none\"\n"
        ))
        .unwrap();
        let mailer = SmtpMailer::new(&config, "example.org").unwrap();
        let failure = mailer
            .send(OutgoingEmail {
                to: "alice@example.org".to_owned(),
                subject: "Hello".to_owned(),
                body: "x".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(failure, MailFailure::Connection);
    }

    #[test]
    fn addresses_fold_and_must_parse() {
        assert_eq!(
            normalize(" Alice@Example.ORG ").as_deref(),
            Some("alice@example.org")
        );
        assert!(normalize("not an address").is_none());
        assert!(normalize("a@").is_none());
        assert!(normalize(&format!("{}@example.org", "a".repeat(250))).is_none());
    }
}
