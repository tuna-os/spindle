//! The client API's email flows (#608): `requestToken`, then a mailed
//! link, then the call the token was for.
//!
//! The account pages (`email.rs`) already confirm addresses and reset
//! passwords from a browser. Password-login clients (Element's "Forgot
//! password?", its email settings, its sign-up form) speak the spec's shape
//! instead: the client asks for a validation session (`sid`) under a secret
//! of its own choosing, the user follows the mailed link, and the client
//! then spends `{sid, client_secret}` — in the `m.login.email.identity`
//! stage of `POST /account/password` or `POST /register`, or in
//! `POST /account/3pid/add`.
//!
//! The rules `email.rs` keeps hold here too:
//!
//! - **No answer says whether an address is known.** `requestToken` answers
//!   with a `sid` for every well-formed address, after the same work; the
//!   lookup and the mail happen in a task of their own. The spec's
//!   `M_THREEPID_NOT_FOUND`/`M_THREEPID_IN_USE` refusals at this step are
//!   exactly that oracle, and Synapse grew an option to suppress them.
//! - **The link is a button, not the change**, so a mail scanner that
//!   follows it validates nothing.
//! - **Sessions are memory-only and single-use**, as the provider's
//!   authorization codes are: a restart costs the user one more mail,
//!   while a durable session would be a credential at rest. The mailed
//!   token and the client secret are compared as digests and in constant
//!   time respectively.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::accounts::Accounts;
use crate::auth::Authenticated;
use crate::email::{self, OutgoingEmail};
use crate::errors::MatrixError;
use crate::metrics::EmailKind;
use crate::ratelimit::{RESET_REQUEST_PER_ADDRESS, RESET_REQUEST_PER_SOURCE};
use crate::routes::{ClientAddr, localpart_of, password_uia};
use crate::web::{self, FormTargets, escape, hidden};

/// How long a password-reset session lives: the reset link's hour.
const PASSWORD_SESSION_LIFETIME: Duration = Duration::from_millis(email::RESET_TOKEN_LIFETIME_MS);

/// How long an add-an-address session lives: the confirmation link's day.
const ADD_SESSION_LIFETIME: Duration = Duration::from_millis(email::VERIFY_TOKEN_LIFETIME_MS);

/// What a validation session will be spent on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Purpose {
    /// `POST /account/password` without the old password.
    Password,
    /// `POST /account/3pid/add`.
    Add,
    /// `POST /register`'s `m.login.email.identity` stage.
    Register,
}

impl Purpose {
    fn lifetime(self) -> Duration {
        match self {
            Self::Password => PASSWORD_SESSION_LIFETIME,
            Self::Add | Self::Register => ADD_SESSION_LIFETIME,
        }
    }
}

/// One `requestToken`'s session.
struct Session {
    client_secret: String,
    address: String,
    purpose: Purpose,
    send_attempt: u64,
    /// The BLAKE3 digest of the mailed token.
    link_digest: [u8; 32],
    validated: bool,
    next_link: Option<String>,
    expires: Instant,
}

/// The sessions in flight, by `sid`.
#[derive(Default)]
pub struct Sessions {
    by_sid: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.by_sid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/account/password/email/requestToken",
            post(request_password_token),
        )
        .route(
            "/_matrix/client/v3/account/3pid/email/requestToken",
            post(request_add_token),
        )
        .route("/_matrix/client/v3/account/3pid/add", post(add))
        .route(
            "/_matrix/client/v3/register/email/requestToken",
            post(request_register_token),
        )
        .route("/_matrix/client/v3/account/3pid/delete", post(delete))
        .route("/account/3pid/validate", get(validate_page).post(validate))
}

/// The provider's sessions, when this server sends mail at all.
fn sessions(state: &AppState) -> Result<&Sessions, MatrixError> {
    if !email::configured(state) {
        return Err(email::not_configured());
    }
    crate::oidc::provider(state).map(|oidc| &oidc.threepid)
}

fn invalid_param(message: &str) -> MatrixError {
    MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

/// SPEC (client-server §3PID): a client secret is 1–255 characters of
/// `[0-9a-zA-Z.=_-]`.
fn valid_client_secret(secret: &str) -> bool {
    (1..=255).contains(&secret.len())
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".=_-".contains(c))
}

#[derive(Deserialize)]
struct RequestTokenBody {
    client_secret: String,
    email: String,
    send_attempt: u64,
    next_link: Option<String>,
}

/// `POST /_matrix/client/v3/account/password/email/requestToken`
async fn request_password_token(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(body): Json<RequestTokenBody>,
) -> Result<Json<Value>, MatrixError> {
    request_token(&state, &source.to_string(), body, Purpose::Password)
}

/// `POST /_matrix/client/v3/account/3pid/email/requestToken`
async fn request_add_token(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(body): Json<RequestTokenBody>,
) -> Result<Json<Value>, MatrixError> {
    request_token(&state, &source.to_string(), body, Purpose::Add)
}

/// Whether registration offers the email stage: this server mails, and
/// does not require a registration token. Registration's UIA here keeps no
/// session state, so it can offer one-stage flows only; an email flow
/// beside a required token would have to be two stages, and one without
/// the token would be a way around it.
pub(crate) fn registration_by_email(state: &AppState) -> bool {
    sessions(state).is_ok() && !state.config.registration.require_token
}

/// `POST /_matrix/client/v3/register/email/requestToken`
async fn request_register_token(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(body): Json<RequestTokenBody>,
) -> Result<Json<Value>, MatrixError> {
    sessions(&state)?;
    if !registration_by_email(&state) {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_THREEPID_DENIED",
            "registration here needs a registration token; add an address after signing in",
        ));
    }
    request_token(&state, &source.to_string(), body, Purpose::Register)
}

/// Both `requestToken`s: check the request, open (or find) the session,
/// and hand the address-dependent part to a task.
fn request_token(
    state: &AppState,
    source: &str,
    body: RequestTokenBody,
    purpose: Purpose,
) -> Result<Json<Value>, MatrixError> {
    let sessions = sessions(state)?;
    if !valid_client_secret(&body.client_secret) {
        return Err(invalid_param(
            "client_secret must be 1-255 characters of [0-9a-zA-Z.=_-]",
        ));
    }
    let address = email::normalize(&body.email)
        .ok_or_else(|| invalid_param("that is not an email address"))?;
    let next_link = body.next_link.filter(|link| !link.is_empty());
    if next_link
        .as_deref()
        .is_some_and(|link| !link.starts_with("https://") && !link.starts_with("http://"))
    {
        return Err(invalid_param("next_link must be an http(s) URL"));
    }

    // SPEC: a repeated request with the same secret, address and an
    // attempt number no higher is a retry, and gets the same session
    // without another mail.
    {
        let now = Instant::now();
        let mut map = sessions.lock();
        map.retain(|_, session| session.expires > now);
        let existing = map.iter().find(|(_, session)| {
            session.purpose == purpose
                && session.address == address
                && web::ct_eq(
                    session.client_secret.as_bytes(),
                    body.client_secret.as_bytes(),
                )
        });
        if let Some((sid, session)) = existing
            && body.send_attempt <= session.send_attempt
        {
            return Ok(Json(json!({ "sid": sid })));
        }
    }

    // The same budgets as the forgot-password page, shared with it for a
    // reset so the two doors are one; keyed by the address's digest so
    // the limiter's memory is not a list of addresses.
    let (source_key, address_key) = match purpose {
        Purpose::Password => ("reset:source", "reset:address"),
        Purpose::Add | Purpose::Register => ("threepid:source", "threepid:address"),
    };
    for (key, limit) in [
        (format!("{source_key}:{source}"), RESET_REQUEST_PER_SOURCE),
        (
            format!("{address_key}:{}", web::hex_digest(&address)),
            RESET_REQUEST_PER_ADDRESS,
        ),
    ] {
        if let Err(retry) = state.limiter.check(&key, limit) {
            return Err(MatrixError::limit_exceeded(retry.as_millis()));
        }
    }

    let token = web::random_secret();
    let sid = web::random_secret();
    {
        let mut map = sessions.lock();
        // A resend replaces the earlier session of the same secret and
        // address: only the newest link works, as on the pages.
        map.retain(|_, session| {
            !(session.purpose == purpose
                && session.address == address
                && session.client_secret == body.client_secret)
        });
        map.insert(
            sid.clone(),
            Session {
                client_secret: body.client_secret,
                address: address.clone(),
                purpose,
                send_attempt: body.send_attempt,
                link_digest: web::digest(&token),
                validated: false,
                next_link,
                expires: Instant::now() + purpose.lifetime(),
            },
        );
    }
    if purpose == Purpose::Password {
        state.metrics.record_password_reset_requested();
    }
    let task_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = mail_link(&task_state, purpose, &address, &token) {
            tracing::warn!(error = %error.error, "a requestToken could not be processed");
        }
    });
    Ok(Json(json!({ "sid": sid })))
}

/// The address-dependent half of `requestToken`: a reset mail only to an
/// address confirmed on an active account, a confirmation mail only to an
/// address no account holds.
fn mail_link(
    state: &AppState,
    purpose: Purpose,
    address: &str,
    token: &str,
) -> Result<(), MatrixError> {
    let owner = email::owner_of(state, address)?;
    let server = &state.config.server.name;
    let link = email::link(state, "/account/3pid/validate", token);
    let (kind, subject, text) = match (purpose, owner) {
        (Purpose::Password, Some(localpart)) => {
            let accounts = Accounts::new(state.store.as_ref(), server);
            let active = accounts
                .account(&localpart)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .is_some_and(|account| !account.deactivated && !account.locked);
            if !active {
                return Ok(());
            }
            (
                EmailKind::PasswordReset,
                format!("Reset your password on {server}"),
                format!(
                    "Someone asked to reset the password of {user} on {server}.\n\n\
                     To allow it, open this link within the hour and confirm, then go back \
                     to your application to choose the new password:\n\n{link}\n\n\
                     If this wasn't you, ignore this email: your password has not changed.\n",
                    user = accounts.user_id(&localpart),
                ),
            )
        }
        (Purpose::Add, None) => (
            EmailKind::Verification,
            format!("Confirm your email address on {server}"),
            format!(
                "Someone asked to add this address to their account on {server}.\n\n\
                 To confirm it, open this link within a day and confirm, then go back to \
                 your application:\n\n{link}\n\n\
                 If this wasn't you, ignore this email and nothing will change.\n"
            ),
        ),
        (Purpose::Register, None) => (
            EmailKind::Verification,
            format!("Confirm your email address on {server}"),
            format!(
                "Someone is creating an account on {server} with this address.\n\n\
                 To confirm it, open this link within a day and confirm, then go back to \
                 your application:\n\n{link}\n\n\
                 If this wasn't you, ignore this email and nothing will change.\n"
            ),
        ),
        // No account to reset, or an address another account holds:
        // nobody is mailed, and nothing above said so.
        _ => return Ok(()),
    };
    email::dispatch(
        state,
        kind,
        OutgoingEmail {
            to: address.to_owned(),
            subject,
            body: text,
        },
    );
    Ok(())
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// The `sid` of the live, unvalidated session a mailed token opens.
fn session_for_token(sessions: &Sessions, token: &str) -> Option<String> {
    let digest = web::digest(token);
    let now = Instant::now();
    sessions
        .lock()
        .iter()
        .find(|(_, session)| session.expires > now && session.link_digest == digest)
        .map(|(sid, _)| sid.clone())
}

/// `GET /account/3pid/validate?token=…` — the confirmation button.
async fn validate_page(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, MatrixError> {
    let sessions = sessions(&state)?;
    let token = query.token.unwrap_or_default();
    let Some(sid) = session_for_token(sessions, &token) else {
        return Ok(email::dead_link(&state));
    };
    let Some((purpose, address)) = sessions
        .lock()
        .get(&sid)
        .map(|session| (session.purpose, session.address.clone()))
    else {
        return Ok(email::dead_link(&state));
    };
    let question = match purpose {
        Purpose::Password => format!(
            "Allow a new password to be set for the account of <strong>{}</strong>?",
            escape(&address)
        ),
        Purpose::Add => format!(
            "Add <strong>{}</strong> to the account that asked?",
            escape(&address)
        ),
        Purpose::Register => format!(
            "Use <strong>{}</strong> for the new account being created?",
            escape(&address)
        ),
    };
    let body = format!(
        "<h1>Confirm your email address</h1><p>{question}</p>\
         <form method=\"post\" action=\"/account/3pid/validate\">{token}\
         <button type=\"submit\">Confirm</button></form>",
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

/// `POST /account/3pid/validate` — mark the session validated; the
/// client, polling, then spends it.
async fn validate(
    State(state): State<AppState>,
    Form(form): Form<TokenForm>,
) -> Result<Response, MatrixError> {
    let sessions = sessions(&state)?;
    let Some(sid) = session_for_token(sessions, &form.token) else {
        return Ok(email::dead_link(&state));
    };
    let next_link = {
        let mut map = sessions.lock();
        let Some(session) = map.get_mut(&sid) else {
            return Ok(email::dead_link(&state));
        };
        session.validated = true;
        // One press: the token does nothing more once it has validated.
        session.link_digest = [0; 32];
        session.next_link.clone()
    };
    // `next_link` is the client's, and the spec has the server send the
    // user there; a link rather than a redirect, so this server never
    // forwards a browser somewhere it did not show first.
    let onward = next_link.map_or(String::new(), |link| {
        format!("<p><a href=\"{}\">Continue</a></p>", escape(&link))
    });
    let body = format!(
        "<h1>Email address confirmed</h1><p>Go back to your application to \
         continue.</p>{onward}"
    );
    Ok(web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        web::page(&state, "Email address confirmed", &body),
    ))
}

/// The `threepid_creds` of an `m.login.email.identity` stage or of
/// `/3pid/add`, both spellings the spec has used.
fn creds_of(auth: &Value) -> Option<(&str, &str)> {
    let creds = auth
        .get("threepid_creds")
        .or_else(|| auth.get("threepidCreds"))?;
    Some((creds["sid"].as_str()?, creds["client_secret"].as_str()?))
}

/// Take a validated session of `purpose`: its address, `Ok(None)` when it
/// exists but is not validated yet (it stays, for the client to retry),
/// or `Err` when there is no such session.
fn take_validated(
    sessions: &Sessions,
    purpose: Purpose,
    sid: &str,
    client_secret: &str,
) -> Result<Option<String>, ()> {
    let mut map = sessions.lock();
    let Some(session) = map.get(sid) else {
        return Err(());
    };
    if session.purpose != purpose
        || session.expires <= Instant::now()
        || !web::ct_eq(session.client_secret.as_bytes(), client_secret.as_bytes())
    {
        return Err(());
    }
    if !session.validated {
        return Ok(None);
    }
    Ok(map.remove(sid).map(|session| session.address))
}

/// The `m.login.email.identity` half of `POST /account/password`: a reset
/// for whoever holds the validated address, with or without an access
/// token. `Ok(Err(challenge))` is the 401 to send back.
///
/// # Errors
///
/// When there is no such session, or a token for another account.
pub(crate) fn email_identity_reset(
    state: &AppState,
    caller: Option<&str>,
    auth: &Value,
) -> Result<Result<String, Json<Value>>, MatrixError> {
    let sessions = sessions(state)?;
    let unknown = || {
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "no such email validation session",
        )
    };
    let (sid, secret) = creds_of(auth).ok_or_else(unknown)?;
    let Some(address) =
        take_validated(sessions, Purpose::Password, sid, secret).map_err(|()| unknown())?
    else {
        // What Element polls on: still 401, and the stage named again.
        return Ok(Err(Json(json!({
            "errcode": "M_UNAUTHORIZED",
            "error": "the email address has not been confirmed yet",
            "flows": [{ "stages": ["m.login.email.identity"] }],
            "params": {},
            "session": "change_password",
        }))));
    };
    // Who holds the address *now*: one removed or moved since the mail
    // went out takes the session with it.
    let owner = email::owner_of(state, &address)?.ok_or_else(unknown)?;
    if caller.is_some_and(|caller| caller != owner) {
        return Err(MatrixError::forbidden(
            "that address belongs to another account",
        ));
    }
    Ok(Ok(owner))
}

/// The challenge an unauthenticated `POST /account/password` gets when this
/// server can mail: the email stage is the only way in without a token.
pub(crate) fn email_identity_challenge(state: &AppState) -> Option<Json<Value>> {
    sessions(state).ok().map(|_| {
        Json(json!({
            "flows": [{ "stages": ["m.login.email.identity"] }],
            "params": {},
            "session": "change_password",
        }))
    })
}

/// The `m.login.email.identity` stage of `POST /register`: the address a
/// validated session proved, `Ok(None)` while it is not validated yet.
///
/// # Errors
///
/// When there is no such session.
pub(crate) fn email_identity_register(
    state: &AppState,
    auth: &Value,
) -> Result<Option<String>, MatrixError> {
    let sessions = sessions(state)?;
    let unknown = || {
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "no such email validation session",
        )
    };
    let (sid, secret) = creds_of(auth).ok_or_else(unknown)?;
    take_validated(sessions, Purpose::Register, sid, secret).map_err(|()| unknown())
}

#[derive(Deserialize)]
struct AddBody {
    client_secret: String,
    sid: String,
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/account/3pid/add` — behind the password
/// stage, bind the address a validated session proved.
async fn add(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: HeaderMap,
    Json(body): Json<AddBody>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let sessions = sessions(&state)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        body.auth.as_ref(),
        "add_threepid",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    let address = match take_validated(sessions, Purpose::Add, &body.sid, &body.client_secret) {
        Ok(Some(address)) => address,
        Ok(None) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_SESSION_NOT_VALIDATED",
                "the email address has not been confirmed yet",
            ));
        }
        Err(()) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_THREEPID_AUTH_FAILED",
                "no such email validation session",
            ));
        }
    };
    match email::owner_of(&state, &address)? {
        Some(owner) if owner != localpart => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_THREEPID_IN_USE",
                "that address is on another account",
            ));
        }
        Some(_) => {}
        None => email::bind(&state, &localpart, &address)?,
    }
    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Deserialize)]
struct DeleteBody {
    medium: String,
    address: String,
}

/// `POST /_matrix/client/v3/account/3pid/delete` — release an address of
/// the caller's. No identity server is ever told of a binding here, so
/// none is asked to forget one: `no-support`, as deactivation answers.
async fn delete(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(body): Json<DeleteBody>,
) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "third-party identifiers are the identity provider's",
        ));
    }
    if body.medium != "email" {
        return Err(invalid_param("this server holds email addresses only"));
    }
    if let Some(address) = email::normalize(&body.address) {
        email::unbind(&state, &localpart_of(&identity.user_id), &address)?;
    }
    Ok(Json(json!({ "id_server_unbind_result": "no-support" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_secrets_follow_the_spec_grammar() {
        assert!(valid_client_secret("abc.DEF=_-123"));
        assert!(!valid_client_secret(""));
        assert!(!valid_client_secret("has space"));
        assert!(!valid_client_secret(&"a".repeat(256)));
    }

    #[test]
    fn a_session_is_spent_once_and_only_when_validated() {
        let sessions = Sessions::default();
        sessions.lock().insert(
            "sid".to_owned(),
            Session {
                client_secret: "secret".to_owned(),
                address: "a@example.org".to_owned(),
                purpose: Purpose::Add,
                send_attempt: 1,
                link_digest: [1; 32],
                validated: false,
                next_link: None,
                expires: Instant::now() + Duration::from_secs(60),
            },
        );
        assert_eq!(
            take_validated(&sessions, Purpose::Add, "sid", "secret"),
            Ok(None)
        );
        assert_eq!(
            take_validated(&sessions, Purpose::Password, "sid", "secret"),
            Err(()),
            "a session is for one purpose"
        );
        assert_eq!(
            take_validated(&sessions, Purpose::Add, "sid", "wrong"),
            Err(())
        );
        sessions.lock().get_mut("sid").unwrap().validated = true;
        assert_eq!(
            take_validated(&sessions, Purpose::Add, "sid", "secret"),
            Ok(Some("a@example.org".to_owned()))
        );
        assert_eq!(
            take_validated(&sessions, Purpose::Add, "sid", "secret"),
            Err(())
        );
    }
}
