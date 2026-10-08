//! Account management for the built-in provider (#607): the pages a
//! client sends its user to, MSC4191's `account_management_uri`.
//!
//! An OIDC-native client has no password form of its own, so everything
//! a password-login client did in its settings screen — change the
//! display name, change the password, sign a device out, deactivate —
//! has to be somewhere the user can reach. MAS serves those pages; with
//! the built-in provider this module does, over the same accounts,
//! profiles and devices the client API uses, so a change made here is
//! exactly the change the matching client API call would have made.
//!
//! The pages sit behind a browser session (`web.rs`), started by signing
//! in here or on the provider's authorization page. Every change is a
//! POST carrying the session's CSRF secret; every change to a credential
//! or to the account's existence asks for the current password again,
//! counted against the same attempt budget as every other password check.
//! Clients deep-link with `?action=` (and `device_id=` for one device);
//! an action this server does not know shows the profile page, as the
//! MSC asks.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;
use crate::metrics::{AccountAction, LoginMethod, LoginResult};
use crate::routes::ClientAddr;
use crate::web::{self, BrowserSession, FormTargets, escape, hidden, urlencode};

/// MSC4191's actions this server's pages serve, in both spellings the
/// proposal has used: `session_*` first, `device_*` after it was revised
/// (and as the spec adopted it). Clients look for either.
pub const ACTIONS_SUPPORTED: [&str; 9] = [
    "org.matrix.profile",
    "org.matrix.sessions_list",
    "org.matrix.session_view",
    "org.matrix.session_end",
    "org.matrix.devices_list",
    "org.matrix.device_view",
    "org.matrix.device_delete",
    "org.matrix.account_deactivate",
    "org.matrix.cross_signing_reset",
];

/// Where the account pages live: under the issuer, as MAS has them.
#[must_use]
pub fn management_uri(state: &AppState) -> String {
    format!("{}/account/", crate::oidc::issuer(state))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/account", get(home))
        .route("/account/", get(home))
        .route("/account/login", get(login_page).post(login))
        .route("/account/logout", post(logout))
        .route("/account/profile", post(save_profile))
        .route("/account/password", post(change_password))
        .route("/account/sessions/end", post(end_session))
        .route("/account/deactivate", post(deactivate))
}

#[derive(Default, Deserialize)]
struct HomeQuery {
    action: Option<String>,
    device_id: Option<String>,
    notice: Option<String>,
}

/// The fixed messages a redirect-after-POST may ask a page to show. A
/// code rather than text, so the query string cannot put words in this
/// server's mouth.
fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "profile_saved" => "Your profile was saved.",
        "password_changed" => "Your password was changed.",
        "session_ended" => "That device was signed out.",
        "email_sent" => "Check your inbox: we sent a link to confirm that address.",
        "email_verified" => "Your email address was confirmed.",
        "email_removed" => "That email address was removed.",
        _ => return None,
    })
}

/// A signed-in page: navigation, a heading, any notice or error, the body.
fn signed_in_page(
    state: &AppState,
    session: &BrowserSession,
    title: &str,
    notice: Option<&str>,
    error: Option<&str>,
    body: &str,
) -> String {
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&session.localpart);
    let mut nav = String::from(
        "<nav><a href=\"/account/?action=org.matrix.profile\">Profile</a>\
         <a href=\"/account/?action=password\">Password</a>",
    );
    if crate::email::configured(state) {
        nav.push_str("<a href=\"/account/?action=emails\">Email</a>");
    }
    let _ = write!(
        nav,
        "<a href=\"/account/?action=org.matrix.sessions_list\">Devices</a>\
         <a href=\"/account/?action=org.matrix.account_deactivate\">Deactivate</a>\
         <form class=\"inline\" method=\"post\" action=\"/account/logout\">{csrf}\
         <button type=\"submit\">Sign out</button></form></nav>",
        csrf = hidden("csrf", &session.csrf),
    );
    let notice = notice.map_or(String::new(), |text| {
        format!("<p class=\"notice\">{}</p>", escape(text))
    });
    let error = error.map_or(String::new(), |text| {
        format!("<p class=\"error\">{}</p>", escape(text))
    });
    web::page(
        state,
        title,
        &format!(
            "{nav}<p>Signed in as <strong>{user}</strong></p><h1>{title}</h1>{notice}{error}{body}",
            user = escape(&user_id),
            title = escape(title),
        ),
    )
}

/// A page with nothing but a message — expiry, refusal, farewell.
pub(crate) fn message_page(
    state: &AppState,
    status: StatusCode,
    title: &str,
    text: &str,
) -> Response {
    web::html(
        status,
        FormTargets::SelfOnly,
        web::page(
            state,
            title,
            &format!(
                "<h1>{}</h1><p>{}</p><p><a href=\"/account/\">Continue</a></p>",
                escape(title),
                escape(text)
            ),
        ),
    )
}

/// A signed-in page re-rendered with a problem, for the forms that live
/// on another module's page (`email.rs`).
pub(crate) fn refusal_page(
    state: &AppState,
    session: &BrowserSession,
    status: StatusCode,
    title: &str,
    problem: &str,
    body: &str,
) -> Response {
    web::html(
        status,
        FormTargets::SelfOnly,
        signed_in_page(state, session, title, None, Some(problem), body),
    )
}

fn expired_form(state: &AppState) -> Response {
    message_page(
        state,
        StatusCode::FORBIDDEN,
        "This form has expired",
        "Go back, reload the page and try again.",
    )
}

/// The signed-in session for a POST, or the response that refuses it:
/// to the sign-in page without a session, "expired" without the CSRF.
pub(crate) fn session_for_post(
    state: &AppState,
    headers: &HeaderMap,
    csrf: Option<&str>,
) -> Result<Result<BrowserSession, Response>, MatrixError> {
    let Some(session) = web::browser_session(state, headers)? else {
        return Ok(Err(web::see_other("/account/login")));
    };
    if !session.csrf_ok(csrf) {
        return Ok(Err(expired_form(state)));
    }
    Ok(Ok(session))
}

/// `GET /account/` — whichever page `action` names.
async fn home(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Query(query): Query<HomeQuery>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let Some(session) = web::browser_session(&state, &headers)? else {
        let here = uri
            .path_and_query()
            .map_or("/account/", axum::http::uri::PathAndQuery::as_str);
        return Ok(web::see_other(&format!(
            "/account/login?next={}",
            urlencode(&web::safe_next(Some(here)))
        )));
    };
    let notice = query.notice.as_deref().and_then(notice_text);
    let device_id = query.device_id.as_deref().filter(|id| !id.is_empty());
    let (title, body) = match (query.action.as_deref(), device_id) {
        (Some("org.matrix.sessions_list" | "org.matrix.devices_list"), _)
        | (
            Some(
                "org.matrix.session_view"
                | "org.matrix.device_view"
                | "org.matrix.session_end"
                | "org.matrix.device_delete",
            ),
            None,
        ) => ("Devices", devices_view(&state, &session)?),
        (Some("org.matrix.session_view" | "org.matrix.device_view"), Some(device)) => {
            ("Device", device_view(&state, &session, device, false)?)
        }
        (Some("org.matrix.session_end" | "org.matrix.device_delete"), Some(device)) => (
            "Sign out a device",
            device_view(&state, &session, device, true)?,
        ),
        (Some("org.matrix.account_deactivate"), _) => {
            ("Deactivate account", deactivate_view(&session))
        }
        (Some("org.matrix.cross_signing_reset"), _) => {
            state
                .metrics
                .record_account_action(AccountAction::CrossSigningReset);
            ("Reset your identity", cross_signing_view())
        }
        (Some("password"), _) => ("Password", password_view(&session)),
        (Some("emails"), _) if crate::email::configured(&state) => {
            ("Email", crate::email::emails_view(&state, &session)?)
        }
        _ => ("Profile", profile_view(&state, &session)?),
    };
    Ok(web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        signed_in_page(&state, &session, title, notice, None, &body),
    ))
}

fn profile_view(state: &AppState, session: &BrowserSession) -> Result<String, MatrixError> {
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&session.localpart);
    let profile = state
        .profiles
        .get(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(format!(
        "<form method=\"post\" action=\"/account/profile\">{csrf}\
         <label>Display name <input name=\"displayname\" value=\"{name}\" maxlength=\"256\"></label>\
         <label>Avatar (an <code>mxc://</code> URI) <input name=\"avatar_url\" value=\"{avatar}\" \
         maxlength=\"255\"></label>\
         <button type=\"submit\">Save</button></form>",
        csrf = hidden("csrf", &session.csrf),
        name = escape(profile.displayname.as_deref().unwrap_or_default()),
        avatar = escape(profile.avatar_url.as_deref().unwrap_or_default()),
    ))
}

fn password_view(session: &BrowserSession) -> String {
    format!(
        "<form method=\"post\" action=\"/account/password\">{csrf}\
         <input name=\"current_password\" type=\"password\" placeholder=\"Current password\" \
         autocomplete=\"current-password\" required>\
         <input name=\"new_password\" type=\"password\" placeholder=\"New password\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <input name=\"confirm_password\" type=\"password\" placeholder=\"New password, again\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <label class=\"check\"><input type=\"checkbox\" name=\"sign_out_others\" value=\"yes\" \
         checked> Also sign out all my devices (other browsers are always signed out)</label>\
         <button type=\"submit\">Change password</button></form>",
        csrf = hidden("csrf", &session.csrf),
        min = web::MIN_PASSWORD_CHARS,
    )
}

fn devices_view(state: &AppState, session: &BrowserSession) -> Result<String, MatrixError> {
    let devices = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .devices_of(&session.localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if devices.is_empty() {
        return Ok("<p>No devices are signed in.</p>".to_owned());
    }
    let mut rows = String::new();
    for device in devices {
        let _ = write!(
            rows,
            "<tr><td><a href=\"/account/?action=org.matrix.session_view&amp;device_id={link}\">\
             <code>{id}</code></a></td><td>{name}</td><td>\
             <form class=\"inline\" method=\"post\" action=\"/account/sessions/end\">{csrf}{device}\
             <button type=\"submit\">Sign out</button></form></td></tr>",
            link = escape(&urlencode(&device.device_id)),
            id = escape(&device.device_id),
            name = escape(device.display_name.as_deref().unwrap_or("—")),
            csrf = hidden("csrf", &session.csrf),
            device = hidden("device_id", &device.device_id),
        );
    }
    Ok(format!(
        "<table><tr><th>Device</th><th>Name</th><th></th></tr>{rows}</table>"
    ))
}

fn device_view(
    state: &AppState,
    session: &BrowserSession,
    device_id: &str,
    confirming: bool,
) -> Result<String, MatrixError> {
    let device = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .device(&session.localpart, device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let Some(device) = device else {
        return Ok(format!(
            "<p>There is no device <code>{}</code> on this account. It may already be \
             signed out.</p><p><a href=\"/account/?action=org.matrix.sessions_list\">All \
             devices</a></p>",
            escape(device_id)
        ));
    };
    let question = if confirming {
        "<p>Sign this device out? It will need to sign in again, and messages it has not \
         backed up may become unreadable on it.</p>"
    } else {
        ""
    };
    Ok(format!(
        "<table><tr><th>Device ID</th><td><code>{id}</code></td></tr>\
         <tr><th>Name</th><td>{name}</td></tr></table>{question}\
         <form method=\"post\" action=\"/account/sessions/end\">{csrf}{device}\
         <button class=\"danger\" type=\"submit\">Sign out this device</button></form>",
        id = escape(&device.device_id),
        name = escape(device.display_name.as_deref().unwrap_or("—")),
        csrf = hidden("csrf", &session.csrf),
        device = hidden("device_id", &device.device_id),
    ))
}

fn deactivate_view(session: &BrowserSession) -> String {
    format!(
        "<p>Deactivating your account signs out every device, removes you from every room \
         and cannot be undone. Your username stays reserved: nobody else can take it.</p>\
         <form method=\"post\" action=\"/account/deactivate\">{csrf}\
         <input name=\"password\" type=\"password\" placeholder=\"Your password\" \
         autocomplete=\"current-password\" required>\
         <label class=\"check\"><input type=\"checkbox\" name=\"erase\" value=\"yes\"> Also \
         erase my profile (display name and avatar)</label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"confirm\" value=\"yes\" \
         required> I understand this cannot be undone</label>\
         <button class=\"danger\" type=\"submit\">Deactivate my account</button></form>",
        csrf = hidden("csrf", &session.csrf),
    )
}

/// MSC4191's `cross_signing_reset`: a client sends the user here when
/// the server would demand approval before replacing their
/// cross-signing keys. This server demands none — the upload is
/// authenticated by the access token alone, as `/_synapse/mas/
/// allow_cross_signing_reset` already records — so there is nothing to
/// approve, and the page says so rather than inventing a step.
fn cross_signing_view() -> String {
    "<p>You can reset your identity (cross-signing keys) from your app now: this server \
     does not need any further approval. Go back to your app and continue.</p>\
     <p>Resetting means your other devices and the people who verified you will need to \
     verify you again.</p>"
        .to_owned()
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
}

/// `GET /account/login`
async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NextQuery>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let next = web::safe_next(query.next.as_deref());
    if web::browser_session(&state, &headers)?.is_some() {
        return Ok(web::see_other(&next));
    }
    Ok(render_login(&state, &headers, StatusCode::OK, &next, None))
}

fn render_login(
    state: &AppState,
    headers: &HeaderMap,
    status: StatusCode,
    next: &str,
    error: Option<&str>,
) -> Response {
    let (csrf, set_csrf) = web::signed_out_csrf(state, headers);
    let error = error.map_or(String::new(), |text| {
        format!("<p class=\"error\">{}</p>", escape(text))
    });
    let forgot = if crate::email::configured(state) {
        "<p><a href=\"/account/password/forgot\">Forgot your password?</a></p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Sign in to {server}</h1>{error}\
         <form method=\"post\" action=\"/account/login\">{csrf}{next}\
         <input name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required>\
         <input name=\"password\" type=\"password\" placeholder=\"Password\" \
         autocomplete=\"current-password\" required>\
         <button type=\"submit\">Sign in</button></form>{forgot}",
        server = escape(&state.config.server.name),
        csrf = hidden("csrf", &csrf),
        next = hidden("next", next),
    );
    let response = web::html(
        status,
        FormTargets::SelfOnly,
        web::page(state, "Sign in", &body),
    );
    match set_csrf {
        Some(cookie) => web::with_cookie(response, &cookie),
        None => response,
    }
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf: Option<String>,
    next: Option<String>,
}

/// `POST /account/login`
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<LoginForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let next = web::safe_next(form.next.as_deref());
    if !web::signed_out_csrf_ok(&headers, form.csrf.as_deref()) {
        return Ok(render_login(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            &next,
            Some("That form has expired. Please try again."),
        ));
    }
    let localpart = web::localpart_of(&form.username);
    let source = source.to_string();
    if web::spend_password_attempt(&state, &localpart, &source).is_err() {
        state
            .metrics
            .record_login(LoginMethod::Account, LoginResult::RateLimited);
        return Ok(render_login(
            &state,
            &headers,
            StatusCode::TOO_MANY_REQUESTS,
            &next,
            Some("Too many attempts. Wait a minute and try again."),
        ));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let good = accounts
        .verify_password(&localpart, &form.password)
        .map_err(|error| {
            state
                .metrics
                .record_login(LoginMethod::Account, LoginResult::Error);
            MatrixError::internal(&error.to_string())
        })?;
    if !good {
        state
            .metrics
            .record_login(LoginMethod::Account, LoginResult::BadPassword);
        return Ok(render_login(
            &state,
            &headers,
            StatusCode::UNAUTHORIZED,
            &next,
            Some("That username and password did not match."),
        ));
    }
    web::forget_password_attempts(&state, &localpart, &source);
    state
        .metrics
        .record_login(LoginMethod::Account, LoginResult::Success);
    let cookie = web::start_browser_session(&state, &localpart)?;
    let response = web::with_cookie(web::see_other(&next), &cookie);
    // The double-submit token has done its job; a fresh one is minted
    // for the next signed-out form.
    Ok(web::with_cookie(
        response,
        &web::set_cookie(&state, web::CSRF_COOKIE, "", 0),
    ))
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: Option<String>,
}

/// `POST /account/logout`
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    if let Err(refusal) = session_for_post(&state, &headers, form.csrf.as_deref())? {
        return Ok(refusal);
    }
    let cookie = web::end_browser_session(&state, &headers)?;
    Ok(web::with_cookie(web::see_other("/account/login"), &cookie))
}

#[derive(Deserialize)]
struct ProfileForm {
    csrf: Option<String>,
    #[serde(default)]
    displayname: String,
    #[serde(default)]
    avatar_url: String,
}

/// What the profile form may store; the message to show if not.
fn profile_problem(displayname: &str, avatar_url: &str) -> Option<&'static str> {
    if displayname.chars().count() > 256 || displayname.chars().any(char::is_control) {
        return Some("A display name is at most 256 characters, with no control characters.");
    }
    let mxc = avatar_url.strip_prefix("mxc://").is_some_and(|rest| {
        rest.split_once('/')
            .is_some_and(|(server, id)| !server.is_empty() && !id.is_empty())
    });
    if !avatar_url.is_empty()
        && (!mxc
            || avatar_url.len() > 255
            || avatar_url
                .chars()
                .any(|c| c.is_whitespace() || c.is_control()))
    {
        return Some("An avatar is an mxc:// URI, such as one your app uploaded.");
    }
    None
}

/// `POST /account/profile` — the same change `PUT /profile/…` makes,
/// propagated into every joined room's member event the same way.
async fn save_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let session = match session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    let displayname = form.displayname.trim();
    let avatar_url = form.avatar_url.trim();
    if let Some(problem) = profile_problem(displayname, avatar_url) {
        let body = profile_view(&state, &session)?;
        return Ok(web::html(
            StatusCode::BAD_REQUEST,
            FormTargets::SelfOnly,
            signed_in_page(&state, &session, "Profile", None, Some(problem), &body),
        ));
    }
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&session.localpart);
    let field = |value: &str| Some((!value.is_empty()).then(|| value.to_owned()));
    state
        .profiles
        .set(&user_id, field(displayname), field(avatar_url))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    crate::routes::propagate_profile(&state, &user_id)?;
    state.metrics.record_account_action(AccountAction::Profile);
    Ok(web::see_other(
        "/account/?action=org.matrix.profile&notice=profile_saved",
    ))
}

/// Check the current password for a change the session alone must not
/// be enough to make, against the shared attempt budget. `Ok(None)` when
/// it is right; the message to show when it is not.
pub(crate) fn recheck_password(
    state: &AppState,
    localpart: &str,
    source: &str,
    password: &str,
) -> Result<Option<(StatusCode, &'static str)>, MatrixError> {
    if web::spend_password_attempt(state, localpart, source).is_err() {
        return Ok(Some((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Wait a minute and try again.",
        )));
    }
    let good = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .verify_password(localpart, password)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !good {
        return Ok(Some((
            StatusCode::UNAUTHORIZED,
            "Your current password was not right.",
        )));
    }
    web::forget_password_attempts(state, localpart, source);
    Ok(None)
}

#[derive(Deserialize)]
struct PasswordForm {
    csrf: Option<String>,
    current_password: String,
    new_password: String,
    confirm_password: String,
    sign_out_others: Option<String>,
}

/// `POST /account/password`
async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<PasswordForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let session = match session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    let refuse = |status: StatusCode, problem: &str| {
        web::html(
            status,
            FormTargets::SelfOnly,
            signed_in_page(
                &state,
                &session,
                "Password",
                None,
                Some(problem),
                &password_view(&session),
            ),
        )
    };
    if let Some(problem) = web::new_password_problem(&form.new_password, &form.confirm_password) {
        return Ok(refuse(StatusCode::BAD_REQUEST, problem));
    }
    if let Some((status, problem)) = recheck_password(
        &state,
        &session.localpart,
        &source.to_string(),
        &form.current_password,
    )? {
        return Ok(refuse(status, problem));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_password(&session.localpart, &form.new_password)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // The new hash ends every browser session that predates it — a
    // password change is exactly when a stolen one must stop working —
    // except this one, the user's own, which is carried over.
    web::keep_browser_session(&state, &headers)?;
    if form.sign_out_others.is_some() {
        accounts
            .logout_everywhere(&session.localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        web::end_browser_sessions_of(&state, &session.localpart, Some(&headers))?;
    }
    state
        .metrics
        .record_account_action(AccountAction::PasswordChange);
    Ok(web::see_other(
        "/account/?action=password&notice=password_changed",
    ))
}

#[derive(Deserialize)]
struct DeviceForm {
    csrf: Option<String>,
    device_id: String,
}

/// `POST /account/sessions/end` — the device goes whole, as
/// `DELETE /devices/{deviceId}` takes it: the row, its tokens, its E2EE
/// material, and a device-list change so peers stop encrypting to it.
async fn end_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeviceForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let session = match session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let exists = accounts
        .device(&session.localpart, &form.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if exists {
        let user_id = accounts.user_id(&session.localpart);
        crate::mas::remove_device(&state, &accounts, &session.localpart, &form.device_id)?;
        let seq = state.rooms.allocate_stream_id();
        state
            .devices
            .mark_device_list_changed(&user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        state.rooms.wake_sync_waiters();
        crate::e2ee_federation::announce_device_change(
            &state,
            &user_id,
            &form.device_id,
            None,
            seq,
        );
        state
            .metrics
            .record_account_action(AccountAction::SessionEnd);
    }
    Ok(web::see_other(
        "/account/?action=org.matrix.sessions_list&notice=session_ended",
    ))
}

#[derive(Deserialize)]
struct DeactivateForm {
    csrf: Option<String>,
    password: String,
    confirm: Option<String>,
    erase: Option<String>,
}

/// `POST /account/deactivate` — what `POST /account/deactivate` in the
/// client API does: leave every room, then the shared deactivation
/// (devices, sessions, the flag, the optional erasure), and every
/// browser session with it.
async fn deactivate(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<DeactivateForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let session = match session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    let refuse = |status: StatusCode, problem: &str| {
        web::html(
            status,
            FormTargets::SelfOnly,
            signed_in_page(
                &state,
                &session,
                "Deactivate account",
                None,
                Some(problem),
                &deactivate_view(&session),
            ),
        )
    };
    if form.confirm.as_deref() != Some("yes") {
        return Ok(refuse(
            StatusCode::BAD_REQUEST,
            "Tick the box to confirm you understand this cannot be undone.",
        ));
    }
    if let Some((status, problem)) = recheck_password(
        &state,
        &session.localpart,
        &source.to_string(),
        &form.password,
    )? {
        return Ok(refuse(status, problem));
    }
    let localpart = session.localpart.clone();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let user_id = accounts.user_id(&localpart);
    for room_id in state.rooms.joined(&user_id).unwrap_or_default() {
        let _ = state.rooms.set_membership(
            &room_id,
            &user_id,
            &user_id,
            "leave",
            Some("account deactivated"),
            state.key.pair(),
        );
    }
    crate::mas::deactivate_user(&state, &localpart, form.erase.as_deref() == Some("yes"))?;
    accounts
        .logout_everywhere(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    crate::email::forget_account(&state, &localpart)?;
    web::end_browser_sessions_of(&state, &localpart, None)?;
    state.rooms.wake_sync_waiters();
    state
        .metrics
        .record_account_action(AccountAction::Deactivate);
    let cookie = web::set_cookie(&state, web::SESSION_COOKIE, "", 0);
    Ok(web::with_cookie(
        message_page(
            &state,
            StatusCode::OK,
            "Your account has been deactivated",
            "Every device has been signed out. You can close this page.",
        ),
        &cookie,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_fields_are_checked() {
        assert!(profile_problem("Alice", "").is_none());
        assert!(profile_problem("", "mxc://example.org/abc").is_none());
        assert!(profile_problem("Alice", "https://example.org/a.png").is_some());
        assert!(profile_problem("Alice", "mxc://example.org/").is_some());
        assert!(profile_problem("Alice", "mxc://example.org/a b").is_some());
        assert!(profile_problem(&"x".repeat(257), "").is_some());
        assert!(profile_problem("a\u{0}b", "").is_some());
    }

    #[test]
    fn only_fixed_notices_render() {
        assert!(notice_text("profile_saved").is_some());
        assert!(notice_text("<script>").is_none());
    }
}
