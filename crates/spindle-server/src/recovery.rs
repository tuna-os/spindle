//! Password recovery that needs no mail: one-time recovery codes.
//!
//! A deployment without an SMTP relay still has users who forget their
//! password. Two ways back exist without mail: an administrator issues a
//! reset link (`email::issue_reset_link`, from the CLI or the admin API)
//! and hands it over by whatever channel they trust; or the user kept one
//! of the ten recovery codes they generated on the account pages, and
//! uses it on `/account/recover` to choose a new password.
//!
//! **How codes are stored, and why not Argon2.** Each code is 16
//! characters from a 32-symbol alphabet: 80 bits chosen by the OS, not by a
//! person. Argon2 exists to make guessing a *human-chosen* secret from its
//! hash expensive; an 80-bit random value is out of reach of exhaustive
//! search with any hash, fast or slow, so the slowness would buy nothing.
//! It would cost, though: checking one attempt against ten stored codes
//! would be ten 19 MiB Argon2 runs, a lever for anyone who can post the
//! form. So each code is stored as a random 16-byte salt and
//! `BLAKE3(salt ‖ code)`: the salt keeps equal codes on two accounts from
//! sharing a digest, the digest keeps a copy of the store from being a copy
//! of the codes, and the comparison is constant-time. Attempts are counted
//! against the same per-account and per-source budget as every password
//! check, so the form is no faster a guessing oracle than the login.
//!
//! Generating a set requires the current password and replaces any
//! previous set; using a code consumes it, sets the new password, and signs
//! out every device and browser — the same end state as a reset link.

use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store};

use crate::AppState;
use crate::accounts::Accounts;
use crate::errors::MatrixError;
use crate::metrics::{AccountAction, PasswordRecoveryMethod, PasswordRecoveryResult};
use crate::routes::ClientAddr;
use crate::web::{self, BrowserSession, FormTargets, escape, hidden};

/// How many codes one generation makes.
pub const CODES_PER_SET: usize = 10;

/// Characters per code: 16 × 5 bits = 80 bits of entropy.
const CODE_CHARS: usize = 16;

/// 32 symbols, so each is exactly five random bits, without the ones that
/// read alike (`0`/`O`, `1`/`I`).
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredCode {
    salt: String,
    digest: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct CodeSet {
    created_ms: u64,
    codes: Vec<StoredCode>,
}

fn storage(error: &impl std::fmt::Display) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

/// A code as typed, reduced to what was generated: case, spaces and
/// dashes do not matter.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn digest_of(salt: &[u8], code: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt);
    hasher.update(code.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|i| text.get(i * 2..i * 2 + 2))
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect()
}

fn load(store: &FjallStore, localpart: &str) -> Result<CodeSet, MatrixError> {
    Ok(ReadView::get(store, &keys::recovery_codes(localpart))
        .map_err(|e| storage(&e))?
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default())
}

fn save(store: &FjallStore, localpart: &str, set: &CodeSet) -> Result<(), MatrixError> {
    Store::put(
        store,
        &keys::recovery_codes(localpart),
        &serde_json::to_vec(set).map_err(|e| storage(&e))?,
    )
    .map_err(|e| storage(&e))
}

/// Make a fresh set for `localpart`, replacing any earlier one, and return
/// the codes in clear — the only time they exist that way.
///
/// # Errors
///
/// A storage error.
pub fn generate(store: &FjallStore, localpart: &str) -> Result<Vec<String>, MatrixError> {
    let mut shown = Vec::with_capacity(CODES_PER_SET);
    let mut stored = Vec::with_capacity(CODES_PER_SET);
    for _ in 0..CODES_PER_SET {
        let mut random = [0_u8; CODE_CHARS];
        crate::secrets::fill(&mut random);
        let code: String = random
            .iter()
            .map(|byte| char::from(ALPHABET[usize::from(byte & 31)]))
            .collect();
        let mut salt = [0_u8; 16];
        crate::secrets::fill(&mut salt);
        stored.push(StoredCode {
            salt: hex(&salt),
            digest: digest_of(&salt, &code),
        });
        let grouped = code
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("-");
        shown.push(grouped);
    }
    save(
        store,
        localpart,
        &CodeSet {
            created_ms: web::now_ms(),
            codes: stored,
        },
    )?;
    Ok(shown)
}

/// How many unused codes an account has.
///
/// # Errors
///
/// A storage error.
pub fn remaining(store: &FjallStore, localpart: &str) -> Result<usize, MatrixError> {
    Ok(load(store, localpart)?.codes.len())
}

/// Spend `code` if it is one of `localpart`'s. Every stored code is
/// compared, in constant time, whether or not an earlier one matched, and
/// an account with no codes is compared against a set of dummies: the
/// time taken says nothing about which codes exist.
///
/// # Errors
///
/// A storage error.
pub fn consume(store: &FjallStore, localpart: &str, code: &str) -> Result<bool, MatrixError> {
    let code = normalize(code);
    let mut set = load(store, localpart)?;
    let dummies;
    let candidates: &[StoredCode] = if set.codes.is_empty() {
        dummies = vec![
            StoredCode {
                salt: "00".repeat(16),
                digest: "0".repeat(64),
            };
            CODES_PER_SET
        ];
        &dummies
    } else {
        &set.codes
    };
    let mut found = None;
    for (index, stored) in candidates.iter().enumerate() {
        let candidate = digest_of(&unhex(&stored.salt), &code);
        if web::ct_eq(candidate.as_bytes(), stored.digest.as_bytes()) && found.is_none() {
            found = Some(index);
        }
    }
    let Some(index) = found.filter(|_| !set.codes.is_empty()) else {
        return Ok(false);
    };
    set.codes.remove(index);
    save(store, localpart, &set)?;
    Ok(true)
}

/// Drop an account's codes — what deactivation does.
///
/// # Errors
///
/// A storage error.
pub(crate) fn forget_account(state: &AppState, localpart: &str) -> Result<(), MatrixError> {
    Store::delete(state.store.as_ref(), &keys::recovery_codes(localpart)).map_err(|e| storage(&e))
}

/// The links under a sign-in form: the recovery-code page always, the
/// forgotten-password mail only when this server sends mail.
pub(crate) fn recovery_links(state: &AppState) -> String {
    let mut links = String::from("<p><a href=\"/account/recover\">Use a recovery code</a></p>");
    if crate::email::configured(state) {
        links.push_str("<p><a href=\"/account/password/forgot\">Forgot your password?</a></p>");
    }
    links
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/account/recover", get(recover_page).post(recover))
        .route("/account/recovery/generate", post(generate_codes))
}

/// The account page's recovery section (`?action=recovery`).
pub(crate) fn recovery_view(
    state: &AppState,
    session: &BrowserSession,
) -> Result<String, MatrixError> {
    let left = remaining(state.store.as_ref(), &session.localpart)?;
    let status = if left == 0 {
        "<p>You have no recovery codes. Generate a set and keep it somewhere safe: \
         a code lets you choose a new password if you forget this one.</p>"
            .to_owned()
    } else {
        format!("<p>You have <strong>{left}</strong> unused recovery codes.</p>")
    };
    Ok(format!(
        "{status}<p>Generating a new set replaces every code you have now.</p>\
         <form method=\"post\" action=\"/account/recovery/generate\">{csrf}\
         <input name=\"password\" type=\"password\" placeholder=\"Your password\" \
         autocomplete=\"current-password\" required>\
         <button type=\"submit\">Generate {CODES_PER_SET} new codes</button></form>",
        csrf = hidden("csrf", &session.csrf),
    ))
}

#[derive(Deserialize)]
struct GenerateForm {
    csrf: Option<String>,
    password: String,
}

/// `POST /account/recovery/generate` — the codes, shown once.
async fn generate_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<GenerateForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    let session = match crate::account::session_for_post(&state, &headers, form.csrf.as_deref())? {
        Ok(session) => session,
        Err(refusal) => return Ok(refusal),
    };
    if let Some((status, problem)) = crate::account::recheck_password(
        &state,
        &session.localpart,
        &source.to_string(),
        &form.password,
    )? {
        let body = recovery_view(&state, &session)?;
        return Ok(crate::account::refusal_page(
            &state,
            &session,
            status,
            "Recovery codes",
            problem,
            &body,
        ));
    }
    let codes = generate(state.store.as_ref(), &session.localpart)?;
    state
        .metrics
        .record_account_action(AccountAction::RecoveryCodes);
    let list = codes.iter().fold(String::new(), |mut list, code| {
        let _ = write!(list, "<li><code>{}</code></li>", escape(code));
        list
    });
    let body = format!(
        "<p>Write these down or save them somewhere safe. <strong>They will not be shown \
         again.</strong> Each works once; any earlier codes no longer work.</p><ol>{list}</ol>"
    );
    Ok(web::html(
        StatusCode::OK,
        FormTargets::SelfOnly,
        crate::account::signed_in_page(&state, &session, "Recovery codes", None, None, &body),
    ))
}

fn recover_form(
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
        "<h1>Use a recovery code</h1>{error}<p>Enter your username, one of your recovery \
         codes and a new password. The code is used up, and every device is signed out.</p>\
         <form method=\"post\" action=\"/account/recover\">{csrf}\
         <input name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required>\
         <input name=\"code\" placeholder=\"XXXX-XXXX-XXXX-XXXX\" autocomplete=\"off\" required>\
         <input name=\"new_password\" type=\"password\" placeholder=\"New password\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <input name=\"confirm_password\" type=\"password\" placeholder=\"New password, again\" \
         autocomplete=\"new-password\" minlength=\"{min}\" required>\
         <button type=\"submit\">Set new password</button></form>\
         <p>No codes? Ask the server's administrator for a reset link.</p>",
        csrf = hidden("csrf", &csrf),
        min = web::MIN_PASSWORD_CHARS,
    );
    let response = web::html(
        status,
        FormTargets::SelfOnly,
        web::page(state, "Use a recovery code", &body),
    );
    match set_csrf {
        Some(cookie) => web::with_cookie(response, &cookie),
        None => response,
    }
}

/// `GET /account/recover`
async fn recover_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    Ok(recover_form(&state, &headers, StatusCode::OK, None))
}

#[derive(Deserialize)]
struct RecoverForm {
    csrf: Option<String>,
    username: String,
    code: String,
    new_password: String,
    confirm_password: String,
}

/// `POST /account/recover` — the new password is checked before the code
/// is spent, so a typo costs a retry rather than a code; one message for
/// an unknown user and a wrong code.
async fn recover(
    State(state): State<AppState>,
    headers: HeaderMap,
    source: ClientAddr,
    Form(form): Form<RecoverForm>,
) -> Result<Response, MatrixError> {
    crate::oidc::provider(&state)?;
    if !web::signed_out_csrf_ok(&headers, form.csrf.as_deref()) {
        return Ok(recover_form(
            &state,
            &headers,
            StatusCode::FORBIDDEN,
            Some("That form has expired. Please try again."),
        ));
    }
    if let Some(problem) = web::new_password_problem(&form.new_password, &form.confirm_password) {
        return Ok(recover_form(
            &state,
            &headers,
            StatusCode::BAD_REQUEST,
            Some(problem),
        ));
    }
    let localpart = web::localpart_of(&form.username);
    let source = source.to_string();
    if web::spend_password_attempt(&state, &localpart, &source).is_err() {
        state.metrics.record_password_recovery(
            PasswordRecoveryMethod::RecoveryCode,
            PasswordRecoveryResult::RateLimited,
        );
        return Ok(recover_form(
            &state,
            &headers,
            StatusCode::TOO_MANY_REQUESTS,
            Some("Too many attempts. Wait a minute and try again."),
        ));
    }
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let active = accounts
        .account(&localpart)
        .map_err(|e| storage(&e))?
        .is_some_and(|account| !account.deactivated);
    let spent = consume(state.store.as_ref(), &localpart, &form.code)?;
    if !(spent && active) {
        state.metrics.record_password_recovery(
            PasswordRecoveryMethod::RecoveryCode,
            PasswordRecoveryResult::Rejected,
        );
        return Ok(recover_form(
            &state,
            &headers,
            StatusCode::UNAUTHORIZED,
            Some("That username and recovery code did not match."),
        ));
    }
    web::forget_password_attempts(&state, &localpart, &source);
    accounts
        .set_password(&localpart, &form.new_password)
        .map_err(|e| storage(&e))?;
    accounts
        .logout_everywhere(&localpart)
        .map_err(|e| storage(&e))?;
    web::end_browser_sessions_of(&state, &localpart, None)?;
    crate::email::drop_reset_links(state.store.as_ref(), &localpart)?;
    state.metrics.record_password_recovery(
        PasswordRecoveryMethod::RecoveryCode,
        PasswordRecoveryResult::Success,
    );
    let left = remaining(state.store.as_ref(), &localpart)?;
    Ok(crate::account::message_page(
        &state,
        StatusCode::OK,
        "Your password has been changed",
        &format!(
            "Every device has been signed out. Sign in again with your new password. You \
             have {left} recovery codes left."
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_verify_once_and_regeneration_replaces_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let codes = generate(&store, "alice").unwrap();
        assert_eq!(codes.len(), CODES_PER_SET);
        for code in &codes {
            assert_eq!(code.len(), 19, "{code}");
            assert!(
                code.chars()
                    .all(|c| c == '-' || ALPHABET.contains(&u8::try_from(c).unwrap()))
            );
        }
        // Case, spaces and dashes do not matter; each works once.
        let typed = codes[3].to_lowercase().replace('-', " ");
        assert!(consume(&store, "alice", &typed).unwrap());
        assert!(!consume(&store, "alice", &codes[3]).unwrap());
        assert_eq!(remaining(&store, "alice").unwrap(), CODES_PER_SET - 1);
        // Another account's code, or none, is just wrong.
        assert!(!consume(&store, "bob", &codes[0]).unwrap());
        assert!(!consume(&store, "alice", "AAAA-AAAA-AAAA-AAAA").unwrap());
        // A new set retires the old.
        let fresh = generate(&store, "alice").unwrap();
        assert!(!consume(&store, "alice", &codes[0]).unwrap());
        assert!(consume(&store, "alice", &fresh[0]).unwrap());
    }

    #[test]
    fn the_store_holds_no_code() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let codes = generate(&store, "alice").unwrap();
        let raw = ReadView::get(&store, &keys::recovery_codes("alice"))
            .unwrap()
            .unwrap();
        let text = String::from_utf8(raw).unwrap();
        for code in codes {
            assert!(!text.contains(&normalize(&code)), "a code at rest");
        }
    }
}
