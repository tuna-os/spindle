//! `m.login.terms`: a policy a new account accepts before it registers.
//!
//! Registration is stateless: it keeps no table of half-finished flows.
//! So the stage hands back a session ID that proves itself, a timestamp
//! and a keyed hash of it under a key made at start-up. The next stage
//! presents that ID, and registration checks it. A restart voids IDs in
//! flight, and the client simply starts the flow again.

use std::sync::OnceLock;

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::AppState;

/// How long an accepted session stays good.
const SESSION_TTL_MS: u64 = 60 * 60 * 1000;

pub const STAGE: &str = "m.login.terms";

fn key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        crate::secrets::fill(&mut key);
        key
    })
}

/// Whether registration asks for the policy.
#[must_use]
pub fn enabled(state: &AppState) -> bool {
    state.config.registration.terms_url.is_some()
}

/// The stage's `params`, in the shape the spec gives.
#[must_use]
pub fn params(state: &AppState) -> Value {
    let config = &state.config.registration;
    json!({
        "policies": {
            "terms_of_service": {
                "version": config.terms_version,
                "en": { "name": config.terms_name, "url": config.terms_url },
            }
        }
    })
}

fn mac(timestamp: u64) -> String {
    blake3::keyed_hash(key(), timestamp.to_string().as_bytes())
        .to_hex()
        .to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A session ID that shows the policy was accepted.
#[must_use]
pub fn mint_session() -> String {
    let timestamp = now_ms();
    format!("{timestamp}.{}", mac(timestamp))
}

/// Whether `session` is one [`mint_session`] made and is still fresh.
#[must_use]
pub fn session_valid(session: &str) -> bool {
    let Some((timestamp, tag)) = session.split_once('.') else {
        return false;
    };
    let Ok(timestamp) = timestamp.parse::<u64>() else {
        return false;
    };
    let age = now_ms().saturating_sub(timestamp);
    age < SESSION_TTL_MS && mac(timestamp) == tag
}

/// The terms stage of registration. `None` lets the request go on to the
/// stages after it; `Some` is the 401 to send back.
///
/// The `challenge` is the registration challenge the caller builds, so
/// the flows and params the client sees stay in one place.
#[must_use]
pub fn gate(
    auth: Option<&Value>,
    challenge: (StatusCode, Json<Value>),
) -> Option<(StatusCode, Json<Value>)> {
    if auth.is_some_and(|auth| auth["session"].as_str().is_some_and(session_valid)) {
        return None;
    }
    let (status, Json(mut body)) = challenge;
    if auth.is_some_and(|auth| auth["type"] == STAGE) {
        body["completed"] = json!([STAGE]);
        body["session"] = json!(mint_session());
    }
    Some((status, Json(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_verifies_and_a_forged_one_does_not() {
        let session = mint_session();
        assert!(session_valid(&session));
        assert!(!session_valid("register"));
        let (timestamp, _) = session.split_once('.').unwrap();
        assert!(!session_valid(&format!("{timestamp}.{}", "0".repeat(64))));
    }

    #[test]
    fn a_stale_session_is_refused() {
        let old = now_ms() - SESSION_TTL_MS - 1;
        assert!(!session_valid(&format!("{old}.{}", mac(old))));
    }
}
