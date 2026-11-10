//! The stages that come before registration's last one: the policy
//! (`m.login.terms`) and the CAPTCHA (`m.login.recaptcha`).
//!
//! Registration is stateless: it keeps no table of half-finished flows.
//! So a completed stage hands back a session ID that proves itself: a
//! timestamp, the set of stages done and a keyed hash of both under a key
//! made at start-up. The next request presents that ID, and registration
//! checks it. A restart voids IDs in flight, and the client simply starts
//! the flow again. The stages run in a fixed order, policy first, so none
//! can be used to skip another.

use std::sync::OnceLock;

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::AppState;
use crate::registration_terms;

/// How long a session stays good.
const SESSION_TTL_MS: u64 = 60 * 60 * 1000;

const TERMS: u8 = 1;
const CAPTCHA: u8 = 2;

fn key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        crate::secrets::fill(&mut key);
        key
    })
}

/// The stages this server asks for, in order, as `(bit, type)`.
#[must_use]
pub fn required(state: &AppState) -> Vec<(u8, &'static str)> {
    let mut stages = Vec::new();
    if registration_terms::enabled(state) {
        stages.push((TERMS, registration_terms::STAGE));
    }
    if state.captcha.is_some() {
        stages.push((CAPTCHA, crate::captcha::STAGE));
    }
    stages
}

/// The `params` of every stage in front of the last one.
#[must_use]
pub fn params(state: &AppState) -> Value {
    let mut params = json!({});
    if registration_terms::enabled(state) {
        params[registration_terms::STAGE] = registration_terms::params(state);
    }
    if let Some(captcha) = &state.captcha {
        params[crate::captcha::STAGE] = captcha.params();
    }
    params
}

fn mac(timestamp: u64, done: u8) -> String {
    blake3::keyed_hash(key(), format!("{timestamp}.{done}").as_bytes())
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

/// A session ID that shows the stages in `done` are complete.
fn mint_session(done: u8) -> String {
    let timestamp = now_ms();
    format!("{timestamp}.{done}.{}", mac(timestamp, done))
}

/// The stages `session` proves, or `0` for one this server did not make or
/// that is stale.
fn session_done(session: &str) -> u8 {
    let mut parts = session.splitn(3, '.');
    let (Some(timestamp), Some(done), Some(tag)) = (parts.next(), parts.next(), parts.next())
    else {
        return 0;
    };
    let (Ok(timestamp), Ok(done)) = (timestamp.parse::<u64>(), done.parse::<u8>()) else {
        return 0;
    };
    let fresh = now_ms().saturating_sub(timestamp) < SESSION_TTL_MS;
    if fresh && mac(timestamp, done) == tag {
        done
    } else {
        0
    }
}

/// The stages in front of registration's last one. `None` lets the request
/// go on; `Some` is the 401 to send back.
///
/// The `challenge` is the registration challenge the caller builds, so the
/// flows and params the client sees stay in one place.
pub async fn gate(
    state: &AppState,
    auth: Option<&Value>,
    remote_ip: &str,
    challenge: (StatusCode, Json<Value>),
) -> Option<(StatusCode, Json<Value>)> {
    let stages = required(state);
    let all = stages.iter().fold(0, |mask, (bit, _)| mask | bit);
    let done = auth
        .and_then(|auth| auth["session"].as_str())
        .map_or(0, session_done);
    if all != 0 && done & all == all {
        return None;
    }
    let (status, Json(mut body)) = challenge;
    let mut done = done & all;
    // Only the next stage in order can be completed.
    let next = stages.iter().find(|(bit, _)| done & bit == 0);
    if let (Some(auth), Some(&(bit, stage))) = (auth, next)
        && auth["type"] == stage
    {
        let passed = if bit == CAPTCHA {
            let token = auth["response"].as_str().unwrap_or_default();
            // `next` exists only when the verifier does.
            match &state.captcha {
                Some(captcha) => captcha.verify(token, Some(remote_ip)).await,
                None => false,
            }
        } else {
            true
        };
        if passed {
            done |= bit;
        } else {
            body["errcode"] = json!("M_UNAUTHORIZED");
            body["error"] = json!("the CAPTCHA was not solved");
        }
    }
    if done != 0 {
        body["completed"] = json!(
            stages
                .iter()
                .filter(|(bit, _)| done & bit != 0)
                .map(|(_, stage)| *stage)
                .collect::<Vec<_>>()
        );
        body["session"] = json!(mint_session(done));
    }
    Some((status, Json(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_verifies_and_a_forged_one_does_not() {
        let session = mint_session(TERMS);
        assert_eq!(session_done(&session), TERMS);
        assert_eq!(session_done("register"), 0);
        let (timestamp, rest) = session.split_once('.').unwrap();
        // The stage set is covered by the hash: claiming more is refused.
        assert_eq!(
            session_done(&format!(
                "{timestamp}.{}.{}",
                TERMS | CAPTCHA,
                rest.split_once('.').unwrap().1
            )),
            0
        );
        assert_eq!(
            session_done(&format!("{timestamp}.{TERMS}.{}", "0".repeat(64))),
            0
        );
    }

    #[test]
    fn a_stale_session_is_refused() {
        let old = now_ms() - SESSION_TTL_MS - 1;
        assert_eq!(
            session_done(&format!("{old}.{TERMS}.{}", mac(old, TERMS))),
            0
        );
    }
}
