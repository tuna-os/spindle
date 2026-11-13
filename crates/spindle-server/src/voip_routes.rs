//! Voice and video calls: TURN server credentials and the RTC transports a
//! call client may use.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::rtc_transports;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};

/// TURN credentials and RTC transports.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/voip/turnServer", get(voip_turn_server))
        .route(
            "/_matrix/client/v1/rtc/transports",
            get(rtc_transports_endpoint),
        )
        // The unstable path is the one shipping clients actually request:
        // MSC4143 is unmerged, so Element Call and Element X ask here and
        // nowhere else. The stable path above is served alongside it for
        // the day the MSC lands, not instead of it.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
            get(rtc_transports_endpoint),
        )
}

/// `GET /_matrix/client/v3/voip/turnServer`
///
/// Where to relay a call that cannot go peer-to-peer, and how to prove to the
/// relay that this server sent you.
///
/// **An empty object is a real answer**, not a failure: it is what the spec
/// says to return when no relay is configured, and what a client is prepared
/// for. Most calls never need a relay, so a server without one is a working
/// server -- and a 404 here would have clients logging an error on every call
/// setup for a condition that is normal.
///
/// # The credential is minted here and verified without us
///
/// With `shared_secret`, this is the TURN REST scheme coturn's
/// `static-auth-secret` expects: the username is `expiry:user_id`, and the
/// password is an HMAC of that username under the secret. The relay
/// recomputes the same HMAC and decides for itself -- it needs no account
/// database, and it never talks to this server. That is the point of the
/// scheme, and the reason it is preferred over a static pair, which cannot
/// expire and cannot be revoked for one caller.
///
/// HMAC-**SHA1**, which is not a choice: it is what the scheme specifies and
/// what coturn computes, so a stronger digest here would authenticate
/// against nothing.
async fn voip_turn_server(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let turn = &state.config.turn;
    if turn.uris.is_empty() {
        return Ok(Json(json!({})));
    }
    let ttl = turn.ttl_seconds;
    let (username, password) = if let Some(secret) = turn.shared_secret.as_deref() {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0)
            .saturating_add(ttl);
        let username = format!("{expiry}:{}", identity.user_id);
        let password = turn_credential(secret, &username);
        (username, password)
    } else {
        // Validation refuses relays with neither scheme configured, and
        // refuses a username without a password, so both are present here.
        (
            turn.username.clone().unwrap_or_default(),
            turn.password.clone().unwrap_or_default(),
        )
    };
    Ok(Json(json!({
        "username": username,
        "password": password,
        "uris": turn.uris,
        "ttl": ttl,
    })))
}

/// `GET /_matrix/client/v1/rtc/transports` (MSC4143)
///
/// Where a `MatrixRTC` call is carried. This server never touches the media
/// and never speaks to the backend -- the whole of its part in `MatrixRTC` is
/// this answer plus the events it already relays, which is why the MSC
/// calls discovery "the only HS-side requirement".
///
/// Authenticated, as the MSC has it: the unauthenticated half of discovery
/// is `.well-known`, which exists precisely so a client can find a backend
/// before it has a token. Serving this one openly would make the
/// distinction meaningless.
///
/// A deployment with no transport configured answers `{"rtc_transports": []}`
/// rather than 404: the endpoint's presence is the server's claim to
/// implement MSC4143, and the list is what it currently has. A 404 would
/// tell a client to stop asking.
async fn rtc_transports_endpoint(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
) -> Json<Value> {
    Json(json!({ "rtc_transports": rtc_transports(&state) }))
}

/// The TURN REST password: base64 of HMAC-SHA1 over the username.
///
/// Padded base64, unlike everything else here. Matrix uses the unpadded form
/// throughout and `signing.rs` says why; this is not Matrix's encoding, it is
/// coturn's, and coturn compares against the padded string.
fn turn_credential(secret: &str, username: &str) -> String {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(username.as_bytes());
    base64_padded(&mac.finalize().into_bytes())
}

/// Standard base64, with padding.
fn base64_padded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for slot in 0..4 {
            if slot <= chunk.len() {
                let index = (triple >> (18 - 6 * slot)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod turn_credential_tests {
    use super::{base64_padded, turn_credential};

    /// The vector is not from this codebase.
    ///
    /// `base64.b64encode(hmac.new(b"a-shared-secret", b"1700000000:@alice:example.org",
    /// hashlib.sha1).digest())`, run under Python and pasted here. Deriving
    /// the expectation from the code under test would make the assertion
    /// agree with any bug that code contained -- and that is the whole
    /// failure mode for this function, because nothing in this system ever
    /// checks the digest. The relay does, on someone else's machine, at call
    /// time, with nothing reaching this server's log when it rejects one.
    #[test]
    fn the_rest_credential_matches_an_independently_computed_hmac() {
        assert_eq!(
            turn_credential("a-shared-secret", "1700000000:@alice:example.org"),
            "/frbZwByWmVi/+XgyPWs+RCONX0=",
        );
    }

    /// Padding is part of the string coturn compares against.
    ///
    /// Matrix uses unpadded base64 everywhere else here, so the tempting
    /// move is to reuse that encoder. These are the three lengths that tell
    /// the two apart: only a multiple of three encodes identically either
    /// way.
    #[test]
    fn the_encoder_pads() {
        assert_eq!(base64_padded(b"abc"), "YWJj");
        assert_eq!(base64_padded(b"ab"), "YWI=");
        assert_eq!(base64_padded(b"a"), "YQ==");
        assert_eq!(base64_padded(b""), "");
    }
}
