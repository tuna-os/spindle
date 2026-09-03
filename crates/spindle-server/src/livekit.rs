//! The built-in `LiveKit` JWT service (#38, MSC4195).
//!
//! # What this is
//!
//! A `MatrixRTC` call's media runs through a `LiveKit` SFU, and the SFU admits
//! a participant on a JWT signed with its API secret. Something has to mint
//! that JWT for a Matrix user, and the reference deployment runs a separate
//! service for it (`element-hq/lk-jwt-service`): the client fetches an
//! `OpenID` token from its homeserver, posts it to the service, the service
//! redeems it against the homeserver's federation `userinfo` endpoint, and
//! mints a token for whoever that names.
//!
//! This module is that service, inside the homeserver, behind
//! `[rtc.livekit]`. The contract is the one shipping clients already speak
//! -- Element Call posts to `{livekit_service_url}/sfu/get` with the same
//! body it would send the external service -- so a deployment chooses
//! between the two by configuration and no client can tell which it got.
//! ADR 0004 records why it exists at all.
//!
//! # What it checks that the external service cannot
//!
//! The external service verifies that the `OpenID` token is real and mints a
//! token for any room the client names; it has no membership state to
//! consult and asks nobody. This one holds the membership index, so a token
//! is minted only for a Matrix room the user is **joined to right now**,
//! which is the scoping #38 asks for and the single lookup that makes
//! integrating cheaper than delegating. A user who has left gets nothing.
//!
//! What it cannot do is revoke: a JWT is stateless, and a user who leaves
//! the room after minting one holds it until it expires. The window is
//! configured (`token_ttl_seconds`) and short by default, and the
//! limitation is stated here rather than implied away.
//!
//! # The secret
//!
//! `[rtc.livekit] secret` is `LiveKit`'s API secret, shared with the SFU and
//! nothing else. It is deliberately not the server's signing key: the two
//! rotate on different schedules, belong to different parties, and a
//! compromise of one must not be a compromise of the other.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use hmac::Mac as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::config::LivekitConfig;
use crate::errors::MatrixError;
use crate::oidc::base64url_unpadded;
use crate::openid::OpenId;
use crate::ratelimit::LIVEKIT_TOKEN_PER_USER;

/// Where, under the client base URL, the service answers.
///
/// This is what `livekit_service_url` advertises; clients append `/sfu/get`
/// to it themselves, which is why the constant is the prefix and not the
/// route. Under `/_spindle` rather than `/_matrix` because it is not a
/// Matrix endpoint: it is `lk-jwt-service`'s contract, served here.
pub const SERVICE_PATH: &str = "/_spindle/rtc/livekit";

/// The `livekit_service_url` a client is told, when the service is on.
#[must_use]
pub fn service_url(config: &crate::Config) -> Option<String> {
    config
        .rtc
        .livekit
        .as_ref()
        .map(|_| format!("{}{SERVICE_PATH}", config.client_base_url()))
}

/// The service's one route.
///
/// Mounted whether or not `[rtc.livekit]` is set, and answering
/// `M_UNRECOGNIZED` when it is not: a deployment that runs
/// `lk-jwt-service` beside this server has not asked for a second minter,
/// and the honest answer to a client that finds this path anyway is the
/// one an absent endpoint gives, not a refusal that implies a service.
pub fn routes() -> Router<AppState> {
    Router::new().route("/_spindle/rtc/livekit/sfu/get", post(sfu_get))
}

/// The body Element Call sends `lk-jwt-service`, field for field.
#[derive(Debug, Deserialize)]
struct SfuRequest {
    /// The `LiveKit` room to join. Element Call sends the Matrix room ID,
    /// which is what makes the membership check below possible at all.
    room: String,
    openid_token: OpenIdToken,
    #[serde(default)]
    device_id: String,
}

/// The `OpenID` token as `/openid/request_token` handed it out, passed
/// through unchanged. Only two of its four fields matter here.
#[derive(Debug, Deserialize)]
struct OpenIdToken {
    access_token: String,
    matrix_server_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// `POST /_spindle/rtc/livekit/sfu/get`
///
/// Unauthenticated in the Matrix sense -- the `OpenID` token in the body is
/// the credential, exactly as it is for the external service -- and
/// answered in the external service's shape: `{"url": ..., "jwt": ...}`.
///
/// The checks run cheapest-first and each refusal says as little as it can.
/// A token for another server is refused rather than verified: this
/// service mints for this server's users, and a remote user's call is a
/// remote server's problem.
async fn sfu_get(
    State(state): State<AppState>,
    Json(request): Json<SfuRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(livekit) = state.config.rtc.livekit.as_ref() else {
        return Err(MatrixError::new(
            axum::http::StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "the built-in LiveKit service is not configured",
        ));
    };
    if request.room.is_empty() {
        return Err(MatrixError::missing_param("room"));
    }
    if request.device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    if request.openid_token.matrix_server_name != state.config.server.name {
        return Err(MatrixError::forbidden(
            "this service mints tokens for this server's own users only",
        ));
    }
    let user_id =
        match OpenId::new(Arc::clone(&state.store)).redeem(&request.openid_token.access_token) {
            Ok(Some(user_id)) => user_id,
            Ok(None) => return Err(MatrixError::unknown_token()),
            Err(error) => return Err(MatrixError::internal(&error.to_string())),
        };
    if let Err(retry) = state
        .limiter
        .check(&format!("livekit:user:{user_id}"), LIVEKIT_TOKEN_PER_USER)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    // Scoped to membership *now*. This is the check the external service
    // has no state to make, and the reason the token is not minted for
    // whatever room the caller names.
    let joined = state
        .rooms
        .is_joined(&user_id, &request.room)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !joined {
        return Err(MatrixError::forbidden("not a member of that room"));
    }
    let jwt = mint(
        livekit,
        &user_id,
        &request.device_id,
        &request.room,
        now_secs(),
    );
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// A `LiveKit` access token: HS256 over the claims the SFU reads.
///
/// The identity is `{user_id}:{device_id}`, which is the external service's
/// format and the one Element Call parses to match an SFU participant to a
/// call member. The grants are the least the client needs to be in the
/// call: join this one room, publish, subscribe. `roomCreate` is withheld
/// -- it would also permit deleting the room, which is a way to end
/// everyone's call -- and the SFU's own `auto_create` (its default) makes
/// the room on the first join instead.
///
/// `nbf` and `exp` bound the window on both sides; `exp - nbf` is exactly
/// `token_ttl_seconds`, and a test holds it there.
fn mint(
    livekit: &LivekitConfig,
    user_id: &str,
    device_id: &str,
    room: &str,
    now_secs: u64,
) -> String {
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    let claims = json!({
        "iss": livekit.key,
        "sub": format!("{user_id}:{device_id}"),
        "name": user_id,
        "iat": now_secs,
        "nbf": now_secs,
        "exp": now_secs.saturating_add(livekit.token_ttl_seconds),
        "video": {
            "room": room,
            "roomJoin": true,
            "roomCreate": false,
            "canPublish": true,
            "canSubscribe": true,
            "canUpdateOwnMetadata": true,
        },
    });
    let signing_input = format!(
        "{}.{}",
        base64url_unpadded(header.to_string().as_bytes()),
        base64url_unpadded(claims.to_string().as_bytes())
    );
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(livekit.secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(signing_input.as_bytes());
    let signature = base64url_unpadded(&mac.finalize().into_bytes());
    format!("{signing_input}.{signature}")
}

/// Unix seconds now.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
