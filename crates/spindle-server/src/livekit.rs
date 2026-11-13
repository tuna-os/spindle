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
//! # Users of other servers
//!
//! In a call across servers each participant publishes on their own
//! server's SFU and subscribes to everyone else's, so a remote user asks
//! this service for a token with an `OpenID` token from *their* server.
//! That token is confirmed where it was issued -- `openid/userinfo` over
//! federation, as `lk-jwt-service` does -- and must name a user of that
//! server who is joined to the room in this server's view. The token they
//! get joins and subscribes but does not publish unless their server is in
//! `full_access_servers`, and it does not create the `LiveKit` room: the
//! split `lk-jwt-service` makes between full-access and restricted users,
//! kept so that a call's room on this SFU exists because someone of this
//! server's is in it.
//!
//! # Rooms on the SFU
//!
//! Room names and identities are `lk-jwt-service`'s (0.7): the `LiveKit`
//! room is a hash of the Matrix room and the `MatrixRTC` slot, and a Matrix
//! 2.0 participant's identity a hash of user, device and member ID, which
//! clients compute themselves to match a participant to a membership. So
//! a deployment moving between the two services lands a call in the same
//! room either way. Like the external service, this one creates the room
//! through the SFU's API for a full-access user rather than leaning on the
//! SFU's `auto_create`, so an SFU configured the way `lk-jwt-service`
//! recommends (`auto_create: false`) works unchanged; the token itself
//! never carries `roomCreate`.
//!
//! # The secret
//!
//! `[rtc.livekit] secret` is `LiveKit`'s API secret, shared with the SFU and
//! nothing else. It is deliberately not the server's signing key: the two
//! rotate on different schedules, belong to different parties, and a
//! compromise of one must not be a compromise of the other.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{FromRequestParts as _, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use hmac::{KeyInit as _, Mac as _};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Digest as _;
use spindle_store::{FjallStore, ReadView as _, Store as _};

use crate::AppState;
use crate::config::LivekitConfig;
use crate::errors::MatrixError;
use crate::federation::FederationError;
use crate::oidc::base64url_unpadded;
use crate::openid::OpenId;
use crate::ratelimit::{LIVEKIT_TOKEN_PER_REMOTE_SERVER, LIVEKIT_TOKEN_PER_USER};

/// The `livekit-server` release this server's supervision is written
/// against: Element Server Suite parity. The operator upgrades the binary;
/// this server never fetches one. `spindle sfu status` reports the running
/// binary's version beside this pin so drift is visible rather than silent.
pub const LIVEKIT_SERVER_PIN: &str = "v1.13.5";

/// The switch, in the store rather than the config file: `1` on, `0` off.
/// Absent, the config decides (on exactly when `[rtc.livekit]` is set).
/// Operator files are never rewritten by the runtime switch — `spindle sfu
/// on|off` and the admin API write this key, and a restart reads it back.
const SFU_SWITCH_KEY: &[u8; 15] = b"rtc/sfu/enabled";

/// One held delegated leave, recorded by the delegation probe and consumed
/// by the SFU webhook when the participant drops off the media.
const DELEGATION_PREFIX: &str = "rtc/sfu/delegation/";

/// The largest minter request body: a token request names a room and a
/// device, not an upload.
const MAX_BODY: usize = 64 * 1024;

/// The `MatrixRTC` slot of a room's one call: what Element Call names on
/// the Matrix 2.0 endpoints, and what the legacy `sfu/get`, which names no
/// slot, means. `lk-jwt-service` reads the legacy request the same way.
const CALL_SLOT: &str = "m.call#ROOM";

/// How long a server that could not be asked about an `OpenID` token is
/// not asked again. A dead server named in a flood of token requests is
/// tried once per period rather than once per request, and every one of
/// those requests is answered at once rather than after a timeout.
const UNREACHABLE_FOR: Duration = Duration::from_secs(30);

/// The most servers remembered as unreachable at once. Past it a new name
/// is simply asked: the bound keeps strangers' names from growing memory,
/// and the per-server rate limit still bounds the asking.
const MAX_UNREACHABLE: usize = 1024;

/// How long the SFU's room API has to create a room while a client waits
/// for its token.
const SFU_API_TIMEOUT: Duration = Duration::from_secs(5);

/// How far a webhook's `nbf`/`exp` may sit from this server's clock: the
/// SFU and this server keep their own time.
const WEBHOOK_CLOCK_SKEW_SECS: u64 = 60;

/// The minter's process state: the client it reaches the SFU's room API
/// with, and the servers recently found unreachable when asked about an
/// `OpenID` token.
pub struct Minter {
    sfu_api: reqwest::Client,
    unreachable: Mutex<HashMap<String, Instant>>,
}

impl Minter {
    #[must_use]
    pub fn new() -> Arc<Self> {
        // No redirects: the room API answers where it is configured, and a
        // redirect would carry the admin token somewhere else.
        let sfu_api = reqwest::Client::builder()
            .timeout(SFU_API_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Arc::new(Self {
            sfu_api,
            unreachable: Mutex::default(),
        })
    }

    fn recently_unreachable(&self, server: &str) -> bool {
        let now = Instant::now();
        let mut unreachable = self
            .unreachable
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        unreachable.retain(|_, until| *until > now);
        unreachable.contains_key(server)
    }

    fn mark_unreachable(&self, server: &str) {
        let mut unreachable = self
            .unreachable
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if unreachable.len() < MAX_UNREACHABLE {
            unreachable.insert(server.to_owned(), Instant::now() + UNREACHABLE_FOR);
        }
    }

    /// Create `alias` on the SFU through its room API, as `lk-jwt-service`
    /// does for a full-access user: `CreateRoom` answers with the existing
    /// room when there is one, so this is safe to repeat on every mint.
    /// The timeouts are the external service's -- five minutes for a room
    /// nobody joined, twenty seconds after the last participant leaves.
    async fn create_room(&self, livekit: &LivekitConfig, alias: &str) -> Result<(), MatrixError> {
        let url = format!(
            "{}/twirp/livekit.RoomService/CreateRoom",
            api_base(&livekit.url)
        );
        let body = json!({
            "name": alias,
            "empty_timeout": 300,
            "departure_timeout": 20,
            "max_participants": 0,
        });
        let outcome = self
            .sfu_api
            .post(&url)
            .bearer_auth(room_admin_token(livekit, alias, now_secs()))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await;
        match outcome {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => {
                tracing::warn!(status = %response.status(), "the SFU refused to create a call's room");
                Err(MatrixError::internal(
                    "unable to create the room on the SFU",
                ))
            }
            Err(error) => {
                tracing::warn!("the SFU's room API could not be reached: {error}");
                Err(MatrixError::internal(
                    "unable to create the room on the SFU",
                ))
            }
        }
    }
}

/// The SFU's HTTP API under its websocket address, the way `LiveKit`'s own
/// SDKs derive it: same host and path, `ws` to `http`, `wss` to `https`.
fn api_base(url: &str) -> String {
    let base = if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        url.to_owned()
    };
    base.trim_end_matches('/').to_owned()
}

/// `lk-jwt-service`'s hash of a list of strings: SHA-256 over their JSON
/// array, in unpadded standard base64. Room names and Matrix 2.0
/// identities are this, so they agree with the external service's and with
/// the identity a client computes for itself.
fn lk_hash(parts: &[&str]) -> String {
    let marshalled = serde_json::to_vec(parts).unwrap_or_default();
    crate::signing::base64_unpadded(&sha2::Sha256::digest(&marshalled))
}

/// The `LiveKit` room a Matrix room's call slot is held in.
#[must_use]
pub fn room_alias(room_id: &str, slot_id: &str) -> String {
    lk_hash(&[room_id, slot_id])
}

/// A participant's `LiveKit` identity. With a `MatrixRTC` member ID it is
/// the Matrix 2.0 hash; without one, the legacy `{user}:{device}` that
/// pre-2.0 clients match participants by.
fn identity_for(user_id: &str, device_id: &str, member_id: &str) -> String {
    if member_id.is_empty() {
        format!("{user_id}:{device_id}")
    } else {
        lk_hash(&[user_id, device_id, member_id])
    }
}

/// Read a JSON body off a request the router already matched, after a
/// claimed-prefix check handed it back.
async fn read_json<T>(body: Body) -> Result<T, MatrixError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| MatrixError::bad_json("the body is not JSON"))?;
    serde_json::from_slice(&bytes).map_err(|_| MatrixError::bad_json("the body is not JSON"))
}

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
    // `public_base_url` is often written with a trailing slash, and a
    // doubled one in the advertised URL is a different path to a proxy.
    config.rtc.livekit.as_ref().map(|_| {
        format!(
            "{}{SERVICE_PATH}",
            config.client_base_url().trim_end_matches('/')
        )
    })
}

/// The switch, read.
///
/// `Some(true)` / `Some(false)` is an operator's stored `on` / `off`;
/// `None` is "never switched", and the config decides. Reading never
/// fails open or closed: a store error is reported, not guessed.
///
/// # Errors
///
/// The store's error, as text, when the switch row cannot be read.
pub fn stored_switch(store: &FjallStore) -> Result<Option<bool>, String> {
    match store.get(SFU_SWITCH_KEY) {
        Ok(Some(value)) => Ok(Some(value.first().is_some_and(|byte| *byte == b'1'))),
        Ok(None) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// Write the switch. The only writer besides its mirror in `main.rs`'s
/// `spindle sfu` command; both write the store, never the config file.
///
/// # Errors
///
/// The store's error, as text, when the switch row cannot be written.
pub fn set_switch(store: &FjallStore, enabled: bool) -> Result<(), String> {
    store
        .put(SFU_SWITCH_KEY, if enabled { b"1" } else { b"0" })
        .map_err(|error| error.to_string())
}

/// Whether the SFU program is on: the stored switch when the operator has
/// ever flipped it, otherwise whether `[rtc.livekit]` is configured at
/// all. Both models answer through this one gate, so off costs nothing —
/// no process, no advertisement, and every minter path answers the same
/// `M_UNRECOGNIZED` an unconfigured server gives.
pub fn effective_enabled(config: &crate::Config, store: &FjallStore) -> bool {
    stored_switch(store)
        .unwrap_or(None)
        .unwrap_or_else(|| config.rtc.livekit.is_some())
}

/// Which model the configuration asks for, if the program is configured
/// at all. See [`LivekitConfig::model`].
pub fn model(config: &crate::Config) -> Option<&'static str> {
    config.rtc.livekit.as_ref().map(LivekitConfig::model)
}

/// Refuse an SFU path when the program is off or unconfigured, in the one
/// shape both states share: 404 `M_UNRECOGNIZED`, the absent endpoint's
/// answer, not a refusal that implies a service is listening.
fn program_off() -> MatrixError {
    MatrixError::new(
        axum::http::StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "the LiveKit SFU program is not enabled on this server",
    )
}

/// The service's routes.
///
/// Mounted always, and answering `M_UNRECOGNIZED` wherever the program is
/// off or unconfigured: a deployment that runs `lk-jwt-service` beside
/// this server has not asked for a second minter, and the honest answer to
/// a client that finds these paths anyway is the one an absent endpoint
/// gives, not a refusal that implies a service.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_spindle/rtc/livekit/sfu/get", post(sfu_get))
        .route("/_spindle/rtc/livekit/get_token", post(service_get_token))
        .route("/_spindle/rtc/livekit/sfu/webhook", post(sfu_webhook))
        .route(
            "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token",
            post(get_token),
        )
        .route("/_matrix/client/v3/rtc/livekit/get_token", post(get_token))
        .route(
            "/_matrix/federation/unstable/io.element.msc4195/rtc/livekit/get_token",
            post(federation_get_token),
        )
        .route(
            "/_matrix/federation/v1/rtc/livekit/get_token",
            post(federation_get_token),
        )
        .route(
            "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave",
            post(delegate_delayed_leave),
        )
        .route(
            "/_matrix/client/v3/rtc/livekit/delegate_delayed_leave",
            post(delegate_delayed_leave),
        )
}

/// The body Element Call sends `lk-jwt-service`'s legacy `sfu/get`, field
/// for field.
#[derive(Debug, Deserialize)]
struct SfuRequest {
    /// The Matrix room ID, which is what makes the membership check below
    /// possible at all. The `LiveKit` room is derived from it.
    room: String,
    openid_token: OpenIdToken,
    #[serde(default)]
    device_id: String,
    /// Delegation of the delayed leave to the transport: held for this
    /// server's users, see [`check_transport_delegation`].
    #[serde(default)]
    delay_id: String,
}

/// The `OpenID` token as `/openid/request_token` handed it out, passed
/// through unchanged. Only two of its four fields matter here.
#[derive(Debug, Deserialize)]
struct OpenIdToken {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    matrix_server_name: String,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// A `MatrixRTC` member as the Matrix 2.0 endpoints describe it.
#[derive(Debug, Default, Deserialize)]
struct Member {
    #[serde(default)]
    id: String,
    #[serde(default)]
    claimed_user_id: String,
    #[serde(default)]
    claimed_device_id: String,
}

/// The body Element Call sends `lk-jwt-service`'s Matrix 2.0 `get_token`
/// (`{livekit_service_url}/get_token`), field for field.
#[derive(Debug, Deserialize)]
struct ServiceTokenRequest {
    #[serde(default)]
    room_id: String,
    #[serde(default)]
    slot_id: String,
    openid_token: OpenIdToken,
    #[serde(default)]
    member: Member,
    #[serde(default)]
    delay_id: String,
}

/// What one minted token admits, and to which room.
struct Grant<'a> {
    user_id: &'a str,
    /// The Matrix room, checked for membership.
    room_id: &'a str,
    /// The `LiveKit` room the token is for.
    alias: String,
    identity: String,
    /// Full access: publish, and create the room on the SFU. Without it,
    /// join and subscribe only.
    full_access: bool,
}

/// `POST /_spindle/rtc/livekit/sfu/get`
///
/// Unauthenticated in the Matrix sense -- the `OpenID` token in the body is
/// the credential, exactly as it is for the external service -- and
/// answered in the external service's shape: `{"url": ..., "jwt": ...}`.
/// The identity is the legacy `{user}:{device}`.
async fn sfu_get(
    State(state): State<AppState>,
    Json(request): Json<SfuRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(livekit) = state.config.rtc.livekit.as_ref() else {
        return Err(program_off());
    };
    if !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    if request.room.is_empty() {
        return Err(MatrixError::missing_param("room"));
    }
    if request.device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    let user_id = openid_user(&state, &request.openid_token).await?;
    check_transport_delegation(&state, &user_id, &request.delay_id)?;
    let grant = Grant {
        user_id: &user_id,
        room_id: &request.room,
        alias: room_alias(&request.room, CALL_SLOT),
        identity: identity_for(&user_id, &request.device_id, ""),
        full_access: full_access(&state, livekit, &user_id),
    };
    let jwt = mint_for(&state, livekit, &grant).await?;
    if !request.delay_id.is_empty() {
        hold(&state, &grant, &request.device_id, &request.delay_id)?;
    }
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// `POST /_spindle/rtc/livekit/get_token`: the Matrix 2.0 twin of
/// `sfu/get`, which Element Call asks first (and, publishing in Matrix 2.0
/// mode, only). The identity is the hash of user, device and member ID
/// that the client computes for itself; the member's claimed user must be
/// the one the `OpenID` token names.
async fn service_get_token(
    State(state): State<AppState>,
    Json(request): Json<ServiceTokenRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(livekit) = state.config.rtc.livekit.as_ref() else {
        return Err(program_off());
    };
    if !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    if request.room_id.is_empty() || request.slot_id.is_empty() {
        return Err(MatrixError::bad_json(
            "the request body is missing `room_id` or `slot_id`",
        ));
    }
    if request.member.id.is_empty()
        || request.member.claimed_user_id.is_empty()
        || request.member.claimed_device_id.is_empty()
    {
        return Err(MatrixError::bad_json(
            "the request body's `member` is missing `id`, `claimed_user_id` or `claimed_device_id`",
        ));
    }
    let user_id = openid_user(&state, &request.openid_token).await?;
    if user_id != request.member.claimed_user_id {
        return Err(unconfirmed());
    }
    check_transport_delegation(&state, &user_id, &request.delay_id)?;
    let grant = Grant {
        user_id: &user_id,
        room_id: &request.room_id,
        alias: room_alias(&request.room_id, &request.slot_id),
        identity: identity_for(
            &user_id,
            &request.member.claimed_device_id,
            &request.member.id,
        ),
        full_access: full_access(&state, livekit, &user_id),
    };
    let jwt = mint_for(&state, livekit, &grant).await?;
    if !request.delay_id.is_empty() {
        hold(
            &state,
            &grant,
            &request.member.claimed_device_id,
            &request.delay_id,
        )?;
    }
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// A token request that also hands the transport the caller's delayed
/// leave (`delay_id`), as Element Call does once a delegation probe has
/// answered anything but 404: it then schedules an hour-long leave and
/// stops restarting it, and only the SFU webhook releasing the hold takes
/// a crashed participant out of the call. `lk-jwt-service` takes this from
/// full-access users; this server can only send its own users' delayed
/// events, so it takes it from them and refuses everyone else with the
/// external service's `M_BAD_JSON`, which clients answer by asking again
/// without the delay. A delay ID that is not the caller's is refused
/// rather than held, so nobody can arrange for someone else's leave.
fn check_transport_delegation(
    state: &AppState,
    user_id: &str,
    delay_id: &str,
) -> Result<(), MatrixError> {
    if delay_id.is_empty() {
        return Ok(());
    }
    if user_id.split_once(':').map(|(_, server)| server) != Some(state.config.server.name.as_str())
    {
        return Err(MatrixError::bad_json(
            "delegation of delayed events is only supported for this server's users",
        ));
    }
    if state.delayed.get(delay_id, user_id).is_err() {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "unknown `delay_id`",
        ));
    }
    Ok(())
}

/// The refusal for an `OpenID` token that could not be confirmed, in
/// `lk-jwt-service`'s words. One answer for every way it can fail -- an
/// unknown token, a server that does not answer, a server that names
/// someone else's user -- so a caller learns nothing about which.
fn unconfirmed() -> MatrixError {
    MatrixError::new(
        StatusCode::UNAUTHORIZED,
        "M_UNAUTHORIZED",
        "the request could not be authorised",
    )
}

/// Who an `OpenID` token belongs to.
///
/// This server's own tokens are redeemed here. Another server's are
/// confirmed by that server, over federation, the way `lk-jwt-service`
/// confirms every token: and the user it names must be one of its own,
/// because a server vouches for its users and nobody else's. The server
/// name comes from the request body, so it is held to the server-name
/// grammar here and to the federation client's address rules (no inward
/// addresses unless the operator allowed them) when it is asked; it is
/// counted against its own rate limit before it is asked at all, and a
/// server that could not be asked is not asked again for a while.
async fn openid_user(state: &AppState, token: &OpenIdToken) -> Result<String, MatrixError> {
    let server = token.matrix_server_name.as_str();
    if server == state.config.server.name {
        return match OpenId::new(Arc::clone(&state.store)).redeem(&token.access_token) {
            Ok(Some(user_id)) => Ok(user_id),
            Ok(None) => Err(MatrixError::unknown_token()),
            Err(error) => Err(MatrixError::internal(&error.to_string())),
        };
    }
    if token.access_token.is_empty() || ruma::ServerName::parse(server).is_err() {
        return Err(unconfirmed());
    }
    if let Err(retry) = state.limiter.check(
        &format!("livekit:server:{server}"),
        LIVEKIT_TOKEN_PER_REMOTE_SERVER,
    ) {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    if state.minter.recently_unreachable(server) {
        return Err(unconfirmed());
    }
    match state
        .federation
        .remote_openid_userinfo(server, &token.access_token)
        .await
    {
        Ok(sub) => ruma::UserId::parse(sub.as_str())
            .ok()
            .filter(|user_id| user_id.server_name().as_str() == server)
            .map(|user_id| user_id.to_string())
            .ok_or_else(unconfirmed),
        // The server answered, and the answer was no.
        Err(FederationError::Answered { .. }) => Err(unconfirmed()),
        Err(error) => {
            tracing::debug!(%server, "an OpenID token's server could not confirm it: {error}");
            state.minter.mark_unreachable(server);
            Err(unconfirmed())
        }
    }
}

/// Whether `user_id` may publish on this SFU: this server's users always,
/// another server's only when the operator listed that server.
fn full_access(state: &AppState, livekit: &LivekitConfig, user_id: &str) -> bool {
    let server = user_id.split_once(':').map_or("", |(_, server)| server);
    server == state.config.server.name
        || livekit
            .full_access_servers
            .iter()
            .any(|listed| listed == server)
}

/// Rate-limit, membership-check and mint one token, and for a full-access
/// user make sure its room exists on the SFU.
///
/// Shared by every minter path — `sfu/get` and `get_token` on the service,
/// MSC4195's `get_token` on both APIs, and the federation twin — so a
/// token minted for the supervised sidecar and one minted for the remote
/// SFU carry the same checks and the same grants. The model changes where
/// the media runs; it never changes who may join it.
async fn mint_for(
    state: &AppState,
    livekit: &LivekitConfig,
    grant: &Grant<'_>,
) -> Result<String, MatrixError> {
    if let Err(retry) = state.limiter.check(
        &format!("livekit:user:{}", grant.user_id),
        LIVEKIT_TOKEN_PER_USER,
    ) {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    // Scoped to membership *now*, in this server's view of the room --
    // which is how a remote user is checked too: this server holds the
    // room exactly when one of its users is in it, and that is the only
    // call this SFU carries.
    let joined = state
        .rooms
        .is_joined(grant.user_id, grant.room_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !joined {
        return Err(MatrixError::forbidden("not a member of that room"));
    }
    let jwt = mint(livekit, grant, now_secs());
    if grant.full_access {
        state.minter.create_room(livekit, &grant.alias).await?;
    }
    Ok(jwt)
}

/// MSC4195's homeserver token endpoint (`lk-jwt-service` 0.7 shape):
/// `POST .../rtc/livekit/get_token` with `{room_id, slot_id?, member?,
/// device_id?}`.
///
/// Authenticated as the caller — unlike the legacy `sfu/get`, whose
/// credential is the `OpenID` token in the body — so `device_id` defaults
/// to the device that holds the access token when the client does not say.
/// A `member` ID makes the identity the Matrix 2.0 hash, as on the
/// service's `get_token`. Answers in the same `{url, jwt}` shape; a client
/// cannot tell this minter from the external service, local model or
/// remote.
#[derive(Debug, Deserialize)]
struct GetTokenRequest {
    #[serde(default)]
    room_id: String,
    #[serde(default)]
    room: String,
    #[serde(default)]
    slot_id: String,
    #[serde(default)]
    member: Member,
    #[serde(default)]
    device_id: String,
}

async fn get_token(State(state): State<AppState>, request: Request) -> Response {
    match crate::appservice_proxy::forward_claimed(&state, request).await {
        Err(response) => response,
        Ok(request) => get_token_builtin(&state, request).await.into_response(),
    }
}

async fn get_token_builtin(state: &AppState, request: Request) -> Result<Json<Value>, MatrixError> {
    // The gate runs before authentication: an unconfigured or
    // switched-off program answers the absent endpoint's 404 to every
    // caller, authenticated or not, and the probe test holds it there.
    let Some(livekit) = state.config.rtc.livekit.clone() else {
        return Err(program_off());
    };
    if !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    let (mut parts, body) = request.into_parts();
    let identity = crate::auth::Authenticated::from_request_parts(&mut parts, state)
        .await?
        .0;
    let request: GetTokenRequest = read_json(body).await?;
    let room = if request.room_id.is_empty() {
        request.room.clone()
    } else {
        request.room_id.clone()
    };
    if room.is_empty() {
        return Err(MatrixError::missing_param("room_id"));
    }
    let device_id = [
        &request.member.claimed_device_id,
        &request.device_id,
        &identity.device_id,
    ]
    .into_iter()
    .find(|device| !device.is_empty())
    .cloned()
    .unwrap_or_default();
    if device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    let slot = if request.slot_id.is_empty() {
        CALL_SLOT
    } else {
        request.slot_id.as_str()
    };
    let grant = Grant {
        user_id: &identity.user_id,
        room_id: &room,
        alias: room_alias(&room, slot),
        identity: identity_for(&identity.user_id, &device_id, &request.member.id),
        full_access: true,
    };
    let jwt = mint_for(state, &livekit, &grant).await?;
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// MSC4195's federation twin: a remote participant's token, minted here so
/// a federated caller needs no `lk-jwt-service` of their own.
///
/// The origin is authenticated by its X-Matrix signature, and the named
/// user must belong to that origin and be joined to the room *now* — the
/// same membership check local minting makes, applied to whoever the peer
/// server vouches for. The token is a remote user's like any other: it
/// publishes, and creates the room on the SFU, only when the origin is in
/// `full_access_servers`. Counted against the origin's remote-minting
/// limit.
#[derive(Debug, Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "the wire shape is room_id/user_id/device_id"
)]
struct FederationTokenRequest {
    #[serde(default)]
    room_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    slot_id: String,
    #[serde(default)]
    member: Member,
}

async fn federation_get_token(State(state): State<AppState>, request: Request) -> Response {
    match crate::appservice_proxy::forward_claimed(&state, request).await {
        Err(response) => response,
        Ok(request) => federation_get_token_builtin(&state, request)
            .await
            .into_response(),
    }
}

async fn federation_get_token_builtin(
    state: &AppState,
    request: Request,
) -> Result<Json<Value>, MatrixError> {
    // The gate runs before authentication, as on the client paths: off
    // or unconfigured answers 404 to every caller.
    let Some(livekit) = state.config.rtc.livekit.clone() else {
        return Err(program_off());
    };
    if !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| MatrixError::bad_json("the body is not JSON"))?;
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| MatrixError::bad_json("the body is not JSON"))?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    let origin = crate::inbound::federation_origin(
        state,
        &parts.headers,
        parts.method.as_str(),
        &path_and_query,
        Some(&body),
    )
    .await?;
    let request: FederationTokenRequest =
        serde_json::from_value(body).map_err(|_| MatrixError::bad_json("the body is not JSON"))?;
    if request.room_id.is_empty() {
        return Err(MatrixError::missing_param("room_id"));
    }
    if request.user_id.is_empty() {
        return Err(MatrixError::missing_param("user_id"));
    }
    let device_id = if request.device_id.is_empty() {
        request.member.claimed_device_id.clone()
    } else {
        request.device_id.clone()
    };
    if device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    let origin_suffix = format!(":{origin}");
    if !request.user_id.ends_with(origin_suffix.as_str()) {
        return Err(MatrixError::forbidden(
            "a server vouches for its own users only",
        ));
    }
    if let Err(retry) = state.limiter.check(
        &format!("livekit:server:{origin}"),
        LIVEKIT_TOKEN_PER_REMOTE_SERVER,
    ) {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    let slot = if request.slot_id.is_empty() {
        CALL_SLOT
    } else {
        request.slot_id.as_str()
    };
    let grant = Grant {
        user_id: &request.user_id,
        room_id: &request.room_id,
        alias: room_alias(&request.room_id, slot),
        identity: identity_for(&request.user_id, &device_id, &request.member.id),
        full_access: full_access(state, &livekit, &request.user_id),
    };
    let jwt = mint_for(state, &livekit, &grant).await?;
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// Element Call's delegation probe, answered by this server itself:
/// `POST .../rtc/livekit/delegate_delayed_leave`.
///
/// Anything but a 404 tells Element Call the homeserver holds the
/// participant's delayed leave — an hour-long leave it stops restarting —
/// so this answers 404 exactly when the program cannot hold it (off or
/// unconfigured), and records the hold otherwise. The hold is consumed by
/// the SFU webhook when the participant drops off the media; without SFU
/// events there is nothing to learn the drop from, which is why the
/// supervised sidecar points its webhooks here on generation.
#[derive(Debug, Deserialize)]
struct DelegateRequest {
    #[serde(default)]
    room_id: String,
    #[serde(default)]
    room: String,
    #[serde(default)]
    delay_id: String,
    /// The `MatrixRTC` member, as the Matrix 2.0 request names it: with
    /// it, the hold records the participant's hashed `LiveKit` identity,
    /// which is all the SFU webhook will say about them.
    #[serde(default)]
    member: Member,
}

async fn delegate_delayed_leave(State(state): State<AppState>, request: Request) -> Response {
    match crate::appservice_proxy::forward_claimed(&state, request).await {
        Err(response) => response,
        Ok(request) => delegate_delayed_leave_builtin(&state, request)
            .await
            .into_response(),
    }
}

async fn delegate_delayed_leave_builtin(
    state: &AppState,
    request: Request,
) -> Result<Json<Value>, MatrixError> {
    // The gate runs before authentication: the probe's whole contract is
    // that an unheld leave reads as 404, to callers with no token most of
    // all — Element Call probes before it decides the leave length.
    if state.config.rtc.livekit.is_none() || !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    let (mut parts, body) = request.into_parts();
    let identity = crate::auth::Authenticated::from_request_parts(&mut parts, state)
        .await?
        .0;
    let request: DelegateRequest = read_json(body).await?;
    if request.delay_id.is_empty() {
        return Err(MatrixError::missing_param("delay_id"));
    }
    let room = if request.room_id.is_empty() {
        request.room.clone()
    } else {
        request.room_id.clone()
    };
    let device_id = if request.member.claimed_device_id.is_empty() {
        identity.device_id.as_str()
    } else {
        request.member.claimed_device_id.as_str()
    };
    put_hold(
        state,
        &identity.user_id,
        device_id,
        &identity_for(&identity.user_id, device_id, &request.member.id),
        &room,
        &request.delay_id,
    )?;
    Ok(Json(json!({ "held": true })))
}

/// Record that the participant `grant` admits handed this server their
/// delayed leave on the token request.
fn hold(
    state: &AppState,
    grant: &Grant<'_>,
    device_id: &str,
    delay_id: &str,
) -> Result<(), MatrixError> {
    put_hold(
        state,
        grant.user_id,
        device_id,
        &grant.identity,
        grant.room_id,
        delay_id,
    )
}

/// One held delegated leave, keyed by its delay, for the SFU webhook to
/// find by the participant's `LiveKit` identity.
fn put_hold(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    identity: &str,
    room_id: &str,
    delay_id: &str,
) -> Result<(), MatrixError> {
    let record = json!({
        "user_id": user_id,
        "device_id": device_id,
        "identity": identity,
        "room_id": room_id,
        "delay_id": delay_id,
    });
    state
        .store
        .put(
            delegation_key(delay_id).as_slice(),
            serde_json::to_vec(&record)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .as_slice(),
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

/// The SFU webhook: `LiveKit`'s event sink, pointed at this path by the
/// generated sidecar config (and by the operator's hand on the remote
/// model). On a participant leaving the media, the held delegated leave —
/// if one names them — is sent at once, so a crashed client expires from
/// the call instead of lingering on its hour-long leave.
///
/// Authenticated the way `LiveKit` signs it: `Authorization` carries a JWT
/// signed with the API secret, issued by the API key, whose `sha256` claim
/// is the body's digest -- so only the SFU can send one, and a captured one
/// cannot carry a different body.
async fn sfu_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, MatrixError> {
    let Some(livekit) = state.config.rtc.livekit.clone() else {
        return Err(program_off());
    };
    if !effective_enabled(&state.config, &state.store) {
        return Err(program_off());
    }
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !webhook_signed(&livekit, presented, &body, now_secs()) {
        // Worth an operator's eye: an SFU whose webhook key or secret
        // does not match leaves every crashed participant in its call.
        tracing::warn!("refused an SFU webhook that the SFU's key did not sign");
        return Err(MatrixError::unknown_token());
    }
    let events: Value =
        serde_json::from_str(&body).map_err(|_| MatrixError::missing_param("event"))?;
    let mut released = 0_u64;
    for event in events
        .get("events")
        .and_then(Value::as_array)
        .map_or_else(|| vec![events.clone()], Clone::clone)
    {
        let name = event
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if name != "participant_left" {
            continue;
        }
        let identity = event
            .get("participant")
            .and_then(|participant| participant.get("identity"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        released += release_holds_for(&state, identity).await;
    }
    if released > 0 {
        tracing::info!(released, "the SFU webhook released held delayed leaves");
    }
    Ok(Json(json!({ "released": released })))
}

/// Send every held delegated leave the participant `identity` left behind,
/// and forget the holds. A hold matches when it recorded that identity --
/// the Matrix 2.0 hash, or `{user_id}:{device_id}` -- and, for the legacy
/// identity, when it names the same user: the user ID holds a colon
/// (`@local:server`), so the device comes off the end, and every hold of
/// that user is released, as before holds recorded an identity. A hold
/// whose delay is already gone (fired, cancelled, unknown) still clears:
/// holding nothing is not holding.
async fn release_holds_for(state: &AppState, identity: &str) -> u64 {
    if identity.is_empty() {
        return 0;
    }
    let legacy_user = identity.rsplit_once(':').map(|(user_id, _)| user_id);
    let holds = state
        .store
        .scan_prefix(DELEGATION_PREFIX.as_bytes())
        .unwrap_or_default();
    let mut released = 0_u64;
    for (key, value) in holds {
        let value: Value = match serde_json::from_slice(&value) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let recorded = value.get("identity").and_then(Value::as_str) == Some(identity);
        let same_user =
            legacy_user.is_some() && value.get("user_id").and_then(Value::as_str) == legacy_user;
        if !recorded && !same_user {
            continue;
        }
        // `Send` takes the delay off the schedule and hands the event back;
        // sending it is the caller's part, the same send the delayed-events
        // route makes. Dropping it would erase the leave instead of sending
        // it, and the participant would stay in the call for good.
        if let Some(delay_id) = value.get("delay_id").and_then(Value::as_str)
            && let Ok(Some(event)) = state
                .delayed
                .act_by_id(delay_id, crate::delayed::Action::Send)
            && let Err(error) = crate::delayed_routes::send_delayed_now(state, &event).await
        {
            tracing::warn!(%delay_id, errcode = error.errcode, "a released delayed leave was not sent: {}", error.error);
        }
        let _ = state.store.delete(&key);
        released += 1;
    }
    released
}

/// How many delegated leaves are currently held. Reported in status so an
/// operator can see the holding the webhook is meant to consume.
pub fn held_count(store: &FjallStore) -> u64 {
    store
        .scan_prefix(DELEGATION_PREFIX.as_bytes())
        .map(|holds| holds.len() as u64)
        .unwrap_or(0)
}

fn delegation_key(delay_id: &str) -> Vec<u8> {
    [DELEGATION_PREFIX.as_bytes(), delay_id.as_bytes()].concat()
}

/// Whether `authorization` is the SFU's signature over `body`: an HS256 JWT
/// under the API secret, issued by the API key, inside its window (give or
/// take [`WEBHOOK_CLOCK_SKEW_SECS`]), whose `sha256` claim is the body's
/// SHA-256 in standard base64 -- `LiveKit`'s webhook signing, which its
/// server SDKs verify the same way.
fn webhook_signed(livekit: &LivekitConfig, authorization: &str, body: &str, now: u64) -> bool {
    let token = authorization.trim();
    let token = token.strip_prefix("Bearer ").unwrap_or(token);
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(signature) = base64url_decode(signature) else {
        return false;
    };
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(livekit.secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(header.as_bytes());
    mac.update(b".");
    mac.update(claims.as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return false;
    }
    let Some(claims) =
        base64url_decode(claims).and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return false;
    };
    let within =
        |claim: &str, ok: fn(u64, u64) -> bool| claims[claim].as_u64().is_none_or(|at| ok(at, now));
    let digest = crate::signing::base64_unpadded(&sha2::Sha256::digest(body.as_bytes()));
    claims["iss"].as_str() == Some(livekit.key.as_str())
        && within("nbf", |nbf, now| nbf <= now + WEBHOOK_CLOCK_SKEW_SECS)
        && within("exp", |exp, now| exp + WEBHOOK_CLOCK_SKEW_SECS >= now)
        && claims["sha256"]
            .as_str()
            .is_some_and(|claimed| claimed.trim_end_matches('=') == digest)
}

/// Unpadded (or padded) base64url, read back; `None` for anything else.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for symbol in text.bytes() {
        let value = match symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'a'..=b'z' => symbol - b'a' + 26,
            b'0'..=b'9' => symbol - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A `LiveKit` access token: HS256 over the claims the SFU reads.
///
/// The grants are the least the participant needs: join this one room and
/// subscribe, and publish when they have full access. `roomCreate` is
/// withheld -- it would also permit deleting the room, which is a way to
/// end everyone's call -- and the room is created through the SFU's API
/// instead ([`Minter::create_room`]). `name` is the user ID, for the SFU's
/// own logs and dashboards.
///
/// `nbf` and `exp` bound the window on both sides; `exp - nbf` is exactly
/// `token_ttl_seconds`, and a test holds it there.
fn mint(livekit: &LivekitConfig, grant: &Grant<'_>, now_secs: u64) -> String {
    sign(
        livekit,
        &json!({
            "iss": livekit.key,
            "sub": grant.identity,
            "name": grant.user_id,
            "iat": now_secs,
            "nbf": now_secs,
            "exp": now_secs.saturating_add(livekit.token_ttl_seconds),
            "video": {
                "room": grant.alias,
                "roomJoin": true,
                "roomCreate": false,
                "canPublish": grant.full_access,
                "canSubscribe": true,
                "canUpdateOwnMetadata": true,
            },
        }),
    )
}

/// The token this server presents to the SFU's room API to create one
/// room: `roomCreate` for that room alone, for a minute.
fn room_admin_token(livekit: &LivekitConfig, alias: &str, now_secs: u64) -> String {
    sign(
        livekit,
        &json!({
            "iss": livekit.key,
            "nbf": now_secs,
            "exp": now_secs.saturating_add(60),
            "video": { "room": alias, "roomCreate": true },
        }),
    )
}

/// A compact HS256 JWT over `claims`, under `LiveKit`'s API secret.
fn sign(livekit: &LivekitConfig, claims: &Value) -> String {
    let header = json!({ "alg": "HS256", "typ": "JWT" });
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

/// The supervised sidecar: the local model's lifecycle.
///
/// The remote model never touches this: with no `binary` configured there
/// is no child to watch, and every method below reports the absence rather
/// than acting. The local model keeps one child — the operator's
/// `livekit-server` at the configured path — alive across crashes: the
/// config is (re)generated before every start, an exited child is
/// restarted on the next tick, and switching the program off stops the
/// child so the cost is zero.
///
/// Upgrades are deliberately out of band: the operator replaces the binary
/// and restarts this server (or flips the switch off and on), and the new
/// child is whatever they installed. This server never fetches, verifies
/// or rewrites the binary, and never rewrites the operator's own files —
/// the only file it writes is the generated sidecar config.
///
/// A status read doubles as the supervision tick: it reaps an exited child
/// and starts a missing one, so a crash is recovered on the next
/// observation rather than waiting for a restart.
pub struct SfuSupervisor {
    inner: std::sync::Mutex<SupervisedChild>,
    config: crate::Config,
    store: Arc<FjallStore>,
}

#[derive(Default)]
struct SupervisedChild {
    child: Option<std::process::Child>,
    pid: Option<u32>,
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        // Never leave a supervised child behind: the supervisor owns the
        // process it manages, and dropping the supervisor (a restart, a
        // test teardown) ends it rather than orphaning it.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }
}

impl SfuSupervisor {
    /// Capture the configuration and the store. Starts the sidecar when
    /// one is wanted; anywhere the start cannot happen (a missing binary,
    /// an unwritable config) the first status read retries.
    pub fn new(config: crate::Config, store: Arc<FjallStore>) -> Arc<Self> {
        let supervisor = Arc::new(Self {
            inner: std::sync::Mutex::new(SupervisedChild::default()),
            config,
            store,
        });
        supervisor.tick();
        supervisor
    }

    /// The supervision tick: reap an exited child, start a missing one.
    /// Best-effort throughout — a supervisor that throws is worse than one
    /// that reports `running: false` and the reason beside it.
    pub fn tick(&self) {
        if !self.wanted() {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner
            .child
            .as_mut()
            .is_some_and(|child| child.try_wait().ok().flatten().is_some())
        {
            inner.child = None;
            inner.pid = None;
        } else if inner.child.is_some() {
            return;
        }
        let Some(binary) = self.binary() else {
            return;
        };
        if !std::path::Path::new(&binary).exists() {
            return;
        }
        let config_path = self.config_path();
        if self.write_config().is_err() {
            return;
        }
        let spawn = std::process::Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(child) = spawn {
            inner.pid = Some(child.id());
            inner.child = Some(child);
        }
    }

    /// Stop the child, if one runs. The switch-off path calls this so off
    /// means no process; a start is then one tick away when switched on.
    pub fn stop(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(child) = inner.child.as_mut() {
            let _ = child.kill();
        }
        inner.child = None;
        inner.pid = None;
    }

    /// Whether a child is wanted right now: the local model, switched on.
    fn wanted(&self) -> bool {
        self.config
            .rtc
            .livekit
            .as_ref()
            .is_some_and(|livekit| livekit.binary.is_some())
            && effective_enabled(&self.config, &self.store)
    }

    fn binary(&self) -> Option<String> {
        self.config
            .rtc
            .livekit
            .as_ref()
            .and_then(|livekit| livekit.binary.clone())
    }

    /// Where the generated sidecar config lives: the operator's path when
    /// set, `<storage.path>/livekit.yaml` otherwise. Never the operator's
    /// server config; never the binary.
    pub fn config_path(&self) -> PathBuf {
        generated_config_path(&self.config)
    }

    /// (Re)generate the sidecar config the child boots from.
    ///
    /// The only file supervision writes. Keys come from `[rtc.livekit]`
    /// — the same pair the tokens are signed with — rooms self-create on
    /// first join, and webhooks point at this server's receiver so held
    /// delegated leaves release when participants drop.
    ///
    /// # Errors
    ///
    /// When the program is unconfigured, or the generated file cannot be
    /// written — both as text, naming the path.
    pub fn generate_config(&self) -> Result<PathBuf, String> {
        Self::generate_config_for(&self.config)
    }

    /// [`Self::generate_config`] without a supervisor: what `spindle sfu
    /// on` runs, so enabling refreshes the generated file without starting
    /// a child that would die with the command.
    ///
    /// # Errors
    ///
    /// As [`Self::generate_config`].
    pub fn generate_config_for(config: &crate::Config) -> Result<PathBuf, String> {
        let (path, rendered) = render_config(config)?;
        write_rendered(&path, rendered)?;
        Ok(path)
    }

    fn write_config(&self) -> Result<(), String> {
        let (path, rendered) = render_config(&self.config)?;
        write_rendered(&path, rendered)
    }

    /// The supervised half of status: wanted, running, whose binary, which
    /// pin, and where the generated config went. The tick runs first, so a
    /// crashed child already shows as down rather than stale-up.
    pub fn supervised_status(&self) -> Value {
        self.tick();
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let livekit = self.config.rtc.livekit.clone();
        match livekit {
            None => json!({
                "model": Value::Null,
                "wanted": false,
                "running": false,
                "health": "unconfigured",
            }),
            Some(livekit) => {
                let Some(binary) = livekit.binary.clone() else {
                    return json!({
                        "model": "remote",
                        "wanted": false,
                        "running": false,
                        "health": "remote",
                        "sfu_url": livekit.url,
                    });
                };
                let exists = std::path::Path::new(&binary).exists();
                let (running, health) = if !effective_enabled(&self.config, &self.store) {
                    (false, "disabled")
                } else if inner.child.is_some() {
                    (true, "running")
                } else if !exists {
                    (false, "missing-binary")
                } else {
                    (false, "stopped")
                };
                json!({
                    "model": "local",
                    "wanted": self.wanted(),
                    "running": running,
                    "health": health,
                    "pid": inner.pid,
                    "binary": binary,
                    "version_pin": LIVEKIT_SERVER_PIN,
                    "config_path": self.config_path().display().to_string(),
                    "sfu_url": livekit.url,
                })
            }
        }
    }
}

/// Render the generated sidecar config: its path and its bytes. The one
/// template both the supervisor and `spindle sfu on` write from, so the
/// running child and the refreshed file can never disagree.
/// Where the generated sidecar config goes, before it exists.
pub fn generated_config_path(config: &crate::Config) -> PathBuf {
    config
        .rtc
        .livekit
        .as_ref()
        .and_then(|livekit| livekit.sidecar_config_path.clone())
        .map_or_else(|| config.storage.path.join("livekit.yaml"), PathBuf::from)
}

fn render_config(config: &crate::Config) -> Result<(PathBuf, String), String> {
    let Some(livekit) = config.rtc.livekit.clone() else {
        return Err("the LiveKit SFU program is not configured".to_owned());
    };
    let path = generated_config_path(config);
    let webhook_url = format!(
        "{}/_spindle/rtc/livekit/sfu/webhook",
        config.client_base_url().trim_end_matches('/')
    );
    // Rooms are made by the minter, for this server's users (and listed
    // servers'), through the room API; a participant's join never makes
    // one, so a subscribe-only remote user cannot open a room here.
    let rendered = format!(
        "# Generated by spindle for livekit-server {LIVEKIT_SERVER_PIN}.\n\
         # Do not edit: the supervisor rewrites this file on every start.\n\
         # Upgrade the binary, not this file; operator settings live in\n\
         # the spindle config, not here.\n\
         port: 7880\n\
         bind_addresses:\n  - \"127.0.0.1\"\n\
         keys:\n  {}: {}\n\
         room:\n  auto_create: false\n\
         webhook:\n  urls:\n    - \"{}\"\n  api_key: {}\n",
        livekit.key, livekit.secret, webhook_url, livekit.key,
    );
    Ok((path, rendered))
}

/// Write rendered sidecar bytes, making the parent directory. The
/// generated path only — never an operator file.
fn write_rendered(path: &PathBuf, rendered: String) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    std::fs::write(path, rendered)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(())
}

/// The whole program in one document: the switch, the model, the minter's
/// address, the supervised child's health, and the held delegated leaves.
/// Served by the admin API and the `spindle sfu status` command from this
/// same function, so the two can never disagree about what "status" says.
pub fn status_json(config: &crate::Config, store: &FjallStore, sfu: &SfuSupervisor) -> Value {
    let enabled = effective_enabled(config, store);
    json!({
        "enabled": enabled,
        "configured": config.rtc.livekit.is_some(),
        "model": model(config),
        "switch": stored_switch(store).unwrap_or(None),
        "sfu_url": config.rtc.livekit.as_ref().map(|livekit| livekit.url.clone()),
        "token_ttl_seconds": config.rtc.livekit.as_ref().map(|livekit| livekit.token_ttl_seconds),
        "version_pin": LIVEKIT_SERVER_PIN,
        "supervised": sfu.supervised_status(),
        "held_delegations": held_count(store),
    })
}

/// The version a sidecar binary reports for itself: `livekit-server
/// --version` on stdout, first line. `None` when it cannot be asked —
/// missing, unstartable, silent — which is itself the status. Off the
/// async workers: asking means spawning and waiting on a process.
pub async fn sidecar_version(binary: &str) -> Option<String> {
    let binary = binary.to_owned();
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new(&binary)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout)
            .ok()?
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
    })
    .await
    .ok()?
}
