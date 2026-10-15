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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{FromRequestParts as _, Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use hmac::{KeyInit as _, Mac as _};
use serde::Deserialize;
use serde_json::{Value, json};
use spindle_store::{FjallStore, ReadView as _, Store as _};

use crate::AppState;
use crate::config::LivekitConfig;
use crate::errors::MatrixError;
use crate::oidc::base64url_unpadded;
use crate::openid::OpenId;
use crate::ratelimit::LIVEKIT_TOKEN_PER_USER;

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
    config
        .rtc
        .livekit
        .as_ref()
        .map(|_| format!("{}{SERVICE_PATH}", config.client_base_url()))
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
    let jwt = mint_for(&state, livekit, &user_id, &request.device_id, &request.room)?;
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// Rate-limit, membership-check and mint one token.
///
/// Shared by every minter path — the legacy `sfu/get`, MSC4195's
/// `get_token` on both APIs, and the federation twin — so a token minted
/// for the supervised sidecar and one minted for the remote SFU carry the
/// same checks and the same grants. The model changes where the media
/// runs; it never changes who may join it.
fn mint_for(
    state: &AppState,
    livekit: &LivekitConfig,
    user_id: &str,
    device_id: &str,
    room: &str,
) -> Result<String, MatrixError> {
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
        .is_joined(user_id, room)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !joined {
        return Err(MatrixError::forbidden("not a member of that room"));
    }
    Ok(mint(livekit, user_id, device_id, room, now_secs()))
}

/// MSC4195's homeserver token endpoint (`lk-jwt-service` 0.7 shape):
/// `POST .../rtc/livekit/get_token` with `{room_id, device_id?}`.
///
/// Authenticated as the caller — unlike the legacy `sfu/get`, whose
/// credential is the `OpenID` token in the body — so `device_id` defaults
/// to the device that holds the access token when the client does not say.
/// Answers in the same `{url, jwt}` shape; a client cannot tell this minter
/// from the external service, local model or remote.
#[derive(Debug, Deserialize)]
struct GetTokenRequest {
    #[serde(default)]
    room_id: String,
    #[serde(default)]
    room: String,
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
    let device_id = if request.device_id.is_empty() {
        identity.device_id.clone()
    } else {
        request.device_id.clone()
    };
    if device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    let jwt = mint_for(state, &livekit, &identity.user_id, &device_id, &room)?;
    Ok(Json(json!({ "url": livekit.url, "jwt": jwt })))
}

/// MSC4195's federation twin: a remote participant's token, minted here so
/// a federated caller needs no `lk-jwt-service` of their own.
///
/// The origin is authenticated by its X-Matrix signature, and the named
/// user must belong to that origin and be joined to the room *now* — the
/// same membership check local minting makes, applied to whoever the peer
/// server vouches for.
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
    if request.device_id.is_empty() {
        return Err(MatrixError::missing_param("device_id"));
    }
    let origin_suffix = format!(":{origin}");
    if !request.user_id.ends_with(origin_suffix.as_str()) {
        return Err(MatrixError::forbidden(
            "a server vouches for its own users only",
        ));
    }
    let jwt = mint_for(
        state,
        &livekit,
        &request.user_id,
        &request.device_id,
        &request.room_id,
    )?;
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
    let record = json!({
        "user_id": identity.user_id,
        "device_id": identity.device_id,
        "room_id": room,
        "delay_id": request.delay_id,
    });
    state
        .store
        .put(
            delegation_key(&request.delay_id).as_slice(),
            serde_json::to_vec(&record)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .as_slice(),
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "held": true })))
}

/// The SFU webhook: `LiveKit`'s event sink, pointed at this path by the
/// generated sidecar config (and by the operator's hand on the remote
/// model). On a participant leaving the media, the held delegated leave —
/// if one names them — is sent at once, so a crashed client expires from
/// the call instead of lingering on its hour-long leave.
///
/// Authenticated by the API key: `LiveKit` signs nothing here, but it
/// presents the key in `Authorization`, and only the SFU holds it.
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
        .unwrap_or_default()
        .trim()
        .strip_prefix("Bearer ")
        .unwrap_or_else(|| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .trim()
        })
        .to_owned();
    if presented != livekit.key {
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
            .unwrap_or_default()
            .to_owned();
        // The minter's identity is `{user_id}:{device_id}`, and the user
        // ID itself holds a colon (`@local:server`), so the device comes
        // off the end, not the front.
        let Some((user_id, _)) = identity.rsplit_once(':') else {
            continue;
        };
        released += release_holds_for(&state, user_id);
    }
    Ok(Json(json!({ "released": released })))
}

/// Send every held delegated leave naming `user_id`, and forget the holds.
/// A hold whose delay is already gone (fired, cancelled, unknown) still
/// clears: holding nothing is not holding.
fn release_holds_for(state: &AppState, user_id: &str) -> u64 {
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
        if value.get("user_id").and_then(Value::as_str) != Some(user_id) {
            continue;
        }
        if let Some(delay_id) = value.get("delay_id").and_then(Value::as_str) {
            let _ = state
                .delayed
                .act_by_id(delay_id, crate::delayed::Action::Send);
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
        config.client_base_url()
    );
    let rendered = format!(
        "# Generated by spindle for livekit-server {LIVEKIT_SERVER_PIN}.\n\
         # Do not edit: the supervisor rewrites this file on every start.\n\
         # Upgrade the binary, not this file; operator settings live in\n\
         # the spindle config, not here.\n\
         port: 7880\n\
         bind_addresses:\n  - \"127.0.0.1\"\n\
         keys:\n  {}: {}\n\
         room:\n  auto_create: true\n\
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
