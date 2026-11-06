//! The route table, and the router built from it.
//!
//! One table, so [`surface`](crate::surface)'s claims can be checked against
//! what is actually mounted rather than against a second list that agrees with
//! the first only until someone edits one of them.

use crate::AppState;
use crate::accounts::{AccountError, Accounts};
use crate::errors::MatrixError;
use axum::extract::ConnectInfo;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// Every path this server answers.
///
/// Exposed so a test can compare it against [`surface::required_routes`].
pub const MOUNTED: &[&str] = &[
    "/_matrix/client/versions",
    "/_matrix/client/v3/capabilities",
    "/_matrix/client/v3/register",
    "/_matrix/client/v3/login",
    "/_matrix/client/v3/logout",
    "/_matrix/client/v3/refresh",
    "/_matrix/client/v3/account/whoami",
    "/_matrix/client/v3/createRoom",
    "/_matrix/client/v3/joined_rooms",
    "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
    "/_matrix/client/v3/rooms/{room_id}/messages",
    "/_matrix/client/v3/rooms/{room_id}/invite",
    "/_matrix/client/v3/rooms/{room_id}/join",
    "/_matrix/client/v3/rooms/{room_id}/leave",
    "/_matrix/client/v3/join/{room_id_or_alias}",
    "/_matrix/client/v3/knock/{room_id_or_alias}",
    "/_matrix/client/v3/sync",
    "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
    "/_matrix/client/v3/rooms/{room_id}/read_markers",
    "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
    "/_matrix/client/v1/rooms/{room_id}/threads",
    "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
    "/_matrix/client/v3/voip/turnServer",
    "/_matrix/client/v3/user/{user_id}/openid/request_token",
    "/_matrix/federation/v1/openid/userinfo",
    "/_spindle/rtc/livekit/sfu/get",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}",
    "/_matrix/client/unstable/org.matrix.msc4140/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
    "/_matrix/client/v3/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
    "/_matrix/client/v1/delayed_events/{delay_id}",
    "/_matrix/client/v1/delayed_events/{delay_id}/{action}",
    "/_matrix/client/v3/rooms/{room_id}/state",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
    "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
    "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
    "/_matrix/key/v2/server",
    "/_matrix/key/v2/query",
    "/_matrix/key/v2/query/{server_name}",
    "/_matrix/media/v1/create",
    "/_matrix/media/v3/upload/{server_name}/{media_id}",
    "/_matrix/client/v1/login/get_token",
    "/_matrix/client/v1/mutual_rooms",
    "/_matrix/federation/v1/media/thumbnail/{media_id}",
    "/_matrix/federation/v1/event_auth/{room_id}/{event_id}",
    "/_matrix/federation/v1/publicRooms",
    "/_matrix/federation/v1/hierarchy/{room_id}",
    "/_matrix/federation/v1/timestamp_to_event/{room_id}",
    "/_matrix/client/v1/register/m.login.registration_token/validity",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/health",
    "/ready",
];

/// The server's routes.
///
/// Split by what a route is *about* rather than by spec section, because the
/// spec's own grouping cuts across the same path prefixes: `/rooms/{id}/...`
/// holds membership, timeline and state alike. Each domain's builder lives
/// in the `*_routes` module that holds its handlers, so this function only
/// assembles them.
pub fn router(state: AppState) -> Router {
    let routes = Router::new()
        .merge(crate::account_routes::routes())
        .merge(crate::room_routes::routes())
        .merge(crate::keys_routes::routes())
        .merge(crate::sync_routes::routes())
        .merge(crate::account_data_routes::routes())
        .merge(crate::moderation_routes::routes())
        .merge(crate::profile_routes::routes())
        .merge(crate::push_routes::routes())
        .merge(crate::appservice_routes::routes())
        .merge(crate::dehydrated::routes())
        .merge(crate::device_routes::routes())
        .merge(crate::presence_routes::routes())
        .merge(crate::directory_routes::routes())
        .merge(crate::timeline_routes::routes())
        .merge(crate::voip_routes::routes())
        .merge(crate::delayed_routes::routes())
        .merge(crate::media_routes::routes(state.media.max_upload_bytes()))
        .merge(crate::discovery_routes::routes())
        .merge(crate::federation_routes::routes())
        .merge(crate::mas::routes())
        .merge(crate::admin::routes())
        .merge(crate::admin_tasks::routes())
        .merge(crate::admin_ui::routes())
        .merge(crate::admin_federation::routes())
        .merge(crate::admin_media::routes())
        .merge(crate::oidc::routes())
        .merge(crate::account::routes())
        .merge(crate::email::routes())
        .merge(crate::recovery::routes())
        .merge(crate::openid::routes())
        .merge(crate::rendezvous::routes())
        .merge(crate::livekit::routes())
        .merge(crate::appservice_proxy::routes());
    // MSC3995 hub mode (#22): mounted only in a build with the feature and
    // only with `[federation.hub] enabled`. Unmounted, its paths fall to
    // the fallback below like any path this server does not speak.
    #[cfg(feature = "hub-mode")]
    let routes = if state.config.federation.hub.enabled {
        routes.merge(crate::hub::routes())
    } else {
        routes
    };
    let routes = routes
        // SPEC: an endpoint the server does not recognize answers 404
        // M_UNRECOGNIZED — a JSON verdict, not a bare status. Clients (and
        // Complement's TestUnknownEndpoints) read the errcode to tell "this
        // server does not speak that" from "the thing was not found".
        // …unless an application service has claimed the path (MSC4512),
        // in which case it is forwarded there.
        .fallback(crate::appservice_proxy::proxy_or_unknown)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            federation_gate,
        ))
        .layer(axum::middleware::from_fn(cors))
        .layer(axum::middleware::from_fn_with_state(state.clone(), observe))
        .with_state(state);
    // The prefix rewrite has to run *before* routing, and a layer on a
    // router runs after it, so the router sits behind the rewrite as the
    // only service of an outer one.
    Router::new().fallback_service(tower::Layer::layer(
        &axum::middleware::map_request(legacy_prefix),
        routes,
    ))
}

/// Serve the `r0` client and media API prefixes as the `v3` ones.
///
/// `r0` is what every client built before spec v1.1 (late 2021) asks for,
/// and what matrix-js-sdk kept asking for on some endpoints for two years
/// after -- Element Call's full-mesh branch, the peer-to-peer call client
/// (contrib/element-call-full-mesh), registers at `/r0/register` and gets
/// `M_UNRECOGNIZED` from a server that answers only `v3`. The spec has
/// deprecated `r0` but every homeserver in the wild still serves it, and
/// a client that speaks it is refused for no reason a user could act on.
/// The paths are the same endpoints; only the prefix moved.
async fn legacy_prefix(mut request: axum::extract::Request) -> axum::extract::Request {
    const REWRITES: [(&str, &str); 2] = [
        ("/_matrix/client/r0/", "/_matrix/client/v3/"),
        ("/_matrix/media/r0/", "/_matrix/media/v3/"),
    ];
    let path = request.uri().path();
    let Some((from, to)) = REWRITES.iter().find(|(from, _)| path.starts_with(from)) else {
        return request;
    };
    let rewritten = format!("{to}{}", &path[from.len()..]);
    let mut parts = request.uri().clone().into_parts();
    let with_query = match request.uri().query() {
        Some(query) => format!("{rewritten}?{query}"),
        None => rewritten,
    };
    if let Ok(path_and_query) = with_query.parse() {
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = axum::http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
    }
    request
}

/// Time every request and count it, by the route the router matched.
///
/// `MatchedPath` rather than the URI: the raw path carries room and user
/// IDs, so a label taken from it would let any caller mint series until
/// the scrape falls over. The matched path is the template the router
/// holds, so the label set is bounded by the code (#166).
///
/// A request that matched no route has no template, and is counted under
/// a single `unmatched` label rather than by whatever it asked for —
/// otherwise a scanner walking random URLs is an unbounded label source.
async fn observe(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let method = request.method().to_string();
    let started = std::time::Instant::now();
    // One span per request, named by the matched route rather than the
    // path for the same reason the metric is: the template is bounded, the
    // path is whatever was asked. The fields are OpenTelemetry's HTTP
    // semantic conventions, so an exported trace reads like every other
    // service's. Free when no exporter is configured: the log subscriber
    // shows it only at a level operators do not run at.
    let span = tracing::info_span!(
        "request",
        otel.name = %format!("{method} {route}"),
        http.request.method = %method,
        http.route = %route,
        http.response.status_code = tracing::field::Empty,
    );
    let response = {
        use tracing::Instrument as _;
        next.run(request).instrument(span.clone()).await
    };
    span.record("http.response.status_code", response.status().as_u16());
    let long_poll = response
        .extensions()
        .get::<crate::metrics::LongPoll>()
        .is_some();
    state.metrics.observe_request(
        &route,
        &method,
        response.status().as_u16(),
        started.elapsed(),
        long_poll,
    );
    response
}

/// SPEC (client-server, Web Browser Clients): every response carries the
/// recommended CORS headers, and a preflight `OPTIONS` succeeds without
/// reaching a handler. Without this, no client running *in a browser* —
/// Element Web first among them — can make a single request: the
/// browser blocks every cross-origin response before the app sees it,
/// which presents as "cannot reach homeserver" against a server that is
/// reachable fine from curl and every native client. Complement's Go
/// client never sends an Origin header, which is why no ratcheted test
/// could have caught the omission — a real browser did.
async fn cors(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let preflight = request.method() == axum::http::Method::OPTIONS;
    let mut response = if preflight {
        axum::response::Response::new(axum::body::Body::empty())
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert(
        "access-control-allow-origin",
        axum::http::HeaderValue::from_static("*"),
    );
    headers.insert(
        "access-control-allow-methods",
        axum::http::HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        "access-control-allow-headers",
        axum::http::HeaderValue::from_static(
            "X-Requested-With, Content-Type, Authorization, If-Match, If-None-Match",
        ),
    );
    response
}

/// Any `/_matrix` path no route above claimed.
/// Answer the server-server API as unknown when `[federation] enabled` is
/// off. A server that does not federate has no federation surface: nothing
/// on the network can ask it to sign, join or serve anything as its
/// `server_name`.
async fn federation_gate(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();
    if !state.config.federation.enabled
        && (path.starts_with("/_matrix/federation/") || path.starts_with("/_matrix/key/"))
    {
        return unknown_endpoint().into_response();
    }
    next.run(request).await
}

fn unknown_endpoint() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "unrecognized endpoint".to_owned(),
    )
}

/// The registration behind this request's bearer token, if it is an
/// appservice token. Deliberately not derived from the authenticated
/// identity: device IDs are client-chosen at login, so anything derived
/// from them can be worn as a costume by an ordinary account.
pub(crate) fn appservice_of<'a>(
    state: &'a AppState,
    headers: &axum::http::HeaderMap,
) -> Option<&'a std::sync::Arc<crate::appservices::Registration>> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)?;
    state.appservices.by_token(token)
}

/// `@alice:example.org` and `alice` both mean the same localpart.
pub(crate) fn localpart_of(user: &str) -> String {
    // Folded to lowercase for the same reason registration folds: the
    // grammar is lowercase, and "Alice" logging in means the alice who
    // registered.
    user.strip_prefix('@')
        .and_then(|rest| rest.split(':').next())
        .unwrap_or(user)
        .to_lowercase()
}

/// An account operation that failed for none of the reasons a route
/// answers itself: a 500, except a busy password hasher (#571). That is
/// load, not a fault, and the caller is told when to try again.
pub(crate) fn internal(error: &AccountError) -> MatrixError {
    match error {
        AccountError::Busy => MatrixError::limit_exceeded(crate::passwords::BUSY_RETRY_AFTER_MS),
        _ => MatrixError::internal(&error.to_string()),
    }
}

/// The caller's address, as far as it can be known.
///
/// Behind a reverse proxy every request appears to come from the proxy, which
/// would collapse the per-source limit onto a single key and make it useless.
/// Reading a forwarding header instead is worse: any client can set it, so the
/// limit becomes opt-out. Until the deployment can say which proxies it trusts,
/// the peer address is the only value that is not attacker-controlled — and the
/// per-account limit is the one that still bites in that case, which is why
/// both exist.
pub struct ClientAddr(String);

impl std::fmt::Display for ClientAddr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map_or_else(|| "unknown".to_owned(), |info| info.0.ip().to_string()),
        ))
    }
}

/// The longest transaction id `federation_send` accepts.
pub(crate) const MAX_TXN_ID_LEN: usize = 255;

/// Put an accepted federated invite where the invitee's server will find it.
///
/// Two shapes, because there are two situations. An invite arrives out of
/// band precisely because the invitee's server is usually *not* in the room,
/// so the inviter cannot reach it through an ordinary transaction; then the
/// pending record and its stripped state are the whole of what the invitee's
/// client has to render the room from.
///
/// When this server *is* in the room, that reasoning does not apply and the
/// invite is an event in a log we hold. Recording only the pending row would
/// leave our copy saying the user is still gone, so their own join is refused
/// by the rules reading our state while the inviting server believes it told
/// us. Synapse and Continuwuity both add the invite to a room they hold.
///
/// Idempotent against the copy that may also arrive in a transaction:
/// `ingest` returns early for an event already in the log.
pub(crate) fn record_invite(
    state: &AppState,
    origin: &str,
    room_id: &str,
    event_id: &str,
    target: &str,
    body: &Value,
    signed: &Value,
) -> Result<(), MatrixError> {
    if state
        .rooms
        .receive_remote(room_id, event_id, signed)
        .is_ok()
    {
        state.rooms.wake_sync_waiters();
        return Ok(());
    }
    let invite_state: Vec<Value> = body["invite_room_state"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    state
        .rooms
        .record_pending_invite(target, room_id, origin, event_id, &invite_state)
        .map_err(room_error)?;
    state.rooms.wake_sync_waiters();
    Ok(())
}

pub(crate) fn directory_error(error: &crate::directory::DirectoryError) -> MatrixError {
    use crate::directory::DirectoryError as Error;
    match error {
        // One arm for both: an alias this server cannot speak for and one that
        // is not an alias at all are the same answer to the caller -- the name
        // you sent is not one this server will act on -- and they differ only
        // in the message, which `error.to_string()` already carries.
        Error::Malformed(_) | Error::NotOurs(_) => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            error.to_string(),
        ),
        Error::Taken(_) => {
            MatrixError::new(StatusCode::CONFLICT, "M_ROOM_IN_USE", error.to_string())
        }
        Error::Unknown(_) => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", error.to_string())
        }
        Error::Forbidden(_) => MatrixError::forbidden(error.to_string()),
        other => MatrixError::internal(&other.to_string()),
    }
}

/// Parse a request body that the spec allows to be absent.
///
/// `/leave` takes an optional `reason`, and clients send all three of an empty
/// body, `{}`, and a populated object. Extracting `Json<T>` would reject the
/// first with a 400 that the spec does not license, so the bytes are taken raw
/// and only parsed when there are some. A body that is present but malformed
/// is still an error -- silently defaulting there would swallow a client's
/// typo'd `reason` rather than reporting it.
pub(crate) fn optional_body<T: Default + serde::de::DeserializeOwned>(
    body: &axum::body::Bytes,
) -> Result<T, MatrixError> {
    if body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|error| MatrixError::bad_json(error.to_string()))
}

pub(crate) fn account_data_error(error: &crate::account_data::AccountDataError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

/// A per-account cap from `[limits]` has been reached (#268).
///
/// The same code and shape the delayed-events cap answers with, so a
/// client meets one refusal for "you are holding too much here" wherever
/// it meets it. The limit is named because the operator set it, and the
/// client can only act on a number it can see.
pub(crate) fn limit_exceeded(what: &str, limit: usize) -> MatrixError {
    MatrixError::new(
        StatusCode::BAD_REQUEST,
        "M_LIMIT_EXCEEDED",
        format!("at most {limit} {what} may be held for one account"),
    )
}

/// The caller's ruleset, seeded from the defaults if they have never edited it.
///
/// Seeding on read rather than at registration is deliberate: the defaults
/// change as the spec adds rules, and a user who registered before a rule
/// existed should get it. Only an edit freezes a ruleset, because only then is
/// there something of the user's to preserve.
pub(crate) fn ruleset_of(state: &AppState, user_id: &str) -> Result<Value, MatrixError> {
    Ok(state
        .account_data
        .get(user_id, "", crate::push_rules::TYPE)
        .map_err(|error| account_data_error(&error))?
        .map_or_else(
            || crate::push_rules::defaults(user_id),
            |stored| crate::push_rules::with_defaults(stored, user_id),
        ))
}

/// The device-list changes in `(since, until]` that `identity` may see.
///
/// The watermark scan names everyone; this narrows it to the asker's own
/// account plus users they share a room with. Not an optimization — an
/// unnarrowed list would tell any account which strangers reprovisioned a
/// device and when, which is surveillance the room graph never granted.
pub(crate) fn visible_device_changes(
    state: &AppState,
    identity: &crate::accounts::Identity,
    since: u64,
    until: u64,
) -> Result<Vec<String>, MatrixError> {
    let changed = state
        .devices
        .device_lists_changed(since, Some(until))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if changed.is_empty() {
        return Ok(changed);
    }
    let mine = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    let mut visible = Vec::new();
    for user_id in changed {
        // One's own changes are always visible: the account that grew a new
        // device is exactly the account whose other devices must hear it,
        // rooms or no rooms.
        if user_id == identity.user_id {
            visible.push(user_id);
            continue;
        }
        let theirs = state.rooms.joined(&user_id).map_err(room_error)?;
        if theirs.iter().any(|room_id| mine.contains(room_id)) {
            visible.push(user_id);
        }
    }
    Ok(visible)
}

/// Pre-serialize a value so it can sit beside an already-rendered one.
///
/// `serde_json::Value` cannot hold raw JSON, which is the whole reason the
/// sync body is assembled from `RawValue`s rather than as one `Value`: the
/// state block is served from a cache that already holds the exact bytes,
/// and parsing them back into a `Value` so they can be serialized again is
/// the cost this avoids.
pub(crate) fn raw<T: serde::Serialize>(value: &T) -> Result<Box<RawValue>, MatrixError> {
    serde_json::value::to_raw_value(value)
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct TimestampToEventQuery {
    ts: Option<u64>,
    dir: Option<String>,
}

/// The lookup behind both spellings of `timestamp_to_event`.
pub(crate) fn timestamp_lookup(
    state: &AppState,
    room_id: &str,
    query: &TimestampToEventQuery,
) -> Result<Json<Value>, MatrixError> {
    let ts = query
        .ts
        .ok_or_else(|| MatrixError::missing_param("ts is required"))?;
    let direction = match query.dir.as_deref() {
        Some("f") => crate::rooms::TimestampDirection::Forward,
        Some("b") => crate::rooms::TimestampDirection::Backward,
        Some(other) => {
            return Err(MatrixError::bad_json(format!(
                "dir must be 'f' or 'b', not {other:?}"
            )));
        }
        None => return Err(MatrixError::missing_param("dir is required")),
    };
    let (event_id, origin_server_ts) = state
        .rooms
        .event_at_timestamp(room_id, ts, direction)
        .map_err(room_error)?;
    Ok(Json(json!({
        "event_id": event_id,
        "origin_server_ts": origin_server_ts,
    })))
}

/// MSC4140's delay, spelled as the unstable query parameter.
///
/// `serde` renames it rather than the field being called that, because the
/// wire name is not an identifier and will change when the MSC stabilises --
/// at which point this is one line, not a search for every use.
#[derive(Debug, Deserialize)]
pub(crate) struct DelayQuery {
    #[serde(rename = "org.matrix.msc4140.delay")]
    pub(crate) delay: Option<u64>,
    /// MSC4354's sticky duration, spelled as its unstable query parameter.
    /// Capped at an hour by the room layer rather than refused, as the
    /// MSC computes it.
    #[serde(rename = "org.matrix.msc4354.sticky_duration_ms")]
    pub(crate) sticky: Option<u64>,
}

/// Turn a delay failure into the response a client can act on.
///
/// The error codes are MSC4140's as merged. `stable` picks the spelling of
/// the one code the MSC gives an unstable form: a delay past the cap is
/// `M_DELAY_TOO_LARGE` on the stable endpoint and
/// `ORG.MATRIX.MSC4140_DELAY_TOO_LARGE` on the unstable ones, with the cap
/// itself beside it under the key Synapse has always sent it as, which is
/// the one key a client could read to retry with less.
pub(crate) fn delay_error_as(error: crate::delayed::DelayError, stable: bool) -> MatrixError {
    use crate::delayed::DelayError;
    match error {
        DelayError::NotFound => MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such delayed event",
        ),
        DelayError::TooLong { limit_ms } => {
            let mut extra = serde_json::Map::new();
            extra.insert("org.matrix.msc4140.max_delay".to_owned(), json!(limit_ms));
            MatrixError {
                extra: Some(Box::new(extra)),
                ..MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    if stable {
                        "M_DELAY_TOO_LARGE"
                    } else {
                        "ORG.MATRIX.MSC4140_DELAY_TOO_LARGE"
                    },
                    format!("the maximum delay is {limit_ms}ms"),
                )
            }
        }
        // 429 with the wait until the caller's first pending delay is due:
        // nothing about the request was wrong, and the same request works
        // once one of the delays it already holds fires or is cancelled.
        DelayError::TooMany { retry_after_ms, .. } => MatrixError {
            error: error.to_string(),
            ..MatrixError::limit_exceeded(retry_after_ms)
        },
        DelayError::NotPositive => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "a delay must be a whole number of milliseconds greater than zero",
        ),
        DelayError::Conflict => MatrixError::new(
            StatusCode::CONFLICT,
            "M_UNKNOWN",
            "the delayed event has already finished, and not in the way asked for",
        ),
        DelayError::Store(inner) => MatrixError::internal(&inner.to_string()),
    }
}

/// [`delay_error_as`] for the unstable endpoints, which is all of them but
/// the stable scheduling one.
pub(crate) fn delay_error(error: crate::delayed::DelayError) -> MatrixError {
    delay_error_as(error, false)
}

/// The transports this deployment offers, rendered as MSC4143 sends them.
///
/// One renderer for both surfaces on purpose. The same list is served
/// authenticated at `/rtc/transports` and unauthenticated in
/// `.well-known/matrix/client`, and a client that reads one and then the
/// other has to find them consistent -- Element Call reads well-known
/// before login and the endpoint after it, so a deployment whose two
/// answers disagree is one where a call works or does not depending on
/// which surface the client happened to believe.
///
/// The order is the operator's, carried through untouched: MSC4143 has
/// clients read the list as a priority ordering. The one addition is the
/// built-in `LiveKit` service (#38), listed first when `[rtc.livekit]` is
/// set: it is this server's own, and a deployment that configured it did
/// so to use it.
pub(crate) fn rtc_transports(state: &AppState) -> Vec<Value> {
    // The built-in service advertises only while the program is on. Off —
    // by switch or by absence — reads exactly like unconfigured: the
    // operator's `foci` alone, or the empty list, and well-known omitting
    // the key when that list is empty.
    let builtin = if crate::livekit::effective_enabled(&state.config, &state.store) {
        crate::livekit::service_url(&state.config)
            .map(|url| json!({ "type": "livekit", "livekit_service_url": url }))
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    builtin
        .into_iter()
        .chain(state.config.rtc.foci.iter().map(|focus| {
            json!({
                "type": focus.kind,
                "livekit_service_url": focus.livekit_service_url,
            })
        }))
        .collect()
}

/// Attach `unsigned.m.relations` to an event a response is about to carry.
///
/// `unsigned` is the right home because it is the one part of the body the
/// event ID does not cover: an aggregate changes every time someone reacts,
/// and anything under the hash must never change.
fn with_bundle(state: &AppState, room_id: &str, viewer: &str, mut event: Value) -> Value {
    let Some(event_id) = event["event_id"].as_str().map(str::to_owned) else {
        return event;
    };
    match state.rooms.bundle_relations(room_id, &event_id, viewer) {
        Ok(Some(bundle)) => {
            let unsigned = event
                .as_object_mut()
                .expect("a stored event is an object")
                .entry("unsigned")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(unsigned) = unsigned.as_object_mut() {
                unsigned.insert("m.relations".to_owned(), bundle);
            }
            event
        }
        // No relations, or a read failure. The event itself is the answer the
        // client asked for; a bundle that cannot be computed must not turn a
        // working /messages into an error.
        _ => event,
    }
}

/// Map a room failure onto the status a client can act on.
///
/// `M_NOT_FOUND` covers three different absences — the room, a state entry,
/// and an event body — and that is correct: from a client's side they are the
/// same answer, "there is nothing here". What must not collapse is the
/// difference between absent and *refused*, which is why `Forbidden` has its
/// own arm.
pub(crate) fn room_error(error: crate::rooms::RoomError) -> MatrixError {
    match error {
        crate::rooms::RoomError::UnknownRoom(_) => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such room")
        }
        crate::rooms::RoomError::UnknownState(what) => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", format!("no {what}"))
        }
        crate::rooms::RoomError::MissingBody(_) => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such event")
        }
        crate::rooms::RoomError::InvalidPowerLevels(why) => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("power_level_content_override: {why}"),
        ),
        // The message is ruma's own wording for the rule that refused, which
        // is the same explanation a federating peer would give. A generic
        // "forbidden" would make a client's bug report useless.
        crate::rooms::RoomError::Forbidden(rule) => MatrixError::forbidden(rule),
        crate::rooms::RoomError::Policy(error) => *error,
        crate::rooms::RoomError::UnsupportedVersion(version) => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNSUPPORTED_ROOM_VERSION",
            format!("this server does not support room version {version}"),
        ),
        other => MatrixError::internal(&other.to_string()),
    }
}

/// Stamp `unsigned.transaction_id` on an event the reading device sent.
///
/// The spec scopes it to the device: the same user on another device gets
/// no `transaction_id`, since that device never chose one and a client
/// that sees one it did not send would try to match a local echo it does
/// not have.
pub(crate) fn with_transaction_id(
    state: &AppState,
    identity: &crate::accounts::Identity,
    mut event: Value,
) -> Value {
    let Some(event_id) = event["event_id"].as_str() else {
        return event;
    };
    if event["sender"].as_str() != Some(identity.user_id.as_str()) {
        return event;
    }
    let key = spindle_core::keys::transaction_echo(&identity.user_id, event_id);
    let Ok(Some(raw)) = spindle_store::ReadView::get(state.store.as_ref(), &key) else {
        // No transaction: perhaps a delay sent it, which MSC4140 stamps in
        // the transaction's place.
        return with_delay_id(state, identity, event);
    };
    let Some((device_id, txn_id)) = spindle_core::keys::transaction_echo_parts(&raw) else {
        return event;
    };
    if device_id != identity.device_id {
        return event;
    }
    if let Some(unsigned) = event.as_object_mut().and_then(|object| {
        object
            .entry("unsigned")
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
    }) {
        unsigned.insert("transaction_id".to_owned(), Value::String(txn_id));
    }
    event
}

/// Stamp MSC4140's delay ID on an event the reader sent through a delay.
///
/// For the sender only, on every device: the delay is the user's, not one
/// device's, and any of their clients may be the one watching for it.
fn with_delay_id(
    state: &AppState,
    identity: &crate::accounts::Identity,
    mut event: Value,
) -> Value {
    let Some(event_id) = event["event_id"].as_str() else {
        return event;
    };
    if event["sender"].as_str() != Some(identity.user_id.as_str()) {
        return event;
    }
    let key = spindle_core::keys::delay_echo(&identity.user_id, event_id);
    let Ok(Some(raw)) = spindle_store::ReadView::get(state.store.as_ref(), &key) else {
        return event;
    };
    let Ok(delay_id) = String::from_utf8(raw) else {
        return event;
    };
    if let Some(unsigned) = event.as_object_mut().and_then(|object| {
        object
            .entry("unsigned")
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
    }) {
        unsigned.insert(
            "org.matrix.msc4140.delay_id".to_owned(),
            Value::String(delay_id),
        );
    }
    event
}

/// An event as the reading device sees it: its own transaction ID, and
/// the relations bundled on it.
pub(crate) fn as_seen_by(
    state: &AppState,
    room_id: &str,
    identity: &crate::accounts::Identity,
    event: Value,
) -> Value {
    with_transaction_id(
        state,
        identity,
        with_bundle(state, room_id, &identity.user_id, event),
    )
}

/// One page of the room directory.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PublicRoomsQuery {
    pub(crate) limit: Option<usize>,
    pub(crate) since: Option<String>,
    /// Another server's directory. Not served yet -- see the handler.
    pub(crate) server: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PublicRoomsFilter {
    pub(crate) generic_search_term: Option<String>,
    #[serde(default)]
    pub(crate) room_types: Vec<Option<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PublicRoomsRequest {
    pub(crate) limit: Option<usize>,
    pub(crate) since: Option<String>,
    #[serde(default)]
    pub(crate) filter: PublicRoomsFilter,
    pub(crate) server: Option<String>,
}

/// The directory's default and maximum page size.
///
/// A client that asks for everything gets a page, not everything: the
/// directory is the one endpoint a stranger can call to make this server
/// render every published room's state at once.
const DIRECTORY_PAGE: usize = 50;

const DIRECTORY_PAGE_MAX: usize = 200;

pub(crate) fn chunk_of(summary: &crate::rooms::RoomSummary) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("room_id".to_owned(), json!(summary.room_id));
    entry.insert(
        "num_joined_members".to_owned(),
        json!(summary.num_joined_members),
    );
    entry.insert("world_readable".to_owned(), json!(summary.world_readable));
    entry.insert("guest_can_join".to_owned(), json!(summary.guest_can_join));
    for (field, value) in [
        ("name", summary.name.clone()),
        ("topic", summary.topic.clone()),
        ("avatar_url", summary.avatar_url.clone()),
        ("canonical_alias", summary.canonical_alias.clone()),
        ("join_rule", summary.join_rule.clone()),
        ("room_type", summary.room_type.clone()),
    ] {
        if let Some(value) = value {
            entry.insert(field.to_owned(), json!(value));
        }
    }
    Value::Object(entry)
}

fn matches_term(summary: &crate::rooms::RoomSummary, term: &str) -> bool {
    let needle = term.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    [
        summary.name.as_deref(),
        summary.topic.as_deref(),
        summary.canonical_alias.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|field| field.to_lowercase().contains(&needle))
}

/// Build one page of the directory.
///
/// `since` is an offset into the room-ID-ordered list rather than a cursor
/// into storage. That is honest about what it is: the directory is a
/// materialised list rebuilt per request, so a token pointing at a room could
/// name one that has since been unpublished, and an offset degrades more
/// gracefully -- a page boundary shifts by one instead of the whole listing
/// failing.
pub(crate) fn directory_page(
    state: &AppState,
    user_id: &str,
    limit: Option<usize>,
    since: Option<&str>,
    term: Option<&str>,
    room_types: &[Option<String>],
) -> Result<Json<Value>, MatrixError> {
    let limit = limit.unwrap_or(DIRECTORY_PAGE).clamp(1, DIRECTORY_PAGE_MAX);
    let offset: usize = match since {
        Some(token) => token.parse().map_err(|_| {
            MatrixError::bad_json("since is not a directory token this server issued")
        })?,
        None => 0,
    };

    let published = state
        .directory
        .published()
        .map_err(|error| directory_error(&error))?;

    // A published room whose summary cannot be read is skipped rather than
    // failing the page. The directory is a list of pointers, and one dangling
    // pointer -- a room purged while still published -- must not take the
    // whole listing down with it.
    let mut visible: Vec<crate::rooms::RoomSummary> = Vec::new();
    for room_id in &published {
        let Ok(summary) = state.rooms.summary_for(user_id, room_id) else {
            continue;
        };
        if term.is_some_and(|term| !matches_term(&summary, term)) {
            continue;
        }
        if !room_types.is_empty() && !room_types.contains(&summary.room_type) {
            continue;
        }
        visible.push(summary);
    }

    let total = visible.len();
    let page: Vec<Value> = visible
        .iter()
        .skip(offset)
        .take(limit)
        .map(chunk_of)
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(page));
    body.insert("total_room_count_estimate".to_owned(), json!(total));
    if offset + limit < total {
        body.insert("next_batch".to_owned(), json!((offset + limit).to_string()));
    }
    if offset > 0 {
        body.insert(
            "prev_batch".to_owned(),
            json!(offset.saturating_sub(limit).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

pub(crate) const SEARCH_LIMIT_MAX: usize = 100;

/// Where each room's next page starts, as the opaque `next_batch` a client
/// hands back: `li:room_id` pairs joined by `;`, the position first because
/// a room ID has colons of its own. Per room rather than one global
/// position because positions are per room, and a page that stops in the
/// middle of one room's hits must resume exactly there while the other
/// rooms resume where they were.
pub(crate) fn parse_search_cursor(token: &str) -> Result<BTreeMap<String, i64>, MatrixError> {
    let mut cursor = BTreeMap::new();
    for pair in token.split(';').filter(|pair| !pair.is_empty()) {
        let (li, room_id) = pair
            .split_once(':')
            .ok_or_else(|| MatrixError::bad_json("next_batch is not a search token"))?;
        let li = li
            .parse::<i64>()
            .map_err(|_| MatrixError::bad_json("next_batch is not a search token"))?;
        cursor.insert(room_id.to_owned(), li);
    }
    Ok(cursor)
}

pub(crate) fn search_cursor(cursor: &BTreeMap<String, i64>) -> String {
    cursor
        .iter()
        .map(|(room_id, li)| format!("{li}:{room_id}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// One search hit, with where it came from.
pub(crate) struct SearchHit {
    pub(crate) room_id: String,
    pub(crate) event: crate::rooms::TimelineEvent,
}

pub(crate) fn origin_server_ts(hit: &SearchHit) -> i64 {
    hit.event.json["origin_server_ts"].as_i64().unwrap_or(0)
}

/// What the evaluator needs of a room, gathered once per room per page.
pub(crate) struct RoomRuleContext {
    member_count: usize,
    power_levels: Value,
}

impl RoomRuleContext {
    /// The room-kind facts the rules ask about: the joined count and the
    /// power levels.
    pub(crate) fn of(state: &AppState, room_id: &str) -> Result<Self, MatrixError> {
        Ok(Self {
            member_count: state
                .rooms
                .joined_members(room_id)
                .map_err(room_error)?
                .len(),
            power_levels: state
                .rooms
                .state_event_unscoped(room_id, "m.room.power_levels", "")
                .unwrap_or_else(|_| json!({})),
        })
    }

    pub(crate) fn for_reader<'a>(
        &'a self,
        user_id: &'a str,
        display_name: Option<&'a str>,
        room_id: &'a str,
    ) -> crate::push_rules::Context<'a> {
        crate::push_rules::Context {
            user_id,
            display_name,
            room_id,
            member_count: self.member_count,
            power_levels: &self.power_levels,
        }
    }
}

/// Re-prove the password before a change a stolen access token must not be
/// enough to make.
///
/// Returns `Ok(Some(challenge))` when the caller should answer 401 with it,
/// and `Ok(None)` when the stage is satisfied. Two bypasses, both deliberate
/// and both pre-existing: an appservice with `device_management` is already
/// acting for the user by a stronger credential than their password, and a
/// server delegating auth (MSC3861) has no password to check -- the identity
/// provider owns that stage.
pub(crate) fn password_uia(
    state: &AppState,
    localpart: &str,
    headers: &axum::http::HeaderMap,
    auth: Option<&Value>,
    session: &'static str,
) -> Result<Option<Json<Value>>, MatrixError> {
    let manages =
        appservice_of(state, headers).is_some_and(|registration| registration.device_management);
    if manages || state.delegated.is_some() {
        return Ok(None);
    }
    // A dict naming no session is not a completed stage: the session is how a
    // stage is tied back to the flow it completed, so it draws the challenge
    // rather than being accepted.
    let auth =
        auth.filter(|auth| auth["session"].is_string() && auth["type"] == "m.login.password");
    let Some(auth) = auth else {
        return Ok(Some(Json(json!({
            "flows": [{ "stages": ["m.login.password"] }],
            "params": {},
            "session": session,
        }))));
    };
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let password = auth["password"].as_str().unwrap_or_default();
    if !accounts
        .verify_password(localpart, password)
        .map_err(|error| internal(&error))?
    {
        return Err(MatrixError::forbidden("wrong password"));
    }
    Ok(None)
}

/// May `user_id` read `room_id`'s contents at all?
///
/// **One rule, one place, for the whole read surface.** Membership was
/// enforced on `/joined_members` and `/aliases` and nowhere else in the
/// timeline/state group, so `/state`, `/state/{type}/{key}`, `/messages`,
/// `/event/{id}`, `/context/{id}`, `/relations/…` and `/threads` each
/// answered 200 with a private room's full contents to any account that knew
/// its room ID -- including one registered a moment earlier and joined to
/// nothing. The underlying `Rooms` methods do not check either: they take a
/// room id and no user, and `with_room_read` is an existence check.
///
/// The federation surface never had this hole -- `federation_room_origin`
/// refuses a server with no member in the room -- so a remote server was held
/// to a stricter rule than a local account. That asymmetry is the clearest
/// statement of what was wrong.
///
/// Two ways in, and no third:
///
/// - joined, which is a point read and the overwhelmingly common case, so it
///   is answered first and the rest is never reached;
/// - `m.room.history_visibility` of `world_readable`, which is the room
///   saying that anyone may read it. This is about *history*, not about
///   joining: a `public` room is one anyone may enter, not one anyone may
///   read without entering, and conflating them would leave the hole open for
///   every public room on the server.
///
/// A room this server does not hold gets the same refusal as a room the
/// caller may not see. The alternative is a 404-versus-403 oracle that tells
/// a stranger which room IDs exist, which is the smaller half of the same
/// question they were asking.
pub(crate) fn may_read_room(
    state: &AppState,
    user_id: &str,
    room_id: &str,
) -> Result<(), MatrixError> {
    state.rooms.may_read(user_id, room_id).map_err(room_error)
}

/// The `m.space.child` events of a room, in the spec's order.
///
/// Ordered by the child's `order` field then its room ID, because a space
/// with no explicit order still has to paginate stably -- the same argument
/// the room directory makes.
pub(crate) fn space_children(state: &AppState, room_id: &str, suggested_only: bool) -> Vec<Value> {
    let Ok(events) = state.rooms.state_unscoped(room_id) else {
        return Vec::new();
    };
    let mut children: Vec<Value> = events
        .into_iter()
        .filter(|event| event["type"] == "m.space.child")
        // A child with no `via` is not a child: the spec says an
        // `m.space.child` without it is to be ignored, and that is also how a
        // child is *removed* -- by replacing its content with an empty one.
        .filter(|event| {
            event["content"]["via"]
                .as_array()
                .is_some_and(|via| !via.is_empty())
        })
        .filter(|event| !suggested_only || event["content"]["suggested"].as_bool().unwrap_or(false))
        .collect();
    children.sort_by(|left, right| {
        let key = |event: &Value| {
            (
                event["content"]["order"].as_str().unwrap_or("").to_owned(),
                event["state_key"].as_str().unwrap_or("").to_owned(),
            )
        };
        key(left).cmp(&key(right))
    });
    children
}
