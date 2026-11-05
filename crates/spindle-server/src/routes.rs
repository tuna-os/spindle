//! The route table, and the router built from it.
//!
//! One table, so [`surface`](crate::surface)'s claims can be checked against
//! what is actually mounted rather than against a second list that agrees with
//! the first only until someone edits one of them.

use crate::accounts::{AccountError, Accounts};
use crate::auth::{AccountAuthenticated, Authenticated};
use crate::errors::MatrixError;
use crate::inbound::{FederationStateQuery, federation_origin};
use crate::profile_routes::profile_of;
use crate::ratelimit::{Budget, limit_write};
use crate::rooms::ReadScope;
use crate::{AppState, surface};
use axum::extract::ConnectInfo;
use axum::{
    Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
    routing::post,
};
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
/// holds membership, timeline and state alike. Four builders also keep any one
/// of them short enough to read at a glance, which a single chain of forty
/// routes had stopped being.
pub fn router(state: AppState) -> Router {
    let routes = Router::new()
        .merge(crate::account_routes::routes())
        .merge(crate::room_routes::routes())
        .merge(crate::keys_routes::routes())
        .merge(crate::sync_routes::routes())
        .merge(crate::account_data_routes::routes())
        .merge(crate::moderation_routes::routes())
        .merge(crate::profile_routes::routes())
        .merge(push_routes())
        .merge(appservice_routes())
        .merge(crate::dehydrated::routes())
        .merge(crate::device_routes::routes())
        .merge(crate::presence_routes::routes())
        .merge(room_routes())
        .merge(timeline_routes())
        .merge(crate::timeline_routes::routes())
        .merge(delayed_routes())
        .merge(media_routes(state.media.max_upload_bytes()))
        .merge(discovery_routes())
        .merge(federation_read_routes())
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

/// The surface only an appservice speaks.
fn appservice_routes() -> Router<AppState> {
    Router::new().route(
        "/_matrix/client/v1/appservice/{appservice_id}/ping",
        post(appservice_ping),
    )
}

/// Push: where a user's devices are told, and by which rules.
fn push_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/pushers", get(get_pushers))
        .route("/_matrix/client/v3/pushers/set", post(set_pusher))
        // Four arities of the same path, because the spec has four and each
        // reads or writes a different slice of one ruleset.
        .route("/_matrix/client/v3/pushrules/", get(get_push_rules))
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}",
            get(get_push_rule)
                .put(set_push_rule)
                .delete(delete_push_rule),
        )
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled",
            get(get_push_rule_enabled).put(set_push_rule_enabled),
        )
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions",
            get(get_push_rule_actions).put(set_push_rule_actions),
        )
}

/// Creating a room, getting in and out of one, and who else is there.
fn room_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/directory/room/{room_alias}",
            get(resolve_alias).put(create_alias).delete(delete_alias),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/aliases",
            get(room_aliases),
        )
        .route(
            "/_matrix/client/v3/directory/list/room/{room_id}",
            get(get_room_visibility).put(set_room_visibility),
        )
        .route(
            "/_matrix/client/v3/publicRooms",
            get(public_rooms).post(public_rooms_filtered),
        )
        .route(
            "/_matrix/client/v3/user_directory/search",
            post(user_directory_search),
        )
        .route("/_matrix/client/v3/search", post(search))
        .route("/_matrix/client/v3/notifications", get(notifications))
}

/// MSC4140's delayed events: scheduling, lookup and management, under the
/// stable paths the merged MSC names and the unstable ones shipping clients
/// call.
fn delayed_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
            get(delayed_events),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
            post(delayed_event_action).get(delayed_event_lookup),
        )
        // MSC4140 as merged: scheduling through an endpoint of its own, and
        // the stable management and lookup paths, beside the unstable ones
        // shipping clients call.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
            axum::routing::put(delayed_event_put_unstable),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/delayed_event/{event_type}/{txn_id}",
            axum::routing::put(delayed_event_put_stable),
        )
        .route(
            "/_matrix/client/v1/delayed_events/{delay_id}",
            get(delayed_event_lookup),
        )
        .route(
            "/_matrix/client/v1/delayed_events/{delay_id}/{action}",
            post(delayed_event_action_stable),
        )
        // The current MSC4140 shape: the action in the path and no access
        // token, so a delegate (lk-jwt-service) can keep a leave event
        // pending, or send it, for a client that has gone away.
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}",
            post(delayed_event_action_by_id),
        )
}

/// Everything that reads or writes a room's log, and its state.
fn timeline_routes() -> Router<AppState> {
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

/// Uploading and fetching files.
///
/// Only the authenticated surface. The unauthenticated `/media/v3/download`
/// endpoints are deliberately absent: the spec froze and deprecated them
/// because an unauthenticated media URL is a capability that leaks the moment
/// it is pasted anywhere, and serving them would undo the access control the
/// authenticated endpoints exist to impose. A client old enough to need them
/// gets a 404, which is the truthful answer for a surface this server does not
/// offer.
fn media_routes(max_upload_bytes: usize) -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/media/v3/upload",
            post(upload_media)
                // Axum's default body limit is 2 MiB, which would reject an
                // upload before the handler ever saw it -- with a bare 413 and
                // no Matrix error code. The server would then be advertising a
                // configured limit in `/config` and enforcing 2 MiB, which is the
                // worst kind of disagreement: the client is told the file is
                // fine, sends it, and gets an opaque failure.
                //
                // The extractor limit is set one byte above ours so that
                // `Media::put` is the thing that refuses, and refuses with
                // `M_TOO_LARGE`.
                .layer(axum::extract::DefaultBodyLimit::max(
                    max_upload_bytes.saturating_add(1),
                )),
        )
        .route("/_matrix/media/v1/create", post(create_media))
        .route(
            "/_matrix/media/v3/upload/{server_name}/{media_id}",
            axum::routing::put(upload_reserved_media).layer(axum::extract::DefaultBodyLimit::max(
                max_upload_bytes.saturating_add(1),
            )),
        )
        .route("/_matrix/media/v3/config", get(media_config))
        .route("/_matrix/client/v1/media/config", get(media_config))
        .route("/_matrix/client/v1/media/preview_url", get(preview_url))
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}",
            get(download_media),
        )
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}/{file_name}",
            get(download_media_named),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}",
            get(thumbnail_media),
        )
}

/// `POST /_matrix/media/v3/upload`
async fn upload_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    limit_write(&state, Budget::MediaUpload, &identity.user_id)?;
    // The uploader's claim about the type, not a guess at it. Sniffing would
    // mean the server deciding a file is HTML and then having to be right
    // about that forever; taking the claim and refusing to render anything
    // risky inline is the safer half of the same problem.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let media_id = state
        .media
        .put(
            &body,
            &content_type,
            query.filename.as_deref(),
            &identity.user_id,
            upload_quota(&state, &identity.user_id)?,
        )
        .await
        .map_err(|error| upload_error(&state, &error))?;
    Ok(Json(json!({
        "content_uri": format!("mxc://{}/{media_id}", state.config.server.name),
    })))
}

/// Whether `user_id`'s upload is held to the media quota: not when there is
/// none, and not for the accounts the write budgets exempt.
fn upload_quota(state: &AppState, user_id: &str) -> Result<crate::media::Quota, MatrixError> {
    if state.media.quota_bytes().is_none()
        || crate::ratelimit::exempt_from_write_limits(state, user_id)?
    {
        return Ok(crate::media::Quota::Exempt);
    }
    Ok(crate::media::Quota::Enforced)
}

/// [`media_error`], with the `admin_contact` the spec requires on
/// `M_RESOURCE_LIMIT_EXCEEDED` when `[server.support]` names someone: the
/// one thing a user over quota can usefully do is ask for more.
fn upload_error(state: &AppState, error: &crate::media::MediaError) -> MatrixError {
    let mut refusal = media_error(error);
    if matches!(error, crate::media::MediaError::QuotaExceeded { .. })
        && let Some(contact) = admin_contact(state)
    {
        let mut extra = serde_json::Map::new();
        extra.insert("admin_contact".to_owned(), Value::String(contact));
        refusal.extra = Some(Box::new(extra));
    }
    refusal
}

/// A URI for reaching this server's administrator, from
/// `[server.support]`: the support page, else an admin's address, else
/// anyone's.
fn admin_contact(state: &AppState) -> Option<String> {
    let support = state.config.server.support.as_ref()?;
    if let Some(page) = &support.support_page {
        return Some(page.clone());
    }
    let mut contacts: Vec<_> = support.contacts.iter().collect();
    // Admins first; a stable sort keeps the operator's order otherwise.
    contacts.sort_by_key(|contact| contact.role != "m.role.admin");
    contacts.iter().find_map(|contact| {
        contact
            .email_address
            .as_ref()
            .map(|address| format!("mailto:{address}"))
            .or_else(|| {
                contact
                    .matrix_id
                    .as_ref()
                    .map(|id| format!("https://matrix.to/#/{id}"))
            })
    })
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    filename: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    url: String,
    // `ts` (the point in history to preview at) is accepted and ignored: we
    // keep no preview history, and serving the current preview for any ts
    // is within what the spec allows.
    #[allow(dead_code)]
    ts: Option<u64>,
}

/// `GET /_matrix/client/v1/media/preview_url`
async fn preview_url(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<PreviewQuery>,
) -> Result<Json<Value>, MatrixError> {
    if !state.config.previews.enabled {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "URL previews are disabled on this server".to_owned(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    match state.previews.preview(&query.url, now).await {
        Ok(og) => Ok(Json(og)),
        // A refused URL and an unfetchable page must stay distinguishable:
        // the refusal is policy and retrying is pointless; the fetch failure
        // is the internet being the internet.
        Err(crate::previews::PreviewError::Refused(why)) => Err(MatrixError::forbidden(&why)),
        Err(crate::previews::PreviewError::Unfetchable(why)) => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("cannot preview that page: {why}"),
        )),
        Err(crate::previews::PreviewError::Storage(why)) => Err(MatrixError::internal(&why)),
    }
}

/// `GET /_matrix/media/v3/config` and its `/client/v1` twin.
async fn media_config(State(state): State<AppState>) -> Json<Value> {
    // Stated rather than discovered: a client that knows the limit can refuse
    // a file before spending a minute sending it.
    Json(json!({ "m.upload.size": state.media.max_upload_bytes() }))
}

/// `GET /_matrix/client/v1/media/download/{server_name}/{media_id}`
async fn download_media(
    State(state): State<AppState>,
    AccountAuthenticated(identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response, MatrixError> {
    serve_media(&state, &identity, &server_name, &media_id).await
}

/// The same, with a filename the client would like the browser to use.
///
/// The name in the path is ignored. The one that goes in the header is the one
/// recorded at upload: letting the *downloader* choose it would let a link
/// dictate what a file appears to be, which is how a `.png` turns into a
/// `.exe` in someone's downloads folder.
async fn download_media_named(
    State(state): State<AppState>,
    AccountAuthenticated(identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id, _file_name)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<axum::response::Response, MatrixError> {
    serve_media(&state, &identity, &server_name, &media_id).await
}

/// The identity is authenticated and then, by ADR 0003, not consulted:
/// possession of the URI is the capability, as the spec and every reference
/// server have it. The binding is what makes the route require a token at
/// all. `docs/architecture-decisions/0003-media-authorization.md` says why,
/// and what would supersede it.
async fn serve_media(
    state: &AppState,
    _identity: &crate::accounts::Identity,
    server_name: &str,
    media_id: &str,
) -> Result<axum::response::Response, MatrixError> {
    let media_id = if state.media.is_ours(server_name) {
        media_id.to_owned()
    } else {
        cached_remote_media(state, server_name, media_id).await?
    };
    let media_id = media_id.as_str();
    let (record, bytes) = state
        .media
        .bytes(media_id)
        .await
        .map_err(|error| media_error(&error))?;

    let mut response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, &record.content_type)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            record.content_disposition(),
        )
        // Without this a browser may decide for itself that an
        // `application/octet-stream` is really HTML, and run it.
        .header("x-content-type-options", "nosniff")
        // Belt and braces around the same risk: even if something renders,
        // it can load nothing, run nothing, and frame nothing.
        .header(
            "content-security-policy",
            "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; \
             style-src 'unsafe-inline'; object-src 'self';",
        )
        .header("cross-origin-resource-policy", "cross-origin");
    if let Some(headers) = response.headers_mut() {
        let _ = headers;
    }
    response
        .body(axum::body::Body::from(bytes))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

/// The local cache ID for a remote server's media, fetching and caching it
/// on first sight.
///
/// The fetch happens once: the blob is content-addressed and the record
/// write idempotent, so every later request — downloads and thumbnails
/// alike — is served from local storage.
async fn cached_remote_media(
    state: &AppState,
    server_name: &str,
    media_id: &str,
) -> Result<String, MatrixError> {
    let cache_id = crate::media::Media::remote_id(server_name, media_id);
    let cached = state
        .media
        .record(&cache_id)
        .map_err(|error| media_error(&error))?
        .is_some();
    if !cached {
        let (content_type, filename, bytes) = state
            .federation
            .remote_media_download(server_name, media_id)
            .await
            .map_err(|error| {
                MatrixError::new(
                    StatusCode::NOT_FOUND,
                    "M_NOT_FOUND",
                    format!("{server_name} did not yield {media_id}: {error}"),
                )
            })?;
        state
            .media
            .put_remote(
                server_name,
                media_id,
                &bytes,
                &content_type,
                filename.as_deref(),
            )
            .await
            .map_err(|error| media_error(&error))?;
    }
    Ok(cache_id)
}

/// `GET /_matrix/federation/v1/media/download/{mediaId}` (MSC3916).
///
/// Serves this server's own media to an authenticated peer, as
/// `multipart/mixed`: a JSON metadata part, then the file — the shape the
/// MSC fixes, and the one the outbound client parses.
async fn federation_media_download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(media_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::response::Response, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    let (record, bytes) = state
        .media
        .bytes(&media_id)
        .await
        .map_err(|error| media_error(&error))?;
    multipart_media(
        &record.content_type,
        Some(&record.content_disposition()),
        &bytes,
    )
}

/// `GET /_matrix/federation/v1/media/thumbnail/{mediaId}` (spec v1.11)
///
/// The authenticated-media twin of the client thumbnail, in the same
/// `multipart/mixed` framing as the federation download.
async fn federation_media_thumbnail(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(media_id): axum::extract::Path<String>,
    // Every field optional so a missing one is refused after the
    // signature check, in the spec's JSON shape, not by the extractor.
    axum::extract::Query(query): axum::extract::Query<FederationThumbnailQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::response::Response, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    let (Some(width), Some(height)) = (query.width, query.height) else {
        return Err(MatrixError::missing_param("width and height are required"));
    };
    if width == 0 || height == 0 {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "width and height must be positive",
        ));
    }
    let crop = query.method.as_deref() == Some("crop");
    let (content_type, bytes) = state
        .media
        .thumbnail(&media_id, width, height, crop)
        .await
        .map_err(|error| media_error(&error))?;
    multipart_media(&content_type, None, &bytes)
}

#[derive(Debug, Default, Deserialize)]
struct FederationThumbnailQuery {
    width: Option<u32>,
    height: Option<u32>,
    method: Option<String>,
}

/// The `multipart/mixed` body authenticated federation media travels in:
/// an empty JSON metadata part, then the bytes.
fn multipart_media(
    content_type: &str,
    disposition: Option<&str>,
    bytes: &[u8],
) -> Result<axum::response::Response, MatrixError> {
    // The boundary need only be absent from the payload's *framing*, and a
    // random 32-hex string followed by the exact dash-CRLF framing has no
    // way to occur inside the file; fixed randomness per response keeps
    // this simple and stateless.
    let boundary = {
        use std::fmt::Write as _;
        let mut raw = [0_u8; 16];
        crate::secrets::fill(&mut raw);
        raw.iter().fold(String::with_capacity(32), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    };
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + 512);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"content-type: application/json\r\n\r\n{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(format!("content-type: {content_type}\r\n").as_bytes());
    if let Some(disposition) = disposition {
        body.extend_from_slice(format!("content-disposition: {disposition}\r\n").as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={boundary}"),
        )
        .body(axum::body::Body::from(body))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

#[derive(Debug, Deserialize)]
struct ThumbnailQuery {
    width: u32,
    height: u32,
    method: Option<String>,
}

/// `GET /_matrix/client/v1/media/thumbnail/{server_name}/{media_id}`
///
/// Authenticated, and open to any account holding the URI, for the reason
/// [`serve_media`] gives (ADR 0003). An account-level session is enough —
/// Element Admin's device-less admin token renders avatars through this —
/// since reading media acts on no device.
async fn thumbnail_media(
    State(state): State<AppState>,
    AccountAuthenticated(_identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<ThumbnailQuery>,
) -> Result<axum::response::Response, MatrixError> {
    let media_id = if state.media.is_ours(&server_name) {
        media_id
    } else {
        cached_remote_media(&state, &server_name, &media_id).await?
    };
    if query.width == 0 || query.height == 0 {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "width and height must be positive",
        ));
    }
    let crop = query.method.as_deref() == Some("crop");
    let (content_type, bytes) = state
        .media
        .thumbnail(&media_id, query.width, query.height, crop)
        .await
        .map_err(|error| media_error(&error))?;
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "cross-origin")
        .body(axum::body::Body::from(bytes))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

fn media_error(error: &crate::media::MediaError) -> MatrixError {
    use crate::media::MediaError as Error;
    match error {
        Error::Unknown(_) | Error::Missing { .. } => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", error.to_string())
        }
        // 504, as the spec has it: the bytes are on their way from another
        // client, and the asker should try again rather than give up.
        Error::NotYetUploaded(_) => MatrixError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "M_NOT_YET_UPLOADED",
            error.to_string(),
        ),
        Error::AlreadyUploaded(_) => MatrixError::new(
            StatusCode::CONFLICT,
            "M_CANNOT_OVERWRITE_MEDIA",
            error.to_string(),
        ),
        Error::NotReserver(_) => MatrixError::forbidden(error.to_string()),
        Error::TooManyPending(_) => MatrixError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            error.to_string(),
        ),
        Error::TooLarge { .. } => MatrixError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            error.to_string(),
        ),
        // 403, because the spec's `/upload` lists "the user has reached a
        // quota for uploaded content" under 403 -- not 413 `M_TOO_LARGE`,
        // which says *this file* is too big and sends a client to
        // `/media/config` to learn a limit the file is already under.
        // `M_RESOURCE_LIMIT_EXCEEDED` rather than plain `M_FORBIDDEN` so a
        // client can tell "over quota" from "not allowed", and because it
        // is the code Synapse's `media_upload_limits` refuses with.
        Error::QuotaExceeded { .. } => MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_RESOURCE_LIMIT_EXCEEDED",
            error.to_string(),
        ),
        // The spec's own code for "this cannot be thumbnailed". Unreadable
        // bytes get the same answer as an unsupported type: either way the
        // uploader's declared type cannot be honoured, and the distinction
        // belongs in the message, not the status.
        Error::Unsupported(_) | Error::Unreadable(_) => {
            MatrixError::new(StatusCode::BAD_REQUEST, "M_UNSUPPORTED", error.to_string())
        }
        other => MatrixError::internal(&other.to_string()),
    }
}

/// What a client or a peer reads before it knows anything else.
/// The read-side federation surface added with the second spec-gap wave,
/// and the key notary.
fn federation_read_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/key/v2/query", post(key_query_batch))
        .route("/_matrix/key/v2/query/{server_name}", get(key_query_one))
        .route(
            "/_matrix/federation/v1/media/thumbnail/{media_id}",
            get(federation_media_thumbnail),
        )
        .route(
            "/_matrix/federation/v1/event_auth/{room_id}/{event_id}",
            get(federation_event_auth),
        )
        .route(
            "/_matrix/federation/v1/publicRooms",
            get(federation_public_rooms).post(federation_public_rooms_filtered),
        )
        .route(
            "/_matrix/federation/v1/hierarchy/{room_id}",
            get(federation_hierarchy),
        )
        .route(
            "/_matrix/federation/v1/timestamp_to_event/{room_id}",
            get(federation_timestamp_to_event),
        )
}

fn discovery_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/client/v3/capabilities", get(capabilities))
        .route("/_matrix/key/v2/server", get(server_keys))
        .route("/_matrix/federation/v1/version", get(federation_version))
        .route(
            "/_matrix/federation/v1/query/directory",
            get(federation_query_directory),
        )
        .route(
            "/_matrix/federation/v1/query/profile",
            get(federation_query_profile),
        )
        .route(
            "/_matrix/federation/v1/send/{txn_id}",
            axum::routing::put(federation_send),
        )
        .route(
            "/_matrix/federation/v1/state/{room_id}",
            get(federation_state),
        )
        .route(
            "/_matrix/federation/v1/state_ids/{room_id}",
            get(federation_state_ids),
        )
        .route(
            "/_matrix/federation/v1/event/{event_id}",
            get(federation_event),
        )
        .route(
            "/_matrix/federation/v1/backfill/{room_id}",
            get(federation_backfill),
        )
        .route(
            "/_matrix/federation/v1/get_missing_events/{room_id}",
            post(federation_missing_events),
        )
        .route(
            "/_matrix/federation/v1/user/keys/query",
            post(federation_keys_query),
        )
        .route(
            "/_matrix/federation/v1/user/keys/claim",
            post(federation_keys_claim),
        )
        .route(
            "/_matrix/federation/v1/user/devices/{user_id}",
            get(federation_user_devices),
        )
        .route(
            "/_matrix/federation/v1/make_join/{room_id}/{user_id}",
            get(federation_make_join),
        )
        .route(
            "/_matrix/federation/v1/make_leave/{room_id}/{user_id}",
            get(federation_make_leave),
        )
        .route(
            "/_matrix/federation/v2/send_leave/{room_id}/{event_id}",
            axum::routing::put(federation_send_leave),
        )
        .route(
            "/_matrix/federation/v2/send_join/{room_id}/{event_id}",
            axum::routing::put(federation_send_join),
        )
        .route(
            "/_matrix/federation/v1/send_join/{room_id}/{event_id}",
            axum::routing::put(federation_send_join_v1),
        )
        .route(
            "/_matrix/federation/v1/send_leave/{room_id}/{event_id}",
            axum::routing::put(federation_send_leave_v1),
        )
        .route(
            "/_matrix/federation/v1/make_knock/{room_id}/{user_id}",
            get(federation_make_knock),
        )
        .route(
            "/_matrix/federation/v1/send_knock/{room_id}/{event_id}",
            axum::routing::put(federation_send_knock),
        )
        .route(
            "/_matrix/federation/v2/invite/{room_id}/{event_id}",
            axum::routing::put(federation_invite),
        )
        .route(
            "/_matrix/federation/v1/media/download/{media_id}",
            get(federation_media_download),
        )
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/.well-known/matrix/support", get(well_known_support))
        .route("/_matrix/client/v1/auth_metadata", get(auth_metadata))
        // The unstable alias is load-bearing: Element Web's js-sdk asks
        // here first, and a deployment serving only the stable path
        // looks to it like a server with no delegation at all.
        .route(
            "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
            get(auth_metadata),
        )
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// `GET /_matrix/client/versions`
async fn versions() -> Json<Value> {
    let mut unstable = serde_json::Map::new();
    for (feature, enabled) in surface::UNSTABLE_FEATURES {
        unstable.insert((*feature).to_owned(), json!(enabled));
    }
    Json(json!({
        "versions": surface::spec_version_names(),
        "unstable_features": Value::Object(unstable),
    }))
}

/// `GET /_matrix/client/v3/capabilities`
///
/// Room-version capability is omitted entirely rather than sent empty: the spec
/// treats a missing capability as "unknown, assume the default", whereas an
/// empty `available` map is a positive claim that no room version works. Until
/// rooms exist (#7) the honest thing is to say nothing, not to say none.
async fn capabilities(State(state): State<AppState>) -> Json<Value> {
    let mut capabilities = serde_json::Map::new();
    // MSC4140: both limits, which the server must enforce and so must
    // state, under the stable name and the unstable one clients read today.
    let (max_delay_ms, max_scheduled) = state.delayed.limits();
    let delayed = json!({ "max_delay_ms": max_delay_ms, "max_scheduled": max_scheduled });
    capabilities.insert("m.delayed_events".to_owned(), delayed.clone());
    capabilities.insert("org.matrix.msc4140.delayed_events".to_owned(), delayed);
    if let Some(default) = surface::DEFAULT_ROOM_VERSION {
        let available: serde_json::Map<String, Value> = surface::ROOM_VERSIONS
            .iter()
            .map(|version| {
                let stability = if *version == spindle_core::STATE_DAG_V12 {
                    "unstable"
                } else {
                    "stable"
                };
                ((*version).to_owned(), json!(stability))
            })
            .collect();
        capabilities.insert(
            "m.room_versions".to_owned(),
            json!({ "default": default, "available": Value::Object(available) }),
        );
    }
    capabilities.insert("m.get_login_token".to_owned(), json!({ "enabled": true }));
    Json(json!({ "capabilities": Value::Object(capabilities) }))
}

/// How long a well-known document may be reused, in seconds.
///
/// Both documents are configuration this server publishes about itself,
/// and both are read by things that cache. Without a header the caching
/// is somebody else's default, and the defaults are long: the
/// server-server spec tells a peer with no header to assume **24 hours**
/// (capping at 48), and a browser is free to pick a heuristic of its own
/// for the client document. That is the shape of the problem #37 names --
/// an operator changes a setting, restarts, and the change is not visible
/// for a day, from a server that is already serving the new answer.
///
/// An hour is a deliberate trade rather than a spec value, because the
/// spec gives none for the client document and only a default for the
/// other. It bounds propagation to something an operator can wait out
/// while a fetch per peer per hour is nothing next to the traffic a peer
/// already sends. The spec explicitly says a peer should respect the
/// header when it is present, so this shortens the 24-hour default rather
/// than fighting it.
const WELL_KNOWN_MAX_AGE_SECONDS: u32 = 3600;

/// A well-known document, with the caching this server chose.
fn well_known(body: Value) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            format!("public, max-age={WELL_KNOWN_MAX_AGE_SECONDS}"),
        )],
        Json(body),
    )
}

/// `GET /.well-known/matrix/client`
async fn well_known_client(
    State(state): State<AppState>,
) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    let mut body = json!({
        "m.homeserver": { "base_url": state.config.client_base_url() },
    });
    // MSC2965: a delegated deployment names its issuer here, which is
    // how a client knows to speak OIDC before it ever hits /login.
    if let Some(delegated) = &state.delegated {
        body["org.matrix.msc2965.authentication"] = json!({
            "issuer": delegated.issuer(),
            "account": format!("{}/account", delegated.issuer().trim_end_matches('/')),
        });
    } else if state.oidc.is_some() {
        // The built-in provider is its own issuer, and serves its own
        // account pages (#607).
        body["org.matrix.msc2965.authentication"] = json!({
            "issuer": format!("{}/", crate::oidc::issuer(&state)),
            "account": crate::account::management_uri(&state),
        });
    }
    // MSC4143 (which absorbed MSC4158): the MatrixRTC backend, named here
    // as well as on `/rtc/transports` because a client discovers calls
    // before it has a token to ask with. Omitted entirely when nothing is
    // configured -- an empty array here would be a positive claim to have
    // no backend, where absence is "this server does not answer that".
    let foci = rtc_transports(&state);
    if !foci.is_empty() {
        body["org.matrix.msc4143.rtc_foci"] = Value::Array(foci);
    }
    well_known(body)
}

/// `GET /_matrix/client/v1/auth_metadata`
///
/// MSC2965's discovery endpoint: the provider's own `OpenID Connect`
/// metadata document, relayed. A non-delegated deployment answers 404
/// `M_UNRECOGNIZED` — the endpoint's absence is how a client learns this
/// server does its own auth.
async fn auth_metadata(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    if state.oidc.is_some() {
        return Ok(Json(crate::oidc::metadata(&state)));
    }
    let Some(delegated) = &state.delegated else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "authentication is not delegated",
        ));
    };
    Ok(Json(delegated.metadata().await?))
}

/// `GET /.well-known/matrix/server`
///
/// Served so a peer resolving this server name finds the port it actually
/// listens on rather than assuming 8448.
async fn well_known_server(
    State(state): State<AppState>,
) -> ([(axum::http::HeaderName, String); 1], Json<Value>) {
    well_known(json!({ "m.server": state.config.server.name }))
}

/// Liveness: the process is up.
///
/// Takes no state and no lock -- not the room registry, not a room --
/// and must stay that way: it answers whenever a worker can poll it, and
/// #614 is about making sure one always can, by keeping room work off the
/// async workers. A liveness answer that waited on the work it is meant
/// to see past would get a busy server killed.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Readiness: the process can serve.
///
/// Storage is open, the stream counters resumed and the signing key loaded
/// before the listener accepts anything, so by the time this can answer at
/// all the server can serve every request. It does **not** wait for the
/// startup room warm-up (`spawn_room_warmup`): a room of a million events
/// takes minutes to load, and holding a single-replica deployment out of
/// rotation for that long is an outage bought to avoid a slow first
/// request. A room not yet warm is loaded by the request that needs it,
/// off the async workers.
///
/// What it does wait on is the store: once the engine refuses a write (a
/// full disk, a failing one) it refuses every write after it, and a server
/// that answers `/sync` but fails every `/send` with a 500 is not one to
/// route clients to. A readiness probe that lies is worse than none.
///
/// Liveness stays up on purpose. The process is fine and its disk is not;
/// restarting it onto the same full disk only adds a crash loop to the page.
/// The remedy is in `docs/lifecycle.md`, under "A full disk".
async fn ready(State(state): State<AppState>) -> StatusCode {
    if spindle_store::Store::accepts_writes(state.store.as_ref()) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// `GET /.well-known/matrix/support` (spec v1.10)
///
/// Who to contact about this server. Unconfigured, it is a 404 rather
/// than an empty list: the spec reads an empty answer as "nobody", and
/// "not published" is the truer thing to say.
async fn well_known_support(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    let Some(support) = &state.config.server.support else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "this server publishes no support contacts",
        ));
    };
    let contacts: Vec<Value> = support
        .contacts
        .iter()
        .map(|contact| {
            let mut entry = serde_json::Map::new();
            if let Some(matrix_id) = &contact.matrix_id {
                entry.insert("matrix_id".to_owned(), json!(matrix_id));
            }
            if let Some(email) = &contact.email_address {
                entry.insert("email_address".to_owned(), json!(email));
            }
            entry.insert("role".to_owned(), json!(contact.role));
            Value::Object(entry)
        })
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("contacts".to_owned(), Value::Array(contacts));
    if let Some(page) = &support.support_page {
        body.insert("support_page".to_owned(), json!(page));
    }
    Ok(Json(Value::Object(body)))
}

/// MSC2659 (spec v1.7): an appservice asks to be pinged back, to prove the
/// homeserver can reach its push URL before anything real depends on it.
///
/// Authorization is the `as_token` itself, checked against the registration
/// the path names — not the authenticated identity, because a device ID is
/// client-chosen at login and anything derived from it can be worn as a
/// costume by an ordinary account.
async fn appservice_ping(
    State(state): State<AppState>,
    axum::extract::Path(appservice_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    let registration = state.appservices.by_token(token).ok_or_else(|| {
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNKNOWN_TOKEN",
            "only an appservice can ask for its own ping",
        )
    })?;
    if registration.id != appservice_id {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "an appservice can only ping itself",
        ));
    }
    let Some(url) = &registration.url else {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_URL_NOT_SET",
            "the registration has no url to ping",
        ));
    };
    let mut ping_body = json!({});
    if let Some(Json(body)) = &body
        && let Some(transaction_id) = body["transaction_id"].as_str()
    {
        ping_body["transaction_id"] = Value::String(transaction_id.to_owned());
    }
    let started = std::time::Instant::now();
    let response = reqwest::Client::new()
        .post(format!("{}/_matrix/app/v1/ping", url.trim_end_matches('/')))
        .header("authorization", format!("Bearer {}", registration.hs_token))
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(30))
        .body(ping_body.to_string())
        .send()
        .await;
    match response {
        Err(error) if error.is_timeout() => Err(MatrixError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "M_CONNECTION_TIMEOUT",
            "the appservice did not answer in time",
        )),
        Err(error) => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_CONNECTION_FAILED",
            format!("the appservice could not be reached: {error}"),
        )),
        Ok(response) if !response.status().is_success() => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_BAD_STATUS",
            format!("the appservice answered {}", response.status()),
        )),
        Ok(_) => Ok(Json(json!({
            "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }))),
    }
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

pub(crate) fn internal(error: &AccountError) -> MatrixError {
    MatrixError::internal(&error.to_string())
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

/// `GET /_matrix/federation/v1/version`
///
/// Unauthenticated by spec: it exists so operators can tell what is on the
/// other end before trust is established.
async fn federation_version() -> Json<Value> {
    Json(json!({
        "server": { "name": "spindle", "version": env!("CARGO_PKG_VERSION") }
    }))
}

#[derive(Debug, Deserialize)]
struct FederationDirectoryQuery {
    room_alias: String,
}

/// `GET /_matrix/federation/v1/query/directory`
async fn federation_query_directory(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<FederationDirectoryQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    let Some(room_id) = state
        .directory
        .resolve(&query.room_alias)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{} is not here", query.room_alias),
        ));
    };
    Ok(Json(json!({
        "room_id": room_id.room_id,
        "servers": [state.config.server.name],
    })))
}

#[derive(Debug, Deserialize)]
struct FederationProfileQuery {
    user_id: String,
}

/// `GET /_matrix/federation/v1/query/profile`
async fn federation_query_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<FederationProfileQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    // Local users only: proxying another server's profile through this
    // endpoint would let any server launder queries through us.
    if query.user_id.split_once(':').map(|(_, domain)| domain)
        != Some(state.config.server.name.as_str())
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{} is not here", query.user_id),
        ));
    }
    profile_of(&state, &query.user_id).await.map(Json)
}

/// The longest transaction id `federation_send` accepts.
pub(crate) const MAX_TXN_ID_LEN: usize = 255;

/// `PUT /_matrix/federation/v1/send/{txnId}`
/// Extractor shell; the handler is [`crate::inbound::send_transaction`].
async fn federation_send(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_transaction(state, headers, txn_id, request).await
}

/// `GET /_matrix/federation/v1/state/{roomId}?event_id=`
/// Extractor shell; the handler is [`crate::inbound::room_state`].
async fn federation_state(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<FederationStateQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::room_state(state, headers, room_id, query, request).await
}

/// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=`
/// Extractor shell; the handler is [`crate::inbound::room_state_ids`].
async fn federation_state_ids(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<FederationStateQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::room_state_ids(state, headers, room_id, query, request).await
}

/// `GET /_matrix/federation/v1/event/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::event`].
async fn federation_event(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(event_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::event(state, headers, event_id, request).await
}

/// `GET /_matrix/federation/v1/backfill/{roomId}?v=&limit=`
/// Extractor shell; the handler is [`crate::inbound::backfill`].
async fn federation_backfill(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::backfill(state, headers, room_id, request).await
}

/// `POST /_matrix/federation/v1/user/keys/query`
/// Extractor shell; the handler is [`crate::e2ee_federation::keys_query`].
async fn federation_keys_query(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::e2ee_federation::keys_query(state, headers, request).await
}

/// `POST /_matrix/federation/v1/user/keys/claim`
/// Extractor shell; the handler is [`crate::e2ee_federation::keys_claim`].
async fn federation_keys_claim(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::e2ee_federation::keys_claim(state, headers, request).await
}

/// `GET /_matrix/federation/v1/user/devices/{userId}`
/// Extractor shell; the handler is [`crate::e2ee_federation::user_devices`].
async fn federation_user_devices(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::e2ee_federation::user_devices(state, headers, user_id, request).await
}

/// `POST /_matrix/federation/v1/get_missing_events/{roomId}`
/// Extractor shell; the handler is [`crate::inbound::missing_events`].
async fn federation_missing_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::missing_events(state, headers, room_id, request).await
}

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`
/// Extractor shell; the handler is [`crate::inbound::make_join`].
async fn federation_make_join(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, user_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::make_join(state, headers, room_id, user_id, request).await
}

/// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`
/// Extractor shell; the handler is [`crate::inbound::make_leave`].
async fn federation_make_leave(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, user_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::make_leave(state, headers, room_id, user_id, request).await
}

/// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}`
/// Extractor shell; the handler is [`crate::inbound::make_knock`].
async fn federation_make_knock(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, user_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::make_knock(state, headers, room_id, user_id, request).await
}

/// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::send_knock`].
async fn federation_send_knock(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_knock(state, headers, room_id, event_id, request).await
}

/// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::send_leave`].
async fn federation_send_leave(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_leave(state, headers, room_id, event_id, request).await
}

/// `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::send_leave_v1`].
async fn federation_send_leave_v1(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_leave_v1(state, headers, room_id, event_id, request).await
}

/// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::send_join`].
async fn federation_send_join(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_join(state, headers, room_id, event_id, request).await
}

/// `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::send_join_v1`].
async fn federation_send_join_v1(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::send_join_v1(state, headers, room_id, event_id, request).await
}

/// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`
/// Extractor shell; the handler is [`crate::inbound::invite`].
async fn federation_invite(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    crate::inbound::invite(state, headers, room_id, event_id, request).await
}

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

/// `GET /_matrix/key/v2/server`
///
/// Publishes the *public* half of this server's signing key, so a peer can
/// verify events we signed.
///
/// `valid_until_ts` is a re-fetch hint, not an expiry the spec enforces. It is
/// deliberately short-ish: a peer that caches this for a long time keeps
/// trusting a key we may have had to rotate, and the cost of it being wrong is
/// borne by whoever has to explain why signatures stopped verifying.
async fn server_keys(State(state): State<AppState>) -> Json<Value> {
    Json(own_key_document(&state))
}

/// This server's signed key document, as `/_matrix/key/v2/server` serves it.
fn own_key_document(state: &AppState) -> Value {
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis().saturating_add(24 * 60 * 60 * 1000))
        .unwrap_or_default();

    let document = json!({
        "server_name": state.config.server.name,
        "valid_until_ts": u64::try_from(valid_until).unwrap_or(u64::MAX),
        "verify_keys": {
            state.key.key_id(): { "key": state.key.public_key_base64() },
        },
        // No key has been retired, and saying so explicitly is not the same as
        // omitting it: a peer reads this to decide whether a signature made
        // with an old key should still be honoured.
        "old_verify_keys": {},
    });
    // Self-signed, with the very key inside it: that circularity is the
    // spec's design — the document proves possession of the key it
    // publishes, and a peer that skips this check would trust anyone on
    // the network path. Our own verifier refuses unsigned documents, so an
    // unsigned one here would mean no other Spindle could ever trust us —
    // which is exactly how the first server-to-server test found this.
    sign_with_own_key(state, document)
}

/// Add this server's signature to a JSON object, keeping any it carries.
fn sign_with_own_key(state: &AppState, document: Value) -> Value {
    ruma::CanonicalJsonValue::try_from(document.clone())
        .ok()
        .and_then(|canonical| match canonical {
            ruma::CanonicalJsonValue::Object(mut object) => {
                ruma::signatures::sign_json(
                    &state.config.server.name,
                    state.key.pair(),
                    &mut object,
                )
                .ok()?;
                serde_json::to_value(&object).ok()
            }
            _ => None,
        })
        .unwrap_or(document)
}

#[derive(Debug, Deserialize)]
struct KeyQueryParams {
    /// Accepted and not acted on: a document is served as cached, and a
    /// document that lapsed is refetched by the cache itself.
    #[allow(dead_code)]
    minimum_valid_until_ts: Option<u64>,
}

/// `GET /_matrix/key/v2/query/{serverName}`
///
/// The notary form: another server's key document, from this server's
/// cache (fetched if unseen), with this server's signature added so the
/// asker can hold us to what we handed on. Our own name answers with our
/// own document. A server whose keys cannot be had is simply absent.
async fn key_query_one(
    State(state): State<AppState>,
    axum::extract::Path(server_name): axum::extract::Path<String>,
    axum::extract::Query(_query): axum::extract::Query<KeyQueryParams>,
) -> Json<Value> {
    let server_keys = notary_documents(&state, &[server_name]).await;
    Json(json!({ "server_keys": server_keys }))
}

#[derive(Debug, Deserialize)]
struct KeyQueryBatch {
    #[serde(default)]
    server_keys: BTreeMap<String, Value>,
}

/// `POST /_matrix/key/v2/query`
async fn key_query_batch(
    State(state): State<AppState>,
    Json(request): Json<KeyQueryBatch>,
) -> Json<Value> {
    let names: Vec<String> = request.server_keys.into_keys().collect();
    let server_keys = notary_documents(&state, &names).await;
    Json(json!({ "server_keys": server_keys }))
}

async fn notary_documents(state: &AppState, names: &[String]) -> Vec<Value> {
    let mut documents = Vec::new();
    for name in names {
        let document = if *name == state.config.server.name {
            own_key_document(state)
        } else {
            match state.federation.peer_key_document(name).await {
                Ok(document) => sign_with_own_key(state, document),
                Err(error) => {
                    tracing::debug!(server = %name, "notary: no key document: {error}");
                    continue;
                }
            }
        };
        documents.push(document);
    }
    documents
}

/// `GET /_matrix/client/v3/directory/room/{room_alias}`
///
/// Unauthenticated, as the spec requires: resolving a name is how a client
/// finds a room it has not joined, and requiring an account to look one up
/// would make published aliases useless to anyone not already signed in.
///
/// `servers` is this server alone until federation lands. Naming ourselves is
/// honest -- we are the only server known to hold the room -- where an empty
/// list would tell a client there is nowhere to join through.
async fn resolve_alias(
    State(state): State<AppState>,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(record) = state
        .directory
        .resolve(&room_alias)
        .map_err(|error| directory_error(&error))?
    {
        return Ok(Json(json!({
            "room_id": record.room_id,
            "servers": [state.config.server.name.clone()],
        })));
    }
    // The classic appservice room query: an alias inside a service's
    // namespace may spring into being when asked — the service creates
    // the room and maps the alias before answering 200, so the second
    // resolution finds what the first could not.
    if state.appservices.query_alias(&room_alias).await
        && let Some(record) = state
            .directory
            .resolve(&room_alias)
            .map_err(|error| directory_error(&error))?
    {
        return Ok(Json(json!({
            "room_id": record.room_id,
            "servers": [state.config.server.name.clone()],
        })));
    }
    // An alias another server owns is that server's to answer: the same
    // federated directory query the join path uses, relayed to the client
    // with the servers the owner names.
    if let Some((_, domain)) = room_alias.split_once(':')
        && domain != state.config.server.name
        && let Ok(answer) = state
            .federation
            .remote_query_directory(domain, &room_alias)
            .await
        && answer["room_id"].is_string()
    {
        return Ok(Json(json!({
            "room_id": answer["room_id"],
            "servers": answer["servers"].as_array().cloned().unwrap_or_default(),
        })));
    }
    Err(MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no room is called {room_alias}"),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateAliasRequest {
    room_id: String,
}

/// `PUT /_matrix/client/v3/directory/room/{room_alias}`
///
/// The room must exist. Letting an alias point at nothing would put a name in
/// the directory that resolves to a 404 on join -- a broken link the server
/// handed out itself. And the caller must be in it, or a server admin: see
/// [`may_advertise`]. Existence is checked first, so that "no such room" does
/// not come back as a refusal, which would tell a stranger the room exists
/// and they simply are not in it.
async fn create_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
    Json(request): Json<CreateAliasRequest>,
) -> Result<Json<Value>, MatrixError> {
    state.rooms.exists(&request.room_id).map_err(room_error)?;
    may_advertise(
        &state,
        &identity.user_id,
        &request.room_id,
        "give it an alias",
    )?;
    state
        .directory
        .create(&room_alias, &request.room_id, &identity.user_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/directory/room/{room_alias}`
///
/// Claiming an alias writes no room state -- the room's own opinion about
/// what it is called is the room's to give. Removing one is different: a
/// canonical alias that names an alias the directory no longer resolves
/// is a broken name the server left behind, and the public directory
/// still matches searches against it. So, as Synapse does, the alias is
/// taken out of `m.room.canonical_alias` on the remover's behalf, best
/// effort: a remover the room does not let edit that event keeps the
/// stale name, which is the room's decision rather than an error here.
async fn delete_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = state
        .directory
        .delete(&room_alias, &identity.user_id)
        .map_err(|error| directory_error(&error))?;
    if let Ok(event) = state
        .rooms
        .state_event_full(&room_id, "m.room.canonical_alias", "")
        && let Some(without) = without_alias(&event["content"], &room_alias)
    {
        let _ = state
            .rooms
            .set_state_checked(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                "m.room.canonical_alias",
                "",
                &without,
            )
            .await;
    }
    Ok(Json(json!({})))
}

/// `content` with `alias` gone from `alias` and `alt_aliases`, or `None` if
/// it named it nowhere and there is nothing to write.
fn without_alias(content: &Value, alias: &str) -> Option<Value> {
    let names_it = content["alias"] == json!(alias)
        || content["alt_aliases"]
            .as_array()
            .is_some_and(|alts| alts.iter().any(|alt| alt == alias));
    if !names_it {
        return None;
    }
    let mut without = content.clone();
    if without["alias"] == json!(alias) {
        without.as_object_mut()?.remove("alias");
    }
    if let Some(alts) = without["alt_aliases"].as_array_mut() {
        alts.retain(|alt| alt != alias);
    }
    Some(without)
}

/// `GET /_matrix/client/v3/rooms/{room_id}/aliases`
///
/// Members only. The directory answers alias-to-room for anyone, because that
/// is a name someone published; room-to-alias is the transpose and enumerates
/// what a room is reachable by, which is the room's business.
async fn room_aliases(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    if !joined.iter().any(|room| room == &room_id) {
        return Err(MatrixError::forbidden(format!(
            "{} is not in {room_id}",
            identity.user_id
        )));
    }
    let aliases = state
        .directory
        .for_room(&room_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({ "aliases": aliases })))
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

/// `GET /_matrix/client/v3/pushers`
async fn get_pushers(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let pushers = state
        .pushers
        .list(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "pushers": pushers })))
}

#[derive(Debug, Deserialize)]
struct SetPusherRequest {
    pushkey: String,
    /// `http`, `email`, or `null` to remove the pusher.
    kind: Option<String>,
    app_id: String,
    #[serde(default)]
    app_display_name: String,
    #[serde(default)]
    device_display_name: String,
    #[serde(default)]
    profile_tag: Option<String>,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    data: Value,
    /// The spec's `append` governs pushers of the *same* pushkey held by
    /// *other* users; this server keys pushers per user, so it has nothing
    /// to remove either way and the flag is accepted for the wire shape.
    #[serde(default)]
    #[allow(dead_code)]
    append: bool,
    /// MSC3881: whether this pusher receives anything. Absent is on.
    #[serde(default, alias = "org.matrix.msc3881.enabled")]
    enabled: Option<bool>,
}

/// `POST /_matrix/client/v3/pushers/set`
///
/// Register, replace or (with `kind: null`) remove one of the caller's
/// pushers. An http pusher's URL is what `push::deliver_loop` will fetch
/// for as long as the registration stands, so it is vetted here the way
/// the loop vets it: the spec's path, http or https, and not a literal
/// address inside this server's network -- a hostname is judged by what it
/// resolves to, at every delivery.
async fn set_pusher(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<SetPusherRequest>,
) -> Result<Json<Value>, MatrixError> {
    let internal = |error: spindle_store::StoreError| MatrixError::internal(&error.to_string());
    let Some(kind) = request.kind.as_deref() else {
        state
            .pushers
            .remove(&identity.user_id, &request.app_id, &request.pushkey)
            .map_err(internal)?;
        return Ok(Json(json!({})));
    };
    match kind {
        "http" => {
            let Some(url) = request.data["url"].as_str() else {
                return Err(MatrixError::missing_param("an http pusher needs data.url"));
            };
            state
                .push
                .vet_url(url)
                .map_err(|why| MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", why))?;
        }
        "email" => {}
        other => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("unknown pusher kind {other:?}; expected http, email or null"),
            ));
        }
    }
    // Replacing a registration does not count against the cap: a client
    // that re-registers the same device forever stays where it is.
    let cap = state.config.limits.pushers_per_user;
    if !state
        .pushers
        .holds(&identity.user_id, &request.app_id, &request.pushkey)
        .map_err(internal)?
        && state.pushers.count(&identity.user_id).map_err(internal)? >= cap
    {
        return Err(limit_exceeded("pushers", cap));
    }
    state
        .pushers
        .set(
            &identity.user_id,
            &request.app_id,
            &request.pushkey,
            &json!({
                "pushkey": request.pushkey,
                "kind": kind,
                "app_id": request.app_id,
                "app_display_name": request.app_display_name,
                "device_display_name": request.device_display_name,
                "profile_tag": request.profile_tag,
                "lang": request.lang,
                "data": request.data,
                // MSC3881, under both spellings until the stable one is
                // in a spec this server claims: the device that owns the
                // pusher, so another client can name it, and the switch.
                "enabled": request.enabled.unwrap_or(true),
                "org.matrix.msc3881.enabled": request.enabled.unwrap_or(true),
                "device_id": identity.device_id,
                "org.matrix.msc3881.device_id": identity.device_id,
            }),
        )
        .map_err(internal)?;
    Ok(Json(json!({})))
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

fn save_ruleset(state: &AppState, user_id: &str, ruleset: &Value) -> Result<(), MatrixError> {
    let stream_write = state.rooms.reserve_stream_id();
    let position = stream_write.id();
    state
        .account_data
        .put(user_id, "", crate::push_rules::TYPE, ruleset, position)
        .map_err(|error| account_data_error(&error))?;
    state.rooms.wake_sync_waiters();
    // What was scored under the old rules says nothing under the new.
    state.rooms.forget_scores(user_id);
    Ok(())
}

/// Reject a scope the spec does not define.
///
/// Only `global` exists today. `device` was in older drafts and clients still
/// occasionally ask for it, so answering `M_NOT_FOUND` rather than treating it
/// as `global` keeps a client from believing it stored a per-device rule that
/// silently applied everywhere.
fn check_scope(scope: &str) -> Result<(), MatrixError> {
    if scope == "global" {
        return Ok(());
    }
    Err(MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no such push rule scope: {scope}"),
    ))
}

fn check_kind(kind: &str) -> Result<(), MatrixError> {
    if crate::push_rules::KINDS.contains(&kind) {
        return Ok(());
    }
    Err(MatrixError::new(
        StatusCode::BAD_REQUEST,
        "M_INVALID_PARAM",
        format!("no such push rule kind: {kind}"),
    ))
}

fn rule_not_found(kind: &str, rule_id: &str) -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no {kind} rule {rule_id}"),
    )
}

/// `GET /_matrix/client/v3/pushrules/`
async fn get_push_rules(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    Ok(Json(json!({ "global": ruleset })))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn get_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    let index = crate::push_rules::position(&ruleset, &kind, &rule_id)
        .ok_or_else(|| rule_not_found(&kind, &rule_id))?;
    Ok(Json(ruleset[&kind][index].clone()))
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn set_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    // A dotted ID means a rule the *server* defined. A client may enable,
    // disable and re-action one, but minting a new one would let it claim a
    // meaning the server assigns -- and then a later spec version defining
    // that ID would collide with the client's.
    if crate::push_rules::is_server_default(&rule_id) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "rule IDs beginning with a dot belong to the server",
        ));
    }
    let mut rule = body;
    if !rule["actions"].is_array() {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "a push rule needs an `actions` array",
        ));
    }
    // A rule a client wrote is enabled unless it says otherwise, and is never
    // a default however the body is decorated: `default` is the server's word
    // for "this rule came with the server", and a client cannot make it true.
    if rule.get("enabled").is_none() {
        rule["enabled"] = Value::Bool(true);
    }
    rule["default"] = Value::Bool(false);

    let mut ruleset = ruleset_of(&state, &identity.user_id)?;
    crate::push_rules::upsert(&mut ruleset, &kind, &rule_id, rule);
    save_ruleset(&state, &identity.user_id, &ruleset)?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn delete_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    let mut ruleset = ruleset_of(&state, &identity.user_id)?;
    if !crate::push_rules::remove(&mut ruleset, &kind, &rule_id) {
        return Err(rule_not_found(&kind, &rule_id));
    }
    save_ruleset(&state, &identity.user_id, &ruleset)?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled`
async fn get_push_rule_enabled(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let rule = one_rule(&state, &identity.user_id, &scope, &kind, &rule_id)?;
    Ok(Json(json!({ "enabled": rule["enabled"] })))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions`
async fn get_push_rule_actions(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let rule = one_rule(&state, &identity.user_id, &scope, &kind, &rule_id)?;
    Ok(Json(json!({ "actions": rule["actions"] })))
}

fn one_rule(
    state: &AppState,
    user_id: &str,
    scope: &str,
    kind: &str,
    rule_id: &str,
) -> Result<Value, MatrixError> {
    check_scope(scope)?;
    check_kind(kind)?;
    let ruleset = ruleset_of(state, user_id)?;
    let index = crate::push_rules::position(&ruleset, kind, rule_id)
        .ok_or_else(|| rule_not_found(kind, rule_id))?;
    Ok(ruleset[kind][index].clone())
}

#[derive(Debug, Deserialize)]
struct EnabledRequest {
    enabled: bool,
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled`
///
/// Works on a server default as well as a user's own rule: silencing
/// `.m.rule.message` is exactly what this endpoint is for.
async fn set_push_rule_enabled(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<EnabledRequest>,
) -> Result<Json<Value>, MatrixError> {
    edit_rule(&state, &identity.user_id, &scope, &kind, &rule_id, |rule| {
        rule["enabled"] = Value::Bool(request.enabled);
    })
}

#[derive(Debug, Deserialize)]
struct ActionsRequest {
    actions: Vec<Value>,
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions`
async fn set_push_rule_actions(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<ActionsRequest>,
) -> Result<Json<Value>, MatrixError> {
    edit_rule(&state, &identity.user_id, &scope, &kind, &rule_id, |rule| {
        rule["actions"] = Value::Array(request.actions.clone());
    })
}

/// Read the ruleset, change one rule in place, write it back.
///
/// In place: `enabled` and `actions` are edits to an existing rule, so the
/// rule keeps its position. Moving it would re-prioritise a ruleset the client
/// did not ask to reorder -- and for a default rule, would move it out of the
/// order the spec fixes.
fn edit_rule(
    state: &AppState,
    user_id: &str,
    scope: &str,
    kind: &str,
    rule_id: &str,
    change: impl FnOnce(&mut Value),
) -> Result<Json<Value>, MatrixError> {
    check_scope(scope)?;
    check_kind(kind)?;
    let mut ruleset = ruleset_of(state, user_id)?;
    let index = crate::push_rules::position(&ruleset, kind, rule_id)
        .ok_or_else(|| rule_not_found(kind, rule_id))?;
    change(&mut ruleset[kind][index]);
    save_ruleset(state, user_id, &ruleset)?;
    Ok(Json(json!({})))
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

/// `GET /_matrix/federation/v1/timestamp_to_event/{roomId}` (spec v1.6)
async fn federation_timestamp_to_event(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<TimestampToEventQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    crate::inbound::federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    timestamp_lookup(&state, &room_id, &query)
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
fn delay_error_as(error: crate::delayed::DelayError, stable: bool) -> MatrixError {
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

/// One delay as MSC4140's lookup reports it, pending or finished.
fn delay_info(event: &crate::delayed::DelayedEvent) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("delay_id".to_owned(), json!(event.delay_id));
    entry.insert("room_id".to_owned(), json!(event.room_id));
    entry.insert("type".to_owned(), json!(event.event_type));
    if let Some(state_key) = &event.state_key {
        entry.insert("state_key".to_owned(), json!(state_key));
    }
    let since = event.fire_at_ms.saturating_sub(event.delay_ms);
    entry.insert("delay_ms".to_owned(), json!(event.delay_ms));
    entry.insert("delayed_since_ts".to_owned(), json!(since));
    // The names the list endpoint has always used, kept beside the merged
    // ones: they are what Synapse sends and what shipping clients read.
    entry.insert("delay".to_owned(), json!(event.delay_ms));
    entry.insert("running_since".to_owned(), json!(since));
    entry.insert("content".to_owned(), event.content.clone());
    Value::Object(entry)
}

/// The same for a delay that has finished, with how it finished.
fn finalised_info(record: &crate::delayed::FinalisedDelay) -> Value {
    let mut entry = serde_json::Map::new();
    entry.insert("delay_id".to_owned(), json!(record.delay_id));
    entry.insert("room_id".to_owned(), json!(record.room_id));
    entry.insert("type".to_owned(), json!(record.event_type));
    if let Some(state_key) = &record.state_key {
        entry.insert("state_key".to_owned(), json!(state_key));
    }
    entry.insert("delay_ms".to_owned(), json!(record.delay_ms));
    entry.insert(
        "delayed_since_ts".to_owned(),
        json!(record.delayed_since_ts),
    );
    entry.insert("content".to_owned(), record.content.clone());
    let mut finalised = serde_json::Map::new();
    if let Some(event_id) = &record.event_id {
        finalised.insert("event_id".to_owned(), json!(event_id));
    }
    if let Some(error) = &record.error {
        finalised.insert(
            "error".to_owned(),
            json!({
                "errcode": record.errcode.as_deref().unwrap_or("M_UNKNOWN"),
                "error": error,
            }),
        );
    }
    finalised.insert("finalised_ts".to_owned(), json!(record.finalised_ts));
    entry.insert("finalised".to_owned(), Value::Object(finalised));
    Value::Object(entry)
}

/// `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events`
///
/// What this caller is still waiting on. Scoped to the caller: a delay is a
/// pending action taken in their name, and whose it is is the only sensible
/// unit here. Not in MSC4140 as merged (MSC4486 takes it on), and kept
/// because Synapse serves it and clients call it.
async fn delayed_events(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let pending = state.delayed.list(&identity.user_id).map_err(delay_error)?;
    let chunk: Vec<Value> = pending.iter().map(delay_info).collect();
    Ok(Json(json!({ "delayed_events": chunk })))
}

/// `GET /_matrix/client/v1/delayed_events/{delay_id}`, and its unstable
/// alias.
///
/// One delay of the caller's, pending or finished: MSC4140's way for a
/// client that was away to learn whether its delay was sent, cancelled or
/// refused, and why. Another user's delay is not found, exactly as one that
/// never existed.
async fn delayed_event_lookup(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(delay_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    match state.delayed.get(&delay_id, &identity.user_id) {
        Ok(event) => Ok(Json(delay_info(&event))),
        Err(crate::delayed::DelayError::NotFound) => {
            match state.delayed.outcome(&delay_id).map_err(delay_error)? {
                Some((owner, record)) if owner == identity.user_id => {
                    Ok(Json(finalised_info(&record)))
                }
                _ => Err(delay_error(crate::delayed::DelayError::NotFound)),
            }
        }
        Err(error) => Err(delay_error(error)),
    }
}

#[derive(Debug, Deserialize)]
struct DelayActionRequest {
    action: String,
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}`
///
/// The earliest shape of the management endpoint, with the action in the
/// body; matrix-js-sdk still falls back to it. `restart` is the one that
/// matters: it is the heartbeat a live client sends to say "not yet", and
/// it re-applies the *original* delay rather than what remained.
async fn delayed_event_action(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(delay_id): axum::extract::Path<String>,
    Json(request): Json<DelayActionRequest>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&request.action).ok_or_else(|| {
        MatrixError::bad_json(format!(
            "action must be 'send', 'cancel' or 'restart', not {:?}",
            request.action
        ))
    })?;
    act_on_delay(&state, &delay_id, Some(&identity.user_id), action, false).await
}

/// Apply `action` to a delay -- the caller's when `owner` names them, the
/// holder of the id's otherwise -- and do what follows from it: send the
/// event for `send`, record the outcome for `cancel`.
///
/// `stable` picks how an action that contradicts a finished delay is
/// refused. MSC4140 as merged says 409, and the stable endpoint says so.
/// The unstable endpoints keep the 404 they have always given, because the
/// clients calling them were built against it: matrix-js-sdk before October
/// 2026 treats a 409 on `restart` or `cancel` as unrecoverable and ends the
/// call, and lk-jwt-service before 0.7 retries a 409 until its deadline
/// where a 404 tells it the delay is gone. Synapse answers 404 there too.
async fn act_on_delay(
    state: &AppState,
    delay_id: &str,
    owner: Option<&str>,
    action: crate::delayed::Action,
    stable: bool,
) -> Result<Json<Value>, MatrixError> {
    let pending = state
        .delayed
        .pending(delay_id)
        .filter(|event| owner.is_none_or(|owner| event.sender == owner));
    let acted = match owner {
        Some(owner) => state.delayed.act(delay_id, owner, action),
        None => state.delayed.act_by_id(delay_id, action),
    }
    .map_err(|error| match error {
        crate::delayed::DelayError::Conflict if !stable => {
            delay_error(crate::delayed::DelayError::NotFound)
        }
        other => delay_error(other),
    })?;
    if let Some(event) = acted {
        send_delayed_now(state, &event).await?;
    } else if action == crate::delayed::Action::Cancel {
        // A cancel is kept as an outcome like any other, so a lookup can
        // report it and a repeated cancel is the success it should be. Not
        // when the delay had already finished: that cancel changed nothing.
        if let Some(event) = pending {
            record_cancel(state, &event);
        }
    }
    Ok(Json(json!({})))
}

/// Keep a cancellation as the delay's outcome.
fn record_cancel(state: &AppState, event: &crate::delayed::DelayedEvent) {
    let record = crate::delayed::FinalisedDelay::cancelled(event);
    if let Err(error) =
        state
            .delayed
            .finalise(&event.sender, state.rooms.stream_position(), &record)
    {
        tracing::warn!(
            delay_id = %event.delay_id,
            "a delayed event was cancelled but its outcome was not recorded: {error}"
        );
    }
}

/// Send a delayed event now, on its owner's behalf, and record the outcome
/// for MSC4309 -- the `send` action, from either route.
///
/// Sticky if it was scheduled sticky: `MatrixRTC` 2.0's leave is a sticky
/// delayed event, and a delegate that sends it early (lk-jwt-service, when
/// the participant drops off the SFU) must deliver the same event the fire
/// loop would have, or clients that track membership through the sticky
/// map never see the participant go.
///
/// A send that is refused leaves the delay scheduled and answers with the
/// refusal, as MSC4140 asks: whatever refused it may have changed by its
/// deadline, and the client may retry until then.
async fn send_delayed_now(
    state: &AppState,
    event: &crate::delayed::DelayedEvent,
) -> Result<(), MatrixError> {
    let sent = match &event.state_key {
        Some(state_key) => {
            state
                .rooms
                .set_state_sticky_checked(
                    &event.room_id,
                    &event.sender,
                    state.key.pair(),
                    &event.event_type,
                    state_key,
                    &event.content,
                    event.sticky_ms,
                )
                .await
        }
        None => {
            state
                .rooms
                .send_sticky_checked(
                    &event.room_id,
                    &event.sender,
                    state.key.pair(),
                    &event.event_type,
                    &event.content,
                    event.sticky_ms,
                )
                .await
        }
    };
    let event_id = match sent {
        Ok(event_id) => event_id,
        Err(error) => {
            if let Err(store) = state.delayed.reinstate(event) {
                tracing::warn!(
                    delay_id = %event.delay_id,
                    "a refused delayed send could not be put back: {store}"
                );
            }
            return Err(room_error(error));
        }
    };
    // MSC4309, for the same reason the fire loop records its outcome:
    // this device learns the result from the response, but the user's
    // *other* devices are exactly as uninformed as if the delay had
    // fired on its own. A failure to record must not fail the send that
    // already happened, so it is logged rather than returned.
    let record = crate::delayed::FinalisedDelay::of(event, Ok(event_id));
    if let Err(error) =
        state
            .delayed
            .finalise(&event.sender, state.rooms.stream_position(), &record)
    {
        tracing::warn!(
            delay_id = %event.delay_id,
            "a delayed event was sent but its outcome was not recorded: {error}"
        );
    }
    Ok(())
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}`
///
/// An access token is optional here. With one, the delay must be the
/// caller's, as on the stable endpoint -- which is how lk-jwt-service 0.8
/// calls it, as the user, through its application service. Without one the
/// delay ID is the capability (see [`crate::delayed::Delayed::act_by_id`]),
/// which is how earlier releases call it to restart a delegated leave while
/// the participant is still on the SFU and send it when they are not;
/// answering that 404 makes the service drop the delegation, and the leave
/// fires while the caller is still in the call.
async fn delayed_event_action_by_id(
    State(state): State<AppState>,
    crate::auth::MaybeAuthenticated(identity): crate::auth::MaybeAuthenticated,
    axum::extract::Path((delay_id, action)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&action).ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            format!("no delayed-event action {action:?}"),
        )
    })?;
    act_on_delay(
        &state,
        &delay_id,
        identity.as_ref().map(|identity| identity.user_id.as_str()),
        action,
        false,
    )
    .await
}

/// `POST /_matrix/client/v1/delayed_events/{delay_id}/{action}`
///
/// MSC4140 as merged: authenticated, and scoped to the delay's owner.
async fn delayed_event_action_stable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((delay_id, action)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let action = crate::delayed::Action::parse(&action).ok_or_else(|| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            format!("no delayed-event action {action:?}"),
        )
    })?;
    act_on_delay(&state, &delay_id, Some(&identity.user_id), action, true).await
}

/// The body of MSC4140's scheduling endpoint.
#[derive(Debug, Deserialize)]
struct DelayedEventBody {
    delay_ms: Value,
    content: Option<Value>,
    state_key: Option<Value>,
    /// MSC4354's sticky duration, accepted in the body as well as the query,
    /// as Synapse does until the MSCs settle on one.
    #[serde(rename = "org.matrix.msc4354.sticky_duration_ms")]
    sticky: Option<u64>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/delayed_event/{event_type}/{txn_id}`,
/// and its unstable alias under `org.matrix.msc4140`.
///
/// MSC4140 as merged schedules through an endpoint of its own, with the
/// delay, the content and (for a state event) the state key in the body,
/// rather than through a query parameter on `/send` and `/state` -- which
/// stay served, because that is what shipping clients call. It is a
/// transaction like `/send`: a retried request returns the delay it made
/// the first time, rather than scheduling a second one, which for a
/// participant's leave would be a second leave nobody restarts.
fn schedule_delayed_event(
    state: &AppState,
    identity: &crate::accounts::Identity,
    (room_id, event_type, txn_id): (String, String, String),
    query: &DelayQuery,
    body: DelayedEventBody,
    stable: bool,
) -> Result<Json<Value>, MatrixError> {
    let delay_ms = body
        .delay_ms
        .as_u64()
        .filter(|delay| *delay > 0)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "delay_ms must be a whole number of milliseconds greater than zero",
            )
        })?;
    let content = match body.content {
        Some(Value::Object(content)) => Value::Object(content),
        Some(_) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "content must be an object",
            ));
        }
        None => return Err(MatrixError::missing_param("content is required")),
    };
    let state_key = match body.state_key {
        None => None,
        Some(Value::String(state_key)) => Some(state_key),
        Some(_) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "state_key must be a string",
            ));
        }
    };
    let sticky = match (query.sticky, body.sticky) {
        (Some(query), Some(body)) if query != body => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "conflicting values given for org.matrix.msc4354.sticky_duration_ms",
            ));
        }
        (query, body) => query.or(body),
    };
    let key = delayed_transaction_key(identity, &txn_id);
    if let Ok(Some(stored)) = spindle_store::ReadView::get(state.store.as_ref(), &key)
        && let Ok(delay_id) = String::from_utf8(stored)
    {
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    if !state
        .rooms
        .is_joined(&identity.user_id, &room_id)
        .unwrap_or(false)
    {
        return Err(MatrixError::forbidden(format!(
            "{} is not in {room_id}",
            identity.user_id
        )));
    }
    let delay_id = state
        .delayed
        .schedule(
            &room_id,
            &identity.user_id,
            &event_type,
            state_key.as_deref(),
            &content,
            delay_ms,
            sticky,
        )
        .map_err(|error| delay_error_as(error, stable))?;
    spindle_store::Store::put(state.store.as_ref(), &key, delay_id.as_bytes())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "delay_id": delay_id })))
}

/// Where a scheduling transaction is remembered: the device's transaction
/// row, in a namespace of its own. The spec scopes a transaction ID to one
/// device and one endpoint, so the same ID on `/send` is a different
/// transaction and must not answer with a delay.
fn delayed_transaction_key(identity: &crate::accounts::Identity, txn_id: &str) -> Vec<u8> {
    spindle_core::keys::transaction(
        &identity.user_id,
        &identity.device_id,
        &format!("\u{0}msc4140/{txn_id}"),
    )
}

async fn delayed_event_put_unstable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(path): axum::extract::Path<(String, String, String)>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(body): Json<DelayedEventBody>,
) -> Result<Json<Value>, MatrixError> {
    schedule_delayed_event(&state, &identity, path, &query, body, false)
}

async fn delayed_event_put_stable(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(path): axum::extract::Path<(String, String, String)>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(body): Json<DelayedEventBody>,
) -> Result<Json<Value>, MatrixError> {
    schedule_delayed_event(&state, &identity, path, &query, body, true)
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
fn rtc_transports(state: &AppState) -> Vec<Value> {
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

/// Remember which event a client transaction minted, both ways round:
/// the retry answers with it, and the event comes back to the device
/// with the transaction ID it chose.
pub(crate) fn record_transaction(
    state: &AppState,
    identity: &crate::accounts::Identity,
    txn_id: &str,
    event_id: &str,
) -> Result<Json<Value>, MatrixError> {
    let key = spindle_core::keys::transaction(&identity.user_id, &identity.device_id, txn_id);
    spindle_store::Store::put(state.store.as_ref(), &key, event_id.as_bytes())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // The inverse row, so the event comes back to this device with the
    // transaction ID it chose: that is how a client matches the remote
    // echo to the local one it is still showing.
    spindle_store::Store::put(
        state.store.as_ref(),
        &spindle_core::keys::transaction_echo(&identity.user_id, event_id),
        &spindle_core::keys::transaction_echo_value(&identity.device_id, txn_id),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "event_id": event_id })))
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

/// May `user_id` attach this server's name to `room_id` -- by listing it in
/// the directory, or by giving it an alias?
///
/// The rule: **a joined member may; a server admin may for any room.** One
/// rule for both, because both are the same act: a name this server hands to
/// strangers that resolves to the room. An earlier version of this comment
/// argued that an alias was different -- "a name somebody has to already
/// know" -- and let any account claim any free alias for any room. That was
/// backwards: `/join/#name:server` is precisely how strangers find rooms, so
/// an alias is the more published of the two, and it let anyone who had
/// learnt a room ID hang `#official:example.org` on it from outside. #268
/// named the disagreement; requiring membership for both makes the person
/// answerable for the room they are naming, and matches what Sytest expects
/// of a regular user, who joins before claiming.
///
/// The spec explicitly leaves this to the server ("servers may choose to
/// impose additional restrictions"), so this is a policy choice rather than a
/// reading of the spec, and it is written here so it can be argued with.
/// `action` names the act in the refusal, so a client learns what was refused
/// without learning anything about the room.
fn may_advertise(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    action: &str,
) -> Result<(), MatrixError> {
    if state
        .rooms
        .is_joined(user_id, room_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        return Ok(());
    }
    let admin = crate::admin::is_server_admin(state, user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if admin {
        return Ok(());
    }
    Err(MatrixError::forbidden(format!(
        "only a member of the room, or a server admin, may {action}"
    )))
}

#[derive(Debug, Deserialize)]
struct VisibilityRequest {
    visibility: String,
}

/// `PUT /_matrix/client/v3/directory/list/room/{room_id}`
async fn set_room_visibility(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<VisibilityRequest>,
) -> Result<Json<Value>, MatrixError> {
    // A room that does not exist cannot be advertised. Checked before the
    // permission test so that "no such room" does not come back as a refusal,
    // which would tell a stranger the room exists and they simply are not in
    // it.
    state.rooms.exists(&room_id).map_err(room_error)?;
    may_advertise(
        &state,
        &identity.user_id,
        &room_id,
        "change its directory visibility",
    )?;

    match request.visibility.as_str() {
        "public" => state
            .directory
            .publish(&room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?,
        "private" => state
            .directory
            .unpublish(&room_id)
            .map_err(|error| directory_error(&error))?,
        other => {
            return Err(MatrixError::bad_json(format!(
                "visibility must be \"public\" or \"private\", not {other:?}"
            )));
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/directory/list/room/{room_id}`
///
/// Unauthenticated, as the spec has it: the directory is public, so whether a
/// room is in it is public too.
async fn get_room_visibility(
    State(state): State<AppState>,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let published = state
        .directory
        .is_published(&room_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({
        "visibility": if published { "public" } else { "private" },
    })))
}

/// One page of the room directory.
#[derive(Debug, Default, Deserialize)]
struct PublicRoomsQuery {
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
struct PublicRoomsRequest {
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
fn directory_page(
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

/// Another server's directory is that server's to serve.
///
/// Refused rather than silently answered from our own list, which would show
/// a client our rooms under someone else's name. The federated read is a
/// follow-up.
fn refuse_remote_directory(server: Option<&String>, ours: &str) -> Result<(), MatrixError> {
    match server {
        Some(name) if name != ours => Err(MatrixError::new(
            StatusCode::NOT_IMPLEMENTED,
            "M_UNRECOGNIZED",
            "this server does not proxy another server's room directory yet",
        )),
        _ => Ok(()),
    }
}

/// `GET /_matrix/client/v3/publicRooms`
async fn public_rooms(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<PublicRoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    refuse_remote_directory(query.server.as_ref(), &state.config.server.name)?;
    directory_page(&state, "", query.limit, query.since.as_deref(), None, &[])
}

/// `POST /_matrix/client/v3/publicRooms`
///
/// Authenticated, unlike the GET form: the spec has it that way, and the
/// filter is the reason -- a search term is a thing a user types, so it is
/// attributable.
async fn public_rooms_filtered(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<PublicRoomsRequest>,
) -> Result<Json<Value>, MatrixError> {
    refuse_remote_directory(request.server.as_ref(), &state.config.server.name)?;
    directory_page(
        &state,
        &identity.user_id,
        request.limit,
        request.since.as_deref(),
        request.filter.generic_search_term.as_deref(),
        &request.filter.room_types,
    )
}

#[derive(Debug, Deserialize)]
struct UserSearchRequest {
    search_term: String,
    limit: Option<usize>,
}

/// The default and maximum number of users one search returns.
const USER_SEARCH_LIMIT: usize = 10;

const USER_SEARCH_LIMIT_MAX: usize = 50;

/// Everyone `searcher` is allowed to find.
///
/// The spec sets a *floor* rather than a rule -- results "should at least"
/// cover users you share a room with and users in public rooms -- and
/// explicitly leaves the rest to the server. Spindle serves exactly that floor
/// and nothing wider:
///
/// - **someone you share a joined room with**, because you can already see
///   their name and avatar in that room's member list, so the directory
///   reveals nothing new; and
/// - **someone joined to a published room**, because they chose to be in a
///   room this server advertises to strangers.
///
/// The rejected alternative is "every account on the server", which several
/// homeservers offer behind a config flag. It turns the directory into a user
/// enumeration endpoint: an attacker with one account learns every localpart,
/// and a user who joined no public rooms never consented to that. Making it
/// opt-in would push the decision onto operators who mostly will not read it.
///
/// The cost is proportional to the searcher's rooms plus the published ones,
/// not to the number of accounts -- which is the right shape, but it is still
/// a scan per request, and it is the thing to replace with a maintained index
/// if the directory ever gets hot.
fn visible_users(
    state: &AppState,
    searcher: &str,
) -> Result<std::collections::BTreeSet<String>, MatrixError> {
    let mut visible = std::collections::BTreeSet::new();
    let mut rooms = state
        .rooms
        .joined(searcher)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    rooms.extend(
        state
            .directory
            .published()
            .map_err(|error| directory_error(&error))?,
    );
    rooms.sort();
    rooms.dedup();

    for room_id in rooms {
        // A room in the index that cannot be read is skipped, not fatal: one
        // stale pointer must not make search stop working.
        let Ok(members) = state.rooms.joined_member_ids(&room_id) else {
            continue;
        };
        visible.extend(members.iter().cloned());
    }
    visible.remove(searcher);
    Ok(visible)
}

/// Does `term` match this user?
///
/// Matched against the localpart and the display name, case-insensitively.
/// Not against the full user ID, because every local ID ends in the server
/// name -- searching for it would return the whole directory, which reads as
/// a bug rather than a feature.
fn user_matches(term: &str, user_id: &str, displayname: Option<&str>) -> bool {
    let needle = term.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let localpart = user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':').map(|(local, _)| local))
        .unwrap_or(user_id);
    localpart.to_lowercase().contains(&needle)
        || displayname.is_some_and(|name| name.to_lowercase().contains(&needle))
}

/// `POST /_matrix/client/v3/search`, the body.
#[derive(Deserialize)]
struct SearchRequest {
    search_categories: SearchCategories,
}

#[derive(Deserialize)]
struct SearchCategories {
    room_events: Option<RoomEventsCriteria>,
}

#[derive(Deserialize)]
struct RoomEventsCriteria {
    search_term: String,
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    filter: SearchFilter,
    order_by: Option<String>,
    event_context: Option<SearchContext>,
    #[serde(default)]
    include_state: bool,
}

/// The spec's `RoomEventFilter`, the parts a search can honour.
#[derive(Default, Deserialize)]
struct SearchFilter {
    limit: Option<usize>,
    rooms: Option<Vec<String>>,
    #[serde(default)]
    not_rooms: Vec<String>,
    senders: Option<Vec<String>>,
    #[serde(default)]
    not_senders: Vec<String>,
    types: Option<Vec<String>>,
    #[serde(default)]
    not_types: Vec<String>,
}

#[derive(Deserialize)]
struct SearchContext {
    before_limit: Option<usize>,
    after_limit: Option<usize>,
    #[serde(default)]
    include_profile: bool,
}

#[derive(Deserialize)]
struct SearchQuery {
    next_batch: Option<String>,
}

/// The default and maximum number of results one search page returns.
const SEARCH_LIMIT: usize = 10;

const SEARCH_LIMIT_MAX: usize = 100;

/// The spec's default for each side of a result's context.
const SEARCH_CONTEXT_EACH_SIDE: usize = 5;

/// Where each room's next page starts, as the opaque `next_batch` a client
/// hands back: `li:room_id` pairs joined by `;`, the position first because
/// a room ID has colons of its own. Per room rather than one global
/// position because positions are per room, and a page that stops in the
/// middle of one room's hits must resume exactly there while the other
/// rooms resume where they were.
fn parse_search_cursor(token: &str) -> Result<BTreeMap<String, i64>, MatrixError> {
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

fn search_cursor(cursor: &BTreeMap<String, i64>) -> String {
    cursor
        .iter()
        .map(|(room_id, li)| format!("{li}:{room_id}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// The value at a dotted path into an event (`content.body`), if it is text.
fn text_at<'a>(event: &'a Value, path: &str) -> Option<&'a str> {
    path.split('.')
        .try_fold(event, |node, part| node.get(part))
        .and_then(Value::as_str)
}

/// Does `event` pass the search's filter and carry the term under one of
/// its keys? Case-insensitive containment, which is what "search basics"
/// means here: no stemming, no ranking, no index.
fn search_matches(event: &Value, needle: &str, keys: &[String], filter: &SearchFilter) -> bool {
    let sender = event["sender"].as_str().unwrap_or_default();
    let event_type = event["type"].as_str().unwrap_or_default();
    if filter
        .senders
        .as_ref()
        .is_some_and(|senders| !senders.iter().any(|wanted| wanted == sender))
        || filter.not_senders.iter().any(|unwanted| unwanted == sender)
        || filter
            .types
            .as_ref()
            .is_some_and(|types| !types.iter().any(|wanted| wanted == event_type))
        || filter
            .not_types
            .iter()
            .any(|unwanted| unwanted == event_type)
    {
        return false;
    }
    keys.iter()
        .any(|key| text_at(event, key).is_some_and(|text| text.to_lowercase().contains(needle)))
}

/// One search hit, with where it came from.
struct SearchHit {
    pub(crate) room_id: String,
    pub(crate) event: crate::rooms::TimelineEvent,
}

/// What one walk of the rooms produced: the page's hits, the scope each
/// searched room was read under, and whether there is a page after this.
struct SearchPage {
    hits: Vec<SearchHit>,
    scopes: BTreeMap<String, ReadScope>,
    more: bool,
}

fn origin_server_ts(hit: &SearchHit) -> i64 {
    hit.event.json["origin_server_ts"].as_i64().unwrap_or(0)
}

/// `POST /_matrix/client/v3/search`
///
/// Room-event search over the rooms the caller may read: by default the
/// rooms they are joined to, or the `filter.rooms` they name, each under
/// its own [`crate::rooms::Rooms::read_scope`] so a former member searches only the stretch
/// they may read and a room the caller may not see contributes nothing
/// rather than refusing the whole search. Newest first, by
/// `origin_server_ts` across rooms and by position within one; `rank` is
/// the same order, since nothing here scores.
///
/// `count` is the number on this page. The spec calls the field an
/// approximation of the total, and a true total would mean walking every
/// room to its end on every search, which is the one cost this endpoint
/// declines: a page costs the rooms it walks to fill itself, and no more.
async fn search(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>,
    Json(request): Json<SearchRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(criteria) = request.search_categories.room_events else {
        return Ok(Json(json!({ "search_categories": {} })));
    };
    let needle = criteria.search_term.trim().to_lowercase();
    if needle.is_empty() {
        return Err(MatrixError::bad_json("search_term is empty"));
    }
    if let Some(order) = criteria.order_by.as_deref()
        && order != "recent"
        && order != "rank"
    {
        return Err(MatrixError::bad_json(format!(
            "order_by must be recent or rank, not {order}"
        )));
    }
    let keys = if criteria.keys.is_empty() {
        vec!["content.body".to_owned()]
    } else {
        criteria.keys.clone()
    };
    let limit = criteria
        .filter
        .limit
        .unwrap_or(SEARCH_LIMIT)
        .clamp(1, SEARCH_LIMIT_MAX);
    let mut cursor = match query.next_batch.as_deref() {
        Some(token) => parse_search_cursor(token)?,
        None => BTreeMap::new(),
    };

    let SearchPage { hits, scopes, more } = search_rooms(
        &state,
        &identity.user_id,
        &criteria,
        &needle,
        &keys,
        limit,
        &mut cursor,
    )?;

    let results: Vec<Value> = hits
        .iter()
        .map(|hit| {
            let mut event = hit.event.json.clone();
            if let Some(object) = event.as_object_mut() {
                object.insert("event_id".to_owned(), json!(hit.event.event_id));
                object.insert("room_id".to_owned(), json!(hit.room_id));
            }
            let event = as_seen_by(&state, &hit.room_id, &identity, event);
            let mut result = json!({ "rank": 1.0, "result": event });
            if let Some(wanted) = &criteria.event_context
                && let Some(scope) = scopes.get(&hit.room_id)
            {
                result["context"] = search_context(&state, &identity.user_id, hit, wanted, scope);
            }
            result
        })
        .collect();

    let mut room_events = serde_json::Map::new();
    room_events.insert("count".to_owned(), json!(results.len()));
    room_events.insert(
        "highlights".to_owned(),
        json!(needle.split_whitespace().collect::<Vec<_>>()),
    );
    room_events.insert("results".to_owned(), Value::Array(results));
    if more {
        room_events.insert("next_batch".to_owned(), json!(search_cursor(&cursor)));
    }
    if criteria.include_state {
        room_events.insert(
            "state".to_owned(),
            Value::Object(search_state(&state, &identity.user_id, &hits, &scopes)?),
        );
    }
    Ok(Json(json!({
        "search_categories": { "room_events": Value::Object(room_events) }
    })))
}

/// Walk every room the search covers and gather its hits: the caller's
/// joined rooms, or the `filter.rooms` named, each under its own
/// [`crate::rooms::Rooms::read_scope`], and each resumed from `cursor`. Returns the hits
/// newest first and cut to `limit`, the scope of each room that was
/// searched (the context needs it again), and whether a further page
/// exists; `cursor` is advanced to where that page starts.
fn search_rooms(
    state: &AppState,
    user_id: &str,
    criteria: &RoomEventsCriteria,
    needle: &str,
    keys: &[String],
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> Result<SearchPage, MatrixError> {
    let rooms = match &criteria.filter.rooms {
        Some(rooms) => rooms.clone(),
        None => state.rooms.joined(user_id).map_err(room_error)?,
    };
    let mut scopes: BTreeMap<String, ReadScope> = BTreeMap::new();
    let mut hits: Vec<SearchHit> = Vec::new();
    let mut more = false;
    for room_id in rooms {
        if criteria.filter.not_rooms.contains(&room_id) {
            continue;
        }
        // A room the caller may not read contributes nothing, rather than
        // refusing the search: naming it must not tell them it exists.
        let Ok(scope) = state.rooms.read_scope(user_id, &room_id) else {
            continue;
        };
        let matches = |event: &Value| search_matches(event, needle, keys, &criteria.filter);
        let (found, next) = state
            .rooms
            .reader_with(user_id, &room_id, scope.clone())
            .search(cursor.get(&room_id).copied(), limit, &matches)
            .map_err(room_error)?;
        more |= next.is_some();
        hits.extend(found.into_iter().map(|event| SearchHit {
            room_id: room_id.clone(),
            event,
        }));
        scopes.insert(room_id, scope);
    }
    more |= page_newest_first(&mut hits, limit, cursor);
    Ok(SearchPage { hits, scopes, more })
}

/// Cut a walk's hits to one page, newest first across rooms, and advance
/// the per-room cursor to where the next page starts. Returns whether the
/// cut left anything behind.
///
/// Ties by room and then position, so a page boundary falls in the same
/// place however the rooms were walked. Each room resumes below the oldest
/// position taken from it; a room nothing was taken from resumes where it
/// was, and finds the same hits again -- which is what makes the pages
/// neither skip nor repeat.
fn page_newest_first(
    hits: &mut Vec<SearchHit>,
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> bool {
    hits.sort_by(|a, b| {
        origin_server_ts(b)
            .cmp(&origin_server_ts(a))
            .then_with(|| a.room_id.cmp(&b.room_id))
            .then_with(|| b.event.li.cmp(&a.event.li))
    });
    let more = hits.len() > limit;
    hits.truncate(limit);
    for hit in hits.iter() {
        cursor
            .entry(hit.room_id.clone())
            .and_modify(|from| *from = (*from).min(hit.event.li))
            .or_insert(hit.event.li);
    }
    more
}

#[derive(Deserialize)]
struct NotificationsQuery {
    from: Option<String>,
    limit: Option<usize>,
    only: Option<String>,
}

/// The default number of notifications one page returns.
const NOTIFICATIONS_LIMIT: usize = 50;

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

/// `GET /_matrix/client/v3/notifications`
///
/// The events in the caller's joined rooms that their push rules say to
/// notify about, newest first, with whether each is read. The same walk
/// as `/search` -- there is no notification table; the rules are put to
/// every event the walk passes, which is what the rules are for -- and the
/// same per-room cursor in `next_token`. "Newest" is the server-wide
/// stream order, not `origin_server_ts`: see [`page_by_stream`] for why.
/// A reader's own events never notify,
/// whatever the rules say: the spec's one rule the ruleset does not
/// spell out. `only=highlight` keeps the hits whose actions carry the
/// highlight tweak.
async fn notifications(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<NotificationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let limit = query
        .limit
        .unwrap_or(NOTIFICATIONS_LIMIT)
        .clamp(1, SEARCH_LIMIT_MAX);
    let highlights_only = match query.only.as_deref() {
        None => false,
        Some("highlight") => true,
        Some(other) => {
            return Err(MatrixError::bad_json(format!(
                "only must be highlight, not {other}"
            )));
        }
    };
    let (snapshot, mut cursor) = match query.from.as_deref() {
        Some(token) => parse_notifications_cursor(token)?,
        None => (None, BTreeMap::new()),
    };
    // A token from before the snapshot existed resumes against the stream
    // as it stands now; the token handed back carries that position.
    let snapshot = snapshot.unwrap_or_else(|| state.rooms.stream_position());
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    let profile = state
        .profiles
        .get(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let display_name = profile.displayname.as_deref();

    let mut rooms: BTreeMap<String, RoomRuleContext> = BTreeMap::new();
    let mut hits: Vec<(u64, SearchHit)> = Vec::new();
    let mut more = false;
    for room_id in state.rooms.joined(&identity.user_id).map_err(room_error)? {
        let Ok(scope) = state.rooms.read_scope(&identity.user_id, &room_id) else {
            continue;
        };
        let room = RoomRuleContext::of(&state, &room_id)?;
        let context = room.for_reader(&identity.user_id, display_name, &room_id);
        let notifies = |event: &Value| {
            event["sender"] != identity.user_id.as_str()
                && crate::push_rules::evaluate(&ruleset, event, &context).is_some_and(|actions| {
                    !highlights_only || crate::push_rules::is_highlight(&actions)
                })
        };
        let order = RoomStreamOrder::new(state.rooms.stream_rows(&room_id).map_err(room_error)?);
        let from = match (cursor.get(&room_id).copied(), order.bound(snapshot)) {
            (Some(resume), Some(bound)) => Some(resume.min(bound)),
            (resume, bound) => resume.or(bound),
        };
        let (found, next) = state
            .rooms
            .reader_with(&identity.user_id, &room_id, scope.clone())
            .search(from, limit, &notifies)
            .map_err(room_error)?;
        more |= next.is_some();
        hits.extend(found.into_iter().map(|event| {
            let key = order.key(event.li);
            (
                key,
                SearchHit {
                    room_id: room_id.clone(),
                    event,
                },
            )
        }));
        rooms.insert(room_id, room);
    }
    more |= page_by_stream(&mut hits, limit, &mut cursor);
    let hits: Vec<SearchHit> = hits.into_iter().map(|(_, hit)| hit).collect();

    let notifications = render_notifications(
        &state,
        &identity.user_id,
        display_name,
        &ruleset,
        &rooms,
        &hits,
    )?;
    let mut body = serde_json::Map::new();
    body.insert("notifications".to_owned(), Value::Array(notifications));
    if more {
        body.insert(
            "next_token".to_owned(),
            json!(notifications_cursor(snapshot, &cursor)),
        );
    }
    Ok(Json(Value::Object(body)))
}

/// `/notifications`' `next_token`: `s<stream position>;` and then the
/// `/search` cursor. The position is where the first page stood; every
/// later page is cut to it, so an event or a room arriving mid-walk waits
/// for the next walk instead of landing out of order on a later page.
///
/// A token from before the position was added is the bare `/search`
/// cursor. It still parses, with no position, and resumes each room where
/// it says (no repeats, no skips within a room it names).
fn parse_notifications_cursor(
    token: &str,
) -> Result<(Option<u64>, BTreeMap<String, i64>), MatrixError> {
    // A cursor pair starts with a position (a digit or `-`), so a leading
    // `s` is unambiguous.
    let Some(rest) = token.strip_prefix('s') else {
        return Ok((None, parse_search_cursor(token)?));
    };
    let (position, rooms) = rest.split_once(';').unwrap_or((rest, ""));
    let position = position
        .parse::<u64>()
        .map_err(|_| MatrixError::bad_json("from is not a notifications token"))?;
    Ok((Some(position), parse_search_cursor(rooms)?))
}

fn notifications_cursor(snapshot: u64, cursor: &BTreeMap<String, i64>) -> String {
    format!("s{snapshot};{}", search_cursor(cursor))
}

/// One room's events placed in the server-wide stream order.
///
/// Each event's key is the highest stream id at or below its position in
/// the room. An indexed event gets its own id (ids rise with position, as
/// both are assigned under the room's append lock); an event with no index
/// row inherits the one below it. Taking the running maximum makes the key
/// never fall as the position rises, which is what [`page_by_stream`]
/// needs, whatever the index holds.
struct RoomStreamOrder {
    /// `(li, key)`, ascending in both.
    rows: Vec<(i64, u64)>,
}

impl RoomStreamOrder {
    pub(crate) fn new(mut rows: Vec<(i64, u64)>) -> Self {
        rows.sort_unstable();
        let mut high = 0;
        for row in &mut rows {
            high = high.max(row.1);
            row.1 = high;
        }
        Self { rows }
    }

    pub(crate) fn key(&self, li: i64) -> u64 {
        match self.rows.partition_point(|(at, _)| *at <= li) {
            0 => 0,
            n => self.rows[n - 1].1,
        }
    }

    /// The exclusive `from` that keeps a walk to the events at or before
    /// stream position `snapshot`, or `None` when that is all of them.
    pub(crate) fn bound(&self, snapshot: u64) -> Option<i64> {
        let first_after = self.rows.partition_point(|(_, key)| *key <= snapshot);
        self.rows.get(first_after).map(|(li, _)| *li)
    }
}

/// Cut a `/notifications` walk to one page and advance the per-room cursor,
/// as [`page_newest_first`] does for `/search`, but newest first by stream
/// key (see [`RoomStreamOrder`]), then room, then position: a total order.
///
/// Not `origin_server_ts`. Each room is walked by position and resumed
/// below the oldest position taken from it, so the merge across rooms is
/// exact only if the sort key never rises as the position falls. A
/// timestamp breaks that: a federated event can carry any `ts`, and the
/// local clock can step back. Then a page takes
/// an older position first, the cursor drops below a newer one, and that
/// event is never served (#635). The stream key cannot do this.
fn page_by_stream(
    hits: &mut Vec<(u64, SearchHit)>,
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> bool {
    hits.sort_by(|(a_key, a), (b_key, b)| {
        b_key
            .cmp(a_key)
            .then_with(|| a.room_id.cmp(&b.room_id))
            .then_with(|| b.event.li.cmp(&a.event.li))
    });
    let more = hits.len() > limit;
    hits.truncate(limit);
    for (_, hit) in hits.iter() {
        cursor
            .entry(hit.room_id.clone())
            .and_modify(|from| *from = (*from).min(hit.event.li))
            .or_insert(hit.event.li);
    }
    more
}

/// One `/notifications` entry per hit: the rule's actions, the event with
/// its IDs, and whether the caller's `m.read` receipt is at or past it.
fn render_notifications(
    state: &AppState,
    user_id: &str,
    display_name: Option<&str>,
    ruleset: &Value,
    rooms: &BTreeMap<String, RoomRuleContext>,
    hits: &[SearchHit],
) -> Result<Vec<Value>, MatrixError> {
    let mut notifications = Vec::with_capacity(hits.len());
    for hit in hits {
        let room = &rooms[&hit.room_id];
        let actions = crate::push_rules::evaluate(
            ruleset,
            &hit.event.json,
            &room.for_reader(user_id, display_name, &hit.room_id),
        )
        .unwrap_or_default();
        let read = state
            .rooms
            .receipt(&hit.room_id, user_id, "m.read")
            .map_err(room_error)?
            .is_some_and(|receipt| hit.event.li <= receipt.li);
        let mut event = hit.event.json.clone();
        if let Some(object) = event.as_object_mut() {
            object.insert("event_id".to_owned(), json!(hit.event.event_id));
            object.insert("room_id".to_owned(), json!(hit.room_id));
        }
        notifications.push(json!({
            "actions": actions,
            "event": event,
            "read": read,
            "room_id": hit.room_id,
            "ts": origin_server_ts(hit),
        }));
    }
    Ok(notifications)
}

/// The current state of each room with a hit, for `include_state`: the
/// present for a member, the room as it stood at the bound for a former
/// one, exactly as `/state` answers.
fn search_state(
    state: &AppState,
    user_id: &str,
    hits: &[SearchHit],
    scopes: &BTreeMap<String, ReadScope>,
) -> Result<serde_json::Map<String, Value>, MatrixError> {
    let mut states = serde_json::Map::new();
    for hit in hits {
        if states.contains_key(&hit.room_id) {
            continue;
        }
        let Some(scope) = scopes.get(&hit.room_id) else {
            continue;
        };
        // The gate already ran once per room to build `scopes`; the reader
        // carries that answer rather than asking again.
        let rendered = state
            .rooms
            .reader_with(user_id, &hit.room_id, scope.clone())
            .state_serialized()
            .map_err(room_error)?;
        let room_state = serde_json::from_str::<Value>(&rendered)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        states.insert(hit.room_id.clone(), room_state);
    }
    Ok(states)
}

/// The events around one hit, as `/context` would show them, trimmed to
/// what the search asked for on each side. A hit whose context cannot be
/// read is a hit without context rather than a failed search.
fn search_context(
    state: &AppState,
    user_id: &str,
    hit: &SearchHit,
    wanted: &SearchContext,
    scope: &ReadScope,
) -> Value {
    let before_limit = wanted.before_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let after_limit = wanted.after_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let Ok(context) = state
        .rooms
        .reader_with(user_id, &hit.room_id, scope.clone())
        .context(&hit.event.event_id, before_limit, after_limit)
    else {
        return Value::Null;
    };
    let events_before = context.events_before;
    let events_after = context.events_after;
    let mut out = json!({
        "events_before": events_before,
        "events_after": events_after,
        "start": crate::tokens::Pagination(context.start).to_string(),
        "end": crate::tokens::Pagination(context.end).to_string(),
    });
    if wanted.include_profile {
        // The profile each sender had at the hit, from the state the
        // context already carries.
        let mut profiles = serde_json::Map::new();
        let senders = std::iter::once(&hit.event.json)
            .chain(out["events_before"].as_array().into_iter().flatten())
            .chain(out["events_after"].as_array().into_iter().flatten())
            .filter_map(|event| event["sender"].as_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        for sender in senders {
            let member = context.state.iter().find(|event| {
                event["type"] == "m.room.member" && event["state_key"] == sender.as_str()
            });
            let mut profile = serde_json::Map::new();
            if let Some(name) = member.and_then(|event| event["content"]["displayname"].as_str()) {
                profile.insert("displayname".to_owned(), json!(name));
            }
            if let Some(url) = member.and_then(|event| event["content"]["avatar_url"].as_str()) {
                profile.insert("avatar_url".to_owned(), json!(url));
            }
            profiles.insert(sender, Value::Object(profile));
        }
        out["profile_info"] = Value::Object(profiles);
    }
    out
}

/// `POST /_matrix/client/v3/user_directory/search`
async fn user_directory_search(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<UserSearchRequest>,
) -> Result<Json<Value>, MatrixError> {
    let limit = request
        .limit
        .unwrap_or(USER_SEARCH_LIMIT)
        .clamp(1, USER_SEARCH_LIMIT_MAX);

    let mut results = Vec::new();
    let mut limited = false;
    for user_id in visible_users(&state, &identity.user_id)? {
        let profile = state.profiles.get(&user_id).unwrap_or_default();
        if !user_matches(
            &request.search_term,
            &user_id,
            profile.displayname.as_deref(),
        ) {
            continue;
        }
        // One past the limit is how `limited` is known: the spec asks whether
        // results were cut, which cannot be answered by stopping exactly at
        // the limit.
        if results.len() == limit {
            limited = true;
            break;
        }
        let mut entry = serde_json::Map::new();
        entry.insert("user_id".to_owned(), json!(user_id));
        if let Some(name) = profile.displayname {
            entry.insert("display_name".to_owned(), json!(name));
        }
        if let Some(avatar) = profile.avatar_url {
            entry.insert("avatar_url".to_owned(), json!(avatar));
        }
        results.push(Value::Object(entry));
    }

    Ok(Json(json!({ "results": results, "limited": limited })))
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

/// `POST /_matrix/media/v1/create` (spec v1.7)
///
/// An `mxc://` URI ahead of its bytes, so a client can put the URI in an
/// event while the upload is still going.
async fn create_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    // Counted here, on the mint, and not again on the `PUT` that fills it:
    // a create and its fill are one upload, as `POST /upload` is.
    limit_write(&state, Budget::MediaUpload, &identity.user_id)?;
    let (media_id, unused_expires_at) = state
        .media
        .reserve(&identity.user_id)
        .map_err(|error| media_error(&error))?;
    Ok(Json(json!({
        "content_uri": state.media.mxc(&media_id),
        "unused_expires_at": unused_expires_at,
    })))
}

/// `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` (spec v1.7)
async fn upload_reserved_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    if !state.media.is_ours(&server_name) {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{server_name} is not this server"),
        ));
    }
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    state
        .media
        .put_reserved(
            &media_id,
            &body,
            &content_type,
            query.filename.as_deref(),
            &identity.user_id,
            upload_quota(&state, &identity.user_id)?,
        )
        .await
        .map_err(|error| upload_error(&state, &error))?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`
async fn federation_event_auth(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    crate::inbound::federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    let auth_chain = state
        .rooms
        .auth_chain(&room_id, &event_id)
        .map_err(room_error)?;
    Ok(Json(json!({ "auth_chain": auth_chain })))
}

/// `GET /_matrix/federation/v1/publicRooms`
///
/// This server's published directory, for a peer that asks. The same
/// page a client gets, since the directory is public by definition.
async fn federation_public_rooms(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<PublicRoomsQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    directory_page(&state, "", query.limit, query.since.as_deref(), None, &[])
}

/// `POST /_matrix/federation/v1/publicRooms`
async fn federation_public_rooms_filtered(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    federation_origin(&state, &headers, "POST", &uri, Some(&body)).await?;
    let filter: PublicRoomsRequest =
        serde_json::from_value(body).map_err(|error| MatrixError::bad_json(error.to_string()))?;
    directory_page(
        &state,
        "",
        filter.limit,
        filter.since.as_deref(),
        filter.filter.generic_search_term.as_deref(),
        &filter.filter.room_types,
    )
}

#[derive(Debug, Default, Deserialize)]
struct FederationHierarchyQuery {
    #[serde(default)]
    suggested_only: bool,
}

/// `GET /_matrix/federation/v1/hierarchy/{roomId}` (spec v1.2)
///
/// One level of a space for a peer walking it: the space and its direct
/// children, each as a room summary with its own `m.space.child` state.
/// A child the requesting server may not see (not public, not knockable,
/// not world-readable, and no member of theirs in it) is named in
/// `inaccessible_children` rather than described.
async fn federation_hierarchy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<FederationHierarchyQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let origin = federation_origin(&state, &headers, "GET", &uri, None).await?;
    let visible = |room: &str| -> Option<crate::rooms::RoomSummary> {
        let summary = state.rooms.summary(room).ok()?;
        if state.rooms.server_in_room(room, &origin).unwrap_or(false) {
            return Some(summary);
        }
        let open = summary.world_readable
            || matches!(summary.join_rule.as_deref(), Some("public" | "knock"));
        open.then_some(summary)
    };
    let Some(root) = visible(&room_id) else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "the room is not known here, or not visible to the requesting server",
        ));
    };
    let with_children = |summary: &crate::rooms::RoomSummary| -> Value {
        let mut entry = match chunk_of(summary) {
            Value::Object(entry) => entry,
            _ => serde_json::Map::new(),
        };
        let children = space_children(&state, &summary.room_id, query.suggested_only);
        entry.insert("children_state".to_owned(), Value::Array(children));
        entry.insert("allowed_room_ids".to_owned(), json!([]));
        Value::Object(entry)
    };
    let parent = with_children(&root);
    let mut children = Vec::new();
    let mut inaccessible = Vec::new();
    for child in space_children(&state, &room_id, query.suggested_only) {
        let Some(child_id) = child["state_key"].as_str() else {
            continue;
        };
        match visible(child_id) {
            Some(summary) => children.push(with_children(&summary)),
            None => inaccessible.push(json!(child_id)),
        }
    }
    Ok(Json(json!({
        "room": parent,
        "children": children,
        "inaccessible_children": inaccessible,
    })))
}

#[cfg(test)]
mod notifications_order_tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        RoomStreamOrder, SearchHit, notifications_cursor, page_by_stream,
        parse_notifications_cursor,
    };

    /// One stored event: its room, position, stream id and timestamp.
    #[derive(Clone)]
    struct Stored {
        room: &'static str,
        li: i64,
        stream: u64,
        ts: i64,
    }

    /// Events in arrival order across three rooms, every one stamped the
    /// same millisecond (the tie the CI flake hit), and one late federated
    /// event in `!c` whose `ts` is older than everything else (the case a
    /// timestamp order skips).
    fn history() -> Vec<Stored> {
        let rooms = [
            "!c:x", "!a:x", "!b:x", "!a:x", "!c:x", "!b:x", "!b:x", "!a:x", "!c:x",
        ];
        let mut next_li: BTreeMap<&str, i64> = BTreeMap::new();
        rooms
            .iter()
            .enumerate()
            .map(|(n, room)| {
                let li = next_li.entry(room).or_insert(10);
                *li += 1;
                Stored {
                    room,
                    li: *li,
                    stream: n as u64 + 1,
                    ts: if n == 8 { 5 } else { 1_000 },
                }
            })
            .collect()
    }

    /// The room walk the store does: the newest `limit` positions below
    /// `from`, and whether more remain.
    fn walk(
        history: &[Stored],
        room: &str,
        from: Option<i64>,
        limit: usize,
    ) -> (Vec<Stored>, bool) {
        let mut below: Vec<Stored> = history
            .iter()
            .filter(|event| event.room == room && from.is_none_or(|from| event.li < from))
            .cloned()
            .collect();
        below.sort_by_key(|event| std::cmp::Reverse(event.li));
        let more = below.len() > limit;
        below.truncate(limit);
        (below, more)
    }

    fn hit(event: &Stored) -> SearchHit {
        SearchHit {
            room_id: event.room.to_owned(),
            event: crate::rooms::TimelineEvent {
                event_id: format!("${}", event.stream),
                li: event.li,
                json: json!({ "origin_server_ts": event.ts }),
            },
        }
    }

    /// Page through `history` at `limit` the way the handler does, a token
    /// round trip between pages, and return the stream ids served. `after`
    /// arrives once the first page is out.
    fn page_through(history: &[Stored], after: &[Stored], limit: usize) -> Vec<u64> {
        let mut store = history.to_vec();
        let mut token: Option<String> = None;
        let mut served = Vec::new();
        for _ in 0..=store.len() + after.len() {
            let (snapshot, mut cursor) = match &token {
                Some(token) => parse_notifications_cursor(token).unwrap(),
                None => (None, BTreeMap::new()),
            };
            let snapshot =
                snapshot.unwrap_or_else(|| store.iter().map(|e| e.stream).max().unwrap_or(0));
            let mut hits = Vec::new();
            let mut more = false;
            for room in ["!a:x", "!b:x", "!c:x", "!d:x"] {
                let order = RoomStreamOrder::new(
                    store
                        .iter()
                        .filter(|e| e.room == room)
                        .map(|e| (e.li, e.stream))
                        .collect(),
                );
                let from = match (cursor.get(room).copied(), order.bound(snapshot)) {
                    (Some(resume), Some(bound)) => Some(resume.min(bound)),
                    (resume, bound) => resume.or(bound),
                };
                let (found, next) = walk(&store, room, from, limit);
                more |= next;
                hits.extend(found.iter().map(|e| (order.key(e.li), hit(e))));
            }
            more |= page_by_stream(&mut hits, limit, &mut cursor);
            served.extend(hits.iter().map(|(key, _)| *key));
            if token.is_none() {
                store.extend_from_slice(after);
            }
            if !more {
                return served;
            }
            token = Some(notifications_cursor(snapshot, &cursor));
        }
        panic!("paging at {limit} did not end");
    }

    #[test]
    fn every_page_size_serves_the_stream_newest_first_exactly_once() {
        let history = history();
        let expected: Vec<u64> = (1..=history.len() as u64).rev().collect();
        for limit in 1..=history.len() + 1 {
            assert_eq!(
                page_through(&history, &[], limit),
                expected,
                "limit {limit}"
            );
        }
    }

    #[test]
    fn what_arrives_mid_walk_waits_for_the_next_walk() {
        let history = history();
        let next = history.len() as u64 + 1;
        // A newer event in a room already walked, and one in a room the
        // first page never saw.
        let after = [
            Stored {
                room: "!a:x",
                li: 100,
                stream: next,
                ts: 2_000,
            },
            Stored {
                room: "!d:x",
                li: 1,
                stream: next + 1,
                ts: 2_000,
            },
        ];
        let expected: Vec<u64> = (1..=history.len() as u64).rev().collect();
        for limit in 1..=history.len() {
            assert_eq!(
                page_through(&history, &after, limit),
                expected,
                "limit {limit}"
            );
        }
    }

    #[test]
    fn an_event_with_no_index_row_takes_the_key_below_it() {
        let order = RoomStreamOrder::new(vec![(5, 40), (2, 10), (8, 30)]);
        assert_eq!(order.key(1), 0);
        assert_eq!(order.key(2), 10);
        assert_eq!(order.key(4), 10);
        assert_eq!(order.key(5), 40);
        // A row out of step with its position cannot make the key fall.
        assert_eq!(order.key(8), 40);
        assert_eq!(order.bound(10), Some(5));
        assert_eq!(order.bound(40), None);
        assert_eq!(order.bound(0), Some(2));
    }

    #[test]
    fn a_token_from_before_the_snapshot_still_parses() {
        let (snapshot, rooms) = parse_notifications_cursor("12:!a:x;7:!b:x").unwrap();
        assert_eq!(snapshot, None);
        assert_eq!(rooms.get("!a:x"), Some(&12));
        assert_eq!(rooms.get("!b:x"), Some(&7));
        let (snapshot, rooms) = parse_notifications_cursor("s99;12:!a:x").unwrap();
        assert_eq!(snapshot, Some(99));
        assert_eq!(rooms.get("!a:x"), Some(&12));
        assert_eq!(
            parse_notifications_cursor(&notifications_cursor(5, &BTreeMap::new())).unwrap(),
            (Some(5), BTreeMap::new())
        );
        assert!(parse_notifications_cursor("sx;1:!a:x").is_err());
        assert!(parse_notifications_cursor("garbage").is_err());
    }
}
