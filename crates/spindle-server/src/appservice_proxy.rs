//! What lk-jwt-service needs of a homeserver to run as its sidecar:
//! MSC4502's membership look-up and MSC4512's request proxying.
//!
//! Element Call's token service stopped being a stand-alone web service in
//! its 0.7 release. It now registers as an application service on the
//! homeserver and is reached *through* it: the homeserver answers
//! `/_matrix/client/unstable/io.element.msc4195/rtc/livekit/…` and the
//! federation twin by forwarding them to the service, authenticated as the
//! caller (MSC4512); the service asks the homeserver whether that caller is
//! in the room it wants a token for (MSC4502); and when the room lives on
//! another server, it asks this server to send the federation request for it
//! (`fed_proxy`). Element Call probes the homeserver path to decide whether
//! the server can hold its delayed leave for it -- and if it can, schedules
//! that leave an hour out instead of eighteen seconds.
//!
//! None of it is LiveKit-specific here. A registration names a prefix and a
//! URL; requests under the prefix are authenticated as usual and forwarded,
//! with the service's `hs_token` in place of the caller's credential and the
//! caller named in a header.

use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::appservices::Registration;
use crate::errors::MatrixError;

/// The largest request body forwarded to a service: its endpoints take a
/// token request, not an upload.
const MAX_BODY: usize = 1024 * 1024;

/// The header naming the authenticated user on a proxied client request.
const USER_HEADER: &str = "x-matrix-user-identifier";
/// The header naming the authenticated server on a proxied federation one.
const ORIGIN_HEADER: &str = "x-matrix-origin";

/// RFC 2616's hop-by-hop headers, which never cross a proxy, and the two
/// this proxy sets itself.
const NOT_FORWARDED: [&str; 11] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/unstable/io.element.msc4502/rooms/{room_id}/is_joined",
            get(is_joined),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/is_joined",
            get(is_joined),
        )
        .route(
            "/_matrix/client/unstable/io.element.msc4512/appservice/fed_proxy",
            post(fed_proxy),
        )
        .route("/_matrix/client/v1/appservice/fed_proxy", post(fed_proxy))
}

/// The application service presenting the request's bearer token, if it is
/// one.
fn calling_service<'a>(state: &'a AppState, headers: &HeaderMap) -> Option<&'a Registration> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    state
        .appservices
        .by_token(token)
        .map(std::convert::AsRef::as_ref)
}

#[derive(Debug, Deserialize)]
struct IsJoinedQuery {
    mxid: Option<String>,
    server_name: Option<String>,
}

/// `GET /_matrix/client/v3/rooms/{roomId}/is_joined`, and its MSC4502
/// unstable path.
///
/// Whether one user, or any user of one server, is joined to a room --
/// asked by someone who need not be in it. Reserved, as the MSC says, to
/// services granted the scope and to server administrators: it answers
/// for any room this server knows.
async fn is_joined(
    State(state): State<AppState>,
    headers: HeaderMap,
    crate::auth::Authenticated(identity): crate::auth::Authenticated,
    Path(room_id): Path<String>,
    Query(query): Query<IsJoinedQuery>,
) -> Result<Json<Value>, MatrixError> {
    let scoped =
        calling_service(&state, &headers).is_some_and(Registration::may_look_up_membership);
    let admin = crate::admin::is_server_admin(&state, &identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if !scoped && !admin {
        return Err(MatrixError::forbidden(
            "membership look-ups need the urn:matrix:client:rooms:is_joined scope",
        ));
    }
    if !room_id.starts_with('!') {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "not a room ID",
        ));
    }
    let joined = match (query.mxid, query.server_name) {
        (Some(user_id), None) => {
            if ruma::UserId::parse(&user_id).is_err() {
                return Err(MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "mxid is not a user ID",
                ));
            }
            state.rooms.is_joined(&user_id, &room_id).unwrap_or(false)
        }
        (None, Some(server_name)) => {
            if ruma::ServerName::parse(&server_name).is_err() {
                return Err(MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "server_name is not a server name",
                ));
            }
            state
                .rooms
                .server_in_room(&room_id, &server_name)
                .unwrap_or(false)
        }
        _ => {
            return Err(MatrixError::missing_param(
                "exactly one of mxid and server_name is required",
            ));
        }
    };
    Ok(Json(json!({ "joined": joined })))
}

#[derive(Debug, Deserialize)]
struct FedProxyRequest {
    destination: Option<String>,
    method: Option<String>,
    path: Option<String>,
    #[serde(default)]
    query: Option<serde_json::Map<String, Value>>,
    body: Option<Value>,
}

fn fed_proxy_refusal(status: StatusCode, errcode: &'static str, why: &str) -> MatrixError {
    MatrixError::new(status, errcode, why)
}

/// What a `fed_proxy` request asks to send, once every rule MSC4512 puts
/// on it has been checked: where, how, the path with its query, and the
/// body.
fn fed_proxy_target(
    state: &AppState,
    service: &Registration,
    request: FedProxyRequest,
) -> Result<(String, reqwest::Method, String, Option<Value>), MatrixError> {
    let (Some(destination), Some(method), Some(path)) =
        (request.destination, request.method, request.path)
    else {
        return Err(MatrixError::missing_param(
            "destination, method and path are required",
        ));
    };
    let method = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        _ => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "method must be GET, POST, PUT or DELETE",
            ));
        }
    };
    if request.body.is_some() && matches!(method, reqwest::Method::GET | reqwest::Method::DELETE) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "a GET or DELETE carries no body",
        ));
    }
    if request.body.as_ref().is_some_and(|body| !body.is_object()) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "body must be an object",
        ));
    }
    if ruma::ServerName::parse(&destination).is_err() {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "destination is not a server name",
        ));
    }
    if destination == state.config.server.name || !state.config.federation.enabled {
        return Err(fed_proxy_refusal(
            StatusCode::FORBIDDEN,
            "IO.ELEMENT.MSC4512_FEDPROXY_DESTINATION_DENIED",
            "this server will not send that request there",
        ));
    }
    let allowed = service.proxy().is_some_and(|(prefix, _)| {
        split(&path).is_some_and(|(api, rest)| {
            api == Api::Federation && crate::appservices::claims_path(prefix, rest)
        }) && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    });
    if !allowed {
        return Err(fed_proxy_refusal(
            StatusCode::FORBIDDEN,
            "IO.ELEMENT.MSC4512_FEDPROXY_PATH_NOT_ALLOWED",
            "the path is outside this service's proxy prefix",
        ));
    }
    let mut uri = path;
    if let Some(query) = request.query.filter(|query| !query.is_empty()) {
        let mut encoded = form_urlencoded::Serializer::new(String::new());
        for (key, value) in &query {
            let Some(value) = value.as_str() else {
                return Err(MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "query values must be strings",
                ));
            };
            encoded.append_pair(key, value);
        }
        uri = format!("{uri}?{}", encoded.finish());
    }
    Ok((destination, method, uri, request.body))
}

/// `POST /_matrix/client/v1/appservice/fed_proxy`, and its MSC4512
/// unstable path.
///
/// A service that answers part of the federation API asks this server to
/// send a federation request under that same part, signed as this server,
/// and gets back what the destination said. Only services may ask, only
/// under their own prefix, and never to this server or one it will not
/// federate with.
async fn fed_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FedProxyRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(service) = calling_service(&state, &headers) else {
        return Err(MatrixError::forbidden(
            "only an application service may use fed_proxy",
        ));
    };
    let (destination, method, uri, body) = fed_proxy_target(&state, service, request)?;
    match state
        .federation
        .remote_proxy(&destination, method, &uri, body.as_ref())
        .await
    {
        Ok((status, content)) => {
            let mut response = serde_json::Map::new();
            response.insert("status".to_owned(), json!(status));
            if let Some(content) = content.filter(Value::is_object) {
                response.insert("content".to_owned(), content);
            }
            Ok(Json(Value::Object(response)))
        }
        Err(error) => {
            tracing::debug!(%destination, "fed_proxy could not deliver: {error}");
            Err(fed_proxy_refusal(
                StatusCode::BAD_GATEWAY,
                "IO.ELEMENT.MSC4512_FEDPROXY_CONNECTION_FAILED",
                "the destination could not be reached",
            ))
        }
    }
}

/// One client for every forwarded request, so connections to the service
/// are reused rather than opened per call.
fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Which API a path is under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Api {
    Client,
    Federation,
}

/// Split `/_matrix/{client|federation}/{version}/{rest}`, where the version
/// is `v…` or `unstable/{namespace}`, into the API and `rest`.
pub(crate) fn split(path: &str) -> Option<(Api, &str)> {
    let (api, after) = if let Some(after) = path.strip_prefix("/_matrix/client/") {
        (Api::Client, after)
    } else {
        (Api::Federation, path.strip_prefix("/_matrix/federation/")?)
    };
    let rest = if let Some(unstable) = after.strip_prefix("unstable/") {
        unstable.split_once('/')?.1
    } else {
        let (version, rest) = after.split_once('/')?;
        if !version.starts_with('v') {
            return None;
        }
        rest
    };
    Some((api, rest))
}

/// The router's fallback: a path a service claims (MSC4512) is forwarded to
/// it; anything else is the spec's `M_UNRECOGNIZED`.
pub(crate) async fn proxy_or_unknown(State(state): State<AppState>, request: Request) -> Response {
    match forward_claimed(&state, request).await {
        Err(response) => response,
        Ok(_) => unrecognized(),
    }
}

/// A routed handler's first question, where the built-in service and a
/// sidecar can both answer: when a service claimed the path (MSC4512) the
/// request is forwarded to it and `Err(response)` returns; otherwise
/// `Ok(request)` hands it back and the built-in serves.
///
/// The built-in MSC4195 endpoints need this because the router matches
/// them before the fallback: without it, configuring `lk-jwt-service` as
/// the homeserver's sidecar (option C) would silently stop reaching it
/// the moment the built-in program is on, and the claim in the
/// registration would be a lie.
pub(crate) async fn forward_claimed(
    state: &AppState,
    request: Request,
) -> Result<Request, Response> {
    let path = request.uri().path().to_owned();
    let Some((api, service)) = split(&path).and_then(|(api, rest)| {
        state
            .appservices
            .proxy_for(rest)
            .map(|service| (api, std::sync::Arc::clone(service)))
    }) else {
        return Ok(request);
    };
    Err(match forward(state, api, &service, request).await {
        Ok(response) | Err(response) => response,
    })
}

fn unrecognized() -> Response {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "unrecognized endpoint".to_owned(),
    )
    .into_response()
}

/// Authenticate a claimed request as the API it is under requires, and
/// forward it to the service that claimed it.
async fn forward(
    state: &AppState,
    api: Api,
    service: &Registration,
    request: Request,
) -> Result<Response, Response> {
    let Some((_, proxy_url)) = service.proxy() else {
        return Err(unrecognized());
    };
    let (mut parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, MAX_BODY).await.map_err(|_| {
        MatrixError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            "the request body is too large to forward",
        )
        .into_response()
    })?;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    // Authentication is required for everything under a prefix (MSC4512):
    // a client's access token, or a peer's X-Matrix signature.
    let (header, who) = match api {
        Api::Client => {
            let crate::auth::Authenticated(identity) =
                crate::auth::Authenticated::from_request_parts(&mut parts, state)
                    .await
                    .map_err(IntoResponse::into_response)?;
            (USER_HEADER, identity.user_id)
        }
        Api::Federation => {
            let content: Option<Value> =
                if body.is_empty() {
                    None
                } else {
                    Some(serde_json::from_slice(&body).map_err(|_| {
                        MatrixError::bad_json("the body is not JSON").into_response()
                    })?)
                };
            let origin = crate::inbound::federation_origin(
                state,
                &parts.headers,
                parts.method.as_str(),
                &path_and_query,
                content.as_ref(),
            )
            .await
            .map_err(IntoResponse::into_response)?;
            (ORIGIN_HEADER, origin)
        }
    };
    let mut outbound =
        client().request(parts.method.clone(), format!("{proxy_url}{path_and_query}"));
    for (name, value) in &parts.headers {
        if forwarded(name) {
            outbound = outbound.header(name, value);
        }
    }
    let response = outbound
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", service.hs_token),
        )
        .header(header, who)
        .timeout(std::time::Duration::from_secs(30))
        .body(body)
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(service = %service.id, "the proxied request failed: {error}");
            MatrixError::new(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "the service answering this endpoint could not be reached",
            )
            .into_response()
        })?;
    let status = response.status();
    let mut headers = HeaderMap::new();
    for (name, value) in response.headers() {
        if forwarded(name) {
            headers.insert(name.clone(), value.clone());
        }
    }
    let bytes = response.bytes().await.map_err(|error| {
        tracing::warn!(service = %service.id, "the proxied response was cut short: {error}");
        MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            "the service answering this endpoint did not finish its answer",
        )
        .into_response()
    })?;
    let mut out = Response::new(Body::from(bytes));
    *out.status_mut() = status;
    *out.headers_mut() = headers;
    Ok(out)
}

/// Whether a header crosses the proxy: not hop-by-hop, not one this proxy
/// sets, and never the caller's own credential.
fn forwarded(name: &HeaderName) -> bool {
    let name = name.as_str();
    name != "authorization"
        && name != USER_HEADER
        && name != ORIGIN_HEADER
        && !NOT_FORWARDED.contains(&name)
        // CORS is answered by this server's own layer, once.
        && !name.starts_with("access-control-")
}
