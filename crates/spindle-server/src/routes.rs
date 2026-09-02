//! The route table, and the router built from it.
//!
//! One table, so [`surface`](crate::surface)'s claims can be checked against
//! what is actually mounted rather than against a second list that agrees with
//! the first only until someone edits one of them.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use std::collections::BTreeMap;

use serde_json::value::RawValue;
use serde_json::{Value, json};

use axum::extract::ConnectInfo;
use std::net::SocketAddr;

use crate::accounts::{AccountError, Accounts};
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::inbound::{
    FederationStateQuery, federation_origin, join_candidates, merge_returned_signatures,
    sign_membership_template,
};
use crate::ratelimit::{FAILED_LOGIN_PER_ACCOUNT, FAILED_LOGIN_PER_SOURCE, REGISTER_PER_SOURCE};
use crate::rooms::ReadScope;
use crate::{AppState, surface};

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
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
    "/_matrix/client/v3/rooms/{room_id}/state",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
    "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
    "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
    "/_matrix/key/v2/server",
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
    Router::new()
        .merge(account_routes())
        .merge(push_routes())
        .merge(appservice_routes())
        .merge(device_routes())
        .merge(profile_routes())
        .merge(room_routes())
        .merge(timeline_routes())
        .merge(media_routes())
        .merge(discovery_routes())
        .merge(crate::mas::routes())
        .merge(crate::admin::routes())
        .merge(crate::oidc::routes())
        // SPEC: an endpoint the server does not recognize answers 404
        // M_UNRECOGNIZED — a JSON verdict, not a bare status. Clients (and
        // Complement's TestUnknownEndpoints) read the errcode to tell "this
        // server does not speak that" from "the thing was not found".
        .fallback(unknown_endpoint)
        .layer(axum::middleware::from_fn(cors))
        .layer(axum::middleware::from_fn(observe))
        .with_state(state)
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
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let method = request.method().to_string();
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    crate::metrics::observe_request(
        &route,
        &method,
        response.status().as_u16(),
        started.elapsed(),
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
        axum::http::HeaderValue::from_static("X-Requested-With, Content-Type, Authorization"),
    );
    response
}

/// Any `/_matrix` path no route above claimed.
async fn unknown_endpoint() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "unrecognized endpoint".to_owned(),
    )
}

/// Registration, login, and the per-user data that is not in any room.
/// The global-profile surface: read anyone's, write your own.
fn profile_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/profile/{user_id}", get(get_profile))
        .route(
            "/_matrix/client/v3/profile/{user_id}/displayname",
            get(get_profile_displayname).put(put_profile_displayname),
        )
        .route(
            "/_matrix/client/v3/profile/{user_id}/avatar_url",
            get(get_profile_avatar).put(put_profile_avatar),
        )
        .route(
            "/_matrix/client/v3/presence/{user_id}/status",
            get(get_presence).put(put_presence),
        )
}

/// `PUT /_matrix/client/v3/presence/{user_id}/status`
///
/// Only your own. The spec is explicit that this sets *the caller's*
/// presence, and a server that let one user mark another offline would be
/// handing out a small denial-of-service against every client that renders
/// an online indicator.
async fn put_presence(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<PresenceRequest>,
) -> Result<Json<Value>, MatrixError> {
    if user_id != identity.user_id {
        return Err(MatrixError::forbidden(
            "you cannot set another user's presence",
        ));
    }
    let presence = crate::presence::State::parse(&request.presence).ok_or_else(|| {
        MatrixError::bad_json(format!(
            "presence must be 'online', 'offline' or 'unavailable', not {:?}",
            request.presence
        ))
    })?;
    state
        .presence
        .set(&identity.user_id, presence, request.status_msg.as_deref())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/presence/{user_id}/status`
///
/// Your own, or someone you share a room with. The spec defines a 403 here
/// for exactly this, and it is worth having rather than serving presence to
/// anyone who asks: presence is a continuous signal about when a person is
/// at their computer, and an unauthenticated-in-practice one would let any
/// account on this server watch any other.
async fn get_presence(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if user_id != identity.user_id && !shares_a_room(&state, &identity.user_id, &user_id)? {
        return Err(MatrixError::forbidden(
            "you are not allowed to see this user's presence status",
        ));
    }
    let status = state
        .presence
        .get(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let mut body = json!({
        "presence": status.state.as_str(),
        "last_active_ago": status.last_active_ago,
        "currently_active": status.currently_active,
    });
    if let Some(message) = status.status_msg {
        body["status_msg"] = Value::String(message);
    }
    Ok(Json(body))
}

/// Whether two users are in a room together.
///
/// Asked of the *smaller* side's room list first -- the caller's -- because
/// the answer is symmetric and the caller is the one whose membership this
/// server is certain to hold.
fn shares_a_room(state: &AppState, asker: &str, about: &str) -> Result<bool, MatrixError> {
    let rooms = state
        .rooms
        .joined(asker)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for room in rooms {
        if state
            .rooms
            .is_joined(about, &room)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Deserialize)]
struct PresenceRequest {
    presence: String,
    #[serde(default)]
    status_msg: Option<String>,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/report/{event_id}`
///
/// A user tells the server's operators that an event is a problem. The
/// report goes into the admin audit log, which is the feed an operator
/// already reads -- a report stored somewhere nobody looks is not a
/// moderation feature, it is the appearance of one.
///
/// **404 covers both "no such event" and "you cannot see it", deliberately
/// and per the spec.** Distinguishing them would turn this endpoint into an
/// oracle for whether a given event ID exists in a room the caller is not
/// in, which is exactly the thing a reporting endpoint must not become.
async fn report_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<ReportRequest>,
) -> Result<Json<Value>, MatrixError> {
    // The spec's range, and it is signed: a "score" here runs from -100
    // (worst) to 0, so a positive number is a caller who has misread the
    // API rather than one paying a compliment.
    if let Some(score) = request.score
        && !(-100..=0).contains(&score)
    {
        return Err(MatrixError::bad_json(format!(
            "score must be between -100 and 0, not {score}"
        )));
    }
    let not_found = || MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such event");
    if may_read_room(&state, &identity.user_id, &room_id).is_err() {
        return Err(not_found());
    }
    state
        .rooms
        .event(&room_id, &event_id)
        .map_err(|_| not_found())?;

    crate::admin::audit(
        &state,
        &identity.user_id,
        "report",
        &event_id,
        &json!({
            "room_id": room_id,
            "reason": request.reason,
            "score": request.score,
        }),
    )?;
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct ReportRequest {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    score: Option<i64>,
}

/// The surface only an appservice speaks.
fn appservice_routes() -> Router<AppState> {
    Router::new().route(
        "/_matrix/client/v1/appservice/{appservice_id}/ping",
        post(appservice_ping),
    )
}

/// Device management: listing, renaming, deletion — and MSC4190's
/// appservice half, where PUT mints a device with no session behind it.
fn device_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/devices", get(list_devices))
        .route("/_matrix/client/v3/delete_devices", post(delete_devices))
        .route(
            "/_matrix/client/v3/devices/{device_id}",
            get(get_device).put(put_device).delete(delete_device),
        )
}

fn account_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/register", post(register))
        .route("/_matrix/client/v3/login", get(login_flows).post(login))
        .route(
            "/_matrix/client/v3/register/available",
            get(register_available),
        )
        .route("/_matrix/client/v3/logout", post(logout))
        .route("/_matrix/client/v3/refresh", post(refresh))
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        .route("/_matrix/client/v3/keys/upload", post(upload_keys))
        .route("/_matrix/client/v3/keys/query", post(query_keys))
        .route("/_matrix/client/v3/keys/claim", post(claim_keys))
        .route("/_matrix/client/v3/keys/changes", get(key_changes))
        .route(
            "/_matrix/client/v3/keys/device_signing/upload",
            post(upload_cross_signing),
        )
        .route(
            "/_matrix/client/v3/keys/signatures/upload",
            post(upload_signatures),
        )
        .route(
            "/_matrix/client/v3/room_keys/version",
            post(create_backup_version).get(latest_backup_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/version/{version}",
            get(get_backup_version)
                .put(update_backup_version)
                .delete(delete_backup_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys",
            axum::routing::put(put_backup_keys)
                .get(get_backup_keys)
                .delete(delete_backup_keys),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}",
            axum::routing::put(put_backup_room)
                .get(get_backup_room)
                .delete(delete_backup_room),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}",
            axum::routing::put(put_backup_session)
                .get(get_backup_session)
                .delete(delete_backup_session),
        )
        .route(
            "/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}",
            axum::routing::put(send_to_device),
        )
        .route("/_matrix/client/v3/joined_rooms", get(joined_rooms))
        .route("/_matrix/client/v3/sync", get(sync))
        // Element X speaks the unstable path; MSC4186 has no stable one yet.
        .route(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            post(sliding_sync),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/account_data/{event_type}",
            get(get_account_data).put(set_account_data),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}",
            get(get_room_account_data).put(set_room_account_data),
        )
        // Tags are not their own storage: the spec models them as the `m.tag`
        // room account-data event, and these endpoints are views over it.
        // That is what makes them appear in /sync's per-room account data
        // with no extra wiring -- there is only one value to keep true.
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags",
            get(get_tags),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}",
            axum::routing::put(set_tag).delete(delete_tag),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/filter",
            post(create_filter),
        )
        .route(
            "/_matrix/client/v3/user/{user_id}/filter/{filter_id}",
            get(get_filter),
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
        .route("/_matrix/client/v3/createRoom", post(create_room))
        .route(
            "/_matrix/client/v3/rooms/{room_id}/invite",
            post(invite_to_room),
        )
        .route("/_matrix/client/v3/rooms/{room_id}/join", post(join_room))
        .route("/_matrix/client/v3/rooms/{room_id}/leave", post(leave_room))
        .route(
            "/_matrix/client/v3/rooms/{room_id}/kick",
            post(kick_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/ban",
            post(ban_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/unban",
            post(unban_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/forget",
            post(forget_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/joined_members",
            get(room_joined_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/members",
            get(room_members),
        )
        .route(
            "/_matrix/client/v3/join/{room_id_or_alias}",
            post(join_room_by_id_or_alias),
        )
        .route(
            "/_matrix/client/v3/knock/{room_id_or_alias}",
            post(knock_room),
        )
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
        .route(
            "/_matrix/client/v1/rooms/{room_id}/hierarchy",
            get(room_hierarchy),
        )
        .route("/_matrix/client/v3/account/password", post(change_password))
        .route(
            "/_matrix/client/v3/account/deactivate",
            post(deactivate_account),
        )
        // Two paths for one endpoint. MSC3266 shipped under the unstable
        // prefix long enough that clients still ask for it there, and it
        // became `/v1/room_summary` in Matrix 1.15. Serving both costs one
        // route and spares every client a version probe.
        .route(
            "/_matrix/client/v1/room_summary/{room_id_or_alias}",
            get(room_summary),
        )
        .route(
            "/_matrix/client/unstable/im.nheko.summary/rooms/{room_id_or_alias}/summary",
            get(room_summary),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/typing/{user_id}",
            axum::routing::put(set_typing),
        )
}

/// Everything that reads or writes a room's log, and its state.
fn timeline_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
            axum::routing::put(send_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/messages",
            get(room_messages),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
            post(set_receipt),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/read_markers",
            post(read_markers),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/upgrade",
            post(upgrade_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/report/{event_id}",
            post(report_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
            axum::routing::put(redact_event),
        )
        // Three arities, because the spec has three and a client may use any.
        // `/v1` rather than `/v3`: relations arrived on the versioned path
        // (MSC2675) and that is where clients look for them.
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
            get(relations_all),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
            get(relations_by_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(relations_by_event_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/threads",
            get(room_threads),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
            get(room_timestamp_to_event),
        )
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
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
            get(delayed_events),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
            post(delayed_event_action),
        )
        .route("/_matrix/client/v3/rooms/{room_id}/state", get(room_state))
        // Two routes, because the spec has two forms and a router cannot
        // match an empty trailing segment: `/state/m.room.topic` means the
        // same as `/state/m.room.topic/""`, and a client may send either.
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
            get(room_state_event_default).put(set_room_state_default),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
            get(room_state_event).put(set_room_state),
        )
        // …and the trailing-slash spelling: matrix-bot-sdk — hookshot
        // and most Node bots — writes the empty state key as an empty
        // final segment, which axum matches to neither pattern above.
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/",
            get(room_state_event_default).put(set_room_state_default),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
            get(room_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
            get(room_context),
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
fn media_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/media/v3/upload",
            post(upload_media)
                // Axum's default body limit is 2 MiB, which would reject an
                // upload before the handler ever saw it -- with a bare 413 and
                // no Matrix error code. The server would then be advertising a
                // 50 MiB limit in `/config` and enforcing 2 MiB, which is the
                // worst kind of disagreement: the client is told the file is
                // fine, sends it, and gets an opaque failure.
                //
                // The extractor limit is set one byte above ours so that
                // `Media::put` is the thing that refuses, and refuses with
                // `M_TOO_LARGE`.
                .layer(axum::extract::DefaultBodyLimit::max(
                    crate::media::MAX_UPLOAD + 1,
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
        )
        .await
        .map_err(|error| media_error(&error))?;
    Ok(Json(json!({
        "content_uri": format!("mxc://{}/{media_id}", state.config.server.name),
    })))
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
async fn media_config(State(_state): State<AppState>) -> Json<Value> {
    // Stated rather than discovered: a client that knows the limit can refuse
    // a file before spending a minute sending it.
    Json(json!({ "m.upload.size": crate::media::MAX_UPLOAD }))
}

/// `GET /_matrix/client/v1/media/download/{server_name}/{media_id}`
async fn download_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
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
    Authenticated(identity): Authenticated,
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
    body.extend_from_slice(format!("content-type: {}\r\n", record.content_type).as_bytes());
    body.extend_from_slice(
        format!(
            "content-disposition: {}\r\n\r\n",
            record.content_disposition()
        )
        .as_bytes(),
    );
    body.extend_from_slice(&bytes);
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
/// [`serve_media`] gives (ADR 0003).
async fn thumbnail_media(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
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
        Error::TooLarge { .. } => MatrixError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
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
async fn capabilities() -> Json<Value> {
    let mut capabilities = serde_json::Map::new();
    if let Some(default) = surface::DEFAULT_ROOM_VERSION {
        let available: serde_json::Map<String, Value> = surface::ROOM_VERSIONS
            .iter()
            .map(|version| ((*version).to_owned(), json!("stable")))
            .collect();
        capabilities.insert(
            "m.room_versions".to_owned(),
            json!({ "default": default, "available": Value::Object(available) }),
        );
    }
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
        // The built-in provider is its own issuer; there is no account
        // management UI to point at, so none is advertised.
        body["org.matrix.msc2965.authentication"] = json!({
            "issuer": format!("{}/", crate::oidc::issuer(&state)),
        });
    }
    // MSC4143 (which absorbed MSC4158): the MatrixRTC backend, named here
    // as well as on `/rtc/transports` because a client discovers calls
    // before it has a token to ask with. Omitted entirely when nothing is
    // configured -- an empty array here would be a positive claim to have
    // no backend, where absence is "this server does not answer that".
    let foci = rtc_transports(&state.config);
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

/// The 404 every legacy auth endpoint answers under MSC3861 delegation:
/// the provider owns login, and a working password path beside it would
/// be a second door with its own keys.
fn delegated_refusal() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_UNRECOGNIZED",
        "authentication is delegated to the OIDC provider",
    )
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
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Readiness: the process can serve.
///
/// Currently the same answer as liveness, which is honest only because nothing
/// is initialised asynchronously yet. When storage opens here, this has to stop
/// reporting ready before it is — a readiness probe that lies is worse than no
/// readiness probe, because it takes traffic on the strength of the lie.
async fn ready() -> StatusCode {
    StatusCode::OK
}

/// The identifier half of a login request.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Identifier {
    #[serde(rename = "m.id.user")]
    User { user: String },
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(rename = "type")]
    kind: String,
    identifier: Option<Identifier>,
    /// The deprecated top-level form, still sent by older clients.
    user: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
    #[serde(default)]
    refresh_token: bool,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Default, Deserialize)]
struct RegisterRequest {
    username: Option<String>,
    password: Option<String>,
    device_id: Option<String>,
    initial_device_display_name: Option<String>,
    #[serde(default)]
    inhibit_login: bool,
    #[serde(default)]
    refresh_token: bool,
    auth: Option<Value>,
    /// `m.login.application_service` switches registration to the
    /// appservice path: no UIA, the `as_token` is the whole proof.
    #[serde(rename = "type")]
    login_type: Option<String>,
}

/// The login/register/refresh response body.
///
/// `refresh_token` and `expires_in_ms` are omitted when the client did not ask
/// for refresh, rather than sent null: a client checks for the key's presence
/// to decide whether to schedule a renewal.
fn session_body(user_id: &str, session: &crate::accounts::Session) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("user_id".to_owned(), json!(user_id));
    body.insert("access_token".to_owned(), json!(session.access_token));
    body.insert("device_id".to_owned(), json!(session.device.device_id));
    if let Some(refresh) = &session.refresh_token {
        body.insert("refresh_token".to_owned(), json!(refresh));
    }
    if let Some(expires) = session.expires_in_ms {
        body.insert("expires_in_ms".to_owned(), json!(expires));
    }
    Value::Object(body)
}

/// `GET /_matrix/client/v3/login`
///
/// Only password login. SSO and token login are advertised by servers that
/// implement them; listing a flow we cannot complete would send a client down
/// a path that dead-ends.
async fn login_flows(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(delegated_refusal());
    }
    Ok(Json(json!({ "flows": [{ "type": "m.login.password" }] })))
}

/// `POST /_matrix/client/v3/login`
async fn login(
    State(state): State<AppState>,
    source: ClientAddr,
    Json(request): Json<LoginRequest>,
) -> Result<Json<Value>, MatrixError> {
    if state.delegated.is_some() {
        return Err(delegated_refusal());
    }
    if request.kind != "m.login.password" {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            format!("unsupported login type {:?}", request.kind),
        ));
    }

    let localpart = match (&request.identifier, &request.user) {
        (Some(Identifier::User { user }), _) | (None, Some(user)) => localpart_of(user),
        (None, None) => return Err(MatrixError::bad_json("no user identifier")),
    };
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no password"))?;

    // Both keys are checked before the password is, so a caller already over
    // the limit does not get a free Argon2 verification out of each attempt.
    let account_key = format!("login:account:{localpart}");
    let source_key = format!("login:source:{source}");
    for (key, limit) in [
        (&account_key, FAILED_LOGIN_PER_ACCOUNT),
        (&source_key, FAILED_LOGIN_PER_SOURCE),
    ] {
        if let Err(retry) = state.limiter.check(key, limit) {
            return Err(MatrixError::limit_exceeded(retry.as_millis()));
        }
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    // One message for a wrong password and for an unknown user. The
    // verification cost is already equal (see `verify_password`); saying
    // "no such user" here would give the difference back for free.
    if !accounts
        .verify_password(&localpart, password)
        .map_err(|error| internal(&error))?
    {
        return Err(MatrixError::forbidden("invalid username or password"));
    }

    // A correct login is not the traffic being defended against, and counting
    // it would lock out the legitimate users of a busy shared address first.
    state.limiter.forget(&account_key);
    state.limiter.forget(&source_key);

    let session = accounts
        .create_session(
            &localpart,
            request.device_id,
            request.initial_device_display_name,
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;

    Ok(Json(session_body(&accounts.user_id(&localpart), &session)))
}

/// `POST /_matrix/client/v3/refresh`
///
/// Unauthenticated by design: the refresh token *is* the credential, and a
/// client refreshing precisely because its access token expired has nothing
/// else to present.
async fn refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let session = accounts
        .refresh(&request.refresh_token)
        .map_err(|error| match error {
            AccountError::UnknownToken => MatrixError::unknown_token(),
            other => internal(&other),
        })?;
    let user_id = accounts.user_id(&session.device.localpart);
    Ok(Json(session_body(&user_id, &session)))
}

/// `GET /_matrix/client/v3/register/available`
///
/// The same verdicts registration itself would give, without spending a UIA
/// flow to hear them.
async fn register_available(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, MatrixError> {
    let username = query
        .get("username")
        .ok_or_else(|| MatrixError::bad_json("no username"))?
        .to_lowercase();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    match accounts.availability(&username) {
        Ok(()) => Ok(Json(json!({ "available": true }))),
        Err(AccountError::UserInUse) => Err(MatrixError::user_in_use()),
        Err(AccountError::InvalidUsername) => Err(MatrixError::invalid_username()),
        Err(other) => Err(MatrixError::internal(&other.to_string())),
    }
}

/// `POST /_matrix/client/v3/register`
///
/// One UIA stage, `m.login.dummy`: the first request without `auth` gets a 401
/// carrying the flows, and the client repeats it with the stage completed. The
/// dance is not decoration — clients implement UIA generically and a server
/// that skips it for registration makes them special-case it.
async fn register(
    State(state): State<AppState>,
    source: ClientAddr,
    headers: axum::http::HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    // Under MSC3861 delegation, humans register at the provider — but an
    // appservice still provisions its ghosts here, because the as_token
    // is an authority delegation never displaced.
    if state.delegated.is_some()
        && request.login_type.as_deref() != Some("m.login.application_service")
    {
        return Err(delegated_refusal());
    }
    // Counted after the UIA hand-shake, so the mandatory first 401 does not
    // spend a client's budget on the flow the server itself required.
    if request.auth.is_some()
        && let Err(retry) = state
            .limiter
            .check(&format!("register:source:{source}"), REGISTER_PER_SOURCE)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }

    // Username problems outrank the UIA dance (SPEC: a client should learn
    // M_INVALID_USERNAME or M_USER_IN_USE on its *first* request, before
    // being sent through auth it would complete for nothing), so the checks
    // run even when no auth has been presented yet. Capitals are folded
    // down rather than refused: the localpart grammar is lowercase, and a
    // client typing "Alice" means alice.
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let username = request.username.as_deref().map(str::to_lowercase);
    if let Some(name) = username.as_deref() {
        match accounts.availability(name) {
            Ok(()) => {}
            Err(AccountError::UserInUse) => return Err(MatrixError::user_in_use()),
            Err(AccountError::InvalidUsername) => {
                return Err(MatrixError::invalid_username());
            }
            Err(other) => return Err(MatrixError::internal(&other.to_string())),
        }
    }

    // SPEC (appservice §registration): `m.login.application_service` skips
    // UIA entirely — the as_token in the Authorization header is the whole
    // proof, so it branches before the challenge below.
    if request.login_type.as_deref() == Some("m.login.application_service") {
        return register_appservice_user(&state, &headers, username.as_deref(), &request);
    }

    // An exclusive namespace is a reservation: only its service may create
    // these accounts, through the branch above. Refused before the UIA
    // dance for the same reason the username checks are — a client should
    // not complete auth for a name it can never have.
    if let Some(name) = username.as_deref() {
        let user_id = format!("@{name}:{}", state.config.server.name);
        if state.appservices.exclusively_claims(&user_id) {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_EXCLUSIVE",
                "this localpart is reserved by an application service",
            ));
        }
    }

    // The challenge is the *body* of the 401, not an error wrapping it:
    // SPEC (client-server §UIA) has clients read `flows`/`params`/`session`
    // at the top level, and a challenge folded into an `error` string is
    // invisible to every generic UIA implementation. Complement's
    // RegisterUser is what caught this. An auth dict that names no session
    // gets the same challenge — the session is how a completed stage is
    // tied back to the flow it completed.
    let session_named = request
        .auth
        .as_ref()
        .is_some_and(|auth| auth["session"].is_string());
    if !session_named {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "flows": [{ "stages": ["m.login.dummy"] }],
                "params": {},
                "session": "register",
            })),
        ));
    }

    let username = username.ok_or_else(|| MatrixError::bad_json("no username"))?;
    let username = username.as_str();
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| MatrixError::bad_json("no password"))?;

    accounts
        .register(username, password)
        .map_err(|error| match error {
            AccountError::UserInUse => MatrixError::user_in_use(),
            AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => MatrixError::internal(&other.to_string()),
        })?;

    let user_id = accounts.user_id(username);
    if request.inhibit_login {
        return Ok((StatusCode::OK, Json(json!({ "user_id": user_id }))));
    }

    let session = accounts
        .create_session(
            username,
            request.device_id,
            request.initial_device_display_name,
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;
    Ok((StatusCode::OK, Json(session_body(&user_id, &session))))
}

/// The `m.login.application_service` branch of registration.
///
/// The account is born with an unguessable password held by nobody,
/// exactly like a ghost provisioned on first masquerade — the appservice
/// door is the only door either kind of account should have. The session
/// returned (unless `inhibit_login`) is a real one; MSC4190's deviceless
/// registration comes later.
fn register_appservice_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    username: Option<&str>,
    request: &RegisterRequest,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    let registration = state
        .appservices
        .by_token(token)
        .ok_or_else(MatrixError::unknown_token)?;
    let username = username.ok_or_else(|| MatrixError::bad_json("no username"))?;
    let server_name = &state.config.server.name;
    let user_id = format!("@{username}:{server_name}");
    if !registration.may_masquerade_as(&user_id, server_name) {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_EXCLUSIVE",
            format!(
                "{user_id} is outside the {} appservice's namespaces",
                registration.id
            ),
        ));
    }
    let accounts = Accounts::new(state.store.as_ref(), server_name);
    accounts
        .register(username, &crate::accounts::unguessable_password())
        .map_err(|error| match error {
            AccountError::UserInUse => MatrixError::user_in_use(),
            AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => MatrixError::internal(&other.to_string()),
        })?;
    // MSC4190: a device-managing service gets no session even when it did
    // not ask to inhibit one — the as_token is its only credential, and
    // devices are minted through PUT /devices/{deviceId} instead.
    if request.inhibit_login || registration.device_management {
        return Ok((StatusCode::OK, Json(json!({ "user_id": user_id }))));
    }
    let session = accounts
        .create_session(
            username,
            request.device_id.clone(),
            request.initial_device_display_name.clone(),
            request.refresh_token,
        )
        .map_err(|error| internal(&error))?;
    Ok((StatusCode::OK, Json(session_body(&user_id, &session))))
}

/// `POST /_matrix/client/v3/logout`
async fn logout(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts.logout(&token).map_err(|error| internal(&error))?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/account/whoami`
async fn whoami(Authenticated(identity): Authenticated) -> Json<Value> {
    Json(json!({
        "user_id": identity.user_id,
        "device_id": identity.device_id,
    }))
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
fn appservice_of<'a>(
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

/// A device as the spec's `Device` object. Spindle does not track
/// last-seen data, and the spec has those fields optional, so they are
/// absent rather than present-and-wrong; a device never named has no
/// `display_name` for the same reason, since the spec's field is a string
/// and a null is neither absent nor one.
fn device_body(device: &crate::accounts::Device) -> Value {
    let mut body = json!({ "device_id": device.device_id });
    if let Some(name) = &device.display_name {
        body["display_name"] = json!(name);
    }
    body
}

/// `GET /_matrix/client/v3/devices`
async fn list_devices(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let devices = accounts
        .devices_of(&localpart_of(&identity.user_id))
        .map_err(|error| internal(&error))?;
    Ok(Json(json!({
        "devices": devices.iter().map(device_body).collect::<Vec<_>>(),
    })))
}

/// `GET /_matrix/client/v3/devices/{deviceId}`
async fn get_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .device(&localpart_of(&identity.user_id), &device_id)
        .map_err(|error| internal(&error))?
        .map(|device| Json(device_body(&device)))
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such device"))
}

/// `PUT /_matrix/client/v3/devices/{deviceId}`
///
/// For everyone, this renames an existing device. For a service whose
/// registration declares MSC4190 device management, a PUT on a device
/// that does not exist *creates* it — the deviceless registration's way
/// of minting the device its encryption keys will hang off, with no
/// access token behind it because the `as_token` is the only credential.
async fn put_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Authenticated(identity): Authenticated,
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&identity.user_id);
    let named = body
        .as_ref()
        .and_then(|Json(body)| body.get("display_name").cloned());
    let display_of = |named: Option<Value>, unchanged: Option<String>| match named {
        None => Ok(unchanged),
        Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => Ok(Some(name)),
        Some(_) => Err(MatrixError::bad_json("display_name must be a string")),
    };
    if let Some(existing) = accounts
        .device(&localpart, &device_id)
        .map_err(|error| internal(&error))?
    {
        let display_name = display_of(named, existing.display_name)?;
        accounts
            .put_device(&localpart, &device_id, display_name)
            .map_err(|error| internal(&error))?;
        return Ok((StatusCode::OK, Json(json!({}))));
    }
    if !appservice_of(&state, &headers).is_some_and(|registration| registration.device_management) {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such device",
        ));
    }
    let display_name = display_of(named, None)?;
    accounts
        .put_device(&localpart, &device_id, display_name)
        .map_err(|error| internal(&error))?;
    let seq = state.rooms.allocate_stream_id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    Ok((StatusCode::CREATED, Json(json!({}))))
}

/// `DELETE /_matrix/client/v3/devices/{deviceId}`
///
/// A person re-proves their password (single-stage UIA); a service with
/// MSC4190 device management deletes outright — its `as_token` outranks a
/// password that, for a ghost, nobody holds. Deletion takes the sessions
/// and the E2E material with it, and marks the device list changed so
/// peers stop encrypting to the dead device.
///
/// Under MSC3861 delegation there is no UIA either: a delegated user's
/// local password is unguessable by construction, so the challenge would
/// be one nobody can answer — and the caller's identity was proven
/// moments ago by the provider vouching for their live token, which is
/// a stronger statement than re-typing a password. Synapse makes the
/// same call in its delegated mode.
async fn delete_device(
    State(state): State<AppState>,
    axum::extract::Path(device_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Authenticated(identity): Authenticated,
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let localpart = localpart_of(&identity.user_id);
    if accounts
        .device(&localpart, &device_id)
        .map_err(|error| internal(&error))?
        .is_none()
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such device",
        ));
    }
    let auth = body
        .as_ref()
        .and_then(|Json(body)| body.get("auth").cloned());
    if let Some(challenge) =
        password_uia(&state, &localpart, &headers, auth.as_ref(), "delete_device")?
    {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    accounts
        .delete_device(&localpart, &device_id)
        .map_err(|error| internal(&error))?;
    state
        .devices
        .remove_device_material(&identity.user_id, &device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let seq = state.rooms.allocate_stream_id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    Ok((StatusCode::OK, Json(json!({}))))
}

/// `@alice:example.org` and `alice` both mean the same localpart.
fn localpart_of(user: &str) -> String {
    // Folded to lowercase for the same reason registration folds: the
    // grammar is lowercase, and "Alice" logging in means the alice who
    // registered.
    user.strip_prefix('@')
        .and_then(|rest| rest.split(':').next())
        .unwrap_or(user)
        .to_lowercase()
}

fn internal(error: &AccountError) -> MatrixError {
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
        .record_pending_invite(target, room_id, origin, &invite_state)
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
    let signed = ruma::CanonicalJsonValue::try_from(document.clone())
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
        .unwrap_or(document);
    Json(signed)
}

#[derive(Debug, Default, Deserialize)]
struct CreateRoomRequest {
    name: Option<String>,
    topic: Option<String>,
    preset: Option<String>,
    #[serde(default)]
    invite: Vec<String>,
    #[serde(default)]
    initial_state: Vec<InitialStateEvent>,
    room_alias_name: Option<String>,
    room_version: Option<String>,
    /// `"public"` publishes the new room in this server's directory.
    ///
    /// Defaults to private, which is what the spec asks for and also the
    /// safer way round: a client that forgets the field gets an unlisted
    /// room rather than an advertised one.
    visibility: Option<String>,
    /// Extra `m.room.create` content -- `type: "m.space"`, `m.federate`.
    ///
    /// The server keeps `room_version` and `creator` for itself; see
    /// [`crate::rooms::Rooms::create`].
    creation_content: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct InitialStateEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    state_key: String,
    content: Value,
}

/// `POST /_matrix/client/v3/createRoom`
async fn create_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CreateRoomRequest>,
) -> Result<Json<Value>, MatrixError> {
    let initial_state: Vec<(String, String, Value)> = request
        .initial_state
        .into_iter()
        .map(|event| (event.event_type, event.state_key, event.content))
        .collect();
    let room_id = state
        .rooms
        .create(
            &identity.user_id,
            state.key.pair(),
            request.name.as_deref(),
            request.topic.as_deref(),
            request.preset.as_deref(),
            &initial_state,
            // Honour a version this server advertises; ignore one it does
            // not. Both halves are deliberate, and they are deliberate for
            // different reasons.
            //
            // Honouring the advertised ones is a correctness fix, not a
            // feature. `/capabilities` now lists v12 as available, and a
            // client reads that list precisely so it can ask for something
            // on it. Handing back v11 with a 200 would be the exact lie
            // #201 removed from `make_join` -- worse here, because
            // advertising v12 is what invites the request.
            //
            // Ignoring the rest preserves today's behaviour rather than
            // endorsing it. An unadvertised version is still silently
            // substituted, which is also a lie, but a pre-existing one:
            // 30 allowlisted Complement tests create rooms at v7/v8/v9 to
            // reach knock and restricted-join features and quietly receive
            // the v11 room that happens to have them. Refusing those is a
            // scope decision about which versions this server carries --
            // #178 -- not something to change while fixing v12.
            request
                .room_version
                .as_deref()
                .filter(|version| crate::surface::supports_room_version(version)),
            request.creation_content.as_ref(),
            &member_profile(&state, &identity.user_id),
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // Invites after the room stands, refused invites failing the create the
    // way the spec asks (the room still exists; the error names why).
    for target in &request.invite {
        invite_user(&state, &identity.user_id, &room_id, target, None).await?;
    }
    if request.visibility.as_deref() == Some("public") {
        // The creator is joined by construction, so `may_advertise` would pass;
        // calling it anyway would be a round-trip to re-learn that.
        state
            .directory
            .publish(&room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?;
    }
    if let Some(localpart) = request.room_alias_name.as_deref() {
        let alias = format!("#{localpart}:{}", state.config.server.name);
        state
            .directory
            .create(&alias, &room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?;
    }
    Ok(Json(json!({ "room_id": room_id })))
}

/// `GET /_matrix/client/v3/joined_rooms`
async fn joined_rooms(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let rooms = state
        .rooms
        .joined(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "joined_rooms": rooms })))
}

/// Read a profile, wherever the user lives.
///
/// A local user's profile is the stored row. A remote user's is their
/// server's to answer, over `query/profile` — which is how a client here
/// renders the name of someone it has never shared a room with.
async fn profile_of(state: &AppState, user_id: &str) -> Result<Value, MatrixError> {
    let domain = user_id.split_once(':').map(|(_, domain)| domain);
    if domain == Some(state.config.server.name.as_str()) {
        let localpart = user_id.strip_prefix('@').map_or(user_id, |rest| {
            rest.split_once(':')
                .map_or(rest, |(localpart, _)| localpart)
        });
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        let known = accounts
            .account(localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_some();
        // The classic appservice user query: a namespace ghost may exist
        // the moment its service is asked, so an unknown local user gets
        // one chance to be provisioned before the 404 stands.
        let known = known
            || (state
                .appservices
                .query_user(user_id, &state.config.server.name)
                .await
                && accounts
                    .account(localpart)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?
                    .is_some());
        if !known {
            return Err(MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("{user_id} is not here"),
            ));
        }
        let profile = state
            .profiles
            .get(user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        return serde_json::to_value(profile)
            .map_err(|error| MatrixError::internal(&error.to_string()));
    }
    let Some(domain) = domain else {
        return Err(MatrixError::bad_json(format!("{user_id} is not a user ID")));
    };
    state
        .federation
        .remote_query_profile(domain, user_id)
        .await
        .map_err(|error| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("{domain} did not answer for {user_id}: {error}"),
            )
        })
}

/// `GET /_matrix/client/v3/profile/{userId}`
async fn get_profile(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    Ok(Json(profile_of(&state, &user_id).await?))
}

/// `GET /_matrix/client/v3/profile/{userId}/displayname`
async fn get_profile_displayname(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let profile = profile_of(&state, &user_id).await?;
    let mut body = serde_json::Map::new();
    if let Some(name) = profile.get("displayname").filter(|v| !v.is_null()) {
        body.insert("displayname".to_owned(), name.clone());
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/profile/{userId}/avatar_url`
async fn get_profile_avatar(
    State(state): State<AppState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let profile = profile_of(&state, &user_id).await?;
    let mut body = serde_json::Map::new();
    if let Some(url) = profile.get("avatar_url").filter(|v| !v.is_null()) {
        body.insert("avatar_url".to_owned(), url.clone());
    }
    Ok(Json(Value::Object(body)))
}

#[derive(Debug, Deserialize)]
struct DisplaynameRequest {
    displayname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AvatarRequest {
    avatar_url: Option<String>,
}

/// Store one profile field and copy it into every joined room's member
/// event — the propagation the spec asks for, and the step that carries a
/// renamed user across federation, because member events fan out and
/// profile rows do not.
fn propagate_profile(state: &AppState, user_id: &str) -> Result<(), MatrixError> {
    let profile = state
        .profiles
        .get(user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let rooms = state
        .rooms
        .joined(user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for room_id in rooms {
        let mut content = json!({ "membership": "join" });
        if let Some(name) = &profile.displayname {
            content["displayname"] = json!(name);
        }
        if let Some(url) = &profile.avatar_url {
            content["avatar_url"] = json!(url);
        }
        state
            .rooms
            .set_state(
                &room_id,
                user_id,
                state.key.pair(),
                "m.room.member",
                user_id,
                &content,
            )
            .map_err(room_error)?;
    }
    state.rooms.wake_sync_waiters();
    Ok(())
}

/// `PUT /_matrix/client/v3/profile/{userId}/displayname`
async fn put_profile_displayname(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<DisplaynameRequest>,
) -> Result<Json<Value>, MatrixError> {
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden("a profile belongs to its user"));
    }
    state
        .profiles
        .set(&user_id, Some(request.displayname), None)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    propagate_profile(&state, &user_id)?;
    Ok(Json(json!({})))
}

/// `PUT /_matrix/client/v3/profile/{userId}/avatar_url`
async fn put_profile_avatar(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(request): Json<AvatarRequest>,
) -> Result<Json<Value>, MatrixError> {
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden("a profile belongs to its user"));
    }
    state
        .profiles
        .set(&user_id, None, Some(request.avatar_url))
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    propagate_profile(&state, &user_id)?;
    Ok(Json(json!({})))
}

/// The body every membership endpoint that names a target shares.
///
/// `/invite`, `/kick`, `/ban` and `/unban` differ only in the membership they
/// end up writing, so they differ only in the handler, not in the shape they
/// parse. `reason` is optional everywhere, including on `/invite`, where the
/// spec allows it even though few clients send one.
#[derive(Debug, Deserialize)]
struct TargetedMembershipRequest {
    user_id: String,
    reason: Option<String>,
}

/// The body of `/leave` and `/forget`, neither of which names a target.
#[derive(Debug, Default, Deserialize)]
struct SelfMembershipRequest {
    reason: Option<String>,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/invite`
async fn invite_to_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    invite_user(
        &state,
        &identity.user_id,
        &room_id,
        &request.user_id,
        request.reason.as_deref(),
    )
    .await?;
    Ok(Json(json!({})))
}

/// Invite one user, wherever their server is.
///
/// A local target is one membership event. A remote target is the spec's
/// invite handshake: build and sign the event here, hand it to the target's
/// server to co-sign over `v2/invite`, and only then append it — the
/// co-signed event is the one every other server in the room will accept as
/// proof the invitee's server was told. A refusal from that server fails
/// the invite, because an invite it never co-signed is one its user would
/// never see.
async fn invite_user(
    state: &AppState,
    sender: &str,
    room_id: &str,
    target: &str,
    reason: Option<&str>,
) -> Result<(), MatrixError> {
    let Some((_, domain)) = target.split_once(':') else {
        return Err(MatrixError::bad_json(format!("{target} is not a user ID")));
    };
    if domain == state.config.server.name {
        // An invite is the event that most often names a ghost that does
        // not exist yet; the user query gives its service the chance to
        // provision before the membership is written. The verdict is
        // deliberately unchecked — inviting an unclaimed unknown user is
        // still legal Matrix, and only IDs a service claims cost a request.
        let _ = state
            .appservices
            .query_user(target, &state.config.server.name)
            .await;
        state
            .rooms
            .set_membership_with(
                room_id,
                sender,
                target,
                "invite",
                reason,
                &member_profile(state, target),
                state.key.pair(),
            )
            .map_err(room_error)?;
        return Ok(());
    }

    let (event_id, event) = state
        .rooms
        .build_invite_event(room_id, sender, target, reason, state.key.pair())
        .map_err(room_error)?;
    // The stripped state the invited user renders the invite from — plus
    // the invite itself, which is not yet state anywhere and is exactly the
    // line "who asked you in" a client shows first.
    let mut invite_state = state
        .rooms
        .stripped_state(room_id, target)
        .map_err(room_error)?;
    invite_state.push(json!({
        "type": "m.room.member",
        "state_key": target,
        "sender": event["sender"],
        "content": event["content"],
    }));
    let body = json!({
        "event": event,
        "invite_room_state": invite_state,
        "room_version": crate::rooms::ROOM_VERSION,
    });
    let response = state
        .federation
        .remote_invite(domain, room_id, &event_id, &body)
        .await
        .map_err(|error| {
            MatrixError::new(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("{domain} did not accept the invite: {error}"),
            )
        })?;

    // What comes back must be the same event, co-signature aside — and the
    // reference hash proves it, because signatures are outside the hash.
    let cosigned = response["event"].clone();
    let rules = ruma::RoomVersionId::try_from(crate::rooms::ROOM_VERSION)
        .ok()
        .and_then(|version| version.rules())
        .ok_or_else(|| MatrixError::internal("the room version rules are unavailable"))?;
    let same = ruma::CanonicalJsonValue::try_from(cosigned.clone())
        .ok()
        .and_then(|value| match value {
            ruma::CanonicalJsonValue::Object(object) => Some(object),
            _ => None,
        })
        .and_then(|object| ruma::signatures::reference_hash(&object, &rules).ok())
        .is_some_and(|hash| format!("${hash}") == event_id);
    if !same {
        return Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("{domain} returned a different event than it was asked to sign"),
        ));
    }
    state
        .rooms
        .commit_cosigned(room_id, &event_id, &cosigned)
        .map_err(room_error)?;
    state.rooms.wake_sync_waiters();
    Ok(())
}

/// `POST /_matrix/client/v3/rooms/{room_id}/kick`
///
/// A kick is a `leave` the target did not send, which is why it needs no
/// membership of its own: the spec's auth rules read the sender against the
/// target and decide whether the power levels allow it. That check is ruma's
/// (`docs/divergence.md` §3), so a member without kick power gets `M_FORBIDDEN`
/// from the same code path that refuses any other unauthorized state event.
async fn kick_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "leave")
}

/// `POST /_matrix/client/v3/rooms/{room_id}/ban`
///
/// Ban is its own membership rather than a leave with a flag, because it has
/// to survive the target trying to rejoin: the auth rules refuse a join whose
/// current membership is `ban`, and they can only do that if the state says
/// `ban`.
async fn ban_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "ban")
}

/// `POST /_matrix/client/v3/rooms/{room_id}/unban`
///
/// Unbanning writes `leave`, not "no membership": the room has no way to spell
/// "never here", and `leave` is the state a user who is not banned and not in
/// the room is in.
async fn unban_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "leave")
}

fn targeted_membership(
    state: &AppState,
    sender: &str,
    room_id: &str,
    request: &TargetedMembershipRequest,
    membership: &str,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_membership(
            room_id,
            sender,
            &request.user_id,
            membership,
            request.reason.as_deref(),
            state.key.pair(),
        )
        .map_err(room_error)?;
    // The spec's response is an empty object, not the event ID. A client that
    // wanted the event reads it from the timeline.
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/join`
async fn join_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Value>, MatrixError> {
    join(
        &state,
        &identity.user_id,
        &room_id,
        &server_name_params(query.as_deref()),
    )
    .await
}

/// The repeatable `server_name` query parameters a join may carry.
fn server_name_params(query: Option<&str>) -> Vec<String> {
    form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "server_name" || key == "via")
        .map(|(_, value)| value.into_owned())
        .collect()
}

/// `POST /_matrix/client/v3/knock/{roomIdOrAlias}`
///
/// Asking to be let into a room that will not simply admit you. The server
/// side of knocking has existed since `make_knock`/`send_knock` landed --
/// this is the half a *local* user needs, and without it a knock could
/// arrive from a peer and never be sent by anyone here.
///
/// Nothing decides whether the knock is allowed. `m.room.member` with
/// `membership: knock` goes through the same append as any other membership,
/// and the authorization rules refuse it unless the join rule is `knock` or
/// `knock_restricted` -- which is why knocking on an invite-only room comes
/// back 403 without a line here saying so.
///
/// Re-knocking is deliberately not special-cased. The rules allow
/// knock -> knock, so a user who knocks twice gets a second event and a
/// second chance to be noticed, which is what the spec's "may knock again"
/// amounts to.
async fn knock_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    let request: SelfMembershipRequest = optional_body(&body)?;
    let room_id = resolve_room_target(&state, &room_id_or_alias)?;
    match state.rooms.set_membership_with(
        &room_id,
        &identity.user_id,
        &identity.user_id,
        "knock",
        request.reason.as_deref(),
        &member_profile(&state, &identity.user_id),
        state.key.pair(),
    ) {
        Ok(_) => {
            state.rooms.wake_sync_waiters();
            Ok(Json(json!({ "room_id": room_id })))
        }
        // A room this server does not hold needs `make_knock`/`send_knock`
        // against a server that does, which is the next slice. Saying so is
        // better than a 404 that reads as "no such room": the room may be
        // perfectly real and simply elsewhere.
        Err(crate::rooms::RoomError::UnknownRoom(_)) => Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!(
                "{room_id} is not on this server, and knocking over federation is not implemented"
            ),
        )),
        Err(error) => Err(room_error(error)),
    }
}

/// A room ID, or the room a local alias names.
///
/// Only local aliases: resolving a remote one is a federation round trip
/// that only matters once the knock itself can cross a server boundary.
fn resolve_room_target(state: &AppState, room_id_or_alias: &str) -> Result<String, MatrixError> {
    if !room_id_or_alias.starts_with('#') {
        return Ok(room_id_or_alias.to_owned());
    }
    state
        .directory
        .resolve(room_id_or_alias)
        .map_err(|error| directory_error(&error))?
        .map(|record| record.room_id)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no room is called {room_id_or_alias}"),
            )
        })
}

/// `POST /_matrix/client/v3/join/{room_id_or_alias}`
///
/// Takes either form. An alias is resolved through the directory first; a room
/// ID is used as it stands.
///
/// The two are told apart by their sigil rather than by trying one and falling
/// back to the other. A fallback would turn "this alias points nowhere" into
/// "no such room", which is a different fault with a different fix: one is a
/// directory that needs an entry, the other is a room that does not exist.
async fn join_room_by_id_or_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Value>, MatrixError> {
    let mut servers = server_name_params(query.as_deref());
    let room_id = if room_id_or_alias.starts_with('#') {
        let local = state
            .directory
            .resolve(&room_id_or_alias)
            .map_err(|error| directory_error(&error))?;
        // An alias another server owns is that server's to resolve: ask its
        // directory over federation, and remember the servers it names —
        // they are the ones that can vouch for the room.
        let alias_domain = room_id_or_alias
            .split_once(':')
            .map(|(_, domain)| domain.to_owned());
        let resolved = match (local, alias_domain) {
            (Some(record), _) => Some(record.room_id),
            (None, Some(domain)) if domain != state.config.server.name => {
                match state
                    .federation
                    .remote_query_directory(&domain, &room_id_or_alias)
                    .await
                {
                    Ok(answer) => {
                        for named in answer["servers"].as_array().into_iter().flatten() {
                            if let Some(named) = named.as_str()
                                && !servers.iter().any(|server| server == named)
                            {
                                servers.push(named.to_owned());
                            }
                        }
                        answer["room_id"].as_str().map(str::to_owned)
                    }
                    Err(error) => {
                        tracing::debug!("remote alias resolution failed: {error}");
                        None
                    }
                }
            }
            (None, _) => None,
        };
        resolved.ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no room is called {room_id_or_alias}"),
            )
        })?
    } else {
        room_id_or_alias
    };
    join(&state, &identity.user_id, &room_id, &servers).await
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
async fn delete_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    state
        .directory
        .delete(&room_alias, &identity.user_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({})))
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

fn directory_error(error: &crate::directory::DirectoryError) -> MatrixError {
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

async fn join(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    servers: &[String],
) -> Result<Json<Value>, MatrixError> {
    match state.rooms.set_membership_with(
        room_id,
        user_id,
        user_id,
        "join",
        None,
        &member_profile(state, user_id),
        state.key.pair(),
    ) {
        Ok(_) => Ok(Json(json!({ "room_id": room_id }))),
        // A room this server has never held may still be joinable: through
        // the servers the client named, or the one in the room ID itself.
        Err(crate::rooms::RoomError::UnknownRoom(_)) => {
            join_remote(state, user_id, room_id, servers).await
        }
        Err(error) => Err(room_error(error)),
    }
}

/// The server a pending invite for `user_id` to `room_id` came from, if
/// there is one: the one server certain to hold the room.
fn invite_origin(state: &AppState, user_id: &str, room_id: &str) -> Option<String> {
    state
        .rooms
        .pending_invite(user_id, room_id)
        .ok()
        .flatten()
        .and_then(|record| record["origin"].as_str().map(ToOwned::to_owned))
}

/// Walk the `make_join`/`send_join` handshake as the joining server.
async fn join_remote(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    servers: &[String],
) -> Result<Json<Value>, MatrixError> {
    let candidates = join_candidates(
        &state.config.server.name,
        room_id,
        servers,
        invite_origin(state, user_id, room_id).as_deref(),
    );
    if candidates.is_empty() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{room_id} is not on this server and no server_name was given"),
        ));
    }

    let mut last_refusal = String::new();
    for server in &candidates {
        let (template, version) = match state
            .federation
            .remote_make_join(server, room_id, user_id)
            .await
        {
            Ok(body) => {
                // The resident names the room's version, and this server
                // asked only for versions it speaks -- but a peer is not
                // obliged to answer with one of them, and signing under a
                // version we cannot parse would mint an unnameable event.
                let named = body["room_version"].as_str().unwrap_or_default();
                match ruma::RoomVersionId::try_from(named) {
                    Ok(version) if crate::surface::supports_room_version(named) => {
                        (body["event"].clone(), version)
                    }
                    _ => {
                        last_refusal =
                            format!("{server}: the room is version {named}, which we do not speak");
                        continue;
                    }
                }
            }
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        // Finish the template: timestamp, content hash, our signature —
        // exactly what a resident server's send_join will verify.
        let (join_id, join) = match sign_membership_template(state, &template, &version) {
            Ok(signed) => signed,
            Err(error) => {
                last_refusal = format!("{server}: {error}");
                continue;
            }
        };

        let response = match state
            .federation
            .remote_send_join(server, room_id, &join_id, &join)
            .await
        {
            Ok(body) => body,
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        let mut join = join;
        merge_returned_signatures(&mut join, &response["event"]);

        let arrays =
            |key: &str| -> Vec<Value> { response[key].as_array().cloned().unwrap_or_default() };
        state
            .rooms
            .join_remote(
                room_id,
                &arrays("state"),
                &arrays("auth_chain"),
                &join,
                &join_id,
            )
            .map_err(room_error)?;
        state.rooms.wake_sync_waiters();
        return Ok(Json(json!({ "room_id": room_id })));
    }

    Err(MatrixError::new(
        StatusCode::BAD_GATEWAY,
        "M_UNKNOWN",
        format!("no server admitted the join: {last_refusal}"),
    ))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/leave`
async fn leave_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    let request: SelfMembershipRequest = optional_body(&body)?;
    match state.rooms.set_membership(
        &room_id,
        &identity.user_id,
        &identity.user_id,
        "leave",
        request.reason.as_deref(),
        state.key.pair(),
    ) {
        Ok(_) => Ok(Json(json!({}))),
        // A room this server holds no log for can still be left in the one
        // way that matters here: rejecting the pending invite that named it.
        Err(crate::rooms::RoomError::UnknownRoom(_))
            if state
                .rooms
                .pending_invite(&identity.user_id, &room_id)
                .ok()
                .flatten()
                .is_some() =>
        {
            reject_remote_invite(&state, &identity.user_id, &room_id).await;
            state
                .rooms
                .clear_pending_invite(&identity.user_id, &room_id)
                .map_err(room_error)?;
            Ok(Json(json!({})))
        }
        Err(error) => Err(room_error(error)),
    }
}

/// Walk `make_leave`/`send_leave` against whoever holds the room.
///
/// Best-effort by design, which is Synapse's behavior too: the user must be
/// able to clear an invite even when the inviting server is gone, so a
/// handshake that fails on every candidate is logged and the local record
/// is cleared anyway. The room's own state ends up stale on the resident
/// side only in the case where the resident is unreachable — the one case
/// where it cannot be helped.
async fn reject_remote_invite(state: &AppState, user_id: &str, room_id: &str) {
    for server in join_candidates(
        &state.config.server.name,
        room_id,
        &[],
        invite_origin(state, user_id, room_id).as_deref(),
    ) {
        let (template, version) = match state
            .federation
            .remote_make_leave(&server, room_id, user_id)
            .await
        {
            Ok(body) => {
                let named = body["room_version"].as_str().unwrap_or_default();
                match ruma::RoomVersionId::try_from(named) {
                    Ok(version) if crate::surface::supports_room_version(named) => {
                        (body["event"].clone(), version)
                    }
                    _ => {
                        tracing::debug!("make_leave via {server}: room version {named}");
                        continue;
                    }
                }
            }
            Err(error) => {
                tracing::debug!("make_leave via {server}: {error}");
                continue;
            }
        };
        let (event_id, leave) = match sign_membership_template(state, &template, &version) {
            Ok(signed) => signed,
            Err(error) => {
                tracing::debug!("leave template via {server}: {error}");
                continue;
            }
        };
        match state
            .federation
            .remote_send_leave(&server, room_id, &event_id, &leave)
            .await
        {
            Ok(()) => return,
            Err(error) => tracing::debug!("send_leave via {server}: {error}"),
        }
    }
    tracing::debug!("no server accepted the rejection of {room_id}; clearing locally");
}

#[derive(Debug, Deserialize)]
struct MembersQuery {
    membership: Option<String>,
    not_membership: Option<String>,
    /// A sync token. Accepted and not yet honoured: the roster returned is
    /// the room's present (or, for a former member, the one at their
    /// departure), which is what every client that sends `at` sends it
    /// for -- the token it just synced to, where present and requested
    /// coincide. Recorded here rather than silently dropped.
    #[allow(dead_code)]
    at: Option<String>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/members`
///
/// The room's member events, whole, optionally filtered by membership.
/// Read through [`crate::rooms::Rooms::read_scope`]: a member sees the roster as it is, a former
/// member of a `shared`-visibility room sees it as it stood when they left
/// (#268), and a stranger sees nothing -- this is the membership oracle
/// `/joined_members` guards against, one route over.
async fn room_members(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MembersQuery>,
) -> Result<Json<Value>, MatrixError> {
    let events = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.members())
        .map_err(room_error)?;
    let chunk: Vec<Value> = events
        .into_iter()
        .filter(|event| {
            let membership = event["content"]["membership"].as_str().unwrap_or_default();
            query
                .membership
                .as_deref()
                .is_none_or(|wanted| wanted == membership)
                && query
                    .not_membership
                    .as_deref()
                    .is_none_or(|unwanted| unwanted != membership)
        })
        .collect();
    Ok(Json(json!({ "chunk": chunk })))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/joined_members`
///
/// Restricted to members: the response is the room's roster, and handing it to
/// a non-member would leak who is in a room they cannot see. `joined()` is a
/// prefix scan over the caller's own rooms, so the check costs a scan of what
/// the caller is in rather than a walk of the room.
async fn room_joined_members(
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
    let members = state.rooms.joined_members(&room_id).map_err(room_error)?;
    Ok(Json(json!({ "joined": members })))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/forget`
///
/// Nothing is appended: forgetting is one user's bookkeeping, so the room's
/// log is untouched and every other member's view of it is unchanged. The
/// spec's own wording is that the room is removed from the user's view, not
/// from the server.
async fn forget_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .forget(&identity.user_id, &room_id)
        .map_err(room_error)?;
    Ok(Json(json!({})))
}

/// Parse a request body that the spec allows to be absent.
///
/// `/leave` takes an optional `reason`, and clients send all three of an empty
/// body, `{}`, and a populated object. Extracting `Json<T>` would reject the
/// first with a 400 that the spec does not license, so the bytes are taken raw
/// and only parsed when there are some. A body that is present but malformed
/// is still an error -- silently defaulting there would swallow a client's
/// typo'd `reason` rather than reporting it.
fn optional_body<T: Default + serde::de::DeserializeOwned>(
    body: &axum::body::Bytes,
) -> Result<T, MatrixError> {
    if body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|error| MatrixError::bad_json(error.to_string()))
}

#[derive(Debug, Deserialize)]
struct SyncQuery {
    since: Option<String>,
    timeout: Option<u64>,
    #[serde(rename = "timeline_limit")]
    timeline_limit: Option<usize>,
    filter: Option<String>,
    /// MSC4222. Accepted under the unstable name too, because the MSC shipped
    /// in clients before it was adopted and both spellings are in the wild.
    #[serde(rename = "use_state_after")]
    use_state_after: Option<bool>,
    #[serde(rename = "org.matrix.msc4222.use_state_after")]
    unstable_use_state_after: Option<bool>,
}

impl SyncQuery {
    /// Whether to label the state block `state_after` (MSC4222).
    fn state_after(&self) -> bool {
        self.use_state_after.or(self.unstable_use_state_after) == Some(true)
    }
}

#[derive(Debug, Deserialize)]
struct TypingRequest {
    typing: bool,
    /// Milliseconds. Absent means the server's default; the spec makes it
    /// optional and clients frequently omit it when stopping.
    timeout: Option<u64>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/typing/{user_id}`
///
/// Nothing is appended. Typing has no linear index and never enters the log:
/// it is the clearest case in the API of state that is not an event, and
/// writing it down would mean a restart could restore a claim about the
/// present that is no longer true.
async fn set_typing(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, user_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<TypingRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Only about yourself. The path carries a user ID because the endpoint's
    // shape allows an application service to type as a user it owns; for
    // anyone else it can only ever be their own.
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden(
            "you can only say that you are typing",
        ));
    }
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    if !joined.iter().any(|room| room == &room_id) {
        return Err(MatrixError::forbidden(format!(
            "{user_id} is not in {room_id}"
        )));
    }
    let timeout = request
        .timeout
        .map_or(crate::typing::DEFAULT_TIMEOUT, |ms| {
            std::time::Duration::from_millis(ms)
        });
    state
        .typing
        .set(&room_id, &user_id, request.typing, timeout);
    // The room's remote members hear about it as an m.typing EDU on the
    // next transaction out — and a start or stop with no event traffic
    // still goes, because the drain sends EDU-only transactions.
    if let Ok(domains) = state.rooms.remote_domains(&room_id) {
        for destination in domains {
            state.federation.queue_edu(
                &destination,
                json!({
                    "edu_type": "m.typing",
                    "content": {
                        "room_id": room_id,
                        "user_id": user_id,
                        "typing": request.typing,
                    },
                }),
            );
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/user/{user_id}/account_data/{event_type}`
async fn get_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, event_type)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    read_account_data(&state, &identity, &user_id, "", &event_type)
}

/// `PUT /_matrix/client/v3/user/{user_id}/account_data/{event_type}`
async fn set_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, event_type)): axum::extract::Path<(String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    write_account_data(&state, &identity, &user_id, "", &event_type, &content)
}

/// `GET /_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}`
async fn get_room_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, event_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Value>, MatrixError> {
    read_account_data(&state, &identity, &user_id, &room_id, &event_type)
}

/// `PUT /_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}`
async fn set_room_account_data(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, event_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    write_account_data(&state, &identity, &user_id, &room_id, &event_type, &content)
}

/// Account data is per-user and private, so the `user_id` in the path has to
/// be the caller's.
///
/// The spec says `M_FORBIDDEN` for someone else's, and that is the right code
/// even though the data may not exist: answering `M_NOT_FOUND` for a user who
/// has set nothing and `M_FORBIDDEN` for one who has would turn this endpoint
/// into an oracle for what other people have configured.
fn own_account(identity: &crate::accounts::Identity, user_id: &str) -> Result<(), MatrixError> {
    if identity.user_id == user_id {
        return Ok(());
    }
    Err(MatrixError::forbidden(
        "account data belongs to the user who set it",
    ))
}

fn read_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    user_id: &str,
    room_id: &str,
    event_type: &str,
) -> Result<Json<Value>, MatrixError> {
    own_account(identity, user_id)?;
    state
        .account_data
        .get(user_id, room_id, event_type)
        .map_err(|error| account_data_error(&error))?
        .map(Json)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no {event_type} for {user_id}"),
            )
        })
}

/// Account-data types this endpoint must not write.
///
/// Both have an endpoint of their own that does more than store bytes:
/// `m.push_rules` is edited a rule at a time through `/pushrules/`, and
/// `m.fully_read` moves a receipt through `/read_markers`. Letting a client
/// `PUT` them here would put a second writer on a value the server also
/// maintains, and the two would drift.
const RESERVED_ACCOUNT_DATA: [&str; 2] = ["m.push_rules", "m.fully_read"];

fn write_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    user_id: &str,
    room_id: &str,
    event_type: &str,
    content: &Value,
) -> Result<Json<Value>, MatrixError> {
    own_account(identity, user_id)?;
    if RESERVED_ACCOUNT_DATA.contains(&event_type) {
        return Err(MatrixError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "M_BAD_JSON",
            format!("{event_type} has its own endpoint and cannot be set here"),
        ));
    }
    // The server keeps the bytes and has no opinion about them, so there is no
    // validation of `content` beyond it being JSON -- which the extractor has
    // already established. A client inventing a new `event_type` has to work
    // on a server that has never heard of it.
    //
    // What it may not do is invent them without end. A replacement never
    // counts: the cap is on how much is held, not on how often it changes.
    let cap = state.config.limits.account_data_per_user;
    let is_new = state
        .account_data
        .get(user_id, room_id, event_type)
        .map_err(|error| account_data_error(&error))?
        .is_none();
    if is_new
        && state
            .account_data
            .count(user_id)
            .map_err(|error| account_data_error(&error))?
            >= cap
    {
        return Err(limit_exceeded("account data entries", cap));
    }
    state
        .account_data
        .put(user_id, room_id, event_type, content)
        .map_err(|error| account_data_error(&error))?;
    Ok(Json(json!({})))
}

fn account_data_error(error: &crate::account_data::AccountDataError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

/// A per-account cap from `[limits]` has been reached (#268).
///
/// The same code and shape the delayed-events cap answers with, so a
/// client meets one refusal for "you are holding too much here" wherever
/// it meets it. The limit is named because the operator set it, and the
/// client can only act on a number it can see.
fn limit_exceeded(what: &str, limit: usize) -> MatrixError {
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
}

/// `POST /_matrix/client/v3/pushers/set`
///
/// Register, replace or (with `kind: null`) remove one of the caller's
/// pushers. Registrations are kept, not yet driven: nothing evaluates a
/// push rule against an event yet (#7), so nothing is sent to the URL a
/// client hands over -- which is also why that URL is not fetched, vetted
/// or otherwise touched here.
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
            if request.data["url"].as_str().is_none() {
                return Err(MatrixError::missing_param("an http pusher needs data.url"));
            }
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
fn ruleset_of(state: &AppState, user_id: &str) -> Result<Value, MatrixError> {
    Ok(state
        .account_data
        .get(user_id, "", crate::push_rules::TYPE)
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| crate::push_rules::defaults(user_id)))
}

fn save_ruleset(state: &AppState, user_id: &str, ruleset: &Value) -> Result<(), MatrixError> {
    state
        .account_data
        .put(user_id, "", crate::push_rules::TYPE, ruleset)
        .map_err(|error| account_data_error(&error))?;
    // What was scored under the old rules says nothing under the new.
    state.rooms.forget_highlights(user_id);
    Ok(())
}

/// `unread_notifications.highlight_count`: the reader's unread events in
/// `room_id` that their push rules highlight.
///
/// Scored through the reader's tally ([`crate::rooms::Rooms::unscored_highlights`]):
/// only the bodies after the position last scored are put to the rules, and
/// the ruleset, profile and room context are read only when there is
/// something to score. Nothing unread means nothing highlighted, before any
/// of that.
fn highlight_count(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    unread: &crate::rooms::Unread,
) -> Result<usize, MatrixError> {
    let Some(boundary) = unread.boundary else {
        return Ok(0);
    };
    if unread.notification_count == 0 {
        return Ok(0);
    }
    let pending = state
        .rooms
        .unscored_highlights(room_id, &identity.user_id, boundary)
        .map_err(room_error)?;
    if pending.events.is_empty() {
        return Ok(pending.count);
    }
    let ruleset = ruleset_of(state, &identity.user_id)?;
    let profile = state
        .profiles
        .get(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let room = RoomRuleContext::of(state, room_id)?;
    let context = room.for_reader(&identity.user_id, profile.displayname.as_deref(), room_id);
    let count = pending.count
        + pending
            .events
            .iter()
            .filter(|event| {
                crate::push_rules::evaluate(&ruleset, event, &context)
                    .is_some_and(|actions| crate::push_rules::is_highlight(&actions))
            })
            .count();
    state
        .rooms
        .record_highlights(room_id, &identity.user_id, boundary, pending.upto, count);
    Ok(count)
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

/// `GET /_matrix/client/v1/room_summary/{room_id_or_alias}` (MSC3266)
///
/// Optionally authenticated, which is the whole point: a client showing a
/// preview of a room it has not joined has no membership to offer, and a
/// summary that required one could never be used for a preview.
///
/// Who may see it is decided by the room, not by the caller: a room is
/// summarisable if its join rules invite strangers to look (`public` or
/// `knock`) or its history is `world_readable`. A member may always see their
/// own room's summary whatever the rules say -- they can read the state
/// directly anyway, so refusing here would protect nothing.
async fn room_summary(
    State(state): State<AppState>,
    crate::auth::MaybeAuthenticated(viewer): crate::auth::MaybeAuthenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = if room_id_or_alias.starts_with('#') {
        state
            .directory
            .resolve(&room_id_or_alias)
            .map_err(|error| directory_error(&error))?
            .ok_or_else(|| {
                MatrixError::new(
                    StatusCode::NOT_FOUND,
                    "M_NOT_FOUND",
                    format!("no room is called {room_id_or_alias}"),
                )
            })?
            .room_id
    } else {
        room_id_or_alias
    };

    let summary = state.rooms.summary(&room_id).map_err(room_error)?;
    let membership = match viewer {
        Some(identity) => {
            let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
            joined
                .iter()
                .any(|room| room == &room_id)
                .then(|| "join".to_owned())
        }
        None => None,
    };

    let open =
        matches!(summary.join_rule.as_deref(), Some("public" | "knock")) || summary.world_readable;
    if !open && membership.is_none() {
        // M_FORBIDDEN rather than M_NOT_FOUND: the room ID came from
        // somewhere, so pretending it does not exist tells a caller who
        // already has the ID nothing it did not know, and misleads a caller
        // who mistyped one.
        return Err(MatrixError::forbidden(format!(
            "{room_id} does not publish a summary"
        )));
    }

    let mut body = serde_json::Map::new();
    body.insert("room_id".to_owned(), json!(summary.room_id));
    body.insert(
        "num_joined_members".to_owned(),
        json!(summary.num_joined_members),
    );
    body.insert("world_readable".to_owned(), json!(summary.world_readable));
    body.insert("guest_can_join".to_owned(), json!(summary.guest_can_join));
    // Absent rather than null for everything the room never set: MSC3266's
    // fields are optional, and a client distinguishing "no topic" from "an
    // empty topic" needs the key to be missing rather than null.
    for (field, value) in [
        ("name", summary.name),
        ("topic", summary.topic),
        ("avatar_url", summary.avatar_url),
        ("canonical_alias", summary.canonical_alias),
        ("join_rule", summary.join_rule),
        ("room_type", summary.room_type),
        ("encryption", summary.encryption),
        ("membership", membership),
    ] {
        if let Some(value) = value {
            body.insert(field.to_owned(), json!(value));
        }
    }
    Ok(Json(Value::Object(body)))
}

/// `POST /_matrix/client/v3/user/{user_id}/filter`
///
/// The filter is parsed here rather than stored as opaque bytes, so a
/// malformed one is refused at upload instead of on every sync that quotes it.
async fn create_filter(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(filter): Json<crate::filters::Filter>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    // Every upload mints a new id, so every upload is growth; a client that
    // wants the same filter back is expected to keep the id it was given.
    let cap = state.config.limits.filters_per_user;
    if state
        .filters
        .count(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        >= cap
    {
        return Err(limit_exceeded("filters", cap));
    }
    let filter_id = state
        .filters
        .put(&user_id, &filter)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "filter_id": filter_id })))
}

/// `GET /_matrix/client/v3/user/{user_id}/filter/{filter_id}`
async fn get_filter(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, filter_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let filter = state
        .filters
        .get(&user_id, &filter_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no filter {filter_id}"),
            )
        })?;
    Ok(Json(
        serde_json::to_value(filter).unwrap_or_else(|_| json!({})),
    ))
}

/// The filter a `/sync` request is asking for, in either of the two forms.
///
/// A client may send the JSON inline or the id of one it uploaded. Both end up
/// as the same parsed `Filter`, so a filter cannot mean one thing uploaded and
/// another inline.
///
/// An unknown id is an error rather than "no filter". Silently syncing
/// unfiltered would send a client on a slow connection everything it just
/// asked not to receive, which is the opposite of what it wanted and looks
/// like the server ignoring it.
fn requested_filter(
    state: &AppState,
    user_id: &str,
    raw: Option<&str>,
) -> Result<Option<crate::filters::Filter>, MatrixError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.starts_with('{') {
        return serde_json::from_str(raw)
            .map(Some)
            .map_err(|error| MatrixError::bad_json(error.to_string()));
    }
    state
        .filters
        .get(user_id, raw)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .map(Some)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("no filter {raw}"),
            )
        })
}

/// `GET /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags`
async fn get_tags(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    // A user who never tagged anything gets an empty map, not a 404: "no
    // tags" is an ordinary answer here, where for general account data an
    // unset type is a 404. The difference is that this endpoint's shape is
    // fixed by the spec and a client iterates the map unconditionally.
    Ok(Json(tags))
}

/// `PUT /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}`
async fn set_tag(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, tag)): axum::extract::Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let mut tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    if !tags["tags"].is_object() {
        tags["tags"] = json!({});
    }
    // The body is the tag's content -- `order` and whatever else the client
    // keeps there. Stored as given: the server has no opinion about tag
    // content for the same reason it has none about account data generally.
    tags["tags"][&tag] = content;
    state
        .account_data
        .put(&user_id, &room_id, "m.tag", &tags)
        .map_err(|error| account_data_error(&error))?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}`
async fn delete_tag(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((user_id, room_id, tag)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    own_account(&identity, &user_id)?;
    let mut tags = state
        .account_data
        .get(&user_id, &room_id, "m.tag")
        .map_err(|error| account_data_error(&error))?
        .unwrap_or_else(|| json!({ "tags": {} }));
    let removed = tags["tags"]
        .as_object_mut()
        .is_some_and(|map| map.remove(&tag).is_some());
    if !removed {
        // The spec's own answer for deleting a tag that is not there. Quietly
        // returning {} would be defensible; 404 is what Synapse does and what
        // clients therefore already handle.
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{room_id} is not tagged {tag}"),
        ));
    }
    state
        .account_data
        .put(&user_id, &room_id, "m.tag", &tags)
        .map_err(|error| account_data_error(&error))?;
    Ok(Json(json!({})))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
// The postfix repetition is the spec's: these are `/keys/upload`'s three
// wire field names, verbatim.
#[allow(clippy::struct_field_names)]
struct UploadKeysRequest {
    device_keys: Option<Value>,
    one_time_keys: Option<serde_json::Map<String, Value>>,
    fallback_keys: Option<serde_json::Map<String, Value>>,
}

/// `POST /_matrix/client/v3/keys/upload`
async fn upload_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<UploadKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(device_keys) = &request.device_keys {
        // The claim inside must match the authenticated caller. Accepting a
        // body that names another user or device would let any account plant
        // keys on another's identity, and verification downstream trusts
        // exactly this mapping.
        let claimed_user = device_keys["user_id"].as_str();
        let claimed_device = device_keys["device_id"].as_str();
        if claimed_user != Some(identity.user_id.as_str())
            || claimed_device != Some(identity.device_id.as_str())
        {
            return Err(MatrixError::forbidden(
                "device_keys must belong to the uploading device",
            ));
        }
        state
            .devices
            .upload_device_keys(&identity.user_id, &identity.device_id, device_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // Identity keys changing is what "device list changed" means — other
        // users must re-query before encrypting to this user again. One-time
        // and fallback keys are consumables and do not move the watermark.
        let seq = state.rooms.allocate_stream_id();
        state
            .devices
            .mark_device_list_changed(&identity.user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // Anyone long-polling `/sync` should hear about it now, not at the
        // timeout: encrypting to a stale device set is the failure mode.
        state.rooms.wake_sync_waiters();
    }
    if let Some(fallback_keys) = &request.fallback_keys {
        state
            .devices
            .upload_fallback_keys(&identity.user_id, &identity.device_id, fallback_keys)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let counts = match &request.one_time_keys {
        Some(one_time_keys) => {
            // Counted before the write, against what the device already
            // holds plus what it is sending. A key that re-uses an id it
            // already uploaded is counted twice here; that errs toward
            // refusing at the cap, and a client at the cap has no business
            // uploading more.
            let cap = state.config.limits.one_time_keys_per_device;
            let held = state
                .devices
                .one_time_key_total(&identity.user_id, &identity.device_id)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            if held.saturating_add(one_time_keys.len()) > cap {
                return Err(limit_exceeded("one-time keys per device", cap));
            }
            state
                .devices
                .upload_one_time_keys(&identity.user_id, &identity.device_id, one_time_keys)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
        }
        None => state
            .devices
            .one_time_key_counts(&identity.user_id, &identity.device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?,
    };
    Ok(Json(json!({ "one_time_key_counts": counts })))
}

#[derive(Debug, Deserialize)]
struct QueryKeysRequest {
    device_keys: serde_json::Map<String, Value>,
}

/// `POST /_matrix/client/v3/keys/query`
async fn query_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<QueryKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut device_keys = serde_json::Map::new();
    for (user_id, wanted) in &request.device_keys {
        let all = state
            .devices
            .all_device_keys(user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        // An empty list means every device; a non-empty one narrows.
        let mut narrowed: serde_json::Map<String, Value> = match wanted.as_array() {
            Some(list) if !list.is_empty() => {
                let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
                all.into_iter()
                    .filter(|(device_id, _)| names.contains(&device_id.as_str()))
                    .collect()
            }
            _ => all,
        };
        // A user the store knows nothing about, who exists only through
        // an appservice, gets MSC3984's second chance: the service
        // answers for its own users' keys. Local keys win when present —
        // the store is what this server vouched for.
        if narrowed.is_empty()
            && let Some(registration) = state.appservices.exclusive_claimant(user_id)
        {
            let answer =
                crate::appservices::proxy_key_query(registration, &json!({ user_id: wanted }))
                    .await;
            if let Some(theirs) = answer[user_id].as_object() {
                narrowed.clone_from(theirs);
            }
        }
        device_keys.insert(user_id.clone(), Value::Object(narrowed));
    }
    // Cross-signing keys ride along for every queried user. The
    // user-signing key is the exception: it exists to sign *other people*,
    // which is nobody else's business — only its owner gets it back.
    let mut master_keys = serde_json::Map::new();
    let mut self_signing_keys = serde_json::Map::new();
    let mut user_signing_keys = serde_json::Map::new();
    for user_id in request.device_keys.keys() {
        let fetch = |key_type: &str| {
            state
                .devices
                .cross_signing_key(user_id, key_type)
                .map_err(|error| MatrixError::internal(&error.to_string()))
        };
        if let Some(key) = fetch("master")? {
            master_keys.insert(user_id.clone(), key);
        }
        if let Some(key) = fetch("self_signing")? {
            self_signing_keys.insert(user_id.clone(), key);
        }
        if user_id == &identity.user_id
            && let Some(key) = fetch("user_signing")?
        {
            user_signing_keys.insert(user_id.clone(), key);
        }
    }
    Ok(Json(json!({
        "device_keys": device_keys,
        "master_keys": master_keys,
        "self_signing_keys": self_signing_keys,
        "user_signing_keys": user_signing_keys,
        "failures": {},
    })))
}

#[derive(Debug, Deserialize)]
struct ClaimKeysRequest {
    one_time_keys: serde_json::Map<String, Value>,
}

/// `POST /_matrix/client/v3/keys/claim`
async fn claim_keys(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    Json(request): Json<ClaimKeysRequest>,
) -> Result<Json<Value>, MatrixError> {
    let mut claimed = serde_json::Map::new();
    for (user_id, devices) in &request.one_time_keys {
        let Some(devices) = devices.as_object() else {
            continue;
        };
        let mut per_user = serde_json::Map::new();
        for (device_id, algorithm) in devices {
            let Some(algorithm) = algorithm.as_str() else {
                continue;
            };
            if let Some((key_id, key)) = state
                .devices
                .claim_key(user_id, device_id, algorithm)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
            {
                per_user.insert(device_id.clone(), json!({ key_id: key }));
                continue;
            }
            // A device with none left is simply absent from the response,
            // which is the spec's shape: absence says "no key", and the
            // caller falls back to the fallback key or fails the session.
            // Unless the user exists only through an appservice — then
            // MSC3983 gives that service the chance to hand over a key
            // directly, because its key store is the real one.
            if let Some(registration) = state.appservices.exclusive_claimant(user_id) {
                let answer = crate::appservices::proxy_otk_claim(
                    registration,
                    &json!({ user_id: { device_id: [algorithm] } }),
                )
                .await;
                if let Some(keys) = answer[user_id][device_id].as_object()
                    && !keys.is_empty()
                {
                    per_user.insert(device_id.clone(), Value::Object(keys.clone()));
                }
            }
        }
        if !per_user.is_empty() {
            claimed.insert(user_id.clone(), Value::Object(per_user));
        }
    }
    Ok(Json(json!({ "one_time_keys": claimed, "failures": {} })))
}

#[derive(Debug, Deserialize)]
struct KeyChangesQuery {
    from: String,
    to: String,
}

/// `GET /_matrix/client/v3/keys/changes`
///
/// The catch-up form of `device_lists.changed`: a client that was offline
/// asks for the window between the token it went to sleep on and the token
/// its first sync just returned. Same computation, same visibility rule —
/// only the window is caller-chosen.
async fn key_changes(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<KeyChangesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let from = query
        .from
        .parse::<crate::tokens::Sync>()
        .map_err(|error| MatrixError::bad_json(error.to_string()))?
        .0;
    let to = query
        .to
        .parse::<crate::tokens::Sync>()
        .map_err(|error| MatrixError::bad_json(error.to_string()))?
        .0;
    let changed = visible_device_changes(&state, &identity, from, to)?;
    Ok(Json(json!({ "changed": changed, "left": [] })))
}

// The postfix repetition is the spec's: these are the endpoint's three wire
// field names, verbatim.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CrossSigningUpload {
    master_key: Option<Value>,
    self_signing_key: Option<Value>,
    user_signing_key: Option<Value>,
}

/// `POST /_matrix/client/v3/keys/device_signing/upload`
async fn upload_cross_signing(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CrossSigningUpload>,
) -> Result<Json<Value>, MatrixError> {
    let uploads = [
        ("master", &request.master_key),
        ("self_signing", &request.self_signing_key),
        ("user_signing", &request.user_signing_key),
    ];
    for (key_type, key) in uploads {
        let Some(key) = key else { continue };
        // The same rule as /keys/upload: the body's claim must match the
        // authenticated caller, or any account could plant a master key on
        // another's identity and own every verification derived from it.
        if key["user_id"].as_str() != Some(identity.user_id.as_str()) {
            return Err(MatrixError::forbidden(
                "cross-signing keys must belong to the uploading user",
            ));
        }
        state
            .devices
            .upload_cross_signing(&identity.user_id, key_type, key)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    // New cross-signing keys are a device-list change: peers must re-query
    // before they can trust (or distrust) the new signing tree.
    let seq = state.rooms.allocate_stream_id();
    state
        .devices
        .mark_device_list_changed(&identity.user_id, seq)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/keys/signatures/upload`
async fn upload_signatures(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    Json(request): Json<serde_json::Map<String, Value>>,
) -> Result<Json<Value>, MatrixError> {
    let mut failures = serde_json::Map::new();
    for (user_id, targets) in &request {
        let Some(targets) = targets.as_object() else {
            continue;
        };
        for (target, signed) in targets {
            let added = state
                .devices
                .add_signatures(user_id, target, signed)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
            if !added {
                // The spec's failure shape: per-target errors, not a failed
                // request — the other signatures in the batch still landed.
                failures
                    .entry(user_id.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()))
                    .as_object_mut()
                    .expect("just inserted an object")
                    .insert(
                        target.clone(),
                        json!({ "errcode": "M_NOT_FOUND", "error": "no such key" }),
                    );
            }
        }
    }
    Ok(Json(json!({ "failures": failures })))
}

/// The API's version is a string; storage counts. Anything non-numeric can
/// name no stored version, and "no such version" is 404 territory.
fn parse_backup_version(version: &str) -> Result<u64, MatrixError> {
    version.parse::<u64>().map_err(|_| {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        )
    })
}

fn backup_version_body(info: &crate::backups::VersionInfo) -> Value {
    json!({
        "algorithm": info.algorithm,
        "auth_data": info.auth_data,
        "count": info.count,
        "etag": info.etag.to_string(),
        "version": info.version.to_string(),
    })
}

fn backup_error(error: &spindle_store::StoreError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

#[derive(Debug, Deserialize)]
struct CreateBackupRequest {
    algorithm: String,
    auth_data: Value,
}

/// `POST /_matrix/client/v3/room_keys/version`
async fn create_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CreateBackupRequest>,
) -> Result<Json<Value>, MatrixError> {
    let version = state
        .backups
        .create_version(&identity.user_id, &request.algorithm, &request.auth_data)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({ "version": version.to_string() })))
}

/// `GET /_matrix/client/v3/room_keys/version`
async fn latest_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let Some(info) = state
        .backups
        .latest_version(&identity.user_id)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no backup exists".to_owned(),
        ));
    };
    Ok(Json(backup_version_body(&info)))
}

/// `GET /_matrix/client/v3/room_keys/version/{version}`
async fn get_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    let Some(info) = state
        .backups
        .version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        ));
    };
    Ok(Json(backup_version_body(&info)))
}

/// `PUT /_matrix/client/v3/room_keys/version/{version}`
async fn update_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
    Json(request): Json<CreateBackupRequest>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    let Some(info) = state
        .backups
        .version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("no backup version {version}"),
        ));
    };
    // Same algorithm only: changing the algorithm mid-version would leave a
    // backup whose entries no one recipe decrypts. A new algorithm is a new
    // version.
    if request.algorithm != info.algorithm {
        return Err(MatrixError::bad_json(
            "the algorithm of an existing backup cannot change".to_owned(),
        ));
    }
    state
        .backups
        .update_version(
            &identity.user_id,
            version,
            &request.algorithm,
            &request.auth_data,
        )
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/room_keys/version/{version}`
async fn delete_backup_version(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(version): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let version = parse_backup_version(&version)?;
    state
        .backups
        .delete_version(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    // Deleting the already-deleted succeeds quietly: the state the caller
    // asked for is the state that holds.
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct BackupQuery {
    version: String,
}

/// Reads may name any *live* version; a deleted or never-created one is 404.
///
/// Returning an empty backup instead would be worse than the error: a
/// restoring client would conclude its history is simply gone.
fn require_live_version(
    state: &AppState,
    user_id: &str,
    requested: &str,
) -> Result<u64, MatrixError> {
    let version = parse_backup_version(requested)?;
    state
        .backups
        .version(user_id, version)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no backup version {version}"),
            )
        })?;
    Ok(version)
}

/// The version every write must name: the *current* one.
///
/// A client writing to an old version is a client that missed a reset —
/// its recovery key no longer opens the live backup, and accepting the
/// write would strand those keys where no restore will look. 403 with the
/// current version is the spec's way of saying "re-fetch and re-encrypt".
fn require_current_version(
    state: &AppState,
    user_id: &str,
    requested: &str,
) -> Result<u64, MatrixError> {
    let requested = parse_backup_version(requested)?;
    let current = state
        .backups
        .latest_version(user_id)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "no backup exists".to_owned(),
            )
        })?;
    if requested != current.version {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_WRONG_ROOM_KEYS_VERSION",
            format!("the current backup version is {}", current.version),
        ));
    }
    Ok(requested)
}

fn backup_summary(state: &AppState, user_id: &str, version: u64) -> Result<Value, MatrixError> {
    let info = state
        .backups
        .version(user_id, version)
        .map_err(|error| backup_error(&error))?
        .ok_or_else(|| MatrixError::internal("backup vanished mid-request"))?;
    Ok(json!({ "etag": info.etag.to_string(), "count": info.count }))
}

/// `PUT /_matrix/client/v3/room_keys/keys`
async fn put_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    if let Some(rooms) = request["rooms"].as_object() {
        for (room_id, room) in rooms {
            store_backup_room(&state, &identity.user_id, version, room_id, room)?;
        }
    }
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

fn store_backup_room(
    state: &AppState,
    user_id: &str,
    version: u64,
    room_id: &str,
    room: &Value,
) -> Result<(), MatrixError> {
    if let Some(sessions) = room["sessions"].as_object() {
        for (session_id, data) in sessions {
            state
                .backups
                .put_key(user_id, version, room_id, session_id, data)
                .map_err(|error| backup_error(&error))?;
        }
    }
    Ok(())
}

/// `GET /_matrix/client/v3/room_keys/keys`
async fn get_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(json!({ "rooms": rooms })))
}

/// `PUT /_matrix/client/v3/room_keys/keys/{room_id}`
async fn put_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    store_backup_room(&state, &identity.user_id, version, &room_id, &request)?;
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

/// `GET /_matrix/client/v3/room_keys/keys/{room_id}`
async fn get_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    let sessions = rooms
        .get(&room_id)
        .cloned()
        .unwrap_or_else(|| json!({ "sessions": {} }));
    Ok(Json(sessions))
}

/// `PUT /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn put_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
    Json(data): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(&state, &identity.user_id, &query.version)?;
    state
        .backups
        .put_key(&identity.user_id, version, &room_id, &session_id, &data)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(backup_summary(&state, &identity.user_id, version)?))
}

/// The shared body of the three DELETE granularities.
///
/// Deletes go through the current-version rule like writes do: a client
/// deleting from a superseded version thinks it is trimming the live
/// backup, and quietly deleting somewhere else would let it believe it did.
fn delete_backup(
    state: &AppState,
    user_id: &str,
    requested: &str,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_current_version(state, user_id, requested)?;
    state
        .backups
        .delete_keys(user_id, version, room_id, session_id)
        .map_err(|error| backup_error(&error))?;
    Ok(Json(backup_summary(state, user_id, version)?))
}

/// `DELETE /_matrix/client/v3/room_keys/keys`
async fn delete_backup_keys(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(&state, &identity.user_id, &query.version, None, None)
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{room_id}`
async fn delete_backup_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(
        &state,
        &identity.user_id,
        &query.version,
        Some(&room_id),
        None,
    )
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn delete_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    delete_backup(
        &state,
        &identity.user_id,
        &query.version,
        Some(&room_id),
        Some(&session_id),
    )
}

/// `GET /_matrix/client/v3/room_keys/keys/{room_id}/{session_id}`
async fn get_backup_session(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, session_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<BackupQuery>,
) -> Result<Json<Value>, MatrixError> {
    let version = require_live_version(&state, &identity.user_id, &query.version)?;
    let rooms = state
        .backups
        .keys(&identity.user_id, version)
        .map_err(|error| backup_error(&error))?;
    let Some(data) = rooms
        .get(&room_id)
        .and_then(|room| room["sessions"].get(&session_id))
    else {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such session in the backup".to_owned(),
        ));
    };
    Ok(Json(data.clone()))
}

#[derive(Debug, Deserialize)]
struct SendToDeviceRequest {
    messages: serde_json::Map<String, Value>,
}

/// `PUT /_matrix/client/v3/sendToDevice/{event_type}/{txn_id}`
async fn send_to_device(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((event_type, txn_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<SendToDeviceRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Same replay table as /send: a retried batch must not deliver twice.
    // The stored value is unused here — presence is the answer.
    let txn_key = spindle_core::keys::transaction(
        &identity.user_id,
        &identity.device_id,
        &format!("to-device/{txn_id}"),
    );
    if let Ok(Some(_)) = spindle_store::ReadView::get(state.store.as_ref(), &txn_key) {
        return Ok(Json(json!({})));
    }

    for (target_user, per_device) in &request.messages {
        let Some(per_device) = per_device.as_object() else {
            continue;
        };
        for (target_device, content) in per_device {
            let devices: Vec<String> = if target_device == "*" {
                state
                    .devices
                    .all_device_keys(target_user)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?
                    .keys()
                    .cloned()
                    .collect()
            } else {
                vec![target_device.clone()]
            };
            for device_id in devices {
                let seq = state.rooms.allocate_stream_id();
                let message = json!({
                    "type": event_type,
                    "sender": identity.user_id,
                    "content": content,
                });
                state
                    .devices
                    .queue_to_device(target_user, &device_id, seq, &message)
                    .map_err(|error| MatrixError::internal(&error.to_string()))?;
            }
        }
    }
    spindle_store::Store::put(state.store.as_ref(), &txn_key, b"")
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    // A recipient may be blocked in a long-poll right now, and a to-device
    // message lands in no room, so nothing else would wake them.
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct SlidingQuery {
    pos: Option<String>,
    timeout: Option<u64>,
}

/// `POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync`
///
/// Stateless (`sliding.rs` explains why): `pos` is a stream position, and the
/// request carries its lists in full each time. The response sends a room in
/// full (`initial: true`) on an initial request, and after that only the
/// rooms the stream says changed — the one scan `changed_rooms` exists for.
async fn sliding_sync(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SlidingQuery>,
    Json(request): Json<crate::sliding::SlidingRequest>,
) -> Result<Json<Value>, MatrixError> {
    let since = match query.pos.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Sync>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let lists = request.decoded_lists().map_err(MatrixError::bad_json)?;
    let subscriptions = request
        .decoded_subscriptions()
        .map_err(MatrixError::bad_json)?;

    let mut position = state.rooms.stream_position();
    // Long-poll before answering, not after assembling: an incremental request
    // with nothing new blocks here, and answers fresh when something lands.
    if let Some(since) = since {
        let timeout_ms = request.timeout.or(query.timeout).unwrap_or(0).min(60_000);
        if position <= since && timeout_ms > 0 {
            state
                .rooms
                .wait_for_event(std::time::Duration::from_millis(timeout_ms))
                .await;
            position = state.rooms.stream_position();
        }
    }

    // The sorted room list: every joined room, newest activity first. The
    // sort is recomputed per request because it is what the ranges index
    // into, and a stale order would make the client's window show the wrong
    // rooms — the exact bug sliding sync exists to avoid.
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    let mut ordered: Vec<(String, i64)> = Vec::with_capacity(joined.len());
    for room_id in joined {
        let activity = state.rooms.last_activity(&room_id).map_err(room_error)?;
        ordered.push((room_id, activity));
    }
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Every room this request may be answered with. A list window can only
    // produce rooms out of `ordered`, which came from the caller's own
    // memberships -- but a *subscription* is an arbitrary room id lifted
    // straight out of the request body, and nothing downstream of here looks
    // at who is asking: `sliding_room_entry` takes an identity and never
    // consults it. Without this set, any account on the server could name any
    // room and be sent its name, its state and its whole timeline.
    let visible: std::collections::HashSet<&str> = ordered
        .iter()
        .map(|(room_id, _)| room_id.as_str())
        .collect();

    // Which rooms may appear at all in an incremental response. Asked only
    // about rooms this response could mention, which is exactly `visible`:
    // asking the server's whole stream instead would price a client's
    // sliding sync at everyone else's traffic.
    let changed: Option<std::collections::HashSet<String>> = match since {
        Some(since) => Some(
            state
                .rooms
                .changed_rooms(visible.iter().copied(), since, position)
                .map_err(room_error)?,
        ),
        None => None,
    };

    let mut rooms_out: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut lists_out = serde_json::Map::new();

    // What each room in view should carry: the union over every list whose
    // window it is in, plus any direct subscription. A room in two windows is
    // sent once, with the larger ask.
    let mut wanted: std::collections::HashMap<String, (Vec<(String, String)>, usize)> =
        std::collections::HashMap::new();
    for (name, list) in &lists {
        let indices = crate::sliding::indices_in_view(&list.ranges, ordered.len());
        for &index in &indices {
            let room_id = &ordered[index].0;
            let entry = wanted
                .entry(room_id.clone())
                .or_insert_with(|| (Vec::new(), 0));
            entry.0.extend(list.required_state.iter().cloned());
            entry.1 = entry.1.max(list.timeline_limit);
        }
        lists_out.insert(name.clone(), json!({ "count": ordered.len() }));
    }
    for (room_id, subscription) in &subscriptions {
        // Silence rather than an error: a client that subscribed to a room it
        // has since left should get a response about its other rooms, not a
        // rejected request -- and a client fishing for a room it was never in
        // learns nothing from the difference between "no such room" and "not
        // yours", which is the same reason the room directory does not
        // distinguish them.
        if !visible.contains(room_id.as_str()) {
            continue;
        }
        let entry = wanted
            .entry(room_id.clone())
            .or_insert_with(|| (Vec::new(), 0));
        entry.0.extend(subscription.required_state.iter().cloned());
        entry.1 = entry.1.max(subscription.timeline_limit);
    }

    for (room_id, (required_state, timeline_limit)) in wanted {
        // Incrementally, silence about an unchanged room *is* the answer.
        if let Some(changed) = &changed
            && !changed.contains(&room_id)
        {
            continue;
        }
        let entry = sliding_room_entry(
            &state,
            &identity,
            &room_id,
            &required_state,
            timeline_limit,
            since.is_none(),
        )?;
        rooms_out.insert(room_id, entry);
    }

    Ok(Json(json!({
        "pos": crate::tokens::Sync(position).to_string(),
        "lists": lists_out,
        "rooms": rooms_out,
        "extensions": {},
    })))
}

/// One room's sliding-sync entry.
fn sliding_room_entry(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    required_state: &[(String, String)],
    timeline_limit: usize,
    initial: bool,
) -> Result<Value, MatrixError> {
    let name = state
        .rooms
        .state_event_unscoped(room_id, "m.room.name", "")
        .ok()
        .and_then(|content| content["name"].as_str().map(str::to_owned));
    // A wildcard has to be answered by looking at everything; a list of
    // named keys does not. Element X asks for a handful of concrete keys
    // and gets sent the whole room state to filter down — a stored-body
    // read and a JSON parse per state event, per room in the window, per
    // request, to return three of them.
    let concrete = !required_state.is_empty()
        && required_state
            .iter()
            .all(|(event_type, state_key)| event_type != "*" && state_key != "*");
    let state_events: Vec<Value> = if required_state.is_empty() {
        Vec::new()
    } else if concrete {
        // Deduplicated, because state is a map and the wildcard path reads
        // it as one: a client that names `m.room.name` twice must not be
        // sent the event twice merely because it asked twice.
        let mut seen = std::collections::HashSet::new();
        required_state
            .iter()
            .filter_map(|(event_type, state_key)| {
                let key = if state_key == "$ME" {
                    identity.user_id.as_str()
                } else {
                    state_key.as_str()
                };
                if !seen.insert((event_type.as_str(), key)) {
                    return None;
                }
                // Absent state is absent, not an error: a room with no
                // name simply has no m.room.name to send.
                state.rooms.state_event_full(room_id, event_type, key).ok()
            })
            .collect()
    } else {
        state
            .rooms
            .state(room_id)
            .map_err(room_error)?
            .into_iter()
            .filter(|event| {
                let event_type = event["type"].as_str().unwrap_or_default();
                let state_key = event["state_key"].as_str().unwrap_or_default();
                crate::sliding::wants_state(
                    required_state,
                    &identity.user_id,
                    event_type,
                    state_key,
                )
            })
            .collect()
    };
    let (events, limited, prev_batch) = if timeline_limit == 0 {
        (Vec::new(), false, None)
    } else {
        state
            .rooms
            .timeline_tail_public(room_id, timeline_limit.min(50))
            .map_err(room_error)?
    };
    let timeline = crate::sliding::Timeline {
        events,
        limited,
        prev_batch: prev_batch.map(|li| crate::tokens::Pagination(li).to_string()),
    };
    let joined_count = state
        .rooms
        .joined_member_count(room_id)
        .map_err(room_error)?;
    let unread = state
        .rooms
        .unread(room_id, &identity.user_id)
        .map_err(room_error)?;
    let highlight_count = highlight_count(state, identity, room_id, &unread)?;
    Ok(crate::sliding::room_entry(
        name,
        state_events,
        timeline,
        joined_count,
        crate::sliding::Counts {
            notification_count: unread.notification_count,
            highlight_count,
        },
        initial,
    ))
}

/// The device-list changes in `(since, until]` that `identity` may see.
///
/// The watermark scan names everyone; this narrows it to the asker's own
/// account plus users they share a room with. Not an optimization — an
/// unnarrowed list would tell any account which strangers reprovisioned a
/// device and when, which is surveillance the room graph never granted.
fn visible_device_changes(
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

/// The E2EE sections of a `/sync` response, fetched before assembly.
///
/// To-device messages come first and destructively (`since` acknowledges the
/// previous batch — devices.rs explains the shared-counter protocol), so a
/// crash after this point re-delivers rather than loses. Device-list changes
/// are a diff and so exist only for an incremental sync — an initial sync's
/// client queries every key it cares about anyway. Their window is capped at
/// this response's own token so a change landing mid-assembly is reported by
/// the sync that owns it, exactly once.
#[allow(clippy::type_complexity)]
fn sync_device_sections(
    state: &AppState,
    identity: &crate::accounts::Identity,
    since: Option<u64>,
    next_batch: u64,
) -> Result<
    (
        Vec<Value>,
        Vec<String>,
        serde_json::Map<String, Value>,
        Vec<String>,
    ),
    MatrixError,
> {
    let to_device = state
        .devices
        .take_pending(&identity.user_id, &identity.device_id, since)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let device_changes = match since {
        Some(since) => visible_device_changes(state, identity, since, next_batch)?,
        None => Vec::new(),
    };
    let key_counts = state
        .devices
        .one_time_key_counts(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let unused_fallback = state
        .devices
        .unused_fallback_algorithms(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((to_device, device_changes, key_counts, unused_fallback))
}

/// `GET /_matrix/client/v3/sync`
///
/// The token is a position in the server-global stream (SPEC §10.2), because
/// `/sync` is the one endpoint that needs an order *across* rooms and the
/// linear index only orders within one.
async fn sync(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SyncQuery>,
) -> Result<axum::response::Response, MatrixError> {
    let since = match query.since.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Sync>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let filter = requested_filter(&state, &identity.user_id, query.filter.as_deref())?;
    // A filter's own timeline limit outranks the query parameter: the client
    // set both, and the filter is the more specific of the two.
    let timeline_limit = filter
        .as_ref()
        .and_then(|filter| filter.room.timeline.as_ref())
        .and_then(|timeline| timeline.limit)
        .or(query.timeline_limit)
        .unwrap_or(20)
        .clamp(1, 100);

    // Asked for in the read, not filtered out of the answer: see
    // `Rooms::sync`. The exact narrowing still happens in `sync_join`,
    // against the filtered timeline; this is what stops the roster being
    // read and parsed in the first place.
    let state_section = filter
        .as_ref()
        .and_then(|filter| filter.room.state.as_ref());
    let lazy_members = state_section.and_then(|state| state.lazy_load_members) == Some(true);
    // A client that asked for the whole state block and applied no filter to
    // it wants exactly the bytes the state-render cache already holds. In
    // that case nothing downstream narrows the block, so materializing it
    // into `Value`s only to serialize them straight back is work done to
    // arrive where we started -- `sync_join` splices the cached render
    // instead. Any state filter at all, however permissive, takes the
    // ordinary path: deciding which filters happen to be no-ops is a way to
    // be subtly wrong, and the win is in the unfiltered case anyway.
    let state_block = if since.is_some() {
        // An incremental sync carries no state block; the mode is moot, and
        // `Rendered` is the one that materializes nothing in that case.
        crate::rooms::StateBlock::Rendered
    } else if lazy_members {
        crate::rooms::StateBlock::LazyMembers
    } else if state_section.is_some() {
        crate::rooms::StateBlock::Rendered
    } else {
        crate::rooms::StateBlock::Deferred
    };
    let mut result = state
        .rooms
        .sync(&identity.user_id, since, timeline_limit, state_block)
        .map_err(room_error)?;

    // Long-poll, but only for an incremental sync: an initial sync always has
    // something to say, and blocking one would leave a first-time client
    // staring at nothing for the whole timeout.
    if let Some(since) = since {
        let timeout = std::time::Duration::from_millis(query.timeout.unwrap_or(0).min(60_000));
        if result.rooms.is_empty() && !timeout.is_zero() {
            // Either an appended event or a change in who is typing ends the
            // wait. Typing is not an event and has no stream position, so it
            // cannot be discovered by re-reading the log -- without this arm a
            // client would learn that someone started typing only when they
            // stopped and sent the message.
            tokio::select! {
                () = state.rooms.wait_for_event(timeout) => {}
                () = state.typing.wait(timeout) => {}
            }
            result = state
                .rooms
                .sync(&identity.user_id, Some(since), timeline_limit, state_block)
                .map_err(room_error)?;
        }
    }

    let join = sync_join(
        &state,
        &identity,
        result.rooms,
        filter.as_ref(),
        query.state_after(),
        state_block,
    )?;

    let invite = sync_invite(&state, &identity, result.invited, filter.as_ref());
    let knock = sync_knock(&state, &identity, result.knocked, filter.as_ref());
    let leave = sync_leave(result.left, filter.as_ref());

    let (to_device, device_changes, key_counts, unused_fallback) =
        sync_device_sections(&state, &identity, since, result.next_batch)?;

    let global = sync_account_data(&state, &identity, filter.as_ref())?;

    // Assembled from pre-serialized parts rather than as one `Value`, so the
    // joined rooms' state blocks -- which `sync_join` may have taken straight
    // from the render cache -- reach the wire without a parse and a
    // re-serialize in between. Everything else is small and converted here.
    let mut rooms: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    rooms.insert("join", raw(&join)?);
    rooms.insert("invite", raw(&invite)?);
    rooms.insert("knock", raw(&knock)?);
    rooms.insert("leave", raw(&leave)?);

    let mut body: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    body.insert(
        "next_batch",
        raw(&crate::tokens::Sync(result.next_batch).to_string())?,
    );
    body.insert("rooms", raw(&rooms)?);
    body.insert("to_device", raw(&json!({ "events": to_device }))?);
    // `left` is honestly empty until room departures update the watermark; a
    // wrong name here would make clients drop sessions.
    body.insert(
        "device_lists",
        raw(&json!({ "changed": device_changes, "left": [] }))?,
    );
    body.insert("device_one_time_keys_count", raw(&key_counts)?);
    body.insert("device_unused_fallback_key_types", raw(&unused_fallback)?);
    body.insert("account_data", raw(&json!({ "events": global }))?);

    let window = (since, result.next_batch);
    if let Some(done) = finalised_delays(&state, &identity.user_id, filter.as_ref(), window)? {
        body.insert("org.matrix.msc4140.finalised_delayed_events", raw(&done)?);
    }

    let text =
        serde_json::to_string(&body).map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response())
}

/// One room's entry in `rooms.join`, for every joined room the sync found.
///
/// Lifted out of the handler because the handler had four sections to
/// assemble and the joined one is by far the largest: it is the only one that
/// carries state, account data, ephemeral events and an unread count at once.
/// MSC4309's delayed events that finished in this sync's window.
///
/// `None` rather than an empty vector when there is nothing to report, so
/// the caller omits the key entirely as the MSC requires. The distinction
/// matters at this server's scale rather than in principle: almost nobody
/// has ever scheduled a delay, so an always-present key would be dead weight
/// on essentially every sync response this server writes.
fn finalised_delays(
    state: &AppState,
    user_id: &str,
    filter: Option<&crate::filters::Filter>,
    (since, next_batch): (Option<u64>, u64),
) -> Result<Option<Vec<crate::delayed::FinalisedDelay>>, MatrixError> {
    if !filter.is_none_or(crate::filters::Filter::wants_finalised_delayed_events) {
        return Ok(None);
    }
    let finalised = state
        .delayed
        .finalised_between(user_id, since, next_batch)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((!finalised.is_empty()).then_some(finalised))
}

/// The account-level account data a sync carries, defaults included.
///
/// Lifted out of the handler because it is the one section with a rule of
/// its own: a user who has never edited a push rule still has a ruleset, and
/// clients read it from here rather than from `/pushrules/`.
fn sync_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    filter: Option<&crate::filters::Filter>,
) -> Result<Vec<Value>, MatrixError> {
    let mut global = state
        .account_data
        .all(&identity.user_id, "")
        .map_err(|error| account_data_error(&error))?;
    // A user who has never edited a rule still has a ruleset, and a client
    // reads it from here rather than from `/pushrules/`. Injected rather than
    // written at registration for the reason `ruleset_of` gives: only an edit
    // freezes a ruleset, so an unedited one keeps tracking the defaults as the
    // spec adds rules.
    if !global
        .iter()
        .any(|event| event["type"] == crate::push_rules::TYPE)
    {
        global.push(json!({
            "type": crate::push_rules::TYPE,
            "content": crate::push_rules::defaults(&identity.user_id),
        }));
    }
    Ok(crate::filters::Filter::apply(
        filter.and_then(|filter| filter.account_data.as_ref()),
        global,
    ))
}

/// Pre-serialize a value so it can sit beside an already-rendered one.
///
/// `serde_json::Value` cannot hold raw JSON, which is the whole reason the
/// sync body is assembled from `RawValue`s rather than as one `Value`: the
/// state block is served from a cache that already holds the exact bytes,
/// and parsing them back into a `Value` so they can be serialized again is
/// the cost this avoids.
fn raw<T: serde::Serialize>(value: &T) -> Result<Box<RawValue>, MatrixError> {
    serde_json::value::to_raw_value(value)
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

fn sync_invite(
    state: &AppState,
    identity: &crate::accounts::Identity,
    invited: Vec<String>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut invite = serde_json::Map::new();
    for room_id in invited {
        if filter.is_some_and(|f| !f.allows_room(&room_id)) {
            continue;
        }
        // An invited user is not in the room, so there is no timeline to
        // show them. `invite_state` is the stripped state a client renders
        // the invite from: what room, whose, how it admits — and nothing
        // they are not yet entitled to.
        let events = state
            .rooms
            .stripped_state(&room_id, &identity.user_id)
            .unwrap_or_default();
        invite.insert(room_id, json!({ "invite_state": { "events": events } }));
    }
    invite
}

/// The rooms this user has knocked on, with the state a client renders the
/// wait from.
///
/// Deliberately its own section and not folded into `invite`. An invite is
/// something to accept or decline; a knock is something to wait on, and a
/// client that showed them together would offer an accept button for a room
/// that has not agreed to let anyone in. The spec gives it `knock_state` for
/// the same reason it gives an invite `invite_state`: the knocker is not in
/// the room, so there is no timeline they are entitled to -- only enough to
/// know which room they are waiting on.
fn sync_knock(
    state: &AppState,
    identity: &crate::accounts::Identity,
    knocked: Vec<String>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut knock = serde_json::Map::new();
    for room_id in knocked {
        if filter.is_some_and(|f| !f.allows_room(&room_id)) {
            continue;
        }
        let events = state
            .rooms
            .stripped_state(&room_id, &identity.user_id)
            .unwrap_or_default();
        knock.insert(room_id, json!({ "knock_state": { "events": events } }));
    }
    knock
}

fn sync_leave(
    left: Vec<crate::rooms::SyncRoom>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut leave = serde_json::Map::new();
    for room in left {
        if filter.is_some_and(|f| !f.allows_room(&room.room_id)) {
            continue;
        }
        // No `state` block: the state of a room you are not in is not yours to
        // read, and the departure event in the timeline already says what a
        // client needs -- that you are out, and how you came to be.
        leave.insert(
            room.room_id,
            json!({
                "timeline": timeline_block(room.events, room.limited, room.prev_batch),
            }),
        );
    }
    leave
}

/// A sync `timeline` block. `prev_batch` is where the window begins, as
/// the token `/messages?dir=b` pages back from (#331); absent only for an
/// empty window, since a client with no token cannot page back at all.
fn timeline_block(events: Vec<Value>, limited: bool, prev_batch: Option<i64>) -> Value {
    let mut block = serde_json::Map::new();
    block.insert("events".to_owned(), Value::Array(events));
    block.insert("limited".to_owned(), json!(limited));
    if let Some(li) = prev_batch {
        block.insert(
            "prev_batch".to_owned(),
            json!(crate::tokens::Pagination(li).to_string()),
        );
    }
    Value::Object(block)
}

fn sync_join(
    state: &AppState,
    identity: &crate::accounts::Identity,
    rooms: Vec<crate::rooms::SyncRoom>,
    filter: Option<&crate::filters::Filter>,
    state_after: bool,
    state_block: crate::rooms::StateBlock,
) -> Result<BTreeMap<String, Box<RawValue>>, MatrixError> {
    let mut join: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    for room in rooms {
        if filter.is_some_and(|f| !f.allows_room(&room.room_id)) {
            continue;
        }
        let unread = state
            .rooms
            .unread(&room.room_id, &identity.user_id)
            .map_err(room_error)?;
        let highlight_count = highlight_count(state, identity, &room.room_id, &unread)?;
        // Sent in full on every sync, incremental ones included, rather than
        // only when it changed. Account data has no stream position of its
        // own -- the sync token counts room events, and a `PUT` to
        // `/account_data` appends nothing -- so sending only the delta would
        // need a second cursor. Until there is one, repeating it is the
        // answer that cannot silently drop a change.
        let room_data = state
            .account_data
            .all(&identity.user_id, &room.room_id)
            .map_err(|error| account_data_error(&error))?;
        let typing = state.typing.event(&room.room_id);
        let room_filter = filter.map(|filter| &filter.room);
        let events = crate::filters::Filter::apply(
            room_filter.and_then(|room| room.timeline.as_ref()),
            room.events,
        );
        let mut room_state = crate::filters::Filter::apply(
            room_filter.and_then(|room| room.state.as_ref()),
            room.state,
        );
        // Lazy-loaded members: send only the membership events this response
        // makes the client need -- the senders in its timeline -- instead of
        // the whole roster. In a 10,000-member room the roster *is* the
        // initial sync, and a client renders none of it until someone speaks.
        //
        // The syncing user's own membership is always kept: the spec permits
        // redundant members, and a client that cannot find itself in the
        // state it was sent tends to conclude it is not in the room.
        if room_filter
            .and_then(|room| room.state.as_ref())
            .and_then(|state| state.lazy_load_members)
            == Some(true)
        {
            let needed: std::collections::HashSet<&str> = events
                .iter()
                .filter_map(|event| event["sender"].as_str())
                .chain(std::iter::once(identity.user_id.as_str()))
                .collect();
            room_state.retain(|event| {
                event["type"] != "m.room.member"
                    || event["state_key"]
                        .as_str()
                        .is_some_and(|member| needed.contains(member))
            });
        }
        let room_data = crate::filters::Filter::apply(
            room_filter.and_then(|room| room.account_data.as_ref()),
            room_data,
        );
        let mut entry: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
        entry.insert(
            "timeline",
            raw(&timeline_block(events, room.limited, room.prev_batch))?,
        );
        // MSC4222 renames the block rather than changing what is in it, *for
        // this server*. What we send is already the state at the end of the
        // timeline -- it is read from the head entry's own snapshot, which is
        // exactly what `state_after` is defined to mean. A DAG server has to
        // compute that; here it is the thing that was already materialized.
        //
        // So the flag changes the label, and the label is the part that was
        // wrong: `state` promises the state *before* the timeline, which is
        // not what this server was ever sending.
        // The deferred case: `Rooms::sync` materialized nothing, and the
        // cached render is already the exact bytes this block should carry.
        // Spliced rather than parsed and re-serialized -- which is the whole
        // point, since parsing it only to serialize it back is the cost this
        // avoids.
        let state_json = if state_block == crate::rooms::StateBlock::Deferred {
            let rendered = state
                .rooms
                .state_serialized_unscoped(&room.room_id)
                .map_err(room_error)?;
            RawValue::from_string(format!(r#"{{"events":{rendered}}}"#))
                .map_err(|error| MatrixError::internal(&error.to_string()))?
        } else {
            raw(&json!({ "events": room_state }))?
        };
        entry.insert(
            if state_after { "state_after" } else { "state" },
            state_json,
        );
        entry.insert("account_data", raw(&json!({ "events": room_data }))?);
        entry.insert(
            "ephemeral",
            raw(&json!({
                "events": crate::filters::Filter::apply(
                    room_filter.and_then(|room| room.ephemeral.as_ref()),
                    typing.map(|event| vec![event]).unwrap_or_default(),
                ),
            }))?,
        );
        entry.insert(
            "unread_notifications",
            raw(&json!({
                "notification_count": unread.notification_count,
                "highlight_count": highlight_count,
            }))?,
        );
        join.insert(room.room_id, raw(&entry)?);
    }

    // A room where the only news is that someone is typing has no timeline
    // events, so `Rooms::sync` leaves it out -- correctly, since it knows
    // nothing about typing. Adding it back here is what keeps typing out of
    // the log layer entirely.
    for room_id in state.rooms.joined(&identity.user_id).map_err(room_error)? {
        if join.contains_key(&room_id) || filter.is_some_and(|f| !f.allows_room(&room_id)) {
            continue;
        }
        let Some(typing) = state.typing.event(&room_id) else {
            continue;
        };
        join.insert(
            room_id,
            raw(&json!({ "ephemeral": { "events": [typing] } }))?,
        );
    }
    Ok(join)
}

/// `POST /_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}`
async fn set_receipt(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, receipt_type, event_id)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_receipt(&room_id, &identity.user_id, &receipt_type, &event_id)
        .map_err(room_error)?;
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct ReadMarkers {
    #[serde(rename = "m.fully_read")]
    fully_read: Option<String>,
    #[serde(rename = "m.read")]
    read: Option<String>,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/read_markers`
///
/// Two markers with different jobs: `m.fully_read` is private and is where the
/// client puts its "jump to first unread" line, while `m.read` is public and
/// is what other people see and what the unread count is measured from. A
/// client may set either or both, so neither is required.
async fn read_markers(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(markers): Json<ReadMarkers>,
) -> Result<Json<Value>, MatrixError> {
    for (receipt_type, event_id) in [
        ("m.fully_read", markers.fully_read.as_deref()),
        ("m.read", markers.read.as_deref()),
    ] {
        if let Some(event_id) = event_id {
            state
                .rooms
                .set_receipt(&room_id, &identity.user_id, receipt_type, event_id)
                .map_err(room_error)?;
        }
    }
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct RedactRequest {
    reason: Option<String>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}`
///
/// Replayed like `/send`. A duplicated redaction is the mildest duplicate --
/// it redacts an already-redacted event -- but it still mints a second
/// event into the log, and the log is forever.
async fn redact_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, txn_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<RedactRequest>,
) -> Result<Json<Value>, MatrixError> {
    with_transaction(&state, &identity, &txn_id, || {
        state
            .rooms
            .redact(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                &event_id,
                request.reason.as_deref(),
            )
            .map_err(room_error)
    })
}

#[derive(Debug, Deserialize)]
struct RelationsQuery {
    from: Option<String>,
    limit: Option<usize>,
}

async fn relations_all(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        None,
        None,
        &query,
    )
}

async fn relations_by_type(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, rel_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        Some(&rel_type),
        None,
        &query,
    )
}

async fn relations_by_event_type(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, rel_type, event_type)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        Some(&rel_type),
        Some(&event_type),
        &query,
    )
}

/// `GET /_matrix/client/v1/rooms/{room_id}/relations/{event_id}[/{rel_type}[/{event_type}]]`
fn relations(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    event_id: &str,
    rel_type: Option<&str>,
    event_type: Option<&str>,
    query: &RelationsQuery,
) -> Result<Json<Value>, MatrixError> {
    // Every edit, reply, reaction and thread reply hanging off an event --
    // and an `m.replace` carries the replacement's whole new body, so this
    // reads as much of a private room as `/messages` does.
    may_read_room(state, user_id, room_id)?;
    // The same `t`-tagged pagination token `/messages` uses, because it is the
    // same thing: a position in this room's linear index.
    let from = match query.from.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Pagination>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let (chunk, next) = state
        .rooms
        .relations(room_id, event_id, rel_type, event_type, from, limit)
        .map_err(room_error)?;

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    // Absent when there is nothing more, which is how a client stops.
    if let Some(next) = next {
        body.insert(
            "next_batch".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

#[derive(Debug, Deserialize)]
struct ThreadsQuery {
    from: Option<String>,
    limit: Option<usize>,
    include: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TimestampToEventQuery {
    ts: Option<u64>,
    dir: Option<String>,
}

/// `GET /_matrix/client/v1/rooms/{room_id}/timestamp_to_event`
///
/// Jump-to-date: the client has a calendar date and wants somewhere in the
/// timeline to start paginating from. It asks for the event nearest a
/// timestamp on one side, then pages from there with `/messages`.
///
/// `dir` is required and has no default. `f` and `b` are opposite answers to
/// the same question, and a client that omitted it by mistake would get a
/// plausible event from the wrong side of the date and page away from what it
/// was looking for -- a silently wrong answer, which is worse than a 400.
///
/// The room is subject to the same read rule as every other room read.
async fn room_timestamp_to_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<TimestampToEventQuery>,
) -> Result<Json<Value>, MatrixError> {
    may_read_room(&state, &identity.user_id, &room_id)?;
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
        .event_at_timestamp(&room_id, ts, direction)
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
struct DelayQuery {
    #[serde(rename = "org.matrix.msc4140.delay")]
    delay: Option<u64>,
}

/// Turn a delay failure into the response a client can act on.
fn delay_error(error: crate::delayed::DelayError) -> MatrixError {
    use crate::delayed::DelayError;
    match error {
        DelayError::NotFound => MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "no such delayed event",
        ),
        // `M_INVALID_PARAM` with the limit in the message: a client that
        // asked for too long can retry with less, but only if it is told
        // what "too long" is.
        DelayError::TooLong { limit_ms } => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("the maximum delay is {limit_ms}ms"),
        ),
        // `M_LIMIT_EXCEEDED` rather than `M_INVALID_PARAM`: nothing about the
        // request was wrong, and the same request will work once one of this
        // caller's pending delays in this room fires or is cancelled.
        DelayError::TooMany { limit } => MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_LIMIT_EXCEEDED",
            format!("at most {limit} delayed events may be pending in one room"),
        ),
        DelayError::Store(inner) => MatrixError::internal(&inner.to_string()),
    }
}

/// `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events`
///
/// What this caller is still waiting on. Scoped to the caller: a delay is a
/// pending action taken in their name, and whose it is is the only sensible
/// unit here.
async fn delayed_events(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let pending = state.delayed.list(&identity.user_id).map_err(delay_error)?;
    let chunk: Vec<Value> = pending
        .into_iter()
        .map(|event| {
            let mut entry = serde_json::Map::new();
            entry.insert("delay_id".to_owned(), json!(event.delay_id));
            entry.insert("room_id".to_owned(), json!(event.room_id));
            entry.insert("type".to_owned(), json!(event.event_type));
            if let Some(state_key) = event.state_key {
                entry.insert("state_key".to_owned(), json!(state_key));
            }
            entry.insert("delay".to_owned(), json!(event.delay_ms));
            // When the current window started, which is the one field a
            // client could not have computed for itself and the one it needs
            // in order to decide whether to restart.
            entry.insert(
                "running_since".to_owned(),
                json!(event.fire_at_ms.saturating_sub(event.delay_ms)),
            );
            entry.insert("content".to_owned(), event.content);
            Value::Object(entry)
        })
        .collect();
    Ok(Json(json!({ "delayed_events": chunk })))
}

#[derive(Debug, Deserialize)]
struct DelayActionRequest {
    action: String,
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}`
///
/// `restart` is the one that matters: it is the heartbeat a live client sends
/// to say "not yet", and it re-applies the *original* delay rather than what
/// remained. A restart that shortened the window each time would converge on
/// firing while the client was still there, which is the opposite of what
/// restarting means.
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
    let to_send = state
        .delayed
        .act(&delay_id, &identity.user_id, action)
        .map_err(delay_error)?;
    if let Some(event) = to_send {
        let sent = match &event.state_key {
            Some(state_key) => state.rooms.set_state(
                &event.room_id,
                &event.sender,
                state.key.pair(),
                &event.event_type,
                state_key,
                &event.content,
            ),
            None => state.rooms.send(
                &event.room_id,
                &event.sender,
                state.key.pair(),
                &event.event_type,
                &event.content,
            ),
        };
        // MSC4309, for the same reason the fire loop records its outcome:
        // this device learns the result from the response, but the user's
        // *other* devices are exactly as uninformed as if the delay had
        // fired on its own. A failure to record must not fail the send that
        // already happened, so it is logged rather than returned.
        let record = crate::delayed::FinalisedDelay {
            delay_id: event.delay_id.clone(),
            room_id: event.room_id.clone(),
            event_type: event.event_type.clone(),
            state_key: event.state_key.clone(),
            event_id: sent.as_ref().ok().cloned(),
            error: sent.as_ref().err().map(ToString::to_string),
        };
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
        sent.map_err(room_error)?;
    }
    Ok(Json(json!({})))
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
/// clients read the list as a priority ordering.
fn rtc_transports(config: &crate::Config) -> Vec<Value> {
    config
        .rtc
        .foci
        .iter()
        .map(|focus| {
            json!({
                "type": focus.kind,
                "livekit_service_url": focus.livekit_service_url,
            })
        })
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
    Json(json!({ "rtc_transports": rtc_transports(&state.config) }))
}

/// The TURN REST password: base64 of HMAC-SHA1 over the username.
///
/// Padded base64, unlike everything else here. Matrix uses the unpadded form
/// throughout and `signing.rs` says why; this is not Matrix's encoding, it is
/// coturn's, and coturn compares against the padded string.
fn turn_credential(secret: &str, username: &str) -> String {
    use hmac::Mac;
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

/// `GET /_matrix/client/v1/rooms/{room_id}/threads`
///
/// The chunk is thread *roots*, each carrying the `m.thread` aggregate in
/// `unsigned.m.relations` — so a client renders the list, with each thread's
/// reply count and latest reply, from this one response.
///
/// `include` is `all` or `participated`; anything else is a 400 rather than a
/// silent fallback to `all`, because the two answers differ and a client that
/// misspells the value would otherwise be shown other people's threads and
/// never learn why.
async fn room_threads(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<ThreadsQuery>,
) -> Result<Json<Value>, MatrixError> {
    // `threads` already takes the viewer, which is what made this one look
    // guarded. It is not: the viewer decides the `participated` filter, and
    // the only access check underneath is that the room exists.
    may_read_room(&state, &identity.user_id, &room_id)?;
    let participated_only = match query.include.as_deref() {
        None | Some("all") => false,
        Some("participated") => true,
        Some(other) => {
            return Err(MatrixError::bad_json(format!(
                "include must be 'all' or 'participated', not {other:?}"
            )));
        }
    };
    // The same `t`-tagged token the rest of the room's pagination uses: this
    // is a position in the same linear index.
    let from = match query.from.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Pagination>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let (roots, next) = state
        .rooms
        .threads(&room_id, &identity.user_id, participated_only, from, limit)
        .map_err(room_error)?;

    let chunk: Vec<Value> = roots
        .into_iter()
        .map(|root| with_bundle(&state, &room_id, &identity.user_id, root))
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    if let Some(next) = next {
        body.insert(
            "next_batch".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state`
async fn room_state(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, MatrixError> {
    let body = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.state_serialized())
        .map_err(room_error)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}`
///
/// Returns the event's *content*, not the event — which is what the spec says
/// and what surprises people, so it is worth stating here rather than leaving
/// to the reader.
async fn room_state_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, state_key)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Value>, MatrixError> {
    // Also a membership oracle without this: `…/state/m.room.member/@someone`
    // answers whether a named user is in a named room, to anyone who asks.
    let content = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.state_event(&event_type, &state_key))
        .map_err(room_error)?;
    Ok(Json(content))
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}`
///
/// Also the MSC4140 entry point that Matrix RTC actually uses: a call
/// participant's *departure* is a state event, and delaying one is how a
/// client arranges to be removed from a call it can no longer say it has
/// left.
async fn set_room_state(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, state_key)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(delay_ms) = query.delay {
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
                Some(&state_key),
                &content,
                delay_ms,
            )
            .map_err(delay_error)?;
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    let event_id = state
        .rooms
        .set_state(
            &room_id,
            &identity.user_id,
            state.key.pair(),
            &event_type,
            &state_key,
            &content,
        )
        .map_err(room_error)?;
    Ok(Json(json!({ "event_id": event_id })))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state/{event_type}`
///
/// The state key is empty, which is what the two-segment form means.
async fn room_state_event_default(
    state: State<AppState>,
    identity: Authenticated,
    axum::extract::Path((room_id, event_type)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    room_state_event(
        state,
        identity,
        axum::extract::Path((room_id, event_type, String::new())),
    )
    .await
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/state/{event_type}`
async fn set_room_state_default(
    state: State<AppState>,
    identity: Authenticated,
    axum::extract::Path((room_id, event_type)): axum::extract::Path<(String, String)>,
    query: axum::extract::Query<DelayQuery>,
    content: Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    set_room_state(
        state,
        identity,
        axum::extract::Path((room_id, event_type, String::new())),
        query,
        content,
    )
    .await
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

/// `GET /_matrix/client/v3/rooms/{room_id}/event/{event_id}`
async fn room_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let event = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.event(&event_id))
        .map_err(room_error)?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such event"))?;
    Ok(Json(with_bundle(
        &state,
        &room_id,
        &identity.user_id,
        event,
    )))
}

#[derive(Debug, Deserialize)]
struct ContextQuery {
    limit: Option<usize>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/context/{event_id}`
///
/// What a permalink resolves to: the event, a symmetric window either side of
/// it, and the room's state as it stood there.
async fn room_context(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<ContextQuery>,
) -> Result<Json<Value>, MatrixError> {
    // The spec's limit is the total window, so each side gets half.
    let limit = query.limit.unwrap_or(10).clamp(1, 100);
    let each_side = limit.div_ceil(2);

    let context = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.context(&event_id, each_side))
        .map_err(room_error)?;

    Ok(Json(json!({
        "event": with_bundle(&state, &room_id, &identity.user_id, context.event),
        "events_before": context.events_before,
        "events_after": context.events_after,
        "state": context.state,
        // The same `t`-tagged tokens `/messages` pages with, because they are
        // positions in the same index -- so a client can carry on paginating
        // outwards from either edge of the window.
        "start": crate::tokens::Pagination(context.start).to_string(),
        "end": crate::tokens::Pagination(context.end).to_string(),
    })))
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
        // The message is ruma's own wording for the rule that refused, which
        // is the same explanation a federating peer would give. A generic
        // "forbidden" would make a client's bug report useless.
        crate::rooms::RoomError::Forbidden(rule) => MatrixError::forbidden(rule),
        // #225: this was a 500 with an empty body, which told a client
        // nothing and an operator nothing. It is not an internal error --
        // the server is working correctly and the *room* is in a state it
        // cannot fold until #16 wires the resolver into ingest. 503 says
        // "this server, this room, not now", which is the true shape of it,
        // and naming the contested key makes it diagnosable.
        crate::rooms::RoomError::Contested { key } => MatrixError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "M_UNKNOWN",
            format!(
                "this room has a fork contesting {key}, which this server cannot \
                 resolve yet; sends are refused until it is settled"
            ),
        ),
        other => MatrixError::internal(&other.to_string()),
    }
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`
/// Replay a transaction if this device has already sent it, or run `mint` and
/// record what it produced.
///
/// The check-then-record is not atomic, and deliberately so: the race it
/// leaves open is two *concurrent* retries of the same transaction, which can
/// both mint. Closing it would mean a lock held across `append`. The failure
/// the spec's idempotency exists for is the sequential retry -- a client that
/// timed out, cannot know whether its send landed, and asks again -- and that
/// case a durable read-then-write handles completely, including across a
/// server restart, which an in-memory lock would not.
///
/// Only success is recorded. A refused send must stay refusable: recording a
/// failure would replay the *error* forever, and recording nothing means the
/// retry gets a fresh chance, which is what a client expects of a 429 or an
/// auth refusal that a later state change resolves.
fn with_transaction(
    state: &AppState,
    identity: &crate::accounts::Identity,
    txn_id: &str,
    mint: impl FnOnce() -> Result<String, MatrixError>,
) -> Result<Json<Value>, MatrixError> {
    let key = spindle_core::keys::transaction(&identity.user_id, &identity.device_id, txn_id);
    if let Ok(Some(stored)) = spindle_store::ReadView::get(state.store.as_ref(), &key)
        && let Ok(event_id) = String::from_utf8(stored)
    {
        return Ok(Json(json!({ "event_id": event_id })));
    }
    let event_id = mint()?;
    spindle_store::Store::put(state.store.as_ref(), &key, event_id.as_bytes())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "event_id": event_id })))
}

async fn send_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, txn_id)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    // MSC4140 rides the existing send rather than adding a parallel one: the
    // event, its authorization and its transaction handling are identical,
    // and only *when* it is appended changes. A separate endpoint would be a
    // second copy of all of that, drifting.
    if let Some(delay_ms) = query.delay {
        // The room is checked now, not when it fires: a client that cannot
        // send here should be told so while it is still listening, rather
        // than have its event silently refused an hour later.
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
                None,
                &content,
                delay_ms,
            )
            .map_err(delay_error)?;
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    with_transaction(&state, &identity, &txn_id, || {
        state
            .rooms
            .send(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                &event_type,
                &content,
            )
            .map_err(room_error)
    })
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    from: Option<String>,
    limit: Option<usize>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/messages`
///
/// The pagination token is the linear index, which is what SPEC 10.2's
/// "tokens are opaque to clients" buys: the ordering already exists, so there
/// is nothing to sort at read time and nothing to maintain alongside.
async fn room_messages(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let reader = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .map_err(room_error)?;
    let from = match query.from.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Pagination>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(10).clamp(1, 100);

    let (events, next) = reader.messages(from, limit).map_err(room_error)?;

    let chunk: Vec<Value> = events
        .iter()
        .map(|event| {
            let mut json = event.json.clone();
            if let Some(object) = json.as_object_mut() {
                object.insert("event_id".to_owned(), json!(event.event_id));
            }
            with_bundle(&state, &room_id, &identity.user_id, json)
        })
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    // Where this chunk began. Without a `from` that is the room's head, which
    // is one past the newest event -- not the literal string "end", which is
    // what this sent before and which no client could page from.
    let start =
        from.unwrap_or_else(|| events.first().map_or(0, |event| event.li.saturating_add(1)));
    body.insert(
        "start".to_owned(),
        json!(crate::tokens::Pagination(start).to_string()),
    );
    // Absent when there is nothing more, which is how a client knows to stop.
    if let Some(next) = next {
        body.insert(
            "end".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

/// The fields of `user_id`'s profile that a join or an invite carries in
/// its member event: `displayname` and `avatar_url`, each only if set
/// (#317). A client shows the roster from member events, so a joiner
/// without them is shown by ID until they next change their profile.
fn member_profile(state: &AppState, user_id: &str) -> serde_json::Map<String, Value> {
    let mut fields = serde_json::Map::new();
    let Ok(profile) = state.profiles.get(user_id) else {
        return fields;
    };
    if let Some(name) = profile.displayname {
        fields.insert("displayname".to_owned(), Value::String(name));
    }
    if let Some(url) = profile.avatar_url {
        fields.insert("avatar_url".to_owned(), Value::String(url));
    }
    fields
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
    limit: Option<usize>,
    since: Option<String>,
    /// Another server's directory. Not served yet -- see the handler.
    server: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PublicRoomsFilter {
    generic_search_term: Option<String>,
    #[serde(default)]
    room_types: Vec<Option<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct PublicRoomsRequest {
    limit: Option<usize>,
    since: Option<String>,
    #[serde(default)]
    filter: PublicRoomsFilter,
    server: Option<String>,
}

/// The directory's default and maximum page size.
///
/// A client that asks for everything gets a page, not everything: the
/// directory is the one endpoint a stranger can call to make this server
/// render every published room's state at once.
const DIRECTORY_PAGE: usize = 50;
const DIRECTORY_PAGE_MAX: usize = 200;

fn chunk_of(summary: &crate::rooms::RoomSummary) -> Value {
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
        let Ok(summary) = state.rooms.summary(room_id) else {
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
    directory_page(&state, query.limit, query.since.as_deref(), None, &[])
}

/// `POST /_matrix/client/v3/publicRooms`
///
/// Authenticated, unlike the GET form: the spec has it that way, and the
/// filter is the reason -- a search term is a thing a user types, so it is
/// attributable.
async fn public_rooms_filtered(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    Json(request): Json<PublicRoomsRequest>,
) -> Result<Json<Value>, MatrixError> {
    refuse_remote_directory(request.server.as_ref(), &state.config.server.name)?;
    directory_page(
        &state,
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
    room_id: String,
    event: crate::rooms::TimelineEvent,
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
            let event = with_bundle(&state, &hit.room_id, &identity.user_id, event);
            let mut result = json!({ "rank": 1.0, "result": event });
            if let Some(wanted) = &criteria.event_context
                && let Some(scope) = scopes.get(&hit.room_id)
            {
                result["context"] = search_context(&state, hit, wanted, scope);
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
            Value::Object(search_state(&state, &hits, &scopes)?),
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
            .reader_with(&room_id, scope.clone())
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
struct RoomRuleContext {
    member_count: usize,
    power_levels: Value,
}

impl RoomRuleContext {
    /// The room-kind facts the rules ask about: the joined count and the
    /// power levels.
    fn of(state: &AppState, room_id: &str) -> Result<Self, MatrixError> {
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

    fn for_reader<'a>(
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
/// same per-room `next_token`. A reader's own events never notify,
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
    let mut cursor = match query.from.as_deref() {
        Some(token) => parse_search_cursor(token)?,
        None => BTreeMap::new(),
    };
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    let profile = state
        .profiles
        .get(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let display_name = profile.displayname.as_deref();

    let mut rooms: BTreeMap<String, RoomRuleContext> = BTreeMap::new();
    let mut hits: Vec<SearchHit> = Vec::new();
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
        let (found, next) = state
            .rooms
            .reader_with(&room_id, scope.clone())
            .search(cursor.get(&room_id).copied(), limit, &notifies)
            .map_err(room_error)?;
        more |= next.is_some();
        hits.extend(found.into_iter().map(|event| SearchHit {
            room_id: room_id.clone(),
            event,
        }));
        rooms.insert(room_id, room);
    }
    more |= page_newest_first(&mut hits, limit, &mut cursor);

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
        body.insert("next_token".to_owned(), json!(search_cursor(&cursor)));
    }
    Ok(Json(Value::Object(body)))
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
            .reader_with(&hit.room_id, scope.clone())
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
    hit: &SearchHit,
    wanted: &SearchContext,
    scope: &ReadScope,
) -> Value {
    let before_limit = wanted.before_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let after_limit = wanted.after_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let Ok(context) = state
        .rooms
        .reader_with(&hit.room_id, scope.clone())
        .context(&hit.event.event_id, before_limit.max(after_limit))
    else {
        return Value::Null;
    };
    let events_before: Vec<Value> = context
        .events_before
        .into_iter()
        .take(before_limit)
        .collect();
    let events_after: Vec<Value> = context.events_after.into_iter().take(after_limit).collect();
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
fn password_uia(
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

#[derive(Debug, Default, Deserialize)]
struct PasswordChangeRequest {
    new_password: Option<String>,
    /// Defaults to true, per the spec: changing a password because it leaked
    /// is the common case, and leaving the other sessions signed in would
    /// defeat the point.
    logout_devices: Option<bool>,
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/account/password`
async fn change_password(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: PasswordChangeRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "change_password",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }
    let new_password = request
        .new_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| MatrixError::bad_json("no new_password"))?;

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_password(&localpart, new_password)
        .map_err(|error| internal(&error))?;
    if request.logout_devices.unwrap_or(true) {
        accounts
            .logout_everywhere(&localpart)
            .map_err(|error| internal(&error))?;
    }
    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Debug, Default, Deserialize)]
struct DeactivateRequest {
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/account/deactivate`
///
/// Deactivation leaves every room the user is in, rather than only flipping
/// the flag. A deactivated account that is still joined shows up in member
/// lists, counts toward `num_joined_members`, and keeps appearing in other
/// people's user-directory results -- so the flag alone would make the
/// account unusable without making it *gone*, which is the thing the user
/// asked for.
///
/// A room that refuses the leave is recorded and reported rather than
/// aborting: the account is still deactivated, and the honest answer is which
/// rooms it could not be removed from.
async fn deactivate_account(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: DeactivateRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "deactivate",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }

    let rooms = state.rooms.joined(&identity.user_id).unwrap_or_default();
    for room_id in rooms {
        let _ = state.rooms.set_membership(
            &room_id,
            &identity.user_id,
            &identity.user_id,
            "leave",
            Some("account deactivated"),
            state.key.pair(),
        );
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_deactivated(&localpart, true)
        .map_err(|error| internal(&error))?;
    accounts
        .logout_everywhere(&localpart)
        .map_err(|error| internal(&error))?;
    state.rooms.wake_sync_waiters();

    // No identity server is contacted, so no third-party binding is removed.
    // `no-support` is the spec's word for exactly that, and it is more honest
    // than `success`.
    Ok((
        StatusCode::OK,
        Json(json!({ "id_server_unbind_result": "no-support" })),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct DeleteDevicesRequest {
    #[serde(default)]
    devices: Vec<String>,
    auth: Option<Value>,
}

/// `POST /_matrix/client/v3/delete_devices`
///
/// The bulk form of `DELETE /devices/{deviceId}`, and it shares that
/// endpoint's password stage. A device that does not exist is not an error:
/// the request asks for it to be gone, and it is.
async fn delete_devices(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let request: DeleteDevicesRequest = optional_body(&body)?;
    let localpart = localpart_of(&identity.user_id);
    if let Some(challenge) = password_uia(
        &state,
        &localpart,
        &headers,
        request.auth.as_ref(),
        "delete_devices",
    )? {
        return Ok((StatusCode::UNAUTHORIZED, challenge));
    }

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    for device_id in &request.devices {
        accounts
            .delete_device(&localpart, device_id)
            .map_err(|error| internal(&error))?;
        state
            .devices
            .remove_device_material(&identity.user_id, device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if !request.devices.is_empty() {
        let seq = state.rooms.allocate_stream_id();
        state
            .devices
            .mark_device_list_changed(&identity.user_id, seq)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        state.rooms.wake_sync_waiters();
    }
    Ok((StatusCode::OK, Json(json!({}))))
}

#[derive(Debug, Default, Deserialize)]
struct HierarchyQuery {
    from: Option<String>,
    limit: Option<usize>,
    max_depth: Option<usize>,
    #[serde(default)]
    suggested_only: bool,
}

/// How many rooms one hierarchy page returns, and the ceiling on a walk.
///
/// `max_depth` has no default in the spec, and an uncapped recursive walk over
/// a graph strangers can extend is a denial of service against your own
/// server: one request, arbitrarily many room-state reads. So the cap is the
/// server's, not the client's, and a client asking for more gets this.
const HIERARCHY_PAGE: usize = 50;
const HIERARCHY_PAGE_MAX: usize = 100;
const HIERARCHY_DEPTH_MAX: usize = 8;

/// May `user` see this room in a hierarchy at all?
///
/// The same shape as the directory's rule and for the same reason: a
/// hierarchy is a list handed to somebody who may be in none of these rooms,
/// so it must not become a way to enumerate private ones. A room is included
/// when the user is joined -- they can already see it -- or when it is
/// world-readable, public or knockable, which are the ways a room says it
/// expects to be found by strangers.
///
/// A room this server holds no log for is *not* an error: over federation the
/// tree crosses servers, and the honest answer is to leave out what we cannot
/// speak for rather than to fail the page.
fn hierarchy_visible(
    state: &AppState,
    user: &str,
    room_id: &str,
) -> Option<crate::rooms::RoomSummary> {
    let summary = state.rooms.summary(room_id).ok()?;
    if state.rooms.is_joined(user, room_id).unwrap_or(false) {
        return Some(summary);
    }
    let open =
        summary.world_readable || matches!(summary.join_rule.as_deref(), Some("public" | "knock"));
    open.then_some(summary)
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
fn may_read_room(state: &AppState, user_id: &str, room_id: &str) -> Result<(), MatrixError> {
    state.rooms.may_read(user_id, room_id).map_err(room_error)
}

/// The state a room upgrade carries across.
///
/// Everything here is a room-level *setting* rather than a record of who
/// did what: the new room is the same room continued, so it should look and
/// behave the same the moment it opens. Deliberately absent:
///
/// - `m.room.member` — the whole point of an upgrade is that members rejoin
///   through the tombstone, which is what re-runs the join rules against
///   the new version's own rules rather than trusting the old room's.
/// - `m.room.create` — the new room has its own, carrying `predecessor`.
/// - `m.room.tombstone` — the old room gets one; a new room born with one
///   would be dead on arrival.
/// - Anything not listed: an unknown state event is room content whose
///   meaning this server does not know, and copying it blind could carry a
///   stale reference to the old room across.
const UPGRADE_CARRIES: &[&str] = &[
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.join_rules",
    "m.room.guest_access",
    "m.room.history_visibility",
    "m.room.encryption",
    "m.room.server_acl",
    "m.space.parent",
];

#[derive(Debug, Deserialize)]
struct UpgradeRequest {
    new_version: String,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/upgrade`
///
/// The room continues at a new version. This is the path that matters for
/// #178's v12 work: a room created at 11 has no other way to reach 12, and
/// v12 exists because the old state-resolution behaviour was exploitable.
///
/// The order is deliberate and is the part worth getting right. The new
/// room is built *first*, and the tombstone in the old room is written
/// last, because the tombstone is what tells clients where to go. A
/// tombstone written before the replacement exists points at nothing, and
/// there is no way to withdraw it -- every client in the room would follow
/// it into a room that is not there.
async fn upgrade_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<UpgradeRequest>,
) -> Result<Json<Value>, MatrixError> {
    if !crate::surface::supports_room_version(&request.new_version) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNSUPPORTED_ROOM_VERSION",
            format!(
                "this server does not support room version {}",
                request.new_version
            ),
        ));
    }
    may_read_room(&state, &identity.user_id, &room_id)?;
    let old_state = state.rooms.state(&room_id).map_err(room_error)?;

    // Whether this user may end the room, asked of the old room before
    // anything is built. The tombstone is a real state event and faces the
    // real power-level check when it is sent; asking first means a refusal
    // does not leave an orphaned replacement room behind.
    let carried: Vec<(String, String, Value)> = old_state
        .iter()
        .filter_map(|event| {
            let event_type = event["type"].as_str()?;
            if !UPGRADE_CARRIES.contains(&event_type) {
                return None;
            }
            Some((
                event_type.to_owned(),
                event["state_key"].as_str().unwrap_or_default().to_owned(),
                event["content"].clone(),
            ))
        })
        .collect();

    // The old room's power levels come across too, but only after the
    // creator has been able to write the rest: a copied ruleset that
    // already forbids the creator from sending would freeze the new room
    // half-built. So it is applied as the last state write, not carried in
    // the initial state.
    let power_levels = old_state
        .iter()
        .find(|event| event["type"] == "m.room.power_levels")
        .map(|event| event["content"].clone());

    let mut creation_content = serde_json::Map::new();
    creation_content.insert(
        "predecessor".to_owned(),
        json!({ "room_id": room_id.clone() }),
    );
    let replacement = state
        .rooms
        .create(
            &identity.user_id,
            state.key.pair(),
            None,
            None,
            None,
            &carried,
            Some(&request.new_version),
            Some(&creation_content),
            &member_profile(&state, &identity.user_id),
        )
        .map_err(room_error)?;

    if let Some(levels) = power_levels {
        // Best effort, and said so: a ruleset the new room refuses is a
        // ruleset the old room should not have had either, and failing the
        // whole upgrade over it would strand the user in a room they have
        // already been told is being replaced.
        if let Err(error) = state.rooms.set_state(
            &replacement,
            &identity.user_id,
            state.key.pair(),
            "m.room.power_levels",
            "",
            &levels,
        ) {
            tracing::warn!(
                %room_id, %replacement,
                "the upgraded room kept default power levels: {error}"
            );
        }
    }

    // Last, and the reason for the whole ordering above.
    state
        .rooms
        .set_state(
            &room_id,
            &identity.user_id,
            state.key.pair(),
            "m.room.tombstone",
            "",
            &json!({
                "body": "this room has been replaced",
                "replacement_room": replacement.clone(),
            }),
        )
        .map_err(room_error)?;

    Ok(Json(json!({ "replacement_room": replacement })))
}

/// The `m.space.child` events of a room, in the spec's order.
///
/// Ordered by the child's `order` field then its room ID, because a space
/// with no explicit order still has to paginate stably -- the same argument
/// the room directory makes.
fn space_children(state: &AppState, room_id: &str, suggested_only: bool) -> Vec<Value> {
    let Ok(events) = state.rooms.state(room_id) else {
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

/// `GET /_matrix/client/v1/rooms/{room_id}/hierarchy`
///
/// A breadth-first walk of `m.space.child`, which is a *graph* and not a tree:
/// a space may contain itself, directly or through a cycle, and nothing stops
/// two spaces containing each other. The visited set is therefore not an
/// optimisation -- without it this endpoint never returns.
async fn room_hierarchy(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<HierarchyQuery>,
) -> Result<Json<Value>, MatrixError> {
    let limit = query
        .limit
        .unwrap_or(HIERARCHY_PAGE)
        .clamp(1, HIERARCHY_PAGE_MAX);
    let max_depth = query
        .max_depth
        .unwrap_or(HIERARCHY_DEPTH_MAX)
        .min(HIERARCHY_DEPTH_MAX);
    let offset: usize = match query.from.as_deref() {
        Some(token) => token.parse().map_err(|_| {
            MatrixError::bad_json("from is not a hierarchy token this server issued")
        })?,
        None => 0,
    };

    // The root itself has to be visible, and a root nobody may see is a 403
    // rather than an empty page: an empty page would say "this space is
    // empty", which is a different and false claim.
    if hierarchy_visible(&state, &identity.user_id, &room_id).is_none() {
        return Err(MatrixError::forbidden(
            "you are not allowed to view this room's hierarchy",
        ));
    }

    // Visibility is decided ONCE, as a room enters the walk. Filtering again
    // at render time would look like belt and braces and is actually a bug:
    // `ordered` would count rooms the caller cannot see, so `total` -- and
    // therefore `next_batch` -- would be computed from a number that does not
    // match what is returned, and `take(limit)` would hand back a SHORT page
    // whenever an invisible room fell inside it. A client paging by counting
    // would then mis-page. So nothing invisible is ever put in the list.
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut ordered: Vec<(crate::rooms::RoomSummary, Vec<Value>)> = Vec::new();
    let mut frontier = vec![(room_id.clone(), 0_usize)];
    visited.insert(room_id.clone());

    while !frontier.is_empty() {
        let (current, depth) = frontier.remove(0);
        // The ONE visibility check, and it is deliberately here rather than at
        // enqueue time. `continue` skips the child expansion below too, so an
        // invisible room is neither returned nor descended into -- a second
        // check on the way in would be pure optimisation, and a second check
        // at render time is the bug described above. One check, one place.
        let Some(summary) = hierarchy_visible(&state, &identity.user_id, &current) else {
            continue;
        };
        let children = space_children(&state, &current, query.suggested_only);
        ordered.push((summary, children.clone()));
        if depth >= max_depth {
            continue;
        }
        for child in &children {
            let Some(child_id) = child["state_key"].as_str() else {
                continue;
            };
            if !visited.insert(child_id.to_owned()) {
                continue;
            }
            frontier.push((child_id.to_owned(), depth + 1));
        }
    }

    let total = ordered.len();
    let mut rooms = Vec::new();
    for (summary, children) in ordered.into_iter().skip(offset).take(limit) {
        let Value::Object(mut entry) = chunk_of(&summary) else {
            continue;
        };
        entry.insert("children_state".to_owned(), Value::Array(children));
        rooms.push(Value::Object(entry));
    }

    let mut body = serde_json::Map::new();
    body.insert("rooms".to_owned(), Value::Array(rooms));
    if offset + limit < total {
        body.insert("next_batch".to_owned(), json!((offset + limit).to_string()));
    }
    Ok(Json(Value::Object(body)))
}
