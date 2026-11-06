//! The server-server API: transactions, room state, joins, leaves, knocks,
//! invites, user keys, and the key server and notary.

use crate::AppState;
use crate::errors::MatrixError;
use crate::inbound::{FederationStateQuery, federation_origin};
use crate::profile_routes::profile_of;
use crate::routes::{
    PublicRoomsQuery, PublicRoomsRequest, TimestampToEventQuery, chunk_of, directory_page,
    room_error, space_children, timestamp_lookup,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The server-server API and the key server.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(server_routes())
        .merge(federation_read_routes())
}

/// Transactions, room state, membership handshakes, user keys and
/// directory and profile queries.
fn server_routes() -> Router<AppState> {
    Router::new()
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
}

/// What a client or a peer reads before it knows anything else.
/// The read-side federation surface added with the second spec-gap wave,
/// and the key notary.
fn federation_read_routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/key/v2/query", post(key_query_batch))
        .route("/_matrix/key/v2/query/{server_name}", get(key_query_one))
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
    directory_page(&state, query.limit, query.since.as_deref(), None, &[])
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
