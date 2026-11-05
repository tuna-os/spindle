//! The federation half of the rule (#744), at the path the real inbound
//! handlers live at.
//!
//! `room_state` below is the shape the federation `/state` handler would
//! have if it authenticated the peer and stopped there: a valid X-Matrix
//! signature from any server on the internet, and the room's full state
//! back. The fixed version asks `federation_room_origin`, which refuses a
//! server with no member in the room. `make_join` is the named exemption:
//! the handshake that lets a server with nobody in the room get somebody
//! in cannot demand membership first.
//!
//! Compiling-shaped rather than compiling, for the reason vulnerable.rs
//! gives.

/// `GET /_matrix/federation/v1/state/{roomId}`, authenticated and no more.
pub(crate) async fn room_state(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    query: FederationStateQuery,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request.uri().path().to_owned();
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    // ruleid: federation-room-read-without-membership
    let (pdus, auth_chain) = state
        .rooms
        .federation_state(&room_id, &query.event_id)
        .map_err(room_error)?;
    Ok(Json(json!({ "pdus": pdus, "auth_chain": auth_chain })))
}

/// `GET /_matrix/federation/v1/backfill/{roomId}` through the qualified
/// path, as the router-side wrappers spell it.
async fn federation_backfill(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request.uri().path().to_owned();
    let origin = crate::inbound::federation_origin(&state, &headers, "GET", &uri, None).await?;
    // ruleid: federation-room-read-without-membership
    let pdus = state.rooms.backfill(&room_id, &[], 100).map_err(room_error)?;
    Ok(Json(json!({ "origin": origin, "pdus": pdus })))
}

/// The fixed `/state`: the peer is asked whether it is in the room.
pub(crate) async fn room_state_guarded(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    query: FederationStateQuery,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request.uri().path().to_owned();
    federation_room_origin(&state, &headers, "GET", &uri, None, &room_id).await?;
    // ok: federation-room-read-without-membership
    let (pdus, auth_chain) = state
        .rooms
        .federation_state(&room_id, &query.event_id)
        .map_err(room_error)?;
    Ok(Json(json!({ "pdus": pdus, "auth_chain": auth_chain })))
}

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`: the door in.
pub(crate) async fn make_join(
    state: AppState,
    headers: axum::http::HeaderMap,
    room_id: String,
    user_id: String,
    request: axum::http::Request<axum::body::Body>,
) -> Result<Json<Value>, MatrixError> {
    let uri = request.uri().path().to_owned();
    let origin = federation_origin(&state, &headers, "GET", &uri, None).await?;
    if user_id.split_once(':').map(|(_, domain)| domain) != Some(origin.as_str()) {
        return Err(MatrixError::forbidden("not your user"));
    }
    // ok: federation-room-read-without-membership
    let version = state.rooms.room_version(&room_id).map_err(room_error)?;
    let event = state
        .rooms
        .make_join_template(&room_id, &user_id)
        .map_err(room_error)?;
    Ok(Json(json!({ "room_version": version, "event": event })))
}
