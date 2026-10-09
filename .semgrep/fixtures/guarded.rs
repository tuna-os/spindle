//! The same handler after #258, which the rule must *not* flag.
//!
//! Present so the rule is held to both halves. A rule that fires on
//! everything is as useless as one that fires on nothing, and only this
//! file distinguishes "the gate works" from "the gate is stuck on".

async fn room_messages(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    may_read_room(&state, &identity.user_id, &room_id)?;
    let from = match query.from.as_deref() {
        Some(token) => Some(
            token
                .parse::<crate::tokens::Pagination>()
                .map_err(|error| MatrixError::bad_json(error.to_string()))?
                .0,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(10).min(100);
    let (events, next) = state
        .rooms
        .messages(&room_id, from, limit)
        .map_err(room_error)?;
    Ok(Json(json!({ "chunk": events, "end": next })))
}

/// The same handler once a former member may read up to their departure
/// (#268): the gate is `read_scope`, which refuses strangers and bounds
/// everyone else, and the rule must know that shape too.
async fn room_messages_bounded(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let scope = read_scope(&state, &identity.user_id, &room_id)?;
    let bound = match scope {
        ReadScope::Whole => None,
        ReadScope::UpTo(bound) => Some(bound),
    };
    let limit = query.limit.unwrap_or(10).clamp(1, 100);
    let (events, next) = state
        .rooms
        .messages_within(&room_id, None, limit, bound)
        .map_err(room_error)?;
    Ok(Json(json!({ "chunk": events, "end": next })))
}

/// The same handler holding a `RoomReader`: `rooms.reader` runs
/// `read_scope` and refuses a stranger, so a later read of the room (here
/// the gap check that pokes the backfill loop) is already authorised.
async fn room_messages_reader(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let reader = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .map_err(room_error)?;
    if state.rooms.has_open_gap(&room_id).unwrap_or(false) {
        state.backfill.poke(&room_id);
    }
    let limit = query.limit.unwrap_or(10).clamp(1, 100);
    let (events, next) = reader.page(Page::default(), limit).map_err(room_error)?;
    Ok(Json(json!({ "chunk": events, "end": next })))
}
