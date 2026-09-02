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
