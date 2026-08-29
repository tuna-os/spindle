//! The shape the rule exists to catch, taken from the real pre-#258 code.
//!
//! This is `room_messages` as it stood at 473623f^ — authenticated, handed a
//! room id, reading that room's timeline, and never asking whether the
//! caller was in it. Four sibling handlers had the same shape. All five were
//! found by a person reading the file.
//!
//! It is kept compiling-shaped rather than compiling: the rule reads
//! structure, and a fixture that has to be kept building against the real
//! crate would rot into being edited for reasons unrelated to the rule.
//!
//! `scripts/authorization-rule.py` asserts the rule fires here. If this
//! file stops matching, the gate has stopped guarding and the CI job says so
//! rather than passing quietly.

async fn room_messages(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
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
    // No gate. The caller is authenticated, which says who they are and
    // nothing about what they may read.
    let (events, next) = state
        .rooms
        .messages(&room_id, from, limit)
        .map_err(room_error)?;
    Ok(Json(json!({ "chunk": events, "end": next })))
}
