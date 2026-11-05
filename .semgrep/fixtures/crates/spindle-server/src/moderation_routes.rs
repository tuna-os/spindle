//! The #258 shape outside routes.rs (#744).
//!
//! Named after a real handler module and kept at the path that module has,
//! so it reaches the rule only through the crate-wide include glob: if the
//! rule is ever narrowed back to one file, the `ruleid:` lines here stop
//! firing and `scripts/authorization-rule.py` fails. It also carries the
//! extractor spellings routes.rs does not use -- the imported `Path`, a
//! multi-segment path, and the fully qualified `Authenticated` -- because
//! semgrep matches each spelling separately and an unnamed one is a hole.
//!
//! Compiling-shaped rather than compiling, for the reason vulnerable.rs
//! gives.

/// A room's summary for anyone with an access token.
async fn room_summary(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    // ruleid: room-read-without-authorization
    let summary = state.rooms.summary(&room_id).map_err(room_error)?;
    Ok(Json(json!({ "name": summary.name })))
}

/// One event of a room, the room named by the first path segment.
async fn report_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(request): Json<ReportRequest>,
) -> Result<Json<Value>, MatrixError> {
    // ruleid: room-read-without-authorization
    let event = state.rooms.pdu(&room_id, &event_id).map_err(room_error)?;
    file_report(&state, &identity, &event, request)?;
    Ok(Json(json!({})))
}

/// The room in the second segment, behind the qualified extractor.
async fn member_tags(
    State(state): State<AppState>,
    crate::auth::Authenticated(identity): crate::auth::Authenticated,
    axum::extract::Path((user_id, room_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    // ruleid: room-read-without-authorization
    let members = state
        .rooms
        .joined_member_ids(&room_id)
        .map_err(room_error)?;
    Ok(Json(json!({ "members": members, "asked_by": user_id })))
}

/// The fixed `report_event`: the gate first, then the read.
async fn report_event_guarded(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(request): Json<ReportRequest>,
) -> Result<Json<Value>, MatrixError> {
    may_read_room(&state, &identity.user_id, &room_id)?;
    // ok: room-read-without-authorization
    let event = state.rooms.pdu(&room_id, &event_id).map_err(room_error)?;
    file_report(&state, &identity, &event, request)?;
    Ok(Json(json!({})))
}
