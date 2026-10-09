//! Synapse's media admin API, as far as this server's media store can
//! answer it: a user's uploads, one item's details, and deletion.
//!
//! Quarantine and protection are not routed. This store has no quarantine
//! flag, and an endpoint that answered `{}` without quarantining anything
//! would tell the operator that offending media is gone when it is not.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::admin::AdminActor;
use crate::errors::MatrixError;
use crate::media::{Media, MediaRecord};

pub fn routes() -> Router<AppState> {
    let group = |prefix: &str| {
        Router::new()
            .route(
                &format!("{prefix}/users/{{user_id}}/media"),
                get(list_user_media).delete(delete_user_media),
            )
            .route(
                &format!("{prefix}/media/{{server_name}}/{{media_id}}"),
                get(media_info).delete(delete_media),
            )
    };
    group("/_synapse/admin/v1").merge(group("/_spindle/admin/v1"))
}

fn media_error(error: &crate::media::MediaError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

fn invalid(message: impl Into<String>) -> MatrixError {
    MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

fn local_user(state: &AppState, user_id: &str) -> Result<(), MatrixError> {
    let localpart = crate::admin::local_localpart(state, user_id)
        .ok_or_else(|| invalid("Can only look up local users"))?;
    crate::accounts::Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown user"))?;
    Ok(())
}

/// The local uploads of `user_id`, by media ID. Cached remote media is
/// not anyone's upload here, so it is left out.
fn uploads_of(state: &AppState, user_id: &str) -> Result<Vec<(String, MediaRecord)>, MatrixError> {
    let mut uploads: Vec<(String, MediaRecord)> = state
        .media
        .records()
        .map_err(|error| media_error(&error))?
        .into_iter()
        .filter(|(id, record)| record.uploaded_by == user_id && !id.contains('/'))
        .collect();
    uploads.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(uploads)
}

/// One upload as Synapse's user media listing shows it. When it was
/// uploaded and last read are not recorded here, and are `null`.
fn upload_json(media_id: &str, record: &MediaRecord) -> Value {
    json!({
        "media_id": media_id,
        "media_type": record.content_type,
        "media_length": record.size,
        "upload_name": record.filename,
        "created_ts": null,
        "last_access_ts": null,
        "quarantined_by": null,
        "safe_from_quarantine": false,
    })
}

#[derive(Deserialize)]
struct MediaQuery {
    from: Option<i64>,
    limit: Option<i64>,
    order_by: Option<String>,
    dir: Option<String>,
}

/// `GET /users/{userId}/media?from&limit&order_by&dir`
async fn list_user_media(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
    Query(query): Query<MediaQuery>,
) -> Result<Json<Value>, MatrixError> {
    local_user(&state, &user_id)?;
    let from = usize::try_from(query.from.unwrap_or(0)).map_err(|_| {
        invalid("Query parameter from must be a string representing a positive integer.")
    })?;
    let limit = usize::try_from(query.limit.unwrap_or(100)).map_err(|_| {
        invalid("Query parameter limit must be a string representing a positive integer.")
    })?;
    let mut uploads: Vec<Value> = uploads_of(&state, &user_id)?
        .iter()
        .map(|(id, record)| upload_json(id, record))
        .collect();
    let order_by = query.order_by.as_deref().unwrap_or("created_ts");
    match order_by {
        // Not recorded: every value is null, so the media ID decides.
        "created_ts"
        | "last_access_ts"
        | "quarantined_by"
        | "safe_from_quarantine"
        | "media_id" => {}
        "upload_name" | "media_type" => uploads.sort_by(|a, b| {
            a[order_by]
                .as_str()
                .unwrap_or_default()
                .cmp(b[order_by].as_str().unwrap_or_default())
        }),
        "media_length" => uploads.sort_by_key(|upload| upload["media_length"].as_u64()),
        other => return Err(invalid(format!("Unknown value for order_by: {other}"))),
    }
    match query.dir.as_deref().unwrap_or("f") {
        "f" => {}
        "b" => uploads.reverse(),
        other => return Err(invalid(format!("Unknown direction: {other}"))),
    }
    let total = uploads.len();
    let page: Vec<Value> = uploads.into_iter().skip(from).take(limit).collect();
    let mut body = json!({ "media": page, "total": total });
    if from + limit < total && limit > 0 {
        body["next_token"] = json!(from + limit);
    }
    Ok(Json(body))
}

/// `DELETE /users/{userId}/media` — every upload the user made.
async fn delete_user_media(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    local_user(&state, &user_id)?;
    let mut deleted = Vec::new();
    for (media_id, _) in uploads_of(&state, &user_id)? {
        if state
            .media
            .delete(&media_id)
            .await
            .map_err(|error| media_error(&error))?
        {
            deleted.push(media_id);
        }
    }
    crate::admin::audit(
        &state,
        &actor.identity().user_id,
        "delete_user_media",
        &user_id,
        &json!({ "deleted_media": deleted }),
    )?;
    Ok(Json(
        json!({ "total": deleted.len(), "deleted_media": deleted }),
    ))
}

/// The store ID of `server_name`'s `media_id`.
fn stored_id(state: &AppState, server_name: &str, media_id: &str) -> String {
    if state.media.is_ours(server_name) {
        media_id.to_owned()
    } else {
        Media::remote_id(server_name, media_id)
    }
}

/// `GET /media/{serverName}/{mediaId}` — `{media_info}`.
async fn media_info(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let record = state
        .media
        .record(&stored_id(&state, &server_name, &media_id))
        .map_err(|error| media_error(&error))?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Media not found"))?;
    let local = state.media.is_ours(&server_name);
    Ok(Json(json!({
        "media_info": {
            "media_origin": server_name,
            "user_id": if local { Value::String(record.uploaded_by.clone()) } else { Value::Null },
            "media_id": media_id,
            "media_type": record.content_type,
            "media_length": record.size,
            "upload_name": record.filename,
            "created_ts": null,
            "last_access_ts": null,
            "quarantined_by": null,
            "authenticated": null,
            "safe_from_quarantine": false,
            "sha256": null,
        }
    })))
}

/// `DELETE /media/{serverName}/{mediaId}` — local media only, as in
/// Synapse: remote media is the other server's to delete.
async fn delete_media(
    State(state): State<AppState>,
    actor: AdminActor,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    if !state.media.is_ours(&server_name) {
        return Err(invalid("Can only delete local media"));
    }
    if !state
        .media
        .delete(&media_id)
        .await
        .map_err(|error| media_error(&error))?
    {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Unknown media",
        ));
    }
    crate::admin::audit(
        &state,
        &actor.identity().user_id,
        "delete_media",
        &format!("mxc://{server_name}/{media_id}"),
        &json!({}),
    )?;
    Ok(Json(json!({ "deleted_media": [media_id], "total": 1 })))
}
