//! Administrative background tasks: Synapse's v2 room deletion and the
//! `scheduled_tasks` listing that reports on it.
//!
//! Element Admin deletes a room with `DELETE /_synapse/admin/v2/rooms/{id}`,
//! which answers at once with a `delete_id`, and then polls
//! `GET /_synapse/admin/v1/scheduled_tasks?resource_id={id}` every second
//! until the task is `complete` or `failed`. Its room page reads that
//! listing on every load, so without it the page does not render at all.
//!
//! The deletion itself is [`crate::admin::shutdown_room`], the same code
//! the synchronous v1 endpoint runs. What this module adds is the task
//! record: written before the work starts, updated when it ends, and kept
//! in its own keyspace so the outcome survives a restart. A task that was
//! still running when the process stopped is reported as `failed`, with
//! the reason, rather than left `active` forever: nothing will finish it.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{ReadView, Store};

use crate::AppState;
use crate::admin::{AdminActor, DeleteRoom};
use crate::errors::MatrixError;

/// Synapse's action name for a room deletion; Element Admin filters on it.
const SHUTDOWN_AND_PURGE_ROOM: &str = "shutdown_and_purge_room";

pub fn routes() -> Router<AppState> {
    let tasks = |prefix: &str| {
        Router::new().route(
            &format!("{prefix}/scheduled_tasks"),
            get(list_scheduled_tasks),
        )
    };
    tasks("/_synapse/admin/v1")
        .merge(tasks("/_spindle/admin/v1"))
        .route(
            "/_synapse/admin/v2/rooms/{room_id}",
            axum::routing::delete(delete_room_v2),
        )
        .route(
            "/_synapse/admin/v2/rooms/{room_id}/delete_status",
            get(room_delete_status),
        )
        .route(
            "/_synapse/admin/v2/rooms/delete_status/{delete_id}",
            get(delete_status),
        )
}

/// One task as stored. The first seven fields are Synapse's
/// `ScheduledTask`; `boot` says which run of this process started it.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Task {
    id: String,
    action: String,
    status: String,
    timestamp_ms: u64,
    resource_id: Option<String>,
    result: Option<Value>,
    error: Option<String>,
    #[serde(default)]
    boot: String,
}

impl Task {
    /// The task as the API reports it: one this process did not start
    /// and that never finished was interrupted by a restart.
    fn reported(mut self) -> Self {
        if matches!(self.status.as_str(), "scheduled" | "active") && self.boot != *BOOT {
            "failed".clone_into(&mut self.status);
            self.error = Some("interrupted by a server restart; run the deletion again".to_owned());
        }
        self
    }

    fn json(&self) -> Value {
        json!({
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "timestamp_ms": self.timestamp_ms,
            "resource_id": self.resource_id,
            "result": self.result,
            "error": self.error,
        })
    }

    /// The task in the shape of Synapse's `delete_status` answers.
    fn delete_status(&self) -> Value {
        json!({
            "delete_id": self.id,
            "status": self.status,
            "error": self.error,
            "shutdown_room": self.result.clone().unwrap_or_else(|| json!({
                "kicked_users": [],
                "failed_to_kick_users": [],
                "local_aliases": [],
                "new_room_id": null,
            })),
        })
    }
}

/// A random name for this run of the process.
static BOOT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| random_id(8));

fn random_id(bytes: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut raw = vec![0_u8; bytes * 2];
    crate::secrets::fill(&mut raw);
    raw.iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect()
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis()),
    )
    .unwrap_or(u64::MAX)
}

fn save(state: &AppState, task: &Task) -> Result<(), MatrixError> {
    let bytes =
        serde_json::to_vec(task).map_err(|error| MatrixError::internal(&error.to_string()))?;
    Store::put(state.store.as_ref(), &keys::admin_task(&task.id), &bytes)
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

/// Every task, oldest first, as reported.
fn all_tasks(state: &AppState) -> Result<Vec<Task>, MatrixError> {
    let mut tasks: Vec<Task> =
        ReadView::scan_prefix(state.store.as_ref(), &keys::admin_tasks_prefix())
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .into_iter()
            .filter_map(|(_, raw)| serde_json::from_slice::<Task>(&raw).ok())
            .map(Task::reported)
            .collect();
    tasks.sort_by(|a, b| {
        a.timestamp_ms
            .cmp(&b.timestamp_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(tasks)
}

#[derive(Deserialize)]
struct TasksQuery {
    action_name: Option<String>,
    resource_id: Option<String>,
    job_status: Option<String>,
    max_timestamp: Option<u64>,
}

/// `GET /scheduled_tasks?action_name&resource_id&job_status&max_timestamp`
async fn list_scheduled_tasks(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<TasksQuery>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(status) = &query.job_status
        && !matches!(
            status.as_str(),
            "scheduled" | "active" | "complete" | "failed"
        )
    {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "job_status is one of scheduled, active, complete, failed",
        ));
    }
    let tasks: Vec<Value> = all_tasks(&state)?
        .into_iter()
        .filter(|task| {
            query
                .action_name
                .as_deref()
                .is_none_or(|action| task.action == action)
                && query
                    .resource_id
                    .as_deref()
                    .is_none_or(|resource| task.resource_id.as_deref() == Some(resource))
                && query
                    .job_status
                    .as_deref()
                    .is_none_or(|status| task.status == status)
                && query
                    .max_timestamp
                    .is_none_or(|max| task.timestamp_ms <= max)
        })
        .map(|task| task.json())
        .collect();
    Ok(Json(json!({ "scheduled_tasks": tasks })))
}

/// `DELETE /_synapse/admin/v2/rooms/{roomId}` — the deletion as a task.
///
/// Refuses at once what would only fail later: a malformed room ID, an
/// unknown room it is not asked to block, a replacement-room creator who
/// is not local, or a second deletion while one is still running.
async fn delete_room_v2(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<DeleteRoom>,
) -> Result<Json<Value>, MatrixError> {
    if !room_id.starts_with('!') || !room_id.contains(':') {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("{room_id} is not a legal room ID"),
        ));
    }
    crate::admin::validate_delete(&state, &request)?;
    if !request.block {
        state
            .rooms
            .exists(&room_id)
            .map_err(crate::routes::room_error)?;
    }
    if all_tasks(&state)?.iter().any(|task| {
        task.action == SHUTDOWN_AND_PURGE_ROOM
            && task.resource_id.as_deref() == Some(room_id.as_str())
            && matches!(task.status.as_str(), "scheduled" | "active")
    }) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            format!("Purge already in progress for {room_id}"),
        ));
    }

    let task = Task {
        id: random_id(8),
        action: SHUTDOWN_AND_PURGE_ROOM.to_owned(),
        status: "active".to_owned(),
        timestamp_ms: now_ms(),
        resource_id: Some(room_id.clone()),
        result: None,
        error: None,
        boot: BOOT.clone(),
    };
    save(&state, &task)?;
    let delete_id = task.id.clone();
    let worker_actor = actor.duplicate();
    let worker_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let outcome = crate::admin::shutdown_room(&worker_state, &worker_actor, &room_id, &request);
        let mut task = task;
        task.timestamp_ms = now_ms();
        match outcome {
            Ok(result) => {
                "complete".clone_into(&mut task.status);
                task.result = Some(result);
            }
            Err(error) => {
                tracing::warn!("room deletion {} of {room_id} failed: {error:?}", task.id);
                "failed".clone_into(&mut task.status);
                task.error = Some(error.error.clone());
            }
        }
        if let Err(error) = save(&worker_state, &task) {
            tracing::warn!("recording room deletion {}: {error:?}", task.id);
        }
    });
    Ok(Json(json!({ "delete_id": delete_id })))
}

/// `GET /_synapse/admin/v2/rooms/{roomId}/delete_status`
async fn room_delete_status(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let results: Vec<Value> = all_tasks(&state)?
        .iter()
        .filter(|task| {
            task.action == SHUTDOWN_AND_PURGE_ROOM && task.resource_id.as_deref() == Some(&room_id)
        })
        .map(Task::delete_status)
        .collect();
    if results.is_empty() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No delete task for room_id",
        ));
    }
    Ok(Json(json!({ "results": results })))
}

/// `GET /_synapse/admin/v2/rooms/delete_status/{deleteId}`
async fn delete_status(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(delete_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let task = all_tasks(&state)?
        .into_iter()
        .find(|task| task.id == delete_id && task.action == SHUTDOWN_AND_PURGE_ROOM)
        .ok_or_else(|| {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "delete id not found")
        })?;
    let mut body = task.delete_status();
    if let Some(object) = body.as_object_mut() {
        object.remove("delete_id");
    }
    Ok(Json(body))
}
