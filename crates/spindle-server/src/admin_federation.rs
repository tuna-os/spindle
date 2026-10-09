//! Synapse's federation admin API: `GET /federation/destinations`, one
//! destination, the rooms shared with it, and `reset_connection`.
//!
//! Element Admin's Federation page reads these. Synapse answers from its
//! `destinations` table, which names every server it has ever sent to.
//! This server has no such table; the set it reports is every server it
//! shares a room with, every server with deliveries waiting in the
//! outbox, and every server the outbox has tried since this process
//! started. The retry columns come from the outbox loop
//! (`Federation::delivery_health`), so they say how delivery stands now,
//! and a restart starts them afresh, which is also when the outbox
//! retries every destination at once.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::ReadView;

use crate::AppState;
use crate::admin::AdminActor;
use crate::errors::MatrixError;
use crate::federation::DeliveryHealth;

pub fn routes() -> Router<AppState> {
    let group = |prefix: &str| {
        Router::new()
            .route(
                &format!("{prefix}/federation/destinations"),
                get(list_destinations),
            )
            .route(
                &format!("{prefix}/federation/destinations/{{destination}}"),
                get(get_destination),
            )
            .route(
                &format!("{prefix}/federation/destinations/{{destination}}/rooms"),
                get(destination_rooms),
            )
            .route(
                &format!("{prefix}/federation/destinations/{{destination}}/reset_connection"),
                post(reset_connection),
            )
    };
    group("/_synapse/admin/v1").merge(group("/_spindle/admin/v1"))
}

fn server_of(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, server)| server)
}

/// Every remote server this server shares a room with, and the rooms.
fn shared_rooms(
    state: &AppState,
    actor: &AdminActor,
) -> Result<BTreeMap<String, BTreeSet<String>>, MatrixError> {
    let ours = state.config.server.name.as_str();
    let mut shared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for room_id in state
        .rooms
        .admin(actor)
        .all_room_ids()
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        let Ok(members) = state.rooms.joined_member_ids(&room_id) else {
            continue;
        };
        for server in members.iter().filter_map(|user| server_of(user)) {
            if server != ours {
                shared
                    .entry(server.to_owned())
                    .or_default()
                    .insert(room_id.clone());
            }
        }
    }
    Ok(shared)
}

/// Every destination this server knows, with how delivery to it stands.
fn known_destinations(
    state: &AppState,
    actor: &AdminActor,
) -> Result<BTreeMap<String, DeliveryHealth>, MatrixError> {
    let mut known: BTreeMap<String, DeliveryHealth> = shared_rooms(state, actor)?
        .into_keys()
        .map(|server| (server, DeliveryHealth::default()))
        .collect();
    // Visited rather than collected: a destination that has been down a
    // while can have thousands of PDUs queued, and only the keys matter.
    ReadView::visit_prefix(
        state.store.as_ref(),
        &keys::federation_outbox_all(),
        &mut |key, _| {
            if let Some(destination) = keys::federation_outbox_destination(key) {
                known.entry(destination).or_default();
            }
            Ok(())
        },
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;
    known.extend(state.federation.delivery_health());
    known.remove(&state.config.server.name);
    Ok(known)
}

fn destination_json(destination: &str, health: &DeliveryHealth) -> Value {
    json!({
        "destination": destination,
        "retry_last_ts": health.retry_last_ts,
        "retry_interval": health.retry_interval,
        "failure_ts": health.failure_ts,
        "last_successful_stream_ordering": health.last_successful_stream_ordering,
    })
}

fn invalid(message: impl Into<String>) -> MatrixError {
    MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

fn unknown_destination() -> MatrixError {
    MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown destination")
}

/// Synapse's paging parameters: `from` an offset, `limit` the page size,
/// `dir` the direction.
#[derive(Deserialize)]
struct PageQuery {
    from: Option<String>,
    limit: Option<i64>,
    order_by: Option<String>,
    dir: Option<String>,
    destination: Option<String>,
}

fn page_bounds(query: &PageQuery) -> Result<(usize, usize), MatrixError> {
    let from = match query.from.as_deref() {
        None => 0,
        Some(from) => from.parse::<usize>().map_err(|_| {
            invalid("Query parameter from must be a string representing a positive integer.")
        })?,
    };
    let limit = query.limit.unwrap_or(100);
    let limit = usize::try_from(limit)
        .map_err(|_| invalid("Query parameter limit must be a positive integer."))?;
    Ok((from, limit))
}

fn ascending(dir: Option<&str>) -> Result<bool, MatrixError> {
    match dir.unwrap_or("f") {
        "f" => Ok(true),
        "b" => Ok(false),
        other => Err(invalid(format!("Unknown direction: {other}"))),
    }
}

/// `GET /federation/destinations?from&limit&order_by&dir&destination`
async fn list_destinations(
    State(state): State<AppState>,
    actor: AdminActor,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, MatrixError> {
    let (from, limit) = page_bounds(&query)?;
    let forward = ascending(query.dir.as_deref())?;
    let needle = query.destination.as_deref().map(str::to_lowercase);
    let mut rows: Vec<(String, DeliveryHealth)> = known_destinations(&state, &actor)?
        .into_iter()
        .filter(|(destination, _)| {
            needle
                .as_deref()
                .is_none_or(|needle| destination.to_lowercase().contains(needle))
        })
        .collect();
    // Synapse's orderings, ties broken by name; a null sorts as the
    // smallest value, so it comes first ascending and last descending.
    let order = query.order_by.as_deref().unwrap_or("destination");
    let key = |health: &DeliveryHealth| -> Option<u64> {
        match order {
            "retry_last_ts" => Some(health.retry_last_ts),
            "retry_interval" => Some(health.retry_interval),
            "failure_ts" => health.failure_ts,
            "last_successful_stream_ordering" => health.last_successful_stream_ordering,
            _ => None,
        }
    };
    match order {
        "destination" => rows.sort_by(|a, b| a.0.cmp(&b.0)),
        "retry_last_ts" | "retry_interval" | "failure_ts" | "last_successful_stream_ordering" => {
            rows.sort_by(|a, b| key(&a.1).cmp(&key(&b.1)).then_with(|| a.0.cmp(&b.0)));
        }
        other => return Err(invalid(format!("Unknown value for order_by: {other}"))),
    }
    if !forward {
        rows.reverse();
    }
    let total = rows.len();
    let page: Vec<Value> = rows
        .iter()
        .skip(from)
        .take(limit)
        .map(|(destination, health)| destination_json(destination, health))
        .collect();
    let mut body = json!({ "destinations": page, "total": total });
    if from + page.len() < total && limit > 0 {
        body["next_token"] = json!((from + page.len()).to_string());
    }
    Ok(Json(body))
}

/// `GET /federation/destinations/{destination}`
async fn get_destination(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(destination): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let known = known_destinations(&state, &actor)?;
    let health = known.get(&destination).ok_or_else(unknown_destination)?;
    Ok(Json(destination_json(&destination, health)))
}

/// `GET /federation/destinations/{destination}/rooms?from&limit&dir`
///
/// The rooms this server shares with the destination. Synapse also gives
/// each one the stream position last sent there; this server's outbox
/// does not record that per room, so it is `null`.
async fn destination_rooms(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(destination): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, MatrixError> {
    let (from, limit) = page_bounds(&query)?;
    let forward = ascending(query.dir.as_deref())?;
    if !known_destinations(&state, &actor)?.contains_key(&destination) {
        return Err(unknown_destination());
    }
    let mut rooms: Vec<String> = shared_rooms(&state, &actor)?
        .remove(&destination)
        .unwrap_or_default()
        .into_iter()
        .collect();
    if !forward {
        rooms.reverse();
    }
    let total = rooms.len();
    let page: Vec<Value> = rooms
        .iter()
        .skip(from)
        .take(limit)
        .map(|room_id| json!({ "room_id": room_id, "stream_ordering": null }))
        .collect();
    let mut body = json!({ "rooms": page, "total": total });
    if from + page.len() < total && limit > 0 {
        body["next_token"] = json!((from + page.len()).to_string());
    }
    Ok(Json(body))
}

/// `POST /federation/destinations/{destination}/reset_connection`
///
/// Clear the destination's backoff so the outbox tries it on its next
/// pass. As in Synapse, a destination that is not backing off has nothing
/// to reset, and that is a 400.
async fn reset_connection(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(destination): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let known = known_destinations(&state, &actor)?;
    let health = known.get(&destination).ok_or_else(unknown_destination)?;
    if health.retry_last_ts == 0 {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "The retry timing does not need to be reset for this destination.",
        ));
    }
    state.federation.reset_delivery(&destination);
    crate::admin::audit(
        &state,
        &actor.identity().user_id,
        "reset_connection",
        &destination,
        &json!({}),
    )?;
    Ok(Json(json!({})))
}
