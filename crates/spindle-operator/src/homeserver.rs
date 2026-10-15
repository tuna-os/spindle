//! Read-only views of a homeserver's people, rooms and reports, for the
//! console's "People & access" and "Rooms & safety" pages (#458).
//!
//! The browser never holds a Matrix admin credential. It asks the operator,
//! and the operator calls the homeserver's Synapse-compatible admin API
//! (`/_synapse/admin`, which Spindle and Synapse both serve) with the
//! credential its [`Connection`](crate::model::Connection) names by
//! reference. The value is resolved for the one request and never
//! returned, logged or journalled.
//!
//! Every answer is reshaped to a fixed set of fields rather than relayed,
//! so a homeserver that adds a field cannot add it to the browser, and is
//! passed through [`secret::redact`] on the way out.
//!
//! A homeserver that is down, refuses the credential, or answers with an
//! error is a stated condition with its own error code, never a blank
//! page: the console exists to be useful while the homeserver is not.
//! A person or room page whose secondary lookups fail still shows what
//! did load and names what did not under `unavailable`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Json, Router, routing};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::auth::{AppState, Authenticated};
use crate::error::ApiError;
use crate::model::Role;
use crate::secret;

const PREFIX: &str = "/_spindle/operator/v1";
/// The largest page the console may ask for.
const MAX_PAGE: u64 = 100;

pub fn routes() -> Router<AppState> {
    // `{target}`, not `{id}`: the router requires one name per position,
    // and `/connections/{target}` already uses this one.
    let route = |path: &str| format!("{PREFIX}/connections/{{target}}{path}");
    Router::new()
        .route(&route("/people"), routing::get(list_people))
        .route(&route("/people/{user_id}"), routing::get(person))
        .route(&route("/rooms"), routing::get(list_rooms))
        .route(&route("/rooms/{room_id}"), routing::get(room))
        .route(&route("/reports"), routing::get(reports))
}

/// Why a homeserver lookup failed, in codes the console branches on.
fn unreachable(detail: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "homeserver_unreachable", detail)
}

/// One authenticated GET against a connection's admin API.
async fn upstream(app: &AppState, connection: &str, path: &str) -> Result<Value, ApiError> {
    let (base, credential) = app
        .engine
        .read(|state| {
            state
                .connections
                .get(connection)
                .map(|c| (c.base_url.clone(), c.credential.clone()))
        })
        .ok_or_else(|| ApiError::not_found("connection"))?;
    let credential = credential.ok_or_else(|| {
        ApiError::conflict(
            "no_credential",
            "this connection has no admin credential; give it one to browse people and rooms",
        )
    })?;
    let token = credential.resolve().map_err(|why| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential_unavailable",
            why,
        )
    })?;
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let response = app
        .engine
        .http()
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| {
            unreachable(if error.is_timeout() {
                "the homeserver did not answer in time"
            } else if error.is_connect() {
                "the homeserver refused the connection or could not be reached"
            } else {
                "the request to the homeserver failed"
            })
        })?;
    let status = response.status();
    let body: Value = response
        .bytes()
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    match status.as_u16() {
        200..=299 => Ok(body),
        401 | 403 => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "homeserver_refused",
            format!(
                "the homeserver refused this connection's admin credential ({})",
                status.as_u16()
            ),
        )),
        404 if body["errcode"] == "M_NOT_FOUND" => Err(ApiError::not_found("user or room")),
        _ => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "homeserver_error",
            format!(
                "the homeserver answered {}{}",
                status.as_u16(),
                body["errcode"]
                    .as_str()
                    .map_or(String::new(), |code| format!(" {code}"))
            ),
        )),
    }
}

/// Copy the named fields, and nothing else, then redact.
fn pick(source: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    for field in fields {
        out.insert(
            (*field).to_owned(),
            source.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    let mut out = Value::Object(out);
    secret::redact(&mut out);
    out
}

fn encode(segment: &str) -> String {
    form_urlencoded::byte_serialize(segment.as_bytes()).collect()
}

fn query_string(pairs: &[(&str, Option<String>)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if let Some(value) = value {
            query.append_pair(key, value);
        }
    }
    query.finish()
}

#[derive(Deserialize)]
struct ListQuery {
    search: Option<String>,
    from: Option<u64>,
    limit: Option<u64>,
}

impl ListQuery {
    fn from(&self) -> Option<String> {
        self.from.map(|from| from.to_string())
    }
    fn limit(&self) -> String {
        self.limit.unwrap_or(50).clamp(1, MAX_PAGE).to_string()
    }
    fn search(&self) -> Option<String> {
        self.search
            .as_deref()
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .map(str::to_owned)
    }
}

/// The next offset, as a number, whichever way the homeserver spelled it.
fn next_offset(value: &Value) -> Value {
    match value {
        Value::Number(_) => value.clone(),
        Value::String(text) => text.parse::<u64>().map_or(Value::Null, Value::from),
        _ => Value::Null,
    }
}

const PERSON_SUMMARY: &[&str] = &[
    "name",
    "displayname",
    "admin",
    "deactivated",
    "locked",
    "suspended",
    "erased",
    "shadow_banned",
    "creation_ts",
    "last_seen_ts",
];

/// `GET /connections/{id}/people?search&from&limit`
async fn list_people(
    State(app): State<AppState>,
    who: Authenticated,
    Path(target): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let path = format!(
        "/_synapse/admin/v2/users?{}",
        query_string(&[
            ("name", query.search()),
            ("from", query.from()),
            ("limit", Some(query.limit())),
        ])
    );
    let body = upstream(&app, &target, &path).await?;
    let people: Vec<Value> = body["users"]
        .as_array()
        .map(|users| {
            users
                .iter()
                .map(|user| pick(user, PERSON_SUMMARY))
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({
        "people": people,
        "total": body["total"],
        "next": next_offset(&body["next_token"]),
    })))
}

/// `GET /connections/{id}/people/{userId}`: the account, its devices and
/// its rooms. Devices and rooms are best-effort.
async fn person(
    State(app): State<AppState>,
    who: Authenticated,
    Path((target, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let user = encode(&user_id);
    let account = upstream(&app, &target, &format!("/_synapse/admin/v2/users/{user}")).await?;
    let mut fields: Vec<&str> = PERSON_SUMMARY.to_vec();
    fields.extend(["threepids", "external_ids"]);
    let mut out = json!({ "person": pick(&account, &fields) });
    let mut unavailable = Vec::new();
    match upstream(
        &app,
        &target,
        &format!("/_synapse/admin/v2/users/{user}/devices"),
    )
    .await
    {
        Ok(body) => {
            out["devices"] = Value::Array(
                body["devices"]
                    .as_array()
                    .map(|devices| {
                        devices
                            .iter()
                            .map(|device| {
                                pick(
                                    device,
                                    &["device_id", "display_name", "last_seen_ts", "last_seen_ip"],
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            );
        }
        Err(error) => {
            out["devices"] = Value::Null;
            unavailable
                .push(json!({ "part": "devices", "code": error.code, "message": error.message }));
        }
    }
    match upstream(
        &app,
        &target,
        &format!("/_synapse/admin/v1/users/{user}/joined_rooms"),
    )
    .await
    {
        Ok(body) => out["joined_rooms"] = body["joined_rooms"].clone(),
        Err(error) => {
            out["joined_rooms"] = Value::Null;
            unavailable.push(
                json!({ "part": "joined_rooms", "code": error.code, "message": error.message }),
            );
        }
    }
    out["unavailable"] = Value::Array(unavailable);
    // Contact details and where a device connects from are personal data
    // an investigation may need, and a viewer does not.
    if !who.principal.has(Role::Operator) {
        if let Some(person) = out["person"].as_object_mut() {
            person.remove("threepids");
            person.remove("external_ids");
        }
        if let Some(devices) = out["devices"].as_array_mut() {
            for device in devices {
                if let Some(device) = device.as_object_mut() {
                    device.remove("last_seen_ip");
                }
            }
        }
        out["restricted"] = json!(["threepids", "external_ids", "last_seen_ip"]);
    }
    Ok(Json(out))
}

const ROOM_SUMMARY: &[&str] = &[
    "room_id",
    "name",
    "canonical_alias",
    "joined_members",
    "joined_local_members",
    "version",
    "creator",
    "encryption",
    "federatable",
    "public",
    "join_rules",
    "room_type",
];

#[derive(Deserialize)]
struct RoomsQuery {
    search: Option<String>,
    from: Option<u64>,
    limit: Option<u64>,
    order_by: Option<String>,
}

/// `GET /connections/{id}/rooms?search&from&limit&order_by`
async fn list_rooms(
    State(app): State<AppState>,
    who: Authenticated,
    Path(target): Path<String>,
    Query(query): Query<RoomsQuery>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let order_by = match query.order_by.as_deref() {
        None => None,
        Some(order @ ("name" | "joined_members" | "joined_local_members" | "state_events")) => {
            Some(order.to_owned())
        }
        Some(other) => {
            return Err(ApiError::invalid(format!(
                "cannot order rooms by {other:?}"
            )));
        }
    };
    let list = ListQuery {
        search: query.search,
        from: query.from,
        limit: query.limit,
    };
    let path = format!(
        "/_synapse/admin/v1/rooms?{}",
        query_string(&[
            ("search_term", list.search()),
            ("from", list.from()),
            ("limit", Some(list.limit())),
            ("order_by", order_by),
        ])
    );
    let body = upstream(&app, &target, &path).await?;
    let rooms: Vec<Value> = body["rooms"]
        .as_array()
        .map(|rooms| rooms.iter().map(|room| pick(room, ROOM_SUMMARY)).collect())
        .unwrap_or_default();
    Ok(Json(json!({
        "rooms": rooms,
        "total": body["total_rooms"],
        "next": next_offset(&body["next_batch"]),
    })))
}

/// `GET /connections/{id}/rooms/{roomId}`: the room, its members, whether
/// it is blocked, deletion tasks, and reports filed about it.
async fn room(
    State(app): State<AppState>,
    who: Authenticated,
    Path((target, room_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let room = encode(&room_id);
    let detail = upstream(&app, &target, &format!("/_synapse/admin/v1/rooms/{room}")).await?;
    let mut fields: Vec<&str> = ROOM_SUMMARY.to_vec();
    fields.extend([
        "topic",
        "history_visibility",
        "guest_access",
        "state_events",
        "joined_local_devices",
        "forgotten",
    ]);
    let mut out = json!({ "room": pick(&detail, &fields) });
    let mut unavailable = Vec::new();
    let parts: [(&str, String); 4] = [
        (
            "members",
            format!("/_synapse/admin/v1/rooms/{room}/members"),
        ),
        ("block", format!("/_synapse/admin/v1/rooms/{room}/block")),
        (
            "tasks",
            format!("/_synapse/admin/v1/scheduled_tasks?resource_id={room}"),
        ),
        (
            "reports",
            format!("/_synapse/admin/v1/event_reports?room_id={room}&limit=50"),
        ),
    ];
    for (part, path) in parts {
        match upstream(&app, &target, &path).await {
            Ok(body) => {
                out[part] = match part {
                    "members" => json!({
                        "total": body["total"],
                        "members": body["members"]
                            .as_array()
                            .map(|members| members.iter().take(500).cloned().collect::<Vec<_>>())
                            .unwrap_or_default(),
                    }),
                    "block" => pick(&body, &["block", "user_id"]),
                    "tasks" => Value::Array(
                        body["scheduled_tasks"]
                            .as_array()
                            .map(|tasks| {
                                tasks
                                    .iter()
                                    .map(|task| {
                                        pick(
                                            task,
                                            &["id", "action", "status", "timestamp_ms", "error"],
                                        )
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    ),
                    _ => report_list(&body),
                };
            }
            Err(error) => {
                out[part] = Value::Null;
                unavailable
                    .push(json!({ "part": part, "code": error.code, "message": error.message }));
            }
        }
    }
    out["unavailable"] = Value::Array(unavailable);
    secret::redact(&mut out);
    Ok(Json(out))
}

fn report_list(body: &Value) -> Value {
    Value::Array(
        body["event_reports"]
            .as_array()
            .map(|reports| {
                reports
                    .iter()
                    .map(|report| {
                        pick(
                            report,
                            &[
                                "id",
                                "received_ts",
                                "room_id",
                                "name",
                                "event_id",
                                "user_id",
                                "sender",
                                "reason",
                                "score",
                            ],
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// `GET /connections/{id}/reports?from&limit`: newest first.
async fn reports(
    State(app): State<AppState>,
    who: Authenticated,
    Path(target): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let path = format!(
        "/_synapse/admin/v1/event_reports?{}",
        query_string(&[("from", query.from()), ("limit", Some(query.limit()))])
    );
    let body = upstream(&app, &target, &path).await?;
    Ok(Json(json!({
        "reports": report_list(&body),
        "total": body["total"],
        "next": next_offset(&body["next_token"]),
    })))
}
