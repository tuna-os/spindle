//! The admin API — `/_spindle/admin/v1`, with the
//! `/_synapse/admin/v1` compatibility alias existing tooling drives.
//!
//! The shape is deliberately Synapse's (#83): operators have tooling and
//! muscle memory, and inventing a different spelling for the same
//! operations buys nothing. What is *not* Synapse's is the auth model —
//! an `admin` flag on an ordinary account rather than a shared secret,
//! so every audit record names who acted and revocation is per-operator
//! — and the audit log itself: an append-only record per mutating
//! request, in its own keyspace, exempt from purge.
//!
//! The honest-advertisement rule from `surface.rs` applies here in its
//! sternest form: an admin endpoint that is routed must work, because a
//! stub returning `{}` is indistinguishable from success to the tooling
//! that calls it. This module carries the groups of #83's spec that are
//! built — the users group and the rooms group entire — and routes
//! nothing beyond what it serves: event reports, registration tokens and
//! server notices are not here because they are not built.

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::Store;

use crate::AppState;
use crate::accounts::{Account, Accounts, unguessable_password};
use crate::auth::Authenticated;
use crate::errors::MatrixError;

pub fn routes() -> Router<AppState> {
    let group = |prefix: &str| {
        Router::new()
            .route(&format!("{prefix}/server_version"), get(server_version))
            .route(&format!("{prefix}/users"), get(list_users))
            .route(
                &format!("{prefix}/users/{{user_id}}"),
                get(get_user).put(put_user),
            )
            .route(
                &format!("{prefix}/users/{{user_id}}/deactivate"),
                post(deactivate),
            )
            .route(
                &format!("{prefix}/users/{{user_id}}/reset_password"),
                post(reset_password),
            )
            .route(&format!("{prefix}/users/{{user_id}}/devices"), get(devices))
            .route(
                &format!("{prefix}/users/{{user_id}}/devices/{{device_id}}"),
                axum::routing::delete(delete_device),
            )
            .route(
                &format!("{prefix}/users/{{user_id}}/joined_rooms"),
                get(joined_rooms),
            )
            .route(&format!("{prefix}/whois/{{user_id}}"), get(whois))
            .route(&format!("{prefix}/rooms"), get(list_rooms))
            .route(
                &format!("{prefix}/rooms/{{room_id}}"),
                get(room_detail).delete(delete_room),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/members"),
                get(room_members),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/state"),
                get(room_state),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/state_at"),
                get(room_state_at),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/timeline"),
                get(room_timeline),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/purge_history"),
                post(purge_history),
            )
            .route(
                &format!("{prefix}/rooms/{{room_id}}/make_room_admin"),
                post(make_room_admin),
            )
            .route(&format!("{prefix}/audit"), get(audit_log))
    };
    group("/_spindle/admin/v1").merge(group("/_synapse/admin/v1"))
}

/// The caller, proven to be a server admin.
///
/// An extractor for the same reason [`Authenticated`] is one: a handler
/// in this module either takes this and is authorized, or cannot see
/// the request at all. The acceptance test iterates every route with a
/// non-admin token; this type is why that test cannot find a gap.
pub struct AdminActor(crate::accounts::Identity);

impl AdminActor {
    /// Who the admin is. The field itself stays private: the type is a
    /// capability -- [`Rooms::admin`] asks for one as proof -- and a
    /// public field would let any handler in the crate mint that proof
    /// out of an ordinary identity (#311).
    #[must_use]
    pub fn identity(&self) -> &crate::accounts::Identity {
        &self.0
    }
}

impl FromRequestParts<AppState> for AdminActor {
    type Rejection = MatrixError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated(identity) = Authenticated::from_request_parts(parts, state).await?;
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        let localpart = local_localpart(state, &identity.user_id)
            .ok_or_else(|| MatrixError::forbidden("only local accounts can be admins"))?;
        let is_admin = accounts
            .account(&localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_some_and(|account| account.admin && !account.deactivated);
        if !is_admin {
            return Err(MatrixError::forbidden("not a server admin"));
        }
        Ok(Self(identity))
    }
}

/// Append one audit record. Every mutating handler calls this after the
/// action succeeded — the record says what happened, not what was
/// attempted, and a storage failure writing it is a server error the
/// caller hears about rather than a silent gap in the log.
pub(crate) fn audit(
    state: &AppState,
    actor: &str,
    action: &str,
    target: &str,
    detail: &Value,
) -> Result<(), MatrixError> {
    let record = json!({
        "actor": actor,
        "action": action,
        "target": target,
        "detail": detail,
        "ts_ms": u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis()),
        )
        .unwrap_or(u64::MAX),
    });
    let seq = state.rooms.allocate_stream_id();
    Store::put(
        state.store.as_ref(),
        &keys::audit_entry(seq),
        serde_json::to_vec(&record)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .as_slice(),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))
}

/// `@name:this.server` → `name`; anything else is not ours.
/// Whether `user_id` is a live admin account on this server.
///
/// The same predicate [`AdminActor`] enforces, exposed for handlers that treat
/// admin as *one* way to be allowed rather than the only one -- the extractor
/// rejects a non-admin outright, which is the wrong shape when membership also
/// grants the right.
///
/// # Errors
///
/// Returns [`crate::accounts::AccountError`] if the account cannot be read.
pub fn is_server_admin(
    state: &AppState,
    user_id: &str,
) -> Result<bool, crate::accounts::AccountError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let Some(localpart) = local_localpart(state, user_id) else {
        return Ok(false);
    };
    Ok(accounts
        .account(&localpart)?
        .is_some_and(|account| account.admin && !account.deactivated))
}

fn local_localpart(state: &AppState, user_id: &str) -> Option<String> {
    user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .filter(|(_, domain)| *domain == state.config.server.name)
        .map(|(localpart, _)| localpart.to_owned())
}

/// The path accepts a full user ID (what Synapse tooling sends) and
/// resolves it to a local account, or says which of the two failed.
fn target_account(state: &AppState, user_id: &str) -> Result<(String, Account), MatrixError> {
    let localpart = local_localpart(state, user_id).ok_or_else(|| {
        MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "not a user of this server",
        )
    })?;
    let account = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such user"))?;
    Ok((localpart, account))
}

fn user_json(state: &AppState, account: &Account) -> Value {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let user_id = accounts.user_id(&account.localpart);
    let profile = state.profiles.get(&user_id).unwrap_or_default();
    json!({
        "name": user_id,
        "displayname": profile.displayname,
        "avatar_url": profile.avatar_url,
        "admin": account.admin,
        "deactivated": account.deactivated,
    })
}

/// `GET /server_version`
async fn server_version(
    State(state): State<AppState>,
    _actor: AdminActor,
) -> Result<Json<Value>, MatrixError> {
    let _ = &state;
    Ok(Json(json!({
        "server_version": format!("spindle {}", env!("CARGO_PKG_VERSION")),
    })))
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    from: usize,
    limit: Option<usize>,
    name: Option<String>,
    deactivated: Option<bool>,
    actor: Option<String>,
    action: Option<String>,
}

/// `GET /users?from&limit&name&deactivated`
async fn list_users(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, MatrixError> {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let all = accounts
        .all_accounts()
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let matching: Vec<&Account> = all
        .iter()
        .filter(|account| {
            query
                .name
                .as_deref()
                .is_none_or(|name| account.localpart.contains(name))
                && query
                    .deactivated
                    .is_none_or(|wanted| account.deactivated == wanted)
        })
        .collect();
    let total = matching.len();
    let limit = query.limit.unwrap_or(100);
    let page: Vec<Value> = matching
        .iter()
        .skip(query.from)
        .take(limit)
        .map(|account| user_json(&state, account))
        .collect();
    let mut body = json!({ "users": page, "total": total });
    if query.from + limit < total {
        body["next_token"] = json!((query.from + limit).to_string());
    }
    Ok(Json(body))
}

/// `GET /users/{userId}`
async fn get_user(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let (_, account) = target_account(&state, &user_id)?;
    Ok(Json(user_json(&state, &account)))
}

#[derive(Deserialize)]
struct PutUser {
    displayname: Option<String>,
    admin: Option<bool>,
    deactivated: Option<bool>,
    password: Option<String>,
}

/// `PUT /users/{userId}` — create or modify.
async fn put_user(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    Json(request): Json<PutUser>,
) -> Result<(StatusCode, Json<Value>), MatrixError> {
    let localpart = local_localpart(&state, &user_id).ok_or_else(|| {
        MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "not a user of this server",
        )
    })?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let existed = accounts
        .account(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if !existed {
        let password = request
            .password
            .clone()
            .unwrap_or_else(unguessable_password);
        accounts
            .register(&localpart, &password)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    } else if let Some(password) = &request.password {
        accounts
            .set_password(&localpart, password)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if let Some(admin) = request.admin {
        accounts
            .set_admin(&localpart, admin)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if let Some(true) = request.deactivated {
        crate::mas::deactivate_user(&state, &localpart, false)?;
    } else if let Some(false) = request.deactivated {
        accounts
            .set_deactivated(&localpart, false)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if let Some(displayname) = &request.displayname {
        state
            .profiles
            .set(
                &accounts.user_id(&localpart),
                Some(Some(displayname.clone())),
                None,
            )
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    // The password never enters the audit record; that it changed does.
    audit(
        &state,
        &actor.identity().user_id,
        "put_user",
        &user_id,
        &json!({
            "created": !existed,
            "password_changed": request.password.is_some(),
            "admin": request.admin,
            "deactivated": request.deactivated,
            "displayname": request.displayname,
        }),
    )?;
    let (_, account) = target_account(&state, &user_id)?;
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(user_json(&state, &account))))
}

#[derive(Deserialize)]
struct Deactivate {
    #[serde(default)]
    erase: bool,
}

/// `POST /users/{userId}/deactivate`
async fn deactivate(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    body: Option<Json<Deactivate>>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let erase = body.is_some_and(|Json(body)| body.erase);
    crate::mas::deactivate_user(&state, &localpart, erase)?;
    audit(
        &state,
        &actor.identity().user_id,
        "deactivate",
        &user_id,
        &json!({ "erase": erase }),
    )?;
    Ok(Json(json!({ "id_server_unbind_result": "no-support" })))
}

#[derive(Deserialize)]
struct ResetPassword {
    new_password: String,
    logout_devices: Option<bool>,
}

/// `POST /users/{userId}/reset_password`
async fn reset_password(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    Json(request): Json<ResetPassword>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_password(&localpart, &request.new_password)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let logout = request.logout_devices.unwrap_or(true);
    if logout {
        accounts
            .logout_everywhere(&localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    audit(
        &state,
        &actor.identity().user_id,
        "reset_password",
        &user_id,
        &json!({ "logout_devices": logout }),
    )?;
    Ok(Json(json!({})))
}

/// `GET /users/{userId}/devices`
async fn devices(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let devices: Vec<Value> = accounts
        .devices_of(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .into_iter()
        .map(|device| {
            json!({
                "device_id": device.device_id,
                "display_name": device.display_name,
            })
        })
        .collect();
    Ok(Json(json!({ "total": devices.len(), "devices": devices })))
}

/// `DELETE /users/{userId}/devices/{deviceId}`
async fn delete_device(
    State(state): State<AppState>,
    actor: AdminActor,
    Path((user_id, device_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    crate::mas::remove_device(&state, &accounts, &localpart, &device_id)?;
    crate::mas::device_list_changed(&state, &accounts.user_id(&localpart));
    audit(
        &state,
        &actor.identity().user_id,
        "delete_device",
        &user_id,
        &json!({ "device_id": device_id }),
    )?;
    Ok(Json(json!({})))
}

/// `GET /users/{userId}/joined_rooms`
async fn joined_rooms(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    // The membership index answers for remote users too, which is the
    // point of the admin view: "which of my rooms is this stranger in".
    let rooms = state
        .rooms
        .joined(&user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "total": rooms.len(), "joined_rooms": rooms })))
}

/// `GET /whois/{userId}`
///
/// The devices are real; connection detail (IPs, user agents) is not
/// tracked by this server, and the sessions lists are honestly empty
/// rather than invented.
async fn whois(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let mut devices = serde_json::Map::new();
    for device in accounts
        .devices_of(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        devices.insert(device.device_id, json!({ "sessions": [] }));
    }
    Ok(Json(json!({ "user_id": user_id, "devices": devices })))
}

/// One room as the admin listing and detail views describe it.
///
/// Everything here is read from the room's current state and metadata —
/// nothing is cached or estimated, because an operator acting on this
/// view (blocking, purging) needs it to be the room, not a summary of
/// last week's room.
fn room_json(state: &AppState, room_id: &str) -> Result<Value, crate::rooms::RoomError> {
    let events = state.rooms.state(room_id)?;
    let content = |event_type: &str, field: &str| -> Value {
        events
            .iter()
            .find(|event| event["type"] == event_type && event["state_key"] == "")
            .map_or(Value::Null, |event| event["content"][field].clone())
    };
    let create = events
        .iter()
        .find(|event| event["type"] == "m.room.create" && event["state_key"] == "");
    let joined = state.rooms.joined_members(room_id)?;
    let local_suffix = format!(":{}", state.config.server.name);
    let joined_local = joined
        .keys()
        .filter(|user| user.ends_with(&local_suffix))
        .count();
    Ok(json!({
        "room_id": room_id,
        "name": content("m.room.name", "name"),
        "topic": content("m.room.topic", "topic"),
        "avatar": content("m.room.avatar", "url"),
        "canonical_alias": content("m.room.canonical_alias", "alias"),
        "joined_members": joined.len(),
        "joined_local_members": joined_local,
        // The spec's default when m.room.create names no version.
        "version": create
            .and_then(|event| event["content"]["room_version"].as_str())
            .unwrap_or("1"),
        "creator": create.and_then(|event| event["sender"].as_str()),
        "encryption": content("m.room.encryption", "algorithm"),
        "federatable": create.is_none_or(|event| event["content"]["m.federate"] != false),
        "public": content("m.room.join_rules", "join_rule") == "public",
        "join_rules": content("m.room.join_rules", "join_rule"),
        "guest_access": content("m.room.guest_access", "guest_access"),
        "history_visibility": content("m.room.history_visibility", "history_visibility"),
        "room_type": create.map_or(Value::Null, |event| event["content"]["type"].clone()),
        "state_events": events.len(),
    }))
}

#[derive(Deserialize)]
struct RoomsQuery {
    #[serde(default)]
    from: usize,
    limit: Option<usize>,
    order_by: Option<String>,
    search_term: Option<String>,
}

/// `GET /rooms?from&limit&order_by&search_term`
async fn list_rooms(
    State(state): State<AppState>,
    actor: AdminActor,
    Query(query): Query<RoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let mut rooms = Vec::new();
    for room_id in state
        .rooms
        .admin(&actor)
        .all_room_ids()
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        let room = room_json(&state, &room_id).map_err(crate::routes::room_error)?;
        let matches = query.search_term.as_deref().is_none_or(|term| {
            [&room["room_id"], &room["name"], &room["canonical_alias"]]
                .iter()
                .any(|field| field.as_str().is_some_and(|value| value.contains(term)))
        });
        if matches {
            rooms.push(room);
        }
    }
    // Synapse's orderings, the ones this store can answer exactly: name
    // ascending (rooms without one sort by ID, so they group last rather
    // than vanishing), sizes descending.
    match query.order_by.as_deref().unwrap_or("name") {
        "name" => rooms.sort_by_key(|room| {
            (
                room["name"].as_str().is_none(),
                room["name"].as_str().unwrap_or_default().to_owned(),
                room["room_id"].as_str().unwrap_or_default().to_owned(),
            )
        }),
        "joined_members" => {
            rooms.sort_by_key(|room| std::cmp::Reverse(room["joined_members"].as_u64()));
        }
        "state_events" => {
            rooms.sort_by_key(|room| std::cmp::Reverse(room["state_events"].as_u64()));
        }
        other => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("cannot order by {other:?}"),
            ));
        }
    }
    let total = rooms.len();
    let limit = query.limit.unwrap_or(100);
    let page: Vec<Value> = rooms.into_iter().skip(query.from).take(limit).collect();
    let mut body = json!({ "rooms": page, "offset": query.from, "total_rooms": total });
    if query.from + limit < total {
        body["next_batch"] = json!(query.from + limit);
    }
    Ok(Json(body))
}

/// `GET /rooms/{roomId}`
async fn room_detail(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room = room_json(&state, &room_id).map_err(crate::routes::room_error)?;
    Ok(Json(room))
}

/// `GET /rooms/{roomId}/members`
async fn room_members(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let members = state
        .rooms
        .joined_members(&room_id)
        .map_err(crate::routes::room_error)?;
    let names: Vec<&String> = members.keys().collect();
    Ok(Json(json!({ "total": names.len(), "members": names })))
}

/// `GET /rooms/{roomId}/state`
async fn room_state(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let events = state
        .rooms
        .state(&room_id)
        .map_err(crate::routes::room_error)?;
    Ok(Json(json!({ "state": events })))
}

#[derive(Deserialize)]
struct StateAtQuery {
    li: Option<i64>,
    ts: Option<u64>,
    event_id: Option<String>,
}

/// `GET /rooms/{roomId}/state_at?li|ts|event_id`
///
/// The capability #83 §4 gives its own endpoint: "what did this room
/// look like at that point" as one seek plus a trie root, rather than a
/// forensic exercise. Exactly one anchor is required — a request naming
/// two is ambiguous about which point it means, and refused rather than
/// second-guessed. The response says which entry it resolved to and
/// whether the answer came from the resident window or was rehydrated.
async fn room_state_at(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Query(query): Query<StateAtQuery>,
) -> Result<Json<Value>, MatrixError> {
    use crate::rooms::StateAtAnchor;
    let anchor = match (query.li, query.ts, query.event_id) {
        (Some(li), None, None) => StateAtAnchor::Li(li),
        (None, Some(ts), None) => StateAtAnchor::Ts(ts),
        (None, None, Some(event_id)) => StateAtAnchor::Event(event_id),
        _ => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "exactly one of li, ts, event_id",
            ));
        }
    };
    let (li, event_id, resident, events) = state
        .rooms
        .admin(&actor)
        .admin_state_at(&room_id, &anchor)
        .map_err(crate::routes::room_error)?;
    let ts = state
        .rooms
        .event(&room_id, &event_id)
        .ok()
        .and_then(|event| event["origin_server_ts"].as_u64());
    Ok(Json(json!({
        "room_id": room_id,
        "li": li,
        "event_id": event_id,
        "origin_server_ts": ts,
        "source": if resident { "resident" } else { "rehydrated" },
        "state": events,
    })))
}

#[derive(Deserialize)]
struct TimelineQuery {
    from: Option<i64>,
    limit: Option<usize>,
    dir: Option<String>,
}

/// `GET /rooms/{roomId}/timeline?from&limit&dir`
///
/// The admin view of the log, in storage order — which for this store
/// *is* the topological order, the query #83's table calls trivial.
/// Forward is the default because the operator's question is "what does
/// the log say", read the way the log is written.
async fn room_timeline(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<Value>, MatrixError> {
    let forward = match query.dir.as_deref().unwrap_or("f") {
        "f" => true,
        "b" => false,
        other => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("dir must be \"f\" or \"b\", not {other:?}"),
            ));
        }
    };
    let (events, next) = state
        .rooms
        .admin(&actor)
        .admin_timeline(&room_id, query.from, query.limit.unwrap_or(100), forward)
        .map_err(crate::routes::room_error)?;
    let chunk: Vec<Value> = events
        .into_iter()
        .map(|entry| {
            json!({
                "li": entry.li,
                "event_id": entry.event_id,
                "chain": entry.chain.map(hex),
                "purged": entry.json.is_none(),
                "event": entry.json,
            })
        })
        .collect();
    let mut body = json!({ "chunk": chunk });
    if let Some(next) = next {
        body["next_token"] = json!(next);
    }
    Ok(Json(body))
}

/// Lowercase hex, for the 32-byte chain values the admin timeline shows.
fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[derive(Deserialize)]
struct PurgeRequest {
    before_li: Option<i64>,
    before_ts: Option<u64>,
}

/// `POST /rooms/{roomId}/purge_history` — `{before_li}` or `{before_ts}`.
///
/// Deletes the bodies, keeps the spine (#83 §3): entries below the cutoff
/// lose their content but keep `(li, event_id, chain)`, so the chain
/// still verifies over the purged range and a reader can tell "purged"
/// from "never existed". State event bodies survive — current state and
/// `state_at` keep folding from the log. The one audit record names how
/// far and how many.
async fn purge_history(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<PurgeRequest>,
) -> Result<Json<Value>, MatrixError> {
    use crate::rooms::StateAtAnchor;
    let before_li = match (request.before_li, request.before_ts) {
        (Some(li), None) => li,
        (None, Some(ts)) => {
            // "Everything at or before this time" purges up to, and
            // including, the entry that anchor resolves to.
            let (li, _) = state
                .rooms
                .resolve_anchor(&room_id, &StateAtAnchor::Ts(ts))
                .map_err(crate::routes::room_error)?;
            li + 1
        }
        _ => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "exactly one of before_li, before_ts",
            ));
        }
    };
    let purged = state
        .rooms
        .admin(&actor)
        .purge_history(&room_id, before_li)
        .map_err(crate::routes::room_error)?;
    audit(
        &state,
        &actor.identity().user_id,
        "purge_history",
        &room_id,
        &json!({ "before_li": before_li, "events_purged": purged }),
    )?;
    Ok(Json(
        json!({ "purged_up_to": before_li, "events_purged": purged }),
    ))
}

#[derive(Deserialize)]
struct DeleteRoom {
    #[serde(default)]
    block: bool,
    #[serde(default)]
    purge: bool,
    new_room_user_id: Option<String>,
    message: Option<String>,
}

/// A fresh room owned by `creator` with nothing in it yet: no name, no
/// topic, no preset, and no profile on the creator's join, since an
/// administrator creating a room on a user's behalf is not that user
/// joining it.
fn bare_room(state: &AppState, creator: &str) -> Result<String, MatrixError> {
    state
        .rooms
        .create(
            creator,
            state.key.pair(),
            None,
            None,
            None,
            &[],
            None,
            None,
            &serde_json::Map::new(),
        )
        .map_err(crate::routes::room_error)
}

/// `DELETE /rooms/{roomId}` — `{block, purge, new_room_user_id, message}`.
///
/// Every departure is a real leave event through the ordinary append
/// path (#83 §2) — the log records the eviction the same way it records
/// any other membership change, so a peer replaying it computes the
/// same room. The block row is written first so nobody rejoins between
/// the eviction and the block; `purge` reuses `purge_history` over the
/// whole log, so the spine and the chain survive even total deletion.
async fn delete_room(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<DeleteRoom>,
) -> Result<Json<Value>, MatrixError> {
    let members = state
        .rooms
        .joined_members(&room_id)
        .map_err(crate::routes::room_error)?;
    let local_suffix = format!(":{}", state.config.server.name);
    let locals: Vec<String> = members
        .keys()
        .filter(|user| user.ends_with(&local_suffix))
        .cloned()
        .collect();

    if request.block {
        state
            .rooms
            .admin(&actor)
            .set_room_block(&room_id, &json!({ "actor": actor.identity().user_id }))
            .map_err(crate::routes::room_error)?;
    }

    // The replacement room, when asked for: created by the named local
    // user, opening with the administrator's message, every evicted
    // local user invited into it.
    let new_room = match &request.new_room_user_id {
        Some(creator) => {
            local_localpart(&state, creator).ok_or_else(|| {
                MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "new_room_user_id must be a user of this server",
                )
            })?;
            let new_room = bare_room(&state, creator)?;
            if let Some(message) = &request.message {
                state
                    .rooms
                    .send(
                        &new_room,
                        creator,
                        state.key.pair(),
                        "m.room.message",
                        &json!({ "msgtype": "m.text", "body": message }),
                    )
                    .map_err(crate::routes::room_error)?;
            }
            Some(new_room)
        }
        None => None,
    };

    let mut kicked = Vec::new();
    let mut failed = Vec::new();
    for user in &locals {
        if let (Some(new_room), Some(creator)) = (&new_room, &request.new_room_user_id)
            && user != creator
        {
            // Best-effort: an invite the new room refuses must not stop
            // the eviction from the old one.
            let _ = state.rooms.set_membership(
                new_room,
                creator,
                user,
                "invite",
                None,
                state.key.pair(),
            );
        }
        match state.rooms.set_membership(
            &room_id,
            user,
            user,
            "leave",
            request.message.as_deref(),
            state.key.pair(),
        ) {
            Ok(_) => kicked.push(user.clone()),
            Err(_) => failed.push(user.clone()),
        }
    }

    if request.purge {
        state
            .rooms
            .admin(&actor)
            .purge_history(&room_id, i64::MAX)
            .map_err(crate::routes::room_error)?;
    }

    audit(
        &state,
        &actor.identity().user_id,
        "delete_room",
        &room_id,
        &json!({
            "block": request.block,
            "purge": request.purge,
            "kicked": kicked.len(),
            "new_room_id": new_room,
        }),
    )?;
    Ok(Json(json!({
        "kicked_users": kicked,
        "failed_to_kick_users": failed,
        "new_room_id": new_room,
    })))
}

#[derive(Deserialize)]
struct MakeRoomAdmin {
    user_id: Option<String>,
}

/// `POST /rooms/{roomId}/make_room_admin` — `{user_id}`, default caller.
///
/// Authors a real `m.room.power_levels` event *as a local user who has
/// the power to* (#83 §2), never by writing state directly: state here
/// is the fold of the log, and surgery would produce a room whose state
/// no peer could recompute. The grant is the author's own level — the
/// auth rules cap a grant at the granter's power, and this endpoint
/// works inside the rules rather than around them. When no local user
/// can author the event, it says so.
async fn make_room_admin(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<MakeRoomAdmin>,
) -> Result<Json<Value>, MatrixError> {
    let target = request
        .user_id
        .unwrap_or_else(|| actor.identity().user_id.clone());
    let members = state
        .rooms
        .joined_members(&room_id)
        .map_err(crate::routes::room_error)?;
    let levels = state
        .rooms
        .admin(&actor)
        .state_event(&room_id, "m.room.power_levels", "")
        .unwrap_or_else(|_| json!({}));
    let users_default = levels["users_default"].as_i64().unwrap_or(0);
    let level_of = |user: &str| -> i64 { levels["users"][user].as_i64().unwrap_or(users_default) };
    let required = levels["events"]["m.room.power_levels"]
        .as_i64()
        .or_else(|| levels["state_default"].as_i64())
        .unwrap_or(50);

    let local_suffix = format!(":{}", state.config.server.name);
    let author = members
        .keys()
        .filter(|user| user.ends_with(&local_suffix))
        .max_by_key(|user| level_of(user))
        .filter(|user| level_of(user) >= required)
        .cloned()
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_UNKNOWN",
                "no local user has the power to author m.room.power_levels here",
            )
        })?;
    let granted = level_of(&author);
    if level_of(&target) >= granted {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "the user is already at or above the highest local power level",
        ));
    }

    let mut content = levels;
    content["users"][&target] = json!(granted);
    let event_id = state
        .rooms
        .set_state(
            &room_id,
            &author,
            state.key.pair(),
            "m.room.power_levels",
            "",
            &content,
        )
        .map_err(crate::routes::room_error)?;

    audit(
        &state,
        &actor.identity().user_id,
        "make_room_admin",
        &room_id,
        &json!({ "user_id": target, "granted": granted, "authored_by": author }),
    )?;
    Ok(Json(json!({
        "event_id": event_id,
        "user_id": target,
        "power_level": granted,
    })))
}

/// `GET /audit?from&limit&actor&action`
async fn audit_log(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, MatrixError> {
    let prefix = [keys::KEY_SCHEMA_VERSION, keys::Keyspace::AuditLog as u8];
    let mut entries = Vec::new();
    for (_, raw) in spindle_store::ReadView::scan_prefix(state.store.as_ref(), &prefix)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        let record: Value = serde_json::from_slice(&raw)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        let keep = query
            .actor
            .as_deref()
            .is_none_or(|actor| record["actor"] == actor)
            && query
                .action
                .as_deref()
                .is_none_or(|action| record["action"] == action);
        if keep {
            entries.push(record);
        }
    }
    let total = entries.len();
    let limit = query.limit.unwrap_or(100);
    let page: Vec<Value> = entries.into_iter().skip(query.from).take(limit).collect();
    let mut body = json!({ "entries": page, "total": total });
    if query.from + limit < total {
        body["next_token"] = json!((query.from + limit).to_string());
    }
    Ok(Json(body))
}
