//! The admin API — `/_spindle/admin/v1`, with the
//! `/_synapse/admin/v1` compatibility alias existing tooling drives.
//!
//! The shape is deliberately Synapse's (#83): operators have tooling and
//! muscle memory, and inventing a different spelling for the same
//! operations buys nothing. Element Admin, the console the ESS deployment
//! ships, is the strictest of those tools: it validates every response
//! against Synapse's schema, so a missing field breaks a whole page.
//! What is *not* Synapse's is the auth model — an `admin` flag on an
//! ordinary account, or a delegated token carrying the
//! `urn:synapse:admin:*` scope, rather than a shared secret, so every
//! audit record names who acted — and the audit log itself: an
//! append-only record per mutating request, in its own keyspace, exempt
//! from purge.
//!
//! The honest-advertisement rule from `surface.rs` applies here in its
//! sternest form: an admin endpoint that is routed must work, because a
//! stub returning `{}` is indistinguishable from success to the tooling
//! that calls it. Where Synapse reports something this server does not
//! record (when an account was created, where a device was last seen),
//! the field is present and `null`, never invented.
//!
//! This module carries the users, rooms, event-report, registration-token
//! and server-notice groups. Background room deletion and the
//! `scheduled_tasks` listing are in `admin_tasks`, federation
//! destinations in `admin_federation`, and media in `admin_media`.

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use spindle_core::keys;
use spindle_store::Store;

use crate::AppState;
use crate::accounts::{Account, Accounts, unguessable_password};
use crate::auth::Authenticated;
use crate::errors::MatrixError;

#[allow(clippy::too_many_lines, reason = "one row per route")]
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
            .route(
                &format!("{prefix}/users/{{user_id}}/password_hash"),
                post(set_password_hash),
            )
            .route(
                &format!("{prefix}/users/{{user_id}}/reset_link"),
                post(issue_reset_link),
            )
            .route(&format!("{prefix}/users/{{user_id}}/devices"), get(devices))
            .route(
                &format!("{prefix}/users/{{user_id}}/devices/{{device_id}}"),
                get(get_device).put(put_device).delete(delete_device),
            )
            .route(
                &format!("{prefix}/users/{{user_id}}/admin"),
                get(get_user_admin).put(put_user_admin),
            )
            .route(
                &format!("{prefix}/username_available"),
                get(username_available),
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
                &format!("{prefix}/rooms/{{room_id}}/block"),
                get(get_room_block).put(put_room_block),
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
            .route(&format!("{prefix}/event_reports"), get(list_event_reports))
            .route(
                &format!("{prefix}/event_reports/{{report_id}}"),
                get(get_event_report).delete(delete_event_report),
            )
            .route(&format!("{prefix}/audit"), get(audit_log))
            .route(
                &format!("{prefix}/registration_tokens"),
                get(list_registration_tokens),
            )
            .route(
                &format!("{prefix}/registration_tokens/new"),
                post(new_registration_token),
            )
            .route(
                &format!("{prefix}/registration_tokens/{{token}}"),
                get(get_registration_token)
                    .put(update_registration_token)
                    .delete(delete_registration_token),
            )
            .route(
                &format!("{prefix}/send_server_notice"),
                post(send_server_notice),
            )
            .route(
                &format!("{prefix}/rtc/sfu"),
                get(sfu_status).put(sfu_switch),
            )
    };
    group("/_spindle/admin/v1")
        .merge(group("/_synapse/admin/v1"))
        .merge(synapse_spellings())
}

/// The paths Synapse spells differently, so that the tooling written
/// against it -- synadm, the admin panels -- drives this server without
/// a patch. Same handlers; only the URL differs. Synapse's v2 user
/// endpoints are its current ones (v1's were retired), its `deactivate`,
/// `reset_password` and `purge_history` put the verb first and the target
/// second, and `delete_devices` takes a list where this API takes one
/// device per DELETE.
fn synapse_spellings() -> Router<AppState> {
    Router::new()
        .route(
            "/_synapse/admin/v1/register",
            get(shared_secret_nonce).post(shared_secret_register),
        )
        .route("/_synapse/admin/v2/users", get(list_users))
        .route(
            "/_synapse/admin/v2/users/{user_id}",
            get(get_user).put(put_user),
        )
        .route("/_synapse/admin/v2/users/{user_id}/devices", get(devices))
        .route(
            "/_synapse/admin/v2/users/{user_id}/devices/{device_id}",
            get(get_device).put(put_device).delete(delete_device),
        )
        .route(
            "/_synapse/admin/v2/users/{user_id}/delete_devices",
            post(delete_devices),
        )
        .route("/_synapse/admin/v1/deactivate/{user_id}", post(deactivate))
        .route(
            "/_synapse/admin/v1/reset_password/{user_id}",
            post(reset_password),
        )
        .route(
            "/_synapse/admin/v1/purge_history/{room_id}",
            post(purge_history),
        )
}

/// `GET /_synapse/admin/v1/register` — one short-lived registration nonce.
async fn shared_secret_nonce(State(state): State<AppState>) -> Result<Json<Value>, MatrixError> {
    shared_registration_secret(&state)?;
    Ok(Json(json!({ "nonce": state.registration_nonces.issue() })))
}

#[derive(Deserialize)]
struct SharedSecretRegistration {
    nonce: String,
    username: String,
    password: String,
    #[serde(default)]
    displayname: Option<String>,
    #[serde(default)]
    admin: bool,
    mac: String,
}

/// `POST /_synapse/admin/v1/register` — Synapse's shared-secret fixture API.
async fn shared_secret_register(
    State(state): State<AppState>,
    Json(request): Json<SharedSecretRegistration>,
) -> Result<Json<Value>, MatrixError> {
    let secret = shared_registration_secret(&state)?;
    // Spent before the MAC is judged. A failed guess does not leave a live
    // challenge to brute-force, and two concurrent requests cannot both win.
    if !state.registration_nonces.consume(&request.nonce) {
        return Err(MatrixError::forbidden(
            "the registration nonce is not valid",
        ));
    }
    let supplied = decode_hex(&request.mac)
        .ok_or_else(|| MatrixError::forbidden("the registration MAC is not valid"))?;
    let mut expected = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
        .map_err(|_| MatrixError::internal("the registration secret is not valid"))?;
    for (index, part) in [
        request.nonce.as_str(),
        request.username.as_str(),
        request.password.as_str(),
        if request.admin { "admin" } else { "notadmin" },
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            expected.update(&[0]);
        }
        expected.update(part.as_bytes());
    }
    expected
        .verify_slice(&supplied)
        .map_err(|_| MatrixError::forbidden("the registration MAC is not valid"))?;

    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .register(&request.username, &request.password)
        .map_err(|error| match error {
            crate::accounts::AccountError::UserInUse => MatrixError::user_in_use(),
            crate::accounts::AccountError::InvalidUsername => MatrixError::invalid_username(),
            other => MatrixError::internal(&other.to_string()),
        })?;
    if request.admin {
        accounts
            .set_admin(&request.username, true)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let user_id = accounts.user_id(&request.username);
    if let Some(displayname) = request.displayname {
        state
            .profiles
            .set(&user_id, Some(Some(displayname)), None)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let session = accounts
        .create_session(&request.username, None, None, false)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({
        "access_token": session.access_token,
        "user_id": user_id,
        "home_server": state.config.server.name,
        "device_id": session.device.device_id,
    })))
}

fn shared_registration_secret(state: &AppState) -> Result<&str, MatrixError> {
    state
        .config
        .registration
        .shared_secret
        .as_deref()
        // An empty secret is one anybody knows; treat it as no secret.
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "not found"))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from((high << 4) | low).ok()
        })
        .collect()
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
    /// capability -- [`crate::rooms::Rooms::admin`] asks for one as proof -- and a
    /// public field would let any handler in the crate mint that proof
    /// out of an ordinary identity (#311).
    #[must_use]
    pub fn identity(&self) -> &crate::accounts::Identity {
        &self.0
    }

    /// A second handle on the same proof, for work an admin request hands
    /// to a background task (`admin_tasks`). Only an existing proof can be
    /// duplicated, so this mints nothing a handler did not already hold.
    #[must_use]
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl FromRequestParts<AppState> for AdminActor {
    type Rejection = MatrixError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        let token = crate::auth::bearer(parts).ok_or_else(MatrixError::missing_token)?;
        if let Some(delegated) = &state.delegated
            && accounts
                .identify(&token)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .is_none()
            && state.appservices.by_token(&token).is_none()
        {
            let identity = delegated
                .identify_admin(state.store.as_ref(), &state.config.server.name, &token)
                .await?;
            let localpart = local_localpart(state, &identity.user_id)
                .ok_or_else(|| MatrixError::forbidden("only local accounts can be admins"))?;
            if accounts
                .account(&localpart)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .is_none_or(|account| account.deactivated || account.locked || account.suspended)
            {
                return Err(MatrixError::forbidden(
                    "account cannot administer the server",
                ));
            }
            return Ok(Self(identity));
        }
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
        "ts_ms": now_ms(),
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

/// File one event report and return its id.
///
/// Called from the client `/report` handler, which has already checked
/// the reporter may see the event; this only records. The id is a fresh
/// stream sequence number, so reports list in the order they were filed
/// and an operator can quote one without ambiguity.
pub(crate) fn file_event_report(
    state: &AppState,
    reporter: &str,
    room_id: &str,
    event_id: &str,
    sender: Option<&str>,
    reason: Option<&str>,
    score: Option<i64>,
) -> Result<u64, MatrixError> {
    file_report(
        state,
        reporter,
        Some(room_id),
        Some(event_id),
        sender,
        reason,
        score,
    )
}

/// File a report about an event, a room (spec v1.13) or a user (spec
/// v1.14): the same queue, with the parts the report is about filled in.
/// `sender` is the reported user: an event's sender, or the user
/// reported directly.
pub(crate) fn file_report(
    state: &AppState,
    reporter: &str,
    room_id: Option<&str>,
    event_id: Option<&str>,
    sender: Option<&str>,
    reason: Option<&str>,
    score: Option<i64>,
) -> Result<u64, MatrixError> {
    let seq = state.rooms.allocate_stream_id();
    let record = json!({
        "id": seq,
        "received_ts": now_ms(),
        "room_id": room_id,
        "event_id": event_id,
        "user_id": reporter,
        "sender": sender,
        "reason": reason,
        "score": score,
    });
    Store::put(
        state.store.as_ref(),
        &keys::event_report(seq),
        serde_json::to_vec(&record)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .as_slice(),
    )
    .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(seq)
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis()),
    )
    .unwrap_or(u64::MAX)
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

pub(crate) fn local_localpart(state: &AppState, user_id: &str) -> Option<String> {
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

/// One account in the shape of Synapse's user listing.
///
/// The fields Synapse reports that this server does not track are
/// present with the value that is true here: no guests, no shadow bans,
/// no user types, no consent tracking, every account approved. When an
/// account was created and when it was last seen are not recorded, and
/// are `null` rather than invented.
fn user_json(state: &AppState, account: &Account) -> Value {
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let user_id = accounts.user_id(&account.localpart);
    let profile = state.profiles.get(&user_id).unwrap_or_default();
    json!({
        "name": user_id,
        "user_type": null,
        "is_guest": false,
        "admin": account.admin,
        "deactivated": account.deactivated,
        "erased": account.erased,
        "shadow_banned": false,
        "displayname": profile.displayname,
        "avatar_url": profile.avatar_url,
        "creation_ts": null,
        "approved": true,
        "locked": account.locked,
        "suspended": account.suspended,
        "last_seen_ts": null,
    })
}

/// One account in the shape of Synapse's user detail: the listing's
/// fields, its email addresses as third-party IDs, and the fields this
/// server has no counterpart for.
fn user_detail_json(state: &AppState, account: &Account) -> Value {
    let mut user = user_json(state, account);
    let threepids: Vec<Value> = crate::email::addresses_of(state, &account.localpart)
        .unwrap_or_default()
        .into_iter()
        .map(|(address, added_at)| {
            json!({
                "medium": "email",
                "address": address,
                "added_at": added_at,
                "validated_at": added_at,
            })
        })
        .collect();
    user["threepids"] = json!(threepids);
    user["external_ids"] = json!([]);
    user["appservice_id"] = Value::Null;
    user["consent_server_notice_sent"] = Value::Null;
    user["consent_version"] = Value::Null;
    user["consent_ts"] = Value::Null;
    user
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
    actor: Option<String>,
    action: Option<String>,
}

#[derive(Deserialize)]
struct UsersQuery {
    from: Option<String>,
    limit: Option<i64>,
    user_id: Option<String>,
    name: Option<String>,
    /// Accepted for Synapse's callers. There are no guest accounts, so
    /// including or excluding them changes nothing.
    #[allow(dead_code, reason = "accepted and ignored, as documented")]
    guests: Option<bool>,
    admins: Option<bool>,
    deactivated: Option<bool>,
    locked: Option<bool>,
    suspended: Option<bool>,
    order_by: Option<String>,
    dir: Option<String>,
}

/// `GET /users` — Synapse's v2 listing.
///
/// `user_id` matches part of the user ID; `name` matches part of the user
/// ID or the display name, either case-insensitively. `deactivated`,
/// `admins`, `locked` and `suspended` narrow to accounts with or without
/// the flag. `guests=true` adds nothing, since there are no guests.
/// `from` is an offset, and `next_token` the next one, as a string.
async fn list_users(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<UsersQuery>,
) -> Result<Json<Value>, MatrixError> {
    let from = match query.from.as_deref() {
        None => 0,
        Some(from) => from.parse::<usize>().map_err(|_| {
            invalid_param("Query parameter from must be a string representing a positive integer.")
        })?,
    };
    let limit = usize::try_from(query.limit.unwrap_or(100))
        .map_err(|_| invalid_param("Query parameter limit must be a positive integer."))?;
    let order_by = query.order_by.as_deref().unwrap_or("name");
    if !matches!(
        order_by,
        "name"
            | "is_guest"
            | "admin"
            | "user_type"
            | "deactivated"
            | "shadow_banned"
            | "displayname"
            | "avatar_url"
            | "creation_ts"
            | "last_seen_ts"
            | "locked"
            | "suspended"
            | "approved"
    ) {
        return Err(invalid_param(format!(
            "Unknown value for order_by: {order_by}"
        )));
    }
    let ascending = match query.dir.as_deref().unwrap_or("f") {
        "f" => true,
        "b" => false,
        other => return Err(invalid_param(format!("Unknown direction: {other}"))),
    };
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let all = accounts
        .all_accounts()
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let user_needle = query.user_id.as_deref().map(str::to_lowercase);
    let name_needle = query.name.as_deref().map(str::to_lowercase);
    let mut users: Vec<Value> = all
        .iter()
        .filter(|account| {
            query
                .deactivated
                .is_none_or(|wanted| account.deactivated == wanted)
                && query.admins.is_none_or(|wanted| account.admin == wanted)
                && query.locked.is_none_or(|wanted| account.locked == wanted)
                && query
                    .suspended
                    .is_none_or(|wanted| account.suspended == wanted)
        })
        .map(|account| user_json(&state, account))
        .filter(|user| {
            let id = user["name"].as_str().unwrap_or_default().to_lowercase();
            let displayname = user["displayname"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            user_needle
                .as_deref()
                .is_none_or(|needle| id.contains(needle))
                && name_needle
                    .as_deref()
                    .is_none_or(|needle| id.contains(needle) || displayname.contains(needle))
        })
        .collect();
    users.sort_by(|a, b| {
        let order = compare_field(&a[order_by], &b[order_by])
            .then_with(|| compare_field(&a["name"], &b["name"]));
        if ascending { order } else { order.reverse() }
    });
    let total = users.len();
    let page: Vec<Value> = users.into_iter().skip(from).take(limit).collect();
    let mut body = json!({ "users": page, "total": total });
    if from + limit < total && limit > 0 {
        body["next_token"] = json!((from + limit).to_string());
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
    Ok(Json(user_detail_json(&state, &account)))
}

#[derive(Deserialize)]
struct PutUser {
    displayname: Option<String>,
    avatar_url: Option<String>,
    admin: Option<bool>,
    deactivated: Option<bool>,
    locked: Option<bool>,
    password: Option<String>,
    /// Synapse signs the user out everywhere when an administrator sets
    /// their password, unless told not to.
    logout_devices: Option<bool>,
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
        if request.logout_devices.unwrap_or(true) {
            accounts
                .logout_everywhere(&localpart)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
        }
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
    if let Some(locked) = request.locked {
        accounts
            .set_locked(&localpart, locked)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    if request.displayname.is_some() || request.avatar_url.is_some() {
        state
            .profiles
            .set(
                &accounts.user_id(&localpart),
                request.displayname.clone().map(Some),
                request.avatar_url.clone().map(Some),
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
            "locked": request.locked,
            "displayname": request.displayname,
            "avatar_url": request.avatar_url,
        }),
    )?;
    let (_, account) = target_account(&state, &user_id)?;
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(user_detail_json(&state, &account))))
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

#[derive(Deserialize)]
struct SetPasswordHash {
    password_hash: String,
    /// Off by default, unlike `reset_password`: importing the hash a user
    /// already signs in with elsewhere changes nothing they know, and
    /// signing every migrated user out would be the migration's only
    /// visible effect.
    #[serde(default)]
    logout_devices: bool,
}

/// `POST /users/{userId}/password_hash` (#611)
///
/// Store an Argon2 PHC hash computed elsewhere — a Matrix Authentication
/// Service's `user_passwords.hashed_password`, typically — so its user
/// signs in here with the password they already have. The hash is
/// validated (`accounts::validate_password_hash`) and refused with
/// `M_INVALID_PARAM` when it cannot verify. Works while authentication is
/// still delegated, which is the point: hashes land before the cutover.
/// Neither the hash nor any part of it reaches the audit log.
async fn set_password_hash(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    Json(request): Json<SetPasswordHash>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .set_password_hash(&localpart, &request.password_hash)
        .map_err(|error| match error {
            crate::accounts::AccountError::InvalidHash(why) => {
                MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", why)
            }
            other => MatrixError::internal(&other.to_string()),
        })?;
    if request.logout_devices {
        accounts
            .logout_everywhere(&localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    let algorithm = request
        .password_hash
        .split('$')
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    audit(
        &state,
        &actor.identity().user_id,
        "set_password_hash",
        &user_id,
        &json!({ "algorithm": algorithm, "logout_devices": request.logout_devices }),
    )?;
    Ok(Json(json!({})))
}

#[derive(Default, Deserialize)]
struct ResetLinkRequest {
    /// How long the link works, as `24h`, `30m`, `2d` or seconds; a day
    /// when absent, a week at most.
    ttl: Option<String>,
}

/// `POST /users/{userId}/reset_link` — a password-reset link for a user
/// who cannot sign in, issued by an administrator rather than mailed: the
/// recovery path for a server without SMTP. The URL is in the response
/// and nowhere else — it is the only time the token exists in clear — and
/// opens the same page a mailed link does, which signs every device out.
/// Single-use, expiring, newest-only. The audit log records the issuance
/// and its lifetime, never the token.
async fn issue_reset_link(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    body: Option<Json<ResetLinkRequest>>,
) -> Result<Json<Value>, MatrixError> {
    if state.oidc.is_none() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "reset links open the built-in provider's pages, and it is not enabled",
        ));
    }
    let (localpart, _) = target_account(&state, &user_id)?;
    let request = body.map(|Json(request)| request).unwrap_or_default();
    let ttl_ms = match request.ttl.as_deref() {
        Some(text) => crate::email::parse_ttl(text)
            .map_err(|why| MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", why))?,
        None => crate::email::DEFAULT_RESET_LINK_TTL_MS,
    };
    let (url, expires_at_ms) =
        crate::email::issue_reset_link(state.store.as_ref(), &state.config, &localpart, ttl_ms)
            .map_err(|why| MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", why))?;
    state.metrics.record_reset_link_issued();
    audit(
        &state,
        &actor.identity().user_id,
        "issue_reset_link",
        &user_id,
        &json!({ "ttl_ms": ttl_ms }),
    )?;
    Ok(Json(
        json!({ "reset_url": url, "expires_at_ms": expires_at_ms }),
    ))
}

/// `GET /users/{userId}/devices`
async fn devices(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let user_id = accounts.user_id(&localpart);
    let devices: Vec<Value> = accounts
        .devices_of(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .iter()
        .map(|device| device_json(&user_id, device))
        .collect();
    Ok(Json(json!({ "total": devices.len(), "devices": devices })))
}

/// One device in Synapse's shape. Where and when a device was last seen
/// is not recorded here, so those fields are `null`, as Synapse reports a
/// device it has never seen.
fn device_json(user_id: &str, device: &crate::accounts::Device) -> Value {
    json!({
        "device_id": device.device_id,
        "display_name": device.display_name,
        "last_seen_ip": null,
        "last_seen_ts": null,
        "last_seen_user_agent": null,
        "user_id": user_id,
        "dehydrated": false,
    })
}

fn target_device(
    state: &AppState,
    user_id: &str,
    device_id: &str,
) -> Result<(String, crate::accounts::Device), MatrixError> {
    let (localpart, _) = target_account(state, user_id)?;
    let device = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .device(&localpart, device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No device found"))?;
    Ok((localpart, device))
}

/// `GET /users/{userId}/devices/{deviceId}`
async fn get_device(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path((user_id, device_id)): Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, device) = target_device(&state, &user_id, &device_id)?;
    let user_id =
        Accounts::new(state.store.as_ref(), &state.config.server.name).user_id(&localpart);
    Ok(Json(device_json(&user_id, &device)))
}

#[derive(Deserialize)]
struct PutDevice {
    display_name: Option<String>,
}

/// `PUT /users/{userId}/devices/{deviceId}` — `{display_name}`.
async fn put_device(
    State(state): State<AppState>,
    actor: AdminActor,
    Path((user_id, device_id)): Path<(String, String)>,
    Json(request): Json<PutDevice>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_device(&state, &user_id, &device_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    accounts
        .put_device(&localpart, &device_id, request.display_name.clone())
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    crate::mas::device_list_changed(&state, &accounts.user_id(&localpart));
    audit(
        &state,
        &actor.identity().user_id,
        "rename_device",
        &user_id,
        &json!({ "device_id": device_id, "display_name": request.display_name }),
    )?;
    Ok(Json(json!({})))
}

/// `GET /users/{userId}/admin` — `{admin}`.
async fn get_user_admin(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let (_, account) = target_account(&state, &user_id)?;
    Ok(Json(json!({ "admin": account.admin })))
}

#[derive(Deserialize)]
struct SetAdmin {
    admin: bool,
}

/// `PUT /users/{userId}/admin` — `{admin}`. As in Synapse, an admin
/// cannot take their own admin flag away: the last admin doing so by
/// mistake leaves nobody able to give it back.
async fn put_user_admin(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    Json(request): Json<SetAdmin>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    if !request.admin && actor.identity().user_id == user_id {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "You may not demote yourself.",
        ));
    }
    Accounts::new(state.store.as_ref(), &state.config.server.name)
        .set_admin(&localpart, request.admin)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    audit(
        &state,
        &actor.identity().user_id,
        "set_admin",
        &user_id,
        &json!({ "admin": request.admin }),
    )?;
    Ok(Json(json!({})))
}

/// `GET /rtc/sfu` — the SFU program's status: the switch, the model, the
/// minter's address, the supervised child's health. Same document `spindle
/// sfu status` prints, from the same function, so the two never disagree.
async fn sfu_status(
    State(state): State<AppState>,
    _actor: AdminActor,
) -> Result<Json<Value>, MatrixError> {
    Ok(Json(crate::livekit::status_json(
        &state.config,
        &state.store,
        &state.sfu,
    )))
}

#[derive(Deserialize)]
struct SfuSwitch {
    enabled: bool,
}

/// `PUT /rtc/sfu` — `{enabled}`. The runtime switch: stored server-side,
/// surviving restarts, never rewriting the operator's config file. Turning
/// off stops the supervised child and silences every minter path to
/// `M_UNRECOGNIZED`; turning on starts the child again on the next tick.
async fn sfu_switch(
    State(state): State<AppState>,
    actor: AdminActor,
    Json(request): Json<SfuSwitch>,
) -> Result<Json<Value>, MatrixError> {
    if request.enabled && state.config.rtc.livekit.is_none() {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "the LiveKit SFU program is not configured — set [rtc.livekit] first",
        ));
    }
    crate::livekit::set_switch(&state.store, request.enabled)
        .map_err(|error| MatrixError::internal(&error))?;
    if request.enabled {
        state.sfu.tick();
    } else {
        state.sfu.stop();
    }
    audit(
        &state,
        &actor.identity().user_id,
        "sfu_switch",
        "rtc/sfu",
        &json!({ "enabled": request.enabled }),
    )?;
    Ok(Json(crate::livekit::status_json(
        &state.config,
        &state.store,
        &state.sfu,
    )))
}

#[derive(Deserialize)]
struct UsernameQuery {
    username: String,
}

/// `GET /username_available?username=` — `{available: true}`, or a 400
/// `M_USER_IN_USE` / `M_INVALID_USERNAME`, as Synapse answers.
async fn username_available(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<UsernameQuery>,
) -> Result<Json<Value>, MatrixError> {
    let localpart = query.username.to_lowercase();
    if localpart.is_empty()
        || !localpart.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._=-/+".contains(&byte)
        })
    {
        return Err(MatrixError::invalid_username());
    }
    let taken = Accounts::new(state.store.as_ref(), &state.config.server.name)
        .account(&localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if taken {
        return Err(MatrixError::user_in_use());
    }
    Ok(Json(json!({ "available": true })))
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

#[derive(Deserialize)]
struct DeleteDevices {
    #[serde(default)]
    devices: Vec<String>,
}

/// `POST /_synapse/admin/v2/users/{userId}/delete_devices`, Synapse's
/// list form of the DELETE above: one audit record per device, as if each
/// had been deleted on its own, so the log reads the same either way.
async fn delete_devices(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(user_id): Path<String>,
    Json(request): Json<DeleteDevices>,
) -> Result<Json<Value>, MatrixError> {
    let (localpart, _) = target_account(&state, &user_id)?;
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    for device_id in &request.devices {
        crate::mas::remove_device(&state, &accounts, &localpart, device_id)?;
        audit(
            &state,
            &actor.identity().user_id,
            "delete_device",
            &user_id,
            &json!({ "device_id": device_id }),
        )?;
    }
    if !request.devices.is_empty() {
        crate::mas::device_list_changed(&state, &accounts.user_id(&localpart));
    }
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

/// One room as Synapse's admin room listing describes it.
///
/// Everything here is read from the room's current state and metadata —
/// nothing is cached or estimated, because an operator acting on this
/// view (blocking, purging) needs it to be the room, not a summary of
/// last week's room. Each field is one state lookup, not a read of the
/// whole state: a listing reads every room, and some rooms' state runs
/// to tens of thousands of events.
///
/// `public` is Synapse's: whether the room is in this server's room
/// directory, not whether its join rule is public.
fn room_json(
    state: &AppState,
    actor: &AdminActor,
    room_id: &str,
) -> Result<Value, crate::rooms::RoomError> {
    let joined = state.rooms.joined_member_ids(room_id)?;
    let content = |event_type: &str, field: &str| -> Value {
        state
            .rooms
            .admin(actor)
            .state_event(room_id, event_type, "")
            .map_or(Value::Null, |content| content[field].clone())
    };
    let create = state
        .rooms
        .state_event_full(room_id, "m.room.create", "")
        .ok();
    let local_suffix = format!(":{}", state.config.server.name);
    let joined_local = joined
        .iter()
        .filter(|user| user.ends_with(&local_suffix))
        .count();
    let public = state.directory.is_published(room_id).unwrap_or(false);
    let string_or_null = |value: Value| {
        if value.is_string() {
            value
        } else {
            Value::Null
        }
    };
    Ok(json!({
        "room_id": room_id,
        "name": string_or_null(content("m.room.name", "name")),
        "canonical_alias": string_or_null(content("m.room.canonical_alias", "alias")),
        "joined_members": joined.len(),
        "joined_local_members": joined_local,
        // The spec's default when m.room.create names no version.
        "version": create
            .as_ref()
            .and_then(|event| event["content"]["room_version"].as_str())
            .unwrap_or("1"),
        "creator": create
            .as_ref()
            .and_then(|event| event["content"]["creator"].as_str().or_else(|| event["sender"].as_str()))
            .unwrap_or_default(),
        "encryption": string_or_null(content("m.room.encryption", "algorithm")),
        "federatable": create
            .as_ref()
            .is_none_or(|event| event["content"]["m.federate"] != false),
        "public": public,
        "join_rules": string_or_null(content("m.room.join_rules", "join_rule")),
        "guest_access": string_or_null(content("m.room.guest_access", "guest_access")),
        "history_visibility": string_or_null(content("m.room.history_visibility", "history_visibility")),
        "state_events": state.rooms.admin(actor).state_entry_count(room_id)?,
        "room_type": create
            .as_ref()
            .map_or(Value::Null, |event| string_or_null(event["content"]["type"].clone())),
    }))
}

/// The room as Synapse's room detail describes it: the listing's fields,
/// and the topic, avatar, local device count and whether every local
/// member has forgotten it.
fn room_detail_json(
    state: &AppState,
    actor: &AdminActor,
    room_id: &str,
) -> Result<Value, crate::rooms::RoomError> {
    let mut room = room_json(state, actor, room_id)?;
    let content = |event_type: &str, field: &str| -> Value {
        state
            .rooms
            .admin(actor)
            .state_event(room_id, event_type, "")
            .ok()
            .map(|content| content[field].clone())
            .filter(Value::is_string)
            .unwrap_or(Value::Null)
    };
    room["topic"] = content("m.room.topic", "topic");
    room["avatar"] = content("m.room.avatar", "url");
    let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
    let joined = state.rooms.joined_member_ids(room_id)?;
    let devices: usize = joined
        .iter()
        .filter_map(|user| local_localpart(state, user))
        .map(|localpart| {
            accounts
                .devices_of(&localpart)
                .map_or(0, |devices| devices.len())
        })
        .sum();
    room["joined_local_devices"] = json!(devices);
    // Synapse: true once every local user who was ever in the room has
    // forgotten it. Nobody local still joined is the cheap first test;
    // only then are the room's member events read.
    let forgotten = room["joined_local_members"] == 0 && {
        let local_suffix = format!(":{}", state.config.server.name);
        let locals: Vec<String> = state
            .rooms
            .state(room_id)?
            .iter()
            .filter(|event| event["type"] == "m.room.member")
            .filter_map(|event| event["state_key"].as_str())
            .filter(|user| user.ends_with(&local_suffix))
            .map(str::to_owned)
            .collect();
        !locals.is_empty()
            && locals
                .iter()
                .all(|user| state.rooms.is_forgotten(user, room_id).unwrap_or(false))
    };
    room["forgotten"] = json!(forgotten);
    Ok(room)
}

#[derive(Deserialize)]
struct RoomsQuery {
    from: Option<i64>,
    limit: Option<i64>,
    order_by: Option<String>,
    dir: Option<String>,
    search_term: Option<String>,
    public_rooms: Option<bool>,
    empty_rooms: Option<bool>,
}

fn invalid_param(message: impl Into<String>) -> MatrixError {
    MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
}

/// Synapse's alias search, `LOWER(canonical_alias) LIKE '#%term%:%'`: the
/// term must fall in the alias's localpart, before a `:`. A search for a
/// server name therefore does not match every alias on that server.
fn alias_matches(alias: &str, needle: &str) -> bool {
    alias
        .to_lowercase()
        .strip_prefix('#')
        .and_then(|rest| {
            rest.find(needle)
                .map(|at| rest[at + needle.len()..].contains(':'))
        })
        .unwrap_or(false)
}

/// Synapse's room orderings: the field each sorts on, and whether it
/// sorts ascending before `dir=b` flips it.
///
/// These are Synapse's defaults (`get_rooms_paginate`): the counts and the
/// room version sort descending by default, so `dir=b` lists the
/// *smallest* rooms first, and the text columns sort ascending, so
/// `name&dir=b` puts unnamed rooms first, as `PostgreSQL` does with `NULL`
/// in a descending sort. Text compares byte by byte, as under the `C`
/// collation Synapse requires, so the room version `"6"` sorts above
/// `"12"`. Element Admin sends no `order_by`, and gets `name` ascending.
fn room_order(order_by: &str) -> Option<(&'static str, bool)> {
    Some(match order_by {
        "name" | "alphabetical" => ("name", true),
        "size" | "joined_members" => ("joined_members", false),
        "joined_local_members" => ("joined_local_members", false),
        "version" => ("version", false),
        "state_events" => ("state_events", false),
        "canonical_alias" => ("canonical_alias", true),
        "creator" => ("creator", true),
        "encryption" => ("encryption", true),
        "federatable" => ("federatable", true),
        "public" => ("public", true),
        "join_rules" => ("join_rules", true),
        "guest_access" => ("guest_access", true),
        "history_visibility" => ("history_visibility", true),
        _ => return None,
    })
}

/// Compare two JSON values of one room field. A null sorts after every
/// value, as `PostgreSQL` sorts `NULL` ascending, so it comes last ascending
/// and first descending.
fn compare_field(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Greater,
        (_, Value::Null) => Ordering::Less,
        (Value::Number(a), Value::Number(b)) => a
            .as_u64()
            .unwrap_or_default()
            .cmp(&b.as_u64().unwrap_or_default()),
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        (Value::String(a), Value::String(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

/// `GET /rooms?from&limit&order_by&dir&search_term&public_rooms&empty_rooms`
///
/// Synapse's room listing, field for field: `search_term` matches a
/// room's name or canonical alias case-insensitively, or its ID exactly;
/// `public_rooms` filters on the directory; `empty_rooms` on whether
/// anyone is joined. `from` is an offset, and the page carries
/// `offset`, `total_rooms`, and `next_batch`/`prev_batch` offsets.
async fn list_rooms(
    State(state): State<AppState>,
    actor: AdminActor,
    Query(query): Query<RoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let from = usize::try_from(query.from.unwrap_or(0))
        .map_err(|_| invalid_param("Query parameter from must be a non-negative integer."))?;
    let limit = usize::try_from(query.limit.unwrap_or(100))
        .map_err(|_| invalid_param("Query parameter limit must be a non-negative integer."))?;
    let order_by = query.order_by.as_deref().unwrap_or("name");
    let (field, ascending) = room_order(order_by)
        .ok_or_else(|| invalid_param(format!("Unknown value for order_by: {order_by}")))?;
    let ascending = match query.dir.as_deref().unwrap_or("f") {
        "f" => ascending,
        "b" => !ascending,
        other => return Err(invalid_param(format!("Unknown direction: {other}"))),
    };
    let needle = query.search_term.as_deref().map(str::to_lowercase);

    let mut rooms = Vec::new();
    for room_id in state
        .rooms
        .admin(&actor)
        .all_room_ids()
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        let room = match room_json(&state, &actor, &room_id) {
            Ok(room) => room,
            // A room whose metadata row outlived its log is not a room
            // anyone can act on; one bad room must not blank the list.
            Err(crate::rooms::RoomError::UnknownRoom(_)) => continue,
            Err(error) => return Err(crate::routes::room_error(error)),
        };
        let matches = needle.as_deref().is_none_or(|needle| {
            room_id == query.search_term.as_deref().unwrap_or_default()
                || room["name"]
                    .as_str()
                    .is_some_and(|name| name.to_lowercase().contains(needle))
                || room["canonical_alias"]
                    .as_str()
                    .is_some_and(|alias| alias_matches(alias, needle))
        }) && query
            .public_rooms
            .is_none_or(|public| room["public"] == public)
            && query
                .empty_rooms
                .is_none_or(|empty| (room["joined_members"] == 0) == empty);
        if matches {
            rooms.push(room);
        }
    }
    rooms.sort_by(|a, b| {
        let order = compare_field(&a[field], &b[field])
            .then_with(|| compare_field(&a["room_id"], &b["room_id"]));
        if ascending { order } else { order.reverse() }
    });
    let total = rooms.len();
    let page: Vec<Value> = rooms.into_iter().skip(from).take(limit).collect();
    let mut body = json!({ "rooms": page, "offset": from, "total_rooms": total });
    if from + limit < total {
        body["next_batch"] = json!(from + limit);
    }
    if from > 0 {
        body["prev_batch"] = json!(from.saturating_sub(limit));
    }
    Ok(Json(body))
}

/// `GET /rooms/{roomId}`
async fn room_detail(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room = room_detail_json(&state, &actor, &room_id).map_err(crate::routes::room_error)?;
    Ok(Json(room))
}

/// `GET /rooms/{roomId}/members`
async fn room_members(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    // The IDs alone: rendering every member's profile to throw it away
    // is most of the cost of a large room.
    let members = state
        .rooms
        .joined_member_ids(&room_id)
        .map_err(crate::routes::room_error)?;
    Ok(Json(
        json!({ "total": members.len(), "members": members.as_slice() }),
    ))
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

/// The body of Synapse's room deletion, v1 and v2 alike.
#[derive(Clone, Deserialize)]
pub(crate) struct DeleteRoom {
    #[serde(default)]
    pub(crate) block: bool,
    /// Synapse's default is to purge; a caller that wants the history
    /// kept says `"purge": false`.
    #[serde(default = "purge_by_default")]
    pub(crate) purge: bool,
    pub(crate) new_room_user_id: Option<String>,
    pub(crate) room_name: Option<String>,
    pub(crate) message: Option<String>,
    /// Accepted for Synapse's callers. This server's purge keeps the
    /// spine and needs no members gone first, so there is nothing to
    /// force.
    #[serde(default)]
    #[allow(dead_code, reason = "accepted and ignored, as documented")]
    pub(crate) force_purge: bool,
}

const fn purge_by_default() -> bool {
    true
}

/// A fresh room owned by `creator` with nothing in it yet: no topic, no
/// preset, and no profile on the creator's join, since an
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
            &[],
            None,
            None,
            None,
            &serde_json::Map::new(),
        )
        .map_err(crate::routes::room_error)
}

/// Check what can be checked before a deletion starts, so the v2 endpoint
/// refuses a bad request rather than scheduling a task that will fail.
pub(crate) fn validate_delete(state: &AppState, request: &DeleteRoom) -> Result<(), MatrixError> {
    if let Some(creator) = &request.new_room_user_id
        && local_localpart(state, creator).is_none()
    {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "new_room_user_id must be a user of this server",
        ));
    }
    Ok(())
}

/// Delete a room as Synapse's `DELETE /rooms/{roomId}` does: block it if
/// asked, take its local aliases out of the directory, evict every local
/// member, optionally open a replacement room, and purge.
///
/// Every departure is a real leave event through the ordinary append
/// path (#83 §2) — the log records the eviction the same way it records
/// any other membership change, so a peer replaying it computes the
/// same room. The block row is written first so nobody rejoins between
/// the eviction and the block; `purge` reuses `purge_history` over the
/// whole log, so the spine and the chain survive even total deletion.
///
/// A room this server does not hold can still be blocked, so a room
/// can be refused before anyone here joins it; anything else about an
/// unknown room is a 404. Returns Synapse's `shutdown_room` result.
#[allow(
    clippy::too_many_lines,
    reason = "one sequence, in the order Synapse performs it"
)]
pub(crate) fn shutdown_room(
    state: &AppState,
    actor: &AdminActor,
    room_id: &str,
    request: &DeleteRoom,
) -> Result<Value, MatrixError> {
    validate_delete(state, request)?;
    let members = match state.rooms.joined_members(room_id) {
        Ok(members) => Some(members),
        Err(crate::rooms::RoomError::UnknownRoom(_)) if request.block => None,
        Err(error) => return Err(crate::routes::room_error(error)),
    };
    let local_suffix = format!(":{}", state.config.server.name);
    let locals: Vec<String> = members
        .as_ref()
        .map(|members| {
            members
                .keys()
                .filter(|user| user.ends_with(&local_suffix))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if request.block {
        state
            .rooms
            .admin(actor)
            .set_room_block(room_id, &json!({ "actor": actor.identity().user_id }))
            .map_err(crate::routes::room_error)?;
    }
    let Some(_) = members else {
        return Ok(json!({
            "kicked_users": [],
            "failed_to_kick_users": [],
            "local_aliases": [],
            "new_room_id": null,
        }));
    };

    // The room leaves this server's directory, and its aliases stop
    // resolving to it: Synapse moves them to the replacement room when
    // there is one, and so does this.
    let local_aliases = state
        .directory
        .for_room(room_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    for alias in &local_aliases {
        Store::delete(state.store.as_ref(), &keys::alias(alias))
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    state
        .directory
        .unpublish(room_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;

    // The replacement room, when asked for: created by the named local
    // user, opening with the administrator's message, every evicted
    // local user invited into it.
    let new_room = match &request.new_room_user_id {
        Some(creator) => {
            let new_room = bare_room(state, creator)?;
            let name = request
                .room_name
                .as_deref()
                .unwrap_or("Content Violation Notification");
            state
                .rooms
                .set_state(
                    &new_room,
                    creator,
                    state.key.pair(),
                    "m.room.name",
                    "",
                    &json!({ "name": name }),
                )
                .map_err(crate::routes::room_error)?;
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
            for alias in &local_aliases {
                // Best-effort, as the invites below are: an alias the
                // new room cannot take must not stop the deletion.
                let _ = state.directory.create(alias, &new_room, creator);
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
            room_id,
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
            .admin(actor)
            .purge_history(room_id, i64::MAX)
            .map_err(crate::routes::room_error)?;
    }

    audit(
        state,
        &actor.identity().user_id,
        "delete_room",
        room_id,
        &json!({
            "block": request.block,
            "purge": request.purge,
            "kicked": kicked.len(),
            "new_room_id": new_room,
            "local_aliases": local_aliases,
        }),
    )?;
    Ok(json!({
        "kicked_users": kicked,
        "failed_to_kick_users": failed,
        "local_aliases": local_aliases,
        "new_room_id": new_room,
    }))
}

/// `DELETE /rooms/{roomId}` — `{block, purge, new_room_user_id, room_name,
/// message}`, synchronously: Synapse's v1. The v2 spelling, which runs the
/// same deletion as a background task, is in `admin_tasks`.
async fn delete_room(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<DeleteRoom>,
) -> Result<Json<Value>, MatrixError> {
    shutdown_room(&state, &actor, &room_id, &request).map(Json)
}

/// `GET /rooms/{roomId}/block` — `{block, user_id}` when blocked, and
/// `{block: false}` otherwise. Answers for a room this server does not
/// hold, since a room can be blocked before anyone here joins it.
async fn get_room_block(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    legal_room_id(&room_id)?;
    let block = state
        .rooms
        .room_block(&room_id)
        .map_err(crate::routes::room_error)?;
    Ok(Json(match block {
        Some(record) => json!({ "block": true, "user_id": record["actor"] }),
        None => json!({ "block": false }),
    }))
}

#[derive(Deserialize)]
struct BlockRequest {
    block: bool,
}

/// `PUT /rooms/{roomId}/block` — `{block}`. Blocking stops local users
/// joining; it evicts nobody (that is what deleting the room does).
async fn put_room_block(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(room_id): Path<String>,
    Json(request): Json<BlockRequest>,
) -> Result<Json<Value>, MatrixError> {
    legal_room_id(&room_id)?;
    let admin = state.rooms.admin(&actor);
    if request.block {
        admin
            .set_room_block(&room_id, &json!({ "actor": actor.identity().user_id }))
            .map_err(crate::routes::room_error)?;
    } else {
        admin
            .clear_room_block(&room_id)
            .map_err(crate::routes::room_error)?;
    }
    audit(
        &state,
        &actor.identity().user_id,
        if request.block {
            "block_room"
        } else {
            "unblock_room"
        },
        &room_id,
        &json!({}),
    )?;
    Ok(Json(json!({ "block": request.block })))
}

fn legal_room_id(room_id: &str) -> Result<(), MatrixError> {
    if room_id.starts_with('!') && room_id.contains(':') {
        Ok(())
    } else {
        Err(invalid_param(format!("{room_id} is not a legal room ID")))
    }
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
    // Room versions before 10 allow a level written as a string.
    let parse = crate::rooms::power_level;
    let users_default = parse(&levels["users_default"]).unwrap_or(0);
    let level_of = |user: &str| -> i64 { parse(&levels["users"][user]).unwrap_or(users_default) };
    let required = parse(&levels["events"]["m.room.power_levels"])
        .or_else(|| parse(&levels["state_default"]))
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

/// The room's current name and canonical alias, as Synapse's report
/// listing carries them: read at listing time, so a renamed room shows
/// its present name, and null rather than an error for a room that has
/// neither or is gone.
fn report_room_labels(state: &AppState, actor: &AdminActor, record: &mut Value) {
    let Some(room_id) = record["room_id"].as_str().map(str::to_owned) else {
        return;
    };
    let admin = state.rooms.admin(actor);
    let content = |event_type: &str, field: &str| -> Value {
        admin
            .state_event(&room_id, event_type, "")
            .map_or(Value::Null, |content| content[field].clone())
    };
    record["name"] = content("m.room.name", "name");
    record["canonical_alias"] = content("m.room.canonical_alias", "alias");
}

#[derive(Deserialize)]
struct ReportsQuery {
    from: Option<i64>,
    limit: Option<i64>,
    dir: Option<String>,
    room_id: Option<String>,
    user_id: Option<String>,
    event_sender_user_id: Option<String>,
}

/// `GET /event_reports?from&limit&dir&room_id&user_id&event_sender_user_id`
///
/// Newest first by default, as Synapse lists them: the report an operator
/// has not yet seen is the one filed most recently. `dir=f` is oldest
/// first. `user_id` matches part of the reporter's ID; `room_id` part of
/// the room's; `event_sender_user_id` is the reported user, exactly.
/// `next_token` is an integer offset, as Synapse's is.
async fn list_event_reports(
    State(state): State<AppState>,
    actor: AdminActor,
    Query(query): Query<ReportsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let from = usize::try_from(query.from.unwrap_or(0))
        .map_err(|_| invalid_param("The start parameter must be a positive integer."))?;
    let limit = usize::try_from(query.limit.unwrap_or(100))
        .map_err(|_| invalid_param("The limit parameter must be a positive integer."))?;
    let newest_first = match query.dir.as_deref().unwrap_or("b") {
        "b" => true,
        "f" => false,
        other => return Err(invalid_param(format!("Unknown direction: {other}"))),
    };
    let mut reports = Vec::new();
    for (_, raw) in
        spindle_store::ReadView::scan_prefix(state.store.as_ref(), &keys::event_reports_prefix())
            .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        let record: Value = serde_json::from_slice(&raw)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        let contains = |field: &str, wanted: Option<&String>| {
            wanted.is_none_or(|wanted| {
                record[field]
                    .as_str()
                    .is_some_and(|value| value.contains(wanted.as_str()))
            })
        };
        if contains("room_id", query.room_id.as_ref())
            && contains("user_id", query.user_id.as_ref())
            && query
                .event_sender_user_id
                .as_deref()
                .is_none_or(|sender| record["sender"] == sender)
        {
            reports.push(record);
        }
    }
    if newest_first {
        reports.reverse();
    }
    let total = reports.len();
    let page: Vec<Value> = reports
        .into_iter()
        .skip(from)
        .take(limit)
        .map(|mut record| {
            report_room_labels(&state, &actor, &mut record);
            record
        })
        .collect();
    let mut body = json!({ "event_reports": page, "total": total });
    if from + limit < total && limit > 0 {
        body["next_token"] = json!(from + limit);
    }
    Ok(Json(body))
}

/// `DELETE /event_reports/{reportId}` — the report is dealt with.
async fn delete_event_report(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(report_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let not_found = || {
        MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Event report not found",
        )
    };
    let seq: u64 = report_id.parse().map_err(|_| {
        invalid_param("The report_id parameter must be a string representing a positive integer.")
    })?;
    let key = keys::event_report(seq);
    spindle_store::ReadView::get(state.store.as_ref(), &key)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(not_found)?;
    Store::delete(state.store.as_ref(), &key)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    audit(
        &state,
        &actor.identity().user_id,
        "delete_event_report",
        &report_id,
        &json!({}),
    )?;
    Ok(Json(json!({})))
}

/// `GET /event_reports/{reportId}`
///
/// The report with the reported event itself under `event_json`, so the
/// operator reads what was reported without a second round trip. The
/// event is read through the operator's view rather than the reporter's:
/// the report is the reason it is being looked at. If the event has been
/// purged since, `event_json` is null and the report still stands.
async fn get_event_report(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(report_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let not_found = || MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such report");
    let seq: u64 = report_id.parse().map_err(|_| not_found())?;
    let raw = spindle_store::ReadView::get(state.store.as_ref(), &keys::event_report(seq))
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .ok_or_else(not_found)?;
    let mut record: Value =
        serde_json::from_slice(&raw).map_err(|error| MatrixError::internal(&error.to_string()))?;
    report_room_labels(&state, &actor, &mut record);
    let event = match (record["room_id"].as_str(), record["event_id"].as_str()) {
        (Some(room_id), Some(event_id)) => state.rooms.event(room_id, event_id).ok(),
        _ => None,
    };
    record["event_json"] = event.unwrap_or(Value::Null);
    Ok(Json(record))
}

#[derive(Deserialize)]
struct TokenListQuery {
    valid: Option<bool>,
}

fn tokens(state: &AppState) -> crate::registration_tokens::RegistrationTokens {
    crate::registration_tokens::RegistrationTokens::new(std::sync::Arc::clone(&state.store))
}

fn store_error(error: &spindle_store::StoreError) -> MatrixError {
    MatrixError::internal(&error.to_string())
}

/// `GET /registration_tokens?valid=`
async fn list_registration_tokens(
    State(state): State<AppState>,
    _actor: AdminActor,
    Query(query): Query<TokenListQuery>,
) -> Result<Json<Value>, MatrixError> {
    let list = tokens(&state)
        .list(query.valid)
        .map_err(|error| store_error(&error))?;
    Ok(Json(json!({ "registration_tokens": list })))
}

#[derive(Deserialize)]
struct NewTokenRequest {
    token: Option<String>,
    uses_allowed: Option<u64>,
    expiry_time: Option<u64>,
    length: Option<usize>,
}

/// `POST /registration_tokens/new`
async fn new_registration_token(
    State(state): State<AppState>,
    actor: AdminActor,
    Json(request): Json<NewTokenRequest>,
) -> Result<Json<Value>, MatrixError> {
    use crate::registration_tokens::{DEFAULT_TOKEN_LEN, TokenError};
    let row = tokens(&state)
        .create(
            request.token,
            request.uses_allowed,
            request.expiry_time,
            request.length.unwrap_or(DEFAULT_TOKEN_LEN),
        )
        .map_err(|error| match error {
            TokenError::InUse | TokenError::Invalid => MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                error.to_string(),
            ),
            TokenError::Storage(inner) => store_error(&inner),
        })?;
    audit(
        &state,
        &actor.identity().user_id,
        "registration_token.create",
        &row.token,
        &json!({ "uses_allowed": row.uses_allowed, "expiry_time": row.expiry_time }),
    )?;
    Ok(Json(serde_json::to_value(row).unwrap_or_default()))
}

/// `GET /registration_tokens/{token}`
async fn get_registration_token(
    State(state): State<AppState>,
    _actor: AdminActor,
    Path(token): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    match tokens(&state)
        .get(&token)
        .map_err(|error| store_error(&error))?
    {
        Some(row) => Ok(Json(serde_json::to_value(row).unwrap_or_default())),
        None => Err(no_such_token()),
    }
}

fn no_such_token() -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        "no such registration token",
    )
}

/// `PUT /registration_tokens/{token}` with `uses_allowed` and
/// `expiry_time`, each absent to keep, `null` to clear.
async fn update_registration_token(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(token): Path<String>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    let bound = |field: &str| -> Result<Option<Option<u64>>, MatrixError> {
        match request.get(field) {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(None)),
            Some(value) => value.as_u64().map(|n| Some(Some(n))).ok_or_else(|| {
                MatrixError::new(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    format!("{field} is a non-negative integer or null"),
                )
            }),
        }
    };
    let uses_allowed = bound("uses_allowed")?;
    let expiry_time = bound("expiry_time")?;
    let Some(row) = tokens(&state)
        .update(&token, uses_allowed, expiry_time)
        .map_err(|error| store_error(&error))?
    else {
        return Err(no_such_token());
    };
    audit(
        &state,
        &actor.identity().user_id,
        "registration_token.update",
        &token,
        &json!({ "uses_allowed": row.uses_allowed, "expiry_time": row.expiry_time }),
    )?;
    Ok(Json(serde_json::to_value(row).unwrap_or_default()))
}

/// `DELETE /registration_tokens/{token}`
async fn delete_registration_token(
    State(state): State<AppState>,
    actor: AdminActor,
    Path(token): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if !tokens(&state)
        .delete(&token)
        .map_err(|error| store_error(&error))?
    {
        return Err(no_such_token());
    }
    audit(
        &state,
        &actor.identity().user_id,
        "registration_token.delete",
        &token,
        &json!({}),
    )?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct ServerNoticeRequest {
    user_id: String,
    content: Value,
    #[serde(rename = "type")]
    event_type: Option<String>,
}

/// `POST /send_server_notice`
///
/// A message from the operator to one user, as a real event in a room
/// this server opens for the two of them (`crate::server_notices`).
async fn send_server_notice(
    State(state): State<AppState>,
    actor: AdminActor,
    Json(request): Json<ServerNoticeRequest>,
) -> Result<Json<Value>, MatrixError> {
    if !request.content.is_object() {
        return Err(MatrixError::bad_json("content is an object"));
    }
    let event_type = request.event_type.as_deref().unwrap_or("m.room.message");
    let event_id = crate::server_notices::send(
        &state,
        &crate::server_notices::Notice {
            user_id: &request.user_id,
            content: &request.content,
            event_type,
        },
    )?;
    audit(
        &state,
        &actor.identity().user_id,
        "server_notice",
        &request.user_id,
        &json!({ "event_id": event_id, "type": event_type }),
    )?;
    Ok(Json(json!({ "event_id": event_id })))
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
