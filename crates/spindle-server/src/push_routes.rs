//! Push: pushers, push rules, and the notifications list.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{
    RoomRuleContext, SEARCH_LIMIT_MAX, SearchHit, account_data_error, limit_exceeded,
    origin_server_ts, parse_search_cursor, room_error, ruleset_of, search_cursor,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Push: where a user's devices are told, and by which rules.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/pushers", get(get_pushers))
        .route("/_matrix/client/v3/pushers/set", post(set_pusher))
        // Four arities of the same path, because the spec has four and each
        // reads or writes a different slice of one ruleset.
        .route("/_matrix/client/v3/pushrules/", get(get_push_rules))
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}",
            get(get_push_rule)
                .put(set_push_rule)
                .delete(delete_push_rule),
        )
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled",
            get(get_push_rule_enabled).put(set_push_rule_enabled),
        )
        .route(
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions",
            get(get_push_rule_actions).put(set_push_rule_actions),
        )
        .route("/_matrix/client/v3/notifications", get(notifications))
}

/// `GET /_matrix/client/v3/pushers`
async fn get_pushers(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let pushers = state
        .pushers
        .list(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "pushers": pushers })))
}

#[derive(Debug, Deserialize)]
struct SetPusherRequest {
    pushkey: String,
    /// `http`, `email`, or `null` to remove the pusher.
    kind: Option<String>,
    app_id: String,
    #[serde(default)]
    app_display_name: String,
    #[serde(default)]
    device_display_name: String,
    #[serde(default)]
    profile_tag: Option<String>,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    data: Value,
    /// The spec's `append` governs pushers of the *same* pushkey held by
    /// *other* users; this server keys pushers per user, so it has nothing
    /// to remove either way and the flag is accepted for the wire shape.
    #[serde(default)]
    #[allow(dead_code)]
    append: bool,
    /// MSC3881: whether this pusher receives anything. Absent is on.
    #[serde(default, alias = "org.matrix.msc3881.enabled")]
    enabled: Option<bool>,
}

/// `POST /_matrix/client/v3/pushers/set`
///
/// Register, replace or (with `kind: null`) remove one of the caller's
/// pushers. An http pusher's URL is what `push::deliver_loop` will fetch
/// for as long as the registration stands, so it is vetted here the way
/// the loop vets it: the spec's path, http or https, and not a literal
/// address inside this server's network -- a hostname is judged by what it
/// resolves to, at every delivery.
async fn set_pusher(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<SetPusherRequest>,
) -> Result<Json<Value>, MatrixError> {
    let internal = |error: spindle_store::StoreError| MatrixError::internal(&error.to_string());
    let Some(kind) = request.kind.as_deref() else {
        state
            .pushers
            .remove(&identity.user_id, &request.app_id, &request.pushkey)
            .map_err(internal)?;
        return Ok(Json(json!({})));
    };
    match kind {
        "http" => {
            let Some(url) = request.data["url"].as_str() else {
                return Err(MatrixError::missing_param("an http pusher needs data.url"));
            };
            state
                .push
                .vet_url(url)
                .map_err(|why| MatrixError::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", why))?;
        }
        "email" => {}
        other => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("unknown pusher kind {other:?}; expected http, email or null"),
            ));
        }
    }
    // Replacing a registration does not count against the cap: a client
    // that re-registers the same device forever stays where it is.
    let cap = state.config.limits.pushers_per_user;
    if !state
        .pushers
        .holds(&identity.user_id, &request.app_id, &request.pushkey)
        .map_err(internal)?
        && state.pushers.count(&identity.user_id).map_err(internal)? >= cap
    {
        return Err(limit_exceeded("pushers", cap));
    }
    state
        .pushers
        .set(
            &identity.user_id,
            &request.app_id,
            &request.pushkey,
            &json!({
                "pushkey": request.pushkey,
                "kind": kind,
                "app_id": request.app_id,
                "app_display_name": request.app_display_name,
                "device_display_name": request.device_display_name,
                "profile_tag": request.profile_tag,
                "lang": request.lang,
                "data": request.data,
                // MSC3881, under both spellings until the stable one is
                // in a spec this server claims: the device that owns the
                // pusher, so another client can name it, and the switch.
                "enabled": request.enabled.unwrap_or(true),
                "org.matrix.msc3881.enabled": request.enabled.unwrap_or(true),
                "device_id": identity.device_id,
                "org.matrix.msc3881.device_id": identity.device_id,
            }),
        )
        .map_err(internal)?;
    Ok(Json(json!({})))
}

fn save_ruleset(state: &AppState, user_id: &str, ruleset: &Value) -> Result<(), MatrixError> {
    let stream_write = state.rooms.reserve_stream_id();
    let position = stream_write.id();
    state
        .account_data
        .put(user_id, "", crate::push_rules::TYPE, ruleset, position)
        .map_err(|error| account_data_error(&error))?;
    state.rooms.wake_sync_waiters();
    // What was scored under the old rules says nothing under the new.
    state.rooms.forget_scores(user_id);
    Ok(())
}

/// Reject a scope the spec does not define.
///
/// Only `global` exists today. `device` was in older drafts and clients still
/// occasionally ask for it, so answering `M_NOT_FOUND` rather than treating it
/// as `global` keeps a client from believing it stored a per-device rule that
/// silently applied everywhere.
fn check_scope(scope: &str) -> Result<(), MatrixError> {
    if scope == "global" {
        return Ok(());
    }
    Err(MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no such push rule scope: {scope}"),
    ))
}

fn check_kind(kind: &str) -> Result<(), MatrixError> {
    if crate::push_rules::KINDS.contains(&kind) {
        return Ok(());
    }
    Err(MatrixError::new(
        StatusCode::BAD_REQUEST,
        "M_INVALID_PARAM",
        format!("no such push rule kind: {kind}"),
    ))
}

fn rule_not_found(kind: &str, rule_id: &str) -> MatrixError {
    MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no {kind} rule {rule_id}"),
    )
}

/// `GET /_matrix/client/v3/pushrules/`
async fn get_push_rules(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    Ok(Json(json!({ "global": ruleset })))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn get_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    let index = crate::push_rules::position(&ruleset, &kind, &rule_id)
        .ok_or_else(|| rule_not_found(&kind, &rule_id))?;
    Ok(Json(ruleset[&kind][index].clone()))
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn set_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    // A dotted ID means a rule the *server* defined. A client may enable,
    // disable and re-action one, but minting a new one would let it claim a
    // meaning the server assigns -- and then a later spec version defining
    // that ID would collide with the client's.
    if crate::push_rules::is_server_default(&rule_id) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "rule IDs beginning with a dot belong to the server",
        ));
    }
    let mut rule = body;
    if !rule["actions"].is_array() {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "a push rule needs an `actions` array",
        ));
    }
    // A rule a client wrote is enabled unless it says otherwise, and is never
    // a default however the body is decorated: `default` is the server's word
    // for "this rule came with the server", and a client cannot make it true.
    if rule.get("enabled").is_none() {
        rule["enabled"] = Value::Bool(true);
    }
    rule["default"] = Value::Bool(false);

    let mut ruleset = ruleset_of(&state, &identity.user_id)?;
    crate::push_rules::upsert(&mut ruleset, &kind, &rule_id, rule);
    save_ruleset(&state, &identity.user_id, &ruleset)?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}`
async fn delete_push_rule(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    check_scope(&scope)?;
    check_kind(&kind)?;
    let mut ruleset = ruleset_of(&state, &identity.user_id)?;
    if !crate::push_rules::remove(&mut ruleset, &kind, &rule_id) {
        return Err(rule_not_found(&kind, &rule_id));
    }
    save_ruleset(&state, &identity.user_id, &ruleset)?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled`
async fn get_push_rule_enabled(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let rule = one_rule(&state, &identity.user_id, &scope, &kind, &rule_id)?;
    Ok(Json(json!({ "enabled": rule["enabled"] })))
}

/// `GET /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions`
async fn get_push_rule_actions(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let rule = one_rule(&state, &identity.user_id, &scope, &kind, &rule_id)?;
    Ok(Json(json!({ "actions": rule["actions"] })))
}

fn one_rule(
    state: &AppState,
    user_id: &str,
    scope: &str,
    kind: &str,
    rule_id: &str,
) -> Result<Value, MatrixError> {
    check_scope(scope)?;
    check_kind(kind)?;
    let ruleset = ruleset_of(state, user_id)?;
    let index = crate::push_rules::position(&ruleset, kind, rule_id)
        .ok_or_else(|| rule_not_found(kind, rule_id))?;
    Ok(ruleset[kind][index].clone())
}

#[derive(Debug, Deserialize)]
struct EnabledRequest {
    enabled: bool,
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/enabled`
///
/// Works on a server default as well as a user's own rule: silencing
/// `.m.rule.message` is exactly what this endpoint is for.
async fn set_push_rule_enabled(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<EnabledRequest>,
) -> Result<Json<Value>, MatrixError> {
    edit_rule(&state, &identity.user_id, &scope, &kind, &rule_id, |rule| {
        rule["enabled"] = Value::Bool(request.enabled);
    })
}

#[derive(Debug, Deserialize)]
struct ActionsRequest {
    actions: Vec<Value>,
}

/// `PUT /_matrix/client/v3/pushrules/{scope}/{kind}/{rule_id}/actions`
async fn set_push_rule_actions(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((scope, kind, rule_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<ActionsRequest>,
) -> Result<Json<Value>, MatrixError> {
    edit_rule(&state, &identity.user_id, &scope, &kind, &rule_id, |rule| {
        rule["actions"] = Value::Array(request.actions.clone());
    })
}

/// Read the ruleset, change one rule in place, write it back.
///
/// In place: `enabled` and `actions` are edits to an existing rule, so the
/// rule keeps its position. Moving it would re-prioritise a ruleset the client
/// did not ask to reorder -- and for a default rule, would move it out of the
/// order the spec fixes.
fn edit_rule(
    state: &AppState,
    user_id: &str,
    scope: &str,
    kind: &str,
    rule_id: &str,
    change: impl FnOnce(&mut Value),
) -> Result<Json<Value>, MatrixError> {
    check_scope(scope)?;
    check_kind(kind)?;
    let mut ruleset = ruleset_of(state, user_id)?;
    let index = crate::push_rules::position(&ruleset, kind, rule_id)
        .ok_or_else(|| rule_not_found(kind, rule_id))?;
    change(&mut ruleset[kind][index]);
    save_ruleset(state, user_id, &ruleset)?;
    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct NotificationsQuery {
    from: Option<String>,
    limit: Option<usize>,
    only: Option<String>,
}

/// The default number of notifications one page returns.
const NOTIFICATIONS_LIMIT: usize = 50;

/// `GET /_matrix/client/v3/notifications`
///
/// The events in the caller's joined rooms that their push rules say to
/// notify about, newest first, with whether each is read. The same walk
/// as `/search` -- there is no notification table; the rules are put to
/// every event the walk passes, which is what the rules are for -- and the
/// same per-room cursor in `next_token`. "Newest" is the server-wide
/// stream order, not `origin_server_ts`: see [`page_by_stream`] for why.
/// A reader's own events never notify,
/// whatever the rules say: the spec's one rule the ruleset does not
/// spell out. `only=highlight` keeps the hits whose actions carry the
/// highlight tweak.
async fn notifications(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<NotificationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    let limit = query
        .limit
        .unwrap_or(NOTIFICATIONS_LIMIT)
        .clamp(1, SEARCH_LIMIT_MAX);
    let highlights_only = match query.only.as_deref() {
        None => false,
        Some("highlight") => true,
        Some(other) => {
            return Err(MatrixError::bad_json(format!(
                "only must be highlight, not {other}"
            )));
        }
    };
    let (snapshot, mut cursor) = match query.from.as_deref() {
        Some(token) => parse_notifications_cursor(token)?,
        None => (None, BTreeMap::new()),
    };
    // A token from before the snapshot existed resumes against the stream
    // as it stands now; the token handed back carries that position.
    let snapshot = snapshot.unwrap_or_else(|| state.rooms.stream_position());
    let ruleset = ruleset_of(&state, &identity.user_id)?;
    let profile = state
        .profiles
        .get(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let display_name = profile.displayname.as_deref();

    let mut rooms: BTreeMap<String, RoomRuleContext> = BTreeMap::new();
    let mut hits: Vec<(u64, SearchHit)> = Vec::new();
    let mut more = false;
    for room_id in state.rooms.joined(&identity.user_id).map_err(room_error)? {
        let Ok(scope) = state.rooms.read_scope(&identity.user_id, &room_id) else {
            continue;
        };
        let room = RoomRuleContext::of(&state, &room_id)?;
        let context = room.for_reader(&identity.user_id, display_name, &room_id);
        let notifies = |event: &Value| {
            event["sender"] != identity.user_id.as_str()
                && crate::push_rules::evaluate(&ruleset, event, &context).is_some_and(|actions| {
                    !highlights_only || crate::push_rules::is_highlight(&actions)
                })
        };
        let order = RoomStreamOrder::new(state.rooms.stream_rows(&room_id).map_err(room_error)?);
        let from = match (cursor.get(&room_id).copied(), order.bound(snapshot)) {
            (Some(resume), Some(bound)) => Some(resume.min(bound)),
            (resume, bound) => resume.or(bound),
        };
        let (found, next) = state
            .rooms
            .reader_with(&identity.user_id, &room_id, scope.clone())
            .search(from, limit, &notifies)
            .map_err(room_error)?;
        more |= next.is_some();
        hits.extend(found.into_iter().map(|event| {
            let key = order.key(event.li);
            (
                key,
                SearchHit {
                    room_id: room_id.clone(),
                    event,
                },
            )
        }));
        rooms.insert(room_id, room);
    }
    more |= page_by_stream(&mut hits, limit, &mut cursor);
    let hits: Vec<SearchHit> = hits.into_iter().map(|(_, hit)| hit).collect();

    let notifications = render_notifications(
        &state,
        &identity.user_id,
        display_name,
        &ruleset,
        &rooms,
        &hits,
    )?;
    let mut body = serde_json::Map::new();
    body.insert("notifications".to_owned(), Value::Array(notifications));
    if more {
        body.insert(
            "next_token".to_owned(),
            json!(notifications_cursor(snapshot, &cursor)),
        );
    }
    Ok(Json(Value::Object(body)))
}

/// `/notifications`' `next_token`: `s<stream position>;` and then the
/// `/search` cursor. The position is where the first page stood; every
/// later page is cut to it, so an event or a room arriving mid-walk waits
/// for the next walk instead of landing out of order on a later page.
///
/// A token from before the position was added is the bare `/search`
/// cursor. It still parses, with no position, and resumes each room where
/// it says (no repeats, no skips within a room it names).
fn parse_notifications_cursor(
    token: &str,
) -> Result<(Option<u64>, BTreeMap<String, i64>), MatrixError> {
    // A cursor pair starts with a position (a digit or `-`), so a leading
    // `s` is unambiguous.
    let Some(rest) = token.strip_prefix('s') else {
        return Ok((None, parse_search_cursor(token)?));
    };
    let (position, rooms) = rest.split_once(';').unwrap_or((rest, ""));
    let position = position
        .parse::<u64>()
        .map_err(|_| MatrixError::bad_json("from is not a notifications token"))?;
    Ok((Some(position), parse_search_cursor(rooms)?))
}

fn notifications_cursor(snapshot: u64, cursor: &BTreeMap<String, i64>) -> String {
    format!("s{snapshot};{}", search_cursor(cursor))
}

/// One room's events placed in the server-wide stream order.
///
/// Each event's key is the highest stream id at or below its position in
/// the room. An indexed event gets its own id (ids rise with position, as
/// both are assigned under the room's append lock); an event with no index
/// row inherits the one below it. Taking the running maximum makes the key
/// never fall as the position rises, which is what [`page_by_stream`]
/// needs, whatever the index holds.
struct RoomStreamOrder {
    /// `(li, key)`, ascending in both.
    rows: Vec<(i64, u64)>,
}

impl RoomStreamOrder {
    pub(crate) fn new(mut rows: Vec<(i64, u64)>) -> Self {
        rows.sort_unstable();
        let mut high = 0;
        for row in &mut rows {
            high = high.max(row.1);
            row.1 = high;
        }
        Self { rows }
    }

    pub(crate) fn key(&self, li: i64) -> u64 {
        match self.rows.partition_point(|(at, _)| *at <= li) {
            0 => 0,
            n => self.rows[n - 1].1,
        }
    }

    /// The exclusive `from` that keeps a walk to the events at or before
    /// stream position `snapshot`, or `None` when that is all of them.
    pub(crate) fn bound(&self, snapshot: u64) -> Option<i64> {
        let first_after = self.rows.partition_point(|(_, key)| *key <= snapshot);
        self.rows.get(first_after).map(|(li, _)| *li)
    }
}

/// Cut a `/notifications` walk to one page and advance the per-room cursor,
/// as [`page_newest_first`] does for `/search`, but newest first by stream
/// key (see [`RoomStreamOrder`]), then room, then position: a total order.
///
/// Not `origin_server_ts`. Each room is walked by position and resumed
/// below the oldest position taken from it, so the merge across rooms is
/// exact only if the sort key never rises as the position falls. A
/// timestamp breaks that: a federated event can carry any `ts`, and the
/// local clock can step back. Then a page takes
/// an older position first, the cursor drops below a newer one, and that
/// event is never served (#635). The stream key cannot do this.
fn page_by_stream(
    hits: &mut Vec<(u64, SearchHit)>,
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> bool {
    hits.sort_by(|(a_key, a), (b_key, b)| {
        b_key
            .cmp(a_key)
            .then_with(|| a.room_id.cmp(&b.room_id))
            .then_with(|| b.event.li.cmp(&a.event.li))
    });
    let more = hits.len() > limit;
    hits.truncate(limit);
    for (_, hit) in hits.iter() {
        cursor
            .entry(hit.room_id.clone())
            .and_modify(|from| *from = (*from).min(hit.event.li))
            .or_insert(hit.event.li);
    }
    more
}

/// One `/notifications` entry per hit: the rule's actions, the event with
/// its IDs, and whether the caller's `m.read` receipt is at or past it.
fn render_notifications(
    state: &AppState,
    user_id: &str,
    display_name: Option<&str>,
    ruleset: &Value,
    rooms: &BTreeMap<String, RoomRuleContext>,
    hits: &[SearchHit],
) -> Result<Vec<Value>, MatrixError> {
    let mut notifications = Vec::with_capacity(hits.len());
    for hit in hits {
        let room = &rooms[&hit.room_id];
        let actions = crate::push_rules::evaluate(
            ruleset,
            &hit.event.json,
            &room.for_reader(user_id, display_name, &hit.room_id),
        )
        .unwrap_or_default();
        let read = state
            .rooms
            .receipt(&hit.room_id, user_id, "m.read")
            .map_err(room_error)?
            .is_some_and(|receipt| hit.event.li <= receipt.li);
        let mut event = hit.event.json.clone();
        if let Some(object) = event.as_object_mut() {
            object.insert("event_id".to_owned(), json!(hit.event.event_id));
            object.insert("room_id".to_owned(), json!(hit.room_id));
        }
        notifications.push(json!({
            "actions": actions,
            "event": event,
            "read": read,
            "room_id": hit.room_id,
            "ts": origin_server_ts(hit),
        }));
    }
    Ok(notifications)
}

#[cfg(test)]
mod notifications_order_tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        RoomStreamOrder, SearchHit, notifications_cursor, page_by_stream,
        parse_notifications_cursor,
    };

    /// One stored event: its room, position, stream id and timestamp.
    #[derive(Clone)]
    struct Stored {
        room: &'static str,
        li: i64,
        stream: u64,
        ts: i64,
    }

    /// Events in arrival order across three rooms, every one stamped the
    /// same millisecond (the tie the CI flake hit), and one late federated
    /// event in `!c` whose `ts` is older than everything else (the case a
    /// timestamp order skips).
    fn history() -> Vec<Stored> {
        let rooms = [
            "!c:x", "!a:x", "!b:x", "!a:x", "!c:x", "!b:x", "!b:x", "!a:x", "!c:x",
        ];
        let mut next_li: BTreeMap<&str, i64> = BTreeMap::new();
        rooms
            .iter()
            .enumerate()
            .map(|(n, room)| {
                let li = next_li.entry(room).or_insert(10);
                *li += 1;
                Stored {
                    room,
                    li: *li,
                    stream: n as u64 + 1,
                    ts: if n == 8 { 5 } else { 1_000 },
                }
            })
            .collect()
    }

    /// The room walk the store does: the newest `limit` positions below
    /// `from`, and whether more remain.
    fn walk(
        history: &[Stored],
        room: &str,
        from: Option<i64>,
        limit: usize,
    ) -> (Vec<Stored>, bool) {
        let mut below: Vec<Stored> = history
            .iter()
            .filter(|event| event.room == room && from.is_none_or(|from| event.li < from))
            .cloned()
            .collect();
        below.sort_by_key(|event| std::cmp::Reverse(event.li));
        let more = below.len() > limit;
        below.truncate(limit);
        (below, more)
    }

    fn hit(event: &Stored) -> SearchHit {
        SearchHit {
            room_id: event.room.to_owned(),
            event: crate::rooms::TimelineEvent {
                event_id: format!("${}", event.stream),
                li: event.li,
                json: json!({ "origin_server_ts": event.ts }),
            },
        }
    }

    /// Page through `history` at `limit` the way the handler does, a token
    /// round trip between pages, and return the stream ids served. `after`
    /// arrives once the first page is out.
    fn page_through(history: &[Stored], after: &[Stored], limit: usize) -> Vec<u64> {
        let mut store = history.to_vec();
        let mut token: Option<String> = None;
        let mut served = Vec::new();
        for _ in 0..=store.len() + after.len() {
            let (snapshot, mut cursor) = match &token {
                Some(token) => parse_notifications_cursor(token).unwrap(),
                None => (None, BTreeMap::new()),
            };
            let snapshot =
                snapshot.unwrap_or_else(|| store.iter().map(|e| e.stream).max().unwrap_or(0));
            let mut hits = Vec::new();
            let mut more = false;
            for room in ["!a:x", "!b:x", "!c:x", "!d:x"] {
                let order = RoomStreamOrder::new(
                    store
                        .iter()
                        .filter(|e| e.room == room)
                        .map(|e| (e.li, e.stream))
                        .collect(),
                );
                let from = match (cursor.get(room).copied(), order.bound(snapshot)) {
                    (Some(resume), Some(bound)) => Some(resume.min(bound)),
                    (resume, bound) => resume.or(bound),
                };
                let (found, next) = walk(&store, room, from, limit);
                more |= next;
                hits.extend(found.iter().map(|e| (order.key(e.li), hit(e))));
            }
            more |= page_by_stream(&mut hits, limit, &mut cursor);
            served.extend(hits.iter().map(|(key, _)| *key));
            if token.is_none() {
                store.extend_from_slice(after);
            }
            if !more {
                return served;
            }
            token = Some(notifications_cursor(snapshot, &cursor));
        }
        panic!("paging at {limit} did not end");
    }

    #[test]
    fn every_page_size_serves_the_stream_newest_first_exactly_once() {
        let history = history();
        let expected: Vec<u64> = (1..=history.len() as u64).rev().collect();
        for limit in 1..=history.len() + 1 {
            assert_eq!(
                page_through(&history, &[], limit),
                expected,
                "limit {limit}"
            );
        }
    }

    #[test]
    fn what_arrives_mid_walk_waits_for_the_next_walk() {
        let history = history();
        let next = history.len() as u64 + 1;
        // A newer event in a room already walked, and one in a room the
        // first page never saw.
        let after = [
            Stored {
                room: "!a:x",
                li: 100,
                stream: next,
                ts: 2_000,
            },
            Stored {
                room: "!d:x",
                li: 1,
                stream: next + 1,
                ts: 2_000,
            },
        ];
        let expected: Vec<u64> = (1..=history.len() as u64).rev().collect();
        for limit in 1..=history.len() {
            assert_eq!(
                page_through(&history, &after, limit),
                expected,
                "limit {limit}"
            );
        }
    }

    #[test]
    fn an_event_with_no_index_row_takes_the_key_below_it() {
        let order = RoomStreamOrder::new(vec![(5, 40), (2, 10), (8, 30)]);
        assert_eq!(order.key(1), 0);
        assert_eq!(order.key(2), 10);
        assert_eq!(order.key(4), 10);
        assert_eq!(order.key(5), 40);
        // A row out of step with its position cannot make the key fall.
        assert_eq!(order.key(8), 40);
        assert_eq!(order.bound(10), Some(5));
        assert_eq!(order.bound(40), None);
        assert_eq!(order.bound(0), Some(2));
    }

    #[test]
    fn a_token_from_before_the_snapshot_still_parses() {
        let (snapshot, rooms) = parse_notifications_cursor("12:!a:x;7:!b:x").unwrap();
        assert_eq!(snapshot, None);
        assert_eq!(rooms.get("!a:x"), Some(&12));
        assert_eq!(rooms.get("!b:x"), Some(&7));
        let (snapshot, rooms) = parse_notifications_cursor("s99;12:!a:x").unwrap();
        assert_eq!(snapshot, Some(99));
        assert_eq!(rooms.get("!a:x"), Some(&12));
        assert_eq!(
            parse_notifications_cursor(&notifications_cursor(5, &BTreeMap::new())).unwrap(),
            (Some(5), BTreeMap::new())
        );
        assert!(parse_notifications_cursor("sx;1:!a:x").is_err());
        assert!(parse_notifications_cursor("garbage").is_err());
    }
}
