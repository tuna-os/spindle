//! The room directory, room aliases, the user directory and server-side
//! search.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::rooms::ReadScope;
use crate::routes::{
    PublicRoomsQuery, PublicRoomsRequest, SEARCH_LIMIT_MAX, SearchHit, as_seen_by, directory_error,
    directory_page, origin_server_ts, parse_search_cursor, room_error, search_cursor,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The directories and search.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/directory/room/{room_alias}",
            get(resolve_alias).put(create_alias).delete(delete_alias),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/aliases",
            get(room_aliases),
        )
        .route(
            "/_matrix/client/v3/directory/list/room/{room_id}",
            get(get_room_visibility).put(set_room_visibility),
        )
        .route(
            "/_matrix/client/v3/publicRooms",
            get(public_rooms).post(public_rooms_filtered),
        )
        .route(
            "/_matrix/client/v3/user_directory/search",
            post(user_directory_search),
        )
        .route("/_matrix/client/v3/search", post(search))
}

/// `GET /_matrix/client/v3/directory/room/{room_alias}`
///
/// Unauthenticated, as the spec requires: resolving a name is how a client
/// finds a room it has not joined, and requiring an account to look one up
/// would make published aliases useless to anyone not already signed in.
///
/// `servers` is this server alone until federation lands. Naming ourselves is
/// honest -- we are the only server known to hold the room -- where an empty
/// list would tell a client there is nowhere to join through.
async fn resolve_alias(
    State(state): State<AppState>,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    if let Some(record) = state
        .directory
        .resolve(&room_alias)
        .map_err(|error| directory_error(&error))?
    {
        return Ok(Json(json!({
            "room_id": record.room_id,
            "servers": [state.config.server.name.clone()],
        })));
    }
    // The classic appservice room query: an alias inside a service's
    // namespace may spring into being when asked — the service creates
    // the room and maps the alias before answering 200, so the second
    // resolution finds what the first could not.
    if state.appservices.query_alias(&room_alias).await
        && let Some(record) = state
            .directory
            .resolve(&room_alias)
            .map_err(|error| directory_error(&error))?
    {
        return Ok(Json(json!({
            "room_id": record.room_id,
            "servers": [state.config.server.name.clone()],
        })));
    }
    // An alias another server owns is that server's to answer: the same
    // federated directory query the join path uses, relayed to the client
    // with the servers the owner names.
    if let Some((_, domain)) = room_alias.split_once(':')
        && domain != state.config.server.name
        && let Ok(answer) = state
            .federation
            .remote_query_directory(domain, &room_alias)
            .await
        && answer["room_id"].is_string()
    {
        return Ok(Json(json!({
            "room_id": answer["room_id"],
            "servers": answer["servers"].as_array().cloned().unwrap_or_default(),
        })));
    }
    Err(MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no room is called {room_alias}"),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateAliasRequest {
    room_id: String,
}

/// `PUT /_matrix/client/v3/directory/room/{room_alias}`
///
/// The room must exist. Letting an alias point at nothing would put a name in
/// the directory that resolves to a 404 on join -- a broken link the server
/// handed out itself. And the caller must be in it, or a server admin: see
/// [`may_advertise`]. Existence is checked first, so that "no such room" does
/// not come back as a refusal, which would tell a stranger the room exists
/// and they simply are not in it.
async fn create_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
    Json(request): Json<CreateAliasRequest>,
) -> Result<Json<Value>, MatrixError> {
    state.rooms.exists(&request.room_id).map_err(room_error)?;
    may_advertise(
        &state,
        &identity.user_id,
        &request.room_id,
        "give it an alias",
    )?;
    state
        .directory
        .create(&room_alias, &request.room_id, &identity.user_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/directory/room/{room_alias}`
///
/// Claiming an alias writes no room state -- the room's own opinion about
/// what it is called is the room's to give. Removing one is different: a
/// canonical alias that names an alias the directory no longer resolves
/// is a broken name the server left behind, and the public directory
/// still matches searches against it. So, as Synapse does, the alias is
/// taken out of `m.room.canonical_alias` on the remover's behalf, best
/// effort: a remover the room does not let edit that event keeps the
/// stale name, which is the room's decision rather than an error here.
async fn delete_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = state
        .directory
        .delete(&room_alias, &identity.user_id)
        .map_err(|error| directory_error(&error))?;
    if let Ok(event) = state
        .rooms
        .state_event_full(&room_id, "m.room.canonical_alias", "")
        && let Some(without) = without_alias(&event["content"], &room_alias)
    {
        let _ = state
            .rooms
            .set_state_checked(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                "m.room.canonical_alias",
                "",
                &without,
            )
            .await;
    }
    Ok(Json(json!({})))
}

/// `content` with `alias` gone from `alias` and `alt_aliases`, or `None` if
/// it named it nowhere and there is nothing to write.
fn without_alias(content: &Value, alias: &str) -> Option<Value> {
    let names_it = content["alias"] == json!(alias)
        || content["alt_aliases"]
            .as_array()
            .is_some_and(|alts| alts.iter().any(|alt| alt == alias));
    if !names_it {
        return None;
    }
    let mut without = content.clone();
    if without["alias"] == json!(alias) {
        without.as_object_mut()?.remove("alias");
    }
    if let Some(alts) = without["alt_aliases"].as_array_mut() {
        alts.retain(|alt| alt != alias);
    }
    Some(without)
}

/// `GET /_matrix/client/v3/rooms/{room_id}/aliases`
///
/// Members only. The directory answers alias-to-room for anyone, because that
/// is a name someone published; room-to-alias is the transpose and enumerates
/// what a room is reachable by, which is the room's business.
async fn room_aliases(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    if !joined.iter().any(|room| room == &room_id) {
        return Err(MatrixError::forbidden(format!(
            "{} is not in {room_id}",
            identity.user_id
        )));
    }
    let aliases = state
        .directory
        .for_room(&room_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({ "aliases": aliases })))
}

/// May `user_id` attach this server's name to `room_id` -- by listing it in
/// the directory, or by giving it an alias?
///
/// The rule: **a joined member may; a server admin may for any room.** One
/// rule for both, because both are the same act: a name this server hands to
/// strangers that resolves to the room. An earlier version of this comment
/// argued that an alias was different -- "a name somebody has to already
/// know" -- and let any account claim any free alias for any room. That was
/// backwards: `/join/#name:server` is precisely how strangers find rooms, so
/// an alias is the more published of the two, and it let anyone who had
/// learnt a room ID hang `#official:example.org` on it from outside. #268
/// named the disagreement; requiring membership for both makes the person
/// answerable for the room they are naming, and matches what Sytest expects
/// of a regular user, who joins before claiming.
///
/// The spec explicitly leaves this to the server ("servers may choose to
/// impose additional restrictions"), so this is a policy choice rather than a
/// reading of the spec, and it is written here so it can be argued with.
/// `action` names the act in the refusal, so a client learns what was refused
/// without learning anything about the room.
fn may_advertise(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    action: &str,
) -> Result<(), MatrixError> {
    if state
        .rooms
        .is_joined(user_id, room_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
    {
        return Ok(());
    }
    let admin = crate::admin::is_server_admin(state, user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    if admin {
        return Ok(());
    }
    Err(MatrixError::forbidden(format!(
        "only a member of the room, or a server admin, may {action}"
    )))
}

#[derive(Debug, Deserialize)]
struct VisibilityRequest {
    visibility: String,
}

/// `PUT /_matrix/client/v3/directory/list/room/{room_id}`
async fn set_room_visibility(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<VisibilityRequest>,
) -> Result<Json<Value>, MatrixError> {
    // A room that does not exist cannot be advertised. Checked before the
    // permission test so that "no such room" does not come back as a refusal,
    // which would tell a stranger the room exists and they simply are not in
    // it.
    state.rooms.exists(&room_id).map_err(room_error)?;
    may_advertise(
        &state,
        &identity.user_id,
        &room_id,
        "change its directory visibility",
    )?;

    match request.visibility.as_str() {
        "public" => state
            .directory
            .publish(&room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?,
        "private" => state
            .directory
            .unpublish(&room_id)
            .map_err(|error| directory_error(&error))?,
        other => {
            return Err(MatrixError::bad_json(format!(
                "visibility must be \"public\" or \"private\", not {other:?}"
            )));
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/directory/list/room/{room_id}`
///
/// Unauthenticated, as the spec has it: the directory is public, so whether a
/// room is in it is public too.
async fn get_room_visibility(
    State(state): State<AppState>,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let published = state
        .directory
        .is_published(&room_id)
        .map_err(|error| directory_error(&error))?;
    Ok(Json(json!({
        "visibility": if published { "public" } else { "private" },
    })))
}

/// Another server's directory is that server's to serve.
///
/// Refused rather than silently answered from our own list, which would show
/// a client our rooms under someone else's name. The federated read is a
/// follow-up.
fn refuse_remote_directory(server: Option<&String>, ours: &str) -> Result<(), MatrixError> {
    match server {
        Some(name) if name != ours => Err(MatrixError::new(
            StatusCode::NOT_IMPLEMENTED,
            "M_UNRECOGNIZED",
            "this server does not proxy another server's room directory yet",
        )),
        _ => Ok(()),
    }
}

/// `GET /_matrix/client/v3/publicRooms`
async fn public_rooms(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<PublicRoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    refuse_remote_directory(query.server.as_ref(), &state.config.server.name)?;
    directory_page(&state, query.limit, query.since.as_deref(), None, &[])
}

/// `POST /_matrix/client/v3/publicRooms`
///
/// Authenticated, unlike the GET form: the spec has it that way, and the
/// filter is the reason -- a search term is a thing a user types, so it is
/// attributable.
async fn public_rooms_filtered(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    Json(request): Json<PublicRoomsRequest>,
) -> Result<Json<Value>, MatrixError> {
    refuse_remote_directory(request.server.as_ref(), &state.config.server.name)?;
    directory_page(
        &state,
        request.limit,
        request.since.as_deref(),
        request.filter.generic_search_term.as_deref(),
        &request.filter.room_types,
    )
}

#[derive(Debug, Deserialize)]
struct UserSearchRequest {
    search_term: String,
    limit: Option<usize>,
}

/// The default and maximum number of users one search returns.
const USER_SEARCH_LIMIT: usize = 10;

const USER_SEARCH_LIMIT_MAX: usize = 50;

/// Everyone `searcher` is allowed to find.
///
/// The spec sets a *floor* rather than a rule -- results "should at least"
/// cover users you share a room with and users in public rooms -- and
/// explicitly leaves the rest to the server. Spindle serves exactly that floor
/// and nothing wider:
///
/// - **someone you share a joined room with**, because you can already see
///   their name and avatar in that room's member list, so the directory
///   reveals nothing new; and
/// - **someone joined to a published room**, because they chose to be in a
///   room this server advertises to strangers.
///
/// The rejected alternative is "every account on the server", which several
/// homeservers offer behind a config flag. It turns the directory into a user
/// enumeration endpoint: an attacker with one account learns every localpart,
/// and a user who joined no public rooms never consented to that. Making it
/// opt-in would push the decision onto operators who mostly will not read it.
///
/// The cost is proportional to the searcher's rooms plus the published ones,
/// not to the number of accounts -- which is the right shape, but it is still
/// a scan per request, and it is the thing to replace with a maintained index
/// if the directory ever gets hot.
fn visible_users(
    state: &AppState,
    searcher: &str,
) -> Result<std::collections::BTreeSet<String>, MatrixError> {
    let mut visible = std::collections::BTreeSet::new();
    let mut rooms = state
        .rooms
        .joined(searcher)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    rooms.extend(
        state
            .directory
            .published()
            .map_err(|error| directory_error(&error))?,
    );
    rooms.sort();
    rooms.dedup();

    for room_id in rooms {
        // A room in the index that cannot be read is skipped, not fatal: one
        // stale pointer must not make search stop working.
        let Ok(members) = state.rooms.joined_member_ids(&room_id) else {
            continue;
        };
        visible.extend(members.iter().cloned());
    }
    visible.remove(searcher);
    Ok(visible)
}

/// Does `term` match this user?
///
/// Matched against the localpart and the display name, case-insensitively.
/// Not against the full user ID, because every local ID ends in the server
/// name -- searching for it would return the whole directory, which reads as
/// a bug rather than a feature.
fn user_matches(term: &str, user_id: &str, displayname: Option<&str>) -> bool {
    let needle = term.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let localpart = user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':').map(|(local, _)| local))
        .unwrap_or(user_id);
    localpart.to_lowercase().contains(&needle)
        || displayname.is_some_and(|name| name.to_lowercase().contains(&needle))
}

/// `POST /_matrix/client/v3/search`, the body.
#[derive(Deserialize)]
struct SearchRequest {
    search_categories: SearchCategories,
}

#[derive(Deserialize)]
struct SearchCategories {
    room_events: Option<RoomEventsCriteria>,
}

#[derive(Deserialize)]
struct RoomEventsCriteria {
    search_term: String,
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    filter: SearchFilter,
    order_by: Option<String>,
    event_context: Option<SearchContext>,
    #[serde(default)]
    include_state: bool,
}

/// The spec's `RoomEventFilter`, the parts a search can honour.
#[derive(Default, Deserialize)]
struct SearchFilter {
    limit: Option<usize>,
    rooms: Option<Vec<String>>,
    #[serde(default)]
    not_rooms: Vec<String>,
    senders: Option<Vec<String>>,
    #[serde(default)]
    not_senders: Vec<String>,
    types: Option<Vec<String>>,
    #[serde(default)]
    not_types: Vec<String>,
}

#[derive(Deserialize)]
struct SearchContext {
    before_limit: Option<usize>,
    after_limit: Option<usize>,
    #[serde(default)]
    include_profile: bool,
}

#[derive(Deserialize)]
struct SearchQuery {
    next_batch: Option<String>,
}

/// The default and maximum number of results one search page returns.
const SEARCH_LIMIT: usize = 10;

/// The spec's default for each side of a result's context.
const SEARCH_CONTEXT_EACH_SIDE: usize = 5;

/// The value at a dotted path into an event (`content.body`), if it is text.
fn text_at<'a>(event: &'a Value, path: &str) -> Option<&'a str> {
    path.split('.')
        .try_fold(event, |node, part| node.get(part))
        .and_then(Value::as_str)
}

/// Does `event` pass the search's filter and carry the term under one of
/// its keys? Case-insensitive containment, which is what "search basics"
/// means here: no stemming, no ranking, no index.
fn search_matches(event: &Value, needle: &str, keys: &[String], filter: &SearchFilter) -> bool {
    let sender = event["sender"].as_str().unwrap_or_default();
    let event_type = event["type"].as_str().unwrap_or_default();
    if filter
        .senders
        .as_ref()
        .is_some_and(|senders| !senders.iter().any(|wanted| wanted == sender))
        || filter.not_senders.iter().any(|unwanted| unwanted == sender)
        || filter
            .types
            .as_ref()
            .is_some_and(|types| !types.iter().any(|wanted| wanted == event_type))
        || filter
            .not_types
            .iter()
            .any(|unwanted| unwanted == event_type)
    {
        return false;
    }
    keys.iter()
        .any(|key| text_at(event, key).is_some_and(|text| text.to_lowercase().contains(needle)))
}

/// What one walk of the rooms produced: the page's hits, the scope each
/// searched room was read under, and whether there is a page after this.
struct SearchPage {
    hits: Vec<SearchHit>,
    scopes: BTreeMap<String, ReadScope>,
    more: bool,
}

/// `POST /_matrix/client/v3/search`
///
/// Room-event search over the rooms the caller may read: by default the
/// rooms they are joined to, or the `filter.rooms` they name, each under
/// its own [`crate::rooms::Rooms::read_scope`] so a former member searches only the stretch
/// they may read and a room the caller may not see contributes nothing
/// rather than refusing the whole search. Newest first, by
/// `origin_server_ts` across rooms and by position within one; `rank` is
/// the same order, since nothing here scores.
///
/// `count` is the number on this page. The spec calls the field an
/// approximation of the total, and a true total would mean walking every
/// room to its end on every search, which is the one cost this endpoint
/// declines: a page costs the rooms it walks to fill itself, and no more.
async fn search(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>,
    Json(request): Json<SearchRequest>,
) -> Result<Json<Value>, MatrixError> {
    let Some(criteria) = request.search_categories.room_events else {
        return Ok(Json(json!({ "search_categories": {} })));
    };
    let needle = criteria.search_term.trim().to_lowercase();
    if needle.is_empty() {
        return Err(MatrixError::bad_json("search_term is empty"));
    }
    if let Some(order) = criteria.order_by.as_deref()
        && order != "recent"
        && order != "rank"
    {
        return Err(MatrixError::bad_json(format!(
            "order_by must be recent or rank, not {order}"
        )));
    }
    let keys = if criteria.keys.is_empty() {
        vec!["content.body".to_owned()]
    } else {
        criteria.keys.clone()
    };
    let limit = criteria
        .filter
        .limit
        .unwrap_or(SEARCH_LIMIT)
        .clamp(1, SEARCH_LIMIT_MAX);
    let mut cursor = match query.next_batch.as_deref() {
        Some(token) => parse_search_cursor(token)?,
        None => BTreeMap::new(),
    };

    let SearchPage { hits, scopes, more } = search_rooms(
        &state,
        &identity.user_id,
        &criteria,
        &needle,
        &keys,
        limit,
        &mut cursor,
    )?;

    let results: Vec<Value> = hits
        .iter()
        .map(|hit| {
            let mut event = hit.event.json.clone();
            if let Some(object) = event.as_object_mut() {
                object.insert("event_id".to_owned(), json!(hit.event.event_id));
                object.insert("room_id".to_owned(), json!(hit.room_id));
            }
            let event = as_seen_by(&state, &hit.room_id, &identity, event);
            let mut result = json!({ "rank": 1.0, "result": event });
            if let Some(wanted) = &criteria.event_context
                && let Some(scope) = scopes.get(&hit.room_id)
            {
                result["context"] = search_context(&state, &identity.user_id, hit, wanted, scope);
            }
            result
        })
        .collect();

    let mut room_events = serde_json::Map::new();
    room_events.insert("count".to_owned(), json!(results.len()));
    room_events.insert(
        "highlights".to_owned(),
        json!(needle.split_whitespace().collect::<Vec<_>>()),
    );
    room_events.insert("results".to_owned(), Value::Array(results));
    if more {
        room_events.insert("next_batch".to_owned(), json!(search_cursor(&cursor)));
    }
    if criteria.include_state {
        room_events.insert(
            "state".to_owned(),
            Value::Object(search_state(&state, &identity.user_id, &hits, &scopes)?),
        );
    }
    Ok(Json(json!({
        "search_categories": { "room_events": Value::Object(room_events) }
    })))
}

/// Walk every room the search covers and gather its hits: the caller's
/// joined rooms, or the `filter.rooms` named, each under its own
/// [`crate::rooms::Rooms::read_scope`], and each resumed from `cursor`. Returns the hits
/// newest first and cut to `limit`, the scope of each room that was
/// searched (the context needs it again), and whether a further page
/// exists; `cursor` is advanced to where that page starts.
fn search_rooms(
    state: &AppState,
    user_id: &str,
    criteria: &RoomEventsCriteria,
    needle: &str,
    keys: &[String],
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> Result<SearchPage, MatrixError> {
    let rooms = match &criteria.filter.rooms {
        Some(rooms) => rooms.clone(),
        None => state.rooms.joined(user_id).map_err(room_error)?,
    };
    let mut scopes: BTreeMap<String, ReadScope> = BTreeMap::new();
    let mut hits: Vec<SearchHit> = Vec::new();
    let mut more = false;
    for room_id in rooms {
        if criteria.filter.not_rooms.contains(&room_id) {
            continue;
        }
        // A room the caller may not read contributes nothing, rather than
        // refusing the search: naming it must not tell them it exists.
        let Ok(scope) = state.rooms.read_scope(user_id, &room_id) else {
            continue;
        };
        let matches = |event: &Value| search_matches(event, needle, keys, &criteria.filter);
        let (found, next) = state
            .rooms
            .reader_with(user_id, &room_id, scope.clone())
            .search(cursor.get(&room_id).copied(), limit, &matches)
            .map_err(room_error)?;
        more |= next.is_some();
        hits.extend(found.into_iter().map(|event| SearchHit {
            room_id: room_id.clone(),
            event,
        }));
        scopes.insert(room_id, scope);
    }
    more |= page_newest_first(&mut hits, limit, cursor);
    Ok(SearchPage { hits, scopes, more })
}

/// Cut a walk's hits to one page, newest first across rooms, and advance
/// the per-room cursor to where the next page starts. Returns whether the
/// cut left anything behind.
///
/// Ties by room and then position, so a page boundary falls in the same
/// place however the rooms were walked. Each room resumes below the oldest
/// position taken from it; a room nothing was taken from resumes where it
/// was, and finds the same hits again -- which is what makes the pages
/// neither skip nor repeat.
fn page_newest_first(
    hits: &mut Vec<SearchHit>,
    limit: usize,
    cursor: &mut BTreeMap<String, i64>,
) -> bool {
    hits.sort_by(|a, b| {
        origin_server_ts(b)
            .cmp(&origin_server_ts(a))
            .then_with(|| a.room_id.cmp(&b.room_id))
            .then_with(|| b.event.li.cmp(&a.event.li))
    });
    let more = hits.len() > limit;
    hits.truncate(limit);
    for hit in hits.iter() {
        cursor
            .entry(hit.room_id.clone())
            .and_modify(|from| *from = (*from).min(hit.event.li))
            .or_insert(hit.event.li);
    }
    more
}

/// The current state of each room with a hit, for `include_state`: the
/// present for a member, the room as it stood at the bound for a former
/// one, exactly as `/state` answers.
fn search_state(
    state: &AppState,
    user_id: &str,
    hits: &[SearchHit],
    scopes: &BTreeMap<String, ReadScope>,
) -> Result<serde_json::Map<String, Value>, MatrixError> {
    let mut states = serde_json::Map::new();
    for hit in hits {
        if states.contains_key(&hit.room_id) {
            continue;
        }
        let Some(scope) = scopes.get(&hit.room_id) else {
            continue;
        };
        // The gate already ran once per room to build `scopes`; the reader
        // carries that answer rather than asking again.
        let rendered = state
            .rooms
            .reader_with(user_id, &hit.room_id, scope.clone())
            .state_serialized()
            .map_err(room_error)?;
        let room_state = serde_json::from_str::<Value>(&rendered)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        states.insert(hit.room_id.clone(), room_state);
    }
    Ok(states)
}

/// The events around one hit, as `/context` would show them, trimmed to
/// what the search asked for on each side. A hit whose context cannot be
/// read is a hit without context rather than a failed search.
fn search_context(
    state: &AppState,
    user_id: &str,
    hit: &SearchHit,
    wanted: &SearchContext,
    scope: &ReadScope,
) -> Value {
    let before_limit = wanted.before_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let after_limit = wanted.after_limit.unwrap_or(SEARCH_CONTEXT_EACH_SIDE);
    let Ok(context) = state
        .rooms
        .reader_with(user_id, &hit.room_id, scope.clone())
        .context(&hit.event.event_id, before_limit, after_limit)
    else {
        return Value::Null;
    };
    let events_before = context.events_before;
    let events_after = context.events_after;
    let mut out = json!({
        "events_before": events_before,
        "events_after": events_after,
        "start": crate::tokens::Pagination(context.start).to_string(),
        "end": crate::tokens::Pagination(context.end).to_string(),
    });
    if wanted.include_profile {
        // The profile each sender had at the hit, from the state the
        // context already carries.
        let mut profiles = serde_json::Map::new();
        let senders = std::iter::once(&hit.event.json)
            .chain(out["events_before"].as_array().into_iter().flatten())
            .chain(out["events_after"].as_array().into_iter().flatten())
            .filter_map(|event| event["sender"].as_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        for sender in senders {
            let member = context.state.iter().find(|event| {
                event["type"] == "m.room.member" && event["state_key"] == sender.as_str()
            });
            let mut profile = serde_json::Map::new();
            if let Some(name) = member.and_then(|event| event["content"]["displayname"].as_str()) {
                profile.insert("displayname".to_owned(), json!(name));
            }
            if let Some(url) = member.and_then(|event| event["content"]["avatar_url"].as_str()) {
                profile.insert("avatar_url".to_owned(), json!(url));
            }
            profiles.insert(sender, Value::Object(profile));
        }
        out["profile_info"] = Value::Object(profiles);
    }
    out
}

/// `POST /_matrix/client/v3/user_directory/search`
async fn user_directory_search(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<UserSearchRequest>,
) -> Result<Json<Value>, MatrixError> {
    let limit = request
        .limit
        .unwrap_or(USER_SEARCH_LIMIT)
        .clamp(1, USER_SEARCH_LIMIT_MAX);

    let mut results = Vec::new();
    let mut limited = false;
    for user_id in visible_users(&state, &identity.user_id)? {
        let profile = state.profiles.get(&user_id).unwrap_or_default();
        if !user_matches(
            &request.search_term,
            &user_id,
            profile.displayname.as_deref(),
        ) {
            continue;
        }
        // One past the limit is how `limited` is known: the spec asks whether
        // results were cut, which cannot be answered by stopping exactly at
        // the limit.
        if results.len() == limit {
            limited = true;
            break;
        }
        let mut entry = serde_json::Map::new();
        entry.insert("user_id".to_owned(), json!(user_id));
        if let Some(name) = profile.displayname {
            entry.insert("display_name".to_owned(), json!(name));
        }
        if let Some(avatar) = profile.avatar_url {
            entry.insert("avatar_url".to_owned(), json!(avatar));
        }
        results.push(Value::Object(entry));
    }

    Ok(Json(json!({ "results": results, "limited": limited })))
}
