//! Rooms of a space that this server does not hold, learnt over federation.
//!
//! The client hierarchy walk and the MSC3266 room summary both fall back to
//! the federation `hierarchy` endpoint of the server that owns the room. What
//! comes back is another server's claim, so it is rebuilt field by field
//! (never forwarded as received) and then judged against the *requesting
//! user*, not the requesting server: the remote server only vouched that this
//! server may see the room.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::AppState;

/// Peers asked for one room before giving up. The `via` list is the room's
/// own advice, and a hostile space can make it long.
const MAX_SERVERS_PER_ROOM: usize = 4;
/// Federation requests one client request may start.
pub(crate) const MAX_REMOTE_FETCHES: usize = 8;
/// `m.space.child` events kept from one remote room.
const MAX_CHILDREN: usize = 500;
const MAX_VIA: usize = 10;

/// One remote room, rebuilt from a peer's hierarchy answer.
#[derive(Clone, Debug)]
pub(crate) struct RemoteRoom {
    pub room_id: String,
    /// The room-level summary fields, in the shape `chunk_of` produces.
    pub chunk: serde_json::Map<String, Value>,
    pub children_state: Vec<Value>,
    pub allowed_room_ids: Vec<String>,
}

/// A fetched level: the room and those of its children the peer described.
pub(crate) struct RemoteLevel {
    pub room: RemoteRoom,
    pub children: HashMap<String, RemoteRoom>,
}

impl RemoteRoom {
    /// Whether `user` (or nobody, for an unauthenticated summary) may be shown
    /// this room: the same rule the local walk applies, using the remote
    /// server's own `join_rule`, `world_readable` and `allowed_room_ids`.
    pub(crate) fn visible_to(&self, state: &AppState, user: Option<&str>) -> bool {
        if self.chunk.get("world_readable") == Some(&Value::Bool(true)) {
            return true;
        }
        match self.chunk.get("join_rule").and_then(Value::as_str) {
            Some("public" | "knock") => true,
            Some("restricted" | "knock_restricted") => user.is_some_and(|user| {
                self.allowed_room_ids
                    .iter()
                    .any(|room| state.rooms.is_joined(user, room).unwrap_or(false))
            }),
            _ => false,
        }
    }
}

/// The servers to ask about a room: those the parent's `m.space.child` names,
/// then the server in the room ID. Never this server, which does not hold it.
pub(crate) fn candidate_servers(state: &AppState, room_id: &str, via: &[String]) -> Vec<String> {
    let mut servers: Vec<String> = Vec::new();
    let named = via
        .iter()
        .map(String::as_str)
        .chain(room_id.split_once(':').map(|(_, server)| server));
    for server in named {
        if server != state.config.server.name && !servers.iter().any(|known| known == server) {
            servers.push(server.to_owned());
        }
    }
    servers.truncate(MAX_SERVERS_PER_ROOM);
    servers
}

/// The `via` list of an `m.space.child` event.
pub(crate) fn via_of(child: &Value) -> Vec<String> {
    child["content"]["via"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Ask each candidate in turn until one describes `room_id`. `budget` counts
/// requests started and is shared across a whole walk.
pub(crate) async fn fetch_level(
    state: &AppState,
    room_id: &str,
    via: &[String],
    suggested_only: bool,
    budget: &mut usize,
) -> Option<RemoteLevel> {
    for server in candidate_servers(state, room_id, via) {
        if *budget == 0 {
            return None;
        }
        // A peer the outbox already knows is down is skipped: waiting out
        // its timeout again would make every page of a space slow.
        if state.federation.unreachable_backing_off(&server) {
            continue;
        }
        *budget -= 1;
        match state
            .federation
            .remote_hierarchy(&server, room_id, suggested_only)
            .await
        {
            Ok(answer) => {
                if let Some(level) = parse_level(&answer, room_id, suggested_only) {
                    return Some(level);
                }
                tracing::debug!(%server, %room_id, "unusable hierarchy answer");
            }
            Err(error) => tracing::debug!(%server, %room_id, "remote hierarchy failed: {error}"),
        }
    }
    None
}

/// Rebuild an answer, accepting only the requested room and children that
/// room names.
fn parse_level(answer: &Value, room_id: &str, suggested_only: bool) -> Option<RemoteLevel> {
    let room = parse_room(&answer["room"], suggested_only)?;
    if room.room_id != room_id {
        return None;
    }
    let named: Vec<&str> = room
        .children_state
        .iter()
        .filter_map(|child| child["state_key"].as_str())
        .collect();
    let children = answer["children"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|child| parse_room(child, suggested_only))
        .filter(|child| named.contains(&child.room_id.as_str()))
        .map(|child| (child.room_id.clone(), child))
        .collect();
    Some(RemoteLevel { room, children })
}

fn parse_room(value: &Value, suggested_only: bool) -> Option<RemoteRoom> {
    let room_id = value["room_id"].as_str().filter(|id| id.starts_with('!'))?;
    let mut chunk = serde_json::Map::new();
    chunk.insert("room_id".to_owned(), json!(room_id));
    chunk.insert(
        "num_joined_members".to_owned(),
        json!(value["num_joined_members"].as_u64().unwrap_or(0)),
    );
    for field in ["world_readable", "guest_can_join"] {
        chunk.insert(
            field.to_owned(),
            json!(value[field].as_bool() == Some(true)),
        );
    }
    for field in [
        "name",
        "topic",
        "avatar_url",
        "canonical_alias",
        "join_rule",
        "room_type",
    ] {
        if let Some(text) = value[field].as_str() {
            chunk.insert(field.to_owned(), json!(text));
        }
    }
    let children_state = value["children_state"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|event| clean_child(event, suggested_only))
        .take(MAX_CHILDREN)
        .collect();
    let allowed_room_ids = value["allowed_room_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Some(RemoteRoom {
        room_id: room_id.to_owned(),
        chunk,
        children_state,
        allowed_room_ids,
    })
}

/// A stripped `m.space.child`: the fields the spec lists and the content
/// fields a client uses. A child with no usable `via` is not a child.
fn clean_child(event: &Value, suggested_only: bool) -> Option<Value> {
    if event["type"] != "m.space.child" {
        return None;
    }
    let state_key = event["state_key"]
        .as_str()
        .filter(|key| key.starts_with('!'))?;
    let via: Vec<&str> = event["content"]["via"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .take(MAX_VIA)
        .collect();
    if via.is_empty() {
        return None;
    }
    let suggested = event["content"]["suggested"].as_bool() == Some(true);
    if suggested_only && !suggested {
        return None;
    }
    let mut content = json!({ "via": via });
    if suggested {
        content["suggested"] = json!(true);
    }
    if let Some(order) = event["content"]["order"].as_str() {
        content["order"] = json!(order);
    }
    Some(json!({
        "type": "m.space.child",
        "state_key": state_key,
        "content": content,
        "sender": event["sender"].as_str().unwrap_or_default(),
        "origin_server_ts": event["origin_server_ts"].as_u64().unwrap_or(0),
    }))
}
