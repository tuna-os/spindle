//! Simplified Sliding Sync (MSC4186) — the surface Element X speaks.
//!
//! The idea the MSC exists for: a client with a thousand rooms wants the
//! *visible window* of its room list, not all thousand — so the request names
//! ranges over a sorted list, and the response carries only the rooms in
//! view plus whatever changed.
//!
//! This implementation is **stateless**: `pos` is a position in the global
//! stream, exactly like classic sync's token, and every request must carry
//! its full lists and subscriptions. MSC4186's sticky parameters — where the
//! server remembers the last request per connection — are an optimization on
//! top of the same wire shape, tracked as follow-up work. Stateless first,
//! because a connection table is one more thing that must survive a restart,
//! and correctness here does not need it.
//!
//! The sort is by each room's last activity, newest first. The linear index
//! cannot order rooms against each other — it is per-room by design — so the
//! sort key is the head event's timestamp, one point read per room.

use serde::Deserialize;
use serde_json::{Map, Value, json};

/// One list's request: which slice of the sorted rooms, and what to send for
/// each room in it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListRequest {
    pub ranges: Vec<(usize, usize)>,
    pub required_state: Vec<(String, String)>,
    pub timeline_limit: usize,
}

/// A direct subscription to one room, window position notwithstanding.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RoomSubscription {
    pub required_state: Vec<(String, String)>,
    pub timeline_limit: usize,
}

/// The whole request body.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SlidingRequest {
    pub lists: Map<String, Value>,
    pub room_subscriptions: Map<String, Value>,
    /// Milliseconds to long-poll when nothing has changed.
    pub timeout: Option<u64>,
}

impl SlidingRequest {
    /// The lists, decoded individually so one malformed list names itself.
    ///
    /// # Errors
    ///
    /// Returns the offending list's name.
    pub fn decoded_lists(&self) -> Result<Vec<(String, ListRequest)>, String> {
        let mut lists = Vec::new();
        for (name, value) in &self.lists {
            let list: ListRequest = serde_json::from_value(value.clone())
                .map_err(|error| format!("list {name:?}: {error}"))?;
            lists.push((name.clone(), list));
        }
        Ok(lists)
    }

    /// The room subscriptions, decoded like the lists.
    ///
    /// # Errors
    ///
    /// Returns the offending room's ID.
    pub fn decoded_subscriptions(&self) -> Result<Vec<(String, RoomSubscription)>, String> {
        let mut subscriptions = Vec::new();
        for (room_id, value) in &self.room_subscriptions {
            let subscription: RoomSubscription = serde_json::from_value(value.clone())
                .map_err(|error| format!("subscription {room_id:?}: {error}"))?;
            subscriptions.push((room_id.clone(), subscription));
        }
        Ok(subscriptions)
    }
}

/// Whether `required_state` asks for this `(type, state_key)`.
///
/// `["*", "*"]` is everything; `["m.room.member", "*"]` is every member;
/// `["m.room.member", "$ME"]` is the asking user's own membership, which is
/// how Element X asks for exactly the memberships it can render. An empty
/// list is *nothing*, not everything — a client that wants no state says so
/// by saying nothing, and the timeline is unaffected either way.
#[must_use]
pub fn wants_state(
    required: &[(String, String)],
    viewer: &str,
    event_type: &str,
    state_key: &str,
) -> bool {
    required.iter().any(|(wanted_type, wanted_key)| {
        let type_matches = wanted_type == "*" || wanted_type == event_type;
        let key = if wanted_key == "$ME" {
            viewer
        } else {
            wanted_key
        };
        type_matches && (key == "*" || key == state_key)
    })
}

/// Clip `ranges` to a list of `len` rooms, yielding the indices in view.
///
/// Ranges are inclusive on both ends, as the MSC writes them. Out-of-bounds
/// ends are clipped rather than refused: the client's window is sized by its
/// screen, not by how many rooms exist, and a request for rooms 0–19 of a
/// 3-room account means the 3 rooms.
#[must_use]
pub fn indices_in_view(ranges: &[(usize, usize)], len: usize) -> Vec<usize> {
    let mut indices = Vec::new();
    for &(start, end) in ranges {
        for index in start..=end.min(len.saturating_sub(1)) {
            if index < len && !indices.contains(&index) {
                indices.push(index);
            }
        }
        if len == 0 {
            break;
        }
    }
    indices
}

/// The `rooms` entry for one room, from the pieces the caller fetched.
#[must_use]
pub fn room_entry(
    name: Option<String>,
    required_state: Vec<Value>,
    timeline: Vec<Value>,
    limited: bool,
    joined_count: usize,
    notification_count: usize,
    initial: bool,
) -> Value {
    let mut entry = Map::new();
    if let Some(name) = name {
        entry.insert("name".to_owned(), json!(name));
    }
    entry.insert("required_state".to_owned(), Value::Array(required_state));
    entry.insert("timeline".to_owned(), Value::Array(timeline));
    entry.insert("limited".to_owned(), json!(limited));
    entry.insert("joined_count".to_owned(), json!(joined_count));
    entry.insert("notification_count".to_owned(), json!(notification_count));
    // `initial: true` marks a room sent in full, so a client knows to replace
    // its copy rather than append. Stateless as we are, that is every room in
    // an initial response and every *newly windowed* room later — the caller
    // decides, this just records it.
    entry.insert("initial".to_owned(), json!(initial));
    Value::Object(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_inclusive_and_clipped() {
        assert_eq!(indices_in_view(&[(0, 2)], 10), vec![0, 1, 2]);
        assert_eq!(indices_in_view(&[(0, 19)], 3), vec![0, 1, 2]);
        assert_eq!(indices_in_view(&[(0, 0)], 0), Vec::<usize>::new());
        // Two ranges, overlapping: each index once.
        assert_eq!(indices_in_view(&[(0, 2), (2, 4)], 10), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn required_state_wildcards() {
        let all = vec![("*".to_owned(), "*".to_owned())];
        assert!(wants_state(&all, "@a:x", "m.room.name", ""));
        assert!(wants_state(&all, "@a:x", "m.room.member", "@b:x"));

        let members = vec![("m.room.member".to_owned(), "*".to_owned())];
        assert!(wants_state(&members, "@a:x", "m.room.member", "@b:x"));
        assert!(!wants_state(&members, "@a:x", "m.room.name", ""));

        let me = vec![("m.room.member".to_owned(), "$ME".to_owned())];
        assert!(wants_state(&me, "@a:x", "m.room.member", "@a:x"));
        assert!(!wants_state(&me, "@a:x", "m.room.member", "@b:x"));

        // Empty means nothing, not everything.
        assert!(!wants_state(&[], "@a:x", "m.room.name", ""));
    }
}
