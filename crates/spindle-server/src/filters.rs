//! Client-supplied filters for `/sync`.
//!
//! A filter is a client saying "do not send me things I will throw away". It
//! is a bandwidth and battery question rather than a correctness one: a server
//! that ignored every filter would still be *correct*, just wasteful, which is
//! why the spec lets a server drop fields it does not understand.
//!
//! Two shapes of the same thing. A client may hand the JSON inline on every
//! request, or upload it once and pass the id back. Both go through the same
//! parse, so a filter cannot mean one thing uploaded and another inline.
//!
//! Matching is deliberately literal. `types` and `not_types` support the
//! spec's trailing-`*` wildcard and nothing else -- no globbing, no regex --
//! because a filter is applied to every event of every sync and a pattern
//! language is a cost paid on the hot path forever.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// A whole `/sync` filter.
///
/// Every field is optional, and an absent field means "no opinion" rather than
/// "exclude everything" -- the difference matters, because the empty *list* is
/// the way a client says "none of these", and conflating the two would make an
/// empty `types: []` silently mean "all types".
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub room: RoomFilter,
    /// Accepted, stored, echoed back, and not applied: this server has no
    /// presence to filter. Keeping it rather than rejecting it is what lets a
    /// client upload one filter and use it against any server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_fields: Option<Vec<String>>,
}

/// The room half, which is where almost every real filter lives.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RoomFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<EventFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<EventFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<EventFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_data: Option<EventFilter>,
    /// Room-level include and exclude, applied to every section at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rooms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_rooms: Option<Vec<String>>,
}

/// The filter applied to one section's events.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rooms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_rooms: Option<Vec<String>>,
}

impl EventFilter {
    /// Whether one event survives this filter.
    ///
    /// **Exclusion beats inclusion**, which the spec is explicit about: an
    /// event named by both `types` and `not_types` is excluded. A server that
    /// resolved that the other way would let a client widen a filter by
    /// accident and receive something it had asked twice not to see.
    #[must_use]
    pub fn matches(&self, event: &Value) -> bool {
        let event_type = event["type"].as_str().unwrap_or_default();
        let sender = event["sender"].as_str().unwrap_or_default();
        Self::allowed(
            event_type,
            self.types.as_deref(),
            self.not_types.as_deref(),
            true,
        ) && Self::allowed(
            sender,
            self.senders.as_deref(),
            self.not_senders.as_deref(),
            false,
        )
    }

    /// Whether this filter permits a room at all.
    #[must_use]
    pub fn allows_room(&self, room_id: &str) -> bool {
        Self::allowed(
            room_id,
            self.rooms.as_deref(),
            self.not_rooms.as_deref(),
            false,
        )
    }

    /// One include/exclude pair, applied to one value.
    ///
    /// `wildcards` is only true for event types: the spec gives the trailing
    /// `*` to `types` and `not_types` and to nothing else, so a sender called
    /// `@bot*:example.org` is a sender, not a pattern.
    fn allowed(
        value: &str,
        include: Option<&[String]>,
        exclude: Option<&[String]>,
        wildcards: bool,
    ) -> bool {
        if let Some(exclude) = exclude
            && exclude.iter().any(|p| Self::hit(value, p, wildcards))
        {
            return false;
        }
        match include {
            // Absent is "no opinion"; an empty list is "none of these", and a
            // client that sends `types: []` means it.
            None => true,
            Some(include) => include.iter().any(|p| Self::hit(value, p, wildcards)),
        }
    }

    fn hit(value: &str, pattern: &str, wildcards: bool) -> bool {
        if wildcards && let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }
        value == pattern
    }
}

impl Filter {
    /// Whether the whole filter permits a room.
    #[must_use]
    pub fn allows_room(&self, room_id: &str) -> bool {
        let excluded = self
            .room
            .not_rooms
            .as_ref()
            .is_some_and(|rooms| rooms.iter().any(|room| room == room_id));
        if excluded {
            return false;
        }
        self.room
            .rooms
            .as_ref()
            .is_none_or(|rooms| rooms.iter().any(|room| room == room_id))
    }

    /// Apply a section's filter to a list of events, honouring its `limit`.
    ///
    /// The limit is applied **after** matching, and to the *end* of the list:
    /// a timeline is oldest-first and a client asking for ten events wants the
    /// ten most recent, not the ten oldest that happen to match.
    #[must_use]
    pub fn apply(section: Option<&EventFilter>, mut events: Vec<Value>) -> Vec<Value> {
        let Some(section) = section else {
            return events;
        };
        events.retain(|event| section.matches(event));
        if let Some(limit) = section.limit
            && events.len() > limit
        {
            events.drain(..events.len() - limit);
        }
        events
    }
}

/// Filters a user has uploaded.
pub struct Filters {
    store: Arc<FjallStore>,
}

impl Filters {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Store a filter and return the id a client passes back.
    ///
    /// The id is the count of what the user already has, which is enough: ids
    /// are per-user, never reused within a user, and a client only ever echoes
    /// back one this server gave it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn put(&self, user_id: &str, filter: &Filter) -> Result<String, StoreError> {
        let next = ReadView::scan_prefix(self.store.as_ref(), &keys::filter_prefix(user_id))?.len();
        let id = next.to_string();
        Store::put(
            self.store.as_ref(),
            &keys::filter(user_id, &id),
            serde_json::to_string(filter)
                .unwrap_or_else(|_| "{}".to_owned())
                .as_bytes(),
        )?;
        Ok(id)
    }

    /// One stored filter, or `None` if the user never uploaded it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read fails.
    pub fn get(&self, user_id: &str, filter_id: &str) -> Result<Option<Filter>, StoreError> {
        let Some(bytes) = ReadView::get(self.store.as_ref(), &keys::filter(user_id, filter_id))?
        else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }
}
