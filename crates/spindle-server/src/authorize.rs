//! Authorization: ruma's predicate, our state.
//!
//! `docs/divergence.md` calls the row this module implements "the project's
//! thesis in one row" — both sibling homeservers call ruma's auth check on
//! their local send path, and so do we. **The rules are not a divergence and
//! must not become one.** What differs is the cost of reaching the rules'
//! inputs: a DAG server computes or looks up the state to check against, while
//! here it is already materialized as a snapshot hanging off the previous log
//! entry.
//!
//! So this module deliberately contains no authorization logic. It converts a
//! stored event into the shape `ruma-state-res` reads, resolves state lookups
//! through the linear snapshot, and hands both to ruma. Anything here that
//! started deciding *whether* an event is allowed would be a bug.

use ruma::state_res::check_state_dependent_auth_rules;
use ruma::state_res::events::Event;
use ruma::{
    MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UInt, UserId,
    events::{StateEventType, TimelineEventType},
    room_version_rules::AuthorizationRules,
};
use serde_json::{Value, value::RawValue as RawJsonValue};

/// A stored event in the shape `ruma-state-res` reads.
///
/// Built from the persisted JSON rather than from the log entry: the log holds
/// ordering and state, and the authorization rules read content — membership,
/// power levels, join rules — which only the event body carries.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    event_id: OwnedEventId,
    room_id: OwnedRoomId,
    sender: OwnedUserId,
    origin_server_ts: MilliSecondsSinceUnixEpoch,
    event_type: TimelineEventType,
    content: Box<RawJsonValue>,
    state_key: Option<String>,
    prev_events: Vec<OwnedEventId>,
    auth_events: Vec<OwnedEventId>,
}

impl StoredEvent {
    /// Parse persisted event JSON.
    ///
    /// The event ID is passed separately because a v11 event does not carry
    /// one: it *is* the reference hash of these bytes.
    ///
    /// # Errors
    ///
    /// Returns a description of the first field that is missing or malformed.
    /// A stored event that cannot be parsed is a corrupt event, and refusing to
    /// authorize against it is the only safe answer — treating it as absent
    /// would silently widen what the rules allow.
    pub fn parse(event_id: &str, json: &Value) -> Result<Self, String> {
        let string = |field: &str| -> Result<&str, String> {
            json[field]
                .as_str()
                .ok_or_else(|| format!("`{field}` is missing or not a string"))
        };
        let ids = |field: &str| -> Result<Vec<OwnedEventId>, String> {
            json[field]
                .as_array()
                .ok_or_else(|| format!("`{field}` is missing or not an array"))?
                .iter()
                .map(|id| {
                    let id = id
                        .as_str()
                        .ok_or_else(|| format!("`{field}` holds a non-string"))?;
                    OwnedEventId::try_from(id).map_err(|error| format!("`{field}`: {error}"))
                })
                .collect()
        };

        Ok(Self {
            event_id: OwnedEventId::try_from(event_id)
                .map_err(|error| format!("event ID: {error}"))?,
            room_id: OwnedRoomId::try_from(string("room_id")?)
                .map_err(|error| format!("room ID: {error}"))?,
            sender: OwnedUserId::try_from(string("sender")?)
                .map_err(|error| format!("sender: {error}"))?,
            origin_server_ts: MilliSecondsSinceUnixEpoch(
                json["origin_server_ts"]
                    .as_u64()
                    .and_then(|ts| UInt::try_from(ts).ok())
                    .ok_or_else(|| "`origin_server_ts` is missing or out of range".to_owned())?,
            ),
            event_type: string("type")?.into(),
            content: serde_json::value::to_raw_value(&json["content"])
                .map_err(|error| format!("content: {error}"))?,
            state_key: json["state_key"].as_str().map(ToOwned::to_owned),
            prev_events: ids("prev_events")?,
            auth_events: ids("auth_events")?,
        })
    }
}

impl Event for StoredEvent {
    type Id = OwnedEventId;

    fn event_id(&self) -> &Self::Id {
        &self.event_id
    }
    fn room_id(&self) -> Option<&RoomId> {
        Some(&self.room_id)
    }
    fn sender(&self) -> &UserId {
        &self.sender
    }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        self.origin_server_ts
    }
    fn event_type(&self) -> &TimelineEventType {
        &self.event_type
    }
    fn content(&self) -> &RawJsonValue {
        &self.content
    }
    fn state_key(&self) -> Option<&str> {
        self.state_key.as_deref()
    }
    fn prev_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.prev_events.iter())
    }
    fn auth_events(&self) -> Box<dyn DoubleEndedIterator<Item = &Self::Id> + '_> {
        Box::new(self.auth_events.iter())
    }
    fn redacts(&self) -> Option<&Self::Id> {
        None
    }
    fn rejected(&self) -> bool {
        false
    }
}

/// Run the authorization predicate over `candidate`.
///
/// `by_state` resolves a `(type, state_key)` against the room state the
/// candidate is being sent into — for us, a point query on the materialized
/// snapshot plus one read of the event body. `None` means the room does not
/// have that state, which the rules treat as absent rather than as an error.
///
/// **Only the state-dependent rules run here.** ruma also offers
/// `check_state_independent_auth_rules`, which inspects the `auth_events` list
/// itself; a receiving peer runs it because the list arrived from somebody
/// else. On the local send path the list is one we just built, so running it
/// would cost up to five extra keyed reads per event to re-check our own
/// arithmetic — and no reachable input can make it fire. That property is
/// worth verifying, so `tests/federation_auth.rs` runs it over every event the
/// server produces, where it costs nothing on the write path. A check that
/// cannot fail in production does not belong in production.
///
/// # Errors
///
/// Returns the rule that refused, verbatim from ruma. The wording is ruma's on
/// purpose: it is the same explanation a peer would give.
pub fn authorize(
    rules: &AuthorizationRules,
    candidate: &StoredEvent,
    by_state: impl Fn(&StateEventType, &str) -> Option<StoredEvent>,
) -> Result<(), String> {
    check_state_dependent_auth_rules(rules, candidate.clone(), by_state)
}
