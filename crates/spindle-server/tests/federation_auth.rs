//! The claim this file exists to settle: **the events Spindle creates are ones
//! a federating peer would accept.**
//!
//! `crates/spindle-server/tests/rooms.rs` asserts that each event names the
//! right auth events. That is our belief about the rules. This file does not
//! restate the rules — it hands the events to `ruma-state-res`, the same
//! implementation the reference homeservers authorize with, and asks it. The
//! two checks below are exactly the ones a receiving server runs:
//!
//! - `check_state_independent_auth_rules` inspects the `auth_events` list
//!   itself: right types, no duplicates, nothing missing, nothing extra.
//! - `check_state_dependent_auth_rules` runs the actual predicate against the
//!   state those auth events name.
//!
//! An event with an empty `auth_events` fails the first. That is why this is a
//! defect and not a deferred feature: without it, every event the server has
//! ever minted is unacceptable to anybody else.
//!
//! Per ADR 0002 this comparison is deliberately one-sided — ruma builds nothing
//! here, it only judges. What it judges is produced by the HTTP API, so the
//! path under test is the one a real client drives.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::state_res::events::Event;
use ruma::state_res::{
    auth_types_for_event, check_state_dependent_auth_rules, check_state_independent_auth_rules,
};
use ruma::{
    EventId, MilliSecondsSinceUnixEpoch, OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UInt,
    UserId,
    events::{StateEventType, TimelineEventType},
    room_version_rules::RoomVersionRules,
};
use serde_json::{Value, json, value::RawValue as RawJsonValue};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A stored event, in the shape `ruma-state-res` reads.
///
/// Built by deserializing what the server actually persisted — not by
/// re-deriving it — so a field the server omits is a field missing here.
#[derive(Clone, Debug)]
struct ServerPdu {
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

impl ServerPdu {
    fn parse(json: &Value) -> Self {
        let ids = |field: &str| -> Vec<OwnedEventId> {
            json[field]
                .as_array()
                .unwrap_or_else(|| panic!("{field} is missing from {json}"))
                .iter()
                .map(|id| {
                    OwnedEventId::try_from(id.as_str().expect("an event ID is a string"))
                        .expect("the server minted a well-formed event ID")
                })
                .collect()
        };
        Self {
            event_id: OwnedEventId::try_from(json["event_id"].as_str().expect("an event ID"))
                .expect("a well-formed event ID"),
            room_id: OwnedRoomId::try_from(json["room_id"].as_str().expect("a room ID"))
                .expect("a well-formed room ID"),
            sender: OwnedUserId::try_from(json["sender"].as_str().expect("a sender"))
                .expect("a well-formed user ID"),
            origin_server_ts: MilliSecondsSinceUnixEpoch(
                UInt::try_from(json["origin_server_ts"].as_u64().expect("a timestamp"))
                    .expect("a timestamp that fits"),
            ),
            event_type: json["type"].as_str().expect("a type").into(),
            content: serde_json::value::to_raw_value(&json["content"]).expect("re-encodable"),
            state_key: json["state_key"].as_str().map(ToOwned::to_owned),
            prev_events: ids("prev_events"),
            auth_events: ids("auth_events"),
        }
    }
}

impl Event for ServerPdu {
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

/// Drive the public API and return every event of the room it built, oldest
/// first.
async fn room_as_a_peer_would_see_it() -> Vec<ServerPdu> {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
    let app = spindle_server::app(config, store).expect("a signing key is established");

    let call = |request: Request<Body>| {
        let app = app.clone();
        async move {
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };

    let (status, body) = call(
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "alice",
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy" },
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();

    let (status, body) = call(
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/createRoom")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "name": "Federated", "topic": "A topic" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().unwrap().to_owned();

    for index in 0..3 {
        let (status, body) = call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn{index}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "msgtype": "m.text", "body": format!("message {index}") }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let (status, body) = call(
        Request::builder()
            .uri(format!(
                "/_matrix/client/v3/rooms/{room_id}/messages?limit=100"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // `/messages` is newest first; authorization runs in the order the events
    // were created, because each one is checked against the state its
    // predecessors established.
    let mut events: Vec<ServerPdu> = body["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(ServerPdu::parse)
        .collect();
    events.reverse();
    assert!(events.len() >= 9, "expected the full room, got {events:?}");
    events
}

#[tokio::test]
async fn every_event_passes_rumas_authorization_rules() {
    let events = room_as_a_peer_would_see_it().await;
    let rules = RoomVersionRules::V11;

    let by_id: HashMap<OwnedEventId, ServerPdu> = events
        .iter()
        .map(|event| (event.event_id.clone(), event.clone()))
        .collect();

    for event in &events {
        let describe = format!("{} {}", event.event_type, event.event_id);

        // What the peer checks first: is the `auth_events` list itself
        // well-formed and complete? An empty list fails here for everything
        // but the create event.
        check_state_independent_auth_rules(&rules.authorization, event.clone(), |id: &EventId| {
            by_id.get(id).cloned()
        })
        .unwrap_or_else(|error| panic!("{describe} has an unacceptable auth_events: {error}"));

        // Then the predicate, resolved **only against the events this event
        // cites** -- which is the whole point. A receiving peer has no room
        // state to consult; it has the auth events the sender named and
        // nothing else. Handing the check a full room state instead would let
        // a selection that omits the power levels or the sender's membership
        // pass here and fail in production, which is precisely the mistake
        // this test exists to catch.
        let cited: HashMap<(StateEventType, String), ServerPdu> = event
            .auth_events
            .iter()
            .filter_map(|id| by_id.get(id))
            .filter_map(|cited| {
                let state_key = cited.state_key.clone()?;
                Some((
                    (cited.event_type.to_string().into(), state_key),
                    cited.clone(),
                ))
            })
            .collect();
        check_state_dependent_auth_rules(
            &rules.authorization,
            event.clone(),
            |event_type: &StateEventType, state_key: &str| {
                cited
                    .get(&(event_type.clone(), state_key.to_owned()))
                    .cloned()
            },
        )
        .unwrap_or_else(|error| panic!("{describe} is not authorized: {error}"));
    }
}

/// The verdict above is necessary but not sufficient: ruma accepts some
/// omissions, because several auth events are "the current X, **if any**" and
/// a room without one is a legitimate room. Room v11 still requires citing the
/// ones that exist — a peer resolving state from a short list gets a different
/// room than the sender meant, and state resolution diverges.
///
/// So this asserts the selection itself, against `auth_types_for_event`: the
/// same function ruma uses to decide what an event should cite. Our
/// `auth_events_for` is not consulted here, only its output.
#[tokio::test]
async fn the_selection_is_the_one_ruma_would_have_made() {
    let events = room_as_a_peer_would_see_it().await;
    let rules = RoomVersionRules::V11;

    // State as it stood *before* each event, which is what the selection reads.
    let mut state: HashMap<(StateEventType, String), OwnedEventId> = HashMap::new();

    for event in &events {
        let describe = format!("{} {}", event.event_type, event.event_id);
        let wanted = auth_types_for_event(
            &event.event_type,
            &event.sender,
            event.state_key.as_deref(),
            &event.content,
            &rules.authorization,
        )
        .unwrap_or_else(|error| panic!("ruma cannot select auth events for {describe}: {error}"));

        // "If any": a type the room does not have yet is not citable.
        let expected: BTreeSet<OwnedEventId> = wanted
            .into_iter()
            .filter_map(|key| state.get(&key).cloned())
            .collect();
        let actual: BTreeSet<OwnedEventId> = event.auth_events.iter().cloned().collect();
        assert_eq!(actual, expected, "{describe} cites the wrong auth events");

        if let Some(state_key) = &event.state_key {
            state.insert(
                (event.event_type.to_string().into(), state_key.clone()),
                event.event_id.clone(),
            );
        }
    }
}
