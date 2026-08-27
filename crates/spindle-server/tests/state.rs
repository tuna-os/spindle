//! Room state: reading all of it, reading one entry, and setting one.
//!
//! The `O(state)` read here is the only one in the server, and it is on a read
//! path by design. Authorization does point queries into the same snapshot —
//! `/state` walking the room is fine; sending an event walking it would not be.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn post(&self, path: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                token,
                &json!({ "name": "Original", "topic": "Original topic" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn a_rooms_state_is_every_current_state_event_and_nothing_else() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    // A message is not state, and must not appear here however many are sent.
    for index in 0..3 {
        harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/t{index}"),
                &token,
                &json!({ "msgtype": "m.text", "body": "chatter" }),
            )
            .await;
    }

    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room_id}/state"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body.as_array().expect("an array of events");

    // Asserted in order, not sorted first. The trie places entries by hash, so
    // its natural walk order is an artefact of the digest and would differ run
    // to run; `/state` sorts, and a client diffing two responses depends on
    // that. Sorting the assertion instead would hide the day it stops.
    let keys: Vec<(&str, &str)> = events
        .iter()
        .map(|event| {
            (
                event["type"].as_str().unwrap(),
                event["state_key"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            ("m.room.create", ""),
            ("m.room.join_rules", ""),
            ("m.room.member", "@alice:example.org"),
            ("m.room.name", ""),
            ("m.room.power_levels", ""),
            ("m.room.topic", ""),
        ]
    );

    // Full events, not bare content: a client resolving state needs the sender
    // and the event ID, not just the payload.
    for event in events {
        assert!(event["event_id"].is_string(), "{event}");
        assert_eq!(event["sender"], "@alice:example.org", "{event}");
        assert!(event["state_key"].is_string(), "{event}");
    }
}

#[tokio::test]
async fn setting_state_replaces_it_rather_than_appending_to_it() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    let topic = format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic");
    let (status, body) = harness.get(&topic, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["topic"], "Original topic");

    let (status, body) = harness
        .put(&topic, &token, &json!({ "topic": "A new topic" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["event_id"].as_str().unwrap().starts_with('$'));

    let (status, body) = harness.get(&topic, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["topic"], "A new topic");

    // Current state, not history: the room still has exactly one topic, even
    // though two topic events are now in the log.
    let (_, all) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room_id}/state"), &token)
        .await;
    let topics: Vec<&Value> = all
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "m.room.topic")
        .collect();
    assert_eq!(topics.len(), 1, "{all}");
    assert_eq!(topics[0]["content"]["topic"], "A new topic");

    // The superseded event is still in the timeline -- replaced in state is
    // not erased from history.
    let (_, messages) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=100"),
            &token,
        )
        .await;
    let topic_events = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "m.room.topic")
        .count();
    assert_eq!(topic_events, 2, "{messages}");
}

#[tokio::test]
async fn absent_state_is_not_found_rather_than_empty() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    // A client reading `m.room.avatar` has to tell "no avatar" from "an avatar
    // whose content happens to be empty". An empty object for both would make
    // that impossible.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.avatar"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");

    // And the same for a state key that exists as a type but not as a key.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.member/@bob:example.org"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn state_reads_and_writes_are_subject_to_the_same_rules_as_everything_else() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.create_room(&alice).await;

    // Bob is not in the room, so he cannot set its topic. The refusal is
    // ruma's, not a check written for this endpoint.
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic"),
            &bob,
            &json!({ "topic": "mine now" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");

    // Unauthenticated is unauthenticated, whatever the endpoint.
    let (status, body) = harness
        .call(
            Request::builder()
                .uri(format!("/_matrix/client/v3/rooms/{room_id}/state"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // An unknown room is unknown, not an empty state.
    let (status, body) = harness
        .get("/_matrix/client/v3/rooms/!nope:example.org/state", &alice)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_single_event_can_be_fetched_by_id() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    let (_, sent) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/t1"),
            &token,
            &json!({ "msgtype": "m.text", "body": "find me" }),
        )
        .await;
    let event_id = sent["event_id"].as_str().unwrap().to_owned();

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/event/{event_id}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["event_id"], event_id);
    assert_eq!(body["content"]["body"], "find me");
    assert!(body["signatures"].is_object(), "{body}");

    // An event ID that does not exist in a room that does is "no such event",
    // and one in a room that does not exist is "no such room" -- a client
    // cannot act on the two the same way.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/event/$nope"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "no such event");

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/!nope:example.org/event/{event_id}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "no such room");
}

#[tokio::test]
async fn a_state_change_is_visible_in_the_very_next_full_state_read() {
    // The full-state response is served from a render cache keyed by the
    // state root. The mutant this test exists to kill is the cache that
    // serves a render without comparing roots: read once to warm it, change
    // the state, and the very next read must show the change.
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room_id}/state"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic"),
            &token,
            &json!({ "topic": "after the warm read" }),
        )
        .await;

    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room_id}/state"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let topic = body
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.room.topic")
        .expect("the topic is state");
    assert_eq!(
        topic["content"]["topic"], "after the warm read",
        "a warmed render must not outlive its state root: {body}"
    );
}

#[tokio::test]
async fn an_empty_state_key_may_be_spelled_as_a_trailing_slash() {
    // matrix-bot-sdk — hookshot and most Node bots — URL-encodes the
    // empty state key as an empty final path segment. Complement's Go
    // client drops the segment instead, which is why only a real bridge
    // could find the 404; hookshot crashed on it.
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;

    let (status, with_slash) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.create/"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{with_slash}");
    let (_, without) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.create"),
            &token,
        )
        .await;
    assert_eq!(with_slash, without, "the two spellings are one endpoint");

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic/"),
            &token,
            &json!({ "topic": "set through the trailing slash" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, read_back) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic"),
            &token,
        )
        .await;
    assert_eq!(read_back["topic"], "set through the trailing slash");
}
