//! Relations: edits, reactions, threads.
//!
//! SPEC §7 gives the index as `(room_id, target_event_id, rel_type, li)`, and
//! the tail of that key is the point. A prefix scan returns a target's
//! relations **already in the order they were sent**, with nothing doing the
//! sorting — the same property `/messages` rests on, applied to a different
//! question. A DAG server has to establish that order itself.
//!
//! The original event is never mutated (SPEC §10.5): an edit is a new event
//! that points at the old one, and aggregation happens at read time.

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
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
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
                            "auth": { "type": "m.login.dummy" },
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

    async fn room(&self, token: &str) -> String {
        let (_, created) = self
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        created["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(
        &self,
        room: &str,
        token: &str,
        kind: &str,
        txn: &str,
        content: &Value,
    ) -> String {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/send/{kind}/{txn}"),
                token,
                content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn react(&self, room: &str, token: &str, target: &str, key: &str, txn: &str) -> String {
        self.send(
            room,
            token,
            "m.reaction",
            txn,
            &json!({
                "m.relates_to": {
                    "rel_type": "m.annotation",
                    "event_id": target,
                    "key": key,
                }
            }),
        )
        .await
    }

    async fn relations(&self, token: &str, path: &str) -> Value {
        let (status, body) = self.get(path, token).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }
}

fn ids(body: &Value) -> Vec<String> {
    body["chunk"]
        .as_array()
        .expect("a chunk")
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn relations_come_back_in_the_order_they_were_sent() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"hi"}),
        )
        .await;

    let mut sent = Vec::new();
    for (index, key) in ["👍", "🎉", "😀", "🚀", "❤"].iter().enumerate() {
        sent.push(
            harness
                .react(&room, &token, &target, key, &format!("r{index}"))
                .await,
        );
    }

    // Oldest first, and asserted in order rather than as a set: the index key
    // ends in `li`, so this order is the storage order and nothing sorts it.
    let body = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
        )
        .await;
    assert_eq!(ids(&body), sent, "relations came back out of order");
}

#[tokio::test]
async fn relations_can_be_narrowed_by_type_and_by_event_type() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"hi"}),
        )
        .await;

    let reaction = harness.react(&room, &token, &target, "👍", "r0").await;
    let edit = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "e0",
            &json!({
                "msgtype": "m.text",
                "body": "* corrected",
                "m.new_content": { "msgtype": "m.text", "body": "corrected" },
                "m.relates_to": { "rel_type": "m.replace", "event_id": target },
            }),
        )
        .await;
    let threaded = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "th0",
            &json!({
                "msgtype": "m.text",
                "body": "in the thread",
                "m.relates_to": { "rel_type": "m.thread", "event_id": target },
            }),
        )
        .await;

    let all = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
        )
        .await;
    assert_eq!(
        ids(&all),
        vec![reaction.clone(), edit.clone(), threaded.clone()]
    );

    for (rel_type, expected) in [
        ("m.annotation", &reaction),
        ("m.replace", &edit),
        ("m.thread", &threaded),
    ] {
        let body = harness
            .relations(
                &token,
                &format!("/_matrix/client/v1/rooms/{room}/relations/{target}/{rel_type}"),
            )
            .await;
        assert_eq!(ids(&body), vec![expected.clone()], "{rel_type}");
    }

    // Narrowed further by event type: the edit is an m.room.message, the
    // reaction is not, so asking for messages under m.annotation is empty
    // rather than wrong.
    let body = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}/m.replace/m.room.message"),
        )
        .await;
    assert_eq!(ids(&body), vec![edit]);

    let body = harness
        .relations(
            &token,
            &format!(
                "/_matrix/client/v1/rooms/{room}/relations/{target}/m.annotation/m.room.message"
            ),
        )
        .await;
    assert!(ids(&body).is_empty(), "{body}");
}

/// The original is never mutated (SPEC §10.5). An edit is a new event that
/// points at the old one; aggregation is a read-time question.
#[tokio::test]
async fn an_edit_does_not_touch_the_event_it_edits() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"orignal"}),
        )
        .await;

    harness
        .send(
            &room,
            &token,
            "m.room.message",
            "e0",
            &json!({
                "msgtype": "m.text",
                "body": "* original",
                "m.new_content": { "msgtype": "m.text", "body": "original" },
                "m.relates_to": { "rel_type": "m.replace", "event_id": target },
            }),
        )
        .await;

    let (_, event) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{target}"),
            &token,
        )
        .await;
    assert_eq!(
        event["content"]["body"], "orignal",
        "the edit rewrote the original: {event}"
    );
}

/// Redacting a reaction removes it. `m.relates_to` lives in `content`, which
/// redaction strips, so the event stops being a relation — and a client
/// counting reactions must stop counting it.
#[tokio::test]
async fn a_redacted_relation_stops_relating() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"hi"}),
        )
        .await;

    let kept = harness.react(&room, &token, &target, "👍", "r0").await;
    let doomed = harness.react(&room, &token, &target, "👎", "r1").await;

    let body = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
        )
        .await;
    assert_eq!(ids(&body), vec![kept.clone(), doomed.clone()]);

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{doomed}/x1"),
            &token,
            &json!({}),
        )
        .await;

    let body = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
        )
        .await;
    assert_eq!(
        ids(&body),
        vec![kept],
        "a redacted reaction is still counted: {body}"
    );
}

#[tokio::test]
async fn relations_paginate_with_the_same_token_kind_as_messages() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"hi"}),
        )
        .await;

    let mut sent = Vec::new();
    for index in 0..9 {
        sent.push(
            harness
                .react(
                    &room,
                    &token,
                    &target,
                    &format!("k{index}"),
                    &format!("r{index}"),
                )
                .await,
        );
    }

    let mut seen = Vec::new();
    let mut from: Option<String> = None;
    for _ in 0..10 {
        let path = match &from {
            Some(cursor) => {
                format!("/_matrix/client/v1/rooms/{room}/relations/{target}?limit=4&from={cursor}")
            }
            None => format!("/_matrix/client/v1/rooms/{room}/relations/{target}?limit=4"),
        };
        let body = harness.relations(&token, &path).await;
        seen.extend(ids(&body));
        match body["next_batch"].as_str() {
            Some(next) => {
                assert!(next.starts_with('t'), "not a pagination token: {next}");
                from = Some(next.to_owned());
            }
            None => break,
        }
    }
    assert_eq!(seen, sent, "pagination lost or duplicated a relation");

    // A sync token is refused here for the same reason it is on /messages.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}?from=s3"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn an_unknown_room_is_not_an_event_with_no_relations() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "t0",
            &json!({"msgtype":"m.text","body":"hi"}),
        )
        .await;

    // An event nobody replied to: empty, and that is an answer.
    let body = harness
        .relations(
            &token,
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
        )
        .await;
    assert!(ids(&body).is_empty(), "{body}");

    // A room that does not exist is not an answer.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/!nope:example.org/relations/{target}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
