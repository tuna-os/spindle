//! Bundled aggregations — `unsigned.m.relations` (MSC2675).
//!
//! `unsigned` is the one part of an event's body the event ID does not cover,
//! which is why the bundle lives there: an aggregate changes every time
//! someone reacts, and anything under the hash must never change.

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
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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
            .request("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn admit(&self, room: &str, host: &str, guest: &str, user_id: &str) {
        self.request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            host,
            &json!({ "user_id": user_id }),
        )
        .await;
        self.request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            guest,
            &json!({}),
        )
        .await;
    }

    async fn send(&self, room: &str, token: &str, txn: &str, content: &Value) -> String {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn react(&self, room: &str, token: &str, txn: &str, target: &str, key: &str) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}"),
                token,
                &json!({ "m.relates_to": { "rel_type": "m.annotation", "event_id": target, "key": key } }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn event(&self, room: &str, token: &str, event_id: &str) -> Value {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

#[tokio::test]
async fn reactions_bundle_into_counts_by_key() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let target = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "hi" }),
        )
        .await;
    harness.react(&room, &alice, "r1", &target, "👍").await;
    harness.react(&room, &bob, "r2", &target, "👍").await;
    harness.react(&room, &bob, "r3", &target, "🎉").await;

    let event = harness.event(&room, &alice, &target).await;
    let chunk = event["unsigned"]["m.relations"]["m.annotation"]["chunk"]
        .as_array()
        .unwrap_or_else(|| panic!("no annotation chunk in {event}"));
    let count = |key: &str| {
        chunk
            .iter()
            .find(|entry| entry["key"] == key)
            .map(|entry| entry["count"].as_u64().unwrap())
    };
    assert_eq!(count("👍"), Some(2), "{chunk:?}");
    assert_eq!(count("🎉"), Some(1), "{chunk:?}");
}

#[tokio::test]
async fn the_latest_edit_rides_in_the_bundle() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let target = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "typo" }),
        )
        .await;
    for (txn, text) in [("e1", "first fix"), ("e2", "second fix")] {
        harness
            .send(
                &room,
                &alice,
                txn,
                &json!({
                    "msgtype": "m.text",
                    "body": format!("* {text}"),
                    "m.new_content": { "msgtype": "m.text", "body": text },
                    "m.relates_to": { "rel_type": "m.replace", "event_id": target },
                }),
            )
            .await;
    }

    let event = harness.event(&room, &alice, &target).await;
    let replace = &event["unsigned"]["m.relations"]["m.replace"];
    assert_eq!(
        replace["content"]["m.new_content"]["body"], "second fix",
        "the bundle carries the LATEST edit, whole: {replace}"
    );
    // And the original body is untouched — aggregation is read-time, the
    // stored event is never mutated.
    assert_eq!(event["content"]["body"], "typo");
}

#[tokio::test]
async fn threads_bundle_count_latest_and_participation() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let thread_root = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "thread me" }),
        )
        .await;
    for (token, txn, text) in [
        (&alice, "t1", "one"),
        (&alice, "t2", "two"),
        (&bob, "t3", "three"),
    ] {
        harness
            .send(
                &room,
                token,
                txn,
                &json!({
                    "msgtype": "m.text",
                    "body": text,
                    "m.relates_to": { "rel_type": "m.thread", "event_id": thread_root },
                }),
            )
            .await;
    }

    // Bob replied, so from bob's view he participated.
    let seen_by_bob = harness.event(&room, &bob, &thread_root).await;
    let thread = &seen_by_bob["unsigned"]["m.relations"]["m.thread"];
    assert_eq!(thread["count"], 3, "{thread}");
    assert_eq!(thread["latest_event"]["content"]["body"], "three");
    assert_eq!(thread["current_user_participated"], true);

    // Carol never spoke in it, so from carol's view she did not — the bundle
    // is viewer-dependent, which is why it cannot be stored in the event.
    let carol = harness.register("carol").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;
    let seen_by_carol = harness.event(&room, &carol, &thread_root).await;
    assert_eq!(
        seen_by_carol["unsigned"]["m.relations"]["m.thread"]["current_user_participated"],
        false
    );
}

#[tokio::test]
async fn an_event_with_no_relations_carries_no_bundle() {
    // Absent rather than empty: a client checks for the key, and an empty
    // object would make every event look like it has an aggregate to render.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let target = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "alone" }),
        )
        .await;

    let event = harness.event(&room, &alice, &target).await;
    assert!(event["unsigned"].get("m.relations").is_none(), "{event}");
}

#[tokio::test]
async fn a_redacted_reaction_leaves_the_count() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let target = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "hi" }),
        )
        .await;
    harness.react(&room, &alice, "r1", &target, "👍").await;

    // Find the reaction's event ID through /relations, then redact it.
    let (_, relations) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/relations/{target}"),
            &alice,
        )
        .await;
    let reaction_id = relations["chunk"][0]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/redact/{reaction_id}/rd1"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let event = harness.event(&room, &alice, &target).await;
    assert!(
        event["unsigned"].get("m.relations").is_none(),
        "a redacted reaction stops counting: {event}"
    );
}

#[tokio::test]
async fn messages_and_context_carry_the_same_bundle() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let target = harness
        .send(
            &room,
            &alice,
            "m1",
            &json!({ "msgtype": "m.text", "body": "hi" }),
        )
        .await;
    harness.react(&room, &alice, "r1", &target, "👍").await;

    let (_, messages) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?limit=50"),
            &alice,
        )
        .await;
    let in_messages = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["event_id"] == target.as_str())
        .unwrap_or_else(|| panic!("target not in {messages}"));
    assert_eq!(
        in_messages["unsigned"]["m.relations"]["m.annotation"]["chunk"][0]["count"], 1,
        "{in_messages}"
    );

    let (_, context) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{target}"),
            &alice,
        )
        .await;
    assert_eq!(
        context["event"]["unsigned"]["m.relations"]["m.annotation"]["chunk"][0]["count"], 1,
        "{context}"
    );
}
