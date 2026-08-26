//! Invite, join and leave.
//!
//! What is worth noticing about this file is how little of it is about
//! permission. Nothing in `rooms.rs` decides whether a join is allowed —
//! `crate::authorize` runs the spec's own rules, so "you were not invited to
//! an invite-only room" is ruma refusing, not a check written here. These
//! tests assert that the refusals happen, which is the same thing as asserting
//! the rules are actually wired in.

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

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
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

    async fn joined(&self, token: &str) -> Vec<String> {
        let (status, body) = self.get("/_matrix/client/v3/joined_rooms", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["joined_rooms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect()
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn an_invited_user_can_join_and_an_uninvited_one_cannot() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.create_room(&alice).await;

    // `createRoom` sets `join_rule: invite`, so this is refused by the join
    // rules rather than by anything in our code.
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
    assert!(harness.joined(&bob).await.is_empty());

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An invite is not a membership: bob is invited, not joined, and
    // `/joined_rooms` must not conflate the two.
    assert!(
        harness.joined(&bob).await.is_empty(),
        "an invite is not a join"
    );

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id);
    assert_eq!(harness.joined(&bob).await, vec![room_id.clone()]);

    // And joining is what makes writing possible -- the same request that was
    // refused before the join now succeeds.
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            &bob,
            &json!({ "msgtype": "m.text", "body": "hello from bob" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn leaving_a_room_gives_up_the_ability_to_write_to_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.create_room(&alice).await;

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(harness.joined(&bob).await, vec![room_id.clone()]);

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Gone from the index -- this is the end-to-end version of the membership
    // filter that could only be unit-tested until `/leave` existed.
    assert!(
        harness.joined(&bob).await.is_empty(),
        "a room bob left is still listed as one he is in"
    );

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn2"),
            &bob,
            &json!({ "msgtype": "m.text", "body": "one more thing" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Alice is unaffected: one member leaving is not the room ending.
    assert_eq!(harness.joined(&alice).await, vec![room_id.clone()]);
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn3"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "still here" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_stranger_cannot_invite_and_an_unknown_room_cannot_be_joined() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let _carol = harness.register("carol").await;
    let room_id = harness.create_room(&alice).await;

    // Bob is not in the room, so he has no standing to invite anyone into it.
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            &bob,
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A room that does not exist is not joinable, and the answer says so
    // rather than inventing one.
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/rooms/!nope:example.org/join",
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");

    // Aliases do not resolve yet. The truthful answer for a name this server
    // cannot resolve is "not found", not a room.
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/join/%23general%3Aexample.org",
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn joining_by_id_through_the_alias_endpoint_works() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.create_room(&alice).await;

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;

    let encoded = room_id.replace('!', "%21").replace(':', "%3A");
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/join/{encoded}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id);
    assert_eq!(harness.joined(&bob).await, vec![room_id]);
}
