//! Read receipts, and the unread count they define.
//!
//! The design point: **the unread boundary is arithmetic.** Every accepted
//! event holds a linear index and the occupied range is contiguous — backfill
//! fills `0, -1, -2, …` while live events fill `1, 2, 3, …`, so the two meet
//! rather than leaving a hole. "Which events come after this one" is therefore
//! a comparison against `li`, not an ordering of a graph. A DAG server has to
//! establish that order before it can answer at all.
//!
//! What still costs is deciding which of those events *notify*, because the
//! sender lives in the event body. That is a scan of a contiguous range, and
//! these tests pin down what it counts and what it does not.

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

    /// A room alice and bob are both in.
    async fn shared_room(&self, alice: &str, bob: &str) -> String {
        let (_, created) = self
            .post("/_matrix/client/v3/createRoom", alice, &json!({}))
            .await;
        let room_id = created["room_id"].as_str().unwrap().to_owned();
        self.post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
        self.post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            bob,
            &json!({}),
        )
        .await;
        room_id
    }

    async fn say(&self, room_id: &str, token: &str, text: &str, txn: &str) -> String {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn unread(&self, token: &str, room_id: &str) -> u64 {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rooms"]["join"][room_id]["unread_notifications"]["notification_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("no unread count for {room_id}: {body}"))
    }
}

#[tokio::test]
async fn a_receipt_moves_the_unread_boundary() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.shared_room(&alice, &bob).await;

    let first = harness.say(&room_id, &alice, "one", "a1").await;
    harness.say(&room_id, &alice, "two", "a2").await;
    harness.say(&room_id, &alice, "three", "a3").await;
    assert_eq!(harness.unread(&bob, &room_id).await, 3);

    // Read up to the first: two left.
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{first}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.unread(&bob, &room_id).await, 2);

    // Read to the end: none.
    let last = harness.say(&room_id, &alice, "four", "a4").await;
    assert_eq!(harness.unread(&bob, &room_id).await, 3);
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{last}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(harness.unread(&bob, &room_id).await, 0);

    // Alice's own messages never counted for her.
    assert_eq!(harness.unread(&alice, &room_id).await, 0);
}

#[tokio::test]
async fn your_own_messages_and_state_changes_do_not_notify_you() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.shared_room(&alice, &bob).await;

    // Bob talks to himself.
    for index in 0..5 {
        harness
            .say(&room_id, &bob, "thinking aloud", &format!("b{index}"))
            .await;
    }
    assert_eq!(
        harness.unread(&bob, &room_id).await,
        0,
        "a user's own messages notified them"
    );
    // Alice sees them, though -- otherwise this test would pass with counting
    // switched off entirely.
    assert_eq!(harness.unread(&alice, &room_id).await, 5);

    // A state change from alice is not a notification for bob.
    let before = harness.unread(&bob, &room_id).await;
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "a new topic" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness.unread(&bob, &room_id).await,
        before,
        "a state change was counted as a notification"
    );
}

#[tokio::test]
async fn read_markers_set_both_the_private_and_the_public_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.shared_room(&alice, &bob).await;

    let first = harness.say(&room_id, &alice, "one", "a1").await;
    let second = harness.say(&room_id, &alice, "two", "a2").await;
    assert_eq!(harness.unread(&bob, &room_id).await, 2);

    // `m.read` is what the count is measured from; `m.fully_read` is the
    // private line and must not move it on its own.
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/read_markers"),
            &bob,
            &json!({ "m.fully_read": second }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness.unread(&bob, &room_id).await,
        2,
        "m.fully_read moved the public unread count"
    );

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/read_markers"),
            &bob,
            &json!({ "m.read": first }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.unread(&bob, &room_id).await, 1);
}

#[tokio::test]
async fn a_receipt_for_an_event_this_room_does_not_have_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room_id = harness.shared_room(&alice, &bob).await;
    let other = harness.shared_room(&alice, &bob).await;
    let elsewhere = harness.say(&other, &alice, "over here", "o1").await;

    // A receipt naming an event the room does not hold would put the unread
    // boundary at a position that means nothing -- silently, and forever.
    for event_id in ["$nonsense", elsewhere.as_str()] {
        let (status, body) = harness
            .post(
                &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}"),
                &bob,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{event_id}: {body}");
    }

    harness.say(&room_id, &alice, "still unread", "a1").await;
    assert_eq!(
        harness.unread(&bob, &room_id).await,
        1,
        "a refused receipt moved the boundary anyway"
    );
}

#[tokio::test]
async fn receipts_are_per_user_and_per_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let first = harness.shared_room(&alice, &bob).await;
    let second = harness.shared_room(&alice, &bob).await;

    let read_this = harness.say(&first, &alice, "in the first", "f1").await;
    harness.say(&second, &alice, "in the second", "s1").await;

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{first}/receipt/m.read/{read_this}"),
            &bob,
            &json!({}),
        )
        .await;

    // One room read, the other not: the key carries the room.
    assert_eq!(harness.unread(&bob, &first).await, 0);
    assert_eq!(harness.unread(&bob, &second).await, 1);

    // And two people in the *same* room keep separate positions. This needs
    // bob to be the one talking: alice's own messages never count for her, so
    // a version of this test where alice speaks reports zero for her whether
    // or not the receipts collide, and cannot tell the two apart.
    let shared = harness.shared_room(&alice, &bob).await;
    harness.say(&shared, &bob, "one", "s1").await;
    let last = harness.say(&shared, &bob, "two", "s2").await;
    assert_eq!(harness.unread(&alice, &shared).await, 2);

    // Bob marks the room read for *himself*. Alice has read nothing, so her
    // count must not move -- if the receipt key omitted the user, bob's
    // receipt would answer alice's lookup and silently zero her badge.
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{shared}/receipt/m.read/{last}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(
        harness.unread(&alice, &shared).await,
        2,
        "one user's receipt cleared another user's unread count"
    );
}
