//! Transaction-ID idempotency on `/send` and `/redact`.
//!
//! The retry that matters is the one after a timeout: the client cannot know
//! whether its send landed, so it asks again with the same transaction ID,
//! and the server must answer with the same event rather than a new one. A
//! server that ignores the ID turns every flaky connection into duplicate
//! messages — which is what this server did until now.

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
        Self {
            app: Self::build(store),
            _dir: dir,
        }
    }

    fn build(store: Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        spindle_server::app(config, store).expect("a signing key is established")
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

    /// A second device for the same account.
    async fn login(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "type": "m.login.password",
                            "identifier": { "type": "m.id.user", "user": username },
                            "password": "hunter2",
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

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .request("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, room: &str, token: &str, txn: &str, text: &str) -> (StatusCode, Value) {
        self.request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
            token,
            &json!({ "msgtype": "m.text", "body": text }),
        )
        .await
    }

    async fn count_messages(&self, room: &str, token: &str) -> usize {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?limit=100"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["type"] == "m.room.message")
            .count()
    }
}

#[tokio::test]
async fn a_retried_send_returns_the_same_event_and_mints_nothing() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, first) = harness.send(&room, &alice, "txn1", "hello").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = harness.send(&room, &alice, "txn1", "hello").await;
    assert_eq!(status, StatusCode::OK, "{second}");

    assert_eq!(
        first["event_id"], second["event_id"],
        "the retry must answer with the original event"
    );
    assert_eq!(
        harness.count_messages(&room, &alice).await,
        1,
        "and must not have minted a second one"
    );
}

#[tokio::test]
async fn different_transaction_ids_are_different_sends() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (_, first) = harness.send(&room, &alice, "txn1", "one").await;
    let (_, second) = harness.send(&room, &alice, "txn2", "two").await;
    assert_ne!(first["event_id"], second["event_id"]);
    assert_eq!(harness.count_messages(&room, &alice).await, 2);
}

#[tokio::test]
async fn the_scope_is_the_device_not_the_user() {
    // The spec scopes transaction IDs to a device: two devices may reuse an
    // ID and mean different sends. A user-scoped table would silently swallow
    // the second device's message and hand it the first device's event ID.
    let harness = Harness::new();
    let alice_phone = harness.register("alice").await;
    let alice_laptop = harness.login("alice").await;
    let room = harness.create_room(&alice_phone).await;

    let (_, from_phone) = harness
        .send(&room, &alice_phone, "txn1", "from phone")
        .await;
    let (status, from_laptop) = harness
        .send(&room, &alice_laptop, "txn1", "from laptop")
        .await;
    assert_eq!(status, StatusCode::OK, "{from_laptop}");
    assert_ne!(
        from_phone["event_id"], from_laptop["event_id"],
        "the same txn ID on another device is another send"
    );
    assert_eq!(harness.count_messages(&room, &alice_phone).await, 2);
}

#[tokio::test]
async fn a_refused_send_is_not_replayed_as_a_refusal() {
    // Only success is recorded. Recording the failure would replay the error
    // forever; recording nothing lets the retry succeed once the state that
    // refused it changes.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;

    // Bob is not in the room, so this send is refused.
    let (status, body) = harness.send(&room, &bob, "txn1", "let me in").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Now he is, and the *same transaction* is retried. It must succeed
    // rather than replay the refusal.
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &bob,
            &json!({}),
        )
        .await;
    let (status, body) = harness.send(&room, &bob, "txn1", "let me in").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["event_id"].is_string());
}

#[tokio::test]
async fn a_replayed_redaction_mints_no_second_redaction() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let (_, sent) = harness.send(&room, &alice, "m1", "delete me").await;
    let target = sent["event_id"].as_str().unwrap();

    let redact = |txn: &'static str| {
        let harness = &harness;
        let alice = &alice;
        let room = &room;
        let target = target.to_owned();
        async move {
            harness
                .request(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room}/redact/{target}/{txn}"),
                    alice,
                    &json!({ "reason": "gone" }),
                )
                .await
        }
    };

    let (status, first) = redact("r1").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = redact("r1").await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(first["event_id"], second["event_id"]);
}

#[tokio::test]
async fn replay_survives_a_restart() {
    // The retry that matters most arrives after a crash: the client cannot
    // know whether its send landed, which is exactly when the server must.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (token, room, first_id) = {
        let harness = Harness {
            _dir: TempDir::new().unwrap(),
            app: Harness::build(Arc::clone(&store)),
        };
        let alice = harness.register("alice").await;
        let room = harness.create_room(&alice).await;
        let (_, body) = harness
            .send(&room, &alice, "txn1", "before the crash")
            .await;
        (alice, room, body["event_id"].as_str().unwrap().to_owned())
    };

    let restarted = Harness {
        _dir: TempDir::new().unwrap(),
        app: Harness::build(store),
    };
    let (status, body) = restarted
        .send(&room, &token, "txn1", "before the crash")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["event_id"], first_id,
        "the replay table must be durable, not in-memory"
    );
    assert_eq!(restarted.count_messages(&room, &token).await, 1);
}
