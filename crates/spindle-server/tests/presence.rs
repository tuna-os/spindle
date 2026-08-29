//! Presence: a user says whether they are around, and someone who shares a
//! room with them can ask.
//!
//! The gate is the part worth testing hardest. Presence is a continuous
//! signal about when a person is at their computer, so "any account on this
//! server can watch any other" is a real privacy answer, not a hypothetical
//! one — and it is the answer a server gets by *not* deciding.

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
        let app = spindle_server::app(config, store).unwrap();
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

    async fn set(&self, who: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/presence/@{who}:example.org/status"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, who: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/presence/@{who}:example.org/status"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn invite_and_join(&self, room: &str, host: &str, guest_name: &str, guest: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/invite"))
                    .header("authorization", format!("Bearer {host}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "user_id": format!("@{guest_name}:example.org") }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/join"))
                    .header("authorization", format!("Bearer {guest}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// The round trip, and the derived fields the spec asks for.
#[tokio::test]
async fn a_user_sets_their_own_presence_and_reads_it_back() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "writing tests" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "online");
    assert_eq!(body["status_msg"], "writing tests");
    assert_eq!(
        body["currently_active"], true,
        "someone who just said they are online is currently active: {body}"
    );
    assert!(
        body["last_active_ago"].as_u64().unwrap_or(u64::MAX) < 10_000,
        "the duration is since the row was written, not the row's timestamp: {body}"
    );
}

/// A user nobody has heard from is offline, not an error and not absent.
#[tokio::test]
async fn a_user_who_never_set_presence_is_offline() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "offline");
    assert_eq!(body["currently_active"], false);
    assert!(
        body.get("status_msg").is_none(),
        "no message was ever set, so the key is absent rather than null: {body}"
    );
}

/// Only "online" is currently active. Idle is recent but not present, and
/// conflating the two would make a client's away indicator never appear.
#[tokio::test]
async fn only_online_counts_as_currently_active() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    for state in ["unavailable", "offline"] {
        let (status, body) = harness
            .set("alice", &alice, &json!({ "presence": state }))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = harness.get("alice", &alice).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["presence"], state);
        assert_eq!(
            body["currently_active"], false,
            "{state} was reported as currently active: {body}"
        );
    }
}

/// The gate: a stranger cannot watch you.
#[tokio::test]
async fn a_stranger_cannot_read_your_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;

    let (status, body) = harness.get("alice", &mallory).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "presence leaked to someone sharing no room: {body}"
    );
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

/// And the other half: someone you share a room with can.
///
/// Asserted alongside the refusal because a gate that refuses everyone is
/// also "secure", and would break every client that renders an online dot.
#[tokio::test]
async fn someone_in_your_room_can_read_your_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;
    harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;

    let (status, body) = harness.get("alice", &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "online");
}

/// You cannot set someone else's presence — otherwise marking a rival
/// offline is a one-request denial of service against every client that
/// renders their status.
#[tokio::test]
async fn you_cannot_set_another_users_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;

    let (status, body) = harness
        .set("alice", &bob, &json!({ "presence": "offline" }))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Bob set Alice's presence: {body}"
    );

    // Sharing a room is enough to *read*, and still not enough to write.
    let (status, body) = harness.get("alice", &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["presence"], "offline",
        "the default, not Bob's write: {body}"
    );
}

/// An unknown state is refused rather than stored and echoed. A server that
/// accepted "busy" would be inventing protocol, and the client that sent it
/// would have no way to learn nobody else understands it.
#[tokio::test]
async fn an_unknown_presence_state_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .set("alice", &alice, &json!({ "presence": "busy" }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_JSON");
}

/// An empty message clears one rather than storing a blank.
#[tokio::test]
async fn an_empty_status_message_clears_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "here" }),
        )
        .await;
    harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "" }),
        )
        .await;

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("status_msg").is_none(),
        "the cleared message came back as a blank one: {body}"
    );
}
