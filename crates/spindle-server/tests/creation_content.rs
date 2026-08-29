//! `creation_content` on createRoom.
//!
//! It is how a client says what *kind* of room this is -- `type: "m.space"`
//! above all, which is the prerequisite for the spaces hierarchy -- and how
//! it sets `m.federate`. Most of the tests here are about the two keys a
//! client must NOT be able to set through it.

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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

impl Harness {
    async fn create(&self, token: &str, body: &Value) -> (StatusCode, Value) {
        self.request("POST", "/_matrix/client/v3/createRoom", Some(token), body)
            .await
    }

    async fn create_event(&self, token: &str, room: &str) -> Value {
        let (status, body) = self
            .request(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.create/"),
                Some(token),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// A space can be created, which is what the hierarchy endpoint will need.
#[tokio::test]
async fn a_space_can_be_created() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .create(
            &alice,
            &json!({ "creation_content": { "type": "m.space" } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    assert_eq!(harness.create_event(&alice, &room).await["type"], "m.space");
}

/// An ordinary room still has no `type`, rather than an empty one.
#[tokio::test]
async fn an_ordinary_room_has_no_type() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness.create(&alice, &json!({})).await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    assert!(
        harness
            .create_event(&alice, &room)
            .await
            .get("type")
            .is_none()
    );
}

/// Arbitrary content passes through -- `m.federate` is the other real user.
#[tokio::test]
async fn other_creation_content_passes_through() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .create(
            &alice,
            &json!({ "creation_content": { "m.federate": false } }),
        )
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    assert_eq!(
        harness.create_event(&alice, &room).await["m.federate"],
        false
    );
}

/// A client cannot set `room_version` through `creation_content`.
///
/// The version was negotiated by the outer field and refused rather than
/// substituted. A client that could overwrite it here would be describing a
/// room that is not the one being built -- and the room really is v11, so the
/// claim would be a lie the client could not detect until something that
/// depends on the version failed.
#[tokio::test]
async fn creation_content_cannot_claim_the_room_version() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .create(
            &alice,
            &json!({ "creation_content": { "room_version": "1", "type": "m.space" } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    let create = harness.create_event(&alice, &room).await;
    assert_eq!(
        create["room_version"], "11",
        "a client overwrote room_version"
    );
    // The rest of what they asked for still applied.
    assert_eq!(create["type"], "m.space");
}

/// A client cannot set `creator` through `creation_content`.
///
/// Before v12 `creator` is an authorization input, so a client that could set
/// it would be handing itself somebody else's privileges. The room is v11
/// here, which is exactly the version where the field still bites.
#[tokio::test]
async fn creation_content_cannot_claim_the_creator() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .create(
            &alice,
            &json!({ "creation_content": { "creator": "@mallory:example.org" } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    let create = harness.create_event(&alice, &room).await;
    assert_eq!(
        create["creator"], "@alice:example.org",
        "a client claimed somebody else as the room's creator"
    );
}
