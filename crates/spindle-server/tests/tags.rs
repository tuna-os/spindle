//! Room tags.
//!
//! Tags are not their own storage: the spec models them as the `m.tag` room
//! account-data event, and the endpoints are views over it. The property
//! worth testing is exactly that — a tag set through `/tags` appears in
//! `/sync`'s per-room account data with no extra machinery, because there is
//! only one value and two doors to it.

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
}

fn tag_path(room: &str, tag: &str) -> String {
    format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/tags/{tag}")
}

fn tags_path(room: &str) -> String {
    format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/tags")
}

#[tokio::test]
async fn a_tag_round_trips_with_its_order() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .request(
            "PUT",
            &tag_path(&room, "m.favourite"),
            &alice,
            &json!({ "order": 0.25 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.get(&tags_path(&room), &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tags"]["m.favourite"]["order"], 0.25);
}

#[tokio::test]
async fn no_tags_is_an_empty_map_not_a_404() {
    // The endpoint's shape is fixed and a client iterates the map
    // unconditionally — unlike general account data, where unset is a 404.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness.get(&tags_path(&room), &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "tags": {} }));
}

#[tokio::test]
async fn deleting_a_tag_removes_only_that_tag() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    for tag in ["m.favourite", "u.work"] {
        harness
            .request("PUT", &tag_path(&room, tag), &alice, &json!({}))
            .await;
    }
    let (status, body) = harness
        .request(
            "DELETE",
            &tag_path(&room, "m.favourite"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, body) = harness.get(&tags_path(&room), &alice).await;
    assert!(body["tags"].get("m.favourite").is_none(), "{body}");
    assert!(body["tags"].get("u.work").is_some(), "{body}");

    // Deleting it again is the spec's 404, and must not have side effects.
    let (status, _) = harness
        .request(
            "DELETE",
            &tag_path(&room, "m.favourite"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = harness.get(&tags_path(&room), &alice).await;
    assert!(body["tags"].get("u.work").is_some(), "{body}");
}

#[tokio::test]
async fn a_tag_appears_in_syncs_room_account_data() {
    // The point of storing tags as m.tag: one value, two doors.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness
        .request(
            "PUT",
            &tag_path(&room, "m.favourite"),
            &alice,
            &json!({ "order": 0.5 }),
        )
        .await;

    let (status, sync) = harness.get("/_matrix/client/v3/sync", &alice).await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    let events = sync["rooms"]["join"][&room]["account_data"]["events"]
        .as_array()
        .unwrap();
    let tag_event = events
        .iter()
        .find(|event| event["type"] == "m.tag")
        .unwrap_or_else(|| panic!("no m.tag in {events:?}"));
    assert_eq!(tag_event["content"]["tags"]["m.favourite"]["order"], 0.5);
}

#[tokio::test]
async fn tags_are_per_room_and_per_user() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let first = harness.create_room(&alice).await;
    let second = harness.create_room(&alice).await;

    harness
        .request("PUT", &tag_path(&first, "m.favourite"), &alice, &json!({}))
        .await;

    let (_, body) = harness.get(&tags_path(&second), &alice).await;
    assert_eq!(body["tags"], json!({}), "the other room is untagged");

    // Bob may not read alice's tags.
    let (status, body) = harness.get(&tags_path(&first), &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}
