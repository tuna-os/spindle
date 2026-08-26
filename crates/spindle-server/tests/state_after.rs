//! MSC4222's `state_after`.
//!
//! The MSC exists because `state` is ambiguous: it promises the state
//! *before* the timeline, so a client that received a gapped sync cannot tell
//! what the state is *now* without replaying the gap it never got.
//!
//! For this server the fix is a rename rather than a computation. The state
//! block is read from the head entry's own materialized snapshot, so it has
//! always been the state at the *end* of the timeline — which is what
//! `state_after` is defined to mean. What was wrong was the label.

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

    async fn sync(&self, token: &str, query: &str) -> Value {
        let (status, body) = self
            .get(&format!("/_matrix/client/v3/sync{query}"), token)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// The topic in whichever state block the response carries.
fn topic(sync: &Value, room: &str, block: &str) -> Option<String> {
    sync["rooms"]["join"][room][block]["events"]
        .as_array()?
        .iter()
        .find(|event| event["type"] == "m.room.topic")
        .and_then(|event| event["content"]["topic"].as_str())
        .map(str::to_owned)
}

#[tokio::test]
async fn without_the_flag_the_block_is_still_called_state() {
    // The default must not move: a client that has never heard of MSC4222
    // reads `state`, and renaming it unasked would break every one of them.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let sync = harness.sync(&alice, "").await;
    assert!(
        sync["rooms"]["join"][&room]["state"].is_object(),
        "state block missing: {sync}"
    );
    assert!(
        sync["rooms"]["join"][&room]["state_after"].is_null(),
        "state_after must not appear unasked: {sync}"
    );
}

#[tokio::test]
async fn the_flag_renames_the_block() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let sync = harness.sync(&alice, "?use_state_after=true").await;
    assert!(
        sync["rooms"]["join"][&room]["state_after"].is_object(),
        "state_after missing: {sync}"
    );
    assert!(
        sync["rooms"]["join"][&room]["state"].is_null(),
        "the two must not both appear -- a client would apply the state twice: {sync}"
    );
}

#[tokio::test]
async fn the_unstable_spelling_works_too() {
    // The MSC shipped in clients before it was adopted, so both spellings are
    // in the wild and a server that took only the stable one would silently
    // ignore the flag for exactly the clients that implemented it first.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let sync = harness
        .sync(&alice, "?org.matrix.msc4222.use_state_after=true")
        .await;
    assert!(
        sync["rooms"]["join"][&room]["state_after"].is_object(),
        "{sync}"
    );

    // And it is advertised, which is what a client checks before sending it.
    let (_, versions) = harness.get("/_matrix/client/versions", &alice).await;
    assert_eq!(
        versions["unstable_features"]["org.matrix.msc4222.use_state_after"],
        true
    );
}

#[tokio::test]
async fn false_is_not_true() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let sync = harness.sync(&alice, "?use_state_after=false").await;
    assert!(
        sync["rooms"]["join"][&room]["state"].is_object(),
        "an explicit false is the default, not the opt-in: {sync}"
    );
}

#[tokio::test]
async fn the_block_holds_the_state_at_the_end_of_the_timeline() {
    // The property the rename claims. The topic is set twice; what comes back
    // must be the *second* value, because that is the state after the
    // timeline rather than before it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    for topic_text in ["first topic", "second topic"] {
        let (status, body) = harness
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
                &alice,
                &json!({ "topic": topic_text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let sync = harness.sync(&alice, "?use_state_after=true").await;
    assert_eq!(
        topic(&sync, &room, "state_after").as_deref(),
        Some("second topic"),
        "state_after is the state *after* the timeline: {sync}"
    );

    // And the unflagged block carries the same value, which is the point of
    // the commit message: this server was already sending state-after under
    // the name `state`. The flag corrects the label, not the content.
    let unflagged = harness.sync(&alice, "").await;
    assert_eq!(
        topic(&unflagged, &room, "state").as_deref(),
        Some("second topic"),
        "the content was always state-after; only the name was wrong"
    );
}

#[tokio::test]
async fn an_incremental_sync_carries_an_empty_state_after() {
    // Correct here, and worth stating why: this server's incremental timeline
    // is never gapped -- it returns everything since the token -- so every
    // state change is already in the timeline and there is nothing left for
    // `state_after` to add. MSC4222 exists for the gapped case, which this
    // server does not produce.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let since = harness.sync(&alice, "?use_state_after=true").await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "changed after the token" }),
        )
        .await;

    let sync = harness
        .sync(&alice, &format!("?since={since}&use_state_after=true"))
        .await;
    let after = &sync["rooms"]["join"][&room]["state_after"]["events"];
    assert_eq!(
        after.as_array().map(Vec::len),
        Some(0),
        "nothing to add: the change is in the timeline: {sync}"
    );

    let timeline = sync["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(
        timeline.iter().any(|event| event["type"] == "m.room.topic"
            && event["content"]["topic"] == "changed after the token"),
        "and it really is in the timeline: {timeline:?}"
    );
}
