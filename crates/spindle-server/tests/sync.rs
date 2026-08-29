//! `/sync`, and the token discipline it forces.
//!
//! `/sync` is the one endpoint that needs an order *across* rooms, which the
//! linear index does not give: `li` orders events within a room and says
//! nothing about two rooms' events relative to each other. So SPEC §10.2's
//! global stream exists for exactly this, and a sync token is a position in
//! it — a different thing from a `/messages` token, which is a position in one
//! room's `li`. Both are opaque to clients, so the only mistake a client can
//! make is handing back the wrong one; the tests below say that is a 400 with
//! a reason rather than a silently wrong answer.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = Self::build(&store);
        Self { dir, store, app }
    }

    fn build(store: &Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        spindle_server::app(config, Arc::clone(store)).expect("a signing key is established")
    }

    /// A second server over the same store.
    ///
    /// Shares the handle rather than reopening the directory, which fjall 3
    /// locks while any handle lives. The stream counter this test is about is
    /// re-read from the stored rows whenever a server is built, so the claim
    /// survives -- see `restart.rs` for the fuller note.
    fn restart(&mut self) {
        self.app = Self::build(&self.store);
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
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room_id: &str, token: &str, text: &str, txn: &str) {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn sync(&self, token: &str, since: Option<&str>) -> Value {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?since={since}"),
            None => "/_matrix/client/v3/sync".to_owned(),
        };
        let (status, body) = self.get(&path, token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn bodies(room: &Value) -> Vec<String> {
    room["timeline"]["events"]
        .as_array()
        .expect("a timeline")
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

#[tokio::test]
async fn an_initial_sync_gives_state_and_a_tail_and_an_incremental_one_gives_the_difference() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;
    harness.say(&room_id, &token, "before", "t0").await;

    let initial = harness.sync(&token, None).await;
    let since = initial["next_batch"].as_str().expect("a token").to_owned();
    assert!(since.starts_with('s'), "{since}");

    let room = &initial["rooms"]["join"][&room_id];
    assert!(!room.is_null(), "the joined room is missing: {initial}");
    assert_eq!(bodies(room), vec!["before"]);
    // Initial sync carries state; a client has nothing to render the room from
    // otherwise.
    let kinds: Vec<&str> = room["state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"m.room.create"), "{room}");
    assert!(kinds.contains(&"m.room.member"), "{room}");

    // Nothing has happened since, so the room is absent rather than present
    // and empty -- a client diffing what it was sent would read an empty
    // timeline as a change.
    let quiet = harness.sync(&token, Some(&since)).await;
    assert!(
        quiet["rooms"]["join"].as_object().unwrap().is_empty(),
        "{quiet}"
    );

    harness.say(&room_id, &token, "after", "t1").await;
    let incremental = harness.sync(&token, Some(&since)).await;
    let room = &incremental["rooms"]["join"][&room_id];
    assert_eq!(bodies(room), vec!["after"], "{incremental}");
    // Only the difference: the earlier message is not sent again.
    assert_eq!(
        room["state"]["events"].as_array().unwrap().len(),
        0,
        "incremental sync repeated the state: {room}"
    );
}

/// The reason the global stream exists. `li` orders events inside one room and
/// says nothing across rooms, so two rooms both at `li = 5` are not the same
/// moment. A sync token has to order them anyway.
#[tokio::test]
async fn one_token_orders_events_across_rooms() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let first = harness.create_room(&token).await;
    let second = harness.create_room(&token).await;

    let since = harness.sync(&token, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    // Interleaved across the two rooms.
    harness.say(&first, &token, "first-1", "a").await;
    harness.say(&second, &token, "second-1", "b").await;
    harness.say(&first, &token, "first-2", "c").await;

    let incremental = harness.sync(&token, Some(&since)).await;
    let join = incremental["rooms"]["join"].as_object().unwrap();
    assert_eq!(join.len(), 2, "{incremental}");
    assert_eq!(bodies(&join[&first]), vec!["first-1", "first-2"]);
    assert_eq!(bodies(&join[&second]), vec!["second-1"]);

    // And the token advances past all of them, so a follow-up is quiet.
    let next = incremental["next_batch"].as_str().unwrap().to_owned();
    let quiet = harness.sync(&token, Some(&next)).await;
    assert!(
        quiet["rooms"]["join"].as_object().unwrap().is_empty(),
        "{quiet}"
    );
}

#[tokio::test]
async fn a_token_from_the_other_endpoint_is_refused_with_a_reason() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;
    harness.say(&room_id, &token, "hello", "t0").await;

    let sync_token = harness.sync(&token, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, messages) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=1"),
            &token,
        )
        .await;
    let page_token = messages["end"].as_str().expect("an end token").to_owned();
    assert!(page_token.starts_with('t'), "{page_token}");
    assert!(
        messages["start"].as_str().unwrap().starts_with('t'),
        "{messages}"
    );

    // A sync token handed to /messages.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?from={sync_token}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("`s` token"),
        "the error does not say which token was given: {body}"
    );

    // And a pagination token handed to /sync.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/sync?since={page_token}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("`t` token"),
        "{body}"
    );

    // Something neither endpoint minted.
    let (status, body) = harness
        .get("/_matrix/client/v3/sync?since=banana", &token)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn an_invite_shows_up_as_an_invite_and_not_as_a_joined_room() {
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

    let sync = harness.sync(&bob, None).await;
    assert!(
        sync["rooms"]["join"].as_object().unwrap().is_empty(),
        "an invite was reported as a join: {sync}"
    );
    assert!(
        sync["rooms"]["invite"][&room_id].is_object(),
        "the invite is missing: {sync}"
    );

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            &bob,
            &json!({}),
        )
        .await;
    let sync = harness.sync(&bob, None).await;
    assert!(sync["rooms"]["join"][&room_id].is_object(), "{sync}");
    assert!(
        sync["rooms"]["invite"].as_object().unwrap().is_empty(),
        "still invited after joining: {sync}"
    );
}

/// The stream counter is on disk, not only in memory. One that restarted at
/// zero would re-issue ids that already name other events, overwriting them --
/// worse than forgetting, because `/sync` would then deliver the wrong room's
/// events for a token a client still holds.
#[tokio::test]
async fn the_global_stream_survives_a_restart() {
    let mut harness = Harness::new();
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;
    harness.say(&room_id, &token, "before", "t0").await;

    let since = harness.sync(&token, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness.restart();

    harness.say(&room_id, &token, "after", "t1").await;
    let incremental = harness.sync(&token, Some(&since)).await;
    let room = &incremental["rooms"]["join"][&room_id];
    assert_eq!(
        bodies(room),
        vec!["after"],
        "the stream did not continue across the restart: {incremental}"
    );

    // The new token is strictly beyond the old one, which it would not be if
    // the counter had restarted.
    let next = incremental["next_batch"].as_str().unwrap().to_owned();
    let (old, new) = (
        since.trim_start_matches('s').parse::<u64>().unwrap(),
        next.trim_start_matches('s').parse::<u64>().unwrap(),
    );
    assert!(new > old, "the stream went backwards: {since} -> {next}");
}

#[tokio::test]
async fn a_long_poll_returns_as_soon_as_something_happens() {
    let harness = Arc::new(Harness::new());
    let token = harness.register("alice").await;
    let room_id = harness.create_room(&token).await;
    let since = harness.sync(&token, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let waiting = {
        let harness = Arc::clone(&harness);
        let token = token.clone();
        let since = since.clone();
        tokio::spawn(async move {
            harness
                .get(
                    &format!("/_matrix/client/v3/sync?since={since}&timeout=30000"),
                    &token,
                )
                .await
        })
    };

    // Give the poll a moment to block, then say something.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    harness.say(&room_id, &token, "wake up", "t1").await;

    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .expect("the long poll did not return when an event landed")
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(bodies(&body["rooms"]["join"][&room_id]), vec!["wake up"]);
}
