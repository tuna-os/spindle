//! `/context` — what a permalink resolves to.
//!
//! SPEC §10.5 states it in one line: "`/context` is a symmetric scan around it
//! and `state_at(li)` for the state block". Both halves are cheap here, and
//! for different reasons worth separating.
//!
//! The **window** is arithmetic: `li - n ..= li + n` over a contiguous range,
//! because ordering was decided once at write. The **state** is a rehydrate of
//! the content address the log entry already carries — so it works at any
//! depth, not only inside the resident window, and a permalink to a very old
//! message gets the state people actually had then rather than today's.

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
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
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

    async fn room(&self, token: &str) -> String {
        let (_, created) = self
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        created["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) -> String {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }
}

fn bodies(events: &Value) -> Vec<String> {
    events
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

#[tokio::test]
async fn the_window_is_symmetric_around_the_event() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let mut ids = Vec::new();
    for index in 0..11 {
        ids.push(
            harness
                .say(&room, &token, &format!("m{index}"), &format!("t{index}"))
                .await,
        );
    }
    let middle = &ids[5];

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{middle}?limit=4"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["event"]["event_id"], *middle);
    // `events_before` is newest-first, walking away from the event.
    assert_eq!(bodies(&body["events_before"]), vec!["m4", "m3"]);
    // `events_after` is oldest-first, likewise.
    assert_eq!(bodies(&body["events_after"]), vec!["m6", "m7"]);

    // Both edges are pagination tokens of the same kind /messages issues, so a
    // client can carry on outwards from either.
    for edge in ["start", "end"] {
        let token = body[edge]
            .as_str()
            .unwrap_or_else(|| panic!("no {edge}: {body}"));
        assert!(
            token.starts_with('t'),
            "{edge} is not a pagination token: {token}"
        );
    }
}

#[tokio::test]
async fn the_window_stops_at_the_ends_of_the_room() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let first = harness.say(&room, &token, "first", "t0").await;
    let last = harness.say(&room, &token, "last", "t1").await;

    // Asking for a wide window around the newest event: nothing after it.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{last}?limit=50"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["events_after"].as_array().unwrap().is_empty(),
        "there is nothing after the newest event: {body}"
    );
    // And before it: the first message plus the four create-sequence events.
    assert_eq!(body["events_before"].as_array().unwrap().len(), 5, "{body}");

    // Around the *first* message: the create sequence before, `last` after.
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{first}?limit=50"),
            &token,
        )
        .await;
    assert_eq!(bodies(&body["events_after"]), vec!["last"]);
}

/// The state block is the room as it was *there*, not as it is now. That is
/// the half a DAG server pays for: it has to walk state-group deltas, while
/// every entry here already carries the content address of its own state.
#[tokio::test]
async fn the_state_block_is_the_state_at_that_point_not_the_state_now() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &token,
            &json!({ "topic": "the old topic" }),
        )
        .await;
    let pinned = harness.say(&room, &token, "pinned", "t0").await;

    // The topic changes afterwards, twice.
    for topic in ["an interim topic", "the current topic"] {
        harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
                &token,
                &json!({ "topic": topic }),
            )
            .await;
    }

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{pinned}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let topic = body["state"]
        .as_array()
        .expect("a state block")
        .iter()
        .find(|event| event["type"] == "m.room.topic")
        .unwrap_or_else(|| panic!("no topic in the state block: {body}"));
    assert_eq!(
        topic["content"]["topic"], "the old topic",
        "the state block shows the topic as it is now, not as it was: {topic}"
    );

    // And the room really has moved on, so the assertion above is not just
    // reading a room that never changed.
    let (_, current) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &token,
        )
        .await;
    assert_eq!(current["topic"], "the current topic");
}

/// Beyond the resident window the snapshot has been evicted, and the state is
/// rebuilt from content-addressed nodes instead. A permalink into deep history
/// must still answer — this is the case that separates "we kept it in memory"
/// from "we can reconstruct it".
#[tokio::test]
async fn state_is_rebuilt_for_an_event_far_outside_the_resident_window() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &token,
            &json!({ "topic": "ancient" }),
        )
        .await;
    let ancient = harness.say(&room, &token, "ancient message", "t0").await;

    // DEFAULT_RESIDENT_WINDOW is 512, so this pushes the snapshot out of it.
    for index in 0..600 {
        harness
            .say(
                &room,
                &token,
                &format!("filler {index}"),
                &format!("f{index}"),
            )
            .await;
    }
    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &token,
            &json!({ "topic": "modern" }),
        )
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{ancient}?limit=2"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["event"]["event_id"], ancient);

    let topic = body["state"]
        .as_array()
        .expect("a state block")
        .iter()
        .find(|event| event["type"] == "m.room.topic")
        .unwrap_or_else(|| panic!("no topic in the state block: {body}"));
    assert_eq!(
        topic["content"]["topic"], "ancient",
        "state outside the resident window was not rebuilt correctly: {topic}"
    );
}

/// Inside a room the caller can read, a missing event says so.
///
/// This used to assert that a missing *room* said so too, which was a better
/// error message and a room-ID oracle: 404 for "no such room" against 403 for
/// "not yours" answers, for anyone who asks, which room IDs this server
/// holds. The read guard now answers both the same way, which is also what
/// Synapse does. The distinction is kept where it is free -- a caller who may
/// read the room is told plainly that the event is not in it.
#[tokio::test]
async fn a_missing_event_says_so_and_a_missing_room_does_not() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let known = harness.say(&room, &token, "here", "t0").await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/$nope"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "no such event");

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/!nope:example.org/context/{known}"),
            &token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a room this caller is not in must not be distinguishable from one \
         that does not exist: {body}"
    );

    // And unauthenticated is unauthenticated.
    let (status, _) = harness
        .call(
            Request::builder()
                .uri(format!("/_matrix/client/v3/rooms/{room}/context/{known}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
