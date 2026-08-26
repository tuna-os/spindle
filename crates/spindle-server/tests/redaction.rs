//! Redaction.
//!
//! Two things this file is really about.
//!
//! **The algorithm is ruma's.** Which keys survive a redaction is spec-defined
//! and version-dependent, so a second implementation is a second thing to keep
//! in step with the spec — the same argument `docs/divergence.md` §3 makes for
//! the auth rules. What is ours is when it runs and what is stored after.
//!
//! **Rewriting the stored event does not break anything.** A v11 event ID is
//! the reference hash of the *redacted* form, and `ChainHash::extend` covers
//! the event ID — so redacting changes neither the ID nor the chain. That is
//! the property asserted at the bottom, and the same one that lets an admin
//! purge event bodies without destroying the integrity construction (#83).

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

#[tokio::test]
async fn redacting_strips_the_content_and_leaves_the_event() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness.say(&room, &token, "regrettable", "t1").await;

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{target}/r1"),
            &token,
            &json!({ "reason": "spam" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let redaction = body["event_id"].as_str().unwrap().to_owned();

    let (status, event) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{target}"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{event}");

    // The content is gone.
    assert_eq!(event["content"], json!({}), "content survived: {event}");
    assert!(
        !serde_json::to_string(&event)
            .unwrap()
            .contains("regrettable"),
        "the redacted text is still in the stored event: {event}"
    );

    // The event is not: type, sender, room and the ID all remain, because a
    // client has to render a tombstone in the timeline rather than a hole.
    assert_eq!(event["type"], "m.room.message");
    assert_eq!(event["sender"], "@alice:example.org");
    assert_eq!(event["room_id"], room);
    assert_eq!(event["event_id"], target);

    // And why, which lives in `unsigned` -- not covered by the event ID, so
    // saying why cannot change what the event is.
    assert_eq!(event["unsigned"]["redacted_because"]["event_id"], redaction);
}

/// The property that makes rewriting the stored event safe: a v11 event ID is
/// the reference hash of the **redacted** form, so redacting does not change
/// it — and `ChainHash::extend` covers the ID, so the log chain is untouched.
#[tokio::test]
async fn a_redaction_changes_neither_the_event_id_nor_the_events_around_it() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let before = harness.say(&room, &token, "before", "t1").await;
    let target = harness.say(&room, &token, "doomed", "t2").await;
    let after = harness.say(&room, &token, "after", "t3").await;

    let ids = |body: &Value| -> Vec<String> {
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["event_id"].as_str().unwrap().to_owned())
            .collect()
    };
    let (_, timeline_before) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?limit=100"),
            &token,
        )
        .await;
    let ids_before = ids(&timeline_before);

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{target}/r1"),
            &token,
            &json!({}),
        )
        .await;

    let (_, timeline_after) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?limit=100"),
            &token,
        )
        .await;
    let ids_after = ids(&timeline_after);

    // Same events, same order, same IDs -- plus the redaction itself at the
    // head. The redacted event keeps its identity.
    assert_eq!(
        ids_after[1..],
        ids_before[..],
        "redaction disturbed the timeline"
    );
    assert!(ids_after.contains(&target), "the redacted event vanished");
    assert!(ids_after.contains(&before) && ids_after.contains(&after));

    // Neighbours are untouched.
    for (id, text) in [(&before, "before"), (&after, "after")] {
        let (_, event) = harness
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/event/{id}"),
                &token,
            )
            .await;
        assert_eq!(event["content"]["body"], text, "{event}");
    }
}

#[tokio::test]
async fn a_stranger_cannot_redact_and_an_unknown_event_cannot_be_redacted() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice).await;
    let target = harness.say(&room, &alice, "mine", "t1").await;

    // Bob is not in the room. The refusal is ruma's rules, not a check written
    // for this endpoint.
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{target}/r1"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // And the event survived that attempt.
    let (_, event) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{target}"),
            &alice,
        )
        .await;
    assert_eq!(event["content"]["body"], "mine", "{event}");

    // Redacting something this room does not have would mint an event that
    // refers to nothing -- and federate that nothing to every peer.
    for absent in ["$nonsense", "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let (status, body) = harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/redact/{absent}/r2"),
                &alice,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{absent}: {body}");
    }

    // The status code alone does not establish that. Without the check up
    // front, the redaction is appended and signed *first* and only then fails
    // on the missing body -- same 404, but the room is left holding a
    // redaction event pointing at nothing. So count the room, not the reply:
    // the four events `createRoom` emits, plus alice's one message, and no
    // redaction at all.
    let (_, timeline) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?limit=100"),
            &alice,
        )
        .await;
    let events = timeline["chunk"].as_array().unwrap();
    assert!(
        events
            .iter()
            .all(|event| event["type"] != "m.room.redaction"),
        "a refused redaction was appended anyway: {timeline}"
    );
    assert_eq!(events.len(), 5, "{timeline}");
}

/// Room v11 carries the target in `content.redacts` (MSC2174), not at the top
/// level as v1–v10 did. A peer reading the old location finds nothing.
#[tokio::test]
async fn the_redaction_names_its_target_where_room_v11_puts_it() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;
    let target = harness.say(&room, &token, "doomed", "t1").await;

    let (_, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{target}/r1"),
            &token,
            &json!({ "reason": "off topic" }),
        )
        .await;
    let redaction = body["event_id"].as_str().unwrap().to_owned();

    let (_, event) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{redaction}"),
            &token,
        )
        .await;
    assert_eq!(event["type"], "m.room.redaction");
    assert_eq!(event["content"]["redacts"], target, "{event}");
    assert_eq!(event["content"]["reason"], "off topic");
    assert!(
        event["redacts"].is_null(),
        "the v1-v10 top-level `redacts` is set on a v11 event: {event}"
    );
}

/// State survives redaction as state: the entry still points at the event, and
/// the room still has a topic slot even though its content is gone. A redacted
/// state event that vanished from state would silently un-set the room's name,
/// topic or join rules.
#[tokio::test]
async fn redacting_a_state_event_leaves_the_state_entry_in_place() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &token,
            &json!({ "topic": "a topic" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let topic_event = body["event_id"].as_str().unwrap().to_owned();

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{topic_event}/r1"),
            &token,
            &json!({}),
        )
        .await;

    let (status, state) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room}/state"), &token)
        .await;
    assert_eq!(status, StatusCode::OK, "{state}");
    let topic = state
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.room.topic")
        .expect("the topic state entry disappeared");
    assert_eq!(topic["event_id"], topic_event);
    assert_eq!(topic["content"], json!({}), "{topic}");
}
