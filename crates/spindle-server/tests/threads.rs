//! `/threads`: the room's thread roots, most recently active first.
//!
//! The endpoint's ordering is by *latest reply*, not by when the root was
//! sent, so a thread started first can be listed last and usually is. That
//! key is the tail of the relation index — one prefix scan over the room
//! hands back every relation in log order, and a target's last row is its
//! latest reply — so the list is read, not maintained.
//!
//! `include=participated` is the spec's definition and Synapse's: the viewer
//! replied in the thread, **or** sent the root. Both halves are tested,
//! because either one alone passes a test that only exercises the other.

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

    async fn send(
        &self,
        room: &str,
        token: &str,
        kind: &str,
        txn: &str,
        content: &Value,
    ) -> String {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/send/{kind}/{txn}"),
                token,
                content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn react(&self, room: &str, token: &str, target: &str, key: &str, txn: &str) -> String {
        self.send(
            room,
            token,
            "m.reaction",
            txn,
            &json!({
                "m.relates_to": {
                    "rel_type": "m.annotation",
                    "event_id": target,
                    "key": key,
                }
            }),
        )
        .await
    }
}

fn ids(body: &Value) -> Vec<String> {
    body["chunk"]
        .as_array()
        .expect("a chunk")
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect()
}

impl Harness {
    async fn admit(&self, room: &str, host: &str, guest: &str, user_id: &str) {
        self.post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            host,
            &json!({ "user_id": user_id }),
        )
        .await;
        self.post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            guest,
            &json!({}),
        )
        .await;
    }

    /// A message in `target`'s thread.
    async fn reply(&self, room: &str, token: &str, target: &str, txn: &str) -> String {
        self.send(
            room,
            token,
            "m.room.message",
            txn,
            &json!({
                "msgtype": "m.text",
                "body": txn,
                "m.relates_to": { "rel_type": "m.thread", "event_id": target },
            }),
        )
        .await
    }

    async fn threads(&self, token: &str, room: &str, query: &str) -> Value {
        let path = format!("/_matrix/client/v1/rooms/{room}/threads{query}");
        let (status, body) = self.get(&path, token).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }
}

#[tokio::test]
async fn threads_are_listed_by_latest_reply_not_by_root() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let first = harness
        .send(&room, &token, "m.room.message", "r1", &text("first root"))
        .await;
    let second = harness
        .send(&room, &token, "m.room.message", "r2", &text("second root"))
        .await;

    // Reply to the *older* root last. By root order the answer is
    // [second, first]; by latest reply it is [first, second] reversed --
    // which is the whole point of the endpoint's sort key.
    harness.reply(&room, &token, &second, "a").await;
    harness.reply(&room, &token, &first, "b").await;

    let body = harness.threads(&token, &room, "").await;
    assert_eq!(
        ids(&body),
        vec![first, second],
        "the thread replied to most recently comes first"
    );
}

#[tokio::test]
async fn a_thread_root_carries_its_aggregate() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let target = harness
        .send(&room, &token, "m.room.message", "r", &text("root"))
        .await;
    harness.reply(&room, &token, &target, "a").await;
    let latest = harness.reply(&room, &token, &target, "b").await;

    let body = harness.threads(&token, &room, "").await;
    let thread = &body["chunk"][0]["unsigned"]["m.relations"]["m.thread"];
    assert_eq!(thread["count"], 2, "{body}");
    assert_eq!(
        thread["latest_event"]["event_id"].as_str(),
        Some(latest.as_str()),
        "the bundle's latest_event is the reply the list sorted on: {body}"
    );
}

#[tokio::test]
async fn an_event_with_no_replies_is_not_a_thread() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let lonely = harness
        .send(
            &room,
            &token,
            "m.room.message",
            "r",
            &text("nobody replied"),
        )
        .await;
    // A reaction is a relation but not a thread, so an event carrying one
    // must still not appear: the filter is on rel_type, not on having
    // relations at all.
    harness.react(&room, &token, &lonely, "👍", "x").await;

    let body = harness.threads(&token, &room, "").await;
    assert!(ids(&body).is_empty(), "{body}");
}

#[tokio::test]
async fn participated_includes_a_thread_the_viewer_only_replied_in() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let hers = harness
        .send(&room, &alice, "m.room.message", "r1", &text("alice's root"))
        .await;
    let theirs = harness
        .send(&room, &alice, "m.room.message", "r2", &text("untouched"))
        .await;
    harness.reply(&room, &alice, &theirs, "a").await;
    // Bob replies in Alice's thread but starts none of his own.
    harness.reply(&room, &bob, &hers, "b").await;

    let all = harness.threads(&bob, &room, "").await;
    assert_eq!(all["chunk"].as_array().unwrap().len(), 2, "{all}");

    let mine = harness.threads(&bob, &room, "?include=participated").await;
    assert_eq!(ids(&mine), vec![hers], "{mine}");
}

#[tokio::test]
async fn participated_includes_a_thread_the_viewer_only_started() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    // Bob's root, replied to only by Alice. Starting a thread is
    // participating in it -- the half of the rule that a reply-only test
    // cannot see.
    let bobs = harness
        .send(&room, &bob, "m.room.message", "r1", &text("bob's root"))
        .await;
    harness.reply(&room, &alice, &bobs, "a").await;

    let alices = harness
        .send(&room, &alice, "m.room.message", "r2", &text("alice's root"))
        .await;
    harness.reply(&room, &alice, &alices, "b").await;

    let mine = harness.threads(&bob, &room, "?include=participated").await;
    assert_eq!(ids(&mine), vec![bobs], "{mine}");
}

#[tokio::test]
async fn the_bundle_agrees_with_the_participated_filter() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let bobs = harness
        .send(&room, &bob, "m.room.message", "r", &text("bob's root"))
        .await;
    harness.reply(&room, &alice, &bobs, "a").await;

    // The filter let this through on the strength of Bob starting it, so
    // the aggregate it carries must say so too. A client that hides
    // threads whose bundle reads false would otherwise render an empty
    // list from a non-empty response.
    let mine = harness.threads(&bob, &room, "?include=participated").await;
    assert_eq!(
        mine["chunk"][0]["unsigned"]["m.relations"]["m.thread"]["current_user_participated"],
        json!(true),
        "{mine}"
    );
}

#[tokio::test]
async fn paging_walks_every_thread_exactly_once() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let mut targets = Vec::new();
    for index in 0..5 {
        let target = harness
            .send(
                &room,
                &token,
                "m.room.message",
                &format!("r{index}"),
                &text("root"),
            )
            .await;
        harness
            .reply(&room, &token, &target, &format!("a{index}"))
            .await;
        targets.push(target);
    }
    // Newest reply first, and the replies went out in root order.
    targets.reverse();

    let mut seen = Vec::new();
    let mut query = "?limit=2".to_owned();
    // Bounded rather than `loop`: a token that fails to advance is a real
    // defect, and the test has to *fail* on it rather than page forever.
    // Five threads at two a page is three requests; ten is slack enough to
    // distinguish "stuck" from "one more page than expected".
    let mut pages = 0;
    while pages < 10 {
        pages += 1;
        let page = harness.threads(&token, &room, &query).await;
        seen.extend(ids(&page));
        let Some(next) = page["next_batch"].as_str() else {
            break;
        };
        assert_ne!(
            query,
            format!("?limit=2&from={next}"),
            "next_batch repeated itself -- paging would never terminate"
        );
        query = format!("?limit=2&from={next}");
    }
    assert!(pages < 10, "paging did not terminate");
    assert_eq!(seen, targets, "every thread once, in order, across pages");
}

#[tokio::test]
async fn a_redacted_reply_stops_counting_toward_its_thread() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let older = harness
        .send(&room, &token, "m.room.message", "r1", &text("older"))
        .await;
    let newer = harness
        .send(&room, &token, "m.room.message", "r2", &text("newer"))
        .await;
    harness.reply(&room, &token, &newer, "a").await;
    // Sent last, so while it stands `older` sorts first.
    let doomed = harness.reply(&room, &token, &older, "b").await;

    assert_eq!(ids(&harness.threads(&token, &room, "").await)[0], older);

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/redact/{doomed}/t1"),
            &token,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Redaction strips `m.relates_to`, so that reply is no longer in the
    // thread -- and `older`, having no replies left, is no longer a thread.
    assert_eq!(
        ids(&harness.threads(&token, &room, "").await),
        vec![newer],
        "a thread whose only reply was redacted stops being one"
    );
}

#[tokio::test]
async fn an_unknown_include_is_refused_rather_than_ignored() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let room = harness.room(&token).await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/threads?include=mine"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn an_unknown_room_is_not_an_empty_thread_list() {
    let harness = Harness::new();
    let token = harness.register("alice").await;

    let (status, body) = harness
        .get("/_matrix/client/v1/rooms/!nope:example.org/threads", &token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

fn text(body: &str) -> Value {
    json!({ "msgtype": "m.text", "body": body })
}
