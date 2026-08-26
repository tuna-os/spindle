//! Who is typing, right now.
//!
//! Typing is the clearest case in the API of state that is *not* an event: no
//! linear index, never in the log, worthless a minute later. Most of what is
//! worth testing follows from that — it does not survive a restart, it does
//! not appear in the timeline, and it reaches a long-polling client even
//! though there is nothing in the log to discover.
//!
//! The subtle one is `a_refreshed_typing_notice_does_not_wake_a_long_poll`.
//! Clients re-send `typing: true` every few seconds to refresh the timeout,
//! and a server that woke every sync in the room each time would answer
//! instantly, be re-polled instantly, and burn a phone's battery for as long
//! as the conversation lasted.

use std::sync::Arc;
use std::time::Duration;

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
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
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

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
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
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn admit(&self, room: &str, host: &str, guest: &str, user_id: &str) {
        self.post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            host,
            &json!({ "user_id": user_id }),
        )
        .await;
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                guest,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn typing(&self, room: &str, token: &str, user_id: &str, body: &Value) -> StatusCode {
        self.put(
            &format!("/_matrix/client/v3/rooms/{room}/typing/{user_id}"),
            token,
            body,
        )
        .await
        .0
    }

    async fn sync(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// Who a sync response says is typing in `room`.
fn typists(sync: &Value, room: &str) -> Vec<String> {
    sync["rooms"]["join"][room]["ephemeral"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|event| event["type"] == "m.typing")
                .flat_map(|event| {
                    event["content"]["user_ids"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                })
                .map(|id| id.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn typing_appears_in_sync_and_stops_when_told_to() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    assert!(typists(&harness.sync(&alice).await, &room).is_empty());

    assert_eq!(
        harness
            .typing(
                &room,
                &bob,
                "@bob:example.org",
                &json!({ "typing": true, "timeout": 30_000 })
            )
            .await,
        StatusCode::OK
    );
    assert_eq!(
        typists(&harness.sync(&alice).await, &room),
        vec!["@bob:example.org"]
    );

    assert_eq!(
        harness
            .typing(&room, &bob, "@bob:example.org", &json!({ "typing": false }))
            .await,
        StatusCode::OK
    );
    assert!(typists(&harness.sync(&alice).await, &room).is_empty());
}

#[tokio::test]
async fn typing_is_never_an_event_in_the_timeline() {
    // The property the whole design rests on: nothing was appended, so the
    // room's log is exactly as long as it was.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let before = harness.sync(&alice).await["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .unwrap()
        .len();

    harness
        .typing(
            &room,
            &alice,
            "@alice:example.org",
            &json!({ "typing": true }),
        )
        .await;

    let after = harness.sync(&alice).await;
    assert_eq!(
        after["rooms"]["join"][&room]["timeline"]["events"]
            .as_array()
            .unwrap()
            .len(),
        before,
        "typing must append nothing: {after}"
    );
    let (status, messages) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?limit=100"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{messages}");
    assert!(
        !messages.to_string().contains("m.typing"),
        "no m.typing in the timeline: {messages}"
    );
}

#[tokio::test]
async fn typing_does_not_survive_a_restart() {
    // Correct rather than unfortunate: anyone still typing says so again
    // within seconds, and a notification restored from disk would be a claim
    // about the present that is no longer true.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());

    let harness = Harness {
        _dir: TempDir::new().unwrap(),
        app: Harness::build(Arc::clone(&store)),
    };
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness
        .typing(
            &room,
            &alice,
            "@alice:example.org",
            &json!({ "typing": true, "timeout": 120_000 }),
        )
        .await;
    assert_eq!(
        typists(&harness.sync(&alice).await, &room),
        vec!["@alice:example.org"]
    );

    let restarted = Harness {
        _dir: TempDir::new().unwrap(),
        app: Harness::build(store),
    };
    assert!(
        typists(&restarted.sync(&alice).await, &room).is_empty(),
        "a restart forgets who was typing"
    );
}

#[tokio::test]
async fn a_notice_expires_on_its_own() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    harness
        .typing(
            &room,
            &alice,
            "@alice:example.org",
            &json!({ "typing": true, "timeout": 50 }),
        )
        .await;
    assert_eq!(
        typists(&harness.sync(&alice).await, &room),
        vec!["@alice:example.org"]
    );

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        typists(&harness.sync(&alice).await, &room).is_empty(),
        "an expired notice must not be reported, with no sweeper having run"
    );
}

#[tokio::test]
async fn you_can_only_say_that_you_are_typing_and_only_where_you_are() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    assert_eq!(
        harness
            .typing(
                &room,
                &bob,
                "@alice:example.org",
                &json!({ "typing": true })
            )
            .await,
        StatusCode::FORBIDDEN,
        "bob must not be able to type as alice"
    );
    assert!(
        typists(&harness.sync(&alice).await, &room).is_empty(),
        "a refused request must not have half-happened"
    );

    let carol = harness.register("carol").await;
    assert_eq!(
        harness
            .typing(
                &room,
                &carol,
                "@carol:example.org",
                &json!({ "typing": true })
            )
            .await,
        StatusCode::FORBIDDEN,
        "a non-member must not be able to type into a room"
    );
    assert!(typists(&harness.sync(&alice).await, &room).is_empty());
}

#[tokio::test]
async fn an_over_long_timeout_is_clamped_rather_than_refused() {
    // The number is a hint about a person's hands, not a protocol invariant:
    // a client sending an hour means "a long time".
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    assert_eq!(
        harness
            .typing(
                &room,
                &alice,
                "@alice:example.org",
                &json!({ "typing": true, "timeout": 3_600_000_u64 })
            )
            .await,
        StatusCode::OK
    );
    assert_eq!(
        typists(&harness.sync(&alice).await, &room),
        vec!["@alice:example.org"]
    );
}

#[tokio::test]
async fn several_typists_come_back_in_a_stable_order() {
    // A client diffs this list against the one it holds, so a HashMap's order
    // would make an unchanged set look changed on every read.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;

    for (token, user) in [
        (&carol, "@carol:example.org"),
        (&alice, "@alice:example.org"),
        (&bob, "@bob:example.org"),
    ] {
        harness
            .typing(&room, token, user, &json!({ "typing": true }))
            .await;
    }

    let expected = vec![
        "@alice:example.org".to_owned(),
        "@bob:example.org".to_owned(),
        "@carol:example.org".to_owned(),
    ];
    for _ in 0..5 {
        assert_eq!(typists(&harness.sync(&alice).await, &room), expected);
    }
}

#[tokio::test]
async fn one_rooms_typing_does_not_appear_in_another() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.create_room(&alice).await;
    let second = harness.create_room(&alice).await;

    harness
        .typing(
            &first,
            &alice,
            "@alice:example.org",
            &json!({ "typing": true }),
        )
        .await;

    let sync = harness.sync(&alice).await;
    assert_eq!(typists(&sync, &first), vec!["@alice:example.org"]);
    assert!(
        typists(&sync, &second).is_empty(),
        "the other room has nobody typing: {sync}"
    );
}

#[tokio::test]
async fn a_long_poll_wakes_when_someone_starts_typing() {
    // There is nothing in the log to discover, so without the typing arm of
    // the wait a client would learn that someone started typing only when they
    // stopped and sent the message.
    let harness = Arc::new(Harness::new());
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let since = harness.sync(&alice).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let poller = {
        let harness = Arc::clone(&harness);
        let alice = alice.clone();
        tokio::spawn(async move {
            harness
                .get(
                    &format!("/_matrix/client/v3/sync?since={since}&timeout=10000"),
                    &alice,
                )
                .await
        })
    };

    tokio::time::sleep(Duration::from_millis(100)).await;
    harness
        .typing(&room, &bob, "@bob:example.org", &json!({ "typing": true }))
        .await;

    let (status, body) = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("the poll must return well before its own timeout")
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        typists(&body, &room),
        vec!["@bob:example.org"],
        "the woken sync must carry the typing notice: {body}"
    );
}

#[tokio::test]
async fn a_refreshed_typing_notice_does_not_wake_a_long_poll() {
    // Clients re-send `typing: true` every few seconds to refresh the timeout.
    // Waking every sync in the room each time would answer instantly, be
    // re-polled instantly, and burn a phone's battery for the length of the
    // conversation. Only a *change* in who is typing is news.
    let harness = Arc::new(Harness::new());
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness
        .typing(
            &room,
            &bob,
            "@bob:example.org",
            &json!({ "typing": true, "timeout": 30_000 }),
        )
        .await;
    let since = harness.sync(&alice).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let poller = {
        let harness = Arc::clone(&harness);
        let alice = alice.clone();
        tokio::spawn(async move {
            harness
                .get(
                    &format!("/_matrix/client/v3/sync?since={since}&timeout=1000"),
                    &alice,
                )
                .await
        })
    };

    // Three refreshes of a notice that is already set: no change, no news.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        harness
            .typing(
                &room,
                &bob,
                "@bob:example.org",
                &json!({ "typing": true, "timeout": 30_000 }),
            )
            .await;
    }

    let started = std::time::Instant::now();
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("the poll must still finish")
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "a refresh must not have woken the poll early: returned after {:?}",
        started.elapsed()
    );
}
