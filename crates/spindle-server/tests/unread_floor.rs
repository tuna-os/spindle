//! Where the unread count starts counting from.
//!
//! This is a correctness question with a performance answer attached. A user
//! is not behind on what was said before they arrived, so the count starts at
//! their own membership event — and because it does, a new joiner's first
//! sync no longer walks the room's entire history to find out.
//!
//! Before that floor existed, `/sync` was the one endpoint whose cost grew
//! with room size: 3.3x from a 100-event room to a 1600-event one, while
//! send, join, `/messages` and `/state` all stayed flat. These tests pin the
//! behaviour that makes it flat, because a benchmark is not a CI gate.

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

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) -> String {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}: {body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn admit(&self, room: &str, host: &str, guest: &str, user_id: &str) {
        self.request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            host,
            &json!({ "user_id": user_id }),
        )
        .await;
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                guest,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn notifications(&self, room: &str, token: &str) -> u64 {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rooms"]["join"][room]["unread_notifications"]["notification_count"]
            .as_u64()
            .unwrap_or_else(|| panic!("no notification count in {body}"))
    }
}

#[tokio::test]
async fn a_new_joiner_is_not_behind_on_history_from_before_they_joined() {
    // The floor, stated directly. Without it the count is "every message in
    // the room", and finding that number means reading every event body.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;

    for index in 0..40 {
        harness
            .say(
                &room,
                &alice,
                &format!("before bob {index}"),
                &format!("b{index}"),
            )
            .await;
    }
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    assert_eq!(
        harness.notifications(&room, &bob).await,
        0,
        "forty messages bob was not there for are not forty things bob has missed"
    );
}

#[tokio::test]
async fn messages_sent_after_joining_do_count() {
    // The other half: the floor must not swallow everything.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "before", "b0").await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    for index in 0..3 {
        harness
            .say(
                &room,
                &alice,
                &format!("after {index}"),
                &format!("a{index}"),
            )
            .await;
    }

    assert_eq!(harness.notifications(&room, &bob).await, 3);
}

#[tokio::test]
async fn a_receipt_after_the_join_moves_the_count_forward() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let first = harness.say(&room, &alice, "one", "a1").await;
    harness.say(&room, &alice, "two", "a2").await;
    harness.say(&room, &alice, "three", "a3").await;
    assert_eq!(harness.notifications(&room, &bob).await, 3);

    let (status, body) = harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{first}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness.notifications(&room, &bob).await,
        2,
        "a receipt on the first of three leaves two"
    );
}

#[tokio::test]
async fn your_own_messages_are_not_unread_to_you() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness.say(&room, &bob, "mine", "m1").await;
    harness.say(&room, &alice, "hers", "h1").await;

    assert_eq!(
        harness.notifications(&room, &bob).await,
        1,
        "only alice's message is news to bob"
    );
}

#[tokio::test]
async fn rejoining_starts_the_count_again_from_the_rejoin() {
    // The floor is the *current* membership event, so a user who leaves and
    // comes back is not handed everything said while they were away. Nothing
    // else could be right: they were not in the room for it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    // A receipt *before* leaving, which is what makes this test bite. On the
    // rejoin that receipt sits below the new membership event, so taking the
    // receipt alone would count everything said while bob was away. Only the
    // later of the two is right, and without this line a mutant that ignored
    // the join entirely survived.
    let read = harness
        .say(&room, &alice, "read before leaving", "r0")
        .await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{read}"),
            &bob,
            &json!({}),
        )
        .await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;

    for index in 0..10 {
        harness
            .say(
                &room,
                &alice,
                &format!("while away {index}"),
                &format!("w{index}"),
            )
            .await;
    }
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    assert_eq!(
        harness.notifications(&room, &bob).await,
        0,
        "ten messages bob was away for are not ten things bob has missed"
    );

    harness.say(&room, &alice, "welcome back", "wb").await;
    assert_eq!(harness.notifications(&room, &bob).await, 1);
}

#[tokio::test]
async fn the_count_does_not_grow_with_history_the_user_missed() {
    // The performance property, asserted as behaviour rather than timing: two
    // rooms differing only in how much history preceded the join must report
    // the same count. A timing assertion would be flaky; this is exact, and it
    // fails for the same reason the slow version was slow.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let small = harness.create_room(&alice).await;
    for index in 0..5 {
        harness
            .say(&small, &alice, &format!("s{index}"), &format!("s{index}"))
            .await;
    }
    harness
        .admit(&small, &alice, &bob, "@bob:example.org")
        .await;

    let large = harness.create_room(&alice).await;
    for index in 0..200 {
        harness
            .say(&large, &alice, &format!("l{index}"), &format!("l{index}"))
            .await;
    }
    harness
        .admit(&large, &alice, &bob, "@bob:example.org")
        .await;

    harness.say(&small, &alice, "new in small", "ns").await;
    harness.say(&large, &alice, "new in large", "nl").await;

    assert_eq!(harness.notifications(&small, &bob).await, 1);
    assert_eq!(
        harness.notifications(&large, &bob).await,
        1,
        "forty times the history, the same count -- and the same work to find it"
    );
}

#[tokio::test]
async fn a_non_member_has_nothing_to_be_behind_on() {
    // Asserted against `Rooms` directly, because `/sync` only ever asks about
    // rooms the caller is joined to -- so this arm is unreachable through the
    // API and a mutant that deleted it survived every endpoint test.
    //
    // It still matters: `unread` is public, and without the early return a
    // caller who is not in the room gets `i64::MIN` as a floor and walks the
    // entire history to count messages that were never theirs. That is the
    // exact O(room) behaviour the floor exists to remove, reachable by the one
    // caller the floor cannot help.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), "example.org");
    let room = rooms
        .create("@alice:example.org", key.pair(), None, None)
        .unwrap();
    for index in 0..25 {
        rooms
            .send(
                &room,
                "@alice:example.org",
                key.pair(),
                "m.room.message",
                &json!({ "msgtype": "m.text", "body": format!("{index}") }),
            )
            .unwrap();
    }

    let unread = rooms.unread(&room, "@stranger:example.org").unwrap();
    assert_eq!(
        unread.notification_count, 0,
        "a stranger is not behind on a room they were never in"
    );
    assert!(unread.read_up_to.is_none());
}
