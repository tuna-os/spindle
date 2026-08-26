//! `/sync`'s leave section.
//!
//! Two things make this more than bookkeeping.
//!
//! The first is that a left room keeps receiving events, so the timeline has
//! to stop at the departing user's own departure. Without that cap, leaving a
//! room would hand the departed member everything said afterwards — the one
//! thing leaving is supposed to prevent.
//!
//! The second is that this is where forgetting finally becomes visible. A
//! forgotten room is one the user asked to stop seeing, and the leave section
//! is the only place it would otherwise keep turning up.

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

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}: {body}");
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

/// The message bodies in a room's leave-section timeline.
fn left_bodies(sync: &Value, room: &str) -> Vec<String> {
    sync["rooms"]["leave"][room]["timeline"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter_map(|event| event["content"]["body"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn left_rooms(sync: &Value) -> Vec<String> {
    sync["rooms"]["leave"]
        .as_object()
        .map(|rooms| rooms.keys().cloned().collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_left_room_appears_in_the_leave_section_with_the_departure() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;

    let sync = harness.sync(&bob, None).await;
    assert_eq!(left_rooms(&sync), vec![room.clone()]);
    assert!(
        sync["rooms"]["join"].as_object().unwrap().is_empty(),
        "a left room is not a joined one: {sync}"
    );
    let events = sync["rooms"]["leave"][&room]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(events.len(), 1, "the departure itself: {events:?}");
    assert_eq!(events[0]["type"], "m.room.member");
    assert_eq!(events[0]["content"]["membership"], "leave");
    assert_eq!(events[0]["state_key"], "@bob:example.org");
}

#[tokio::test]
async fn the_leave_timeline_stops_at_the_departure() {
    // The one that matters. A left room keeps receiving events, and an
    // incremental sync scans the global stream — so without a cap the
    // departed member is handed everything said after they left.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness.say(&room, &alice, "before bob leaves", "t1").await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    harness.say(&room, &alice, "after bob leaves", "t2").await;
    harness.say(&room, &alice, "and again", "t3").await;

    let sync = harness.sync(&bob, Some(&since)).await;
    let bodies = left_bodies(&sync, &room);
    assert!(
        bodies.contains(&"before bob leaves".to_owned()),
        "what was said while bob was there is his to see: {sync}"
    );
    assert!(
        !bodies.contains(&"after bob leaves".to_owned())
            && !bodies.contains(&"and again".to_owned()),
        "what was said after bob left is not: {sync}"
    );
}

#[tokio::test]
async fn a_forgotten_room_disappears_from_the_leave_section() {
    // Forgetting is a user asking to stop seeing a room, and this is the only
    // place it would otherwise keep turning up.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;

    assert_eq!(
        left_rooms(&harness.sync(&bob, None).await),
        vec![room.clone()]
    );

    let (status, body) = harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert!(
        left_rooms(&harness.sync(&bob, None).await).is_empty(),
        "a forgotten room is gone from the user's view"
    );

    // And alice's view of her own room is untouched, because forgetting is
    // bookkeeping rather than a change to the room.
    let alices = harness.sync(&alice, None).await;
    assert!(
        alices["rooms"]["join"]
            .as_object()
            .unwrap()
            .contains_key(&room)
    );
}

#[tokio::test]
async fn a_banned_user_is_in_the_leave_section_too() {
    // Ban and leave are different memberships — the auth rules need them to be
    // — but for /sync they are the same section: either way the user is out.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/ban"),
            &alice,
            &json!({ "user_id": "@bob:example.org", "reason": "spam" }),
        )
        .await;

    let sync = harness.sync(&bob, None).await;
    assert_eq!(left_rooms(&sync), vec![room.clone()]);
    let events = sync["rooms"]["leave"][&room]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(events[0]["content"]["membership"], "ban");
    assert_eq!(events[0]["content"]["reason"], "spam");
}

#[tokio::test]
async fn a_kicked_user_learns_of_the_kick_on_the_next_incremental_sync() {
    // Without the leave section they never would: they are no longer joined,
    // so the room is skipped and the kick — an event about them — is the one
    // event they never receive.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@bob:example.org", "reason": "off topic" }),
        )
        .await;

    let sync = harness.sync(&bob, Some(&since)).await;
    let events = sync["rooms"]["leave"][&room]["timeline"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no leave timeline in {sync}"));
    let kick = events
        .iter()
        .find(|event| event["type"] == "m.room.member")
        .unwrap_or_else(|| panic!("no membership event in {events:?}"));
    assert_eq!(kick["content"]["membership"], "leave");
    assert_eq!(kick["content"]["reason"], "off topic");
    assert_eq!(
        kick["sender"], "@alice:example.org",
        "a kick is a leave someone else sent, and the sender is how bob knows"
    );
}

#[tokio::test]
async fn an_incremental_sync_says_nothing_about_a_room_left_long_ago() {
    // Same rule the joined section follows: a client diffing what it was sent
    // against what it knows would read an unchanged room as a change.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;

    let since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    harness.say(&room, &alice, "life goes on", "t1").await;

    let sync = harness.sync(&bob, Some(&since)).await;
    assert!(
        left_rooms(&sync).is_empty(),
        "nothing changed for bob, so the leave section is silent: {sync}"
    );
}

#[tokio::test]
async fn rejoining_moves_a_room_back_out_of_the_leave_section() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(
        left_rooms(&harness.sync(&bob, None).await),
        vec![room.clone()]
    );

    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let sync = harness.sync(&bob, None).await;
    assert!(left_rooms(&sync).is_empty(), "bob is back in: {sync}");
    assert!(
        sync["rooms"]["join"]
            .as_object()
            .unwrap()
            .contains_key(&room),
        "and the room is joined: {sync}"
    );
}

#[tokio::test]
async fn the_leave_section_carries_no_state_block() {
    // The state of a room you are not in is not yours to read, and the
    // departure event already says what a client needs.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "a secret" }),
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

    let sync = harness.sync(&bob, None).await;
    let entry = &sync["rooms"]["leave"][&room];
    assert!(
        entry.get("state").is_none(),
        "no state block in the leave section: {entry}"
    );
}

#[tokio::test]
async fn one_users_departure_is_not_anothers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;

    assert_eq!(
        left_rooms(&harness.sync(&bob, None).await),
        vec![room.clone()]
    );
    assert!(
        left_rooms(&harness.sync(&carol, None).await).is_empty(),
        "carol is still in the room"
    );
}
