//! Who may read a room, on every endpoint that hands one over.
//!
//! Membership was checked on `/joined_members` and `/aliases` and nowhere
//! else in the timeline/state group. Everything below answered 200 with a
//! private room's full contents to any account that knew its room ID --
//! including one registered a moment earlier and joined to nothing. The
//! federation surface never had the hole, so a remote server was held to a
//! stricter rule than a local account.
//!
//! The table is the point. A guard added to five of the eight and forgotten
//! on the other three is the state this file exists to prevent, and the only
//! way to say that is to name every route in one place and walk them.

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
    txn: std::sync::atomic::AtomicU64,
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
        Self {
            _dir: dir,
            app,
            txn: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
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

    async fn create_room(&self, token: &str, extra: Value) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(extra.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// The transaction id is a counter rather than the text: a body with a
    /// space in it is not a legal path segment, and the failure is a panic in
    /// the URI builder rather than anything to do with the endpoint.
    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        let txn = self.txn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/send/m.room.message/t{txn}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "msgtype": "m.text", "body": text }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// Every read route that hands over a room's contents, as a caller reaches it.
///
/// `/joined_members` and `/aliases` are here because they were the two that
/// were already right: if a later change breaks them, this is where it shows,
/// and they are the reason the rest of the list is not a matter of opinion.
fn every_read_route(room: &str, event: &str) -> Vec<(&'static str, String)> {
    vec![
        ("state", format!("/_matrix/client/v3/rooms/{room}/state")),
        (
            "state event",
            format!("/_matrix/client/v3/rooms/{room}/state/m.room.name/"),
        ),
        (
            "state event, default key",
            format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
        ),
        (
            "messages",
            format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
        ),
        (
            "event",
            format!("/_matrix/client/v3/rooms/{room}/event/{event}"),
        ),
        (
            "context",
            format!("/_matrix/client/v3/rooms/{room}/context/{event}?limit=5"),
        ),
        (
            "relations",
            format!("/_matrix/client/v1/rooms/{room}/relations/{event}"),
        ),
        (
            "relations by type",
            format!("/_matrix/client/v1/rooms/{room}/relations/{event}/m.annotation"),
        ),
        (
            "relations by event type",
            format!("/_matrix/client/v1/rooms/{room}/relations/{event}/m.annotation/m.reaction"),
        ),
        (
            "threads",
            format!("/_matrix/client/v1/rooms/{room}/threads"),
        ),
        (
            "joined members",
            format!("/_matrix/client/v3/rooms/{room}/joined_members"),
        ),
        (
            "aliases",
            format!("/_matrix/client/v3/rooms/{room}/aliases"),
        ),
    ]
}

/// A stranger gets nothing from any of them.
///
/// The secret is asserted against the whole serialized response rather than
/// against a field, because the routes disagree about shape and agree about
/// what they must not contain. A 200 carrying an empty chunk would pass a
/// status check and still be wrong the moment the room had a reaction in it.
#[tokio::test]
async fn a_stranger_reads_nothing_from_a_private_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness
        .create_room(
            &alice,
            json!({ "name": "TOPSECRETNAME", "preset": "private_chat" }),
        )
        .await;
    let event = harness.say(&room, &alice, "TOPSECRETBODY").await;

    for (label, uri) in every_read_route(&room, &event) {
        let (status, body) = harness.get(&uri, &mallory).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label} answered {status} to a user in no rooms at all: {body}"
        );
        let rendered = serde_json::to_string(&body).unwrap();
        assert!(
            !rendered.contains("TOPSECRET"),
            "{label} refused and leaked anyway: {rendered}"
        );
    }
}

/// A member still reads everything.
///
/// The other half of the guard, and the one a too-strict fix breaks: a
/// refusal that also refuses the room's own members is not a fix.
#[tokio::test]
async fn a_member_still_reads_all_of_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness
        .create_room(&alice, json!({ "name": "alice's room" }))
        .await;
    let event = harness.say(&room, &alice, "hello").await;

    for (label, uri) in every_read_route(&room, &event) {
        let (status, body) = harness.get(&uri, &alice).await;
        assert_eq!(status, StatusCode::OK, "{label} refused a member: {body}");
    }
}

/// A room that says anyone may read it is read by anyone.
///
/// `world_readable` is the one way in that is not membership, and it is about
/// *history* rather than joining -- which is why the guard reads
/// `m.room.history_visibility` and not the join rules. A `public` room is one
/// anyone may enter, not one anyone may read without entering, and a guard
/// that accepted `public` would have left the hole open for every public room
/// on the server. The second half of this test is that distinction.
#[tokio::test]
async fn world_readable_is_readable_and_merely_public_is_not() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;

    let open = harness
        .create_room(
            &alice,
            json!({
                "name": "open room",
                "preset": "public_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": { "history_visibility": "world_readable" }
                }],
            }),
        )
        .await;
    let open_event = harness.say(&open, &alice, "public words").await;

    for (label, uri) in every_read_route(&open, &open_event) {
        let (status, body) = harness.get(&uri, &mallory).await;
        // `/joined_members` and `/aliases` are membership-only by their own
        // rule, which predates this guard and is not being changed here.
        if matches!(label, "joined members" | "aliases") {
            continue;
        }
        assert_eq!(
            status,
            StatusCode::OK,
            "{label} refused a world-readable room: {body}"
        );
    }

    let merely_public = harness
        .create_room(
            &alice,
            json!({ "name": "PUBLICSECRET", "preset": "public_chat" }),
        )
        .await;
    let public_event = harness.say(&merely_public, &alice, "not for you").await;
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{merely_public}/messages?dir=b&limit=10"),
            &mallory,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a public room is joinable, not readable without joining: {body}"
    );
    let _ = public_event;
}

/// A room that does not exist is refused, not reported as missing.
///
/// Otherwise the guard hands back a room-ID oracle: 404 for "no such room"
/// and 403 for "not yours" tells a stranger which IDs exist, which is the
/// smaller half of the question they were asking.
#[tokio::test]
async fn a_room_that_does_not_exist_is_refused_like_one_that_does() {
    let harness = Harness::new();
    let mallory = harness.register("mallory").await;
    let (status, _) = harness
        .get(
            "/_matrix/client/v3/rooms/!nosuchroom:example.org/messages?dir=b",
            &mallory,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
