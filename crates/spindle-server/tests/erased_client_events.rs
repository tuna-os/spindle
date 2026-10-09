//! Erasure is a client view; authenticated federation retains the PDU.
use std::sync::Arc;

use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_server::rooms::{Rooms, StateBlock};
use spindle_store::FjallStore;

const ALICE: &str = "@alice:example.org";
const BOB: &str = "@bob:example.org";
const CAROL: &str = "@carol:example.org";

#[test]
fn erasure_uses_membership_at_the_event_across_readers_and_restart() {
    for version in 1..=12 {
        check_erasure(&version.to_string());
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one persisted room exercises every reader view"
)]
fn check_erasure(version: &str) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let accounts = Accounts::new(store.as_ref(), "example.org");
    accounts.register_hashed("alice", "unused").unwrap();
    let document = Ed25519KeyPair::generate();
    let key = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let room = rooms
        .create(
            ALICE,
            &key,
            None,
            None,
            Some("public_chat"),
            &[],
            &[],
            Some(version),
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap();
    rooms
        .set_membership(&room, BOB, BOB, "join", None, &key)
        .unwrap();
    let message = rooms
        .send(
            &room,
            ALICE,
            &key,
            "m.room.message",
            &json!({
                "msgtype": "m.text", "body": "erasure-secret"
            }),
        )
        .unwrap();
    rooms
        .set_state(
            &room,
            ALICE,
            &key,
            "m.room.topic",
            "",
            &json!({
                "topic": "erasure-secret"
            }),
        )
        .unwrap();
    rooms
        .set_membership(&room, CAROL, CAROL, "join", None, &key)
        .unwrap();
    let original = rooms.pdu(&room, &message).unwrap();
    // Warm the shared state render before changing the policy.
    assert!(
        rooms
            .reader(CAROL, &room)
            .unwrap()
            .state_serialized()
            .unwrap()
            .contains("erasure-secret")
    );
    accounts.set_erased("alice", true).unwrap();
    let earlier = rooms.reader(BOB, &room).unwrap();
    let later = rooms.reader(CAROL, &room).unwrap();
    assert_eq!(
        earlier.event(&message).unwrap().unwrap()["content"]["body"],
        "erasure-secret"
    );
    assert_eq!(
        later.event(&message).unwrap().unwrap()["content"],
        json!({})
    );
    assert_eq!(later.state_event("m.room.topic", "").unwrap(), json!({}));
    assert!(!later.state_serialized().unwrap().contains("erasure-secret"));
    let (page, _) = later.messages(None, 100).unwrap();
    assert_eq!(
        page.iter()
            .find(|event| event.event_id == message)
            .unwrap()
            .json["content"],
        json!({})
    );
    let matches = |event: &Value| event["content"]["body"] == "erasure-secret";
    assert!(later.search(None, 100, &matches).unwrap().0.is_empty());
    assert_eq!(earlier.search(None, 100, &matches).unwrap().0.len(), 1);
    assert_eq!(
        later.context(&message, 10, 10).unwrap().event["content"],
        json!({})
    );
    let sync = rooms
        .sync(CAROL, None, 100, StateBlock::Deferred, true)
        .unwrap();
    let synced = sync
        .rooms
        .iter()
        .find(|entry| entry.room_id == room)
        .unwrap();
    assert!(!synced.cached_state);
    assert!(
        !serde_json::to_string(&synced.state)
            .unwrap()
            .contains("erasure-secret")
    );
    assert_eq!(rooms.pdu(&room, &message).unwrap(), original);
    // A new state event must not reveal its erased predecessor in unsigned.
    let new_topic = rooms
        .set_state(
            &room,
            ALICE,
            &key,
            "m.room.topic",
            "",
            &json!({"topic": "public"}),
        )
        .unwrap();
    let new_topic = later.event(&new_topic).unwrap().unwrap();
    assert_eq!(new_topic["content"]["topic"], "public");
    assert_eq!(new_topic["unsigned"]["prev_content"], json!({}));
    drop(rooms);
    drop(store);
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let rooms = Rooms::new(store, "example.org");
    assert_eq!(
        rooms
            .reader(CAROL, &room)
            .unwrap()
            .event(&message)
            .unwrap()
            .unwrap()["content"],
        json!({})
    );
    assert_eq!(
        rooms
            .reader(BOB, &room)
            .unwrap()
            .event(&message)
            .unwrap()
            .unwrap()["content"]["body"],
        "erasure-secret"
    );
    assert_eq!(rooms.pdu(&room, &message).unwrap(), original);
}

async fn client_call(
    app: &axum::Router,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> Value {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let response = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, StatusCode::OK, "{path}: {response}");
    response
}

fn append_erased_history(
    rooms: &Rooms,
    room: &str,
    key: &spindle_server::signing::ServerKey,
) -> String {
    let message = rooms
        .send(
            room,
            ALICE,
            key.pair(),
            "m.room.message",
            &json!({
                "msgtype": "m.text", "body": "erasure-secret"
            }),
        )
        .unwrap();
    for content in [
        json!({
            "msgtype": "m.text", "body": "erasure-secret-edit",
            "m.new_content": {"msgtype": "m.text", "body": "erasure-secret-edit"},
            "m.relates_to": {"rel_type": "m.replace", "event_id": message}
        }),
        json!({
            "msgtype": "m.text", "body": "erasure-secret-thread",
            "m.relates_to": {"rel_type": "m.thread", "event_id": message}
        }),
    ] {
        rooms
            .send(room, ALICE, key.pair(), "m.room.message", &content)
            .unwrap();
    }
    for event_type in ["m.room.topic", "m.room.name"] {
        let field = if event_type == "m.room.topic" {
            "topic"
        } else {
            "name"
        };
        rooms
            .set_state(
                room,
                ALICE,
                key.pair(),
                event_type,
                "",
                &json!({field: "erasure-secret"}),
            )
            .unwrap();
    }
    message
}

struct ClientFixture {
    _directory: tempfile::TempDir,
    app: axum::Router,
    room: String,
    message: String,
    bob: String,
    carol: String,
    dave: String,
}

impl ClientFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(FjallStore::open(directory.path()).unwrap());
        let accounts = Accounts::new(store.as_ref(), "example.org");
        for localpart in ["alice", "bob", "carol", "dave"] {
            accounts.register_hashed(localpart, "unused").unwrap();
        }
        let bob = accounts
            .create_session("bob", None, None, false)
            .unwrap()
            .access_token;
        let carol = accounts
            .create_session("carol", None, None, false)
            .unwrap()
            .access_token;
        let dave = accounts
            .create_session("dave", None, None, false)
            .unwrap()
            .access_token;
        let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
        let rooms = Rooms::new(Arc::clone(&store), "example.org");
        let room = rooms
            .create(
                ALICE,
                key.pair(),
                None,
                None,
                Some("public_chat"),
                &[],
                &[],
                None,
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        rooms
            .set_membership(&room, BOB, BOB, "join", None, key.pair())
            .unwrap();
        let message = append_erased_history(&rooms, &room, &key);
        rooms
            .set_membership(&room, CAROL, CAROL, "join", None, key.pair())
            .unwrap();
        rooms
            .set_membership(
                &room,
                ALICE,
                "@dave:example.org",
                "invite",
                None,
                key.pair(),
            )
            .unwrap();
        accounts.set_erased("alice", true).unwrap();
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).unwrap();
        Self {
            _directory: directory,
            app,
            room,
            message,
            bob,
            carol,
            dave,
        }
    }
}

#[tokio::test]
async fn all_client_routes_filter_erased_history_before_matching_or_bundling() {
    let fixture = ClientFixture::new();
    let ClientFixture {
        app,
        room,
        message,
        bob,
        carol,
        dave,
        ..
    } = &fixture;
    for (token, visible) in [(bob, true), (carol, false)] {
        for suffix in [
            format!("event/{message}"),
            format!("context/{message}"),
            "messages?dir=b&limit=100".to_owned(),
            "state".to_owned(),
            format!("relations/{message}"),
            "threads".to_owned(),
        ] {
            let api_version = if suffix == "threads" || suffix.starts_with("relations/") {
                "v1"
            } else {
                "v3"
            };
            let response = client_call(
                app,
                token,
                "GET",
                &format!("/_matrix/client/{api_version}/rooms/{room}/{suffix}"),
                json!({}),
            )
            .await;
            assert_eq!(
                response.to_string().contains("erasure-secret"),
                visible,
                "{suffix}: {response}"
            );
        }
        let sync = client_call(app, token, "GET", "/_matrix/client/v3/sync", json!({})).await;
        assert_eq!(
            sync.to_string().contains("erasure-secret"),
            visible,
            "sync: {sync}"
        );
        let sliding = client_call(app, token, "POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", json!({
            "room_subscriptions": {room.clone(): {"timeline_limit": 100, "required_state": [["*", "*"]]}}
        })).await;
        assert_eq!(
            sliding.to_string().contains("erasure-secret"),
            visible,
            "sliding: {sliding}"
        );
        let search = client_call(app, token, "POST", "/_matrix/client/v3/search", json!({
            "search_categories": {"room_events": {"search_term": "erasure-secret", "include_state": true}}
        })).await;
        let results = &search["search_categories"]["room_events"]["results"];
        assert_eq!(
            results.to_string().contains("erasure-secret"),
            visible,
            "search: {search}"
        );
        if !visible {
            assert_eq!(results, &json!([]));
            assert_eq!(
                search["search_categories"]["room_events"]["state"],
                json!({})
            );
        }
    }
    for path in [
        "/_matrix/client/v3/sync",
        "/_matrix/client/v3/notifications",
    ] {
        let response = client_call(app, dave, "GET", path, json!({})).await;
        assert!(
            !response.to_string().contains("erasure-secret"),
            "{path}: {response}"
        );
    }
}
