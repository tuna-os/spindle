//! Erasure (#576), by Synapse's rule: an erased user's events reach a
//! client redacted unless it was joined at the event, and reach another
//! server redacted always; room state is served as stored, and the stored
//! PDU is never rewritten.
use std::sync::Arc;

use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_server::rooms::{Rooms, StateBlock};
use spindle_store::FjallStore;

const ALICE: &str = "@alice:example.org";
const BOB: &str = "@bob:example.org";
const CAROL: &str = "@carol:example.org";
const ERIN: &str = "@erin:example.org";
const FRANK: &str = "@frank:example.org";

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
    for member in [BOB, ERIN, FRANK] {
        rooms
            .set_membership(&room, member, member, "join", None, &key)
            .unwrap();
    }
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
    // Membership changes the erased user made to others, for Synapse's
    // own-membership rule below.
    let ban = rooms
        .set_membership(&room, ALICE, ERIN, "ban", Some("ban-reason"), &key)
        .unwrap();
    let kick = rooms
        .set_membership(&room, ALICE, FRANK, "leave", Some("kick-reason"), &key)
        .unwrap();
    rooms
        .set_membership(&room, CAROL, CAROL, "join", None, &key)
        .unwrap();
    let original = rooms.pdu(&room, &message).unwrap();
    // Before the erasure, as after it: state is not filtered.
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
    // The reader's own membership event counts as the more joined of its
    // new and previous membership (`_check_membership`): a member banned
    // while joined was joined, so sees the ban whole; a member kicked
    // while joined sees the kick redacted; a later joiner sees both
    // redacted.
    let reason = |user: &str, event: &str| {
        rooms
            .reader(user, &room)
            .unwrap()
            .event(event)
            .unwrap()
            .unwrap()["content"]
            .clone()
    };
    assert_eq!(reason(ERIN, &ban)["reason"], "ban-reason");
    assert_eq!(reason(FRANK, &kick), json!({"membership": "leave"}));
    assert_eq!(reason(BOB, &ban)["reason"], "ban-reason");
    assert_eq!(reason(CAROL, &ban), json!({"membership": "ban"}));
    // Synapse's `filter_events_for_client` sees timeline events, never
    // room state: the topic an erased user set stays the room's topic.
    assert_eq!(
        later.state_event("m.room.topic", "").unwrap(),
        json!({"topic": "erasure-secret"})
    );
    assert!(later.state_serialized().unwrap().contains("erasure-secret"));
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
    let synced_message = synced
        .events
        .iter()
        .find(|event| event["event_id"] == message.as_str())
        .unwrap();
    assert_eq!(synced_message["content"], json!({}));
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
                &json!({field: "erasure-setting"}),
            )
            .unwrap();
    }
    message
}

fn alices_public_room(rooms: &Rooms, key: &spindle_server::signing::ServerKey) -> String {
    rooms
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
        .unwrap()
}

fn client_app(store: &Arc<FjallStore>) -> axum::Router {
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
    )
    .unwrap();
    spindle_server::app(config, Arc::clone(store)).unwrap()
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
        let room = alices_public_room(&rooms, &key);
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
        let app = client_app(&store);
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
        // Room state is served as stored, as Synapse serves it: the name
        // and topic the erased user set reach both readers.
        let room_state = client_call(
            app,
            token,
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/state"),
            json!({}),
        )
        .await;
        assert!(
            room_state.to_string().contains("erasure-setting"),
            "{room_state}"
        );
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
        // Matched against the pruned copy, so erased text makes no hit at
        // all. Synapse matches the stored text and returns the pruned
        // event, which tells a later joiner that the erased user wrote the
        // term; this is the one place Spindle is stricter on purpose.
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

/// The hazard state pruning had: an erased user who enabled encryption
/// left later joiners an `m.room.encryption` with content `{}`, and
/// summaries with no `encryption`, so a client could take an encrypted
/// room for a plaintext one. Synapse never filters room state
/// (`filter_events_for_client` sees timeline events only), and nor does
/// Spindle now: the settings an erased user made stay the room's settings.
#[tokio::test]
async fn a_later_joiner_sees_an_erased_users_room_settings_intact() {
    const ALGORITHM: &str = "m.megolm.v1.aes-sha2";
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let accounts = Accounts::new(store.as_ref(), "example.org");
    for localpart in ["alice", "carol"] {
        accounts.register_hashed(localpart, "unused").unwrap();
    }
    let carol = accounts
        .create_session("carol", None, None, false)
        .unwrap()
        .access_token;
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let room = alices_public_room(&rooms, &key);
    rooms
        .set_state(
            &room,
            ALICE,
            key.pair(),
            "m.room.encryption",
            "",
            &json!({"algorithm": ALGORITHM}),
        )
        .unwrap();
    rooms
        .set_state(
            &room,
            ALICE,
            key.pair(),
            "m.room.name",
            "",
            &json!({"name": "erasure-setting"}),
        )
        .unwrap();
    rooms
        .set_membership(&room, CAROL, CAROL, "join", None, key.pair())
        .unwrap();
    accounts.set_erased("alice", true).unwrap();
    let app = client_app(&store);
    let get = |path: String| {
        let app = app.clone();
        let carol = carol.clone();
        async move { client_call(&app, &carol, "GET", &path, json!({})).await }
    };

    let encryption = get(format!(
        "/_matrix/client/v3/rooms/{room}/state/m.room.encryption/"
    ))
    .await;
    assert_eq!(encryption["algorithm"], ALGORITHM, "{encryption}");
    let state = get(format!("/_matrix/client/v3/rooms/{room}/state")).await;
    assert!(state.to_string().contains(ALGORITHM), "{state}");
    let summary = get(format!("/_matrix/client/v1/room_summary/{room}")).await;
    assert_eq!(summary["encryption"], ALGORITHM, "{summary}");
    assert_eq!(summary["name"], "erasure-setting", "{summary}");
    // A one-event timeline leaves the settings to the state block.
    let sync = get(
        "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A1%7D%7D%7D"
            .to_owned(),
    )
    .await;
    let sync_state = &sync["rooms"]["join"][&room]["state"]["events"];
    assert!(
        sync_state
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["type"] == "m.room.encryption"
                && event["content"]["algorithm"] == ALGORITHM),
        "{sync}"
    );
    let sliding = client_call(
        &app,
        &carol,
        "POST",
        "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
        json!({"room_subscriptions": {room.clone(): {
            "timeline_limit": 1,
            "required_state": [["m.room.encryption", ""], ["m.room.name", ""]]
        }}}),
    )
    .await;
    let entry = &sliding["rooms"][&room];
    assert_eq!(entry["name"], "erasure-setting", "{sliding}");
    assert!(
        entry["required_state"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["content"]["algorithm"] == ALGORITHM),
        "{sliding}"
    );
}

/// Erasure is rare, and once one account is erased every served event
/// asks whether its sender is. Asked of the account record that was a
/// store read per event (and the state block's events too); asked of the
/// erased set cached per erasure generation it costs nothing per event.
/// So erasing an account that sent nothing must not change what any read
/// path costs: counted, per endpoint, before and after the erasure.
#[tokio::test]
async fn an_erasure_adds_no_reads_per_served_event() {
    const MESSAGES: usize = 30;
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let accounts = Accounts::new(store.as_ref(), "example.org");
    for localpart in ["alice", "bob", "zed"] {
        accounts.register_hashed(localpart, "unused").unwrap();
    }
    let bob = accounts
        .create_session("bob", None, None, false)
        .unwrap()
        .access_token;
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let room = alices_public_room(&rooms, &key);
    rooms
        .set_membership(&room, BOB, BOB, "join", None, key.pair())
        .unwrap();
    let mut middle = String::new();
    for index in 0..MESSAGES {
        let id = rooms
            .send(
                &room,
                BOB,
                key.pair(),
                "m.room.message",
                &json!({"msgtype": "m.text", "body": format!("counted {index}")}),
            )
            .unwrap();
        if index == MESSAGES / 2 {
            middle = id;
        }
    }
    drop(rooms);
    let app = client_app(&store);
    let requests = [
        (
            "GET",
            format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit={MESSAGES}"),
            json!({}),
        ),
        (
            "GET",
            format!("/_matrix/client/v3/rooms/{room}/context/{middle}?limit=20"),
            json!({}),
        ),
        (
            "GET",
            format!("/_matrix/client/v3/rooms/{room}/event/{middle}"),
            json!({}),
        ),
        (
            "GET",
            "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A30%7D%7D%7D"
                .to_owned(),
            json!({}),
        ),
        (
            "POST",
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
            json!({"room_subscriptions": {room.clone(): {
                "timeline_limit": MESSAGES, "required_state": [["*", "*"]]
            }}}),
        ),
        (
            "POST",
            "/_matrix/client/v3/search".to_owned(),
            json!({"search_categories": {"room_events": {"search_term": "counted"}}}),
        ),
    ];
    // The second of two identical calls, so warm-up loads are not counted.
    let cost = async |method: &str, path: &str, body: &Value| {
        client_call(&app, &bob, method, path, body.clone()).await;
        let before = store.reads();
        client_call(&app, &bob, method, path, body.clone()).await;
        store.reads() - before
    };
    let mut unerased = Vec::new();
    for (method, path, body) in &requests {
        unerased.push(cost(method, path, body).await);
    }
    accounts.set_erased("zed", true).unwrap();
    let mut grown = Vec::new();
    for ((method, path, body), unerased) in requests.iter().zip(unerased) {
        let erased = cost(method, path, body).await;
        if erased != unerased {
            grown.push(format!(
                "{method} {path}: {unerased} reads before the erasure, {erased} after"
            ));
        }
    }
    assert!(grown.is_empty(), "{grown:#?}");
}
