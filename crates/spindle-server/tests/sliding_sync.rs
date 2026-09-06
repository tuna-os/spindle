//! Simplified Sliding Sync (MSC4186), statelessly.
//!
//! The property under test is the windowing: a client with many rooms asks
//! for the visible slice of a sorted list, and gets those rooms and no
//! others — sorted by activity, newest first, because that is the order a
//! room list renders in.

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

    /// A named room, so window assertions read as room names.
    async fn named_room(&self, token: &str, name: &str) -> String {
        let (status, body) = self
            .request("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        self.request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            token,
            &json!({ "name": name }),
        )
        .await;
        room
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
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn invite(&self, room: &str, token: &str, username: &str) {
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                token,
                &json!({ "user_id": format!("@{username}:example.org") }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn join(&self, room: &str, token: &str) {
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn leave(&self, room: &str, token: &str) {
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/leave"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn sliding(&self, token: &str, pos: Option<&str>, body: &Value) -> Value {
        let path = match pos {
            Some(pos) => {
                format!("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}")
            }
            None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
        };
        let (status, response) = self.request("POST", &path, token, body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response
    }
}

async fn joined_count(harness: &Harness, token: &str, room: &str) -> u64 {
    let response = harness.sliding(token, None, &window()).await;
    response["rooms"][room]["joined_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("joined_count is reported: {response}"))
}

fn window() -> Value {
    json!({
        "lists": {
            "main": {
                "ranges": [[0, 1]],
                "required_state": [["m.room.name", ""]],
                "timeline_limit": 3,
            }
        }
    })
}

fn room_names(response: &Value) -> Vec<String> {
    response["rooms"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|room| room["name"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_window_holds_the_most_recently_active_rooms() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let quiet = harness.named_room(&alice, "quiet").await;
    let _middle = harness.named_room(&alice, "middle").await;
    let busy = harness.named_room(&alice, "busy").await;
    // `quiet` spoke long ago (creation order), `busy` speaks last.
    harness.say(&quiet, &alice, "old news", "t1").await;
    harness.say(&busy, &alice, "fresh", "t2").await;

    let response = harness.sliding(&alice, None, &window()).await;
    let mut names = room_names(&response);
    names.sort();
    assert_eq!(
        names,
        vec!["busy", "quiet"],
        "a 2-slot window holds the two most recent speakers: {response}"
    );
    assert_eq!(response["lists"]["main"]["count"], 3, "count is all rooms");
}

#[tokio::test]
async fn activity_reorders_the_window() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.named_room(&alice, "first").await;
    let _second = harness.named_room(&alice, "second").await;
    let _third = harness.named_room(&alice, "third").await;

    // `first` is oldest by creation; one message makes it newest.
    harness.say(&first, &alice, "bump", "t1").await;

    let response = harness.sliding(&alice, None, &window()).await;
    assert!(
        room_names(&response).contains(&"first".to_owned()),
        "the bumped room enters the window: {response}"
    );
}

#[tokio::test]
async fn required_state_is_honoured_and_me_resolves() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "mine").await;
    harness.say(&room, &alice, "hello", "t1").await;

    let body = json!({
        "lists": {
            "main": {
                "ranges": [[0, 0]],
                "required_state": [["m.room.member", "$ME"]],
                "timeline_limit": 1,
            }
        }
    });
    let response = harness.sliding(&alice, None, &body).await;
    let entry = &response["rooms"][&room];
    let state = entry["required_state"].as_array().unwrap();
    assert_eq!(state.len(), 1, "only the asked-for state: {state:?}");
    assert_eq!(state[0]["type"], "m.room.member");
    assert_eq!(state[0]["state_key"], "@alice:example.org", "$ME resolved");
    assert_eq!(
        entry["timeline"].as_array().unwrap().len(),
        1,
        "timeline_limit honoured: {entry}"
    );
    assert_eq!(entry["initial"], true);
    assert_eq!(entry["notification_count"], 0, "{entry}");
    assert_eq!(entry["highlight_count"], 0, "{entry}");
    // The window says where it begins (#331), and `/messages` pages back from
    // there to what was left out: everything up to the room's creation, and
    // not the window's own event again.
    assert_eq!(entry["limited"], true, "{entry}");
    let from = entry["prev_batch"]
        .as_str()
        .expect("a window says where it begins");
    let (status, page) = harness
        .request(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&from={from}&limit=100"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let chunk = page["chunk"].as_array().unwrap();
    assert_eq!(chunk.last().unwrap()["type"], "m.room.create", "{page}");
    assert!(
        chunk
            .iter()
            .all(|event| event["content"]["body"] != "hello"),
        "the window's own event came back: {page}"
    );
}

#[tokio::test]
async fn naming_keys_returns_what_a_wildcard_would_have_selected() {
    // The reason this test exists: naming keys and asking for everything are
    // now two different code paths, and they were one. A room with several
    // members is where they would diverge -- the targeted path reads the
    // three events it was asked for, the wildcard path reads every state
    // event and filters. Same answer, or the optimisation is a bug.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "shared").await;
    for name in ["bob", "carol", "dave"] {
        let member = harness.register(name).await;
        harness.invite(&room, &alice, name).await;
        harness.join(&room, &member).await;
    }

    let ask = |required_state: Value| {
        json!({
            "lists": {
                "main": {
                    "ranges": [[0, 0]],
                    "required_state": required_state,
                    "timeline_limit": 0,
                }
            }
        })
    };
    let named = harness
        .sliding(
            &alice,
            None,
            &ask(json!([["m.room.name", ""], ["m.room.create", ""]])),
        )
        .await;
    let wildcard = harness
        .sliding(
            &alice,
            None,
            &ask(json!([["m.room.name", "*"], ["m.room.create", "*"]])),
        )
        .await;

    let key = |response: &Value| {
        let mut events: Vec<(String, String)> = response["rooms"][&room]["required_state"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    event["type"].as_str().unwrap().to_owned(),
                    event["event_id"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        events.sort();
        events
    };
    assert_eq!(key(&named), key(&wildcard), "{named}\n{wildcard}");
    assert_eq!(key(&named).len(), 2, "both keys came back: {named}");

    // Asking twice is still one event: state is a map, and the wildcard
    // path reads it as one.
    let twice = harness
        .sliding(
            &alice,
            None,
            &ask(json!([["m.room.name", ""], ["m.room.name", ""]])),
        )
        .await;
    assert_eq!(
        key(&twice).len(),
        1,
        "a repeated key is not a repeated event: {twice}"
    );
}

#[tokio::test]
async fn the_joined_count_follows_membership_rather_than_a_stale_cache() {
    // `joined_count` is served from a cache keyed on the state root. The
    // failure mode a root key is chosen to prevent is exactly this sequence:
    // count, change the membership, count again. A cache keyed on the room
    // id alone passes every test that only ever counts once.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.named_room(&alice, "counted").await;

    assert_eq!(joined_count(&harness, &alice, &room).await, 1);
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;
    assert_eq!(
        joined_count(&harness, &alice, &room).await,
        2,
        "the join is counted"
    );
    harness.leave(&room, &bob).await;
    assert_eq!(
        joined_count(&harness, &alice, &room).await,
        1,
        "and so is the leave"
    );
}

#[tokio::test]
async fn an_incremental_request_is_silent_about_unchanged_rooms() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let loud = harness.named_room(&alice, "loud").await;
    let _quiet = harness.named_room(&alice, "quiet2").await;

    let first = harness.sliding(&alice, None, &window()).await;
    let pos = first["pos"].as_str().unwrap().to_owned();

    harness.say(&loud, &alice, "again", "t1").await;

    let second = harness.sliding(&alice, Some(&pos), &window()).await;
    let rooms = second["rooms"].as_object().unwrap();
    assert!(
        rooms.contains_key(&loud),
        "the changed room is sent: {second}"
    );
    assert_eq!(
        rooms.len(),
        1,
        "and silence about the unchanged one is the answer: {second}"
    );
}

#[tokio::test]
async fn a_subscription_reaches_a_room_outside_every_window() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let pinned = harness.named_room(&alice, "pinned").await;
    // Three more recent rooms push `pinned` out of a 2-slot window.
    for name in ["a", "b", "c"] {
        let room = harness.named_room(&alice, name).await;
        harness.say(&room, &alice, name, &format!("t{name}")).await;
    }

    let mut body = window();
    body["room_subscriptions"] = json!({
        &pinned: { "required_state": [["m.room.name", ""]], "timeline_limit": 1 }
    });
    let response = harness.sliding(&alice, None, &body).await;
    assert!(
        response["rooms"].as_object().unwrap().contains_key(&pinned),
        "a subscription overrides the window: {response}"
    );
}

/// A subscription is a room id from the request body, and nothing else in
/// the handler checks who is asking.
///
/// The list windows can only produce rooms the caller is joined to, so the
/// membership check lived in the *derivation* of the list rather than in the
/// endpoint -- and a subscription skips that derivation entirely.
/// `sliding_room_entry` takes an `identity` and never consults it, so before
/// this a freshly registered account in no rooms at all could name any room
/// on the server and be sent its name, its state and its whole timeline,
/// message bodies included.
///
/// The assertion is on the timeline, not just on the room's absence: a fix
/// that returned the room with an empty timeline would still be handing over
/// the name and the state.
#[tokio::test]
async fn a_stranger_cannot_subscribe_their_way_into_a_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let private = harness.named_room(&alice, "alice's room").await;
    harness.say(&private, &alice, "secret", "t1").await;

    let mut body = window();
    body["room_subscriptions"] = json!({
        &private: { "required_state": [["m.room.name", ""]], "timeline_limit": 10 }
    });
    let response = harness.sliding(&mallory, None, &body).await;

    assert!(
        !response["rooms"]
            .as_object()
            .unwrap()
            .contains_key(&private),
        "mallory is in no rooms at all and was sent one: {response}"
    );
    assert!(
        !serde_json::to_string(&response).unwrap().contains("secret"),
        "the room was withheld but its timeline was not: {response}"
    );
}

/// Leaving a room ends the subscription too.
///
/// The same hole with a plausible client behind it: a client that subscribed
/// to a room and stayed subscribed after leaving it would keep receiving that
/// room's timeline for as long as it kept asking.
#[tokio::test]
async fn a_subscription_does_not_outlive_membership() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.named_room(&alice, "shared").await;
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;

    let mut body = window();
    body["room_subscriptions"] = json!({
        &room: { "required_state": [["m.room.name", ""]], "timeline_limit": 10 }
    });
    let seen = harness.sliding(&bob, None, &body).await;
    assert!(
        seen["rooms"].as_object().unwrap().contains_key(&room),
        "bob is joined and should see it: {seen}"
    );

    harness.leave(&room, &bob).await;
    harness.say(&room, &alice, "after bob left", "t2").await;

    let response = harness.sliding(&bob, None, &body).await;
    assert!(
        !serde_json::to_string(&response)
            .unwrap()
            .contains("after bob left"),
        "bob left and is still being sent the room's timeline: {response}"
    );
}

#[tokio::test]
async fn ranges_past_the_end_are_clipped_not_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.named_room(&alice, "only").await;

    let body = json!({
        "lists": { "main": { "ranges": [[0, 19]], "timeline_limit": 1 } }
    });
    let response = harness.sliding(&alice, None, &body).await;
    assert_eq!(response["rooms"].as_object().unwrap().len(), 1);
    assert_eq!(response["lists"]["main"]["count"], 1);
}

#[tokio::test]
async fn a_bump_after_a_sync_still_reorders_the_window() {
    // Same claim as activity_reorders_the_window, but with a sync in
    // between: the first request warms whatever the server caches about
    // room recency, and the bump must invalidate it. A recency cache that
    // is filled on read and never refreshed on append passes the other
    // test and fails this one.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.named_room(&alice, "first").await;
    let _second = harness.named_room(&alice, "second").await;
    let _third = harness.named_room(&alice, "third").await;

    let before = harness.sliding(&alice, None, &window()).await;
    assert!(
        !room_names(&before).contains(&"first".to_owned()),
        "the oldest room starts outside a two-room window: {before}"
    );

    harness.say(&first, &alice, "bump", "t-after").await;

    let after = harness.sliding(&alice, None, &window()).await;
    assert!(
        room_names(&after).contains(&"first".to_owned()),
        "the bump moves the room into the window even though its old \
         recency was already read once: {after}"
    );
}

// --- extensions ------------------------------------------------------------
//
// Element X reads its to-device traffic, key counts, account data, receipts
// and typing through the sliding-sync extensions and nothing else; a server
// that serves them only on classic sync leaves the flagship client unable
// to decrypt a single message.

fn with_extensions(extensions: Value) -> Value {
    let mut request = window();
    request["extensions"] = extensions;
    request
}

#[tokio::test]
async fn extensions_are_absent_unless_asked_for() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.named_room(&alice, "Quiet").await;
    let response = harness.sliding(&alice, None, &window()).await;
    assert_eq!(response["extensions"], json!({}), "{response}");
}

#[tokio::test]
async fn the_to_device_extension_delivers_and_its_token_acknowledges() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let (status, whoami) = harness
        .request("GET", "/_matrix/client/v3/account/whoami", &bob, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{whoami}");
    let bob_device = whoami["device_id"].as_str().unwrap().to_owned();

    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.room_key_request/txn1",
            &alice,
            &json!({ "messages": { "@bob:example.org": { bob_device: { "action": "request" } } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let enabled = with_extensions(json!({ "to_device": { "enabled": true } }));
    let response = harness.sliding(&bob, None, &enabled).await;
    let events = response["extensions"]["to_device"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("a to_device section: {response}"));
    assert_eq!(events.len(), 1, "{response}");
    assert_eq!(events[0]["type"], "m.room_key_request");
    assert_eq!(events[0]["sender"], "@alice:example.org");
    let next_batch = response["extensions"]["to_device"]["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    // Not acknowledged yet: a request without the token gets it again, which
    // is what lets a client that lost its state recover.
    let again = harness.sliding(&bob, None, &enabled).await;
    assert_eq!(
        again["extensions"]["to_device"]["events"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{again}"
    );

    // Acknowledged by the token: gone.
    let acknowledged =
        with_extensions(json!({ "to_device": { "enabled": true, "since": next_batch } }));
    let after = harness.sliding(&bob, None, &acknowledged).await;
    assert_eq!(
        after["extensions"]["to_device"]["events"],
        json!([]),
        "{after}"
    );
}

#[tokio::test]
async fn the_e2ee_extension_reports_key_counts_and_changed_devices() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.named_room(&alice, "Shared").await;
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &bob,
            &json!({
                "one_time_keys": {
                    "signed_curve25519:AAAAAQ": { "key": "one" },
                    "signed_curve25519:AAAAAg": { "key": "two" },
                },
                "fallback_keys": { "signed_curve25519:FB": { "key": "fallback" } },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let enabled = with_extensions(json!({ "e2ee": { "enabled": true } }));
    let response = harness.sliding(&bob, None, &enabled).await;
    let e2ee = &response["extensions"]["e2ee"];
    assert_eq!(
        e2ee["device_one_time_keys_count"]["signed_curve25519"], 2,
        "{response}"
    );
    assert_eq!(
        e2ee["device_unused_fallback_key_types"],
        json!(["signed_curve25519"]),
        "{response}"
    );
    assert_eq!(e2ee["device_lists"]["changed"], json!([]), "{response}");
    let pos = response["pos"].as_str().unwrap().to_owned();

    // Alice, who shares a room with bob, announces a device: bob's next
    // incremental response names her.
    let (status, whoami) = harness
        .request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{whoami}");
    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice,
            &json!({ "device_keys": { "user_id": "@alice:example.org", "device_id": whoami["device_id"] } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response = harness.sliding(&bob, Some(&pos), &enabled).await;
    assert_eq!(
        response["extensions"]["e2ee"]["device_lists"]["changed"],
        json!(["@alice:example.org"]),
        "{response}"
    );
}

#[tokio::test]
async fn the_account_data_extension_carries_global_and_room_data() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "Tagged").await;
    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/user/@alice:example.org/account_data/io.example.global",
            &alice,
            &json!({ "colour": "teal" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/account_data/m.tag"),
            &alice,
            &json!({ "tags": { "m.favourite": {} } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let enabled = with_extensions(json!({ "account_data": { "enabled": true } }));
    let response = harness.sliding(&alice, None, &enabled).await;
    let global = response["extensions"]["account_data"]["global"]
        .as_array()
        .unwrap_or_else(|| panic!("global account data: {response}"));
    assert!(
        global
            .iter()
            .any(|event| event["type"] == "io.example.global"
                && event["content"]["colour"] == "teal"),
        "{response}"
    );
    assert!(
        global.iter().any(|event| event["type"] == "m.push_rules"),
        "the default push rules ride along, as on classic sync: {response}"
    );
    let room_data = &response["extensions"]["account_data"]["rooms"][&room];
    assert_eq!(room_data[0]["type"], "m.tag", "{response}");
}

#[tokio::test]
async fn the_receipts_extension_carries_read_receipts_and_keeps_private_ones_private() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.named_room(&alice, "Read").await;
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;
    let (status, sent) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/m1"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "read me" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let event_id = sent["event_id"].as_str().unwrap().to_owned();
    for (token, kind) in [(&bob, "m.read"), (&bob, "m.read.private")] {
        let (status, body) = harness
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/receipt/{kind}/{event_id}"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let enabled = with_extensions(json!({ "receipts": { "enabled": true } }));
    let seen_by_alice = harness.sliding(&alice, None, &enabled).await;
    let receipt = &seen_by_alice["extensions"]["receipts"]["rooms"][&room];
    assert_eq!(receipt["type"], "m.receipt", "{seen_by_alice}");
    assert!(
        receipt["content"][&event_id]["m.read"]["@bob:example.org"]["ts"].is_u64(),
        "{seen_by_alice}"
    );
    assert!(
        receipt["content"][&event_id]["m.read.private"].is_null(),
        "bob's private receipt is not alice's to see: {seen_by_alice}"
    );

    let seen_by_bob = harness.sliding(&bob, None, &enabled).await;
    assert!(
        seen_by_bob["extensions"]["receipts"]["rooms"][&room]["content"][&event_id]["m.read.private"]
            ["@bob:example.org"]["ts"]
            .is_u64(),
        "{seen_by_bob}"
    );
}

#[tokio::test]
async fn the_typing_extension_says_who_is_typing() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.named_room(&alice, "Typing").await;
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/typing/@alice:example.org"),
            &alice,
            &json!({ "typing": true, "timeout": 30_000 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let enabled = with_extensions(json!({ "typing": { "enabled": true } }));
    let response = harness.sliding(&bob, None, &enabled).await;
    let typing = &response["extensions"]["typing"]["rooms"][&room];
    assert_eq!(typing["type"], "m.typing", "{response}");
    assert_eq!(
        typing["content"]["user_ids"],
        json!(["@alice:example.org"]),
        "{response}"
    );

    // Off again: the room drops out of the section.
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/typing/@alice:example.org"),
            &alice,
            &json!({ "typing": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response = harness.sliding(&bob, None, &enabled).await;
    assert!(
        response["extensions"]["typing"]["rooms"][&room].is_null(),
        "{response}"
    );
}
