//! Simplified Sliding Sync (MSC4186).
//!
//! The property under test is the windowing: a client with many rooms asks
//! for the visible slice of a sorted list, and gets those rooms and no
//! others — sorted by activity, newest first, because that is the order a
//! room list renders in. And the connection: what a `pos` remembers of the
//! parameters it was asked with and of the rooms it already sent.

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
        let (status, response) = self.sliding_status(token, pos, body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response
    }

    async fn sliding_status(
        &self,
        token: &str,
        pos: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let path = match pos {
            Some(pos) => {
                format!("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}")
            }
            None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
        };
        self.request("POST", &path, token, body).await
    }

    /// A second device of an existing account.
    async fn login(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "type": "m.login.password",
                            "identifier": { "type": "m.id.user", "user": username },
                            "password": "hunter2",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }
}

fn pos(response: &Value) -> String {
    response["pos"]
        .as_str()
        .unwrap_or_else(|| panic!("a pos: {response}"))
        .to_owned()
}

fn state_types(entry: &Value) -> Vec<String> {
    let mut types: Vec<String> = entry["required_state"]
        .as_array()
        .unwrap_or_else(|| panic!("required_state: {entry}"))
        .iter()
        .map(|event| event["type"].as_str().unwrap().to_owned())
        .collect();
    types.sort();
    types
}

fn bodies(entry: &Value) -> Vec<String> {
    entry["timeline"]
        .as_array()
        .unwrap_or_else(|| panic!("timeline: {entry}"))
        .iter()
        .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
        .collect()
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

/// Element X starts with a small window and grows it. A quiet room that
/// enters the window has not changed, but the client has never been sent it:
/// it must arrive in full, or the client's room list silently lacks it. This
/// is how migrated reilly.asia accounts lost quiet rooms from Element X.
#[tokio::test]
async fn a_growing_window_sends_quiet_rooms_that_enter_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let quiet = harness.named_room(&alice, "quiet").await;
    for name in ["a", "b"] {
        let room = harness.named_room(&alice, name).await;
        harness.say(&room, &alice, name, &format!("t{name}")).await;
    }

    // Rooms 0–1 of 3: the quiet room sorts last and is out of view.
    let first = harness.sliding(&alice, None, &window()).await;
    assert!(!first["rooms"].as_object().unwrap().contains_key(&quiet));
    let pos = first["pos"].as_str().unwrap().to_owned();

    // The client widens to 0–9 with nothing new on the server.
    let mut wider = window();
    wider["lists"]["main"]["ranges"] = json!([[0, 9]]);
    let second = harness.sliding(&alice, Some(&pos), &wider).await;
    let rooms = second["rooms"].as_object().unwrap();
    assert!(
        rooms.contains_key(&quiet),
        "the quiet room entering the window is sent: {second}"
    );
    assert_eq!(rooms[&quiet]["initial"], json!(true), "in full: {second}");
    assert_eq!(rooms.len(), 1, "rooms already sent stay silent: {second}");

    // And once sent, it is silent again at the same window.
    let pos = second["pos"].as_str().unwrap().to_owned();
    let third = harness.sliding(&alice, Some(&pos), &wider).await;
    assert!(
        third["rooms"].as_object().unwrap().is_empty(),
        "nothing new, nothing sent: {third}"
    );
}

/// A `pos` names a position of one connection of one device. One the server
/// does not hold -- from before connections, made up, issued to another
/// connection or device, or retired -- is MSC4186's `M_UNKNOWN_POS`, which
/// a client answers by starting over; anything else it retries forever.
#[tokio::test]
async fn a_pos_the_server_does_not_hold_is_unknown() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let laptop = harness.login("alice").await;
    harness.named_room(&alice, "only").await;

    let first = harness.sliding(&alice, None, &window()).await;
    let held = pos(&first);
    let mut elsewhere = window();
    elsewhere["conn_id"] = json!("encryption");

    let stream = held.split_once('.').unwrap().0.to_owned();
    let cases = [
        (
            &alice,
            stream.clone(),
            window(),
            "a pos from before connections",
        ),
        (
            &alice,
            format!("{stream}.7b7d"),
            window(),
            "a pos carrying windows",
        ),
        (&alice, "nonsense".to_owned(), window(), "garbage"),
        (&alice, held.clone(), elsewhere, "another connection's pos"),
        (&laptop, held.clone(), window(), "another device's pos"),
    ];
    for (token, pos, body, case) in cases {
        let (status, response) = harness.sliding_status(token, Some(&pos), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {response}");
        assert_eq!(response["errcode"], "M_UNKNOWN_POS", "{case}: {response}");
    }

    // The pos it was issued still works, and using the one after it retires
    // it: the client has moved on, so an old pos is a client gone wrong.
    let second = harness.sliding(&alice, Some(&held), &window()).await;
    harness
        .sliding(&alice, Some(&pos(&second)), &window())
        .await;
    let (status, response) = harness.sliding_status(&alice, Some(&held), &window()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["errcode"], "M_UNKNOWN_POS", "{response}");
}

/// Sticky parameters: a request that leaves its lists out runs with the
/// connection's previous ones, and a list named with one field keeps the
/// others.
#[tokio::test]
async fn a_request_without_lists_keeps_the_previous_lists() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let quiet = harness.named_room(&alice, "quiet").await;
    let loud = harness.named_room(&alice, "loud").await;
    let third = harness.named_room(&alice, "third").await;
    harness.say(&third, &alice, "bump", "t0").await;
    harness.say(&loud, &alice, "bump", "t1").await;

    let first = harness.sliding(&alice, None, &window()).await;
    assert!(!first["rooms"].as_object().unwrap().contains_key(&quiet));

    harness.say(&loud, &alice, "again", "t2").await;
    let second = harness
        .sliding(&alice, Some(&pos(&first)), &json!({}))
        .await;
    assert_eq!(
        second["lists"]["main"]["count"],
        json!(3),
        "the list stands: {second}"
    );
    assert_eq!(
        bodies(&second["rooms"][&loud]),
        vec!["again"],
        "and its window is answered: {second}"
    );

    // Only the ranges sent: the quiet room enters with the list's
    // required_state and timeline limit from the first request.
    let wider = json!({ "lists": { "main": { "ranges": [[0, 9]] } } });
    let widened = harness.sliding(&alice, Some(&pos(&second)), &wider).await;
    let entry = &widened["rooms"][&quiet];
    assert_eq!(entry["initial"], json!(true), "{widened}");
    assert_eq!(state_types(entry), vec!["m.room.name"], "{widened}");
    assert_eq!(entry["timeline"].as_array().unwrap().len(), 3, "{widened}");
}

/// A room the connection already sent is sent again as what changed: the
/// new events, the state that changed, `initial: false` -- not the room in
/// full every time it moves.
#[tokio::test]
async fn a_room_already_sent_is_sent_as_what_changed() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "before").await;
    harness.say(&room, &alice, "one", "t1").await;
    harness.say(&room, &alice, "two", "t2").await;

    let first = harness.sliding(&alice, None, &window()).await;
    let entry = &first["rooms"][&room];
    assert_eq!(entry["initial"], json!(true), "{first}");
    assert_eq!(state_types(entry), vec!["m.room.name"], "{first}");

    // Nothing changed: nothing sent, not the room in full again.
    let quiet = harness.sliding(&alice, Some(&pos(&first)), &window()).await;
    assert!(quiet["rooms"].as_object().unwrap().is_empty(), "{quiet}");

    harness.say(&room, &alice, "three", "t3").await;
    let second = harness.sliding(&alice, Some(&pos(&quiet)), &window()).await;
    let entry = &second["rooms"][&room];
    assert_eq!(entry["initial"], json!(false), "{second}");
    assert_eq!(
        bodies(entry),
        vec!["three"],
        "only the new event, though the limit is 3: {second}"
    );
    assert_eq!(entry["limited"], json!(false), "{second}");
    assert!(
        state_types(entry).is_empty(),
        "the name did not change, so it is not resent: {second}"
    );

    // A rename is state that changed.
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            &alice,
            &json!({ "name": "after" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let third = harness
        .sliding(&alice, Some(&pos(&second)), &window())
        .await;
    let entry = &third["rooms"][&room];
    assert_eq!(entry["initial"], json!(false), "{third}");
    assert_eq!(
        entry["required_state"][0]["content"]["name"], "after",
        "{third}"
    );
    assert_eq!(entry["name"], "after", "{third}");
}

/// A room out of view while it changed is caught up from where the client
/// left it when it comes back, not from the previous request.
#[tokio::test]
async fn a_room_back_in_view_is_caught_up_from_where_the_client_left_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "roamer").await;
    harness.say(&room, &alice, "seen", "t1").await;

    let first = harness.sliding(&alice, None, &window()).await;
    assert_eq!(first["rooms"][&room]["initial"], json!(true), "{first}");

    // Out of view (an empty list) while it says something.
    let empty = json!({ "lists": { "main": { "ranges": [] } } });
    let away = harness.sliding(&alice, Some(&pos(&first)), &empty).await;
    harness.say(&room, &alice, "missed", "t2").await;
    let still_away = harness.sliding(&alice, Some(&pos(&away)), &empty).await;
    assert!(still_away["rooms"].as_object().unwrap().is_empty());

    let back = harness
        .sliding(&alice, Some(&pos(&still_away)), &window())
        .await;
    let entry = &back["rooms"][&room];
    assert_eq!(entry["initial"], json!(false), "{back}");
    assert_eq!(bodies(entry), vec!["missed"], "{back}");
}

/// A client that asks for more state of a room it holds is sent the state
/// it did not have, without waiting for the room to change, and not the
/// state it had.
#[tokio::test]
async fn widened_required_state_sends_the_newly_asked_state() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "deep").await;

    let first = harness.sliding(&alice, None, &window()).await;
    assert_eq!(state_types(&first["rooms"][&room]), vec!["m.room.name"]);

    let mut wider = window();
    wider["lists"]["main"]["required_state"] = json!([["m.room.name", ""], ["m.room.create", ""]]);
    let second = harness.sliding(&alice, Some(&pos(&first)), &wider).await;
    let entry = &second["rooms"][&room];
    assert_eq!(entry["initial"], json!(false), "{second}");
    assert_eq!(
        state_types(entry),
        vec!["m.room.create"],
        "the new key only: {second}"
    );
    assert!(bodies(entry).is_empty(), "nothing new to say: {second}");

    // Asked again at the same width, nothing.
    let third = harness.sliding(&alice, Some(&pos(&second)), &wider).await;
    assert!(third["rooms"].as_object().unwrap().is_empty(), "{third}");
}

/// A timeline limit that grows sends the newest events up to it at once,
/// already-sent ones included, and says so (MSC4186 `expanded_timeline`).
#[tokio::test]
async fn a_longer_timeline_limit_expands_the_timeline() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "long").await;
    for (index, text) in ["one", "two", "three"].iter().enumerate() {
        harness.say(&room, &alice, text, &format!("t{index}")).await;
    }
    let mut short = window();
    short["lists"]["main"]["timeline_limit"] = json!(1);
    let first = harness.sliding(&alice, None, &short).await;
    assert_eq!(bodies(&first["rooms"][&room]), vec!["three"]);

    let second = harness.sliding(&alice, Some(&pos(&first)), &window()).await;
    let entry = &second["rooms"][&room];
    assert_eq!(bodies(entry), vec!["one", "two", "three"], "{second}");
    assert_eq!(entry["unstable_expanded_timeline"], json!(true), "{second}");
    assert_eq!(entry["initial"], json!(false), "{second}");
}

/// Two connections of one device are two connections: each keeps its own
/// parameters and its own record of what it sent, and neither's pos is the
/// other's.
#[tokio::test]
async fn connections_of_one_device_are_independent() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.named_room(&alice, "shared").await;

    let mut rooms = window();
    rooms["conn_id"] = json!("room-list");
    let keys = json!({
        "conn_id": "encryption",
        "extensions": { "e2ee": { "enabled": true } },
    });
    let list = harness.sliding(&alice, None, &rooms).await;
    let encryption = harness.sliding(&alice, None, &keys).await;
    assert!(encryption["rooms"].as_object().unwrap().is_empty());

    // The room-list connection moves on; the encryption one is untouched.
    harness.say(&room, &alice, "news", "t1").await;
    let list_next = harness
        .sliding(
            &alice,
            Some(&pos(&list)),
            &json!({ "conn_id": "room-list" }),
        )
        .await;
    assert_eq!(
        bodies(&list_next["rooms"][&room]),
        vec!["news"],
        "{list_next}"
    );
    let keys_again = json!({ "conn_id": "encryption" });
    let encryption_next = harness
        .sliding(&alice, Some(&pos(&encryption)), &keys_again)
        .await;
    assert!(
        encryption_next["rooms"].as_object().unwrap().is_empty(),
        "the encryption connection never had lists: {encryption_next}"
    );
    assert!(
        encryption_next["extensions"]["e2ee"].is_object(),
        "and keeps its own extensions: {encryption_next}"
    );

    // Starting one over does not start the other over.
    let restarted = harness.sliding(&alice, None, &rooms).await;
    assert_eq!(restarted["rooms"][&room]["initial"], json!(true));
    let (status, response) = harness
        .sliding_status(&alice, Some(&pos(&encryption_next)), &keys_again)
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
}

#[tokio::test]
async fn the_txn_id_is_echoed() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mut body = window();
    body["txn_id"] = json!("abc123");
    let response = harness.sliding(&alice, None, &body).await;
    assert_eq!(response["txn_id"], json!("abc123"), "{response}");
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

/// An extension's `lists` and `rooms` say which rooms it speaks about: the
/// windows of the lists it names and the subscriptions it names, `*` for
/// all of them. And the scoping is sticky with the rest of the extension's
/// config.
#[tokio::test]
async fn an_extension_speaks_only_about_the_lists_and_rooms_it_names() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let one = harness.named_room(&alice, "one").await;
    let two = harness.named_room(&alice, "two").await;
    for room in [&one, &two] {
        harness.invite(room, &alice, "bob").await;
        harness.join(room, &bob).await;
    }
    // `one` spoke last, so it is index 0 and `two` index 1.
    let mut said = Vec::new();
    for (room, txn) in [(&two, "t2"), (&one, "t1")] {
        // Recency is a timestamp: a millisecond apart, or a tie sorts by id.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let (status, sent) = harness
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                &alice,
                &json!({ "msgtype": "m.text", "body": txn }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        said.push((room.clone(), sent["event_id"].as_str().unwrap().to_owned()));
    }
    for (room, event_id) in &said {
        for (method, path, body) in [
            (
                "POST",
                format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event_id}"),
                json!({}),
            ),
            (
                "PUT",
                format!("/_matrix/client/v3/user/@bob:example.org/rooms/{room}/account_data/m.tag"),
                json!({ "tags": { "m.favourite": {} } }),
            ),
            (
                "PUT",
                format!("/_matrix/client/v3/rooms/{room}/typing/@alice:example.org"),
                json!({ "typing": true, "timeout": 30_000 }),
            ),
        ] {
            let token = if path.contains("typing") {
                &alice
            } else {
                &bob
            };
            let (status, response) = harness.request(method, &path, token, &body).await;
            assert_eq!(status, StatusCode::OK, "{path}: {response}");
        }
    }

    let body = json!({
        "lists": {
            "first": { "ranges": [[0, 0]], "timeline_limit": 1 },
            "second": { "ranges": [[1, 1]], "timeline_limit": 1 },
        },
        "room_subscriptions": { &two: { "timeline_limit": 1 } },
        "extensions": {
            "typing": { "enabled": true, "lists": ["first"], "rooms": [] },
            "receipts": { "enabled": true, "lists": ["second"], "rooms": [] },
            "account_data": { "enabled": true, "lists": [], "rooms": ["*"] },
        },
    });
    let keys = |response: &Value, extension: &str| -> Vec<String> {
        response["extensions"][extension]["rooms"]
            .as_object()
            .unwrap_or_else(|| panic!("{extension}: {response}"))
            .keys()
            .cloned()
            .collect()
    };
    let response = harness.sliding(&bob, None, &body).await;
    assert_eq!(
        response["rooms"].as_object().unwrap().len(),
        2,
        "{response}"
    );
    assert_eq!(keys(&response, "typing"), vec![one.clone()], "{response}");
    assert_eq!(keys(&response, "receipts"), vec![two.clone()], "{response}");
    assert_eq!(
        keys(&response, "account_data"),
        vec![two.clone()],
        "only the subscription: {response}"
    );

    // A request that restates nothing keeps the scopes: typing, which is
    // repeated every time, is still about the first list alone.
    let next = harness
        .sliding(&bob, Some(&pos(&response)), &json!({}))
        .await;
    assert_eq!(keys(&next, "typing"), vec![one.clone()], "{next}");
    assert_eq!(keys(&next, "account_data"), vec![two.clone()], "{next}");
}

#[tokio::test]
async fn a_room_entry_carries_what_a_row_is_drawn_from() {
    // MSC4186 sends, beside the counts, what a room-list row needs when the
    // room has no name: the members' own names and avatars (`heroes`), the
    // room avatar, who is invited, and a recency stamp comparable across
    // rooms. Without them a client asks for every member's state to label
    // a direct chat, and sorts its list by a timeline it did not want.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/profile/@bob:example.org/displayname",
            &bob,
            &json!({ "displayname": "Bob" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .request("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;
    harness.invite(&room, &alice, "carol").await;
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.avatar/"),
            &alice,
            &json!({ "url": "mxc://example.org/room" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let response = harness.sliding(&alice, None, &window()).await;
    let entry = &response["rooms"][&room];
    assert_eq!(entry["joined_count"], json!(2), "{entry}");
    assert_eq!(entry["invited_count"], json!(1), "{entry}");
    assert_eq!(entry["avatar"], json!("mxc://example.org/room"), "{entry}");
    // Heroes leave the viewer out and come joined first, then invited,
    // with the name the member event carries.
    let heroes = entry["heroes"]
        .as_array()
        .unwrap_or_else(|| panic!("{entry}"));
    let ids: Vec<&str> = heroes
        .iter()
        .filter_map(|hero| hero["user_id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["@bob:example.org", "@carol:example.org"],
        "{entry}"
    );
    assert_eq!(heroes[0]["name"], json!("Bob"), "{entry}");
    assert!(
        heroes[1].get("name").is_none(),
        "carol never set one: {entry}"
    );

    // The bump stamp is the newest event's timestamp, so it moves when the
    // room does and orders rooms without a timeline in the response.
    let before = entry["bump_stamp"]
        .as_i64()
        .unwrap_or_else(|| panic!("{entry}"));
    let newest = entry["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["origin_server_ts"].as_i64())
        .max()
        .unwrap();
    assert_eq!(before, newest, "{entry}");
    drop(carol);
}

#[tokio::test]
async fn an_invite_is_a_room_in_the_list() {
    // MSC4186 has no invite section: an invited room is in the list like any
    // other, with the stripped state the invite is rendered from and no
    // timeline. Without it a sliding-sync client -- Element X -- never sees
    // an invite at all (matrix-rust-sdk's
    // `test_delayed_invite_response_and_sent_message_decryption` waited on
    // one for three seconds and gave up).
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    // Bob is up to date, then the invite lands: the incremental response
    // names the room, and it is an invite entry.
    let before = harness.sliding(&bob, None, &window()).await;
    assert_eq!(before["lists"]["main"]["count"], json!(0), "{before}");
    let pos = before["pos"].as_str().unwrap().to_owned();
    let room = harness.named_room(&alice, "the reading circle").await;
    harness.invite(&room, &alice, "bob").await;

    let response = harness.sliding(&bob, Some(&pos), &window()).await;
    assert_eq!(response["lists"]["main"]["count"], json!(1), "{response}");
    let entry = &response["rooms"][&room];
    assert_eq!(entry["initial"], json!(true), "{response}");
    assert_eq!(entry["name"], json!("the reading circle"), "{entry}");
    let stripped = entry["invite_state"]
        .as_array()
        .unwrap_or_else(|| panic!("{entry}"));
    assert!(
        stripped.iter().any(|event| event["type"] == "m.room.member"
            && event["state_key"] == "@bob:example.org"
            && event["content"]["membership"] == "invite"),
        "the invite itself is in the stripped state: {entry}"
    );
    assert!(
        stripped.iter().all(|event| event.get("event_id").is_none()),
        "stripped events carry no event IDs: {entry}"
    );
    assert!(
        entry.get("timeline").is_none(),
        "an invitee gets no timeline: {entry}"
    );
    assert!(entry.get("joined_count").is_none(), "nor counts: {entry}");
    let ids: Vec<&str> = entry["heroes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|hero| hero["user_id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["@alice:example.org"],
        "the inviter is the hero: {entry}"
    );

    // On an initial request the invite is there too, sorted with the rest.
    let initial = harness.sliding(&bob, None, &window()).await;
    assert_eq!(initial["lists"]["main"]["count"], json!(1), "{initial}");
    assert!(
        initial["rooms"][&room]["invite_state"].is_array(),
        "{initial}"
    );

    // Once Bob joins, the same room is an ordinary entry.
    harness.join(&room, &bob).await;
    let joined = harness.sliding(&bob, None, &window()).await;
    let entry = &joined["rooms"][&room];
    assert!(entry.get("invite_state").is_none(), "{entry}");
    assert_eq!(entry["joined_count"], json!(2), "{entry}");
}
