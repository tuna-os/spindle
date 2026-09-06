//! Three defects matrix-rust-sdk's integration suite found on its first run
//! against Spindle (#392, run 34031964690), each pinned here so the suite
//! is not the only thing that knows.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { dir, app }
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

    async fn sync(&self, token: &str, query: &str) -> Value {
        let (status, body) = self
            .get(&format!("/_matrix/client/v3/sync{query}"), token)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Alice creates a room with Bob invited and a name, as a client does.
    async fn room_with_invite(&self, alice: &str, bob_id: &str) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "name": "the reading circle", "invite": [bob_id] }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn an_invite_already_pending_does_not_wait_out_the_long_poll() {
    // `tests::room::test_event_with_context`: Bob's sync loop polls at 30 s,
    // Alice invites him, and his next poll starts *after* the invite lands.
    // The poll had the invite in hand and waited for an unrelated event
    // anyway, so Bob never saw the room inside the 8 s the test allowed.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;

    let initial = server.sync(&bob, "").await;
    let since = initial["next_batch"].as_str().unwrap().to_owned();

    let room = server.room_with_invite(&alice, "@bob:example.org").await;

    let started = std::time::Instant::now();
    let sync = server
        .sync(&bob, &format!("?since={since}&timeout=5000"))
        .await;
    let waited = started.elapsed();

    assert!(
        !sync["rooms"]["invite"][&room].is_null(),
        "the invite is in bob's sync: {sync}"
    );
    assert!(
        waited < std::time::Duration::from_secs(2),
        "a poll with an invite to report returned only after {waited:?}"
    );
}

#[tokio::test]
async fn the_push_rules_account_data_event_wraps_its_ruleset_in_global() {
    // The SDK refused the whole event with "missing field `global`" and
    // carried on with no push rules at all. The spec's content is
    // `{"global": ruleset}`; `/pushrules/` already answered that way, sync
    // did not.
    let server = Harness::new();
    let alice = server.register("alice").await;

    let sync = server.sync(&alice, "").await;
    let event = sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.push_rules")
        .unwrap_or_else(|| panic!("no m.push_rules in {sync}"));
    let global = &event["content"]["global"];
    assert!(global.is_object(), "content.global is the ruleset: {event}");
    for kind in ["override", "content", "room", "sender", "underride"] {
        assert!(
            global[kind].is_array(),
            "the {kind} kind is under global: {event}"
        );
    }
    assert!(
        event["content"]["override"].is_null(),
        "the kinds are not also at the top level: {event}"
    );

    // And it is the same ruleset `/pushrules/` serves.
    let (status, rules) = server.get("/_matrix/client/v3/pushrules/", &alice).await;
    assert_eq!(status, StatusCode::OK, "{rules}");
    assert_eq!(rules["global"], *global);
}

#[tokio::test]
async fn an_invite_carries_the_inviter_s_membership() {
    // `tests::invitations::test_invitation_details`: the SDK reads the
    // invitee's member event for the inviter's ID and then wants the
    // inviter's own member event for their name. Synapse sends both; only
    // the invitee's was here.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.room_with_invite(&alice, "@bob:example.org").await;

    let sync = server.sync(&bob, "").await;
    let events = sync["rooms"]["invite"][&room]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("an invite with stripped state: {sync}"));
    let member = |user: &str| {
        events
            .iter()
            .find(|event| event["type"] == "m.room.member" && event["state_key"] == json!(user))
    };
    let bob_event = member("@bob:example.org").expect("the invitee's own member event");
    assert_eq!(bob_event["sender"], json!("@alice:example.org"));
    assert_eq!(bob_event["content"]["membership"], json!("invite"));
    let alice_event = member("@alice:example.org").expect("the inviter's member event");
    assert_eq!(alice_event["content"]["membership"], json!("join"));
    // Still stripped: nothing an invitee is not entitled to.
    assert!(
        events.iter().all(|event| event.get("event_id").is_none()),
        "stripped events carry no event IDs: {events:?}"
    );
}

#[tokio::test]
async fn a_context_window_of_zero_is_the_event_alone() {
    // `tests::room::test_event_with_context`: the SDK asks `/context` with
    // `limit=0` for the event and its tokens and nothing around it. The
    // limit was clamped up to one, so a neighbour came back.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let room = server.room_with_invite(&alice, "@bob:example.org").await;
    let mut ids = Vec::new();
    for index in 0..3 {
        let (status, body) = server
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/txn{index}"),
                &alice,
                &json!({ "msgtype": "m.text", "body": index.to_string() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        ids.push(body["event_id"].as_str().unwrap().to_owned());
    }

    let (status, context) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{}?limit=0", ids[1]),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{context}");
    assert_eq!(context["event"]["event_id"], json!(ids[1]));
    assert_eq!(context["events_before"], json!([]), "{context}");
    assert_eq!(context["events_after"], json!([]), "{context}");
    assert!(
        context["start"].is_string() && context["end"].is_string(),
        "{context}"
    );
}

#[tokio::test]
async fn a_direct_room_s_invites_say_so() {
    // `tests::sliding_sync::notification_client::test_notification`: a room
    // created with `is_direct` invites with `is_direct: true` on the member
    // event, which is how the invitee's client knows to file it as a DM.
    // The flag was accepted and dropped.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let (status, body) = server
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({ "invite": ["@bob:example.org"], "is_direct": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    let sync = server.sync(&bob, "").await;
    let events = sync["rooms"]["invite"][&room]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{sync}"));
    let own = events
        .iter()
        .find(|event| event["type"] == "m.room.member" && event["state_key"] == "@bob:example.org")
        .unwrap_or_else(|| panic!("{sync}"));
    assert_eq!(own["content"]["is_direct"], json!(true), "{own}");

    // And a plain invite says nothing, so a client does not file a group
    // room as a DM.
    let (status, body) = server
        .post("/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let plain = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{plain}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sync = server.sync(&bob, "").await;
    let own = sync["rooms"]["invite"][&plain]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{sync}"))
        .iter()
        .find(|event| event["type"] == "m.room.member" && event["state_key"] == "@bob:example.org")
        .cloned()
        .unwrap_or_else(|| panic!("{sync}"));
    assert!(own["content"].get("is_direct").is_none(), "{own}");
}

#[tokio::test]
async fn a_room_created_with_an_alias_names_it_as_canonical() {
    // `tests::sliding_sync::room::test_room_preview`: the preview reads the
    // canonical alias from room state, and the spec has the server write
    // `m.room.canonical_alias` for a room created with `room_alias_name`.
    // The alias was claimed in the directory and the state left unwritten.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let (status, body) = server
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({ "room_alias_name": "reading-circle" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, canonical) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.canonical_alias/"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{canonical}");
    assert_eq!(canonical["alias"], json!("#reading-circle:example.org"));

    // A client that set its own canonical alias in initial_state keeps it:
    // the server does not overwrite what the room already said.
    let (status, body) = server
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({
                "room_alias_name": "second",
                "initial_state": [{
                    "type": "m.room.canonical_alias",
                    "state_key": "",
                    "content": { "alias": "#second:example.org", "alt_aliases": ["#other:example.org"] }
                }]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (_, canonical) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.canonical_alias/"),
            &alice,
        )
        .await;
    assert_eq!(
        canonical["alt_aliases"],
        json!(["#other:example.org"]),
        "{canonical}"
    );
}

/// The device that sent an event reads it back with the transaction ID it
/// chose, in `unsigned`, everywhere the event is served; nobody else does,
/// the same user's other device included.
///
/// matrix-rust-sdk matches the remote echo to the local one it is still
/// showing by this field. Without it the local echo is never replaced,
/// and an edit aimed at it fails with `EventNotInTimeline`
/// (`test_stale_local_echo_time_abort_edit`).
#[tokio::test]
async fn the_sending_device_reads_its_transaction_id_back_and_nobody_else_does() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let (status, body) = server
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({ "preset": "public_chat" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let alice_phone = second_device(&server, "alice").await;

    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/txn-hello"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "hi!" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event_id = body["event_id"].as_str().unwrap().to_owned();

    let txn_in_sync = |sync: &Value| -> Value {
        transaction_id_of(
            &sync["rooms"]["join"][&room]["timeline"]["events"],
            &event_id,
        )
    };
    let sync = server.sync(&alice, "?timeout=0").await;
    assert_eq!(txn_in_sync(&sync), json!("txn-hello"), "{sync}");
    let sync = server.sync(&alice_phone, "?timeout=0").await;
    assert!(txn_in_sync(&sync).is_null(), "{sync}");
    let sync = server.sync(&bob, "?timeout=0").await;
    assert!(txn_in_sync(&sync).is_null(), "{sync}");

    // The same on the other reads a client replaces a local echo from.
    let (status, body) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=5"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        transaction_id_of(&body["chunk"], &event_id),
        json!("txn-hello")
    );

    let (status, body) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["unsigned"]["transaction_id"], json!("txn-hello"));

    let (status, body) = server
        .post(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            &alice,
            &json!({ "lists": { "all": { "ranges": [[0, 9]], "timeline_limit": 5 } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        transaction_id_of(&body["rooms"][&room]["timeline"], &event_id),
        json!("txn-hello")
    );
}

/// The `unsigned.transaction_id` on the event with `event_id` in a list
/// of events, `Null` when there is none or the event is not there.
fn transaction_id_of(events: &Value, event_id: &str) -> Value {
    events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["event_id"] == event_id)
        .map_or(Value::Null, |event| {
            event["unsigned"]["transaction_id"].clone()
        })
}

/// A second login for a registered user: another device, another token.
async fn second_device(server: &Harness, username: &str) -> String {
    let (status, body) = server
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

/// A read receipt is not an event, but it changes the reader's own unread
/// counts, so the reader's next incremental sliding sync must speak about
/// the room again and carry the new count. It did not: the room was
/// "unchanged" and stayed silent until something else happened there,
/// which is what matrix-rust-sdk's `test_room_notification_count` waited
/// four seconds for.
#[tokio::test]
async fn a_receipt_makes_the_next_sliding_sync_recount_the_room() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let (status, body) = server
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({ "preset": "public_chat" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let request = json!({ "lists": { "all": { "ranges": [[0, 9]], "timeline_limit": 5 } } });
    let sliding = |token: String, pos: Option<String>| {
        let request = request.clone();
        let server = &server;
        async move {
            let path = match pos {
                Some(pos) => format!(
                    "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}&timeout=0"
                ),
                None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
            };
            let (status, body) = server.post(&path, &token, &request).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };

    // Alice is caught up, then Bob speaks: one unread for Alice.
    let body = sliding(alice.clone(), None).await;
    let pos = body["pos"].as_str().unwrap().to_owned();
    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/rc-1"),
            &bob,
            &json!({ "msgtype": "m.text", "body": "hello" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event_id = body["event_id"].as_str().unwrap().to_owned();
    let body = sliding(alice.clone(), Some(pos)).await;
    assert_eq!(
        body["rooms"][&room]["notification_count"],
        json!(1),
        "{body}"
    );
    let pos = body["pos"].as_str().unwrap().to_owned();

    // Nothing has happened since: the room stays silent.
    let body = sliding(alice.clone(), Some(pos.clone())).await;
    assert!(body["rooms"][&room].is_null(), "{body}");

    // Alice reads. That is not an event, and it is still a change to her
    // room: the next incremental response names it, count at zero.
    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event_id}"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let body = sliding(alice.clone(), Some(pos)).await;
    assert_eq!(
        body["rooms"][&room]["notification_count"],
        json!(0),
        "{body}"
    );

    // Bob, who did not read anything, is told nothing about it.
    let bob_body = sliding(bob.clone(), None).await;
    let bob_pos = bob_body["pos"].as_str().unwrap().to_owned();
    let bob_body = sliding(bob.clone(), Some(bob_pos)).await;
    assert!(bob_body["rooms"][&room].is_null(), "{bob_body}");
}
