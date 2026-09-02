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

    async fn post(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// Invite and join, so `user` is a member of `room`.
    async fn admit(&self, room: &str, inviter: &str, user: &str, user_id: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                inviter,
                &json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                user,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn leave(&self, room: &str, token: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/leave"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn put(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
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

/// The bodies in a `/messages` chunk, so a test can say what was and was not
/// handed over without caring about order or shape.
fn bodies(chunk: &Value) -> Vec<String> {
    chunk["chunk"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The third way in, which #258 knowingly left out: **a former member reads
/// up to their departure and no further.** Under `shared` history
/// visibility -- the default -- what was said while bob was there is his to
/// read after he leaves, and what was said after is not. The departure event
/// itself is the last thing he sees.
#[tokio::test]
async fn a_former_member_reads_up_to_their_departure_and_no_further() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness
        .create_room(&alice, json!({ "preset": "private_chat" }))
        .await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let before = harness.say(&room, &alice, "WHILEBOBWASHERE").await;
    harness.leave(&room, &bob).await;
    let after = harness.say(&room, &alice, "AFTERBOBLEFT").await;
    harness.say(&room, &alice, "ANDAGAIN").await;

    // /messages: the page stops at the departure.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = bodies(&body);
    assert!(seen.contains(&"WHILEBOBWASHERE".to_owned()), "{body}");
    assert!(
        !seen.contains(&"AFTERBOBLEFT".to_owned()) && !seen.contains(&"ANDAGAIN".to_owned()),
        "what was said after bob left is not his to read: {body}"
    );
    // ... and includes the leave itself, which is the bound.
    assert!(
        serde_json::to_string(&body)
            .unwrap()
            .contains("\"membership\":\"leave\""),
        "the departure is the last thing a former member sees: {body}"
    );

    // /event: before the departure, yes; after it, absent rather than
    // forbidden, so the refusal does not confirm the event exists.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{before}"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/event/{after}"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        !serde_json::to_string(&body)
            .unwrap()
            .contains("AFTERBOBLEFT")
    );

    // /context: the window's later half stops at the departure.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{before}?limit=10"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rendered = serde_json::to_string(&body).unwrap();
    assert!(rendered.contains("WHILEBOBWASHERE"), "{body}");
    assert!(
        !rendered.contains("AFTERBOBLEFT") && !rendered.contains("ANDAGAIN"),
        "{body}"
    );
    let (status, _) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/context/{after}?limit=10"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A stranger is still a stranger on every one of them.
    let mallory = harness.register("mallory").await;
    for uri in [
        format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
        format!("/_matrix/client/v3/rooms/{room}/event/{before}"),
        format!("/_matrix/client/v3/rooms/{room}/context/{before}?limit=10"),
    ] {
        let (status, body) = harness.get(&uri, &mallory).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
}

/// A kick and a ban are departures too: what was said up to the event that
/// removed the user is theirs, and what came after is not.
#[tokio::test]
async fn a_banned_member_reads_up_to_the_ban() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness
        .create_room(&alice, json!({ "preset": "private_chat" }))
        .await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness.say(&room, &alice, "BEFORETHEBAN").await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/ban"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    harness.say(&room, &alice, "AFTERTHEBAN").await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = bodies(&body);
    assert!(seen.contains(&"BEFORETHEBAN".to_owned()), "{body}");
    assert!(!seen.contains(&"AFTERTHEBAN".to_owned()), "{body}");
}

/// The part still narrower than the spec, pinned so it is a decision and
/// not an accident. Under `joined` visibility the spec makes each event's
/// visibility depend on whether the reader was a member *when it was sent*
/// -- membership intervals, not one bound. That is not implemented, and a
/// former member of such a room is refused outright, which errs on the
/// side of showing less. When intervals land, this test is the one to turn
/// around.
#[tokio::test]
async fn a_former_member_of_a_joined_visibility_room_is_still_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness
        .create_room(
            &alice,
            json!({
                "preset": "private_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": { "history_visibility": "joined" },
                }],
            }),
        )
        .await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness.say(&room, &alice, "WHILEJOINED").await;
    harness.leave(&room, &bob).await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// The state a former member reads is the room as it stood when they were
/// removed, not the room as it is now: a topic set after they left, and a
/// member who joined after they left, are not theirs to see.
#[tokio::test]
async fn a_former_member_reads_the_state_as_it_stood_when_they_left() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness
        .create_room(&alice, json!({ "preset": "private_chat" }))
        .await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "OLDTOPIC" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness.leave(&room, &bob).await;

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "NEWTOPIC" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let carol = harness.register("carol").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;

    // /state: the whole state, as of the departure.
    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room}/state"), &bob)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rendered = serde_json::to_string(&body).unwrap();
    assert!(rendered.contains("OLDTOPIC"), "{body}");
    assert!(
        !rendered.contains("NEWTOPIC"),
        "a topic set after bob left: {body}"
    );
    assert!(
        !rendered.contains("@carol:example.org"),
        "a member who joined after bob left: {body}"
    );
    assert!(
        body.as_array().unwrap().iter().any(|event| {
            event["type"] == "m.room.member"
                && event["state_key"] == "@bob:example.org"
                && event["content"]["membership"] == "leave"
        }),
        "the departure itself is part of the state bob sees: {body}"
    );

    // /state/{type}/{key}: the same bound, one key at a time.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["topic"], "OLDTOPIC", "{body}");
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/@carol:example.org"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Alice, still in the room, reads the present.
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
        )
        .await;
    assert_eq!(body["topic"], "NEWTOPIC", "{body}");

    // A stranger is still a stranger on both.
    let mallory = harness.register("mallory").await;
    for uri in [
        format!("/_matrix/client/v3/rooms/{room}/state"),
        format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
    ] {
        let (status, body) = harness.get(&uri, &mallory).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
}

/// `/members` is the roster, whole: a member reads the present, filtered
/// by membership if they ask; a former member reads the roster as it stood
/// when they left, departure included and later arrivals absent; a
/// stranger reads nothing.
#[tokio::test]
async fn the_member_list_is_the_roster_a_caller_may_see() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness
        .create_room(&alice, json!({ "preset": "private_chat" }))
        .await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness.leave(&room, &bob).await;
    let carol = harness.register("carol").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;

    let members = |body: &Value| -> Vec<(String, String)> {
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    event["state_key"].as_str().unwrap().to_owned(),
                    event["content"]["membership"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };

    // A member: the present, with both filters honoured.
    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room}/members"), &alice)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let all = members(&body);
    assert!(
        all.contains(&("@alice:example.org".to_owned(), "join".to_owned())),
        "{body}"
    );
    assert!(
        all.contains(&("@bob:example.org".to_owned(), "leave".to_owned())),
        "{body}"
    );
    assert!(
        all.contains(&("@carol:example.org".to_owned(), "join".to_owned())),
        "{body}"
    );
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/members?membership=join"),
            &alice,
        )
        .await;
    let joined = members(&body);
    assert_eq!(joined.len(), 2, "{body}");
    assert!(joined.iter().all(|(_, m)| m == "join"), "{body}");
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/members?not_membership=join"),
            &alice,
        )
        .await;
    assert_eq!(
        members(&body),
        vec![("@bob:example.org".to_owned(), "leave".to_owned())],
        "{body}"
    );

    // A former member: the roster as it stood at the departure.
    let (status, body) = harness
        .get(&format!("/_matrix/client/v3/rooms/{room}/members"), &bob)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let then = members(&body);
    assert!(
        then.contains(&("@bob:example.org".to_owned(), "leave".to_owned())),
        "{body}"
    );
    assert!(
        !then.iter().any(|(user, _)| user == "@carol:example.org"),
        "carol joined after bob left: {body}"
    );

    // A stranger: nothing, and not a hint of who is inside.
    let mallory = harness.register("mallory").await;
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/members"),
            &mallory,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!serde_json::to_string(&body).unwrap().contains("@alice"));
}
