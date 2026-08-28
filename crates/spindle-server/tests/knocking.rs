//! Knocking, from the side that does the knocking.
//!
//! `make_knock`/`send_knock` have existed since federation landed, so this
//! server could always *receive* a knock from a peer. It could not send one:
//! `POST /_matrix/client/v3/knock/{roomIdOrAlias}` was not a route, so a
//! local user had no way to ask, and nobody's `/sync` had anywhere to show a
//! knock if one arrived. Half a feature, and the half that was missing is
//! the one every Complement knock test starts with.
//!
//! As with membership everywhere else in this server, none of these
//! outcomes is decided here. `m.room.member` with `membership: knock` goes
//! through the same append as any other, and it is `crate::authorize` --
//! ruma's own rules — that refuses a knock on an invite-only room. These
//! tests assert the refusals happen, which is the same as asserting the
//! rules are wired in.

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
            .post(
                "/_matrix/client/v3/register",
                "",
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if !token.is_empty() {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::from(body.to_string())).unwrap())
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

    /// A private room, which is what Complement knocks against: created
    /// invite-only, then opened to knocking by changing the join rule.
    async fn private_room(&self, token: &str) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                token,
                &json!({ "preset": "private_chat" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn set_join_rule(&self, room: &str, token: &str, rule: &str) {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                token,
                &json!({ "join_rule": rule }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn knock(&self, room: &str, token: &str, reason: Option<&str>) -> (StatusCode, Value) {
        let body = match reason {
            Some(reason) => json!({ "reason": reason }),
            None => json!({}),
        };
        self.post(&format!("/_matrix/client/v3/knock/{room}"), token, &body)
            .await
    }

    async fn sync(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/sync?timeout=0", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn member_content(&self, room: &str, viewer: &str, user_id: &str) -> (StatusCode, Value) {
        self.get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{user_id}"),
            viewer,
        )
        .await
    }
}

#[tokio::test]
async fn a_knock_room_can_be_knocked_on_and_an_invite_only_one_cannot() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.private_room(&alice).await;

    // `private_chat` leaves the join rule at `invite`, and the rules refuse a
    // knock there. Nothing in the handler says so — this is ruma.
    let (status, body) = harness.knock(&room, &bob, Some("let me in")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    harness.set_join_rule(&room, &alice, "knock").await;

    let (status, body) = harness
        .knock(&room, &bob, Some("Let me in... LET ME IN!!!"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"].as_str(), Some(room.as_str()));

    // The knock is a membership event in the room, which is what makes it
    // visible to the people who can answer it.
    let (status, member) = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(status, StatusCode::OK, "{member}");
    assert_eq!(member["membership"], "knock");
    assert_eq!(member["reason"], "Let me in... LET ME IN!!!");
}

#[tokio::test]
async fn a_knock_shows_up_in_the_knockers_sync_and_not_as_an_invite() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.private_room(&alice).await;
    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            &alice,
            &json!({ "name": "Behind the door" }),
        )
        .await;
    harness.set_join_rule(&room, &alice, "knock").await;
    assert_eq!(harness.knock(&room, &bob, None).await.0, StatusCode::OK);

    let sync = harness.sync(&bob).await;
    let knock = &sync["rooms"]["knock"][&room];
    assert!(knock.is_object(), "no knock section for the room: {sync}");

    // `knock_state`, not `invite_state`: a client offering an accept button
    // for a room that has not agreed to admit anyone would be lying about
    // what happened. And not in `invite` or `join` either.
    let events = knock["knock_state"]["events"].as_array().unwrap();
    assert!(
        events.iter().any(|event| event["type"] == "m.room.name"),
        "the stripped state does not say which room is being waited on: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "m.room.join_rules"),
        "the stripped state does not say how the room admits people: {events:?}"
    );
    assert!(sync["rooms"]["invite"][&room].is_null(), "{sync}");
    assert!(sync["rooms"]["join"][&room].is_null(), "{sync}");
}

#[tokio::test]
async fn a_user_may_knock_again_on_the_same_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.private_room(&alice).await;
    harness.set_join_rule(&room, &alice, "knock").await;

    assert_eq!(
        harness.knock(&room, &bob, Some("first")).await.0,
        StatusCode::OK
    );
    // The rules allow knock -> knock, so a second ask is a second event and
    // a second chance to be noticed rather than an error.
    let (status, body) = harness.knock(&room, &bob, Some("second")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, member) = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(member["reason"], "second", "the re-knock did not land");
}

#[tokio::test]
async fn a_member_can_answer_a_knock_with_an_invite() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.private_room(&alice).await;
    harness.set_join_rule(&room, &alice, "knock").await;
    assert_eq!(harness.knock(&room, &bob, None).await.0, StatusCode::OK);

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Once in, the room is a joined room and no longer a knock: a client
    // that kept showing it in both would show the door open and still being
    // knocked on.
    let sync = harness.sync(&bob).await;
    assert!(sync["rooms"]["join"][&room].is_object(), "{sync}");
    assert!(sync["rooms"]["knock"][&room].is_null(), "{sync}");
}

#[tokio::test]
async fn knocking_on_a_room_elsewhere_is_taken_to_the_server_that_holds_it() {
    let harness = Harness::new();
    let bob = harness.register("bob").await;

    // Not a 404 that reads "no such room". The domain in the room ID names a
    // server to ask, so the knock is carried there over
    // `make_knock`/`send_knock` -- and `remote.example` does not resolve, so
    // what comes back is a gateway failure. The distinction is the whole
    // point: "nobody could be reached" is a transient fault worth retrying,
    // and "no such room" is not.
    let (status, body) = harness.knock("!elsewhere:remote.example", &bob, None).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("admitted the knock"),
        "the refusal does not say what was attempted: {body}"
    );
}
