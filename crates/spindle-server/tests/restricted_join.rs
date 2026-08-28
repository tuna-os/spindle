//! Restricted rooms: joining because of a membership somewhere else.
//!
//! MSC3083 is the one join rule whose decision the auth rules deliberately
//! do not make. Every other rule is answerable from the room's own state —
//! public, invited, banned — but `restricted` says *you may join this room
//! because you are in that one*, and the rules judge one room at a time.
//!
//! So the spec splits it: a server that can see both rooms decides, and
//! records the decision as a nomination — `join_authorised_via_users_server`,
//! naming a member of this room who could have invited the joiner. The auth
//! rules then check the nomination, which is what everybody else verifies.
//! These tests pin both halves: that we nominate when we can vouch, and that
//! we do not when we cannot.

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

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
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

    /// A public room, which is what an `allow` entry usually names.
    async fn public_room(&self, token: &str) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                token,
                &json!({ "preset": "public_chat" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// A room whose join rule admits members of `allowed`.
    async fn restricted_room(&self, token: &str, rule: &str, allowed: &[&str]) -> String {
        let (status, body) = self
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room_id = body["room_id"].as_str().unwrap().to_owned();
        let allow: Vec<Value> = allowed
            .iter()
            .map(|room| json!({ "type": "m.room_membership", "room_id": room }))
            .collect();
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.join_rules"),
                token,
                &json!({ "join_rule": rule, "allow": allow }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room_id
    }

    async fn join(&self, room_id: &str, token: &str) -> (StatusCode, Value) {
        self.post(
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            token,
            &json!({}),
        )
        .await
    }

    async fn leave(&self, room_id: &str, token: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// The member event this server actually wrote, as the room holds it.
    async fn member_content(&self, room_id: &str, viewer: &str, user_id: &str) -> Value {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.member/{user_id}"),
                viewer,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

#[tokio::test]
async fn a_member_of_an_allowed_room_may_join_a_restricted_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let room = harness
        .restricted_room(&alice, "restricted", &[&space])
        .await;

    // Bob is nowhere near the allowed room yet: nothing to vouch for.
    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness.join(&space, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The nomination is on the event, not merely implied by its acceptance —
    // every other server verifies the join against exactly this field.
    let content = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(content["membership"], "join");
    assert_eq!(
        content["join_authorised_via_users_server"], "@alice:example.org",
        "the only member who could have invited Bob is the one named: {content}"
    );
}

#[tokio::test]
async fn leaving_the_allowed_room_withdraws_the_way_in() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let room = harness
        .restricted_room(&alice, "restricted", &[&space])
        .await;

    harness.join(&space, &bob).await;
    assert_eq!(harness.join(&room, &bob).await.0, StatusCode::OK);
    harness.leave(&room, &bob).await;
    harness.leave(&space, &bob).await;

    // Membership in the allowed room is a live fact, not a permit that was
    // issued once: having left it, Bob is a stranger again.
    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn knock_restricted_admits_the_same_membership() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let room = harness
        .restricted_room(&alice, "knock_restricted", &[&space])
        .await;

    harness.join(&space, &bob).await;
    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_allow_entry_naming_a_room_this_server_cannot_see_vouches_for_nobody() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    // A room on another server: we hold no membership rows for it, so we
    // cannot say whether Bob is in it — and must not guess that he is.
    let room = harness
        .restricted_room(&alice, "restricted", &["!elsewhere:remote.example"])
        .await;

    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn an_invited_user_joins_a_restricted_room_without_a_nomination() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let room = harness
        .restricted_room(&alice, "restricted", &[&space])
        .await;

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.join(&room, &bob).await.0, StatusCode::OK);

    // An invite is its own answer. Nominating anyway would put a claim on the
    // event that nothing needed to make — and that a redaction would strip.
    let content = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(content["membership"], "join");
    assert_eq!(content["join_authorised_via_users_server"], Value::Null);
}

#[tokio::test]
async fn a_room_that_names_nobody_still_nominates_the_member_it_has() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let room = harness
        .restricted_room(&alice, "restricted", &[&space])
        .await;
    // Alice gives up her named power. Every remaining member sits at
    // `users_default`, so the ranking has nothing to rank — and a room with
    // no ranked candidate still has someone who can vouch.
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"),
            &alice,
            &json!({
                "users": {},
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50, "kick": 50, "redact": 50, "invite": 0,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness.join(&space, &bob).await;
    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let content = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(
        content["join_authorised_via_users_server"],
        "@alice:example.org"
    );
}

#[tokio::test]
async fn a_v12_room_nominates_a_creator_no_power_levels_event_can_name() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let carol = harness.register("carol").await;
    let bob = harness.register("bob").await;

    let space = harness.public_room(&alice).await;
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/createRoom",
            &alice,
            &json!({ "room_version": "12" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    assert!(
        !room.contains(':'),
        "a v12 room ID is a hash, not a name on a server: {room}"
    );

    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            &alice,
            &json!({
                "join_rule": "restricted",
                "allow": [{ "type": "m.room_membership", "room_id": space }],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Carol is the only member a v12 `users` map is *allowed* to name —
    // MSC4289 forbids naming creators there — and she is deliberately set
    // below the invite level. So the room's own power-levels event offers no
    // usable candidate, and only Alice's implicit creator power can vouch.
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.join(&room, &carol).await.0, StatusCode::OK);
    let (status, body) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"),
            &alice,
            &json!({
                "users": { "@carol:example.org": 50 },
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50, "kick": 50, "redact": 50, "invite": 60,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness.join(&space, &bob).await;
    let (status, body) = harness.join(&room, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let content = harness
        .member_content(&room, &alice, "@bob:example.org")
        .await;
    assert_eq!(
        content["join_authorised_via_users_server"], "@alice:example.org",
        "ranking by the `users` map alone would have nominated Carol, whom \
         the rules refuse at invite level 60: {content}"
    );
}
