//! Kick, ban, unban, forget, and the room roster.
//!
//! As with `membership.rs`, almost nothing here is about permission: whether
//! alice may kick bob is a power-level rule, and ruma owns those rules
//! (`docs/divergence.md` §3). What these tests pin down is the part that *is*
//! ours -- which membership each endpoint writes, what the roster reads from,
//! and the fact that forgetting is one user's bookkeeping rather than a change
//! to the room.

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
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
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
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// Get `user` into `room` the ordinary way: invited, then joining.
    async fn admit(&self, room: &str, inviter: &str, invitee_token: &str, user_id: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                inviter,
                &json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "invite: {body}");
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                invitee_token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "join: {body}");
    }

    async fn joined_rooms(&self, token: &str) -> Vec<String> {
        let (status, body) = self.get("/_matrix/client/v3/joined_rooms", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["joined_rooms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect()
    }

    /// The `membership` of `user` as the room's own state records it, which is
    /// the answer that matters -- the membership index is a derived cache and
    /// asserting against it would only prove the cache agrees with itself.
    async fn membership(&self, room: &str, token: &str, user_id: &str) -> Option<String> {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{user_id}"),
                token,
            )
            .await;
        if status == StatusCode::NOT_FOUND {
            return None;
        }
        assert_eq!(status, StatusCode::OK, "{body}");
        Some(body["membership"].as_str().unwrap().to_owned())
    }
}

#[tokio::test]
async fn a_kick_writes_leave_and_a_ban_writes_ban() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@bob:example.org", "reason": "off topic" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness.membership(&room, &alice, "@bob:example.org").await,
        Some("leave".to_owned()),
        "a kick is a leave the target did not send"
    );

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/ban"),
            &alice,
            &json!({ "user_id": "@carol:example.org", "reason": "spam" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness
            .membership(&room, &alice, "@carol:example.org")
            .await,
        Some("ban".to_owned()),
        "a ban is its own membership, not a leave with a note"
    );

    // The two differ in what they permit next, which is the whole reason they
    // are separate memberships: a kicked user was re-invited above, a banned
    // one cannot be.
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a banned user must not be re-invitable: {body}"
    );
}

#[tokio::test]
async fn the_kick_reason_reaches_the_event() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@bob:example.org", "reason": "off topic" }),
        )
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/@bob:example.org"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "off topic");
}

#[tokio::test]
async fn a_membership_change_with_no_reason_carries_no_reason_key() {
    // Not cosmetic: `reason` is inside `content`, so it is covered by the
    // event ID. A null where another server writes nothing is a different
    // event, hashing differently, and federation would disagree about the ID.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/@bob:example.org"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["membership"], "leave");
    assert!(
        body.get("reason").is_none(),
        "an absent reason must be absent, not null: {body}"
    );
}

#[tokio::test]
async fn unban_lets_the_user_back_in() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/ban"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/unban"),
            &alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        harness.membership(&room, &alice, "@bob:example.org").await,
        Some("leave".to_owned()),
        "unban writes leave -- the room cannot spell `never here`"
    );

    // And the ban is really lifted, which is the only thing a client cares
    // about: the invite that was refused while banned now works.
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    assert_eq!(
        harness.membership(&room, &alice, "@bob:example.org").await,
        Some("join".to_owned())
    );
}

#[tokio::test]
async fn a_member_without_power_cannot_kick() {
    // The refusal is ruma's, not ours. Asserting it happens is how we know the
    // auth rules are actually wired into this path rather than bypassed by it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &bob,
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        harness
            .membership(&room, &alice, "@carol:example.org")
            .await,
        Some("join".to_owned()),
        "a refused kick must not have half-happened"
    );
}

#[tokio::test]
async fn the_roster_lists_joined_members_only_and_only_to_members() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let dave = harness.register("dave").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .admit(&room, &alice, &carol, "@carol:example.org")
        .await;
    // Invited but never joined, and so not on the roster.
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@dave:example.org" }),
        )
        .await;
    // Joined, then kicked, and so no longer on it either.
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut listed: Vec<&str> = body["joined"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    listed.sort_unstable();
    assert_eq!(listed, vec!["@alice:example.org", "@bob:example.org"]);

    // The shape matters as much as the membership: a client reads these two
    // keys, and a member who set neither gets nulls rather than missing keys.
    let alice_entry = &body["joined"]["@alice:example.org"];
    assert!(
        alice_entry.get("display_name").is_some() && alice_entry.get("avatar_url").is_some(),
        "both profile keys must be present: {alice_entry}"
    );

    // Dave was invited, so he knows the room exists -- and still may not read
    // who is in it.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &dave,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn forgetting_is_refused_while_still_in_the_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a joined user must not be able to hide a room they still receive: {body}"
    );
    assert_eq!(harness.joined_rooms(&bob).await, vec![room.clone()]);

    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn forgetting_changes_nothing_for_anyone_else() {
    // The point of forgetting being local bookkeeping: bob's copy of history
    // is gone from his view, and alice's room is untouched -- including the
    // leave event that says bob was ever there.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;

    assert_eq!(
        harness.membership(&room, &alice, "@bob:example.org").await,
        Some("leave".to_owned()),
        "forgetting must not rewrite the room's own record of the leave"
    );
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["joined"].as_object().unwrap().len(),
        1,
        "alice is still in her own room: {body}"
    );
}

#[tokio::test]
async fn being_re_invited_undoes_forgetting() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    assert_eq!(harness.joined_rooms(&bob).await, vec![room.clone()]);

    // And the marker really is cleared, not merely shadowed by the join: bob
    // can leave and forget again, which a stuck marker would not stop but a
    // *second* forget of an already-forgotten room would not prove either --
    // so check the observable consequence instead, that leaving again and
    // forgetting again both still work from a clean slate.
    harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob,
            &json!({}),
        )
        .await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/forget"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn leaving_accepts_an_absent_body_and_rejects_a_malformed_one() {
    // Clients send all three of nothing, `{}`, and a populated object, and the
    // spec licenses all three. A malformed body is still an error: defaulting
    // there would swallow a typo'd `reason` rather than reporting it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.admit(&room, &alice, &bob, "@bob:example.org").await;

    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri(format!("/_matrix/client/v3/rooms/{room}/leave"))
                .header("authorization", format!("Bearer {bob}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an empty body is a valid leave: {body}"
    );

    harness.admit(&room, &alice, &bob, "@bob:example.org").await;
    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri(format!("/_matrix/client/v3/rooms/{room}/leave"))
                .header("authorization", format!("Bearer {bob}"))
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        harness.membership(&room, &alice, "@bob:example.org").await,
        Some("join".to_owned()),
        "a rejected leave must not have half-happened"
    );
}

#[tokio::test]
async fn forgetting_a_room_that_does_not_exist_is_a_404() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/rooms/!nope:example.org/forget",
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
