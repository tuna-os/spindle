//! MSC3266's room summary — what a room looks like from outside it.
//!
//! The endpoint exists so a client can render a preview of a room it has not
//! joined, which shapes almost every decision here: it is optionally
//! authenticated, the room decides who may see it rather than the caller, and
//! every field is optional because a room with no name, no topic and no avatar
//! is ordinary rather than broken.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

fn encoded(alias: &str) -> String {
    alias.replace('#', "%23")
}

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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut builder = Request::builder().uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::empty()).unwrap()).await
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn set_state(&self, room: &str, token: &str, event_type: &str, content: &Value) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}"),
                Some(token),
                content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{event_type}: {body}");
    }

    async fn summary(&self, room: &str, token: Option<&str>) -> (StatusCode, Value) {
        self.get(&format!("/_matrix/client/v1/room_summary/{room}"), token)
            .await
    }

    /// Make the room public, which is what makes it summarisable by strangers.
    async fn publish(&self, room: &str, token: &str) {
        self.set_state(
            room,
            token,
            "m.room.join_rules",
            &json!({ "join_rule": "public" }),
        )
        .await;
    }
}

#[tokio::test]
async fn a_public_room_summarises_to_a_stranger_with_no_token() {
    // The whole point of the endpoint: a preview needs no account, because a
    // client previewing a room it has not joined has no membership to offer.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;
    harness
        .set_state(
            &room,
            &alice,
            "m.room.name",
            &json!({ "name": "The Lobby" }),
        )
        .await;
    harness
        .set_state(
            &room,
            &alice,
            "m.room.topic",
            &json!({ "topic": "Come in" }),
        )
        .await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);
    assert_eq!(body["name"], "The Lobby");
    assert_eq!(body["topic"], "Come in");
    assert_eq!(body["num_joined_members"], 1);
    assert_eq!(body["join_rule"], "public");
    assert!(
        body.get("membership").is_none(),
        "a caller with no token has no membership to report: {body}"
    );
}

#[tokio::test]
async fn a_private_room_is_refused_to_a_stranger_and_shown_to_a_member() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    // createRoom sets join_rule: invite, so this room publishes nothing.
    let room = harness.create_room(&alice).await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness.summary(&room, Some(&bob)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token is not membership: {body}"
    );

    // A member may always see their own room, whatever the rules say: they can
    // read the state directly anyway, so refusing here would protect nothing.
    let (status, body) = harness.summary(&room, Some(&alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["membership"], "join");
}

#[tokio::test]
async fn world_readable_history_makes_a_room_summarisable_even_when_invite_only() {
    // `world_readable` is about history, not about joining. A room that lets
    // anyone read it is one anyone may summarise, even though nobody may join.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness
        .set_state(
            &room,
            &alice,
            "m.room.history_visibility",
            &json!({ "history_visibility": "world_readable" }),
        )
        .await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["world_readable"], true);
    assert_eq!(
        body["join_rule"], "invite",
        "readable is not joinable, and the summary says so: {body}"
    );
}

#[tokio::test]
async fn world_readable_is_not_inferred_from_the_join_rule() {
    // The two are separate state events, and conflating them would report a
    // public room whose history is members-only as readable by anyone.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;
    harness
        .set_state(
            &room,
            &alice,
            "m.room.history_visibility",
            &json!({ "history_visibility": "joined" }),
        )
        .await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["join_rule"], "public");
    assert_eq!(
        body["world_readable"], false,
        "a public room may still keep its history private: {body}"
    );
}

#[tokio::test]
async fn a_knockable_room_publishes_a_summary() {
    // Knocking is asking to be let in, which is impossible without first
    // seeing what you are asking about.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness
        .set_state(
            &room,
            &alice,
            "m.room.join_rules",
            &json!({ "join_rule": "knock" }),
        )
        .await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["join_rule"], "knock");
}

#[tokio::test]
async fn fields_the_room_never_set_are_absent_rather_than_null() {
    // A client distinguishing "no topic" from "an empty topic" needs the key
    // missing, not null.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;

    let (status, body) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for absent in [
        "name",
        "topic",
        "avatar_url",
        "canonical_alias",
        "encryption",
    ] {
        assert!(
            body.get(absent).is_none(),
            "{absent} was never set and must be absent, not null: {body}"
        );
    }
    // The two booleans are always present: for them, unset and false mean the
    // same thing, so there is nothing to distinguish.
    assert_eq!(body["world_readable"], false);
    assert_eq!(body["guest_can_join"], false);
}

#[tokio::test]
async fn the_member_count_is_the_joined_count() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;

    for (token, user) in [(&bob, "@bob:example.org"), (&carol, "@carol:example.org")] {
        let (status, body) = harness
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(token),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{user}: {body}");
    }
    let (_, body) = harness.summary(&room, None).await;
    assert_eq!(body["num_joined_members"], 3);

    // An invited user is not joined, and a kicked one is no longer.
    let dave = harness.register("dave").await;
    let _ = dave;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            &json!({ "user_id": "@dave:example.org" }),
        )
        .await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            Some(&alice),
            &json!({ "user_id": "@carol:example.org" }),
        )
        .await;

    let (_, body) = harness.summary(&room, None).await;
    assert_eq!(
        body["num_joined_members"], 2,
        "an invite is not a join and a kick is not one either: {body}"
    );
}

#[tokio::test]
async fn a_summary_can_be_asked_for_by_alias() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;
    harness
        .request(
            "PUT",
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            Some(&alice),
            &json!({ "room_id": room }),
        )
        .await;

    let (status, body) = harness.summary(&encoded("#lobby:example.org"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);
}

#[tokio::test]
async fn an_alias_pointing_nowhere_is_a_404_and_names_the_alias() {
    let harness = Harness::new();
    let (status, body) = harness.summary(&encoded("#absent:example.org"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("#absent:example.org"),
        "{body}"
    );
}

#[tokio::test]
async fn an_unknown_room_is_a_404() {
    let harness = Harness::new();
    let (status, body) = harness.summary("!nope:example.org", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_present_but_invalid_token_is_an_error_not_an_anonymous_view() {
    // Falling back to anonymous would quietly downgrade a caller whose session
    // expired, showing them a stranger's view of a room they are in.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;

    let (status, body) = harness.summary(&room, Some("not-a-real-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

#[tokio::test]
async fn the_unstable_path_serves_the_same_summary() {
    // MSC3266 shipped under the unstable prefix long enough that clients still
    // ask for it there.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.publish(&room, &alice).await;

    let (status, stable) = harness.summary(&room, None).await;
    assert_eq!(status, StatusCode::OK, "{stable}");
    let (status, unstable) = harness
        .get(
            &format!("/_matrix/client/unstable/im.nheko.summary/rooms/{room}/summary"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{unstable}");
    assert_eq!(stable, unstable);

    // And the flag says so, which is what a client checks before probing.
    let (_, versions) = harness.get("/_matrix/client/versions", None).await;
    assert_eq!(versions["unstable_features"]["im.nheko.summary"], true);
}
