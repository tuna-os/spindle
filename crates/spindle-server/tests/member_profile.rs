//! A member event carries the member's profile (#317).
//!
//! Clients draw the roster from `m.room.member` events, not from profile
//! lookups, so a join that says only `{"membership": "join"}` shows the
//! joiner by ID until they next change their name. The spec has a join, an
//! invite and a knock carry `displayname` and `avatar_url`; a kick or a
//! leave adds nothing, because neither is about the target's profile.

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

    async fn send(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn ok(&self, method: &str, uri: &str, token: &str, body: &Value) -> Value {
        let (status, body) = self.send(method, uri, token, body).await;
        assert_eq!(status, StatusCode::OK, "{method} {uri}: {body}");
        body
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

    async fn set_profile(&self, token: &str, user_id: &str, name: &str, avatar: &str) {
        self.ok(
            "PUT",
            &format!("/_matrix/client/v3/profile/{user_id}/displayname"),
            token,
            &json!({ "displayname": name }),
        )
        .await;
        self.ok(
            "PUT",
            &format!("/_matrix/client/v3/profile/{user_id}/avatar_url"),
            token,
            &json!({ "avatar_url": avatar }),
        )
        .await;
    }

    async fn member(&self, room: &str, token: &str, user_id: &str) -> Value {
        self.call(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.member/{user_id}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .1
    }
}

#[tokio::test]
async fn the_creator_and_a_joiner_carry_their_profiles_and_a_kick_carries_none() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    h.set_profile(
        &alice,
        "@alice:example.org",
        "Alice",
        "mxc://example.org/alice",
    )
    .await;
    h.set_profile(&bob, "@bob:example.org", "Bob", "mxc://example.org/bob")
        .await;

    let room = h
        .ok("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        h.member(&room, &alice, "@alice:example.org").await,
        json!({
            "membership": "join",
            "displayname": "Alice",
            "avatar_url": "mxc://example.org/alice",
        }),
        "the creator's own join"
    );

    // The invite carries the *invitee's* profile: the inviter's client
    // shows who was invited from it.
    h.ok(
        "POST",
        &format!("/_matrix/client/v3/rooms/{room}/invite"),
        &alice,
        &json!({ "user_id": "@bob:example.org" }),
    )
    .await;
    assert_eq!(
        h.member(&room, &alice, "@bob:example.org").await,
        json!({
            "membership": "invite",
            "displayname": "Bob",
            "avatar_url": "mxc://example.org/bob",
        })
    );
    h.ok(
        "POST",
        &format!("/_matrix/client/v3/rooms/{room}/join"),
        &bob,
        &json!({}),
    )
    .await;
    assert_eq!(
        h.member(&room, &alice, "@bob:example.org").await,
        json!({
            "membership": "join",
            "displayname": "Bob",
            "avatar_url": "mxc://example.org/bob",
        })
    );

    // A kick is about the kicker's decision, not the target's profile.
    h.ok(
        "POST",
        &format!("/_matrix/client/v3/rooms/{room}/kick"),
        &alice,
        &json!({ "user_id": "@bob:example.org", "reason": "testing" }),
    )
    .await;
    assert_eq!(
        h.member(&room, &alice, "@bob:example.org").await,
        json!({ "membership": "leave", "reason": "testing" })
    );
}

#[tokio::test]
async fn a_user_without_a_profile_joins_with_a_bare_membership() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let room = h
        .ok("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        h.member(&room, &alice, "@alice:example.org").await,
        json!({ "membership": "join" }),
        "no nulls for a profile never set"
    );
}
