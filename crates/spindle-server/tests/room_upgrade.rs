//! Upgrading a room to a new version.
//!
//! This is the path #178's v12 work depends on: a room created at 11 has no
//! other way to reach 12, and v12 exists because the old state-resolution
//! behaviour was exploitable (CVE-2025-49090, CVE-2025-54315). An upgrade
//! nobody can perform means those rooms stay on the vulnerable version.

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
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
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

    async fn create_room(&self, token: &str, payload: &Value) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn upgrade(&self, room: &str, token: &str, version: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(format!("/_matrix/client/v3/rooms/{room}/upgrade"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "new_version": version }).to_string()))
                .unwrap(),
        )
        .await
    }

    async fn state(&self, room: &str, token: &str) -> Vec<Value> {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(format!("/_matrix/client/v3/rooms/{room}/state"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body.as_array().cloned().unwrap_or_default()
    }

    async fn joined_rooms(&self, token: &str) -> Vec<String> {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/_matrix/client/v3/joined_rooms")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["joined_rooms"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|room| room.as_str().map(str::to_owned))
            .collect()
    }

    async fn invite_and_join(&self, room: &str, host: &str, guest_name: &str, guest: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/invite"))
                    .header("authorization", format!("Bearer {host}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "user_id": format!("@{guest_name}:example.org") }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/join"))
                    .header("authorization", format!("Bearer {guest}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    fn find<'a>(state: &'a [Value], event_type: &str) -> Option<&'a Value> {
        state.iter().find(|event| event["type"] == event_type)
    }
}

/// The whole round trip: a v11 room becomes a v12 room that knows where it
/// came from, and the old room points at it.
#[tokio::test]
async fn a_room_upgrades_and_both_halves_know_about_each_other() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let old = harness
        .create_room(
            &alice,
            &json!({ "name": "the room", "topic": "about things" }),
        )
        .await;

    let (status, body) = harness.upgrade(&old, &alice, "12").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["replacement_room"].as_str().unwrap().to_owned();
    assert_ne!(new, old, "the replacement is a different room");

    // Forwards: the old room's tombstone points at the new one.
    let old_state = harness.state(&old, &alice).await;
    let tombstone = Harness::find(&old_state, "m.room.tombstone")
        .unwrap_or_else(|| panic!("the old room was not tombstoned: {old_state:?}"));
    assert_eq!(tombstone["content"]["replacement_room"], new.as_str());

    // Backwards: the new room's create event names its predecessor, which
    // is what lets a client show the room's history across the boundary.
    let new_state = harness.state(&new, &alice).await;
    let create = Harness::find(&new_state, "m.room.create").unwrap();
    assert_eq!(create["content"]["predecessor"]["room_id"], old.as_str());
    assert_eq!(
        create["content"]["room_version"], "12",
        "the upgrade went to the version that was asked for: {create}"
    );
}

/// Room settings come across; the things that must not, do not.
#[tokio::test]
async fn an_upgrade_carries_the_settings_and_not_the_membership() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let old = harness
        .create_room(
            &alice,
            &json!({ "name": "carried", "topic": "also carried" }),
        )
        .await;
    // Bob exists so that "membership was not copied" is a claim with teeth:
    // in a room whose only member is the upgrader, copying membership and
    // not copying it produce the same one-member result.
    harness.invite_and_join(&old, &alice, "bob", &bob).await;

    let (status, body) = harness.upgrade(&old, &alice, "12").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new = body["replacement_room"].as_str().unwrap().to_owned();
    let new_state = harness.state(&new, &alice).await;

    assert_eq!(
        Harness::find(&new_state, "m.room.name").map(|e| e["content"]["name"].clone()),
        Some(json!("carried")),
    );
    assert_eq!(
        Harness::find(&new_state, "m.room.topic").map(|e| e["content"]["topic"].clone()),
        Some(json!("also carried")),
    );
    assert!(
        Harness::find(&new_state, "m.room.tombstone").is_none(),
        "a new room born with a tombstone is dead on arrival: {new_state:?}"
    );

    // Only the upgrading user is in the new room. Everyone else rejoins
    // through the tombstone, which is what re-runs the join rules against
    // the new version rather than trusting the old room's answer.
    let members: Vec<&Value> = new_state
        .iter()
        .filter(|event| event["type"] == "m.room.member")
        .collect();
    assert_eq!(
        members.len(),
        1,
        "Bob was carried across instead of rejoining through the tombstone, \
         which skips re-running the join rules under the new version: {members:?}"
    );
}

/// A version this server does not speak is refused, with the spec's code.
///
/// Substituting a supported version and reporting success would be the same
/// lie `Rooms::create` already refuses to tell: the client cannot detect it
/// until something version-dependent fails.
#[tokio::test]
async fn an_unsupported_version_is_refused_by_name() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let old = harness.create_room(&alice, &json!({})).await;

    let (status, body) = harness.upgrade(&old, &alice, "99").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_UNSUPPORTED_ROOM_VERSION");

    // And the old room is untouched — no tombstone was written on the way
    // to failing, which is the ordering property this endpoint depends on.
    let old_state = harness.state(&old, &alice).await;
    assert!(
        Harness::find(&old_state, "m.room.tombstone").is_none(),
        "a refused upgrade still tombstoned the room: {old_state:?}"
    );
}

/// Someone who is not in the room cannot upgrade it.
#[tokio::test]
async fn an_outsider_cannot_upgrade_a_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let old = harness.create_room(&alice, &json!({})).await;

    let before = harness.joined_rooms(&mallory).await;
    let (status, body) = harness.upgrade(&old, &mallory, "12").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let old_state = harness.state(&old, &alice).await;
    assert!(
        Harness::find(&old_state, "m.room.tombstone").is_none(),
        "a refused upgrade still tombstoned the room: {old_state:?}"
    );
    // And no half-built replacement was left lying around. Refusing at the
    // tombstone instead of at the door would return the same 403 while
    // having already created a room -- a leak the status code hides.
    assert_eq!(
        harness.joined_rooms(&mallory).await,
        before,
        "the refused upgrade still created a replacement room"
    );
}
