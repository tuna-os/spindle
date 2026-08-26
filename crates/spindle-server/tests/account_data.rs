//! Per-user data the server stores and never interprets.
//!
//! Two things are worth testing here and they pull in opposite directions.
//! The first is that the server really does have no opinion: a type it has
//! never heard of, holding content it cannot make sense of, has to round-trip
//! unchanged. The second is that the *keys* are exact -- account data is
//! keyed by three strings glued together, and the encoding has to make
//! collisions impossible rather than unlikely.

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

    async fn sync(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// The `content` stored under `event_type`, or `None` if the events block has
/// no such type.
fn from_events(events: &Value, event_type: &str) -> Option<Value> {
    events
        .as_array()?
        .iter()
        .find(|event| event["type"] == event_type)
        .map(|event| event["content"].clone())
}

#[tokio::test]
async fn account_data_round_trips_a_type_the_server_has_never_heard_of() {
    // The whole point of the endpoint: no schema, no validation, no opinion.
    // A client inventing a type has to work on a server that predates it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let content = json!({
        "nested": { "deeply": [1, 2, { "and": null }] },
        "unicode": "🪡",
        "empty_string": "",
    });

    let (status, body) = harness
        .put(
            "/_matrix/client/v3/user/@alice:example.org/account_data/com.example.nonsense",
            &alice,
            &content,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/com.example.nonsense",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, content, "stored bytes must come back unchanged");
}

#[tokio::test]
async fn a_type_that_was_never_set_is_a_404_not_an_empty_object() {
    // Same distinction `/state` draws: "no m.direct" and "an m.direct that is
    // empty" are different answers, and a client that cannot tell them apart
    // will overwrite one thinking it is the other.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");

    harness
        .put(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
            &alice,
            &json!({}),
        )
        .await;
    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "an empty object is a value: {body}");
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn a_put_replaces_rather_than_merges() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let path = "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct";

    harness
        .put(
            path,
            &alice,
            &json!({ "@bob:example.org": ["!a:example.org"] }),
        )
        .await;
    harness
        .put(
            path,
            &alice,
            &json!({ "@carol:example.org": ["!b:example.org"] }),
        )
        .await;

    let (_, body) = harness.get(path, &alice).await;
    assert_eq!(
        body,
        json!({ "@carol:example.org": ["!b:example.org"] }),
        "the second put must not have been merged into the first"
    );
}

#[tokio::test]
async fn one_user_cannot_read_or_write_anothers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let alices = "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct";

    harness
        .put(alices, &alice, &json!({ "secret": true }))
        .await;

    let (status, body) = harness.get(alices, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness.put(alices, &bob, &json!({ "secret": false })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (_, body) = harness.get(alices, &alice).await;
    assert_eq!(
        body,
        json!({ "secret": true }),
        "a refused write must not have half-happened"
    );

    // `M_FORBIDDEN` rather than `M_NOT_FOUND`, and for a type alice has never
    // set too: a server that answered 404 for the unset and 403 for the set
    // would be an oracle for what other people have configured.
    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/com.example.unset",
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn global_and_room_data_of_the_same_type_do_not_collide() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    harness
        .put(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.tag",
            &alice,
            &json!({ "scope": "global" }),
        )
        .await;
    harness
        .put(
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/account_data/m.tag"),
            &alice,
            &json!({ "scope": "room" }),
        )
        .await;

    let (_, global) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.tag",
            &alice,
        )
        .await;
    let (_, per_room) = harness
        .get(
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/account_data/m.tag"),
            &alice,
        )
        .await;
    assert_eq!(global, json!({ "scope": "global" }));
    assert_eq!(per_room, json!({ "scope": "room" }));
}

#[tokio::test]
async fn a_room_id_and_a_type_cannot_be_confused_for_a_longer_room_id() {
    // The key is (user, room, type) glued together, so without a length on the
    // room ID, room `!a:example.org` + type `xy` and room `!a:example.orgx` +
    // type `y` are the same bytes. Real room IDs make that hard to hit by
    // accident, which is exactly why it needs a test rather than a reader's
    // confidence: nothing in the types stops it and the failure is one room's
    // settings silently answering for another's.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let base = "/_matrix/client/v3/user/@alice:example.org/rooms";

    harness
        .put(
            &format!("{base}/!a:example.org/account_data/xy"),
            &alice,
            &json!({ "which": "first" }),
        )
        .await;
    harness
        .put(
            &format!("{base}/!a:example.orgx/account_data/y"),
            &alice,
            &json!({ "which": "second" }),
        )
        .await;

    let (_, first) = harness
        .get(&format!("{base}/!a:example.org/account_data/xy"), &alice)
        .await;
    let (_, second) = harness
        .get(&format!("{base}/!a:example.orgx/account_data/y"), &alice)
        .await;
    assert_eq!(first, json!({ "which": "first" }));
    assert_eq!(second, json!({ "which": "second" }));
}

#[tokio::test]
async fn one_users_data_is_not_reachable_under_a_similar_user_id() {
    // The user ID's length prefix, from the other direction: `@ab:x` must not
    // scan into `@abc:x`. Checked through the scan that `/sync` uses, because
    // a point lookup would pass even with a broken prefix.
    let harness = Harness::new();
    let ab = harness.register("ab").await;
    let abc = harness.register("abc").await;

    harness
        .put(
            "/_matrix/client/v3/user/@ab:example.org/account_data/m.tag",
            &ab,
            &json!({ "who": "ab" }),
        )
        .await;
    harness
        .put(
            "/_matrix/client/v3/user/@abc:example.org/account_data/m.tag",
            &abc,
            &json!({ "who": "abc" }),
        )
        .await;

    let events = harness.sync(&ab).await["account_data"]["events"].clone();
    assert_eq!(from_events(&events, "m.tag"), Some(json!({ "who": "ab" })));
    // Asserted as "abc's value appears nowhere" rather than as a count of the
    // events block: the server injects a default `m.push_rules` alongside, so
    // a count would measure how many kinds of account data exist rather than
    // whose data leaked.
    assert!(
        !events.to_string().contains("abc"),
        "abc's data must not be reachable under @ab: {events}"
    );
}

#[tokio::test]
async fn sync_carries_global_and_per_room_account_data_in_their_own_blocks() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    harness
        .put(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
            &alice,
            &json!({ "@bob:example.org": [&room] }),
        )
        .await;
    harness
        .put(
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room}/account_data/m.tag"),
            &alice,
            &json!({ "tags": { "m.favourite": {} } }),
        )
        .await;

    let body = harness.sync(&alice).await;
    let global = &body["account_data"]["events"];
    let per_room = &body["rooms"]["join"][&room]["account_data"]["events"];

    assert_eq!(
        from_events(global, "m.direct"),
        Some(json!({ "@bob:example.org": [&room] }))
    );
    assert!(
        from_events(global, "m.tag").is_none(),
        "a room's data must not leak into the global block: {global}"
    );
    assert_eq!(
        from_events(per_room, "m.tag"),
        Some(json!({ "tags": { "m.favourite": {} } }))
    );
    assert!(
        from_events(per_room, "m.direct").is_none(),
        "global data must not leak into a room's block: {per_room}"
    );
}

#[tokio::test]
async fn one_rooms_account_data_does_not_appear_under_another() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.create_room(&alice).await;
    let second = harness.create_room(&alice).await;

    harness
        .put(
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{first}/account_data/m.tag"),
            &alice,
            &json!({ "room": "first" }),
        )
        .await;

    let body = harness.sync(&alice).await;
    assert_eq!(
        from_events(
            &body["rooms"]["join"][&first]["account_data"]["events"],
            "m.tag"
        ),
        Some(json!({ "room": "first" }))
    );
    assert_eq!(
        body["rooms"]["join"][&second]["account_data"]["events"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "the other room has no account data: {body}"
    );
}

#[tokio::test]
async fn account_data_survives_a_restart() {
    // It is stored, not held: a client's settings outliving the process is the
    // only reason to write them down at all.
    let dir = TempDir::new().unwrap();
    let config = || spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();

    let token = {
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let harness = Harness {
            _dir: TempDir::new().unwrap(),
            app: spindle_server::app(config(), store).unwrap(),
        };
        let alice = harness.register("alice").await;
        harness
            .put(
                "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
                &alice,
                &json!({ "kept": true }),
            )
            .await;
        alice
    };

    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let harness = Harness {
        _dir: TempDir::new().unwrap(),
        app: spindle_server::app(config(), store).unwrap(),
    };
    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/account_data/m.direct",
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "kept": true }));
}
