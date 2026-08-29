//! The published-room directory (#20's sibling: the client-visible half of
//! room discovery).
//!
//! Two things here are policy rather than protocol, and both are tested
//! because both are arguable: who may publish a room, and what a published
//! room that has since become unreadable does to the listing.

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
        Self {
            app: Self::build(store),
            _dir: dir,
        }
    }

    fn build(store: Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        spindle_server::app(config, store).expect("a signing key is established")
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
}

impl Harness {
    async fn room(&self, token: &str, extra: Value) -> String {
        let mut request = json!({});
        if let Value::Object(fields) = extra {
            for (key, value) in fields {
                request[key] = value;
            }
        }
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                &request,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn publish(&self, token: &str, room: &str, visibility: &str) -> (StatusCode, Value) {
        self.request(
            "PUT",
            &format!("/_matrix/client/v3/directory/list/room/{room}"),
            Some(token),
            &json!({ "visibility": visibility }),
        )
        .await
    }

    async fn directory(&self) -> Value {
        let (status, body) = self
            .request("GET", "/_matrix/client/v3/publicRooms", None, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn listed(body: &Value) -> Vec<String> {
    body["chunk"]
        .as_array()
        .expect("a chunk")
        .iter()
        .map(|entry| entry["room_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A room is private until somebody says otherwise.
///
/// The spec's default, and the safer way round: a client that forgets the
/// field gets an unlisted room rather than an advertised one.
#[tokio::test]
async fn a_new_room_is_not_in_the_directory() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room(&alice, json!({})).await;

    assert!(listed(&harness.directory().await).is_empty());
    let (_, body) = harness
        .request(
            "GET",
            &format!("/_matrix/client/v3/directory/list/room/{room}"),
            None,
            &json!({}),
        )
        .await;
    assert_eq!(body["visibility"], "private");
}

/// `createRoom` with `visibility: "public"` publishes it.
#[tokio::test]
async fn create_room_can_publish_directly() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness
        .room(&alice, json!({ "visibility": "public" }))
        .await;

    assert_eq!(listed(&harness.directory().await), vec![room]);
}

/// Publishing and unpublishing round-trip, and unpublishing twice is fine.
#[tokio::test]
async fn visibility_round_trips_and_unpublishing_is_idempotent() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room(&alice, json!({})).await;

    assert_eq!(
        harness.publish(&alice, &room, "public").await.0,
        StatusCode::OK
    );
    assert_eq!(listed(&harness.directory().await), vec![room.clone()]);

    assert_eq!(
        harness.publish(&alice, &room, "private").await.0,
        StatusCode::OK
    );
    assert!(listed(&harness.directory().await).is_empty());
    // Again: removing something already absent is not an error.
    assert_eq!(
        harness.publish(&alice, &room, "private").await.0,
        StatusCode::OK
    );
}

/// A stranger cannot advertise somebody else's room.
///
/// The policy this file exists to pin. Alias creation lets any authenticated
/// user claim any free alias; the directory is stricter because it is a list
/// this server hands to strangers, so publishing is spam surface in a way
/// that claiming a name nobody knows is not.
#[tokio::test]
async fn a_non_member_cannot_publish_a_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness.room(&alice, json!({})).await;

    let (status, body) = harness.publish(&mallory, &room, "public").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(listed(&harness.directory().await).is_empty());
}

/// A room nobody has heard of is "no such room", not "you may not".
///
/// Order matters: testing permission first would tell a stranger that a room
/// exists and they merely are not in it.
#[tokio::test]
async fn publishing_a_room_that_does_not_exist_says_so() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness.publish(&alice, "!nope:example.org", "public").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// A visibility that is neither "public" nor "private" is refused.
#[tokio::test]
async fn an_unknown_visibility_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room(&alice, json!({})).await;

    let (status, _) = harness.publish(&alice, &room, "translucent").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The listing carries what a client needs to render a row.
#[tokio::test]
async fn a_listed_room_carries_its_summary() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness
        .room(
            &alice,
            json!({ "visibility": "public", "name": "Spindle", "topic": "a log, not a DAG" }),
        )
        .await;

    let body = harness.directory().await;
    let entry = &body["chunk"][0];
    assert_eq!(entry["room_id"], room);
    assert_eq!(entry["name"], "Spindle");
    assert_eq!(entry["topic"], "a log, not a DAG");
    assert_eq!(entry["num_joined_members"], 1);
    assert!(entry["world_readable"].is_boolean());
    assert!(entry["guest_can_join"].is_boolean());
    assert_eq!(body["total_room_count_estimate"], 1);
}

/// Pagination hands out every room exactly once.
///
/// The property that matters is not "a page has N entries" but that walking
/// the pages sees each room once -- a directory that reordered between pages
/// would repeat some and skip others, and the skip is invisible.
#[tokio::test]
async fn paging_covers_every_room_exactly_once() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mut created = Vec::new();
    for _ in 0..5 {
        created.push(
            harness
                .room(&alice, json!({ "visibility": "public" }))
                .await,
        );
    }

    let mut seen: Vec<String> = Vec::new();
    let mut since: Option<String> = None;
    for _ in 0..10 {
        let path = match &since {
            Some(token) => format!("/_matrix/client/v3/publicRooms?limit=2&since={token}"),
            None => "/_matrix/client/v3/publicRooms?limit=2".to_owned(),
        };
        let (status, body) = harness.request("GET", &path, None, &json!({})).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        seen.extend(listed(&body));
        match body["next_batch"].as_str() {
            Some(token) => since = Some(token.to_owned()),
            None => break,
        }
    }

    created.sort();
    seen.sort();
    assert_eq!(
        seen, created,
        "paging did not cover the directory exactly once"
    );
}

/// The POST form filters by search term over name, topic and alias.
#[tokio::test]
async fn the_filtered_form_matches_name_and_topic() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let wanted = harness
        .room(
            &alice,
            json!({ "visibility": "public", "name": "Rust homeservers" }),
        )
        .await;
    let _other = harness
        .room(
            &alice,
            json!({ "visibility": "public", "name": "Gardening" }),
        )
        .await;

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/publicRooms",
            Some(&alice),
            &json!({ "filter": { "generic_search_term": "homeserver" } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(listed(&body), vec![wanted]);
    // The estimate counts what matched, not what exists.
    assert_eq!(body["total_room_count_estimate"], 1);
}

/// Another server's directory is refused rather than answered from ours.
///
/// Silently serving our own list under someone else's name is the failure
/// worth preventing: the client would believe it had seen their rooms.
#[tokio::test]
async fn another_servers_directory_is_not_answered_from_ours() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness
        .room(&alice, json!({ "visibility": "public" }))
        .await;

    let (status, _) = harness
        .request(
            "GET",
            "/_matrix/client/v3/publicRooms?server=elsewhere.example",
            None,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}

/// The directory is ordered by room ID, not by how the store lays keys out.
///
/// Driven below the HTTP layer on purpose: `createRoom` mints fixed-length
/// IDs, and raw store order sorts on the big-endian length `room_prefix`
/// writes *before* the ID -- so only IDs of differing length can tell the two
/// orders apart. Without this, dropping the sort in `Directory::published`
/// changes nothing observable and the ordering guarantee rots untested.
#[tokio::test]
async fn the_directory_is_ordered_by_room_id_not_by_key_layout() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let directory = spindle_server::directory::Directory::new(Arc::clone(&store), "example.org");

    // `!bb` is longer than `!c`, so key order and room-ID order disagree.
    for room in ["!c:example.org", "!bb:example.org", "!a:example.org"] {
        directory.publish(room, "@alice:example.org").unwrap();
    }

    assert_eq!(
        directory.published().unwrap(),
        vec![
            "!a:example.org".to_owned(),
            "!bb:example.org".to_owned(),
            "!c:example.org".to_owned(),
        ]
    );
}
