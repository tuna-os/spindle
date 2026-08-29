//! Who a user directory search is allowed to find.
//!
//! The endpoint is small; the visibility rule is not, and it is the whole
//! reason this file exists. The spec sets a floor -- users you share a room
//! with, users in public rooms -- and leaves the rest to the server, so what
//! Spindle does NOT return is as much a decision as what it does.

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

    async fn invite_and_join(&self, host: &str, room: &str, guest: &str, guest_id: &str) {
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                Some(host),
                &json!({ "user_id": guest_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "invite: {body}");
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(guest),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "join: {body}");
    }

    async fn set_displayname(&self, token: &str, user_id: &str, name: &str) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/profile/{user_id}/displayname"),
                Some(token),
                &json!({ "displayname": name }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn search(&self, token: &str, term: &str) -> Value {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/user_directory/search",
                Some(token),
                &json!({ "search_term": term }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn found(body: &Value) -> Vec<String> {
    body["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|entry| entry["user_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A stranger with no shared room and no public room is not findable.
///
/// The decision this file exists to pin. Returning every account would make
/// the directory a user-enumeration endpoint: one account would reveal every
/// localpart on the server, and somebody who joined no public room never
/// agreed to that.
#[tokio::test]
async fn a_user_sharing_nothing_is_not_findable() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let _bob = harness.register("bob").await;

    assert!(
        found(&harness.search(&alice, "bob").await).is_empty(),
        "an unrelated account was exposed by search"
    );
}

/// Someone you share a joined room with is findable.
///
/// Their name and avatar are already in that room's member list, so the
/// directory reveals nothing the searcher could not already see.
#[tokio::test]
async fn someone_you_share_a_room_with_is_findable() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice, json!({})).await;
    harness
        .invite_and_join(&alice, &room, &bob, "@bob:example.org")
        .await;

    assert_eq!(
        found(&harness.search(&alice, "bob").await),
        vec!["@bob:example.org".to_owned()]
    );
}

/// Someone in a published room is findable even with no room in common.
///
/// The other half of the spec's floor, and the half #242 made reachable:
/// they chose to be in a room this server advertises to strangers.
#[tokio::test]
async fn someone_in_a_published_room_is_findable() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let carol = harness.register("carol").await;
    // Carol's room is published; alice is not in it.
    harness
        .room(&carol, json!({ "visibility": "public" }))
        .await;

    assert_eq!(
        found(&harness.search(&alice, "carol").await),
        vec!["@carol:example.org".to_owned()]
    );
}

/// Unpublishing the room takes its members back out of the directory.
///
/// Visibility is not a one-way door: a room withdrawn from the directory
/// stops exposing the people in it.
#[tokio::test]
async fn unpublishing_a_room_hides_its_members_again() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let carol = harness.register("carol").await;
    let room = harness
        .room(&carol, json!({ "visibility": "public" }))
        .await;
    assert!(!found(&harness.search(&alice, "carol").await).is_empty());

    let (status, _) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/directory/list/room/{room}"),
            Some(&carol),
            &json!({ "visibility": "private" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        found(&harness.search(&alice, "carol").await).is_empty(),
        "unpublishing the room left its members exposed"
    );
}

/// The searcher is never their own result.
#[tokio::test]
async fn the_searcher_is_not_returned_to_themselves() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness
        .room(&alice, json!({ "visibility": "public" }))
        .await;

    assert!(
        !found(&harness.search(&alice, "alice").await).contains(&"@alice:example.org".to_owned())
    );
}

/// Display names are searchable, and come back with the result.
#[tokio::test]
async fn a_display_name_is_searchable_and_returned() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let carol = harness.register("carol").await;
    harness
        .set_displayname(&carol, "@carol:example.org", "Carolina Quartz")
        .await;
    harness
        .room(&carol, json!({ "visibility": "public" }))
        .await;

    let body = harness.search(&alice, "quartz").await;
    assert_eq!(found(&body), vec!["@carol:example.org".to_owned()]);
    assert_eq!(body["results"][0]["display_name"], "Carolina Quartz");
}

/// The server name is not a search term.
///
/// Every local ID ends in it, so matching the full user ID would return the
/// whole directory for a search of "example.org" -- which reads as a bug.
#[tokio::test]
async fn the_server_name_does_not_match_everyone() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let carol = harness.register("carol").await;
    harness
        .room(&carol, json!({ "visibility": "public" }))
        .await;

    assert!(
        found(&harness.search(&alice, "example.org").await).is_empty(),
        "searching the server name returned the directory"
    );
}

/// `limited` says whether results were cut, and the cut is honoured.
#[tokio::test]
async fn a_truncated_search_says_it_was_truncated() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mut tokens = Vec::new();
    for index in 0..4 {
        tokens.push(harness.register(&format!("finder{index}")).await);
    }
    for token in &tokens {
        harness.room(token, json!({ "visibility": "public" })).await;
    }

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/user_directory/search",
            Some(&alice),
            &json!({ "search_term": "finder", "limit": 2 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(found(&body).len(), 2);
    assert_eq!(body["limited"], true);

    // And an uncut search says so.
    let whole = harness.search(&alice, "finder").await;
    assert_eq!(found(&whole).len(), 4);
    assert_eq!(whole["limited"], false);
}
