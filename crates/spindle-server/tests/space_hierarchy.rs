//! The spaces hierarchy walk.
//!
//! `m.space.child` is a GRAPH, not a tree: a space may contain itself, and
//! two spaces may contain each other. The cycle test here is not a nicety --
//! without the visited set the endpoint never returns, so it is the
//! difference between a feature and a hang.

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
    async fn space(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                &json!({ "creation_content": { "type": "m.space" } }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn plain_room(&self, token: &str, public: bool) -> String {
        let preset = if public {
            "public_chat"
        } else {
            "private_chat"
        };
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                &json!({ "preset": preset }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// Add `child` to `parent`'s children.
    async fn add_child(&self, token: &str, parent: &str, child: &str) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{parent}/state/m.space.child/{child}"),
                Some(token),
                &json!({ "via": ["example.org"] }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "add_child: {body}");
    }

    async fn hierarchy(&self, token: &str, room: &str, query: &str) -> (StatusCode, Value) {
        self.request(
            "GET",
            &format!("/_matrix/client/v1/rooms/{room}/hierarchy{query}"),
            Some(token),
            &json!({}),
        )
        .await
    }
}

fn walked(body: &Value) -> Vec<String> {
    body["rooms"]
        .as_array()
        .expect("rooms")
        .iter()
        .map(|entry| entry["room_id"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A space with one child returns both, the child carrying its own summary.
#[tokio::test]
async fn a_space_and_its_child_are_returned() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let space = harness.space(&alice).await;
    let child = harness.plain_room(&alice, true).await;
    harness.add_child(&alice, &space, &child).await;

    let (status, body) = harness.hierarchy(&alice, &space, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(walked(&body), vec![space.clone(), child.clone()]);

    // The root carries the child pointer; the leaf carries none.
    assert_eq!(body["rooms"][0]["children_state"][0]["state_key"], child);
    assert_eq!(body["rooms"][0]["room_type"], "m.space");
    assert_eq!(
        body["rooms"][1]["children_state"].as_array().map(Vec::len),
        Some(0)
    );
}

/// A space that contains itself terminates.
///
/// Without the visited set this hangs rather than fails, which is why it is
/// tested directly instead of trusted to the walk's shape.
#[tokio::test]
async fn a_space_containing_itself_terminates() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let space = harness.space(&alice).await;
    harness.add_child(&alice, &space, &space).await;

    let (status, body) = harness.hierarchy(&alice, &space, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(walked(&body), vec![space]);
}

/// Two spaces containing each other terminate, and each appears once.
#[tokio::test]
async fn mutually_containing_spaces_terminate() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.space(&alice).await;
    let second = harness.space(&alice).await;
    harness.add_child(&alice, &first, &second).await;
    harness.add_child(&alice, &second, &first).await;

    let (status, body) = harness.hierarchy(&alice, &first, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut seen = walked(&body);
    seen.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(seen, expected, "a room appeared twice or the walk diverged");
}

/// A private room somebody else owns is left out of the tree.
///
/// The hierarchy is handed to people who may be in none of these rooms, so it
/// must not become a way to enumerate private ones.
#[tokio::test]
async fn a_private_child_is_not_shown_to_a_stranger() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let space = harness.plain_room(&alice, true).await;
    let secret = harness.plain_room(&alice, false).await;
    harness.add_child(&alice, &space, &secret).await;

    // Alice, who is in it, sees it.
    let (_, mine) = harness.hierarchy(&alice, &space, "").await;
    assert!(walked(&mine).contains(&secret));

    // Bob, who is not, does not.
    let (status, theirs) = harness.hierarchy(&bob, &space, "").await;
    assert_eq!(status, StatusCode::OK, "{theirs}");
    assert!(
        !walked(&theirs).contains(&secret),
        "a private room leaked into a stranger's hierarchy"
    );
}

/// A root the caller may not see is a refusal, not an empty page.
///
/// An empty page would say "this space is empty", which is a different claim
/// and a false one.
#[tokio::test]
async fn an_invisible_root_is_refused_rather_than_empty() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let secret = harness.plain_room(&alice, false).await;

    let (status, _) = harness.hierarchy(&bob, &secret, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// `suggested_only` filters to the children marked suggested.
#[tokio::test]
async fn suggested_only_filters_the_children() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let space = harness.space(&alice).await;
    let plain = harness.plain_room(&alice, true).await;
    let suggested = harness.plain_room(&alice, true).await;
    harness.add_child(&alice, &space, &plain).await;
    let (status, body) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{space}/state/m.space.child/{suggested}"),
            Some(&alice),
            &json!({ "via": ["example.org"], "suggested": true }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, all) = harness.hierarchy(&alice, &space, "").await;
    assert_eq!(walked(&all).len(), 3);

    let (_, only) = harness
        .hierarchy(&alice, &space, "?suggested_only=true")
        .await;
    assert_eq!(walked(&only), vec![space, suggested]);
}

/// A child whose `via` is empty is not a child.
///
/// That is how the spec says a child is *removed* -- the state event stays,
/// with content emptied -- so treating it as present would make deletion
/// impossible.
#[tokio::test]
async fn a_child_with_no_via_is_ignored() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let space = harness.space(&alice).await;
    let child = harness.plain_room(&alice, true).await;
    harness.add_child(&alice, &space, &child).await;
    assert_eq!(
        walked(&harness.hierarchy(&alice, &space, "").await.1).len(),
        2
    );

    // Remove it the way the spec says to.
    let (status, _) = harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{space}/state/m.space.child/{child}"),
            Some(&alice),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        walked(&harness.hierarchy(&alice, &space, "").await.1),
        vec![space]
    );
}

/// Paging covers the tree exactly once.
#[tokio::test]
async fn paging_covers_the_tree_exactly_once() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let space = harness.space(&alice).await;
    let mut expected = vec![space.clone()];
    for _ in 0..4 {
        let child = harness.plain_room(&alice, true).await;
        harness.add_child(&alice, &space, &child).await;
        expected.push(child);
    }

    let mut seen = Vec::new();
    let mut from: Option<String> = None;
    for _ in 0..10 {
        let query = match &from {
            Some(token) => format!("?limit=2&from={token}"),
            None => "?limit=2".to_owned(),
        };
        let (status, body) = harness.hierarchy(&alice, &space, &query).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        seen.extend(walked(&body));
        match body["next_batch"].as_str() {
            Some(token) => from = Some(token.to_owned()),
            None => break,
        }
    }

    seen.sort();
    expected.sort();
    assert_eq!(seen, expected, "paging did not cover the tree exactly once");
}

/// An invisible room in the middle of the tree does not shorten a page.
///
/// The bug this pins is subtle and was live until visibility moved to a
/// single check: filtering once on the way in and again at render time makes
/// `total` count rooms the caller cannot see, so `next_batch` is computed
/// from one number while the page is built from another -- and a page
/// containing an invisible room comes back SHORT. A client that pages by
/// counting then mis-pages, and nothing about the response says why.
#[tokio::test]
async fn an_invisible_room_does_not_shorten_a_page() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let space = harness.plain_room(&alice, true).await;

    // A private room between two public ones, so it lands inside bob's
    // first page rather than at the end where a short page would not show.
    let first = harness.plain_room(&alice, true).await;
    let secret = harness.plain_room(&alice, false).await;
    let second = harness.plain_room(&alice, true).await;
    for child in [&first, &secret, &second] {
        harness.add_child(&alice, &space, child).await;
    }

    // Bob sees the space and the two public children: three rooms.
    let (status, all) = harness.hierarchy(&bob, &space, "").await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(walked(&all).len(), 3, "{all}");

    // Paging two at a time must give 2 then 1, never a short first page.
    let (_, page) = harness.hierarchy(&bob, &space, "?limit=2").await;
    assert_eq!(
        walked(&page).len(),
        2,
        "the first page was short because an invisible room was counted: {page}"
    );
    let token = page["next_batch"]
        .as_str()
        .expect("a second page")
        .to_owned();
    let (_, rest) = harness
        .hierarchy(&bob, &space, &format!("?limit=2&from={token}"))
        .await;
    assert_eq!(walked(&rest).len(), 1);

    let mut seen = walked(&page);
    seen.extend(walked(&rest));
    seen.sort();
    let mut expected = vec![space, first, second];
    expected.sort();
    assert_eq!(seen, expected);
}

/// A chain deeper than the server's cap is truncated, not walked.
///
/// `max_depth` has no default in the spec, and the graph is one strangers can
/// extend, so an uncapped walk is a denial of service against your own server
/// -- one request, arbitrarily many state reads. The cap is therefore the
/// server's, and a client asking to go deeper does not get to.
#[tokio::test]
async fn a_deep_chain_stops_at_the_servers_cap() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    // A chain of 12 spaces, each containing the next: deeper than the cap.
    let mut chain = Vec::new();
    for _ in 0..12 {
        chain.push(harness.space(&alice).await);
    }
    for pair in chain.windows(2) {
        harness.add_child(&alice, &pair[0], &pair[1]).await;
    }

    // Asking for more depth than the server allows does not get it.
    let (status, body) = harness
        .hierarchy(&alice, &chain[0], "?max_depth=100&limit=100")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = walked(&body).len();
    assert!(
        seen < chain.len(),
        "the walk followed the client's depth past the server's cap: {seen} rooms"
    );
}
