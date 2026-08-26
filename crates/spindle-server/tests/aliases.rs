//! Human-readable names for rooms.
//!
//! The thing worth keeping straight here is that an alias is **not** room
//! state. `m.room.canonical_alias` records what a room prefers to be called;
//! the alias-to-room mapping lives in the server's directory, because it has
//! to be answerable by a server that is not in the room and has no state to
//! read. The two are kept in step by clients, not by the server.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Percent-encode an alias for use in a path.
///
/// A raw `#` in a URI starts the fragment, so `/directory/room/#lobby:x` never
/// sends the alias to the server at all — the request arrives as a bare
/// `/directory/room/` and 404s with an empty body, which looks like a routing
/// bug and is not one. Real clients encode it; so does this.
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

    async fn claim(&self, alias: &str, room: &str, token: &str) -> (StatusCode, Value) {
        self.request(
            "PUT",
            &format!("/_matrix/client/v3/directory/room/{}", encoded(alias)),
            Some(token),
            &json!({ "room_id": room }),
        )
        .await
    }
}

#[tokio::test]
async fn an_alias_resolves_to_the_room_it_names() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness.claim("#lobby:example.org", &room, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);
    assert_eq!(
        body["servers"],
        json!(["example.org"]),
        "naming ourselves is honest; an empty list would say there is nowhere to join through"
    );
}

#[tokio::test]
async fn resolving_needs_no_account() {
    // Resolving a name is how a client finds a room it has not joined.
    // Requiring an account would make a published alias useless to anyone not
    // already signed in.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.claim("#open:example.org", &room, &alice).await;

    let (status, body) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#open:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);
}

#[tokio::test]
async fn an_unclaimed_alias_is_a_404() {
    let harness = Harness::new();
    let (status, body) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#nobody:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn a_claimed_alias_cannot_be_repointed_by_someone_else() {
    // Silently repointing an alias is how one room hijacks another's name.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let alices_room = harness.create_room(&alice).await;
    let bobs_room = harness.create_room(&bob).await;

    let (status, body) = harness
        .claim("#lobby:example.org", &alices_room, &alice)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.claim("#lobby:example.org", &bobs_room, &bob).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["errcode"], "M_ROOM_IN_USE");

    let (_, body) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(
        body["room_id"], alices_room,
        "a refused claim must not have half-happened"
    );
}

#[tokio::test]
async fn only_the_creator_may_remove_an_alias() {
    // Deletion is a question about the past — who put this here — which no
    // amount of current room state can answer, so the directory records it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.claim("#lobby:example.org", &room, &alice).await;

    let (status, body) = harness
        .request(
            "DELETE",
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            Some(&bob),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness
        .request(
            "DELETE",
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            Some(&alice),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And the name is free again, which is the point of removing it.
    let (status, body) = harness.claim("#lobby:example.org", &room, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_alias_on_another_server_is_refused() {
    // Accepting it would let this server answer for a name it has no authority
    // over, and every peer resolving it would get a different room depending on
    // who they asked.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness.claim("#lobby:elsewhere.org", &room, &alice).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
}

#[tokio::test]
async fn a_malformed_alias_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    for bad in ["lobby:example.org", "#lobby", "#:example.org"] {
        let (status, body) = harness.claim(bad, &room, &alice).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert_eq!(body["errcode"], "M_INVALID_PARAM", "{bad}");
    }
}

#[tokio::test]
async fn an_alias_cannot_point_at_a_room_that_does_not_exist() {
    // A name in the directory that 404s on join is a broken link the server
    // handed out itself.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .claim("#ghost:example.org", "!nope:example.org", &alice)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, _) = harness
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#ghost:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "and nothing was written");
}

#[tokio::test]
async fn joining_by_alias_lands_in_the_right_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.claim("#lobby:example.org", &room, &alice).await;

    // A public room, so bob can join without an invite.
    harness
        .request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            Some(&alice),
            &json!({ "join_rule": "public" }),
        )
        .await;

    let (status, body) = harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/join/{}", encoded("#lobby:example.org")),
            Some(&bob),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);

    let (status, joined) = harness
        .get("/_matrix/client/v3/joined_rooms", Some(&bob))
        .await;
    assert_eq!(status, StatusCode::OK, "{joined}");
    assert_eq!(joined["joined_rooms"], json!([room]));
}

#[tokio::test]
async fn an_alias_pointing_nowhere_is_told_apart_from_a_room_that_does_not_exist() {
    // The two are different faults with different fixes: one is a directory
    // that needs an entry, the other is a room that does not exist. Telling
    // them apart by sigil rather than by falling back keeps them distinct.
    let harness = Harness::new();
    let bob = harness.register("bob").await;

    let (status, body) = harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/join/{}", encoded("#absent:example.org")),
            Some(&bob),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("#absent:example.org"),
        "the message must name the alias, not a room ID: {body}"
    );

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/join/!absent:example.org",
            Some(&bob),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        !body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("called"),
        "an unknown room is not a naming problem: {body}"
    );
}

#[tokio::test]
async fn a_rooms_aliases_are_listed_to_members_only() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    let other = harness.create_room(&alice).await;

    // Claimed out of alphabetical order, to prove the listing sorts.
    for alias in ["#zebra:example.org", "#lobby:example.org"] {
        let (status, body) = harness.claim(alias, &room, &alice).await;
        assert_eq!(status, StatusCode::OK, "{alias}: {body}");
    }
    harness
        .claim("#elsewhere:example.org", &other, &alice)
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/aliases"),
            Some(&alice),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["aliases"],
        json!(["#lobby:example.org", "#zebra:example.org"]),
        "sorted, and not carrying the other room's alias"
    );

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/aliases"),
            Some(&bob),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "room-to-alias enumerates what a room is reachable by, which is the room's business: {body}"
    );
}

#[tokio::test]
async fn aliases_survive_a_restart() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());

    let (token, room) = {
        let harness = Harness {
            _dir: TempDir::new().unwrap(),
            app: Harness::build(Arc::clone(&store)),
        };
        let alice = harness.register("alice").await;
        let room = harness.create_room(&alice).await;
        harness.claim("#lobby:example.org", &room, &alice).await;
        (alice, room)
    };

    let restarted = Harness {
        _dir: TempDir::new().unwrap(),
        app: Harness::build(store),
    };
    let (status, body) = restarted
        .get(
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);

    // And the creator is still the creator, so deletion still respects it.
    let (status, body) = restarted
        .request(
            "DELETE",
            &format!(
                "/_matrix/client/v3/directory/room/{}",
                encoded("#lobby:example.org")
            ),
            Some(&token),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_alias_is_not_room_state() {
    // Claiming an alias appends nothing. `m.room.canonical_alias` is the
    // room's own opinion about what it prefers to be called, and the server
    // does not write it on the room's behalf.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let before = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state"),
            Some(&alice),
        )
        .await
        .1
        .as_array()
        .unwrap()
        .len();

    harness.claim("#lobby:example.org", &room, &alice).await;

    let (status, after) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state"),
            Some(&alice),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(
        after.as_array().unwrap().len(),
        before,
        "claiming an alias must append nothing: {after}"
    );
    assert!(
        !after.to_string().contains("canonical_alias"),
        "the server does not write the room's opinion for it: {after}"
    );
}
