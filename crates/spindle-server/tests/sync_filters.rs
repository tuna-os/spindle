//! Client-supplied filters for `/sync`.
//!
//! A filter is a client saying "do not send me things I will throw away". It
//! is a bandwidth question rather than a correctness one — a server that
//! ignored every filter would still be correct, just wasteful.
//!
//! The subtleties worth pinning are the ones where a plausible reading is
//! wrong: exclusion beats inclusion, an empty list is not an absent one, and
//! a timeline limit takes the *newest* matches rather than the first.

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
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
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
            .request("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) {
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}: {body}");
    }

    /// Sync with an inline filter.
    async fn sync_filtered(&self, token: &str, filter: &Value) -> Value {
        let encoded = urlencode(&filter.to_string());
        let (status, body) = self
            .get(&format!("/_matrix/client/v3/sync?filter={encoded}"), token)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn upload_filter(&self, user_id: &str, token: &str, filter: &Value) -> String {
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/user/{user_id}/filter"),
                token,
                filter,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["filter_id"].as_str().unwrap().to_owned()
    }
}

/// Percent-encode a filter for a query string.
///
/// `{`, `"`, `,` and the rest are not query-safe, and a raw `#` would take the
/// whole filter into the URI fragment — the same trap the alias tests hit.
fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn timeline_types(sync: &Value, room: &str) -> Vec<String> {
    sync["rooms"]["join"][room]["timeline"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter_map(|e| e["type"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn timeline_bodies(sync: &Value, room: &str) -> Vec<String> {
    sync["rooms"]["join"][room]["timeline"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter_map(|e| e["content"]["body"].as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn a_type_filter_keeps_only_what_it_names() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "hello", "t1").await;

    let all = harness.sync_filtered(&alice, &json!({})).await;
    assert!(
        timeline_types(&all, &room)
            .iter()
            .any(|t| t.starts_with("m.room.")),
        "unfiltered carries the create sequence: {all}"
    );

    let only_messages = harness
        .sync_filtered(
            &alice,
            &json!({ "room": { "timeline": { "types": ["m.room.message"] } } }),
        )
        .await;
    let types = timeline_types(&only_messages, &room);
    assert!(!types.is_empty(), "the message survives: {only_messages}");
    assert!(
        types.iter().all(|t| t == "m.room.message"),
        "and nothing else does: {types:?}"
    );
}

#[tokio::test]
async fn not_types_beats_types() {
    // The spec is explicit that exclusion wins. A server resolving it the
    // other way would let a client widen a filter by accident and receive
    // something it had asked twice not to see.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "hello", "t1").await;

    let sync = harness
        .sync_filtered(
            &alice,
            &json!({ "room": { "timeline": {
                "types": ["m.room.message"],
                "not_types": ["m.room.message"],
            } } }),
        )
        .await;
    assert!(
        timeline_types(&sync, &room).is_empty(),
        "named by both means excluded: {sync}"
    );
}

#[tokio::test]
async fn a_trailing_star_matches_a_prefix_and_only_types_get_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "hello", "t1").await;

    let sync = harness
        .sync_filtered(
            &alice,
            &json!({ "room": { "timeline": { "types": ["m.room.*"] } } }),
        )
        .await;
    assert!(
        !timeline_types(&sync, &room).is_empty(),
        "m.room.* matches m.room.message: {sync}"
    );

    // A sender is not a pattern: the spec gives the wildcard to types alone,
    // so a literal star in a sender matches nothing rather than everything.
    let sync = harness
        .sync_filtered(
            &alice,
            &json!({ "room": { "timeline": { "senders": ["@alice*"] } } }),
        )
        .await;
    assert!(
        timeline_types(&sync, &room).is_empty(),
        "a starred sender is a sender, not a glob: {sync}"
    );
}

#[tokio::test]
async fn an_empty_list_excludes_everything_and_an_absent_one_excludes_nothing() {
    // The distinction that makes `Option<Vec<_>>` the right type. Collapsing
    // them would make `types: []` silently mean "all types" — the exact
    // opposite of what a client asking for nothing meant.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "hello", "t1").await;

    let absent = harness
        .sync_filtered(&alice, &json!({ "room": { "timeline": {} } }))
        .await;
    assert!(
        !timeline_types(&absent, &room).is_empty(),
        "no opinion means everything: {absent}"
    );

    let empty = harness
        .sync_filtered(&alice, &json!({ "room": { "timeline": { "types": [] } } }))
        .await;
    assert!(
        timeline_types(&empty, &room).is_empty(),
        "an empty list means none of these: {empty}"
    );
}

#[tokio::test]
async fn a_timeline_limit_keeps_the_newest_matches() {
    // A timeline is oldest-first, and a client asking for two events wants the
    // two most recent — not the two oldest that happen to match.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    for index in 0..6 {
        harness
            .say(&room, &alice, &format!("m{index}"), &format!("t{index}"))
            .await;
    }

    let sync = harness
        .sync_filtered(
            &alice,
            &json!({ "room": { "timeline": {
                "types": ["m.room.message"],
                "limit": 2,
            } } }),
        )
        .await;
    assert_eq!(
        timeline_bodies(&sync, &room),
        vec!["m4".to_owned(), "m5".to_owned()],
        "the newest two, in order: {sync}"
    );
}

#[tokio::test]
async fn a_room_filter_drops_the_whole_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let kept = harness.create_room(&alice).await;
    let dropped = harness.create_room(&alice).await;

    let sync = harness
        .sync_filtered(&alice, &json!({ "room": { "not_rooms": [&dropped] } }))
        .await;
    let rooms = sync["rooms"]["join"].as_object().unwrap();
    assert!(rooms.contains_key(&kept), "{sync}");
    assert!(!rooms.contains_key(&dropped), "{sync}");

    let sync = harness
        .sync_filtered(&alice, &json!({ "room": { "rooms": [&kept] } }))
        .await;
    let rooms = sync["rooms"]["join"].as_object().unwrap();
    assert!(rooms.contains_key(&kept));
    assert!(
        !rooms.contains_key(&dropped),
        "an include list excludes the rest: {sync}"
    );
}

#[tokio::test]
async fn an_uploaded_filter_and_the_same_filter_inline_agree() {
    // Two shapes of one thing. If they could disagree, a client that switched
    // between them would see the server change its mind.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.say(&room, &alice, "hello", "t1").await;

    let filter = json!({ "room": { "timeline": { "types": ["m.room.message"] } } });
    let id = harness
        .upload_filter("@alice:example.org", &alice, &filter)
        .await;

    let (status, by_id) = harness
        .get(&format!("/_matrix/client/v3/sync?filter={id}"), &alice)
        .await;
    assert_eq!(status, StatusCode::OK, "{by_id}");
    let inline = harness.sync_filtered(&alice, &filter).await;

    assert_eq!(
        timeline_types(&by_id, &room),
        timeline_types(&inline, &room)
    );
    assert_eq!(timeline_types(&by_id, &room), vec!["m.room.message"]);
}

#[tokio::test]
async fn an_uploaded_filter_reads_back() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let filter = json!({ "room": { "timeline": { "types": ["m.room.message"], "limit": 5 } } });
    let id = harness
        .upload_filter("@alice:example.org", &alice, &filter)
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/user/@alice:example.org/filter/{id}"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room"]["timeline"]["types"], json!(["m.room.message"]));
    assert_eq!(body["room"]["timeline"]["limit"], 5);
}

#[tokio::test]
async fn an_unknown_filter_id_is_refused_rather_than_ignored() {
    // Syncing unfiltered would send a client on a slow connection everything
    // it just asked not to receive, and look like the server ignoring it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .get("/_matrix/client/v3/sync?filter=404", &alice)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");

    let (status, body) = harness
        .get(
            "/_matrix/client/v3/user/@alice:example.org/filter/404",
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_malformed_inline_filter_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/sync?filter={}", urlencode("{not json")),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn one_users_filter_is_not_anothers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/user/@alice:example.org/filter",
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let id = harness
        .upload_filter("@alice:example.org", &alice, &json!({}))
        .await;
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/user/@alice:example.org/filter/{id}"),
            &bob,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn a_filter_limit_outranks_the_query_parameter() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    for index in 0..8 {
        harness
            .say(&room, &alice, &format!("m{index}"), &format!("t{index}"))
            .await;
    }

    let filter = urlencode(
        &json!({ "room": { "timeline": { "types": ["m.room.message"], "limit": 2 } } }).to_string(),
    );
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/sync?timeline_limit=50&filter={filter}"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        timeline_bodies(&body, &room).len(),
        2,
        "the filter is the more specific of the two: {body}"
    );
}
