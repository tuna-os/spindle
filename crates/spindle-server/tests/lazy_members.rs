//! Lazy-loaded members.
//!
//! In a 10,000-member room the roster *is* the initial sync: thousands of
//! `m.room.member` events a client renders none of until someone speaks.
//! With `lazy_load_members` the state block carries only the members this
//! response makes the client need — the senders in its timeline — and the
//! client fetches anyone else when it first has a reason to draw them.

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
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
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

    async fn create_public_room(&self, token: &str) -> String {
        let (status, body) = self
            .request("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        self.request(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            token,
            &json!({ "join_rule": "public" }),
        )
        .await;
        room
    }

    async fn sync_with_filter(&self, token: &str, filter: &Value) -> Value {
        let encoded: String = filter
            .to_string()
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(format!("/_matrix/client/v3/sync?filter={encoded}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

// A timeline limit rides along, as it does in real clients: in a room this
// small the default tail reaches back to every member's *join*, and a join is
// a timeline event whose sender is the quiet member -- so without the limit,
// lazy loading correctly includes everyone and the test would prove nothing.
// The first version of this file did exactly that.
const LAZY: &str = r#"{"room":{"state":{"lazy_load_members":true},"timeline":{"limit":2}}}"#;

fn members(sync: &Value, room: &str) -> Vec<String> {
    sync["rooms"]["join"][room]["state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "m.room.member")
        .map(|event| event["state_key"].as_str().unwrap().to_owned())
        .collect()
}

/// A room with `quiet_count` joined users who never speak, plus alice (the
/// creator, who speaks) and bob (the observer).
async fn build_room(harness: &Harness, quiet_count: usize) -> (String, String, String) {
    let alice = harness.register("alice").await;
    let room = harness.create_public_room(&alice).await;
    for index in 0..quiet_count {
        let token = harness.register(&format!("quiet{index}")).await;
        harness
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                &token,
                &json!({}),
            )
            .await;
    }
    let bob = harness.register("bob").await;
    harness
        .request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &bob,
            &json!({}),
        )
        .await;
    // Two messages after every join, so a limit-2 timeline holds only
    // alice's messages and *no* join -- not even bob's. Without this the
    // window reaches the joins, every member is a timeline sender, and the
    // tests cannot tell lazy loading from not stripping at all. Two mutants
    // survived the first version of this file for exactly that reason.
    for txn in ["t1", "t2"] {
        harness
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                &alice,
                &json!({ "msgtype": "m.text", "body": "only alice speaks" }),
            )
            .await;
    }
    (room, alice, bob)
}

#[tokio::test]
async fn only_timeline_senders_and_yourself_come_back() {
    let harness = Harness::new();
    let (room, _alice, bob) = build_room(&harness, 8).await;

    let filter: Value = serde_json::from_str(LAZY).unwrap();
    let sync = harness.sync_with_filter(&bob, &filter).await;
    let mut listed = members(&sync, &room);
    listed.sort();

    // Alice spoke, bob is the syncing user; the eight quiet members are what
    // lazy loading exists to omit. The timeline limit keeps their joins out
    // of the window, which is what makes them omittable.
    assert!(
        listed.contains(&"@alice:example.org".to_owned()),
        "the sender of a timeline event must be present: {listed:?}"
    );
    assert!(
        listed.contains(&"@bob:example.org".to_owned()),
        "the syncing user must always find themselves -- his join is outside \
         the window, so only the self rule keeps him: {listed:?}"
    );
    assert!(
        !listed.iter().any(|member| member.starts_with("@quiet")),
        "members who never spoke must be omitted: {listed:?}"
    );

    // And the rest of the state is untouched -- lazy loading is about
    // members, not state in general.
    let types: Vec<&str> = sync["rooms"]["join"][&room]["state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    assert!(types.contains(&"m.room.create"), "{types:?}");
    assert!(types.contains(&"m.room.join_rules"), "{types:?}");
}

#[tokio::test]
async fn without_the_filter_the_whole_roster_still_comes_back() {
    // The default must not move: a client that never asked for lazy loading
    // renders the member list from the state block and would show an
    // eight-person room as empty.
    let harness = Harness::new();
    let (room, _alice, bob) = build_room(&harness, 8).await;

    // A timeline limit with no lazy_load_members: the roster must still be
    // complete even though the quiet members are not senders in the window.
    // Without the limit the joins are in the tail, every member is a sender,
    // and a mutant that lazy-loads unasked strips nobody and survives.
    let filter: Value = serde_json::from_str(r#"{"room":{"timeline":{"limit":2}}}"#).unwrap();
    let sync = harness.sync_with_filter(&bob, &filter).await;
    let listed = members(&sync, &room);
    assert_eq!(
        listed.len(),
        10,
        "alice + bob + eight quiet members: {listed:?}"
    );
}

#[tokio::test]
async fn lazy_load_false_is_the_default_not_the_opt_in() {
    let harness = Harness::new();
    let (room, _alice, bob) = build_room(&harness, 3).await;

    let filter: Value =
        serde_json::from_str(r#"{"room":{"state":{"lazy_load_members":false}}}"#).unwrap();
    let sync = harness.sync_with_filter(&bob, &filter).await;
    assert_eq!(members(&sync, &room).len(), 5);
}

#[tokio::test]
async fn an_uploaded_filter_lazy_loads_too() {
    // The filter param takes an ID as well as inline JSON, and the two must
    // mean the same thing.
    let harness = Harness::new();
    let (room, _alice, bob) = build_room(&harness, 5).await;

    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/user/@bob:example.org/filter",
            &bob,
            &serde_json::from_str(LAZY).unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let filter_id = body["filter_id"].as_str().unwrap();

    let (status, sync) = harness
        .call(
            Request::builder()
                .uri(format!("/_matrix/client/v3/sync?filter={filter_id}"))
                .header("authorization", format!("Bearer {bob}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    let listed = members(&sync, &room);
    assert!(
        !listed.iter().any(|member| member.starts_with("@quiet")),
        "{listed:?}"
    );
}
