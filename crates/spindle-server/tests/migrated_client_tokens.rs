//! A client that synced against the homeserver this one replaced.
//!
//! Every client keeps its stream position across restarts. The first
//! request after a migration from Synapse carries Synapse's token, not
//! ours, and the server has to answer in a way the client recovers from
//! on its own. A 400 is not that answer: the client retries the same
//! token until someone signs it out.
//!
//! - `/sync` answers another server's `since` as an initial sync, and
//!   names everyone the user shares a room with under
//!   `device_lists.changed` so the client re-queries keys it may hold
//!   stale copies of.
//! - Sliding sync answers another server's `pos` with MSC4186's
//!   `M_UNKNOWN_POS`, which clients handle by starting over.
//! - The to-device extension treats another server's `since` as no
//!   acknowledgement, so nothing pending is lost.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Tokens Synapse v1.156 handed Element X and Element Web on reilly.asia.
const SYNAPSE_SINCE: &str = "s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1";
const SYNAPSE_POS: &str = "20489/s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1";
const SYNAPSE_TO_DEVICE: &str = "8005";
const SLIDING: &str = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync";

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

struct User {
    token: String,
    device_id: String,
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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
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

    async fn register(&self, username: &str) -> User {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        User {
            token: body["access_token"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
        }
    }

    /// A room alice made, bob joined, and alice spoke in.
    async fn shared_room(&self, alice: &User, bob: &User) -> String {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(&alice.token),
                Some(&json!({ "invite": ["@bob:example.org"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(&bob.token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .request(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1"),
                Some(&alice.token),
                Some(&json!({ "msgtype": "m.text", "body": "before the switch" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room
    }
}

#[tokio::test]
async fn sync_answers_another_servers_since_as_an_initial_sync() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.shared_room(&alice, &bob).await;

    let (status, body) = harness
        .request(
            "GET",
            &format!("/_matrix/client/v3/sync?since={SYNAPSE_SINCE}&timeout=0"),
            Some(&alice.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The room arrives whole: its state and its timeline, as on a first
    // sync, so the client rebuilds it instead of trusting its cache.
    let joined = &body["rooms"]["join"][&room];
    let timeline = joined["timeline"]["events"].as_array().unwrap();
    assert!(
        timeline
            .iter()
            .any(|event| event["content"]["body"] == "before the switch"),
        "{body}"
    );
    let state = joined["state"]["events"].as_array().unwrap();
    let in_state_or_timeline = |kind: &str| {
        state
            .iter()
            .chain(timeline)
            .any(|event| event["type"] == kind)
    };
    assert!(in_state_or_timeline("m.room.create"), "{body}");

    // Device lists: everyone alice shares a room with, herself included.
    let changed: Vec<&str> = body["device_lists"]["changed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(changed.contains(&"@bob:example.org"), "{body}");
    assert!(changed.contains(&"@alice:example.org"), "{body}");

    // And the token handed back is ours, which the next request resumes
    // from normally.
    let next = body["next_batch"].as_str().unwrap();
    assert!(
        next.starts_with('s') && next[1..].parse::<u64>().is_ok(),
        "{next}"
    );
    let (status, body) = harness
        .request(
            "GET",
            &format!("/_matrix/client/v3/sync?since={next}&timeout=0"),
            Some(&alice.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["rooms"]["join"].get(&room).is_none(), "{body}");
    assert!(
        body["device_lists"]["changed"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{body}"
    );
}

#[tokio::test]
async fn sync_still_refuses_our_own_pagination_token_as_since() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .request(
            "GET",
            "/_matrix/client/v3/sync?since=t17&timeout=0",
            Some(&alice.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn sliding_sync_answers_another_servers_pos_with_unknown_pos() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.shared_room(&alice, &bob).await;
    let request = json!({
        "lists": { "all": { "ranges": [[0, 10]], "timeline_limit": 5 } }
    });

    let (status, body) = harness
        .request(
            "POST",
            &format!("{SLIDING}?pos={}", SYNAPSE_POS.replace('/', "%2F")),
            Some(&alice.token),
            Some(&request),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_POS", "{body}");

    // What a client does next: the same request without `pos`.
    let (status, body) = harness
        .request("POST", SLIDING, Some(&alice.token), Some(&request))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["rooms"].get(&room).is_some(), "{body}");
    let pos = body["pos"].as_str().unwrap().to_owned();
    let (status, body) = harness
        .request(
            "POST",
            &format!("{SLIDING}?pos={pos}&timeout=0"),
            Some(&alice.token),
            Some(&request),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn to_device_extension_delivers_everything_for_another_servers_since() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let (status, body) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.room_key_request/txn1",
            Some(&bob.token),
            Some(&json!({
                "messages": {
                    "@alice:example.org": {
                        alice.device_id.as_str(): { "action": "request_cancellation", "request_id": "r1", "requesting_device_id": "BOB" }
                    }
                }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness
        .request(
            "POST",
            SLIDING,
            Some(&alice.token),
            Some(&json!({
                "lists": {},
                "extensions": { "to_device": { "enabled": true, "since": SYNAPSE_TO_DEVICE } }
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["extensions"]["to_device"]["events"]
        .as_array()
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "m.room_key_request"
                && event["sender"] == "@bob:example.org"),
        "{body}"
    );
}

#[tokio::test]
async fn versions_lets_element_x_discover_native_sliding_sync() {
    // matrix-sdk's `VersionBuilder::DiscoverNative`, which Element X logs
    // in with, accepts a server only if `/versions` carries this flag.
    let harness = Harness::new();
    let (status, body) = harness
        .request("GET", "/_matrix/client/versions", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["unstable_features"]["org.matrix.simplified_msc3575"],
        json!(true),
        "{body}"
    );
}
