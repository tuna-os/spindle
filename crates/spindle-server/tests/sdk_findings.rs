//! Three defects matrix-rust-sdk's integration suite found on its first run
//! against Spindle (#392, run 34031964690), each pinned here so the suite
//! is not the only thing that knows.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { dir, app }
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

    async fn post(&self, path: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
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

    async fn sync(&self, token: &str, query: &str) -> Value {
        let (status, body) = self
            .get(&format!("/_matrix/client/v3/sync{query}"), token)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Alice creates a room with Bob invited and a name, as a client does.
    async fn room_with_invite(&self, alice: &str, bob_id: &str) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "name": "the reading circle", "invite": [bob_id] }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn an_invite_already_pending_does_not_wait_out_the_long_poll() {
    // `tests::room::test_event_with_context`: Bob's sync loop polls at 30 s,
    // Alice invites him, and his next poll starts *after* the invite lands.
    // The poll had the invite in hand and waited for an unrelated event
    // anyway, so Bob never saw the room inside the 8 s the test allowed.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;

    let initial = server.sync(&bob, "").await;
    let since = initial["next_batch"].as_str().unwrap().to_owned();

    let room = server.room_with_invite(&alice, "@bob:example.org").await;

    let started = std::time::Instant::now();
    let sync = server
        .sync(&bob, &format!("?since={since}&timeout=5000"))
        .await;
    let waited = started.elapsed();

    assert!(
        !sync["rooms"]["invite"][&room].is_null(),
        "the invite is in bob's sync: {sync}"
    );
    assert!(
        waited < std::time::Duration::from_secs(2),
        "a poll with an invite to report returned only after {waited:?}"
    );
}

#[tokio::test]
async fn the_push_rules_account_data_event_wraps_its_ruleset_in_global() {
    // The SDK refused the whole event with "missing field `global`" and
    // carried on with no push rules at all. The spec's content is
    // `{"global": ruleset}`; `/pushrules/` already answered that way, sync
    // did not.
    let server = Harness::new();
    let alice = server.register("alice").await;

    let sync = server.sync(&alice, "").await;
    let event = sync["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["type"] == "m.push_rules")
        .unwrap_or_else(|| panic!("no m.push_rules in {sync}"));
    let global = &event["content"]["global"];
    assert!(global.is_object(), "content.global is the ruleset: {event}");
    for kind in ["override", "content", "room", "sender", "underride"] {
        assert!(
            global[kind].is_array(),
            "the {kind} kind is under global: {event}"
        );
    }
    assert!(
        event["content"]["override"].is_null(),
        "the kinds are not also at the top level: {event}"
    );

    // And it is the same ruleset `/pushrules/` serves.
    let (status, rules) = server.get("/_matrix/client/v3/pushrules/", &alice).await;
    assert_eq!(status, StatusCode::OK, "{rules}");
    assert_eq!(rules["global"], *global);
}

#[tokio::test]
async fn an_invite_carries_the_inviter_s_membership() {
    // `tests::invitations::test_invitation_details`: the SDK reads the
    // invitee's member event for the inviter's ID and then wants the
    // inviter's own member event for their name. Synapse sends both; only
    // the invitee's was here.
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.room_with_invite(&alice, "@bob:example.org").await;

    let sync = server.sync(&bob, "").await;
    let events = sync["rooms"]["invite"][&room]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("an invite with stripped state: {sync}"));
    let member = |user: &str| {
        events
            .iter()
            .find(|event| event["type"] == "m.room.member" && event["state_key"] == json!(user))
    };
    let invitee = member("@bob:example.org").expect("the invitee's own member event");
    assert_eq!(invitee["sender"], json!("@alice:example.org"));
    assert_eq!(invitee["content"]["membership"], json!("invite"));
    let inviter = member("@alice:example.org").expect("the inviter's member event");
    assert_eq!(inviter["content"]["membership"], json!("join"));
    // Still stripped: nothing an invitee is not entitled to.
    assert!(
        events.iter().all(|event| event.get("event_id").is_none()),
        "stripped events carry no event IDs: {events:?}"
    );
}
