//! Reporting an event to the server's operators.
//!
//! The property worth testing hardest is the one that looks like sloppiness:
//! "no such event" and "you cannot see that event" are the **same** 404.
//! Distinguishing them would make this endpoint an oracle for whether a
//! given event ID exists in a room the caller is not in — which is exactly
//! what a reporting endpoint must not become, since anyone may call it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
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
        let app = spindle_server::app(config, Arc::clone(&store)).unwrap();
        Self {
            _dir: dir,
            store,
            app,
        }
    }

    /// The offline promotion path, as the CLI subcommand does it. Admin is
    /// not something an account can grant itself over HTTP, which is why
    /// the audit assertion below needs this rather than a first-user rule.
    fn promote(&self, localpart: &str) {
        assert!(
            Accounts::new(self.store.as_ref(), "example.org")
                .set_admin(localpart, true)
                .unwrap(),
            "the account exists"
        );
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

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, txn: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "msgtype": "m.text", "body": txn }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn report(
        &self,
        room: &str,
        event: &str,
        token: &str,
        payload: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(format!("/_matrix/client/v3/rooms/{room}/report/{event}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
    }
}

/// A member reports an event, and an operator can find it.
///
/// The second half is the point: a report stored where nobody looks is not
/// a moderation feature, it is the appearance of one. It goes into the
/// admin audit log, which is the feed an operator already reads.
#[tokio::test]
async fn a_report_reaches_the_admin_audit_log() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let event = harness.say(&room, &alice, "spam").await;

    let (status, body) = harness
        .report(
            &room,
            &event,
            &alice,
            &json!({ "reason": "spam", "score": -100 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({}), "the spec's response is an empty object");

    harness.promote("alice");
    let (status, log) = harness
        .call(
            Request::builder()
                .uri("/_spindle/admin/v1/audit")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{log}");
    let found = log["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| {
            entry["action"] == "report"
                && entry["target"] == event.as_str()
                && entry["detail"]["reason"] == "spam"
                && entry["detail"]["score"] == -100
        });
    assert!(found, "the report is not in the operator's feed: {log}");
}

/// The privacy property: an outsider gets the same 404 for an event that
/// exists as for one that does not, so the endpoint cannot be used to probe
/// what a room contains.
#[tokio::test]
async fn an_outsider_cannot_tell_a_real_event_from_a_fake_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness.create_room(&alice).await;
    let real = harness.say(&room, &alice, "private").await;

    let (real_status, real_body) = harness
        .report(&room, &real, &mallory, &json!({ "reason": "probing" }))
        .await;
    let (fake_status, fake_body) = harness
        .report(
            &room,
            "$definitely-not-a-real-event",
            &mallory,
            &json!({ "reason": "probing" }),
        )
        .await;

    assert_eq!(real_status, StatusCode::NOT_FOUND, "{real_body}");
    assert_eq!(
        real_status, fake_status,
        "a real event and an invented one answered differently, which is an \
         oracle for what the room holds: {real_body} vs {fake_body}"
    );
    assert_eq!(real_body["errcode"], fake_body["errcode"]);
}

/// A member reporting an event that does not exist still gets a 404.
#[tokio::test]
async fn a_member_reporting_a_missing_event_is_not_found() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .report(&room, "$nope", &alice, &json!({ "reason": "typo" }))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// The score is signed and runs -100..=0. A positive number is a caller who
/// has misread the API, and telling them so is more useful than storing it.
#[tokio::test]
async fn a_score_outside_the_specs_range_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let event = harness.say(&room, &alice, "fine").await;

    for score in [1, -101] {
        let (status, body) = harness
            .report(&room, &event, &alice, &json!({ "score": score }))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "score {score} was accepted: {body}"
        );
        assert_eq!(body["errcode"], "M_BAD_JSON");
    }

    // The ends of the range are inside it.
    for score in [0, -100] {
        let (status, body) = harness
            .report(&room, &event, &alice, &json!({ "score": score }))
            .await;
        assert_eq!(status, StatusCode::OK, "score {score} refused: {body}");
    }
}

/// Both fields are optional: a bare report is a valid report.
#[tokio::test]
async fn a_report_needs_neither_a_reason_nor_a_score() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let event = harness.say(&room, &alice, "hm").await;

    let (status, body) = harness.report(&room, &event, &alice, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
