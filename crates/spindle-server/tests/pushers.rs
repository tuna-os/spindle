//! Pushers: a client's registration of where to be told about events.
//!
//! Stored and served, not yet driven (#7). What must hold: a registration
//! reads back whole; re-registering the same `(app_id, pushkey)` replaces
//! rather than duplicates; `kind: null` removes; an unknown kind and an
//! http pusher without a URL are refused; the per-account cap is the one
//! the operator set; and one account never sees another's.

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
        Self::with_config("")
    }

    fn with_config(extra: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{extra}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
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

    async fn set(&self, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/pushers/set")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn list(&self, token: &str) -> Vec<Value> {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/_matrix/client/v3/pushers")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["pushers"].as_array().unwrap().clone()
    }
}

fn http_pusher(pushkey: &str) -> Value {
    json!({
        "pushkey": pushkey,
        "kind": "http",
        "app_id": "org.example.app",
        "app_display_name": "Example",
        "device_display_name": "Phone",
        "lang": "en",
        "data": { "url": "https://push.example.org/_matrix/push/v1/notify", "format": "event_id_only" },
    })
}

#[tokio::test]
async fn a_registration_reads_back_whole_and_replaces_rather_than_duplicates() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    assert!(harness.list(&alice).await.is_empty());

    let (status, body) = harness.set(&alice, &http_pusher("KEY1")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pushers = harness.list(&alice).await;
    assert_eq!(pushers.len(), 1, "{pushers:?}");
    assert_eq!(pushers[0]["pushkey"], "KEY1");
    assert_eq!(pushers[0]["kind"], "http");
    assert_eq!(pushers[0]["app_id"], "org.example.app");
    assert_eq!(pushers[0]["device_display_name"], "Phone");
    assert_eq!(pushers[0]["data"]["format"], "event_id_only");

    let mut again = http_pusher("KEY1");
    again["device_display_name"] = json!("Tablet");
    let (status, _) = harness.set(&alice, &again).await;
    assert_eq!(status, StatusCode::OK);
    let pushers = harness.list(&alice).await;
    assert_eq!(pushers.len(), 1, "re-registering duplicated: {pushers:?}");
    assert_eq!(pushers[0]["device_display_name"], "Tablet");
}

#[tokio::test]
async fn kind_null_removes_and_an_email_pusher_needs_no_url() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.set(&alice, &http_pusher("KEY1")).await;
    let (status, body) = harness
        .set(
            &alice,
            &json!({ "pushkey": "alice@example.org", "kind": "email", "app_id": "m.email", "data": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.list(&alice).await.len(), 2);

    let (status, body) = harness
        .set(
            &alice,
            &json!({ "pushkey": "KEY1", "kind": null, "app_id": "org.example.app" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let left = harness.list(&alice).await;
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0]["kind"], "email");
}

#[tokio::test]
async fn an_unknown_kind_and_an_http_pusher_without_a_url_are_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mut odd = http_pusher("KEY1");
    odd["kind"] = json!("carrier-pigeon");
    let (status, body) = harness.set(&alice, &odd).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");

    let mut no_url = http_pusher("KEY1");
    no_url["data"] = json!({});
    let (status, body) = harness.set(&alice, &no_url).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");
    assert!(
        harness.list(&alice).await.is_empty(),
        "a refused pusher was stored"
    );
}

#[tokio::test]
async fn the_cap_is_the_one_the_operator_set_and_a_replacement_is_free() {
    let harness = Harness::with_config("[limits]\npushers_per_user = 2\n");
    let alice = harness.register("alice").await;
    for key in ["KEY1", "KEY2"] {
        let (status, body) = harness.set(&alice, &http_pusher(key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = harness.set(&alice, &http_pusher("KEY3")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
    let (status, body) = harness.set(&alice, &http_pusher("KEY2")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a replacement counted against the cap: {body}"
    );
    assert_eq!(harness.list(&alice).await.len(), 2);
}

#[tokio::test]
async fn one_account_never_sees_anothers_pushers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    harness.set(&alice, &http_pusher("KEY1")).await;
    assert!(harness.list(&bob).await.is_empty());
    // Bob removing alice's key by name removes nothing of hers.
    harness
        .set(
            &bob,
            &json!({ "pushkey": "KEY1", "kind": null, "app_id": "org.example.app" }),
        )
        .await;
    assert_eq!(harness.list(&alice).await.len(), 1);
}
