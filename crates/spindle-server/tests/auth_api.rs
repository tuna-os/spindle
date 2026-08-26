//! The client-facing auth flow, end to end over HTTP.
//!
//! #11's exit criterion is that a client can discover, register, log in,
//! refresh and log out. This covers all but refresh, which needs refresh
//! tokens and is not built yet.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        Self { _dir: dir, store }
    }

    fn config() -> spindle_server::Config {
        spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap()
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let app = spindle_server::app(Self::config(), Arc::clone(&self.store));
        let response = app.oneshot(request).await.expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str, password: &str) -> Value {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/register",
                &json!({
                    "username": username,
                    "password": password,
                    "auth": { "type": "m.login.dummy" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "register failed: {body}");
        body
    }
}

/// The whole point: discover, register, log in, use the token, log out.
#[tokio::test]
async fn a_client_can_register_log_in_and_log_out() {
    let harness = Harness::new();

    let registered = harness.register("alice", "correct horse").await;
    assert_eq!(registered["user_id"], "@alice:example.org");
    assert!(registered["access_token"].is_string());

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/login",
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "alice" },
                "password": "correct horse",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(body["user_id"], "@alice:example.org");

    let (status, who) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["user_id"], "@alice:example.org");
    assert_eq!(who["device_id"], body["device_id"]);

    let (status, _) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/logout")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // And the token is dead immediately, not at some later expiry.
    let (status, body) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

/// Registration is a UIA flow. Clients implement UIA generically; a server that
/// skips the dance for registration makes them special-case it.
#[tokio::test]
async fn registration_without_auth_returns_the_uia_flows() {
    let harness = Harness::new();
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({ "username": "alice", "password": "hunter2" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let flows: Value = serde_json::from_str(body["error"].as_str().unwrap()).unwrap();
    assert_eq!(flows["flows"][0]["stages"][0], "m.login.dummy");
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_user_are_indistinguishable() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let attempt = |user: &'static str, password: &'static str| async move {
        let harness = Harness::new();
        harness.register("alice", "hunter2").await;
        harness
            .post(
                "/_matrix/client/v3/login",
                &json!({
                    "type": "m.login.password",
                    "identifier": { "type": "m.id.user", "user": user },
                    "password": password,
                }),
            )
            .await
    };

    let (wrong_status, wrong_body) = attempt("alice", "nope").await;
    let (unknown_status, unknown_body) = attempt("nobody", "nope").await;
    assert_eq!(wrong_status, StatusCode::FORBIDDEN);
    assert_eq!(
        (wrong_status, &wrong_body),
        (unknown_status, &unknown_body),
        "the two responses differ, which tells an attacker which usernames exist"
    );
}

#[tokio::test]
async fn a_taken_username_gets_the_errcode_a_client_can_act_on() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({
                "username": "alice",
                "password": "other",
                "auth": { "type": "m.login.dummy" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Not M_UNKNOWN: a client that sees this shows "pick another name" rather
    // than a generic failure.
    assert_eq!(body["errcode"], "M_USER_IN_USE");
}

#[tokio::test]
async fn an_authenticated_endpoint_refuses_a_missing_or_bogus_token() {
    let harness = Harness::new();

    let (status, body) = harness
        .send(
            Request::builder()
                .uri("/_matrix/client/v3/account/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");

    let (status, body) = harness
        .get_auth("/_matrix/client/v3/account/whoami", "syt_not_a_real_token")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

/// The deprecated `?access_token=` form is not read, deliberately: a bearer
/// credential in a query string lands in access logs, proxy logs and browser
/// history.
#[tokio::test]
async fn a_token_in_the_query_string_is_not_accepted() {
    let harness = Harness::new();
    let registered = harness.register("alice", "hunter2").await;
    let token = registered["access_token"].as_str().unwrap();

    let (status, body) = harness
        .send(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/account/whoami?access_token={token}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");
}

#[tokio::test]
async fn login_flows_advertise_only_password() {
    let harness = Harness::new();
    let (status, body) = harness
        .send(
            Request::builder()
                .uri("/_matrix/client/v3/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let flows = body["flows"].as_array().unwrap();
    assert_eq!(flows.len(), 1, "only what is implemented: {body}");
    assert_eq!(flows[0]["type"], "m.login.password");
}

/// Restart preserves accounts and devices — an exit criterion of #11.
#[tokio::test]
async fn accounts_survive_a_restart() {
    let dir = TempDir::new().unwrap();
    let token = {
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let harness = Harness {
            _dir: TempDir::new().unwrap(),
            store,
        };
        let registered = harness.register("alice", "hunter2").await;
        registered["access_token"].as_str().unwrap().to_owned()
    };

    // A fresh handle over the same directory, as a restart would open.
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let harness = Harness {
        _dir: TempDir::new().unwrap(),
        store,
    };
    let (status, who) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::OK, "the session did not survive: {who}");
    assert_eq!(who["user_id"], "@alice:example.org");
}
