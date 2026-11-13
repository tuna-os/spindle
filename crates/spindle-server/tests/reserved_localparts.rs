//! Service localparts are reserved: an appservice's `sender_localpart` and the
//! server-notices account (default `server`) are created by the service on
//! first use, so a user who registered the name first would keep a password
//! login to the service's identity. Ordinary account creation refuses them,
//! and a service never adopts an account it did not create.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const AS_TOKEN: &str = "as_secret_token_for_tests";

struct Harness {
    _dir: TempDir,
    _reg_dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    /// A service whose sender is not in any exclusive namespace (so only the
    /// sender reservation can protect it), and `[server_notices]` at its
    /// default localpart `server`.
    fn new() -> Self {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(
            &reg_path,
            "id: testbridge\nurl: null\nas_token: as_secret_token_for_tests\n\
             hs_token: hs_secret_token_for_tests\nsender_localpart: bridgebot\n\
             namespaces:\n  users:\n    - exclusive: false\n      regex: \"@ghost_.*:example\\\\.org\"\n",
        )
        .unwrap();
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n[server_notices]\n",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        Self {
            _dir: dir,
            _reg_dir: reg_dir,
            store,
            app,
        }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        payload: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = if let Some(payload) = payload {
            builder = builder.header("content-type", "application/json");
            Body::from(payload.to_string())
        } else {
            Body::empty()
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> (StatusCode, Value) {
        self.send(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(&json!({
                "username": username,
                "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "register" },
            })),
        )
        .await
    }

    async fn available(&self, username: &str) -> (StatusCode, Value) {
        self.send(
            "GET",
            &format!("/_matrix/client/v3/register/available?username={username}"),
            None,
            None,
        )
        .await
    }
}

#[tokio::test]
async fn service_localparts_cannot_be_registered_or_reported_available() {
    let harness = Harness::new();
    for name in ["bridgebot", "server", "BridgeBot"] {
        let (status, body) = harness.register(name).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert_eq!(body["errcode"], "M_EXCLUSIVE", "{name}");
        let (status, body) = harness.available(name).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert_eq!(body["errcode"], "M_EXCLUSIVE", "{name}");
    }
    assert!(
        Accounts::new(harness.store.as_ref(), "example.org")
            .account("bridgebot")
            .unwrap()
            .is_none(),
        "no account was created"
    );

    let (status, body) = harness.register("alice").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness.available("carol").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_appservice_does_not_adopt_an_account_it_did_not_create() {
    let harness = Harness::new();
    // Written straight to the store: the state of a server where a user
    // registered the name before the reservation existed.
    Accounts::new(harness.store.as_ref(), "example.org")
        .register("bridgebot", "hunter2")
        .unwrap();

    let (status, body) = harness
        .send(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(AS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
    assert!(
        body["error"].as_str().unwrap().contains("not created"),
        "{body}"
    );
}

#[tokio::test]
async fn an_appservice_keeps_the_sender_account_it_created() {
    let harness = Harness::new();
    for _ in 0..2 {
        let (status, body) = harness
            .send(
                "GET",
                "/_matrix/client/v3/account/whoami",
                Some(AS_TOKEN),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user_id"], "@bridgebot:example.org");
    }
    // A user cannot use the freed-up password flow to take it over either.
    let (status, _) = harness.register("bridgebot").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_notices_account_is_not_adopted_either() {
    let harness = Harness::new();
    let (_, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(&json!({
                "username": "root",
                "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "register" },
            })),
        )
        .await;
    let admin = body["access_token"].as_str().unwrap().to_owned();
    let accounts = Accounts::new(harness.store.as_ref(), "example.org");
    accounts.set_admin("root", true).unwrap();
    accounts.register("alice", "hunter2").unwrap();
    accounts.register("server", "hunter2").unwrap();

    let (status, body) = harness
        .send(
            "POST",
            "/_synapse/admin/v1/send_server_notice",
            Some(&admin),
            Some(&json!({
                "user_id": "@alice:example.org",
                "content": { "msgtype": "m.text", "body": "hello" },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["errcode"], "M_USER_IN_USE");
}
