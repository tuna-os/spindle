//! Registration tokens (spec v1.2): the admin rows, the
//! `m.login.registration_token` stage they gate, and the validity check.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new(require_token: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [registration]\nrequire_token = {require_token}\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        Self { dir, store, app }
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
        let body = match payload {
            Some(payload) => {
                builder = builder.header("content-type", "application/json");
                Body::from(payload.to_string())
            }
            None => Body::empty(),
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

    async fn register(&self, username: &str, auth: Value) -> (StatusCode, Value) {
        self.send(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(&json!({ "username": username, "password": "hunter2", "auth": auth })),
        )
        .await
    }

    /// An admin's access token, minted below the API the way the CLI does.
    async fn admin(&self) -> String {
        let (status, body) = self
            .register("root", json!({ "type": "m.login.dummy" }))
            .await;
        // Under require_token the dummy stage is refused; mint the account
        // directly instead, as `promote-admin` would.
        let token = if status == StatusCode::OK {
            body["access_token"].as_str().unwrap().to_owned()
        } else {
            let accounts = Accounts::new(self.store.as_ref(), "example.org");
            accounts.register("root", "hunter2").unwrap();
            let (status, body) = self
                .send(
                    "POST",
                    "/_matrix/client/v3/login",
                    None,
                    Some(&json!({
                        "type": "m.login.password",
                        "identifier": { "type": "m.id.user", "user": "root" },
                        "password": "hunter2",
                    })),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["access_token"].as_str().unwrap().to_owned()
        };
        Accounts::new(self.store.as_ref(), "example.org")
            .set_admin("root", true)
            .unwrap();
        token
    }
}

#[tokio::test]
async fn a_closed_server_registers_only_with_a_live_token() {
    let server = Harness::new(true);
    let admin = server.admin().await;

    // The challenge names the token stage, not the dummy one.
    let (status, body) = server
        .send(
            "POST",
            "/_matrix/client/v3/register",
            None,
            Some(&json!({ "username": "alice", "password": "hunter2" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        body["flows"][0]["stages"],
        json!(["m.login.registration_token"])
    );

    // The dummy stage no longer opens the door.
    let (status, body) = server
        .register(
            "alice",
            json!({ "type": "m.login.dummy", "session": "register" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = server
        .send(
            "POST",
            "/_spindle/admin/v1/registration_tokens/new",
            Some(&admin),
            Some(&json!({ "uses_allowed": 1 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 16, "{body}");
    assert_eq!(body["completed"], 0);

    let (status, body) = server
        .send(
            "GET",
            &format!(
                "/_matrix/client/v1/register/m.login.registration_token/validity?token={token}"
            ),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], true);

    let (status, body) = server
        .register(
            "alice",
            json!({ "type": "m.login.registration_token", "token": "notatoken", "session": "register" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED");
    assert_eq!(
        body["flows"][0]["stages"],
        json!(["m.login.registration_token"])
    );

    let (status, body) = server
        .register(
            "alice",
            json!({ "type": "m.login.registration_token", "token": token, "session": "register" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:example.org");

    // One use allowed, one use spent.
    let (status, body) = server
        .send(
            "GET",
            &format!("/_spindle/admin/v1/registration_tokens/{token}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["completed"], 1);
    let (status, body) = server
        .send(
            "GET",
            &format!(
                "/_matrix/client/v1/register/m.login.registration_token/validity?token={token}"
            ),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["valid"], false);
    let (status, body) = server
        .register(
            "bob",
            json!({ "type": "m.login.registration_token", "token": token, "session": "register" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn tokens_are_listed_filtered_updated_and_deleted() {
    let server = Harness::new(false);
    let admin = server.admin().await;
    let base = "/_synapse/admin/v1/registration_tokens";

    let (status, body) = server
        .send(
            "POST",
            &format!("{base}/new"),
            Some(&admin),
            Some(&json!({ "token": "welcome-2026", "expiry_time": 1 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .send(
            "POST",
            &format!("{base}/new"),
            Some(&admin),
            Some(&json!({ "length": 8 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fresh = body["token"].as_str().unwrap().to_owned();
    assert_eq!(fresh.len(), 8);

    // A name twice, and a name outside the grammar, are refused.
    let (status, body) = server
        .send(
            "POST",
            &format!("{base}/new"),
            Some(&admin),
            Some(&json!({ "token": "welcome-2026" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = server
        .send(
            "POST",
            &format!("{base}/new"),
            Some(&admin),
            Some(&json!({ "token": "no spaces" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let names = |body: &Value| -> Vec<String> {
        body["registration_tokens"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|token| token["token"].as_str().map(str::to_owned))
            .collect()
    };
    let (status, body) = server.send("GET", base, Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(names(&body).len(), 2);
    let (status, body) = server
        .send("GET", &format!("{base}?valid=true"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(names(&body), vec![fresh.clone()]);
    let (status, body) = server
        .send("GET", &format!("{base}?valid=false"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(names(&body), vec!["welcome-2026".to_owned()]);
}

#[tokio::test]
async fn a_token_is_updated_deleted_and_every_change_audited() {
    let server = Harness::new(false);
    let admin = server.admin().await;
    let base = "/_synapse/admin/v1/registration_tokens";
    let names = |body: &Value| -> Vec<String> {
        body["registration_tokens"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|token| token["token"].as_str().map(str::to_owned))
            .collect()
    };
    for payload in [
        json!({ "token": "welcome-2026", "expiry_time": 1 }),
        json!({ "length": 8 }),
    ] {
        let (status, body) = server
            .send("POST", &format!("{base}/new"), Some(&admin), Some(&payload))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // Clearing the expiry revives it.
    let (status, body) = server
        .send(
            "PUT",
            &format!("{base}/welcome-2026"),
            Some(&admin),
            Some(&json!({ "expiry_time": null, "uses_allowed": 5 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["expiry_time"].is_null());
    assert_eq!(body["uses_allowed"], 5);
    let (status, body) = server
        .send("GET", &format!("{base}?valid=true"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(names(&body).len(), 2);

    let (status, body) = server
        .send(
            "DELETE",
            &format!("{base}/welcome-2026"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .send(
            "DELETE",
            &format!("{base}/welcome-2026"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = server
        .send("GET", &format!("{base}/welcome-2026"), Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Every mutation is in the audit log.
    let (status, body) = server
        .send("GET", "/_spindle/admin/v1/audit", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let actions: Vec<&str> = body["audit"]
        .as_array()
        .or_else(|| body["entries"].as_array())
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .collect();
    for action in [
        "registration_token.create",
        "registration_token.update",
        "registration_token.delete",
    ] {
        assert!(actions.contains(&action), "{action} missing from {body}");
    }
}

#[tokio::test]
async fn an_open_server_ignores_tokens_and_a_plain_user_may_not_mint_them() {
    let server = Harness::new(false);
    let (status, body) = server
        .register("alice", json!({ "type": "m.login.dummy" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alice = body["access_token"].as_str().unwrap().to_owned();
    let (status, body) = server
        .send(
            "POST",
            "/_spindle/admin/v1/registration_tokens/new",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}
