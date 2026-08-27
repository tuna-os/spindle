//! Application services: a client with a skeleton key over its namespaces.
//!
//! What the suite pins: a registration file loads or the server refuses to
//! start; the `as_token` authenticates as the sender user; `?user_id=`
//! masquerades within the user namespaces and provisions virtual users on
//! first use; outside the namespaces the service is a stranger and hears
//! `M_EXCLUSIVE`; and a virtual user is a real user — rooms, messages,
//! profiles all work through the masquerade.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const AS_TOKEN: &str = "as_secret_token_for_tests";

fn registration_yaml() -> &'static str {
    r#"
id: testbridge
url: null
as_token: as_secret_token_for_tests
hs_token: hs_secret_token_for_tests
sender_localpart: _bridge_bot
namespaces:
  users:
    - exclusive: true
      regex: "@_bridge_.*:example\\.org"
"#
}

struct Harness {
    _dir: TempDir,
    _reg_dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(&reg_path, registration_yaml()).unwrap();
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self {
            _dir: dir,
            _reg_dir: reg_dir,
            app,
        }
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

    async fn send(
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
}

#[test]
fn a_bad_registration_refuses_to_start() {
    let reg_dir = TempDir::new().unwrap();
    let reg_path = reg_dir.path().join("broken.yaml");
    std::fs::write(&reg_path, "id: broken\nas_token: [not, a, string").unwrap();
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[appservices]\nregistrations = [\"{}\"]\n",
        reg_path.display()
    ))
    .unwrap();
    assert!(
        spindle_server::app(config, store).is_err(),
        "a registration that does not parse is startup-fatal"
    );
}

#[test]
fn a_bad_namespace_regex_refuses_to_start() {
    let reg_dir = TempDir::new().unwrap();
    let reg_path = reg_dir.path().join("badregex.yaml");
    std::fs::write(
        &reg_path,
        "id: badregex\nurl: null\nas_token: t1\nhs_token: t2\n\
         sender_localpart: bot\nnamespaces:\n  users:\n    - regex: \"@[\"\n",
    )
    .unwrap();
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[appservices]\nregistrations = [\"{}\"]\n",
        reg_path.display()
    ))
    .unwrap();
    assert!(spindle_server::app(config, store).is_err());
}

#[tokio::test]
async fn the_as_token_speaks_as_the_sender_user_by_default() {
    let harness = Harness::new();
    let (status, body) = harness
        .get("/_matrix/client/v3/account/whoami", AS_TOKEN)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@_bridge_bot:example.org");
}

#[tokio::test]
async fn masquerade_inside_the_namespace_provisions_and_acts() {
    let harness = Harness::new();
    let ghost = "@_bridge_alice:example.org";
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/account/whoami?user_id={ghost}"),
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], ghost, "the masquerade holds: {body}");

    // The virtual user is a real user: it can hold a room and speak.
    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/createRoom?user_id={ghost}"),
            AS_TOKEN,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1?user_id={ghost}"),
            AS_TOKEN,
            &json!({ "msgtype": "m.text", "body": "bridged hello" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1&user_id={ghost}"),
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["chunk"][0]["sender"], ghost, "{body}");
}

#[tokio::test]
async fn masquerade_outside_the_namespace_is_exclusive() {
    let harness = Harness::new();
    // A real human's account, well outside `@_bridge_.*`.
    harness.register("alice").await;
    let (status, body) = harness
        .get(
            "/_matrix/client/v3/account/whoami?user_id=@alice:example.org",
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE", "{body}");
}

#[tokio::test]
async fn a_wrong_token_is_still_a_wrong_token() {
    let harness = Harness::new();
    let (status, body) = harness
        .get("/_matrix/client/v3/account/whoami", "not_a_real_token")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

#[tokio::test]
async fn the_appservice_registration_type_skips_uia_entirely() {
    let harness = Harness::new();
    // No `auth` dict, no session, no password: the as_token is the proof.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/register",
            AS_TOKEN,
            &json!({
                "type": "m.login.application_service",
                "username": "_bridge_new",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@_bridge_new:example.org", "{body}");
    let token = body["access_token"].as_str().unwrap();
    // And the session it returns is a real one.
    let (status, body) = harness
        .get("/_matrix/client/v3/account/whoami", token)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@_bridge_new:example.org");
}

#[tokio::test]
async fn appservice_registration_outside_the_namespace_is_exclusive() {
    let harness = Harness::new();
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/register",
            AS_TOKEN,
            &json!({
                "type": "m.login.application_service",
                "username": "eve",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE", "{body}");
}

#[tokio::test]
async fn appservice_registration_without_the_token_is_refused() {
    let harness = Harness::new();
    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "type": "m.login.application_service",
                        "username": "_bridge_impostor",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

#[tokio::test]
async fn an_exclusive_namespace_refuses_ordinary_registration() {
    let harness = Harness::new();
    // A human walks in wearing a bridge name. The reservation answers
    // before the UIA dance would even start.
    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "_bridge_stolen",
                        "password": "hunter2",
                        "auth": { "type": "m.login.dummy", "session": "register" },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_EXCLUSIVE", "{body}");
}

#[tokio::test]
async fn a_provisioned_ghost_cannot_be_logged_into_from_outside() {
    // The virtual account exists after first use, but its password is
    // random and held by nobody — the appservice door is the only door.
    let harness = Harness::new();
    let ghost = "@_bridge_ghost:example.org";
    let (status, _) = harness
        .get(
            &format!("/_matrix/client/v3/account/whoami?user_id={ghost}"),
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "type": "m.login.password",
                        "identifier": { "type": "m.id.user", "user": "_bridge_ghost" },
                        "password": "",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "no password opens it: {body}");
}
