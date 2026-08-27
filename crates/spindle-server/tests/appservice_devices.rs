//! MSC4190: appservices manage devices; sessions manage themselves.
//!
//! What the suite pins: a device-managing service's registration mints
//! no session (`user_id` only, no `access_token`); the service creates a
//! ghost's device with `PUT /devices/{deviceId}` (201, then visible in
//! the list) and deletes it without UIA; an ordinary account cannot mint
//! devices by PUT (404) and must re-prove its password to delete one;
//! and deletion actually kills the device's access token.

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
device_management: true
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

#[tokio::test]
async fn a_device_managing_registration_mints_no_session() {
    let harness = Harness::new();
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/register",
            AS_TOKEN,
            &json!({
                "type": "m.login.application_service",
                "username": "_bridge_deviceless",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@_bridge_deviceless:example.org");
    assert!(
        body.get("access_token").is_none() && body.get("device_id").is_none(),
        "MSC4190: the as_token is the only credential: {body}"
    );
}

#[tokio::test]
async fn the_service_creates_and_deletes_a_ghost_device_without_uia() {
    let harness = Harness::new();
    let ghost = "@_bridge_ghost:example.org";

    // PUT on a device that does not exist creates it.
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/devices/BRIDGEDEV?user_id={ghost}"),
            AS_TOKEN,
            &json!({ "display_name": "bridge bot" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // It shows up in the ghost's device list, name intact.
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/devices?user_id={ghost}"),
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"][0]["device_id"], "BRIDGEDEV", "{body}");
    assert_eq!(body["devices"][0]["display_name"], "bridge bot");

    // And DELETE needs no UIA dance: no auth dict, straight 200.
    let (status, body) = harness
        .send(
            "DELETE",
            &format!("/_matrix/client/v3/devices/BRIDGEDEV?user_id={ghost}"),
            AS_TOKEN,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = harness
        .get(
            &format!("/_matrix/client/v3/devices/BRIDGEDEV?user_id={ghost}"),
            AS_TOKEN,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "gone means gone");
}

#[tokio::test]
async fn an_ordinary_account_cannot_mint_devices_by_put() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/devices/CONJURED",
            &alice,
            &json!({ "display_name": "not a bridge" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
}

#[tokio::test]
async fn a_person_renames_but_re_proves_their_password_to_delete() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, whoami) = harness
        .get("/_matrix/client/v3/account/whoami", &alice)
        .await;
    let device_id = whoami["device_id"].as_str().unwrap().to_owned();

    // Renaming an existing device is a plain PUT.
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            &alice,
            &json!({ "display_name": "laptop" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = harness
        .get(&format!("/_matrix/client/v3/devices/{device_id}"), &alice)
        .await;
    assert_eq!(body["display_name"], "laptop");

    // Deletion without auth: the UIA challenge, not a deletion.
    let (status, body) = harness
        .send(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password", "{body}");

    // The wrong password is refused.
    let (status, body) = harness
        .send(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            &alice,
            &json!({ "auth": {
                "type": "m.login.password",
                "session": "delete_device",
                "password": "wrong",
            }}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The right one deletes — and takes the session with it.
    let (status, body) = harness
        .send(
            "DELETE",
            &format!("/_matrix/client/v3/devices/{device_id}"),
            &alice,
            &json!({ "auth": {
                "type": "m.login.password",
                "session": "delete_device",
                "password": "hunter2",
            }}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .get("/_matrix/client/v3/account/whoami", &alice)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a deleted device's token no longer authenticates: {body}"
    );
}
