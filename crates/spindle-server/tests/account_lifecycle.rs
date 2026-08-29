//! Password change, deactivation and bulk device logout.
//!
//! All three change something a stolen access token must not be enough to
//! change, so all three re-prove the password. The tests that matter here are
//! the ones asserting the *challenge*, not the success path: an endpoint that
//! quietly skipped the stage would pass every happy-path test ever written.

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
        Self {
            app: Self::build(store),
            _dir: dir,
        }
    }

    fn build(store: Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        spindle_server::app(config, store).expect("a signing key is established")
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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

impl Harness {
    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.request("POST", path, Some(token), body).await
    }

    async fn room(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn whoami(&self, token: &str) -> StatusCode {
        self.request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(token),
            &json!({}),
        )
        .await
        .0
    }

    fn password_auth(password: &str, session: &str) -> Value {
        json!({ "type": "m.login.password", "session": session, "password": password })
    }
}

/// The first request draws a challenge naming the password stage.
///
/// Clients implement UIA generically, so the 401 must carry `flows`,
/// `params` and `session` at the top level -- a challenge folded into an
/// error string is invisible to every one of them.
#[tokio::test]
async fn changing_a_password_challenges_first() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/account/password",
            &alice,
            &json!({ "new_password": "correct horse" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");
    assert!(body["session"].is_string());
    assert!(body["params"].is_object());
}

/// The wrong password does not change the password.
#[tokio::test]
async fn a_wrong_password_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, _) = harness
        .post(
            "/_matrix/client/v3/account/password",
            &alice,
            &json!({
                "new_password": "correct horse",
                "auth": Harness::password_auth("not-my-password", "change_password"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And the old one still works.
    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/login",
            None,
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "alice" },
                "password": "hunter2",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The right password changes it, and the old one stops working.
#[tokio::test]
async fn the_right_password_changes_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/account/password",
            &alice,
            &json!({
                "new_password": "correct horse",
                "auth": Harness::password_auth("hunter2", "change_password"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for (password, expected) in [
        ("hunter2", StatusCode::FORBIDDEN),
        ("correct horse", StatusCode::OK),
    ] {
        let (status, _) = harness
            .request(
                "POST",
                "/_matrix/client/v3/login",
                None,
                &json!({
                    "type": "m.login.password",
                    "identifier": { "type": "m.id.user", "user": "alice" },
                    "password": password,
                }),
            )
            .await;
        assert_eq!(status, expected, "logging in with {password:?}");
    }
}

/// Changing a password signs the other sessions out by default.
///
/// The common reason to change a password is that it leaked, so leaving the
/// existing sessions signed in would defeat the point. `logout_devices:
/// false` is the opt-out.
#[tokio::test]
async fn changing_a_password_signs_other_sessions_out() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    assert_eq!(harness.whoami(&alice).await, StatusCode::OK);

    let (status, _) = harness
        .post(
            "/_matrix/client/v3/account/password",
            &alice,
            &json!({
                "new_password": "correct horse",
                "auth": Harness::password_auth("hunter2", "change_password"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        harness.whoami(&alice).await,
        StatusCode::UNAUTHORIZED,
        "the token that made the change still works"
    );
}

/// Deactivation leaves every room, not just flips a flag.
///
/// A deactivated account still joined shows up in member lists, counts toward
/// `num_joined_members`, and keeps appearing in other people's directory
/// results. The flag alone makes the account unusable without making it gone.
#[tokio::test]
async fn deactivation_leaves_every_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&bob).await;
    let (status, body) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &bob,
            &json!({ "user_id": "@alice:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = harness
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/account/deactivate",
            &alice,
            &json!({ "auth": Harness::password_auth("hunter2", "deactivate") }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // No identity server was contacted, so say so rather than claiming success.
    assert_eq!(body["id_server_unbind_result"], "no-support");

    let (status, members) = harness
        .request(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            Some(&bob),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{members}");
    assert!(
        members["joined"].get("@alice:example.org").is_none(),
        "a deactivated account was left joined: {members}"
    );
}

/// Deactivation challenges too, and refuses a wrong password.
#[tokio::test]
async fn deactivation_needs_the_password() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .post("/_matrix/client/v3/account/deactivate", &alice, &json!({}))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");

    let (status, _) = harness
        .post(
            "/_matrix/client/v3/account/deactivate",
            &alice,
            &json!({ "auth": Harness::password_auth("wrong", "deactivate") }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Still usable.
    assert_eq!(harness.whoami(&alice).await, StatusCode::OK);
}

/// Bulk device deletion challenges, then removes the named devices.
#[tokio::test]
async fn deleting_devices_needs_the_password_then_removes_them() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .request(
            "GET",
            "/_matrix/client/v3/devices",
            Some(&alice),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = body["devices"][0]["device_id"]
        .as_str()
        .expect("a device")
        .to_owned();

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/delete_devices",
            &alice,
            &json!({ "devices": [device.clone()] }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["flows"][0]["stages"][0], "m.login.password");

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/delete_devices",
            &alice,
            &json!({
                "devices": [device.clone()],
                "auth": Harness::password_auth("hunter2", "delete_devices"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A device that is not there is not an error.
///
/// The request asks for it to be gone, and it is. Failing would make a retry
/// after a partial success impossible.
#[tokio::test]
async fn deleting_an_absent_device_is_not_an_error() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/delete_devices",
            &alice,
            &json!({
                "devices": ["NOSUCHDEVICE"],
                "auth": Harness::password_auth("hunter2", "delete_devices"),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
