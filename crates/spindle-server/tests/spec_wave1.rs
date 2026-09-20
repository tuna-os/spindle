//! The first wave of client-server endpoints filled in from the spec-gap
//! report (`docs/spec-gaps.md`): logging out everywhere, the support
//! contacts well-known, room and user reports, generic profile fields,
//! `whois`, and the v1.18 lock and suspend holds.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const PLAIN: &str = "[server]\nname = \"example.org\"\n";

const WITH_SUPPORT: &str = r#"
[server]
name = "example.org"

[server.support]
support_page = "https://example.org/help"
contacts = [
  { matrix_id = "@ops:example.org", email_address = "ops@example.org", role = "m.role.admin" },
  { matrix_id = "@safety:example.org", role = "m.role.security" },
]
"#;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new(config: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(config).unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("a signing key");
        Self { dir, store, app }
    }

    fn make_admin(&self, localpart: &str) {
        Accounts::new(self.store.as_ref(), "example.org")
            .set_admin(localpart, true)
            .unwrap();
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
            .send(
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
        body["access_token"].as_str().unwrap().to_owned()
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
        self.call(builder.body(body).unwrap()).await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.send("GET", path, Some(token), None).await
    }

    async fn post(&self, path: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.send("POST", path, Some(token), Some(payload)).await
    }

    async fn put(&self, path: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.send("PUT", path, Some(token), Some(payload)).await
    }

    async fn delete(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.send("DELETE", path, Some(token), None).await
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .post("/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn logout_all_revokes_every_device_of_the_user() {
    let server = Harness::new(PLAIN);
    let first = server.register("alice").await;
    let (status, login) = server
        .send(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(&json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "alice" },
                "password": "hunter2",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let second = login["access_token"].as_str().unwrap().to_owned();

    let (status, body) = server
        .post("/_matrix/client/v3/logout/all", &first, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for token in [&first, &second] {
        let (status, body) = server.get("/_matrix/client/v3/account/whoami", token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
}

#[tokio::test]
async fn support_contacts_are_published_only_when_configured() {
    let quiet = Harness::new(PLAIN);
    let (status, body) = quiet
        .send("GET", "/.well-known/matrix/support", None, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");

    let helpful = Harness::new(WITH_SUPPORT);
    let (status, body) = helpful
        .send("GET", "/.well-known/matrix/support", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["support_page"], "https://example.org/help");
    let contacts = body["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 2);
    assert_eq!(contacts[0]["matrix_id"], "@ops:example.org");
    assert_eq!(contacts[0]["email_address"], "ops@example.org");
    assert_eq!(contacts[0]["role"], "m.role.admin");
    assert_eq!(contacts[1]["role"], "m.role.security");
    assert!(contacts[1].get("email_address").is_none());
}

#[tokio::test]
async fn rooms_and_users_can_be_reported_when_they_exist() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    server.register("bob").await;
    let room = server.create_room(&alice).await;

    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/report"),
            &alice,
            &json!({ "reason": "spam" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = server
        .post(
            "/_matrix/client/v3/rooms/!nowhere:example.org/report",
            &alice,
            &json!({ "reason": "spam" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = server
        .post(
            "/_matrix/client/v3/users/@bob:example.org/report",
            &alice,
            &json!({ "reason": "rude" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = server
        .post(
            "/_matrix/client/v3/users/@nobody:example.org/report",
            &alice,
            &json!({ "reason": "rude" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_profile_field_round_trips_and_belongs_to_its_user() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let path = "/_matrix/client/v3/profile/@alice:example.org/org.example.pronouns";

    let (status, body) = server.get(path, &bob).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = server
        .put(
            path,
            &alice,
            &json!({ "org.example.pronouns": "they/them" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = server.get(path, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["org.example.pronouns"], "they/them");

    let (status, body) = server
        .get("/_matrix/client/v3/profile/@alice:example.org", &bob)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["org.example.pronouns"], "they/them");

    let (status, body) = server
        .put(path, &bob, &json!({ "org.example.pronouns": "it" }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = server.delete(path, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = server.delete(path, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = server.get(path, &bob).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profile_fields_are_bounded_and_the_named_ones_stay_strings() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    let base = "/_matrix/client/v3/profile/@alice:example.org";

    let long_key = "k".repeat(256);
    let (status, body) = server
        .put(
            &format!("{base}/{long_key}"),
            &alice,
            &json!({ long_key.clone(): 1 }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_KEY_TOO_LARGE");

    let huge = "x".repeat(70 * 1024);
    let (status, body) = server
        .put(
            &format!("{base}/org.example.bio"),
            &alice,
            &json!({ "org.example.bio": huge }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_PROFILE_TOO_LARGE");

    let (status, body) = server
        .put(
            &format!("{base}/displayname"),
            &alice,
            &json!({ "displayname": 7 }),
        )
        .await;
    assert!(status.is_client_error(), "{status} {body}");

    let (status, body) = server
        .put(
            &format!("{base}/displayname"),
            &alice,
            &json!({ "displayname": "Alice" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server.get(&format!("{base}/displayname"), &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["displayname"], "Alice");
}

#[tokio::test]
async fn whois_is_for_the_user_and_the_admins() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let admin = server.register("admin").await;
    server.make_admin("admin");
    let path = "/_matrix/client/v3/admin/whois/@alice:example.org";

    let (status, body) = server.get(path, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:example.org");
    let devices = body["devices"].as_object().unwrap();
    assert_eq!(devices.len(), 1);
    let sessions = devices.values().next().unwrap()["sessions"]
        .as_array()
        .unwrap();
    assert_eq!(sessions.len(), 1);

    let (status, body) = server.get(path, &bob).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = server.get(path, &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_locked_user_is_told_so_with_a_soft_logout() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    let admin = server.register("admin").await;
    server.make_admin("admin");
    let path = "/_matrix/client/v1/admin/lock/@alice:example.org";

    let (status, body) = server.get(path, &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["locked"], false);

    let (status, body) = server.put(path, &alice, &json!({ "locked": true })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = server.put(path, &admin, &json!({ "locked": true })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["locked"], true);

    let (status, body) = server
        .get("/_matrix/client/v3/account/whoami", &alice)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_USER_LOCKED");
    assert_eq!(body["soft_logout"], true);

    let (status, body) = server.put(path, &admin, &json!({ "locked": false })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .get("/_matrix/client/v3/account/whoami", &alice)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = server
        .get("/_matrix/client/v1/admin/lock/@ghost:example.org", &admin)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_suspended_user_can_read_and_log_out_but_not_write() {
    let server = Harness::new(PLAIN);
    let alice = server.register("alice").await;
    let admin = server.register("admin").await;
    server.make_admin("admin");
    let room = server.create_room(&alice).await;
    let path = "/_matrix/client/v1/admin/suspend/@alice:example.org";

    let (status, body) = server
        .put(path, &admin, &json!({ "suspended": true }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["suspended"], true);
    let (status, body) = server.get(path, &admin).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["suspended"], true);

    let (status, body) = server.get("/_matrix/client/v3/sync", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "hello?" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_USER_SUSPENDED");

    let (status, body) = server
        .post("/_matrix/client/v3/logout", &alice, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
