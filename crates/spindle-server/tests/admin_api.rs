//! The admin users group (#83) — a real Spindle over TCP.
//!
//! The two acceptance properties from the spec are asserted literally:
//! a non-admin token is refused on *every* admin route, enumerated so a
//! route added without the guard fails here; and every mutating
//! endpoint leaves an audit record naming the actor.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;

struct Instance {
    _dir: TempDir,
    name: String,
    store: Arc<FjallStore>,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            store,
            client: reqwest::Client::new(),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }

    /// Register through the ordinary client API; returns the token.
    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username, "password": "hunter2hunter2",
                    "auth": { "type": "m.login.dummy", "session": "s" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// The offline promotion path, as the CLI subcommand does it.
    fn promote(&self, localpart: &str) {
        assert!(
            Accounts::new(self.store.as_ref(), &self.name)
                .set_admin(localpart, true)
                .unwrap(),
            "the account exists"
        );
    }

    fn user(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.name)
    }
}

/// Every admin route, both prefixes, as (method, path-template) pairs.
/// New endpoints must be added here — the refusal test walks this list.
fn all_admin_routes(user: &str) -> Vec<(reqwest::Method, String)> {
    let mut routes = Vec::new();
    for prefix in ["/_spindle/admin/v1", "/_synapse/admin/v1"] {
        routes.extend([
            (reqwest::Method::GET, format!("{prefix}/server_version")),
            (reqwest::Method::GET, format!("{prefix}/users")),
            (reqwest::Method::GET, format!("{prefix}/users/{user}")),
            (reqwest::Method::PUT, format!("{prefix}/users/{user}")),
            (
                reqwest::Method::POST,
                format!("{prefix}/users/{user}/deactivate"),
            ),
            (
                reqwest::Method::POST,
                format!("{prefix}/users/{user}/reset_password"),
            ),
            (
                reqwest::Method::GET,
                format!("{prefix}/users/{user}/devices"),
            ),
            (
                reqwest::Method::DELETE,
                format!("{prefix}/users/{user}/devices/DEV"),
            ),
            (
                reqwest::Method::GET,
                format!("{prefix}/users/{user}/joined_rooms"),
            ),
            (reqwest::Method::GET, format!("{prefix}/whois/{user}")),
            (reqwest::Method::GET, format!("{prefix}/audit")),
        ]);
    }
    routes
}

#[tokio::test]
async fn a_non_admin_is_refused_on_every_route() {
    let server = Instance::start().await;
    let token = server.register("mallory").await;
    let target = server.user("mallory");

    for (method, path) in all_admin_routes(&target) {
        let (status, body) = server
            .request(method.clone(), &path, Some(&token), Some(&json!({})))
            .await;
        assert_eq!(status, 403, "{method} {path} admitted a non-admin: {body}");
        assert_eq!(body["errcode"], "M_FORBIDDEN", "{method} {path}: {body}");
    }

    // No token at all is a 401, not a quieter 403.
    let (status, _) = server
        .request(reqwest::Method::GET, "/_spindle/admin/v1/users", None, None)
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn listing_creation_and_versioning_work() {
    let server = Instance::start().await;
    let admin_token = server.register("root").await;
    server.promote("root");
    server.register("alice").await;
    let alice = server.user("alice");

    // server_version answers something versioned.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/server_version",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["server_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("spindle ")),
        "{body}"
    );

    // Listing sees both accounts; filtering narrows.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/users",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 2, "{body}");
    let (_, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/users?name=ali",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(body["total"], 1, "{body}");
    assert_eq!(body["users"][0]["name"], alice.as_str(), "{body}");
    assert_eq!(body["users"][0]["admin"], false, "{body}");

    // Pagination: page size one, walk both pages.
    let (_, page) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/users?limit=1",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(page["users"].as_array().unwrap().len(), 1);
    assert_eq!(page["next_token"], "1", "{page}");

    // PUT creates a fresh account (201) and modifies an existing one.
    let bob = server.user("bob");
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_spindle/admin/v1/users/{bob}"),
            Some(&admin_token),
            Some(&json!({ "displayname": "Bob", "password": "made-by-admin-1" })),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["displayname"], "Bob", "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_spindle/admin/v1/users/{alice}"),
            Some(&admin_token),
            Some(&json!({ "admin": true })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["admin"], true, "an admin can mint another: {body}");

    // The freshly created account can actually log in with the password
    // the admin set — creation is real, not a row without a door.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(&json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "bob" },
                "password": "made-by-admin-1",
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn devices_rooms_and_whois_see_real_state() {
    let server = Instance::start().await;
    let admin_token = server.register("root").await;
    server.promote("root");
    let alice_token = server.register("alice").await;
    let alice = server.user("alice");

    // whois and devices see the sessions that exist.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_spindle/admin/v1/users/{alice}/devices"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 1, "alice's login device: {body}");
    let device_id = body["devices"][0]["device_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_spindle/admin/v1/whois/{alice}"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["devices"][&device_id].is_object(), "{body}");

    // Deleting the device ends its session.
    let (status, body) = server
        .request(
            reqwest::Method::DELETE,
            &format!("/_spindle/admin/v1/users/{alice}/devices/{device_id}"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&alice_token),
            None,
        )
        .await;
    assert_eq!(status, 401, "the deleted device's token is dead");

    // joined_rooms reflects membership.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&admin_token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let admin_user = server.user("root");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_spindle/admin/v1/users/{admin_user}/joined_rooms"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["joined_rooms"][0], room.as_str(), "{body}");
}

#[tokio::test]
async fn every_mutation_lands_in_the_audit_log() {
    let server = Instance::start().await;
    let admin_token = server.register("root").await;
    server.promote("root");
    server.register("victim").await;
    let victim = server.user("victim");
    let root = server.user("root");

    // Four mutations, in order.
    for (method, path, body) in [
        (
            reqwest::Method::PUT,
            format!("/_spindle/admin/v1/users/{victim}"),
            json!({ "displayname": "Vic" }),
        ),
        (
            reqwest::Method::POST,
            format!("/_spindle/admin/v1/users/{victim}/reset_password"),
            json!({ "new_password": "rotated-by-admin-1" }),
        ),
        (
            reqwest::Method::POST,
            format!("/_spindle/admin/v1/users/{victim}/deactivate"),
            json!({ "erase": true }),
        ),
        (
            reqwest::Method::PUT,
            format!("/_spindle/admin/v1/users/{victim}"),
            json!({ "deactivated": false }),
        ),
    ] {
        let (status, response) = server
            .request(method, &path, Some(&admin_token), Some(&body))
            .await;
        assert!((200..300).contains(&status), "{path}: {response}");
    }

    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/audit",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().unwrap();
    let actions: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .collect();
    assert_eq!(
        actions,
        ["put_user", "reset_password", "deactivate", "put_user"],
        "{body}"
    );
    for entry in entries {
        assert_eq!(entry["actor"], root.as_str(), "the log names who: {body}");
        assert_eq!(entry["target"], victim.as_str(), "{body}");
    }
    // The password itself never reaches the log — only that it changed.
    assert!(
        !body.to_string().contains("rotated-by-admin-1"),
        "a credential leaked into the audit log"
    );

    // Filtering by action narrows.
    let (_, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/audit?action=deactivate",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(body["total"], 1, "{body}");
}

#[tokio::test]
async fn deactivation_takes_the_admin_bit_with_the_sessions() {
    let server = Instance::start().await;
    let root_token = server.register("root").await;
    server.promote("root");
    let second_token = server.register("second").await;
    server.promote("second");
    let second = server.user("second");

    // Deactivate the second admin; their token dies with their devices,
    // and even a fresh session could not act: the extractor refuses
    // deactivated accounts whatever their flag says.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            &format!("/_spindle/admin/v1/users/{second}/deactivate"),
            Some(&root_token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/users",
            Some(&second_token),
            None,
        )
        .await;
    assert_eq!(status, 401, "the deactivated admin's session is gone");

    // reset_password logs out everywhere by default…
    let victim_token = server.register("victim").await;
    let victim = server.user("victim");
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            &format!("/_spindle/admin/v1/users/{victim}/reset_password"),
            Some(&root_token),
            Some(&json!({ "new_password": "rotated-by-admin-1" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&victim_token),
            None,
        )
        .await;
    assert_eq!(status, 401, "old sessions died with the password");
    // …and the new password opens the door.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(&json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "victim" },
                "password": "rotated-by-admin-1",
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}
