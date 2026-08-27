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
            (reqwest::Method::GET, format!("{prefix}/rooms")),
            (reqwest::Method::GET, format!("{prefix}/rooms/!r:x")),
            (reqwest::Method::GET, format!("{prefix}/rooms/!r:x/members")),
            (reqwest::Method::GET, format!("{prefix}/rooms/!r:x/state")),
            (
                reqwest::Method::GET,
                format!("{prefix}/rooms/!r:x/state_at"),
            ),
            (
                reqwest::Method::GET,
                format!("{prefix}/rooms/!r:x/timeline"),
            ),
            (
                reqwest::Method::POST,
                format!("{prefix}/rooms/!r:x/purge_history"),
            ),
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

/// Two rooms an admin would look at: a named public one with two members
/// and a little traffic, and an unnamed private one. Returns the admin
/// token and both room IDs, named one first.
async fn rooms_fixture(server: &Instance) -> (String, String, String) {
    let admin_token = server.register("root").await;
    server.promote("root");
    let alice_token = server.register("alice").await;

    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&admin_token),
            Some(&json!({ "name": "Operations", "preset": "public_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let ops = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{ops}"),
            Some(&alice_token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    for n in 0..3 {
        let (status, body) = server
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{ops}/send/m.room.message/t{n}"),
                Some(&admin_token),
                Some(&json!({ "msgtype": "m.text", "body": format!("message {n}") })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice_token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let unnamed = body["room_id"].as_str().unwrap().to_owned();
    (admin_token, ops, unnamed)
}

#[tokio::test]
async fn the_room_listing_orders_filters_and_paginates() {
    let server = Instance::start().await;
    let (admin_token, ops, unnamed) = rooms_fixture(&server).await;
    let list = |query: &'static str| {
        let server = &server;
        let token = admin_token.clone();
        async move {
            server
                .request(
                    reqwest::Method::GET,
                    &format!("/_spindle/admin/v1/rooms{query}"),
                    Some(&token),
                    None,
                )
                .await
        }
    };

    // Default ordering is by name; the unnamed room sorts after, not out.
    let (status, body) = list("").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_rooms"], 2, "{body}");
    assert_eq!(body["rooms"][0]["room_id"], ops.as_str(), "{body}");
    assert_eq!(body["rooms"][1]["room_id"], unnamed.as_str(), "{body}");
    assert_eq!(body["rooms"][0]["name"], "Operations", "{body}");
    assert_eq!(body["rooms"][0]["joined_members"], 2, "{body}");
    assert_eq!(body["rooms"][0]["public"], true, "{body}");
    assert_eq!(body["rooms"][1]["public"], false, "{body}");
    assert!(body["rooms"][0]["version"].is_string(), "{body}");
    assert_eq!(
        body["rooms"][0]["creator"],
        server.user("root").as_str(),
        "{body}"
    );

    // Search matches names; the size orderings put the busy room first.
    let (status, body) = list("?search_term=Opera").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total_rooms"], 1, "{body}");
    let (status, body) = list("?order_by=joined_members").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["rooms"][0]["room_id"], ops.as_str(), "{body}");
    let (status, body) = list("?order_by=shoe_size").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");

    // Pagination walks the same order without overlap.
    let (status, body) = list("?limit=1").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["rooms"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["next_batch"], 1, "{body}");
    let (status, body) = list("?limit=1&from=1").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["rooms"][0]["room_id"], unnamed.as_str(), "{body}");
    assert!(body.get("next_batch").is_none(), "{body}");
}

#[tokio::test]
async fn room_detail_members_state_and_timeline_read_the_log() {
    let server = Instance::start().await;
    let (admin_token, ops, _) = rooms_fixture(&server).await;
    let get = |path: String| {
        let server = &server;
        let token = admin_token.clone();
        async move {
            server
                .request(reqwest::Method::GET, &path, Some(&token), None)
                .await
        }
    };

    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "Operations", "{body}");
    assert_eq!(body["joined_members"], 2, "{body}");
    assert_eq!(body["joined_local_members"], 2, "{body}");
    assert_eq!(body["federatable"], true, "{body}");
    assert!(body["state_events"].as_u64().unwrap() >= 5, "{body}");
    let (status, body) = get("/_spindle/admin/v1/rooms/!missing:nowhere".to_owned()).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");

    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}/members")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 2, "{body}");
    let members = body["members"].as_array().unwrap();
    assert!(
        members.iter().any(|m| m == server.user("alice").as_str()),
        "{body}"
    );

    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}/state")).await;
    assert_eq!(status, 200, "{body}");
    let state = body["state"].as_array().unwrap();
    assert!(
        state.iter().any(|event| event["type"] == "m.room.create"),
        "{body}"
    );

    // The timeline reads forward in storage order and starts at creation.
    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}/timeline")).await;
    assert_eq!(status, 200, "{body}");
    let chunk = body["chunk"].as_array().unwrap();
    assert_eq!(chunk[0]["event"]["type"], "m.room.create", "{body}");
    let all_ids: Vec<Value> = chunk
        .iter()
        .map(|entry| entry["event_id"].clone())
        .collect();
    let lis: Vec<i64> = chunk
        .iter()
        .map(|entry| entry["li"].as_i64().unwrap())
        .collect();
    assert!(lis.windows(2).all(|pair| pair[0] < pair[1]), "{lis:?}");

    // Paging forward re-walks exactly the same entries, no seam, no overlap.
    let mut paged = Vec::new();
    let mut from = String::new();
    loop {
        let (status, body) = get(format!(
            "/_spindle/admin/v1/rooms/{ops}/timeline?limit=2{from}"
        ))
        .await;
        assert_eq!(status, 200, "{body}");
        for entry in body["chunk"].as_array().unwrap() {
            paged.push(entry["event_id"].clone());
        }
        match body.get("next_token") {
            Some(next) => from = format!("&from={next}"),
            None => break,
        }
    }
    assert_eq!(paged, all_ids, "pagination must not tear the log");

    // Backward shows the newest first; a made-up direction is refused.
    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}/timeline?dir=b")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["chunk"][0]["event"]["content"]["body"], "message 2",
        "{body}"
    );
    let (status, body) = get(format!("/_spindle/admin/v1/rooms/{ops}/timeline?dir=x")).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
}

/// Current state of a `state_at` response, folded down to the one field
/// the assertions care about.
fn name_in(body: &Value) -> Option<&str> {
    body["state"]
        .as_array()?
        .iter()
        .find(|event| event["type"] == "m.room.name")
        .and_then(|event| event["content"]["name"].as_str())
}

#[tokio::test]
async fn state_at_answers_for_any_point_in_the_log() {
    let server = Instance::start().await;
    let admin_token = server.register("root").await;
    server.promote("root");

    // A room whose name changes after a log deep enough that the early
    // entries have left the 512-entry resident window: create, name it
    // "One", drop a marker, bury both under filler, rename to "Two".
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&admin_token),
            Some(&json!({ "name": "One" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/marker"),
            Some(&admin_token),
            Some(&json!({ "msgtype": "m.text", "body": "the marker" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let marker = body["event_id"].as_str().unwrap().to_owned();
    for n in 0..520 {
        let (status, body) = server
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/f{n}"),
                Some(&admin_token),
                Some(&json!({ "msgtype": "m.text", "body": "filler" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name/"),
            Some(&admin_token),
            Some(&json!({ "name": "Two" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let get = |query: String| {
        let server = &server;
        let token = admin_token.clone();
        let room = room.clone();
        async move {
            server
                .request(
                    reqwest::Method::GET,
                    &format!("/_spindle/admin/v1/rooms/{room}/state_at?{query}"),
                    Some(&token),
                    None,
                )
                .await
        }
    };

    // Anchored by event ID, deep in the log: the answer predates the
    // rename, and the window no longer holds it — rehydrated, honestly.
    let (status, body) = get(format!("event_id={marker}")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("One"), "{body}");
    assert_eq!(body["event_id"], marker.as_str(), "{body}");
    assert_eq!(body["source"], "rehydrated", "{body}");
    let marker_li = body["li"].as_i64().unwrap();
    let marker_ts = body["origin_server_ts"].as_u64().unwrap();

    // The same point by li, and by any li in the buried filler.
    let (status, body) = get(format!("li={marker_li}")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("One"), "{body}");

    // Near the head the window still holds the answer.
    let (status, body) = get("li=9999999".to_owned()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("Two"), "{body}");
    assert_eq!(body["source"], "resident", "{body}");

    // By time: at the marker's stamp the room is still "One" (filler
    // sharing the millisecond changes nothing it asserts), and any
    // future time answers the present.
    let (status, body) = get(format!("ts={marker_ts}")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("One"), "{body}");
    assert!(body["li"].as_i64().unwrap() >= marker_li, "{body}");
    let (status, body) = get("ts=99999999999999".to_owned()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("Two"), "{body}");
}

#[tokio::test]
async fn state_at_refuses_what_it_cannot_answer() {
    let server = Instance::start().await;
    let (admin_token, ops, _) = rooms_fixture(&server).await;
    let get = |room: &str, query: &str| {
        let path = format!("/_spindle/admin/v1/rooms/{room}/state_at?{query}");
        let server = &server;
        let token = admin_token.clone();
        async move {
            server
                .request(reqwest::Method::GET, &path, Some(&token), None)
                .await
        }
    };

    // No anchor, or two, is ambiguous — refused, not guessed.
    let (status, body) = get(&ops, "").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
    let (status, body) = get(&ops, "li=1&ts=5").await;
    assert_eq!(status, 400, "{body}");

    // Points the log cannot answer for are 404s that say so.
    let (status, body) = get(&ops, "li=-9999999").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
    let (status, body) = get(&ops, "ts=1").await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = get(&ops, "event_id=$nowhere:x").await;
    assert_eq!(status, 404, "{body}");
    let (status, body) = get("!missing:nowhere", "li=1").await;
    assert_eq!(status, 404, "{body}");
}

/// Recompute the log chain the way `ChainHash` defines it and demand the
/// stored values match — the §3 acceptance property, asserted literally.
fn assert_chain_verifies(chunk: &[Value]) {
    use std::fmt::Write as _;
    let mut running = spindle_core::ChainHash::seed();
    for entry in chunk {
        let event_id = entry["event_id"].as_str().unwrap();
        running = running.extend(&spindle_core::EventId::new(event_id));
        let expected =
            running
                .as_bytes()
                .iter()
                .fold(String::with_capacity(64), |mut out, byte| {
                    let _ = write!(out, "{byte:02x}");
                    out
                });
        assert_eq!(
            entry["chain"].as_str(),
            Some(expected.as_str()),
            "chain mismatch at {entry}"
        );
    }
}

#[tokio::test]
async fn purge_keeps_the_spine_and_the_chain_still_verifies() {
    let server = Instance::start().await;
    let (admin_token, ops, _) = rooms_fixture(&server).await;
    let timeline = || {
        let server = &server;
        let token = admin_token.clone();
        let ops = ops.clone();
        async move {
            let (status, body) = server
                .request(
                    reqwest::Method::GET,
                    &format!("/_spindle/admin/v1/rooms/{ops}/timeline"),
                    Some(&token),
                    None,
                )
                .await;
            assert_eq!(status, 200, "{body}");
            body["chunk"].as_array().unwrap().clone()
        }
    };

    let before = timeline().await;
    assert_chain_verifies(&before);
    let last_li = before.last().unwrap()["li"].as_i64().unwrap();

    // Purge everything before the newest message: the two older message
    // bodies die, every state event body survives.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            &format!("/_spindle/admin/v1/rooms/{ops}/purge_history"),
            Some(&admin_token),
            Some(&json!({ "before_li": last_li })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events_purged"], 2, "{body}");

    // The spine is unchanged — same lis, same event IDs, same chain
    // values — and the chain still verifies over the purged range.
    let after = timeline().await;
    assert_chain_verifies(&after);
    for (was, is) in before.iter().zip(after.iter()) {
        assert_eq!(was["li"], is["li"]);
        assert_eq!(was["event_id"], is["event_id"]);
        assert_eq!(was["chain"], is["chain"]);
    }
    let purged: Vec<&Value> = after.iter().filter(|e| e["purged"] == true).collect();
    assert_eq!(purged.len(), 2, "{after:?}");
    assert!(purged.iter().all(|e| e["event"].is_null()));
    assert!(
        after
            .iter()
            .filter(|e| e["event"]["type"] == "m.room.create")
            .all(|e| e["purged"] == false),
        "state bodies survive a purge"
    );

    // A client sees markers, not holes: same entry count, the purged
    // slots typed unmistakably, the newest message intact.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{ops}/messages?dir=b&limit=100"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let chunk = body["chunk"].as_array().unwrap();
    assert_eq!(chunk.len(), after.len(), "markers, not holes: {body}");
    assert_eq!(
        chunk
            .iter()
            .filter(|e| e["type"] == "org.spindle.purged")
            .count(),
        2,
        "{body}"
    );
    assert_eq!(chunk[0]["content"]["body"], "message 2", "{body}");

    // The room is not a museum: state still folds, and new events extend
    // the same chain the purge preserved.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_spindle/admin/v1/rooms/{ops}/state_at?li={last_li}"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(name_in(&body), Some("Operations"), "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{ops}/send/m.room.message/after-purge"),
            Some(&admin_token),
            Some(&json!({ "msgtype": "m.text", "body": "life goes on" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_chain_verifies(&timeline().await);
}

#[tokio::test]
async fn purge_resolves_time_and_refuses_ambiguity() {
    let server = Instance::start().await;
    let (admin_token, ops, _) = rooms_fixture(&server).await;
    let purge = |room: &str, body: Value| {
        let path = format!("/_spindle/admin/v1/rooms/{room}/purge_history");
        let server = &server;
        let token = admin_token.clone();
        async move {
            server
                .request(reqwest::Method::POST, &path, Some(&token), Some(&body))
                .await
        }
    };

    // Anchored by time: everything at or before the newest message dies,
    // and the audit log names the purge.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_spindle/admin/v1/rooms/{ops}/timeline?dir=b&limit=1"),
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let newest_ts = body["chunk"][0]["event"]["origin_server_ts"]
        .as_u64()
        .unwrap();
    let (status, body) = purge(&ops, json!({ "before_ts": newest_ts })).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events_purged"], 3, "all three messages: {body}");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_spindle/admin/v1/audit?action=purge_history",
            Some(&admin_token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["entries"][0]["target"], ops.as_str(), "{body}");
    assert_eq!(
        body["entries"][0]["actor"],
        server.user("root").as_str(),
        "{body}"
    );

    // Purging again is honest about there being nothing left to delete.
    let (status, body) = purge(&ops, json!({ "before_ts": newest_ts })).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["events_purged"], 0, "{body}");

    // Ambiguity and unknown rooms are refused.
    let (status, body) = purge(&ops, json!({})).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
    let (status, _) = purge(&ops, json!({ "before_li": 1, "before_ts": 5 })).await;
    assert_eq!(status, 400);
    let (status, _) = purge("!missing:nowhere", json!({ "before_li": 1 })).await;
    assert_eq!(status, 404);
}
