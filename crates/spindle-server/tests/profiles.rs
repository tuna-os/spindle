//! Global profiles: the display name and avatar a user carries everywhere.
//!
//! The profile row is the source; member events copy it at set time, which
//! is how a rename reaches rooms and, through their fan-out, other servers.
//! Reading a remote user's profile walks federation `query/profile` — the
//! one profile read that leaves the building.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One full homeserver on a real TCP listener, named by its own address.
struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Instance {
            _dir: dir,
            name,
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn a_profile_is_set_read_back_and_scoped_to_its_owner() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let alice_id = format!("@alice:{}", server.name);

    // Never set: an empty object, not an error — the user exists.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{alice_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, json!({}));

    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(&alice),
            Some(&json!({ "displayname": "Alice of the Log" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/avatar_url"),
            Some(&alice),
            Some(&json!({ "avatar_url": "mxc://example/alice" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{alice_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["displayname"], "Alice of the Log");
    assert_eq!(body["avatar_url"], "mxc://example/alice");

    // The field views answer one field each.
    let (_, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            None,
            None,
        )
        .await;
    assert_eq!(body, json!({ "displayname": "Alice of the Log" }));

    // Bob cannot write alice's profile.
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(&bob),
            Some(&json!({ "displayname": "Mallory" })),
        )
        .await;
    assert_eq!(status, 403, "{body}");

    // A user who does not exist is a 404, distinct from an empty profile.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/@nobody:{}", server.name),
            None,
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn a_display_name_reaches_the_member_event_of_every_joined_room() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let alice_id = format!("@alice:{}", server.name);
    let (_, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(&alice),
            Some(&json!({ "displayname": "The Renamed" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The member event copied the profile — this is the propagation the
    // spec asks for, and what carries the rename over federation.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{alice_id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["displayname"], "The Renamed");
    assert_eq!(body["membership"], "join", "still joined: {body}");
}

#[tokio::test]
async fn a_remote_users_profile_is_answered_by_their_server() {
    let theirs = Instance::start().await;
    let ours = Instance::start().await;
    let alice = theirs.register("alice").await;
    let alice_id = format!("@alice:{}", theirs.name);
    let (status, body) = theirs
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(&alice),
            Some(&json!({ "displayname": "Alice Abroad" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Asked here, answered there: the read proxies over query/profile.
    let (status, body) = ours
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{alice_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["displayname"], "Alice Abroad");

    // A remote user their server disowns is a 404 here too.
    let (status, body) = ours
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/@nobody:{}", theirs.name),
            None,
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
}
