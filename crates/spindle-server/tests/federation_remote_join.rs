//! Joining a room that lives on another server — two real Spindle
//! instances federating over TCP.
//!
//! This is the first test where both sides of the wire are us: server B
//! holds the room, server A walks `make_join`/`send_join` as the joining
//! server, seeds the room from the response, and afterwards ordinary
//! federation carries messages both ways. What the suite pins: the join
//! lands and is visible to clients of both servers, the seeded state is
//! the room's real state (topic, memberships), history flows to the
//! joiner, and a room nobody can vouch for is refused without a seeded
//! husk left behind.

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
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("spindle_server=debug")
                .try_init();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nretry_base_ms = 50\n",
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

    async fn public_room(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                Some(token),
                Some(&json!({ "join_rule": "public" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        room
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
                Some(token),
                Some(&json!({ "msgtype": "m.text", "body": text })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn joined_members(&self, room: &str, token: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["joined"].clone()
    }

    async fn messages(&self, room: &str, token: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["content"]["body"].as_str())
            .map(str::to_owned)
            .collect()
    }
}

/// Poll until `check` returns true or two seconds pass — federation
/// delivery is asynchronous by design.
async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..40 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_user_joins_a_room_on_another_server_and_both_sides_converge() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let room = remote.public_room(&alice).await;
    remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            Some(&alice),
            Some(&json!({ "topic": "the room's real topic" })),
        )
        .await;
    remote.say(&room, &alice, "before").await;
    // Two profile changes give alice three member events — the newest in
    // the state, the older two only in the auth chain — so seeding order
    // is observable: applied oldest-last, the room would show a stale name.
    for name in ["older name", "newest name"] {
        remote
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.member/@alice:{}",
                    remote.name
                ),
                Some(&alice),
                Some(&json!({ "membership": "join", "displayname": name })),
            )
            .await;
    }

    let bob = local.register("bob").await;
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", remote.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["room_id"].as_str(), Some(room.as_str()));

    // Both servers see both members.
    let bob_id = format!("@bob:{}", local.name);
    let alice_id = format!("@alice:{}", remote.name);
    let local_members = local.joined_members(&room, &bob).await;
    assert!(local_members.get(&alice_id).is_some(), "{local_members}");
    assert!(local_members.get(&bob_id).is_some(), "{local_members}");
    assert_eq!(
        local_members[&alice_id]["display_name"], "newest name",
        "the final state wins over its auth-chain ancestors: {local_members}"
    );

    // The join took a stream row: bob's sync surfaces the room.
    let (status, sync) = local
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/sync?timeout=0",
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{sync}");
    assert!(
        sync["rooms"]["join"].get(&room).is_some(),
        "the joined room is in sync: {sync}"
    );
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(&bob_id)
                .is_some()
        })
        .await,
        "the resident server sees the joiner"
    );

    // The seeded state is the room's real state.
    let (status, topic) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{topic}");
    assert_eq!(topic["topic"], "the room's real topic");

    // Ordinary federation now carries messages both ways.
    remote.say(&room, &alice, "from the resident side").await;
    assert!(
        eventually(async || {
            local
                .messages(&room, &bob)
                .await
                .contains(&"from the resident side".to_owned())
        })
        .await,
        "resident-side messages reach the joiner"
    );
    local.say(&room, &bob, "from the joining side").await;
    assert!(
        eventually(async || {
            remote
                .messages(&room, &alice)
                .await
                .contains(&"from the joining side".to_owned())
        })
        .await,
        "joiner-side messages reach the resident server"
    );
}

#[tokio::test]
async fn an_unjoinable_room_leaves_nothing_behind() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    // Invite-only, and bob holds no invite.
    let (_, body) = remote
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    let bob = local.register("bob").await;
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", remote.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_ne!(status, 200, "{body}");

    // No seeded husk: the room is still unknown here.
    let (status, body) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            Some(&bob),
            None,
        )
        .await;
    assert_ne!(status, 200, "{body}");
}

#[tokio::test]
async fn a_join_with_no_server_to_ask_is_a_clean_404() {
    let local = Instance::start().await;
    let bob = local.register("bob").await;
    // The room ID names this very server, so there is no one else to ask.
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/!nosuch:{}", local.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
}
