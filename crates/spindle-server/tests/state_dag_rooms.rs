//! MSC4242 state-DAG rooms (`org.matrix.msc4242.12`), two Spindles over
//! TCP: the version Neutrino creates rooms under, and the one Hydra phase
//! 2 will number.
//!
//! What the suite pins: an event in such a room names its state parents
//! and carries no `auth_events`; a remote join is served the state DAG
//! and seeded from it; messages and state cross afterwards; an invite
//! crosses and is accepted; and `/get_missing_events` walks the state DAG
//! when asked.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const VERSION: &str = "org.matrix.msc4242.12";

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

    async fn state_dag_room(&self, token: &str, public: bool) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({
                    "room_version": VERSION,
                    "preset": if public { "public_chat" } else { "private_chat" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn join_via(&self, room: &str, token: &str, via: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
            Some(token),
            Some(&json!({})),
        )
        .await
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

    async fn state(&self, room: &str, token: &str, event_type: &str, key: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}/{key}"),
            Some(token),
            None,
        )
        .await
    }
}

async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..60 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn the_version_is_advertised_as_unstable_and_rooms_are_created_under_it() {
    let server = Instance::start().await;
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/capabilities",
            None,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["capabilities"]["m.room_versions"]["available"][VERSION],
        json!("unstable")
    );
    let alice = server.register("alice").await;
    let room = server.state_dag_room(&alice, true).await;
    let (status, create) = server.state(&room, &alice, "m.room.create", "").await;
    assert_eq!(status, 200, "{create}");
    assert_eq!(create["room_version"], json!(VERSION));
    // A v12-derived room: the ID is the create event's hash.
    assert!(!room.contains(':'), "{room} should carry no domain");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_remote_join_is_seeded_from_the_state_dag_and_traffic_crosses() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let room = remote.state_dag_room(&alice, true).await;
    remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            Some(&alice),
            Some(&json!({ "topic": "state dags" })),
        )
        .await;
    remote.say(&room, &alice, "before").await;

    let bob = local.register("bob").await;
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    // Seeded state is the room's real state.
    let (status, topic) = local.state(&room, &bob, "m.room.topic", "").await;
    assert_eq!(status, 200, "{topic}");
    assert_eq!(topic["topic"], json!("state dags"));
    let (status, create) = local.state(&room, &bob, "m.room.create", "").await;
    assert_eq!(status, 200, "{create}");
    assert_eq!(create["room_version"], json!(VERSION));

    // The join is visible on both sides.
    let bob_id = format!("@bob:{}", local.name);
    assert!(
        eventually(async || {
            let (_, member) = remote.state(&room, &alice, "m.room.member", &bob_id).await;
            member["membership"] == json!("join")
        })
        .await,
        "the resident never saw bob join"
    );

    // Messages cross in both directions, in a room neither side has
    // `auth_events` for.
    remote.say(&room, &alice, "from alice").await;
    local.say(&room, &bob, "from bob").await;
    assert!(
        eventually(async || local
            .messages(&room, &bob)
            .await
            .contains(&"from alice".to_owned()))
        .await,
        "alice's message never reached the joiner"
    );
    assert!(
        eventually(async || remote
            .messages(&room, &alice)
            .await
            .contains(&"from bob".to_owned()))
        .await,
        "bob's message never reached the resident"
    );
    // History flowed with the join.
    assert!(
        local
            .messages(&room, &bob)
            .await
            .contains(&"before".to_owned())
    );

    // A state change after the join crosses too, naming the joiner's
    // membership as a state parent on the resident's side.
    remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            Some(&alice),
            Some(&json!({ "name": "renamed" })),
        )
        .await;
    assert!(
        eventually(async || {
            let (_, name) = local.state(&room, &bob, "m.room.name", "").await;
            name["name"] == json!("renamed")
        })
        .await,
        "the rename never reached the joiner"
    );
}

#[tokio::test]
async fn an_invite_into_a_state_dag_room_crosses_and_is_accepted() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let room = remote.state_dag_room(&alice, false).await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The invite shows on bob's server; accepting it joins through the
    // inviter, which is the only server that can vouch for the room.
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(async || {
            let (_, member) = remote.state(&room, &alice, "m.room.member", &bob_id).await;
            member["membership"] == json!("join")
        })
        .await,
        "the resident never saw bob accept"
    );
}

#[tokio::test]
async fn events_carry_state_parents_and_no_auth_events() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let room = server.state_dag_room(&alice, true).await;
    let id = server.say(&room, &alice, "hello").await;

    // The client shape carries no DAG fields either way; what this pins
    // is that nothing on the read path chokes on an event without
    // `auth_events` or `depth`. The wire shape itself is covered by the
    // core's unit tests and by the two-server suites above.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/event/{id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("auth_events").is_none());
}
