//! The client hierarchy and room summary for rooms this server does not
//! hold (#823): two real Spindle instances, A holding a space and its
//! children, B holding only the space.

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

    /// A room with the given join rule content and a name.
    async fn room(&self, token: &str, name: &str, rules: Value) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({ "name": name })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        self.put_state(&room, token, "m.room.join_rules", "", &rules)
            .await;
        room
    }

    async fn put_state(&self, room: &str, token: &str, kind: &str, key: &str, content: &Value) {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/{kind}/{key}"),
                Some(token),
                Some(content),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn add_child(&self, space: &str, token: &str, child: &str, via: &str) {
        self.put_state(
            space,
            token,
            "m.space.child",
            child,
            &json!({ "via": [via] }),
        )
        .await;
    }

    async fn join_via(&self, room: &str, token: &str, via: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    /// The room names a hierarchy returns, in order.
    async fn hierarchy_names(&self, space: &str, token: &str, query: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v1/rooms/{space}/hierarchy{query}"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|room| room["name"].as_str().unwrap_or("").to_owned())
            .collect()
    }
}

fn public() -> Value {
    json!({ "join_rule": "public" })
}

/// Server A holds a space and its children; server B holds only the space.
struct Rig {
    a: Instance,
    b: Instance,
    alice: String,
    bob: String,
    space: String,
}

async fn rig() -> Rig {
    let a = Instance::start().await;
    let b = Instance::start().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let space = a.room(&alice, "the space", public()).await;
    b.join_via(&space, &bob, &a.name).await;
    Rig {
        a,
        b,
        alice,
        bob,
        space,
    }
}

#[tokio::test]
async fn a_child_only_the_other_server_holds_appears_in_the_hierarchy() {
    let rig = rig().await;
    let open = rig.a.room(&rig.alice, "open child", public()).await;
    let private = rig
        .a
        .room(
            &rig.alice,
            "private child",
            json!({ "join_rule": "invite" }),
        )
        .await;
    rig.a
        .add_child(&rig.space, &rig.alice, &open, &rig.a.name)
        .await;
    rig.a
        .add_child(&rig.space, &rig.alice, &private, &rig.a.name)
        .await;
    // The children's events reach B only via the space; B holds neither room.
    let names = eventually_names(&rig, "").await;
    assert!(names.contains(&"open child".to_owned()), "{names:?}");
    assert!(!names.contains(&"private child".to_owned()), "{names:?}");
    assert_eq!(names.len(), 2, "{names:?}");
}

/// The space's own `m.space.child` events reach B by federation.
async fn eventually_names(rig: &Rig, query: &str) -> Vec<String> {
    let mut names = Vec::new();
    for _ in 0..60 {
        names = rig.b.hierarchy_names(&rig.space, &rig.bob, query).await;
        if names.len() > 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    names
}

#[tokio::test]
async fn a_restricted_child_shows_only_to_members_of_the_room_it_admits() {
    let rig = rig().await;
    let child = rig
        .a
        .room(
            &rig.alice,
            "restricted child",
            json!({ "join_rule": "restricted",
                    "allow": [{ "type": "m.room_membership", "room_id": rig.space }] }),
        )
        .await;
    rig.a
        .add_child(&rig.space, &rig.alice, &child, &rig.a.name)
        .await;
    // Bob is in the space, so the room admits him.
    let names = eventually_names(&rig, "").await;
    assert!(names.contains(&"restricted child".to_owned()), "{names:?}");
    // Carol is on B but not in the space, so she may not see it.
    let carol = rig.b.register("carol").await;
    let names = rig.b.hierarchy_names(&rig.space, &carol, "").await;
    assert_eq!(names, vec!["the space".to_owned()], "{names:?}");
}

#[tokio::test]
async fn a_dead_remote_server_leaves_out_its_child_without_failing_the_request() {
    let rig = rig().await;
    let open = rig.a.room(&rig.alice, "open child", public()).await;
    rig.a
        .add_child(&rig.space, &rig.alice, &open, &rig.a.name)
        .await;
    // A peer that accepts connections and never answers.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_name = format!("127.0.0.1:{}", silent.local_addr().unwrap().port());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = silent.accept().await {
            held.push(socket);
        }
    });
    let dead = format!("!gone:{silent_name}");
    rig.a
        .add_child(&rig.space, &rig.alice, &dead, &silent_name)
        .await;
    // And one that refuses at once.
    let refused = "!nobody:127.0.0.1:1";
    rig.a
        .add_child(&rig.space, &rig.alice, refused, "127.0.0.1:1")
        .await;

    let started = std::time::Instant::now();
    let names = eventually_names(&rig, "").await;
    assert!(names.contains(&"open child".to_owned()), "{names:?}");
    assert_eq!(names.len(), 2, "dead children are left out: {names:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "the silent peer must be cut off: {:?}",
        started.elapsed()
    );
    // The failure is remembered, so the next page does not wait again.
    let again = std::time::Instant::now();
    let names = rig.b.hierarchy_names(&rig.space, &rig.bob, "").await;
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(again.elapsed() < std::time::Duration::from_secs(2));
}

#[tokio::test]
async fn a_summary_of_a_remote_public_room_works_by_id_and_by_alias() {
    let rig = rig().await;
    let open = rig.a.room(&rig.alice, "open child", public()).await;
    let private = rig
        .a
        .room(
            &rig.alice,
            "private child",
            json!({ "join_rule": "invite" }),
        )
        .await;
    let alias = format!("#open:{}", rig.a.name);
    let (status, body) = rig
        .a
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/directory/room/%23open%3A{}", rig.a.name),
            Some(&rig.alice),
            Some(&json!({ "room_id": open })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let by_id = format!("/_matrix/client/v1/room_summary/{open}?via={}", rig.a.name);
    let (status, body) = rig
        .b
        .request(reqwest::Method::GET, &by_id, Some(&rig.bob), None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "open child");
    assert_eq!(body["join_rule"], "public");

    let by_alias = format!("/_matrix/client/v1/room_summary/%23open%3A{}", rig.a.name);
    let (status, body) = rig
        .b
        .request(reqwest::Method::GET, &by_alias, None, None)
        .await;
    assert_eq!(status, 200, "{alias}: {body}");
    assert_eq!(body["room_id"], json!(open));

    let hidden = format!(
        "/_matrix/client/v1/room_summary/{private}?via={}",
        rig.a.name
    );
    let (status, body) = rig
        .b
        .request(reqwest::Method::GET, &hidden, Some(&rig.bob), None)
        .await;
    assert_ne!(status, 200, "{body}");
    assert!(!body.to_string().contains("private child"), "{body}");
}
