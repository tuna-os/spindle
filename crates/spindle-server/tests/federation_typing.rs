//! Typing across servers — two real Spindle instances over TCP.
//!
//! Typing is the first EDU to cross the wire: ephemeral, unsigned content
//! inside a signed transaction, applied only for the origin's own joined
//! users. What the suite pins: a keystroke on one server reaches the other
//! server's sync, a stop clears it, and it flows even when no event
//! traffic is pending — the EDU-only transaction path.

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

    async fn typing_in(&self, token: &str, room: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/sync",
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["rooms"]["join"][room]["ephemeral"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.typing")
            .flat_map(|event| {
                event["content"]["user_ids"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|user| user.as_str().map(str::to_owned))
            .collect()
    }
}

/// Poll until `check` returns true or three seconds pass — EDU delivery
/// rides the outbox drain's poll interval.
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
async fn typing_crosses_the_wire_and_stops_crossing_it() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;
    let alice_id = format!("@alice:{}", origin.name);

    // A shared room: alice's, bob joins over federation.
    let (status, body) = origin
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({ "preset": "public_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = mirror
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", origin.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Alice types. No events are in flight — this is the EDU-only
    // transaction, not a passenger on a PDU.
    let (status, body) = origin
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/typing/{alice_id}"),
            Some(&alice),
            Some(&json!({ "typing": true, "timeout": 30000 })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    assert!(
        eventually(async || mirror.typing_in(&bob, &room).await.contains(&alice_id)).await,
        "bob's server hears that alice is typing"
    );

    // And stops hearing it the moment she stops.
    let (status, body) = origin
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/typing/{alice_id}"),
            Some(&alice),
            Some(&json!({ "typing": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(async || !mirror.typing_in(&bob, &room).await.contains(&alice_id)).await,
        "the stop crosses too"
    );
}
