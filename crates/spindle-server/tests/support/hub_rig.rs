//! Real Spindles on loopback for the MSC3995 hub-mode tests (#22), each
//! behind a TCP proxy that can cut it off from every other server.
//!
//! A node's server name is its proxy's address, so everything another
//! server sends it -- transactions, key fetches, hub submissions, probes --
//! crosses the proxy, and [`Node::partition`] severs all of it at once,
//! established connections included. The test's own client requests go to
//! the listener directly, so a partitioned server can still be driven.

#![allow(dead_code, reason = "shared by test binaries that each use a part")]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use spindle_server::AppState;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One full homeserver, reached by peers through a proxy it can close.
pub struct Node {
    _dir: TempDir,
    /// The server name: the proxy's address.
    pub name: String,
    /// The listener itself, for the test's client requests.
    direct: String,
    pub state: AppState,
    pub store: Arc<FjallStore>,
    client: reqwest::Client,
    cut: tokio::sync::watch::Sender<bool>,
}

impl Node {
    /// A node with `[federation.hub] enabled` as given.
    pub async fn start(hub: bool) -> Node {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct = listener.local_addr().unwrap().to_string();
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = proxy.local_addr().unwrap().to_string();
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let hub_section = if hub {
            "[federation.hub]\nenabled = true\nsubmit_timeout_ms = 1500\nsubmit_attempts = 10\n\
             failover_after_ms = 400\ncheckpoint_interval = 4\n"
        } else {
            ""
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
             retry_base_ms = 50\n{hub_section}",
        ))
        .unwrap();
        let (app, state) = spindle_server::app_with_state(
            config,
            store.clone(),
            Arc::new(spindle_server::metrics::Metrics::new()),
        )
        .expect("the app builds");
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let (cut, _) = tokio::sync::watch::channel(false);
        tokio::spawn(forward(proxy, direct.clone(), cut.clone()));
        Node {
            _dir: dir,
            name,
            direct,
            state,
            store,
            client: reqwest::Client::new(),
            cut,
        }
    }

    /// Cut this node off from every other server, or reconnect it.
    pub fn partition(&self, cut: bool) {
        self.cut.send_replace(cut);
    }

    pub async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.direct));
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

    /// A signed federation request from this node to `to`, sent straight to
    /// `to`'s listener: what a peer would send, without the proxy.
    pub async fn federation_put(&self, to: &Node, uri: &str, body: &Value) -> (u16, Value) {
        let header = self
            .state
            .federation
            .sign_request("PUT", uri, &to.name, Some(body))
            .unwrap();
        let response = self
            .client
            .put(format!("http://{}{uri}", to.direct))
            .header("authorization", header)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }

    pub async fn register(&self, username: &str) -> (String, String) {
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
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }

    pub async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                // Anyone may set the topic, so a joined user's state event
                // can go through the hub like a message does; and anyone
                // may send `m.room.hub`, so any server's user can hand the
                // hub over or claim it.
                Some(&json!({
                    "preset": "public_chat",
                    "power_level_content_override": {
                        "events": { "m.room.topic": 0, "m.room.hub": 0 },
                    },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// Name this node the room's hub: an `m.room.hub` sent by `token`.
    pub async fn designate_hub(&self, token: &str, room: &str) -> String {
        self.designate_hub_with(token, room, &json!({})).await
    }

    /// An `m.room.hub` with `content`, sent by `token`: the first one, a
    /// handoff to this node, or whatever the content makes it.
    pub async fn designate_hub_with(&self, token: &str, room: &str, content: &Value) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.hub"),
                Some(token),
                Some(content),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    pub async fn join(&self, token: &str, room: &str, via: &Node) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/join/{room}?server_name={}", via.name),
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    pub async fn say(&self, token: &str, room: &str, text: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/{}",
                    txn()
                ),
                Some(token),
                Some(&json!({ "msgtype": "m.text", "body": text })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    pub async fn set_topic(&self, token: &str, room: &str, topic: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
                Some(token),
                Some(&json!({ "topic": topic })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    /// The room's message events this node holds, oldest first.
    pub async fn messages(&self, token: &str, room: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=500"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let mut ids: Vec<String> = body["chunk"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.room.message")
            .filter_map(|event| event["event_id"].as_str().map(str::to_owned))
            .collect();
        ids.reverse();
        ids
    }

    /// The room's current state as `(type, state_key) -> event_id`.
    pub async fn state_ids(&self, token: &str, room: &str) -> Vec<(String, String, String)> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/state"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let mut ids: Vec<(String, String, String)> = body
            .as_array()
            .into_iter()
            .flatten()
            .map(|event| {
                (
                    event["type"].as_str().unwrap_or_default().to_owned(),
                    event["state_key"].as_str().unwrap_or_default().to_owned(),
                    event["event_id"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        ids.sort();
        ids
    }

    /// The stored PDU for an event, as this node would serve it.
    pub fn pdu(&self, room: &str, event_id: &str) -> Value {
        self.state.rooms.pdu(room, event_id).unwrap()
    }

    pub fn holds(&self, room: &str, event_id: &str) -> bool {
        self.state.rooms.pdu(room, event_id).is_ok()
    }
}

/// Forward each connection to `direct` until the node is cut off; while it
/// is, refuse new ones and drop the ones open.
async fn forward(
    proxy: tokio::net::TcpListener,
    direct: String,
    cut: tokio::sync::watch::Sender<bool>,
) {
    loop {
        let Ok((mut inbound, _)) = proxy.accept().await else {
            return;
        };
        if *cut.borrow() {
            drop(inbound);
            continue;
        }
        let direct = direct.clone();
        let mut watch = cut.subscribe();
        tokio::spawn(async move {
            let Ok(mut outbound) = tokio::net::TcpStream::connect(&direct).await else {
                return;
            };
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                _ = watch.wait_for(|cut| *cut) => {}
            }
        });
    }
}

fn txn() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("t{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Poll until `check` holds or `seconds` pass.
pub async fn eventually(seconds: u64, mut check: impl AsyncFnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
