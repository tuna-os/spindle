//! The device-list update chain across federation (#740): each
//! `m.device_list_update` names the update before it as `prev_id`, a
//! receiver applies an update that follows inline and refetches the whole
//! list through `GET /_matrix/federation/v1/user/devices/{userId}` once when
//! one went missing, and the `stream_id` that route serves is the one the
//! next update names.
//!
//! Two Spindles on loopback, each reached by its peers through a proxy that
//! writes down every request it forwards, so the tests can read the EDUs
//! that crossed and count the refetches.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_server::AppState;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One request a node's proxy forwarded: method, path, JSON body.
type Seen = Arc<Mutex<Vec<(String, String, Value)>>>;

struct Node {
    _dir: TempDir,
    /// The server name: the proxy's address.
    name: String,
    /// The listener itself, for requests nobody should count.
    direct: String,
    state: AppState,
    client: reqwest::Client,
    seen: Seen,
}

impl Node {
    async fn start() -> Node {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let direct = listener.local_addr().unwrap().to_string();
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = proxy.local_addr().unwrap().to_string();
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
             retry_base_ms = 50\n",
        ))
        .unwrap();
        let (app, state) = spindle_server::app_with_state(
            config,
            store,
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
        let seen = Seen::default();
        tokio::spawn(record_and_forward(proxy, direct.clone(), Arc::clone(&seen)));
        Node {
            _dir: dir,
            name,
            direct,
            state,
            client: reqwest::Client::new(),
            seen,
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Value {
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
        let body = parse(&response.bytes().await.unwrap_or_default());
        assert_eq!(status, 200, "{path}: {body}");
        body
    }

    /// Register `username`, returning the token and the user ID.
    async fn register(&self, username: &str) -> (String, String) {
        let body = self
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
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }

    /// Log `username` in on a new device and give it identity keys: one
    /// device-list change. Returns the device ID.
    async fn new_device(&self, username: &str, user_id: &str) -> String {
        let body = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/login",
                None,
                Some(&json!({
                    "type": "m.login.password",
                    "identifier": { "type": "m.id.user", "user": username },
                    "password": "hunter2",
                })),
            )
            .await;
        let token = body["access_token"].as_str().unwrap();
        let device_id = body["device_id"].as_str().unwrap().to_owned();
        self.request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(token),
            Some(&json!({ "device_keys": device_keys(user_id, &device_id) })),
        )
        .await;
        device_id
    }

    /// A signed federation request from this node straight to `to`'s
    /// listener, past its proxy.
    async fn federation(&self, to: &Node, method: &str, uri: &str, body: Option<&Value>) -> Value {
        let header = self
            .state
            .federation
            .sign_request(method, uri, &to.name, body)
            .unwrap();
        let mut request = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{}{uri}", to.direct),
            )
            .header("authorization", header);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = parse(&response.bytes().await.unwrap_or_default());
        assert_eq!(status, 200, "{uri}: {body}");
        body
    }

    /// Send `to` a transaction carrying `edus`.
    async fn send_edus(&self, to: &Node, txn_id: &str, edus: Vec<Value>) {
        let body = json!({
            "origin": self.name,
            "origin_server_ts": 0,
            "pdus": [],
            "edus": edus,
        });
        let uri = format!("/_matrix/federation/v1/send/{txn_id}");
        self.federation(to, "PUT", &uri, Some(&body)).await;
    }

    /// How many times another server fetched a user's device list here.
    fn refetches(&self) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, path, _)| {
                method == "GET" && path.starts_with("/_matrix/federation/v1/user/devices/")
            })
            .count()
    }

    /// Every `m.device_list_update` this node was sent, in arrival order.
    fn device_list_updates(&self) -> Vec<Value> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, path, _)| {
                method == "PUT" && path.starts_with("/_matrix/federation/v1/send/")
            })
            .flat_map(|(_, _, body)| body["edus"].as_array().cloned().unwrap_or_default())
            .filter(|edu| edu["edu_type"] == "m.device_list_update")
            .map(|edu| edu["content"].clone())
            .collect()
    }
}

/// Record each request, then forward it to `direct`. A device-list fetch is
/// answered a beat late, so updates that arrive behind a gap reach the
/// receiver while its refetch is still in flight -- the window in which an
/// uncoalesced receiver would ask twice.
async fn record_and_forward(proxy: tokio::net::TcpListener, direct: String, seen: Seen) {
    let client = reqwest::Client::new();
    let app = axum::Router::new().fallback(move |request: Request<Body>| {
        let (client, direct, seen) = (client.clone(), direct.clone(), Arc::clone(&seen));
        async move {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap_or_default();
            let path = parts
                .uri
                .path_and_query()
                .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
            seen.lock().unwrap().push((
                parts.method.to_string(),
                path.clone(),
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            ));
            if path.contains("/user/devices/") {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let mut forward = client.request(
                reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap(),
                format!("http://{direct}{path}"),
            );
            for name in ["authorization", "content-type"] {
                if let Some(value) = parts.headers.get(name) {
                    forward = forward.header(name, value.as_bytes());
                }
            }
            let response = forward.body(bytes).send().await.unwrap();
            let status = axum::http::StatusCode::from_u16(response.status().as_u16()).unwrap();
            (status, response.bytes().await.unwrap_or_default().to_vec())
        }
    });
    axum::serve(proxy, app).await.unwrap();
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

fn device_keys(user_id: &str, device_id: &str) -> Value {
    json!({
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {
            format!("curve25519:{device_id}"): "curvekey",
            format!("ed25519:{device_id}"): "edkey",
        },
        "signatures": {},
    })
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn each_update_names_the_last_and_a_contiguous_chain_is_applied_inline() {
    let a = Node::start().await;
    let b = Node::start().await;
    let (alice_token, alice) = a.register("alice").await;
    let (bob_token, _) = b.register("bob").await;
    let room = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice_token),
            Some(&json!({ "preset": "public_chat" })),
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    b.request(
        reqwest::Method::POST,
        &format!("/_matrix/client/v3/join/{room}?server_name={}", a.name),
        Some(&bob_token),
        Some(&json!({})),
    )
    .await;

    let first = a.new_device("alice", &alice).await;
    let second = a.new_device("alice", &alice).await;
    assert!(
        eventually(|| b.device_list_updates().len() >= 2).await,
        "both updates reach the server sharing the room: {:?}",
        b.device_list_updates()
    );
    let updates = b.device_list_updates();
    assert_eq!(updates.len(), 2, "{updates:?}");
    assert_eq!(updates[0]["device_id"], first.as_str());
    assert_eq!(updates[1]["device_id"], second.as_str());
    let first_id = updates[0]["stream_id"].as_u64().unwrap();
    let second_id = updates[1]["stream_id"].as_u64().unwrap();
    assert!(second_id > first_id, "{updates:?}");
    // The first update of alice's chain has nothing before it; the second
    // names the first, not an empty list.
    assert_eq!(updates[0]["prev_id"], json!([]));
    assert_eq!(updates[1]["prev_id"], json!([first_id]));

    // Both followed what b held, so b applied them as they came and never
    // asked a for the whole list.
    assert!(
        eventually(|| {
            b.state
                .devices
                .remote_device_list_stream_id(&alice)
                .unwrap()
                == Some(second_id)
        })
        .await
    );
    let held = b.state.devices.all_device_keys(&alice).unwrap();
    assert!(
        held.contains_key(&first) && held.contains_key(&second),
        "{held:?}"
    );
    assert_eq!(a.refetches(), 0, "a contiguous chain needs no refetch");

    // The snapshot a serves is at the head of that same chain: a peer that
    // refetched now would recognise the next update as following it.
    let listing = b
        .federation(
            &a,
            "GET",
            &format!("/_matrix/federation/v1/user/devices/{alice}"),
            None,
        )
        .await;
    assert_eq!(listing["stream_id"], json!(second_id), "{listing}");
    assert_eq!(listing["devices"].as_array().unwrap().len(), 2, "{listing}");
    let third = a.new_device("alice", &alice).await;
    assert!(eventually(|| b.device_list_updates().len() >= 3).await);
    let update = &b.device_list_updates()[2];
    assert_eq!(update["device_id"], third.as_str());
    assert_eq!(update["prev_id"], json!([listing["stream_id"]]));
}

#[tokio::test]
async fn a_gap_in_the_chain_costs_exactly_one_refetch() {
    let a = Node::start().await;
    let b = Node::start().await;
    let (_, alice) = a.register("alice").await;
    // Four real changes on a, so the list a serves is the one the chain
    // describes. alice shares no room with b, so a tells b nothing itself;
    // the test carries the updates, and loses one.
    let mut devices = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..4 {
        devices.push(a.new_device("alice", &alice).await);
        ids.push(a.state.devices.device_list_stream_id(&alice).unwrap());
    }
    let update = |index: usize, prev: &[u64]| {
        json!({
            "edu_type": "m.device_list_update",
            "content": {
                "user_id": alice,
                "device_id": devices[index],
                "stream_id": ids[index],
                "prev_id": prev,
                "deleted": false,
                "keys": device_keys(&alice, &devices[index]),
            },
        })
    };

    // The start of the chain applies inline.
    a.send_edus(&b, "start", vec![update(0, &[])]).await;
    assert!(
        eventually(|| b
            .state
            .devices
            .remote_device_list_stream_id(&alice)
            .unwrap()
            == Some(ids[0]))
        .await
    );
    assert_eq!(
        a.refetches(),
        0,
        "the start of a chain is applied as it stands"
    );

    // The second update is lost. The third names it, and the fourth, in
    // flight at the same time, names the third: both arrive behind the gap.
    tokio::join!(
        a.send_edus(&b, "third", vec![update(2, &[ids[1]])]),
        a.send_edus(&b, "fourth", vec![update(3, &[ids[2]])]),
    );
    assert!(
        eventually(|| b
            .state
            .devices
            .remote_device_list_stream_id(&alice)
            .unwrap()
            == Some(ids[3]))
        .await,
        "b accounts for the whole chain after the refetch"
    );
    assert_eq!(
        a.refetches(),
        1,
        "one gap, one refetch, however many updates wait on it"
    );
    // The lost update's device came back with the snapshot.
    let held = b.state.devices.all_device_keys(&alice).unwrap();
    for device in &devices {
        assert!(held.contains_key(device), "{device} missing from {held:?}");
    }

    // Past the refetch, the chain is continuous again.
    let fifth = a.new_device("alice", &alice).await;
    let fifth_id = a.state.devices.device_list_stream_id(&alice).unwrap();
    let next = json!({
        "edu_type": "m.device_list_update",
        "content": {
            "user_id": alice,
            "device_id": fifth,
            "stream_id": fifth_id,
            "prev_id": [ids[3]],
            "deleted": false,
            "keys": device_keys(&alice, &fifth),
        },
    });
    a.send_edus(&b, "fifth", vec![next]).await;
    assert!(
        eventually(|| b
            .state
            .devices
            .remote_device_list_stream_id(&alice)
            .unwrap()
            == Some(fifth_id))
        .await
    );
    assert_eq!(
        a.refetches(),
        1,
        "an update that follows the snapshot needs none"
    );
}
