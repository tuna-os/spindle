//! The appservice transaction push — a real Spindle instance over TCP,
//! delivering to a mock bridge.
//!
//! What the suite pins: events in a room the service is interested in
//! arrive at its push URL bearing the `hs_token`; a failed delivery is
//! retried under the *same* transaction ID with the same events, and an
//! acknowledged one is never re-sent; and traffic in rooms outside the
//! namespaces is not delivered at all — while still advancing the cursor,
//! so the interesting event that follows arrives alone.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One recorded delivery to the mock bridge. `ephemeral` is `None` when
/// the transaction body carried no such key at all — MSC2409 has
/// non-opted services never see the key, so its absence is an assertion.
#[derive(Clone, Debug)]
struct Delivery {
    txn_id: String,
    authorization: String,
    events: Vec<Value>,
    ephemeral: Option<Vec<Value>>,
    /// The whole body, for MSC3202 payloads keyed by unstable names.
    raw: Value,
}

/// The mock bridge: records every transaction, and can be told to fail
/// the next N requests with a 500 first.
#[derive(Clone, Default)]
struct Bridge {
    deliveries: Arc<Mutex<Vec<Delivery>>>,
    failures_left: Arc<Mutex<u32>>,
}

impl Bridge {
    async fn serve() -> (Self, String) {
        let bridge = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let state = bridge.clone();
        let app = axum::Router::new()
            .route(
                "/_matrix/app/v1/transactions/{txn_id}",
                axum::routing::put(
                    |axum::extract::State(state): axum::extract::State<Bridge>,
                     axum::extract::Path(txn_id): axum::extract::Path<String>,
                     request: Request<Body>| async move {
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                            .await
                            .unwrap_or_default();
                        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        let delivery = Delivery {
                            txn_id,
                            authorization,
                            events: as_events(&body),
                            ephemeral: body["ephemeral"].as_array().cloned(),
                            raw: body.clone(),
                        };
                        {
                            let mut failures = state.failures_left.lock().unwrap();
                            if *failures > 0 {
                                *failures -= 1;
                                state.deliveries.lock().unwrap().push(delivery);
                                return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                            }
                        }
                        state.deliveries.lock().unwrap().push(delivery);
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .with_state(bridge.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (state, url)
    }

    fn deliveries(&self) -> Vec<Delivery> {
        self.deliveries.lock().unwrap().clone()
    }

    fn fail_next(&self, count: u32) {
        *self.failures_left.lock().unwrap() = count;
    }
}

fn as_events(body: &Value) -> Vec<Value> {
    body["events"].as_array().cloned().unwrap_or_default()
}

const AS_TOKEN: &str = "as_secret_token_for_tests";
const HS_TOKEN: &str = "hs_secret_token_for_tests";

/// One homeserver on a real TCP listener, registered to push at `as_url`.
struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start(as_url: &str) -> Instance {
        Self::start_with(as_url, false).await
    }

    async fn start_with(as_url: &str, receive_ephemeral: bool) -> Instance {
        // The MSC3202/MSC4190 flags under their unstable names, which is
        // what shipping bridge registrations actually contain — so the
        // aliases are what this suite exercises.
        Self::start_yaml(&format!(
            "id: testbridge\nurl: \"{as_url}\"\nas_token: {AS_TOKEN}\n\
             hs_token: {HS_TOKEN}\nsender_localpart: _bridge_bot\n\
             receive_ephemeral: {receive_ephemeral}\n\
             namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
        ))
        .await
    }

    async fn start_msc3202(as_url: &str) -> Instance {
        Self::start_yaml(&format!(
            "id: testbridge\nurl: \"{as_url}\"\nas_token: {AS_TOKEN}\n\
             hs_token: {HS_TOKEN}\nsender_localpart: _bridge_bot\n\
             io.element.msc4190: true\n\
             org.matrix.msc3202: true\n\
             namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
        ))
        .await
    }

    async fn start_yaml(registration: &str) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(&reg_path, registration).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\nretry_base_ms = 50\n\
             [appservices]\nregistrations = [\"{}\"]\n",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            _reg_dir: reg_dir,
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

    /// A room created and spoken into by the bridge's ghost user.
    async fn ghost_room_with_message(&self, ghost: &str, text: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/createRoom?user_id={ghost}"),
                Some(AS_TOKEN),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/t-{text}?user_id={ghost}"
                ),
                Some(AS_TOKEN),
                Some(&json!({ "msgtype": "m.text", "body": text })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        room
    }
}

/// Poll until `check` passes or five seconds elapse — push delivery rides
/// the poll interval of the push loop.
async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

fn bodies(deliveries: &[Delivery]) -> Vec<String> {
    deliveries
        .iter()
        .flat_map(|delivery| delivery.events.iter())
        .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn interested_events_arrive_bearing_the_hs_token() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_alice:{}", server.name);

    server.ghost_room_with_message(&ghost, "bridged").await;

    assert!(
        eventually(|| bodies(&bridge.deliveries()).contains(&"bridged".to_owned())).await,
        "the message reaches the bridge: {:?}",
        bridge.deliveries()
    );
    let deliveries = bridge.deliveries();
    let carrying = deliveries
        .iter()
        .find(|delivery| bodies(std::slice::from_ref(delivery)).contains(&"bridged".to_owned()))
        .unwrap();
    assert_eq!(
        carrying.authorization,
        format!("Bearer {HS_TOKEN}"),
        "the homeserver identifies itself with the hs_token"
    );
    // The batch carries the room's whole birth: creation state, then the
    // message, in stream order — the message is last.
    let last = carrying.events.last().unwrap();
    assert_eq!(last["content"]["body"], "bridged");
    assert_eq!(last["sender"], Value::String(ghost));
}

#[tokio::test]
async fn a_failed_delivery_retries_under_the_same_transaction_id() {
    let (bridge, as_url) = Bridge::serve().await;
    bridge.fail_next(1);
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_bob:{}", server.name);

    server.ghost_room_with_message(&ghost, "retried").await;

    assert!(
        eventually(|| bridge.deliveries().len() >= 2).await,
        "a failure and its retry both arrive"
    );
    let deliveries = bridge.deliveries();
    let (first, second) = (&deliveries[0], &deliveries[1]);
    assert_eq!(
        first.txn_id, second.txn_id,
        "the retry re-uses the transaction ID, so the bridge can deduplicate"
    );
    assert_eq!(
        bodies(std::slice::from_ref(first)),
        bodies(std::slice::from_ref(second)),
        "and carries the identical batch"
    );

    // Once acknowledged, the batch never comes back: whatever arrives
    // next (nothing, or a later batch) does not repeat this txn_id.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let after = bridge.deliveries();
    assert_eq!(
        after
            .iter()
            .filter(|delivery| delivery.txn_id == first.txn_id)
            .count(),
        2,
        "an acknowledged transaction is done: {after:?}"
    );
}

#[tokio::test]
async fn uninterested_traffic_is_skipped_not_delivered() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url).await;

    // A human's private room, well outside the namespaces.
    let alice = server.register("alice").await;
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let private = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{private}/send/m.room.message/t1"),
            Some(&alice),
            Some(&json!({ "msgtype": "m.text", "body": "private words" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Then one interesting event. The push must skip past the private
    // room's whole history — cursor advanced without delivery — and hand
    // over only the ghost's room.
    let ghost = format!("@_bridge_carol:{}", server.name);
    server
        .ghost_room_with_message(&ghost, "public enough")
        .await;

    assert!(
        eventually(|| bodies(&bridge.deliveries()).contains(&"public enough".to_owned())).await,
        "the interesting event still arrives"
    );
    let all_bodies = bodies(&bridge.deliveries());
    assert!(
        !all_bodies.contains(&"private words".to_owned()),
        "nothing from outside the namespaces leaks: {all_bodies:?}"
    );
    assert!(
        bridge.deliveries().iter().all(|delivery| delivery
            .events
            .iter()
            .all(|event| event["room_id"] != Value::String(private.clone()))),
        "not even the private room's state events"
    );
}

/// The `m.typing` ephemeral entries for one room across all deliveries.
fn typing_for(deliveries: &[Delivery], room: &str) -> Vec<Value> {
    deliveries
        .iter()
        .flat_map(|delivery| delivery.ephemeral.iter().flatten())
        .filter(|entry| entry["type"] == "m.typing" && entry["room_id"] == room)
        .cloned()
        .collect()
}

#[tokio::test]
async fn typing_rides_the_transaction_as_ephemeral() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start_with(&as_url, true).await;
    let ghost = format!("@_bridge_typist:{}", server.name);
    let room = server.ghost_room_with_message(&ghost, "warmup").await;

    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/typing/{ghost}?user_id={ghost}"),
            Some(AS_TOKEN),
            Some(&json!({ "typing": true, "timeout": 30000 })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    assert!(
        eventually(|| {
            typing_for(&bridge.deliveries(), &room).iter().any(|entry| {
                entry["content"]["user_ids"]
                    .as_array()
                    .is_some_and(|users| users.iter().any(|user| user == ghost.as_str()))
            })
        })
        .await,
        "the typing start reaches the bridge: {:?}",
        bridge.deliveries()
    );

    // Stopping is announced exactly once, as an empty list — and then
    // silence, not a heartbeat of empty lists every poll.
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/typing/{ghost}?user_id={ghost}"),
            Some(AS_TOKEN),
            Some(&json!({ "typing": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(|| {
            typing_for(&bridge.deliveries(), &room)
                .last()
                .is_some_and(|entry| entry["content"]["user_ids"] == json!([]))
        })
        .await,
        "the stop arrives: {:?}",
        bridge.deliveries()
    );
    let settled = typing_for(&bridge.deliveries(), &room).len();
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        typing_for(&bridge.deliveries(), &room).len(),
        settled,
        "no repeated announcements once reality stopped changing"
    );
}

#[tokio::test]
async fn a_service_that_did_not_opt_in_never_sees_the_key() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_quiet:{}", server.name);
    let room = server.ghost_room_with_message(&ghost, "hello").await;

    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/typing/{ghost}?user_id={ghost}"),
            Some(AS_TOKEN),
            Some(&json!({ "typing": true, "timeout": 30000 })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The room's events still arrive...
    assert!(
        eventually(|| bodies(&bridge.deliveries()).contains(&"hello".to_owned())).await,
        "events flow regardless"
    );
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    // ...but no delivery ever carries the ephemeral key at all.
    assert!(
        bridge
            .deliveries()
            .iter()
            .all(|delivery| delivery.ephemeral.is_none()),
        "MSC2409 is opt-in; the key must be absent: {:?}",
        bridge.deliveries()
    );
}

#[tokio::test]
async fn device_lists_and_key_counts_ride_the_transaction_for_msc3202() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start_msc3202(&as_url).await;
    let ghost = format!("@_bridge_keyed:{}", server.name);
    let room = server.ghost_room_with_message(&ghost, "warmup").await;
    assert!(
        eventually(|| bodies(&bridge.deliveries()).contains(&"warmup".to_owned())).await,
        "the warmup batch lands first"
    );

    // The bridge mints the ghost's device (MSC4190) and uploads identity
    // keys plus one OTK through the ordinary endpoints, device-masqueraded
    // per MSC3202.
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/devices/GHOSTDEV?user_id={ghost}"),
            Some(AS_TOKEN),
            Some(&json!({ "display_name": "ghost shell" })),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            &format!(
                "/_matrix/client/v3/keys/upload?user_id={ghost}&org.matrix.msc3202.device_id=GHOSTDEV"
            ),
            Some(AS_TOKEN),
            Some(&json!({
                "device_keys": {
                    "user_id": ghost,
                    "device_id": "GHOSTDEV",
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                    "keys": {},
                    "signatures": {},
                },
                "one_time_keys": { "signed_curve25519:AAAA": { "key": "k" } },
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Another message closes the window; the batch carrying it must also
    // carry the device-list change and the ghost device's key counts.
    server
        .request(
            reqwest::Method::PUT,
            &format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/t-trigger?user_id={ghost}"
            ),
            Some(AS_TOKEN),
            Some(&json!({ "msgtype": "m.text", "body": "trigger" })),
        )
        .await;

    assert!(
        eventually(|| {
            bridge.deliveries().iter().any(|delivery| {
                delivery.raw["org.matrix.msc3202.device_lists"]["changed"]
                    .as_array()
                    .is_some_and(|changed| changed.iter().any(|user| user == ghost.as_str()))
            })
        })
        .await,
        "the device-list change reaches the bridge: {:?}",
        bridge.deliveries()
    );
    assert!(
        eventually(|| {
            bridge.deliveries().iter().any(|delivery| {
                delivery.raw["org.matrix.msc3202.device_one_time_keys_count"][&ghost]["GHOSTDEV"]
                    ["signed_curve25519"]
                    == json!(1)
            })
        })
        .await,
        "the ghost device's OTK count says exactly one key: {:?}",
        bridge.deliveries()
    );
}

#[tokio::test]
async fn a_service_without_msc3202_never_sees_its_keys() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_plain:{}", server.name);

    // A human's key upload marks their device list changed inside the
    // window the next batch covers...
    let alice = server.register("alice").await;
    let (_, whoami) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    let device = whoami["device_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(&json!({
                "device_keys": {
                    "user_id": format!("@alice:{}", server.name),
                    "device_id": device,
                    "algorithms": [], "keys": {}, "signatures": {},
                },
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // ...and the batch itself still arrives, without a single MSC3202 key.
    server.ghost_room_with_message(&ghost, "plain").await;
    assert!(
        eventually(|| bodies(&bridge.deliveries()).contains(&"plain".to_owned())).await,
        "events flow regardless"
    );
    assert!(
        bridge.deliveries().iter().all(|delivery| {
            delivery.raw.as_object().is_some_and(|body| {
                body.keys()
                    .all(|key| !key.starts_with("org.matrix.msc3202"))
            })
        }),
        "MSC3202 is opt-in; its keys must be absent: {:?}",
        bridge.deliveries()
    );
}
