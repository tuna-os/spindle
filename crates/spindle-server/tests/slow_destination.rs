//! #21's slow-destination drill: a federation peer answers, but slowly.
//!
//! The property under test is that one slow destination does not wedge
//! this server: client sends return while the peer is still thinking,
//! readiness stays 200, and the outbox still delivers once the peer
//! answers. The stub peer sleeps a controlled delay before answering
//! `PUT /_matrix/federation/v1/send/{txn}`, where the existing
//! `federation_outbox` stubs answer at once.
//!
//! Unlike the disk-full drill this needs no privileges and runs in
//! seconds, so it is an ordinary (non-ignored) test rather than a
//! scripted drill.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// How long the stub waits before answering a transaction. Long enough
/// that a client send coupled to delivery could not beat it, short enough
/// that the test stays quick -- and under the federation client's send
/// timeout, so the first attempt succeeds rather than retrying.
const PEER_DELAY: Duration = Duration::from_secs(5);
/// A client send paced by a 5s peer would take at least the delay. Twice
/// as fast as the peer is still orders slower than a decoupled send.
const SEND_BUDGET: Duration = Duration::from_millis(2_500);

/// One recorded delivery: transaction ID and body.
type Delivery = (String, Value);

struct SlowStub {
    name: String,
    deliveries: Arc<Mutex<Vec<Delivery>>>,
    delay_ms: Arc<AtomicU64>,
}

impl SlowStub {
    async fn start() -> SlowStub {
        let deliveries: Arc<Mutex<Vec<Delivery>>> = Arc::default();
        let delay_ms = Arc::new(AtomicU64::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        let record = Arc::clone(&deliveries);
        let delay = Arc::clone(&delay_ms);
        let router = axum::Router::new()
            .route(
                "/_matrix/federation/v1/send/{txn}",
                axum::routing::put(
                    move |axum::extract::Path(txn): axum::extract::Path<String>, body: String| {
                        let record = Arc::clone(&record);
                        let delay = Arc::clone(&delay);
                        async move {
                            let wait = delay.load(Ordering::SeqCst);
                            if wait > 0 {
                                tokio::time::sleep(Duration::from_millis(wait)).await;
                            }
                            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                            record.lock().unwrap().push((txn, parsed));
                            (StatusCode::OK, json!({ "pdus": {} }).to_string())
                        }
                    },
                ),
            )
            // Same echo answer as the outbox stub: the inviting server
            // checks the reference hash, and signatures sit outside it.
            .route(
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    |axum::extract::Json(body): axum::extract::Json<Value>| async move {
                        axum::Json(json!({ "event": body["event"] }))
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        SlowStub {
            name,
            deliveries,
            delay_ms,
        }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    fn set_delay(&self, delay: Duration) {
        self.delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    fn pdus(&self) -> Vec<Value> {
        self.deliveries
            .lock()
            .unwrap()
            .iter()
            .flat_map(|(_, body)| body["pdus"].as_array().cloned().unwrap_or_default())
            .collect()
    }

    async fn wait_for<F: Fn(&SlowStub) -> bool>(&self, what: F) -> bool {
        for _ in 0..1_200 {
            if what(self) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    #[allow(dead_code, reason = "the app borrows nothing; the store outlives it")]
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        )
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        Self { dir, store, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }
}

/// A slow destination neither blocks local sends nor loses them: the
/// client send returns long before the peer answers, readiness stays 200
/// throughout, and the PDU is delivered once the peer responds.
#[tokio::test]
async fn a_slow_destination_neither_blocks_nor_loses_delivery() {
    let peer = SlowStub::start().await;
    let server = Harness::new();
    let alice = server.register("alice").await;

    let (_, body) = server
        .send("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": peer.user() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The room now has a remote member, so every message fans out to a
    // peer that takes five seconds to answer.
    peer.set_delay(PEER_DELAY);

    let started = Instant::now();
    let (status, body) = server
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/first"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "first" }),
        )
        .await;
    let send_latency = started.elapsed();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        send_latency < SEND_BUDGET,
        "the send waited on the slow peer: {send_latency:?}"
    );

    // A second send while the first is still in flight is just as fast:
    // nothing serialises behind the slow destination.
    let started = Instant::now();
    let (status, body) = server
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/second"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "second" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        started.elapsed() < SEND_BUDGET,
        "the second send queued behind the first: {:?}",
        started.elapsed()
    );

    // Readiness never wavers: a slow peer is not an unhealthy server.
    let (status, _) = server
        .call(Request::get("/ready").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);

    // And once the peer answers, both PDUs land.
    assert!(
        peer.wait_for(|stub| stub.pdus().len() >= 2).await,
        "the slow peer never got both messages: {:?}",
        peer.pdus()
    );
}
