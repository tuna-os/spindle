//! Outbound federation: what we create reaches the servers sharing the room.
//!
//! The stub peer records every transaction and can be told to refuse the
//! first N — because the property under test is not "a request is made"
//! but the delivery discipline around it: rows deleted only on
//! acknowledgement, retries of the same rows reusing the same transaction
//! ID so the peer's replay table absorbs duplicates, a retry that carries
//! more rows getting a new one so the replay table cannot swallow them,
//! and delivery surviving a server rebuild over the same directory -- for
//! PDUs, and for the EDUs a peer cannot ask for again (to-device messages,
//! device-list updates), while typing stays fire-once. And for a peer
//! that stays down (#801): a wait that grows with the outage, survives a
//! restart and ends when the peer speaks to us, and a catch-up that sends
//! a returning peer each room's newest events rather than its backlog.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_server::federation::DeliveryHealth;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// One recorded delivery: transaction ID, X-Matrix header, body.
type Delivery = (String, String, Value);

struct Stub {
    name: String,
    deliveries: Arc<Mutex<Vec<Delivery>>>,
    /// Refuse this many requests with a 500 before accepting.
    refuse: Arc<AtomicUsize>,
    /// The attempts refused, recorded like deliveries.
    refused: Arc<Mutex<Vec<Delivery>>>,
    /// The key it signs its own requests with, served at
    /// `/_matrix/key/v2/server`.
    pair: Ed25519KeyPair,
}

impl Stub {
    // `fetch_update` is deprecated from Rust 1.99 (renamed `try_update`,
    // absent from the pinned 1.90 toolchain).
    #[allow(deprecated)]
    async fn start() -> Stub {
        let deliveries: Arc<Mutex<Vec<Delivery>>> = Arc::default();
        let refuse = Arc::new(AtomicUsize::new(0));
        let refused: Arc<Mutex<Vec<Delivery>>> = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 600_000,
            "verify_keys": { "ed25519:0": { "key": unpadded(&pair.public_key()) } },
        });
        sign_value(&name, &pair, &mut key_document);

        let record = Arc::clone(&deliveries);
        let gate = Arc::clone(&refuse);
        let refused_log = Arc::clone(&refused);
        let router = axum::Router::new()
            .route(
                "/_matrix/federation/v1/send/{txn}",
                axum::routing::put(
                    move |axum::extract::Path(txn): axum::extract::Path<String>,
                          headers: axum::http::HeaderMap,
                          body: String| {
                        let record = Arc::clone(&record);
                        let gate = Arc::clone(&gate);
                        let refused_log = Arc::clone(&refused_log);
                        async move {
                            let authorization = headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                            if gate
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                    (left > 0).then(|| left - 1)
                                })
                                .is_ok()
                            {
                                refused_log
                                    .lock()
                                    .unwrap()
                                    .push((txn, authorization, parsed));
                                return (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_owned());
                            }
                            record.lock().unwrap().push((txn, authorization, parsed));
                            (StatusCode::OK, json!({ "pdus": {} }).to_string())
                        }
                    },
                ),
            )
            // The invite handshake's other half: the harness invites the
            // stub's user to give the room a remote member, and the inviting
            // server will not append the invite until this server answers.
            // Echoing the event back is a valid answer — the reference hash
            // is what the inviter checks, and signatures sit outside it.
            .route(
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    |axum::extract::Json(body): axum::extract::Json<Value>| async move {
                        axum::Json(json!({ "event": body["event"] }))
                    },
                ),
            )
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let document = key_document.clone();
                    async move { axum::Json(document) }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Stub {
            name,
            deliveries,
            refuse,
            refused,
            pair,
        }
    }

    /// A signed request from this peer to `destination`'s `uri`, the way a
    /// homeserver signs one.
    fn authorization(&self, method: &str, uri: &str, destination: &str, body: &Value) -> String {
        let mut object = json!({
            "method": method,
            "uri": uri,
            "origin": self.name,
            "destination": destination,
            "content": body,
        });
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap()
            .to_owned();
        format!(
            "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"ed25519:0\",sig=\"{signature}\"",
            self.name
        )
    }

    /// Every attempt this peer has seen, refused or accepted.
    fn attempts(&self) -> usize {
        self.refused.lock().unwrap().len() + self.deliveries.lock().unwrap().len()
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    fn delivered(&self) -> Vec<Delivery> {
        self.deliveries.lock().unwrap().clone()
    }

    fn refused(&self) -> Vec<Delivery> {
        self.refused.lock().unwrap().clone()
    }

    /// All PDU bodies delivered so far, flattened.
    fn pdus(&self) -> Vec<Value> {
        self.delivered()
            .iter()
            .flat_map(|(_, _, body)| body["pdus"].as_array().cloned().unwrap_or_default())
            .collect()
    }

    /// All EDUs delivered so far, flattened.
    fn edus(&self) -> Vec<Value> {
        flat_edus(self.delivered().iter().map(|(_, _, body)| body))
    }

    /// All EDUs in refused attempts so far, flattened.
    fn refused_edus(&self) -> Vec<Value> {
        flat_edus(self.refused().iter().map(|(_, _, body)| body))
    }

    async fn wait_for<F: Fn(&Stub) -> bool>(&self, what: F) -> bool {
        for _ in 0..100 {
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
    store: Arc<FjallStore>,
    app: axum::Router,
    state: spindle_server::AppState,
    retry_base_ms: u64,
}

impl Harness {
    fn new() -> Self {
        Self::with_retry_base(50)
    }

    /// A server whose outbox backs off from `retry_base_ms`: a destination
    /// down for 600 times that is in its long wait (#801).
    fn with_retry_base(retry_base_ms: u64) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let (app, state) = Self::build(&store, retry_base_ms);
        Self {
            dir,
            store,
            app,
            state,
            retry_base_ms,
        }
    }

    fn build(
        store: &Arc<FjallStore>,
        retry_base_ms: u64,
    ) -> (axum::Router, spindle_server::AppState) {
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
             retry_base_ms = {retry_base_ms}\n",
        ))
        .unwrap();
        spindle_server::app_with_state(
            config,
            Arc::clone(store),
            Arc::new(spindle_server::metrics::Metrics::new()),
        )
        .expect("the app builds")
    }

    /// How the outbox stands with `destination`.
    fn health(&self, destination: &str) -> DeliveryHealth {
        self.state
            .federation
            .delivery_health()
            .remove(destination)
            .unwrap_or_default()
    }

    /// Wait, up to `seconds`, until the outbox waits at least `millis`
    /// between attempts at `destination`.
    async fn wait_for_backoff(&self, destination: &str, millis: u64, seconds: u64) -> bool {
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(seconds) {
            if self.health(destination).retry_interval >= millis {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// A second server over the same store.
    ///
    /// Shares the handle rather than reopening the directory, which fjall 3
    /// locks for as long as any handle lives -- and a running server's own
    /// delivery loops hold one. The outbox claim is unchanged: the pending
    /// rows are read back from the store by the new server's drain loop,
    /// which is what "survive a rebuild" means here.
    fn restart(&mut self) {
        (self.app, self.state) = Self::build(&self.store, self.retry_base_ms);
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

    async fn room_with_remote_invite(&self, alice: &str, remote_user: &str) -> String {
        let (_, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", alice, &json!({}))
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                alice,
                &json!({ "user_id": remote_user }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room
    }

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// A to-device message from `token`'s user to one device of `user`.
    async fn send_to_device(&self, token: &str, user: &str, txn: &str, text: &str) {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/sendToDevice/m.room_key/{txn}"),
                token,
                &json!({ "messages": { user: { "PHONE": { "body": text } } } }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn whoami(&self, token: &str) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/_matrix/client/v3/account/whoami")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Publish device keys for `token`'s device: a device-list change every
    /// server sharing a room with its user is told about.
    async fn upload_device_keys(&self, token: &str) {
        let whoami = self.whoami(token).await;
        let user_id = whoami["user_id"].as_str().unwrap();
        let device_id = whoami["device_id"].as_str().unwrap();
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/keys/upload",
                token,
                &json!({
                    "device_keys": {
                        "user_id": user_id,
                        "device_id": device_id,
                        "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                        "keys": { format!("ed25519:{device_id}"): "edkey" },
                        "signatures": {},
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// A transaction from `stub` with nothing in it: the peer talking to
    /// us, as a server back up does.
    async fn hear_from(&self, stub: &Stub, txn: &str) {
        let uri = format!("/_matrix/federation/v1/send/{txn}");
        let body = json!({ "origin": stub.name, "origin_server_ts": now_millis(), "pdus": [] });
        let (status, answer) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(&uri)
                    .header(
                        "authorization",
                        stub.authorization("PUT", &uri, "example.org", &body),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }

    async fn start_typing(&self, room: &str, token: &str) {
        let whoami = self.whoami(token).await;
        let user_id = whoami["user_id"].as_str().unwrap();
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/typing/{user_id}"),
                token,
                &json!({ "typing": true, "timeout": 30_000 }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn local_events_reach_the_remote_members_server_signed() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "for the neighbours", "t1").await;

    assert!(
        stub.wait_for(|stub| {
            stub.pdus()
                .iter()
                .any(|pdu| pdu["content"]["body"] == json!("for the neighbours"))
        })
        .await,
        "the message reached the peer: {:?}",
        stub.delivered()
    );
    // Every delivery arrived signed as us.
    for (_, authorization, _) in stub.delivered() {
        assert!(
            authorization.starts_with("X-Matrix origin=\"example.org\""),
            "{authorization}"
        );
    }
}

#[tokio::test]
async fn acknowledged_rows_are_not_sent_again() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "once", "t1").await;

    assert!(
        stub.wait_for(|stub| !stub.pdus().is_empty()).await,
        "delivered at all"
    );
    let settled = stub.delivered().len();
    // Several poll cycles later, nothing new: the rows were deleted on
    // acknowledgement, not merely marked.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(stub.delivered().len(), settled, "{:?}", stub.delivered());
}

#[tokio::test]
async fn a_retry_reuses_its_transaction_id_only_for_the_same_rows() {
    let stub = Stub::start().await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    let carries = |body: &Value, text: &str| {
        body["pdus"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|pdu| pdu["content"]["body"] == json!(text))
    };

    // Refused twice with the same rows waiting: one transaction, retried.
    harness.say(&room, &alice, "first", "t1").await;
    assert!(
        stub.wait_for(|stub| {
            stub.refused()
                .iter()
                .filter(|(_, _, body)| carries(body, "first"))
                .count()
                >= 2
        })
        .await,
        "{:?}",
        stub.refused()
    );
    // A row queued since: the retry carries more, as it does after a peer
    // took an attempt and its answer was lost.
    harness.say(&room, &alice, "second", "t2").await;
    assert!(
        stub.wait_for(|stub| stub
            .refused()
            .iter()
            .any(|(_, _, body)| carries(body, "second")))
            .await,
        "{:?}",
        stub.refused()
    );
    stub.refuse.store(0, Ordering::SeqCst);
    assert!(
        stub.wait_for(|stub| stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("second")))
            .await,
        "delivered after refusals"
    );

    // One ID per set of rows, both ways. A retry of the same rows reuses
    // its ID, so a peer that half-processed an earlier try dedups instead
    // of doubling; a transaction that carries more never reuses the ID of
    // one the peer may already have answered, so its replay table cannot
    // swallow the rows added since.
    let attempts: Vec<(String, Value)> = stub
        .refused()
        .into_iter()
        .chain(stub.delivered())
        .filter(|(_, _, body)| body["pdus"].as_array().is_some_and(|pdus| !pdus.is_empty()))
        .map(|(txn, _, body)| (txn, body["pdus"].clone()))
        .collect();
    for (txn, pdus) in &attempts {
        for (other_txn, other_pdus) in &attempts {
            assert_eq!(
                txn == other_txn,
                pdus == other_pdus,
                "{txn} {pdus} / {other_txn} {other_pdus}"
            );
        }
    }
    let (delivered, _, _) = stub
        .delivered()
        .into_iter()
        .find(|(_, _, body)| carries(body, "second"))
        .unwrap();
    assert!(
        stub.refused().iter().any(|(txn, _, _)| *txn == delivered),
        "the delivery reused the ID its refused attempt had"
    );
}

#[tokio::test]
async fn a_server_whose_members_all_left_hears_the_kick_and_nothing_after() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;

    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": stub.user() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The kick itself is the one event the removed server must hear.
    assert!(
        stub.wait_for(|stub| {
            stub.pdus().iter().any(|pdu| {
                pdu["type"] == json!("m.room.member")
                    && pdu["content"]["membership"] == json!("leave")
            })
        })
        .await,
        "the kick was delivered: {:?}",
        stub.delivered()
    );

    // What is said afterwards is not theirs to receive.
    harness
        .say(&room, &alice, "after the door closed", "t2")
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("after the door closed")),
        "{:?}",
        stub.delivered()
    );
}

/// A server that was in the audience leaves it when its last member does.
///
/// The audience is cached against the room's state root, so this is the
/// direction that can go silently wrong: a stale entry keeps a departed
/// server on the list and it goes on receiving a room it is no longer in.
///
/// `a_server_whose_members_all_left_hears_the_kick_and_nothing_after` looks
/// like it covers this and does not. Breaking the cache's invalidation
/// leaves it green, because the kick reaches the stub through the
/// membership bypass rather than the cache, and "nothing after" is
/// satisfied for free by a room that never delivered anything. The
/// difference here is the assertion *before* the kick: it proves the domain
/// really was in the cached audience, so a stale entry would deliver the
/// message that follows.
#[tokio::test]
async fn a_kicked_servers_audience_entry_does_not_survive_in_cache() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;

    // Before: the domain is in the audience, and the cache now holds it.
    harness
        .say(&room, &alice, "while the door was open", "t1")
        .await;
    assert!(
        stub.wait_for(|stub| {
            stub.pdus()
                .iter()
                .any(|pdu| pdu["content"]["body"] == json!("while the door was open"))
        })
        .await,
        "the stub must receive events while its member is live, or the rest of \
         this test proves nothing: {:?}",
        stub.delivered()
    );

    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": stub.user() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // After: the membership change moved the state root, so the cached
    // audience is not reused.
    harness
        .say(&room, &alice, "after the door closed", "t2")
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("after the door closed")),
        "a departed server kept receiving the room: {:?}",
        stub.delivered()
    );
}

#[tokio::test]
async fn pending_rows_survive_a_rebuild_and_deliver_after() {
    let stub = Stub::start().await;
    // Refuse everything while the first incarnation runs.
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let mut harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "across the restart", "t1").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The queue rows are durable; the rebuilt server picks them up once
    // the peer accepts again.
    harness.restart();
    stub.refuse.store(0, Ordering::SeqCst);
    assert!(
        stub.wait_for(|stub| {
            stub.pdus()
                .iter()
                .any(|pdu| pdu["content"]["body"] == json!("across the restart"))
        })
        .await,
        "delivered after the rebuild: {:?}",
        stub.delivered()
    );
}

/// Rows queued while a peer is down are all delivered, in the order they
/// were queued, by a server rebuilt over the same store: the index the
/// planner works from is rebuilt from the rows, not from memory (#821).
#[tokio::test]
async fn a_backlog_is_delivered_in_order_and_whole_after_a_restart() {
    let stub = Stub::start().await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let mut harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    for number in 0..8 {
        harness
            .say(
                &room,
                &alice,
                &format!("backlog {number}"),
                &format!("b{number}"),
            )
            .await;
    }
    harness.restart();
    stub.refuse.store(0, Ordering::SeqCst);
    assert!(
        stub.wait_for(|stub| {
            (0..8).all(|number| {
                stub.pdus()
                    .iter()
                    .any(|pdu| pdu["content"]["body"] == json!(format!("backlog {number}")))
            })
        })
        .await,
        "the whole backlog arrived: {:?}",
        stub.pdus()
    );
    let order: Vec<String> = stub
        .pdus()
        .iter()
        .filter_map(|pdu| pdu["content"]["body"].as_str().map(str::to_owned))
        .filter(|body| body.starts_with("backlog "))
        .collect();
    let mut first_seen: Vec<String> = Vec::new();
    for body in order {
        if !first_seen.contains(&body) {
            first_seen.push(body);
        }
    }
    let expected: Vec<String> = (0..8).map(|number| format!("backlog {number}")).collect();
    assert_eq!(first_seen, expected);
}

fn flat_edus<'a>(bodies: impl Iterator<Item = &'a Value>) -> Vec<Value> {
    bodies
        .flat_map(|body| body["edus"].as_array().cloned().unwrap_or_default())
        .collect()
}

fn carries_to_device(edus: &[Value], text: &str) -> bool {
    edus.iter().any(|edu| {
        edu["edu_type"] == "m.direct_to_device"
            && edu["content"]["messages"]
                .as_object()
                .into_iter()
                .flat_map(|users| users.values())
                .any(|devices| devices["PHONE"]["body"] == json!(text))
    })
}

fn carries(edus: &[Value], edu_type: &str) -> bool {
    edus.iter().any(|edu| edu["edu_type"] == edu_type)
}

/// #739: the EDUs a peer cannot ask for again -- a to-device message, a
/// device-list change -- queued while it was unreachable are still owed to
/// it after this server restarts, and arrive once it answers.
#[tokio::test]
async fn to_device_and_device_list_edus_for_a_dark_peer_arrive_after_a_restart() {
    let stub = Stub::start().await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let mut harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.upload_device_keys(&alice).await;
    harness
        .send_to_device(&alice, &stub.user(), "k1", "across the restart")
        .await;
    // Tried and refused: before #739 that attempt was the only one.
    assert!(
        stub.wait_for(|stub| {
            let refused = stub.refused_edus();
            carries_to_device(&refused, "across the restart")
                && carries(&refused, "m.device_list_update")
        })
        .await,
        "the EDUs were attempted: {:?}",
        stub.refused_edus()
    );

    harness.restart();
    stub.refuse.store(0, Ordering::SeqCst);
    assert!(
        stub.wait_for(|stub| {
            let edus = stub.edus();
            carries_to_device(&edus, "across the restart") && carries(&edus, "m.device_list_update")
        })
        .await,
        "delivered after the restart: {:?}",
        stub.edus()
    );
}

/// #739: a refused transaction's to-device message is sent again, under
/// the transaction ID it was refused under, and its typing notification
/// is not -- typing redelivered late is a lie about the present.
#[tokio::test]
async fn a_refused_transaction_retries_to_device_but_not_typing() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    harness.start_typing(&room, &alice).await;
    harness
        .send_to_device(&alice, &stub.user(), "k1", "retried")
        .await;
    assert!(
        stub.wait_for(|stub| {
            let refused = stub.refused_edus();
            carries_to_device(&refused, "retried") && carries(&refused, "m.typing")
        })
        .await,
        "both were attempted: {:?}",
        stub.refused_edus()
    );

    stub.refuse.store(0, Ordering::SeqCst);
    assert!(
        stub.wait_for(|stub| carries_to_device(&stub.edus(), "retried"))
            .await,
        "the to-device message was retried: {:?}",
        stub.delivered()
    );
    // Several passes later, still no typing: it went with the failure.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!carries(&stub.edus(), "m.typing"), "{:?}", stub.edus());

    // The retry is a replay of a refused attempt, not a new transaction: a
    // peer that took the refused one and lost its answer dedups it.
    let refused: Vec<String> = stub.refused().into_iter().map(|(txn, _, _)| txn).collect();
    let landed: Vec<String> = stub
        .delivered()
        .into_iter()
        .filter(|(_, _, body)| carries_to_device(&flat_edus(std::iter::once(body)), "retried"))
        .map(|(txn, _, _)| txn)
        .collect();
    assert!(
        landed.iter().all(|txn| refused.contains(txn)),
        "landed {landed:?} vs refused {refused:?}"
    );
}

/// A server that accepts connections and never answers: what a dead or
/// wedged homeserver looks like to the outbox, a request that runs into
/// its timeout. Returns its server name.
async fn hanging_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    name
}

/// reilly.asia, 2026-11-06: a call ring for matrix.org never rang because
/// the outbox sent one destination at a time, and every pass first waited
/// out the 30 s timeout of each dead server it owed a transaction. Here
/// three hanging servers are owed rows and the drain loop is already
/// waiting on them when a message for a live peer is sent: the live peer
/// must get it within seconds, not after the dead servers' timeouts.
#[tokio::test]
async fn a_live_peer_is_not_kept_waiting_behind_dead_servers() {
    let stub = Stub::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    assert!(
        stub.wait_for(|stub| !stub.delivered().is_empty()).await,
        "the invite reached the peer first"
    );

    for seq in 0..3_u64 {
        let dead = hanging_server().await;
        spindle_store::Store::put(
            harness.store.as_ref(),
            &spindle_core::keys::federation_outbox(&dead, u64::MAX - seq),
            json!({ "type": "m.room.message", "content": {} })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    }
    // Let the drain loop pick the dead destinations up and start waiting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    harness.say(&room, &alice, "ring ring", "ring").await;
    let started = std::time::Instant::now();
    let mut arrived = false;
    while started.elapsed() < Duration::from_secs(10) {
        if stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("ring ring"))
        {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        arrived,
        "the live peer got nothing within 10 s while dead servers were owed rows"
    );
}

fn sign_value(entity: &str, pair: &Ed25519KeyPair, value: &mut Value) {
    let ruma::CanonicalJsonValue::Object(mut object) =
        ruma::CanonicalJsonValue::try_from(value.clone()).unwrap()
    else {
        unreachable!()
    };
    ruma::signatures::sign_json(entity, pair, &mut object).unwrap();
    *value = serde_json::to_value(&object).unwrap();
}

fn unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for position in 0..=chunk.len() {
            out.push(ALPHABET[((triple >> (18 - 6 * position)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap()
}

/// The `retry_base_ms` of the #801 tests: 5 ms, so an outage is long after
/// 600 times that, three seconds, and its wait is seconds long too.
const FAST_BASE_MS: u64 = 5;

/// #801: a peer down for long is waited on for as long as it has been down
/// -- not once a minute forever -- and the wait ends the moment the peer
/// sends us a request, as Synapse's does.
#[tokio::test]
async fn a_long_dead_peer_waits_as_long_as_it_was_down_until_it_speaks_to_us() {
    let stub = Stub::start().await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let harness = Harness::with_retry_base(FAST_BASE_MS);
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "while you were out", "t1").await;

    // The old cap was 64× the base, 320 ms here; six seconds is the
    // outage's own length.
    assert!(
        harness.wait_for_backoff(&stub.name, 6_000, 20).await,
        "the wait never grew past the fast phase: {:?}",
        harness.health(&stub.name)
    );
    stub.refuse.store(0, Ordering::SeqCst);
    let attempts = stub.attempts();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(stub.attempts(), attempts, "the wait was not kept");
    assert_eq!(
        harness.state.metrics.destinations_backing_off(),
        (0, 1),
        "counted as one destination in its long wait"
    );

    // The peer talks to us: it is up, and the wait is over.
    harness.hear_from(&stub, "back").await;
    let heard = std::time::Instant::now();
    let mut arrived = false;
    while heard.elapsed() < Duration::from_millis(2_000) {
        if stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("while you were out"))
        {
            arrived = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        arrived,
        "not delivered within 2 s of the peer's request, with seconds of wait left: {:?}",
        harness.health(&stub.name)
    );
    // Healthy again: nothing stored for it any more.
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(2)
        && !spindle_store::ReadView::scan_prefix(
            harness.store.as_ref(),
            &spindle_core::keys::destination_retry_all(),
        )
        .unwrap()
        .is_empty()
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let health = harness.health(&stub.name);
    assert_eq!(
        (health.retry_interval, health.failure_ts),
        (0, None),
        "{health:?}"
    );
    assert!(
        spindle_store::ReadView::scan_prefix(
            harness.store.as_ref(),
            &spindle_core::keys::destination_retry_all(),
        )
        .unwrap()
        .is_empty()
    );
}

/// #801: the wait survives a restart. Without the stored row a restart
/// tried every dead server at once and started each one's schedule over.
#[tokio::test]
async fn a_restart_keeps_waiting_on_a_long_dead_peer() {
    let stub = Stub::start().await;
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    let mut harness = Harness::with_retry_base(FAST_BASE_MS);
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "across the restart", "t1").await;
    assert!(
        harness.wait_for_backoff(&stub.name, 4_000, 20).await,
        "{:?}",
        harness.health(&stub.name)
    );
    let attempts = stub.attempts();
    harness.restart();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        stub.attempts(),
        attempts,
        "the restarted server retried at once"
    );
    let restored = harness.health(&stub.name);
    assert!(restored.retry_interval >= 4_000, "{restored:?}");
    assert!(restored.failure_ts.is_some(), "{restored:?}");

    // And it still delivers once the peer is back and says so.
    stub.refuse.store(0, Ordering::SeqCst);
    harness.hear_from(&stub, "back").await;
    assert!(
        stub.wait_for(|stub| stub
            .pdus()
            .iter()
            .any(|pdu| pdu["content"]["body"] == json!("across the restart")))
            .await,
        "{:?}",
        stub.delivered()
    );
}

/// #801: a peer back from a long outage gets each room's newest events,
/// not its whole backlog -- it fetches the rest through their
/// `prev_events` if it wants it -- and every to-device message and
/// device-list update queued for it, which it could not ask for again.
#[tokio::test]
async fn a_peer_back_from_a_long_outage_is_caught_up_and_keeps_its_to_device_messages() {
    let stub = Stub::start().await;
    let harness = Harness::with_retry_base(FAST_BASE_MS);
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    assert!(
        stub.wait_for(|stub| !stub.delivered().is_empty()).await,
        "the invite reached the peer first"
    );
    let before = stub.delivered().len();
    stub.refuse.store(usize::MAX / 2, Ordering::SeqCst);
    for index in 0..25 {
        harness
            .say(&room, &alice, &format!("m{index}"), &format!("t{index}"))
            .await;
    }
    harness.upload_device_keys(&alice).await;
    for index in 0..3 {
        harness
            .send_to_device(
                &alice,
                &stub.user(),
                &format!("k{index}"),
                &format!("key {index}"),
            )
            .await;
    }
    assert!(
        harness.wait_for_backoff(&stub.name, 3_000, 20).await,
        "{:?}",
        harness.health(&stub.name)
    );
    // Cut at the failure that found the outage long: fifteen of the
    // twenty-five messages.
    assert_eq!(harness.state.metrics.catch_up_dropped(), 15);

    stub.refuse.store(0, Ordering::SeqCst);
    harness.hear_from(&stub, "back").await;
    assert!(
        stub.wait_for(|stub| {
            let edus = stub.edus();
            (0..3).all(|index| carries_to_device(&edus, &format!("key {index}")))
                && carries(&edus, "m.device_list_update")
                && stub
                    .pdus()
                    .iter()
                    .any(|pdu| pdu["content"]["body"] == json!("m24"))
        })
        .await,
        "{:?}",
        stub.delivered()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bodies: Vec<String> = stub.delivered()[before..]
        .iter()
        .flat_map(|(_, _, body)| body["pdus"].as_array().cloned().unwrap_or_default())
        .filter_map(|pdu| pdu["content"]["body"].as_str().map(str::to_owned))
        .collect();
    let newest: Vec<String> = (15..25).map(|index| format!("m{index}")).collect();
    assert_eq!(bodies, newest);
    assert_eq!(harness.state.metrics.destinations_backing_off(), (0, 0));
}
