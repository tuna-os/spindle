//! Outbound federation: what we create reaches the servers sharing the room.
//!
//! The stub peer records every transaction and can be told to refuse the
//! first N — because the property under test is not "a request is made"
//! but the delivery discipline around it: rows deleted only on
//! acknowledgement, retries reusing the same transaction ID so the peer's
//! replay table absorbs duplicates, and delivery surviving a server
//! rebuild over the same directory.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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
    /// The transaction IDs of refused attempts — the retry contract is
    /// that a later success reuses them.
    refused_ids: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    async fn start() -> Stub {
        let deliveries: Arc<Mutex<Vec<Delivery>>> = Arc::default();
        let refuse = Arc::new(AtomicUsize::new(0));
        let refused_ids: Arc<Mutex<Vec<String>>> = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        let record = Arc::clone(&deliveries);
        let gate = Arc::clone(&refuse);
        let refused_log = Arc::clone(&refused_ids);
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
                            if gate
                                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                                    (left > 0).then(|| left - 1)
                                })
                                .is_ok()
                            {
                                refused_log.lock().unwrap().push(txn);
                                return (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_owned());
                            }
                            let authorization = headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
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
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Stub {
            name,
            deliveries,
            refuse,
            refused_ids,
        }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    fn delivered(&self) -> Vec<Delivery> {
        self.deliveries.lock().unwrap().clone()
    }

    /// All PDU bodies delivered so far, flattened.
    fn pdus(&self) -> Vec<Value> {
        self.delivered()
            .iter()
            .flat_map(|(_, _, body)| body["pdus"].as_array().cloned().unwrap_or_default())
            .collect()
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
    dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let app = Self::build(dir.path());
        Self { dir, app }
    }

    fn build(path: &std::path::Path) -> axum::Router {
        let store = Arc::new(FjallStore::open(path).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nretry_base_ms = 50\n",
        )
        .unwrap();
        spindle_server::app(config, store).expect("the app builds")
    }

    fn restart(&mut self) {
        self.app = Self::build(self.dir.path());
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
async fn a_refused_transaction_retries_under_the_same_id() {
    let stub = Stub::start().await;
    stub.refuse.store(2, Ordering::SeqCst);
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_remote_invite(&alice, &stub.user()).await;
    harness.say(&room, &alice, "eventually", "t1").await;

    assert!(
        stub.wait_for(|stub| {
            stub.pdus()
                .iter()
                .any(|pdu| pdu["content"]["body"] == json!("eventually"))
        })
        .await,
        "delivered after refusals"
    );
    assert_eq!(
        stub.refuse.load(Ordering::SeqCst),
        0,
        "the refusals were spent"
    );
    // The delivery that finally landed reused the refused attempts' own
    // transaction ID — derived from the queue rows, not the attempt — so a
    // peer that half-processed an earlier try dedups instead of doubling.
    let refused = stub.refused_ids.lock().unwrap().clone();
    assert!(!refused.is_empty());
    let succeeded: Vec<String> = stub
        .delivered()
        .iter()
        .map(|(txn, _, _)| txn.clone())
        .collect();
    assert!(
        refused.iter().all(|txn| succeeded.contains(txn)),
        "refused {refused:?} vs succeeded {succeeded:?}"
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
