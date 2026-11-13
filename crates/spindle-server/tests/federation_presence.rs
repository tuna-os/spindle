//! Presence across federation (#745).
//!
//! Inbound, against a signing peer harness: an `m.presence` EDU about the
//! origin's own user, who shares a room with a local user, lands in that
//! local user's `/sync` and status endpoint; one about another server's
//! user, about a user sharing no room here, or about a local user is
//! ignored and counted. Outbound, against a peer that records the
//! transactions it is sent: a local user's change goes to the server they
//! share a room with. And with `[presence] enabled = false`, nothing goes
//! out and nothing comes in.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::{EduResult, EduType, Metrics};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A peer server: publishes its key and records every transaction it is
/// sent.
struct Peer {
    name: String,
    pair: Ed25519KeyPair,
    received: Arc<Mutex<Vec<Value>>>,
}

impl Peer {
    async fn start() -> Peer {
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        let signing = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 60_000,
            "verify_keys": { "ed25519:0": { "key": unpadded(&pair.public_key()) } },
        });
        sign_value(&name, &signing, &mut key_document);
        let received: Arc<Mutex<Vec<Value>>> = Arc::default();
        let sink = Arc::clone(&received);
        let router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { axum::Json(body) }
                }),
            )
            .route(
                "/_matrix/federation/v1/send/{_txn_id}",
                axum::routing::put(
                    move |axum::extract::Json(body): axum::extract::Json<Value>| {
                        let sink = Arc::clone(&sink);
                        async move {
                            sink.lock().unwrap().push(body);
                            axum::Json(json!({ "pdus": {} }))
                        }
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer {
            name,
            pair,
            received,
        }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    fn event(&self, event: Value) -> Value {
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.pair, &mut canonical, &rules.redaction).unwrap();
        serde_json::to_value(&canonical).unwrap()
    }

    fn transaction_header(&self, txn_id: &str, body: &Value) -> String {
        let mut object = json!({
            "method": "PUT",
            "uri": format!("/_matrix/federation/v1/send/{txn_id}"),
            "origin": self.name,
            "destination": "example.org",
            "content": body,
        });
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{signature}\"",
            self.name
        )
    }

    /// Every EDU of `edu_type` this peer has been sent so far.
    fn edus(&self, edu_type: &str) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .flat_map(|txn| txn["edus"].as_array().cloned().unwrap_or_default())
            .filter(|edu| edu["edu_type"] == edu_type)
            .collect()
    }
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

/// Poll until `check` returns true or five seconds pass -- EDU delivery
/// rides the outbox drain's poll interval.
async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
    store: Arc<FjallStore>,
    metrics: Arc<Metrics>,
}

impl Harness {
    fn new() -> Self {
        Self::with("")
    }

    fn with(extra: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n{extra}"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let app = spindle_server::app_with_metrics(config, store.clone(), Arc::clone(&metrics))
            .expect("the app builds");
        Self {
            _dir: dir,
            app,
            store,
            metrics,
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
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

    async fn get(&self, path: &str, token: &str) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
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

    async fn deliver(&self, peer: &Peer, txn_id: &str, pdus: Vec<Value>, edus: Vec<Value>) {
        let mut body =
            json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": pdus });
        if !edus.is_empty() {
            body["edus"] = Value::Array(edus);
        }
        let header = peer.transaction_header(txn_id, &body);
        let (status, response) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/_matrix/federation/v1/send/{txn_id}"))
                    .header("authorization", header)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        for (event_id, result) in response["pdus"].as_object().into_iter().flatten() {
            assert_eq!(result, &json!({}), "{event_id} refused: {response}");
        }
    }

    /// A room of alice's with the peer's user joined over federation.
    async fn shared_room(&self, alice: &str, peer: &Peer) -> String {
        let (_, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "preset": "public_chat" }),
            )
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let head = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"),
                alice,
            )
            .await["chunk"][0]["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let join = peer.event(federation_auth::with_auth_events(
            &self.store,
            json!({
                "type": "m.room.member",
                "state_key": peer.user(),
                "sender": peer.user(),
                "room_id": room,
                "content": { "membership": "join" },
                "origin_server_ts": now_millis(),
                "depth": 10,
                "prev_events": [head],
                "auth_events": [],
            }),
        ));
        self.deliver(peer, "join", vec![join], Vec::new()).await;
        room
    }
}

fn presence_edu(user: &str, presence: &str, status_msg: &str) -> Value {
    json!({
        "edu_type": "m.presence",
        "content": { "push": [{
            "user_id": user,
            "presence": presence,
            "status_msg": status_msg,
            "last_active_ago": 2_000,
            "currently_active": true,
        }] },
    })
}

/// The `m.presence` events about `user` in one `/sync` response.
fn presence_of(sync: &Value, user: &str) -> Vec<Value> {
    sync["presence"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["sender"] == user)
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_joined_remote_users_presence_from_their_own_server_reaches_sync() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.shared_room(&alice, &peer).await;
    let bob = peer.user();

    let before = harness.get("/_matrix/client/v3/sync", &alice).await;
    let since = before["next_batch"].as_str().unwrap().to_owned();
    assert!(presence_of(&before, &bob).is_empty(), "{before}");

    harness
        .deliver(
            &peer,
            "p1",
            Vec::new(),
            vec![presence_edu(&bob, "online", "from afar")],
        )
        .await;

    let incremental = harness
        .get(&format!("/_matrix/client/v3/sync?since={since}"), &alice)
        .await;
    let events = presence_of(&incremental, &bob);
    assert_eq!(events.len(), 1, "{incremental}");
    assert_eq!(events[0]["type"], "m.presence");
    assert_eq!(events[0]["content"]["presence"], "online");
    assert_eq!(events[0]["content"]["status_msg"], "from afar");
    assert_eq!(events[0]["content"]["currently_active"], true);
    assert!(
        events[0]["content"]["last_active_ago"].as_u64().unwrap() >= 2_000,
        "the peer's duration, counted from when it arrived: {incremental}"
    );

    let status = harness
        .get(&format!("/_matrix/client/v3/presence/{bob}/status"), &alice)
        .await;
    assert_eq!(status["presence"], "online", "{status}");
    assert_eq!(
        harness
            .metrics
            .edu_received_count(EduType::Presence, EduResult::Accepted),
        1
    );
}

#[tokio::test]
async fn presence_the_origin_has_no_authority_for_is_ignored() {
    let peer = Peer::start().await;
    let other = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.shared_room(&alice, &peer).await;
    let bob = peer.user();
    let since = harness.get("/_matrix/client/v3/sync", &alice).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    // Another server speaking for the peer's user.
    harness
        .deliver(
            &other,
            "p1",
            Vec::new(),
            vec![presence_edu(&bob, "online", "forged")],
        )
        .await;
    // The peer speaking for one of its users who shares no room here, and
    // for a user of this server.
    harness
        .deliver(
            &peer,
            "p2",
            Vec::new(),
            vec![
                presence_edu(&format!("@carol:{}", peer.name), "online", "stranger"),
                presence_edu("@alice:example.org", "offline", "forged"),
            ],
        )
        .await;

    let incremental = harness
        .get(&format!("/_matrix/client/v3/sync?since={since}"), &alice)
        .await;
    assert!(presence_of(&incremental, &bob).is_empty(), "{incremental}");
    assert!(
        presence_of(&incremental, &format!("@carol:{}", peer.name)).is_empty(),
        "{incremental}"
    );
    let bob_status = harness
        .get(&format!("/_matrix/client/v3/presence/{bob}/status"), &alice)
        .await;
    assert_eq!(bob_status["presence"], "offline", "{bob_status}");
    let alice_status = harness
        .get(
            "/_matrix/client/v3/presence/@alice:example.org/status",
            &alice,
        )
        .await;
    assert_eq!(alice_status["presence"], "online", "{alice_status}");
    assert_eq!(
        harness
            .metrics
            .edu_received_count(EduType::Presence, EduResult::Ignored),
        3
    );
    assert_eq!(
        harness
            .metrics
            .edu_received_count(EduType::Presence, EduResult::Accepted),
        0
    );
}

#[tokio::test]
async fn a_local_presence_change_goes_to_the_rooms_other_server() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.shared_room(&alice, &peer).await;

    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/presence/@alice:example.org/status",
            &alice,
            &json!({ "presence": "unavailable", "status_msg": "lunch" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let told = |edu: &Value| {
        edu["content"]["push"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| {
                entry["user_id"] == "@alice:example.org"
                    && entry["presence"] == "unavailable"
                    && entry["status_msg"] == "lunch"
            })
    };
    assert!(
        eventually(|| peer.edus("m.presence").iter().any(told)).await,
        "the peer hears alice's presence: {:?}",
        peer.edus("m.presence")
    );
    assert!(harness.metrics.edu_sent_count(EduType::Presence) >= 1);
}

#[tokio::test]
async fn presence_switched_off_sends_and_applies_nothing() {
    let peer = Peer::start().await;
    let harness = Harness::with("[presence]\nenabled = false\n");
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    let bob = peer.user();

    let initial = harness.get("/_matrix/client/v3/sync", &alice).await;
    assert!(initial.get("presence").is_none(), "{initial}");
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/presence/@alice:example.org/status",
            &alice,
            &json!({ "presence": "online" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "still answered: {body}");
    harness
        .deliver(
            &peer,
            "p1",
            Vec::new(),
            vec![presence_edu(&bob, "online", "ignored")],
        )
        .await;

    // Typing goes out on the same queue, after the presence would have:
    // once it has arrived, anything presence queued would have too.
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/typing/@alice:example.org"),
            &alice,
            &json!({ "typing": true, "timeout": 10_000 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        eventually(|| !peer.edus("m.typing").is_empty()).await,
        "the drain ran"
    );
    assert!(
        peer.edus("m.presence").is_empty(),
        "{:?}",
        peer.edus("m.presence")
    );

    let status = harness
        .get(&format!("/_matrix/client/v3/presence/{bob}/status"), &alice)
        .await;
    assert_eq!(status["presence"], "offline", "{status}");
    let since = initial["next_batch"].as_str().unwrap();
    let incremental = harness
        .get(&format!("/_matrix/client/v3/sync?since={since}"), &alice)
        .await;
    assert!(incremental.get("presence").is_none(), "{incremental}");
    assert_eq!(
        harness
            .metrics
            .edu_received_count(EduType::Presence, EduResult::Unsupported),
        1
    );
    assert_eq!(harness.metrics.edu_sent_count(EduType::Presence), 0);
}
