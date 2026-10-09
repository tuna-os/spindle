//! Read receipts across federation (#624).
//!
//! Inbound, against a signing peer harness: an `m.receipt` EDU from the
//! origin's own joined user lands in classic `/sync` (initial and
//! incremental) and in sliding sync's receipts extension, threaded or not;
//! a receipt for a user not on the origin, for a user not in the room, of
//! a private type, or for an event this server lacks is ignored and
//! counted. Outbound, against a peer that records the transactions it is
//! sent: a local public receipt goes to the room's other server as a
//! coalesced `m.receipt` EDU and a private one never does. And end to end,
//! two real Spindles: a threaded receipt set on one is seen, thread and
//! all, by the other's clients.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::{EduResult, EduType, Metrics, ReceiptResult};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A peer server: publishes its key, answers invites, and records every
/// transaction it is sent.
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
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    |axum::extract::Json(body): axum::extract::Json<Value>| async move {
                        axum::Json(json!({ "event": body["event"] }))
                    },
                ),
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

    /// Every `m.receipt` EDU this peer has been sent so far.
    fn receipt_edus(&self) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .flat_map(|txn| txn["edus"].as_array().cloned().unwrap_or_default())
            .filter(|edu| edu["edu_type"] == "m.receipt")
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
async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check().await {
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
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        )
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

    async fn head_event(&self, room: &str, token: &str) -> String {
        let body = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"),
                token,
            )
            .await;
        body["chunk"][0]["event_id"].as_str().unwrap().to_owned()
    }

    async fn deliver_edus(&self, peer: &Peer, txn_id: &str, edus: Vec<Value>) -> StatusCode {
        self.deliver(peer, txn_id, Vec::new(), edus).await
    }

    async fn deliver(
        &self,
        peer: &Peer,
        txn_id: &str,
        pdus: Vec<Value>,
        edus: Vec<Value>,
    ) -> StatusCode {
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
        status
    }

    /// A room of alice's with the peer's user joined over federation, and
    /// one message of alice's in it: `(room, message event ID)`.
    async fn shared_room(&self, alice: &str, peer: &Peer) -> (String, String) {
        let (_, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "preset": "public_chat" }),
            )
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let head = self.head_event(&room, alice).await;
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
        let (status, sent) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/m1"),
                alice,
                &json!({ "msgtype": "m.text", "body": "read me" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{sent}");
        (room, sent["event_id"].as_str().unwrap().to_owned())
    }

    async fn sliding_receipts(&self, token: &str, room: &str) -> Value {
        self.sliding(token, None).await["extensions"]["receipts"]["rooms"][room]["content"].clone()
    }

    async fn sliding(&self, token: &str, pos: Option<&str>) -> Value {
        let path = match pos {
            Some(pos) => {
                format!("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}")
            }
            None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
        };
        let (status, body) = self
            .send(
                "POST",
                &path,
                token,
                &json!({
                    "lists": { "main": { "ranges": [[0, 9]], "timeline_limit": 1 } },
                    "extensions": { "receipts": { "enabled": true } },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// The `m.receipt` content in one room's `/sync` ephemeral events.
fn sync_receipts(sync: &Value, room: &str) -> Value {
    sync["rooms"]["join"][room]["ephemeral"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|event| event["type"] == "m.receipt")
        .map_or(Value::Null, |event| event["content"].clone())
}

fn receipt_edu(
    room: &str,
    receipt_type: &str,
    user: &str,
    event_ids: &[&str],
    data: &Value,
) -> Value {
    json!({
        "edu_type": "m.receipt",
        "content": {
            room: { receipt_type: { user: { "event_ids": event_ids, "data": data } } }
        },
    })
}

#[tokio::test]
async fn a_joined_remote_readers_receipt_reaches_classic_and_sliding_sync() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, message) = harness.shared_room(&alice, &peer).await;
    let bob = peer.user();

    let before = harness.get("/_matrix/client/v3/sync", &alice).await;
    let since = before["next_batch"].as_str().unwrap().to_owned();
    assert!(
        sync_receipts(&before, &room)[&message]["m.read"][&bob].is_null(),
        "no receipt yet: {before}"
    );

    harness
        .deliver_edus(
            &peer,
            "r1",
            vec![receipt_edu(
                &room,
                "m.read",
                &bob,
                &[&message],
                &json!({ "ts": 1_700_000_000_000_u64 }),
            )],
        )
        .await;

    // Incremental: the room is spoken about for the receipt alone.
    let incremental = harness
        .get(&format!("/_matrix/client/v3/sync?since={since}"), &alice)
        .await;
    let receipts = sync_receipts(&incremental, &room);
    assert_eq!(
        receipts[&message]["m.read"][&bob]["ts"],
        json!(1_700_000_000_000_u64),
        "the reader's own timestamp: {incremental}"
    );
    // And not again once acknowledged.
    let next = incremental["next_batch"].as_str().unwrap();
    let quiet = harness
        .get(&format!("/_matrix/client/v3/sync?since={next}"), &alice)
        .await;
    assert!(sync_receipts(&quiet, &room).is_null(), "{quiet}");

    // Initial: on the event in the timeline it sends.
    let initial = harness.get("/_matrix/client/v3/sync", &alice).await;
    assert!(
        sync_receipts(&initial, &room)[&message]["m.read"][&bob]["ts"].is_u64(),
        "{initial}"
    );

    // Sliding sync's receipts extension reads the same rows.
    let first = harness.sliding(&alice, None).await;
    let sliding = &first["extensions"]["receipts"]["rooms"][&room]["content"];
    assert!(sliding[&message]["m.read"][&bob]["ts"].is_u64(), "{first}");
    let pos = first["pos"].as_str().unwrap().to_owned();

    // A threaded receipt in the same room keeps its thread.
    harness
        .deliver_edus(
            &peer,
            "r2",
            vec![receipt_edu(
                &room,
                "m.read",
                &bob,
                &[&message],
                &json!({ "ts": now_millis(), "thread_id": "main" }),
            )],
        )
        .await;
    // Incrementally, sliding sync sends what moved since `pos`, and then
    // nothing more until something moves again.
    let next = harness.sliding(&alice, Some(&pos)).await;
    let threaded = &next["extensions"]["receipts"]["rooms"][&room]["content"][&message]["m.read"]
        [&bob]["thread_id"];
    assert_eq!(threaded, &json!("main"), "{next}");
    let pos = next["pos"].as_str().unwrap().to_owned();
    let quiet = harness.sliding(&alice, Some(&pos)).await;
    assert!(
        quiet["extensions"]["receipts"]["rooms"][&room].is_null(),
        "{quiet}"
    );

    assert_eq!(
        harness
            .metrics
            .receipt_received_count(ReceiptResult::Accepted),
        2
    );
    assert_eq!(
        harness
            .metrics
            .edu_received_count(EduType::Receipt, EduResult::Accepted),
        2
    );
}

#[tokio::test]
async fn receipts_the_origin_has_no_authority_for_are_ignored() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, message) = harness.shared_room(&alice, &peer).await;
    let stranger = format!("@carol:{}", peer.name);

    harness
        .deliver_edus(
            &peer,
            "r1",
            vec![
                // Not the origin's user: no server speaks for another's.
                receipt_edu(
                    &room,
                    "m.read",
                    "@alice:example.org",
                    &[&message],
                    &json!({}),
                ),
                // The origin's user, but not in the room.
                receipt_edu(&room, "m.read", &stranger, &[&message], &json!({})),
                // A private receipt never federates.
                receipt_edu(
                    &room,
                    "m.read.private",
                    &peer.user(),
                    &[&message],
                    &json!({}),
                ),
                // An event this server does not hold.
                receipt_edu(&room, "m.read", &peer.user(), &["$nope"], &json!({})),
                // Not the shape the spec gives it.
                json!({ "edu_type": "m.receipt", "content": [] }),
                // Presence is not federated (see `receipts`): counted only.
                json!({ "edu_type": "m.presence", "content": { "push": [] } }),
            ],
        )
        .await;

    let sliding = harness.sliding_receipts(&alice, &room).await;
    for user in [
        "@alice:example.org",
        stranger.as_str(),
        peer.user().as_str(),
    ] {
        assert!(
            sliding[&message]["m.read"][user].is_null()
                && sliding[&message]["m.read.private"][user].is_null(),
            "{user} must have no receipt: {sliding}"
        );
    }
    let sync = harness.get("/_matrix/client/v3/sync", &alice).await;
    assert!(
        sync_receipts(&sync, &room)[&message]["m.read"][&peer.user()].is_null(),
        "{sync}"
    );

    let metrics = &harness.metrics;
    assert_eq!(
        metrics.receipt_received_count(ReceiptResult::ForeignUser),
        1
    );
    assert_eq!(metrics.receipt_received_count(ReceiptResult::NotJoined), 1);
    assert_eq!(
        metrics.receipt_received_count(ReceiptResult::UnsupportedType),
        1
    );
    assert_eq!(
        metrics.receipt_received_count(ReceiptResult::UnknownEvent),
        1
    );
    assert_eq!(metrics.receipt_received_count(ReceiptResult::Accepted), 0);
    assert_eq!(
        metrics.edu_received_count(EduType::Receipt, EduResult::Ignored),
        4
    );
    assert_eq!(
        metrics.edu_received_count(EduType::Receipt, EduResult::Malformed),
        1
    );
    assert_eq!(
        metrics.edu_received_count(EduType::Presence, EduResult::Unsupported),
        1
    );
}

#[tokio::test]
async fn a_local_public_receipt_goes_to_the_rooms_other_server_and_a_private_one_does_not() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let alice_id = "@alice:example.org";
    let (room, message) = harness.shared_room(&alice, &peer).await;

    // Private first: if it were going to leak, it would be in the
    // transaction the public one rides in, or one before it.
    for (path, body) in [
        (
            format!("/_matrix/client/v3/rooms/{room}/receipt/m.read.private/{message}"),
            json!({}),
        ),
        (
            format!("/_matrix/client/v3/rooms/{room}/read_markers"),
            json!({ "m.fully_read": message }),
        ),
        (
            format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{message}"),
            json!({ "thread_id": "main" }),
        ),
    ] {
        let (status, response) = harness.send("POST", &path, &alice, &body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    assert!(
        eventually(async || {
            peer.receipt_edus().iter().any(|edu| {
                edu["content"][&room]["m.read"][alice_id]["event_ids"] == json!([message])
            })
        })
        .await,
        "the peer hears alice's public receipt: {:?}",
        peer.receipt_edus()
    );
    let edus = peer.receipt_edus();
    let receipt = &edus
        .iter()
        .find(|edu| !edu["content"][&room]["m.read"][alice_id].is_null())
        .unwrap()["content"][&room]["m.read"][alice_id];
    assert_eq!(receipt["data"]["thread_id"], "main", "{receipt}");
    assert!(receipt["data"]["ts"].is_u64(), "{receipt}");
    let everything = serde_json::to_string(&*peer.received.lock().unwrap()).unwrap();
    assert!(
        !everything.contains("m.read.private") && !everything.contains("m.fully_read"),
        "nothing private crossed: {everything}"
    );

    // The read-markers endpoint's public half federates too, and a burst
    // of receipts is coalesced: one reader, one entry per thread.
    let (status, response) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/read_markers"),
            &alice,
            &json!({ "m.read": message }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        eventually(async || {
            peer.receipt_edus().iter().any(|edu| {
                let entry = &edu["content"][&room]["m.read"][alice_id];
                !entry.is_null() && entry["data"]["thread_id"].is_null()
            })
        })
        .await,
        "the unthreaded receipt from /read_markers crosses: {:?}",
        peer.receipt_edus()
    );
    assert!(harness.metrics.edu_sent_count(EduType::Receipt) >= 2);
}

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
}

#[tokio::test]
async fn a_threaded_receipt_round_trips_between_two_spindles() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;
    let bob_id = format!("@bob:{}", mirror.name);

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
    let (status, sent) = origin
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/m1"),
            Some(&alice),
            Some(&json!({ "msgtype": "m.text", "body": "thread root" })),
        )
        .await;
    assert_eq!(status, 200, "{sent}");
    let message = sent["event_id"].as_str().unwrap().to_owned();

    // Bob can only read what his server holds: wait for the event to cross,
    // then set a receipt in the thread it roots.
    let path = format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{message}");
    assert!(
        eventually(async || {
            let (status, _) = mirror
                .request(
                    reqwest::Method::POST,
                    &path,
                    Some(&bob),
                    Some(&json!({ "thread_id": message })),
                )
                .await;
            status == 200
        })
        .await,
        "the message reaches bob's server and his receipt is taken"
    );

    let receipt_seen = async || {
        let (status, sync) = origin
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/sync",
                Some(&alice),
                None,
            )
            .await;
        assert_eq!(status, 200, "{sync}");
        sync_receipts(&sync, &room)[&message]["m.read"][&bob_id]["thread_id"] == json!(message)
    };
    assert!(
        eventually(receipt_seen).await,
        "alice's classic sync shows bob's threaded receipt"
    );
    let (status, sliding) = origin
        .request(
            reqwest::Method::POST,
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            Some(&alice),
            Some(&json!({
                "lists": { "main": { "ranges": [[0, 9]], "timeline_limit": 1 } },
                "extensions": { "receipts": { "enabled": true } },
            })),
        )
        .await;
    assert_eq!(status, 200, "{sliding}");
    assert_eq!(
        sliding["extensions"]["receipts"]["rooms"][&room]["content"][&message]["m.read"][&bob_id]["thread_id"],
        json!(message),
        "{sliding}"
    );
}
