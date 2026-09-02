//! Part of #267, target 2: the federation front door, fed by a stranger.
//!
//! `PUT /_matrix/federation/v1/send/{txnId}` is the one endpoint every
//! server on the internet may call before this one has decided whether to
//! trust it. Everything a peer controls arrives here: the X-Matrix header,
//! the transaction id in the path, and fifty PDUs of JSON. Each is driven
//! below with inputs no honest peer sends, and the property is the same in
//! every case -- the server answers, with a status it meant, and is still
//! standing afterwards.
//!
//! One finding is pinned rather than fuzzed. The X-Matrix `origin` was
//! pasted into a URL and fetched from before anything about the request
//! had been checked, because fetching the origin's keys is how the check
//! begins. A name that is not a server name -- `127.0.0.1:6379/x?` -- was
//! therefore a request this server would make to a host, port and path of
//! a stranger's choosing, from inside its own network. The sentinel below
//! is that host, and it must never hear the doorbell.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Map, Value, json};
use spindle_server::federation::parse_x_matrix;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

// -- a real peer, so the envelope verifies and the PDUs inside are judged --

struct Peer {
    name: String,
    pair: Ed25519KeyPair,
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
            "verify_keys": { "ed25519:0": { "key": unpadded(&public_key(&pair)) } },
        });
        sign_value(&name, &signing, &mut key_document);
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
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer { name, pair }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    /// A V11 event of this peer's making: hashed and signed like the real thing.
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
}

fn public_key(pair: &Ed25519KeyPair) -> Vec<u8> {
    pair.public_key().to_vec()
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

// -- the server under test ------------------------------------------------

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { _dir: dir, app }
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

    /// A room with the peer's user invited, and the head event's ID.
    async fn room_with_invite(&self, alice: &str, peer_user: &str) -> (String, String) {
        let (_, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", alice, &json!({}))
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                alice,
                &json!({ "user_id": peer_user }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, body) = self
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                    ))
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let head = body["chunk"][0]["event_id"].as_str().unwrap().to_owned();
        (room, head)
    }

    /// A transaction the peer signed, carrying whatever `pdus` and `edus`
    /// hold -- the envelope is honest so the contents get judged.
    async fn deliver(
        &self,
        peer: &Peer,
        txn_id: &str,
        pdus: Vec<Value>,
        edus: Vec<Value>,
    ) -> (StatusCode, Value) {
        let body = json!({
            "origin": peer.name,
            "origin_server_ts": now_millis(),
            "pdus": pdus,
            "edus": edus,
        });
        let header = peer.transaction_header(txn_id, &body);
        self.call(
            Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/federation/v1/send/{txn_id}"))
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// A request whose only claim is the header: no peer, no signature.
    async fn knock_with(&self, authorization: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri("/_matrix/federation/v1/send/knock")
                .header("authorization", authorization)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "pdus": [] }).to_string()))
                .unwrap(),
        )
        .await
    }
}

fn join_event(peer: &Peer, room: &str, prev: &str) -> Value {
    peer.event(json!({
        "type": "m.room.member",
        "state_key": peer.user(),
        "sender": peer.user(),
        "room_id": room,
        "content": { "membership": "join" },
        "origin_server_ts": now_millis(),
        "depth": 10,
        "prev_events": [prev],
        "auth_events": [],
    }))
}

// -- the finding ----------------------------------------------------------

/// A host on this server's own network that no stranger should be able to
/// make it call. Counts the connections it receives and hangs up.
struct Sentinel {
    port: u16,
    knocks: Arc<AtomicUsize>,
}

impl Sentinel {
    async fn listen() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let knocks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&knocks);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, knocks }
    }

    fn knocks(&self) -> usize {
        self.knocks.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_hostile_origin_never_becomes_an_outbound_request() {
    let sentinel = Sentinel::listen().await;
    let harness = Harness::new();
    let port = sentinel.port;

    // Each of these parses as an X-Matrix header. Before the gate, each
    // became `http://<origin>/_matrix/key/v2/server` -- and with the origin
    // carrying its own path, a request to wherever that path pointed.
    let origins = [
        format!("127.0.0.1:{port}/x?y="),
        format!("127.0.0.1:{port}/../../admin"),
        format!("127.0.0.1:{port}#"),
        format!("nobody@127.0.0.1:{port}"),
        format!("127.0.0.1:{port}?"),
    ];
    for origin in &origins {
        let header = format!("X-Matrix origin=\"{origin}\",key=\"ed25519:0\",sig=\"AAAA\"");
        assert!(parse_x_matrix(&header).is_ok(), "{header} should parse");
        let (status, body) = harness.knock_with(&header).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{origin}: {body}");
    }

    // Enough time for a connection that was going to happen to have
    // happened; the sentinel is on the loopback.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        sentinel.knocks(),
        0,
        "a stranger's header made this server call a host of their choosing"
    );
}

#[tokio::test]
async fn an_honest_origin_is_still_fetched_from() {
    // The gate must not be a wall: the peer here is `127.0.0.1:<port>`,
    // exactly the shape the sentinel test refuses with a path attached.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (status, body) = harness
        .deliver(&peer, "honest", Vec::new(), Vec::new())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_unsignable_body_is_refused_not_fatal() {
    // Canonical JSON has no floats and no integers past 2^53, so a peer
    // cannot sign a body holding one. The header here is honest for a
    // different body; the server canonicalises this one to check it, and
    // the canonicalisation is the refusal.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let header = peer.transaction_header("odd", &json!({ "pdus": [] }));
    for body in [
        json!({ "pdus": [{ "depth": 9_007_199_254_740_993_u64 }] }),
        json!({ "pdus": [{ "depth": 1.5 }] }),
        json!({ "pdus": [{ "depth": -9_007_199_254_740_993_i64 }] }),
    ] {
        let (status, answer) = harness
            .call(
                Request::builder()
                    .method("PUT")
                    .uri("/_matrix/federation/v1/send/odd")
                    .header("authorization", &header)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}: {answer}");
    }
    let (status, body) = harness
        .deliver(&peer, "after", Vec::new(), Vec::new())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_transaction_id_the_replay_key_cannot_hold_is_refused() {
    let peer = Peer::start().await;
    let harness = Harness::new();

    let at_the_bound = "t".repeat(255);
    let (status, body) = harness
        .deliver(&peer, &at_the_bound, Vec::new(), Vec::new())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let past_it = "t".repeat(256);
    let (status, body) = harness
        .deliver(&peer, &past_it, Vec::new(), Vec::new())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

// -- the fuzzing ----------------------------------------------------------

/// Any JSON a peer could have signed: a few levels deep, small enough that
/// fifty of them fit under the transaction body limit, and with integers
/// inside the range canonical JSON admits. Floats and wider integers never
/// arrive inside a verified envelope, because no peer can sign them;
/// `an_unsignable_body_is_refused_not_fatal` covers what happens when one
/// tries.
fn any_json() -> impl Strategy<Value = Value> {
    const CANONICAL: i64 = 1 << 53;
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-CANONICAL..=CANONICAL).prop_map(|number| json!(number)),
        "\\PC{0,16}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 24, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map("\\PC{0,8}", inner, 0..5)
                .prop_map(|fields| Value::Object(fields.into_iter().collect())),
        ]
    })
}

/// A real, signed join with one field replaced by anything. The signature
/// no longer holds, or the hash does not, or the field is the wrong shape:
/// each is a different refusal, and every one of them has to be a refusal
/// rather than a crash.
fn mutated(honest: &Map<String, Value>) -> impl Strategy<Value = Value> + '_ {
    let fields: Vec<String> = honest.keys().cloned().collect();
    (prop::sample::select(fields), any_json()).prop_map(move |(field, replacement)| {
        let mut pdu = honest.clone();
        pdu.insert(field, replacement);
        Value::Object(pdu)
    })
}

#[tokio::test]
async fn arbitrary_pdus_in_signed_transactions_are_answered_not_fatal() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    // A real join first, so later events are judged against a room the
    // peer is actually in and the authorization rules have state to read.
    let join = join_event(&peer, &room, &head);
    let (status, body) = harness
        .deliver(&peer, "join", vec![join.clone()], Vec::new())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let Value::Object(honest) = join else {
        unreachable!("a signed event is an object")
    };

    // Deterministic, so a failure here is a failure next time too.
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
    );
    let strategy = prop_oneof![
        3 => mutated(&honest),
        1 => any_json(),
    ];

    // Eight transactions of fifty on an ordinary run; the scheduled long
    // run raises `PROPTEST_CASES` and this suite follows it, one PDU per
    // case, so the budget means the same thing here as in the `proptest!`
    // arms.
    let batches = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse::<usize>().ok())
        .map_or(8, |cases| cases.div_ceil(50).clamp(8, 400));
    for batch in 0..batches {
        let pdus: Vec<Value> = (0..50)
            .map(|_| strategy.new_tree(&mut runner).unwrap().current())
            .collect();
        let edus: Vec<Value> = (0..5)
            .map(|_| any_json().new_tree(&mut runner).unwrap().current())
            .collect();
        let (status, body) = harness
            .deliver(&peer, &format!("fuzz-{batch}"), pdus, edus)
            .await;
        assert_eq!(status, StatusCode::OK, "batch {batch}: {body}");
        assert!(
            body["pdus"].is_object(),
            "batch {batch} answered without per-PDU results: {body}"
        );
    }

    // Still standing, and still a server: the honest peer's next message
    // lands after every hostile one.
    let message = peer.event(json!({
        "type": "m.room.message",
        "sender": peer.user(),
        "room_id": room,
        "content": { "msgtype": "m.text", "body": "still here" },
        "origin_server_ts": now_millis(),
        "depth": 11,
        "prev_events": [honest_event_id(&harness, &alice, &room).await],
        "auth_events": [],
    }));
    let (status, body) = harness
        .deliver(&peer, "after", vec![message], Vec::new())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pdus"].as_object().unwrap().len(), 1);
    assert!(
        body["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|result| result == &json!({})),
        "the honest message after the fuzz was refused: {body}"
    );
}

/// The room's current head, as the peer would learn it.
async fn honest_event_id(harness: &Harness, alice: &str, room: &str) -> String {
    let (_, body) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    body["chunk"][0]["event_id"].as_str().unwrap().to_owned()
}

proptest! {
    /// The header parser, fed anything: it answers or it refuses.
    #[test]
    fn x_matrix_headers_parse_or_refuse(header in "\\PC{0,200}") {
        let _ = std::hint::black_box(parse_x_matrix(&header));
    }

    /// The header parser, fed near-misses: a real header with one
    /// parameter's value replaced by anything printable, quotes included.
    #[test]
    fn a_header_with_one_odd_value_parses_or_refuses(
        parameter in prop::sample::select(vec!["origin", "destination", "key", "sig"]),
        value in "\\PC{0,64}",
    ) {
        let mut parts = vec![
            ("origin", "peer.example".to_owned()),
            ("destination", "example.org".to_owned()),
            ("key", "ed25519:0".to_owned()),
            ("sig", "AAAA".to_owned()),
        ];
        for (name, slot) in &mut parts {
            if *name == parameter {
                *slot = value.clone();
            }
        }
        let header = format!(
            "X-Matrix {}",
            parts
                .iter()
                .map(|(name, value)| format!("{name}=\"{value}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let _ = std::hint::black_box(parse_x_matrix(&header));
    }
}
