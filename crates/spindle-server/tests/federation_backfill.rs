//! Serving history to federation peers: `/backfill` and
//! `/get_missing_events`.
//!
//! Both are range reads on the linear log where a DAG server walks a graph.
//! What the suite pins: backfill walks backwards from the named event with
//! that event included and the limit honoured; `get_missing_events` fills
//! exactly the open interval between what the peer has and what it is
//! holding, preferring the events nearest the ones it is holding when the
//! gap outgrows the limit; and both reads are gated on the asking server
//! having a joined member.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

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
            "verify_keys": { "ed25519:0": { "key": unpadded(&pair.public_key()) } },
        });
        sign_value(&name, &signing, &mut key_document);
        let router = axum::Router::new().route(
            "/_matrix/key/v2/server",
            axum::routing::get(move || {
                let body = key_document.clone();
                async move { axum::Json(body) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer { name, pair }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    fn event(&self, event: &Value) -> Value {
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.pair, &mut canonical, &rules.redaction).unwrap();
        serde_json::to_value(&canonical).unwrap()
    }

    fn get_header(&self, uri: &str) -> String {
        let mut object = json!({
            "method": "GET",
            "uri": uri,
            "origin": self.name,
            "destination": "example.org",
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

    fn post_header(&self, uri: &str, body: &Value) -> String {
        let mut object = json!({
            "method": "POST",
            "uri": uri,
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

    fn put_header(&self, uri: &str, body: &Value) -> String {
        let mut object = json!({
            "method": "PUT",
            "uri": uri,
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

    async fn head_event(&self, room: &str, token: &str) -> String {
        let (_, body) = self
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        body["chunk"][0]["event_id"].as_str().unwrap().to_owned()
    }

    /// Alice's room with the peer's user joined via a federation transaction.
    async fn shared_room(&self, alice: &str, peer: &Peer) -> String {
        let (_, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", alice, &json!({}))
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                alice,
                &json!({ "user_id": peer.user() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let head = self.head_event(&room, alice).await;
        let join = peer.event(&json!({
            "type": "m.room.member",
            "state_key": peer.user(),
            "sender": peer.user(),
            "room_id": room,
            "content": { "membership": "join" },
            "origin_server_ts": now_millis(),
            "depth": 10,
            "prev_events": [head],
            "auth_events": [],
        }));
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": [join] });
        let header = peer.put_header("/_matrix/federation/v1/send/join1", &body);
        let (status, response) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri("/_matrix/federation/v1/send/join1")
                    .header("authorization", header)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        room
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn federation_get(&self, peer: &Peer, uri: &str) -> (StatusCode, Value) {
        let header = peer.get_header(uri);
        self.call(
            Request::builder()
                .uri(uri)
                .header("authorization", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn federation_post(&self, peer: &Peer, uri: &str, body: &Value) -> (StatusCode, Value) {
        let header = peer.post_header(uri, body);
        self.call(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }
}

fn bodies(pdus: &Value) -> Vec<String> {
    pdus.as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn backfill_walks_backwards_from_the_named_event_inclusive() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    for text in ["one", "two", "three"] {
        harness.say(&room, &alice, text).await;
    }
    let head = harness.head_event(&room, &alice).await;

    let uri = format!("/_matrix/federation/v1/backfill/{room}?v={head}&limit=2");
    let (status, body) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Newest first, the named event included, the limit honoured.
    assert_eq!(bodies(&body["pdus"]), ["three", "two"], "{body}");
    assert_eq!(body["origin"], json!("example.org"));

    // A big enough limit reaches the room's creation.
    let uri = format!("/_matrix/federation/v1/backfill/{room}?v={head}&limit=100");
    let (_, body) = harness.federation_get(&peer, &uri).await;
    let pdus = body["pdus"].as_array().unwrap();
    assert_eq!(
        pdus.last().unwrap()["type"],
        json!("m.room.create"),
        "history bottoms out at creation: {body}"
    );
}

#[tokio::test]
async fn missing_events_fills_exactly_the_open_interval() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    let first = harness.say(&room, &alice, "one").await;
    harness.say(&room, &alice, "two").await;
    harness.say(&room, &alice, "three").await;
    let last = harness.say(&room, &alice, "four").await;

    let uri = format!("/_matrix/federation/v1/get_missing_events/{room}");
    let (status, body) = harness
        .federation_post(
            &peer,
            &uri,
            &json!({ "earliest_events": [first], "latest_events": [last], "limit": 10 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Both endpoints excluded: they have "one", they are holding "four".
    assert_eq!(bodies(&body["events"]), ["two", "three"], "{body}");
}

#[tokio::test]
async fn a_narrow_limit_prefers_the_events_nearest_what_the_peer_holds() {
    // The requester's purpose is connecting the event it is holding to
    // history; events adjacent to it serve that, events adjacent to what
    // it already has do not.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    let first = harness.say(&room, &alice, "one").await;
    harness.say(&room, &alice, "two").await;
    harness.say(&room, &alice, "three").await;
    let last = harness.say(&room, &alice, "four").await;

    let uri = format!("/_matrix/federation/v1/get_missing_events/{room}");
    let (_, body) = harness
        .federation_post(
            &peer,
            &uri,
            &json!({ "earliest_events": [first], "latest_events": [last], "limit": 1 }),
        )
        .await;
    assert_eq!(bodies(&body["events"]), ["three"], "{body}");
}

#[tokio::test]
async fn both_reads_refuse_a_server_with_no_member() {
    let member = Peer::start().await;
    let stranger = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &member).await;
    let head = harness.head_event(&room, &alice).await;

    let uri = format!("/_matrix/federation/v1/backfill/{room}?v={head}&limit=10");
    let (status, body) = harness.federation_get(&stranger, &uri).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let uri = format!("/_matrix/federation/v1/get_missing_events/{room}");
    let (status, body) = harness
        .federation_post(
            &stranger,
            &uri,
            &json!({ "earliest_events": [], "latest_events": [head], "limit": 10 }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn unknown_reference_points_are_handled_not_500s() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    let head = harness.head_event(&room, &alice).await;

    // Backfill from an event we do not hold: nothing to anchor on.
    let uri = format!("/_matrix/federation/v1/backfill/{room}?v=$nosuch&limit=10");
    let (status, body) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Missing-events where nothing they hold is known to us: an empty
    // answer, not an error — there is no gap in our log to describe.
    let uri = format!("/_matrix/federation/v1/get_missing_events/{room}");
    let (status, body) = harness
        .federation_post(
            &peer,
            &uri,
            &json!({ "earliest_events": [head], "latest_events": ["$nosuch"], "limit": 10 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["events"], json!([]));
}
