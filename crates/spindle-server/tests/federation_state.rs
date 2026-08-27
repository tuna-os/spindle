//! Serving room state and events to federation peers.
//!
//! `/state` at an arbitrary historical event is the read SPEC §18.1 is
//! about: the entry carries the state's content address, so answering is
//! one rehydration — no resolution, no walk. What this suite pins beyond
//! the happy path: the answer is the state *before* the named event
//! (observable via two topic changes), the auth chain accompanies it, and
//! every read is gated on the asking server having a joined member —
//! an authenticated stranger is still a stranger.

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
        let router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { axum::Json(body) }
                }),
            )
            // The invite handshake's other half: the harness invites this
            // peer's user, and the inviting server will not append the
            // invite until the peer answers. Echoing the event back is a
            // valid answer — the reference hash is what the inviter
            // checks, and signatures sit outside it.
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

    /// Alice's room with the peer's user joined via a real federation
    /// transaction, so the peer's server is *in* the room.
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
        assert_eq!(
            response["pdus"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap(),
            &json!({}),
            "{response}"
        );
        room
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
}

#[tokio::test]
async fn state_at_an_event_is_the_state_before_it_with_its_auth_chain() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;

    // Two topic changes: asking at the second must show the first.
    harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "the old topic" }),
        )
        .await;
    let (_, second) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "the new topic" }),
        )
        .await;
    let second_id = second["event_id"].as_str().unwrap();

    let uri = format!("/_matrix/federation/v1/state/{room}?event_id={second_id}");
    let (status, body) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let topics: Vec<&str> = body["pdus"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "m.room.topic")
        .filter_map(|event| event["content"]["topic"].as_str())
        .collect();
    assert_eq!(topics, ["the old topic"], "{body}");
    assert!(
        !body["auth_chain"].as_array().unwrap().is_empty(),
        "the auth chain accompanies the state: {body}"
    );

    // The IDs form agrees with the bodies form.
    let uri = format!("/_matrix/federation/v1/state_ids/{room}?event_id={second_id}");
    let (status, ids) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::OK, "{ids}");
    assert_eq!(
        ids["pdu_ids"].as_array().unwrap().len(),
        body["pdus"].as_array().unwrap().len()
    );
    assert_eq!(
        ids["auth_chain_ids"].as_array().unwrap().len(),
        body["auth_chain"].as_array().unwrap().len()
    );
}

#[tokio::test]
async fn a_stranger_server_gets_403_from_every_room_read() {
    let member = Peer::start().await;
    let stranger = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &member).await;
    let head = harness.head_event(&room, &alice).await;

    for uri in [
        format!("/_matrix/federation/v1/state/{room}?event_id={head}"),
        format!("/_matrix/federation/v1/state_ids/{room}?event_id={head}"),
        format!("/_matrix/federation/v1/event/{head}"),
    ] {
        let (status, body) = harness.federation_get(&stranger, &uri).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
}

#[tokio::test]
async fn an_event_fetch_returns_the_body_and_unknown_ids_are_404() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;
    let (_, sent) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "fetch me" }),
        )
        .await;
    let event_id = sent["event_id"].as_str().unwrap();

    let uri = format!("/_matrix/federation/v1/event/{event_id}");
    let (status, body) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pdus"][0]["content"]["body"], json!("fetch me"));
    assert_eq!(body["origin"], json!("example.org"));

    let (status, body) = harness
        .federation_get(&peer, "/_matrix/federation/v1/event/$nosuch")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn an_invited_but_never_joined_server_is_still_a_stranger() {
    // Membership "invite" is not "in": until someone actually joins, the
    // room's state and history are not that server's to read.
    let invited = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .send("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();
    harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": invited.user() }),
        )
        .await;
    let head = harness.head_event(&room, &alice).await;

    let uri = format!("/_matrix/federation/v1/state/{room}?event_id={head}");
    let (status, body) = harness.federation_get(&invited, &uri).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn the_auth_chain_reaches_superseded_ancestors_the_state_no_longer_cites() {
    // Three consecutive profile changes build a member-event chain
    // M1 -> M2 -> M3 -> M4 where M2 is cited only by M3: the state holds
    // M4, every other state event predates M2, so M2 is reachable only by
    // walking the chain transitively. A chain that stops at direct
    // references hands the joining server an auth set it cannot validate.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.shared_room(&alice, &peer).await;

    let mut change_ids = Vec::new();
    for name in ["one", "two", "three"] {
        let (status, body) = harness
            .send(
                "PUT",
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.member/%40alice%3Aexample.org"
                ),
                &alice,
                &json!({ "membership": "join", "displayname": name }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        change_ids.push(body["event_id"].as_str().unwrap().to_owned());
    }
    let (_, sent) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t9"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "anchor" }),
        )
        .await;
    let anchor = sent["event_id"].as_str().unwrap();

    let uri = format!("/_matrix/federation/v1/state_ids/{room}?event_id={anchor}");
    let (status, ids) = harness.federation_get(&peer, &uri).await;
    assert_eq!(status, StatusCode::OK, "{ids}");
    let chain: Vec<&str> = ids["auth_chain_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        chain.contains(&change_ids[0].as_str()),
        "the depth-2 ancestor {} is in the chain: {chain:?}",
        change_ids[0]
    );
}
