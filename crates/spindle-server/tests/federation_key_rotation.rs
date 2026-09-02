//! A peer that has rotated its signing key (#296).
//!
//! The spec has a peer move a retired key to `old_verify_keys` with the
//! `expired_ts` at which it stopped signing, so that everything it signed
//! before the rotation still verifies. What must hold: an event the peer
//! signed with the retired key *before* `expired_ts` lands; one it claims to
//! have signed with that key *after* `expired_ts` is refused, or a rotation
//! would change nothing; a retired key published without an expiry verifies
//! nothing; and a request signed with a retired key is refused, because a
//! request is made now.

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

/// A peer whose key `ed25519:0` is retired and `ed25519:1` is current.
struct RotatedPeer {
    name: String,
    retired: Ed25519KeyPair,
    current: Ed25519KeyPair,
}

impl RotatedPeer {
    /// `expired_ts` is what the key document says about the retired key;
    /// `None` publishes it under `old_verify_keys` with no expiry at all.
    async fn start(expired_ts: Option<u64>) -> RotatedPeer {
        let retired_der = Ed25519KeyPair::generate();
        let current_der = Ed25519KeyPair::generate();
        let retired = Ed25519KeyPair::from_der(&retired_der, "0".to_owned()).unwrap();
        let current = Ed25519KeyPair::from_der(&current_der, "1".to_owned()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        let mut old_entry = json!({ "key": unpadded(retired.public_key().as_ref()) });
        if let Some(expired_ts) = expired_ts {
            old_entry["expired_ts"] = json!(expired_ts);
        }
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 60_000,
            "verify_keys": { "ed25519:1": { "key": unpadded(current.public_key().as_ref()) } },
            "old_verify_keys": { "ed25519:0": old_entry },
        });
        let signer = Ed25519KeyPair::from_der(&current_der, "1".to_owned()).unwrap();
        sign_value(&name, &signer, &mut key_document);
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
        RotatedPeer {
            name,
            retired,
            current,
        }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    /// A V11 event signed with the *retired* key, as the peer's history is.
    fn event_signed_with_retired_key(&self, mut event: Value) -> Value {
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.retired, &mut canonical, &rules.redaction).unwrap();
        event = serde_json::to_value(&canonical).unwrap();
        event
    }

    fn transaction_header(&self, txn_id: &str, body: &Value, pair: &Ed25519KeyPair) -> String {
        let mut object = json!({
            "method": "PUT",
            "uri": format!("/_matrix/federation/v1/send/{txn_id}"),
            "origin": self.name,
            "destination": "example.org",
            "content": body,
        });
        sign_value(&self.name, pair, &mut object);
        let key_id = format!("ed25519:{}", pair.version());
        let signature = object["signatures"][&self.name][&key_id].as_str().unwrap();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"{key_id}\",sig=\"{signature}\"",
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
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n",
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

    async fn deliver(
        &self,
        peer: &RotatedPeer,
        txn_id: &str,
        pdus: Vec<Value>,
        request_key: &Ed25519KeyPair,
    ) -> (StatusCode, Value) {
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": pdus });
        let header = peer.transaction_header(txn_id, &body, request_key);
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
}

fn join_signed_before_rotation(peer: &RotatedPeer, room: &str, prev: &str, at: u64) -> Value {
    peer.event_signed_with_retired_key(json!({
        "type": "m.room.member",
        "state_key": peer.user(),
        "sender": peer.user(),
        "room_id": room,
        "content": { "membership": "join" },
        "origin_server_ts": at,
        "depth": 10,
        "prev_events": [prev],
        "auth_events": [],
    }))
}

fn only_result(body: &Value) -> Value {
    let results = body["pdus"].as_object().unwrap();
    assert_eq!(results.len(), 1, "{body}");
    results.values().next().unwrap().clone()
}

#[tokio::test]
async fn an_event_signed_with_the_retired_key_before_it_expired_lands() {
    let expired_ts = now_millis() - 60_000;
    let peer = RotatedPeer::start(Some(expired_ts)).await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_signed_before_rotation(&peer, &room, &head, expired_ts - 60_000);
    let (status, body) = harness
        .deliver(&peer, "t1", vec![join], &peer.current)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(only_result(&body), json!({}), "{body}");

    let (_, members) = harness
        .call(
            Request::builder()
                .uri(format!("/_matrix/client/v3/rooms/{room}/joined_members"))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(members["joined"].get(peer.user()).is_some(), "{members}");
}

#[tokio::test]
async fn an_event_claimed_after_the_key_expired_is_refused() {
    let expired_ts = now_millis() - 60_000;
    let peer = RotatedPeer::start(Some(expired_ts)).await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_signed_before_rotation(&peer, &room, &head, expired_ts + 30_000);
    let (status, body) = harness
        .deliver(&peer, "t1", vec![join], &peer.current)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result = only_result(&body);
    let error = result["error"].as_str().unwrap_or_default();
    assert!(error.contains("signature"), "{body}");
}

#[tokio::test]
async fn a_retired_key_published_without_an_expiry_verifies_nothing() {
    let peer = RotatedPeer::start(None).await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_signed_before_rotation(&peer, &room, &head, now_millis() - 120_000);
    let (status, body) = harness
        .deliver(&peer, "t1", vec![join], &peer.current)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let result = only_result(&body);
    let error = result["error"].as_str().unwrap_or_default();
    assert!(error.contains("signature"), "{body}");
}

#[tokio::test]
async fn a_request_signed_with_the_retired_key_is_refused() {
    let expired_ts = now_millis() - 60_000;
    let peer = RotatedPeer::start(Some(expired_ts)).await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_signed_before_rotation(&peer, &room, &head, expired_ts - 60_000);
    let (status, body) = harness
        .deliver(&peer, "t1", vec![join], &peer.retired)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}
