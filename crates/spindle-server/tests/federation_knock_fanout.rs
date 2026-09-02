//! What a peer that joined over federation actually receives when someone knocks (#229).
//!
//! `TestKnocking`'s last red subtest — *"Users in the room see a user's
//! membership update when they knock"* — asserts something no other test in
//! that file does: that Complement's **synthetic** federation server, which
//! joined through `make_join`/`send_join` and then tracks state purely from
//! the transactions it is sent, ends up holding the knocker's `m.room.member`
//! event with `membership: knock`.
//!
//! Every other subtest passes, so whatever is wrong is specific to that path,
//! and the path has three places to fail:
//!
//! 1. the knock is never enqueued for that server,
//! 2. it is enqueued and delivered, but the PDU is shaped such that a
//!    receiver refuses it, or
//! 3. it is delivered and accepted, and something later loses it.
//!
//! This file pins (1) and (2) shut. The peer here is not a real Spindle: it
//! is a signing key, a `/send` recorder, and nothing else — deliberately, so
//! that "the peer accepted it" means only "the bytes arrived", the same claim
//! Complement's server makes. Two earlier reproductions of this used a real
//! second Spindle, and a real server is exactly the wrong instrument here: it
//! shares this one's idea of what a well-formed PDU is.
//!
//! What it therefore does **not** cover, and what #229 still needs, is the
//! knocker being on a *third* server — Complement's federated `#01` variant.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A signing key, a `/send` recorder, and nothing else.
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
        let record = Arc::clone(&received);
        let invite_name = name.clone();
        let invite_pair = Arc::new(Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap());
        let router = axum::Router::new()
            .route(
                "/_matrix/federation/v1/send/{_txn}",
                axum::routing::put(
                    move |axum::extract::Json(body): axum::extract::Json<Value>| {
                        let record = Arc::clone(&record);
                        async move {
                            for pdu in body["pdus"].as_array().cloned().unwrap_or_default() {
                                record.lock().unwrap().push(pdu);
                            }
                            axum::Json(json!({ "pdus": {} }))
                        }
                    },
                ),
            )
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { axum::Json(body) }
                }),
            )
            // The invitee's half of the `v2/invite` handshake: the room here
            // is invite-only before the join rule changes, so without this
            // the peer never becomes a member and there is nothing to test.
            .route(
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    move |axum::extract::Json(body): axum::extract::Json<Value>| {
                        let name = invite_name.clone();
                        let pair = Arc::clone(&invite_pair);
                        async move {
                            let ruma::CanonicalJsonValue::Object(mut canonical) =
                                ruma::CanonicalJsonValue::try_from(body["event"].clone()).unwrap()
                            else {
                                unreachable!()
                            };
                            let rules = RoomVersionId::V11.rules().unwrap();
                            hash_and_sign_event(
                                &name,
                                pair.as_ref(),
                                &mut canonical,
                                &rules.redaction,
                            )
                            .unwrap();
                            axum::Json(
                                json!({ "event": serde_json::to_value(&canonical).unwrap() }),
                            )
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
        format!("@david:{}", self.name)
    }

    fn received(&self) -> Vec<Value> {
        self.received.lock().unwrap().clone()
    }

    async fn wait_for<F: Fn(&[Value]) -> bool>(&self, what: F) -> bool {
        for _ in 0..100 {
            if what(&self.received()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn sign_event(&self, event: &Value) -> Value {
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.pair, &mut canonical, &rules.redaction).unwrap();
        serde_json::to_value(&canonical).unwrap()
    }

    fn header(&self, method: &str, uri: &str, body: Option<&Value>) -> String {
        let mut object = json!({
            "method": method,
            "uri": uri,
            "origin": self.name,
            "destination": "example.org",
        });
        if let Some(body) = body {
            object["content"] = body.clone();
        }
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

/// The reference hash the event's ID is derived from -- both sides must
/// compute the same one or the handshake's path parameter is a lie.
fn event_id_of(event: &Value) -> String {
    let ruma::CanonicalJsonValue::Object(canonical) =
        ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
    else {
        unreachable!()
    };
    format!(
        "${}",
        ruma::signatures::reference_hash(&canonical, &RoomVersionId::V11.rules().unwrap()).unwrap()
    )
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
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
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

    /// Complement's arrangement: an invite-only room, the peer invited and
    /// then joined through the real handshake, and only afterwards the join
    /// rule changed to `knock`. The order matters — a peer that joined while
    /// the room was invite-only is the one whose membership the knock has to
    /// find.
    async fn room_with_joined_peer(&self, alice: &str, peer: &Peer) -> String {
        let (_, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "preset": "private_chat" }),
            )
            .await;
        let room = body["room_id"].as_str().expect("a room id").to_owned();

        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                alice,
                &json!({ "user_id": peer.user() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "invite: {body}");

        let uri = format!(
            "/_matrix/federation/v1/make_join/{room}/{}?ver=11",
            peer.user()
        );
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(&uri)
                    .header("authorization", peer.header("GET", &uri, None))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "make_join: {body}");
        let join = peer.sign_event(&body["event"]);
        let join_id = event_id_of(&join);
        let uri = format!("/_matrix/federation/v2/send_join/{room}/{join_id}");
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(&uri)
                    .header("authorization", peer.header("PUT", &uri, Some(&join)))
                    .header("content-type", "application/json")
                    .body(Body::from(join.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "send_join: {body}");

        // The guard that keeps every test in this file from being vacuous.
        // The peer was *invited* before it joined, and `destinations_in`
        // treats an invited server as live too -- so if `send_join` quietly
        // failed to record the membership, the peer would still receive the
        // fan-out and every assertion below would pass while testing the
        // invited path instead of the joined one. That is the same shape as
        // the vacuous pass `federation_fork.rs` was written to catch.
        let (status, body) = self
            .send(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
                alice,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "joined_members: {body}");
        assert!(
            body["joined"].get(peer.user()).is_some(),
            "the peer is not joined after send_join, so these tests would \
             only be exercising the invited path: {body}"
        );

        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                alice,
                &json!({ "join_rule": "knock" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "join_rules: {body}");
        room
    }

    async fn knock(&self, room: &str, token: &str, reason: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/knock/{room}"),
                token,
                &json!({ "reason": reason }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "knock {reason}: {body}");
    }
}

/// A short label per received PDU, for a failure message that says what did
/// arrive rather than only what did not.
fn manifest(pdus: &[Value]) -> Vec<String> {
    pdus.iter()
        .map(|pdu| {
            format!(
                "{}/{}",
                pdu["type"].as_str().unwrap_or("?"),
                pdu["content"]["membership"].as_str().unwrap_or("-")
            )
        })
        .collect()
}

fn knocks(pdus: &[Value]) -> Vec<Value> {
    pdus.iter()
        .filter(|pdu| pdu["type"] == "m.room.member" && pdu["content"]["membership"] == "knock")
        .cloned()
        .collect()
}

/// A peer that joined over federation is sent the knock, with its reason.
///
/// The join-rules change is asserted first and deliberately: it is a local
/// state event sent after the peer joined, so it separates "this peer is not
/// in the fan-out set at all" from "the knock specifically was not sent".
/// Without that split a failure here says only that something is wrong.
#[tokio::test]
async fn a_peer_that_joined_over_federation_is_sent_the_knock() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_joined_peer(&alice, &peer).await;

    assert!(
        peer.wait_for(|pdus| pdus.iter().any(|pdu| pdu["type"] == "m.room.join_rules"))
            .await,
        "the peer is not in the fan-out set at all; saw {:?}",
        manifest(&peer.received())
    );

    let bob = harness.register("bob").await;
    harness
        .knock(&room, &bob, "Let me in... LET ME IN!!!")
        .await;

    assert!(
        peer.wait_for(|pdus| !knocks(pdus).is_empty()).await,
        "the knock was not sent to a joined peer; saw {:?}",
        manifest(&peer.received())
    );
    let knock = knocks(&peer.received()).remove(0);
    assert_eq!(knock["content"]["reason"], "Let me in... LET ME IN!!!");
    assert_eq!(knock["state_key"], "@bob:example.org");
}

/// The knock arrives as a PDU a receiver can actually take.
///
/// The failure this rules out is the quiet one: a transaction that returns
/// 200 while the peer discards the event, because Complement's transaction
/// handler parses each PDU and *silently skips* one it cannot — no error, no
/// entry in the response, just a member event that never reaches its
/// `ServerRoom`. A knock that is sent but unparseable looks exactly like a
/// knock that was never sent.
#[tokio::test]
async fn the_knock_pdu_carries_what_a_receiver_needs() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_joined_peer(&alice, &peer).await;
    let bob = harness.register("bob").await;
    harness
        .knock(&room, &bob, "Let me in... LET ME IN!!!")
        .await;
    assert!(peer.wait_for(|pdus| !knocks(pdus).is_empty()).await);

    let knock = knocks(&peer.received()).remove(0);
    for field in [
        "room_id",
        "sender",
        "type",
        "state_key",
        "content",
        "prev_events",
        "auth_events",
        "depth",
        "origin_server_ts",
        "hashes",
        "signatures",
    ] {
        assert!(
            knock.get(field).is_some(),
            "the knock PDU has no {field}: {knock}"
        );
    }
    assert!(
        knock["hashes"]["sha256"].is_string(),
        "no content hash: {knock}"
    );
    assert!(
        knock["signatures"]["example.org"]["ed25519:0"].is_string(),
        "not signed by the sending server: {knock}"
    );
    // Room versions from 3 on derive the ID from the event; carrying one is
    // how a v1 event is recognised, and a receiver on a later version
    // refuses it.
    assert!(
        knock.get("event_id").is_none(),
        "a room-version-1 event_id was included: {knock}"
    );
}

/// Both of two successive knocks arrive, in order.
///
/// Complement knocks twice with different reasons and then asserts the
/// *first* one's reason. A server that collapsed the pair into one delivery,
/// or delivered only the newer, would satisfy every "a knock was sent" check
/// and still fail that assertion.
#[tokio::test]
async fn a_second_knock_does_not_replace_the_first_in_the_fan_out() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room_with_joined_peer(&alice, &peer).await;
    let bob = harness.register("bob").await;

    harness
        .knock(&room, &bob, "Let me in... LET ME IN!!!")
        .await;
    harness
        .knock(&room, &bob, "I really like knock knock jokes")
        .await;

    assert!(
        peer.wait_for(|pdus| knocks(pdus).len() >= 2).await,
        "only {} knock(s) reached the peer; saw {:?}",
        knocks(&peer.received()).len(),
        manifest(&peer.received())
    );
    let reasons: Vec<String> = knocks(&peer.received())
        .iter()
        .map(|pdu| pdu["content"]["reason"].as_str().unwrap_or("-").to_owned())
        .collect();
    assert_eq!(
        reasons,
        vec![
            "Let me in... LET ME IN!!!".to_owned(),
            "I really like knock knock jokes".to_owned(),
        ]
    );
}
