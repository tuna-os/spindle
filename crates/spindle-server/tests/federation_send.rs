//! Inbound federation transactions: receiving what another server signed.
//!
//! The peer here creates real V11 events — membership and messages —
//! signed with its own key, exactly as a homeserver would, and delivers
//! them through `PUT /send/{txnId}`. What must hold: a valid event lands
//! and is readable over the CS API like any local one; every invalid PDU
//! (bad signature, foreign sender, unauthorized, unknown room or parents)
//! soft-fails alone without poisoning its batch; and a retried
//! transaction answers what the first delivery answered, exactly once.

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

    /// A V11 event of this peer's making: hashed and signed like the real thing.
    fn event(&self, mut event: Value) -> Value {
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.pair, &mut canonical, &rules.redaction).unwrap();
        event = serde_json::to_value(&canonical).unwrap();
        event
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

    /// A room with the peer's user invited, and the head event's ID for
    /// `prev_events`.
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
        let head = self.head_event(&room, alice).await;
        (room, head)
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

    async fn deliver(&self, peer: &Peer, txn_id: &str, pdus: Vec<Value>) -> (StatusCode, Value) {
        self.deliver_with_edus(peer, txn_id, pdus, Vec::new()).await
    }

    async fn deliver_with_edus(
        &self,
        peer: &Peer,
        txn_id: &str,
        pdus: Vec<Value>,
        edus: Vec<Value>,
    ) -> (StatusCode, Value) {
        let mut body =
            json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": pdus });
        if !edus.is_empty() {
            body["edus"] = Value::Array(edus);
        }
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

fn message_event(peer: &Peer, room: &str, prev: &str, text: &str) -> Value {
    peer.event(json!({
        "type": "m.room.message",
        "sender": peer.user(),
        "room_id": room,
        "content": { "msgtype": "m.text", "body": text },
        "origin_server_ts": now_millis(),
        "depth": 11,
        "prev_events": [prev],
        "auth_events": [],
    }))
}

#[tokio::test]
async fn a_remote_join_and_message_land_and_read_back_over_the_cs_api() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_event(&peer, &room, &head);
    let (status, body) = harness.deliver(&peer, "t1", vec![join]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let join_result = body["pdus"].as_object().unwrap();
    assert_eq!(join_result.len(), 1);
    assert_eq!(join_result.values().next().unwrap(), &json!({}), "{body}");

    // The peer's user is now a member, visible over the CS API.
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

    // And a message from them reads back like any local event.
    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&peer, &room, &head, "hello from over there");
    let (status, body) = harness.deliver(&peer, "t2", vec![message]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["pdus"].as_object().unwrap().values().next().unwrap(),
        &json!({})
    );
    let (_, messages) = harness
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
    assert_eq!(
        messages["chunk"][0]["content"]["body"],
        json!("hello from over there")
    );
    assert_eq!(messages["chunk"][0]["sender"], json!(peer.user()));
}

#[tokio::test]
async fn bad_pdus_soft_fail_alone_and_good_neighbours_still_land() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    // An unauthorized event: a message from a user who never joined.
    let uninvited = message_event(&peer, &room, &head, "should not land");
    // A signature broken after signing.
    let mut tampered = join_event(&peer, &room, &head);
    tampered["content"]["membership"] = json!("join "); // changes the hash
    // A room this server does not have.
    let wrong_room = join_event(&peer, "!nowhere:example.org", &head);
    // A parent this server has never seen.
    let orphan = join_event(&peer, &room, "$unknown:elsewhere");
    // And one good event.
    let good = join_event(&peer, &room, &head);

    let (status, body) = harness
        .deliver(
            &peer,
            "t1",
            vec![uninvited, tampered, wrong_room, orphan, good],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let results = body["pdus"].as_object().unwrap();
    assert_eq!(results.len(), 5, "{body}");
    let failures = results
        .values()
        .filter(|outcome| outcome.get("error").is_some())
        .count();
    assert_eq!(failures, 4, "four bad, one good: {body}");

    // The good join landed despite its neighbours.
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
async fn a_sender_from_another_server_is_refused() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    // Signed by the peer, but claiming a sender on a different server:
    // accepting it would let any peer forge any server's events.
    let forged = peer.event(json!({
        "type": "m.room.message",
        "sender": "@mallory:elsewhere.org",
        "room_id": room,
        "content": { "msgtype": "m.text", "body": "forged" },
        "origin_server_ts": now_millis(),
        "depth": 11,
        "prev_events": [head],
        "auth_events": [],
    }));
    let (status, body) = harness.deliver(&peer, "t1", vec![forged]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let outcome = body["pdus"].as_object().unwrap().values().next().unwrap();
    assert!(
        outcome["error"].as_str().unwrap().contains("origin"),
        "{body}"
    );
}

#[tokio::test]
async fn a_retried_transaction_answers_once_and_applies_once() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    harness
        .deliver(&peer, "t1", vec![join_event(&peer, &room, &head)])
        .await;

    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&peer, &room, &head, "exactly once");
    let (_, first) = harness.deliver(&peer, "t2", vec![message.clone()]).await;
    let (_, second) = harness.deliver(&peer, "t2", vec![message]).await;
    assert_eq!(
        first, second,
        "a replay answers what the first delivery answered"
    );

    let (_, messages) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let copies = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["content"]["body"] == json!("exactly once"))
        .count();
    assert_eq!(copies, 1, "{messages}");
}

#[tokio::test]
async fn the_transaction_signature_binds_method_and_body() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&peer, &room, &head);
    let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": [join] });

    // Signed over a different body than the one sent: 401 before any PDU
    // is looked at. This is the HTTP-level kill for the method/content
    // binding the identity suite could only reach at the library level.
    let other = json!({ "origin": peer.name, "origin_server_ts": 0, "pdus": [] });
    let header = peer.transaction_header("t1", &other);
    let (status, refused) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri("/_matrix/federation/v1/send/t1")
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
}

#[tokio::test]
async fn a_replayed_transaction_answers_from_history_even_when_the_world_changed() {
    // The replay table's actual job. Event-level dedup already makes a
    // replayed success idempotent; what only the table can do is freeze an
    // *outcome*: a PDU that failed on first delivery keeps its recorded
    // failure on replay, even after the missing parent arrives and a fresh
    // attempt would succeed. At-least-once means the peer re-sends under a
    // NEW transaction when it wants a new verdict.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&peer, &room, &head);
    let ruma::CanonicalJsonValue::Object(canonical) =
        ruma::CanonicalJsonValue::try_from(join.clone()).unwrap()
    else {
        unreachable!()
    };
    let join_id = format!(
        "${}",
        ruma::signatures::reference_hash(&canonical, &RoomVersionId::V11.rules().unwrap()).unwrap()
    );

    // A message whose parent (the join) has not arrived yet: refused.
    let early = message_event(&peer, &room, &join_id, "too early");
    let (_, first) = harness.deliver(&peer, "t-early", vec![early.clone()]).await;
    let outcome = first["pdus"].as_object().unwrap().values().next().unwrap();
    assert!(outcome.get("error").is_some(), "{first}");

    // The parent lands under its own transaction.
    let (_, joined) = harness.deliver(&peer, "t-join", vec![join]).await;
    assert_eq!(
        joined["pdus"].as_object().unwrap().values().next().unwrap(),
        &json!({})
    );

    // Replaying the early transaction returns the recorded refusal — not a
    // fresh attempt that would now succeed.
    let (_, replayed) = harness.deliver(&peer, "t-early", vec![early]).await;
    assert_eq!(first, replayed, "the recorded outcome stands");
    let (_, messages) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !messages["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["content"]["body"] == json!("too early")),
        "{messages}"
    );
}

#[tokio::test]
async fn the_same_event_in_two_transactions_lands_once_and_upsets_nobody() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&peer, &room, &head);

    let (_, first) = harness.deliver(&peer, "t1", vec![join.clone()]).await;
    assert_eq!(
        first["pdus"].as_object().unwrap().values().next().unwrap(),
        &json!({})
    );
    // A different transaction carrying the same event: redelivery is not an
    // error — the event is already exactly where it would go.
    let (_, second) = harness.deliver(&peer, "t2", vec![join]).await;
    assert_eq!(
        second["pdus"].as_object().unwrap().values().next().unwrap(),
        &json!({}),
        "{second}"
    );
}

#[tokio::test]
async fn a_message_edited_after_signing_is_refused_by_the_hash_alone() {
    // Authorization has no opinion about a message's text — the only check
    // standing between an on-path edit and the room is the content hash
    // and signature. The event here is perfectly authorized (its sender
    // has joined); only its body was altered after signing.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    harness
        .deliver(&peer, "t-join", vec![join_event(&peer, &room, &head)])
        .await;

    let head = harness.head_event(&room, &alice).await;
    let mut edited = message_event(&peer, &room, &head, "what was signed");
    edited["content"]["body"] = json!("what an attacker wrote");
    let (status, body) = harness.deliver(&peer, "t-msg", vec![edited]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The spec's answer to a hash mismatch is redact, not drop: the event's
    // position is authentic (its ID is the reference hash over the redacted
    // form), only its content is not. Accepted…
    let outcome = body["pdus"].as_object().unwrap().values().next().unwrap();
    assert_eq!(outcome, &json!({}), "{body}");

    // …but neither the attacker's text nor the signed original is stored:
    // redaction strips the body entirely.
    let (_, messages) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let chunk = messages["chunk"].as_array().unwrap();
    assert!(
        !chunk.iter().any(|event| {
            event["content"]["body"] == json!("what an attacker wrote")
                || event["content"]["body"] == json!("what was signed")
        }),
        "{messages}"
    );
    // The event itself survives, contentless.
    assert!(
        chunk.iter().any(|event| {
            event["type"] == json!("m.room.message")
                && event["content"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
        }),
        "{messages}"
    );
}

/// One `m.typing` EDU, as a peer would send it.
fn typing_edu(room: &str, user: &str, typing: bool) -> Value {
    json!({
        "edu_type": "m.typing",
        "content": { "room_id": room, "user_id": user, "typing": typing },
    })
}

#[tokio::test]
async fn a_typing_edu_is_applied_for_the_origins_own_joined_user_only() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&peer, &room, &head);
    let (status, _) = harness.deliver(&peer, "t1", vec![join]).await;
    assert_eq!(status, StatusCode::OK);

    let typing_of = |body: &Value| -> Vec<String> {
        body["rooms"]["join"][&room]["ephemeral"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.typing")
            .flat_map(|event| {
                event["content"]["user_ids"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|user| user.as_str().map(str::to_owned))
            .collect()
    };

    // The peer says its own joined user is typing: applied.
    let (status, body) = harness
        .deliver_with_edus(
            &peer,
            "t2",
            Vec::new(),
            vec![typing_edu(&room, &peer.user(), true)],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sync) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        typing_of(&sync).contains(&peer.user()),
        "the peer's own typing lands: {sync}"
    );

    // The peer says *alice* is typing: an EDU is unsigned content inside a
    // signed envelope, and the envelope's origin does not own alice — so
    // no server can put words in another's hands.
    let (status, _) = harness
        .deliver_with_edus(
            &peer,
            "t3",
            Vec::new(),
            vec![typing_edu(&room, "@alice:example.org", true)],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the transaction itself is fine");
    let (_, sync) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/v3/sync")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !typing_of(&sync).contains(&"@alice:example.org".to_owned()),
        "the forged claim is ignored: {sync}"
    );
}
