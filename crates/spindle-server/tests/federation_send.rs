//! Inbound federation transactions: receiving what another server signed.
//!
//! The peer here creates real V11 events — membership and messages —
//! signed with its own key, exactly as a homeserver would, and delivers
//! them through `PUT /send/{txnId}`. What must hold: a valid event lands
//! and is readable over the CS API like any local one; every invalid PDU
//! (bad signature, unauthorized, unknown room or parents)
//! soft-fails alone; an event the origin relays for another server
//! verifies by the signature of that server. Each bad PDU
//! fails without poisoning its batch; and a retried
//! transaction answers what the first delivery answered, exactly once.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::inbound::INGEST_SLOTS;
use spindle_server::metrics::{BlockingTask, Metrics, PduOutcome};
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
    state: spindle_server::AppState,
    store: Arc<FjallStore>,
    metrics: Arc<Metrics>,
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
        let metrics = Arc::new(Metrics::new());
        let (app, state) =
            spindle_server::app_with_state(config, store.clone(), Arc::clone(&metrics))
                .expect("the app builds");
        Self {
            _dir: dir,
            app,
            state,
            store,
            metrics,
        }
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

fn join_event(store: &Arc<FjallStore>, peer: &Peer, room: &str, prev: &str) -> Value {
    peer.event(federation_auth::with_auth_events(
        store,
        json!({
            "type": "m.room.member",
            "state_key": peer.user(),
            "sender": peer.user(),
            "room_id": room,
            "content": { "membership": "join" },
            "origin_server_ts": now_millis(),
            "depth": 10,
            "prev_events": [prev],
            "auth_events": [],
        }),
    ))
}

fn message_event(
    store: &Arc<FjallStore>,
    peer: &Peer,
    room: &str,
    prev: &str,
    text: &str,
) -> Value {
    peer.event(federation_auth::with_auth_events(
        store,
        json!({
            "type": "m.room.message",
            "sender": peer.user(),
            "room_id": room,
            "content": { "msgtype": "m.text", "body": text },
            "origin_server_ts": now_millis(),
            "depth": 11,
            "prev_events": [prev],
            "auth_events": [],
        }),
    ))
}

#[tokio::test]
async fn known_invalid_auth_before_a_missing_entry_preserves_valid_descendants() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&harness.store, &peer, &room, &head);
    let (_, joined) = harness.deliver(&peer, "auth-order-join", vec![join]).await;
    assert!(
        joined["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v == &json!({}))
    );
    let head = harness.head_event(&room, &alice).await;
    let rooms = spindle_server::rooms::Rooms::new(harness.store.clone(), "example.org");
    let join_rules = rooms
        .state(&room)
        .unwrap()
        .into_iter()
        .find(|event| event["type"] == "m.room.join_rules")
        .unwrap();
    let mut invalid = message_event(&harness.store, &peer, &room, &head, "invalid auth list");
    let auth = invalid["auth_events"].as_array_mut().unwrap();
    auth.insert(0, join_rules["event_id"].clone());
    auth.push(json!("$missing-auth-event"));
    let invalid = peer.event(invalid);
    let canonical = serde_json::from_value(invalid.clone()).unwrap();
    let invalid_id = format!(
        "${}",
        ruma::signatures::reference_hash(&canonical, &RoomVersionId::V11.rules().unwrap(),)
            .unwrap()
    );
    let (_, rejected) = harness
        .deliver(&peer, "auth-order-invalid", vec![invalid])
        .await;
    assert!(
        rejected["pdus"][&invalid_id]["error"]
            .as_str()
            .unwrap()
            .contains("unexpected auth event"),
        "{rejected}"
    );
    let sentinel = message_event(
        &harness.store,
        &peer,
        &room,
        &invalid_id,
        "valid descendant",
    );
    let (_, accepted) = harness
        .deliver(&peer, "auth-order-sentinel", vec![sentinel])
        .await;
    assert!(
        accepted["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v == &json!({})),
        "{accepted}"
    );
    let (_, event) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/event/{invalid_id}"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(event["errcode"], "M_NOT_FOUND");
    let last = harness.head_event(&room, &alice).await;
    assert_ne!(last, invalid_id);
}

#[tokio::test]
async fn a_remote_join_and_message_land_and_read_back_over_the_cs_api() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    let join = join_event(&harness.store, &peer, &room, &head);
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
    let message = message_event(&harness.store, &peer, &room, &head, "hello from over there");
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

/// `m.room.server_acl`, both halves: once the room denies the peer, its
/// PDUs are refused before verification, its room reads are forbidden,
/// and nothing after the ACL is queued to it on the outbox. The ACL event
/// itself is: it is how the peer learns it was denied (Complement's
/// `TestACLs` waits for it on the denied server).
#[tokio::test]
async fn a_server_acl_closes_both_directions() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&harness.store, &peer, &room, &head);
    let (status, body) = harness.deliver(&peer, "acl-join", vec![join]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["pdus"].as_object().unwrap().values().next().unwrap(),
        &json!({})
    );

    let outbox_rows = |destination: &str| -> usize {
        spindle_store::ReadView::scan_prefix(
            harness.store.as_ref(),
            &spindle_core::keys::federation_outbox_all(),
        )
        .unwrap()
        .into_iter()
        .filter(|(key, _)| {
            spindle_core::keys::federation_outbox_destination(key).as_deref() == Some(destination)
        })
        .count()
    };
    let before_acl = outbox_rows(&peer.name);
    assert!(before_acl > 0, "the join's fan-out should have queued rows");

    // Alice denies the peer. The ACL event itself is the last thing the
    // peer is told.
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.server_acl"),
            &alice,
            // The peer's name is `127.0.0.1:port`; the ACL matches hosts
            // with the port stripped, so the deny names the host.
            &json!({ "allow": ["*"], "deny": ["127.0.0.1"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after_acl = outbox_rows(&peer.name);
    assert_eq!(
        after_acl,
        before_acl + 1,
        "the ACL event must reach the server it denies"
    );

    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/after-acl"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "not for you" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        outbox_rows(&peer.name),
        after_acl,
        "nothing after the ACL goes to the denied server"
    );

    // Inbound: the peer's message is refused, naming the ACL, and lands
    // nowhere.
    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&harness.store, &peer, &room, &head, "let me in");
    let (status, body) = harness.deliver(&peer, "acl-denied", vec![message]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, result) = body["pdus"].as_object().unwrap().iter().next().unwrap();
    assert!(
        result["error"].as_str().unwrap().contains("server ACL"),
        "{body}"
    );
    assert_eq!(
        harness.head_event(&room, &alice).await,
        head,
        "the denied message must not land"
    );

    // Room reads are forbidden too.
    let uri = format!("/_matrix/federation/v1/state_ids/{room}?event_id={head}");
    let mut object = json!({
        "method": "GET",
        "uri": uri,
        "origin": peer.name,
        "destination": "example.org",
    });
    sign_value(&peer.name, &peer.pair, &mut object);
    let signature = object["signatures"][&peer.name]["ed25519:0"]
        .as_str()
        .unwrap();
    let header = format!(
        "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{signature}\"",
        peer.name
    );
    let (status, body) = harness
        .call(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header("authorization", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("server ACL"),
        "{body}"
    );
}

#[tokio::test]
async fn bad_pdus_soft_fail_alone_and_good_neighbours_still_land() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;

    // An unauthorized event: a message from a user who never joined.
    let uninvited = message_event(&harness.store, &peer, &room, &head, "should not land");
    // A signature broken after signing.
    let mut tampered = join_event(&harness.store, &peer, &room, &head);
    tampered["content"]["membership"] = json!("join "); // changes the hash
    // A room this server does not have.
    let wrong_room = join_event(&harness.store, &peer, "!nowhere:example.org", &head);
    // A parent this server has never seen.
    let orphan = join_event(&harness.store, &peer, &room, "$unknown:elsewhere");
    // And one good event.
    let good = join_event(&harness.store, &peer, &room, &head);

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

/// The result for the one PDU of a transaction.
fn only_result(body: &Value) -> &Value {
    let results = body["pdus"].as_object().unwrap();
    assert_eq!(results.len(), 1, "{body}");
    results.values().next().unwrap()
}

/// A room where both peers' users have joined, each through its own server.
async fn room_with_two_peers(
    harness: &Harness,
    alice: &str,
    origin: &Peer,
    other: &Peer,
) -> String {
    let (room, _) = harness.room_with_invite(alice, &origin.user()).await;
    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            alice,
            &json!({ "user_id": other.user() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = harness.head_event(&room, alice).await;
    let join = join_event(&harness.store, origin, &room, &head);
    let (_, body) = harness.deliver(origin, "join-origin", vec![join]).await;
    assert_eq!(only_result(&body), &json!({}), "{body}");
    let head = harness.head_event(&room, alice).await;
    let join = join_event(&harness.store, other, &room, &head);
    let (_, body) = harness.deliver(other, "join-other", vec![join]).await;
    assert_eq!(only_result(&body), &json!({}), "{body}");
    room
}

#[tokio::test]
async fn a_relayed_pdu_signed_by_its_senders_server_is_accepted() {
    // #631: servers relay the events of other servers, for example after
    // catch-up. The signature of the sender's server identifies the event,
    // whichever server delivers it.
    let origin = Peer::start().await;
    let other = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = room_with_two_peers(&harness, &alice, &origin, &other).await;

    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&harness.store, &other, &room, &head, "relayed");
    let (status, body) = harness.deliver(&origin, "relay", vec![message]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(only_result(&body), &json!({}), "{body}");

    let (_, messages) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(messages["chunk"][0]["content"]["body"], json!("relayed"));
    assert_eq!(messages["chunk"][0]["sender"], json!(other.user()));
    assert_eq!(
        harness
            .metrics
            .relayed_pdu_count(PduOutcome::Accepted, true),
        1
    );
    assert_eq!(
        harness
            .metrics
            .relayed_pdu_count(PduOutcome::Accepted, false),
        2
    );
}

#[tokio::test]
async fn a_relayed_pdu_without_its_senders_signature_is_refused() {
    let origin = Peer::start().await;
    let other = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = room_with_two_peers(&harness, &alice, &origin, &other).await;
    let head = harness.head_event(&room, &alice).await;

    // Signed by the origin only: the sender's server never signed it.
    // Without this rule, any peer could forge the events of any server.
    let mut unsigned = message_event(&harness.store, &origin, &room, &head, "forged");
    unsigned["sender"] = json!(other.user());
    let unsigned = origin.event(unsigned);
    // Signed in the name of the sender's server, with a key it does not
    // publish.
    let impostor = Peer {
        name: other.name.clone(),
        pair: Ed25519KeyPair::from_der(&Ed25519KeyPair::generate(), "0".to_owned()).unwrap(),
    };
    let bad = message_event(&harness.store, &impostor, &room, &head, "bad signature");

    for (txn, pdu, reason) in [
        ("missing", unsigned, "missing_signature"),
        ("bad", bad, "bad_signature"),
    ] {
        let (status, body) = harness.deliver(&origin, txn, vec![pdu]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let error = only_result(&body)["error"].as_str().unwrap_or_default();
        assert!(error.contains(reason), "{body}");
    }
    let (_, messages) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
            &alice,
            &json!({}),
        )
        .await;
    assert!(
        messages["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["type"] != json!("m.room.message")),
        "{messages}"
    );
    assert_eq!(
        harness.metrics.relayed_pdu_count(PduOutcome::Refused, true),
        2
    );
}

#[tokio::test]
async fn a_relayed_pdu_for_a_room_its_origin_is_not_in_is_judged_by_signature_and_auth() {
    let origin = Peer::start().await;
    let other = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    // Only the other server's user joins; the origin has no one here.
    let (room, head) = harness.room_with_invite(&alice, &other.user()).await;
    let join = join_event(&harness.store, &other, &room, &head);
    let (_, body) = harness.deliver(&other, "join", vec![join]).await;
    assert_eq!(only_result(&body), &json!({}), "{body}");

    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&harness.store, &other, &room, &head, "via a stranger");
    let (_, body) = harness.deliver(&origin, "relay", vec![message]).await;
    assert_eq!(only_result(&body), &json!({}), "{body}");

    // Correctly signed, but its sender is not a member: the room's
    // authorization rules refuse it, as for any other event.
    let head = harness.head_event(&room, &alice).await;
    let mut stranger = message_event(&harness.store, &other, &room, &head, "not a member");
    stranger["sender"] = json!(format!("@carol:{}", other.name));
    let stranger = other.event(stranger);
    let (_, body) = harness.deliver(&origin, "stranger", vec![stranger]).await;
    let error = only_result(&body)["error"].as_str().unwrap_or_default();
    assert!(!error.is_empty(), "{body}");
    assert!(!error.contains("signature"), "{body}");

    let (_, messages) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=10"),
            &alice,
            &json!({}),
        )
        .await;
    let bodies: Vec<&Value> = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == json!("m.room.message"))
        .map(|event| &event["content"]["body"])
        .collect();
    assert_eq!(bodies, [&json!("via a stranger")], "{messages}");
    assert_eq!(
        harness
            .metrics
            .relayed_pdu_count(PduOutcome::Accepted, true),
        1
    );
}

#[tokio::test]
async fn a_retried_transaction_answers_once_and_applies_once() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    harness
        .deliver(
            &peer,
            "t1",
            vec![join_event(&harness.store, &peer, &room, &head)],
        )
        .await;

    let head = harness.head_event(&room, &alice).await;
    let message = message_event(&harness.store, &peer, &room, &head, "exactly once");
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
    let join = join_event(&harness.store, &peer, &room, &head);
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
    let join = join_event(&harness.store, &peer, &room, &head);
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
    let mut early = message_event(&harness.store, &peer, &room, &join_id, "too early");
    // Bind to the pending join's state so a fresh retry can succeed once it lands.
    let rooms = spindle_server::rooms::Rooms::new(harness.store.clone(), "example.org");
    let mut auth: Vec<_> = join["auth_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|id| {
            matches!(
                rooms.pdu(&room, id.as_str().unwrap()).unwrap()["type"].as_str(),
                Some("m.room.create" | "m.room.power_levels")
            )
        })
        .cloned()
        .collect();
    auth.push(json!(join_id));
    early["auth_events"] = json!(auth);
    early = peer.event(early);
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
    let (_, replayed) = harness.deliver(&peer, "t-early", vec![early.clone()]).await;
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
    // A new transaction retries against the history that is now available.
    let (_, retried) = harness.deliver(&peer, "t-after-join", vec![early]).await;
    assert_eq!(
        retried["pdus"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap(),
        &json!({}),
        "a missing parent must not permanently reject an otherwise valid event: {retried}"
    );
}

#[tokio::test]
async fn the_same_event_in_two_transactions_lands_once_and_upsets_nobody() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&harness.store, &peer, &room, &head);

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
        .deliver(
            &peer,
            "t-join",
            vec![join_event(&harness.store, &peer, &room, &head)],
        )
        .await;

    let head = harness.head_event(&room, &alice).await;
    let mut edited = message_event(&harness.store, &peer, &room, &head, "what was signed");
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
    let join = join_event(&harness.store, &peer, &room, &head);
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

/// MSC4163: a server the room's ACL denies has its typing and read
/// receipts dropped like its PDUs. Before the ACL both land; after it,
/// neither a stop-typing nor a newer receipt changes what alice sees.
#[tokio::test]
async fn a_server_acl_drops_the_denied_servers_typing_and_receipts() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
    let join = join_event(&harness.store, &peer, &room, &head);
    let (status, _) = harness.deliver(&peer, "edu-join", vec![join]).await;
    assert_eq!(status, StatusCode::OK);
    let joined_head = harness.head_event(&room, &alice).await;

    let receipt_edu = |event_id: &str| {
        json!({
            "edu_type": "m.receipt",
            "content": {
                &room: { "m.read": { peer.user(): {
                    "event_ids": [event_id],
                    "data": { "ts": now_millis() },
                } } }
            },
        })
    };
    let sync = || async {
        let (status, body) = harness
            .call(
                Request::builder()
                    .uri("/_matrix/client/v3/sync")
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    };
    let ephemeral = |body: &Value, kind: &str| -> Value {
        body["rooms"]["join"][&room]["ephemeral"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|event| event["type"] == kind)
            .map_or(Value::Null, |event| event["content"].clone())
    };

    let (status, body) = harness
        .deliver_with_edus(
            &peer,
            "edu-before",
            Vec::new(),
            vec![
                typing_edu(&room, &peer.user(), true),
                receipt_edu(&joined_head),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = sync().await;
    assert_eq!(
        ephemeral(&before, "m.typing")["user_ids"],
        json!([peer.user()]),
        "{before}"
    );
    assert!(
        ephemeral(&before, "m.receipt")[&joined_head]["m.read"][peer.user()].is_object(),
        "{before}"
    );

    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.server_acl"),
            &alice,
            &json!({ "allow": ["*"], "deny": ["127.0.0.1"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let acl_event = body["event_id"].as_str().unwrap().to_owned();

    let (status, body) = harness
        .deliver_with_edus(
            &peer,
            "edu-after",
            Vec::new(),
            vec![
                typing_edu(&room, &peer.user(), false),
                receipt_edu(&acl_event),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = sync().await;
    assert_eq!(
        ephemeral(&after, "m.typing")["user_ids"],
        json!([peer.user()]),
        "the denied server's stop-typing is dropped: {after}"
    );
    assert!(
        ephemeral(&after, "m.receipt")[&acl_event].is_null(),
        "the denied server's receipt is dropped: {after}"
    );
}

/// #614: a server back from an outage meets every peer's backlog at once,
/// most of it for the same busy room. Here that room is held -- standing in
/// for an ingest working through it -- while three times as many
/// transactions as there are ingest slots arrive for it, on a runtime whose
/// blocking pool has a few threads beyond the slots. Then as many room
/// reads as there are workers arrive and wait on the same room, each
/// handing its worker on (`blocking::section`), which takes a pool thread.
///
/// Liveness and readiness must still answer, with the room still held. The
/// backlog beyond the slots waits as tasks, so the pool keeps threads for
/// the readers' hand-offs. Admitted all at once, the backlog took every
/// pool thread; each reader then held its worker while it waited for a
/// thread that never came, and with both workers stopped `/health` was
/// not polled again until the room was let go.
///
/// Waits here are on the test's own thread: once the workers stop, an
/// async timer in this future would never fire.
#[test]
fn probes_answer_while_a_federation_backlog_waits_on_one_room() {
    const WORKERS: usize = 2;
    const SPARE_THREADS: usize = 8;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .max_blocking_threads(INGEST_SLOTS + SPARE_THREADS)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let peer = Arc::new(Peer::start().await);
        let harness = Arc::new(Harness::new());
        let alice = harness.register("alice").await;
        let (room, head) = harness.room_with_invite(&alice, &peer.user()).await;
        let join = join_event(&harness.store, &peer, &room, &head);
        let (status, body) = harness.deliver(&peer, "join", vec![join]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let head = harness.head_event(&room, &alice).await;

        let backlog = 3 * INGEST_SLOTS;
        let messages: Vec<Value> = (0..backlog)
            .map(|n| message_event(&harness.store, &peer, &room, &head, &format!("backlog {n}")))
            .collect();

        let (release, holder) = hold_on_a_thread(harness.state.rooms.lock_for_test(&room).unwrap());

        let deliveries: Vec<_> = messages
            .into_iter()
            .enumerate()
            .map(|(n, message)| {
                let harness = Arc::clone(&harness);
                let peer = Arc::clone(&peer);
                tokio::spawn(async move {
                    harness
                        .deliver(&peer, &format!("backlog-{n}"), vec![message])
                        .await
                })
            })
            .collect();
        let in_flight = |task| harness.metrics.blocking_in_flight(task);
        wait_on_this_thread("the backlog reaches the held room", || {
            in_flight(BlockingTask::FederationSend) >= INGEST_SLOTS as u64
        });

        let readers: Vec<_> = (0..2 * WORKERS)
            .map(|_| {
                let harness = Arc::clone(&harness);
                let request = Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                    ))
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap();
                tokio::spawn(async move { harness.call(request).await.0 })
            })
            .collect();
        wait_on_this_thread("the readers wait on the held room", || {
            in_flight(BlockingTask::LockWait) >= WORKERS as u64
        });

        let answered = probes_from_a_task(harness.app.clone());
        for _ in 0..2 {
            let (path, status) = answered
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the probes answer while the backlog waits on the room");
            assert_eq!(status, StatusCode::OK, "{path}");
        }
        assert_eq!(
            in_flight(BlockingTask::FederationSend),
            INGEST_SLOTS as u64,
            "the rest of the backlog waits for a turn, holding no thread"
        );

        release.send(()).unwrap();
        holder.join().unwrap();
        for delivery in deliveries {
            let (status, body) = delivery.await.unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(only_result(&body), &json!({}), "{body}");
        }
        for reader in readers {
            assert_eq!(reader.await.unwrap(), StatusCode::OK);
        }
    });
}

/// Hold `lock` exclusively on a thread of its own until told to let go, or
/// until the sender is dropped -- by a failed assertion, say -- so that the
/// runtime can shut down.
fn hold_on_a_thread<T: Send + Sync + 'static>(
    lock: Arc<std::sync::RwLock<T>>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _guard = lock.write().unwrap();
        held_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    held_rx.recv().unwrap();
    (release_tx, holder)
}

/// Poll `done` on the calling thread, never on a runtime timer.
fn wait_on_this_thread(what: &str, done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "{what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Ask `/health`, then `/ready`, from a spawned task -- which needs a
/// worker to run, as a kubelet's probe does -- and hand back each answer.
fn probes_from_a_task(app: axum::Router) -> std::sync::mpsc::Receiver<(&'static str, StatusCode)> {
    let (answered_tx, answered) = std::sync::mpsc::channel();
    tokio::spawn(async move {
        for path in ["/health", "/ready"] {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            // A test that gave up waiting has dropped the receiver.
            let _ = answered_tx.send((path, response.status()));
        }
    });
    answered
}
