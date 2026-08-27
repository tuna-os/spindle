//! The join handshake: `make_join`, then `send_join`.
//!
//! This is the doorway through which a remote server's user enters a room
//! for the first time — no prior membership, no shared history. What the
//! suite pins: the template previews the same authorization the real join
//! will face (public or invited, nothing else), a server can only make
//! joins for its own users, the event the peer sends back must hash to the
//! ID it claims and carry an honest signature, and the state in the
//! response is the room *before* the join — the newcomer's starting point,
//! not a mirror of their own arrival.

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
        // The peer co-signs invites like a real invitee's server would:
        // the harness's `/invite` walks the live `v2/invite` handshake, and
        // a peer that cannot answer it would fail every invite before the
        // property under test is reached.
        let invite_name = name.clone();
        let invite_pair =
            std::sync::Arc::new(Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap());
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
                    move |axum::extract::Json(body): axum::extract::Json<Value>| {
                        let name = invite_name.clone();
                        let pair = invite_pair.clone();
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
                            let signed = serde_json::to_value(&canonical).unwrap();
                            axum::Json(json!({ "event": signed }))
                        }
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

    /// Content-hash and sign an event, the way a real peer finishes a
    /// `make_join` template before sending it back.
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

/// The reference hash the event's ID is derived from — both sides must
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

    async fn public_room(&self, alice: &str) -> String {
        let (_, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", alice, &json!({}))
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                alice,
                &json!({ "join_rule": "public" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room
    }

    async fn make_join(&self, peer: &Peer, room: &str, user: &str) -> (StatusCode, Value) {
        let uri = format!("/_matrix/federation/v1/make_join/{room}/{user}?ver=11");
        let header = peer.get_header(&uri);
        self.call(
            Request::builder()
                .uri(&uri)
                .header("authorization", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn send_join(
        &self,
        peer: &Peer,
        room: &str,
        event_id: &str,
        join: &Value,
    ) -> (StatusCode, Value) {
        let uri = format!("/_matrix/federation/v2/send_join/{room}/{event_id}");
        let header = peer.put_header(&uri, join);
        self.call(
            Request::builder()
                .method("PUT")
                .uri(&uri)
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(join.to_string()))
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn the_full_handshake_lands_the_peer_joined() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    let (status, body) = harness.make_join(&peer, &room, &peer.user()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_version"], json!("11"), "{body}");
    let template = &body["event"];
    assert_eq!(template["type"], json!("m.room.member"), "{template}");
    assert_eq!(template["content"]["membership"], json!("join"));
    assert_eq!(template["sender"], template["state_key"]);
    assert!(
        !template["prev_events"].as_array().unwrap().is_empty(),
        "the template hangs off the room's head: {template}"
    );
    assert!(
        !template["auth_events"].as_array().unwrap().is_empty(),
        "the template cites its authorization: {template}"
    );

    let join = peer.sign_event(template);
    let join_id = event_id_of(&join);
    let (status, body) = harness.send_join(&peer, &room, &join_id, &join).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["origin"], json!("example.org"));
    assert_eq!(body["event"]["sender"], json!(peer.user()));
    let state = body["state"].as_array().unwrap();
    assert!(
        state
            .iter()
            .any(|event| event["type"] == json!("m.room.create")),
        "the state carries the room's foundation: {body}"
    );
    assert!(
        !state
            .iter()
            .any(|event| event["state_key"] == json!(peer.user())),
        "the state is the room *before* the join, so the newcomer is not in it: {body}"
    );
    assert!(
        !body["auth_chain"].as_array().unwrap().is_empty(),
        "the auth chain accompanies the state: {body}"
    );

    // The join persisted: the local view of the room now shows the peer's
    // user as a member.
    let (status, members) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{members}");
    assert!(
        members["joined"].get(peer.user()).is_some(),
        "the handshake ends with the peer's user joined: {members}"
    );
}

#[tokio::test]
async fn an_invite_opens_a_room_that_is_not_public() {
    // The template previews the same rule the real join will face: an
    // invite-only room refuses until the invite exists, then admits.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .send("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    let (status, body) = harness.make_join(&peer, &room, &peer.user()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": peer.user() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.make_join(&peer, &room, &peer.user()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // And the invite carries through the whole handshake, not just the
    // preview.
    let join = peer.sign_event(&body["event"]);
    let join_id = event_id_of(&join);
    let (status, body) = harness.send_join(&peer, &room, &join_id, &join).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_server_cannot_make_a_join_for_another_servers_user() {
    // A template for someone else's user would be a forgery kit: the
    // requesting origin must own the user it asks for.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    let (status, body) = harness
        .make_join(&peer, &room, "@mallory:elsewhere.example")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn make_join_names_rooms_and_versions_it_cannot_serve() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    // A room this server has never seen.
    let (status, body) = harness
        .make_join(&peer, "!nosuch:example.org", &peer.user())
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A peer that cannot speak v11 gets told which version the room is,
    // not a template it cannot parse.
    let uri = format!(
        "/_matrix/federation/v1/make_join/{room}/{}?ver=10",
        peer.user()
    );
    let header = peer.get_header(&uri);
    let (status, body) = harness
        .call(
            Request::builder()
                .uri(&uri)
                .header("authorization", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], json!("M_INCOMPATIBLE_ROOM_VERSION"));
}

#[tokio::test]
async fn send_join_refuses_an_id_the_event_does_not_hash_to() {
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    let (_, body) = harness.make_join(&peer, &room, &peer.user()).await;
    let join = peer.sign_event(&body["event"]);
    let (status, body) = harness
        .send_join(&peer, &room, "$not-the-real-hash", &join)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn send_join_refuses_a_join_tampered_after_signing() {
    // The peer signs the template, then edits it: the signature no longer
    // covers what arrived, and the join is refused — not redacted-and-kept
    // like a mid-stream PDU, because a join with its content stripped is
    // not a join at all.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    let (_, body) = harness.make_join(&peer, &room, &peer.user()).await;
    let mut join = peer.sign_event(&body["event"]);
    join["origin_server_ts"] = json!(now_millis() + 12345);
    let join_id = event_id_of(&join);
    let (status, body) = harness.send_join(&peer, &room, &join_id, &join).await;
    // Exactly 403: the judgement refused it. A different failure (say, a 404
    // from looking up state at an event that never landed) would mean the
    // refusal happened by accident somewhere downstream, not by the check.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // And nothing landed: the peer's user is not a member.
    let (_, members) = harness
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &alice,
            &json!({}),
        )
        .await;
    assert!(
        members["joined"].get(peer.user()).is_none(),
        "a refused join must not persist: {members}"
    );
}

#[tokio::test]
async fn send_join_admits_only_join_events() {
    // However well signed, anything that is not a join event for this room
    // is a peer using the handshake to smuggle.
    let peer = Peer::start().await;
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.public_room(&alice).await;

    let (_, body) = harness.make_join(&peer, &room, &peer.user()).await;
    let mut template = body["event"].clone();
    template["content"] = json!({ "membership": "leave" });
    let leave = peer.sign_event(&template);
    let leave_id = event_id_of(&leave);
    let (status, body) = harness.send_join(&peer, &room, &leave_id, &leave).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
