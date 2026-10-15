//! MSC4284 policy server opt-in, federation signatures and refusal-before-publication.
#[path = "support/federation_auth.rs"]
mod federation_auth;
use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode},
};
use ruma::{
    RoomVersionId,
    signatures::{Ed25519KeyPair, hash_and_sign_event},
};
use serde_json::{Value, json};
use spindle_server::{
    metrics::Metrics,
    policy::{KEY_ID, PolicyServer},
};
use spindle_store::FjallStore;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tower::ServiceExt;

struct Peer {
    name: String,
    pair: Ed25519KeyPair,
    policy_pair: Arc<Ed25519KeyPair>,
    mode: Arc<AtomicU8>,
    requests: Arc<Mutex<Vec<Value>>>,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}
impl Peer {
    #[allow(
        clippy::too_many_lines,
        reason = "the signed federation and policy HTTP fixture"
    )]
    async fn start() -> Self {
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let policy_document = Ed25519KeyPair::generate();
        let policy_pair = Arc::new(
            Ed25519KeyPair::from_der(&policy_document, "policy_server".to_owned()).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let mut key_document = json!({"server_name": name, "valid_until_ts": now_millis() + 86_400_000,
            "verify_keys": {"ed25519:0": {"key": unpadded(pair.public_key().as_ref())}}});
        sign_value(&name, &pair, &mut key_document);
        let mode = Arc::new(AtomicU8::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let mut router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { Json(body) }
                }),
            )
            .route(
                "/_matrix/federation/v2/invite/{room}/{event}",
                axum::routing::put(|Json(body): Json<Value>| async move {
                    let mut event = body["event"].clone();
                    if let Some(signers) = event["signatures"].as_object_mut() {
                        for keys in signers.values_mut() {
                            keys.as_object_mut().unwrap().remove(KEY_ID);
                        }
                    }
                    Json(json!({"event":event}))
                }),
            );
        for path in [
            "/_matrix/policy/v1/sign",
            "/_matrix/policy/unstable/org.matrix.msc4284/sign",
        ] {
            let (mode, requests, name, pair, entered, release) = (
                mode.clone(),
                requests.clone(),
                name.clone(),
                policy_pair.clone(),
                entered.clone(),
                release.clone(),
            );
            router = router.route(
                path,
                axum::routing::post(
                    move |headers: axum::http::HeaderMap, Json(event): Json<Value>| {
                        let (mode, requests, name, pair, entered, release) = (
                            mode.clone(),
                            requests.clone(),
                            name.clone(),
                            pair.clone(),
                            entered.clone(),
                            release.clone(),
                        );
                        async move {
                            assert!(
                                headers["authorization"]
                                    .to_str()
                                    .unwrap()
                                    .starts_with("X-Matrix ")
                            );
                            assert!(event["event"].is_null(), "request is the PDU itself");
                            assert!(
                                event["event_id"].is_null(),
                                "v11 wire PDU excludes the event id"
                            );
                            requests.lock().unwrap().push(event.clone());
                            let mode = mode.load(Ordering::SeqCst);
                            if mode == 3 && path.contains("/v1/") {
                                return (StatusCode::NOT_FOUND, "unsupported".to_owned());
                            }
                            if mode == 1 {
                                return (
                                    StatusCode::FORBIDDEN,
                                    json!({"errcode":"M_FORBIDDEN","error":"policy denied"})
                                        .to_string(),
                                );
                            }
                            if mode == 2 {
                                return (
                                    StatusCode::OK,
                                    json!({name: {KEY_ID: "bad"}}).to_string(),
                                );
                            }
                            if mode == 6 { return (StatusCode::TOO_MANY_REQUESTS, json!({"errcode":"M_LIMIT_EXCEEDED","error":"try later","retry_after_ms":2000}).to_string()); }
                    if mode == 7 { return (StatusCode::UNAUTHORIZED, json!({"errcode":"M_UNKNOWN_TOKEN","error":"unknown token","soft_logout":true}).to_string()); }
                    if mode == 8 { return (StatusCode::IM_A_TEAPOT, json!({"errcode":"M_FORBIDDEN","error":"No coffee here"}).to_string()); }
                    if mode == 4 {
                                return (StatusCode::OK, "{}".to_owned());
                            }
                            if mode == 5 {
                                entered.add_permits(1);
                                release.acquire().await.unwrap().forget();
                            }
                            let mut event =
                                policy_signature(&name, &pair, &event, &RoomVersionId::V11);
                            (StatusCode::OK, event["signatures"].take().to_string())
                        }
                    },
                ),
            );
        }
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            name,
            pair,
            policy_pair,
            mode,
            requests,
            entered,
            release,
        }
    }
    fn user(&self) -> String {
        format!("@peer:{}", self.name)
    }
    fn policy(&self) -> PolicyServer {
        PolicyServer {
            server_name: self.name.clone(),
            public_key: unpadded(self.policy_pair.public_key().as_ref()),
        }
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
}
fn policy_signature(
    name: &str,
    pair: &Ed25519KeyPair,
    event: &Value,
    version: &RoomVersionId,
) -> Value {
    let ruma::CanonicalJsonValue::Object(mut object) =
        ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
    else {
        unreachable!()
    };
    if spindle_core::version::names_events_by_hash(version) {
        object.remove("event_id");
    }
    let mut redacted = spindle_core::version::redact(&object, version).unwrap();
    ruma::signatures::sign_json(name, pair, &mut redacted).unwrap();
    let signed = serde_json::to_value(redacted).unwrap();
    let mut result = event.clone();
    result["signatures"] = signed["signatures"].clone();
    result
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
}
impl Harness {
    fn new(rooms: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
             retry_base_ms = 50\n[rooms]\n{rooms}"
        ))
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
    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
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
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"),
                token,
            )
            .await;
        body["chunk"][0]["event_id"].as_str().unwrap().to_owned()
    }
    async fn inject(&self, peer: &Peer, txn_id: &str, pdu: Value) -> String {
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": [pdu] });
        let header = peer.transaction_header(txn_id, &body);
        let (status, body) = self
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
        assert_eq!(status, StatusCode::OK, "{body}");
        let (id, outcome) = body["pdus"]
            .as_object()
            .and_then(|map| {
                map.iter()
                    .next()
                    .map(|(id, outcome)| (id.clone(), outcome.clone()))
            })
            .expect("the transaction response names the PDU");
        assert!(outcome["error"].is_null(), "the PDU was refused: {outcome}");
        id
    }
    async fn shared_room(&self, peer: &Peer) -> (String, String, String) {
        let alice = self.register("alice").await;
        let (_, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                &alice,
                &json!({ "user_id": peer.user() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the invite was refused: {body}");
        let head = self.head_event(&room, &alice).await;
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
        self.inject(peer, "join", join).await;
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"),
                &alice,
                &json!({
                    "users": { "@alice:example.org": 100, peer.user(): 100 },
                    "users_default": 0,
                    "state_default": 50,
                    "events_default": 0,
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "power levels were refused: {body}");
        let head = self.head_event(&room, &alice).await;
        (room, alice, head)
    }
    fn peer_pdu(
        &self,
        peer: &Peer,
        room: &str,
        parent: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Value {
        let mut pdu = json!({
            "type": event_type,
            "sender": peer.user(),
            "room_id": room,
            "content": content,
            "origin_server_ts": now_millis(),
            "depth": 20,
            "prev_events": [parent],
            "auth_events": [],
        });
        if let Some(state_key) = state_key {
            pdu["state_key"] = json!(state_key);
        }
        peer.event(federation_auth::with_auth_events(&self.store, pdu))
    }
    fn message(&self, peer: &Peer, room: &str, parent: &str, text: &str) -> Value {
        self.peer_pdu(
            peer,
            room,
            parent,
            "m.room.message",
            None,
            &json!({ "msgtype": "m.text", "body": text }),
        )
    }
    async fn enable(&self, peer: &Peer, room: &str, token: &str, unstable: bool) {
        let (kind, content) = if unstable {
            (
                "org.matrix.msc4284.policy",
                json!({"via":peer.name,"public_key":peer.policy().public_key}),
            )
        } else {
            (
                "m.room.policy",
                json!({"via":peer.name,"public_keys":{"ed25519":peer.policy().public_key}}),
            )
        };
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/{kind}"),
                token,
                &content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    async fn local(&self, room: &str, token: &str, txn: &str) -> (StatusCode, Value) {
        self.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
            token,
            &json!({"msgtype":"m.text","body":txn}),
        )
        .await
    }
}

#[tokio::test]
async fn local_approval_is_verified_and_denials_never_publish() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    let (status, body) = h.local(&room, &alice, "approved").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["event_id"].as_str().unwrap();
    let event = h.state.rooms.pdu(&room, id).unwrap();
    assert!(peer.policy().verifies(&event, &RoomVersionId::V11));
    assert!(event["signatures"]["example.org"]["ed25519:0"].is_string());
    let requests = peer.requests.lock().unwrap().len();
    let (_, again) = h.local(&room, &alice, "approved").await;
    assert_eq!(again, body);
    assert_eq!(peer.requests.lock().unwrap().len(), requests);
    for mode in [1, 2, 4] {
        peer.mode.store(mode, Ordering::SeqCst);
        let before = h.state.rooms.stream_position();
        let (status, body) = h.local(&room, &alice, &format!("denied-{mode}")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(h.state.rooms.stream_position(), before);
    }
    // A failed transaction may succeed on a subsequent attempt.
    peer.mode.store(0, Ordering::SeqCst);
    assert_eq!(h.local(&room, &alice, "denied-1").await.0, StatusCode::OK);
}

#[tokio::test]
async fn unstable_compatibility_and_stable_disable_precedence() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, true).await;
    peer.mode.store(3, Ordering::SeqCst);
    assert_eq!(h.local(&room, &alice, "fallback").await.0, StatusCode::OK);
    assert_eq!(peer.requests.lock().unwrap().len(), 2);
    peer.mode.store(1, Ordering::SeqCst);
    let (status, body) = h
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.policy"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(h.state.rooms.policy_server(&room).unwrap().is_none());
    assert_eq!(h.local(&room, &alice, "disabled").await.0, StatusCode::OK);
    assert_eq!(peer.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn approval_does_not_hold_room_lock_and_concurrent_txn_retries_share_result() {
    let peer = Peer::start().await;
    let h = Arc::new(Harness::new(""));
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    peer.mode.store(5, Ordering::SeqCst);
    let before = h.state.rooms.stream_position();
    let task = {
        let (h, room, alice) = (h.clone(), room.clone(), alice.clone());
        tokio::spawn(async move { h.local(&room, &alice, "waiting").await })
    };
    tokio::time::timeout(Duration::from_secs(2), peer.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(h.state.rooms.stream_position(), before);
    let retry = {
        let (h, room, alice) = (h.clone(), room.clone(), alice.clone());
        tokio::spawn(async move { h.local(&room, &alice, "waiting").await })
    };
    // Room reads and emergency policy removal still work while signing stalls.
    let remove = async {
        h.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.policy"),
            &alice,
            &json!({}),
        )
        .await
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), remove)
            .await
            .unwrap()
            .0,
        StatusCode::OK
    );
    peer.release.add_permits(1);
    let first = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    let second = retry.await.unwrap();
    assert_eq!(first.0, StatusCode::OK, "{first:?}");
    assert_eq!(first, second);
    assert_eq!(peer.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn incoming_approval_preserves_origin_keys_and_signed_events_skip_network() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    let head = h.head_event(&room, &alice).await;
    let pdu = h.message(&peer, &room, &head, "incoming");
    let id = h.inject(&peer, "incoming", pdu).await;
    let stored = h.state.rooms.pdu(&room, &id).unwrap();
    assert!(stored["signatures"][&peer.name]["ed25519:0"].is_string());
    assert!(peer.policy().verifies(&stored, &RoomVersionId::V11));
    let count = peer.requests.lock().unwrap().len();
    peer.mode.store(1, Ordering::SeqCst);
    let head = h.head_event(&room, &alice).await;
    let event = h.message(&peer, &room, &head, "signed");
    let signed = policy_signature(&peer.name, &peer.policy_pair, &event, &RoomVersionId::V11);
    h.inject(&peer, "signed", signed).await;
    assert_eq!(peer.requests.lock().unwrap().len(), count);
    // Historical dependency receipt is not judged under today's policy.
    let head = h.head_event(&room, &alice).await;
    let historical = h.message(&peer, &room, &head, "historical");
    let ruma::CanonicalJsonValue::Object(canonical) =
        ruma::CanonicalJsonValue::try_from(historical.clone()).unwrap()
    else {
        unreachable!()
    };
    let id = spindle_core::Pdu::from_remote(RoomVersionId::V11, canonical)
        .unwrap()
        .event_id()
        .as_str()
        .to_owned();
    h.state
        .rooms
        .receive_remote(&room, &id, &historical)
        .unwrap();
}

#[tokio::test]
async fn policy_requires_joined_server_and_self_policy_is_inactive() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let alice = h.register("alice").await;
    let (_, body) = h
        .send("POST", "/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    let room = body["room_id"].as_str().unwrap();
    h.enable(&peer, room, &alice, false).await;
    assert!(h.state.rooms.policy_server(room).unwrap().is_none());
    assert_eq!(h.local(room, &alice, "not-joined").await.0, StatusCode::OK);
    assert!(peer.requests.lock().unwrap().is_empty());
    assert!(
        PolicyServer::from_content(
            &json!({"via":"example.org","public_keys":{"ed25519":"key"}}),
            false,
            "example.org"
        )
        .is_none()
    );
    assert!(
        PolicyServer::from_content(
            &json!({"via":"not a server","public_keys":{"ed25519":"key"}}),
            false,
            "example.org"
        )
        .is_none()
    );
}

#[tokio::test]
async fn refusals_cover_membership_redaction_state_delays_and_live_federation() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    let (_, message) = h.local(&room, &alice, "before-policy").await;
    h.enable(&peer, &room, &alice, false).await;
    peer.mode.store(1, Ordering::SeqCst);
    let before = h.state.rooms.stream_position();
    for (path, body) in [
        (
            format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            json!({"topic":"denied"}),
        ),
        (
            format!("/_matrix/client/v3/rooms/{room}/invite"),
            json!({"user_id":"@bob:example.org"}),
        ),
        (format!("/_matrix/client/v3/rooms/{room}/leave"), json!({})),
        (
            format!(
                "/_matrix/client/v3/rooms/{room}/redact/{}/redact-txn",
                message["event_id"].as_str().unwrap()
            ),
            json!({}),
        ),
    ] {
        let method = if path.contains("/state/") || path.contains("/redact/") {
            "PUT"
        } else {
            "POST"
        };
        let (status, body) = h.send(method, &path, &alice, &body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(h.state.rooms.stream_position(), before);
    }
    assert_eq!(
        h.state
            .rooms
            .event(&room, message["event_id"].as_str().unwrap())
            .unwrap()["content"]["body"],
        "before-policy"
    );
    let (status, body) = h
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/delayed_event/m.room.message/delay-txn"),
            &alice,
            &json!({"delay_ms":60000,"content":{"msgtype":"m.text","body":"delayed"}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delay = body["delay_id"].as_str().unwrap();
    let (status, body) = h
        .send(
            "POST",
            &format!("/_matrix/client/v1/delayed_events/{delay}/send"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(h.state.rooms.stream_position(), before);
    let head = h.head_event(&room, &alice).await;
    let pdu = h.message(&peer, &room, &head, "rejected remote");
    let body = json!({"origin":peer.name,"origin_server_ts":now_millis(),"pdus":[pdu]});
    let header = peer.transaction_header("rejected", &body);
    let (status, response) = h
        .call(
            Request::builder()
                .method("PUT")
                .uri("/_matrix/federation/v1/send/rejected")
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        response["pdus"]
            .as_object()
            .unwrap()
            .values()
            .all(|outcome| outcome["error"].is_string())
    );
    assert_eq!(h.state.rooms.stream_position(), before);
    let denied = response["pdus"].as_object().unwrap().keys().next().unwrap();
    assert!(h.state.rooms.event(&room, denied).is_err());
    assert!(
        h.state.rooms.pdu(&room, denied).is_ok(),
        "soft-failed body remains available for DAG dependencies"
    );
    peer.mode.store(0, Ordering::SeqCst);
    let mut descendant = h.message(&peer, &room, &head, "allowed descendant");
    descendant["prev_events"] = json!([denied]);
    let descendant = peer.event(descendant);
    h.inject(&peer, "descendant", descendant).await;
    assert!(h.state.rooms.event(&room, denied).is_err());
}

#[test]
fn approvals_use_room_keys_and_room_version_redaction() {
    let document = Ed25519KeyPair::generate();
    let pair = Ed25519KeyPair::from_der(&document, "policy_server".to_owned()).unwrap();
    let policy = PolicyServer {
        server_name: "policy.example".to_owned(),
        public_key: unpadded(pair.public_key().as_ref()),
    };
    for version in [
        RoomVersionId::V1,
        RoomVersionId::V3,
        RoomVersionId::V11,
        RoomVersionId::V12,
        RoomVersionId::try_from(spindle_core::STATE_DAG_V12).unwrap(),
    ] {
        let event = json!({"event_id":"$id:origin.example","room_id":"!room:origin.example","type":"m.room.message",
            "sender":"@alice:origin.example","origin_server_ts":1,"content":{"body":"hello","msgtype":"m.text"},
            "prev_events":[],"auth_events":[],"depth":1,"hashes":{"sha256":"digest"}});
        let signed = policy_signature(&policy.server_name, &pair, &event, &version);
        assert!(policy.verifies(&signed, &version), "{version}");
        let mut corrupted = signed.clone();
        corrupted["hashes"]["sha256"] = json!("changed");
        assert!(!policy.verifies(&corrupted, &version));
        let mut wrong_key = policy.clone();
        wrong_key.public_key = "invalid".to_owned();
        assert!(!wrong_key.verifies(&signed, &version));
    }
    assert!(spindle_server::policy::exempt(
        &json!({"type":"m.room.policy","state_key":""})
    ));
    assert!(!spindle_server::policy::exempt(
        &json!({"type":"m.room.policy","state_key":"other"})
    ));
    assert!(!spindle_server::policy::exempt(
        &json!({"type":"m.room.policy"})
    ));
}

#[tokio::test]
async fn policy_timeout_refuses_without_publishing() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    peer.mode.store(5, Ordering::SeqCst);
    let before = h.state.rooms.stream_position();
    let (status, body) =
        tokio::time::timeout(Duration::from_secs(35), h.local(&room, &alice, "timeout"))
            .await
            .expect("signing has a 30-second deadline");
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(h.state.rooms.stream_position(), before);
    peer.release.add_permits(1);
}

#[tokio::test]
async fn a_policy_server_leaving_disables_its_policy() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    let head = h.head_event(&room, &alice).await;
    let leave = h.peer_pdu(
        &peer,
        &room,
        &head,
        "m.room.member",
        Some(&peer.user()),
        &json!({"membership":"leave"}),
    );
    h.inject(&peer, "depart", leave).await;
    assert!(h.state.rooms.policy_server(&room).unwrap().is_none());
    let count = peer.requests.lock().unwrap().len();
    peer.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        h.local(&room, &alice, "after-departure").await.0,
        StatusCode::OK
    );
    assert_eq!(peer.requests.lock().unwrap().len(), count);
}

#[tokio::test]
async fn actionable_policy_errors_are_relayed_without_invalidating_client_tokens() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    for (mode, status, code, message) in [
        (
            6,
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            "try later",
        ),
        (7, StatusCode::BAD_REQUEST, "M_UNKNOWN", "unknown token"),
        (8, StatusCode::IM_A_TEAPOT, "M_FORBIDDEN", "No coffee here"),
    ] {
        peer.mode.store(mode, Ordering::SeqCst);
        let (actual, body) = h.local(&room, &alice, &format!("error-{mode}")).await;
        assert_eq!(actual, status, "{body}");
        assert_eq!(body["errcode"], code);
        assert_eq!(body["error"], message);
        assert!(body["soft_logout"].is_null());
        if mode == 6 {
            assert_eq!(body["retry_after_ms"], 2000);
        }
    }
    peer.mode.store(0, Ordering::SeqCst);
    assert_eq!(
        h.local(&room, &alice, "session-still-valid").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn remote_invites_retain_approval_and_brokered_joins_return_it() {
    let peer = Peer::start().await;
    let h = Harness::new("");
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    let user = format!("@other:{}", peer.name);
    let (status, body) = h
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({"user_id":user}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = h.head_event(&room, &alice).await;
    assert!(
        peer.policy()
            .verifies(&h.state.rooms.pdu(&room, &id).unwrap(), &RoomVersionId::V11)
    );
    let mut join = h.state.rooms.make_join_template(&room, &user).unwrap();
    join["origin_server_ts"] = json!(now_millis());
    let join = peer.event(join);
    let ruma::CanonicalJsonValue::Object(canonical) =
        ruma::CanonicalJsonValue::try_from(join.clone()).unwrap()
    else {
        unreachable!()
    };
    let id = spindle_core::Pdu::from_remote(RoomVersionId::V11, canonical)
        .unwrap()
        .event_id()
        .as_str()
        .to_owned();
    let uri = format!("/_matrix/federation/v2/send_join/{room}/{id}");
    let mut auth = json!({"method":"PUT","uri":uri,"origin":peer.name,"destination":"example.org","content":join});
    sign_value(&peer.name, &peer.pair, &mut auth);
    let header = format!(
        "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{}\"",
        peer.name,
        auth["signatures"][&peer.name]["ed25519:0"]
            .as_str()
            .unwrap()
    );
    let (status, body) = h
        .call(
            Request::builder()
                .method("PUT")
                .uri(&uri)
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(join.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(peer.policy().verifies(&body["event"], &RoomVersionId::V11));
    assert!(body["event"]["signatures"][&peer.name]["ed25519:0"].is_string());
}

#[tokio::test]
async fn timeline_activity_during_signing_does_not_force_approval_retries() {
    let peer = Peer::start().await;
    let h = Arc::new(Harness::new(""));
    let (room, alice, _) = h.shared_room(&peer).await;
    h.enable(&peer, &room, &alice, false).await;
    peer.mode.store(5, Ordering::SeqCst);
    let task = {
        let (h, room, alice) = (h.clone(), room.clone(), alice.clone());
        tokio::spawn(async move { h.local(&room, &alice, "busy-room").await })
    };
    tokio::time::timeout(Duration::from_secs(5), peer.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let head = h.head_event(&room, &alice).await;
    let event = h.message(&peer, &room, &head, "concurrent timeline message");
    let signed = policy_signature(&peer.name, &peer.policy_pair, &event, &RoomVersionId::V11);
    h.inject(&peer, "concurrent-timeline", signed).await;
    peer.release.add_permits(1);
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(peer.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn client_member_state_cannot_supply_a_restricted_join_nominee() {
    let peer = Peer::start().await;
    for active in [false, true] {
        let h = Harness::new("");
        let (room, alice, _) = h.shared_room(&peer).await;
        if active {
            h.enable(&peer, &room, &alice, false).await;
        }
        let (status, body) = h
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/@alice:example.org"),
                &alice,
                &json!({
                    "membership": "join",
                    "displayname": "Alice",
                    "join_authorised_via_users_server": "unused",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let event = h
            .state
            .rooms
            .state_event_full(&room, "m.room.member", "@alice:example.org")
            .unwrap();
        assert_eq!(event["content"]["displayname"], "Alice");
        assert!(event["content"]["join_authorised_via_users_server"].is_null());
        if active {
            let policy = h.state.rooms.policy_server(&room).unwrap().unwrap();
            assert!(policy.verifies(&event, &RoomVersionId::V11));
            assert!(peer.requests.lock().unwrap().last().unwrap()["content"]
                ["join_authorised_via_users_server"]
                .is_null());
        }
    }
}
