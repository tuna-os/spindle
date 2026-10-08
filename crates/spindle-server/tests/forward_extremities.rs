//! Forks that do not merge by themselves (#626).
//!
//! A room with several forward extremities re-resolves its current state on
//! every append. Production showed a room whose extremities never merged:
//! the tips from a Synapse import and the peers' tips, in a room where only
//! remote users speak. Each remote state event then resolved the same
//! conflicted events again. These tests pin the three parts of the fix:
//!
//! - an append whose extremities' states are unchanged is a resolution-cache
//!   hit, and a state change on one branch is a new question;
//! - a room that is crowded with extremities, or forked and stale, is merged
//!   by an `org.matrix.dummy_event` from a local member, which federates;
//! - a dummy event is nobody's unread message.
//!
//! The peer is the same deliberate stale-parent peer `federation_fork.rs`
//! uses, plus a `/send` endpoint that records what this server federates.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::Metrics;
use spindle_server::rooms::extremities::{DUMMY_EVENT_TYPE, MergePolicy};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Peer {
    name: String,
    pair: Ed25519KeyPair,
    /// Every PDU this server has sent the peer.
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
            "verify_keys": { "ed25519:0": { "key": unpadded(pair.public_key().as_ref()) } },
        });
        sign_value(&name, &signing, &mut key_document);
        let received = Arc::new(Mutex::new(Vec::new()));
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
                            if let Some(pdus) = body["pdus"].as_array() {
                                sink.lock().unwrap().extend(pdus.iter().cloned());
                            }
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
        format!("@peer:{}", self.name)
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

    /// The dummy events this server has federated to the peer.
    fn dummy_events(&self) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|pdu| pdu["type"] == DUMMY_EVENT_TYPE)
            .cloned()
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

struct Harness {
    _dir: TempDir,
    app: axum::Router,
    state: spindle_server::AppState,
    metrics: Arc<Metrics>,
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
            metrics,
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

    /// Register a local user, invite them, and have them join.
    async fn admit(&self, room: &str, inviter: &str, username: &str) -> String {
        let token = self.register(username).await;
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                inviter,
                &json!({ "user_id": format!("@{username}:example.org") }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                &token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        token
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

    /// Deliver one PDU and insist it was accepted, returning its ID.
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

    /// A room the peer has joined with power to write state, alice's token,
    /// and the head event.
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

    /// A PDU from the peer naming `parent` as its only parent.
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

    fn topic(&self, peer: &Peer, room: &str, parent: &str, topic: &str) -> Value {
        self.peer_pdu(
            peer,
            room,
            parent,
            "m.room.topic",
            Some(""),
            &json!({ "topic": topic }),
        )
    }

    fn extremities(&self, room: &str) -> usize {
        self.state.rooms.forward_extremity_count(room).unwrap()
    }

    fn merge(&self) -> spindle_server::rooms::extremities::MergePass {
        self.state.rooms.merge_extremities(
            self.state.key.pair(),
            &MergePolicy::of(&self.state.config.rooms),
            now_millis(),
        )
    }

    /// `/sync`'s `unread_notifications.notification_count` for `room`.
    async fn badge(&self, room: &str, token: &str) -> u64 {
        let (status, body) = self.get("/_matrix/client/v3/sync", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rooms"]["join"][room]["unread_notifications"]["notification_count"]
            .as_u64()
            .unwrap_or(0)
    }

    /// The arithmetic unread count the push gateway badge is made of.
    fn unread(&self, room: &str, user: &str) -> usize {
        self.state
            .rooms
            .unread(room, user)
            .unwrap()
            .notification_count
    }
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The production shape of #626: a fork that no event merges. While its
/// branches' states hold still, every append asks the resolver the same
/// question and the cache answers it. A state change on one branch makes a
/// question nobody has asked, which is what kept the production room
/// resolving.
#[tokio::test]
async fn an_unmerged_fork_resolves_once_until_a_branch_state_moves() {
    let peer = Peer::start().await;
    let harness = Harness::new("");
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    // Our branch changes state, and so does the peer's, from the same point.
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
            &json!({ "topic": "ours" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (resolved_before, _, _) = harness.metrics.state_res_counts();
    let theirs = harness.topic(&peer, &room, &fork_point, "theirs");
    let mut tip = harness.inject(&peer, "fork", theirs).await;
    assert_eq!(harness.extremities(&room), 2);
    let (resolved, hits, _) = harness.metrics.state_res_counts();
    assert_eq!(resolved - resolved_before, 1, "the fork is resolved once");

    // The peer keeps talking on its own branch, never naming ours.
    for index in 0..5 {
        let pdu = harness.message(&peer, &room, &tip, &format!("m{index}"));
        tip = harness.inject(&peer, &format!("m{index}"), pdu).await;
    }
    assert_eq!(harness.extremities(&room), 2, "nothing merged the fork");
    let (after, after_hits, _) = harness.metrics.state_res_counts();
    assert_eq!(after, resolved, "an unchanged fork was resolved again");
    assert!(
        after_hits - hits >= 5,
        "every append's resolution is a cache hit: {} hits",
        after_hits - hits
    );

    // One state event on the peer's branch moves its root: a new question.
    let pdu = harness.topic(&peer, &room, &tip, "theirs again");
    harness.inject(&peer, "topic2", pdu).await;
    let (moved, _, _) = harness.metrics.state_res_counts();
    assert_eq!(moved, after + 1);
}

/// A room with more extremities than `max_forward_extremities` is merged by
/// one dummy event from the local member with the most power. The event
/// names every tip, leaves the room with one extremity, and is federated to
/// the peer.
#[tokio::test]
async fn a_crowded_room_is_merged_by_a_dummy_event_that_federates() {
    let peer = Peer::start().await;
    let harness = Harness::new("max_forward_extremities = 2\n");
    let (room, _alice, fork_point) = harness.shared_room(&peer).await;
    let mut tips = Vec::new();
    for index in 0..3 {
        let pdu = harness.message(&peer, &room, &fork_point, &format!("branch {index}"));
        tips.push(harness.inject(&peer, &format!("b{index}"), pdu).await);
    }
    assert_eq!(harness.extremities(&room), 3);

    let pass = harness.merge();
    assert_eq!(pass.merged.len(), 1, "{pass:?}");
    assert_eq!(pass.buckets, [0, 1, 0, 0], "the census saw the fork");
    assert_eq!(harness.metrics.extremity_buckets(), [0, 1, 0, 0]);
    assert_eq!(harness.metrics.dummy_event_counts(), (1, 0));
    let (merged_room, dummy) = &pass.merged[0];
    assert_eq!(merged_room, &room);
    assert_eq!(harness.extremities(&room), 1);
    assert_eq!(
        harness.state.rooms.forward_extremity_ids(&room).unwrap(),
        vec![dummy.clone()]
    );

    let pdu = harness.state.rooms.pdu(&room, dummy).unwrap();
    assert_eq!(pdu["type"], DUMMY_EVENT_TYPE);
    assert_eq!(pdu["content"], json!({}));
    assert_eq!(pdu["sender"], "@alice:example.org");
    let parents: Vec<&str> = pdu["prev_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for tip in &tips {
        assert!(
            parents.contains(&tip.as_str()),
            "{tip} not named: {parents:?}"
        );
    }

    assert!(
        eventually(|| !peer.dummy_events().is_empty()).await,
        "the dummy event never reached the peer"
    );
    let federated = peer.dummy_events();
    assert_eq!(federated.len(), 1);
    assert_eq!(federated[0]["prev_events"], pdu["prev_events"]);

    // Merged: the next census finds one extremity and sends nothing.
    let again = harness.merge();
    assert!(again.merged.is_empty());
    assert_eq!(again.buckets, [1, 0, 0, 0]);
}

/// A fork too small to crowd the room is merged once it is stale -- and
/// only in a room an append showed to be forked -- and at most once per
/// `dummy_event_interval_secs`.
#[tokio::test]
async fn a_stale_fork_is_merged_once_per_interval() {
    let peer = Peer::start().await;
    let harness = Harness::new("stale_forward_extremity_secs = 0\n");
    let (room, alice, fork_point) = harness.shared_room(&peer).await;
    let (status, _) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/ours"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "ours" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let pdu = harness.message(&peer, &room, &fork_point, "theirs");
    let theirs = harness.inject(&peer, "theirs", pdu).await;
    assert_eq!(harness.extremities(&room), 2);

    let pass = harness.merge();
    assert_eq!(pass.merged.len(), 1, "{pass:?}");
    assert_eq!(harness.extremities(&room), 1);

    // The peer forks it again at once. The room is due, but was merged
    // inside the interval, so it waits.
    let pdu = harness.message(&peer, &room, &theirs, "again");
    harness.inject(&peer, "again", pdu).await;
    assert_eq!(harness.extremities(&room), 2);
    let pass = harness.merge();
    assert!(pass.merged.is_empty(), "{pass:?}");
    assert_eq!(harness.extremities(&room), 2);
    assert_eq!(harness.metrics.dummy_event_counts(), (1, 0));
}

/// A young two-way fork is left to merge by itself, and the switch turns
/// merging off while the census keeps counting.
#[tokio::test]
async fn young_forks_and_a_disabled_merge_send_nothing() {
    for rooms in [
        "",
        "dummy_events = false\nstale_forward_extremity_secs = 0\n",
    ] {
        let peer = Peer::start().await;
        let harness = Harness::new(rooms);
        let (room, alice, fork_point) = harness.shared_room(&peer).await;
        let (status, _) = harness
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/ours"),
                &alice,
                &json!({ "msgtype": "m.text", "body": "ours" }),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let pdu = harness.message(&peer, &room, &fork_point, "theirs");
        harness.inject(&peer, "theirs", pdu).await;
        let pass = harness.merge();
        assert!(pass.merged.is_empty(), "{rooms:?}: {pass:?}");
        assert_eq!(pass.buckets, [0, 1, 0, 0], "{rooms:?}");
        assert_eq!(harness.extremities(&room), 2, "{rooms:?}");
    }
}

/// A dummy event is not a message. It moves neither the arithmetic unread
/// count -- from a warm index, or one built after it landed -- nor the
/// push-rule badge `/sync` reports.
#[tokio::test]
async fn a_dummy_event_is_nobodys_unread_message() {
    let peer = Peer::start().await;
    let harness = Harness::new("max_forward_extremities = 2\n");
    let (room, alice, _) = harness.shared_room(&peer).await;
    let bob = harness.admit(&room, &alice, "bob").await;
    let carol = harness.admit(&room, &alice, "carol").await;
    let fork_point = harness.head_event(&room, &alice).await;
    for index in 0..3 {
        let pdu = harness.message(&peer, &room, &fork_point, &format!("branch {index}"));
        harness.inject(&peer, &format!("b{index}"), pdu).await;
    }

    // Bob's index is warm before the merge; carol's is built after it.
    let bob_unread = harness.unread(&room, "@bob:example.org");
    assert_eq!(bob_unread, 3);
    let bob_badge = harness.badge(&room, &bob).await;
    assert_eq!(bob_badge, 3);

    let pass = harness.merge();
    assert_eq!(pass.merged.len(), 1, "{pass:?}");

    assert_eq!(harness.unread(&room, "@bob:example.org"), bob_unread);
    assert_eq!(harness.badge(&room, &bob).await, bob_badge);
    assert_eq!(harness.unread(&room, "@carol:example.org"), 3);
    assert_eq!(harness.badge(&room, &carol).await, 3);
}
