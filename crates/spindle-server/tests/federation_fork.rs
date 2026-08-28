//! Forks that arrive the way real forks arrive: over federation.
//!
//! `docs/benchmarks.md` retires an assumption this file exists to answer —
//! *no amount of client-server benchmarking against a single peer can
//! demonstrate the design's central claim, because the workload that
//! triggers the cost cannot be constructed through that API.* A single
//! server linearizes everything it accepts. Forks need a second server that
//! accepted something concurrently.
//!
//! The fork here is **deliberate, not raced**. Two live servers sending at
//! the same instant would fork only if delivery lost the race, which on a
//! loopback listener is a coin toss and in CI is a flake. Instead the peer
//! signs a PDU naming an intentionally *stale* `prev_event` — the head as it
//! was before this server's own last append. That is exactly the "inject
//! stale message" case #16 asks for, and it is reproducible.
//!
//! Nothing is resolved when that PDU lands: it appends at the tail with its
//! own parent's state, and the log simply has two forward extremities. The
//! merge happens on the *next local append*, which names both — so every
//! test here ends by sending one more event, and that event is the one under
//! examination.
//!
//! `spindle-core`'s `state_res_comparison` bench measures the same merge on
//! a hand-built log. This is the first place a fork reaches it through the
//! federation surface, with real signatures, real authorization and the real
//! ingest path in between.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::{ForkCase, fork_case_count};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// The fork-case counters are process-global, as metrics registries are, so
/// a delta is only attributable to one test while no other test is
/// appending. These tests are the only ones in this binary and each holds
/// this for its duration.
///
/// Without it the counter assertions would be the kind that passes by
/// accident, which is the specific failure #16's exit criterion names: *no
/// test can pass by silently taking a more expensive path.*
///
/// Each test holds it across its awaits, which clippy flags as a hazard and
/// which here is the point: serializing them is the whole job. The hazard
/// the lint guards against — a task parked holding the lock while another
/// task on the same runtime waits for it — cannot arise, because
/// `#[tokio::test]` gives every test its own current-thread runtime and
/// nothing else runs on it.
static COUNTERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A snapshot of every fork-case counter, for delta comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cases {
    non_state: u64,
    uncontested: u64,
    contested: u64,
}

impl Cases {
    fn read() -> Self {
        Self {
            non_state: fork_case_count(ForkCase::NonState),
            uncontested: fork_case_count(ForkCase::StateUncontested),
            contested: fork_case_count(ForkCase::StateContested),
        }
    }

    /// How many of each case happened since `self`.
    fn since(self, earlier: Self) -> Self {
        Self {
            non_state: self.non_state - earlier.non_state,
            uncontested: self.uncontested - earlier.uncontested,
            contested: self.contested - earlier.contested,
        }
    }
}

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
            "verify_keys": { "ed25519:0": { "key": unpadded(pair.public_key().as_ref()) } },
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

    /// Set one state event locally, and return the status.
    async fn set_state(
        &self,
        room: &str,
        token: &str,
        event_type: &str,
        content: &Value,
    ) -> StatusCode {
        self.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}"),
            token,
            content,
        )
        .await
        .0
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> StatusCode {
        self.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
            token,
            &json!({ "msgtype": "m.text", "body": text }),
        )
        .await
        .0
    }

    /// The room's current state as `(type, state_key) -> event_id`.
    ///
    /// The comparison is on event IDs rather than content because an event ID
    /// is a reference hash: equal IDs are equal bytes, so nothing else has to
    /// be enumerated to say two views of a room agree.
    async fn state_ids(
        &self,
        room: &str,
        token: &str,
    ) -> std::collections::BTreeMap<String, String> {
        let (status, body) = self
            .get(&format!("/_matrix/client/v3/rooms/{room}/state"), token)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body.as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    format!(
                        "{}/{}",
                        event["type"].as_str().unwrap_or_default(),
                        event["state_key"].as_str().unwrap_or_default()
                    ),
                    event["event_id"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }

    /// Deliver PDUs and insist every one of them was accepted.
    ///
    /// The guard that matters most in this file. A refused PDU still answers
    /// 200 at the transaction level -- soft-fail is per-PDU by design -- so a
    /// fork that never happened looks exactly like a fork that merged for
    /// free. Both counter assertions below would pass on it. Asking the
    /// response whether the branch actually landed is what stops that.
    async fn inject(&self, peer: &Peer, txn_id: &str, pdu: Value) -> Value {
        let (status, body) = self.deliver(peer, txn_id, vec![pdu]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let outcome = body["pdus"]
            .as_object()
            .and_then(|map| map.values().next().cloned())
            .unwrap_or(Value::Null);
        assert!(
            outcome["error"].is_null(),
            "the branch was refused, so there is no fork to merge: {outcome}"
        );
        body
    }

    async fn deliver(&self, peer: &Peer, txn_id: &str, pdus: Vec<Value>) -> (StatusCode, Value) {
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": pdus });
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

    /// A room the peer has joined, plus alice's token and the head event.
    ///
    /// The head is the fork point: every stale PDU below names it, which is
    /// what makes these forks deterministic instead of a delivery race.
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
        let join = peer.event(json!({
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
        self.inject(peer, "join", join).await;

        // The peer needs power to write state, or every state PDU below is
        // refused for lack of it and no fork is ever produced -- which is
        // precisely the vacuous pass `inject` exists to catch. A room's
        // default `state_default` is 50 and a joined user's is 0.
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"),
                &alice,
                &json!({
                    "users": { format!("@alice:example.org"): 100, peer.user(): 100 },
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

    /// A state PDU from the peer that names `stale` as its only parent.
    fn stale_state(
        peer: &Peer,
        room: &str,
        stale: &str,
        event_type: &str,
        state_key: &str,
        content: &Value,
    ) -> Value {
        peer.event(json!({
            "type": event_type,
            "state_key": state_key,
            "sender": peer.user(),
            "room_id": room,
            "content": content,
            "origin_server_ts": now_millis(),
            "depth": 11,
            "prev_events": [stale],
            "auth_events": [],
        }))
    }

    /// A message PDU from the peer that names `stale` as its only parent.
    fn stale_message(peer: &Peer, room: &str, stale: &str, text: &str) -> Value {
        peer.event(json!({
            "type": "m.room.message",
            "sender": peer.user(),
            "room_id": room,
            "content": { "msgtype": "m.text", "body": text },
            "origin_server_ts": now_millis(),
            "depth": 11,
            "prev_events": [stale],
            "auth_events": [],
        }))
    }
}

/// Two messages, one on each branch: SPEC §9.2 case 1.
///
/// A non-state event cannot conflict, so the merge that follows must cost
/// nothing beyond the append itself. This is the fork the design says is
/// free, and the counter is what says it actually was.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_of_two_messages_costs_no_resolution() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    // Our branch.
    assert_eq!(harness.say(&room, &alice, "ours").await, StatusCode::OK);
    // Theirs, naming the head as it was before ours — the fork.
    let pdu = Harness::stale_message(&peer, &room, &fork_point, "theirs");
    harness.inject(&peer, "fork1", pdu).await;

    // The merge: one more local append, naming both extremities.
    let before = Cases::read();
    assert_eq!(harness.say(&room, &alice, "after").await, StatusCode::OK);
    let delta = Cases::read().since(before);

    assert_eq!(
        delta.contested, 0,
        "a message fork took the state-resolution path: {delta:?}"
    );

    // Both branches survived the merge. A merge that dropped one would be a
    // silent history loss, and the counter above would still read clean.
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
            &alice,
        )
        .await;
    let bodies: Vec<&str> = body["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .collect();
    for expected in ["ours", "theirs", "after"] {
        assert!(
            bodies.contains(&expected),
            "{expected} is missing: {bodies:?}"
        );
    }
}

/// Each branch writes a state slot the other never held: SPEC §9.2 case 2.
///
/// This is the fork the whole design rests on — the one Spindle claims to
/// merge without running state resolution, and the one
/// `state_res_comparison` benchmarks. Here it arrives over the wire.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_on_slots_neither_branch_held_merges_without_resolution() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    // Two different state slots, neither set in the common ancestor: a
    // freshly created room has no topic and no name.
    assert_eq!(
        harness
            .set_state(&room, &alice, "m.room.topic", &json!({ "topic": "ours" }))
            .await,
        StatusCode::OK
    );
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.name",
        "",
        &json!({ "name": "theirs" }),
    );
    harness.inject(&peer, "fork2", pdu).await;

    let before = Cases::read();
    assert_eq!(harness.say(&room, &alice, "after").await, StatusCode::OK);
    let delta = Cases::read().since(before);
    assert_eq!(
        delta.contested, 0,
        "a disjoint-slot fork took the state-resolution path: {delta:?}"
    );

    // Convergence: the merged state carries *both* branches' writes. Taking
    // either parent's state wholesale would drop the other's, and that is
    // exactly what the state_res oracle's deliberate-regression check
    // catches in `spindle-core`.
    let state = harness.state_ids(&room, &alice).await;
    assert!(state.contains_key("m.room.topic/"), "{state:?}");
    assert!(state.contains_key("m.room.name/"), "{state:?}");
}

/// Both branches write the *same* slot: SPEC §9.2 case 3.
///
/// This is the expensive case, and today it is not resolved but refused —
/// `metrics.rs` says so in as many words: *bounded resolution exists in
/// `spindle-core` but is not yet wired into ingest (#16)*. The test pins the
/// refusal rather than the aspiration, because a test asserting the intended
/// behaviour would fail today and a test asserting nothing would let the
/// refusal turn into silent data loss unnoticed.
///
/// What must hold either way: the room is not corrupted. Whichever way the
/// merge goes, both servers must still be able to read a consistent state,
/// and the case-3 counter must have moved — the design's falsifiable target
/// (§18.3, case 3 under 0.1% of federated events) is meaningless if the
/// expensive path can be taken without being counted.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_on_the_same_slot_is_counted_as_the_expensive_case() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    assert_eq!(
        harness
            .set_state(&room, &alice, "m.room.topic", &json!({ "topic": "ours" }))
            .await,
        StatusCode::OK
    );
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.topic",
        "",
        &json!({ "topic": "theirs" }),
    );
    harness.inject(&peer, "fork3", pdu).await;

    let before = Cases::read();
    let merged = harness.say(&room, &alice, "after").await;
    let delta = Cases::read().since(before);

    // The append is refused today. When #16 wires bounded resolution into
    // ingest this becomes an OK, and the assertion below is the one that
    // has to change -- deliberately, with the counter still moving.
    assert_ne!(
        merged,
        StatusCode::OK,
        "the same-slot fork was merged; #16 has landed and this test needs its other half"
    );
    assert_eq!(
        delta.contested, 1,
        "the expensive path was taken without being counted: {delta:?}"
    );

    // Refused is not corrupted: the room still reads, and still holds one of
    // the two topics rather than neither.
    let state = harness.state_ids(&room, &alice).await;
    assert!(
        state.contains_key("m.room.topic/"),
        "the refused merge lost the topic entirely: {state:?}"
    );
}

/// Disjoint slots that both already held a value: the case #225 got wrong.
///
/// The same fork as the test above — our branch writes the topic, theirs
/// writes the name — with one difference: both slots already had a value at
/// the fork point. Nothing is in conflict either way. Matrix's own state
/// resolution builds its conflicted set from events that differ from the
/// base, so a key only one branch moved is unconflicted there too.
///
/// `merge_states` used to disagree, because it unioned the parents' *full*
/// snapshots: the branch that left the topic alone still contributed the old
/// topic event, so the key had two candidates and read as contested. The
/// merge was refused — and, because every later local append names all
/// forward extremities, refused permanently. One ordinary concurrent edit
/// from a peer made the room unwritable for its local users, answering 500
/// forever with no way out.
///
/// Both halves are asserted: the merge succeeds *and* the room keeps
/// working afterwards, because the second is what made the first severe.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_disjoint_fork_on_preexisting_slots_merges_and_leaves_the_room_writable() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, _) = harness.shared_room(&peer).await;

    // The difference from the case that always worked: both slots hold a
    // value before the branches diverge.
    for (event_type, content) in [
        ("m.room.topic", json!({ "topic": "t0" })),
        ("m.room.name", json!({ "name": "n0" })),
    ] {
        assert_eq!(
            harness.set_state(&room, &alice, event_type, &content).await,
            StatusCode::OK
        );
    }
    let fork_point = harness.head_event(&room, &alice).await;

    assert_eq!(
        harness
            .set_state(&room, &alice, "m.room.topic", &json!({ "topic": "ours" }))
            .await,
        StatusCode::OK
    );
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.name",
        "",
        &json!({ "name": "theirs" }),
    );
    harness.inject(&peer, "disjoint", pdu).await;

    let before = Cases::read();
    let merged = harness.say(&room, &alice, "after").await;
    let delta = Cases::read().since(before);

    assert_eq!(merged, StatusCode::OK, "the disjoint fork was refused");
    assert_eq!(
        delta.contested, 0,
        "a fork with an empty conflicted set took the state-resolution path: {delta:?}"
    );

    // Both branches' writes survived. Taking either parent's state wholesale
    // would keep one and drop the other, and the counter above would still
    // read clean.
    let (_, topic) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
        )
        .await;
    let (_, name) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            &alice,
        )
        .await;
    assert_eq!(topic["topic"], json!("ours"), "our write was lost");
    assert_eq!(name["name"], json!("theirs"), "their write was lost");

    // The severe half: the room is still writable. Before the fix every one
    // of these was a 500, with no path back.
    for attempt in 0..3 {
        assert_eq!(
            harness.say(&room, &alice, &format!("retry{attempt}")).await,
            StatusCode::OK,
            "the room wedged on retry {attempt}"
        );
    }
    assert_eq!(
        harness
            .set_state(&room, &alice, "m.room.topic", &json!({ "topic": "later" }))
            .await,
        StatusCode::OK,
        "a state write after the merge was refused"
    );
}
