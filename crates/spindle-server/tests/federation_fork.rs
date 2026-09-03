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
//!
//! The later tests also read the result back the way a peer would: the
//! same peer signs `GET`s for federation's `/state`, `/state_ids` and
//! `/event`, and what those say must match what a client of this server
//! sees. That is the `/state_ids` agreement #16 asks for, and the first
//! time it was checked it failed -- the read answered with the linearly
//! previous entry's state, which after a fork is one branch's.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::{ForkCase, Metrics};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Serialises the tests in this binary.
///
/// The fork-case counters were process-global once, and a delta was only
/// attributable to one test while no other test was appending; each
/// harness has a registry of its own now (#174), so the counters no
/// longer need this. The two-instance peers below still bind real ports
/// and share the runtime's clock for their backoff, and one at a time
/// keeps their timing readable, so the lock stays.
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
    fn read(metrics: &Metrics) -> Self {
        Self {
            non_state: metrics.fork_case_count(ForkCase::NonState),
            uncontested: metrics.fork_case_count(ForkCase::StateUncontested),
            contested: metrics.fork_case_count(ForkCase::StateContested),
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

    /// Sign a GET the way `transaction_header` signs a PUT.
    ///
    /// A peer reading this server's federation state is authenticated too,
    /// and the reads below are the point of the interop tests: what a real
    /// Synapse would be told after a fork, not what a local client sees.
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

/// The `event_id` a client-API send answered with.
fn event_id_in(body: &Value) -> String {
    body["event_id"].as_str().unwrap_or_default().to_owned()
}

/// The ID of the one PDU a `/send` transaction carried.
fn injected_id(body: &Value) -> String {
    body["pdus"]
        .as_object()
        .and_then(|map| map.keys().next().cloned())
        .expect("the transaction response names the PDU")
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
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
        let app = spindle_server::app_with_metrics(config, store, Arc::clone(&metrics))
            .expect("the app builds");
        Self {
            _dir: dir,
            app,
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
    async fn admit(&self, room: &str, inviter: &str, username: &str) {
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
        self.put_state(room, token, event_type, content).await.0
    }

    /// Set one state event locally, and return its event ID with the status.
    async fn put_state(
        &self,
        room: &str,
        token: &str,
        event_type: &str,
        content: &Value,
    ) -> (StatusCode, String) {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}"),
                token,
                content,
            )
            .await;
        (status, event_id_in(&body))
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> StatusCode {
        self.send_message(room, token, text).await.0
    }

    /// Send a message locally, and return its event ID with the status.
    async fn send_message(&self, room: &str, token: &str, text: &str) -> (StatusCode, String) {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
                token,
                &json!({ "msgtype": "m.text", "body": text }),
            )
            .await;
        (status, event_id_in(&body))
    }

    /// A signed federation read by the peer, which must succeed.
    async fn peer_get(&self, peer: &Peer, uri: &str) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(uri)
                    .header("authorization", peer.get_header(uri))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        body
    }

    /// The state federation's `/state_ids` reports before `event_id`, as
    /// the peer would be told it.
    ///
    /// This is the assertion #16 asks for and no generic suite makes: after
    /// a scenario, `/state_ids` and the client's view of the room name the
    /// same set of events. For a message the state before it is the state
    /// after it, so asking at the merge event reads the merged state.
    async fn federation_state_ids(
        &self,
        peer: &Peer,
        room: &str,
        event_id: &str,
    ) -> std::collections::BTreeSet<String> {
        let uri = format!("/_matrix/federation/v1/state_ids/{room}?event_id={event_id}");
        let body = self.peer_get(peer, &uri).await;
        body["pdu_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect()
    }

    /// The slots federation's `/state` reports before `event_id`, keyed the
    /// way `state_ids` keys the client's view.
    async fn federation_state_keys(
        &self,
        peer: &Peer,
        room: &str,
        event_id: &str,
    ) -> std::collections::BTreeSet<String> {
        let uri = format!("/_matrix/federation/v1/state/{room}?event_id={event_id}");
        let body = self.peer_get(peer, &uri).await;
        body["pdus"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                format!(
                    "{}/{}",
                    event["type"].as_str().unwrap_or_default(),
                    event["state_key"].as_str().unwrap_or_default()
                )
            })
            .collect()
    }

    /// One event as federation serves it, with its signed `prev_events`.
    async fn federation_event(&self, peer: &Peer, event_id: &str) -> Value {
        let body = self
            .peer_get(peer, &format!("/_matrix/federation/v1/event/{event_id}"))
            .await;
        body["pdus"][0].clone()
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
    let before = Cases::read(&harness.metrics);
    assert_eq!(harness.say(&room, &alice, "after").await, StatusCode::OK);
    let delta = Cases::read(&harness.metrics).since(before);

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

    let before = Cases::read(&harness.metrics);
    assert_eq!(harness.say(&room, &alice, "after").await, StatusCode::OK);
    let delta = Cases::read(&harness.metrics).since(before);
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
/// This is the expensive case, and today it is not resolved: bounded
/// resolution exists in `spindle-core` but is not yet wired into ingest
/// (#16). What the server does instead is the subject of this test.
///
/// Before #225 the merge was refused, and because every later local append
/// named the same two extremities, refused *permanently*: one concurrent
/// edit from a peer made the room unwritable for every local user, with no
/// path out. The server must not wedge on a fork it cannot fold. It keeps
/// authoring on its linear head, sets the contested branch aside for the
/// resolver, and says so: the case-3 counter moves exactly once for the
/// fork -- not once per send while it stays open -- because §18.3's target
/// is meaningless if the expensive path can be taken without being counted,
/// and equally meaningless if one fork is counted as many.
///
/// What must hold either way: the room is not corrupted. Whichever branch
/// survives, the room still reads a consistent state and still holds one of
/// the two topics rather than neither.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_on_the_same_slot_is_counted_once_and_leaves_the_room_writable() {
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

    let before = Cases::read(&harness.metrics);
    let merged = harness.say(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

    // The severe half of #225: the send after a contested fork answered 500
    // (503 once the error was mapped), and so did every send after it.
    assert_eq!(
        merged,
        StatusCode::OK,
        "a contested fork wedged the room on the first send"
    );
    assert_eq!(
        delta.contested, 1,
        "the expensive path was taken without being counted: {delta:?}"
    );

    // The room stays writable, and the fork that is still open is not
    // counted again on every send that steps around it.
    let before = Cases::read(&harness.metrics);
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
        "a state write after the fork was refused"
    );
    let delta = Cases::read(&harness.metrics).since(before);
    assert_eq!(
        delta.contested, 0,
        "one open fork was counted again on later sends: {delta:?}"
    );

    // Set aside is not corrupted: the room still reads, and the last local
    // write is what it now holds.
    let (status, topic) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{topic}");
    assert_eq!(topic["topic"], json!("later"), "the topic after the fork");
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

    let before = Cases::read(&harness.metrics);
    let merged = harness.say(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

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

/// Both branches move the power levels: SPEC §9.2 case 3 on the slot whose
/// loss is worst.
///
/// The topic test above proves the same-slot fork is counted once and does
/// not wedge the room. Power levels are the slot every later authorization
/// reads, so this is the fork where "set aside" has to mean something more
/// precise than "still writable": which branch the room holds afterwards
/// decides who may write to it at all. #359's rule is that the linear head
/// stays -- the entry this server's order puts last, whose state
/// authorization already reads -- and the tip that contests it is set
/// aside. The peer's PDU is appended after our write, so the peer's power
/// levels are what the room now enforces, and both the client's view and
/// federation's must say so, or the two servers' disagreement (#16) would
/// be joined by a disagreement inside this one.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_on_the_power_levels_is_set_aside_and_the_head_decides_who_may_write() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    let levels = |charlie: u64| {
        json!({
            "users": {
                "@alice:example.org": 100,
                peer.user(): 100,
                "@charlie:example.org": charlie,
            },
            "users_default": 0,
            "state_default": 50,
            "events_default": 0,
        })
    };
    // Our branch promotes charlie.
    let (status, ours) = harness
        .put_state(&room, &alice, "m.room.power_levels", &levels(50))
        .await;
    assert_eq!(status, StatusCode::OK);
    // Theirs, from the same fork point, leaves charlie at zero.
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.power_levels",
        "",
        &levels(0),
    );
    let theirs = injected_id(&harness.inject(&peer, "fork_pl", pdu).await);

    let before = Cases::read(&harness.metrics);
    let (merged, merge) = harness.send_message(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

    assert_eq!(
        merged,
        StatusCode::OK,
        "a contested power-levels fork wedged the room"
    );
    assert_eq!(
        delta.contested, 1,
        "the expensive path was taken without being counted: {delta:?}"
    );

    // The head's branch is the one the room holds: theirs, because it was
    // appended last. Ours is set aside, not lost -- it stays a forward
    // extremity for the resolver -- but it is not what the room reads.
    let state = harness.state_ids(&room, &alice).await;
    assert_eq!(
        state.get("m.room.power_levels/"),
        Some(&theirs),
        "the room does not hold the linear head's power levels (ours: {ours})"
    );
    let (_, held) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.power_levels"),
            &alice,
        )
        .await;
    assert_eq!(held["users"]["@charlie:example.org"], json!(0), "{held}");

    // Federation tells the peer the same thing the client is told.
    let federation = harness.federation_state_ids(&peer, &room, &merge).await;
    assert_eq!(
        federation,
        state.values().cloned().collect(),
        "/state_ids disagrees with the client's view of the room"
    );

    // The room stays writable under the levels it holds, and the fork that
    // is still open is not counted again.
    let before = Cases::read(&harness.metrics);
    for attempt in 0..3 {
        assert_eq!(
            harness.say(&room, &alice, &format!("retry{attempt}")).await,
            StatusCode::OK,
            "the room wedged on retry {attempt}"
        );
    }
    assert_eq!(
        harness
            .set_state(&room, &alice, "m.room.power_levels", &levels(25))
            .await,
        StatusCode::OK,
        "a power-levels write after the fork was refused"
    );
    let delta = Cases::read(&harness.metrics).since(before);
    assert_eq!(
        delta.contested, 0,
        "one open fork was counted again on later sends: {delta:?}"
    );
}

/// Both branches move one user's membership: SPEC §9.2 case 3 on the slot
/// #16's scope names alongside power levels.
///
/// We kick charlie; the peer, from the same fork point, bans them. The
/// same rule as the power-levels test decides the outcome -- the peer's
/// ban is the linear head -- and the assertion that matters is that the
/// room *enforces* the membership it holds: a banned user cannot be
/// re-invited, so the invite that a kick would have allowed is refused.
/// A room that read one membership and enforced another would be the
/// inconsistency the set-aside rule exists to avoid.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_fork_on_one_membership_is_set_aside_and_the_head_is_what_is_enforced() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, _) = harness.shared_room(&peer).await;

    // Charlie is a member before the branches diverge, so both a kick and
    // a ban move the slot away from the value both branches inherited.
    harness.admit(&room, &alice, "charlie").await;
    let fork_point = harness.head_event(&room, &alice).await;

    // Ours: a kick.
    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            &alice,
            &json!({ "user_id": "@charlie:example.org" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Theirs, from the fork point: a ban.
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.member",
        "@charlie:example.org",
        &json!({ "membership": "ban" }),
    );
    let theirs = injected_id(&harness.inject(&peer, "fork_member", pdu).await);

    let before = Cases::read(&harness.metrics);
    let (merged, merge) = harness.send_message(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

    assert_eq!(
        merged,
        StatusCode::OK,
        "a contested membership fork wedged the room"
    );
    assert_eq!(
        delta.contested, 1,
        "the expensive path was taken without being counted: {delta:?}"
    );

    let state = harness.state_ids(&room, &alice).await;
    assert_eq!(
        state.get("m.room.member/@charlie:example.org"),
        Some(&theirs),
        "the room does not hold the linear head's membership"
    );
    let (_, held) = harness
        .get(
            &format!(
                "/_matrix/client/v3/rooms/{room}/state/m.room.member/%40charlie%3Aexample.org"
            ),
            &alice,
        )
        .await;
    assert_eq!(held["membership"], json!("ban"), "{held}");

    // Enforced, not merely read: the invite a kick would permit is refused
    // under the ban the room now holds.
    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": "@charlie:example.org" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the room reads a ban but does not enforce it: {body}"
    );

    let federation = harness.federation_state_ids(&peer, &room, &merge).await;
    assert_eq!(
        federation,
        state.values().cloned().collect(),
        "/state_ids disagrees with the client's view of the room"
    );

    let before = Cases::read(&harness.metrics);
    for attempt in 0..3 {
        assert_eq!(
            harness.say(&room, &alice, &format!("retry{attempt}")).await,
            StatusCode::OK,
            "the room wedged on retry {attempt}"
        );
    }
    let delta = Cases::read(&harness.metrics).since(before);
    assert_eq!(
        delta.contested, 0,
        "one open fork was counted again on later sends: {delta:?}"
    );
}

/// Each branch moves two slots the other left alone: SPEC §9.2 case 2,
/// wider than one write, and read back through every surface.
///
/// The single-slot disjoint tests above prove the merge is free. This one
/// is about agreement: after the merge, the client's `/state`, federation's
/// `/state` and federation's `/state_ids` must describe the same set of
/// events. `/state_ids` is the read #16 names -- it is what a peer compares
/// against its own view -- and the three are separate code paths, so a
/// merge that materialized one thing and served another would pass every
/// counter assertion in this file and still be wrong on the wire.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_disjoint_fork_over_several_slots_merges_and_every_state_read_agrees() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, fork_point) = harness.shared_room(&peer).await;

    // Ours: two slots, one after the other.
    let (status, our_topic) = harness
        .put_state(&room, &alice, "m.room.topic", &json!({ "topic": "ours" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, our_visibility) = harness
        .put_state(
            &room,
            &alice,
            "m.room.history_visibility",
            &json!({ "history_visibility": "joined" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Theirs: two other slots, the second building on the first, so the
    // peer's branch is two events deep like ours.
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &fork_point,
        "m.room.name",
        "",
        &json!({ "name": "theirs" }),
    );
    let their_name = injected_id(&harness.inject(&peer, "multi_name", pdu).await);
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &their_name,
        "m.room.join_rules",
        "",
        &json!({ "join_rule": "public" }),
    );
    let their_rules = injected_id(&harness.inject(&peer, "multi_rules", pdu).await);

    let before = Cases::read(&harness.metrics);
    let (merged, merge) = harness.send_message(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

    assert_eq!(merged, StatusCode::OK, "the disjoint fork was refused");
    assert_eq!(
        delta.contested, 0,
        "a disjoint fork took the state-resolution path: {delta:?}"
    );

    // All four writes survived, each as the event that made it.
    let state = harness.state_ids(&room, &alice).await;
    for (slot, expected) in [
        ("m.room.topic/", &our_topic),
        ("m.room.history_visibility/", &our_visibility),
        ("m.room.name/", &their_name),
        ("m.room.join_rules/", &their_rules),
    ] {
        assert_eq!(state.get(slot), Some(expected), "{slot} after the merge");
    }

    // The three state reads agree.
    let ids = harness.federation_state_ids(&peer, &room, &merge).await;
    assert_eq!(
        ids,
        state.values().cloned().collect(),
        "/state_ids disagrees with the client's view of the room"
    );
    let keys = harness.federation_state_keys(&peer, &room, &merge).await;
    assert_eq!(
        keys,
        state.keys().cloned().collect(),
        "federation's /state disagrees with the client's view of the room"
    );
}

/// A partition that heals: both servers keep going, then meet again.
///
/// The scenario #16 names by name. During the partition each side sets
/// state and sends a message on its own branch; the peer's branch arrives
/// in one go when the partition heals, and the next local send is the
/// event that names both branches. What is asserted is that it really
/// does -- its signed `prev_events` are the two branches' tips, read back
/// through federation rather than inferred from a counter -- and that the
/// state it leaves is one both the client and the peer's `/state_ids` read
/// identically, with nothing from either side of the partition lost.
#[tokio::test]
#[allow(
    clippy::await_holding_lock,
    reason = "serializing the tests is the job"
)]
async fn a_partition_heals_into_one_state_the_client_and_the_peer_read_alike() {
    let _guard = COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let peer = Peer::start().await;
    let harness = Harness::new();
    let (room, alice, partition_point) = harness.shared_room(&peer).await;

    // Our side of the partition: a state change and a message.
    let (status, our_topic) = harness
        .put_state(&room, &alice, "m.room.topic", &json!({ "topic": "ours" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, our_message) = harness.send_message(&room, &alice, "ours").await;
    assert_eq!(status, StatusCode::OK);

    // Theirs, delivered when the partition heals: a state change and a
    // message on top of it, both unaware of ours.
    let pdu = Harness::stale_state(
        &peer,
        &room,
        &partition_point,
        "m.room.name",
        "",
        &json!({ "name": "theirs" }),
    );
    let their_name = injected_id(&harness.inject(&peer, "heal_name", pdu).await);
    let pdu = Harness::stale_message(&peer, &room, &their_name, "theirs");
    let their_message = injected_id(&harness.inject(&peer, "heal_message", pdu).await);

    // The heal: the next local event names both branches.
    let before = Cases::read(&harness.metrics);
    let (merged, heal) = harness.send_message(&room, &alice, "after").await;
    let delta = Cases::read(&harness.metrics).since(before);

    assert_eq!(merged, StatusCode::OK, "the healed partition was refused");
    assert_eq!(
        delta.contested, 0,
        "healing a disjoint partition took the state-resolution path: {delta:?}"
    );
    let signed = harness.federation_event(&peer, &heal).await;
    let parents: std::collections::BTreeSet<String> = signed["prev_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        parents,
        [our_message.clone(), their_message.clone()].into(),
        "the heal event does not name both branches"
    );

    // One state, with both sides' writes, read alike by the client and by
    // the peer.
    let state = harness.state_ids(&room, &alice).await;
    assert_eq!(state.get("m.room.topic/"), Some(&our_topic), "our topic");
    assert_eq!(state.get("m.room.name/"), Some(&their_name), "their name");
    let federation = harness.federation_state_ids(&peer, &room, &heal).await;
    assert_eq!(
        federation,
        state.values().cloned().collect(),
        "/state_ids disagrees with the client's view of the room"
    );

    // And one timeline, with both sides' messages.
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
