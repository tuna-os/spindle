//! A pushed PDU whose predecessors cannot be recovered is accepted across
//! the gap on a peer's `/state_ids`, over sockets, with a signed mock peer:
//! when the gap is wider than the recovery budget, when the peer answers
//! `get_missing_events` with 429, and never when the state it serves is
//! forged.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::Pdu;
use spindle_server::metrics::{FetchKind, GapResult, Metrics, PduOutcome, RecoveryResult};
use spindle_server::{rooms::Rooms, signing::ServerKey};
use spindle_store::{FjallStore, RoomStore};
use tempfile::TempDir;

const ALICE: &str = "@alice:example.org";

fn canonical(value: &Value) -> ruma::CanonicalJsonObject {
    let CanonicalJsonValue::Object(object) = CanonicalJsonValue::try_from(value.clone()).unwrap()
    else {
        unreachable!()
    };
    object
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

/// What the mock peer serves, and what it was asked.
#[derive(Default)]
struct Served {
    bodies: BTreeMap<String, Value>,
    window: Vec<Value>,
    /// `get_missing_events` answers 429 while set.
    limit_missing: bool,
    /// The `/state_ids` answer for any event, or 404 when unset.
    state_ids: Option<Value>,
    calls: Vec<String>,
}

struct Peer {
    _dir: TempDir,
    name: String,
    key: Arc<ServerKey>,
    served: Arc<Mutex<Served>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Reply = (axum::http::StatusCode, axum::Json<Value>);

fn not_found() -> Reply {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(json!({"errcode":"M_NOT_FOUND","error":"not divulged"})),
    )
}

impl Peer {
    async fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let key = Arc::new(ServerKey::load_or_create(&store).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = listener.local_addr().unwrap().to_string();
        let mut document = canonical(
            &json!({"server_name":name,"valid_until_ts":now()+86_400_000,
            "verify_keys":{key.key_id():{"key":key.public_key_base64()}}}),
        );
        ruma::signatures::sign_json(&name, key.pair(), &mut document).unwrap();
        let document = serde_json::to_value(document).unwrap();
        let served: Arc<Mutex<Served>> = Arc::default();
        let app = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let document = document.clone();
                    async move { axum::Json(document) }
                }),
            )
            .route(
                "/_matrix/federation/v1/get_missing_events/{room}",
                axum::routing::post({
                    let served = Arc::clone(&served);
                    move || {
                        let mut served = served.lock().unwrap();
                        served.calls.push("missing".to_owned());
                        let reply: Reply = if served.limit_missing {
                            (
                                axum::http::StatusCode::TOO_MANY_REQUESTS,
                                axum::Json(json!({"errcode":"M_LIMIT_EXCEEDED",
                                    "error":"Too many duplicate requests","retry_after_ms":60_000})),
                            )
                        } else {
                            (
                                axum::http::StatusCode::OK,
                                axum::Json(json!({"events":served.window})),
                            )
                        };
                        async move { reply }
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/state_ids/{room}",
                axum::routing::get({
                    let served = Arc::clone(&served);
                    move || {
                        let mut served = served.lock().unwrap();
                        served.calls.push("state_ids".to_owned());
                        let reply = match &served.state_ids {
                            Some(answer) => (axum::http::StatusCode::OK, axum::Json(answer.clone())),
                            None => not_found(),
                        };
                        async move { reply }
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/event/{event}",
                axum::routing::get({
                    let served = Arc::clone(&served);
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        let mut served = served.lock().unwrap();
                        served.calls.push(format!("event:{id}"));
                        let reply = match served.bodies.get(&id) {
                            Some(body) => (
                                axum::http::StatusCode::OK,
                                axum::Json(json!({"pdus":[body]})),
                            ),
                            None => not_found(),
                        };
                        async move { reply }
                    }
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            _dir: dir,
            name,
            key,
            served,
            task,
        }
    }

    fn calls(&self, prefix: &str) -> usize {
        self.served
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|call| call.starts_with(prefix))
            .count()
    }

    fn serve(&self, event: &(String, Value)) {
        self.served
            .lock()
            .unwrap()
            .bodies
            .insert(event.0.clone(), event.1.clone());
    }

    fn transaction_header(&self, uri: &str, body: &Value) -> String {
        let mut object = canonical(
            &json!({"method":"PUT","uri":uri,"origin":self.name,"destination":"example.org","content":body}),
        );
        ruma::signatures::sign_json(&self.name, self.key.pair(), &mut object).unwrap();
        let signature = object["signatures"].as_object().unwrap()[&self.name]
            .as_object()
            .unwrap()[&self.key.key_id()]
            .as_str()
            .unwrap();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"{}\",sig=\"{signature}\"",
            self.name,
            self.key.key_id()
        )
    }
}

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    peer: Peer,
    metrics: Arc<Metrics>,
    room: String,
    version: RoomVersionId,
    /// The room's head as this server holds it: bob's join.
    head: (String, Value),
    /// The local state, by `(type, state_key)`.
    state: BTreeMap<(String, String), (String, Value)>,
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new(version: u8) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let key = ServerKey::load_or_create(store.as_ref()).unwrap();
        let peer = Peer::new().await;
        let local = Rooms::new(Arc::clone(&store), "example.org");
        let room = local
            .create(
                ALICE,
                key.pair(),
                None,
                None,
                Some("public_chat"),
                &[],
                &[],
                Some(&version.to_string()),
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        let remote = Rooms::new(Arc::clone(&store), peer.name.clone());
        let bob = format!("@bob:{}", peer.name);
        let joined = remote
            .set_membership(&room, &bob, &bob, "join", None, peer.key.pair())
            .unwrap();
        let head = (joined.clone(), remote.pdu(&room, &joined).unwrap());
        let state = remote
            .state(&room)
            .unwrap()
            .into_iter()
            .map(|event| {
                let id = event["event_id"].as_str().unwrap().to_owned();
                (
                    (
                        event["type"].as_str().unwrap().to_owned(),
                        event["state_key"].as_str().unwrap().to_owned(),
                    ),
                    (id.clone(), remote.pdu(&room, &id).unwrap()),
                )
            })
            .collect();
        let version = RoomVersionId::try_from(version.to_string()).unwrap();
        let metrics = Arc::new(Metrics::new());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n[federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n").unwrap();
        let app =
            spindle_server::app_with_metrics(config, Arc::clone(&store), Arc::clone(&metrics))
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            _dir: dir,
            store,
            peer,
            metrics,
            room,
            version,
            head,
            state,
            address,
            task,
        }
    }

    fn user(&self, name: &str) -> String {
        format!("@{name}:{}", self.peer.name)
    }

    fn held_state(&self, kind: &str, key: &str) -> (String, Value) {
        self.state[&(kind.to_owned(), key.to_owned())].clone()
    }

    fn edge(&self, event: &(String, Value)) -> Value {
        serde_json::to_value(
            spindle_core::version::edge(&event.0, &canonical(&event.1), &self.version).unwrap(),
        )
        .unwrap()
    }

    /// Sign an event from the peer, naming `prev` by ID and `auth` by event.
    #[allow(clippy::too_many_arguments, reason = "an event's fields")]
    fn event(
        &self,
        sender: &str,
        kind: &str,
        state_key: Option<&str>,
        content: &Value,
        depth: u64,
        prev: &[Value],
        auth: &[&(String, Value)],
    ) -> (String, Value) {
        let mut body = json!({"room_id":self.room,"sender":sender,"type":kind,
            "origin_server_ts":now(),"depth":depth,"prev_events":prev,
            "auth_events":auth.iter().map(|event| self.edge(event)).collect::<Vec<_>>(),
            "content":content});
        if let Some(state_key) = state_key {
            body["state_key"] = json!(state_key);
        }
        let event = Pdu::sign(
            self.version.clone(),
            canonical(&body),
            &self.peer.name,
            self.peer.key.pair(),
        )
        .unwrap();
        (
            event.event_id().as_str().to_owned(),
            serde_json::to_value(event.canonical()).unwrap(),
        )
    }

    /// Carol of the peer joins the public room after `parent`, in history
    /// this server has not seen.
    fn carol_joins(&self, parent: &(String, Value)) -> (String, Value) {
        let carol = self.user("carol");
        self.event(
            &carol,
            "m.room.member",
            Some(&carol),
            &json!({"membership":"join"}),
            parent.1["depth"].as_u64().unwrap() + 1,
            &[self.edge(parent)],
            &[
                &self.held_state("m.room.create", ""),
                &self.held_state("m.room.join_rules", ""),
                &self.held_state("m.room.power_levels", ""),
            ],
        )
    }

    fn message(
        &self,
        sender: &str,
        member: &(String, Value),
        parent: &(String, Value),
        label: &str,
    ) -> (String, Value) {
        self.event(
            sender,
            "m.room.message",
            None,
            &json!({"msgtype":"m.text","body":label}),
            parent.1["depth"].as_u64().unwrap() + 1,
            &[self.edge(parent)],
            &[
                &self.held_state("m.room.create", ""),
                &self.held_state("m.room.power_levels", ""),
                member,
            ],
        )
    }

    /// A `/state_ids` answer: this server's state, with `extra` added.
    fn state_ids(&self, extra: &[&(String, Value)]) -> Value {
        let mut ids: Vec<String> = self.state.values().map(|(id, _)| id.clone()).collect();
        ids.extend(extra.iter().map(|event| event.0.clone()));
        json!({"pdu_ids":ids,"auth_chain_ids":ids})
    }

    async fn push(&self, events: &[&(String, Value)]) -> Value {
        let uri = format!("/_matrix/federation/v1/send/gap-{}", now());
        let body = json!({"origin":self.peer.name,"origin_server_ts":now(),
            "pdus":events.iter().map(|event| event.1.clone()).collect::<Vec<_>>(),"edus":[]});
        let response = reqwest::Client::new()
            .put(format!("http://{}{uri}", self.address))
            .header("authorization", self.peer.transaction_header(&uri, &body))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    fn rooms(&self) -> Rooms {
        Rooms::new(Arc::clone(&self.store), "example.org")
    }

    fn held(&self, id: &str) -> bool {
        self.rooms().pdu(&self.room, id).is_ok()
    }

    fn in_timeline(&self, id: &str) -> bool {
        RoomStore::new(self.store.as_ref(), &self.room)
            .load()
            .unwrap()
            .unwrap()
            .log
            .get(&spindle_core::EventId::new(id))
            .is_some()
    }
}

/// (a) A gap wider than the recovery budget: the event is accepted on the
/// peer's state, reaches the timeline, and the room's state takes in the
/// member who joined inside the gap. The next event takes the ordinary path.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, asserted end to end")]
async fn a_gap_wider_than_the_recovery_budget_is_accepted_on_the_peers_state() {
    for version in [10, 11] {
        let harness = Harness::new(version).await;
        let bob = harness.user("bob");
        let carol = harness.user("carol");
        let bob_join = harness.head.clone();
        let carol_join = harness.carol_joins(&harness.head);
        harness.peer.serve(&carol_join);
        let mut parent = carol_join.clone();
        let mut history = Vec::new();
        for index in 0..600 {
            let message = harness.message(&bob, &bob_join, &parent, &format!("gap {index}"));
            harness.peer.serve(&message);
            history.push(message.clone());
            parent = message;
        }
        harness.peer.served.lock().unwrap().window = history[history.len() - 100..]
            .iter()
            .map(|event| event.1.clone())
            .collect();
        harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[&carol_join]));
        let latest = harness.message(&carol, &carol_join, &parent, "after the outage");

        let response = harness.push(&[&latest]).await;
        assert_eq!(
            response["pdus"][&latest.0],
            json!({}),
            "v{version}: {response}"
        );
        assert!(harness.in_timeline(&latest.0), "v{version}");
        assert!(
            !harness.in_timeline(&history[0].0),
            "v{version}: the gap's history is not invented"
        );
        assert!(
            harness.held(&carol_join.0) && !harness.in_timeline(&carol_join.0),
            "v{version}: the state event is retained outside the timeline"
        );

        let rooms = harness.rooms();
        let (page, _) = rooms.messages(&harness.room, None, 5).unwrap();
        assert!(
            page.iter().any(|event| event.event_id == latest.0),
            "v{version}: the event reads back in the timeline"
        );
        let state = rooms.state(&harness.room).unwrap();
        assert!(
            state.iter().any(|event| event["type"] == "m.room.member"
                && event["state_key"] == carol.as_str()
                && event["content"]["membership"] == "join"),
            "v{version}: the current state takes in the gap's join: {state:?}"
        );
        assert!(
            rooms
                .joined_members(&harness.room)
                .unwrap()
                .contains_key(&carol),
            "v{version}"
        );
        let extremities = RoomStore::new(harness.store.as_ref(), &harness.room)
            .load()
            .unwrap()
            .unwrap()
            .log
            .forward_extremities()
            .clone();
        assert!(
            extremities.contains(&spindle_core::EventId::new(bob_join.0.as_str()))
                && extremities.contains(&spindle_core::EventId::new(latest.0.as_str())),
            "v{version}: our head and the gap event are both extremities: {extremities:?}"
        );
        let gaps = rooms.federation_gaps(&harness.room).unwrap();
        assert_eq!(gaps.len(), 1, "v{version}: {gaps:?}");
        assert_eq!(gaps[0]["event_id"], latest.0.as_str());
        assert_eq!(gaps[0]["missing_prev_events"], json!([parent.0]));

        assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 1);
        assert_eq!(
            harness
                .metrics
                .recovery_count(RecoveryResult::BudgetExceeded),
            1
        );
        assert_eq!(harness.metrics.gap_count(GapResult::Accepted), 1);
        assert_eq!(harness.metrics.fetched_count(FetchKind::GapState), 1);
        assert!(harness.metrics.fetched_count(FetchKind::Predecessor) >= 512);

        // The next event names the gap event and takes the ordinary path.
        let state_ids = harness.peer.calls("state_ids");
        let missing = harness.peer.calls("missing");
        let next = harness.message(&carol, &carol_join, &latest, "and then");
        let response = harness.push(&[&next]).await;
        assert_eq!(
            response["pdus"][&next.0],
            json!({}),
            "v{version}: {response}"
        );
        assert!(harness.in_timeline(&next.0));
        assert_eq!(harness.peer.calls("state_ids"), state_ids);
        assert_eq!(harness.peer.calls("missing"), missing);
        assert_eq!(harness.metrics.pdu_count(PduOutcome::Accepted), 1);
        assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 1);
    }
}

/// (b) A peer answering `get_missing_events` with 429: one transaction of
/// PDUs that each need recovery asks once, and every PDU is still accepted
/// on the peer's state.
#[tokio::test]
async fn a_rate_limited_peer_is_asked_once_and_the_events_are_still_accepted() {
    let harness = Harness::new(10).await;
    let bob = harness.user("bob");
    let bob_join = harness.head.clone();
    harness.peer.served.lock().unwrap().limit_missing = true;
    harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[]));
    // Each names a different unseen predecessor, so none of them is placed
    // by an earlier one; each would recover on its own.
    let pushed: Vec<(String, Value)> = (0..5)
        .map(|index| {
            let hidden =
                harness.message(&bob, &bob_join, &harness.head, &format!("hidden {index}"));
            harness.message(&bob, &bob_join, &hidden, &format!("pushed {index}"))
        })
        .collect();
    let response = harness.push(&pushed.iter().collect::<Vec<_>>()).await;
    for event in &pushed {
        assert_eq!(response["pdus"][&event.0], json!({}), "{response}");
        assert!(harness.in_timeline(&event.0));
    }
    assert_eq!(
        harness.peer.calls("missing"),
        1,
        "a 429 is respected for the rest of the window"
    );
    assert_eq!(harness.peer.calls("state_ids"), 5);
    assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 5);
    assert_eq!(
        harness.metrics.recovery_count(RecoveryResult::RateLimited),
        5,
        "one 429, then four attempts skipped while the peer cools down"
    );
    assert_eq!(harness.metrics.gap_count(GapResult::Accepted), 5);
    assert_eq!(
        harness
            .rooms()
            .federation_gaps(&harness.room)
            .unwrap()
            .len(),
        5
    );
}

/// (c) A state event in the peer's `/state_ids` that is forged or unsigned
/// refuses the event: nothing the peer said is stored.
#[tokio::test]
async fn a_forged_or_unsigned_state_event_refuses_the_event() {
    for unsigned in [false, true] {
        let harness = Harness::new(10).await;
        let bob = harness.user("bob");
        let carol = harness.user("carol");
        let carol_join = harness.carol_joins(&harness.head);
        let mut forged = carol_join.1.clone();
        if unsigned {
            forged.as_object_mut().unwrap().remove("signatures");
        } else {
            forged["signatures"][&harness.peer.name][harness.peer.key.key_id()] = json!("invalid");
        }
        harness.peer.serve(&(carol_join.0.clone(), forged));
        let hidden = harness.message(&bob, &harness.head, &carol_join, "undivulged");
        harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[&carol_join]));
        let latest = harness.message(&carol, &carol_join, &hidden, "on a forged join");

        let response = harness.push(&[&latest]).await;
        assert!(
            response["pdus"][&latest.0]["error"].is_string(),
            "unsigned={unsigned}: {response}"
        );
        assert!(!harness.held(&latest.0) && !harness.held(&carol_join.0));
        assert!(
            harness
                .rooms()
                .federation_gaps(&harness.room)
                .unwrap()
                .is_empty()
        );
        assert_eq!(harness.metrics.gap_count(GapResult::Invalid), 1);
        assert_eq!(harness.metrics.pdu_count(PduOutcome::RefusedMissingDeps), 1);
        assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 0);
    }
}

/// The event itself is still judged: a sender the peer's state does not
/// admit is refused even when every state event checks out.
#[tokio::test]
async fn an_event_the_peers_state_does_not_admit_is_refused() {
    let harness = Harness::new(10).await;
    let bob = harness.user("bob");
    let carol = harness.user("carol");
    let carol_join = harness.carol_joins(&harness.head);
    harness.peer.serve(&carol_join);
    let hidden = harness.message(&bob, &harness.head, &carol_join, "undivulged");
    // The peer's state leaves carol out, so her message cites a join the
    // state before it does not hold.
    harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[]));
    let latest = harness.message(&carol, &carol_join, &hidden, "not a member here");
    let response = harness.push(&[&latest]).await;
    assert!(
        response["pdus"][&latest.0]["error"].is_string(),
        "{response}"
    );
    assert!(!harness.in_timeline(&latest.0));
    assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 0);
    assert_eq!(harness.metrics.pdu_count(PduOutcome::Rejected), 1);
}

/// (d) A small gap still recovers its full history and never asks for state.
#[tokio::test]
async fn a_gap_within_budget_recovers_history_without_state_ids() {
    let harness = Harness::new(10).await;
    let bob = harness.user("bob");
    let first = harness.message(&bob, &harness.head, &harness.head, "first");
    let second = harness.message(&bob, &harness.head, &first, "second");
    let latest = harness.message(&bob, &harness.head, &second, "latest");
    harness.peer.served.lock().unwrap().window = vec![second.1.clone(), first.1.clone()];
    harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[]));
    let response = harness.push(&[&latest]).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    for event in [&first, &second, &latest] {
        assert!(harness.in_timeline(&event.0));
    }
    assert_eq!(harness.peer.calls("state_ids"), 0);
    assert_eq!(harness.metrics.pdu_count(PduOutcome::Accepted), 1);
    assert_eq!(harness.metrics.recovery_count(RecoveryResult::Recovered), 1);
    assert_eq!(harness.metrics.fetched_count(FetchKind::Predecessor), 2);
    assert!(
        harness
            .rooms()
            .federation_gaps(&harness.room)
            .unwrap()
            .is_empty()
    );
}
