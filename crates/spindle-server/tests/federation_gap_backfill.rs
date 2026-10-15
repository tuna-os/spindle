//! A recorded federation gap is backfilled in the background, over
//! sockets, from a signed mock peer: the missing history lands between the
//! old head and the event accepted across the gap, `/messages` pages
//! through it in order and without duplicates, and it is never synced as
//! new, notified, or allowed to move the room's state. The walk resumes
//! after a restart, respects a peer's 429, refuses a forged chunk without
//! losing earlier progress, applies redactions the history carries, and
//! picks the servers most joined to the room first (#620).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::Pdu;
use spindle_server::metrics::{BackfillChunk, BackfillEvent, GapResult, Metrics, PduOutcome};
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
    /// Bodies `/backfill` serves instead of the real ones: a forgery.
    forged: BTreeMap<String, Value>,
    window: Vec<Value>,
    /// `get_missing_events` answers 429 while set, so recovery fails and
    /// the PDU is accepted across the gap whatever its width.
    limit_missing: bool,
    /// `/state_ids` for any event not in `state_ids_at`, or 404.
    state_ids: Option<Value>,
    state_ids_at: BTreeMap<String, Value>,
    /// `/backfill` answers 429 while set.
    limit_backfill: bool,
    /// `/backfill` answers this many pages, then 500 until reset.
    backfill_budget: Option<usize>,
    /// Events this peer will not serve -- what Synapse does with an event
    /// it rejected: left out of `/backfill` pages (whose walk still goes on
    /// through it) and 404 over `/event`.
    hidden: BTreeSet<String>,
    /// With `hidden`: the peer does not know those events at all, so a
    /// `/backfill` walk stops at them instead of going on through them.
    hidden_unknown: bool,
    calls: Vec<String>,
}

impl Served {
    /// `/backfill`: breadth-first back from `from` over `prev_events`,
    /// starting events included, deepest first -- what Synapse serves.
    fn backfill(&self, from: &[String], limit: usize) -> Vec<Value> {
        let mut queue: VecDeque<String> = from.iter().cloned().collect();
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        while let Some(id) = queue.pop_front() {
            if out.len() == limit || !seen.insert(id.clone()) {
                continue;
            }
            let Some(body) = self.forged.get(&id).or_else(|| self.bodies.get(&id)) else {
                continue;
            };
            let hidden = self.hidden.contains(&id);
            if hidden && self.hidden_unknown {
                continue;
            }
            for parent in body["prev_events"].as_array().into_iter().flatten() {
                if let Some(parent) = parent.as_str() {
                    queue.push_back(parent.to_owned());
                }
            }
            if !hidden {
                out.push(body.clone());
            }
        }
        out.sort_by_key(|body| std::cmp::Reverse(body["depth"].as_u64().unwrap_or(0)));
        out
    }
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
    #[allow(clippy::too_many_lines, reason = "one mock server's routes")]
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
                                    "error":"Too many duplicate requests"})),
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
                "/_matrix/federation/v1/backfill/{room}",
                axum::routing::get({
                    let served = Arc::clone(&served);
                    move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                        let mut served = served.lock().unwrap();
                        let mut from = Vec::new();
                        let mut limit = 100;
                        for (key, value) in
                            form_urlencoded::parse(query.unwrap_or_default().as_bytes())
                        {
                            match key.as_ref() {
                                "v" => from.push(value.into_owned()),
                                "limit" => limit = value.parse().unwrap(),
                                _ => {}
                            }
                        }
                        served.calls.push(format!("backfill:{}", from.join(",")));
                        let reply: Reply = if served.limit_backfill {
                            (
                                axum::http::StatusCode::TOO_MANY_REQUESTS,
                                axum::Json(json!({"errcode":"M_LIMIT_EXCEEDED",
                                    "error":"Too many requests","retry_after_ms":6_000})),
                            )
                        } else if served.backfill_budget == Some(0) {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(json!({"errcode":"M_UNKNOWN","error":"down"})),
                            )
                        } else {
                            if let Some(budget) = served.backfill_budget.as_mut() {
                                *budget -= 1;
                            }
                            (
                                axum::http::StatusCode::OK,
                                axum::Json(json!({"origin":"peer","origin_server_ts":now(),
                                    "pdus":served.backfill(&from, limit)})),
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
                    move |axum::extract::Query(query): axum::extract::Query<
                        HashMap<String, String>,
                    >| {
                        let mut served = served.lock().unwrap();
                        served.calls.push("state_ids".to_owned());
                        let at = query.get("event_id").cloned().unwrap_or_default();
                        let reply = match served.state_ids_at.get(&at).or(served.state_ids.as_ref())
                        {
                            Some(answer) => {
                                (axum::http::StatusCode::OK, axum::Json(answer.clone()))
                            }
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
                        let reply = match served
                            .bodies
                            .get(&id)
                            .filter(|_| !served.hidden.contains(&id))
                        {
                            None if served.hidden.contains(&id) => (
                                axum::http::StatusCode::NOT_FOUND,
                                axum::Json(json!({"errcode":"M_NOT_FOUND",
                                    "error":"Could not find event"})),
                            ),
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

/// How the app under test is configured.
#[derive(Clone, Copy)]
struct Setup {
    backfill: bool,
    per_room: usize,
    idle_ms: u64,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            backfill: true,
            per_room: 10,
            idle_ms: 50,
        }
    }
}

/// A fresh app over `store`, serving on a socket of its own, with the
/// backfill loop paced for a test.
async fn serve(
    store: &Arc<FjallStore>,
    metrics: &Arc<Metrics>,
    setup: Setup,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
         [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
         gap_backfill = {}\ngap_backfill_interval_ms = 5\ngap_backfill_idle_ms = {}\n\
         gap_backfill_retry_ms = 50\ngap_acceptances_per_room = {}\n",
        setup.backfill, setup.idle_ms, setup.per_room
    ))
    .unwrap();
    let app =
        spindle_server::app_with_metrics(config, Arc::clone(store), Arc::clone(metrics)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, task)
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

/// A gap's history as the peer holds it: carol joins, then bob talks.
struct History {
    bob_join: (String, Value),
    carol_join: (String, Value),
    /// Oldest first.
    messages: Vec<(String, Value)>,
}

impl Harness {
    async fn new(setup: Setup) -> Self {
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
                Some("10"),
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
        let state: BTreeMap<(String, String), (String, Value)> = remote
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
        // The peer holds the room's history too: a `/backfill` that walks
        // into it hands back events this server already has, which the
        // walk must stop at rather than store again.
        for event in state.values() {
            peer.serve(event);
        }
        let metrics = Arc::new(Metrics::new());
        let (address, task) = serve(&store, &metrics, setup).await;
        Self {
            _dir: dir,
            store,
            peer,
            metrics,
            room,
            version: RoomVersionId::V10,
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

    /// Bob redacts `target`, after `parent`.
    fn redaction(
        &self,
        member: &(String, Value),
        parent: &(String, Value),
        target: &str,
    ) -> (String, Value) {
        let mut event = self.event(
            &self.user("bob"),
            "m.room.redaction",
            None,
            &json!({}),
            parent.1["depth"].as_u64().unwrap() + 1,
            &[self.edge(parent)],
            &[
                &self.held_state("m.room.create", ""),
                &self.held_state("m.room.power_levels", ""),
                member,
            ],
        );
        // Re-sign with the v10 top-level `redacts`.
        let mut body = event.1.clone();
        let object = body.as_object_mut().unwrap();
        object.remove("signatures");
        object.remove("hashes");
        object.remove("unsigned");
        object.insert("redacts".to_owned(), json!(target));
        let signed = Pdu::sign(
            self.version.clone(),
            canonical(&body),
            &self.peer.name,
            self.peer.key.pair(),
        )
        .unwrap();
        event = (
            signed.event_id().as_str().to_owned(),
            serde_json::to_value(signed.canonical()).unwrap(),
        );
        event
    }

    /// `/state_ids` with this server's state and `extra`.
    fn state_ids(&self, extra: &[&(String, Value)]) -> Value {
        let mut ids: Vec<String> = self.state.values().map(|(id, _)| id.clone()).collect();
        ids.extend(extra.iter().map(|event| event.0.clone()));
        json!({"pdu_ids":ids,"auth_chain_ids":ids})
    }

    /// Carol joins and bob sends `count` messages, all unseen here, and
    /// the peer serves all of it: bodies, the recovery window, and the
    /// state at every point of it.
    fn history(&self, count: usize) -> History {
        let bob = self.user("bob");
        let bob_join = self.head.clone();
        let carol_join = self.carol_joins(&self.head);
        self.peer.serve(&carol_join);
        let mut parent = carol_join.clone();
        let mut messages = Vec::new();
        for index in 0..count {
            let message = self.message(&bob, &bob_join, &parent, &format!("gap {index} alice"));
            self.peer.serve(&message);
            messages.push(message.clone());
            parent = message;
        }
        let mut served = self.peer.served.lock().unwrap();
        served.limit_missing = true;
        served.state_ids = Some(self.state_ids(&[&carol_join]));
        served
            .state_ids_at
            .insert(carol_join.0.clone(), self.state_ids(&[]));
        drop(served);
        History {
            bob_join,
            carol_join,
            messages,
        }
    }

    async fn push(&self, events: &[&(String, Value)]) -> Value {
        let uri = format!("/_matrix/federation/v1/send/gap-{}-{}", now(), events[0].0);
        let uri = uri.replace('$', "");
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

    async fn restart(&mut self, setup: Setup) {
        self.task.abort();
        let _ = (&mut self.task).await;
        self.metrics = Arc::new(Metrics::new());
        let (address, task) = serve(&self.store, &self.metrics, setup).await;
        self.address = address;
        self.task = task;
    }

    async fn client(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Value {
        let request = reqwest::Client::new().request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("http://{}{path}", self.address),
        );
        let request = if token.is_empty() {
            request
        } else {
            request.header("authorization", format!("Bearer {token}"))
        };
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(body.to_string()),
            None => request,
        };
        let response = request.send().await.unwrap();
        let status = response.status();
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert!(status.is_success(), "{method} {path}: {status} {body}");
        body
    }

    async fn login_alice(&self) -> String {
        self.client(
            "POST",
            "/_matrix/client/v3/register",
            "",
            Some(json!({"username":"alice","password":"hunter2",
                "auth":{"type":"m.login.dummy","session":"register"}})),
        )
        .await["access_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn rooms(&self) -> Rooms {
        Rooms::new(Arc::clone(&self.store), "example.org")
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

    fn gaps(&self) -> Vec<Value> {
        self.rooms().federation_gaps(&self.room).unwrap()
    }

    /// The gap is closed and the loop has counted the chunk that closed it
    /// (the marker goes inside the write, the metrics just after it).
    fn filled(&self) -> bool {
        self.gaps().is_empty() && self.metrics.backfill_chunk_count(BackfillChunk::Completed) >= 1
    }

    /// Wait for `done`, polling; panics with `what` after `seconds`.
    async fn until(&self, seconds: u64, what: &str, done: impl Fn(&Self) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
        while !done(self) {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Every event `/messages` returns walking back from the head,
    /// `limit` at a time, with the `end` token of each page.
    async fn page_back(&self, token: &str, limit: usize) -> (Vec<String>, Vec<String>) {
        let mut ids = Vec::new();
        let mut tokens = Vec::new();
        let mut from: Option<String> = None;
        loop {
            let path = match &from {
                Some(from) => format!(
                    "/_matrix/client/v3/rooms/{}/messages?dir=b&limit={limit}&from={from}",
                    self.room
                ),
                None => format!(
                    "/_matrix/client/v3/rooms/{}/messages?dir=b&limit={limit}",
                    self.room
                ),
            };
            let page = self.client("GET", &path, token, None).await;
            for event in page["chunk"].as_array().unwrap() {
                ids.push(event["event_id"].as_str().unwrap().to_owned());
            }
            match page["end"].as_str() {
                Some(end) => {
                    tokens.push(end.to_owned());
                    from = Some(end.to_owned());
                }
                None => return (ids, tokens),
            }
            assert!(ids.len() < 10_000, "pagination does not end");
        }
    }
}

/// Accept `latest` across the gap `history` leaves and return the gap
/// event's linear index.
async fn accept_gap(harness: &Harness, latest: &(String, Value)) -> i64 {
    let response = harness.push(&[latest]).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 1);
    assert!(harness.in_timeline(&latest.0));
    RoomStore::new(harness.store.as_ref(), &harness.room)
        .load()
        .unwrap()
        .unwrap()
        .log
        .get(&spindle_core::EventId::new(latest.0.as_str()))
        .unwrap()
        .li
        .get()
}

/// The room's timeline as `/messages` must page it once the gap is
/// filled, newest first: the gap event, the gap's history, then what this
/// server held before.
fn expected_order(harness: &Harness, history: &History, latest: &(String, Value)) -> Vec<String> {
    let mut expected = vec![latest.0.clone()];
    expected.extend(history.messages.iter().rev().map(|event| event.0.clone()));
    expected.push(history.carol_join.0.clone());
    expected.push(history.bob_join.0.clone());
    let held = RoomStore::new(harness.store.as_ref(), &harness.room)
        .load()
        .unwrap()
        .unwrap()
        .log;
    let older: Vec<String> = held
        .entries()
        .rev()
        .map(|entry| entry.event_id.as_str().to_owned())
        .filter(|id| *id != latest.0 && *id != history.bob_join.0)
        .collect();
    expected.extend(older);
    expected
}

/// A 600-message gap fills in the background; `/messages` then pages from
/// the gap event back through the whole of it to the old head, in order
/// and with nothing twice, forward paging agrees, `/context` serves a
/// backfilled event with its state, and nothing of it was synced as new,
/// notified, or allowed to move the room's state.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one scenario, asserted end to end")]
async fn a_recorded_gap_is_backfilled_and_pages_contiguously() {
    let harness = Harness::new(Setup::default()).await;
    let history = harness.history(600);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    let token = harness.login_alice().await;
    let sync = harness
        .client("GET", "/_matrix/client/v3/sync", &token, None)
        .await;
    let since = sync["next_batch"].as_str().unwrap().to_owned();

    let anchor = accept_gap(&harness, &latest).await;
    let state_after_gap: BTreeSet<String> = harness
        .rooms()
        .state(&harness.room)
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect();
    let sync = harness
        .client(
            "GET",
            &format!("/_matrix/client/v3/sync?since={since}&timeout=0"),
            &token,
            None,
        )
        .await;
    let since = sync["next_batch"].as_str().unwrap().to_owned();

    harness
        .until(60, "the gap is backfilled", Harness::filled)
        .await;

    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        601,
        "carol's join and every message"
    );
    assert_eq!(
        harness
            .metrics
            .backfill_event_count(BackfillEvent::Inserted),
        601
    );
    assert_eq!(
        harness
            .metrics
            .backfill_event_count(BackfillEvent::Rejected),
        0
    );
    assert_eq!(
        harness
            .metrics
            .backfill_chunk_count(BackfillChunk::Completed),
        1
    );
    assert!(harness.metrics.backfill_chunk_count(BackfillChunk::Filled) >= 6);
    assert_eq!(harness.metrics.gaps_remaining(), 0);
    // SPEC §6.5: one /state_ids per chunk, plus the gap acceptance's own.
    let chunks = harness.metrics.backfill_chunk_count(BackfillChunk::Filled)
        + harness
            .metrics
            .backfill_chunk_count(BackfillChunk::Completed);
    assert_eq!(
        u64::try_from(harness.peer.calls("state_ids")).unwrap(),
        chunks + 1
    );
    for event in &history.messages {
        assert!(
            !harness.in_timeline(&event.0),
            "history stays out of the log"
        );
    }

    // (1) Backward pagination: the whole room, in order, once each.
    let expected = expected_order(&harness, &history, &latest);
    for limit in [7, 50, 100] {
        let (ids, _) = harness.page_back(&token, limit).await;
        let unique: HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "limit {limit}: no duplicates");
        assert_eq!(ids, expected, "limit {limit}: the stitched order");
    }

    // (2) Forward from a token inside the segment: the events above it,
    // oldest first.
    let (ids, tokens) = harness.page_back(&token, 50).await;
    let inside = &tokens[5];
    let page = harness
        .client(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{}/messages?dir=f&limit=20&from={inside}",
                harness.room
            ),
            &token,
            None,
        )
        .await;
    let forward: Vec<&str> = page["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap())
        .collect();
    let above: Vec<&str> = ids[280..300].iter().rev().map(String::as_str).collect();
    assert_eq!(forward, above, "a forward page from inside the segment");
    // And back from that forward page's end: the same events, newest first.
    let end = page["end"].as_str().unwrap();
    let back = harness
        .client(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{}/messages?dir=b&limit=20&from={end}",
                harness.room
            ),
            &token,
            None,
        )
        .await;
    let back: Vec<&str> = back["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        back,
        ids[280..300].iter().map(String::as_str).collect::<Vec<_>>()
    );

    // (3) /context on a backfilled event: its neighbours and its state.
    let middle = &history.messages[300].0;
    let context = harness
        .client(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{}/context/{middle}?limit=10",
                harness.room
            ),
            &token,
            None,
        )
        .await;
    let ids_of = |field: &str| -> Vec<String> {
        context[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["event_id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        ids_of("events_before"),
        (295..300)
            .rev()
            .map(|index| history.messages[index].0.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        ids_of("events_after"),
        (301..306)
            .map(|index| history.messages[index].0.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        context["state"].as_array().unwrap().iter().any(|event| {
            event["type"] == "m.room.member" && event["state_key"] == carol.as_str()
        }),
        "the state at a backfilled event: {}",
        context["state"]
    );
    let event = harness
        .client(
            "GET",
            &format!("/_matrix/client/v3/rooms/{}/event/{middle}", harness.room),
            &token,
            None,
        )
        .await;
    assert_eq!(event["content"]["body"], "gap 300 alice");

    // (4) Nothing moved: not the state, not the sync stream, no pushes.
    let state_now: BTreeSet<String> = harness
        .rooms()
        .state(&harness.room)
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        state_now, state_after_gap,
        "backfill leaves the state alone"
    );
    let sync = harness
        .client(
            "GET",
            &format!("/_matrix/client/v3/sync?since={since}&timeout=0"),
            &token,
            None,
        )
        .await;
    let timeline = sync["rooms"]["join"][&harness.room]["timeline"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(timeline.is_empty(), "backfill is not synced as new: {sync}");
    let notifications = harness
        .client("GET", "/_matrix/client/v3/notifications", &token, None)
        .await;
    let gap_ids: HashSet<&str> = history.messages.iter().map(|e| e.0.as_str()).collect();
    assert!(
        !notifications["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| gap_ids.contains(n["event"]["event_id"].as_str().unwrap_or_default())),
        "backfill notifies nobody: {notifications}"
    );
}

/// A restart mid-backfill resumes from the last stored chunk: nothing is
/// fetched or stored twice, and the result pages exactly as an
/// uninterrupted fill does.
#[tokio::test]
async fn a_backfill_resumes_after_a_restart() {
    let mut harness = Harness::new(Setup::default()).await;
    let history = harness.history(350);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    harness.peer.served.lock().unwrap().backfill_budget = Some(2);
    let anchor = accept_gap(&harness, &latest).await;
    harness
        .until(30, "two chunks, then failures", |harness| {
            harness.gaps().first().is_some_and(|marker| {
                marker["backfill"]["filled"] == 200
                    && marker["backfill"]["attempts"].as_u64() > Some(0)
            })
        })
        .await;
    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        200
    );
    assert!(
        harness
            .metrics
            .backfill_chunk_count(BackfillChunk::PeerError)
            >= 1
    );

    harness.restart(Setup::default()).await;
    harness.peer.served.lock().unwrap().backfill_budget = None;
    harness
        .until(
            30,
            "the gap is backfilled after the restart",
            Harness::filled,
        )
        .await;
    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        351
    );
    assert_eq!(
        harness
            .metrics
            .backfill_event_count(BackfillEvent::Inserted),
        151,
        "only what the first run had not stored"
    );
    let token = harness.login_alice().await;
    let (ids, _) = harness.page_back(&token, 40).await;
    assert_eq!(ids, expected_order(&harness, &history, &latest));
}

/// A peer answering `/backfill` with 429 is left alone for the room until
/// its cooldown ends; then the gap fills.
#[tokio::test]
async fn a_rate_limited_peer_is_left_alone_until_its_cooldown_ends() {
    let harness = Harness::new(Setup::default()).await;
    let history = harness.history(150);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    harness.peer.served.lock().unwrap().limit_backfill = true;
    accept_gap(&harness, &latest).await;
    harness
        .until(10, "a 429", |harness| {
            harness
                .metrics
                .backfill_chunk_count(BackfillChunk::RateLimited)
                >= 2
        })
        .await;
    // Retries kept coming (every 50ms, doubling), and none of them asked.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        harness.peer.calls("backfill"),
        1,
        "one request, then the cooldown"
    );
    assert_eq!(harness.gaps().len(), 1);

    harness.peer.served.lock().unwrap().limit_backfill = false;
    harness
        .until(30, "the gap fills once the cooldown ends", Harness::filled)
        .await;
    assert_eq!(
        harness
            .metrics
            .backfill_event_count(BackfillEvent::Inserted),
        151
    );
    assert!(harness.peer.calls("backfill") >= 3);
}

/// A forged event in a chunk refuses the chunk: nothing of it is stored,
/// what earlier chunks stored is untouched, and once the peer serves the
/// real event the gap fills.
#[tokio::test]
async fn a_forged_event_refuses_its_chunk_and_keeps_earlier_progress() {
    let harness = Harness::new(Setup::default()).await;
    let history = harness.history(150);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    // Message 20 is in the second chunk (the first is 149..=50).
    let target = history.messages[20].clone();
    let mut forged = target.1.clone();
    forged["signatures"][&harness.peer.name][harness.peer.key.key_id()] = json!("forged");
    harness
        .peer
        .served
        .lock()
        .unwrap()
        .forged
        .insert(target.0.clone(), forged);
    let anchor = accept_gap(&harness, &latest).await;
    harness
        .until(30, "the forged chunk is refused, twice", |harness| {
            harness.metrics.backfill_chunk_count(BackfillChunk::Invalid) >= 2
        })
        .await;
    let marker = harness.gaps()[0].clone();
    assert_eq!(marker["backfill"]["filled"], 100, "{marker}");
    assert_eq!(
        marker["backfill"]["frontier"],
        json!([history.messages[49].0]),
        "the frontier is where the first chunk left it"
    );
    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        100
    );
    assert!(
        harness.rooms().pdu(&harness.room, &target.0).is_err(),
        "nothing of the forged chunk is stored"
    );
    assert!(
        harness
            .rooms()
            .pdu(&harness.room, &history.messages[49].0)
            .is_err()
    );

    harness.peer.served.lock().unwrap().forged.clear();
    harness
        .until(30, "the gap fills from the real events", Harness::filled)
        .await;
    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        151
    );
    let token = harness.login_alice().await;
    let (ids, _) = harness.page_back(&token, 60).await;
    assert_eq!(ids, expected_order(&harness, &history, &latest));
    let body = harness.rooms().event(&harness.room, &target.0).unwrap();
    assert_eq!(body["content"]["body"], "gap 20 alice");
}

/// Redactions apply to backfilled history as they would have live: one
/// inside the gap rewrites its target, and one that arrived live before
/// its target was backfilled is applied when the target arrives.
#[tokio::test]
async fn redactions_apply_to_backfilled_history() {
    let mut harness = Harness::new(Setup {
        backfill: false,
        ..Setup::default()
    })
    .await;
    let bob = harness.user("bob");
    let history = harness.history(30);
    // Inside the gap: bob redacts message 3.
    let in_gap = harness.redaction(
        &history.bob_join,
        history.messages.last().unwrap(),
        &history.messages[3].0,
    );
    harness.peer.serve(&in_gap);
    let carol = harness.user("carol");
    let latest = harness.message(&carol, &history.carol_join, &in_gap, "after the outage");
    accept_gap(&harness, &latest).await;
    // Live, before backfill: bob redacts message 7, which is not held yet.
    let live = harness.redaction(&history.bob_join, &latest, &history.messages[7].0);
    let response = harness.push(&[&live]).await;
    assert_eq!(response["pdus"][&live.0], json!({}), "{response}");
    assert!(harness.in_timeline(&live.0));

    harness.restart(Setup::default()).await;
    harness
        .until(30, "the gap is backfilled", Harness::filled)
        .await;
    let rooms = harness.rooms();
    for (index, by) in [(3, &in_gap.0), (7, &live.0)] {
        let event = rooms
            .event(&harness.room, &history.messages[index].0)
            .unwrap();
        assert!(event["content"].as_object().unwrap().is_empty(), "{event}");
        assert_eq!(
            event["unsigned"]["redacted_because"]["event_id"],
            by.as_str()
        );
    }
    let untouched = rooms.event(&harness.room, &history.messages[4].0).unwrap();
    assert_eq!(untouched["content"]["body"], "gap 4 alice");
    assert_eq!(untouched["sender"], bob.as_str());
}

/// #620: the servers asked about a room are the ones with members joined
/// to it, most-joined first -- not invited ones, not ones whose users all
/// left, and not alphabetical.
#[tokio::test]
async fn participating_servers_are_ranked_by_joined_members() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = ServerKey::load_or_create(store.as_ref()).unwrap();
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
            Some("10"),
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap();
    let pair = || {
        let document = ruma::signatures::Ed25519KeyPair::generate();
        ruma::signatures::Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap()
    };
    // a.example: one joined. fedora.example: two joined, both leave.
    // m.example: two joined. z.example: three joined. b.example: invited.
    for (domain, joined, leave) in [
        ("a.example", 1, false),
        ("fedora.example", 2, true),
        ("m.example", 2, false),
        ("z.example", 3, false),
    ] {
        let remote = Rooms::new(Arc::clone(&store), domain);
        let key = pair();
        for index in 0..joined {
            let user = format!("@user{index}:{domain}");
            remote
                .set_membership(&room, &user, &user, "join", None, &key)
                .unwrap();
            if leave {
                remote
                    .set_membership(&room, &user, &user, "leave", None, &key)
                    .unwrap();
            }
        }
    }
    Rooms::new(Arc::clone(&store), "example.org")
        .set_membership(&room, ALICE, "@guest:b.example", "invite", None, key.pair())
        .unwrap();
    let ranked = Rooms::new(Arc::clone(&store), "example.org")
        .participating_servers(&room)
        .unwrap();
    assert_eq!(ranked, vec!["z.example", "m.example", "a.example"]);
}

/// The amplification guard: a room gets only so many gap acceptances per
/// window, and the rest are refused as they were before gap acceptance.
#[tokio::test]
async fn gap_acceptances_are_capped_per_room() {
    let harness = Harness::new(Setup {
        backfill: false,
        per_room: 2,
        ..Setup::default()
    })
    .await;
    let bob = harness.user("bob");
    let bob_join = harness.head.clone();
    harness.peer.served.lock().unwrap().state_ids = Some(harness.state_ids(&[]));
    let pushed: Vec<(String, Value)> = (0..4)
        .map(|index| {
            let hidden =
                harness.message(&bob, &bob_join, &harness.head, &format!("hidden {index}"));
            harness.message(&bob, &bob_join, &hidden, &format!("pushed {index}"))
        })
        .collect();
    for event in &pushed {
        harness.push(&[event]).await;
    }
    assert_eq!(harness.metrics.pdu_count(PduOutcome::GapAccepted), 2);
    assert_eq!(harness.metrics.gap_count(GapResult::CappedRoom), 2);
    assert_eq!(harness.metrics.pdu_count(PduOutcome::RefusedMissingDeps), 2);
    assert_eq!(harness.gaps().len(), 2);
}

/// A client paging back into a room with an open gap wakes an idle
/// backfill loop and puts that room first; the page itself does not wait.
#[tokio::test]
async fn paging_into_an_open_gap_wakes_the_backfill() {
    let harness = Harness::new(Setup {
        idle_ms: 600_000,
        ..Setup::default()
    })
    .await;
    let history = harness.history(120);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    let token = harness.login_alice().await;
    // Let the loop's first pass find nothing and go idle.
    tokio::time::sleep(Duration::from_millis(200)).await;
    accept_gap(&harness, &latest).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(harness.peer.calls("backfill"), 0, "the loop is idle");
    assert_eq!(harness.gaps().len(), 1);

    let page = harness
        .client(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{}/messages?dir=b&limit=5",
                harness.room
            ),
            &token,
            None,
        )
        .await;
    assert_eq!(page["chunk"][0]["event_id"], latest.0.as_str());
    harness
        .until(30, "the poked room is backfilled", Harness::filled)
        .await;
    let (ids, _) = harness.page_back(&token, 100).await;
    assert_eq!(ids, expected_order(&harness, &history, &latest));

    // A history purge up to the gap event takes the segment's message
    // bodies with it, and keeps its state events, as it does the log's.
    assert!(
        spindle_server::accounts::Accounts::new(harness.store.as_ref(), "example.org")
            .set_admin("alice", true)
            .unwrap()
    );
    let anchor = RoomStore::new(harness.store.as_ref(), &harness.room)
        .load()
        .unwrap()
        .unwrap()
        .log
        .get(&spindle_core::EventId::new(latest.0.as_str()))
        .unwrap()
        .li
        .get();
    let purged = harness
        .client(
            "POST",
            &format!("/_spindle/admin/v1/rooms/{}/purge_history", harness.room),
            &token,
            Some(json!({ "before_li": anchor })),
        )
        .await;
    assert!(purged["events_purged"].as_u64().unwrap() >= 120, "{purged}");
    let rooms = harness.rooms();
    assert!(rooms.pdu(&harness.room, &history.messages[60].0).is_err());
    assert!(rooms.pdu(&harness.room, &history.carol_join.0).is_ok());
    assert!(rooms.pdu(&harness.room, &latest.0).is_ok());
    let (after, _) = harness.page_back(&token, 100).await;
    assert_eq!(after, ids, "purged events keep their place as markers");
}

/// The calls the peer saw with `prefix`, for asserting none repeats.
fn calls_of(harness: &Harness, prefix: &str) -> Vec<String> {
    harness
        .peer
        .served
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|call| call.starts_with(prefix))
        .cloned()
        .collect()
}

/// Production, 2026-10-08: the walk reached an event no participating
/// server would serve -- left out of `/backfill` (as Synapse leaves out an
/// event it rejected) and 404 over `/event` -- and every later chunk asked
/// the same question again until the peers answered 429 "Too many
/// duplicate requests". Now the walk steps over that event onto what the
/// page held below it, finishes the gap, and never asks a peer the same
/// question twice.
#[tokio::test]
async fn an_event_no_peer_serves_is_stepped_over_without_repeating_requests() {
    let harness = Harness::new(Setup::default()).await;
    let history = harness.history(250);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    let unserved = history.messages[120].0.clone();
    harness
        .peer
        .served
        .lock()
        .unwrap()
        .hidden
        .insert(unserved.clone());
    let anchor = accept_gap(&harness, &latest).await;
    harness
        .until(
            30,
            "the gap is backfilled past the unserved event",
            Harness::filled,
        )
        .await;

    assert_eq!(
        harness
            .rooms()
            .gap_segment_len(&harness.room, anchor)
            .unwrap(),
        250,
        "everything but the one event nobody serves"
    );
    assert_eq!(
        harness.metrics.backfill_event_count(BackfillEvent::Skipped),
        1
    );
    let backfills = calls_of(&harness, "backfill:");
    let distinct: HashSet<&String> = backfills.iter().collect();
    assert_eq!(
        distinct.len(),
        backfills.len(),
        "a repeated request: {backfills:?}"
    );
    assert_eq!(
        calls_of(&harness, &format!("event:{unserved}")).len(),
        1,
        "the unserved event is asked for once"
    );

    let token = harness.login_alice().await;
    let (ids, _) = harness.page_back(&token, 50).await;
    let expected: Vec<String> = expected_order(&harness, &history, &latest)
        .into_iter()
        .filter(|id| *id != unserved)
        .collect();
    assert_eq!(ids, expected);
}

/// A peer that has nothing at all for the frontier -- an empty page and a
/// 404 -- is not asked the same question again while the gap backs off:
/// one request, then silence, and the gap stays open for a later answer.
#[tokio::test]
async fn a_peer_with_nothing_for_the_frontier_is_not_asked_again() {
    let harness = Harness::new(Setup::default()).await;
    let history = harness.history(150);
    let carol = harness.user("carol");
    let latest = harness.message(
        &carol,
        &history.carol_join,
        history.messages.last().unwrap(),
        "after the outage",
    );
    let unknown = history.messages[100].0.clone();
    {
        let mut served = harness.peer.served.lock().unwrap();
        served.hidden.insert(unknown.clone());
        served.hidden_unknown = true;
    }
    accept_gap(&harness, &latest).await;
    harness
        .until(30, "the stuck frontier fails a few times", |harness| {
            harness
                .gaps()
                .first()
                .is_some_and(|marker| marker["backfill"]["attempts"].as_u64() >= Some(4))
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let marker = harness.gaps()[0].clone();
    assert_eq!(marker["backfill"]["frontier"], json!([unknown]), "{marker}");
    assert_eq!(marker["backfill"]["status"], "open");
    assert_eq!(
        calls_of(&harness, &format!("backfill:{unknown}")).len(),
        1,
        "asked once"
    );
    assert_eq!(calls_of(&harness, &format!("event:{unknown}")).len(), 1);
    let backfills = calls_of(&harness, "backfill:");
    let distinct: HashSet<&String> = backfills.iter().collect();
    assert_eq!(distinct.len(), backfills.len(), "{backfills:?}");
}
