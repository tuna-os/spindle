//! Live /send dependency recovery over sockets, with signed mock-peer history.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::Pdu;
use spindle_server::{
    metrics::{Metrics, PduOutcome, RecoveryAdmission},
    rooms::{PartialState, Rooms},
    signing::ServerKey,
};
use spindle_store::{FjallStore, RoomStore};
use tempfile::TempDir;

const ALICE: &str = "@alice:example.org";
/// How long `/send` waits for a dependency recovery
/// (`inbound::recovery::SEND_BUDGET`, #808).
const SEND_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
/// Room for the key fetches and room work around a recovery, and for a
/// loaded host. Still well under the 60 s after which Synapse gives up.
const MARGIN: std::time::Duration = std::time::Duration::from_secs(10);

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

struct Peer {
    _dir: TempDir,
    name: String,
    key: Arc<ServerKey>,
    bodies: Arc<Mutex<BTreeMap<String, Value>>>,
    window: Arc<Mutex<Vec<Value>>>,
    calls: Arc<Mutex<Vec<String>>>,
    /// While `false`, `get_missing_events` is held unanswered: a peer that
    /// hangs (#808).
    open: Arc<tokio::sync::watch::Sender<bool>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
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
        let bodies: Arc<Mutex<BTreeMap<String, Value>>> = Arc::default();
        let window: Arc<Mutex<Vec<Value>>> = Arc::default();
        let calls: Arc<Mutex<Vec<String>>> = Arc::default();
        let open = Arc::new(tokio::sync::watch::Sender::new(true));
        let app = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get({
                    let calls = Arc::clone(&calls);
                    move || {
                        let document = document.clone();
                        calls.lock().unwrap().push("keys".to_owned());
                        async move { axum::Json(document) }
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/get_missing_events/{room}",
                axum::routing::post({
                    let window = Arc::clone(&window);
                    let calls = Arc::clone(&calls);
                    let open = Arc::clone(&open);
                    move || {
                        calls.lock().unwrap().push("missing".to_owned());
                        let window = Arc::clone(&window);
                        let mut open = open.subscribe();
                        async move {
                            let _ = open.wait_for(|open| *open).await;
                            let events = window.lock().unwrap().clone();
                            axum::Json(json!({"events":events}))
                        }
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/event/{event}",
                axum::routing::get({
                    let bodies = Arc::clone(&bodies);
                    let calls = Arc::clone(&calls);
                    move |axum::extract::Path(id): axum::extract::Path<String>| {
                        calls.lock().unwrap().push(format!("event:{id}"));
                        let body = bodies.lock().unwrap().get(&id).cloned();
                        async move {
                            match body {
                                Some(body) => (
                                    axum::http::StatusCode::OK,
                                    axum::Json(json!({"pdus":[body]})),
                                ),
                                None => (
                                    axum::http::StatusCode::NOT_FOUND,
                                    axum::Json(
                                        json!({"errcode":"M_NOT_FOUND","error":"not divulged"}),
                                    ),
                                ),
                            }
                        }
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
            bodies,
            window,
            calls,
            open,
            task,
        }
    }

    fn sign(&self, version: &RoomVersionId, body: Value) -> (String, Value) {
        signed(version, &self.name, &self.key, body)
    }

    /// Hold `get_missing_events` unanswered, or answer what was held.
    fn hang(&self, hung: bool) {
        self.open.send_replace(!hung);
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

fn signed(
    version: &RoomVersionId,
    server: &str,
    key: &ServerKey,
    mut body: Value,
) -> (String, Value) {
    if let Some(object) = body.as_object_mut() {
        object.remove("event_id");
        object.remove("unsigned");
    }
    let event = Pdu::sign(version.clone(), canonical(&body), server, key.pair()).unwrap();
    (
        event.event_id().as_str().to_owned(),
        serde_json::to_value(event.canonical()).unwrap(),
    )
}

/// A room of this server that bob of the peer joined: its ID, bob's join,
/// and the auth events of a message from bob.
struct Seat {
    room: String,
    head: (String, Value),
    auth: Vec<(String, Value)>,
}

fn create_room(store: &Arc<FjallStore>, key: &ServerKey, version: u8) -> String {
    Rooms::new(Arc::clone(store), "example.org")
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
        .unwrap()
}

fn join_bob(store: &Arc<FjallStore>, peer: &Peer, room: String, version: &RoomVersionId) -> Seat {
    let remote = Rooms::new(Arc::clone(store), peer.name.clone());
    let bob = format!("@bob:{}", peer.name);
    let joined = remote
        .set_membership(&room, &bob, &bob, "join", None, peer.key.pair())
        .unwrap();
    let head = (joined.clone(), remote.pdu(&room, &joined).unwrap());
    let content = serde_json::value::to_raw_value(&json!({"body":"synthetic"})).unwrap();
    let kinds = ruma::state_res::auth_types_for_event(
        &ruma::events::TimelineEventType::RoomMessage,
        &ruma::UserId::parse(&bob).unwrap(),
        None,
        &content,
        &spindle_core::rules_of(version).unwrap().authorization,
    )
    .unwrap();
    let state = remote.state(&room).unwrap();
    let auth = kinds
        .into_iter()
        .filter_map(|(kind, key)| {
            let event = state.iter().find(|event| {
                event["type"].as_str() == Some(kind.to_string().as_str())
                    && event["state_key"].as_str() == Some(key.as_str())
            })?;
            let id = event["event_id"].as_str().unwrap().to_owned();
            Some((id.clone(), remote.pdu(&room, &id).unwrap()))
        })
        .collect();
    Seat { room, head, auth }
}

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    key: ServerKey,
    peer: Peer,
    /// A second server in the room, which relays the first peer's events.
    relay: Option<Peer>,
    room: String,
    version: RoomVersionId,
    head: (String, Value),
    auth: Vec<(String, Value)>,
    /// A second room bob joined, when asked for.
    other: Option<Seat>,
    metrics: Arc<Metrics>,
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
        Self::build(version, false).await
    }

    async fn with_relay(version: u8) -> Self {
        Self::build(version, true).await
    }

    async fn build(version: u8, with_relay: bool) -> Self {
        Self::build_with(version, with_relay, |_, _| {}).await
    }

    /// [`Self::new`], and bob joined to a second room.
    async fn with_other_room(version: u8) -> Self {
        Self::build_full(version, false, true, |_, _| {}).await
    }

    /// [`Self::build`], with `seat` run on the store and the room after the
    /// room is created and before bob joins and the app opens it: what
    /// else the room holds, and what this server recorded about it.
    async fn build_with(
        version: u8,
        with_relay: bool,
        seat: impl FnOnce(&Arc<FjallStore>, &str),
    ) -> Self {
        Self::build_full(version, with_relay, false, seat).await
    }

    async fn build_full(
        version: u8,
        with_relay: bool,
        other: bool,
        seat: impl FnOnce(&Arc<FjallStore>, &str),
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let key = ServerKey::load_or_create(store.as_ref()).unwrap();
        let peer = Peer::new().await;
        let room = create_room(&store, &key, version);
        let relay = if with_relay {
            let relay = Peer::new().await;
            let carol = format!("@carol:{}", relay.name);
            Rooms::new(Arc::clone(&store), relay.name.clone())
                .set_membership(&room, &carol, &carol, "join", None, relay.key.pair())
                .unwrap();
            Some(relay)
        } else {
            None
        };
        seat(&store, &room);
        let version_id = RoomVersionId::try_from(version.to_string()).unwrap();
        let main = join_bob(&store, &peer, room, &version_id);
        let other = other.then(|| {
            join_bob(
                &store,
                &peer,
                create_room(&store, &key, version),
                &version_id,
            )
        });
        let version = version_id;
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n[federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\ngap_backfill_idle_ms = 100\ngap_backfill_interval_ms = 50\ngap_backfill_retry_ms = 100\n").unwrap();
        let metrics = Arc::new(Metrics::new());
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
            key,
            peer,
            relay,
            room: main.room,
            version,
            head: main.head,
            auth: main.auth,
            other,
            metrics,
            address,
            task,
        }
    }

    fn edge(&self, event: &(String, Value)) -> Value {
        serde_json::to_value(
            spindle_core::version::edge(&event.0, &canonical(&event.1), &self.version).unwrap(),
        )
        .unwrap()
    }

    fn message(&self, parent: &(String, Value), label: &str) -> (String, Value) {
        self.message_with(&self.room, &self.auth, parent, label)
    }

    /// [`Self::message`], in the second room.
    fn message_in(&self, seat: &Seat, parent: &(String, Value), label: &str) -> (String, Value) {
        self.message_with(&seat.room, &seat.auth, parent, label)
    }

    fn message_with(
        &self,
        room: &str,
        auth: &[(String, Value)],
        parent: &(String, Value),
        label: &str,
    ) -> (String, Value) {
        self.peer.sign(&self.version, json!({"room_id":room,"sender":format!("@bob:{}",self.peer.name),
            "type":"m.room.message","origin_server_ts":now(),"depth":parent.1["depth"].as_u64().unwrap()+1,
            "prev_events":[self.edge(parent)],"auth_events":auth.iter().map(|event|self.edge(event)).collect::<Vec<_>>(),
            "content":{"msgtype":"m.text","body":label}}))
    }

    async fn push(&self, event: &(String, Value)) -> Value {
        self.push_from(&self.peer, event).await
    }

    async fn push_from(&self, origin: &Peer, event: &(String, Value)) -> Value {
        let uri = "/_matrix/federation/v1/send/recovery-test";
        let body =
            json!({"origin":origin.name,"origin_server_ts":now(),"pdus":[event.1],"edus":[]});
        let response = reqwest::Client::new()
            .put(format!("http://{}{uri}", self.address))
            .header("authorization", origin.transaction_header(uri, &body))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    fn held(&self, id: &str) -> bool {
        self.held_in(&self.room, id)
    }

    fn held_in(&self, room: &str, id: &str) -> bool {
        Rooms::new(Arc::clone(&self.store), "example.org")
            .pdu(room, id)
            .is_ok()
    }

    /// A signed transaction of `pdus` from the peer, under its own ID,
    /// which gives up after the budget and a margin.
    fn transaction(&self, txn: &str, pdus: &[&(String, Value)]) -> reqwest::RequestBuilder {
        let uri = format!("/_matrix/federation/v1/send/{txn}");
        let pdus: Vec<&Value> = pdus.iter().map(|event| &event.1).collect();
        let body = json!({"origin":self.peer.name,"origin_server_ts":now(),"pdus":pdus,"edus":[]});
        reqwest::Client::new()
            .put(format!("http://{}{uri}", self.address))
            .header("authorization", self.peer.transaction_header(&uri, &body))
            .header("content-type", "application/json")
            .timeout(SEND_BUDGET + MARGIN)
            .body(body.to_string())
    }
}

#[tokio::test]
async fn missing_predecessors_are_verified_and_inserted_in_order_in_all_room_versions() {
    for version in 1..=12 {
        let harness = Harness::new(version).await;
        let first = harness.message(&harness.head, "first");
        let second = harness.message(&first, "second");
        let latest = harness.message(&second, "latest");
        let unrelated = harness.message(&harness.head, "unrelated");
        *harness.peer.window.lock().unwrap() =
            vec![second.1.clone(), unrelated.1.clone(), first.1.clone()];
        let response = harness.push(&latest).await;
        assert_eq!(
            response["pdus"][&latest.0],
            json!({}),
            "version {version}: {response}"
        );
        assert!(harness.held(&first.0) && harness.held(&second.0) && harness.held(&latest.0));
        assert!(
            !harness.held(&unrelated.0),
            "unrelated offered events never reach storage"
        );
        let log = RoomStore::new(harness.store.as_ref(), &harness.room)
            .load()
            .unwrap()
            .unwrap()
            .log;
        let position = |id: &str| log.get(&spindle_core::EventId::new(id)).unwrap().li;
        assert!(
            position(&first.0) < position(&second.0) && position(&second.0) < position(&latest.0)
        );
    }
}

#[tokio::test]
async fn missing_auth_is_retained_without_becoming_timeline_state() {
    let harness = Harness::new(11).await;
    let rooms = Rooms::new(Arc::clone(&harness.store), "example.org");
    let state = rooms.state(&harness.room).unwrap();
    let powers = state
        .iter()
        .find(|event| event["type"] == "m.room.power_levels")
        .unwrap();
    let old = powers["event_id"].as_str().unwrap();
    let mut body = rooms.pdu(&harness.room, old).unwrap();
    body["origin_server_ts"] = json!(now());
    body["content"]["users_default"] = json!(1);
    let auth = signed(&harness.version, "example.org", &harness.key, body);
    harness
        .peer
        .bodies
        .lock()
        .unwrap()
        .insert(auth.0.clone(), auth.1.clone());
    let mut latest = harness.message(&harness.head, "with missing auth").1;
    for id in latest["auth_events"].as_array_mut().unwrap() {
        if id.as_str() == Some(old) {
            *id = json!(auth.0);
        }
    }
    let latest = harness.peer.sign(&harness.version, latest);
    let response = harness.push(&latest).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    assert!(harness.held(&auth.0) && harness.held(&latest.0));
    let restored = RoomStore::new(harness.store.as_ref(), &harness.room)
        .load()
        .unwrap()
        .unwrap();
    assert!(
        restored
            .log
            .get(&spindle_core::EventId::new(auth.0.as_str()))
            .is_none()
    );
    let current = Rooms::new(Arc::clone(&harness.store), "example.org")
        .state(&harness.room)
        .unwrap();
    assert_eq!(
        current
            .iter()
            .find(|event| event["type"] == "m.room.power_levels")
            .unwrap()["event_id"],
        old
    );
    assert!(
        !harness
            .peer
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "missing")
    );
}

#[tokio::test]
async fn a_forged_predecessor_or_undivulged_history_refuses_the_latest_event() {
    for forged in [true, false] {
        let harness = Harness::new(11).await;
        let parent = harness.message(&harness.head, "parent");
        let latest = harness.message(&parent, "latest");
        if forged {
            let mut body = parent.1.clone();
            body["signatures"][&harness.peer.name][harness.peer.key.key_id()] = json!("invalid");
            *harness.peer.window.lock().unwrap() = vec![body];
        }
        let response = harness.push(&latest).await;
        assert!(
            response["pdus"][&latest.0]["error"].is_string(),
            "{response}"
        );
        assert!(!harness.held(&parent.0) && !harness.held(&latest.0));
    }
}

#[tokio::test]
async fn legacy_events_require_the_distinct_event_id_servers_signature() {
    for version in [1, 2] {
        for signed_by_id_server in [true, false] {
            let harness = Harness::new(version).await;
            let id_server = Peer::new().await;
            let mut object = canonical(&harness.message(&harness.head, "distinct ID server").1);
            object.insert(
                "event_id".to_owned(),
                CanonicalJsonValue::String(format!("$distinct:{}", id_server.name)),
            );
            object.remove("signatures");
            let event = Pdu::sign(
                harness.version.clone(),
                object,
                &harness.peer.name,
                harness.peer.key.pair(),
            )
            .unwrap();
            let mut object = event.canonical().clone();
            if signed_by_id_server {
                spindle_core::version::hash_and_sign(
                    &id_server.name,
                    id_server.key.pair(),
                    &mut object,
                    &harness.version,
                )
                .unwrap();
            }
            let event = (
                event.event_id().as_str().to_owned(),
                serde_json::to_value(object).unwrap(),
            );
            let response = harness.push(&event).await;
            if signed_by_id_server {
                assert_eq!(
                    response["pdus"][&event.0],
                    json!({}),
                    "v{version}: {response}"
                );
                assert!(harness.held(&event.0));
            } else {
                assert!(
                    response["pdus"][&event.0]["error"].is_string(),
                    "v{version}: {response}"
                );
                assert!(!harness.held(&event.0));
            }
        }
    }
}

#[tokio::test]
async fn an_invalid_pushed_event_does_not_fetch_dependencies() {
    let harness = Harness::new(11).await;
    let parent = harness.message(&harness.head, "parent");
    let mut latest = harness.message(&parent, "forged latest");
    latest.1["signatures"][&harness.peer.name][harness.peer.key.key_id()] = json!("invalid");
    let response = harness.push(&latest).await;
    assert!(
        response["pdus"][&latest.0]["error"].is_string(),
        "{response}"
    );
    assert!(!harness.held(&parent.0) && !harness.held(&latest.0));
    assert!(
        harness
            .peer
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call == "keys")
    );
}

#[tokio::test]
async fn recovery_for_a_relayed_event_asks_the_origin_that_relayed_it() {
    // #631: the origin that relays an event holds its history, so recovery
    // asks the origin first, as for its own events. The sender's server is
    // asked only for its keys.
    let harness = Harness::with_relay(11).await;
    let relay = harness.relay.as_ref().unwrap();
    let first = harness.message(&harness.head, "first");
    let latest = harness.message(&first, "latest");
    *relay.window.lock().unwrap() = vec![first.1.clone()];
    let response = harness.push_from(relay, &latest).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    assert!(harness.held(&first.0) && harness.held(&latest.0));
    let asked = |peer: &Peer| {
        peer.calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "missing")
    };
    assert!(asked(relay));
    assert!(!asked(&harness.peer));
}

/// Whether `peer` was asked for missing events.
fn asked_for_missing(peer: &Peer) -> bool {
    peer.calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call == "missing")
}

/// #620: when the origin cannot serve an event's history, recovery turns
/// to a server with members joined to the room -- never to one whose users
/// all left, though it has the most member events, nor to one with only an
/// invited user, though both could answer.
#[tokio::test]
async fn recovery_falls_back_to_a_joined_server_never_a_departed_or_invited_one() {
    let departed = Peer::new().await;
    let invited = Peer::new().await;
    let joined = Peer::new().await;
    let harness = Harness::build_with(11, false, |store, room| {
        for (peer, users, leave) in [(&departed, 3, true), (&joined, 1, false)] {
            let rooms = Rooms::new(Arc::clone(store), peer.name.clone());
            for index in 0..users {
                let user = format!("@user{index}:{}", peer.name);
                rooms
                    .set_membership(room, &user, &user, "join", None, peer.key.pair())
                    .unwrap();
                if leave {
                    rooms
                        .set_membership(room, &user, &user, "leave", None, peer.key.pair())
                        .unwrap();
                }
            }
        }
        let key = ServerKey::load_or_create(store.as_ref()).unwrap();
        let guest = format!("@guest:{}", invited.name);
        Rooms::new(Arc::clone(store), "example.org")
            .set_membership(room, ALICE, &guest, "invite", None, key.pair())
            .unwrap();
    })
    .await;
    let first = harness.message(&harness.head, "first");
    let latest = harness.message(&first, "latest");
    for peer in [&departed, &invited, &joined] {
        *peer.window.lock().unwrap() = vec![first.1.clone()];
    }
    let response = harness.push(&latest).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    assert!(harness.held(&first.0) && harness.held(&latest.0));
    assert!(
        asked_for_missing(&harness.peer),
        "the origin is asked first"
    );
    assert!(asked_for_missing(&joined));
    assert!(!asked_for_missing(&departed), "a departed server was asked");
    assert!(!asked_for_missing(&invited), "an invited server was asked");
}

/// #620: a partial-state room (MSC3706) holds few member events, so the
/// server the join went through is named only by the resident's
/// `servers_in_room` -- and it is where recovery turns when the origin
/// cannot answer, as it was before servers were ranked by joined members.
#[tokio::test]
async fn recovery_in_a_partial_state_room_falls_back_to_the_resident() {
    let resident = Peer::new().await;
    let harness = Harness::build_with(11, false, |store, room| {
        let record = PartialState {
            room_id: room.to_owned(),
            join_event_id: "$join".to_owned(),
            via: resident.name.clone(),
            servers_in_room: vec!["example.org".to_owned(), resident.name.clone()],
        };
        spindle_store::Store::put(
            store.as_ref(),
            &spindle_core::keys::partial_state_room(room),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
    })
    .await;
    let first = harness.message(&harness.head, "first");
    let latest = harness.message(&first, "latest");
    *resident.window.lock().unwrap() = vec![first.1.clone()];
    let response = harness.push(&latest).await;
    assert_eq!(response["pdus"][&latest.0], json!({}), "{response}");
    assert!(harness.held(&first.0) && harness.held(&latest.0));
    assert!(asked_for_missing(&harness.peer) && asked_for_missing(&resident));
}

/// The answer to one transaction, which must come within its timeout.
async fn answer(request: reqwest::RequestBuilder) -> Value {
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

/// Wait for `done`, at most `limit`.
async fn wait_until(what: &str, limit: std::time::Duration, done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(started.elapsed() < limit, "{what} within {limit:?}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// How many times `peer` was asked for missing events.
fn missing_asked(peer: &Peer) -> usize {
    peer.calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| *call == "missing")
        .count()
}

/// #808: the origin hangs on `get_missing_events`. `/send` still answers
/// within its budget, and the PDU of another room in the same transaction
/// and in a later one is placed at once. A retry of the PDU joins the
/// recovery in flight, and a room takes two recoveries at most. When the
/// peer answers, the recovery that `/send` stopped waiting for places the
/// event, with one request for the missing events in all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hung_recovery_answers_within_the_budget_and_holds_back_no_other_room() {
    let harness = Harness::with_other_room(11).await;
    let other = harness.other.as_ref().unwrap();
    let first = harness.message(&harness.head, "first");
    let second = harness.message(&first, "second");
    let latest = harness.message(&second, "latest");
    let branch = harness.message(&first, "branch");
    let crowded = harness.message(&second, "crowded");
    let elsewhere = harness.message_in(other, &other.head, "elsewhere");
    let later = harness.message_in(other, &elsewhere, "later");
    *harness.peer.window.lock().unwrap() = vec![second.1.clone(), first.1.clone()];
    harness.peer.hang(true);

    let started = std::time::Instant::now();
    let held = tokio::spawn(answer(harness.transaction("held", &[&latest, &elsewhere])));
    wait_until("the recovery asks the origin", MARGIN, || {
        missing_asked(&harness.peer) == 1
    })
    .await;
    wait_until(
        "the PDU of another room in the same transaction is placed",
        MARGIN,
        || harness.held_in(&other.room, &elsewhere.0),
    )
    .await;

    let asked = std::time::Instant::now();
    let response = answer(harness.transaction("later", &[&later])).await;
    assert_eq!(response["pdus"][&later.0], json!({}), "{response}");
    assert!(
        asked.elapsed() < MARGIN,
        "a later transaction for another room waited {:?}",
        asked.elapsed()
    );

    let retry = tokio::spawn(answer(harness.transaction("retry", &[&latest])));
    let queued = tokio::spawn(answer(harness.transaction("queued", &[&branch])));
    let admitted = |result| harness.metrics.recovery_admission_count(result);
    wait_until(
        "the retry joins and the branch waits its turn",
        MARGIN,
        || admitted(RecoveryAdmission::Joined) == 1 && admitted(RecoveryAdmission::Started) == 2,
    )
    .await;
    let asked = std::time::Instant::now();
    let response = answer(harness.transaction("crowded", &[&crowded])).await;
    let refusal = response["pdus"][&crowded.0]["error"].as_str().unwrap_or("");
    assert!(refusal.contains("in flight"), "{response}");
    assert!(asked.elapsed() < MARGIN, "a refusal waited");

    let response = held.await.unwrap();
    assert!(
        started.elapsed() < SEND_BUDGET + MARGIN,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(response["pdus"][&elsewhere.0], json!({}), "{response}");
    let pending = response["pdus"][&latest.0]["error"].as_str().unwrap_or("");
    assert!(pending.contains("still running"), "{response}");
    assert!(!harness.held(&latest.0));
    assert!(harness.metrics.pdu_count(PduOutcome::Pending) >= 1);

    harness.peer.hang(false);
    retry.await.unwrap();
    queued.await.unwrap();
    wait_until(
        "the detached recovery places the event and the one queued",
        MARGIN,
        || harness.held(&latest.0) && harness.held(&branch.0),
    )
    .await;
    assert!(harness.held(&first.0) && harness.held(&second.0));
    assert_eq!(missing_asked(&harness.peer), 1, "no recovery ran twice");
    assert_eq!(admitted(RecoveryAdmission::Started), 2);
    assert_eq!(admitted(RecoveryAdmission::Joined), 1);
    assert_eq!(admitted(RecoveryAdmission::Busy), 1);
}

/// #822: the newest event of a room, refused because the room already has
/// two recoveries in flight, is not lost. The sender was answered 200 and
/// does not send it again, and no later event arrives. The gap-backfill
/// loop applies it once its predecessor is placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tip_event_refused_while_the_room_was_busy_is_applied_later() {
    let harness = Harness::new(11).await;
    let first = harness.message(&harness.head, "first");
    let second = harness.message(&first, "second");
    let latest = harness.message(&second, "latest");
    let branch = harness.message(&first, "branch");
    let tip = harness.message(&second, "tip");
    *harness.peer.window.lock().unwrap() = vec![second.1.clone(), first.1.clone()];
    harness.peer.hang(true);

    let held = tokio::spawn(answer(harness.transaction("held", &[&latest])));
    let queued = tokio::spawn(answer(harness.transaction("queued", &[&branch])));
    let admitted = |result| harness.metrics.recovery_admission_count(result);
    wait_until("the room has two recoveries", MARGIN, || {
        admitted(RecoveryAdmission::Started) == 2
    })
    .await;
    let response = answer(harness.transaction("tip", &[&tip])).await;
    let refusal = response["pdus"][&tip.0]["error"].as_str().unwrap_or("");
    assert!(refusal.contains("in flight"), "{response}");
    assert!(!harness.held(&tip.0));

    harness.peer.hang(false);
    held.await.unwrap();
    queued.await.unwrap();
    // No event follows the tip: only the retry can place it.
    wait_until("the owed tip event is applied", MARGIN, || {
        harness.held(&tip.0)
    })
    .await;
    wait_until("nothing is owed any more", MARGIN, || {
        harness.metrics.owed_events() == 0
    })
    .await;
}
