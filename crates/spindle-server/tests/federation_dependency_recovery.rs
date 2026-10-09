//! Live /send dependency recovery over sockets, with signed mock-peer history.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::Pdu;
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

struct Peer {
    _dir: TempDir,
    name: String,
    key: Arc<ServerKey>,
    bodies: Arc<Mutex<BTreeMap<String, Value>>>,
    window: Arc<Mutex<Vec<Value>>>,
    calls: Arc<Mutex<Vec<String>>>,
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
                    move || {
                        let events = window.lock().unwrap().clone();
                        calls.lock().unwrap().push("missing".to_owned());
                        async move { axum::Json(json!({"events":events})) }
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
            task,
        }
    }

    fn sign(&self, version: &RoomVersionId, body: Value) -> (String, Value) {
        signed(version, &self.name, &self.key, body)
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

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    key: ServerKey,
    peer: Peer,
    room: String,
    version: RoomVersionId,
    head: (String, Value),
    auth: Vec<(String, Value)>,
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
        let version = RoomVersionId::try_from(version.to_string()).unwrap();
        let content = serde_json::value::to_raw_value(&json!({"body":"synthetic"})).unwrap();
        let kinds = ruma::state_res::auth_types_for_event(
            &ruma::events::TimelineEventType::RoomMessage,
            &ruma::UserId::parse(&bob).unwrap(),
            None,
            &content,
            &spindle_core::rules_of(&version).unwrap().authorization,
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
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n[federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n").unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).unwrap();
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
            room,
            version,
            head,
            auth,
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
        self.peer.sign(&self.version, json!({"room_id":self.room,"sender":format!("@bob:{}",self.peer.name),
            "type":"m.room.message","origin_server_ts":now(),"depth":parent.1["depth"].as_u64().unwrap()+1,
            "prev_events":[self.edge(parent)],"auth_events":self.auth.iter().map(|event|self.edge(event)).collect::<Vec<_>>(),
            "content":{"msgtype":"m.text","body":label}}))
    }

    async fn push(&self, event: &(String, Value)) -> Value {
        let uri = "/_matrix/federation/v1/send/recovery-test";
        let body =
            json!({"origin":self.peer.name,"origin_server_ts":now(),"pdus":[event.1],"edus":[]});
        let response = reqwest::Client::new()
            .put(format!("http://{}{uri}", self.address))
            .header("authorization", self.peer.transaction_header(uri, &body))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    fn held(&self, id: &str) -> bool {
        Rooms::new(Arc::clone(&self.store), "example.org")
            .pdu(&self.room, id)
            .is_ok()
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
