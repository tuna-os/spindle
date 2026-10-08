//! Keys from a trusted notary, and keys from history.
//!
//! A server that has gone dark, or that this server cannot reach, still
//! signed events that live servers hand on: a membership it brokered, a
//! join its user made. Synapse verifies those by asking `matrix.org` for
//! the dark server's keys (`trusted_key_servers`), and so does this server
//! now. What must hold:
//!
//! - an unreachable server's event verifies with keys a notary vouches
//!   for, and only if the notary's own signature and the server's
//!   self-signature both check out;
//! - a key that a notary says expired before the event was signed does
//!   not verify it, whether by `valid_until_ts` or a retired key's
//!   `expired_ts`;
//! - a retired key (`old_verify_keys`) still verifies what was signed
//!   before it was retired;
//! - a server that rotated its key without listing the old one -- Synapse's
//!   default -- still has its earlier events verify: from the document this
//!   server held before the rotation, or from a notary's history;
//! - what a notary handed on is never served on by our own notary endpoint.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_server::metrics::{KeyFetchResult, KeySource, Metrics, SignatureFailure};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

fn pair(version: &str) -> Ed25519KeyPair {
    Ed25519KeyPair::from_der(&Ed25519KeyPair::generate(), version.to_owned()).unwrap()
}

fn key_id(pair: &Ed25519KeyPair) -> String {
    format!("ed25519:{}", pair.version())
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

/// A key document for `name`: `current` under `verify_keys`, each of
/// `retired` under `old_verify_keys` with its `expired_ts`, self-signed
/// with `signer`.
fn key_document(
    name: &str,
    current: &[&Ed25519KeyPair],
    retired: &[(&Ed25519KeyPair, u64)],
    valid_until_ts: u64,
    signer: &Ed25519KeyPair,
) -> Value {
    let verify_keys: serde_json::Map<String, Value> = current
        .iter()
        .map(|pair| (key_id(pair), json!({ "key": unpadded(&pair.public_key()) })))
        .collect();
    let old_verify_keys: serde_json::Map<String, Value> = retired
        .iter()
        .map(|(pair, expired_ts)| {
            (
                key_id(pair),
                json!({ "key": unpadded(&pair.public_key()), "expired_ts": expired_ts }),
            )
        })
        .collect();
    let mut document = json!({
        "server_name": name,
        "valid_until_ts": valid_until_ts,
        "verify_keys": verify_keys,
        "old_verify_keys": old_verify_keys,
    });
    sign_value(name, signer, &mut document);
    document
}

/// A free loopback port nothing listens on: a server that is down.
async fn dead_name() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

/// A server that answers `/_matrix/key/v2/server` with whatever
/// `document` holds right now, and counts the asking.
struct KeyServer {
    name: String,
    document: Arc<Mutex<Value>>,
    fetches: Arc<AtomicUsize>,
}

impl KeyServer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());
        let document = Arc::new(Mutex::new(Value::Null));
        let fetches = Arc::new(AtomicUsize::new(0));
        let (served, counted) = (Arc::clone(&document), Arc::clone(&fetches));
        let router = axum::Router::new().route(
            "/_matrix/key/v2/server",
            axum::routing::get(move || {
                let body = served.lock().unwrap().clone();
                counted.fetch_add(1, Ordering::SeqCst);
                async move { axum::Json(body) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            name,
            document,
            fetches,
        }
    }

    fn serve(&self, document: Value) {
        *self.document.lock().unwrap() = document;
    }
}

/// A notary: its own key document at `/_matrix/key/v2/server`, and at
/// `/_matrix/key/v2/query` whatever `answers` holds, each document
/// countersigned with `signing` -- which is not its published key when a
/// test wants a forgery.
struct Notary {
    name: String,
    published: Ed25519KeyPair,
    answers: Arc<Mutex<Vec<Value>>>,
    queries: Arc<AtomicUsize>,
    last_query: Arc<Mutex<Value>>,
}

impl Notary {
    async fn start(forge: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());
        let published_der = Ed25519KeyPair::generate();
        let published = Ed25519KeyPair::from_der(&published_der, "n".to_owned()).unwrap();
        let own = key_document(
            &name,
            &[&published],
            &[],
            now_millis() + 3_600_000,
            &published,
        );
        let signing = if forge {
            pair("n")
        } else {
            Ed25519KeyPair::from_der(&published_der, "n".to_owned()).unwrap()
        };
        let answers: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let queries = Arc::new(AtomicUsize::new(0));
        let last_query = Arc::new(Mutex::new(Value::Null));
        let (served, counted, seen) = (
            Arc::clone(&answers),
            Arc::clone(&queries),
            Arc::clone(&last_query),
        );
        let notary_name = name.clone();
        let signing = Arc::new(signing);
        let router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = own.clone();
                    async move { axum::Json(body) }
                }),
            )
            .route(
                "/_matrix/key/v2/query",
                axum::routing::post(
                    move |axum::extract::Json(query): axum::extract::Json<Value>| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        *seen.lock().unwrap() = query;
                        let documents: Vec<Value> = served
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|document| {
                                let mut document = document.clone();
                                sign_value(&notary_name, &signing, &mut document);
                                document
                            })
                            .collect();
                        async move { axum::Json(json!({ "server_keys": documents })) }
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            name,
            published,
            answers,
            queries,
            last_query,
        }
    }

    fn hold(&self, document: Value) {
        self.answers.lock().unwrap().push(document);
    }
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
    store: Arc<FjallStore>,
    metrics: Arc<Metrics>,
}

impl Harness {
    /// This server, trusting `notary` -- given as the TOML of one
    /// `trusted_key_servers` entry -- or none.
    fn new(notary: Option<String>) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let trusted = notary.map_or_else(
            || "trusted_key_servers = []\n".to_owned(),
            |entry| format!("trusted_key_servers = [{entry}]\n"),
        );
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n{trusted}"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let app = spindle_server::app_with_metrics(config, store.clone(), Arc::clone(&metrics))
            .expect("the app builds");
        Self {
            _dir: dir,
            app,
            store,
            metrics,
        }
    }

    fn trusting(notary: &Notary) -> Self {
        Self::new(Some(format!("\"{}\"", notary.name)))
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

    async fn send(&self, method: &str, path: &str, token: &str, body: &Value) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
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

    /// A public room of alice's, and its head event.
    async fn public_room(&self, alice: &str) -> (String, String) {
        let body = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                alice,
                &json!({ "preset": "public_chat" }),
            )
            .await;
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (_, body) = self
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
        let head = body["chunk"][0]["event_id"].as_str().unwrap().to_owned();
        (room, head)
    }

    async fn joined(&self, alice: &str, room: &str, user: &str) -> bool {
        let (_, members) = self
            .call(
                Request::builder()
                    .uri(format!("/_matrix/client/v3/rooms/{room}/joined_members"))
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        members["joined"].get(user).is_some()
    }

    /// A transaction from `origin`, signed with `request_key`.
    async fn deliver(
        &self,
        origin: &str,
        request_key: &Ed25519KeyPair,
        txn_id: &str,
        pdus: Vec<Value>,
    ) -> Value {
        let body = json!({ "origin": origin, "origin_server_ts": now_millis(), "pdus": pdus });
        let uri = format!("/_matrix/federation/v1/send/{txn_id}");
        let mut object = json!({
            "method": "PUT",
            "uri": uri,
            "origin": origin,
            "destination": "example.org",
            "content": body,
        });
        sign_value(origin, request_key, &mut object);
        let id = key_id(request_key);
        let signature = object["signatures"][origin][&id].as_str().unwrap();
        let header = format!(
            "X-Matrix origin=\"{origin}\",destination=\"example.org\",key=\"{id}\",sig=\"{signature}\""
        );
        let (status, response) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("authorization", header)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let results = response["pdus"].as_object().unwrap();
        assert_eq!(results.len(), 1, "{response}");
        results.values().next().unwrap().clone()
    }
}

/// `@user:server`'s join to `room`, signed by `server` with `key` at `at`.
fn join(
    store: &Arc<FjallStore>,
    server: &str,
    key: &Ed25519KeyPair,
    room: &str,
    prev: &str,
    at: u64,
) -> Value {
    let user = format!("@user:{server}");
    let event = federation_auth::with_auth_events(
        store,
        json!({
            "type": "m.room.member",
            "state_key": user,
            "sender": user,
            "room_id": room,
            "content": { "membership": "join" },
            "origin_server_ts": at,
            "depth": 10,
            "prev_events": [prev],
            "auth_events": [],
        }),
    );
    let ruma::CanonicalJsonValue::Object(mut canonical) =
        ruma::CanonicalJsonValue::try_from(event).unwrap()
    else {
        unreachable!()
    };
    let rules = RoomVersionId::V11.rules().unwrap();
    hash_and_sign_event(server, key, &mut canonical, &rules.redaction).unwrap();
    serde_json::to_value(&canonical).unwrap()
}

/// A live server relaying the join of a user whose own server is down --
/// the brokered membership every resident hands on.
async fn relay(harness: &Harness, join: Value) -> Value {
    let relay = KeyServer::start().await;
    let relay_key = pair("r");
    relay.serve(key_document(
        &relay.name,
        &[&relay_key],
        &[],
        now_millis() + 600_000,
        &relay_key,
    ));
    harness
        .deliver(&relay.name, &relay_key, "t1", vec![join])
        .await
}

#[tokio::test]
async fn an_unreachable_servers_event_verifies_with_keys_a_notary_vouches_for() {
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let dead_key = pair("d");
    notary.hold(key_document(
        &dead,
        &[&dead_key],
        &[],
        now_millis() + 600_000,
        &dead_key,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &dead_key, &room, &head, now_millis());
    let result = relay(&harness, event).await;
    assert_eq!(result, json!({}), "{result}");
    assert!(
        harness
            .joined(&alice, &room, &format!("@user:{dead}"))
            .await
    );
    assert_eq!(notary.queries.load(Ordering::SeqCst), 1);
    let metrics = &harness.metrics;
    assert_eq!(
        metrics.key_fetch_count(KeySource::Notary, KeyFetchResult::Ok),
        1
    );
    assert!(metrics.key_fetch_count(KeySource::Direct, KeyFetchResult::Error) >= 1);
    assert!(
        metrics
            .render()
            .contains("spindle_federation_key_fetches_total{source=\"notary\",result=\"ok\"} 1")
    );

    // What the notary handed on is not ours to hand on: our own notary
    // endpoint serves only what a server published to us itself.
    let (status, served) = harness
        .call(
            Request::builder()
                .uri(format!("/_matrix/key/v2/query/{dead}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(served["server_keys"], json!([]), "{served}");
}

#[tokio::test]
async fn a_notary_answer_the_notary_did_not_sign_is_refused() {
    // Signed by a key the notary does not publish: what an on-path
    // attacker posing as the notary would serve.
    let notary = Notary::start(true).await;
    let dead = dead_name().await;
    let dead_key = pair("d");
    notary.hold(key_document(
        &dead,
        &[&dead_key],
        &[],
        now_millis() + 600_000,
        &dead_key,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &dead_key, &room, &head, now_millis());
    let result = relay(&harness, event).await;
    assert!(result["error"].is_string(), "{result}");
    assert!(
        !harness
            .joined(&alice, &room, &format!("@user:{dead}"))
            .await
    );
    let metrics = &harness.metrics;
    assert_eq!(
        metrics.key_fetch_count(KeySource::Notary, KeyFetchResult::Invalid),
        1
    );
}

#[tokio::test]
async fn a_notary_answer_the_origin_did_not_sign_is_refused() {
    // The notary vouches for a document the origin never signed: a notary
    // alone cannot mint a server's key.
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let dead_key = pair("d");
    notary.hold(key_document(
        &dead,
        &[&dead_key],
        &[],
        now_millis() + 600_000,
        &pair("d"),
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &dead_key, &room, &head, now_millis());
    let result = relay(&harness, event).await;
    assert!(result["error"].is_string(), "{result}");
    assert!(
        !harness
            .joined(&alice, &room, &format!("@user:{dead}"))
            .await
    );
}

#[tokio::test]
async fn a_pinned_notary_key_is_required() {
    // The notary signs with its published key, but the operator pinned
    // another: its answers are not believed.
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let dead_key = pair("d");
    notary.hold(key_document(
        &dead,
        &[&dead_key],
        &[],
        now_millis() + 600_000,
        &dead_key,
    ));
    let other = pair("n");
    let harness = Harness::new(Some(format!(
        "{{ server_name = \"{}\", verify_keys = {{ \"ed25519:n\" = \"{}\" }} }}",
        notary.name,
        unpadded(&other.public_key())
    )));
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;
    let event = join(&harness.store, &dead, &dead_key, &room, &head, now_millis());
    let result = relay(&harness, event).await;
    assert!(result["error"].is_string(), "{result}");

    // Pinned to the key it really signs with, the same answer is believed.
    let harness = Harness::new(Some(format!(
        "{{ server_name = \"{}\", verify_keys = {{ \"ed25519:n\" = \"{}\" }} }}",
        notary.name,
        unpadded(&notary.published.public_key())
    )));
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;
    let event = join(&harness.store, &dead, &dead_key, &room, &head, now_millis());
    let result = relay(&harness, event).await;
    assert_eq!(result, json!({}), "{result}");
}

#[tokio::test]
async fn a_key_that_lapsed_before_the_event_was_signed_verifies_nothing() {
    // The notary's document for the dark server was valid until two
    // minutes ago; the event says it was signed one minute ago. Room
    // version 11 enforces key validity.
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let dead_key = pair("d");
    let now = now_millis();
    notary.hold(key_document(
        &dead,
        &[&dead_key],
        &[],
        now - 120_000,
        &dead_key,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &dead_key, &room, &head, now - 60_000);
    let result = relay(&harness, event).await;
    let error = result["error"].as_str().unwrap_or_default();
    assert!(error.contains("expired_key"), "{result}");
    assert!(
        !harness
            .joined(&alice, &room, &format!("@user:{dead}"))
            .await
    );
    let metrics = &harness.metrics;
    assert_eq!(
        metrics.signature_failure_count(SignatureFailure::ExpiredKey),
        1
    );
}

#[tokio::test]
async fn a_key_retired_before_the_event_was_signed_verifies_nothing() {
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let (old, new) = (pair("old"), pair("new"));
    let clock = now_millis();
    notary.hold(key_document(
        &dead,
        &[&new],
        &[(&old, clock - 120_000)],
        clock + 600_000,
        &new,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &old, &room, &head, clock - 60_000);
    let result = relay(&harness, event).await;
    let error = result["error"].as_str().unwrap_or_default();
    assert!(error.contains("expired_key"), "{result}");
}

#[tokio::test]
async fn a_retired_key_verifies_what_was_signed_before_it_was_retired() {
    // `old_verify_keys`, as a notary hands them on for a dark server --
    // Tuwunel's shape, two retired keys beside the current one.
    let notary = Notary::start(false).await;
    let dead = dead_name().await;
    let (older, old, new) = (pair("older"), pair("old"), pair("new"));
    let clock = now_millis();
    notary.hold(key_document(
        &dead,
        &[&new],
        &[(&older, clock - 60_000), (&old, clock - 60_000)],
        clock + 600_000,
        &new,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(&harness.store, &dead, &old, &room, &head, clock - 120_000);
    let result = relay(&harness, event).await;
    assert_eq!(result, json!({}), "{result}");
    assert!(
        harness
            .joined(&alice, &room, &format!("@user:{dead}"))
            .await
    );
}

#[tokio::test]
async fn a_rotation_without_old_verify_keys_is_bridged_by_the_notarys_history() {
    // A live server that rotated a while ago, Synapse-style: its document
    // lists only the new key. The event was signed with the old one while
    // it was valid, and only the notary still holds that document.
    let notary = Notary::start(false).await;
    let server = KeyServer::start().await;
    let (old, new) = (pair("old"), pair("new"));
    let clock = now_millis();
    server.serve(key_document(
        &server.name,
        &[&new],
        &[],
        clock + 600_000,
        &new,
    ));
    notary.hold(key_document(
        &server.name,
        &[&old],
        &[],
        clock - 60_000,
        &old,
    ));
    let harness = Harness::trusting(&notary);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    let event = join(
        &harness.store,
        &server.name,
        &old,
        &room,
        &head,
        clock - 120_000,
    );
    let result = harness.deliver(&server.name, &new, "t1", vec![event]).await;
    assert_eq!(result, json!({}), "{result}");
    assert!(
        harness
            .joined(&alice, &room, &format!("@user:{}", server.name))
            .await
    );
    // Asked for the key the event named, valid when it was signed.
    let query = notary.last_query.lock().unwrap().clone();
    let criteria = &query["server_keys"][&server.name]["ed25519:old"];
    assert_eq!(
        criteria["minimum_valid_until_ts"],
        json!(clock - 120_000),
        "{query}"
    );
}

#[tokio::test]
async fn a_rotation_seen_here_keeps_the_old_document_for_history() {
    // No notary at all. This server held the old document before the
    // rotation; the new one does not list the old key; an event signed
    // with it before the rotation still verifies.
    let server = KeyServer::start().await;
    let (old, new) = (pair("old"), pair("new"));
    let clock = now_millis();
    server.serve(key_document(
        &server.name,
        &[&old],
        &[],
        clock + 600_000,
        &old,
    ));
    let harness = Harness::new(None);
    let alice = harness.register("alice").await;
    let (room, head) = harness.public_room(&alice).await;

    // Something signed with the old key, while it was current: the old
    // document is fetched and kept.
    let event = join(
        &harness.store,
        &server.name,
        &old,
        &room,
        &head,
        clock - 1_000,
    );
    let result = harness.deliver(&server.name, &old, "t1", vec![event]).await;
    assert_eq!(result, json!({}), "{result}");
    assert_eq!(server.fetches.load(Ordering::SeqCst), 1);

    // The server rotates without listing the old key.
    server.serve(key_document(
        &server.name,
        &[&new],
        &[],
        clock + 600_000,
        &new,
    ));
    // A peer naming a key we lack is refetched at most once per interval,
    // and the old document was fetched just clock.
    tokio::time::sleep(std::time::Duration::from_millis(10_500)).await;

    // A transaction signed with the new key, carrying the user's leave
    // signed with the old key before the rotation.
    let user = format!("@user:{}", server.name);
    let (_, state) = harness
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
    let head = state["chunk"][0]["event_id"].as_str().unwrap().to_owned();
    let leave = {
        let event = federation_auth::with_auth_events(
            &harness.store,
            json!({
                "type": "m.room.member",
                "state_key": user,
                "sender": user,
                "room_id": room,
                "content": { "membership": "leave" },
                "origin_server_ts": clock - 500,
                "depth": 11,
                "prev_events": [head],
                "auth_events": [],
            }),
        );
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&server.name, &old, &mut canonical, &rules.redaction).unwrap();
        serde_json::to_value(&canonical).unwrap()
    };
    let result = harness.deliver(&server.name, &new, "t2", vec![leave]).await;
    assert_eq!(result, json!({}), "{result}");
    assert_eq!(server.fetches.load(Ordering::SeqCst), 2, "one refetch");
    let metrics = &harness.metrics;
    assert!(metrics.key_fetch_count(KeySource::Cache, KeyFetchResult::Hit) >= 1);
    assert!(!harness.joined(&alice, &room, &user).await);
}
