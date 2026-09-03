//! The delivery loops do not own what they read (#292).
//!
//! `spindle_server::app` spawns four loops that run for the life of the
//! process: delayed-event firing, the federation outbox drain, the
//! appservice push and push-gateway delivery. A runtime tears its tasks down
//! as it shuts down, and a task dropped that way is the wrong place for the store to close: fjall's
//! close joins its worker threads, and #292 caught it waiting forever there,
//! in a test whose assertions had all passed. So the loops hold their
//! sources weakly: the store closes where its last owner -- the router --
//! is dropped, and each loop returns on its next pass.
//!
//! Idle is the easy case. A loop that upgraded for a pass and is awaiting a
//! peer's answer holds what it upgraded for as long as the peer takes, and
//! a runtime shutting down cancels it right there. So the second half of
//! the claim is that a pass lets go of its sources before it sends: the
//! router is dropped with a request of each sending loop in flight, and the
//! store must be gone at once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use spindle_core::keys;
use spindle_store::{FjallStore, Store};
use tempfile::TempDir;
use tower::ServiceExt;

/// A router with all four loops running and its peers on loopback. The
/// appservice push only starts for a registration with a URL, so one is
/// supplied; the federation and push settings let the outbox and the
/// push loop reach a loopback stub.
fn app_with_every_loop(dir: &TempDir, store: Arc<FjallStore>, bridge_url: &str) -> axum::Router {
    let registration = dir.path().join("bridge.yaml");
    std::fs::write(
        &registration,
        format!(
            "id: bridge\nurl: \"{bridge_url}\"\nas_token: as_token\n\
             hs_token: hs_token\nsender_localpart: _bridge\n\
             namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
        ),
    )
    .unwrap();
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
         [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n\
         retry_base_ms = 50\n\
         [push]\nallow_internal = [\"127.0.0.0/8\"]\n\
         [appservices]\nregistrations = [\"{}\"]\n",
        registration.display()
    ))
    .unwrap();
    spindle_server::app(config, store).expect("the app builds")
}

/// A peer that accepts every connection and answers none of them: what a
/// delivery loop is waiting on while its request is in flight. Released,
/// every held connection closes and the waiting request fails at once.
struct StalledPeer {
    /// `host:port`, which is a federation destination as well as the host
    /// of an appservice URL.
    address: String,
    accepted: Arc<AtomicUsize>,
    held: Arc<Mutex<Vec<tokio::net::TcpStream>>>,
    acceptor: tokio::task::JoinHandle<()>,
}

impl StalledPeer {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let accepted = Arc::new(AtomicUsize::new(0));
        let held: Arc<Mutex<Vec<tokio::net::TcpStream>>> = Arc::default();
        let acceptor = tokio::spawn({
            let accepted = Arc::clone(&accepted);
            let held = Arc::clone(&held);
            async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    held.lock().unwrap().push(stream);
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        Self {
            address,
            accepted,
            held,
            acceptor,
        }
    }

    /// Wait until a request has reached this peer and is waiting on it.
    async fn wait_for_a_request(&self) {
        for _ in 0..200 {
            if self.accepted.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no request reached the stalled peer");
    }

    /// Close every held connection and stop accepting, so the loop that
    /// was waiting fails its request and takes its next pass.
    async fn release(self) {
        self.acceptor.abort();
        let _ = self.acceptor.await;
        self.held.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn dropping_the_router_closes_the_store_and_ends_every_loop() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let observer: Weak<FjallStore> = Arc::downgrade(&store);
    // Nothing listens on port 9, and nothing is ever queued for it.
    let app = app_with_every_loop(&dir, store, "http://127.0.0.1:9");
    let tasks = tokio::runtime::Handle::current().metrics();
    assert_eq!(tasks.num_alive_tasks(), 4, "the four delivery loops");

    // Every loop has taken at least one pass with the router alive, which
    // is where a loop that upgraded once and kept the result would show.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(tasks.num_alive_tasks(), 4, "the loops outlive a pass");

    drop(app);
    assert!(
        observer.upgrade().is_none(),
        "the router was the store's last owner; a loop is holding it"
    );

    // Each loop notices on its next pass; the slowest ticks once a second.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        tasks.num_alive_tasks(),
        0,
        "a loop is still running after its sources are gone"
    );
}

/// The outbox drain, with a transaction in flight to a peer that never
/// answers, is not holding the store.
#[tokio::test]
async fn a_transaction_in_flight_does_not_keep_the_store_alive() {
    let dir = TempDir::new().unwrap();
    let peer = StalledPeer::start().await;
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    // One PDU queued for the peer, as the send path queues it, before the
    // router exists so the drain's first pass finds it.
    store
        .put(
            &keys::federation_outbox(&peer.address, 1),
            br#"{"type":"m.room.message","content":{"body":"queued"}}"#,
        )
        .unwrap();
    let observer: Weak<FjallStore> = Arc::downgrade(&store);
    let app = app_with_every_loop(&dir, store, "http://127.0.0.1:9");
    let tasks = tokio::runtime::Handle::current().metrics();

    // The drain is inside its send now, waiting on the peer.
    peer.wait_for_a_request().await;
    drop(app);
    assert!(
        observer.upgrade().is_none(),
        "the router is gone and the outbox drain, mid-send, still holds the store"
    );

    // Released, the request fails, and the drain's next pass finds its
    // sources gone. The acceptor is aborted with the release, so what is
    // left alive is the loops, and they must all have returned.
    peer.release().await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        tasks.num_alive_tasks(),
        0,
        "a loop is still running after its sources are gone"
    );
}

/// The appservice push, with a transaction in flight to a bridge that
/// never answers, is not holding the store.
#[tokio::test]
async fn an_appservice_push_in_flight_does_not_keep_the_store_alive() {
    let dir = TempDir::new().unwrap();
    let bridge = StalledPeer::start().await;
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let observer: Weak<FjallStore> = Arc::downgrade(&store);
    let app = app_with_every_loop(&dir, store, &format!("http://{}", bridge.address));
    let tasks = tokio::runtime::Handle::current().metrics();

    // Something to push: a room the bridge's ghost created is one the
    // bridge is interested in, and its creation events are the batch.
    let response = app
        .clone()
        .oneshot(
            Request::post("/_matrix/client/v3/createRoom?user_id=@_bridge_ghost:example.org")
                .header("authorization", "Bearer as_token")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The push is inside its delivery now, waiting on the bridge.
    bridge.wait_for_a_request().await;
    drop(app);
    assert!(
        observer.upgrade().is_none(),
        "the router is gone and the appservice push, mid-send, still holds the store"
    );

    bridge.release().await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        tasks.num_alive_tasks(),
        0,
        "a loop is still running after its sources are gone"
    );
}

/// One JSON request against the router, as a client would make it.
async fn post_json(
    app: &axum::Router,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::post(uri).header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn register(app: &axum::Router, username: &str) -> String {
    let (status, body) = post_json(
        app,
        "/_matrix/client/v3/register",
        None,
        serde_json::json!({
            "username": username,
            "password": "hunter2",
            "auth": { "type": "m.login.dummy", "session": "register" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

/// The push loop, with a notification in flight to a gateway that never
/// answers, is not holding the store.
#[tokio::test]
async fn a_push_in_flight_does_not_keep_the_store_alive() {
    let dir = TempDir::new().unwrap();
    let gateway = StalledPeer::start().await;
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let observer: Weak<FjallStore> = Arc::downgrade(&store);
    let app = app_with_every_loop(&dir, store, "http://127.0.0.1:9");
    let tasks = tokio::runtime::Handle::current().metrics();

    // Something to push: alice's phone is registered with the gateway,
    // and an invite from bob is what `.m.rule.invite_for_me` reaches her
    // with before she is a member of anything.
    let alice = register(&app, "alice").await;
    let bob = register(&app, "bob").await;
    let (status, body) = post_json(
        &app,
        "/_matrix/client/v3/pushers/set",
        Some(&alice),
        serde_json::json!({
            "pushkey": "phone",
            "kind": "http",
            "app_id": "org.example.app",
            "app_display_name": "Example",
            "device_display_name": "Phone",
            "lang": "en",
            "data": { "url": format!("http://{}/_matrix/push/v1/notify", gateway.address) },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post_json(
        &app,
        "/_matrix/client/v3/createRoom",
        Some(&bob),
        serde_json::json!({ "invite": ["@alice:example.org"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The push loop is inside its send now, waiting on the gateway.
    gateway.wait_for_a_request().await;
    drop(app);
    assert!(
        observer.upgrade().is_none(),
        "the router is gone and the push loop, mid-send, still holds the store"
    );

    gateway.release().await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        tasks.num_alive_tasks(),
        0,
        "a loop is still running after its sources are gone"
    );
}
