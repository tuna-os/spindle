//! What a send leaves behind when the store refuses a write part way
//! through it (#779, #780).
//!
//! The disk-full drill (`disk_full.rs`) fills a real filesystem, and the
//! write that does not fit is whichever one the disk refuses. These tests
//! choose the write with [`FjallStore::inject_fault`]. It refuses writes the
//! way fjall does after a failed write: every write and every sync from then
//! on.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::AppState;
use spindle_server::metrics::{BlockingTask, Metrics};
use spindle_store::{Fault, FjallStore};
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
    state: AppState,
    store: Arc<FjallStore>,
    metrics: Arc<Metrics>,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let (app, state) =
            spindle_server::app_with_state(config, Arc::clone(&store), Arc::clone(&metrics))
                .unwrap();
        Self {
            _dir: dir,
            app,
            state,
            store,
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

    async fn authed(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::post("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .authed(
                "POST",
                "/_matrix/client/v3/createRoom",
                token,
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, room: &str, token: &str, txn: &str, text: &str) -> (StatusCode, Value) {
        self.authed(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
            token,
            Some(&json!({ "msgtype": "m.text", "body": text })),
        )
        .await
    }

    /// The newest `limit` events of `room`, newest first.
    async fn newest(&self, room: &str, token: &str, limit: usize) -> Vec<Value> {
        let (status, body) = self
            .authed(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit={limit}"),
                token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["chunk"].as_array().unwrap().clone()
    }
}

/// #779: the send's batch lands, then the sync after it is refused, so the
/// send answers 5xx for an event the room holds.
///
/// The transaction was recorded after the event, by writes of its own,
/// which the full disk then refused too. The client's retry with the same
/// transaction ID found no record and sent the message a second time once
/// the disk had room. Now the record is in the event's batch: the retry is
/// answered with the event that landed, and the room holds it once.
#[tokio::test]
async fn a_send_answered_with_an_error_after_its_event_landed_is_replayed_not_resent() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    harness.store.inject_fault(Fault::AtNextSync);
    let (status, body) = harness.send(&room, &alice, "txn1", "once").await;
    assert!(
        status.is_server_error(),
        "the refused sync is the send's error: {status} {body}"
    );
    let newest = harness.newest(&room, &alice, 2).await;
    assert_eq!(
        newest[0]["content"]["body"],
        json!("once"),
        "the event landed before the sync failed: {newest:?}"
    );
    let landed = newest[0]["event_id"].as_str().unwrap().to_owned();
    assert_eq!(
        newest[0]["unsigned"]["transaction_id"],
        json!("txn1"),
        "the transaction's echo row landed with the event: {newest:?}"
    );

    let (status, body) = harness.send(&room, &alice, "txn1", "once").await;
    assert_eq!(
        (status, &body["event_id"]),
        (StatusCode::OK, &json!(landed)),
        "the retry is answered with the event that landed: {body}"
    );
    let newest = harness.newest(&room, &alice, 2).await;
    assert_eq!(newest[0]["event_id"], json!(landed));
    assert_ne!(
        newest[1]["content"]["body"],
        json!("once"),
        "the retry sent the message again: {newest:?}"
    );
}

/// #780: a send whose batch the store refuses, while another room's batch
/// lands between the moment it starts and its own commit.
///
/// That other batch moves the store's journal count, so the send syncs
/// after its work, and the sync fails on the same refusing store. The room
/// whose batch was refused had appended its entry in memory first, and
/// `with_room` returned the sync's error before it evicted the room. The
/// entry stayed in memory with no body stored, so the room's next read
/// failed. Now the room is evicted whatever the sync did, and the next read
/// reloads it from the store.
///
/// Both orderings are pinned with the room's lock, held on a plain thread:
/// the send starts and waits on it, the other room's send lands, the store
/// starts to refuse, and then the lock is let go. Waits are on the test's
/// own thread, never on a runtime timer.
#[test]
fn a_room_whose_write_was_refused_holds_nothing_the_store_does_not() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let harness = Arc::new(Harness::new());
        let alice = harness.register("alice").await;
        let refused_room = harness.create_room(&alice).await;
        let other_room = harness.create_room(&alice).await;
        let (status, body) = harness
            .send(&refused_room, &alice, "stored", "stored")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (release, holder) =
            hold_on_a_thread(harness.state.rooms.lock_for_test(&refused_room).unwrap());
        let refused = {
            let harness = Arc::clone(&harness);
            let (room, token) = (refused_room.clone(), alice.clone());
            tokio::spawn(async move { harness.send(&room, &token, "refused", "refused").await })
        };
        wait_on_this_thread("the send waits on the held room", || {
            harness.metrics.blocking_in_flight(BlockingTask::LockWait) >= 1
        });

        let journalled = harness.store.journalled();
        let (status, body) = harness.send(&other_room, &alice, "other", "other").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            harness.store.journalled() > journalled,
            "the other room's batch moves the journal count"
        );

        harness.store.inject_fault(Fault::Now);
        release.send(()).unwrap();
        holder.join().unwrap();
        let (status, body) = refused.await.unwrap();
        assert!(
            status.is_server_error(),
            "the refused batch is the send's error: {status} {body}"
        );

        let newest = harness.newest(&refused_room, &alice, 1).await;
        assert_eq!(
            newest[0]["content"]["body"],
            json!("stored"),
            "the room serves what the store holds: {newest:?}"
        );
    });
}

/// Take `lock` for writing on a plain thread, and hold it until the sender
/// is used.
fn hold_on_a_thread<T: Send + Sync + 'static>(
    lock: Arc<std::sync::RwLock<T>>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _guard = lock.write().unwrap();
        held_tx.send(()).unwrap();
        let _ = release_rx.recv();
    });
    held_rx.recv().unwrap();
    (release_tx, holder)
}

/// Poll `done` on the calling thread, never on a runtime timer.
fn wait_on_this_thread(what: &str, done: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !done() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "{what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
