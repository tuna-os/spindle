//! Which requests make the whole server wait?
//!
//! Two locks, and the difference between them is the point.
//!
//! The **registry** maps room ids to their locks and is one lock for the
//! entire process, so taking it exclusively stalls every request for every
//! room. It is taken exclusively only to admit a room this process has not
//! opened before.
//!
//! A **room's** lock is taken shared to read it and exclusively to append
//! to it. Contention there is confined to that room -- which is the
//! ordering the log rests on, not a defect -- and two requests for
//! different rooms do not meet at all.
//!
//! The exposition counts both (#166), so "what does this endpoint block"
//! is a subtraction.
//!
//! Counted rather than timed, for the reason `read_budget.rs` gives and
//! then some: the run-to-run spread on the host this was written on is
//! 10-14% with worse outliers, wider than the effect a lock split
//! produces. A wall clock here would measure the machine's mood; a count
//! is the same number everywhere.
//!
//! The counters are process-global, as `metrics` explains, so the reads
//! and the write live in one sequential test rather than two that would
//! race: one asserts an exact delta the other would perturb.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (_, body) = self
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
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn room(&self, token: &str) -> String {
        let (_, created) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        created["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, room: &str, token: &str, txn: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "msgtype": "m.text", "body": "x" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// `(exclusive, shared)` acquisitions of the named counter.
    ///
    /// Read out of `metrics::render()` -- the same function the `/metrics`
    /// listener serves -- rather than a test-only accessor, so the number
    /// the test trusts is the number an operator scrapes.
    fn acquisitions(metric: &str) -> (u64, u64) {
        let text = spindle_server::metrics::render();
        let read = |mode: &str| {
            text.lines()
                .find(|line| line.starts_with(metric) && line.contains(mode))
                .and_then(|line| line.rsplit(' ').next())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("no {metric} {mode} in the exposition:\n{text}"))
        };
        (read("exclusive"), read("shared"))
    }

    fn room_locks() -> (u64, u64) {
        Self::acquisitions("spindle_room_lock_acquisitions_total")
    }

    fn registry_locks() -> (u64, u64) {
        Self::acquisitions("spindle_room_registry_acquisitions_total")
    }

    async fn sync(&self, token: &str, since: Option<&str>) -> Value {
        let uri = match since {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// Reads take a room shared, writes take it exclusively, and neither
/// touches the process-wide registry exclusively once the room is open.
///
/// One test rather than three, because the counters are process-global and
/// separate tests would perturb each other's deltas.
///
/// Which calls count as reads is decided by the compiler rather than by
/// judgement: `with_room_read` hands its closure `&RoomLog`, so anything
/// that mutates the log fails to build and stays on the writer.
///
/// The write half is here so the read half cannot be satisfied by making
/// everything shared: append ordering rests on writers to one room
/// excluding each other, and a change that quietly relaxed that would pass
/// a test which only checked reads.
///
/// The registry half is the one that changed with per-room locks. Before,
/// an append took the registry exclusively and so stalled every request for
/// every *other* room; now it takes the registry shared and the room
/// exclusively, which is what lets appends to different rooms proceed at
/// once.
#[tokio::test]
async fn rooms_are_locked_but_the_registry_is_not() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.room(&alice).await;
    harness.send(&room, &alice, "seed").await;
    let batch = harness.sync(&alice, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    // One sync first, to warm what a first sync legitimately builds: the
    // unread index is walked once per room per process, and that build
    // takes the room exclusively on purpose so no append slips past it
    // unindexed. The claim being pinned is about the *steady state*, which
    // is every sync after that one, for every room, forever.
    harness.sync(&alice, None).await;
    // And something for the incremental sync to actually report: with no
    // change since the token it correctly touches no room at all, which
    // would make the probe measure nothing rather than measure zero.
    harness.send(&room, &alice, "after-the-token").await;

    for (what, since) in [
        ("a warm initial sync", None),
        ("a warm incremental sync", Some(batch.clone())),
    ] {
        let rooms_before = Harness::room_locks();
        let registry_before = Harness::registry_locks();
        harness.sync(&alice, since.as_deref()).await;
        let rooms_after = Harness::room_locks();
        let registry_after = Harness::registry_locks();

        assert_eq!(
            rooms_after.0,
            rooms_before.0,
            "{what} took a room exclusively {} time(s)",
            rooms_after.0 - rooms_before.0
        );
        assert!(
            rooms_after.1 > rooms_before.1,
            "{what} read no room at all -- the probe is measuring nothing"
        );
        assert_eq!(
            registry_after.0, registry_before.0,
            "{what} took the process-wide registry exclusively"
        );
    }

    let rooms_before = Harness::room_locks();
    let registry_before = Harness::registry_locks();
    harness.send(&room, &alice, "one-more").await;
    let rooms_after = Harness::room_locks();
    let registry_after = Harness::registry_locks();
    assert!(
        rooms_after.0 > rooms_before.0,
        "a send took no room exclusively: appends to one room are no longer serialised"
    );
    assert_eq!(
        registry_after.0, registry_before.0,
        "a send took the process-wide registry exclusively, so it stalled every \
         request for every other room -- which is the thing per-room locks removed"
    );
}
