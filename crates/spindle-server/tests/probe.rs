//! Does the write path scale with the number of clients writing?
//!
//! Ignored by default and run on demand, like `spindle-store`'s scale
//! tests:
//!
//! ```text
//! cargo test -p spindle-server --test probe -- --ignored --nocapture
//! ```
//!
//! It prints rather than asserts. A throughput threshold would be a wall
//! clock on a shared runner, which this project does not gate on (#177);
//! what it reports is a **shape**, and the shape is build-independent.
//!
//! Group commit can only coalesce fsyncs that are in flight together, so
//! `rode` staying at zero however many clients are sending says the commits
//! never overlap -- and then the WAL is not the ceiling, the lock is.
//!
//! Measured on the group-commit branch, debug build, 8 tokio workers, 8
//! independent rooms:
//!
//! ```text
//! concurrency  sends/sec   fsyncs  rode  coalescing
//!           1        615      200     0       1.00x
//!           2        669      200     0       1.00x
//!           4        649      200     0       1.00x
//!           8        656      200     0       1.00x
//! ```
//!
//! Flat. Eight clients writing to eight different rooms get the throughput
//! of one, because `Rooms::with_room` holds a single process-wide mutex
//! across the commit and its fsync. Absolute figures are a debug build and
//! in-process; the flatness is the result.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement, not an assertion -- see the module docs"]
async fn concurrent_appends_to_different_rooms() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
    )
    .unwrap();
    let app = spindle_server::app(config, Arc::clone(&store)).unwrap();

    let (_, registered) = call(
        &app,
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "alice",
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    let token = registered["access_token"].as_str().unwrap().to_owned();

    // Eight separate rooms, so nothing but a shared lock could serialize them.
    let mut rooms = Vec::new();
    for _ in 0..8 {
        let (_, created) = call(
            &app,
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        rooms.push(created["room_id"].as_str().unwrap().to_owned());
    }

    // Sweep concurrency. If the server scales, sends/sec rises with the
    // number of clients in flight. If one lock serializes every append, it
    // does not move at all.
    println!("concurrency  sends/sec   fsyncs  rode  coalescing");
    for clients in [1usize, 2, 4, 8] {
        let per_client = 200 / clients;
        let before = store.group_commits();
        let start = std::time::Instant::now();

        let mut senders = Vec::new();
        for index in 0..clients {
            let app = app.clone();
            let token = token.clone();
            let room = rooms[index % rooms.len()].clone();
            let tag = format!("c{clients}-{index}");
            senders.push(tokio::spawn(async move {
                for message in 0..per_client {
                    let (status, body) = call(
                        &app,
                        Request::builder()
                            .method("PUT")
                            .uri(format!(
                                "/_matrix/client/v3/rooms/{room}/send/m.room.message/{tag}-{message}"
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
            }));
        }
        for sender in senders {
            sender.await.unwrap();
        }

        let elapsed = start.elapsed();
        let after = store.group_commits();
        let led = after.0 - before.0;
        let rode = after.1 - before.1;
        // Counts here are hundreds, so the lossy-cast lint is about a range
        // this loop cannot reach; the rates are for printing, not for a gate.
        #[allow(
            clippy::cast_precision_loss,
            reason = "printed rates over counts in the hundreds"
        )]
        let (rate, coalescing) = (
            (per_client * clients) as f64 / elapsed.as_secs_f64(),
            (led + rode) as f64 / led.max(1) as f64,
        );
        println!("{clients:>11}  {rate:>9.0}   {led:>6}  {rode:>4}  {coalescing:>9.2}x");
    }
}
