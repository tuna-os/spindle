//! A burst of password logins is bounded, not queued without end (#571).
//!
//! Each Argon2 hash needs a 19 MiB workspace. The process keeps at most
//! `[limits] password_hashes_at_once` of them and lets at most
//! `password_hashes_waiting` callers wait; past that a login is answered
//! 429 `M_LIMIT_EXCEEDED` at once. Before the bound, every login of a burst
//! waited its turn, each holding a thread, and nothing was ever refused.
//!
//! One test in its own binary: the hashing pool is process-wide and sized
//! by the first server the process builds, so another test's server here
//! would size it first.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

async fn call(app: axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn login() -> Value {
    json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": "alice" },
        "password": "correct horse",
    })
}

/// Logins started at once: more than the one workspace and empty queue
/// the server below is configured with.
const BURST: usize = 8;

// A multi-threaded runtime, as in production: the logins below run at the
// same time on different workers, not one after another on a single one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logins_past_the_hashing_queue_are_refused_429() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    // Login rate limits off, so any 429 below is the hashing bound's.
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
         [limits]\npassword_hashes_at_once = 1\npassword_hashes_waiting = 0\n",
    )
    .unwrap();
    let app = spindle_server::app(config, store).expect("the app builds");

    let (status, body) = call(
        app.clone(),
        "/_matrix/client/v3/register",
        json!({
            "username": "alice",
            "password": "correct horse",
            "auth": { "type": "m.login.dummy", "session": "register" },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let barrier = Arc::new(tokio::sync::Barrier::new(BURST));
    let logins: Vec<_> = (0..BURST)
        .map(|_| {
            let app = app.clone();
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                call(app, "/_matrix/client/v3/login", login()).await
            })
        })
        .collect();

    let (mut succeeded, mut refused) = (0, 0);
    for login in logins {
        let (status, body) = login.await.unwrap();
        match status {
            StatusCode::OK => succeeded += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
                assert!(body["retry_after_ms"].as_u64().unwrap() > 0, "{body}");
                refused += 1;
            }
            other => panic!("login answered {other}: {body}"),
        }
    }
    // One workspace and no queue: the first login to start hashes, and the
    // others that arrive while it hashes are refused rather than queued.
    assert!(succeeded >= 1, "{succeeded} succeeded, {refused} refused");
    assert!(refused >= 1, "{succeeded} succeeded, {refused} refused");

    // The refusals took nothing with them: the next login is answered.
    let (status, body) = call(app, "/_matrix/client/v3/login", login()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
