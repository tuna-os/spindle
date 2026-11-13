//! The default log filter is quiet about authorized events (#726).
//!
//! The vendored ruma-state-res logs two `INFO` lines for every event it
//! authorizes. At the old default of plain `info` they made up all of a
//! lightly used server's log. This test installs the filter a config without
//! `[logging] filter` gets, drives a stream of authorized events through the
//! app, and counts the library's per-event lines in what was logged.
//!
//! The subscriber is process-global, because room work runs on blocking
//! threads that a thread-local default would not reach. So this file holds
//! one test.

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::config::DEFAULT_LOG_FILTER;
use spindle_server::metrics::Metrics;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, reload};

/// Everything the log layer writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The lines ruma-state-res logs at `INFO` for each event it authorizes.
fn per_event_lines(log: &str) -> usize {
    log.lines()
        .filter(|line| {
            line.contains("check_state_dependent_auth_rules")
                || line.contains("allowing event passed all checks")
        })
        .count()
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post(app: &axum::Router, method: &str, path: &str, token: &str, body: &Value) -> Value {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !token.is_empty() {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let (status, body) = call(app, request.body(Body::from(body.to_string())).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    body
}

#[tokio::test]
async fn the_default_filter_logs_nothing_per_authorized_event() {
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
    )
    .unwrap();
    assert_eq!(config.logging.filter_directive(), DEFAULT_LOG_FILTER);

    let captured = Captured::default();
    let (filter, handle) = reload::Layer::new(EnvFilter::new(config.logging.filter_directive()));
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(captured.clone()),
        )
        .init();

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (app, _state) =
        spindle_server::app_with_state(config, store, Arc::new(Metrics::new())).unwrap();
    let registered = post(
        &app,
        "POST",
        "/_matrix/client/v3/register",
        "",
        &json!({
            "username": "alice",
            "password": "hunter2",
            "auth": { "type": "m.login.dummy", "session": "register" },
        }),
    )
    .await;
    let token = registered["access_token"].as_str().unwrap().to_owned();
    let room = post(
        &app,
        "POST",
        "/_matrix/client/v3/createRoom",
        &token,
        &json!({}),
    )
    .await;
    let room = room["room_id"].as_str().unwrap().to_owned();
    let message = |index: usize| {
        (
            format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t{index}"),
            json!({ "msgtype": "m.text", "body": format!("m{index}") }),
        )
    };
    for index in 0..10 {
        let (path, body) = message(index);
        post(&app, "PUT", &path, &token, &body).await;
    }
    let quiet = captured.text();
    assert_eq!(
        per_event_lines(&quiet),
        0,
        "the default filter logged per-event authorization lines:\n{quiet}"
    );

    // The same stream at plain `info`, the old default, does log them: the
    // zero above is the filter's doing, not a capture that saw nothing.
    handle.reload(EnvFilter::new("info")).unwrap();
    let (path, body) = message(10);
    post(&app, "PUT", &path, &token, &body).await;
    let loud = captured.text();
    assert!(
        per_event_lines(&loud[quiet.len()..]) >= 2,
        "plain `info` should show the library's lines:\n{loud}"
    );
}
