//! The counters move when the thing they count happens (#166).
//!
//! The rule the issue sets is that a metric which never moves is worse
//! than a missing one — a flat zero on a dashboard reads as health. So
//! these drive real traffic through a real server and assert the delta,
//! rather than asserting that the module compiles.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::metrics::{self, ForkCase, Origin};
use spindle_store::FjallStore;
use tempfile::TempDir;

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            client: reqwest::Client::new(),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username, "password": "hunter2hunter2",
                    "auth": { "type": "m.login.dummy", "session": "s" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn ordinary_traffic_moves_the_case_counters() {
    let server = Instance::start().await;
    let token = server.register("alice").await;

    let before_local = metrics::event_count(Origin::Local);
    let before_case1 = metrics::fork_case_count(ForkCase::NonState);
    let before_case2 = metrics::fork_case_count(ForkCase::StateUncontested);

    // Creating a room is a burst of state events (case 2); a message is a
    // non-state event (case 1). Both are local.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&token),
            Some(&json!({ "name": "Metrics" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/m1"),
            Some(&token),
            Some(&json!({ "msgtype": "m.text", "body": "hello" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    assert!(
        metrics::fork_case_count(ForkCase::NonState) > before_case1,
        "the message is a case-1 append"
    );
    assert!(
        metrics::fork_case_count(ForkCase::StateUncontested) > before_case2,
        "the room's state events are case-2 appends"
    );
    assert!(
        metrics::event_count(Origin::Local) > before_local,
        "and all of them are local"
    );
}

#[tokio::test]
async fn the_exposition_carries_what_the_counters_hold() {
    let server = Instance::start().await;
    let token = server.register("bob").await;
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The scrape is a rendering of the same counters, so it must agree
    // with them rather than being assembled separately.
    let text = metrics::render();
    let scraped = |needle: &str| -> u64 {
        text.lines()
            .find(|line| line.starts_with(needle))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("no {needle} in {text}"))
    };
    assert_eq!(
        scraped("spindle_events_appended_total{origin=\"local\"}"),
        metrics::event_count(Origin::Local)
    );
    assert_eq!(
        scraped("spindle_fork_resolutions_total{case=\"2\"}"),
        metrics::fork_case_count(ForkCase::StateUncontested)
    );
    assert!(text.contains("spindle_build_info{version="), "{text}");
}

/// Case 3 is the number the design is judged by, so its counter is wired
/// even though ingest cannot yet reach it: bounded resolution lives in
/// `spindle-core` but is not on the ingest path (#16). This asserts the
/// wiring — the counter and its series exist and are reachable — so that
/// #16's test has something to assert against when it lands.
#[test]
fn the_contested_case_is_wired_and_visible() {
    let before = metrics::fork_case_count(ForkCase::StateContested);
    metrics::record_contested_state(Origin::Federated);
    assert_eq!(
        metrics::fork_case_count(ForkCase::StateContested),
        before + 1
    );
    assert!(
        metrics::render().contains("spindle_fork_resolutions_total{case=\"3\"}"),
        "case 3 must have a series even at zero"
    );
}
