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

/// Pull one counter or bucket value out of a scrape.
///
/// `u64` rather than `f64`: every series asserted here is a count, and
/// comparing counts as floats is both imprecise and a lint away from
/// being wrong. Only `_sum` is fractional, and nothing here asserts it.
fn scrape(text: &str, needle: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(needle))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
}

#[tokio::test]
async fn serving_a_request_times_it_under_its_matched_route() {
    let server = Instance::start().await;
    let token = server.register("carol").await;

    // A route with parameters in it, so the label can be checked against
    // the template rather than the path that was actually requested.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/tx1"),
            Some(&token),
            Some(&json!({ "msgtype": "m.text", "body": "timed" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let text = metrics::render();
    let template = "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}";
    let count = scrape(
        &text,
        &format!("spindle_http_request_duration_seconds_count{{route=\"{template}\"}}"),
    )
    .unwrap_or_else(|| panic!("no histogram for {template} in {text}"));
    assert!(count >= 1, "the send was timed: {count}");

    // The label is the template, so the room ID must appear nowhere in
    // the exposition — that is the whole cardinality argument.
    assert!(
        !text.contains(&room),
        "a room ID leaked into a label: {text}"
    );

    let requests = scrape(
        &text,
        &format!(
            "spindle_http_requests_total{{route=\"{template}\",method=\"PUT\",status=\"200\"}}"
        ),
    )
    .unwrap_or_else(|| panic!("no request counter for {template} in {text}"));
    assert!(requests >= 1, "{requests}");
}

#[tokio::test]
async fn committing_an_event_times_the_append() {
    let server = Instance::start().await;
    let token = server.register("dave").await;
    let before = scrape(
        &metrics::render(),
        "spindle_append_duration_seconds_count{durability=\"group\"}",
    )
    .unwrap_or(0);

    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&token),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let text = metrics::render();
    let after = scrape(
        &text,
        "spindle_append_duration_seconds_count{durability=\"group\"}",
    )
    .expect("the append histogram exists once something has been appended");
    assert!(after > before, "{before} -> {after}");

    // A histogram is only usable if its buckets are cumulative and its
    // +Inf bucket equals the count — a scraper silently mis-renders it
    // otherwise.
    let inf = scrape(
        &text,
        "spindle_append_duration_seconds_bucket{durability=\"group\",le=\"+Inf\"}",
    )
    .expect("an +Inf bucket");
    assert_eq!(inf, after, "+Inf must equal the count");
    let mut previous = 0;
    for bound in ["0.0005", "0.001", "0.002", "0.005", "0.01", "2.5"] {
        let value = scrape(
            &text,
            &format!(
                "spindle_append_duration_seconds_bucket{{durability=\"group\",le=\"{bound}\"}}"
            ),
        )
        .unwrap_or_else(|| panic!("no le={bound} bucket in {text}"));
        assert!(value >= previous, "buckets must not decrease: {text}");
        previous = value;
    }
    assert!(previous <= inf, "no bucket may exceed +Inf");
}
