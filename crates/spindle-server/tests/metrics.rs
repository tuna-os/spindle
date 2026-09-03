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
    //
    // Bracketed rather than compared to a single reading. The counters are
    // process-global and every other test in this binary is appending to
    // them concurrently, so `render()` and a reading taken after it are
    // two different instants: asserting they are equal asserts that
    // nothing happened in between, which is not a property of the code.
    // The render happened inside this window, so its value has to lie in
    // it -- an exposition assembled from anywhere but these counters still
    // falls outside, which is what the test is for.
    let before_local = metrics::event_count(Origin::Local);
    let before_case2 = metrics::fork_case_count(ForkCase::StateUncontested);
    let text = metrics::render();
    let after_local = metrics::event_count(Origin::Local);
    let after_case2 = metrics::fork_case_count(ForkCase::StateUncontested);
    let scraped = |needle: &str| -> u64 {
        text.lines()
            .find(|line| line.starts_with(needle))
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("no {needle} in {text}"))
    };
    let local = scraped("spindle_events_appended_total{origin=\"local\"}");
    assert!(
        (before_local..=after_local).contains(&local),
        "exposition says {local} local appends, counters were \
         {before_local}..={after_local} across the render"
    );
    let case2 = scraped("spindle_fork_resolutions_total{case=\"2\"}");
    assert!(
        (before_case2..=after_case2).contains(&case2),
        "exposition says {case2} case-2 resolutions, counters were \
         {before_case2}..={after_case2} across the render"
    );
    assert!(text.contains("spindle_build_info{version="), "{text}");
}

/// Case 3 is the number the design is judged by, so its counter is wired
/// even though ingest cannot yet resolve it: bounded resolution lives in
/// `spindle-core` but is not on the ingest path (#16). This asserts the
/// wiring — the counter and its series exist and are reachable — so that
/// #16's test has something to assert against when it lands.
#[test]
fn the_contested_case_is_wired_and_visible() {
    let before = metrics::fork_case_count(ForkCase::StateContested);
    metrics::record_contested_state();
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

#[tokio::test]
async fn syncing_records_how_stale_the_newest_event_was() {
    let server = Instance::start().await;
    let token = server.register("erin").await;
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
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/lag1"),
            Some(&token),
            Some(&json!({ "msgtype": "m.text", "body": "fresh" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let before = scrape(&metrics::render(), "spindle_sync_lag_seconds_count{}").unwrap_or(0);
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/sync",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let text = metrics::render();
    let after = scrape(&text, "spindle_sync_lag_seconds_count{}")
        .expect("the lag histogram exists once a sync has delivered something");
    assert!(after > before, "{before} -> {after}");
    // A sync that just delivered an event created moments ago must land
    // in a low bucket; if it did not, the metric is measuring the wrong
    // clock rather than the lag.
    let quick =
        scrape(&text, "spindle_sync_lag_seconds_bucket{le=\"2.5\"}").expect("a 2.5s bucket");
    assert!(
        quick >= after,
        "a just-created event is not 2.5s stale: {text}"
    );
}

#[tokio::test]
async fn the_federation_queue_gauge_caps_its_label_set() {
    // Set directly: standing up 25 real peers to prove a cap is a slower
    // way to test the cap. What matters is that a large destination set
    // cannot mint a series per destination.
    let many: Vec<(String, u64)> = (0..25u64)
        .map(|n| (format!("peer{n}.example"), n + 1))
        .collect();
    spindle_server::metrics::set_federation_queue(&many);

    let text = metrics::render();
    let series = text
        .lines()
        .filter(|line| line.starts_with("spindle_federation_queue_depth{"))
        .count();
    assert!(
        series <= 21,
        "capped at 20 plus other, got {series}: {text}"
    );
    assert!(
        text.contains("spindle_federation_queue_depth{destination=\"other\"}"),
        "the tail is summed, not dropped: {text}"
    );
    // Deepest first, so the cap keeps the destinations worth looking at.
    assert!(
        text.contains("spindle_federation_queue_depth{destination=\"peer24.example\"} 25"),
        "{text}"
    );
    // And a fresh reading replaces rather than accumulates.
    spindle_server::metrics::set_federation_queue(&[("solo.example".to_owned(), 3)]);
    let text = metrics::render();
    assert!(!text.contains("peer24.example"), "stale gauge: {text}");
    assert!(text.contains("spindle_federation_queue_depth{destination=\"solo.example\"} 3"));
}

#[tokio::test]
async fn a_blocked_sync_shows_up_as_a_subscriber() {
    let server = Instance::start().await;
    let token = server.register("frank").await;

    // An initial sync returns at once — there is state to hand over, so
    // nothing waits. Only a sync from a known position with nothing new
    // reaches wait_for_event, which is the thing being counted.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/sync",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let since = body["next_batch"].as_str().unwrap().to_owned();

    // Sample for exactly as long as the request is in flight rather than
    // for a fixed number of ticks: under a loaded test run a fixed window
    // can expire before the request even reaches the server, which is a
    // flaky test rather than a real signal.
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiting = {
        let done = std::sync::Arc::clone(&done);
        async move {
            let result = server
                .request(
                    reqwest::Method::GET,
                    &format!("/_matrix/client/v3/sync?since={since}&timeout=1500"),
                    Some(&token),
                    None,
                )
                .await;
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            result
        }
    };
    let observing = async {
        let mut peak = 0;
        while !done.load(std::sync::atomic::Ordering::Relaxed) {
            peak = peak.max(metrics::sync_subscribers());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        peak
    };
    let ((status, body), peak) = tokio::join!(waiting, observing);
    assert_eq!(status, 200, "{body}");
    assert!(peak >= 1, "a blocked sync is a subscriber: {peak}");
}
