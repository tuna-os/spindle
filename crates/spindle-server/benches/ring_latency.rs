//! Ring dispatch latency: how long after a ring is appended each phone in
//! the room is told about it.
//!
//! The measurement #39 asks for. A `MatrixRTC` ring (MSC4075) is an event
//! like any other on the way in, and on the way out it is a notification
//! to every member it mentions, through the gateway each of their devices
//! registered. What matters to a call is the gap between the sender's
//! `PUT` returning and the gateway receiving the notification, and how it
//! grows with the room, because a ring in a large room is many
//! notifications to one URL.
//!
//! Two figures per room size, each a distribution over rings:
//!
//! - **first**: the earliest phone. Bounded below by the push loop's tick,
//!   which is where an event appended just after a pass waits; it should
//!   sit under one tick and not move with the size.
//! - **last**: the latest phone. Every member's notification goes to the
//!   same gateway in one batch, one round-trip each, so this grows with
//!   the room; the shape to read is whether it grows linearly with the
//!   member count and no worse.
//!
//! Like `delayed_firing`, this is wall-clock time against a real listener
//! and a real loop, so it is a measurement to take and record, not a
//! criterion benchmark and not a CI gate. The gateway here answers in
//! microseconds; a real one answers in milliseconds, and the *last* column
//! scales with that. Per #34 the output is the shape across sizes.
//!
//! Run with `cargo bench -p spindle-server --bench ring_latency`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_store::FjallStore;

/// Members with a pusher, per row. The sender is one more.
const SIZES: [usize; 3] = [10, 100, 1_000];
/// Rings per row: one at a time, each waited for in full.
const RINGS: usize = 20;

/// The gateway: records the instant each notification arrived.
#[derive(Clone, Default)]
struct Gateway {
    arrivals: Arc<Mutex<Vec<Instant>>>,
}

impl Gateway {
    async fn serve() -> (Self, String) {
        let gateway = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/_matrix/push/v1/notify",
            listener.local_addr().unwrap().port()
        );
        let app = axum::Router::new()
            .route(
                "/_matrix/push/v1/notify",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<Gateway>,
                     request: Request<Body>| async move {
                        let _ = axum::body::to_bytes(request.into_body(), 1024 * 1024).await;
                        state.arrivals.lock().unwrap().push(Instant::now());
                        axum::Json(json!({ "rejected": [] }))
                    },
                ),
            )
            .with_state(gateway.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (gateway, url)
    }

    fn count(&self) -> usize {
        self.arrivals.lock().unwrap().len()
    }

    /// Wait until `count` arrivals are recorded, then return them.
    async fn wait_for(&self, count: usize) -> Vec<Instant> {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(600);
        let mut reported = Duration::ZERO;
        loop {
            if self.count() >= count {
                return self.arrivals.lock().unwrap().clone();
            }
            if started.elapsed() - reported > Duration::from_secs(10) {
                reported = started.elapsed();
                eprintln!("waiting: {} of {count} after {reported:?}", self.count());
            }
            assert!(
                Instant::now() < deadline,
                "the gateway is still waiting: {} of {count}",
                self.count()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn clear(&self) {
        self.arrivals.lock().unwrap().clear();
    }
}

struct Instance {
    _dir: tempfile::TempDir,
    base: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [push]\nallow_internal = [\"127.0.0.0/8\"]\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            _dir: dir,
            base: format!("http://{name}"),
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: reqwest::Method, path: &str, token: &str, body: &Value) -> Value {
        let response = self
            .client
            .request(method, format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        let bytes = response.bytes().await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    async fn register(&self, username: &str) -> (String, String) {
        let body = self
            .call(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                "",
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }
}

/// A room with `members` pushered members besides the sender, and the
/// invites that summoned them already delivered.
async fn room_of(hs: &Instance, gateway: &Gateway, url: &str, members: usize) -> (String, String) {
    let (sender, _) = hs.register(&format!("caller{members}")).await;
    let room = hs
        .call(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            &sender,
            &json!({ "name": "The call" }),
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for number in 0..members {
        let (token, user_id) = hs.register(&format!("member{members}_{number}")).await;
        hs.call(
            reqwest::Method::POST,
            "/_matrix/client/v3/pushers/set",
            &token,
            &json!({
                "kind": "http",
                "app_id": "org.example.app",
                "pushkey": format!("key{number}"),
                "app_display_name": "App",
                "device_display_name": "Phone",
                "lang": "en",
                "data": { "url": url, "format": "event_id_only" },
            }),
        )
        .await;
        hs.call(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &sender,
            &json!({ "user_id": user_id }),
        )
        .await;
        hs.call(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            &token,
            &json!({}),
        )
        .await;
    }
    // Every invite pushed its invitee; let those land before timing.
    gateway.wait_for(members).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    gateway.clear();
    (sender, room)
}

/// The `percent`th percentile of `sorted`, nearest-rank.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted[(sorted.len() - 1) * percent / 100]
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (gateway, url) = Gateway::serve().await;
        let hs = Instance::start().await;
        println!("| pushered members | first p50 | first p99 | last p50 | last p99 | last max |");
        println!("|---|---|---|---|---|---|");
        for members in SIZES {
            let (sender, room) = room_of(&hs, &gateway, &url, members).await;
            let mut firsts = Vec::with_capacity(RINGS);
            let mut lasts = Vec::with_capacity(RINGS);
            for ring in 0..RINGS {
                gateway.clear();
                let sent = Instant::now();
                hs.call(
                    reqwest::Method::PUT,
                    &format!("/_matrix/client/v3/rooms/{room}/send/m.rtc.notification/ring{ring}"),
                    &sender,
                    &json!({
                        "m.mentions": { "room": true },
                        "notification_type": "ring",
                        "lifetime": 30_000,
                    }),
                )
                .await;
                let appended = Instant::now();
                let arrivals = gateway.wait_for(members).await;
                let first = arrivals.iter().min().unwrap();
                let last = arrivals.iter().max().unwrap();
                // Measured from the send's return: the append is inside the
                // request, and the request's own cost is bounded by `sent`.
                assert!(appended.duration_since(sent) < Duration::from_secs(1));
                firsts.push(first.saturating_duration_since(appended));
                lasts.push(last.saturating_duration_since(appended));
            }
            firsts.sort_unstable();
            lasts.sort_unstable();
            println!(
                "| {members} | {:.1} ms | {:.1} ms | {:.1} ms | {:.1} ms | {:.1} ms |",
                ms(percentile(&firsts, 50)),
                ms(percentile(&firsts, 99)),
                ms(percentile(&lasts, 50)),
                ms(percentile(&lasts, 99)),
                ms(*lasts.last().unwrap()),
            );
        }
    });
}
