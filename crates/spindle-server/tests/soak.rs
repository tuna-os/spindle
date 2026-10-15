//! #21's soak drill: sustained mixed load stays correct.
//!
//! For `SOAK_SECONDS` (default 120) the drill sends, incrementally syncs
//! and pages across two users and two rooms, asserting every response is
//! 200. At the end it asserts completeness -- every sent body comes back
//! in order -- and that steady-state send latency has not collapsed: the
//! last window's median send stays under both an absolute bound and a
//! generous multiple of the opening window's median (medians, not maxima,
//! so one compaction stall cannot fail the drill).
//!
//! What it deliberately does not assert is a memory ceiling. Payloads are
//! small on purpose so growth would come from overhead, but RSS in-process
//! mixes allocator retention with leaks, and a number picked here would
//! be either vacuous or flaky. The drill proves the server keeps serving
//! correctly under sustained load; residency is a profiling question, not
//! a gate.
//!
//! Like the slow-destination drill this needs no privileges, so it is an
//! ordinary (non-ignored) test.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

/// Sustained-load window. Long enough that background work (compaction,
/// sync pruning, delivery retries) actually runs mid-drill.
const DEFAULT_SOAK_SECONDS: u64 = 120;
/// A median send slower than this is a collapse, not noise: in-process
/// sends cost milliseconds.
const SEND_MEDIAN_CEILING: Duration = Duration::from_millis(100);
/// Opening-to-closing median ratio past this is degradation, not growth:
/// the room holds thousands more events at the end, so some slowdown is
/// honest, but an order of magnitude is not logarithmic cost.
const DEGRADATION_FACTOR: f64 = 10.0;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    #[allow(dead_code, reason = "the app borrows nothing; the store outlives it")]
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        Self { dir, store, app }
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
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        self.call(request).await
    }

    async fn register(&self, username: &str) -> (String, String) {
        let (status, body) = self
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
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }
}

fn median(mut samples: Vec<Duration>) -> Duration {
    assert!(!samples.is_empty());
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Completeness: every sent body pages back, newest first per room.
async fn check_complete(server: &Harness, token: &str, rooms: &[String], sent: &[(usize, u64)]) {
    for (room_idx, room) in rooms.iter().enumerate() {
        let expected: Vec<String> = sent
            .iter()
            .filter(|(room, _)| *room == room_idx)
            .map(|(_, seq)| {
                if seq % 4 < 2 {
                    format!("soak-a-{seq}")
                } else {
                    format!("soak-b-{seq}")
                }
            })
            .rev()
            .collect();
        let mut seen: Vec<String> = Vec::new();
        let mut from: Option<String> = None;
        while seen.len() < expected.len() {
            let path = match &from {
                Some(token) => {
                    format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50&from={token}")
                }
                None => format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
            };
            let (status, response) = server.authed("GET", &path, token, None).await;
            assert_eq!(status, StatusCode::OK, "{response}");
            let chunk = response["chunk"].as_array().cloned().unwrap_or_default();
            if chunk.is_empty() {
                break;
            }
            for event in &chunk {
                if event["type"] == "m.room.message"
                    && let Some(body) = event["content"]["body"].as_str()
                    && body.starts_with("soak-")
                {
                    seen.push(body.to_owned());
                }
            }
            from = response["end"].as_str().map(str::to_owned);
            if from.is_none() {
                break;
            }
        }
        assert_eq!(seen, expected, "room {room} lost or reordered messages");
    }
}

/// Sustained mixed load stays correct: every send, sync and page is 200,
/// every sent body comes back, and send latency does not collapse.
/// Two users, two rooms, both joined to both: each user creates one room
/// and invites the other. Returns the access tokens and the room IDs.
async fn setup_two_rooms(server: &Harness) -> ((String, String), Vec<String>) {
    let (alice, alice_id) = server.register("alice").await;
    let (bob, bob_id) = server.register("bob").await;
    let mut rooms = Vec::new();
    for (creator, guest, guest_id) in [(&alice, &bob, &bob_id), (&bob, &alice, &alice_id)] {
        let (status, body) = server
            .authed(
                "POST",
                "/_matrix/client/v3/createRoom",
                creator,
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = server
            .authed(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                creator,
                Some(&json!({ "user_id": guest_id })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = server
            .authed(
                "POST",
                &format!("/_matrix/client/v3/join/{room}"),
                guest,
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        rooms.push(room);
    }
    ((alice, bob), rooms)
}

#[tokio::test]
async fn sustained_mixed_load_stays_correct() {
    let soak = std::env::var("SOAK_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_SOAK_SECONDS);
    let deadline = Instant::now() + Duration::from_secs(soak);

    let server = Harness::new();
    let ((alice, bob), rooms) = setup_two_rooms(&server).await;

    // (room, sequence) per send, for the completeness check.
    let mut sent: Vec<(usize, u64)> = Vec::new();
    let mut send_latencies: Vec<(Instant, Duration)> = Vec::new();
    let mut sync_token: Option<String> = None;
    let mut seq = 0u64;
    let mut iterations = 0u64;
    while Instant::now() < deadline {
        let room_idx = (iterations % 2) as usize;
        let (token, body) = if iterations % 4 < 2 {
            (&alice, format!("soak-a-{seq}"))
        } else {
            (&bob, format!("soak-b-{seq}"))
        };
        let room = &rooms[room_idx];
        let started = Instant::now();
        let (status, response) = server
            .authed(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/soak{seq}"),
                token,
                Some(&json!({ "msgtype": "m.text", "body": body })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        send_latencies.push((started, started.elapsed()));
        sent.push((room_idx, seq));

        let sync_path = match &sync_token {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, response) = server.authed("GET", &sync_path, &alice, None).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        sync_token = response["next_batch"].as_str().map(str::to_owned);

        let (status, response) = server
            .authed(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=5"),
                token,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");

        seq += 1;
        iterations += 1;
    }
    assert!(iterations > 10, "the soak ended before it began");

    check_complete(&server, &alice, &rooms, &sent).await;

    // No latency collapse: compare opening and closing thirds by time.
    let first = send_latencies.first().unwrap().0;
    let last = send_latencies.last().unwrap().0;
    let span = last.saturating_duration_since(first);
    let opening: Vec<Duration> = send_latencies
        .iter()
        .filter(|(at, _)| at.saturating_duration_since(first) < span / 3)
        .map(|(_, elapsed)| *elapsed)
        .collect();
    let closing: Vec<Duration> = send_latencies
        .iter()
        .filter(|(at, _)| last.saturating_duration_since(*at) < span / 3)
        .map(|(_, elapsed)| *elapsed)
        .collect();
    let (open_median, close_median) = (median(opening), median(closing));
    assert!(
        close_median < SEND_MEDIAN_CEILING,
        "closing median send latency collapsed: {close_median:?} (opening {open_median:?})"
    );
    assert!(
        close_median.as_secs_f64() < open_median.as_secs_f64() * DEGRADATION_FACTOR,
        "send latency degraded {open_median:?} -> {close_median:?} over {iterations} iterations"
    );
}
