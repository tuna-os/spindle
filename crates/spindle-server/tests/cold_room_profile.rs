//! Where the first sliding sync after a restart spends its time in a room
//! of very many events: the room's cold load, or the work the first render
//! of that room does on top of it.
//!
//! A measurement, not a gate, so it is `#[ignore]`d:
//!
//! ```text
//! SPINDLE_COLD_EVENTS=100000 cargo test -p spindle-server --release \
//!     --test cold_room_profile -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spindle_server::metrics::Metrics;
use spindle_store::FjallStore;
use tempfile::TempDir;

const SERVER: &str = "example.org";
const ALICE: &str = "@alice:example.org";
/// A member with no receipt: their unread boundary is their join, at the
/// start of the room, so counting for them still reads the whole room.
const BOB: &str = "@bob:example.org";

fn restarted(store: &Arc<FjallStore>) -> (axum::Router, spindle_server::AppState) {
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"{SERVER}\"\n[ratelimit]\nenabled = false\n"
    ))
    .unwrap();
    spindle_server::app_with_state(config, Arc::clone(store), Arc::new(Metrics::new())).unwrap()
}

async fn sliding(app: &axum::Router, token: &str) -> Value {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "lists": { "main": {
                    "ranges": [[0, 19]],
                    "required_state": [["m.room.name", ""], ["m.room.avatar", ""]],
                    "timeline_limit": 1,
                }}
            })
            .to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn time<T>(label: &str, work: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = work();
    println!("  {label:<44} {:>8.3}s", started.elapsed().as_secs_f64());
    out
}

/// A room alice created and bob joined, then `events` messages from
/// alice, with alice's receipt on the last. Returns alice's token and the
/// room.
fn seed(store: &Arc<FjallStore>, events: usize) -> (String, String) {
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let accounts = spindle_server::accounts::Accounts::new(store.as_ref(), SERVER);
    accounts.register("alice", "hunter2").unwrap();
    accounts.register("bob", "hunter2").unwrap();
    let token = accounts
        .create_session("alice", Some("PHONE".to_owned()), None, false)
        .unwrap()
        .access_token;
    let room = {
        let rooms = spindle_server::rooms::Rooms::new(Arc::clone(store), SERVER);
        let room = rooms
            .create(
                ALICE,
                key.pair(),
                Some("huge"),
                None,
                Some("public_chat"),
                &[],
                &[],
                None,
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        rooms
            .set_membership(&room, BOB, BOB, "join", None, key.pair())
            .unwrap();
        let started = Instant::now();
        let mut last = String::new();
        for n in 0..events {
            last = rooms
                .send(
                    &room,
                    ALICE,
                    key.pair(),
                    "m.room.message",
                    &json!({ "msgtype": "m.text", "body": format!("message {n}") }),
                )
                .unwrap();
        }
        println!(
            "seeded {events} messages in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        // A reader who keeps up: their receipt is at the head.
        rooms
            .set_receipt(&room, ALICE, "m.read", &last, None)
            .unwrap();
        room
    };
    (token, room)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "resource-envelope measurement; run explicitly with --ignored --release"]
async fn profile_first_sliding_sync_over_a_huge_room() {
    let events: usize = std::env::var("SPINDLE_COLD_EVENTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (token, room) = seed(&store, events);

    println!("restart 1, phase by phase:");
    {
        let (app, state) = restarted(&store);
        time("cold load (Rooms::warm)", || {
            state.rooms.warm(&room).unwrap();
        });
        time("first unread count", || {
            state.rooms.unread(&room, ALICE).unwrap()
        });
        let started = Instant::now();
        sliding(&app, &token).await;
        println!(
            "  {:<44} {:>8.3}s",
            "first sliding sync (room resident)",
            started.elapsed().as_secs_f64()
        );
        let started = Instant::now();
        sliding(&app, &token).await;
        println!(
            "  {:<44} {:>8.3}s",
            "second sliding sync (warm)",
            started.elapsed().as_secs_f64()
        );
    }
    println!("restart 2, end to end:");
    {
        let (app, _state) = restarted(&store);
        let started = Instant::now();
        let body = sliding(&app, &token).await;
        println!(
            "  {:<44} {:>8.3}s",
            "first sliding sync (cold)",
            started.elapsed().as_secs_f64()
        );
        assert!(body["rooms"].get(&room).is_some(), "{body}");
    }
    println!("restart 3, a reader whose boundary is the start of the room:");
    {
        let (_app, state) = restarted(&store);
        time("cold load (Rooms::warm)", || {
            state.rooms.warm(&room).unwrap();
        });
        time("first unread count, boundary at join", || {
            state.rooms.unread(&room, BOB).unwrap()
        });
        time("second unread count", || {
            state.rooms.unread(&room, BOB).unwrap()
        });
    }
    std::thread::sleep(Duration::from_millis(10));
}
