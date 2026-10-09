//! #614: a restarted server answers promptly.
//!
//! Two failures in production, one cause underneath: room work done on the
//! async workers. The first sliding sync after a restart cold-loaded every
//! room the account was in, just to read one timestamp from each for the
//! sort, and took 105 s for an account in a room of a million events. And
//! with the four workers busy loading and ingesting, `/health` -- which
//! does nothing -- could not be polled for 95 s, and the kubelet killed a
//! server that was only busy.
//!
//! What is pinned here: ordering the room list loads no room; the cost of
//! the first request does not grow with the size of rooms outside its
//! window; the warm-up loads what it should; and liveness answers while
//! every request that touches a room is stuck behind that room's lock.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spindle_server::metrics::{BlockingTask, Metrics, RoomSize, SyncPhase};
use spindle_store::FjallStore;
use tempfile::TempDir;

const SERVER: &str = "example.org";
const ALICE: &str = "@alice:example.org";

/// A store holding `sizes.len()` rooms alice created, the `i`th with
/// `sizes[i]` extra messages, written oldest-first so the *last* room is the
/// newest. Returns alice's access token and the rooms, newest first.
fn seed(store: &Arc<FjallStore>, sizes: &[usize]) -> (String, Vec<String>) {
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let accounts = spindle_server::accounts::Accounts::new(store.as_ref(), SERVER);
    accounts.register("alice", "hunter2").unwrap();
    let token = accounts
        .create_session("alice", Some("PHONE".to_owned()), None, false)
        .unwrap()
        .access_token;
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(store), SERVER);
    let mut created = Vec::new();
    for (index, size) in sizes.iter().enumerate() {
        let room = rooms
            .create(
                ALICE,
                key.pair(),
                Some(&format!("room {index}")),
                None,
                None,
                &[],
                &[],
                None,
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        for n in 0..*size {
            rooms
                .send(
                    &room,
                    ALICE,
                    key.pair(),
                    "m.room.message",
                    &json!({ "msgtype": "m.text", "body": format!("{n}") }),
                )
                .unwrap();
        }
        // Distinct origin timestamps, so the order is unambiguous.
        std::thread::sleep(Duration::from_millis(3));
        rooms
            .send(
                &room,
                ALICE,
                key.pair(),
                "m.room.message",
                &json!({ "msgtype": "m.text", "body": "latest" }),
            )
            .unwrap();
        created.push(room);
    }
    created.reverse();
    (token, created)
}

/// A server over `store` as a restart would find it: nothing resident.
struct Restarted {
    app: axum::Router,
    state: spindle_server::AppState,
    metrics: Arc<Metrics>,
}

impl Restarted {
    fn over(store: &Arc<FjallStore>) -> Self {
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{SERVER}\"\n[ratelimit]\nenabled = false\n"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let (app, state) =
            spindle_server::app_with_state(config, Arc::clone(store), Arc::clone(&metrics))
                .unwrap();
        Self {
            app,
            state,
            metrics,
        }
    }

    async fn sliding(&self, token: &str, range: (usize, usize)) -> Value {
        use tower::ServiceExt as _;
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "lists": { "main": {
                        "ranges": [[range.0, range.1]],
                        "required_state": [["m.room.name", ""]],
                        "timeline_limit": 1,
                    }}
                })
                .to_string(),
            ))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, 200, "{body}");
        body
    }
}

/// The room list is sorted without loading a single room: only the room in
/// the window is loaded, to render it. And the order is the one a fully
/// loaded server gives -- newest activity first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordering_the_room_list_loads_no_room() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (token, newest_first) = seed(&store, &[0, 0, 0, 0, 0, 0]);

    let server = Restarted::over(&store);
    assert_eq!(server.metrics.cold_loads_total(), 0);

    for (position, expected) in newest_first.iter().enumerate() {
        let before = server.metrics.cold_loads_total();
        let response = server.sliding(&token, (position, position)).await;
        assert_eq!(response["lists"]["main"]["count"], newest_first.len());
        let rooms = response["rooms"].as_object().unwrap();
        assert_eq!(
            rooms.keys().collect::<Vec<_>>(),
            vec![expected],
            "position {position} holds the room with the {position}th newest activity"
        );
        assert!(
            server.metrics.cold_loads_total() - before <= 1,
            "at most the window's own room is loaded, never the list's"
        );
    }
    // After a pass over every window, everything is resident; the sort read
    // its keys from the store, so before the pass nothing was.
    assert_eq!(
        server.metrics.cold_loads_total(),
        newest_first.len() as u64,
        "each room was loaded once, by the request whose window held it"
    );
    assert!(server.metrics.sync_phases(SyncPhase::SlidingOrder) >= 1);
    assert!(server.metrics.sync_phases(SyncPhase::SlidingAssemble) >= 1);
    assert_eq!(
        server.metrics.blocking_in_flight(BlockingTask::SlidingSync),
        0
    );

    // The same order a warm server gives: every room is resident now, and
    // the sort keys came from memory this time.
    for (position, expected) in newest_first.iter().enumerate() {
        let response = server.sliding(&token, (position, position)).await;
        assert!(response["rooms"].get(expected).is_some(), "{response}");
    }
}

/// The first request's cost does not scale with the size of rooms outside
/// its window. A big room is old, so the window (the newest room) does not
/// hold it; before #614 it was loaded anyway, for its sort key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_request_latency_does_not_scale_with_room_size() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    // Oldest first: the big room, then two small ones.
    let (token, newest_first) = seed(&store, &[2_000, 1, 1]);
    let big = newest_first.last().unwrap().clone();

    let server = Restarted::over(&store);
    let started = Instant::now();
    let response = server.sliding(&token, (0, 0)).await;
    let first = started.elapsed();
    assert!(response["rooms"].get(&newest_first[0]).is_some());
    assert!(
        !server.state.rooms.is_resident(&big),
        "the big room is outside the window and must stay cold"
    );
    assert_eq!(
        server.metrics.cold_loads(RoomSize::Under10k),
        0,
        "no room of a thousand events or more was loaded"
    );

    // For contrast, what the old path paid: the big room's own load.
    let started = Instant::now();
    server.state.rooms.warm(&big).unwrap();
    let big_load = started.elapsed();
    assert_eq!(server.metrics.cold_loads(RoomSize::Under10k), 1);
    eprintln!(
        "#614 evidence: first sliding sync {first:?} with a {}-event room outside the \
         window; that room's cold load alone {big_load:?}",
        2_002
    );
}

/// The warm-up loads every room alice is in, newest first, and counts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_warm_up_loads_every_joined_room() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (_token, newest_first) = seed(&store, &[0, 3, 0]);

    let server = Restarted::over(&store);
    assert_eq!(
        server.state.rooms.warm_candidates().unwrap(),
        newest_first,
        "local joins, newest activity first"
    );
    spindle_server::spawn_room_warmup(&server.state.rooms, &server.metrics, 2);
    let deadline = Instant::now() + Duration::from_secs(30);
    while server.metrics.warmup_loaded_count() < newest_first.len() as u64 {
        assert!(Instant::now() < deadline, "the warm-up finishes");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for room in &newest_first {
        assert!(server.state.rooms.is_resident(room));
    }
    let text = server.metrics.render();
    assert!(text.contains("spindle_room_warmup_pending 0"), "{text}");
    assert!(text.contains("spindle_rooms_resident 3"), "{text}");
    assert!(server.state.rooms.warm_candidates().unwrap().is_empty());
}

/// Liveness is answered while every request that touches a room is stuck
/// behind that room's lock -- the shape of #614, where an ingest held a big
/// room for a backlog and requests for it piled up on the async workers.
/// Two workers, and four times as many stuck requests as workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_answers_while_room_requests_are_blocked() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (token, newest_first) = seed(&store, &[2]);
    let room = newest_first[0].clone();

    let server = Restarted::over(&store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = server.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Stand in for the ingest: hold the room exclusively on a plain thread.
    let lock = server.state.rooms.lock_for_test(&room).unwrap();
    let (held, release) = (
        std::sync::mpsc::channel::<()>(),
        std::sync::mpsc::channel::<()>(),
    );
    let (held_tx, held_rx) = held;
    let (release_tx, release_rx) = release;
    let holder = std::thread::spawn(move || {
        let _guard = lock.write().unwrap();
        held_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    held_rx.recv().unwrap();

    let client = reqwest::Client::new();
    let base = format!("http://{address}");
    let mut stuck = Vec::new();
    for n in 0..8 {
        let client = client.clone();
        let token = token.clone();
        let base = base.clone();
        let room = room.clone();
        stuck.push(tokio::spawn(async move {
            // Classic sync, sliding sync, and a plain room read, which is
            // not offloaded at all: its wait on the room lock is what must
            // not hold a worker.
            let request = match n % 3 {
                0 => client.get(format!("{base}/_matrix/client/v3/sync")),
                1 => client
                    .post(format!(
                        "{base}/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"
                    ))
                    .header("content-type", "application/json")
                    .body(
                        json!({ "lists": { "main": {
                            "ranges": [[0, 0]], "timeline_limit": 1,
                        }}})
                        .to_string(),
                    ),
                _ => client.get(format!(
                    "{base}/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                )),
            };
            request.bearer_auth(token).send().await.map(|r| r.status())
        }));
    }
    // Let them all reach the lock.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for _ in 0..5 {
        let started = Instant::now();
        let response = client
            .get(format!("{base}/health"))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .expect("liveness answers within the probe's 1 s timeout");
        assert_eq!(response.status(), 200);
        assert!(started.elapsed() < Duration::from_secs(1));
        let response = client
            .get(format!("{base}/ready"))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .expect("readiness answers too");
        assert_eq!(response.status(), 200);
    }
    let off_the_workers: u64 = [
        BlockingTask::Sync,
        BlockingTask::SlidingSync,
        BlockingTask::LockWait,
    ]
    .into_iter()
    .map(|task| server.metrics.blocking_in_flight(task))
    .sum();
    assert!(
        off_the_workers >= 8,
        "every stuck request is waiting off the async workers: {off_the_workers}"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    for request in stuck {
        let status = request.await.unwrap().unwrap();
        assert_eq!(
            status, 200,
            "and every one of them is answered once released"
        );
    }
    assert!(
        server
            .metrics
            .lock_waits(spindle_server::metrics::LockKind::Room)
            > 0
    );
}

/// The measurement behind the claim, at sizes too slow for every run:
/// `cargo test --test cold_start -- --ignored --nocapture`. For each size of
/// an old room outside the window, a fresh restart's first sliding sync is
/// timed, then the cost the pre-#614 path paid on top of it -- loading
/// every joined room for its sort key -- is timed separately.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement; slow"]
async fn first_request_latency_by_room_size() {
    for size in [1_000, 10_000, 50_000] {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let (token, newest_first) = seed(&store, &[size, 1, 1]);

        let server = Restarted::over(&store);
        let started = Instant::now();
        server.sliding(&token, (0, 0)).await;
        let first = started.elapsed();
        assert_eq!(server.metrics.cold_loads_total(), 1);

        let started = Instant::now();
        for room in &newest_first {
            server.state.rooms.warm(room).unwrap();
        }
        let every_room = started.elapsed();
        eprintln!(
            "#614 measurement: old room of {size} events outside the window -- first sliding \
             sync {first:?}; loading every joined room (the old path's extra cost) {every_room:?}"
        );
    }
}

/// After a restart, a reader who keeps up costs the first unread count a
/// handful of reads, not one per event the room ever held -- and a reader
/// far behind still gets the exact count, by extending the index down to
/// where they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_unread_count_after_a_restart_reads_only_what_is_unread() {
    const BOB: &str = "@bob:example.org";
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let room = {
        let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), SERVER);
        let room = rooms
            .create(
                ALICE,
                key.pair(),
                Some("busy"),
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
        let mut read_up_to = String::new();
        for n in 0..300 {
            let sender = if n % 30 == 0 { BOB } else { ALICE };
            let id = rooms
                .send(
                    &room,
                    sender,
                    key.pair(),
                    "m.room.message",
                    &json!({ "msgtype": "m.text", "body": format!("{n}") }),
                )
                .unwrap();
            if n == 289 {
                read_up_to = id;
            }
        }
        rooms
            .set_receipt(&room, ALICE, "m.read", &read_up_to, None)
            .unwrap();
        room
    };

    let server = Restarted::over(&store);
    server.state.rooms.warm(&room).unwrap();
    let before = store.reads();
    let alice = server.state.rooms.unread(&room, ALICE).unwrap();
    let reads = store.reads() - before;
    // Messages 290..299 are unread to alice, none of them bob's.
    assert_eq!(alice.notification_count, 0);
    assert!(
        reads < 40,
        "a reader ten events behind read {reads} rows, not the room's 300"
    );
    // Bob has no receipt: everything alice said since he joined is unread.
    let bob = server.state.rooms.unread(&room, BOB).unwrap();
    assert_eq!(bob.notification_count, 290);
    // Both are now answered from the extended index, and an append keeps
    // it current for both.
    let before = store.reads();
    assert_eq!(
        server
            .state
            .rooms
            .unread(&room, ALICE)
            .unwrap()
            .notification_count,
        0
    );
    assert!(store.reads() - before < 40);
    server
        .state
        .rooms
        .send(
            &room,
            BOB,
            key.pair(),
            "m.room.message",
            &json!({ "msgtype": "m.text", "body": "new" }),
        )
        .unwrap();
    assert_eq!(
        server
            .state
            .rooms
            .unread(&room, ALICE)
            .unwrap()
            .notification_count,
        1
    );
    assert_eq!(
        server
            .state
            .rooms
            .unread(&room, BOB)
            .unwrap()
            .notification_count,
        290
    );
}
