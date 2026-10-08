//! Call churn at 5, 20 and 100 participants: the measurement #40 asks for.
//!
//! A `MatrixRTC` call is room state and to-device traffic, and both scale
//! with the call. Each participant holds a membership state event (here in
//! Element Call's compatibility mode, `org.matrix.msc3401.call.member`, the
//! mode that writes room state), a delayed leave it keeps restarting
//! (MSC4140), and, on joining, sends its media key to every other device
//! (to-device). So an N-party call is N state events, N live timers and
//! O(N^2) to-device messages at setup, all in one room -- a single-writer
//! room's worst case. If the per-room executor is going to bottleneck
//! anywhere, a hundred-party call is where.
//!
//! Four phases per size, against a real listener over TCP with a `/sync`
//! long-poll per participant, the way the clients drive it:
//!
//! - **join burst**: every participant at once schedules its delayed leave
//!   and writes its membership. The latency of those writes, and how long
//!   until the first participant has seen every membership arrive.
//! - **key burst**: every participant at once sends its key to every other
//!   device in one `sendToDevice` -- N(N-1) messages. How long until every
//!   device has every key, and -- the property SPEC §16.1 gives to-device
//!   its own stream for -- how late a timeline message sent at the same
//!   moment arrives, against the same message on an idle room.
//! - **churn**: participants leave (membership cleared, delay cancelled)
//!   and rejoin (new delay, new membership) one after another while every
//!   other participant heartbeats its delay every four seconds, as Element
//!   Call does. Write latency, and how long after the write returns the
//!   first participant's sync carries it.
//! - **heartbeat**: the restart latency over HTTP while all of that runs.
//!
//! Wall-clock, like `ring_latency` and `delayed_firing`: a measurement to
//! take and record, not a criterion benchmark and not a CI gate. Per #34
//! the result is the shape across sizes.
//!
//! Run with `cargo bench -p spindle-server --bench call_churn`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spindle_store::FjallStore;

const SIZES: [usize; 3] = [5, 20, 100];
const MEMBER: &str = "org.matrix.msc3401.call.member";
const KEYS: &str = "io.element.call.encryption_keys";
/// Element Call's own timings: an 18-second delayed leave, restarted every
/// four seconds.
const DELAY_MS: u64 = 18_000;
const HEARTBEAT: Duration = Duration::from_secs(4);

#[derive(Clone)]
struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    async fn call(&self, method: reqwest::Method, path: &str, token: &str, body: &Value) -> Value {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .body(body.to_string());
        if !token.is_empty() {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let bytes = response.bytes().await.unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert!(status.is_success(), "{path}: {status} {value}");
        value
    }
}

async fn start() -> (tempfile::TempDir, Client) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dir = tempfile::TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n"
    ))
    .unwrap();
    let app = spindle_server::app(config, store).expect("the app builds");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .build()
        .unwrap();
    (
        dir,
        Client {
            base: format!("http://{name}"),
            http,
        },
    )
}

/// One participant: a session, and a `/sync` long-poll recording when each
/// event and each to-device message arrived.
struct Participant {
    token: String,
    user_id: String,
    device_id: String,
    seen: Arc<Mutex<HashMap<String, Instant>>>,
    keys: Arc<Mutex<Vec<Instant>>>,
    delay_id: Mutex<Option<String>>,
}

impl Participant {
    async fn register(client: &Client, name: &str) -> Self {
        let body = client
            .call(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                "",
                &json!({
                    "username": name,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        Self {
            token: body["access_token"].as_str().unwrap().to_owned(),
            user_id: body["user_id"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
            seen: Arc::default(),
            keys: Arc::default(),
            delay_id: Mutex::new(None),
        }
    }

    /// Start the long-poll from now: an initial sync, then incremental ones
    /// until `stop`.
    async fn sync_from_now(&self, client: &Client, stop: Arc<AtomicBool>) {
        let first = client
            .call(
                reqwest::Method::GET,
                "/_matrix/client/v3/sync?timeout=0",
                &self.token,
                &json!({}),
            )
            .await;
        let mut since = first["next_batch"].as_str().unwrap().to_owned();
        let (client, token) = (client.clone(), self.token.clone());
        let (seen, keys) = (Arc::clone(&self.seen), Arc::clone(&self.keys));
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let body = client
                    .call(
                        reqwest::Method::GET,
                        &format!("/_matrix/client/v3/sync?timeout=5000&since={since}"),
                        &token,
                        &json!({}),
                    )
                    .await;
                let now = Instant::now();
                if let Some(rooms) = body["rooms"]["join"].as_object() {
                    let mut seen = seen.lock().unwrap();
                    for room in rooms.values() {
                        for section in [&room["timeline"]["events"], &room["state"]["events"]] {
                            for event in section.as_array().into_iter().flatten() {
                                if let Some(id) = event["event_id"].as_str() {
                                    seen.entry(id.to_owned()).or_insert(now);
                                }
                            }
                        }
                    }
                }
                let arrived = body["to_device"]["events"].as_array().map_or(0, |events| {
                    events.iter().filter(|event| event["type"] == KEYS).count()
                });
                keys.lock()
                    .unwrap()
                    .extend(std::iter::repeat_n(now, arrived));
                body["next_batch"].as_str().unwrap().clone_into(&mut since);
            }
        });
    }

    async fn schedule_leave(&self, client: &Client, room: &str) {
        let body = client
            .call(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/{MEMBER}/_{}_{}?org.matrix.msc4140.delay={DELAY_MS}",
                    self.user_id, self.device_id
                ),
                &self.token,
                &json!({}),
            )
            .await;
        *self.delay_id.lock().unwrap() = body["delay_id"].as_str().map(str::to_owned);
    }

    async fn write_membership(&self, client: &Client, room: &str, joined: bool) -> String {
        let content = if joined {
            json!({
                "application": "m.call",
                "call_id": "",
                "scope": "m.room",
                "device_id": self.device_id,
                "expires": 14_400_000,
                "focus_active": { "type": "livekit", "focus_selection": "oldest_membership" },
                "foci_preferred": [{
                    "type": "livekit",
                    "livekit_service_url": "https://rtc.example.org/livekit/jwt",
                    "livekit_alias": room,
                }],
            })
        } else {
            json!({})
        };
        client
            .call(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/{MEMBER}/_{}_{}",
                    self.user_id, self.device_id
                ),
                &self.token,
                &content,
            )
            .await["event_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn act_on_delay(&self, client: &Client, action: &str) -> Option<Duration> {
        let delay_id = self.delay_id.lock().unwrap().clone()?;
        let started = Instant::now();
        client
            .call(
                reqwest::Method::POST,
                &format!("/_matrix/client/v1/delayed_events/{delay_id}/{action}"),
                &self.token,
                &json!({}),
            )
            .await;
        Some(started.elapsed())
    }
}

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted[(sorted.len() - 1) * percent / 100]
}

fn ms(duration: Duration) -> String {
    format!("{:.1} ms", duration.as_secs_f64() * 1_000.0)
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(600);
    while !done() {
        assert!(Instant::now() < deadline, "still waiting for {what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

struct Row {
    size: usize,
    join_p50: Duration,
    join_p99: Duration,
    join_seen: Duration,
    keys_all: Duration,
    message_idle: Duration,
    message_burst: Duration,
    churn_write_p50: Duration,
    churn_write_p99: Duration,
    churn_seen_p50: Duration,
    churn_seen_p99: Duration,
    churn_rate: f64,
    heartbeat_p50: Duration,
    heartbeat_p99: Duration,
}

#[allow(clippy::too_many_lines, reason = "one phase after another, in order")]
async fn measure(client: &Client, size: usize) -> Row {
    let mut participants = Vec::with_capacity(size);
    for number in 0..size {
        participants.push(Arc::new(
            Participant::register(client, &format!("p{size}_{number}")).await,
        ));
    }
    let creator = Arc::clone(&participants[0]);
    let room = client
        .call(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            &creator.token,
            &json!({
                "preset": "public_chat",
                "name": format!("Call of {size}"),
                // What Element X sends on every room it creates, so ordinary
                // members can write their own call membership.
                "power_level_content_override": { "events": { MEMBER: 0 } },
            }),
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for participant in &participants[1..] {
        client
            .call(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                &participant.token,
                &json!({}),
            )
            .await;
    }
    let stop = Arc::new(AtomicBool::new(false));
    for participant in &participants {
        participant.sync_from_now(client, Arc::clone(&stop)).await;
    }
    let observer = Arc::clone(&participants[0]);
    let last = Arc::clone(&participants[size - 1]);

    // A timeline message on the idle room, for the key burst to be compared
    // against.
    let sent = Instant::now();
    let idle_id = client
        .call(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/idle{size}"),
            &observer.token,
            &json!({ "msgtype": "m.text", "body": "idle" }),
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_until("the idle message", || {
        last.seen.lock().unwrap().contains_key(&idle_id)
    })
    .await;
    let message_idle = last.seen.lock().unwrap()[&idle_id].duration_since(sent);

    // Join burst.
    let started = Instant::now();
    let joins: Vec<_> = participants
        .iter()
        .map(|participant| {
            let (client, participant, room) =
                (client.clone(), Arc::clone(participant), room.clone());
            tokio::spawn(async move {
                participant.schedule_leave(&client, &room).await;
                let begun = Instant::now();
                let event_id = participant.write_membership(&client, &room, true).await;
                (begun.elapsed(), event_id)
            })
        })
        .collect();
    let mut join_latencies = Vec::with_capacity(size);
    let mut join_events = Vec::with_capacity(size);
    for join in joins {
        let (latency, event_id) = join.await.unwrap();
        join_latencies.push(latency);
        join_events.push(event_id);
    }
    wait_until("every membership", || {
        let seen = observer.seen.lock().unwrap();
        join_events.iter().all(|id| seen.contains_key(id))
    })
    .await;
    let join_seen = join_events
        .iter()
        .map(|id| observer.seen.lock().unwrap()[id])
        .max()
        .unwrap()
        .duration_since(started);
    join_latencies.sort_unstable();

    // Heartbeats from here on, as Element Call sends them.
    let heartbeats = Arc::new(Mutex::new(Vec::new()));
    let beating = Arc::new(AtomicBool::new(true));
    for participant in &participants {
        let (client, participant) = (client.clone(), Arc::clone(participant));
        let (heartbeats, beating) = (Arc::clone(&heartbeats), Arc::clone(&beating));
        tokio::spawn(async move {
            // Spread across the interval, as independent clients would be.
            tokio::time::sleep(HEARTBEAT.mul_f64(rand::random::<f64>())).await;
            while beating.load(Ordering::Relaxed) {
                if let Some(latency) = participant.act_on_delay(&client, "restart").await {
                    heartbeats.lock().unwrap().push(latency);
                }
                tokio::time::sleep(HEARTBEAT).await;
            }
        });
    }

    // Key burst, with a timeline message sent at the same moment.
    let started = Instant::now();
    let bursts: Vec<_> = participants
        .iter()
        .enumerate()
        .map(|(index, participant)| {
            let mut messages = serde_json::Map::new();
            for other in &participants {
                if other.user_id != participant.user_id {
                    let mut device = serde_json::Map::new();
                    device.insert(
                        other.device_id.clone(),
                        json!({
                            "keys": [{ "index": 0, "key": "a2V5a2V5a2V5a2V5a2V5" }],
                            "member": { "claimed_device_id": participant.device_id },
                            "room_id": room,
                            "session": { "application": "m.call", "call_id": "", "scope": "m.room" },
                        }),
                    );
                    messages.insert(other.user_id.clone(), Value::Object(device));
                }
            }
            let (client, participant) = (client.clone(), Arc::clone(participant));
            tokio::spawn(async move {
                client
                    .call(
                        reqwest::Method::PUT,
                        &format!("/_matrix/client/v3/sendToDevice/{KEYS}/k{index}"),
                        &participant.token,
                        &json!({ "messages": messages }),
                    )
                    .await;
            })
        })
        .collect();
    let burst_id = client
        .call(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/burst{size}"),
            &observer.token,
            &json!({ "msgtype": "m.text", "body": "during the burst" }),
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for burst in bursts {
        burst.await.unwrap();
    }
    wait_until("every key on every device", || {
        participants
            .iter()
            .all(|participant| participant.keys.lock().unwrap().len() >= size - 1)
    })
    .await;
    let keys_all = participants
        .iter()
        .filter_map(|participant| participant.keys.lock().unwrap().last().copied())
        .max()
        .unwrap()
        .duration_since(started);
    wait_until("the burst message", || {
        last.seen.lock().unwrap().contains_key(&burst_id)
    })
    .await;
    let message_burst = last.seen.lock().unwrap()[&burst_id].duration_since(started);

    // Churn: leave and rejoin, one participant after another, with every
    // other participant heartbeating throughout.
    let rounds = (size * 2).max(20);
    let mut writes = Vec::with_capacity(rounds * 2);
    let mut visible = Vec::with_capacity(rounds * 2);
    let started = Instant::now();
    for round in 0..rounds {
        let participant = &participants[1 + round % (size - 1)];
        let begun = Instant::now();
        let left = participant.write_membership(client, &room, false).await;
        let returned = Instant::now();
        writes.push(returned.duration_since(begun));
        participant.act_on_delay(client, "cancel").await;
        participant.schedule_leave(client, &room).await;
        let begun = Instant::now();
        let joined = participant.write_membership(client, &room, true).await;
        let rejoined = Instant::now();
        writes.push(rejoined.duration_since(begun));
        for (event_id, at) in [(left, returned), (joined, rejoined)] {
            wait_until("a churn write", || {
                observer.seen.lock().unwrap().contains_key(&event_id)
            })
            .await;
            visible.push(observer.seen.lock().unwrap()[&event_id].saturating_duration_since(at));
        }
    }
    let churn_rate =
        f64::from(u32::try_from(rounds * 2).unwrap()) / started.elapsed().as_secs_f64();
    writes.sort_unstable();
    visible.sort_unstable();

    beating.store(false, Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);
    let mut heartbeats = heartbeats.lock().unwrap().clone();
    heartbeats.sort_unstable();
    Row {
        size,
        join_p50: percentile(&join_latencies, 50),
        join_p99: percentile(&join_latencies, 99),
        join_seen,
        keys_all,
        message_idle,
        message_burst,
        churn_write_p50: percentile(&writes, 50),
        churn_write_p99: percentile(&writes, 99),
        churn_seen_p50: percentile(&visible, 50),
        churn_seen_p99: percentile(&visible, 99),
        churn_rate,
        heartbeat_p50: percentile(&heartbeats, 50),
        heartbeat_p99: percentile(&heartbeats, 99),
    }
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (_dir, client) = start().await;
        let mut rows = Vec::new();
        for size in SIZES {
            eprintln!("measuring a call of {size}");
            rows.push(measure(&client, size).await);
        }
        println!("Join burst and key burst:");
        println!(
            "| participants | membership write p50 | p99 | all memberships seen | all N(N-1) keys delivered | message, idle room | message, during key burst |"
        );
        println!("|---|---|---|---|---|---|---|");
        for row in &rows {
            println!(
                "| {} | {} | {} | {} | {} | {} | {} |",
                row.size,
                ms(row.join_p50),
                ms(row.join_p99),
                ms(row.join_seen),
                ms(row.keys_all),
                ms(row.message_idle),
                ms(row.message_burst),
            );
        }
        println!();
        println!("Churn under heartbeat:");
        println!(
            "| participants | membership write p50 | p99 | seen by a participant p50 | p99 | membership changes/s | heartbeat p50 | p99 |"
        );
        println!("|---|---|---|---|---|---|---|---|");
        for row in &rows {
            println!(
                "| {} | {} | {} | {} | {} | {:.0} | {} | {} |",
                row.size,
                ms(row.churn_write_p50),
                ms(row.churn_write_p99),
                ms(row.churn_seen_p50),
                ms(row.churn_seen_p99),
                row.churn_rate,
                ms(row.heartbeat_p50),
                ms(row.heartbeat_p99),
            );
        }
    });
}
