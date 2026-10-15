//! The two #42 workloads no client-server driver can construct.
//!
//! - **Join a 10,000-member federated room.** The cost is the handshake,
//!   not the joiner: `make_join` hands over state with ten thousand
//!   member events, and the joiner verifies, seeds and replays it.
//! - **Federation catch-up after a partition.** A proxy between the two
//!   servers refuses traffic both ways; one side advances; the proxy
//!   heals and one more event flows. The measured span runs from the
//!   heal to the caught-up server serving everything it missed.
//!
//! Both run Spindle against Spindle over real TCP federation, named by
//! loopback address so no DNS or TLS enters the measurement. The proxy
//! partitions by refusing rather than blackholing: a blackhole would
//! time TCP timeouts rather than recovery, and the recovery is what
//! this measures. Members are seeded store-direct (client registration
//! would hash a password per member); the join itself, the partitioned
//! sends and the marker all go through the client API like any client
//! traffic.
//!
//! Wall-clock, like the other benches: a measurement to take and record,
//! not a CI gate. Prints markdown rows for the record. Run with
//! `cargo bench -p spindle-server --bench federated_timing`. Needs no
//! privileges and no network beyond localhost.
//!
//! Competitor columns belong to the sitting program (`bench-sitting.sh`)
//! on bench hardware; this bench is the driver the parity gate was
//! missing, and the numbers it prints are Spindle's side of that
//! comparison.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spindle_store::FjallStore;

const JOIN_SIZES: [usize; 2] = [1_000, 10_000];
/// Events the partitioned side misses before the heal.
const MISSED: usize = 200;

/// A loopback port reserved by binding once and letting go. Racy in
/// principle; in a bench the window is milliseconds and a collision fails
/// loudly at serve time rather than measuring wrong.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One server: its federation name, where its client API listens, and a
/// client pointed at it.
struct Server {
    name: String,
    base: String,
    client: reqwest::Client,
}

impl Server {
    /// Serve `store` under `name` on `port`, with federation over plain
    /// HTTP to other loopback names.
    async fn start_on(store: Arc<FjallStore>, name: String, port: u16) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            base: format!("http://127.0.0.1:{port}"),
            name,
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

    async fn joined_count(&self, room: &str, token: &str) -> usize {
        self.call(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            token,
            &json!({}),
        )
        .await["joined"]
            .as_object()
            .map(serde_json::Map::len)
            .unwrap_or_default()
    }
}

/// A TCP proxy that forwards to `target` while open and refuses while
/// partitioned. Refusal (RST) rather than a blackhole, so the partitioned
/// phase fails fast and the measured span covers recovery, not timeouts.
/// One proxy covers one direction; partitioning the pair takes both.
///
/// Partitioning also shuts down flows established before the drop:
/// without that, pooled keep-alive connections would sail through the
/// closed gate, which is exactly the leak this bench must not have.
struct Partition {
    gate: Arc<AtomicBool>,
    live: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Partition {
    async fn start(target: SocketAddr) -> (Self, SocketAddr) {
        let gate = Arc::new(AtomicBool::new(true));
        let live: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let open = Arc::clone(&gate);
        let flows = Arc::clone(&live);
        tokio::spawn(async move {
            loop {
                let Ok((inbound, _)) = listener.accept().await else {
                    return;
                };
                if !open.load(Ordering::SeqCst) {
                    drop(inbound);
                    continue;
                }
                let gate = Arc::clone(&open);
                let flows = Arc::clone(&flows);
                let task = tokio::spawn(async move {
                    let Ok(outbound) = tokio::net::TcpStream::connect(target).await else {
                        return;
                    };
                    if !gate.load(Ordering::SeqCst) {
                        return;
                    }
                    let (mut ri, mut wi) = inbound.into_split();
                    let (mut ro, mut wo) = outbound.into_split();
                    let _ = tokio::join!(
                        tokio::io::copy(&mut ri, &mut wo),
                        tokio::io::copy(&mut ro, &mut wi),
                    );
                });
                flows.lock().unwrap().push(task);
            }
        });
        (
            Self {
                gate,
                live: Arc::clone(&live),
            },
            address,
        )
    }

    /// Open or partition. Partitioning refuses new flows and aborts
    /// established ones -- aborting drops both halves, so pooled
    /// keep-alive connections break instead of sailing through.
    fn set(&self, open: bool) {
        self.gate.store(open, Ordering::SeqCst);
        if !open {
            for flow in self.live.lock().unwrap().drain(..) {
                flow.abort();
            }
        }
    }
}

/// Seed a public room with `members` joins store-direct and return the
/// room plus the seed time. Client registration would hash a password per
/// member; the handshake under test never sees those accounts, only the
/// membership state they leave. Runs before the app starts so nothing
/// caches a half-seeded room.
fn seed_room(store: &Arc<FjallStore>, server_name: &str, members: usize) -> (String, Duration) {
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(store), server_name);
    let room = rooms
        .create(
            &format!("@alice:{server_name}"),
            key.pair(),
            None,
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
    let started = Instant::now();
    for number in 0..members {
        let user = format!("@bench{number}:{server_name}");
        rooms
            .set_membership(&room, &user, &user, "join", None, key.pair())
            .unwrap();
    }
    (room, started.elapsed())
}

/// Time a federated join of rooms holding `members` members.
async fn federated_join() {
    println!("| members | seed | join | joined count |");
    println!("|---|---|---|---|");
    for members in JOIN_SIZES {
        let port_a = free_port();
        let name_a = format!("127.0.0.1:{port_a}");
        let dir_a = tempfile::TempDir::new().unwrap();
        let store_a = Arc::new(FjallStore::open(dir_a.path()).unwrap());
        let (room, seed) = seed_room(&store_a, &name_a, members);
        let _server_a = Server::start_on(Arc::clone(&store_a), name_a, port_a).await;

        let port_b = free_port();
        let name_b = format!("127.0.0.1:{port_b}");
        let dir_b = tempfile::TempDir::new().unwrap();
        let store_b = Arc::new(FjallStore::open(dir_b.path()).unwrap());
        let server_b = Server::start_on(store_b, name_b, port_b).await;
        let (token, _) = server_b.register("joiner").await;

        let started = Instant::now();
        server_b
            .call(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/join/{room}"),
                &token,
                &json!({}),
            )
            .await;
        let elapsed = started.elapsed();
        let count = server_b.joined_count(&room, &token).await;
        assert_eq!(
            count,
            members + 2,
            "the join must see the creator, every seeded member and itself"
        );
        println!(
            "| {members} | {:.1} s | {:.1} s | {count} |",
            seed.as_secs_f64(),
            elapsed.as_secs_f64(),
        );
    }
}

/// Poll B's timeline until the marker and every missed event are served,
/// or two minutes pass. Returns whether it caught up, what B served last,
/// and how long the heal took to converge.
async fn poll_until_caught_up(
    server_b: &Server,
    room: &str,
    bob: &str,
    healed: Instant,
) -> (bool, Vec<String>, Duration) {
    let mut bodies = Vec::new();
    let caught_up = loop {
        let mut from: Option<String> = None;
        if healed.elapsed() > Duration::from_secs(120) {
            break false;
        }
        bodies.clear();
        loop {
            let path = match &from {
                Some(token) => {
                    format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100&from={token}")
                }
                None => format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100"),
            };
            let page = server_b
                .call(reqwest::Method::GET, &path, bob, &json!({}))
                .await;
            let chunk = page["chunk"].as_array().cloned().unwrap_or_default();
            if chunk.is_empty() {
                break;
            }
            for event in &chunk {
                if event["type"] == "m.room.message"
                    && let Some(body) = event["content"]["body"].as_str()
                {
                    bodies.push(body.to_owned());
                }
            }
            from = page["end"].as_str().map(str::to_owned);
            if from.is_none() {
                break;
            }
        }
        if bodies.contains(&"marker".to_owned()) && bodies.len() > MISSED {
            break true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    (caught_up, bodies, healed.elapsed())
}

/// Time catch-up after a partition: the proxies refuse both ways, A
/// advances by `MISSED` events, the proxies heal and A sends a marker.
/// The span runs from the heal to B serving everything it missed.
async fn partition_catchup() {
    let port_a = free_port();
    let port_b = free_port();
    let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    // Each server is named by its proxy's address, so federation traffic
    // both ways crosses a proxy: partitioning both proxies partitions
    // the pair. The proxies bind first, so both names are exact.
    let (gate_a, front_a) = Partition::start(SocketAddr::new(localhost, port_a)).await;
    let (gate_b, front_b) = Partition::start(SocketAddr::new(localhost, port_b)).await;
    let name_a = format!("127.0.0.1:{}", front_a.port());
    let name_b = format!("127.0.0.1:{}", front_b.port());

    let dir_a = tempfile::TempDir::new().unwrap();
    let store_a = Arc::new(FjallStore::open(dir_a.path()).unwrap());
    let (room, _) = seed_room(&store_a, &name_a, 0);
    let server_a = Server::start_on(Arc::clone(&store_a), name_a.clone(), port_a).await;

    let dir_b = tempfile::TempDir::new().unwrap();
    let store_b = Arc::new(FjallStore::open(dir_b.path()).unwrap());
    let server_b = Server::start_on(store_b, name_b, port_b).await;

    let partition = (&gate_b, &gate_a);

    let (alice, _) = server_a.register("alice").await;
    let (bob, _) = server_b.register("bob").await;
    // Alice owns the seeded room; invite Bob across the open proxy so
    // both sides share it before the partition.
    server_a
        .call(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": format!("@bob:{}", server_b.name) }),
        )
        .await;
    server_b
        .call(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}"),
            &bob,
            &json!({}),
        )
        .await;
    assert_eq!(server_a.joined_count(&room, &alice).await, 2);
    assert_eq!(server_b.joined_count(&room, &bob).await, 2);

    // Partition: B's view freezes while A advances.
    partition.0.set(false);
    partition.1.set(false);
    for number in 0..MISSED {
        server_a
            .call(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/missed{number}"),
                &alice,
                &json!({ "msgtype": "m.text", "body": format!("missed-{number}") }),
            )
            .await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let newest = server_b
        .call(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"),
            &bob,
            &json!({}),
        )
        .await;
    assert!(
        newest["chunk"][0]["content"]["body"].as_str() != Some("missed-199"),
        "B must not see partitioned events: {newest}"
    );

    // Heal, send the marker, and time the catch-up.
    partition.0.set(true);
    partition.1.set(true);
    let healed = Instant::now();
    server_a
        .call(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/marker"),
            &alice,
            &json!({ "msgtype": "m.text", "body": "marker" }),
        )
        .await;
    let (caught_up, bodies, elapsed) = poll_until_caught_up(&server_b, &room, &bob, healed).await;
    assert!(caught_up, "B never caught up: saw {} bodies", bodies.len());
    println!("| missed events | catch-up | events/s |");
    println!("|---|---|---|");
    // Exact: a few hundred events are nowhere near f64's 52-bit mantissa.
    #[allow(clippy::cast_precision_loss)]
    let rate = (MISSED + 1) as f64 / elapsed.as_secs_f64();
    println!(
        "| {MISSED} | {:.1} s | {:.0} |",
        elapsed.as_secs_f64(),
        rate,
    );
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        federated_join().await;
        partition_catchup().await;
    });
}
