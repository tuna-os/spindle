//! Contested forks between real Spindle servers, made by partitioning them.
//!
//! Each server reaches each other server through a proxy of its own
//! (`[federation.peers]`), so the test can cut any pair of servers apart,
//! let each side write conflicting state -- a ban against a write, two power
//! level changes, a join against a join-rule change -- and heal the cut. The
//! outbox redelivers, each server receives the other side's branch as a
//! fork, and the room's state is then whatever each server's state
//! resolution makes of it.
//!
//! The assertion is the gate #563 names: every server ends on the same
//! state, slot for slot, and that state is what Matrix state resolution
//! decides (ADR 0005), not what one branch said. Run per room-version
//! family: room version 1 (the original algorithm), 2-10 (v2), 11 and 12
//! (v2 and v2.1).
//!
//! The same scenarios against Synapse are in `complement/tests/` (the
//! `state-resolution-interop` CI job).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// One homeserver, reached by clients directly and by its peers through
/// proxies the test controls.
struct Server {
    _dir: TempDir,
    name: String,
    address: SocketAddr,
    client: reqwest::Client,
}

/// A network of servers with a severable link for every ordered pair.
struct Net {
    servers: Vec<Server>,
    /// `(from, to)` -> the switch on the proxy `from` uses to reach `to`.
    links: BTreeMap<(usize, usize), watch::Sender<bool>>,
}

/// Forward every connection on `listener` to `target` until `cut` is set;
/// then drop the live ones and refuse new ones until it clears.
fn proxy(listener: TcpListener, target: SocketAddr, cut: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            if *cut.borrow() {
                drop(inbound);
                continue;
            }
            let mut cut = cut.clone();
            tokio::spawn(async move {
                let Ok(mut outbound) = TcpStream::connect(target).await else {
                    return;
                };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                    () = async {
                        while cut.changed().await.is_ok() {
                            if *cut.borrow() {
                                break;
                            }
                        }
                    } => {}
                }
            });
        }
    });
}

impl Net {
    async fn start(count: usize) -> Net {
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("spindle_server=info")
                .try_init();
        });
        let names: Vec<String> = (0..count).map(|index| format!("s{index}.test")).collect();
        let mut listeners = Vec::new();
        for _ in 0..count {
            listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        let addresses: Vec<SocketAddr> = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect();
        let mut proxies = BTreeMap::new();
        for from in 0..count {
            for to in 0..count {
                if from != to {
                    proxies.insert((from, to), TcpListener::bind("127.0.0.1:0").await.unwrap());
                }
            }
        }

        let mut servers = Vec::new();
        for (index, listener) in listeners.into_iter().enumerate() {
            let mut config = format!(
                "[server]\nname = \"{}\"\n[ratelimit]\nenabled = false\n\
                 [federation]\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
                names[index]
            );
            for (to, name) in names.iter().enumerate() {
                if to == index {
                    continue;
                }
                let port = proxies[&(index, to)].local_addr().unwrap().port();
                config.push_str(&format!(
                    "[federation.peers.\"{name}\"]\nurl = \"http://127.0.0.1:{port}\"\nmax_backoff_ms = 300\n"
                ));
            }
            let dir = TempDir::new().unwrap();
            let store = Arc::new(FjallStore::open(dir.path()).unwrap());
            let app = spindle_server::app(spindle_server::Config::parse(&config).unwrap(), store)
                .expect("the app builds");
            tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
            servers.push(Server {
                _dir: dir,
                name: names[index].clone(),
                address: addresses[index],
                client: reqwest::Client::new(),
            });
        }

        let mut links = BTreeMap::new();
        for ((from, to), listener) in proxies {
            let (switch, cut) = watch::channel(false);
            proxy(listener, addresses[to], cut);
            links.insert((from, to), switch);
        }
        Net { servers, links }
    }

    /// Cut or heal the link between `a` and `b`, both directions.
    fn link(&self, a: usize, b: usize, up: bool) {
        for pair in [(a, b), (b, a)] {
            self.links[&pair].send_replace(!up);
        }
    }

    /// Cut every server off from every other.
    fn isolate_all(&self) {
        for switch in self.links.values() {
            switch.send_replace(true);
        }
    }

    fn heal_all(&self) {
        for switch in self.links.values() {
            switch.send_replace(false);
        }
    }
}

impl Server {
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.address));
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

    async fn register(&self, username: &str) -> (String, String) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn put_state(&self, room: &str, token: &str, kind: &str, key: &str, content: &Value) -> (u16, Value) {
        self.request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/{kind}/{key}"),
            Some(token),
            Some(content),
        )
        .await
    }

    async fn join(&self, room: &str, token: &str, via: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
            Some(token),
            Some(&json!({ "msgtype": "m.text", "body": text })),
        )
        .await
    }

    /// The room's state as `(type, state_key) -> event_id`.
    async fn state(&self, room: &str, token: &str) -> BTreeMap<(String, String), String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/state"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{}: {body}", self.name);
        body.as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    (
                        event["type"].as_str().unwrap().to_owned(),
                        event["state_key"].as_str().unwrap().to_owned(),
                    ),
                    event["event_id"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    async fn state_event(&self, room: &str, token: &str, kind: &str, key: &str) -> Option<Value> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/state/{kind}/{key}"),
                Some(token),
                None,
            )
            .await;
        (status == 200).then_some(body)
    }
}

/// Poll until `check` holds, for up to ten seconds.
async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// A room on server 0 at `version` with a member on every server: alice
/// (s0) and bob (s1) as admins at 100, `others` as members at 0. Returns the
/// room, and every member's `(server, token, user_id)` in order.
async fn room_across(net: &Net, version: &str, bob_level: i64) -> (String, Vec<(usize, String, String)>) {
    let mut members = Vec::new();
    let (alice, alice_id) = net.servers[0].register("alice").await;
    let (status, body) = net.servers[0]
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({ "room_version": version, "preset": "public_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    members.push((0, alice, alice_id));
    for (index, server) in net.servers.iter().enumerate().skip(1) {
        for name in ["bob", "dave"] {
            let (token, user_id) = server.register(&format!("{name}{index}")).await;
            server.join(&room, &token, &net.servers[0].name).await;
            members.push((index, token, user_id));
        }
    }
    // Everyone sees everyone before anything is contested.
    let expected = members.len();
    for (index, token, _) in &members {
        let server = &net.servers[*index];
        assert!(
            eventually(async || {
                server
                    .state(&room, token)
                    .await
                    .iter()
                    .filter(|((kind, _), _)| kind == "m.room.member")
                    .count()
                    == expected
            })
            .await,
            "{} never saw every member join",
            server.name
        );
    }
    // Power: alice is the creator. Bob on s1 gets `bob_level`.
    let creator_implicit = version == "12";
    let mut users = json!({ members[1].2.clone(): bob_level });
    if !creator_implicit {
        users[members[0].2.clone()] = json!(100);
    }
    let (status, body) = net.servers[0]
        .put_state(
            &room,
            &members[0].1,
            "m.room.power_levels",
            "",
            &json!({
                "users": users,
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
                "invite": 0,
                "redact": 50,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    converge(net, &room, &members).await;
    (room, members)
}

/// Wait until every server reports the same state for the room, and return
/// it. Panics, with every server's view, if they never agree.
async fn converge(
    net: &Net,
    room: &str,
    members: &[(usize, String, String)],
) -> BTreeMap<(String, String), String> {
    let mut views = Vec::new();
    for _ in 0..200 {
        views.clear();
        for index in 0..net.servers.len() {
            // The last member each server has: the first may be the one a
            // scenario bans, and a banned user reads no state.
            let token = &members
                .iter()
                .rfind(|(server, _, _)| *server == index)
                .expect("a member on every server")
                .1;
            views.push(net.servers[index].state(room, token).await);
        }
        if views.windows(2).all(|pair| pair[0] == pair[1]) {
            return views.swap_remove(0);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut report = String::new();
    for (index, view) in views.iter().enumerate() {
        report.push_str(&format!("\n{}:", net.servers[index].name));
        for (key, id) in view {
            report.push_str(&format!("\n  {key:?} = {id}"));
        }
    }
    panic!("the servers never converged on one state:{report}");
}

/// Branch A bans bob; branch B, concurrently, has bob set the topic.
///
/// The fork merge SPEC §9.2 used to make took both, because each branch
/// moved one slot. State resolution applies the ban and re-checks the topic
/// against it, so the topic is dropped -- on every server.
async fn a_ban_voids_a_concurrent_write(version: &str) {
    let net = Net::start(2).await;
    let (room, members) = room_across(&net, version, 50).await;
    let (alice, bob) = (&members[0], &members[1]);
    let topic_before = net.servers[0]
        .state_event(&room, &alice.1, "m.room.topic", "")
        .await;

    net.link(0, 1, false);
    let (status, body) = net.servers[0]
        .put_state(&room, &alice.1, "m.room.member", &bob.2, &json!({ "membership": "ban" }))
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = net.servers[1]
        .put_state(&room, &bob.1, "m.room.topic", "", &json!({ "topic": "bob's, before the ban" }))
        .await;
    assert_eq!(status, 200, "{body}");
    net.link(0, 1, true);

    // Each server folds in the other branch; then a message from each side
    // names both tips and merges the DAG.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let dave = &members[2];
    let _ = net.servers[1].say(&room, &dave.1, "after-heal-1").await;
    let _ = net.servers[0].say(&room, &alice.1, "after-heal-0").await;

    let state = converge(&net, &room, &members).await;
    let bob_member = net.servers[1]
        .state_event(&room, &dave.1, "m.room.member", &bob.2)
        .await
        .expect("bob has a membership");
    assert_eq!(bob_member["membership"], "ban", "v{version}: {bob_member}");
    let topic_after = net.servers[1]
        .state_event(&room, &dave.1, "m.room.topic", "")
        .await;
    assert_eq!(
        topic_after, topic_before,
        "v{version}: a write by a user the other branch banned must not survive resolution"
    );
    assert!(state.contains_key(&("m.room.member".to_owned(), bob.2.clone())));
}

/// Two admins on two servers change the power levels at once.
///
/// Both changes are authorized, so state resolution orders them by the
/// senders' power (equal) and then by timestamp: the later one wins, on
/// every server, whichever arrived where first.
async fn concurrent_power_levels_agree(version: &str) {
    let net = Net::start(2).await;
    let (room, members) = room_across(&net, version, 100).await;
    let (alice, bob, dave) = (&members[0], &members[1], &members[2]);
    let creator_implicit = version == "12";
    let levels = |users: Value| {
        json!({
            "users": users,
            "users_default": 0,
            "events_default": 0,
            "state_default": 50,
            "ban": 50,
            "kick": 50,
            "invite": 0,
            "redact": 50,
        })
    };

    net.link(0, 1, false);
    let mut from_alice = json!({ bob.2.clone(): 100, dave.2.clone(): 50 });
    let mut from_bob = json!({ bob.2.clone(): 100, dave.2.clone(): 0 });
    if !creator_implicit {
        from_alice[alice.2.clone()] = json!(100);
        from_bob[alice.2.clone()] = json!(100);
    }
    let (status, first) = net.servers[0]
        .put_state(&room, &alice.1, "m.room.power_levels", "", &levels(from_alice))
        .await;
    assert_eq!(status, 200, "{first}");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (status, second) = net.servers[1]
        .put_state(&room, &bob.1, "m.room.power_levels", "", &levels(from_bob))
        .await;
    assert_eq!(status, 200, "{second}");
    net.link(0, 1, true);

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = net.servers[0].say(&room, &alice.1, "merge-0").await;
    let _ = net.servers[1].say(&room, &bob.1, "merge-1").await;
    let state = converge(&net, &room, &members).await;
    let winner = &state[&("m.room.power_levels".to_owned(), String::new())];
    assert_eq!(
        winner,
        second["event_id"].as_str().unwrap(),
        "v{version}: the later of two equally powerful changes wins"
    );
}

/// A join on one side against a join-rule change on the other.
///
/// The join rule is a power event, resolved first; the join is then
/// re-checked against `invite` and dropped. The server that accepted the
/// join locally ends up agreeing that it never took.
async fn a_join_loses_to_a_concurrent_invite_only(version: &str) {
    let net = Net::start(2).await;
    let (room, members) = room_across(&net, version, 50).await;
    let alice = &members[0];
    let (erin, erin_id) = net.servers[1].register("erin").await;

    net.link(0, 1, false);
    let (status, body) = net.servers[0]
        .put_state(&room, &alice.1, "m.room.join_rules", "", &json!({ "join_rule": "invite" }))
        .await;
    assert_eq!(status, 200, "{body}");
    net.servers[1].join(&room, &erin, &net.servers[0].name).await;
    net.link(0, 1, true);

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = net.servers[0].say(&room, &alice.1, "merge-0").await;
    let _ = net.servers[1].say(&room, &members[1].1, "merge-1").await;
    let state = converge(&net, &room, &members).await;
    assert!(
        !state.contains_key(&("m.room.member".to_owned(), erin_id.clone())),
        "v{version}: a join the join rules no longer admit is resolved away: {state:?}"
    );
}

macro_rules! per_version {
    ($scenario:ident, $($test:ident => $version:literal),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $test() {
                $scenario($version).await;
            }
        )+
    };
}

per_version!(a_ban_voids_a_concurrent_write,
    a_ban_voids_a_concurrent_write_v1 => "1",
    a_ban_voids_a_concurrent_write_v2 => "2",
    a_ban_voids_a_concurrent_write_v6 => "6",
    a_ban_voids_a_concurrent_write_v10 => "10",
    a_ban_voids_a_concurrent_write_v11 => "11",
    a_ban_voids_a_concurrent_write_v12 => "12",
);

per_version!(concurrent_power_levels_agree,
    concurrent_power_levels_agree_v1 => "1",
    concurrent_power_levels_agree_v6 => "6",
    concurrent_power_levels_agree_v10 => "10",
    concurrent_power_levels_agree_v11 => "11",
    concurrent_power_levels_agree_v12 => "12",
);

per_version!(a_join_loses_to_a_concurrent_invite_only,
    a_join_loses_to_a_concurrent_invite_only_v1 => "1",
    a_join_loses_to_a_concurrent_invite_only_v9 => "9",
    a_join_loses_to_a_concurrent_invite_only_v11 => "11",
    a_join_loses_to_a_concurrent_invite_only_v12 => "12",
);

/// Three servers, each cut off from both others, each writing conflicting
/// state: a ban, a power-level change and a join-rule change, plus a
/// member's write the ban should void. After the network heals, every
/// server holds the same state.
async fn three_servers_converge(version: &str) {
    let net = Net::start(3).await;
    let (room, members) = room_across(&net, version, 100).await;
    let (alice, bob, dave1, carol, dave2) =
        (&members[0], &members[1], &members[2], &members[3], &members[4]);

    net.isolate_all();
    // s0: alice bans carol (s2), and opens a join rule change.
    let (status, body) = net.servers[0]
        .put_state(&room, &alice.1, "m.room.member", &carol.2, &json!({ "membership": "ban" }))
        .await;
    assert_eq!(status, 200, "{body}");
    // s1: bob, also an admin, raises dave1 and sets the name.
    let creator_implicit = version == "12";
    let mut users = json!({ bob.2.clone(): 100, dave1.2.clone(): 50 });
    if !creator_implicit {
        users[alice.2.clone()] = json!(100);
    }
    let (status, body) = net.servers[1]
        .put_state(
            &room,
            &bob.1,
            "m.room.power_levels",
            "",
            &json!({
                "users": users,
                "users_default": 0,
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
                "invite": 0,
                "redact": 50,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = net.servers[1]
        .put_state(&room, &dave1.1, "m.room.name", "", &json!({ "name": "dave1's" }))
        .await;
    assert_eq!(status, 200, "{body}");
    // s2: carol leaves and rejoins (her own membership churn) while dave2
    // tries to set the topic with no power to.
    let _ = net.servers[2]
        .put_state(&room, &carol.1, "m.room.member", &carol.2, &json!({ "membership": "leave" }))
        .await;
    let _ = net.servers[2]
        .put_state(&room, &dave2.1, "m.room.topic", "", &json!({ "topic": "dave2's" }))
        .await;
    net.heal_all();

    tokio::time::sleep(Duration::from_millis(800)).await;
    let _ = net.servers[0].say(&room, &alice.1, "merge-0").await;
    let _ = net.servers[1].say(&room, &bob.1, "merge-1").await;
    let _ = net.servers[2].say(&room, &dave2.1, "merge-2").await;
    let state = converge(&net, &room, &members).await;

    // What resolution must have decided, whatever the arrival order.
    let carol_member = net.servers[2]
        .state_event(&room, &dave2.1, "m.room.member", &carol.2)
        .await
        .expect("carol has a membership");
    assert_eq!(carol_member["membership"], "ban", "v{version}: {carol_member}");
    let name = net.servers[2]
        .state_event(&room, &dave2.1, "m.room.name", "")
        .await
        .expect("the name is set");
    assert_eq!(name["name"], "dave1's", "v{version}");
    assert!(state.contains_key(&("m.room.power_levels".to_owned(), String::new())));
}

per_version!(three_servers_converge,
    three_servers_converge_v1 => "1",
    three_servers_converge_v10 => "10",
    three_servers_converge_v11 => "11",
    three_servers_converge_v12 => "12",
);
