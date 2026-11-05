//! Faster joins (MSC3706, spec v1.6 `omit_members`; #746) between two
//! real Spindle instances over TCP.
//!
//! The joining server asks `send_join` to omit the room's member events,
//! the resident leaves them out and names its servers, and the join
//! returns at once with a partial-state room that is usable for reading
//! and sending. The full state follows in the background, from the
//! resident's `/state_ids` and `/state`, and the roster converges.
//!
//! What makes "at once" a counted claim rather than a timing: the
//! resident here sits behind a gate on its `/state_ids` and `/state`
//! routes, and the join must return while the gate has served nothing.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const OPEN: u8 = 0;
const BLOCK: u8 = 1;
const REFUSE: u8 = 2;

/// What a server's `/state` and `/state_ids` routes do: answer, hold the
/// request until opened, or refuse it -- counting each answer and refusal.
#[derive(Default)]
struct Gate {
    mode: AtomicU8,
    served: AtomicUsize,
    refused: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl Gate {
    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    fn refused(&self) -> usize {
        self.refused.load(Ordering::SeqCst)
    }

    async fn pass(
        self: Arc<Self>,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let path = request.uri().path();
        let gated = path.starts_with("/_matrix/federation/v1/state_ids/")
            || path.starts_with("/_matrix/federation/v1/state/");
        if !gated {
            return next.run(request).await;
        }
        loop {
            let changed = self.changed.notified();
            match self.mode.load(Ordering::SeqCst) {
                OPEN => break,
                REFUSE => {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                    return axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(json!({ "errcode": "M_UNKNOWN", "error": "gated" })),
                    ));
                }
                _ => changed.await,
            }
        }
        let response = next.run(request).await;
        self.served.fetch_add(1, Ordering::SeqCst);
        response
    }
}

/// One homeserver on a real TCP listener, named by its own address, whose
/// application can be rebuilt over the same store while the listener --
/// and so the server's name -- stays.
struct Instance {
    _dir: TempDir,
    name: String,
    /// Lines appended to the `[federation]` section of the config.
    federation: String,
    store: Arc<FjallStore>,
    app: Arc<RwLock<axum::Router>>,
    gate: Arc<Gate>,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        Self::start_with("").await
    }

    async fn start_with(federation: &str) -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let gate = Arc::new(Gate::default());
        let app = Arc::new(RwLock::new(Self::build(&name, federation, &store, &gate)));
        let current = Arc::clone(&app);
        let front = axum::Router::new().fallback_service(tower::service_fn(
            move |request: axum::extract::Request| {
                let app = current.read().unwrap().clone();
                async move { app.oneshot(request).await }
            },
        ));
        tokio::spawn(async move {
            axum::serve(
                listener,
                front.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Instance {
            _dir: dir,
            name,
            federation: federation.to_owned(),
            store,
            app,
            gate,
            client: reqwest::Client::new(),
        }
    }

    fn build(
        name: &str,
        federation: &str,
        store: &Arc<FjallStore>,
        gate: &Arc<Gate>,
    ) -> axum::Router {
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n\
             {federation}\n",
        ))
        .unwrap();
        let gate = Arc::clone(gate);
        spindle_server::app(config, Arc::clone(store))
            .expect("the app builds")
            .layer(axum::middleware::from_fn(move |request, next| {
                Arc::clone(&gate).pass(request, next)
            }))
    }

    /// Everything the server held in memory goes; the store and the name
    /// stay -- `restart.rs` explains why a test shares the store rather
    /// than reopening the directory.
    fn restart(&self) {
        *self.app.write().unwrap() =
            Self::build(&self.name, &self.federation, &self.store, &self.gate);
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
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    fn user(&self, username: &str) -> String {
        format!("@{username}:{}", self.name)
    }

    async fn put_state(&self, room: &str, token: &str, kind: &str, content: &Value) {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/{kind}"),
                Some(token),
                Some(content),
            )
            .await;
        assert_eq!(status, 200, "{kind}: {body}");
    }

    /// A public room with a name. Named, so the resident keeps no heroes'
    /// member events: every member but the joiner is omitted.
    async fn named_public_room(&self, token: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({ "name": "faster joins" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        self.put_state(
            &room,
            token,
            "m.room.join_rules",
            &json!({ "join_rule": "public" }),
        )
        .await;
        room
    }

    async fn join_via(&self, room: &str, token: &str, via: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
            Some(token),
            Some(&json!({})),
        )
        .await
    }

    async fn leave(&self, room: &str, token: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/rooms/{room}/leave"),
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn say(&self, room: &str, token: &str, text: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/{}",
                    text.replace(' ', "-")
                ),
                Some(token),
                Some(&json!({ "msgtype": "m.text", "body": text })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn messages(&self, room: &str, token: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["content"]["body"].as_str())
            .map(str::to_owned)
            .collect()
    }

    async fn joined_members(&self, room: &str, token: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let mut members: Vec<String> = body["joined"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        members.sort();
        members
    }

    async fn sync(&self, token: &str, since: Option<&str>) -> Value {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, body) = self
            .request(reqwest::Method::GET, &path, Some(token), None)
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// A sliding sync (MSC4186) of every room, member state and all.
    async fn sliding(&self, token: &str, pos: Option<&str>) -> Value {
        let path = match pos {
            Some(pos) => {
                format!("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}")
            }
            None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
        };
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &path,
                Some(token),
                Some(&json!({
                    "lists": {
                        "all": {
                            "ranges": [[0, 10]],
                            "required_state": [["m.room.member", "*"]],
                            "timeline_limit": 1,
                        }
                    }
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// Whether the roster is still waiting on a resync: a partial-state
    /// room's `/joined_members` does not answer until it lands.
    async fn roster_waits(&self, room: &str, token: &str) -> bool {
        tokio::time::timeout(Duration::from_millis(500), self.joined_members(room, token))
            .await
            .is_err()
    }
}

/// Poll every 50 ms, up to ten seconds, until `check` returns true.
async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_partial_join_is_usable_at_once_and_converges_after_the_resync() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let room = remote.named_public_room(&alice).await;
    let mut tokens = Vec::new();
    for name in ["bob", "carol", "erin"] {
        let token = remote.register(name).await;
        let (status, body) = remote.join_via(&room, &token, &remote.name).await;
        assert_eq!(status, 200, "{body}");
        tokens.push(token);
    }
    // Erin sets the topic and leaves. Her join is then cited by a state
    // event, so it rides the auth chain, while her leave is a member event
    // the resident omits. A joiner that folded the auth chain into its
    // state would seat her, and no resync would unseat her: the fill never
    // replaces a slot that is held.
    remote
        .put_state(
            &room,
            &alice,
            "m.room.power_levels",
            &json!({ "users": { remote.user("alice"): 100, remote.user("erin"): 50 } }),
        )
        .await;
    remote
        .put_state(
            &room,
            &tokens[2],
            "m.room.topic",
            &json!({ "topic": "erin's" }),
        )
        .await;
    remote.leave(&room, &tokens[2]).await;
    remote.say(&room, &alice, "before the join").await;

    remote.gate.set(BLOCK);
    let zara = local.register("zara").await;
    let (status, body) = local.join_via(&room, &zara, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        remote.gate.served(),
        0,
        "the join returned before the resident served any state for the resync"
    );
    assert!(
        local.roster_waits(&room, &zara).await,
        "the room is partial: its roster waits for the resync"
    );

    // Usable while partial: what the joiner says reaches the resident --
    // whose members the joiner does not know, so through `servers_in_room`
    // -- and what an omitted member says reaches the joiner, authorized on
    // the member event it cites.
    local.say(&room, &zara, "said while partial").await;
    assert!(
        eventually(async || remote
            .messages(&room, &alice)
            .await
            .contains(&"said while partial".to_owned()))
        .await,
        "the joiner's message reached the resident"
    );
    remote
        .say(&room, &tokens[0], "from an omitted member")
        .await;
    assert!(
        eventually(async || local
            .messages(&room, &zara)
            .await
            .contains(&"from an omitted member".to_owned()))
        .await,
        "an omitted member's message reached the joiner"
    );
    assert_eq!(remote.gate.served(), 0, "and all of it before any resync");

    // Where the joiner's clients stand while the room is partial: from
    // here on, nothing happens in the room but the resync.
    let token = local.sync(&zara, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let pos = local.sliding(&zara, None).await["pos"]
        .as_str()
        .unwrap()
        .to_owned();

    remote.gate.set(OPEN);
    let members = tokio::time::timeout(Duration::from_secs(20), local.joined_members(&room, &zara))
        .await
        .expect("the resync completes");
    let mut expected = vec![
        remote.user("alice"),
        remote.user("bob"),
        remote.user("carol"),
        local.user("zara"),
    ];
    expected.sort();
    assert_eq!(members, expected, "the roster converged, without erin");
    assert!(remote.gate.served() >= 1, "the resync asked the resident");

    // A client that synced while the room was partial is told the room
    // afresh once the resync lands, member events and all. Nothing else
    // happened in the room since, so without the resync the room would be
    // absent from this sync. Bob's member event is in the state block, or
    // in the timeline when the join's history backfill has already brought
    // it in; either way the client learns of him.
    let next = local.sync(&zara, Some(&token)).await;
    let joined = &next["rooms"]["join"][&room];
    let members: Vec<&str> = ["state", "timeline"]
        .iter()
        .filter_map(|block| joined[*block]["events"].as_array())
        .flatten()
        .filter(|event| event["type"] == "m.room.member")
        .filter_map(|event| event["state_key"].as_str())
        .collect();
    assert!(
        members.contains(&remote.user("bob").as_str()),
        "the incremental sync carries the filled roster: {next}"
    );
    let next = local.sliding(&zara, Some(&pos)).await;
    let entry = &next["rooms"][&room];
    assert_eq!(entry["initial"], json!(true), "{next}");
    assert!(
        entry["required_state"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["state_key"] == json!(remote.user("bob"))),
        "the sliding sync renders the room afresh, filled roster and all: {next}"
    );

    // And the resident's view agrees: the joiner is a member there.
    let resident = remote.joined_members(&room, &alice).await;
    assert!(resident.contains(&local.user("zara")), "{resident:?}");
}

#[tokio::test]
async fn a_resync_cut_short_by_a_restart_resumes() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let room = remote.named_public_room(&alice).await;
    let bob = remote.register("bob").await;
    let (status, body) = remote.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    remote.gate.set(REFUSE);
    let zara = local.register("zara").await;
    let (status, body) = local.join_via(&room, &zara, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(async || remote.gate.refused() >= 1).await,
        "the resync started and was turned away"
    );

    local.restart();
    assert!(
        local.roster_waits(&room, &zara).await,
        "the restarted server still knows the room is partial"
    );
    let refused = remote.gate.refused();
    assert!(
        eventually(async || remote.gate.refused() > refused).await,
        "the restarted server resumed the resync on its own"
    );

    remote.gate.set(OPEN);
    let members = tokio::time::timeout(Duration::from_secs(20), local.joined_members(&room, &zara))
        .await
        .expect("the resumed resync completes");
    let mut expected = vec![remote.user("alice"), remote.user("bob"), local.user("zara")];
    expected.sort();
    assert_eq!(members, expected);
}

/// A room whose history this server never fetched still shows its filled
/// roster. With backfill off, the timeline is the seeded state, the join
/// and what followed; no event in it is an omitted member's, and the state
/// before its first event is empty. The member events the resync filled in
/// are state that no event in the timeline set, so they go in the state
/// block, or no client would ever learn of them.
#[tokio::test]
async fn a_resynced_room_shows_its_roster_without_its_history() {
    let remote = Instance::start().await;
    let local = Instance::start_with("gap_backfill = false").await;

    let alice = remote.register("alice").await;
    let room = remote.named_public_room(&alice).await;
    let bob = remote.register("bob").await;
    let (status, body) = remote.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    let zara = local.register("zara").await;
    let (status, body) = local.join_via(&room, &zara, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    let members = tokio::time::timeout(Duration::from_secs(20), local.joined_members(&room, &zara))
        .await
        .expect("the resync completes");
    assert!(members.contains(&remote.user("bob")), "{members:?}");

    let initial = local.sync(&zara, None).await;
    let joined = &initial["rooms"]["join"][&room];
    let in_block = |block: &str| -> Vec<String> {
        joined[block]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["type"] == "m.room.member")
            .filter_map(|event| event["state_key"].as_str().map(str::to_owned))
            .collect()
    };
    assert!(
        !in_block("timeline").contains(&remote.user("bob")),
        "no history was fetched, so bob's join is no timeline event: {initial}"
    );
    assert!(
        in_block("state").contains(&remote.user("bob")),
        "the filled roster is in the state block: {initial}"
    );
}
