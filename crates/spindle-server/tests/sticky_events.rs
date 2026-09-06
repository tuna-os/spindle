//! MSC4354: sticky events.
//!
//! A `MatrixRTC` participant's `m.rtc.member` is state, and state is a burden
//! on a room that lasts forever; sticky events are the alternative — an
//! event the server keeps handing out to anyone syncing or joining until
//! it lapses, then forgets. What is load-bearing: a sticky event reaches a
//! client that joined after it was sent, is never handed out twice to the
//! same client, stops being handed out when its time is up, and crosses
//! federation to a server that joined afterwards.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const STICKY_PARAM: &str = "org.matrix.msc4354.sticky_duration_ms";
const DELAY_PARAM: &str = "org.matrix.msc4140.delay";

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

struct Session {
    token: String,
    user_id: String,
}

impl Instance {
    async fn start() -> Instance {
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("spindle_server=debug")
                .try_init();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
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

    async fn register(&self, username: &str) -> Session {
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
        Session {
            token: body["access_token"].as_str().unwrap().to_owned(),
            user_id: body["user_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn public_room(&self, session: &Session) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(&session.token),
                Some(&json!({ "preset": "public_chat" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn join(&self, room: &str, session: &Session, via: Option<&str>) {
        let path = match via {
            Some(via) => format!("/_matrix/client/v3/join/{room}?server_name={via}"),
            None => format!("/_matrix/client/v3/join/{room}"),
        };
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &path,
                Some(&session.token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    /// Send a message, sticky for `sticky_ms` if given, and return its id.
    async fn send(
        &self,
        room: &str,
        session: &Session,
        body: &str,
        sticky_ms: Option<u64>,
    ) -> (u16, Value) {
        let query = sticky_ms.map_or(String::new(), |ms| format!("?{STICKY_PARAM}={ms}"));
        self.request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{body}{query}"),
            Some(&session.token),
            Some(&json!({ "msgtype": "m.text", "body": body })),
        )
        .await
    }

    async fn send_ok(
        &self,
        room: &str,
        session: &Session,
        body: &str,
        sticky_ms: Option<u64>,
    ) -> String {
        let (status, response) = self.send(room, session, body, sticky_ms).await;
        assert_eq!(status, 200, "{response}");
        response["event_id"].as_str().unwrap().to_owned()
    }

    async fn event(&self, room: &str, session: &Session, event_id: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"),
                Some(&session.token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn sync(&self, session: &Session, since: Option<&str>) -> Value {
        self.sync_with(session, since, None).await
    }

    async fn sync_with(
        &self,
        session: &Session,
        since: Option<&str>,
        filter: Option<&str>,
    ) -> Value {
        let since = since.map_or(String::new(), |since| format!("&since={since}"));
        let filter = filter.map_or(String::new(), |filter| {
            format!("&filter={}", encoded(filter))
        });
        let path = format!("/_matrix/client/v3/sync?timeout=0{since}{filter}");
        let (status, body) = self
            .request(reqwest::Method::GET, &path, Some(&session.token), None)
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }
}

/// Percent-encode the characters in a query value or path segment that
/// would otherwise change the request's shape.
fn encoded(text: &str) -> String {
    text.replace('%', "%25")
        .replace('#', "%23")
        .replace('&', "%26")
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('"', "%22")
        .replace(':', "%3A")
        .replace('@', "%40")
}

fn room_of<'a>(sync: &'a Value, room: &str) -> &'a Value {
    &sync["rooms"]["join"][room]
}

fn timeline_ids(sync: &Value, room: &str) -> Vec<String> {
    room_of(sync, room)["timeline"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter_map(|event| event["event_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn sticky_events(sync: &Value, room: &str) -> Vec<Value> {
    room_of(sync, room)["msc4354_sticky"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn sticky_ids(sync: &Value, room: &str) -> Vec<String> {
    sticky_events(sync, room)
        .iter()
        .filter_map(|event| event["event_id"].as_str().map(str::to_owned))
        .collect()
}

async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// The server advertises the feature, so a client knows to ask for it.
#[tokio::test]
async fn the_feature_is_advertised() {
    let server = Instance::start().await;
    let (status, body) = server
        .request(reqwest::Method::GET, "/_matrix/client/versions", None, None)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["unstable_features"]["org.matrix.msc4354"], json!(true));
}

/// The duration the client asked for is on the event, capped at the hour
/// the MSC allows, and is not inside `content` where a client could sign
/// it into a message.
#[tokio::test]
async fn the_duration_is_on_the_event_and_capped() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let room = server.public_room(&alice).await;

    let short = server.send_ok(&room, &alice, "short", Some(30_000)).await;
    let long = server
        .send_ok(&room, &alice, "long", Some(86_400_000))
        .await;
    let plain = server.send_ok(&room, &alice, "plain", None).await;

    let short = server.event(&room, &alice, &short).await;
    assert_eq!(
        short["msc4354_sticky"]["duration_ms"],
        json!(30_000),
        "{short}"
    );
    assert!(short["content"].get("msc4354_sticky").is_none());
    let long = server.event(&room, &alice, &long).await;
    assert_eq!(
        long["msc4354_sticky"]["duration_ms"],
        json!(3_600_000),
        "{long}"
    );
    let plain = server.event(&room, &alice, &plain).await;
    assert!(plain.get("msc4354_sticky").is_none(), "{plain}");
}

/// A sticky event that is in the timeline of a sync is not repeated in the
/// sticky section of the same sync: the client has it once.
#[tokio::test]
async fn a_sticky_event_in_the_timeline_is_not_repeated() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let room = server.public_room(&alice).await;
    let sticky = server.send_ok(&room, &alice, "hello", Some(60_000)).await;

    let sync = server.sync(&alice, None).await;
    assert!(timeline_ids(&sync, &room).contains(&sticky), "{sync}");
    assert!(!sticky_ids(&sync, &room).contains(&sticky), "{sync}");

    // And an incremental sync from after it does not bring it back.
    let next = sync["next_batch"].as_str().unwrap();
    let sync = server.sync(&alice, Some(next)).await;
    assert!(sticky_ids(&sync, &room).is_empty(), "{sync}");
}

/// The point of the mechanism: a client that syncs from nothing after the
/// event has scrolled out of its timeline window still receives it, with
/// the time it has left, and a client that joins later receives it too.
#[tokio::test]
async fn a_later_syncer_and_a_later_joiner_receive_it() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.public_room(&alice).await;
    let sticky = server.send_ok(&room, &alice, "here", Some(60_000)).await;
    for n in 0..5 {
        server
            .send_ok(&room, &alice, &format!("noise{n}"), None)
            .await;
    }

    // Alice, from nothing, with a window too small to hold the sticky event.
    let sync = server
        .sync_with(&alice, None, Some(r#"{"room":{"timeline":{"limit":2}}}"#))
        .await;
    assert!(!timeline_ids(&sync, &room).contains(&sticky), "{sync}");
    let handed = sticky_events(&sync, &room);
    assert_eq!(handed.len(), 1, "{sync}");
    assert_eq!(handed[0]["event_id"], json!(sticky));
    let ttl = handed[0]["unsigned"]["msc4354_sticky_duration_ttl_ms"]
        .as_u64()
        .expect("the time left is on the event");
    assert!(ttl > 0 && ttl <= 60_000, "ttl {ttl}");

    // Bob, joining now, from a token that predates the room.
    let before = server.sync(&bob, None).await;
    let before = before["next_batch"].as_str().unwrap();
    server.join(&room, &bob, None).await;
    let sync = server
        .sync_with(
            &bob,
            Some(before),
            Some(r#"{"room":{"timeline":{"limit":1}}}"#),
        )
        .await;
    assert!(!timeline_ids(&sync, &room).contains(&sticky), "{sync}");
    assert_eq!(sticky_ids(&sync, &room), vec![sticky.clone()], "{sync}");

    // Once handed over, it is not handed over again.
    let next = sync["next_batch"].as_str().unwrap();
    let sync = server.sync(&bob, Some(next)).await;
    assert!(sticky_ids(&sync, &room).is_empty(), "{sync}");
}

/// When the time is up the event stops being handed out.
#[tokio::test]
async fn an_expired_sticky_event_is_not_handed_out() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.public_room(&alice).await;
    let sticky = server.send_ok(&room, &alice, "brief", Some(200)).await;
    let lasting = server.send_ok(&room, &alice, "lasting", Some(60_000)).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    server.join(&room, &bob, None).await;
    let sync = server
        .sync_with(&bob, None, Some(r#"{"room":{"timeline":{"limit":1}}}"#))
        .await;
    let ids = sticky_ids(&sync, &room);
    assert!(!ids.contains(&sticky), "{sync}");
    assert!(ids.contains(&lasting), "{sync}");
}

/// A sticky state event: the same, through `/state`.
#[tokio::test]
async fn a_sticky_state_event_is_handed_to_a_joiner() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.public_room(&alice).await;
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!(
                "/_matrix/client/v3/rooms/{room}/state/m.rtc.member/{}?{STICKY_PARAM}=60000",
                encoded(&alice.user_id)
            ),
            Some(&alice.token),
            Some(&json!({ "application": "m.call", "call_id": "" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let member = body["event_id"].as_str().unwrap().to_owned();
    for n in 0..5 {
        server
            .send_ok(&room, &alice, &format!("noise{n}"), None)
            .await;
    }

    server.join(&room, &bob, None).await;
    let sync = server
        .sync_with(&bob, None, Some(r#"{"room":{"timeline":{"limit":1}}}"#))
        .await;
    assert!(sticky_ids(&sync, &room).contains(&member), "{sync}");
}

/// MSC4140 and MSC4354 together, the `MatrixRTC` pairing: a delayed sticky
/// event, when it fires, is sticky.
#[tokio::test]
async fn a_delayed_sticky_event_is_sticky_when_it_fires() {
    let server = Instance::start().await;
    let alice = server.register("alice").await;
    let room = server.public_room(&alice).await;
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/later?{DELAY_PARAM}=1&{STICKY_PARAM}=60000"
            ),
            Some(&alice.token),
            Some(&json!({ "msgtype": "m.text", "body": "later" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["delay_id"].is_string(), "{body}");

    let mut fired = None;
    assert!(
        eventually(async || {
            let sync = server.sync(&alice, None).await;
            fired = room_of(&sync, &room)["timeline"]["events"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|event| event["content"]["body"] == json!("later"))
                .cloned();
            fired.is_some()
        })
        .await,
        "the delayed event never fired"
    );
    let fired = fired.unwrap();
    assert_eq!(
        fired["msc4354_sticky"]["duration_ms"],
        json!(60_000),
        "{fired}"
    );
}

/// Across federation: the sticky event reaches the server that shared the
/// room when it was sent, and is pushed to a server that joins afterwards,
/// which hands it to its own joiner.
#[tokio::test]
async fn a_sticky_event_crosses_federation_and_reaches_a_later_server() {
    let a = Instance::start().await;
    let b = Instance::start().await;
    let c = Instance::start().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let carol = c.register("carol").await;
    let room = a.public_room(&alice).await;
    b.join(&room, &bob, Some(&a.name)).await;

    let sticky = a.send_ok(&room, &alice, "sticky", Some(600_000)).await;
    assert!(
        eventually(async || {
            let sync = b.sync(&bob, None).await;
            timeline_ids(&sync, &room).contains(&sticky)
        })
        .await,
        "the sticky event never reached the server sharing the room"
    );
    let on_b = b.event(&room, &bob, &sticky).await;
    assert_eq!(
        on_b["msc4354_sticky"]["duration_ms"],
        json!(600_000),
        "{on_b}"
    );

    // Carol's server joins later; the event is not state, so the join
    // response cannot carry it. It arrives because the resident pushes it.
    c.join(&room, &carol, Some(&a.name)).await;
    let mut seen = None;
    assert!(
        eventually(async || {
            let sync = c.sync(&carol, None).await;
            let all: Vec<String> = timeline_ids(&sync, &room)
                .into_iter()
                .chain(sticky_ids(&sync, &room))
                .collect();
            seen = Some(sync);
            all.contains(&sticky)
        })
        .await,
        "the sticky event was never pushed to the later server: {seen:?}"
    );
    let on_c = c.event(&room, &carol, &sticky).await;
    assert_eq!(
        on_c["msc4354_sticky"]["duration_ms"],
        json!(600_000),
        "{on_c}"
    );
}
