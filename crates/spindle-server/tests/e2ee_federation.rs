//! End-to-end encryption across federation, two Spindles over TCP: the
//! key directory and one-time key claims for a user on the other server,
//! to-device messages both ways, and a device change announced to the
//! server that shares a room.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

struct Session {
    token: String,
    user_id: String,
    device_id: String,
}

impl Instance {
    async fn start() -> Instance {
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
            device_id: body["device_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn upload_identity(&self, session: &Session) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/keys/upload",
                Some(&session.token),
                Some(&json!({
                    "device_keys": {
                        "user_id": session.user_id,
                        "device_id": session.device_id,
                        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                        "keys": {
                            format!("curve25519:{}", session.device_id): "curvekey",
                            format!("ed25519:{}", session.device_id): "edkey",
                        },
                        "signatures": {},
                    },
                    "one_time_keys": {
                        format!("signed_curve25519:AAAA{}", session.device_id): { "key": "otk" }
                    },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
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

    async fn join_via(&self, room: &str, session: &Session, via: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
                Some(&session.token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn sync(&self, session: &Session, since: Option<&str>) -> Value {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, body) = self
            .request(reqwest::Method::GET, &path, Some(&session.token), None)
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }
}

async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..80 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn keys_are_found_and_claimed_across_federation() {
    let a = Instance::start().await;
    let b = Instance::start().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    b.upload_identity(&bob).await;

    // Alice asks her own server for Bob's keys; it asks Bob's.
    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(&alice.token),
            Some(&json!({ "device_keys": { bob.user_id.clone(): [] } })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let keys = &body["device_keys"][&bob.user_id][&bob.device_id]["keys"];
    assert_eq!(
        keys[format!("curve25519:{}", bob.device_id)],
        json!("curvekey"),
        "{body}"
    );
    assert!(body["failures"].as_object().unwrap().is_empty(), "{body}");

    // And claims a one-time key, which is handed out exactly once.
    let claim = json!({ "one_time_keys": { bob.user_id.clone(): { bob.device_id.clone(): "signed_curve25519" } } });
    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            Some(&alice.token),
            Some(&claim),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["one_time_keys"][&bob.user_id][&bob.device_id]
            [format!("signed_curve25519:AAAA{}", bob.device_id)]["key"],
        json!("otk"),
        "{body}"
    );
    let (_, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            Some(&alice.token),
            Some(&claim),
        )
        .await;
    assert!(
        body["one_time_keys"][&bob.user_id].is_null()
            || body["one_time_keys"][&bob.user_id][&bob.device_id].is_null(),
        "a one-time key was handed out twice: {body}"
    );
}

#[tokio::test]
async fn to_device_messages_cross_in_both_directions() {
    let a = Instance::start().await;
    let b = Instance::start().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    a.upload_identity(&alice).await;
    b.upload_identity(&bob).await;

    // Alice to Bob's device by name.
    let (status, body) = a
        .request(
            reqwest::Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.room_key/t1",
            Some(&alice.token),
            Some(&json!({ "messages": { bob.user_id.clone(): { bob.device_id.clone(): { "session": "one" } } } })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(async || {
            let sync = b.sync(&bob, None).await;
            sync["to_device"]["events"]
                .as_array()
                .is_some_and(|events| {
                    events
                        .iter()
                        .any(|event| event["content"]["session"] == json!("one"))
                })
        })
        .await,
        "alice's to-device message never reached bob"
    );

    // Bob to every device of Alice's, by wildcard: resolved on her server.
    let (status, body) = b
        .request(
            reqwest::Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.room_key/t2",
            Some(&bob.token),
            Some(&json!({ "messages": { alice.user_id.clone(): { "*": { "session": "two" } } } })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        eventually(async || {
            let sync = a.sync(&alice, None).await;
            sync["to_device"]["events"]
                .as_array()
                .is_some_and(|events| {
                    events.iter().any(|event| {
                        event["content"]["session"] == json!("two")
                            && event["sender"] == json!(bob.user_id)
                    })
                })
        })
        .await,
        "bob's to-device message never reached alice"
    );
}

#[tokio::test]
async fn a_device_change_is_announced_to_the_server_sharing_a_room() {
    let a = Instance::start().await;
    let b = Instance::start().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let room = a.public_room(&alice).await;
    b.join_via(&room, &bob, &a.name).await;

    // Bob's client is synced; then Alice's device appears.
    let since = b.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    a.upload_identity(&alice).await;
    assert!(
        eventually(async || {
            let sync = b.sync(&bob, Some(&since)).await;
            sync["device_lists"]["changed"]
                .as_array()
                .is_some_and(|changed| changed.iter().any(|user| user == &json!(alice.user_id)))
        })
        .await,
        "bob's server never heard that alice's device list changed"
    );
    // And the announced keys are already on Bob's server: a query answers
    // even if Alice's server were dark.
    let (status, body) = b
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(&bob.token),
            Some(&json!({ "device_keys": { alice.user_id.clone(): [] } })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["device_keys"][&alice.user_id][&alice.device_id]["keys"]
            [format!("ed25519:{}", alice.device_id)],
        json!("edkey"),
        "{body}"
    );
}

/// A federation peer that takes `delay` to answer every request with an
/// empty JSON object, or never answers when `delay` is `None`. Returns the
/// server name it listens on.
async fn slow_peer(delay: Option<std::time::Duration>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let Some(delay) = delay else {
                    std::future::pending::<()>().await;
                    return;
                };
                tokio::time::sleep(delay).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                          content-length: 2\r\nconnection: close\r\n\r\n{}",
                    )
                    .await;
            });
        }
    });
    name
}

#[tokio::test]
async fn remote_servers_are_asked_for_keys_concurrently() {
    let a = Instance::start().await;
    let alice = a.register("alice").await;
    let delay = std::time::Duration::from_millis(800);
    let mut asked = serde_json::Map::new();
    for _ in 0..4 {
        asked.insert(format!("@u:{}", slow_peer(Some(delay)).await), json!([]));
    }

    let started = std::time::Instant::now();
    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(&alice.token),
            Some(&json!({ "device_keys": asked })),
        )
        .await;
    let elapsed = started.elapsed();
    assert_eq!(status, 200, "{body}");
    // Four peers at 0.8s each: 3.2s one after another, about 0.8s together.
    assert!(
        elapsed < std::time::Duration::from_millis(2000),
        "four slow peers were asked one at a time: {elapsed:?}"
    );

    let claim: serde_json::Map<String, Value> = asked
        .keys()
        .map(|user| (user.clone(), json!({ "DEVICE": "signed_curve25519" })))
        .collect();
    let started = std::time::Instant::now();
    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            Some(&alice.token),
            Some(&json!({ "one_time_keys": claim })),
        )
        .await;
    let elapsed = started.elapsed();
    assert_eq!(status, 200, "{body}");
    assert!(
        elapsed < std::time::Duration::from_millis(2000),
        "four slow peers were claimed from one at a time: {elapsed:?}"
    );
}

#[tokio::test]
async fn a_peer_that_never_answers_is_reported_as_a_failure_within_the_deadline() {
    let a = Instance::start().await;
    let alice = a.register("alice").await;
    let quick = slow_peer(Some(std::time::Duration::from_millis(50))).await;
    let silent = slow_peer(None).await;
    let quick_user = format!("@u:{quick}");
    let silent_user = format!("@u:{silent}");

    let started = std::time::Instant::now();
    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(&alice.token),
            Some(&json!({ "device_keys": { quick_user.clone(): [], silent_user.clone(): [] } })),
        )
        .await;
    let elapsed = started.elapsed();
    assert_eq!(status, 200, "{body}");
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "a silent peer held the request for {elapsed:?}"
    );
    let failures = body["failures"].as_object().unwrap();
    assert!(failures.contains_key(&silent), "{body}");
    assert!(!failures.contains_key(&quick), "{body}");
}

/// A peer that answers `{}` after `delay`, counting how many requests are
/// being held open across every peer sharing `in_flight`/`peak`.
async fn counting_peer(
    delay: std::time::Duration,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
) -> String {
    use std::sync::atomic::Ordering::SeqCst;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (in_flight, peak) = (Arc::clone(&in_flight), Arc::clone(&peak));
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let _ = socket.read(&mut buffer).await;
                peak.fetch_max(in_flight.fetch_add(1, SeqCst) + 1, SeqCst);
                tokio::time::sleep(delay).await;
                in_flight.fetch_sub(1, SeqCst);
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                          content-length: 2\r\nconnection: close\r\n\r\n{}",
                    )
                    .await;
            });
        }
    });
    name
}

#[tokio::test]
async fn a_request_naming_many_servers_holds_a_bounded_number_open() {
    let a = Instance::start().await;
    let alice = a.register("alice").await;
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut asked = serde_json::Map::new();
    for _ in 0..40 {
        let peer = counting_peer(
            std::time::Duration::from_millis(300),
            Arc::clone(&in_flight),
            Arc::clone(&peak),
        )
        .await;
        asked.insert(format!("@u:{peer}"), json!([]));
    }

    let (status, body) = a
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(&alice.token),
            Some(&json!({ "device_keys": asked })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["failures"].as_object().unwrap().is_empty(), "{body}");
    let peak = peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        peak > 1,
        "the servers were not asked together (peak {peak})"
    );
    assert!(peak <= 16, "{peak} servers were held open at once");
}
