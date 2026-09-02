//! A server name that points inward is never connected to (#288).
//!
//! #286 gates every outbound federation URL on the server-name grammar,
//! which stops a stranger's `X-Matrix` origin from choosing a *path*. It
//! does not stop the name being a perfectly valid one that resolves to
//! loopback, the LAN or the cloud metadata service: a fixed-path GET from
//! inside whatever network this server sits in, fired by anyone who can
//! send a header. What must hold: under the default configuration such a
//! name -- literal or resolved -- produces no connection at all; a range
//! the operator lists is reachable; and a name whose key fetch failed is
//! not fetched from again for a while, so the cost of making this server
//! connect somewhere is bounded per name, not per header.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    /// `federation` is the `[federation]` table, verbatim.
    fn with_federation(federation: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\n{federation}\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { _dir: dir, app }
    }

    /// A signed-looking transaction from `origin`. The signature is junk;
    /// what matters is whether this server tries to fetch `origin`'s key.
    async fn knock_from(&self, origin: &str) -> (StatusCode, Value) {
        let header = format!("X-Matrix origin=\"{origin}\",key=\"ed25519:0\",sig=\"AAAA\"");
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/_matrix/federation/v1/send/knock")
                    .header("authorization", header)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "pdus": [] }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// A loopback listener that counts connections and answers nothing.
struct Sentinel {
    port: u16,
    knocks: Arc<AtomicUsize>,
}

impl Sentinel {
    async fn listen() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let knocks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&knocks);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, knocks }
    }

    async fn settled_knocks(&self) -> usize {
        // Enough time for a connection that was going to happen to have
        // happened; the sentinel is on the loopback.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.knocks.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_valid_name_that_points_inward_is_never_connected_to() {
    let sentinel = Sentinel::listen().await;
    let harness = Harness::with_federation("insecure_http = true");
    let port = sentinel.port;

    // Each is a valid server name by the grammar #286 checks. The first
    // two are literals, which never touch DNS; the last resolves.
    let origins = [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("localhost:{port}"),
    ];
    for origin in &origins {
        let (status, body) = harness.knock_from(origin).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{origin}: {body}");
    }
    assert_eq!(
        sentinel.settled_knocks().await,
        0,
        "a stranger's header made this server connect inward"
    );
}

#[tokio::test]
async fn a_listed_range_is_reachable() {
    let sentinel = Sentinel::listen().await;
    let harness =
        Harness::with_federation("insecure_http = true\nallow_internal = [\"127.0.0.0/8\"]");

    // The sentinel answers nothing, so the fetch fails and the request is
    // still refused -- but the connection was made, which is the point.
    let (status, _) = harness
        .knock_from(&format!("127.0.0.1:{}", sentinel.port))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(sentinel.settled_knocks().await, 1);
}

#[tokio::test]
async fn a_name_whose_fetch_failed_is_not_fetched_again_at_once() {
    let sentinel = Sentinel::listen().await;
    let harness =
        Harness::with_federation("insecure_http = true\nallow_internal = [\"127.0.0.0/8\"]");
    let origin = format!("127.0.0.1:{}", sentinel.port);

    for _ in 0..5 {
        let (status, _) = harness.knock_from(&origin).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        sentinel.settled_knocks().await,
        1,
        "five headers naming one unreachable peer cost five connections"
    );
}

#[tokio::test]
async fn a_bad_allow_list_entry_refuses_to_start() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[federation]\nallow_internal = [\"10.0.0.0/33\"]\n",
    )
    .unwrap();
    let error = match spindle_server::app(config, store) {
        Ok(_) => panic!("an allow-list entry with a 33-bit prefix built an app"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("federation config"), "{error}");
}

/// A loopback listener that answers every request with a redirect to
/// `location` and counts what it answered.
struct Redirector {
    port: u16,
    answered: Arc<AtomicUsize>,
}

impl Redirector {
    async fn listen(location: String) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let answered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&answered);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut sink = [0_u8; 4096];
                let _ = socket.read(&mut sink).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(response.as_bytes()).await;
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        Self { port, answered }
    }
}

/// A sentinel on a second loopback address, so an allow-list can admit the
/// redirecting peer and not the place it redirects to.
async fn sentinel_on(address: &str) -> Sentinel {
    let listener = tokio::net::TcpListener::bind((address, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let knocks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&knocks);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    Sentinel { port, knocks }
}

#[tokio::test]
async fn a_redirect_into_an_unlisted_address_is_not_followed() {
    // The peer is reachable (its exact address is listed); where it
    // redirects to is loopback too, but outside the list -- the stand-in
    // for a public peer answering `302 Location: http://169.254.169.254/`,
    // which no test can bind (#312).
    let target = sentinel_on("127.0.0.2").await;
    let peer = Redirector::listen(format!(
        "http://127.0.0.2:{}/_matrix/key/v2/server",
        target.port
    ))
    .await;
    let harness =
        Harness::with_federation("insecure_http = true\nallow_internal = [\"127.0.0.1/32\"]");
    let (status, _) = harness
        .knock_from(&format!("127.0.0.1:{}", peer.port))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        peer.answered.load(Ordering::SeqCst),
        1,
        "the peer was fetched"
    );
    assert_eq!(
        target.settled_knocks().await,
        0,
        "the redirect was followed into an address the allow-list does not cover"
    );

    // The same redirect with the target listed is followed: the policy
    // vets, it does not forbid redirects outright.
    let target = sentinel_on("127.0.0.2").await;
    let peer = Redirector::listen(format!(
        "http://127.0.0.2:{}/_matrix/key/v2/server",
        target.port
    ))
    .await;
    let harness =
        Harness::with_federation("insecure_http = true\nallow_internal = [\"127.0.0.0/8\"]");
    let (status, _) = harness
        .knock_from(&format!("127.0.0.1:{}", peer.port))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        target.settled_knocks().await,
        1,
        "a listed redirect target is reached"
    );
}
