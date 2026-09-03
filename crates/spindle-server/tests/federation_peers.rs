//! Peers reached by configuration, not by name (`[federation] peers`).
//!
//! A federation peer is found by its name: the name is the host. A mesh
//! homeserver named by its node key has no host to be found at, and a
//! venue gateway on a LAN has no DNS; both are listed in the config with
//! the URL their requests go to. What must hold: a request to a listed
//! name reaches the listed URL and nothing tries to resolve the name; a
//! listed URL inside this server's network still needs `allow_internal`;
//! and a peer's `M_TOO_LARGE` for a media file is taken as its answer,
//! with no second request to the legacy endpoint.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::get;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// A peer that counts what it is asked, answers its key document with
/// nothing signed (the fetch fails one step later than this suite cares
/// about), and refuses every media download as too large.
struct Stub {
    url: String,
    keys: Arc<AtomicUsize>,
    media: Arc<AtomicUsize>,
    legacy: Arc<AtomicUsize>,
}

impl Stub {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let keys = Arc::new(AtomicUsize::new(0));
        let media = Arc::new(AtomicUsize::new(0));
        let legacy = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                get({
                    let keys = Arc::clone(&keys);
                    move || {
                        keys.fetch_add(1, Ordering::SeqCst);
                        async { "{}" }
                    }
                }),
            )
            .route(
                "/_matrix/federation/v1/media/download/{media_id}",
                get({
                    let media = Arc::clone(&media);
                    move || {
                        media.fetch_add(1, Ordering::SeqCst);
                        async {
                            (
                                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                                axum::Json(serde_json::json!({
                                    "errcode": "M_TOO_LARGE",
                                    "error": "this peer serves media up to 256 KiB",
                                })),
                            )
                        }
                    }
                }),
            )
            .route(
                "/_matrix/media/v3/download/{server}/{media_id}",
                get({
                    let legacy = Arc::clone(&legacy);
                    move || {
                        legacy.fetch_add(1, Ordering::SeqCst);
                        async { (axum::http::StatusCode::NOT_FOUND, "{}") }
                    }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url,
            keys,
            media,
            legacy,
        }
    }
}

/// A `Federation` with `[federation] peers` naming `name` at `url`.
fn federation(
    store: &Arc<FjallStore>,
    name: &str,
    url: &str,
    allow_internal: &[String],
) -> spindle_server::federation::Federation {
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    let peers = std::collections::BTreeMap::from([(
        name.to_owned(),
        spindle_server::config::PeerConfig {
            url: url.to_owned(),
            max_backoff_ms: Some(3_600_000),
        },
    )]);
    spindle_server::federation::Federation::new(
        Arc::clone(store),
        "example.org",
        key,
        // Not `insecure_http`: a listed peer's URL says its own scheme.
        false,
        allow_internal,
    )
    .unwrap()
    .with_peers(&peers)
}

/// A node named by its key has no host to resolve; the request goes to the
/// URL the operator listed.
#[tokio::test]
async fn a_listed_peer_is_reached_at_its_url_not_by_its_name() {
    let stub = Stub::start().await;
    let name = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let federation = federation(&store, name, &stub.url, &["127.0.0.0/8".to_owned()]);

    // The key document is empty, so the fetch fails after the request --
    // what is asserted is that the request arrived at the listed URL.
    let _ = federation.peer_keys(name).await;
    assert_eq!(
        stub.keys.load(Ordering::SeqCst),
        1,
        "the listed URL was asked"
    );
    assert_eq!(
        federation.peer_max_backoff(name),
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(federation.peer_max_backoff("other.example"), None);
}

/// Listing a peer does not open the network: a URL inside this server's
/// ranges is refused unless `allow_internal` names the range, exactly as a
/// name resolving there would be.
#[tokio::test]
async fn a_listed_peer_inside_the_network_still_needs_allow_internal() {
    let stub = Stub::start().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let federation = federation(&store, "gateway.venue", &stub.url, &[]);

    let outcome = federation.peer_keys("gateway.venue").await;
    assert!(outcome.is_err());
    assert_eq!(stub.keys.load(Ordering::SeqCst), 0, "no socket was opened");
}

/// A peer that says a file is too large has answered; the legacy endpoint
/// is not asked to say it again.
#[tokio::test]
async fn a_peers_too_large_is_final_and_the_legacy_endpoint_is_not_tried() {
    let stub = Stub::start().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let federation = federation(
        &store,
        "gateway.venue",
        &stub.url,
        &["127.0.0.0/8".to_owned()],
    );

    let outcome = federation
        .remote_media_download("gateway.venue", "bigfile")
        .await;
    match outcome {
        Err(spindle_server::federation::FederationError::Answered { status, body }) => {
            assert_eq!(status, 413);
            assert_eq!(body["errcode"], "M_TOO_LARGE");
        }
        other => panic!("expected the peer\'s answer, got {other:?}"),
    }
    assert_eq!(stub.media.load(Ordering::SeqCst), 1);
    assert_eq!(
        stub.legacy.load(Ordering::SeqCst),
        0,
        "the legacy endpoint was tried"
    );
}
