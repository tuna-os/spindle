//! `[federation] enabled = false`: a server that is an island.
//!
//! A migration rehearsal runs a dark copy of a live server with the
//! production `server_name` and signing key. If that copy reached a peer it
//! would speak for the live server, so it must not federate at all, and the
//! switch has to hold where no network policy is enforced. What must hold:
//! no outbound federation request opens a socket, even to a peer the
//! config lists at an allowed address, and the server-server API is not
//! served.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::get;
use serde_json::Value;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// A peer that counts every request it is sent.
async fn counting_peer() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().fallback(get(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async { "{}" }
    }));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, hits)
}

fn federation(
    store: &Arc<FjallStore>,
    name: &str,
    url: &str,
    enabled: bool,
) -> spindle_server::federation::Federation {
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    let peers = std::collections::BTreeMap::from([(
        name.to_owned(),
        spindle_server::config::PeerConfig {
            url: url.to_owned(),
            max_backoff_ms: None,
        },
    )]);
    spindle_server::federation::Federation::new(
        Arc::clone(store),
        "example.org",
        key,
        false,
        &["127.0.0.0/8".to_owned()],
    )
    .unwrap()
    .with_peers(&peers)
    .with_enabled(enabled)
}

#[tokio::test]
async fn disabled_federation_opens_no_socket_even_to_a_listed_peer() {
    let (url, hits) = counting_peer().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());

    // The control: the same peer, enabled, is reached.
    let enabled = federation(&store, "peer.example", &url, true);
    assert!(enabled.enabled());
    let _ = enabled.peer_keys("peer.example").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the enabled control reached the peer"
    );

    let disabled = federation(&store, "other.example", &url, false);
    assert!(!disabled.enabled());
    assert!(disabled.peer_keys("other.example").await.is_err());
    assert!(
        disabled
            .remote_media_download("other.example", "media")
            .await
            .is_err()
    );
    assert!(
        disabled
            .remote_query_profile("other.example", "@someone:other.example")
            .await
            .is_err()
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "disabled federation opened a connection"
    );
}

async fn serve(federation: &str) -> (TempDir, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n[federation]\n{federation}\n"
    ))
    .unwrap();
    let app = spindle_server::app(config, store).expect("the app builds");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, name)
}

#[tokio::test]
async fn disabled_federation_serves_no_server_server_api() {
    let client = reqwest::Client::new();
    for (setting, served) in [("", true), ("enabled = false", false)] {
        let (_dir, name) = serve(setting).await;
        for path in ["/_matrix/key/v2/server", "/_matrix/federation/v1/version"] {
            let response = client
                .get(format!("http://{name}{path}"))
                .send()
                .await
                .unwrap();
            if served {
                assert_eq!(response.status(), 200, "{path} with federation on");
            } else {
                assert_eq!(response.status(), 404, "{path} with federation off");
                let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{path}");
            }
        }
        // The client API is unaffected either way.
        let response = client
            .get(format!("http://{name}/_matrix/client/versions"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
}
