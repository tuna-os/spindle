//! Server discovery: `.well-known/matrix/server` delegation.
//!
//! Most servers on the public federation are not reached at
//! `<name>:8448`. Their name serves `/.well-known/matrix/server`, which
//! names the host and port that do speak federation (matrix.org names
//! `matrix-federation.matrix.org:443`; a typical ESS deployment names
//! `matrix.<name>:443`). A server that skips this step cannot send a
//! single event to such a peer: the Synapse migration drill (#563) found
//! exactly that, with a witness server delegated the way production
//! servers are.
//!
//! What must hold: a delegated name is reached where its `.well-known`
//! says; the answer is fetched once and cached, not once per request; a
//! name without a usable `.well-known` is still reached at `<name>:8448`;
//! and a `.well-known` cannot point this server at an address it would
//! refuse to reach by name.
//!
//! Tests cannot bind 443, so `.well-known` is served on a random port
//! (`with_well_known_port`) over plain http (`insecure_http`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::routing::get;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// A server that answers one request path and counts how often it is asked.
struct Counted {
    port: u16,
    hits: Arc<AtomicUsize>,
}

async fn serve(path: &'static str, status: u16, body: String) -> Counted {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().route(
        path,
        get({
            let hits = Arc::clone(&hits);
            move || {
                hits.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                async move {
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        [("content-type", "application/json")],
                        body,
                    )
                }
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Counted { port, hits }
}

/// A `.well-known/matrix/server` that names `m_server`.
async fn well_known(m_server: &str) -> Counted {
    serve(
        "/.well-known/matrix/server",
        200,
        serde_json::json!({ "m.server": m_server }).to_string(),
    )
    .await
}

/// The federation endpoint a delegation points at, counting profile
/// queries: a plain signed GET, the simplest request that goes through
/// the same addressing as every transaction.
async fn delegated_target() -> Counted {
    serve(
        "/_matrix/federation/v1/query/profile",
        200,
        r#"{"displayname":"reached"}"#.to_owned(),
    )
    .await
}

const USER: &str = "@someone:localhost";

fn federation(
    dir: &TempDir,
    well_known_port: u16,
    allow_internal: &[&str],
) -> spindle_server::federation::Federation {
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    let allow: Vec<String> = allow_internal.iter().map(|&r| r.to_owned()).collect();
    spindle_server::federation::Federation::new(store, "example.org", key, true, &allow)
        .unwrap()
        .with_well_known_port(well_known_port)
}

/// The witness in the drill delegates `witness.lab` to
/// `matrix.witness.lab:443`, as reilly.asia delegates to
/// `matrix.reilly.asia:443`: the request must go to the delegated host
/// and port, not to `<name>:8448`.
#[tokio::test]
async fn a_delegated_name_is_reached_where_its_well_known_says() {
    let target = delegated_target().await;
    let wk = well_known(&format!("127.0.0.1:{}", target.port)).await;
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir, wk.port, &["127.0.0.0/8"]);

    let profile = federation
        .remote_query_profile("localhost", USER)
        .await
        .unwrap();
    assert_eq!(profile["displayname"], "reached");
    assert_eq!(
        wk.hits.load(Ordering::SeqCst),
        1,
        "the .well-known was asked"
    );
    assert_eq!(target.hits.load(Ordering::SeqCst), 1);
}

/// One `.well-known` fetch serves every request to that name until its
/// cache time runs out; a busy destination does not cost a second round
/// trip per transaction.
#[tokio::test]
async fn the_well_known_answer_is_cached() {
    let target = delegated_target().await;
    let wk = well_known(&format!("127.0.0.1:{}", target.port)).await;
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir, wk.port, &["127.0.0.0/8"]);

    for _ in 0..3 {
        federation
            .remote_query_profile("localhost", USER)
            .await
            .unwrap();
    }
    assert_eq!(wk.hits.load(Ordering::SeqCst), 1, "asked once, then cached");
    assert_eq!(target.hits.load(Ordering::SeqCst), 3);
}

/// No `.well-known` (a 404, as from a server that serves federation on
/// 8448 itself) leaves the spec's last step: `<name>:8448`. The delegated
/// stub is never asked.
#[tokio::test]
async fn without_a_well_known_the_name_is_reached_on_8448() {
    let target = delegated_target().await;
    let wk = serve("/.well-known/matrix/server", 404, "{}".to_owned()).await;
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir, wk.port, &["127.0.0.0/8"]);

    let error = federation
        .remote_query_profile("localhost", USER)
        .await
        .unwrap_err();
    assert_eq!(wk.hits.load(Ordering::SeqCst), 1);
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
    assert!(
        error.to_string().contains("localhost:8448"),
        "fell back to <name>:8448: {error}"
    );
}

/// A `.well-known` is written by whoever controls the name, so it is
/// held to the same rules as the name: an `m.server` that is not a server
/// name is ignored, and one that names an address this server will not
/// reach (here a private range not in `allow_internal`) is refused rather
/// than followed. Either way the name falls back to `<name>:8448`.
#[tokio::test]
async fn a_well_known_cannot_point_past_the_address_rules() {
    for m_server in ["10.1.2.3:8448", "127.0.0.1:1/../admin", "not a server name"] {
        let wk = well_known(m_server).await;
        let dir = TempDir::new().unwrap();
        let federation = federation(&dir, wk.port, &["127.0.0.0/8"]);
        let error = federation
            .remote_query_profile("localhost", USER)
            .await
            .unwrap_err();
        assert_eq!(wk.hits.load(Ordering::SeqCst), 1, "{m_server}");
        assert!(
            error.to_string().contains("localhost:8448"),
            "{m_server:?} was not followed: {error}"
        );
    }
}

/// An explicit port or an IP literal is used as it is; the spec reads
/// `.well-known` only for a bare hostname.
#[tokio::test]
async fn a_name_with_a_port_or_a_literal_skips_discovery() {
    let target = delegated_target().await;
    let wk = well_known(&format!("127.0.0.1:{}", target.port)).await;
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir, wk.port, &["127.0.0.0/8"]);

    let named = federation
        .remote_query_profile(&format!("localhost:{}", target.port), USER)
        .await
        .unwrap();
    assert_eq!(named["displayname"], "reached");
    let _ = federation.remote_query_profile("127.0.0.1", USER).await;
    assert_eq!(wk.hits.load(Ordering::SeqCst), 0);
    assert_eq!(target.hits.load(Ordering::SeqCst), 1);
}
