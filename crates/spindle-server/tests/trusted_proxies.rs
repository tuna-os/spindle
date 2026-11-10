//! Source limits behind a reverse proxy (#831).
//!
//! Before `[server] trusted_proxies`, every client behind a proxy on
//! loopback had the source `127.0.0.1`, so one client spending the
//! registration budget refused all the others. The probe is the registration
//! token check: it spends `register:source` and does no hashing.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const PATH: &str = "/_matrix/client/v1/register/m.login.registration_token/validity?token=x";
/// `REGISTER_PER_SOURCE` allows this many in its window.
const BUDGET: usize = 5;

fn app(extra_server: &str) -> (axum::Router, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n{extra_server}\n"
    ))
    .unwrap();
    (
        spindle_server::app(config, store).expect("the app builds"),
        dir,
    )
}

async fn probe(app: &axum::Router, peer: &str, forwarded: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().uri(PATH);
    if let Some(forwarded) = forwarded {
        builder = builder.header("x-forwarded-for", forwarded);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn clients_behind_a_trusted_proxy_get_separate_buckets() {
    let (app, _dir) = app("trusted_proxies = [\"127.0.0.1\"]");
    for _ in 0..BUDGET {
        assert_eq!(
            probe(&app, "127.0.0.1:4000", Some("198.51.100.1")).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        probe(&app, "127.0.0.1:4000", Some("198.51.100.1")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        probe(&app, "127.0.0.1:4000", Some("198.51.100.2")).await,
        StatusCode::OK,
        "a second client must not share the first one's bucket"
    );
}

#[tokio::test]
async fn an_untrusted_peer_cannot_spoof_its_address() {
    let (app, _dir) = app("trusted_proxies = [\"127.0.0.1\"]");
    for number in 0..BUDGET {
        let forged = format!("198.51.100.{number}");
        assert_eq!(
            probe(&app, "203.0.113.9:4000", Some(&forged)).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        probe(&app, "203.0.113.9:4000", Some("198.51.100.200")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a forged header from an untrusted peer must not buy a fresh bucket"
    );
}

#[tokio::test]
async fn without_trusted_proxies_the_header_is_ignored() {
    let (app, _dir) = app("");
    for number in 0..BUDGET {
        let forged = format!("198.51.100.{number}");
        assert_eq!(
            probe(&app, "127.0.0.1:4000", Some(&forged)).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        probe(&app, "127.0.0.1:4000", Some("198.51.100.200")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn one_ipv6_network_shares_a_bucket() {
    let (app, _dir) = app("");
    for number in 0..BUDGET {
        let peer = format!("[2001:db8:1:2::{}]:4000", number + 1);
        assert_eq!(probe(&app, &peer, None).await, StatusCode::OK);
    }
    assert_eq!(
        probe(&app, "[2001:db8:1:2:aaaa::1]:4000", None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}
