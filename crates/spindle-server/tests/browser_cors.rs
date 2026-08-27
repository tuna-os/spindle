//! SPEC (client-server, Web Browser Clients): the CORS headers that let
//! a client running in a browser exist at all. Complement cannot catch
//! their absence — its Go client never sends an Origin header — which is
//! exactly how they went missing until Element Web hit the gap.

use std::sync::Arc;

use spindle_store::FjallStore;
use tempfile::TempDir;

async fn start() -> (TempDir, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n"
    ))
    .unwrap();
    let app = spindle_server::app(config, store).expect("the app builds");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, name)
}

#[tokio::test]
async fn every_response_carries_the_cors_headers() {
    let (_dir, name) = start().await;
    let client = reqwest::Client::new();

    // An ordinary request, an error response, and the 404 fallback all
    // carry the headers — a browser needs them on failures most of all,
    // or the app cannot even read the errcode.
    for path in [
        "/_matrix/client/versions",
        "/_matrix/client/v3/account/whoami",
        "/_matrix/client/v3/no/such/endpoint",
    ] {
        let response = client
            .get(format!("http://{name}{path}"))
            .header("origin", "http://element.example")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("*"),
            "{path}"
        );
        assert!(
            response
                .headers()
                .get("access-control-allow-headers")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|allowed| allowed.contains("Authorization")),
            "{path}: a browser must be allowed to send the bearer token"
        );
    }
}

#[tokio::test]
async fn preflight_succeeds_without_reaching_a_handler() {
    let (_dir, name) = start().await;
    let response = reqwest::Client::new()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{name}/_matrix/client/v3/login"),
        )
        .header("origin", "http://element.example")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "preflight answers 2xx, not the endpoint's own verdict: {}",
        response.status()
    );
    assert!(
        response
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|methods| methods.contains("DELETE")),
        "the allowed methods cover the whole client API"
    );
}
