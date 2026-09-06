//! The `r0` client and media API prefixes, served as `v3`.
//!
//! Every client built before spec v1.1 asks for `/_matrix/client/r0/…`,
//! and matrix-js-sdk kept doing so on some endpoints for two years after:
//! Element Call's full-mesh branch, the peer-to-peer call client, registers
//! at `/r0/register`. A server that answers only `v3` refuses it with
//! `M_UNRECOGNIZED`, which no user can act on. The endpoints are the same;
//! only the prefix moved.

use std::sync::Arc;

use serde_json::{Value, json};
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
async fn r0_is_served_as_v3_with_its_query_string_intact() {
    let (_dir, name) = start().await;
    let client = reqwest::Client::new();

    // Registration on the old prefix, the call a 2023 client makes first.
    let response = client
        .post(format!(
            "http://{name}/_matrix/client/r0/register?kind=user"
        ))
        .header("content-type", "application/json")
        .body(
            json!({
                "username": "alice",
                "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "s" },
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let token = body["access_token"].as_str().expect("a token").to_owned();

    // An authenticated read on the old prefix, and the query string that
    // rode along: a filter-less sync with a timeout of zero returns at once.
    let response = client
        .get(format!("http://{name}/_matrix/client/r0/sync?timeout=0"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(body["next_batch"].is_string(), "{body}");

    // The media prefix moved the same way.
    let response = client
        .get(format!("http://{name}/_matrix/media/r0/config"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // What was never served under any prefix is still unrecognized: the
    // rewrite adds no endpoints, it only spells the existing ones twice.
    let response = client
        .get(format!("http://{name}/_matrix/client/r0/no/such/endpoint"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");
}
