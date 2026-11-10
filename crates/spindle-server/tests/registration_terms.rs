//! `m.login.terms`: with a policy configured, registration needs it
//! accepted first, and no later stage can be used to skip it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

async fn register(app: &axum::Router, auth: Option<Value>) -> (u16, Value) {
    let mut body = json!({ "username": "carol", "password": "hunter2hunter2" });
    if let Some(auth) = auth {
        body["auth"] = auth;
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_terms_stage_cannot_be_skipped() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n[ratelimit]\nenabled = false\n\
         [registration]\nterms_url = \"https://example.org/terms\"\n",
        dir.path().display()
    ))
    .unwrap();
    let app = spindle_server::app(config, store).unwrap();

    let (status, body) = register(&app, None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        body["flows"],
        json!([{ "stages": ["m.login.terms", "m.login.dummy"] }])
    );
    assert_eq!(
        body["params"]["m.login.terms"]["policies"]["terms_of_service"]["en"]["url"],
        "https://example.org/terms"
    );

    // The old dummy-only completions no longer register anyone.
    for auth in [
        json!({ "type": "m.login.dummy" }),
        json!({ "type": "m.login.dummy", "session": "register" }),
    ] {
        let (status, body) = register(&app, Some(auth)).await;
        assert_eq!(status, 401, "{body}");
    }

    let (status, body) = register(
        &app,
        Some(json!({ "type": "m.login.terms", "session": "register" })),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["completed"], json!(["m.login.terms"]));
    let session = body["session"].as_str().unwrap().to_owned();

    let (status, body) = register(
        &app,
        Some(json!({ "type": "m.login.dummy", "session": session })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}
