//! Parallel registrations cannot spend one use twice or take one name twice
//! (#833). Both used to be a check, a slow password hash, then an unlocked
//! write, so every parallel request passed the check.
//!
//! One binary: the hashing pool is process-wide and sized by the first
//! server the process builds.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::registration_tokens::RegistrationTokens;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const PARALLEL: usize = 6;

fn app(require_token: bool) -> (axum::Router, Arc<FjallStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    // A queue long enough that no request is refused for waiting: only the
    // races below may make a registration fail.
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
         [registration]\nrequire_token = {require_token}\n\
         [limits]\npassword_hashes_at_once = 2\npassword_hashes_waiting = 64\n"
    ))
    .unwrap();
    let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
    (app, store, dir)
}

async fn register(app: axum::Router, username: String, auth: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "username": username, "password": "hunter2", "auth": auth })
                        .to_string(),
                ))
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

async fn all(app: &axum::Router, names: Vec<String>, auth: Value) -> Vec<(StatusCode, Value)> {
    let tasks: Vec<_> = names
        .into_iter()
        .map(|name| tokio::spawn(register(app.clone(), name, auth.clone())))
        .collect();
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    results
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_use_token_makes_one_account_however_many_ask() {
    let (app, store, _dir) = app(true);
    let tokens = RegistrationTokens::new(Arc::clone(&store));
    tokens
        .create(Some("once".to_owned()), Some(1), None, 16)
        .unwrap();
    let names = (0..PARALLEL).map(|n| format!("user{n}")).collect();
    let results = all(
        &app,
        names,
        json!({ "type": "m.login.registration_token", "token": "once", "session": "s" }),
    )
    .await;
    let created = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert_eq!(created, 1, "{results:?}");
    assert_eq!(tokens.get("once").unwrap().unwrap().completed, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_name_registered_in_parallel_goes_to_one_request() {
    let (app, _store, _dir) = app(false);
    let names = (0..PARALLEL).map(|_| "alice".to_owned()).collect();
    let results = all(&app, names, json!({ "type": "m.login.dummy" })).await;
    let created = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .count();
    assert_eq!(created, 1, "{results:?}");
    assert!(
        results
            .iter()
            .filter(|(status, _)| *status != StatusCode::OK)
            .all(|(_, body)| body["errcode"] == "M_USER_IN_USE"),
        "{results:?}"
    );
}
