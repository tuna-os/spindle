//! #897: a Simplified Sliding Sync connection survives a restart.
//!
//! Before, the connections lived in memory only, so every `pos` a client
//! held was answered `M_UNKNOWN_POS` after a deploy. matrix-rust-sdk then
//! resets its room list and loads the window again, and Element X users saw
//! the list go blank on every restart. Pinned here: the server stops, the
//! store closes and opens again under a new server, and the client's `pos`
//! is answered as an incremental response that sends only what changed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const CONFIG: &str = "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n";

fn serve(store: &Arc<FjallStore>) -> axum::Router {
    let config = spindle_server::Config::parse(CONFIG).unwrap();
    spindle_server::app(config, Arc::clone(store)).expect("a signing key is established")
}

/// Stop the server as `main` does: drop the router, wait until nothing
/// else holds the store, and close it. Then open the directory again.
async fn restart(app: axum::Router, store: Arc<FjallStore>, dir: &TempDir) -> Arc<FjallStore> {
    drop(app);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut store = store;
    loop {
        match Arc::try_unwrap(store) {
            Ok(store) => {
                drop(store);
                break;
            }
            Err(shared) => {
                assert!(Instant::now() < deadline, "the store did not close");
                store = shared;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    Arc::new(FjallStore::open(dir.path()).unwrap())
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> Value {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let (status, response) = call(app, builder.body(Body::from(body.to_string())).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{method} {path}: {response}");
    response
}

async fn sliding(app: &axum::Router, token: &str, pos: Option<&str>, body: &Value) -> Value {
    let path = match pos {
        Some(pos) => {
            format!("/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos={pos}")
        }
        None => "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync".to_owned(),
    };
    request(app, "POST", &path, Some(token), body).await
}

async fn named_room(app: &axum::Router, token: &str, name: &str) -> String {
    let created = request(
        app,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(token),
        &json!({ "name": name }),
    )
    .await;
    created["room_id"].as_str().unwrap().to_owned()
}

async fn say(app: &axum::Router, token: &str, room: &str, text: &str, txn: &str) {
    request(
        app,
        "PUT",
        &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
        Some(token),
        &json!({ "msgtype": "m.text", "body": text }),
    )
    .await;
}

fn pos(response: &Value) -> String {
    response["pos"]
        .as_str()
        .unwrap_or_else(|| panic!("a pos: {response}"))
        .to_owned()
}

fn bodies(entry: &Value) -> Vec<&str> {
    entry["timeline"]
        .as_array()
        .unwrap_or_else(|| panic!("timeline: {entry}"))
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .collect()
}

fn window() -> Value {
    json!({
        "lists": {
            "main": {
                "ranges": [[0, 9]],
                "required_state": [["m.room.name", ""]],
                "timeline_limit": 5,
            }
        },
        "extensions": { "typing": { "enabled": true } },
    })
}

#[tokio::test]
async fn a_connection_resumes_after_a_restart() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let app = serve(&store);
    let registered = request(
        &app,
        "POST",
        "/_matrix/client/v3/register",
        None,
        &json!({
            "username": "alice",
            "password": "hunter2",
            "auth": { "type": "m.login.dummy", "session": "register" },
        }),
    )
    .await;
    let alice = registered["access_token"].as_str().unwrap().to_owned();
    let busy = named_room(&app, &alice, "busy").await;
    let quiet = named_room(&app, &alice, "quiet").await;
    say(&app, &alice, &busy, "before", "t1").await;
    say(&app, &alice, &quiet, "hello", "t2").await;

    let first = sliding(&app, &alice, None, &window()).await;
    for room in [&busy, &quiet] {
        assert_eq!(first["rooms"][room]["initial"], json!(true), "{first}");
    }
    let held = sliding(&app, &alice, Some(&pos(&first)), &window()).await;
    assert!(held["rooms"].as_object().unwrap().is_empty(), "{held}");
    let token = pos(&held);

    let store = restart(app, store, &dir).await;
    let app = serve(&store);
    say(&app, &alice, &busy, "after", "t3").await;

    // No lists in the body: the sticky parameters came through the restart
    // too, or the answer would have no lists and no rooms.
    let resumed = sliding(&app, &alice, Some(&token), &json!({})).await;
    assert!(resumed.get("errcode").is_none(), "{resumed}");
    assert_eq!(resumed["lists"]["main"]["count"], json!(2), "{resumed}");
    let rooms = resumed["rooms"].as_object().unwrap();
    assert_eq!(
        rooms.keys().collect::<Vec<_>>(),
        vec![&busy],
        "only the room that changed, not the quiet one again: {resumed}"
    );
    let entry = &rooms[&busy];
    assert_eq!(entry["initial"], json!(false), "{resumed}");
    assert_eq!(bodies(entry), vec!["after"], "{resumed}");
    assert!(
        entry["required_state"].as_array().unwrap().is_empty(),
        "the name the client holds is not sent again: {resumed}"
    );
    assert!(
        resumed["extensions"].get("typing").is_some(),
        "the extension config came through: {resumed}"
    );

    // And the connection goes on from the new position.
    let next = sliding(&app, &alice, Some(&pos(&resumed)), &json!({})).await;
    assert!(next["rooms"].as_object().unwrap().is_empty(), "{next}");
}
