//! A store written before the reverse stream index must still sync.
//!
//! The `(room_id, stream_id)` index is what an incremental `/sync` reads,
//! and a store written by an earlier binary has a forward stream and no
//! index at all. Nothing marks such a store as old — the keyspace is
//! additive, so it opens without complaint and every other endpoint works.
//! Only `/sync` would notice, and it would notice by going *quiet*: an empty
//! index says nothing happened, which is the answer a caught-up client gets.
//! A client would sit there, connected and idle, missing every message.
//!
//! So the recovery is not optional and it is not an operator step. Opening
//! the store fills in whatever the index is missing, and this test is the
//! only thing that says so — it deletes the index out from under a working
//! server and asserts the reopened one still hands over the events.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::{FjallStore, ReadView, Store};
use tempfile::TempDir;
use tower::ServiceExt;

fn config() -> spindle_server::Config {
    spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
    )
    .unwrap()
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

async fn register(app: &axum::Router) -> String {
    let (_, body) = call(
        app,
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "alice",
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    body["access_token"].as_str().unwrap().to_owned()
}

async fn create_room(app: &axum::Router, token: &str) -> String {
    let (_, created) = call(
        app,
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/createRoom")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    created["room_id"].as_str().unwrap().to_owned()
}

async fn send(app: &axum::Router, room: &str, token: &str, txn: &str) {
    let (status, body) = call(
        app,
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "msgtype": "m.text", "body": txn }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn sync(app: &axum::Router, token: &str, since: Option<&str>) -> Value {
    let uri = match since {
        Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
        None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
    };
    let (status, body) = call(
        app,
        Request::builder()
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// Every reverse-index row, as a store written before the index would not
/// have them.
fn index_rows(store: &FjallStore) -> Vec<Vec<u8>> {
    store
        .scan_prefix(&[
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::RoomStream as u8,
        ])
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

#[tokio::test]
async fn opening_an_unindexed_store_rebuilds_the_index() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());

    let app = spindle_server::app(config(), Arc::clone(&store)).unwrap();
    let token = register(&app).await;
    let room = create_room(&app, &token).await;
    send(&app, &room, &token, "before-the-token").await;
    let batch = sync(&app, &token, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    send(&app, &room, &token, "after-the-token").await;

    // Turn it into a store from before the index existed. The forward stream
    // stays: that is exactly the state an upgrade finds.
    let rows = index_rows(&store);
    assert!(
        !rows.is_empty(),
        "nothing was indexed, so nothing is proven"
    );
    for key in rows {
        store.delete(&key).unwrap();
    }
    assert!(index_rows(&store).is_empty());

    let reopened = spindle_server::app(config(), Arc::clone(&store)).unwrap();
    assert!(
        !index_rows(&store).is_empty(),
        "opening the store left the index empty; every incremental sync \
         against it will report that nothing has happened"
    );

    let body = sync(&reopened, &token, Some(&batch)).await;
    let events = body["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let bodies: Vec<&str> = events
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .collect();
    assert_eq!(
        bodies,
        vec!["after-the-token"],
        "the event sent before the restart was not delivered: the rebuilt \
         index does not cover the events the old binary wrote"
    );
}
