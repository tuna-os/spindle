//! A resync retains a large room's omitted roster through
//! `Rooms::retain_remote_auth` in one batch (#766). Every member event in
//! that batch cites the same create event, power levels and join rules, so
//! what the batch reads from the store must grow by a small constant per
//! member -- its own existence checks -- and not by a re-read and re-parse
//! of those shared auth events per member, which is what made the batch a
//! large share of a 10,000-member resync.
//!
//! Counted, not timed, for the reason `read_budget.rs` gives.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event, reference_hash};
use serde_json::{Value, json};
use spindle_server::rooms::Rooms;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Store reads the batch may add per member event: whether its own body
/// is held, and which room holds its ID.
const READS_PER_MEMBER: u64 = 2;

async fn call(app: &axum::Router, request: Request<Body>) -> Value {
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn post(path: &str, token: Option<&str>, body: &Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// A public room on `example.org` and the event its next member cites.
async fn public_room(store: &Arc<FjallStore>) -> (String, String) {
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
    )
    .unwrap();
    let app = spindle_server::app(config, Arc::clone(store)).unwrap();
    let registered = call(
        &app,
        post(
            "/_matrix/client/v3/register",
            None,
            &json!({
                "username": "alice",
                "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "s" },
            }),
        ),
    )
    .await;
    let token = registered["access_token"].as_str().unwrap();
    let created = call(
        &app,
        post(
            "/_matrix/client/v3/createRoom",
            Some(token),
            &json!({ "preset": "public_chat" }),
        ),
    )
    .await;
    let room = created["room_id"].as_str().unwrap().to_owned();
    let rooms = Rooms::new(Arc::clone(store), "example.org");
    let head = rooms
        .state(&room)
        .unwrap()
        .into_iter()
        .max_by_key(|event| event["depth"].as_u64())
        .unwrap()["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    (room, head)
}

/// `members` remote join events, each hashed and named as a peer would.
fn joins(store: &Arc<FjallStore>, room: &str, head: &str, members: usize) -> Vec<(String, Value)> {
    let document = Ed25519KeyPair::generate();
    let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
    let rules = RoomVersionId::V11.rules().unwrap();
    (0..members)
        .map(|number| {
            let user = format!("@member{number}:remote.test");
            let event = federation_auth::with_auth_events(
                store,
                json!({
                    "type": "m.room.member",
                    "state_key": user,
                    "sender": user,
                    "room_id": room,
                    "content": { "membership": "join" },
                    "origin_server_ts": 1_700_000_000_000_u64,
                    "depth": 10,
                    "prev_events": [head],
                    "auth_events": [],
                }),
            );
            let ruma::CanonicalJsonValue::Object(mut canonical) =
                ruma::CanonicalJsonValue::try_from(event).unwrap()
            else {
                unreachable!()
            };
            hash_and_sign_event("remote.test", &pair, &mut canonical, &rules.redaction).unwrap();
            let id = format!("${}", reference_hash(&canonical, &rules).unwrap());
            (id, serde_json::to_value(&canonical).unwrap())
        })
        .collect()
}

/// Reads one batch of `members` costs, in a fresh room.
async fn reads_for(members: usize) -> u64 {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (room, head) = public_room(&store).await;
    let batch = joins(&store, &room, &head, members);
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    // Load the room first, so the count is the batch and not the room's
    // first read from disk.
    rooms.state(&room).unwrap();
    let before = store.reads();
    rooms.retain_remote_auth(&room, &batch).unwrap();
    let after = store.reads();
    for (id, _) in &batch {
        rooms
            .pdu(&room, id)
            .expect("every member event is retained");
    }
    after - before
}

#[tokio::test]
async fn a_retained_roster_reads_its_shared_auth_events_once() {
    let small = reads_for(20).await;
    let large = reads_for(120).await;
    assert!(
        large - small <= 100 * READS_PER_MEMBER,
        "100 more members cost {} more reads; the budget is {READS_PER_MEMBER} each \
         ({small} for 20, {large} for 120)",
        large - small
    );
}
