//! Rooms end to end: create, send, read back.
//!
//! The assertion that matters most is the last one — that the pagination token
//! is the linear index, and that paging through it returns every event exactly
//! once in order. That is the design's central claim showing up at the API.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self) -> String {
        let (status, body) = self
            .send(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "alice",
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn a_user_can_create_a_room_and_it_appears_in_their_joined_rooms() {
    let harness = Harness::new();
    let token = harness.register().await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/createRoom",
            &token,
            &json!({ "name": "Test", "topic": "A topic" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let room_id = body["room_id"].as_str().expect("a room ID").to_owned();
    assert!(room_id.starts_with('!'), "{room_id}");
    assert!(room_id.ends_with(":example.org"), "{room_id}");

    let (status, body) = harness.get("/_matrix/client/v3/joined_rooms", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["joined_rooms"], json!([room_id]));
}

#[tokio::test]
async fn a_sent_event_comes_back_with_the_id_the_server_assigned() {
    let harness = Harness::new();
    let token = harness.register().await;
    let (_, created) = harness
        .post("/_matrix/client/v3/createRoom", &token, &json!({}))
        .await;
    let room_id = created["room_id"].as_str().unwrap().to_owned();

    let (status, sent) = harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            &token,
            &json!({ "msgtype": "m.text", "body": "hello" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let event_id = sent["event_id"].as_str().expect("an event ID");
    // Room v11 event IDs are `$` plus a reference hash — not a random string,
    // and not something a client supplied.
    assert!(event_id.starts_with('$'), "{event_id}");
    assert!(event_id.len() > 20, "{event_id}");

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=1"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let newest = &body["chunk"][0];
    assert_eq!(newest["event_id"], event_id);
    assert_eq!(newest["content"]["body"], "hello");
    assert_eq!(newest["sender"], "@alice:example.org");
    assert_eq!(newest["room_id"], room_id);
    // Signed, which is what makes the event ID meaningful.
    assert!(newest["signatures"].is_object(), "{newest}");
    assert!(newest["hashes"].is_object(), "{newest}");
}

/// The design's central claim, at the API: the pagination token is the linear
/// index, and paging through it yields every event once, in order.
#[tokio::test]
async fn paginating_by_linear_index_returns_every_event_exactly_once() {
    let harness = Harness::new();
    let token = harness.register().await;
    let (_, created) = harness
        .post("/_matrix/client/v3/createRoom", &token, &json!({}))
        .await;
    let room_id = created["room_id"].as_str().unwrap().to_owned();

    let mut sent = Vec::new();
    for index in 0..25 {
        let (status, body) = harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn{index}"),
                &token,
                &json!({ "msgtype": "m.text", "body": format!("message {index}") }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        sent.push(body["event_id"].as_str().unwrap().to_owned());
    }

    // Page backwards in fours, following the token the server hands back.
    let mut seen = Vec::new();
    let mut from: Option<String> = None;
    for _ in 0..40 {
        let path = match &from {
            Some(token) => {
                format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=4&from={token}")
            }
            None => format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=4"),
        };
        let (status, body) = harness.get(&path, &token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for event in body["chunk"].as_array().unwrap() {
            seen.push(event["event_id"].as_str().unwrap().to_owned());
        }
        match body["end"].as_str() {
            Some(next) => from = Some(next.to_owned()),
            // Absent means there is nothing more, which is how a client stops.
            None => break,
        }
    }

    // Every event exactly once: no duplicates across page boundaries, and
    // nothing skipped.
    let unique: std::collections::BTreeSet<_> = seen.iter().collect();
    assert_eq!(
        unique.len(),
        seen.len(),
        "an event was returned on more than one page"
    );
    // The room's own create events are in there too, plus the 25 messages.
    assert!(
        seen.len() >= sent.len(),
        "paged {} events but sent {}",
        seen.len(),
        sent.len()
    );
    for event_id in &sent {
        assert!(seen.contains(event_id), "{event_id} was never paged");
    }

    // Newest first, and the order is the reverse of the order they were sent.
    let paged_messages: Vec<_> = seen.iter().filter(|id| sent.contains(id)).collect();
    let expected: Vec<_> = sent.iter().rev().collect();
    assert_eq!(paged_messages, expected, "pagination order is wrong");
}

#[tokio::test]
async fn room_endpoints_need_authentication_and_a_real_room() {
    let harness = Harness::new();
    let token = harness.register().await;

    let (status, body) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/createRoom")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");

    let (status, body) = harness
        .put(
            "/_matrix/client/v3/rooms/!nope:example.org/send/m.room.message/t1",
            &token,
            &json!({ "body": "into the void" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

/// Every event a v11 room emits has to name the state that authorizes it. An
/// empty `auth_events` is not a smaller version of this — it is an event that
/// `auth_check` rejects, so a room built that way produces nothing a peer will
/// ever accept.
#[tokio::test]
async fn every_event_cites_the_state_that_authorizes_it() {
    let harness = Harness::new();
    let token = harness.register().await;
    let (_, created) = harness
        .post("/_matrix/client/v3/createRoom", &token, &json!({}))
        .await;
    let room_id = created["room_id"].as_str().unwrap().to_owned();

    harness
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1"),
            &token,
            &json!({ "msgtype": "m.text", "body": "hello" }),
        )
        .await;

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=100"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let chunk = body["chunk"].as_array().unwrap();

    let mut by_type = std::collections::HashMap::new();
    let mut ids = std::collections::BTreeSet::new();
    for event in chunk {
        let id = event["event_id"].as_str().unwrap().to_owned();
        by_type.insert(event["type"].as_str().unwrap().to_owned(), event.clone());
        ids.insert(id);
    }

    let auth_of = |event: &Value| -> Vec<String> {
        event["auth_events"]
            .as_array()
            .unwrap_or_else(|| panic!("auth_events is missing from {event}"))
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect()
    };

    // The create event is the root of the auth chain: it cites nothing,
    // because there is nothing yet to cite.
    let create = &by_type["m.room.create"];
    assert!(auth_of(create).is_empty(), "{create}");
    let create_id = create["event_id"].as_str().unwrap().to_owned();
    let power_id = by_type["m.room.power_levels"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let member_id = by_type["m.room.member"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A message cites the three that decide whether it is allowed: the room
    // exists, the sender is in it, and the sender is permitted to speak.
    let message = &by_type["m.room.message"];
    let cited: std::collections::BTreeSet<String> = auth_of(message).into_iter().collect();
    assert_eq!(
        cited,
        [create_id.clone(), power_id, member_id.clone()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "{message}"
    );

    // The creator's join happens before power levels exist, so it cites only
    // the create event -- which is also what authorizes it.
    assert_eq!(auth_of(&by_type["m.room.member"]), vec![create_id]);

    // Every event except the create event cites something, and everything
    // cited is an event this room actually contains. A dangling reference
    // fails auth on a peer exactly as an empty list does.
    for event in chunk {
        let cited = auth_of(event);
        if event["type"] != "m.room.create" {
            assert!(!cited.is_empty(), "nothing authorizes {event}");
        }
        for id in cited {
            assert!(ids.contains(&id), "{event} cites {id}, which is not here");
        }
    }
}
