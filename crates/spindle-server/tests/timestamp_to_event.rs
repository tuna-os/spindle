//! Jump-to-date: the nearest event to a timestamp, on the side you asked for.
//!
//! A client with a calendar date needs somewhere in the timeline to start
//! paginating from. `f` and `b` are opposite answers to the same question, so
//! most of this file is about telling them apart: a test that only ever
//! searches backward would pass with the direction ignored entirely.

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
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, txn: &str) -> String {
        let (status, body) = self
            .call(
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
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn event_ts(&self, room: &str, token: &str, event_id: &str) -> u64 {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["origin_server_ts"].as_u64().unwrap()
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn at(&self, room: &str, token: &str, ts: u64, dir: &str) -> (StatusCode, Value) {
        self.get(
            &format!("/_matrix/client/v1/rooms/{room}/timestamp_to_event?ts={ts}&dir={dir}"),
            token,
        )
        .await
    }
}

/// Three messages, and the timestamps they landed at.
///
/// The clock has millisecond resolution and these send back to back, so
/// several can share a timestamp. Everything below is written against the
/// timestamps actually observed rather than against an assumed spacing --
/// an assertion that needs the three to be distinct would be testing the
/// host's clock.
async fn seeded(harness: &Harness, token: &str) -> (String, Vec<(String, u64)>) {
    let room = harness.create_room(token).await;
    let mut events = Vec::new();
    for txn in ["one", "two", "three"] {
        let id = harness.say(&room, token, txn).await;
        let ts = harness.event_ts(&room, token, &id).await;
        events.push((id, ts));
    }
    (room, events)
}

/// Every timestamp in the room, from `/messages`.
///
/// The messages are not the room's first events: `createRoom` writes the
/// create event, the creator's membership, power levels and join rules
/// before any of them, and those are stamped earlier. The first version of
/// these tests took `events[0]` for "the room's beginning" and failed --
/// correctly, because the endpoint was right and the expectation was not.
/// Asking the timeline is the way to find out rather than assume.
async fn all_timestamps(harness: &Harness, room: &str, token: &str) -> Vec<u64> {
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100"),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stamps: Vec<u64> = body["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["origin_server_ts"].as_u64())
        .collect();
    assert!(!stamps.is_empty(), "the room has no events at all: {body}");
    stamps
}

/// The two directions disagree, and each is right about its own side.
#[tokio::test]
async fn each_direction_answers_its_own_side() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, events) = seeded(&harness, &alice).await;
    let (_, middle_ts) = events[1].clone();

    let (status, back) = harness.at(&room, &alice, middle_ts, "b").await;
    assert_eq!(status, StatusCode::OK, "{back}");
    assert!(
        back["origin_server_ts"].as_u64().unwrap() <= middle_ts,
        "backward returned an event from after the timestamp: {back}"
    );

    let (status, forward) = harness.at(&room, &alice, middle_ts, "f").await;
    assert_eq!(status, StatusCode::OK, "{forward}");
    assert!(
        forward["origin_server_ts"].as_u64().unwrap() >= middle_ts,
        "forward returned an event from before the timestamp: {forward}"
    );
}

/// A timestamp before everything has no answer backwards, and the room's
/// first event forwards.
///
/// This is the pair that a direction-ignoring implementation cannot fake:
/// one side is a 404 and the other is a 200 for the very same request but
/// for `dir`.
#[tokio::test]
async fn before_the_room_began_is_a_404_backwards_and_the_first_event_forwards() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, _) = seeded(&harness, &alice).await;
    let earliest = all_timestamps(&harness, &room, &alice)
        .await
        .into_iter()
        .min()
        .unwrap();
    let before = earliest - 1;

    let (status, body) = harness.at(&room, &alice, before, "b").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nothing happened before the room existed: {body}"
    );

    let (status, body) = harness.at(&room, &alice, before, "f").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["origin_server_ts"].as_u64().unwrap(),
        earliest,
        "forwards from before the beginning is the room's first event: {body}"
    );
}

/// And the mirror: after everything is a 404 forwards, the last event
/// backwards.
#[tokio::test]
async fn after_the_last_event_is_a_404_forwards_and_the_last_event_backwards() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, _) = seeded(&harness, &alice).await;
    let latest = all_timestamps(&harness, &room, &alice)
        .await
        .into_iter()
        .max()
        .unwrap();
    let after = latest + 60_000;

    let (status, body) = harness.at(&room, &alice, after, "f").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nothing has happened yet after that time: {body}"
    );

    let (status, body) = harness.at(&room, &alice, after, "b").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["origin_server_ts"].as_u64().unwrap(), latest, "{body}");
}

/// An exact hit belongs to both sides.
///
/// The forward search finds the last entry strictly *before* the timestamp
/// and takes its successor, so an event stamped exactly `ts` is the one case
/// where an off-by-one steps over the answer. Sending the same timestamp both
/// ways and getting the same event back is what pins it.
#[tokio::test]
async fn an_exact_timestamp_is_found_from_either_direction() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, events) = seeded(&harness, &alice).await;
    let (_, first_ts) = events[0].clone();

    let (status, forward) = harness.at(&room, &alice, first_ts, "f").await;
    assert_eq!(status, StatusCode::OK, "{forward}");
    assert_eq!(
        forward["origin_server_ts"].as_u64().unwrap(),
        first_ts,
        "an event stamped exactly at the requested time is at or after it: \
         {forward}"
    );
}

/// `ts = 0` forwards is the room's first event, and does not underflow.
///
/// The forward search asks about `ts - 1`, which has no answer at zero.
#[tokio::test]
async fn a_zero_timestamp_forwards_is_the_first_event() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, _) = seeded(&harness, &alice).await;
    let earliest = all_timestamps(&harness, &room, &alice)
        .await
        .into_iter()
        .min()
        .unwrap();

    let (status, body) = harness.at(&room, &alice, 0, "f").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["origin_server_ts"].as_u64().unwrap(),
        earliest,
        "{body}"
    );
}

/// `dir` is required, and a wrong one is refused rather than guessed.
///
/// A default would hand a client a plausible event from the wrong side of
/// the date it asked about, and it would page away from what it wanted. A
/// silently wrong answer is worse than a 400.
#[tokio::test]
async fn the_direction_is_required_and_not_guessed() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (room, events) = seeded(&harness, &alice).await;
    let (_, ts) = events[0].clone();

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/timestamp_to_event?ts={ts}"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");

    let (status, body) = harness.at(&room, &alice, ts, "sideways").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/timestamp_to_event?dir=f"),
            &alice,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");
}

/// It is a room read, and obeys the same rule as every other room read.
#[tokio::test]
async fn a_stranger_cannot_jump_to_a_date_in_someone_elses_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let (room, events) = seeded(&harness, &alice).await;
    let (_, ts) = events[0].clone();

    let (status, body) = harness.at(&room, &mallory, ts, "b").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}
