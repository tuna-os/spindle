//! Synapse pagination tokens a client kept across the migration (#568).
//!
//! Element X's event cache keeps a Synapse `prev_batch` with every gap in
//! a cached timeline, and Element Web's sync accumulator keeps one per
//! room. After the switch the client sends them back to fill those gaps.
//! The importer records each imported event's Synapse stream ordering
//! beside the linear index it got here, and a Synapse token resolves
//! through that; a room with nothing recorded falls back to paging from
//! the head, which repeats events the client holds rather than losing any.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("an app");
        Self {
            _dir: dir,
            store,
            app,
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn send(&self, method: &str, path: &str, token: &str, body: &Value) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
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

    /// A room with `count` messages `m0..`, and their event IDs.
    async fn room_with(&self, token: &str, count: usize) -> (String, Vec<String>) {
        let created = self
            .send("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        let room = created["room_id"].as_str().unwrap().to_owned();
        let mut ids = Vec::new();
        for index in 0..count {
            let sent = self
                .send(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t{index}"),
                    token,
                    &json!({ "msgtype": "m.text", "body": format!("m{index}") }),
                )
                .await;
            ids.push(sent["event_id"].as_str().unwrap().to_owned());
        }
        (room, ids)
    }

    async fn page(&self, room: &str, token: &str, query: &str) -> (StatusCode, Value) {
        self.get(
            &format!("/_matrix/client/v3/rooms/{room}/messages?{query}"),
            token,
        )
        .await
    }
}

fn bodies(page: &Value) -> Vec<String> {
    page["chunk"]
        .as_array()
        .expect("a chunk")
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

fn names(range: impl Iterator<Item = usize>) -> Vec<String> {
    range.map(|index| format!("m{index}")).collect()
}

/// What the importer does: record the stream ordering Synapse gave each
/// event. Message `i` had stream ordering `1000 + 10 i`.
fn record(harness: &Harness, room: &str, ids: &[String]) {
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&harness.store), "example.org");
    let positions: Vec<(i64, i64, &str)> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            (
                1000 + 10 * i64::try_from(index).unwrap(),
                41 + i64::try_from(index).unwrap(),
                id.as_str(),
            )
        })
        .collect();
    let written = rooms
        .record_synapse_positions(room, positions.iter().copied())
        .unwrap();
    assert_eq!(written, ids.len());
}

#[tokio::test]
async fn a_synapse_token_resolves_through_the_recorded_positions() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let (room, ids) = harness.room_with(&token, 10).await;
    record(&harness, &room, &ids);

    // A `/sync` `prev_batch` whose timeline began at m6 (stream 1060):
    // Synapse's backward token sits one below it. Back from there is m5
    // and older, newest first, and the page carries on in our tokens.
    let synapse = "t46-1059_59480933_23_1472883_8005_125_9029_4969314_0_165_2_1_1";
    let (status, page) = harness
        .page(&room, &token, &format!("dir=b&limit=3&from={synapse}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), names((3..6).rev()));
    assert_eq!(page["start"], synapse, "start is the client's own token");
    let end = page["end"].as_str().expect("more history").to_owned();
    assert!(end.starts_with('t') && !end.contains('-'), "{end}");
    let (_, older) = harness
        .page(&room, &token, &format!("dir=b&limit=50&from={end}"))
        .await;
    assert_eq!(bodies(&older), names((0..3).rev()));

    // A stream token, as an older `/sync` hands out: the same place.
    let (_, page) = harness
        .page(&room, &token, "dir=b&limit=2&from=s1059_59480933_23_1")
        .await;
    assert_eq!(bodies(&page), names([5, 4].into_iter()));

    // Forward from a `/context` `end` Synapse minted on m6.
    let (_, page) = harness
        .page(&room, &token, "dir=f&limit=50&from=t47-1060_1_2")
        .await;
    assert_eq!(bodies(&page), names(7..10));

    // A token older than everything imported: nothing lies behind it.
    let (status, page) = harness
        .page(&room, &token, "dir=b&limit=5&from=t1-12_1_2")
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page["chunk"].as_array().unwrap().is_empty(), "{page}");
    assert!(page.get("end").is_none(), "{page}");

    // Relations take the same tokens.
    let (status, page) = harness
        .get(
            &format!(
                "/_matrix/client/v1/rooms/{room}/relations/{}?from={synapse}",
                ids[0]
            ),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
}

#[tokio::test]
async fn a_room_without_positions_pages_from_the_head_instead_of_refusing() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let (room, _) = harness.room_with(&token, 6).await;

    // Backward: from the head, so the client fills its gap with events it
    // partly holds and carries on with our `end`.
    let (status, page) = harness
        .page(
            &room,
            &token,
            "dir=b&limit=3&from=t16750-1590636_59480933_23",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), names((3..6).rev()));
    assert!(page["end"].is_string(), "{page}");

    // Forward: nowhere to place it, so an empty page at the live end.
    let (status, page) = harness
        .page(
            &room,
            &token,
            "dir=f&limit=3&from=t16750-1590636_59480933_23",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page["chunk"].as_array().unwrap().is_empty(), "{page}");
    assert!(page.get("end").is_none(), "{page}");

    // `/threads` with Synapse's `{depth}_{stream}` token starts over.
    let (status, page) = harness
        .get(
            &format!("/_matrix/client/v1/rooms/{room}/threads?from=16750_1590636"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");

    // `/members?at=` with a Synapse stream token is the members now.
    let (status, page) = harness
        .get(
            &format!(
                "/_matrix/client/v3/rooms/{room}/members?at=s1600473_59519903_23_1472883_8005"
            ),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["chunk"].as_array().unwrap().len(), 1, "{page}");

    // Garbage is still a 400, and so is our own sync token on /messages.
    for bad in ["banana", "s42"] {
        let (status, page) = harness
            .page(&room, &token, &format!("dir=b&from={bad}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {page}");
    }
}

#[test]
fn empty_and_extreme_synapse_positions_have_bounded_lookups() {
    use spindle_store::Store;
    let harness = Harness::new();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&harness.store), "example.org");
    let room = "!imported:example.org";
    let position = |stream| spindle_server::tokens::SynapsePosition {
        topological: None,
        stream,
    };
    for stream in [i64::MIN, -1, 0, 1, i64::MAX] {
        assert_eq!(rooms.synapse_gap(room, position(stream)).unwrap(), None);
    }
    for (stream, li) in [(i64::MIN, 0_i64), (i64::MAX, 1_i64)] {
        harness
            .store
            .put(
                &spindle_core::keys::synapse_position(room, stream),
                &li.to_be_bytes(),
            )
            .unwrap();
    }
    assert_eq!(
        rooms.synapse_gap(room, position(i64::MIN)).unwrap(),
        Some(spindle_server::rooms::SynapseGap::At(1))
    );
    assert_eq!(
        rooms.synapse_gap(room, position(i64::MAX)).unwrap(),
        Some(spindle_server::rooms::SynapseGap::At(2))
    );
    let before = harness.store.scanned();
    assert_eq!(
        rooms.synapse_gap(room, position(0)).unwrap(),
        Some(spindle_server::rooms::SynapseGap::At(1))
    );
    assert_eq!(harness.store.scanned() - before, 1);
}

#[tokio::test]
async fn imported_topology_and_arrival_order_keep_distinct_boundaries() {
    let harness = Harness::new();
    let token = harness.register("alice").await;
    let (room, ids) = harness.room_with(&token, 3).await;
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&harness.store), "example.org");
    rooms
        .record_synapse_positions(
            &room,
            [
                (100, 10, ids[0].as_str()),
                (50, 11, ids[1].as_str()),
                (200, 12, ids[2].as_str()),
            ],
        )
        .unwrap();
    let (_, before) = harness
        .page(&room, &token, "dir=b&limit=50&from=t10-99_1")
        .await;
    assert!(bodies(&before).is_empty(), "{before}");
    let (_, topology) = harness
        .page(&room, &token, "dir=b&limit=50&from=t10-100_1")
        .await;
    assert_eq!(bodies(&topology), names([0].into_iter()));
    let (_, arrival) = harness
        .page(&room, &token, "dir=b&limit=50&from=s100_1")
        .await;
    assert_eq!(bodies(&arrival), names([1, 0].into_iter()));
}
