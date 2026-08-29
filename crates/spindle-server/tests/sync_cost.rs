//! What does one incremental `/sync` actually read?
//!
//! Counted, not timed (#177): `store.reads()` is a point-read counter, so
//! the answer is the same on any machine, and the assertion below is a
//! real gate rather than a wall clock on a shared runner.
//!
//! Two axes, varied independently -- which is the point, because the
//! benchmark driver varies neither. `sync_delta` uses two rooms and a
//! token from moments earlier, so it holds both at their minimum and
//! measured the one case where neither costs anything.

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
    store: Arc<FjallStore>,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).unwrap();
        Self {
            _dir: dir,
            app,
            store,
        }
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
        let (_, body) = self
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
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn room(&self, token: &str) -> String {
        let (_, created) = self
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
        created["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, room: &str, token: &str, txn: &str) {
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
                        json!({ "msgtype": "m.text", "body": "x" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn sync(&self, token: &str, since: Option<&str>) -> Value {
        let uri = match since {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, body) = self
            .call(
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
}

/// Reads must not multiply by the number of rooms the user is in.
///
/// They did. The stream is the *server's* order, so "what happened since
/// this token" is one question with one answer, but it was asked once per
/// joined room and the non-matching rows thrown away. Measured before the
/// fix at exactly `rooms x elsewhere + 1`:
///
/// ```text
/// rooms   1     2     4      8
/// reads   201   401   801    1601
/// ```
///
/// and flat at 201 after it. Note what the second factor is: events in a
/// room the user is **not a member of**. Their sync got more expensive
/// because strangers were talking.
#[tokio::test]
async fn reads_do_not_multiply_by_joined_rooms() {
    let mut measured = Vec::new();
    for rooms in [1usize, 8] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        let bob = harness.register("bob").await;
        let mut mine = Vec::new();
        for _ in 0..rooms {
            mine.push(harness.room(&alice).await);
        }
        let theirs = harness.room(&bob).await;
        for room in &mine {
            harness.send(room, &alice, "seed").await;
        }
        let batch = harness.sync(&alice, None).await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();
        for index in 0..50 {
            harness.send(&theirs, &bob, &format!("x{index}")).await;
        }

        let before = harness.store.reads();
        harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.reads() - before);
    }
    assert_eq!(
        measured[0], measured[1],
        "one room read {} and eight read {} -- the stream range is being \
         walked per room again",
        measured[0], measured[1]
    );
}

/// The cost that remains: linear in how far behind the client is.
///
/// Inherent to reading a server-wide order, and not fixed by the change
/// above. Removing it needs a reverse `(room, stream_id)` index, which is
/// a stored format and therefore a migration.
#[tokio::test]
#[ignore = "a measurement, not an assertion"]
async fn reads_versus_token_age() {
    println!("elsewhere  reads for one incremental sync");
    for elsewhere in [0usize, 50, 200, 800] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        let bob = harness.register("bob").await;
        let mine = harness.room(&alice).await;
        let theirs = harness.room(&bob).await;

        harness.send(&mine, &alice, "seed").await;
        let batch = harness.sync(&alice, None).await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();
        for index in 0..elsewhere {
            harness.send(&theirs, &bob, &format!("x{index}")).await;
        }

        let before = harness.store.reads();
        harness.sync(&alice, Some(&batch)).await;
        println!("{elsewhere:>9}  {}", harness.store.reads() - before);
    }
}
