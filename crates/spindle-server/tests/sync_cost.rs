//! What does one incremental `/sync` actually read?
//!
//! Counted, not timed (#177): `store.reads()` and `store.scanned()` count
//! point reads and scanned rows, so the answer is the same on any machine
//! and the assertions below are real gates rather than wall clocks on a
//! shared runner. Where a test could be satisfied by moving work from a
//! point read into a scan, it sums the two.
//!
//! Three axes, varied independently -- which is the point, because the
//! benchmark driver varies none of them. `sync_delta` uses two rooms and a
//! token from moments earlier, on an otherwise idle server, so it holds all
//! three at their minimum and measured the one case where none costs
//! anything: how many rooms the user is in, how much of the room's own
//! history precedes the token, and how busy the rest of the server has been.

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

    async fn post(&self, path: &str, token: &str, payload: &Value) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// `bob` joins `room` on `alice`'s invite.
    async fn invite_and_join(&self, room: &str, alice: &str, bob: &str) {
        self.post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            alice,
            &json!({ "user_id": "@bob:example.org" }),
        )
        .await;
        self.post(
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            bob,
            &json!({}),
        )
        .await;
    }

    async fn say(&self, room: &str, token: &str, text: &str, txn: &str) {
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
                        json!({ "msgtype": "m.text", "body": text }).to_string(),
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

/// A sync must not get more expensive because *other people* were talking.
///
/// Alice is in one room where nothing has happened since her token. What
/// varies is how many events Bob sent in a room she is not in. Answering
/// her from the server-wide stream meant reading every one of them and
/// throwing them away -- measured at exactly `elsewhere + 1`:
///
/// ```text
/// elsewhere   0    50    200   800
/// reads       1    51    201   801
/// ```
///
/// and flat at 1 after the reverse `(room, stream_id)` index. This is the
/// multi-tenant shape of the defect: on a server with a thousand users, a
/// client in one quiet room paid for the other nine hundred and ninety
/// nine, and its sync got slower every time the server got busier.
///
/// Scanned rows are counted alongside point reads, because the fix moves
/// the question from a point read per stream id to a range scan -- and a
/// scan that still walked the whole range would be the same defect wearing
/// a different counter.
#[tokio::test]
async fn a_sync_does_not_pay_for_other_rooms() {
    let mut measured = Vec::new();
    for elsewhere in [0usize, 800] {
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

        let before = harness.store.reads() + harness.store.scanned();
        harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.reads() + harness.store.scanned() - before);
    }
    assert_eq!(
        measured[0], measured[1],
        "a quiet sync touched {} rows, and the same sync behind 800 events \
         in someone else's room touched {} -- the server-wide stream is \
         being walked again",
        measured[0], measured[1]
    );
}

/// Nor for its own room's history before the token.
///
/// The reverse index is keyed `(room_id, stream_id)`, so a scan that
/// started at the room's first row instead of at the client's token would
/// pass the test above -- the cost would be the room's own past rather
/// than the server's present, which is the same defect at a smaller
/// radius. It is the room a client keeps for years that this protects.
#[tokio::test]
async fn a_sync_does_not_pay_for_its_own_history() {
    let mut measured = Vec::new();
    for before_token in [0usize, 800] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        let mine = harness.room(&alice).await;
        for index in 0..before_token {
            harness.send(&mine, &alice, &format!("old{index}")).await;
        }
        let batch = harness.sync(&alice, None).await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();
        harness.send(&mine, &alice, "new").await;

        let before = harness.store.reads() + harness.store.scanned();
        harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.reads() + harness.store.scanned() - before);
    }
    assert_eq!(
        measured[0], measured[1],
        "a sync one event behind touched {} rows in a new room and {} in a \
         room with 800 events already read -- the scan is starting at the \
         room's first row, not at the token",
        measured[0], measured[1]
    );
}

/// A sync that carries news pays no disk barrier.
///
/// A sync writes nothing a client sent, but it hands out a token, and a
/// restart must never allocate a position at or below one a client holds.
/// The checkpoint that promises it was a full fsync on every sync that
/// moved the stream -- that is, on every sync that carried anything --
/// measured before the fix at one barrier per sync: 8 for the 8 below.
/// That is the benchmark's `sync_delta` cell, which lost to Tuwunel on
/// three sittings in a row (#701). The checkpoint now reaches ahead of the
/// token, so one barrier covers many syncs.
///
/// Barriers rather than rows, because the push loop writes its cursor in
/// the background after each send, and only a barrier is the sync's own.
#[tokio::test]
async fn a_sync_carrying_news_pays_no_disk_barrier() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.room(&alice).await;
    harness.invite_and_join(&room, &alice, &bob).await;
    let mut batch = harness.sync(&alice, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut barriers = 0;
    for index in 0..8 {
        harness.send(&room, &bob, &format!("m{index}")).await;
        let before = harness.store.barriers();
        let body = harness.sync(&alice, Some(&batch)).await;
        barriers += harness.store.barriers() - before;
        let timeline = &body["rooms"]["join"][&room]["timeline"]["events"];
        assert_eq!(timeline.as_array().map(Vec::len), Some(1), "{body}");
        batch = body["next_batch"].as_str().unwrap().to_owned();
    }
    assert_eq!(
        barriers, 0,
        "8 syncs, each carrying one message, paid {barriers} fsyncs between \
         them -- the stream checkpoint is being written for every token again"
    );
}

/// The user's rooms are read once per sync, not once per section.
///
/// Every section -- joined, invited, knocked, left, banned -- scanned the
/// user's whole membership index for its own kind, and the joined rooms
/// were scanned again for the ephemeral sections: six rows per room the
/// user is in, on every sync, before any room was looked at. Measured
/// before the fix as the rows a quiet sync scans:
///
/// ```text
/// rooms     1    8
/// scanned   6    48
/// ```
///
/// One row per room is the floor: a sync has to know which rooms it is
/// answering for.
#[tokio::test]
async fn a_sync_reads_the_membership_index_once() {
    let mut measured = Vec::new();
    for rooms in [1usize, 8] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        for index in 0..rooms {
            let room = harness.room(&alice).await;
            harness.send(&room, &alice, &format!("seed{index}")).await;
        }
        let batch = harness.sync(&alice, None).await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();

        let before = harness.store.scanned();
        harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.scanned() - before);
    }
    assert!(
        measured[1] - measured[0] <= 7,
        "a quiet sync scanned {} rows for one room and {} for eight -- more \
         than one row for each room added, so the membership index is being \
         read once per section again",
        measured[0],
        measured[1]
    );
}

/// Nor for the rooms the user left long ago.
///
/// An incremental sync says nothing about a room nobody spoke in since
/// the token, but for every room the user had ever left it read the
/// forgotten flag and the departure's body to find that out: two point
/// reads per left room, on every sync, for as long as the account lives.
/// Measured before the fix as a quiet sync's reads:
///
/// ```text
/// left   1    8
/// reads  6    20
/// ```
#[tokio::test]
async fn rooms_left_long_ago_cost_a_sync_nothing() {
    let mut measured = Vec::new();
    for left in [1usize, 8] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        let home = harness.room(&alice).await;
        harness.send(&home, &alice, "seed").await;
        for index in 0..left {
            let room = harness.room(&alice).await;
            harness.send(&room, &alice, &format!("bye{index}")).await;
            harness
                .post(
                    &format!("/_matrix/client/v3/rooms/{room}/leave"),
                    &alice,
                    &json!({}),
                )
                .await;
        }
        let batch = harness.sync(&alice, None).await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();

        let before = harness.store.reads();
        harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.reads() - before);
    }
    assert_eq!(
        measured[0], measured[1],
        "a quiet sync read {} rows with one room left behind and {} with \
         eight -- every departed room is being read on every sync again",
        measured[0], measured[1]
    );
}

/// A highlight is a push-rule question answered against the body, so an
/// unread mention has to be read once. Once: the tally remembers how far it
/// scored, and a sync that finds nothing new after that position reads no
/// body it has already scored, however many unread mentions are waiting.
/// Measured as the reads of a sync that brings one new message on top of a
/// backlog of one unread mention against a backlog of eight.
#[tokio::test]
async fn unread_highlights_are_scored_once_and_not_on_every_sync() {
    let mut measured = Vec::new();
    for mentions in [1usize, 8] {
        let harness = Harness::new();
        let alice = harness.register("alice").await;
        let bob = harness.register("bob").await;
        let mine = harness.room(&alice).await;
        harness.invite_and_join(&mine, &alice, &bob).await;
        for index in 0..mentions {
            harness
                .say(
                    &mine,
                    &bob,
                    &format!("alice, {index}"),
                    &format!("m{index}"),
                )
                .await;
        }
        let first = harness.sync(&alice, None).await;
        let counts = &first["rooms"]["join"][&mine]["unread_notifications"];
        assert_eq!(counts["highlight_count"], mentions, "{counts}");
        let batch = first["next_batch"].as_str().unwrap().to_owned();

        // One more message, so the room is in the next window and its badge
        // is served again: the new body is scored, the backlog is not.
        harness.say(&mine, &bob, "and one more", "extra").await;
        let before = harness.store.reads();
        let next = harness.sync(&alice, Some(&batch)).await;
        measured.push(harness.store.reads() - before);
        let counts = &next["rooms"]["join"][&mine]["unread_notifications"];
        assert_eq!(counts["highlight_count"], mentions, "{counts}");
    }
    assert_eq!(
        measured[0], measured[1],
        "a sync behind one unread mention read {} and behind eight read {} \
         -- the unread backlog is being scored again",
        measured[0], measured[1]
    );
}

/// What one incremental sync reads as the client falls further behind.
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
