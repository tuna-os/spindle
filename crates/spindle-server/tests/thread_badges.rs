//! The badge a client shows, scored the way the spec has it: unread
//! events the reader's push rules notify for, split by thread when the
//! client asks (MSC3773), moved by threaded receipts (MSC3771), and the
//! receipt's thread echoed to everyone (spec v1.4).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
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
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { dir, app }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        payload: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = match payload {
            Some(payload) => {
                builder = builder.header("content-type", "application/json");
                Body::from(payload.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn shared_room(&self, alice: &str, bob: &str) -> String {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(alice),
                Some(&json!({ "invite": ["@bob:example.org"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room_id = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room_id}/join"),
                Some(bob),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room_id
    }

    async fn put_event(
        &self,
        room_id: &str,
        token: &str,
        event_type: &str,
        txn: &str,
        content: Value,
    ) -> String {
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn}"),
                Some(token),
                Some(&content),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room_id: &str, token: &str, text: &str, txn: &str) -> String {
        self.put_event(
            room_id,
            token,
            "m.room.message",
            txn,
            json!({ "msgtype": "m.text", "body": text }),
        )
        .await
    }

    async fn reply_in_thread(&self, room_id: &str, token: &str, root: &str, txn: &str) -> String {
        self.put_event(
            room_id,
            token,
            "m.room.message",
            txn,
            json!({
                "msgtype": "m.text",
                "body": "in the thread",
                "m.relates_to": {
                    "rel_type": "m.thread",
                    "event_id": root,
                    "is_falling_back": true,
                    "m.in_reply_to": { "event_id": root },
                },
            }),
        )
        .await
    }

    async fn receipt(&self, room_id: &str, token: &str, event_id: &str, thread: Option<&str>) {
        let body = thread.map_or_else(|| json!({}), |thread| json!({ "thread_id": thread }));
        let (status, response) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}"),
                Some(token),
                Some(&body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    /// The room's `unread_notifications`, and `unread_thread_notifications`
    /// when the timeline filter asks for the split.
    async fn badge(&self, token: &str, room_id: &str, by_thread: bool) -> (Value, Value) {
        let path = if by_thread {
            let filter = json!({
                "room": { "timeline": { "unread_thread_notifications": true } },
            });
            format!(
                "/_matrix/client/v3/sync?filter={}",
                urlencoding(&filter.to_string())
            )
        } else {
            "/_matrix/client/v3/sync".to_owned()
        };
        let (status, body) = self.send("GET", &path, Some(token), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = &body["rooms"]["join"][room_id];
        (
            room["unread_notifications"].clone(),
            room["unread_thread_notifications"].clone(),
        )
    }
}

fn urlencoding(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn counts(value: &Value) -> (u64, u64) {
    (
        value["notification_count"].as_u64().unwrap_or(0),
        value["highlight_count"].as_u64().unwrap_or(0),
    )
}

#[tokio::test]
async fn threads_are_counted_apart_and_read_apart() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.shared_room(&alice, &bob).await;

    let _m1 = server
        .say(&room, &alice, "in the main timeline", "m1")
        .await;
    let thread_root = server.say(&room, &alice, "a thread starts here", "r").await;
    let _t1 = server
        .reply_in_thread(&room, &alice, &thread_root, "t1")
        .await;
    let t2 = server
        .reply_in_thread(&room, &alice, &thread_root, "t2")
        .await;

    // One badge for everything, as before.
    let (total, threads) = server.badge(&bob, &room, false).await;
    assert_eq!(counts(&total), (4, 0), "{total}");
    assert!(threads.is_null(), "{threads}");

    // Split: the main timeline is the message and the root; the thread
    // has its two replies.
    let (main, threads) = server.badge(&bob, &room, true).await;
    assert_eq!(counts(&main), (2, 0), "{main}");
    assert_eq!(counts(&threads[&thread_root]), (2, 0), "{threads}");

    // Reading the thread reads only the thread.
    server.receipt(&room, &bob, &t2, Some(&thread_root)).await;
    let (main, threads) = server.badge(&bob, &room, true).await;
    assert_eq!(counts(&main), (2, 0), "{main}");
    assert!(threads.get(&thread_root).is_none(), "{threads}");
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(
        counts(&total),
        (4, 0),
        "an unthreaded badge moves only with an unthreaded receipt: {total}"
    );

    // A `main` receipt reads the main timeline alone.
    server
        .receipt(&room, &bob, &thread_root, Some("main"))
        .await;
    let (main, _) = server.badge(&bob, &room, true).await;
    assert_eq!(counts(&main), (0, 0), "{main}");

    // An unthreaded receipt at the end reads everything.
    server.receipt(&room, &bob, &t2, None).await;
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(counts(&total), (0, 0), "{total}");
}

#[tokio::test]
async fn only_what_the_rules_notify_for_is_counted() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.shared_room(&alice, &bob).await;

    let hello = server.say(&room, &alice, "hello", "m1").await;
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(counts(&total), (1, 0), "{total}");

    // `.m.rule.suppress_notices`: a bot's notice is not a notification.
    server
        .put_event(
            &room,
            &alice,
            "m.room.message",
            "n1",
            json!({ "msgtype": "m.notice", "body": "build passed" }),
        )
        .await;
    // `.m.rule.reaction`: neither is a reaction.
    server
        .put_event(
            &room,
            &alice,
            "m.reaction",
            "re1",
            json!({ "m.relates_to": { "rel_type": "m.annotation", "event_id": hello, "key": "👍" } }),
        )
        .await;
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(counts(&total), (1, 0), "{total}");

    // A mention is a notification and a highlight.
    server.say(&room, &alice, "bob, are you there", "m2").await;
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(counts(&total), (2, 1), "{total}");

    // Muting the room (a room rule with no actions) rescores what is
    // unread: the plain message stops counting, the mention is a content
    // rule and outranks the room rule, so it still does.
    let (status, body) = server
        .send(
            "PUT",
            &format!("/_matrix/client/v3/pushrules/global/room/{room}"),
            Some(&bob),
            Some(&json!({ "actions": [] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (total, _) = server.badge(&bob, &room, false).await;
    assert_eq!(
        counts(&total),
        (1, 1),
        "the mention still notifies: {total}"
    );
}

#[tokio::test]
async fn a_threaded_receipt_names_its_thread_to_everyone() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let room = server.shared_room(&alice, &bob).await;
    let thread_root = server.say(&room, &alice, "root", "r").await;
    let t1 = server
        .reply_in_thread(&room, &alice, &thread_root, "t1")
        .await;
    server.receipt(&room, &bob, &t1, Some(&thread_root)).await;

    let (status, body) = server
        .send(
            "POST",
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            Some(&alice),
            Some(&json!({
                "lists": { "all": { "ranges": [[0, 9]], "timeline_limit": 1 } },
                "extensions": { "receipts": { "enabled": true } },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let receipt = &body["extensions"]["receipts"]["rooms"][&room]["content"][&t1]["m.read"]["@bob:example.org"];
    assert_eq!(receipt["thread_id"], thread_root, "{body}");
    assert!(receipt["ts"].is_number(), "{body}");
}
