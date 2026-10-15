//! `GET /notifications`: what the caller's push rules say they should have
//! been told about, newest first, with whether they have read it.
//!
//! The evaluator's own tests are unit tests in `push_rules`; these are
//! about the endpoint: which rooms it walks, that a reader's own events are
//! never theirs to be notified about, that the receipt marks what is read,
//! that `only=highlight` keeps the mentions, that a rule a client disabled
//! stays disabled here, and that the pages walk every hit once.

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
    txn: std::sync::atomic::AtomicU64,
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
        Self {
            _dir: dir,
            app,
            txn: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
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

    async fn send(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
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

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say_as(&self, room: &str, token: &str, content: Value) -> String {
        let txn = self.txn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (status, body) = self
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t{txn}"),
                token,
                &content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        self.say_as(room, token, json!({ "msgtype": "m.text", "body": text }))
            .await
    }

    async fn admit(&self, room: &str, inviter: &str, user: &str, user_id: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                inviter,
                &json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                user,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn read_up_to(&self, room: &str, token: &str, event: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn notifications(&self, token: &str, query: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("GET")
                .uri(format!("/_matrix/client/v3/notifications{query}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// A room of three, so the catch-all `.m.rule.message` is what notifies
/// rather than the one-to-one rule.
async fn trio(h: &Harness) -> (String, String, String, String) {
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    let carol = h.register("carol").await;
    let room = h.create_room(&alice).await;
    h.admit(&room, &alice, &bob, "@bob:example.org").await;
    h.admit(&room, &alice, &carol, "@carol:example.org").await;
    (alice, bob, carol, room)
}

/// Each notification's body, or its event type where there is no body
/// (an invite is an `m.room.member` event).
fn bodies(page: &Value) -> Vec<String> {
    page["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            n["event"]["content"]["body"]
                .as_str()
                .or_else(|| n["event"]["type"].as_str())
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn others_messages_notify_newest_first_and_a_receipt_marks_them_read() {
    let h = Harness::new();
    let (alice, bob, _carol, room) = trio(&h).await;
    let first = h.say(&room, &bob, "first from bob").await;
    h.say(&room, &alice, "alice's own, never a notification for her")
        .await;
    h.say(&room, &bob, "second from bob").await;

    let (status, page) = h.notifications(&alice, "").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["second from bob", "first from bob"]);
    assert!(page.get("next_token").is_none(), "{page}");
    let newest = &page["notifications"][0];
    assert_eq!(newest["room_id"], json!(room));
    assert_eq!(newest["event"]["room_id"], json!(room));
    assert!(newest["event"]["event_id"].is_string(), "{newest}");
    assert!(newest["ts"].is_u64(), "{newest}");
    assert!(
        newest["actions"]
            .as_array()
            .unwrap()
            .contains(&json!("notify")),
        "{newest}"
    );
    assert_eq!(newest["read"], json!(false));
    assert_eq!(page["notifications"][1]["read"], json!(false));

    // Reading up to the first leaves the second unread.
    h.read_up_to(&room, &alice, &first).await;
    let (_, page) = h.notifications(&alice, "").await;
    assert_eq!(page["notifications"][0]["read"], json!(false), "{page}");
    assert_eq!(page["notifications"][1]["read"], json!(true), "{page}");

    // Bob's list is alice's message, then his own invitation (the
    // `.m.rule.invite_for_me` default), and nothing he sent himself.
    let (_, page) = h.notifications(&bob, "").await;
    assert_eq!(
        bodies(&page),
        vec!["alice's own, never a notification for her", "m.room.member"]
    );
    let invite = &page["notifications"][1];
    assert_eq!(invite["event"]["state_key"], json!("@bob:example.org"));
    assert!(
        invite["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["set_tweak"] == "sound"),
        "{invite}"
    );
}

#[tokio::test]
async fn only_highlight_keeps_the_mentions() {
    let h = Harness::new();
    let (alice, bob, _carol, room) = trio(&h).await;
    h.say(&room, &bob, "hello there").await;
    h.say(&room, &bob, "hello Alice, are you there?").await;
    h.say_as(
        &room,
        &bob,
        json!({
            "msgtype": "m.text",
            "body": "a mention without the name",
            "m.mentions": { "user_ids": ["@alice:example.org"] },
        }),
    )
    .await;

    let (status, page) = h.notifications(&alice, "?only=highlight").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        bodies(&page),
        vec!["a mention without the name", "hello Alice, are you there?"]
    );
    for notification in page["notifications"].as_array().unwrap() {
        assert!(
            notification["actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action["set_tweak"] == "highlight"),
            "{notification}"
        );
    }
    let (_, page) = h.notifications(&alice, "").await;
    assert_eq!(page["notifications"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_notice_and_a_rule_the_client_disabled_do_not_notify() {
    let h = Harness::new();
    let (alice, bob, _carol, room) = trio(&h).await;
    h.say(&room, &bob, "a message").await;
    h.say_as(
        &room,
        &bob,
        json!({ "msgtype": "m.notice", "body": "a notice" }),
    )
    .await;
    let (_, page) = h.notifications(&alice, "").await;
    assert_eq!(bodies(&page), vec!["a message"]);

    let (status, body) = h
        .send(
            "PUT",
            "/_matrix/client/v3/pushrules/global/underride/.m.rule.message/enabled",
            &alice,
            &json!({ "enabled": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    h.say(&room, &bob, "another message").await;
    let (_, page) = h.notifications(&alice, "").await;
    assert_eq!(bodies(&page), Vec::<String>::new(), "{page}");
    // Bob's ruleset is his own: he still hears alice.
    h.say(&room, &alice, "from alice").await;
    let (_, page) = h.notifications(&bob, "").await;
    assert_eq!(bodies(&page), vec!["from alice", "m.room.member"]);
}

/// Three rooms bob talks in turn in, as alice's notifications: the event
/// IDs in the order they were sent.
async fn three_rooms(h: &Harness) -> (String, String, Vec<String>, Vec<String>) {
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    let mut rooms = Vec::new();
    for _ in 0..3 {
        let room = h.create_room(&alice).await;
        h.admit(&room, &alice, &bob, "@bob:example.org").await;
        rooms.push(room);
    }
    // Back to back, so neighbours share a millisecond as often as not:
    // the tie that made a timestamp order disagree with the send order.
    let mut said = Vec::new();
    for (n, room) in [0, 1, 2, 2, 0, 1, 1, 2, 0].into_iter().enumerate() {
        said.push(h.say(&rooms[room], &bob, &format!("message {n}")).await);
    }
    (alice, bob, rooms, said)
}

/// Walk `/notifications` from `from` at `limit`, asserting nothing comes
/// back twice; returns the event IDs and the number of pages.
async fn walk(
    h: &Harness,
    token: &str,
    limit: usize,
    from: Option<String>,
) -> (Vec<String>, usize) {
    let mut seen: Vec<String> = Vec::new();
    let mut from = from;
    let mut pages = 0;
    loop {
        let query = match &from {
            Some(token) => format!("?limit={limit}&from={token}"),
            None => format!("?limit={limit}"),
        };
        let (status, page) = h.notifications(token, &query).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        pages += 1;
        assert!(pages <= 20, "paging at {limit} does not end");
        for notification in page["notifications"].as_array().unwrap() {
            let id = notification["event"]["event_id"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(!seen.contains(&id), "{id} came back twice at limit {limit}");
            seen.push(id);
        }
        match page["next_token"].as_str() {
            Some(token) => from = Some(token.to_owned()),
            None => return (seen, pages),
        }
    }
}

/// #635: newest first is the order events reached the server, a total
/// order, so every page size serves the same sequence with no skip and no
/// repeat at any page boundary.
#[tokio::test]
async fn pages_walk_every_notification_once_across_rooms() {
    let h = Harness::new();
    let (alice, _, _, mut said) = three_rooms(&h).await;
    said.reverse();
    for limit in 1..=said.len() + 1 {
        let (seen, pages) = walk(&h, &alice, limit, None).await;
        assert_eq!(
            seen, said,
            "limit {limit}: every notification, newest first, once"
        );
        assert!(
            pages <= said.len().div_ceil(limit) + 1,
            "limit {limit}: {pages} pages"
        );
    }
}

/// A walk is cut to where its first page stood: a message sent mid-walk is
/// not served out of order on a later page, and leads the next walk.
#[tokio::test]
async fn a_walk_is_a_snapshot() {
    let h = Harness::new();
    let (alice, bob, rooms, mut said) = three_rooms(&h).await;
    said.reverse();
    let (_, first) = h.notifications(&alice, "?limit=4").await;
    let token = first["next_token"].as_str().unwrap().to_owned();
    let late = h.say(&rooms[1], &bob, "late").await;
    let (rest, _) = walk(&h, &alice, 4, Some(token)).await;
    let ids = |page: &Value| -> Vec<String> {
        page["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["event"]["event_id"].as_str().unwrap().to_owned())
            .collect()
    };
    let mut seen = ids(&first);
    seen.extend(rest);
    assert_eq!(seen, said);
    let (_, fresh) = h.notifications(&alice, "?limit=1").await;
    assert_eq!(ids(&fresh), vec![late]);
}

/// A `next_token` from before the snapshot was added (the bare per-room
/// cursor) still parses, and resumes each room it names exactly.
#[tokio::test]
async fn a_token_without_a_snapshot_still_resumes() {
    let h = Harness::new();
    let (alice, _, _, mut said) = three_rooms(&h).await;
    said.reverse();
    let (_, first) = h.notifications(&alice, "?limit=3").await;
    let token = first["next_token"].as_str().unwrap();
    let (snapshot, old) = token.split_once(';').unwrap();
    assert!(snapshot.starts_with('s'), "{token}");
    let (rest, _) = walk(&h, &alice, 3, Some(old.to_owned())).await;
    let mut seen: Vec<String> = first["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["event"]["event_id"].as_str().unwrap().to_owned())
        .collect();
    seen.extend(rest);
    assert_eq!(seen, said);
}

#[tokio::test]
async fn an_unknown_only_is_refused() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let (status, body) = h.notifications(&alice, "?only=everything").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h.notifications(&alice, "?from=garbage").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
