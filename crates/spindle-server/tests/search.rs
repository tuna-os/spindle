//! `POST /search`: room-event search over the rooms the caller may read.
//!
//! No index behind it (#7's "search basics"): a walk of each room the
//! caller may read, newest first, with the same read scope as `/messages`,
//! paged per room so that a page boundary in the middle of one room's hits
//! resumes exactly there. The tests below are about *which* events come
//! back and in what order, because that is where a search leaks: a hit
//! from a room the caller is not in, or from after they left, is the
//! room's contents handed to someone who may not read them.

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

    async fn post(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, uri: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// A display name, so the member events carry one for `profile_info`.
    async fn name(&self, token: &str, user_id: &str, name: &str) {
        let (status, body) = self
            .put(
                &format!("/_matrix/client/v3/profile/{user_id}/displayname"),
                token,
                &json!({ "displayname": name }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
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

    async fn create_room(&self, token: &str, extra: Value) -> String {
        let (status, body) = self
            .post("/_matrix/client/v3/createRoom", token, &extra)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        let txn = self.txn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/send/m.room.message/t{txn}"
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
        body["event_id"].as_str().unwrap().to_owned()
    }

    /// Invite and join, so `user` is a member of `room`.
    async fn admit(&self, room: &str, inviter: &str, user: &str, user_id: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                inviter,
                &json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                user,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn leave(&self, room: &str, token: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/leave"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// One search page: the `room_events` category, or the whole error body.
    async fn search(
        &self,
        token: &str,
        criteria: Value,
        next_batch: Option<&str>,
    ) -> (StatusCode, Value) {
        let uri = match next_batch {
            Some(token) => format!("/_matrix/client/v3/search?next_batch={token}"),
            None => "/_matrix/client/v3/search".to_owned(),
        };
        let (status, body) = self
            .post(
                &uri,
                token,
                &json!({ "search_categories": { "room_events": criteria } }),
            )
            .await;
        if status == StatusCode::OK {
            (status, body["search_categories"]["room_events"].clone())
        } else {
            (status, body)
        }
    }
}

fn bodies(page: &Value) -> Vec<String> {
    page["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["result"]["content"]["body"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn finds_the_term_in_every_joined_room_newest_first_and_nowhere_else() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    let shared = h.create_room(&alice, json!({})).await;
    h.admit(&shared, &alice, &bob, "@bob:example.org").await;
    let alices = h.create_room(&alice, json!({})).await;
    let bobs = h.create_room(&bob, json!({})).await;

    h.say(&shared, &alice, "first needle in the shared room")
        .await;
    h.say(&alices, &alice, "nothing to see here").await;
    h.say(
        &alices,
        &alice,
        "a NEEDLE, upper-cased, in alice's own room",
    )
    .await;
    h.say(&bobs, &bob, "a needle in bob's room, which alice is not in")
        .await;
    h.say(
        &shared,
        &bob,
        "the newest needle, from bob, in the shared room",
    )
    .await;

    let (status, page) = h
        .search(&alice, json!({ "search_term": "needle" }), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        bodies(&page),
        vec![
            "the newest needle, from bob, in the shared room",
            "a NEEDLE, upper-cased, in alice's own room",
            "first needle in the shared room",
        ],
        "newest first, case-insensitively, and only from alice's rooms"
    );
    assert_eq!(page["count"], 3);
    assert_eq!(page["highlights"], json!(["needle"]));
    assert!(page.get("next_batch").is_none(), "{page}");
    let first = &page["results"][0];
    assert_eq!(first["result"]["room_id"], json!(shared));
    assert!(first["result"]["event_id"].is_string(), "{first}");
    assert_eq!(first["rank"], json!(1.0));

    // Bob sees his own room's hit and the shared room's, not alice's.
    let (status, page) = h
        .search(&bob, json!({ "search_term": "needle" }), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        bodies(&page),
        vec![
            "the newest needle, from bob, in the shared room",
            "a needle in bob's room, which alice is not in",
            "first needle in the shared room",
        ]
    );
}

#[tokio::test]
async fn pages_walk_every_hit_once_across_rooms() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let one = h.create_room(&alice, json!({})).await;
    let two = h.create_room(&alice, json!({})).await;
    let mut said = Vec::new();
    for n in 0..7 {
        let room = if n % 3 == 0 { &two } else { &one };
        said.push(h.say(room, &alice, &format!("needle {n}")).await);
        h.say(room, &alice, &format!("hay {n}")).await;
    }

    let mut seen: Vec<String> = Vec::new();
    let mut next: Option<String> = None;
    let mut pages = 0;
    loop {
        let (status, page) = h
            .search(
                &alice,
                json!({ "search_term": "needle", "filter": { "limit": 3 } }),
                next.as_deref(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        pages += 1;
        assert!(pages <= 3, "more pages than hits allow");
        let ids: Vec<String> = page["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|result| result["result"]["event_id"].as_str().unwrap().to_owned())
            .collect();
        assert!(ids.len() <= 3, "{page}");
        for id in &ids {
            assert!(!seen.contains(id), "{id} came back twice");
        }
        seen.extend(ids);
        match page["next_batch"].as_str() {
            Some(token) => next = Some(token.to_owned()),
            None => break,
        }
    }
    assert_eq!(pages, 3);
    let mut expected = said.clone();
    expected.reverse();
    assert_eq!(seen, expected, "every hit, newest first, exactly once");

    // One room alone, with more hits than a page: the page fills from
    // that room and the room itself is what says there is more.
    let (status, page) = h
        .search(
            &alice,
            json!({ "search_term": "needle", "filter": { "rooms": [one], "limit": 3 } }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["needle 5", "needle 4", "needle 2"]);
    let token = page["next_batch"].as_str().expect("a fourth hit is left");
    let (status, page) = h
        .search(
            &alice,
            json!({ "search_term": "needle", "filter": { "rooms": [one], "limit": 3 } }),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["needle 1"]);
    assert!(page.get("next_batch").is_none(), "{page}");
}

#[tokio::test]
async fn a_former_member_searches_only_what_they_may_read_and_a_stranger_nothing() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    let carol = h.register("carol").await;
    let room = h.create_room(&alice, json!({})).await;
    h.admit(&room, &alice, &bob, "@bob:example.org").await;
    h.say(&room, &alice, "needle while bob was here").await;
    h.leave(&room, &bob).await;
    h.say(&room, &alice, "needle after bob left").await;

    // Bob is in no room now, so the search has to be pointed at this one.
    let criteria = json!({ "search_term": "needle", "filter": { "rooms": [room] } });
    let (status, page) = h.search(&bob, criteria.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["needle while bob was here"]);

    // Naming a room the caller may not read is not a refusal: it is a
    // room that contributes nothing, which tells carol nothing about it.
    let (status, page) = h.search(&carol, criteria, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), Vec::<String>::new());
    assert_eq!(page["count"], 0);

    // And alice, still joined, reads all of it.
    let (status, page) = h
        .search(&alice, json!({ "search_term": "needle" }), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        bodies(&page),
        vec!["needle after bob left", "needle while bob was here"]
    );
}

#[tokio::test]
async fn the_filter_and_the_context_are_honoured() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let bob = h.register("bob").await;
    let room = h.create_room(&alice, json!({})).await;
    h.admit(&room, &alice, &bob, "@bob:example.org").await;
    // Set once joined, which is when a profile reaches the member events.
    h.name(&alice, "@alice:example.org", "Alice").await;
    h.name(&bob, "@bob:example.org", "Bob").await;
    let other = h.create_room(&alice, json!({})).await;
    h.say(&room, &alice, "before one").await;
    h.say(&room, &alice, "before two").await;
    let target = h.say(&room, &bob, "needle from bob").await;
    h.say(&room, &alice, "after one").await;
    h.say(&room, &alice, "after two").await;
    h.say(&room, &alice, "needle from alice").await;
    h.say(&other, &alice, "needle in the other room").await;

    // `senders` and `rooms` narrow the hits; the context brings the
    // neighbours, one on each side as asked, with the senders' profiles.
    let (status, page) = h
        .search(
            &alice,
            json!({
                "search_term": "needle",
                "filter": { "rooms": [room], "senders": ["@bob:example.org"] },
                "event_context": { "before_limit": 1, "after_limit": 2, "include_profile": true },
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["needle from bob"]);
    let result = &page["results"][0];
    assert_eq!(result["result"]["event_id"], json!(target));
    let context = &result["context"];
    let before: Vec<&str> = context["events_before"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["content"]["body"].as_str().unwrap())
        .collect();
    let after: Vec<&str> = context["events_after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["content"]["body"].as_str().unwrap())
        .collect();
    assert_eq!(before, vec!["before two"]);
    assert_eq!(after, vec!["after one", "after two"]);
    assert!(
        context["start"].is_string() && context["end"].is_string(),
        "{context}"
    );
    assert_eq!(
        context["profile_info"]["@bob:example.org"]["displayname"],
        json!("Bob")
    );
    assert_eq!(
        context["profile_info"]["@alice:example.org"]["displayname"],
        json!("Alice")
    );

    // `not_rooms` and `types` in the other direction.
    let (status, page) = h
        .search(
            &alice,
            json!({
                "search_term": "needle",
                "filter": { "not_rooms": [other], "not_senders": ["@bob:example.org"], "types": ["m.room.message"] },
                "include_state": true,
            }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(bodies(&page), vec!["needle from alice"]);
    assert!(
        page["state"][&room]
            .as_array()
            .is_some_and(|state| { state.iter().any(|event| event["type"] == "m.room.create") }),
        "{page}"
    );
    assert!(page["state"].get(&other).is_none(), "{page}");
}

#[tokio::test]
async fn an_empty_term_or_an_unknown_order_is_refused_and_no_category_is_empty() {
    let h = Harness::new();
    let alice = h.register("alice").await;
    let (status, body) = h
        .search(&alice, json!({ "search_term": "   " }), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h
        .search(
            &alice,
            json!({ "search_term": "needle", "order_by": "loudest" }),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h
        .search(&alice, json!({ "search_term": "needle" }), Some("garbage"))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = h
        .post(
            "/_matrix/client/v3/search",
            &alice,
            &json!({ "search_categories": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "search_categories": {} }));
}
