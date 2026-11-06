//! `POST /search`: room-event search over the rooms the caller may read.
//!
//! No index behind it (#7's "search basics"): a walk of each room the
//! caller may read, newest first, with the same read scope as `/messages`,
//! paged per room so that a page boundary in the middle of one room's hits
//! resumes exactly there. The tests below are about *which* events come
//! back and in what order, because that is where a search leaks: a hit
//! from a room the caller is not in, or from after they left, is the
//! room's contents handed to someone who may not read them.

#[path = "support/federation_auth.rs"]
mod federation_auth;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, hash_and_sign_event};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A remote server whose events reach the harness over `PUT /send`, so a
/// hit can carry whatever `origin_server_ts` its sender's clock said.
struct Peer {
    name: String,
    pair: Ed25519KeyPair,
}

impl Peer {
    async fn start() -> Peer {
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 60_000,
            "verify_keys": { "ed25519:0": { "key": unpadded(&pair.public_key()) } },
        });
        sign_value(&name, &pair, &mut key_document);
        let router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { axum::Json(body) }
                }),
            )
            // The invite handshake's other half: echoing the event back is
            // a valid answer, since signatures sit outside the hash the
            // inviter checks.
            .route(
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    |axum::extract::Json(body): axum::extract::Json<Value>| async move {
                        axum::Json(json!({ "event": body["event"] }))
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer { name, pair }
    }

    fn user(&self) -> String {
        format!("@bob:{}", self.name)
    }

    /// A V11 event of this peer's making, its auth events chosen from the
    /// harness's own view of the room: hashed and signed like the real
    /// thing.
    fn event(&self, store: &Arc<FjallStore>, event: Value) -> Value {
        let event = federation_auth::with_auth_events(store, event);
        let ruma::CanonicalJsonValue::Object(mut canonical) =
            ruma::CanonicalJsonValue::try_from(event).unwrap()
        else {
            unreachable!()
        };
        let rules = RoomVersionId::V11.rules().unwrap();
        hash_and_sign_event(&self.name, &self.pair, &mut canonical, &rules.redaction).unwrap();
        serde_json::to_value(&canonical).unwrap()
    }

    fn transaction_header(&self, txn_id: &str, body: &Value) -> String {
        let mut object = json!({
            "method": "PUT",
            "uri": format!("/_matrix/federation/v1/send/{txn_id}"),
            "origin": self.name,
            "destination": "example.org",
            "content": body,
        });
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{signature}\"",
            self.name
        )
    }
}

fn sign_value(entity: &str, pair: &Ed25519KeyPair, value: &mut Value) {
    let ruma::CanonicalJsonValue::Object(mut object) =
        ruma::CanonicalJsonValue::try_from(value.clone()).unwrap()
    else {
        unreachable!()
    };
    ruma::signatures::sign_json(entity, pair, &mut object).unwrap();
    *value = serde_json::to_value(&object).unwrap();
}

fn unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for position in 0..=chunk.len() {
            out.push(ALPHABET[((triple >> (18 - 6 * position)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap()
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
    store: Arc<FjallStore>,
    txn: std::sync::atomic::AtomicU64,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store.clone()).expect("a signing key is established");
        Self {
            _dir: dir,
            app,
            store,
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

    /// The newest event in `room`, for a remote event's `prev_events`.
    async fn head_event(&self, room: &str, token: &str) -> String {
        let (_, body) = self
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=1"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        body["chunk"][0]["event_id"].as_str().unwrap().to_owned()
    }

    /// Deliver `pdu` from `peer` in a transaction of its own, and expect it
    /// accepted. Returns its event ID.
    async fn deliver(&self, peer: &Peer, txn_id: &str, pdu: Value) -> String {
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": [pdu] });
        let (status, answer) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/_matrix/federation/v1/send/{txn_id}"))
                    .header("authorization", peer.transaction_header(txn_id, &body))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let (event_id, outcome) = answer["pdus"].as_object().unwrap().iter().next().unwrap();
        assert_eq!(outcome, &json!({}), "{answer}");
        event_id.clone()
    }

    /// A room of `alice`'s that the peer's user has joined over federation.
    async fn room_with_peer(&self, alice: &str, peer: &Peer) -> String {
        let room = self.create_room(alice, json!({})).await;
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                alice,
                &json!({ "user_id": peer.user() }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let head = self.head_event(&room, alice).await;
        let join = peer.event(
            &self.store,
            json!({
                "type": "m.room.member",
                "state_key": peer.user(),
                "sender": peer.user(),
                "room_id": room,
                "content": { "membership": "join" },
                "origin_server_ts": now_millis(),
                "depth": 10,
                "prev_events": [head],
                "auth_events": [],
            }),
        );
        self.deliver(peer, "join", join).await;
        room
    }

    /// A message from the peer's user, stamped `origin_server_ts` by its
    /// sender's clock. Returns its event ID.
    async fn say_remotely(
        &self,
        peer: &Peer,
        room: &str,
        alice: &str,
        text: &str,
        origin_server_ts: u64,
    ) -> String {
        let head = self.head_event(room, alice).await;
        let message = peer.event(
            &self.store,
            json!({
                "type": "m.room.message",
                "sender": peer.user(),
                "room_id": room,
                "content": { "msgtype": "m.text", "body": text },
                "origin_server_ts": origin_server_ts,
                "depth": 11,
                "prev_events": [head],
                "auth_events": [],
            }),
        );
        let txn = self.txn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.deliver(peer, &format!("m{txn}"), message).await
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

fn event_ids(page: &Value) -> Vec<String> {
    page["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| result["result"]["event_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Search for "needle" at `limit` from `next_batch` until the pages run
/// out, asserting nothing comes back twice; returns the event IDs and the
/// number of pages.
async fn walk(
    h: &Harness,
    token: &str,
    limit: usize,
    next_batch: Option<String>,
) -> (Vec<String>, usize) {
    let mut seen: Vec<String> = Vec::new();
    let mut next = next_batch;
    let mut pages = 0;
    loop {
        let (status, page) = h
            .search(
                token,
                json!({ "search_term": "needle", "filter": { "limit": limit } }),
                next.as_deref(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        pages += 1;
        assert!(pages <= 20, "paging at {limit} does not end");
        for id in event_ids(&page) {
            assert!(!seen.contains(&id), "{id} came back twice at limit {limit}");
            seen.push(id);
        }
        match page["next_batch"].as_str() {
            Some(token) => next = Some(token.to_owned()),
            None => return (seen, pages),
        }
    }
}

/// #637: newest first is the order hits reached the server, not their
/// `origin_server_ts`. A remote server whose clock runs an hour behind
/// stamps a hit older than the ones on either side of it; a timestamp
/// order then takes the hit below it in the same room first, moves that
/// room's cursor past it, and never serves it. Local sends, back to back,
/// also tie on the millisecond across rooms. Every page size serves every
/// hit once, in arrival order.
#[tokio::test]
async fn every_page_size_serves_every_hit_once_when_a_clock_runs_behind() {
    let peer = Peer::start().await;
    let h = Harness::new();
    let alice = h.register("alice").await;
    let local = h.create_room(&alice, json!({})).await;
    let shared = h.room_with_peer(&alice, &peer).await;
    let behind = now_millis() - 3_600_000;
    let mut said = vec![
        h.say(&local, &alice, "needle 0").await,
        h.say(&shared, &alice, "needle 1").await,
        h.say_remotely(&peer, &shared, &alice, "needle 2, an hour behind", behind)
            .await,
        h.say(&local, &alice, "needle 3").await,
        h.say(&shared, &alice, "needle 4").await,
    ];
    said.reverse();
    for limit in 1..=said.len() + 1 {
        let (seen, pages) = walk(&h, &alice, limit, None).await;
        assert_eq!(seen, said, "limit {limit}: every hit, newest first, once");
        assert!(
            pages <= said.len().div_ceil(limit) + 1,
            "limit {limit}: {pages} pages"
        );
    }
}

/// Two rooms with hits sent back to back, newest first.
async fn two_rooms(h: &Harness) -> (String, Vec<String>, Vec<String>) {
    let alice = h.register("alice").await;
    let rooms = vec![
        h.create_room(&alice, json!({})).await,
        h.create_room(&alice, json!({})).await,
    ];
    let mut said = Vec::new();
    for (n, room) in [0, 1, 1, 0, 1, 0].into_iter().enumerate() {
        said.push(h.say(&rooms[room], &alice, &format!("needle {n}")).await);
    }
    said.reverse();
    (alice, rooms, said)
}

/// A walk is cut to where its first page stood: a hit sent mid-walk is not
/// served out of order on a later page, and leads the next walk.
#[tokio::test]
async fn a_walk_is_a_snapshot() {
    let h = Harness::new();
    let (alice, rooms, said) = two_rooms(&h).await;
    let (_, first) = walk_one(&h, &alice, 2).await;
    let token = first["next_batch"].as_str().unwrap().to_owned();
    let late = h.say(&rooms[0], &alice, "needle, late").await;
    let (rest, _) = walk(&h, &alice, 2, Some(token)).await;
    let mut seen = event_ids(&first);
    seen.extend(rest);
    assert_eq!(seen, said);
    let (_, fresh) = walk_one(&h, &alice, 1).await;
    assert_eq!(event_ids(&fresh), vec![late]);
}

/// A `next_batch` from before the snapshot was added (the bare per-room
/// cursor) still parses, and resumes each room it names exactly.
#[tokio::test]
async fn a_token_without_a_snapshot_still_resumes() {
    let h = Harness::new();
    let (alice, _, said) = two_rooms(&h).await;
    let (_, first) = walk_one(&h, &alice, 2).await;
    let token = first["next_batch"].as_str().unwrap();
    let (snapshot, old) = token.split_once(';').unwrap();
    assert!(snapshot.starts_with('s'), "{token}");
    let (rest, _) = walk(&h, &alice, 2, Some(old.to_owned())).await;
    let mut seen = event_ids(&first);
    seen.extend(rest);
    assert_eq!(seen, said);
}

/// The first page of a "needle" search at `limit`.
async fn walk_one(h: &Harness, token: &str, limit: usize) -> (StatusCode, Value) {
    h.search(
        token,
        json!({ "search_term": "needle", "filter": { "limit": limit } }),
        None,
    )
    .await
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
