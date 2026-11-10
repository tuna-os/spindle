//! `[search] index` (#830): the word index narrows `/search` without
//! changing one byte of its answer.
//!
//! Two apps share one store. The indexed app writes; a second app with the
//! index off reads the same log by scanning it. Every query must answer
//! identically through both, event IDs and pagination included, and the
//! store's read counters show what the index saves.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::search_index;
use spindle_store::{Fault, FjallStore, ReadView};
use tempfile::TempDir;
use tower::ServiceExt;

/// Events in the busy room. The scan reads this many bodies; the index
/// reads the candidates.
const EVENTS: usize = 60;
/// A small vocabulary, as a busy room has: the index scans its words, so
/// its cost follows the vocabulary, which grows far slower than the room.
const WORDS: [&str; 6] = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
/// Events that hold the word `needle`.
const NEEDLES: u64 = 3;

fn config(index: bool) -> spindle_server::Config {
    spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n[search]\nindex = {index}\n"
    ))
    .unwrap()
}

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    on: axum::Router,
    token: String,
    room: String,
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn ask(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    call(app, builder.body(Body::from(body.to_string())).unwrap()).await
}

impl Harness {
    /// A room of `EVENTS` messages written through an app whose index is
    /// `index_while_writing`.
    async fn new(index_while_writing: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let on = spindle_server::app(config(index_while_writing), Arc::clone(&store)).unwrap();
        let body = json!({
            "username": "alice", "password": "search-password",
            "auth": { "type": "m.login.dummy" },
        });
        let (status, body) = ask(&on, "POST", "/_matrix/client/v3/register", None, &body).await;
        assert!(status.is_success(), "{body}");
        let token = body["access_token"].as_str().unwrap().to_owned();
        let (_, created) = ask(
            &on,
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&token),
            &json!({}),
        )
        .await;
        let room = created["room_id"].as_str().unwrap().to_owned();
        let harness = Self {
            _dir: dir,
            store,
            on,
            token,
            room,
        };
        for index in 0..EVENTS {
            let text = match index {
                10 => "Héllo wörld, ÑANDÚ crème!".to_owned(),
                11 => "foo-bar baz_qux".to_owned(),
                12 => format!("{} tail", "x".repeat(70)),
                _ if index % 20 == 3 => format!("The Needle is in the haystack number {index}"),
                _ => format!("filler chatter {}", WORDS[index % WORDS.len()]),
            };
            harness.say(&harness.on, &text).await;
        }
        harness
    }

    /// A second app over the same store: nothing cached, index as given.
    fn app(&self, index: bool) -> axum::Router {
        spindle_server::app(config(index), Arc::clone(&self.store)).unwrap()
    }

    async fn say(&self, app: &axum::Router, text: &str) -> String {
        let txn = self.store.written();
        let path = format!(
            "/_matrix/client/v3/rooms/{}/send/m.room.message/t{txn}",
            self.room.replace('!', "%21").replace(':', "%3A")
        );
        let (status, body) = ask(
            app,
            "PUT",
            &path,
            Some(&self.token),
            &json!({ "msgtype": "m.text", "body": text }),
        )
        .await;
        assert!(status.is_success(), "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn search(
        &self,
        app: &axum::Router,
        term: &str,
        limit: u64,
        next: Option<&str>,
    ) -> Value {
        let path = next.map_or_else(
            || "/_matrix/client/v3/search".to_owned(),
            |token| format!("/_matrix/client/v3/search?next_batch={token}"),
        );
        let body = json!({ "search_categories": { "room_events": {
            "search_term": term, "filter": { "limit": limit },
        } } });
        let (status, answer) = ask(app, "POST", &path, Some(&self.token), &body).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        answer
    }

    /// Every page of a search, as the client would walk them.
    async fn pages(&self, app: &axum::Router, term: &str, limit: u64) -> Vec<Value> {
        let mut pages = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let page = self.search(app, term, limit, next.as_deref()).await;
            let events = &page["search_categories"]["room_events"];
            next = events["next_batch"].as_str().map(str::to_owned);
            pages.push(page);
            if next.is_none() || pages.len() > 100 {
                return pages;
            }
        }
    }

    /// The reads and scanned rows one search costs, caches warm.
    async fn cost(&self, app: &axum::Router, term: &str) -> (u64, u64) {
        self.search(app, term, 10, None).await;
        let (reads, scanned) = (self.store.reads(), self.store.scanned());
        self.search(app, term, 10, None).await;
        (self.store.reads() - reads, self.store.scanned() - scanned)
    }

    /// Every index row, raw.
    fn index_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        use spindle_core::keys::{Keyspace, keyspace_prefix};
        [
            Keyspace::SearchPosting,
            Keyspace::SearchVocab,
            Keyspace::SearchMarker,
        ]
        .into_iter()
        .flat_map(|space| self.store.scan_prefix(&keyspace_prefix(space)).unwrap())
        .collect()
    }

    fn postings_for(&self, word: &str) -> usize {
        let prefix = spindle_core::keys::search_posting_prefix(&self.room, word);
        self.store.scan_prefix(&prefix).unwrap().len()
    }
}

const QUERIES: &[&str] = &[
    "needle",
    "NEEDLE haystack",
    "needle in the haystack",
    "absentword",
    "ñandú crème",
    "wörld, ñ",
    "foo-bar",
    "bar baz",
    "ar b",
    "oo-b",
    "qux",
    "xxxxxxxxxxx",
    "!!",
    "filler",
    "number 4",
    "ee",
];

#[tokio::test]
async fn every_query_answers_the_same_with_the_index_as_without() {
    let harness = Harness::new(true).await;
    let scan = harness.app(false);
    for term in QUERIES {
        for limit in [2, 10] {
            let indexed = harness.pages(&harness.on, term, limit).await;
            let scanned = harness.pages(&scan, term, limit).await;
            for (at, (left, right)) in indexed.iter().zip(&scanned).enumerate() {
                if left != right {
                    let (left, right) = (left.to_string(), right.to_string());
                    let first = left
                        .chars()
                        .zip(right.chars())
                        .take_while(|(a, b)| a == b)
                        .count();
                    panic!(
                        "{term:?} at limit {limit}, page {at}: differ at {first}: {} vs {}",
                        &left[first.saturating_sub(80)..(first + 80).min(left.len())],
                        &right[first.saturating_sub(80)..(first + 80).min(right.len())]
                    );
                }
            }
            assert_eq!(indexed.len(), scanned.len(), "{term:?} at limit {limit}");
        }
    }
    let found = harness.search(&harness.on, "needle", 10, None).await;
    assert_eq!(
        found["search_categories"]["room_events"]["count"],
        json!(NEEDLES)
    );
}

#[tokio::test]
async fn a_search_reads_the_candidates_not_the_room() {
    let harness = Harness::new(true).await;
    let scan = harness.app(false);
    let (scan_reads, scan_scanned) = harness.cost(&scan, "needle").await;
    let (idle_reads, idle_scanned) = harness.cost(&harness.on, "qqq absent zzz").await;
    let (index_reads, index_scanned) = harness.cost(&harness.on, "needle").await;
    let (_, phrase_scanned) = harness.cost(&harness.on, "needle in the haystack").await;
    assert!(
        scan_reads >= EVENTS as u64,
        "the scan reads every body: {scan_reads}"
    );
    assert!(
        index_reads * 2 < scan_reads,
        "the index reads a fraction of the scan: {index_reads} against {scan_reads}"
    );
    assert!(
        index_reads <= idle_reads + 2 * NEEDLES,
        "the index reads one body for each hit: {index_reads} against {idle_reads} for none"
    );
    assert!(
        index_scanned - idle_scanned < EVENTS as u64 / 2,
        "and scans the vocabulary on top of the stream order's rows: {index_scanned} (scan {scan_scanned}, idle {idle_scanned}, phrase {phrase_scanned})"
    );
    assert!(
        phrase_scanned - idle_scanned <= 4 * NEEDLES,
        "whole words read only their postings: {phrase_scanned}"
    );
}

#[tokio::test]
async fn an_event_that_is_redacted_leaves_the_index() {
    let harness = Harness::new(true).await;
    let hit = harness.search(&harness.on, "needle", 10, None).await;
    let victim = hit["search_categories"]["room_events"]["results"][0]["result"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = harness.postings_for("needle");
    let path = format!(
        "/_matrix/client/v3/rooms/{}/redact/{victim}/r1",
        harness.room.replace('!', "%21").replace(':', "%3A")
    );
    let (status, body) = ask(&harness.on, "PUT", &path, Some(&harness.token), &json!({})).await;
    assert!(status.is_success(), "{body}");
    assert_eq!(harness.postings_for("needle"), before - 1);
    let scan = harness.app(false);
    let indexed = harness.pages(&harness.on, "needle", 10).await;
    assert_eq!(indexed, harness.pages(&scan, "needle", 10).await);
    assert_eq!(
        indexed[0]["search_categories"]["room_events"]["count"],
        json!(NEEDLES - 1)
    );
}

#[tokio::test]
async fn a_purge_takes_the_purged_words_out_of_the_index() {
    let harness = Harness::new(true).await;
    let dir = TempDir::new().unwrap();
    drop(dir);
    spindle_server::accounts::Accounts::new(harness.store.as_ref(), "example.org")
        .set_admin("alice", true)
        .unwrap();
    assert!(harness.postings_for("needle") > 0);
    // A fresh app, so its own caches are cold, and the index on to maintain.
    let app = harness.app(true);
    let (status, body) = ask(
        &app,
        "POST",
        &format!("/_spindle/admin/v1/rooms/{}/purge_history", harness.room),
        Some(&harness.token),
        &json!({ "before_li": i64::MAX / 2 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(harness.postings_for("needle"), 0);
    assert_eq!(harness.postings_for("filler"), 0);
    let scan = harness.app(false);
    assert_eq!(
        harness.pages(&app, "needle", 10).await,
        harness.pages(&scan, "needle", 10).await
    );
}

#[tokio::test]
async fn the_index_rides_the_events_own_batch() {
    let harness = Harness::new(true).await;
    let rows = harness.index_rows();
    assert!(!rows.is_empty(), "the writes indexed the room");
    harness.store.inject_fault(Fault::Now);
    let path = format!(
        "/_matrix/client/v3/rooms/{}/send/m.room.message/refused",
        harness.room.replace('!', "%21").replace(':', "%3A")
    );
    let (status, _) = ask(
        &harness.on,
        "PUT",
        &path,
        Some(&harness.token),
        &json!({ "msgtype": "m.text", "body": "zzyzx lost word" }),
    )
    .await;
    assert!(status.is_server_error(), "{status}");
    assert_eq!(
        harness.postings_for("zzyzx"),
        0,
        "no word row without the event"
    );
    assert_eq!(harness.index_rows(), rows, "the index did not move");
    let scan = harness.app(false);
    let found = harness.search(&scan, "zzyzx", 10, None).await;
    assert_eq!(found["search_categories"]["room_events"]["count"], json!(0));
}

#[tokio::test]
async fn a_reindex_rebuilds_the_same_index() {
    let harness = Harness::new(true).await;
    let built = harness.index_rows();
    assert!(!built.is_empty());
    let report = search_index::reindex(harness.store.as_ref()).unwrap();
    assert_eq!(report.rooms, 1);
    assert_eq!(harness.index_rows(), built);
}

#[tokio::test]
async fn an_index_enabled_on_an_existing_store_is_correct_and_then_fast() {
    let harness = Harness::new(false).await;
    assert!(
        harness.index_rows().is_empty(),
        "nothing is indexed while off"
    );
    let on = harness.app(true);
    let scan = harness.app(false);
    // Not indexed yet: the scan answers.
    assert_eq!(
        harness.pages(&on, "needle", 10).await,
        harness.pages(&scan, "needle", 10).await
    );
    // A message sent while the index is on does not make the room look
    // indexed from before its first event.
    harness.say(&on, "a later needle").await;
    let scan = harness.app(false);
    assert_eq!(
        harness.pages(&on, "needle", 10).await,
        harness.pages(&scan, "needle", 10).await
    );
    let found = harness.search(&on, "needle", 10, None).await;
    assert_eq!(
        found["search_categories"]["room_events"]["count"],
        json!(NEEDLES + 1)
    );

    search_index::reindex(harness.store.as_ref()).unwrap();
    let on = harness.app(true);
    let scan = harness.app(false);
    for term in QUERIES {
        assert_eq!(
            harness.pages(&on, term, 3).await,
            harness.pages(&scan, term, 3).await,
            "{term:?}"
        );
    }
    let (scan_reads, _) = harness.cost(&scan, "needle").await;
    let (index_reads, _) = harness.cost(&on, "needle").await;
    assert!(
        index_reads < scan_reads,
        "{index_reads} against {scan_reads}"
    );
}

#[tokio::test]
async fn an_event_sent_while_the_index_was_off_is_still_found() {
    let harness = Harness::new(true).await;
    let off = harness.app(false);
    harness.say(&off, "quietly unindexed pelican").await;
    // The next indexed append must not carry the marker over the gap.
    let on = harness.app(true);
    harness.say(&on, "indexed again").await;
    let scan = harness.app(false);
    let found = harness.pages(&on, "pelican", 10).await;
    assert_eq!(found, harness.pages(&scan, "pelican", 10).await);
    assert_eq!(
        found[0]["search_categories"]["room_events"]["count"],
        json!(1)
    );
}

#[test]
fn a_retention_truncation_takes_the_removed_events_postings_with_it() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), "example.org");
    rooms.set_search_index(true);
    let alice = "@alice:example.org";
    let room = rooms
        .create(
            alice,
            key.pair(),
            Some("indexed"),
            None,
            None,
            &[],
            &[],
            None,
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap();
    let mut ids = Vec::new();
    for n in 0..8 {
        let id = rooms
            .send(
                &room,
                alice,
                key.pair(),
                "m.room.message",
                &json!({ "msgtype": "m.text", "body": format!("truncword n{n}") }),
            )
            .unwrap();
        ids.push(id);
    }
    let log = spindle_store::RoomStore::new(store.as_ref(), room.as_str())
        .load_exhaustive()
        .unwrap()
        .unwrap()
        .log;
    let lis: Vec<i64> = ids
        .iter()
        .map(|id| {
            log.get(&spindle_core::EventId::new(id.as_str()))
                .unwrap()
                .li
                .get()
        })
        .collect();
    let postings = |word: &str| {
        store
            .scan_prefix(&spindle_core::keys::search_posting_prefix(&room, word))
            .unwrap()
            .len()
    };
    assert_eq!(postings("truncword"), 8);
    let floor = lis[5];
    let report = rooms.truncate_room_log(&room, floor).unwrap();
    assert!(report.entries > 0 && report.floor <= floor, "{report:?}");
    // The truncation keeps the entry of a parent that a kept entry names, so
    // count what the log still holds instead of what the floor implies.
    let after = spindle_store::RoomStore::new(store.as_ref(), room.as_str())
        .load_exhaustive()
        .unwrap()
        .unwrap()
        .log;
    let kept = lis
        .iter()
        .filter(|li| after.entry_at(**li).is_some())
        .count();
    assert!(kept < 8, "the truncation removed messages");
    assert_eq!(
        postings("truncword"),
        kept,
        "a removed event leaves no posting behind"
    );
}
