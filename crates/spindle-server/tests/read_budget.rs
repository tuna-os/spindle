//! A performance gate that counts work instead of timing it.
//!
//! Every performance defect this project has actually shipped was
//! algorithmic: a stored-body read and a JSON parse *per member* to answer a
//! question about one thing. #172, #173 and #175 fixed nine of them. None was
//! caught by the benchmark — some were invisible to it, and the rest sat
//! inside its noise.
//!
//! So this does not time anything. It counts the store reads a request
//! performs, and asserts how that count behaves as the room grows. The
//! difference matters:
//!
//! - A wall clock on a shared CI runner cannot tell a 20% regression from the
//!   runner's mood. Measured on this project's own idle dev box, six rounds of
//!   an *identical* binary move the median benchmark cell by 1.38x (#171). A
//!   "fail if slower" gate built on that would fire at random, and a gate that
//!   fires at random is one everybody learns to ignore — worse than none.
//! - A read count is deterministic. It is the same on a laptop, a loaded
//!   runner and a Raspberry Pi, so it can be asserted rather than eyeballed.
//!
//! **What this catches:** anything whose cost grows with the room when it
//! should not — the entire class of bug above.
//!
//! **What it does not catch:** constant-factor regressions. Making one read
//! twice as slow, adding an expensive serialization, or allocating wildly are
//! all invisible here. Those need the wall clock, which is what
//! `scripts/bench-rounds.sh` and the comparisons page are for. This gate and
//! that benchmark cover different failures and neither replaces the other.
//!
//! This extends a principle `spindle-core/tests/performance.rs` already
//! established one layer down, where the fork-window gate asserts *entries
//! visited* and treats its wall clock as a crash detector: "a wall-clock
//! budget on a 2ms operation is mostly noise; entries visited is
//! deterministic, and it is what distinguishes a search bounded by the fork
//! from one that walks the room." Every defect fixed in #172, #173 and #175
//! was that same distinction one layer up, in the server, where nothing was
//! asserting it.
//!
//! **Changing a budget** is allowed — "unless we have to" is a real category.
//! The budgets are named constants below, and raising one is a deliberate,
//! reviewable edit with a reason attached, not a number that quietly drifts.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Room sizes the gate compares. The ratio is what matters, not the sizes:
/// four times the members must not mean four times the work, for any
/// operation whose answer does not grow with the member list.
const SMALL: usize = 25;
const LARGE: usize = 100;

/// How much a flat operation may still grow between `SMALL` and `LARGE`.
///
/// Not zero, and deliberately so: a few reads scale with things that happen
/// to correlate with membership in this fixture (the room's own event count,
/// the sync stream position). Ten is comfortably below the ~75 that a single
/// read-per-member would add, so a reintroduced whole-room read cannot hide
/// under it, while ordinary drift does not trip it.
const FLAT_SLACK: u64 = 10;

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
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app =
            spindle_server::app(config, Arc::clone(&store)).expect("a signing key is established");
        Self {
            _dir: dir,
            app,
            store,
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    async fn request(&self, method: &str, path: &str, token: Option<&str>, body: &Value) -> Value {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder.body(Body::from(body.to_string())).unwrap();
        let (status, body) = self.call(request).await;
        assert!(status.is_success(), "{method} {path} -> {status}: {body}");
        body
    }

    async fn register(&self, username: &str) -> String {
        let body = json!({ "username": username, "password": "budget-password" });
        let request = Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, first) = self.call(request).await;
        if status.is_success() {
            return first["access_token"].as_str().unwrap().to_owned();
        }
        let session = first["session"].as_str().unwrap_or_default().to_owned();
        let body = json!({
            "username": username,
            "password": "budget-password",
            "auth": { "type": "m.login.dummy", "session": session },
        });
        self.request("POST", "/_matrix/client/v3/register", None, &body)
            .await["access_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A room with `members` joined users besides the creator, plus an
    /// observer whose requests are the ones measured.
    async fn room_with(&self, members: usize, tag: &str) -> (String, String) {
        let alice = self.register(&format!("alice{tag}")).await;
        let room = self
            .request(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(&alice),
                &json!({}),
            )
            .await["room_id"]
            .as_str()
            .unwrap()
            .to_owned();
        for index in 0..members {
            let name = format!("m{tag}x{index}");
            let token = self.register(&name).await;
            self.request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                Some(&alice),
                &json!({ "user_id": format!("@{name}:example.org") }),
            )
            .await;
            self.request(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(&token),
                &json!({}),
            )
            .await;
        }
        let observer = self.register(&format!("obs{tag}")).await;
        self.request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            &json!({ "user_id": format!("@obs{tag}:example.org") }),
        )
        .await;
        self.request(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/join"),
            Some(&observer),
            &json!({}),
        )
        .await;
        (room, observer)
    }

    fn reads(&self) -> u64 {
        self.store.reads()
    }
}

/// Reads one request performs, with the caches already warm.
///
/// Warm on purpose: a cold read is served once per state change and a warm
/// one is served for every request after it, so the warm number is what a
/// running server actually pays. It is also the stricter test of the caches
/// — one that stopped invalidating correctly, or stopped hitting, shows up
/// here as the count going linear.
async fn reads_for(harness: &Harness, method: &str, uri: &str, token: &str, body: &Value) -> u64 {
    harness.request(method, uri, Some(token), body).await;
    harness.request(method, uri, Some(token), body).await;
    let before = harness.reads();
    harness.request(method, uri, Some(token), body).await;
    harness.reads() - before
}

/// Assert an operation's read count does not grow with the member list.
async fn assert_flat_in_membership(name: &str, path: impl Fn(&str) -> String) {
    let mut counts = Vec::new();
    for (members, tag) in [(SMALL, "s"), (LARGE, "l")] {
        let harness = Harness::new();
        let (room, observer) = harness.room_with(members, tag).await;
        counts.push(reads_for(&harness, "GET", &path(&room), &observer, &json!({})).await);
    }
    let (small, large) = (counts[0], counts[1]);
    assert!(
        large <= small + FLAT_SLACK,
        "{name} performs {small} store reads at {SMALL} members and {large} at \
         {LARGE}. That is growth with the member list, which is the shape every \
         performance defect this project has shipped had (#172, #173, #175). If \
         the operation genuinely has to read every member, move it to the linear \
         list below and say why; if not, this is the bug."
    );
}

#[tokio::test]
#[ignore = "release-mode CI performance gate"]
async fn a_sliding_window_naming_its_state_does_not_read_the_room() {
    // #172. Element X asks for a handful of concrete keys; it used to be sent
    // the whole room state to filter down.
    let mut counts = Vec::new();
    for (members, tag) in [(SMALL, "ws"), (LARGE, "wl")] {
        let harness = Harness::new();
        let (_room, observer) = harness.room_with(members, tag).await;
        let body = json!({
            "lists": { "main": {
                "ranges": [[0, 10]],
                "required_state": [["m.room.name", ""]],
                "timeline_limit": 3,
            }}
        });
        counts.push(
            reads_for(
                &harness,
                "POST",
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
                &observer,
                &body,
            )
            .await,
        );
    }
    assert!(
        counts[1] <= counts[0] + FLAT_SLACK,
        "sliding sync reads {} rows at {SMALL} members and {} at {LARGE}: \
         required_state naming concrete keys, and joined_count, must not scale \
         with the roster",
        counts[0],
        counts[1]
    );
}

#[tokio::test]
#[ignore = "release-mode CI performance gate"]
async fn a_room_summary_counts_members_without_reading_them() {
    // #175. `summary` read and parsed every member's body to render a display
    // name and an avatar, then kept `.len()` of them.
    assert_flat_in_membership("the room summary", |room| {
        format!(
            "/_matrix/client/unstable/im.nheko.summary/rooms/{}/summary",
            urlencode(room)
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "release-mode CI performance gate"]
async fn an_incremental_sync_does_not_read_the_room_per_poll() {
    // #175's `membership_event`: `unread` calls it for every joined room on
    // every sync, and it walked every state key in the room to find one. This
    // is the most common request a Matrix server serves -- a client asking
    // "anything new?" and being told no -- so it is the one most worth
    // pinning.
    let mut counts = Vec::new();
    for (members, tag) in [(SMALL, "is"), (LARGE, "il")] {
        let harness = Harness::new();
        let (_room, observer) = harness.room_with(members, tag).await;
        let since = harness
            .request(
                "GET",
                "/_matrix/client/v3/sync",
                Some(&observer),
                &json!({}),
            )
            .await["next_batch"]
            .as_str()
            .unwrap()
            .to_owned();
        let uri = format!("/_matrix/client/v3/sync?since={since}&timeout=0");
        counts.push(reads_for(&harness, "GET", &uri, &observer, &json!({})).await);
    }
    assert!(
        counts[1] <= counts[0] + FLAT_SLACK,
        "an incremental sync with nothing new reads {} rows at {SMALL} members \
         and {} at {LARGE}. A poll that finds nothing must not cost a walk of \
         the room.",
        counts[0],
        counts[1]
    );
}

#[tokio::test]
#[ignore = "release-mode CI performance gate"]
async fn the_operations_that_do_read_every_member_are_named_and_bounded() {
    // The other half of an honest gate. These three legitimately return
    // something per member, so their reads *must* grow -- asserting they are
    // flat would be asserting they are broken. What is pinned is that they
    // grow no faster than the roster: roughly one read per member, not two,
    // and not one per member per member.
    //
    //   /state                  every state event, by definition
    //   /joined_members         every member's profile, by definition
    //   /sync with no filter    the whole state block, because the client
    //                           did not ask for less
    let harness = Harness::new();
    let (room, observer) = harness.room_with(LARGE, "lin").await;
    let members = LARGE as u64 + 2; // the joiners, alice, and the observer

    for (name, uri) in [
        (
            "/state",
            format!("/_matrix/client/v3/rooms/{}/state", urlencode(&room)),
        ),
        (
            "/joined_members",
            format!(
                "/_matrix/client/v3/rooms/{}/joined_members",
                urlencode(&room)
            ),
        ),
        ("/sync", "/_matrix/client/v3/sync".to_owned()),
    ] {
        let count = reads_for(&harness, "GET", &uri, &observer, &json!({})).await;
        assert!(
            count <= members * 2 + 50,
            "{name} performed {count} reads for {members} members. It is \
             allowed to read each member once; this is more than twice that, \
             which means it is doing something per member *and* something else \
             per member."
        );
    }
}

fn urlencode(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('!', "%21")
        .replace('#', "%23")
        .replace(':', "%3A")
}
