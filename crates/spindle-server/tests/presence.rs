//! Presence: a user says whether they are around, and someone who shares a
//! room with them can ask -- or hears it in `/sync` (#745).
//!
//! The gate is the part worth testing hardest. Presence is a continuous
//! signal about when a person is at their computer, so "any account on this
//! server can watch any other" is a real privacy answer, not a hypothetical
//! one — and it is the answer a server gets by *not* deciding.

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
        Self::with("")
    }

    fn with(extra: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{extra}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    /// `/sync` with `query` (already a query string, or empty).
    async fn sync(&self, token: &str, query: &str) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(format!("/_matrix/client/v3/sync{query}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
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

    async fn set(&self, who: &str, token: &str, payload: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/presence/@{who}:example.org/status"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, who: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/presence/@{who}:example.org/status"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
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

    async fn invite_and_join(&self, room: &str, host: &str, guest_name: &str, guest: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/invite"))
                    .header("authorization", format!("Bearer {host}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "user_id": format!("@{guest_name}:example.org") }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/join"))
                    .header("authorization", format!("Bearer {guest}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// The round trip, and the derived fields the spec asks for.
#[tokio::test]
async fn a_user_sets_their_own_presence_and_reads_it_back() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "writing tests" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "online");
    assert_eq!(body["status_msg"], "writing tests");
    assert_eq!(
        body["currently_active"], true,
        "someone who just said they are online is currently active: {body}"
    );
    assert!(
        body["last_active_ago"].as_u64().unwrap_or(u64::MAX) < 10_000,
        "the duration is since the row was written, not the row's timestamp: {body}"
    );
}

/// A user nobody has heard from is offline, not an error and not absent.
#[tokio::test]
async fn a_user_who_never_set_presence_is_offline() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "offline");
    assert_eq!(body["currently_active"], false);
    assert!(
        body.get("status_msg").is_none(),
        "no message was ever set, so the key is absent rather than null: {body}"
    );
}

/// Only "online" is currently active. Idle is recent but not present, and
/// conflating the two would make a client's away indicator never appear.
#[tokio::test]
async fn only_online_counts_as_currently_active() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    for state in ["unavailable", "offline"] {
        let (status, body) = harness
            .set("alice", &alice, &json!({ "presence": state }))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = harness.get("alice", &alice).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["presence"], state);
        assert_eq!(
            body["currently_active"], false,
            "{state} was reported as currently active: {body}"
        );
    }
}

/// The gate: a stranger cannot watch you.
#[tokio::test]
async fn a_stranger_cannot_read_your_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;

    let (status, body) = harness.get("alice", &mallory).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "presence leaked to someone sharing no room: {body}"
    );
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

/// And the other half: someone you share a room with can.
///
/// Asserted alongside the refusal because a gate that refuses everyone is
/// also "secure", and would break every client that renders an online dot.
#[tokio::test]
async fn someone_in_your_room_can_read_your_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;
    harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;

    let (status, body) = harness.get("alice", &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["presence"], "online");
}

/// You cannot set someone else's presence — otherwise marking a rival
/// offline is a one-request denial of service against every client that
/// renders their status.
#[tokio::test]
async fn you_cannot_set_another_users_presence() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;

    let (status, body) = harness
        .set("alice", &bob, &json!({ "presence": "offline" }))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Bob set Alice's presence: {body}"
    );

    // Sharing a room is enough to *read*, and still not enough to write.
    let (status, body) = harness.get("alice", &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["presence"], "offline",
        "the default, not Bob's write: {body}"
    );
}

/// An unknown state is refused rather than stored and echoed. A server that
/// accepted "busy" would be inventing protocol, and the client that sent it
/// would have no way to learn nobody else understands it.
#[tokio::test]
async fn an_unknown_presence_state_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .set("alice", &alice, &json!({ "presence": "busy" }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_JSON");
}

/// An empty message clears one rather than storing a blank.
#[tokio::test]
async fn an_empty_status_message_clears_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "here" }),
        )
        .await;
    harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "" }),
        )
        .await;

    let (status, body) = harness.get("alice", &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("status_msg").is_none(),
        "the cleared message came back as a blank one: {body}"
    );
}

/// The `m.presence` events about `user` in one `/sync` response.
fn presence_of(sync: &Value, user: &str) -> Vec<Value> {
    sync["presence"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["sender"] == user)
        .cloned()
        .collect()
}

fn since(sync: &Value) -> String {
    format!("?since={}", sync["next_batch"].as_str().unwrap())
}

/// Percent-encode a JSON filter for the query string.
fn encoded(filter: &Value) -> String {
    filter
        .to_string()
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// A change reaches someone sharing a room, incrementally, and not a
/// stranger: `/sync` must not become the surveillance the status
/// endpoint's 403 refuses.
#[tokio::test]
async fn a_presence_change_reaches_a_room_mates_sync_and_not_a_strangers() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let mallory = harness.register("mallory").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;

    let bob_first = harness.sync(&bob, "").await;
    let mallory_first = harness.sync(&mallory, "").await;
    assert!(
        presence_of(&bob_first, "@alice:example.org").is_empty(),
        "alice has said nothing yet: {bob_first}"
    );

    harness
        .set(
            "alice",
            &alice,
            &json!({ "presence": "online", "status_msg": "around" }),
        )
        .await;

    let bob_next = harness.sync(&bob, &since(&bob_first)).await;
    let seen = presence_of(&bob_next, "@alice:example.org");
    assert_eq!(seen.len(), 1, "{bob_next}");
    assert_eq!(seen[0]["type"], "m.presence");
    assert_eq!(seen[0]["content"]["presence"], "online");
    assert_eq!(seen[0]["content"]["status_msg"], "around");
    assert_eq!(seen[0]["content"]["currently_active"], true);
    // Once, not on every sync after.
    let bob_quiet = harness.sync(&bob, &since(&bob_next)).await;
    assert!(
        presence_of(&bob_quiet, "@alice:example.org").is_empty(),
        "{bob_quiet}"
    );

    let mallory_next = harness.sync(&mallory, &since(&mallory_first)).await;
    assert!(
        presence_of(&mallory_next, "@alice:example.org").is_empty(),
        "presence leaked to someone sharing no room: {mallory_next}"
    );
    // Nor on a fresh start.
    let mallory_initial = harness.sync(&mallory, "").await;
    assert!(
        presence_of(&mallory_initial, "@alice:example.org").is_empty(),
        "{mallory_initial}"
    );

    // An initial sync of a room-mate carries where alice stands now.
    let bob_initial = harness.sync(&bob, "").await;
    assert_eq!(
        presence_of(&bob_initial, "@alice:example.org")[0]["content"]["presence"],
        "online",
        "{bob_initial}"
    );
}

/// The filter's `presence` section is applied: a client that asked not to
/// hear about alice does not.
#[tokio::test]
async fn the_presence_filter_is_honoured() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;

    let first = harness.sync(&bob, "").await;
    harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;

    let not_alice = encoded(&json!({ "presence": { "not_senders": ["@alice:example.org"] } }));
    let filtered = harness
        .sync(&bob, &format!("{}&filter={not_alice}", since(&first)))
        .await;
    assert!(
        presence_of(&filtered, "@alice:example.org").is_empty(),
        "the filter excluded alice: {filtered}"
    );
    let none = encoded(&json!({ "presence": { "types": [] } }));
    let silent = harness
        .sync(&bob, &format!("{}&filter={none}", since(&first)))
        .await;
    assert_eq!(silent["presence"]["events"], json!([]), "{silent}");

    // The same window unfiltered does carry it: the filter was the reason.
    let unfiltered = harness.sync(&bob, &since(&first)).await;
    assert_eq!(
        presence_of(&unfiltered, "@alice:example.org").len(),
        1,
        "{unfiltered}"
    );
}

/// A sync brings its user online, as the spec's `set_presence` default
/// says; `set_presence=offline` leaves presence alone; and a sync does not
/// undo an away the user set on purpose.
#[tokio::test]
async fn a_sync_speaks_for_presence_as_set_presence_says() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;
    let bob_first = harness.sync(&bob, "").await;

    harness.sync(&alice, "?set_presence=offline").await;
    let (_, body) = harness.get("alice", &alice).await;
    assert_eq!(body["presence"], "offline", "{body}");

    let own = harness.sync(&alice, "").await;
    assert_eq!(
        presence_of(&own, "@alice:example.org")[0]["content"]["presence"],
        "online",
        "a user's own sync carries their own presence: {own}"
    );
    let bob_next = harness.sync(&bob, &since(&bob_first)).await;
    assert_eq!(
        presence_of(&bob_next, "@alice:example.org")[0]["content"]["presence"],
        "online",
        "{bob_next}"
    );

    harness
        .set("alice", &alice, &json!({ "presence": "unavailable" }))
        .await;
    harness.sync(&alice, "").await;
    let (_, body) = harness.get("alice", &alice).await;
    assert_eq!(body["presence"], "unavailable", "{body}");

    let (status, body) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/v3/sync?set_presence=busy")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// Switched off, `PUT` is still answered, but nothing is kept and `/sync`
/// has no `presence` section at all.
#[tokio::test]
async fn presence_switched_off_serves_nothing() {
    let harness = Harness::with("[presence]\nenabled = false\n");
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite_and_join(&room, &alice, "bob", &bob).await;
    let first = harness.sync(&bob, "").await;
    assert!(first.get("presence").is_none(), "{first}");

    let (status, body) = harness
        .set("alice", &alice, &json!({ "presence": "online" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    harness.sync(&alice, "").await;

    let (_, body) = harness.get("alice", &bob).await;
    assert_eq!(body["presence"], "offline", "{body}");
    let next = harness.sync(&bob, &since(&first)).await;
    assert!(next.get("presence").is_none(), "{next}");
}
