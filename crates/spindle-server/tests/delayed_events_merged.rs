//! MSC4140 as merged (October 2026), beside the unstable shape
//! `delayed_events.rs` pins.
//!
//! The MSC that landed is not the one Element Call first shipped against:
//! scheduling has an endpoint of its own with the delay in the body and a
//! transaction ID, a delay can be looked up by id after it has finished, a
//! repeated action that agrees with how a delay ended succeeds while one
//! that contradicts it is a 409, both limits are capabilities, and the event
//! a delay became names the delay in its `unsigned`. The query-parameter
//! form on `/send` and `/state` stays served -- it is what shipping clients
//! call -- so everything here is in addition to it, not instead.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const UNSTABLE: &str = "/_matrix/client/unstable/org.matrix.msc4140";

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

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(json!({ "preset": "public_chat" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn join(&self, room: &str, token: &str) {
        let (status, body) = self
            .call(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(token),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// Schedule through MSC4140's own endpoint.
    async fn schedule(
        &self,
        prefix: &str,
        room: &str,
        token: &str,
        txn: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let path = if prefix == UNSTABLE {
            format!("{UNSTABLE}/rooms/{room}/delayed_event/m.room.message/{txn}")
        } else {
            format!("/_matrix/client/v3/rooms/{room}/delayed_event/m.room.message/{txn}")
        };
        self.call("PUT", &path, Some(token), Some(body)).await
    }

    async fn scheduled(&self, room: &str, token: &str, txn: &str, delay_ms: u64) -> String {
        let (status, body) = self
            .schedule(
                UNSTABLE,
                room,
                token,
                txn,
                json!({ "delay_ms": delay_ms, "content": { "msgtype": "m.text", "body": txn } }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["delay_id"].as_str().unwrap().to_owned()
    }

    async fn lookup(&self, prefix: &str, delay_id: &str, token: &str) -> (StatusCode, Value) {
        let base = if prefix == UNSTABLE {
            UNSTABLE.to_owned()
        } else {
            "/_matrix/client/v1".to_owned()
        };
        self.call(
            "GET",
            &format!("{base}/delayed_events/{delay_id}"),
            Some(token),
            None,
        )
        .await
    }

    async fn act(&self, delay_id: &str, token: Option<&str>, action: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            &format!("/_matrix/client/v1/delayed_events/{delay_id}/{action}"),
            token,
            Some(json!({})),
        )
        .await
    }

    async fn event(&self, room: &str, event_id: &str, token: &str) -> Value {
        let (status, body) = self
            .call(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// The scheduling endpoint holds the event and answers only a delay id; a
/// retry with the same transaction ID is the same delay, not a second one.
#[tokio::test]
async fn the_scheduling_endpoint_is_a_transaction() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let body = json!({ "delay_ms": 60_000, "content": { "msgtype": "m.text", "body": "later" } });

    let (status, first) = harness
        .schedule(UNSTABLE, &room, &alice, "t1", body.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(first["event_id"].is_null(), "nothing was sent yet: {first}");
    let (status, again) = harness
        .schedule(UNSTABLE, &room, &alice, "t1", body.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        first["delay_id"], again["delay_id"],
        "a retried request scheduled a second delay"
    );

    let (status, listed) = harness
        .call(
            "GET",
            &format!("{UNSTABLE}/delayed_events"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["delayed_events"].as_array().unwrap().len(), 1);

    // The stable path is the same endpoint; a new transaction is a new
    // delay.
    let (status, stable) = harness.schedule("v3", &room, &alice, "t2", body).await;
    assert_eq!(status, StatusCode::OK, "{stable}");
    assert_ne!(stable["delay_id"], first["delay_id"]);
}

/// What the body may and may not say, with MSC4140's error codes.
#[tokio::test]
async fn the_scheduling_endpoint_validates_its_body() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let content = json!({ "msgtype": "m.text", "body": "x" });

    for (txn, body, errcode) in [
        (
            "zero",
            json!({ "delay_ms": 0, "content": content }),
            "M_INVALID_PARAM",
        ),
        (
            "negative",
            json!({ "delay_ms": -5, "content": content }),
            "M_INVALID_PARAM",
        ),
        (
            "fraction",
            json!({ "delay_ms": 1.5, "content": content }),
            "M_INVALID_PARAM",
        ),
        ("no-content", json!({ "delay_ms": 1000 }), "M_MISSING_PARAM"),
        (
            "bad-content",
            json!({ "delay_ms": 1000, "content": 7 }),
            "M_INVALID_PARAM",
        ),
        (
            "bad-state-key",
            json!({ "delay_ms": 1000, "content": content, "state_key": 3 }),
            "M_INVALID_PARAM",
        ),
    ] {
        let (status, response) = harness.schedule(UNSTABLE, &room, &alice, txn, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{txn}: {response}");
        assert_eq!(response["errcode"], errcode, "{txn}: {response}");
    }

    // Past the cap: the stable code on the stable endpoint, the prefixed
    // one on the unstable endpoint, the limit beside both.
    let too_long = json!({ "delay_ms": 999_999_999_999_u64, "content": content });
    let (status, stable) = harness
        .schedule("v3", &room, &alice, "long", too_long.clone())
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{stable}");
    assert_eq!(stable["errcode"], "M_DELAY_TOO_LARGE", "{stable}");
    let (_, unstable) = harness
        .schedule(UNSTABLE, &room, &alice, "long", too_long)
        .await;
    assert_eq!(
        unstable["errcode"], "ORG.MATRIX.MSC4140_DELAY_TOO_LARGE",
        "{unstable}"
    );
    assert_eq!(unstable["org.matrix.msc4140.max_delay"], 86_400_000);
}

/// A delay of zero is refused on the query-parameter form too.
#[tokio::test]
async fn a_zero_delay_is_refused_on_the_query_form() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let (status, body) = harness
        .call(
            "PUT",
            &format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/z?org.matrix.msc4140.delay=0"
            ),
            Some(&alice),
            Some(json!({ "msgtype": "m.text", "body": "now?" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
}

/// A delay can be looked up by id while it is pending and after it has
/// finished, by its owner only, on the stable and the unstable path.
#[tokio::test]
async fn a_delay_is_answerable_by_id_before_and_after() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.scheduled(&room, &alice, "looked", 60_000).await;

    for prefix in [UNSTABLE, "v1"] {
        let (status, body) = harness.lookup(prefix, &delay_id, &alice).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delay_id"], delay_id.as_str());
        assert_eq!(body["room_id"], room.as_str());
        assert_eq!(body["type"], "m.room.message");
        assert_eq!(body["delay_ms"], 60_000);
        assert!(body["delayed_since_ts"].as_u64().unwrap() > 0, "{body}");
        assert_eq!(body["content"]["body"], "looked");
        assert!(body.get("finalised").is_none(), "{body}");
        assert!(body.get("state_key").is_none(), "{body}");

        let (status, body) = harness.lookup(prefix, &delay_id, &bob).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "bob sees alice's delay: {body}"
        );
    }

    let (status, body) = harness.act(&delay_id, Some(&alice), "send").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness.lookup("v1", &delay_id, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event_id = body["finalised"]["event_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the outcome names the event: {body}"));
    assert!(body["finalised"]["finalised_ts"].as_u64().unwrap() > 0);
    assert!(body["finalised"].get("error").is_none());
    assert_eq!(body["content"]["body"], "looked");

    // The event names the delay it came from, for its sender only.
    let seen = harness.event(&room, event_id, &alice).await;
    assert_eq!(
        seen["unsigned"]["org.matrix.msc4140.delay_id"],
        delay_id.as_str(),
        "{seen}"
    );
    assert!(
        seen["unsigned"].get("transaction_id").is_none(),
        "a delayed event has no transaction: {seen}"
    );
    harness.join(&room, &bob).await;
    let seen = harness.event(&room, event_id, &bob).await;
    assert!(
        seen["unsigned"]
            .get("org.matrix.msc4140.delay_id")
            .is_none(),
        "bob was told alice's delay id: {seen}"
    );
}

/// The outcomes, and what a later action on each comes to: the same action
/// again is a success, a contradicting one a 409, and an unknown id a 404.
#[tokio::test]
async fn an_action_after_the_end_agrees_or_conflicts() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let cancelled = harness.scheduled(&room, &alice, "c", 60_000).await;
    let (status, body) = harness.act(&cancelled, Some(&alice), "cancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness.lookup("v1", &cancelled, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let finalised = &body["finalised"];
    assert!(finalised.is_object(), "{body}");
    assert!(finalised.get("event_id").is_none(), "{body}");
    assert!(finalised.get("error").is_none(), "{body}");
    let (status, body) = harness.act(&cancelled, Some(&alice), "cancel").await;
    assert_eq!(status, StatusCode::OK, "a repeated cancel: {body}");
    for action in ["send", "restart"] {
        let (status, body) = harness.act(&cancelled, Some(&alice), action).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{action} after cancel: {body}"
        );
    }

    let (status, body) = harness
        .act("ffffffffffffffffffffffffffffffff", Some(&alice), "cancel")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // On the unstable endpoint a contradiction stays the 404 shipping
    // clients were built against; agreement is still a success.
    let (status, body) = harness
        .call(
            "POST",
            &format!("{UNSTABLE}/delayed_events/{cancelled}/restart"),
            Some(&alice),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness
        .call(
            "POST",
            &format!("{UNSTABLE}/delayed_events/{cancelled}/cancel"),
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The stable management endpoint needs a token, and the delay must be the
/// caller's -- unlike the unstable one, where the id is the capability.
#[tokio::test]
async fn the_stable_management_endpoint_is_the_owners() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.scheduled(&room, &alice, "mine", 60_000).await;

    let (status, body) = harness.act(&delay_id, None, "cancel").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = harness.act(&delay_id, Some(&bob), "cancel").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness.act(&delay_id, Some(&alice), "restart").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // With a token on the unstable route, the owner check applies too: an
    // application service calling as the user (lk-jwt-service 0.8) is
    // held to the user's own delays.
    let (status, body) = harness
        .call(
            "POST",
            &format!("{UNSTABLE}/delayed_events/{delay_id}/cancel"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness.lookup("v1", &delay_id, &alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("finalised").is_none(), "bob cancelled it: {body}");
}

/// A `send` the room refuses answers with the refusal and leaves the delay
/// scheduled, so the client may retry until its deadline.
#[tokio::test]
async fn a_refused_send_stays_scheduled() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let bob = harness.register("bob").await;
    harness.join(&room, &bob).await;
    let delay_id = harness.scheduled(&room, &bob, "refused", 60_000).await;
    let (status, body) = harness
        .call(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.act(&delay_id, Some(&bob), "send").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = harness.lookup("v1", &delay_id, &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("finalised").is_none(),
        "a refused send finalised the delay: {body}"
    );
}

/// Both limits are capabilities, under the stable and the unstable name,
/// and the per-user one is enforced across rooms.
#[tokio::test]
async fn the_limits_are_advertised_and_the_user_cap_spans_rooms() {
    let harness = Harness::with("[delayed_events]\nmax_per_user = 2\nmax_delay_ms = 3600000\n");
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .call("GET", "/_matrix/client/v3/capabilities", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for name in ["m.delayed_events", "org.matrix.msc4140.delayed_events"] {
        assert_eq!(
            body["capabilities"][name],
            json!({ "max_delay_ms": 3_600_000, "max_scheduled": 2 }),
            "{body}"
        );
    }

    let first = harness.create_room(&alice).await;
    let second = harness.create_room(&alice).await;
    harness.scheduled(&first, &alice, "a", 60_000).await;
    harness.scheduled(&second, &alice, "b", 60_000).await;
    let (status, body) = harness
        .schedule(
            UNSTABLE,
            &first,
            &alice,
            "c",
            json!({ "delay_ms": 1000, "content": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED");
    assert!(body["retry_after_ms"].as_u64().unwrap() <= 60_000, "{body}");

    let (_, versions) = harness
        .call("GET", "/_matrix/client/versions", None, None)
        .await;
    assert_eq!(
        versions["unstable_features"]["org.matrix.msc4140.stable"], true,
        "{versions}"
    );
}

/// The refusal carries `Retry-After` as well as `retry_after_ms`.
#[tokio::test]
async fn the_refusal_carries_retry_after() {
    let harness = Harness::with("[delayed_events]\nmax_per_room = 1\n");
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.scheduled(&room, &alice, "held", 30_000).await;
    let request = Request::builder()
        .method("PUT")
        .uri(format!(
            "{UNSTABLE}/rooms/{room}/delayed_event/m.room.message/over"
        ))
        .header("authorization", format!("Bearer {alice}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "delay_ms": 1000, "content": {} }).to_string(),
        ))
        .unwrap();
    let response = harness.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((29..=30).contains(&retry), "Retry-After: {retry}");
}

/// A delay scheduled sticky (MSC4354) is still sticky when a delegate sends
/// it early: `MatrixRTC` 2.0's leave reaches clients through the sticky map,
/// and a non-sticky leave would never take the member out of it.
#[tokio::test]
async fn a_sticky_delay_sent_early_is_still_sticky() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let (status, body) = harness
        .call(
            "PUT",
            &format!(
                "/_matrix/client/v3/rooms/{room}/send/org.matrix.msc4143.rtc.member/m1\
                 ?org.matrix.msc4140.delay=60000&org.matrix.msc4354.sticky_duration_ms=30000"
            ),
            Some(&alice),
            Some(json!({ "msc4354_sticky_key": "k" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delay_id = body["delay_id"].as_str().unwrap().to_owned();

    // Token-less, as a delegate holding only the id sends it.
    let (status, body) = harness
        .call(
            "POST",
            &format!("{UNSTABLE}/delayed_events/{delay_id}/send"),
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, outcome) = harness.lookup("v1", &delay_id, &alice).await;
    let event_id = outcome["finalised"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let event = harness.event(&room, &event_id, &alice).await;
    assert_eq!(
        event["msc4354_sticky"]["duration_ms"], 30_000,
        "the early send dropped the stickiness: {event}"
    );
}

/// What Element Call asks a homeserver before relying on it to hold a
/// delegated leave (MSC4195): an unauthenticated POST, where anything but a
/// 404 means "this homeserver proxies delegation to an SFU-aware service",
/// and Element Call then schedules its leave an hour out. A server that
/// does not serve delegation must say 404, or a crashed participant is a
/// ghost for that hour.
#[tokio::test]
async fn the_delegation_probe_is_answered_not_found() {
    let harness = Harness::new();
    let (status, body) = harness
        .call(
            "POST",
            "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}
