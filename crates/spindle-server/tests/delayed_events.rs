//! MSC4140: an event handed over now and sent later.
//!
//! The mechanism exists for one reason — a call participant can vanish, and
//! the only party who would remove their membership is the one that
//! disappeared. So a client hands the server its own departure, delayed, and
//! restarts the timer while it lives. Its silence is the signal.
//!
//! That makes two things load-bearing and both are tested here: that
//! `restart` re-applies the *original* delay rather than the remainder, and
//! that a pending delay survives a restart of the server. A heartbeat that
//! shrank on each beat would fire while the client was still there; a delay
//! that evaporated on restart would leave exactly the ghosts the mechanism
//! prevents, at the moment many clients are disconnected at once.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const DELAY_PARAM: &str = "org.matrix.msc4140.delay";

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

fn config() -> spindle_server::Config {
    spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
    )
    .unwrap()
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = spindle_server::app(config(), Arc::clone(&store)).unwrap();
        Self {
            _dir: dir,
            store,
            app,
        }
    }

    /// A second server over the same store, as a restart would produce.
    fn restarted(&self) -> axum::Router {
        spindle_server::app(config(), Arc::clone(&self.store)).unwrap()
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        Self::call_on(&self.app, request).await
    }

    async fn call_on(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = app.clone().oneshot(request).await.unwrap();
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

    /// Schedule a delayed message and return its `delay_id`.
    async fn delay_message(&self, room: &str, token: &str, ms: u64, txn: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}?{DELAY_PARAM}={ms}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "msgtype": "m.text", "body": txn }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["event_id"].is_null(),
            "a delayed send must not have sent anything yet: {body}"
        );
        body["delay_id"].as_str().unwrap().to_owned()
    }

    async fn invite(&self, room: &str, token: &str, username: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/invite"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "user_id": format!("@{username}:example.org") }).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn join(&self, room: &str, token: &str) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri(format!("/_matrix/client/v3/rooms/{room}/join"))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn set_state(
        &self,
        room: &str,
        token: &str,
        event_type: &str,
        state_key: &str,
        content: &Value,
    ) {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(content.to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn act(&self, delay_id: &str, token: &str, action: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "action": action }).to_string()))
                .unwrap(),
        )
        .await
    }

    async fn pending_on(app: &axum::Router, token: &str) -> Vec<Value> {
        let (status, body) = Self::call_on(
            app,
            Request::builder()
                .uri("/_matrix/client/unstable/org.matrix.msc4140/delayed_events")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["delayed_events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn pending(&self, token: &str) -> Vec<Value> {
        Self::pending_on(&self.app, token).await
    }

    async fn timeline_bodies(&self, room: &str, token: &str) -> Vec<String> {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["content"]["body"].as_str().map(str::to_owned))
            .collect()
    }
}

/// A delayed send returns an id and sends nothing.
#[tokio::test]
async fn a_delayed_send_is_held_and_listed() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let delay_id = harness.delay_message(&room, &alice, 60_000, "later").await;

    assert!(
        !harness
            .timeline_bodies(&room, &alice)
            .await
            .contains(&"later".to_owned()),
        "the event was sent immediately"
    );
    let pending = harness.pending(&alice).await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0]["delay_id"], delay_id.as_str());
    assert_eq!(pending[0]["room_id"], room.as_str());
    assert_eq!(pending[0]["type"], "m.room.message");
    assert_eq!(pending[0]["delay"], 60_000);
}

/// `send` sends it now and takes it off the queue.
#[tokio::test]
async fn send_delivers_it_immediately_and_only_once() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.delay_message(&room, &alice, 60_000, "now").await;

    let (status, body) = harness.act(&delay_id, &alice, "send").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        harness
            .timeline_bodies(&room, &alice)
            .await
            .contains(&"now".to_owned()),
        "the event was not sent"
    );
    assert!(harness.pending(&alice).await.is_empty());

    // And it is gone: a second `send` has nothing to act on.
    let (status, _) = harness.act(&delay_id, &alice, "send").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the delay survived being sent, so it could be sent twice"
    );
}

/// `cancel` drops it unsent.
#[tokio::test]
async fn cancel_drops_it_without_sending() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.delay_message(&room, &alice, 60_000, "never").await;

    let (status, _) = harness.act(&delay_id, &alice, "cancel").await;
    assert_eq!(status, StatusCode::OK);
    assert!(harness.pending(&alice).await.is_empty());
    assert!(
        !harness
            .timeline_bodies(&room, &alice)
            .await
            .contains(&"never".to_owned()),
        "a cancelled event was sent anyway"
    );
}

/// `restart` re-applies the original delay, not what was left of it.
///
/// This is the heartbeat, and the direction of the bug matters: a restart
/// that kept the remaining time would shrink the window on every beat and
/// eventually fire while the client was still alive and still beating —
/// removing someone from a call they are in. `running_since` moving forward
/// while `delay` stays put is what says the window was reset rather than
/// merely inspected.
#[tokio::test]
async fn restart_reapplies_the_whole_delay() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.delay_message(&room, &alice, 60_000, "beat").await;

    let before = harness.pending(&alice).await;
    let started_at = before[0]["running_since"].as_u64().unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, _) = harness.act(&delay_id, &alice, "restart").await;
    assert_eq!(status, StatusCode::OK);

    let after = harness.pending(&alice).await;
    assert_eq!(after.len(), 1, "restart should not duplicate the delay");
    assert_eq!(
        after[0]["delay"], 60_000,
        "the original delay must be preserved: {after:?}"
    );
    assert!(
        after[0]["running_since"].as_u64().unwrap() > started_at,
        "the window did not move, so restart did not restart anything: \
         {started_at} then {after:?}"
    );
    assert_eq!(after[0]["delay_id"], delay_id.as_str());
}

/// A delay that comes due is sent by the server, with nobody asking.
///
/// The whole mechanism in one test: schedule something short, do nothing at
/// all, and find it in the timeline.
#[tokio::test]
async fn a_delay_that_elapses_is_sent_without_the_client() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    harness.delay_message(&room, &alice, 1, "fired").await;

    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if harness
            .timeline_bodies(&room, &alice)
            .await
            .contains(&"fired".to_owned())
        {
            assert!(
                harness.pending(&alice).await.is_empty(),
                "it fired but stayed on the queue, so it can fire again"
            );
            return;
        }
    }
    panic!("a delay due immediately was never sent");
}

/// Pending delays survive a restart.
///
/// The reason this is persisted at all. A server that forgot them would drop
/// every pending departure exactly when a restart disconnected the clients
/// holding them — the ghosts the mechanism exists to prevent, produced by the
/// mechanism itself.
#[tokio::test]
async fn a_pending_delay_survives_a_restart() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness
        .delay_message(&room, &alice, 60_000, "outlives")
        .await;

    let after_restart = Harness::pending_on(&harness.restarted(), &alice).await;
    assert_eq!(after_restart.len(), 1, "{after_restart:?}");
    assert_eq!(after_restart[0]["delay_id"], delay_id.as_str());
    assert_eq!(after_restart[0]["room_id"], room.as_str());
}

/// A delay is nobody else's to touch, and nobody else's to see.
///
/// Not-found rather than forbidden, and deliberately: telling a caller that a
/// delay exists but is not theirs would let anyone probe for other people's
/// pending events by id.
#[tokio::test]
async fn a_delay_belongs_to_the_caller_who_scheduled_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.delay_message(&room, &alice, 60_000, "mine").await;

    assert!(
        Harness::pending_on(&harness.app, &mallory).await.is_empty(),
        "mallory can see alice's pending delays"
    );
    for action in ["send", "cancel", "restart"] {
        let (status, body) = harness.act(&delay_id, &mallory, action).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "mallory could {action} alice's delay: {body}"
        );
    }
    assert_eq!(
        harness.pending(&alice).await.len(),
        1,
        "alice's delay was disturbed"
    );
}

/// A delay in a room the caller is not in is refused now, not silently later.
#[tokio::test]
async fn a_delay_needs_the_same_membership_a_send_needs() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/x?{DELAY_PARAM}=60000"
                ))
                .header("authorization", format!("Bearer {mallory}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "msgtype": "m.text", "body": "no" }).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(Harness::pending_on(&harness.app, &mallory).await.is_empty());
}

/// A delay longer than the cap is refused, and the cap is in the message.
#[tokio::test]
async fn an_unbounded_delay_is_refused_with_its_limit() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/x?{DELAY_PARAM}=999999999999"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "msgtype": "m.text", "body": "no" }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("86400000"),
        "the limit must be in the message so a client can retry under it: {body}"
    );
}

/// One sender cannot fill the store with pending delays in one room.
///
/// The duration cap does not imply this one: a client can schedule an
/// unbounded number of *short* delays as fast as it can send requests, and
/// each is a row this server holds until it fires. #36 names that as the
/// memory-amplification vector, and a cap on how long a delay lasts does
/// nothing about how many there are.
#[tokio::test]
async fn one_sender_cannot_hold_unbounded_delays_in_one_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    for index in 0..100 {
        harness
            .delay_message(&room, &alice, 600_000, &format!("d{index}"))
            .await;
    }

    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/over?{DELAY_PARAM}=600000"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "msgtype": "m.text", "body": "no" }).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
    assert_eq!(harness.pending(&alice).await.len(), 100, "the cap leaked");
}

/// At the cap, a client can still keep the delays it has alive.
///
/// `restart` replaces a row rather than adding one, so it must not be
/// counted against the cap. If it were, a client that reached the limit
/// could never heartbeat again and every one of its pending departures would
/// fire — turning a cap meant to protect the server into a way to eject
/// every participant of a busy call at once.
#[tokio::test]
async fn a_client_at_the_cap_can_still_restart() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let mut ids = Vec::new();
    for index in 0..100 {
        ids.push(
            harness
                .delay_message(&room, &alice, 600_000, &format!("d{index}"))
                .await,
        );
    }

    let (status, body) = harness.act(&ids[0], &alice, "restart").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "restart was refused at the cap: {body}"
    );
    assert_eq!(harness.pending(&alice).await.len(), 100);
}

/// The cap is per room, not per server.
#[tokio::test]
async fn the_cap_does_not_span_rooms() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let first = harness.create_room(&alice).await;
    let second = harness.create_room(&alice).await;

    for index in 0..100 {
        harness
            .delay_message(&first, &alice, 600_000, &format!("d{index}"))
            .await;
    }
    // The other room starts from zero.
    harness
        .delay_message(&second, &alice, 600_000, "elsewhere")
        .await;
    assert_eq!(harness.pending(&alice).await.len(), 101);
}

/// A delay from someone who has since lost permission is not sent.
///
/// #36 calls for this specifically: the sender's power level may have
/// changed, or they may have been kicked, between scheduling and firing. The
/// authorization that matters is the one at fire time, and it is the ordinary
/// append path's — this test is what says the delayed path did not find a way
/// around it.
///
/// Bob schedules a departure-shaped state event, then loses the power to send
/// it. When it comes due the room must be unchanged, and the delay gone: a
/// refused firing is resolved, not retried forever.
#[tokio::test]
async fn a_delay_is_authorised_when_it_fires_not_when_it_is_scheduled() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite(&room, &alice, "bob").await;
    harness.join(&room, &bob).await;

    // Bob is given exactly enough to set state, and no more. Not 100: a user
    // cannot change the power level of someone at their own level, so Alice
    // could never demote him again and the test would be measuring that rule
    // instead of this one.
    harness
        .set_state(
            &room,
            &alice,
            "m.room.power_levels",
            "",
            &json!({
                "users": { "@alice:example.org": 100, "@bob:example.org": 50 },
                "events": {},
                "events_default": 0,
                "state_default": 50,
            }),
        )
        .await;

    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.topic/?{DELAY_PARAM}=1"
                ))
                .header("authorization", format!("Bearer {bob}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "topic": "bob was here" }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Demote Bob below what setting state needs.
    harness
        .set_state(
            &room,
            &alice,
            "m.room.power_levels",
            "",
            &json!({
                "users": { "@alice:example.org": 100, "@bob:example.org": 0 },
                "events": {},
                "events_default": 0,
                "state_default": 50,
            }),
        )
        .await;

    // Give the loop time to try, then confirm it tried and was refused: the
    // delay is gone, and the topic never landed.
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if harness.pending(&bob).await.is_empty() {
            let (_, topic) = harness
                .call(
                    Request::builder()
                        .uri(format!(
                            "/_matrix/client/v3/rooms/{room}/state/m.room.topic/"
                        ))
                        .header("authorization", format!("Bearer {alice}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
            assert_ne!(
                topic["topic"], "bob was here",
                "a sender who lost permission after scheduling still got the \
                 event sent: {topic}"
            );
            return;
        }
    }
    panic!("the delay never fired at all, so nothing was authorised either way");
}

/// An unknown action is refused rather than treated as one of the three.
#[tokio::test]
async fn an_unknown_action_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let delay_id = harness.delay_message(&room, &alice, 60_000, "x").await;

    let (status, _) = harness.act(&delay_id, &alice, "explode").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.pending(&alice).await.len(), 1);
}

/// The state-event form is the one Matrix RTC uses.
#[tokio::test]
async fn a_delayed_state_event_lands_in_the_state() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.topic/?{DELAY_PARAM}=1"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "topic": "delayed topic" }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["delay_id"].is_string(), "{body}");

    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let (_, topic) = harness
            .call(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v3/rooms/{room}/state/m.room.topic/"
                    ))
                    .header("authorization", format!("Bearer {alice}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        if topic["topic"] == "delayed topic" {
            return;
        }
    }
    panic!("a delayed state event never reached the room state");
}
