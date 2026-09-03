//! `MatrixRTC` membership (#40): what the server owes a call, pinned against
//! what Element Call sends today.
//!
//! Most of `MatrixRTC` is client-to-client over events this server relays
//! without reading. Deployed Element Call keeps one state event per
//! participant device -- `org.matrix.msc3401.call.member`, keyed
//! `_@user:server_DEVICE_m.call` -- and hands the server its own departure
//! as a delayed event (MSC4140) before it joins, restarting the delay while
//! it lives. Everything else is to-device traffic. So what the server owes
//! is small and specific, and each piece is a test here:
//!
//! - **Who may write the key.** The spec's rule, run by ruma: a state key
//!   starting with `@` belongs to that user and nobody else. That rule is
//!   *why* the client's key starts with `_` -- `@alice:example.org_DEVICE`
//!   is not `@alice:example.org`, so the rule would refuse alice's own
//!   membership. The `_` key is ordinary state and the server invents no
//!   owner for it: MSC3757, which would have, is closed, and MSC4354's
//!   sticky events are where the problem is being solved.
//! - **Who may write at all.** A fresh room's `state_default` is 50, so at
//!   the spec's defaults no ordinary member can join a call. The reference
//!   clients fix that on `/createRoom` -- Element X names the membership
//!   type at 0 in `power_level_content_override` on every room it makes,
//!   and its DMs use `trusted_private_chat` -- and the server's job is to
//!   honour both, which until #40 it did not.
//! - **The lifecycle.** The delayed leave is scheduled *before* the join
//!   and survives it, a heartbeat keeps the membership, silence fires the
//!   leave, and everyone sees it: in the room state, on `/sync`, and (for
//!   the client that scheduled it, MSC4309) as a finalised delay.
//! - **To-device signalling (MSC3401).** Call setup is a burst of
//!   to-device invites. They ride the per-device stream (SPEC §16.1), and
//!   the room's own events arrive beside them rather than behind them.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// The membership state type deployed Element Call writes (MSC3401's
/// unstable name; MSC4143's `m.rtc.member` is a sticky event, MSC4354).
const MEMBER: &str = "org.matrix.msc3401.call.member";
const DELAY_PARAM: &str = "org.matrix.msc4140.delay";
const FINALISED: &str = "org.matrix.msc4140.finalised_delayed_events";
/// How many to-device invites a call setup sends in one go, here.
const SETUP_BURST: u64 = 60;

/// The `power_level_content_override` Element X sends on every room it
/// creates: the call membership types writable by anyone, invites open.
fn call_ready() -> Value {
    json!({
        "events": { "m.call.member": 0, MEMBER: 0 },
        "invite": 0,
    })
}

/// One logged-in device of an account.
struct Session {
    user_id: String,
    device_id: String,
    token: String,
}

impl Session {
    /// Element Call's state key for this device: user id, device id and
    /// application, `_`-separated, behind the `_` that keeps it clear of
    /// the spec's `@` rule.
    fn member_key(&self) -> String {
        format!("_{}_{}_m.call", self.user_id, self.device_id)
    }

    /// What Element Call puts in a joined membership.
    fn joined(&self) -> Value {
        json!({
            "application": "m.call",
            "call_id": "",
            "scope": "m.room",
            "device_id": self.device_id,
            "membershipID": format!("{}:{}", self.user_id, self.device_id),
            "expires": 14_400_000,
            "m.call.intent": "video",
            "focus_active": { "type": "livekit", "focus_selection": "oldest_membership" },
            "foci_preferred": [
                { "type": "livekit", "livekit_service_url": "https://livekit.example.org/jwt" },
            ],
        })
    }
}

struct Harness {
    _dir: TempDir,
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
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
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

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str) -> Session {
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
        Session {
            user_id: format!("@{username}:example.org"),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
            token: body["access_token"].as_str().unwrap().to_owned(),
        }
    }

    /// `POST /createRoom` with the given body, as the client sent it.
    async fn create_room(&self, creator: &Session, body: &Value) -> (StatusCode, Value) {
        self.send(
            "POST",
            "/_matrix/client/v3/createRoom",
            &creator.token,
            body,
        )
        .await
    }

    /// A room that must be created, returning its id.
    async fn room(&self, creator: &Session, body: &Value) -> String {
        let (status, response) = self.create_room(creator, body).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["room_id"].as_str().unwrap().to_owned()
    }

    /// A room created the way Element X creates one, with `member` invited
    /// and joined.
    async fn call_room(&self, creator: &Session, member: &Session) -> String {
        let room = self
            .room(
                creator,
                &json!({
                    "invite": [member.user_id],
                    "power_level_content_override": call_ready(),
                }),
            )
            .await;
        self.join(&room, member).await;
        room
    }

    async fn join(&self, room: &str, member: &Session) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                &member.token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn set_state(
        &self,
        room: &str,
        sender: &Session,
        event_type: &str,
        state_key: &str,
        content: &Value,
    ) -> (StatusCode, Value) {
        self.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"),
            &sender.token,
            content,
        )
        .await
    }

    /// The content of one piece of state, or the status that refused it.
    async fn state(
        &self,
        room: &str,
        viewer: &Session,
        event_type: &str,
        state_key: &str,
    ) -> (StatusCode, Value) {
        self.get(
            &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"),
            &viewer.token,
        )
        .await
    }

    /// The room's `m.room.power_levels` content.
    async fn power_levels(&self, room: &str, viewer: &Session) -> Value {
        let (status, body) = self.state(room, viewer, "m.room.power_levels", "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Schedule a delayed state event and return its `delay_id`.
    async fn delayed_state(
        &self,
        room: &str,
        sender: &Session,
        event_type: &str,
        state_key: &str,
        content: &Value,
        delay_ms: u64,
    ) -> String {
        let (status, body) = self
            .send(
                "PUT",
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}?{DELAY_PARAM}={delay_ms}"
                ),
                &sender.token,
                content,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["delay_id"].as_str().unwrap().to_owned()
    }

    async fn act(&self, delay_id: &str, sender: &Session, action: &str) -> (StatusCode, Value) {
        self.send(
            "POST",
            &format!("/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}"),
            &sender.token,
            &json!({ "action": action }),
        )
        .await
    }

    async fn pending(&self, sender: &Session) -> Vec<Value> {
        let (status, body) = self
            .get(
                "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
                &sender.token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["delayed_events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    async fn sync(&self, viewer: &Session, since: Option<&str>) -> Value {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
        };
        let (status, body) = self.get(&path, &viewer.token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Wait for the membership under `state_key` to read `expected`.
    ///
    /// The fire loop ticks once a second and a delay may fire up to that
    /// late, so this polls rather than sleeping a fixed time: the assertion
    /// is that it happens, not how fast the runner is.
    async fn wait_for_member_state(
        &self,
        room: &str,
        viewer: &Session,
        state_key: &str,
        expected: &Value,
    ) {
        for _ in 0..60 {
            let (_, content) = self.state(room, viewer, MEMBER, state_key).await;
            if &content == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("the membership under {state_key} never became {expected}");
    }
}

/// Every event `/sync` carries for `room`, state and timeline alike.
fn room_events(sync: &Value, room: &str) -> Vec<Value> {
    let joined = &sync["rooms"]["join"][room];
    ["state", "timeline"]
        .iter()
        .flat_map(|section| {
            joined[section]["events"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Who may write the key.

/// The spec's `@` rule is why Element Call's key starts with `_`.
///
/// `@alice:example.org_DEVICE` starts with `@` and is not alice's own id,
/// so the rule refuses alice's *own* membership under it; the `_` in front
/// takes the key out of the rule's reach. Both halves are the rules'
/// doing, run by ruma, and neither is this server's to reinterpret.
#[tokio::test]
async fn the_spec_rule_is_why_the_member_key_starts_with_an_underscore() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;

    let bare = format!("{}_{}", alice.user_id, alice.device_id);
    let (status, body) = harness
        .set_state(&room, &alice, MEMBER, &bare, &alice.joined())
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key starting with `@` that is not the sender is refused: {body}"
    );

    let (status, body) = harness
        .set_state(&room, &alice, MEMBER, &alice.member_key(), &alice.joined())
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the `_` key is ordinary state: {body}"
    );

    // And the rule still guards what it is for: bob cannot write state
    // under alice's bare user id.
    let (status, body) = harness
        .set_state(&room, &bob, MEMBER, &alice.user_id, &json!({}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// The `_` key has no owner beyond what the rules give it, and this server
/// does not invent one.
///
/// Any member the power levels let write the type may overwrite anyone's
/// membership. That is the state of the art the reference clients live
/// with: MSC3757, which would have tied `@user_suffix` keys to their
/// user, is closed, and MSC4354's sticky events -- which MSC4143 now
/// mandates for `m.rtc.member` -- exist to replace state for exactly this
/// reason. A local rule here would be one the auth rules do not have
/// (`docs/divergence.md`: they must not diverge), one a federated peer's
/// event would not meet, and one a moderator clearing a ghost would trip
/// over. So the test pins the rules as they stand.
#[tokio::test]
async fn a_member_key_has_no_owner_beyond_what_the_rules_say() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;
    let (status, body) = harness
        .set_state(&room, &alice, MEMBER, &alice.member_key(), &alice.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness
        .set_state(&room, &bob, MEMBER, &alice.member_key(), &json!({}))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bob may write the type, so bob may write alice's key: {body}"
    );
    let (_, content) = harness
        .state(&room, &alice, MEMBER, &alice.member_key())
        .await;
    assert_eq!(content, json!({}));
}

// ---------------------------------------------------------------------------
// Who may write at all.

/// At the spec's defaults nobody but the creator can join a call; the
/// override Element X sends is what opens it, and the server honours it.
#[tokio::test]
async fn the_override_is_what_lets_an_ordinary_member_join_the_call() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    // A room at the defaults: `state_default` 50 keeps bob out.
    let plain = harness
        .room(&alice, &json!({ "invite": [bob.user_id] }))
        .await;
    harness.join(&plain, &bob).await;
    let (status, body) = harness
        .set_state(&plain, &bob, MEMBER, &bob.member_key(), &bob.joined())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = harness
        .set_state(&plain, &alice, MEMBER, &alice.member_key(), &alice.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "the creator still can: {body}");

    // The same room with the override: bob is in.
    let ready = harness.call_room(&alice, &bob).await;
    let (status, body) = harness
        .set_state(&ready, &bob, MEMBER, &bob.member_key(), &bob.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // And the override was applied on top of the defaults, not in their
    // place: the keys it named changed, the ones it did not are the spec's.
    let levels = harness.power_levels(&ready, &alice).await;
    assert_eq!(levels["events"][MEMBER], 0, "{levels}");
    assert_eq!(levels["events"]["m.call.member"], 0, "{levels}");
    assert_eq!(levels["invite"], 0, "{levels}");
    assert_eq!(levels["state_default"], 50, "{levels}");
    assert_eq!(levels["users"][&alice.user_id], 100, "{levels}");
}

/// A `users` override that forgets the creator would have the creator
/// lock themself out of a room they are creating. Refused with the field
/// named, before v12, where that entry is all the power they have.
#[tokio::test]
async fn a_users_override_that_forgets_the_creator_is_refused_before_v12() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let (status, body) = harness
        .create_room(
            &alice,
            &json!({
                "room_version": "11",
                "power_level_content_override": { "users": { bob.user_id.clone(): 100 } },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");

    // Naming the creator alongside is fine, and the map is taken whole.
    let room = harness
        .room(
            &alice,
            &json!({
                "room_version": "11",
                "power_level_content_override": {
                    "users": { alice.user_id.clone(): 100, bob.user_id.clone(): 50 },
                },
            }),
        )
        .await;
    let levels = harness.power_levels(&room, &alice).await;
    assert_eq!(levels["users"][&alice.user_id], 100, "{levels}");
    assert_eq!(levels["users"][&bob.user_id], 50, "{levels}");
}

/// A v12 room's creators may not be named in `users` (MSC4289), and a
/// client whose habit is to name itself gets its room rather than a
/// refusal citing a rule it has never heard of.
#[tokio::test]
async fn a_v12_room_strikes_its_creators_from_the_override() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let room = harness
        .room(
            &alice,
            &json!({
                "room_version": "12",
                "power_level_content_override": {
                    "users": { alice.user_id.clone(): 200 },
                    "events": { MEMBER: 0 },
                },
            }),
        )
        .await;
    let levels = harness.power_levels(&room, &alice).await;
    assert!(
        levels["users"].get(&alice.user_id).is_none(),
        "the creator is struck from `users`: {levels}"
    );
    assert_eq!(
        levels["events"][MEMBER], 0,
        "and the rest is kept: {levels}"
    );
}

/// `trusted_private_chat` -- the preset behind every Element DM -- gives
/// the invitee the creator's power, which is what lets a DM call be
/// answered. Before v12 that is a `users` entry at 100.
#[tokio::test]
async fn a_trusted_private_chat_makes_the_invitee_as_powerful_as_the_creator() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let room = harness
        .room(
            &alice,
            &json!({
                "room_version": "11",
                "preset": "trusted_private_chat",
                "is_direct": true,
                "invite": [bob.user_id],
            }),
        )
        .await;
    let levels = harness.power_levels(&room, &alice).await;
    assert_eq!(levels["users"][&bob.user_id], 100, "{levels}");

    harness.join(&room, &bob).await;
    let (status, body) = harness
        .set_state(&room, &bob, MEMBER, &bob.member_key(), &bob.joined())
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bob can join the call unaided: {body}"
    );
}

/// From v12 the creator's power is implicit and unnameable, so the
/// invitee becomes an additional creator instead -- the only reading of
/// "the same power level as the room creator" a v12 room can express, and
/// the one Synapse takes.
#[tokio::test]
async fn a_v12_trusted_private_chat_makes_the_invitee_an_additional_creator() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let room = harness
        .room(
            &alice,
            &json!({
                "room_version": "12",
                "preset": "trusted_private_chat",
                "invite": [bob.user_id],
            }),
        )
        .await;
    let (status, create) = harness.state(&room, &alice, "m.room.create", "").await;
    assert_eq!(status, StatusCode::OK, "{create}");
    assert_eq!(
        create["additional_creators"],
        json!([bob.user_id]),
        "{create}"
    );
    let levels = harness.power_levels(&room, &alice).await;
    assert_eq!(levels["users"], json!({}), "nobody is named: {levels}");

    harness.join(&room, &bob).await;
    let (status, body) = harness
        .set_state(&room, &bob, MEMBER, &bob.member_key(), &bob.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------------------------------------------------------------------------
// The lifecycle.

/// Element Call's order, end to end: the delayed leave first, then the
/// join. The join does not cancel the leave -- MSC4140 asks for no such
/// thing, and a switch that disarmed itself on the join would leave a
/// window with nothing pending. Heartbeats keep the membership; when they
/// stop, the leave fires, lands in the state, reaches everyone's `/sync`,
/// and reaches the client that scheduled it as a finalised delay.
#[tokio::test]
async fn a_delayed_leave_survives_the_join_and_fires_when_the_heartbeat_stops() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;
    let key = alice.member_key();

    let delay_id = harness
        .delayed_state(&room, &alice, MEMBER, &key, &json!({}), 1_500)
        .await;
    let (status, body) = harness
        .set_state(&room, &alice, MEMBER, &key, &alice.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bob_since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_since = harness.sync(&alice, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let pending = harness.pending(&alice).await;
    assert_eq!(
        pending.len(),
        1,
        "the join did not cancel the leave: {pending:?}"
    );
    assert_eq!(pending[0]["delay_id"].as_str(), Some(delay_id.as_str()));

    // Alive: four heartbeats over 1.6s, longer than the delay itself.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (status, body) = harness.act(&delay_id, &alice, "restart").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (_, content) = harness.state(&room, &alice, MEMBER, &key).await;
    assert_eq!(content, alice.joined(), "the heartbeat kept the membership");

    // Gone: no more heartbeats.
    harness
        .wait_for_member_state(&room, &bob, &key, &json!({}))
        .await;
    assert!(
        harness.pending(&alice).await.is_empty(),
        "the delay is spent"
    );

    // Bob sees the departure...
    let sync = harness.sync(&bob, Some(&bob_since)).await;
    let leave = room_events(&sync, &room)
        .into_iter()
        .find(|event| {
            event["type"] == MEMBER && event["state_key"] == key && event["content"] == json!({})
        })
        .unwrap_or_else(|| panic!("bob's sync carries the leave: {sync}"));
    assert_eq!(leave["sender"], alice.user_id);

    // ...and alice, who by construction was not there, is told what
    // happened and which event it became.
    let sync = harness.sync(&alice, Some(&alice_since)).await;
    let finalised = sync[FINALISED]
        .as_array()
        .unwrap_or_else(|| panic!("the fired leave is reported: {sync}"));
    let report = finalised
        .iter()
        .find(|report| report["delay_id"] == delay_id)
        .unwrap_or_else(|| panic!("the report names the delay: {finalised:?}"));
    assert_eq!(report["room_id"], room);
    assert_eq!(report["event_type"], MEMBER);
    assert_eq!(report["state_key"], key);
    assert_eq!(report["event_id"], leave["event_id"], "the same event");
    assert!(report["error"].is_null(), "{report}");
}

/// Hanging up: the client sends the leave it scheduled, now, and the
/// delay is consumed rather than left to fire a second time.
#[tokio::test]
async fn a_leave_the_client_sends_itself_spends_the_delay() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;
    let key = alice.member_key();

    let delay_id = harness
        .delayed_state(&room, &alice, MEMBER, &key, &json!({}), 60_000)
        .await;
    let (status, body) = harness
        .set_state(&room, &alice, MEMBER, &key, &alice.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = harness.act(&delay_id, &alice, "send").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, content) = harness.state(&room, &bob, MEMBER, &key).await;
    assert_eq!(content, json!({}), "left, immediately");
    assert!(harness.pending(&alice).await.is_empty());
    let (status, body) = harness.act(&delay_id, &alice, "restart").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "nothing left to restart: {body}"
    );
}

/// A membership whose sender has since left the room is refused when it
/// comes due, and the client hears that rather than nothing.
#[tokio::test]
async fn a_leave_that_fires_after_the_sender_left_the_room_is_reported_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;
    let key = bob.member_key();
    let since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let delay_id = harness
        .delayed_state(&room, &bob, MEMBER, &key, &json!({}), 500)
        .await;
    let (status, body) = harness
        .set_state(&room, &bob, MEMBER, &key, &bob.joined())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            &bob.token,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut report = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let sync = harness.sync(&bob, Some(&since)).await;
        if let Some(found) = sync[FINALISED]
            .as_array()
            .into_iter()
            .flatten()
            .find(|report| report["delay_id"] == delay_id)
        {
            report = Some(found.clone());
            break;
        }
    }
    let report = report.expect("the refused leave is reported");
    assert!(report["event_id"].is_null(), "{report}");
    assert!(
        report["error"].is_string(),
        "with the rule that refused it: {report}"
    );
    let (_, content) = harness.state(&room, &alice, MEMBER, &key).await;
    assert_eq!(content, bob.joined(), "and the state is what it was");
}

// ---------------------------------------------------------------------------
// To-device signalling.

/// Call setup is a burst of to-device invites between every pair of
/// participants (MSC3401). They travel on the per-device stream, in
/// order, and the room's timeline arrives beside them: a message sent
/// after the burst is in the same sync as the burst, not behind it.
#[tokio::test]
async fn a_to_device_burst_at_call_setup_does_not_stall_the_room_stream() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.call_room(&alice, &bob).await;
    let since = harness.sync(&bob, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    for seq in 0..SETUP_BURST {
        let (status, body) = harness
            .send(
                "PUT",
                &format!("/_matrix/client/v3/sendToDevice/m.call.invite/setup-{seq}"),
                &alice.token,
                &json!({
                    "messages": {
                        bob.user_id.clone(): {
                            bob.device_id.clone(): {
                                "conf_id": "",
                                "device_id": alice.device_id,
                                "dest_session_id": "bob-session",
                                "sender_session_id": "alice-session",
                                "seq": seq,
                                "call_id": format!("call-{seq}"),
                                "party_id": alice.device_id,
                                "offer": { "type": "offer", "sdp": "v=0" },
                                "version": "1",
                            },
                        },
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/after"),
            &alice.token,
            &json!({ "msgtype": "m.text", "body": "after the burst" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let sync = harness.sync(&bob, Some(&since)).await;
    assert!(
        room_events(&sync, &room)
            .iter()
            .any(|event| event["content"]["body"] == "after the burst"),
        "the room event is not queued behind the burst: {sync}"
    );

    // The burst arrives whole and in order, across as many syncs as the
    // server chooses to spread it over.
    let mut seqs: Vec<u64> = Vec::new();
    let mut token = since;
    for _ in 0..20 {
        let sync = harness.sync(&bob, Some(&token)).await;
        seqs.extend(
            sync["to_device"]["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|event| event["type"] == "m.call.invite")
                .filter_map(|event| event["content"]["seq"].as_u64()),
        );
        token = sync["next_batch"].as_str().unwrap().to_owned();
        if seqs.len() as u64 >= SETUP_BURST {
            break;
        }
    }
    assert_eq!(seqs, (0..SETUP_BURST).collect::<Vec<_>>());
}
