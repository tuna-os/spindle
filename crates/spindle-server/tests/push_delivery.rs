//! Push delivery — a real Spindle instance over TCP, delivering to a mock
//! push gateway.
//!
//! What the suite pins: an event a reader's rules say to notify about
//! arrives at the gateway their pusher named, as the spec's notification
//! body, and never at the sender's own; the rules decide, and a device
//! that asked for `event_id_only` gets exactly that; a failed delivery is
//! retried under the same event and a `rejected` pushkey is forgotten; a
//! `MatrixRTC` ring (MSC4075) reaches the members it mentions at high
//! priority and a decline (MSC4310) reaches nobody; and a gateway inside
//! this server's network is refused at registration.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// The mock gateway: records every notification it is sent, can be told
/// to fail the next N requests with a 500 first, and can be told which
/// pushkeys to report `rejected`.
#[derive(Clone, Default)]
struct Gateway {
    deliveries: Arc<Mutex<Vec<Value>>>,
    failures_left: Arc<Mutex<u32>>,
    rejecting: Arc<Mutex<Vec<String>>>,
}

impl Gateway {
    async fn serve() -> (Self, String) {
        let gateway = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/_matrix/push/v1/notify",
            listener.local_addr().unwrap().port()
        );
        let state = gateway.clone();
        let app = axum::Router::new()
            .route(
                "/_matrix/push/v1/notify",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<Gateway>,
                     request: Request<Body>| async move {
                        let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                            .await
                            .unwrap_or_default();
                        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        {
                            let mut failures = state.failures_left.lock().unwrap();
                            if *failures > 0 {
                                *failures -= 1;
                                state.deliveries.lock().unwrap().push(body);
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    axum::Json(json!({})),
                                );
                            }
                        }
                        state.deliveries.lock().unwrap().push(body);
                        let rejected = state.rejecting.lock().unwrap().clone();
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(json!({ "rejected": rejected })),
                        )
                    },
                ),
            )
            .with_state(gateway.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (state, url)
    }

    fn deliveries(&self) -> Vec<Value> {
        self.deliveries.lock().unwrap().clone()
    }

    fn fail_next(&self, count: u32) {
        *self.failures_left.lock().unwrap() = count;
    }

    fn reject(&self, pushkeys: &[&str]) {
        *self.rejecting.lock().unwrap() = pushkeys.iter().map(|k| (*k).to_owned()).collect();
    }

    /// Wait until at least `count` deliveries have been recorded.
    async fn wait_for(&self, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let deliveries = self.deliveries();
            if deliveries.len() >= count {
                return deliveries;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} deliveries arrived: {deliveries:?}",
                deliveries.len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Give the loop long enough to have delivered anything it was going
    /// to, then assert nothing more arrived.
    async fn settle(&self, expected: usize) {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let deliveries = self.deliveries();
        assert_eq!(deliveries.len(), expected, "{deliveries:?}");
    }
}

/// One homeserver on a real TCP listener.
struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        Self::start_with(true).await
    }

    async fn start_with(allow_loopback: bool) -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let allow = if allow_loopback {
            "allow_internal = [\"127.0.0.0/8\"]\n"
        } else {
            ""
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\nretry_base_ms = 25\n[push]\n{allow}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            client: reqwest::Client::new(),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name))
            .header("authorization", format!("Bearer {token}"));
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }

    async fn register(&self, username: &str) -> (String, String) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                "",
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["user_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn set_pusher(&self, token: &str, pushkey: &str, data: Value) -> (u16, Value) {
        self.request(
            reqwest::Method::POST,
            "/_matrix/client/v3/pushers/set",
            token,
            Some(&json!({
                "kind": "http",
                "app_id": "org.example.app",
                "pushkey": pushkey,
                "app_display_name": "App",
                "device_display_name": "Phone",
                "lang": "en",
                "data": data,
            })),
        )
        .await
    }

    async fn pushers(&self, token: &str) -> Vec<Value> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/pushers",
                token,
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["pushers"].as_array().cloned().unwrap_or_default()
    }

    async fn create_room(&self, token: &str, invite: &[&str]) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                token,
                Some(&json!({ "invite": invite, "name": "The room" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn join(&self, token: &str, room_id: &str) {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/rooms/{room_id}/join"),
                token,
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    async fn send(&self, token: &str, room_id: &str, event_type: &str, content: &Value) -> String {
        let txn = format!("txn{}", rand_suffix());
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn}"),
                token,
                Some(content),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, token: &str, room_id: &str, text: &str) -> String {
        self.send(
            token,
            room_id,
            "m.room.message",
            &json!({ "msgtype": "m.text", "body": text }),
        )
        .await
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// A room alice created with bob joined, both registered, bob with a
/// pusher -- and the invite that summoned bob already delivered, so the
/// caller's count starts after it.
async fn alice_and_bob(
    hs: &Instance,
    gateway: &Gateway,
    gateway_url: &str,
) -> (String, String, String, String) {
    let (alice, _) = hs.register("alice").await;
    let (bob, bob_id) = hs.register("bob").await;
    let (status, body) = hs
        .set_pusher(&bob, "bobkey", json!({ "url": gateway_url }))
        .await;
    assert_eq!(status, 200, "{body}");
    let room = hs.create_room(&alice, &[&bob_id]).await;
    hs.join(&bob, &room).await;
    gateway.wait_for(1).await;
    (alice, bob, bob_id, room)
}

#[tokio::test]
async fn a_message_reaches_the_other_members_gateway_as_the_specs_body() {
    let (gateway, url) = Gateway::serve().await;
    let hs = Instance::start().await;
    let (alice, bob, _, room) = alice_and_bob(&hs, &gateway, &url).await;
    // Alice has a pusher too, on the same gateway, so that "never to the
    // sender" is tested by pushkey rather than by the absence of a pusher.
    let (status, body) = hs
        .set_pusher(&alice, "alicekey", json!({ "url": url }))
        .await;
    assert_eq!(status, 200, "{body}");

    let event_id = hs.say(&alice, &room, "hello bob").await;
    let deliveries = gateway.wait_for(2).await;
    let notification = &deliveries[1]["notification"];
    assert_eq!(notification["event_id"], event_id);
    assert_eq!(notification["room_id"], room);
    assert_eq!(notification["type"], "m.room.message");
    assert!(
        notification["sender"]
            .as_str()
            .unwrap()
            .starts_with("@alice:")
    );
    assert_eq!(notification["content"]["body"], "hello bob");
    assert_eq!(notification["room_name"], "The room");
    // Two members: `.m.rule.room_one_to_one` claims it, with a sound, and
    // a sound is what makes a notification worth waking the device for.
    assert_eq!(notification["prio"], "high");
    // Bob has one unread event: this one.
    assert_eq!(notification["counts"]["unread"], 1);
    let devices = notification["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["app_id"], "org.example.app");
    assert_eq!(devices[0]["pushkey"], "bobkey");
    // The spec: `data` is the pusher's data minus the url.
    assert!(devices[0]["data"].get("url").is_none());
    assert_eq!(devices[0]["tweaks"], json!({ "sound": "default" }));

    // Bob's own message goes to alice's device and never to bob's.
    hs.say(&bob, &room, "hello alice").await;
    let deliveries = gateway.wait_for(3).await;
    let devices = deliveries[2]["notification"]["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["pushkey"], "alicekey");
    gateway.settle(3).await;
}

#[tokio::test]
async fn the_rules_decide_and_event_id_only_strips_the_body() {
    let (gateway, url) = Gateway::serve().await;
    let hs = Instance::start().await;
    let (alice, bob, _, room) = alice_and_bob(&hs, &gateway, &url).await;
    let (carol, carol_id) = hs.register("carol").await;
    let (status, body) = hs
        .set_pusher(
            &carol,
            "carolkey",
            json!({ "url": url, "format": "event_id_only" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = hs
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            Some(&json!({ "user_id": carol_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    hs.join(&carol, &room).await;
    // Carol's invite and join have produced traffic; let it drain.
    gateway.wait_for(1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = gateway.deliveries().len();

    // Bob silences the catch-all rule: an ordinary message no longer
    // notifies him.
    let (status, body) = hs
        .request(
            reqwest::Method::PUT,
            "/_matrix/client/v3/pushrules/global/underride/.m.rule.message/enabled",
            &bob,
            Some(&json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let event_id = hs.say(&alice, &room, "only carol hears this").await;
    let deliveries = gateway.wait_for(before + 1).await;
    let notification = &deliveries[before]["notification"];
    let devices = notification["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1, "{notification}");
    assert_eq!(devices[0]["pushkey"], "carolkey");
    // event_id_only: what its name says, and nothing that would tell the
    // gateway what was said.
    assert_eq!(notification["event_id"], event_id);
    assert_eq!(notification["room_id"], room);
    assert!(notification["counts"]["unread"].is_number());
    assert!(notification.get("content").is_none(), "{notification}");
    assert!(notification.get("sender").is_none());
    assert!(notification.get("type").is_none());
    gateway.settle(before + 1).await;
}

#[tokio::test]
async fn a_failed_delivery_is_retried_and_a_rejected_pushkey_is_removed() {
    let (gateway, url) = Gateway::serve().await;
    let hs = Instance::start().await;
    let (alice, bob, _, room) = alice_and_bob(&hs, &gateway, &url).await;

    gateway.fail_next(2);
    let event_id = hs.say(&alice, &room, "are you there").await;
    let deliveries = gateway.wait_for(4).await;
    // Two failures and a success, all the same event: retried, not
    // re-judged into something else, and not given up on.
    for delivery in &deliveries[1..] {
        assert_eq!(delivery["notification"]["event_id"], event_id);
    }
    gateway.settle(4).await;

    // The gateway reports bob's device gone: the registration goes with it.
    gateway.reject(&["bobkey"]);
    hs.say(&alice, &room, "still there?").await;
    gateway.wait_for(5).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !hs.pushers(&bob).await.is_empty() {
        assert!(Instant::now() < deadline, "the rejected pusher was kept");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // And nothing further is sent for a device that no longer exists.
    hs.say(&alice, &room, "hello?").await;
    gateway.settle(5).await;
}

#[tokio::test]
async fn a_ring_reaches_who_it_mentions_at_high_priority_and_a_decline_reaches_nobody() {
    let (gateway, url) = Gateway::serve().await;
    let hs = Instance::start().await;
    let (alice, bob, bob_id, room) = alice_and_bob(&hs, &gateway, &url).await;
    let (carol, carol_id) = hs.register("carol").await;
    let (status, body) = hs
        .set_pusher(&carol, "carolkey", json!({ "url": url }))
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = hs
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            Some(&json!({ "user_id": carol_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    hs.join(&carol, &room).await;
    gateway.wait_for(1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = gateway.deliveries().len();

    // MSC4075: a ring is routed by `m.mentions`, so the default mention
    // rule is what makes a fresh account's phone ring -- with a highlight,
    // which is what makes the gateway wake the device.
    let ring = json!({
        "application": {
            "type": "m.call",
            "notification_type": "ring",
            "sender_ts": 1_752_583_130_365_u64,
            "lifetime": 30_000,
        },
        "m.text": [{ "body": "Call started by alice" }],
        "m.mentions": { "user_ids": [bob_id] },
        "m.relates_to": { "rel_type": "m.reference", "event_id": "$member:example" },
    });
    let ring_id = hs
        .send(&alice, &room, "org.matrix.msc4075.rtc.notification", &ring)
        .await;
    let deliveries = gateway.wait_for(before + 1).await;
    let notification = &deliveries[before]["notification"];
    assert_eq!(notification["event_id"], ring_id);
    assert_eq!(notification["type"], "org.matrix.msc4075.rtc.notification");
    assert_eq!(notification["prio"], "high", "{notification}");
    let devices = notification["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["pushkey"], "bobkey");
    assert_eq!(devices[0]["tweaks"]["highlight"], true);
    // Carol was not mentioned: her phone stays quiet.
    gateway.settle(before + 1).await;

    // MSC4310: a decline carries no mention and must not push by default.
    hs.send(
        &bob,
        &room,
        "org.matrix.msc4310.rtc.decline",
        &json!({ "m.relates_to": { "rel_type": "m.reference", "event_id": ring_id } }),
    )
    .await;
    gateway.settle(before + 1).await;

    // An @room ring from someone allowed to ring the room reaches everyone
    // but the caller.
    let mut room_ring = ring.clone();
    room_ring["m.mentions"] = json!({ "room": true });
    hs.send(&alice, &room, "m.rtc.notification", &room_ring)
        .await;
    let deliveries = gateway.wait_for(before + 3).await;
    let mut notified: Vec<String> = deliveries[before + 1..]
        .iter()
        .map(|d| {
            d["notification"]["devices"][0]["pushkey"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    notified.sort();
    assert_eq!(notified, ["bobkey", "carolkey"]);
    for delivery in &deliveries[before + 1..] {
        assert_eq!(delivery["notification"]["prio"], "high");
    }
    gateway.settle(before + 3).await;
}

#[tokio::test]
async fn an_invite_reaches_the_invitee_before_they_are_a_member() {
    let (gateway, url) = Gateway::serve().await;
    let hs = Instance::start().await;
    let (alice, _) = hs.register("alice").await;
    let (bob, bob_id) = hs.register("bob").await;
    let (status, body) = hs.set_pusher(&bob, "bobkey", json!({ "url": url })).await;
    assert_eq!(status, 200, "{body}");

    let room = hs.create_room(&alice, &[&bob_id]).await;
    let deliveries = gateway.wait_for(1).await;
    let notification = &deliveries[0]["notification"];
    assert_eq!(notification["room_id"], room);
    assert_eq!(notification["type"], "m.room.member");
    assert_eq!(notification["content"]["membership"], "invite");
    assert_eq!(notification["user_is_target"], true);
    // `.m.rule.invite_for_me` carries a sound, which is high priority.
    assert_eq!(notification["prio"], "high");
    assert_eq!(notification["devices"][0]["tweaks"]["sound"], "default");
    gateway.settle(1).await;
}

#[tokio::test]
async fn a_gateway_inside_the_network_is_refused_at_registration() {
    let hs = Instance::start_with(false).await;
    let (bob, _) = hs.register("bob").await;
    // A loopback literal, with nothing opening the range: the server
    // would never deliver there, so it says so now.
    let (status, body) = hs
        .set_pusher(
            &bob,
            "bobkey",
            json!({ "url": "http://127.0.0.1:1/_matrix/push/v1/notify" }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
    // The cloud metadata service, the canonical target.
    let (status, _) = hs
        .set_pusher(
            &bob,
            "bobkey",
            json!({ "url": "http://169.254.169.254/_matrix/push/v1/notify" }),
        )
        .await;
    assert_eq!(status, 400);
    // A URL that is not a push gateway at all.
    let (status, body) = hs
        .set_pusher(
            &bob,
            "bobkey",
            json!({ "url": "https://push.example.org/hook" }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
    assert!(hs.pushers(&bob).await.is_empty());
    // A public hostname on the spec's path is what a real client sends.
    let (status, body) = hs
        .set_pusher(
            &bob,
            "bobkey",
            json!({ "url": "https://push.example.org/_matrix/push/v1/notify" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}
