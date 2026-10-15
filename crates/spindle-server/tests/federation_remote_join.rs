//! Joining a room that lives on another server — two real Spindle
//! instances federating over TCP.
//!
//! This is the first test where both sides of the wire are us: server B
//! holds the room, server A walks `make_join`/`send_join` as the joining
//! server, seeds the room from the response, and afterwards ordinary
//! federation carries messages both ways. What the suite pins: the join
//! lands and is visible to clients of both servers, the seeded state is
//! the room's real state (topic, memberships), history flows to the
//! joiner, and a room nobody can vouch for is refused without a seeded
//! husk left behind.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One full homeserver on a real TCP listener, named by its own address.
struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        static TRACING: std::sync::Once = std::sync::Once::new();
        TRACING.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("spindle_server=debug")
                .try_init();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
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
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn public_room(&self, token: &str) -> String {
        self.public_room_at_version(token, None).await
    }

    async fn public_room_at_version(&self, token: &str, version: Option<&str>) -> String {
        let mut create = json!({});
        if let Some(version) = version {
            create["room_version"] = json!(version);
        }
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&create),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                Some(token),
                Some(&json!({ "join_rule": "public" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        room
    }

    /// A room whose join rule admits members of `allowed`.
    async fn restricted_room(&self, token: &str, allowed: &str) -> String {
        self.restricted_room_at_version(token, allowed, None).await
    }

    async fn restricted_room_at_version(
        &self,
        token: &str,
        allowed: &str,
        version: Option<&str>,
    ) -> String {
        let mut create = json!({});
        if let Some(version) = version {
            create["room_version"] = json!(version);
        }
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&create),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                Some(token),
                Some(&json!({
                    "join_rule": "restricted",
                    "allow": [{ "type": "m.room_membership", "room_id": allowed }],
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        room
    }

    /// Join a room this server may have to fetch from `via` first.
    async fn join_via(&self, room: &str, token: &str, via: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
            Some(token),
            Some(&json!({})),
        )
        .await
    }

    /// One member event as this server holds it, PDU and all.
    async fn member_event(&self, room: &str, token: &str, user_id: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "m.room.member" && event["state_key"] == json!(user_id))
            .unwrap_or_else(|| panic!("no member event for {user_id} in {body}"))
            .clone()
    }

    async fn say(&self, room: &str, token: &str, text: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{text}"),
                Some(token),
                Some(&json!({ "msgtype": "m.text", "body": text })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn redact(&self, room: &str, token: &str, target: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/redact/{0}/redact-{0}",
                    target.replace('/', "%2F")
                ),
                Some(token),
                Some(&json!({ "reason": "test" })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }

    async fn event(&self, room: &str, token: &str, event_id: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/event/{}",
                    event_id.replace('/', "%2F")
                ),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn joined_members(&self, room: &str, token: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["joined"].clone()
    }

    async fn messages(&self, room: &str, token: &str) -> Vec<String> {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| event["content"]["body"].as_str())
            .map(str::to_owned)
            .collect()
    }
}

/// Poll until `check` returns true or two seconds pass — federation
/// delivery is asynchronous by design.
async fn eventually(check: impl AsyncFnMut() -> bool) -> bool {
    eventually_within(40, check).await
}

/// Poll every 50 ms, up to `polls` times, until `check` returns true.
async fn eventually_within(polls: u32, mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..polls {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// Whether `text` reaches the joining member's backward pagination. The
/// history before a remote join is backfilled in the background (#461).
/// The loop waits a pacing interval of one second before its first chunk,
/// so this waits up to fifteen seconds.
async fn history_arrives(local: &Instance, room: &str, token: &str, text: &str) -> bool {
    eventually_within(300, async || {
        local.messages(room, token).await.contains(&text.to_owned())
    })
    .await
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_user_joins_a_room_on_another_server_and_both_sides_converge() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let room = remote.public_room(&alice).await;
    remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            Some(&alice),
            Some(&json!({ "topic": "the room's real topic" })),
        )
        .await;
    remote.say(&room, &alice, "before").await;
    // Two profile changes give alice three member events — the newest in
    // the state, the older two only in the auth chain — so seeding order
    // is observable: applied oldest-last, the room would show a stale name.
    for name in ["older name", "newest name"] {
        remote
            .request(
                reqwest::Method::PUT,
                &format!(
                    "/_matrix/client/v3/rooms/{room}/state/m.room.member/@alice:{}",
                    remote.name
                ),
                Some(&alice),
                Some(&json!({ "membership": "join", "displayname": name })),
            )
            .await;
    }

    let bob = local.register("bob").await;
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", remote.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["room_id"].as_str(), Some(room.as_str()));

    // Both servers see both members.
    let bob_id = format!("@bob:{}", local.name);
    let alice_id = format!("@alice:{}", remote.name);
    let local_members = local.joined_members(&room, &bob).await;
    assert!(local_members.get(&alice_id).is_some(), "{local_members}");
    assert!(local_members.get(&bob_id).is_some(), "{local_members}");
    assert_eq!(
        local_members[&alice_id]["display_name"], "newest name",
        "the final state wins over its auth-chain ancestors: {local_members}"
    );

    // The join took a stream row: bob's sync surfaces the room.
    let (status, sync) = local
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/sync?timeout=0",
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{sync}");
    assert!(
        sync["rooms"]["join"].get(&room).is_some(),
        "the joined room is in sync: {sync}"
    );
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(&bob_id)
                .is_some()
        })
        .await,
        "the resident server sees the joiner"
    );

    // The seeded state is the room's real state.
    let (status, topic) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{topic}");
    assert_eq!(topic["topic"], "the room's real topic");

    // `send_join` carries state and auth, but no timeline. The joining
    // server backfills the history before the join, so pagination reaches
    // it. Alice's two newer member events are seeded state, and the walk
    // passes through them to reach the message.
    assert!(
        history_arrives(&local, &room, &bob, "before").await,
        "pre-join history is available to the joining member"
    );

    // Ordinary federation now carries messages both ways.
    remote.say(&room, &alice, "from the resident side").await;
    assert!(
        eventually(async || {
            local
                .messages(&room, &bob)
                .await
                .contains(&"from the resident side".to_owned())
        })
        .await,
        "resident-side messages reach the joiner"
    );
    local.say(&room, &bob, "from the joining side").await;
    assert!(
        eventually(async || {
            remote
                .messages(&room, &alice)
                .await
                .contains(&"from the joining side".to_owned())
        })
        .await,
        "joiner-side messages reach the resident server"
    );
}

#[tokio::test]
async fn version_ten_remote_join_backfills_without_version_substitution() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({ "room_version": "10", "preset": "public_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    remote.say(&room, &alice, "version ten history").await;

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        history_arrives(&local, &room, &bob, "version ten history").await,
        "v10 history is verified and stored under v10 rules"
    );
}

/// The commonest join: an invite, then the join. The join's only
/// predecessor is the invite, which `send_join` seeds as current state.
/// The history before the invite is still fetched, in order.
#[tokio::test]
async fn a_join_after_an_invite_brings_the_history_before_the_invite() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({ "preset": "private_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    for text in ["first", "second", "third"] {
        remote.say(&room, &alice, text).await;
    }
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": format!("@bob:{}", local.name) })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        history_arrives(&local, &room, &bob, "first").await,
        "the history before the invite reaches the joiner"
    );
    // Backward pagination: newest first, with nothing invented between.
    let history = local.messages(&room, &bob).await;
    assert_eq!(history, ["third", "second", "first"], "{history:?}");
}

#[tokio::test]
async fn an_unjoinable_room_leaves_nothing_behind() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    // Invite-only, and bob holds no invite.
    let (_, body) = remote
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    let room = body["room_id"].as_str().unwrap().to_owned();

    let bob = local.register("bob").await;
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", remote.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_ne!(status, 200, "{body}");

    // No seeded husk: the room is still unknown here.
    let (status, body) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            Some(&bob),
            None,
        )
        .await;
    assert_ne!(status, 200, "{body}");
}

#[tokio::test]
async fn a_join_with_no_server_to_ask_is_a_clean_404() {
    let local = Instance::start().await;
    let bob = local.register("bob").await;
    // The room ID names this very server, so there is no one else to ask.
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/!nosuch:{}", local.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_restricted_room_admits_a_remote_member_of_a_room_it_allows() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let alice_id = format!("@alice:{}", remote.name);
    let bob_id = format!("@bob:{}", local.name);

    // The allowed room has to be one the *resident* server can see Bob in:
    // it is the resident that vouches, and it can only vouch for what it
    // holds. So Bob federates into the space first.
    let space = remote.public_room(&alice).await;
    let (status, body) = local.join_via(&space, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    let room = remote.restricted_room(&alice, &space).await;

    // Before this slice, `make_join` refused here: the room is not public
    // and Bob holds no invite, which is exactly the pair of cases a
    // restricted rule exists to add a third to.
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    // Both sides agree Bob is in, which means the resident authorized the
    // signed event and not merely the template it handed out.
    assert!(
        local
            .joined_members(&room, &bob)
            .await
            .get(&bob_id)
            .is_some(),
        "the joining server records the join"
    );
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(&bob_id)
                .is_some()
        })
        .await,
        "the resident server records the join"
    );

    // The nomination is the whole basis of the join, so it must be on the
    // event both servers hold -- not an understanding between them.
    for (side, event) in [
        ("joining", local.member_event(&room, &bob, &bob_id).await),
        (
            "resident",
            remote.member_event(&room, &alice, &bob_id).await,
        ),
    ] {
        assert_eq!(
            event["content"]["join_authorised_via_users_server"], alice_id,
            "the {side} server's copy names the authorising user: {event}"
        );
        // Two servers signed it, and they signed it for different reasons:
        // the joiner's server because the sender lives there, the
        // resident's because the nomination is a claim only it can make.
        // A peer checking this event asks for both keys.
        let signatures = event["signatures"]
            .as_object()
            .unwrap_or_else(|| panic!("the {side} server's copy has no signatures: {event}"));
        assert!(
            signatures.contains_key(&local.name),
            "the {side} copy carries the joining server's signature: {event}"
        );
        assert!(
            signatures.contains_key(&remote.name),
            "the {side} copy carries the authorising server's signature: {event}"
        );
    }
}

#[tokio::test]
async fn a_restricted_room_refuses_a_remote_stranger() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    // Bob never joins the space, so there is nothing to vouch for. The
    // refusal has to happen at `make_join`: handing out a template and
    // rejecting the signed event would tell the peer the join was possible.
    let space = remote.public_room(&alice).await;
    let room = remote.restricted_room(&alice, &space).await;

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_ne!(status, 200, "{body}");
    assert!(
        remote
            .joined_members(&room, &alice)
            .await
            .get(format!("@bob:{}", local.name).as_str())
            .is_none(),
        "no membership is left behind"
    );
}

/// Complement's `checkRestrictedRoom`, end to end, across two real servers.
///
/// Every step is here because a shorter version of this test passed twelve
/// times while the real suite failed. The two that mattered and were missing:
/// the displayname change Bob makes *after* joining, which Complement uses to
/// check that a join -> join transition ignores a client-supplied
/// `join_authorised_via_users_server`; and the join he makes immediately
/// after being invited, with no wait, which only works if the invite reached
/// his server's copy of the room rather than only its pending-invite row.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one sequence, told end to end")]
async fn the_whole_restricted_room_sequence_holds_across_two_servers() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let space = remote.public_room(&alice).await;
    let room = remote.restricted_room(&alice, &space).await;

    // 1. fail initially
    assert_ne!(local.join_via(&room, &bob, &remote.name).await.0, 200);

    // 2. succeed when joined to allowed room -- including the displayname
    // change Complement makes in both rooms, which is the step my earlier
    // replica dropped.
    assert_eq!(local.join_via(&space, &bob, &remote.name).await.0, 200);
    let (status, body) = local
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{space}/state/m.room.member/{bob_id}"),
            Some(&bob),
            Some(&json!({ "membership": "join", "displayname": "Bobby" })),
        )
        .await;
    assert_eq!(status, 200, "displayname in the allowed room: {body}");
    assert_eq!(local.join_via(&room, &bob, &remote.name).await.0, 200);
    let (status, body) = local
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{bob_id}"),
            Some(&bob),
            Some(&json!({
                "membership": "join",
                "displayname": "Bobby",
                "join_authorised_via_users_server": "unused",
            })),
        )
        .await;
    assert_eq!(status, 200, "displayname in the restricted room: {body}");

    // 3. fail when left allowed room
    for target in [&room, &space] {
        let (status, body) = local
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/rooms/{target}/leave"),
                Some(&bob),
                Some(&json!({})),
            )
            .await;
        assert_eq!(status, 200, "leaving {target}: {body}");
    }
    assert!(
        eventually(async || {
            remote
                .joined_members(&space, &alice)
                .await
                .get(bob_id.as_str())
                .is_none()
        })
        .await,
        "the allowed room's leave arrives"
    );
    assert_ne!(local.join_via(&room, &bob, &remote.name).await.0, 200);

    // 4. succeed when invited -- the step CI fails on
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "the invite is accepted: {body}");
    // Complement joins immediately after inviting, with no wait.
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "the join right after the invite: {body}");

    // 5. fail with mangled join rules -- and be judged against rules that
    // are current somewhere. Complement waits for nothing here beyond
    // alice seeing her own event, so neither does this: the leave, the
    // rejoin of the allowed room and the rule change are all in flight
    // against each other, which is the window #342 lives in.
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "leaving the room again: {body}");
    assert_eq!(local.join_via(&space, &bob, &remote.name).await.0, 200);
    let (status, body) = remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules/"),
            Some(&alice),
            Some(&json!({ "join_rule": "restricted", "allow": ["invalid"] })),
        )
        .await;
    assert_eq!(status, 200, "mangling the join rules: {body}");
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    if status == 200 {
        // What the joining server believed at the moment it said yes: the
        // two facts that decide the restricted rule.
        let (_, rules) = local
            .request(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules/"),
                Some(&bob),
                None,
            )
            .await;
        let member = local.member_event(&room, &bob, &bob_id).await;
        panic!(
            "a join the resident would refuse was answered locally: {body}\nrules: {rules}\nmember: {member}"
        );
    }
}

/// #342: a server that holds a room's copy but has no joined member left
/// in it is not a resident, so a join goes to a resident instead of being
/// answered from the stale copy. Here the copy says public while the
/// resident has moved to invite-only: the join must come back refused.
#[tokio::test]
async fn a_join_goes_remote_once_no_local_member_is_left() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let room = remote.public_room(&alice).await;

    // The local server joins, then leaves: it holds the copy but has no
    // joined member left in it.
    let first = local.register("first").await;
    assert_eq!(local.join_via(&room, &first, &remote.name).await.0, 200);
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            Some(&first),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "leaving: {body}");
    let first_id = format!("@first:{}", local.name);
    // The resident must see the leave first: while it still counts a
    // joined member here, the rule change below would fan out to the
    // stale copy and the test would prove nothing.
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(first_id.as_str())
                .is_none()
        })
        .await,
        "the resident sees the leave"
    );

    // The resident moves to invite-only. With no member left locally,
    // nothing carries this to the stale copy.
    let (status, body) = remote
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            Some(&alice),
            Some(&json!({ "join_rule": "invite" })),
        )
        .await;
    assert_eq!(status, 200, "restricting the room: {body}");

    // Answered from the stale copy this would be 200. Asked of the
    // resident it is refused.
    let second = local.register("second").await;
    let (status, body) = local.join_via(&room, &second, &remote.name).await;
    assert_eq!(status, 403, "the resident refuses: {body}");
}

#[tokio::test]
async fn a_room_at_a_version_this_server_creates_is_one_it_can_also_join() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(&json!({ "room_version": "12", "preset": "public_chat" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();
    // MSC4291: the ID is the create event's hash and names no server, so
    // `server_name` is the only thing that can point at the resident. There
    // is no domain in the ID to fall back on.
    assert!(!room.contains(':'), "{room}");
    remote.say(&room, &alice, "before the join").await;

    // This is what `/capabilities` promises when it lists v12 as available:
    // not that a room can be created at it, but that it is a room. Until
    // the `ver=` list stopped being one literal, no Spindle server could
    // join another Spindle server's v12 room -- the resident answered "12"
    // truthfully and the asker had said it spoke only 11.
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");

    let bob_id = format!("@bob:{}", local.name);
    assert!(
        local
            .joined_members(&room, &bob)
            .await
            .get(&bob_id)
            .is_some(),
        "the joining server records the join"
    );
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(&bob_id)
                .is_some()
        })
        .await,
        "the resident server records the join"
    );
    // The seeded state came from the resident's state and auth chain, which
    // at v12 includes a create event carrying no `room_id` at all -- the one
    // event whose shape MSC4291 changed. Reading it back proves the joining
    // server stored it under the right room rather than discarding it for
    // not naming one.
    let (status, create) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.create"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{create}");
    assert_eq!(create["room_version"], "12", "{create}");

    local.say(&room, &bob, "after the join").await;
    assert!(
        eventually(async || {
            remote
                .messages(&room, &alice)
                .await
                .contains(&"after the join".to_owned())
        })
        .await,
        "the joiner can write into the room it joined"
    );
}

/// Join, exchange events both ways and redact across two servers, at
/// exactly `version`.
///
/// Each legacy version is exercised at its actual version rather than by
/// proving only that createRoom accepts the name. The redaction matters
/// because its target moved in v11 (MSC2174): a v1–v10 redaction names its
/// target at the top level, and a server that put it in content would sign
/// an event no peer of that version can apply.
async fn join_exchange_and_redact_at(version: &str) {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let room = remote.public_room_at_version(&alice, Some(version)).await;
    let before = format!("before the v{version} join");
    remote.say(&room, &alice, &before).await;

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "v{version}: {body}");
    assert!(
        history_arrives(&local, &room, &bob, &before).await,
        "v{version}: the history before the join is backfilled"
    );
    let (status, create) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.create"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{create}");
    assert_eq!(create["room_version"], version, "{create}");

    let after = format!("after the v{version} join");
    let target = local.say(&room, &bob, &after).await;
    assert!(
        eventually(async || remote.messages(&room, &alice).await.contains(&after)).await,
        "the resident server accepted the v{version} event"
    );

    let redaction = remote.redact(&room, &alice, &target).await;
    let shape = remote.event(&room, &alice, &redaction).await;
    assert_eq!(shape["redacts"], target.as_str(), "v{version}: {shape}");
    assert!(shape["content"]["redacts"].is_null(), "v{version}: {shape}");
    assert!(
        eventually(async || remote.event(&room, &alice, &target).await["content"] == json!({}))
            .await,
        "the resident applied its v{version} redaction"
    );
    assert!(
        eventually(async || local.event(&room, &bob, &target).await["content"] == json!({})).await,
        "the joining server applied the federated v{version} redaction"
    );

    let back = format!("back across the v{version} room");
    remote.say(&room, &alice, &back).await;
    assert!(
        eventually(async || local.messages(&room, &bob).await.contains(&back)).await,
        "the joining server accepted the resident's v{version} event"
    );
}

/// Version 10 is the dominant legacy version in the migration corpus.
#[tokio::test]
async fn a_v10_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("10").await;
}

/// Version 9 rooms are in the migration corpus.
#[tokio::test]
async fn a_v9_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("9").await;
}

/// Version 8 sits between v7's knocks and v9's restricted-join redaction fix.
#[tokio::test]
async fn a_v8_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("8").await;
}

/// Version 7 is the version Complement's knock tests create; a v7
/// `send_join` was once refused with `M_BAD_JSON`.
#[tokio::test]
async fn a_v7_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("7").await;
}

/// Version 6 rooms are in the migration corpus, and it is the oldest
/// version this server serves.
#[tokio::test]
async fn a_v6_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("6").await;
}

/// Version 5 enforces key validity; the keys are fresh, so events verify.
#[tokio::test]
async fn a_v5_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("5").await;
}

/// Version 4 is the first with URL-safe hash IDs.
#[tokio::test]
async fn a_v4_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("4").await;
}

/// Version 3 names events by standard base64, so an ID may hold `/` and has
/// to be escaped in every URL path that carries it, `send_join` included.
#[tokio::test]
async fn a_v3_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("3").await;
}

/// Version 2 is version 1's event shape with state resolution v2.
#[tokio::test]
async fn a_v2_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("2").await;
}

/// Version 1 is in the migration corpus.
#[tokio::test]
async fn a_v1_room_can_be_joined_and_used_across_two_servers() {
    join_exchange_and_redact_at("1").await;
}

/// In a v1 room every event carries an ID its origin chose, and names its
/// parents by `[id, {"sha256": hash}]` pairs. The joining server names its
/// own join under its own name, and the pairs it writes pin the hashes the
/// resident computes.
#[tokio::test]
async fn v1_events_carry_their_names_and_hash_their_parents() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let room = remote.public_room_at_version(&alice, Some("1")).await;
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "{body}");
    local.say(&room, &bob, "named by the sender").await;

    let join = remote.member_event(&room, &alice, &bob_id).await;
    let join_id = join["event_id"].as_str().unwrap();
    assert!(
        join_id.ends_with(&format!(":{}", local.name)),
        "the joiner names its own join: {join}"
    );
    for field in ["prev_events", "auth_events"] {
        let edges = join[field].as_array().unwrap_or_else(|| panic!("{join}"));
        assert!(!edges.is_empty(), "{field}: {join}");
        for edge in edges {
            let pair = edge.as_array().unwrap_or_else(|| panic!("{field}: {join}"));
            assert!(pair[0].as_str().unwrap().starts_with('$'), "{edge}");
            assert!(pair[1]["sha256"].is_string(), "{edge}");
        }
    }

    let (status, messages) = local
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, 200, "{messages}");
    for event in messages["chunk"].as_array().unwrap() {
        let id = event["event_id"].as_str().unwrap();
        let server = id.split_once(':').map(|(_, server)| server).unwrap();
        let sender = event["sender"].as_str().unwrap();
        assert!(
            sender.ends_with(&format!(":{server}")),
            "a v1 event is named under its sender's server: {event}"
        );
    }
}

/// Room versions 1 and 2 let a server redact the events it named itself,
/// whatever the redacter's power: the rule compares the redaction's own ID
/// with its target's, which only a server that reads the top-level
/// `redacts` can apply. Bob holds no power in Alice's room.
#[tokio::test]
async fn a_v1_member_redacts_their_own_event_by_the_v1_rule() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let room = remote.public_room_at_version(&alice, Some("1")).await;
    assert_eq!(local.join_via(&room, &bob, &remote.name).await.0, 200);
    let target = local.say(&room, &bob, "regrettable").await;
    assert!(
        eventually(async || {
            remote
                .messages(&room, &alice)
                .await
                .contains(&"regrettable".to_owned())
        })
        .await
    );

    local.redact(&room, &bob, &target).await;
    assert!(
        eventually(async || local.event(&room, &bob, &target).await["content"] == json!({})).await,
        "bob's server applied his redaction"
    );
    assert!(
        eventually(async || remote.event(&room, &alice, &target).await["content"] == json!({}))
            .await,
        "the resident accepted the v1 same-server redaction"
    );
}

/// A restricted room at `version` admits a remote member of the room it
/// allows, through this server's nomination and countersignature.
async fn restricted_join_at(version: &str) {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let space = remote.public_room_at_version(&alice, Some(version)).await;
    assert_eq!(local.join_via(&space, &bob, &remote.name).await.0, 200);
    let room = remote
        .restricted_room_at_version(&alice, &space, Some(version))
        .await;

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "v{version}: {body}");
    assert!(
        eventually(async || {
            remote
                .joined_members(&room, &alice)
                .await
                .get(&bob_id)
                .is_some()
        })
        .await,
        "the v{version} resident records the restricted join"
    );
    let member = remote.member_event(&room, &alice, &bob_id).await;
    assert!(
        member["content"]["join_authorised_via_users_server"].is_string(),
        "v{version}: a restricted join names its authorising user: {member}"
    );
}

/// Restricted joins were the path that previously exposed version
/// substitution. Keep two-server regressions at every version that has them.
#[tokio::test]
async fn a_v10_restricted_room_admits_a_remote_member() {
    restricted_join_at("10").await;
}

#[tokio::test]
async fn a_v9_restricted_room_admits_a_remote_member() {
    restricted_join_at("9").await;
}

/// Version 8 introduced restricted joins, and its redaction algorithm does
/// not yet keep `join_authorised_via_users_server` (v9 fixed that). The
/// countersignature is over the redacted form all the same, so it must
/// verify without the field.
#[tokio::test]
async fn a_v8_restricted_room_admits_a_remote_member() {
    restricted_join_at("8").await;
}

/// Before v8 `restricted` is a join rule the version does not know, so it
/// admits nobody: no nomination is made and the join is refused, even for a
/// user in the room the rule names.
#[tokio::test]
async fn a_v6_room_does_not_honour_a_restricted_join_rule() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;

    let space = remote.public_room_at_version(&alice, Some("6")).await;
    assert_eq!(local.join_via(&space, &bob, &remote.name).await.0, 200);
    let room = remote
        .restricted_room_at_version(&alice, &space, Some("6"))
        .await;

    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 403, "a v6 restricted room admitted a join: {body}");
}

/// A third resident must fetch and verify both restricted-join signers.
#[tokio::test]
async fn a_third_server_receives_a_restricted_join_with_both_required_signatures() {
    for version in ["8", "9", "10", "12"] {
        let resident = Instance::start().await;
        let joining = Instance::start().await;
        let observer = Instance::start().await;
        let alice = resident.register("alice").await;
        let bob = joining.register("bob").await;
        let carol = observer.register("carol").await;
        let bob_id = format!("@bob:{}", joining.name);
        let space = resident.public_room(&alice).await;
        for (server, token) in [(&joining, &bob), (&observer, &carol)] {
            let (status, body) = server.join_via(&space, token, &resident.name).await;
            assert_eq!(status, 200, "v{version}: {body}");
        }
        let room = resident
            .restricted_room_at_version(&alice, &space, Some(version))
            .await;
        let (status, body) = observer.join_via(&room, &carol, &resident.name).await;
        assert_eq!(status, 200, "v{version}: {body}");
        let (status, body) = joining.join_via(&room, &bob, &resident.name).await;
        assert_eq!(status, 200, "v{version}: {body}");
        assert!(
            eventually(async || {
                observer
                    .joined_members(&room, &carol)
                    .await
                    .get(&bob_id)
                    .is_some()
            })
            .await,
            "v{version}: the third resident must accept the propagated join"
        );
        let event = observer.member_event(&room, &carol, &bob_id).await;
        assert_eq!(event["content"]["membership"], "join");
        assert_eq!(
            event["content"]["join_authorised_via_users_server"],
            format!("@alice:{}", resident.name)
        );
        let signatures = event["signatures"].as_object().unwrap();
        assert!(signatures.contains_key(&resident.name) && signatures.contains_key(&joining.name));
    }
}
