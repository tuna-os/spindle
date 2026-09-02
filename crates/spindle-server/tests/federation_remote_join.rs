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
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({})),
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
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({})),
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
async fn eventually(mut check: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..40 {
        if check().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
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
    assert_eq!(status, 200, "PROBE invite: {body}");
    // Complement joins immediately after inviting, with no wait.
    let (status, body) = local.join_via(&room, &bob, &remote.name).await;
    assert_eq!(status, 200, "PROBE join right after the invite: {body}");
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
