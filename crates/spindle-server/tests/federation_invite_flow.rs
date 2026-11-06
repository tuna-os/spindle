//! Inviting a user who lives on another server — two real Spindle
//! instances federating over TCP.
//!
//! The invite is the one event with two authors: built and signed by the
//! inviter's server, co-signed by the invitee's over `v2/invite`, and only
//! then part of the room. What the suite pins: the invited user sees the
//! invite on their own server with enough stripped state to render it,
//! accepting it works with no `via` hint because the inviting server is
//! remembered as the room's known address, and an invite the target's
//! server never co-signed never enters the room.

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
        Self::start_with("[ratelimit]\nenabled = false\n").await
    }

    async fn start_with(ratelimit: &str) -> Instance {
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
            "[server]\nname = \"{name}\"\n{ratelimit}\
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

    async fn named_room(&self, token: &str, name: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({ "name": name })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn sync(&self, token: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/sync",
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
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
async fn an_invited_user_on_another_server_sees_the_invite_and_accepts_it() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    // A private room: nothing but the invite admits bob.
    let room = remote.named_room(&alice, "the reading circle").await;

    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "the handshake succeeded: {body}");

    // The invite entered the room on the inviter's side: bob's membership
    // is real state there, which only the co-signed event can be.
    let (status, body) = remote
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{bob_id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["membership"].as_str(), Some("invite"));

    // Bob's own server shows the invite, with enough stripped state to
    // render it: the room's name and who is asking.
    let sync = local.sync(&bob).await;
    let invite = &sync["rooms"]["invite"][&room];
    assert!(!invite.is_null(), "the invite is in bob's sync: {sync}");
    let events = invite["invite_state"]["events"].as_array().unwrap();
    let has_name = events.iter().any(|event| {
        event["type"] == "m.room.name" && event["content"]["name"] == "the reading circle"
    });
    let has_invite = events.iter().any(|event| {
        event["type"] == "m.room.member"
            && event["state_key"] == json!(bob_id)
            && event["content"]["membership"] == json!("invite")
    });
    assert!(has_name, "the room's name renders: {events:?}");
    assert!(has_invite, "the ask itself renders: {events:?}");

    // Accepting needs no `via`: the inviting server is the remembered
    // address of a room this server has never held.
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}"),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "the invite admits bob: {body}");

    // Both sides converge on the join.
    assert!(
        eventually(async || {
            let (_, members) = remote
                .request(
                    reqwest::Method::GET,
                    &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
                    Some(&alice),
                    None,
                )
                .await;
            members["joined"][&bob_id].is_object()
        })
        .await,
        "the inviter's server sees bob joined"
    );
    let sync = local.sync(&bob).await;
    assert!(
        sync["rooms"]["join"][&room].is_object(),
        "the room moved from invite to join: {sync}"
    );
    assert!(
        sync["rooms"]["invite"][&room].is_null(),
        "and the invite is gone: {sync}"
    );
}

#[tokio::test]
async fn an_invite_nobody_cosigns_never_enters_the_room() {
    let remote = Instance::start().await;
    let alice = remote.register("alice").await;
    let room = remote.named_room(&alice, "unreachable guest").await;

    // Port 9 answers nothing; the invitee's server never co-signs.
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": "@ghost:127.0.0.1:9" })),
        )
        .await;
    assert_eq!(status, 502, "the invite fails loudly: {body}");

    // And fails completely: no half-invite haunts the room's state.
    let (status, _) = remote
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/@ghost:127.0.0.1:9"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, 404, "no membership was written");
}

#[tokio::test]
async fn an_invite_for_a_user_the_server_does_not_have_is_refused() {
    let remote = Instance::start().await;
    let local = Instance::start().await;
    let alice = remote.register("alice").await;
    let room = remote.named_room(&alice, "ghost hunt").await;

    // The domain is right, the user does not exist: the invitee's server
    // refuses to vouch, and the refusal reaches the inviting client.
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": format!("@nobody:{}", local.name) })),
        )
        .await;
    assert_eq!(status, 502, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("did not accept")),
        "the refusal names the peer: {body}"
    );
}

#[tokio::test]
async fn servers_already_in_the_room_hear_about_the_invite() {
    let origin = Instance::start().await;
    let bystander = Instance::start().await;
    let invited = Instance::start().await;

    let alice = origin.register("alice").await;
    let carol = bystander.register("carol").await;
    let bob = invited.register("bob").await;
    let bob_id = format!("@bob:{}", invited.name);

    // Carol's server is in the room before bob is invited...
    let room = origin.named_room(&alice, "the widening circle").await;
    let (status, body) = origin
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            Some(&alice),
            Some(&json!({ "join_rule": "public" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = bystander
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{room}?server_name={}", origin.name),
            Some(&carol),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = origin
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    // Quiet on bob's server: he was invited, not joined.
    let sync = invited.sync(&bob).await;
    assert!(!sync["rooms"]["invite"][&room].is_null(), "{sync}");

    // ...so the co-signed invite reaches carol's copy of the room like any
    // other event: each server fans out what it originates.
    assert!(
        eventually(async || {
            let (status, body) = bystander
                .request(
                    reqwest::Method::GET,
                    &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{bob_id}"),
                    Some(&carol),
                    None,
                )
                .await;
            status == 200 && body["membership"] == json!("invite")
        })
        .await,
        "carol's server heard about bob's invite"
    );
}

#[tokio::test]
async fn a_rejected_invite_leaves_both_sides_clean() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let room = remote.named_room(&alice, "declined with thanks").await;
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let sync = local.sync(&bob).await;
    assert!(!sync["rooms"]["invite"][&room].is_null(), "{sync}");

    // Bob rejects: /leave on a room his server holds no log for walks
    // make_leave/send_leave against the inviting server.
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/leave"),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "the rejection succeeds: {body}");

    // Gone from bob's sync at once...
    let sync = local.sync(&bob).await;
    assert!(
        sync["rooms"]["invite"][&room].is_null(),
        "the invite stopped appearing: {sync}"
    );

    // ...and the room's real state on the inviting server records the
    // leave, which only the send_leave handshake can have delivered.
    assert!(
        eventually(async || {
            let (status, body) = remote
                .request(
                    reqwest::Method::GET,
                    &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{bob_id}"),
                    Some(&alice),
                    None,
                )
                .await;
            status == 200 && body["membership"] == json!("leave")
        })
        .await,
        "the inviter's room state shows the rejection"
    );

    // Rejected is not forbidden forever: alice may ask again.
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "a re-invite after rejection works: {body}");
    // The invite reaches bob's server over federation, through the
    // inviter's outbox, after the inviter has already answered alice: one
    // sync taken at once can land before the PDU does, and did, on a busy
    // runner (two CI runs on unrelated branches). Poll, as the rejection's
    // own federation leg above is polled.
    assert!(
        eventually(async || {
            let sync = local.sync(&bob).await;
            !sync["rooms"]["invite"][&room].is_null()
        })
        .await,
        "the new invite renders"
    );
}

#[tokio::test]
async fn an_invite_revoked_by_the_room_stops_haunting_the_invitee() {
    let remote = Instance::start().await;
    let local = Instance::start().await;

    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);

    let room = remote.named_room(&alice, "changed our minds").await;
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let sync = local.sync(&bob).await;
    assert!(!sync["rooms"]["invite"][&room].is_null(), "{sync}");

    // Alice withdraws the invite: a kick, from a room bob's server holds
    // no log for. The leave event fans out to bob's domain over /send.
    let (status, body) = remote
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    assert!(
        eventually(async || {
            let sync = local.sync(&bob).await;
            sync["rooms"]["invite"][&room].is_null()
        })
        .await,
        "the revoked invite stops appearing in bob's sync"
    );
}

#[tokio::test]
async fn a_leave_template_for_a_stranger_is_refused() {
    // No membership, no template: the resident server refuses to hand a
    // departure kit for a user who was never invited or joined. This is
    // asserted through the public flow — a /leave for a room the server
    // never heard of and holds no invite for is a clean error, not a
    // fabricated federation departure.
    let local = Instance::start().await;
    let bob = local.register("bob").await;
    let (status, body) = local
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/!nowhere:{}/leave", local.name),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_ne!(status, 200, "leaving nothing is refused: {body}");
}

/// An invite from another server spends the invitee's budget like a local
/// one (#741): past it, this server refuses to co-sign, so the invite never
/// reaches the user or the room, while someone else here can still be
/// invited.
#[tokio::test]
async fn invites_from_another_server_spend_the_invitees_budget() {
    let remote = Instance::start().await;
    let local = Instance::start_with(
        "[ratelimit]\ninvites_per_target = { per_second = 0.001, burst = 1 }\n",
    )
    .await;
    let alice = remote.register("alice").await;
    let bob = local.register("bob").await;
    local.register("carol").await;
    let first = remote.named_room(&alice, "first").await;
    let second = remote.named_room(&alice, "second").await;
    let invite = async |room: &str, user: &str| {
        remote
            .request(
                reqwest::Method::POST,
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                Some(&alice),
                Some(&json!({ "user_id": format!("@{user}:{}", local.name) })),
            )
            .await
    };

    let (status, body) = invite(&first, "bob").await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = invite(&second, "bob").await;
    assert_eq!(status, 502, "the peer refused to co-sign: {body}");
    let (status, body) = invite(&second, "carol").await;
    assert_eq!(status, 200, "the budget is bob's alone: {body}");

    let sync = local.sync(&bob).await;
    assert!(!sync["rooms"]["invite"][&first].is_null(), "{sync}");
    assert!(sync["rooms"]["invite"][&second].is_null(), "{sync}");
}

/// An inviting server that is not a Spindle: it serves its key and signs
/// what it sends, and nothing else.
struct ForeignInviter {
    _dir: TempDir,
    name: String,
    key: spindle_server::signing::ServerKey,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ForeignInviter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn canonical(value: &Value) -> ruma::CanonicalJsonObject {
    let Ok(ruma::CanonicalJsonValue::Object(object)) =
        ruma::CanonicalJsonValue::try_from(value.clone())
    else {
        unreachable!("the tests build objects")
    };
    object
}

impl ForeignInviter {
    async fn start() -> Self {
        let dir = TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let key = spindle_server::signing::ServerKey::load_or_create(&store).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = listener.local_addr().unwrap().to_string();
        let mut document = canonical(&json!({
            "server_name": name,
            "valid_until_ts": 4_000_000_000_000_u64,
            "verify_keys": { key.key_id(): { "key": key.public_key_base64() } },
        }));
        ruma::signatures::sign_json(&name, key.pair(), &mut document).unwrap();
        let document = serde_json::to_value(document).unwrap();
        let app = axum::Router::new().route(
            "/_matrix/key/v2/server",
            axum::routing::get(move || {
                let document = document.clone();
                async move { axum::Json(document) }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            _dir: dir,
            name,
            key,
            task,
        }
    }

    /// PUT `body` to `uri` on `destination`, signed as this server.
    async fn put(&self, destination: &str, uri: &str, body: &Value) -> (u16, Value) {
        let mut request = canonical(&json!({
            "method": "PUT",
            "uri": uri,
            "origin": self.name,
            "destination": destination,
            "content": body,
        }));
        ruma::signatures::sign_json(&self.name, self.key.pair(), &mut request).unwrap();
        let signature = request["signatures"].as_object().unwrap()[&self.name]
            .as_object()
            .unwrap()[&self.key.key_id()]
            .as_str()
            .unwrap()
            .to_owned();
        let response = reqwest::Client::new()
            .put(format!("http://{destination}{uri}"))
            .header(
                "authorization",
                format!(
                    "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"{}\",sig=\"{signature}\"",
                    self.name,
                    self.key.key_id()
                ),
            )
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }
}

/// Synapse's `invite_room_state` names the room and the inviter but not
/// the invite itself: Synapse adds the invitee's own membership when its
/// own `/sync` serves the invite. A Spindle that served the inviter's list
/// as it came gave its user an invite with no `invite` in it, which Element
/// Web does not list at all, so an invite from a Synapse user never showed
/// (#795, found by Element Call's rig with Synapse in the second seat).
#[tokio::test]
async fn an_invite_whose_stripped_state_leaves_out_the_invite_still_renders() {
    let inviter = ForeignInviter::start().await;
    let local = Instance::start().await;
    let bob = local.register("bob").await;
    let bob_id = format!("@bob:{}", local.name);
    let alice_id = format!("@alice:{}", inviter.name);
    let room = format!("!synapse-room:{}", inviter.name);

    let event = spindle_core::Pdu::sign(
        ruma::RoomVersionId::V10,
        canonical(&json!({
            "type": "m.room.member",
            "room_id": room,
            "sender": alice_id,
            "state_key": bob_id,
            "content": { "membership": "invite", "is_direct": true },
            "origin_server_ts": 1_700_000_000_000_u64,
            "depth": 4,
            "auth_events": [],
            "prev_events": [],
        })),
        &inviter.name,
        inviter.key.pair(),
    )
    .unwrap();
    let event_id = event.event_id().as_str().to_owned();
    let body = json!({
        "room_version": "10",
        "event": serde_json::to_value(event.canonical()).unwrap(),
        // What Synapse sends: the room and the inviter's own membership.
        "invite_room_state": [
            {
                "type": "m.room.create", "state_key": "", "sender": alice_id,
                "content": { "creator": alice_id, "room_version": "10" },
            },
            {
                "type": "m.room.join_rules", "state_key": "", "sender": alice_id,
                "content": { "join_rule": "invite" },
            },
            {
                "type": "m.room.member", "state_key": alice_id, "sender": alice_id,
                "content": { "membership": "join", "displayname": "alice" },
            },
        ],
    });
    let (status, answer) = inviter
        .put(
            &local.name,
            &format!("/_matrix/federation/v2/invite/{room}/{event_id}"),
            &body,
        )
        .await;
    assert_eq!(status, 200, "the invite is co-signed: {answer}");

    let sync = local.sync(&bob).await;
    let events = sync["rooms"]["invite"][&room]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("the invite is in bob's sync: {sync}"))
        .clone();
    let asks: Vec<&Value> = events
        .iter()
        .filter(|event| event["type"] == "m.room.member" && event["state_key"] == json!(bob_id))
        .collect();
    assert_eq!(asks.len(), 1, "one membership for bob: {events:?}");
    assert_eq!(asks[0]["content"]["membership"], json!("invite"));
    assert_eq!(asks[0]["content"]["is_direct"], json!(true));
    assert_eq!(asks[0]["sender"], json!(alice_id));
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "m.room.member" && event["state_key"] == json!(alice_id)),
        "the inviter's own membership is kept: {events:?}"
    );
}
