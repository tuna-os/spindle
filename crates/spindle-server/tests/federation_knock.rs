//! Knocking on a room that lives on another server — two real Spindle
//! instances federating over TCP.
//!
//! `make_knock`/`send_knock` were served from the day federation landed, and
//! the local half of `POST /knock` from the slice before this one, so both
//! ends existed and nothing connected them: a user could knock on a room
//! their own server already held, and on nothing else. Every knock worth
//! making is on a room somewhere else.
//!
//! What separates this from the join handshake, and what these tests are
//! really about: a join ends with the joining server *holding the room* —
//! `send_join` returns the state and the auth chain to seed it from. A knock
//! ends with it holding nothing. The knocker is not a member, no peer will
//! send us the room's events, and `send_knock` returns only a stripped view.
//! So the knocking server has to render a room out of a side record, and
//! that record has to be readable as a question rather than as an answer.

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
             [federation]\ninsecure_http = true\nretry_base_ms = 50\n",
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

    /// A named room whose join rule is `rule`.
    ///
    /// The name matters: it is the one piece of the stripped state a knocker
    /// can point at to say *which* door they are waiting outside, so a knock
    /// section that arrives without it is not usable by a client even when
    /// the membership is right.
    async fn room_named(&self, token: &str, name: &str, rule: &str) -> String {
        let (status, body) = self
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(&json!({ "name": name })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .request(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
                Some(token),
                Some(&json!({ "join_rule": rule })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        room
    }

    /// Knock on a room this server may have to reach through `via`.
    async fn knock_via(
        &self,
        room: &str,
        token: &str,
        via: &str,
        reason: Option<&str>,
    ) -> (u16, Value) {
        let body = reason.map_or_else(|| json!({}), |reason| json!({ "reason": reason }));
        self.request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/knock/{room}?server_name={via}"),
            Some(token),
            Some(&body),
        )
        .await
    }

    async fn sync(&self, token: &str) -> Value {
        let (status, body) = self
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/sync?timeout=0",
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// One member event as this server holds it.
    async fn member_state(&self, room: &str, token: &str, user_id: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{user_id}"),
            Some(token),
            None,
        )
        .await
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

/// The whole handshake: knock lands on the resident, and the knocker's own
/// server can show what it did.
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one story, told end to end")]
async fn a_user_knocks_on_a_room_that_lives_on_another_server() {
    let resident = Instance::start().await;
    let asking = Instance::start().await;

    let alice = resident.register("alice").await;
    let room = resident
        .room_named(&alice, "Behind the door", "knock")
        .await;

    let bob = asking.register("bob").await;
    let bob_id = format!("@bob:{}", asking.name);
    let (status, body) = asking
        .knock_via(&room, &bob, &resident.name, Some("let me in"))
        .await;
    assert_eq!(status, 200, "the knock was refused: {body}");
    assert_eq!(body["room_id"], json!(room));

    // The resident holds the room, so its copy is the one that decides
    // whether the knock happened at all. Asserting only on the knocker's
    // own sync would pass on a server that recorded a knock it never sent.
    let (status, member) = resident.member_state(&room, &alice, &bob_id).await;
    assert_eq!(
        status, 200,
        "the resident has no member event for bob: {member}"
    );
    assert_eq!(member["membership"], json!("knock"), "{member}");
    assert_eq!(
        member["reason"],
        json!("let me in"),
        "the knocker's reason did not survive the handshake: {member}"
    );

    // And the knocker's own server can render it: a knock section, with the
    // stripped state `send_knock` returned. This is the half that has no
    // room log behind it -- the asking server is not in the room and never
    // will be unless somebody answers.
    let sync = asking.sync(&bob).await;
    let knock = &sync["rooms"]["knock"][&room];
    assert!(knock.is_object(), "no knock section for the room: {sync}");
    let events = knock["knock_state"]["events"].as_array().unwrap();
    assert!(
        events.iter().any(|event| event["type"] == "m.room.name"),
        "the stripped state does not say which room is being waited on: {events:?}"
    );

    // Not an invite and not a join. A client that read this as an invite
    // would offer an accept button for a room nobody has agreed to admit
    // bob to, which is the one mistake this shape exists to prevent.
    assert!(sync["rooms"]["invite"][&room].is_null(), "{sync}");
    assert!(sync["rooms"]["join"][&room].is_null(), "{sync}");
}

/// The answer arrives over federation and supersedes the question.
#[tokio::test]
async fn an_invite_answers_a_knock_that_crossed_a_server_boundary() {
    let resident = Instance::start().await;
    let asking = Instance::start().await;

    let alice = resident.register("alice").await;
    let room = resident
        .room_named(&alice, "Behind the door", "knock")
        .await;

    let bob = asking.register("bob").await;
    let bob_id = format!("@bob:{}", asking.name);
    let (status, body) = asking
        .knock_via(&room, &bob, &resident.name, Some("please"))
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = resident
        .request(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(&alice),
            Some(&json!({ "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, 200, "the invite was refused: {body}");

    // The knock row and the invite row are separate keys, so "the invite
    // arrived" and "the knock is gone" are two facts, not one. Both are
    // asserted: a knock left standing beside its own answer would show bob
    // a room he is waiting outside of and inside at the same time.
    let landed = eventually(async || {
        let sync = asking.sync(&bob).await;
        sync["rooms"]["invite"][&room].is_object() && sync["rooms"]["knock"][&room].is_null()
    })
    .await;
    assert!(
        landed,
        "the invite never superseded the knock: {}",
        asking.sync(&bob).await
    );
}

/// A room that does not knock says so, in its own words.
///
/// The status is the point. The asking server has nothing to add — it asked
/// on bob's behalf and the room said no — so relaying 403 is the honest
/// answer. A 502 would tell the client the request never landed and invite
/// it to retry something that will be refused every time, and that is
/// exactly what a naive "try every candidate, then give up" loop produces.
#[tokio::test]
async fn a_room_elsewhere_that_does_not_take_knocks_refuses_in_its_own_words() {
    let resident = Instance::start().await;
    let asking = Instance::start().await;

    let alice = resident.register("alice").await;
    let room = resident.room_named(&alice, "No knocking", "invite").await;

    let bob = asking.register("bob").await;
    let (status, body) = asking.knock_via(&room, &bob, &resident.name, None).await;
    assert_eq!(status, 403, "expected the room's own refusal: {body}");
    assert_eq!(body["errcode"], json!("M_FORBIDDEN"), "{body}");

    // Nothing was recorded on the way to being refused.
    let sync = asking.sync(&bob).await;
    assert!(sync["rooms"]["knock"][&room].is_null(), "{sync}");
}

/// A knock with nowhere to go is a 404, not a 502.
///
/// Without `server_name` and with no domain in the room ID to fall back on,
/// there is no server to ask. Saying "no server admitted the knock" would
/// describe a conversation that never happened.
#[tokio::test]
async fn a_knock_on_an_unknown_room_with_no_route_says_there_is_nowhere_to_ask() {
    let asking = Instance::start().await;
    let bob = asking.register("bob").await;

    let (status, body) = asking
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/knock/!nowhere",
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("server_name"),
        "the refusal does not say what is missing: {body}"
    );
}
