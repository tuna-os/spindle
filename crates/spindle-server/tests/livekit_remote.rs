//! The built-in `LiveKit` minter and users of other servers (#796).
//!
//! In a call across servers each participant publishes on their own
//! server's SFU and subscribes to everyone else's, so a remote user asks
//! this server's service for a token with an `OpenID` token from *their*
//! server. `lk-jwt-service` confirms that token at the server that issued
//! it (`openid/userinfo`, over federation) and grants a user outside its
//! full-access list join and subscribe, never publish, and never a room of
//! their own making. This file pins the built-in service to the same,
//! between two real Spindles over TCP with a stand-in SFU behind the first:
//! the grants, decoded; the refusals -- an unknown or expired token, a
//! server vouching for someone else's user, a user who is not in the room,
//! server names that point inward or are not server names at all -- each
//! checked to have reached nothing it should not; the negative cache and
//! the per-server rate limit; the operator's full-access list; and the
//! federation twin's grants, which are a remote user's like any other.

#[path = "support/mock_sfu.rs"]
mod mock_sfu;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hmac::{KeyInit as _, Mac as _};
use mock_sfu::{MockSfu, lk_hash};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const SECRET: &str = "not-the-signing-key";

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
    state: spindle_server::AppState,
}

struct Session {
    token: String,
    user_id: String,
    device_id: String,
}

/// A listener bound before its server is built, so another server's
/// configuration can name it.
struct Bound {
    listener: tokio::net::TcpListener,
    name: String,
}

async fn bind() -> Bound {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    Bound { listener, name }
}

impl Instance {
    /// A Spindle on `bound`, federating over plain http with loopback
    /// peers allowed, rate limits off, and `extra` appended to its config.
    fn launch(bound: Bound, extra: &str) -> Instance {
        Self::launch_with(
            bound,
            &format!(
                "[ratelimit]\nenabled = false\n\
                 [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n{extra}"
            ),
        )
    }

    fn launch_with(bound: Bound, config: &str) -> Instance {
        let Bound { listener, name } = bound;
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config =
            spindle_server::Config::parse(&format!("[server]\nname = \"{name}\"\n{config}"))
                .unwrap();
        let (app, state) = spindle_server::app_with_state(
            config,
            store,
            Arc::new(spindle_server::metrics::Metrics::new()),
        )
        .expect("the app builds");
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
            state,
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name));
        for (name, value) in headers {
            request = request.header(*name, *value);
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

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (u16, Value) {
        let authorization = token.map(|token| format!("Bearer {token}"));
        let headers: Vec<(&str, &str)> = authorization
            .as_deref()
            .map(|value| vec![("authorization", value)])
            .unwrap_or_default();
        self.request(reqwest::Method::POST, path, &headers, Some(body))
            .await
    }

    async fn register(&self, username: &str) -> Session {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/register",
                None,
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        Session {
            token: body["access_token"].as_str().unwrap().to_owned(),
            user_id: body["user_id"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn public_room(&self, session: &Session) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                Some(&session.token),
                &json!({ "preset": "public_chat" }),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn join_via(&self, room: &str, session: &Session, via: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/join/{room}?server_name={via}"),
                Some(&session.token),
                &json!({}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    /// The `OpenID` token as `/openid/request_token` hands it out, whole.
    async fn openid_token(&self, session: &Session) -> Value {
        let (status, body) = self
            .post(
                &format!(
                    "/_matrix/client/v3/user/{}/openid/request_token",
                    session.user_id
                ),
                Some(&session.token),
                &json!({}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    /// What Element Call posts to the legacy endpoint.
    async fn sfu_get(&self, room: &str, openid_token: &Value, device_id: &str) -> (u16, Value) {
        self.post(
            "/_spindle/rtc/livekit/sfu/get",
            None,
            &json!({
                "room": room,
                "openid_token": openid_token,
                "device_id": device_id,
            }),
        )
        .await
    }

    /// What Element Call posts to the Matrix 2.0 endpoint.
    async fn get_token(
        &self,
        room: &str,
        openid_token: &Value,
        session: &Session,
        member_id: &str,
    ) -> (u16, Value) {
        self.post(
            "/_spindle/rtc/livekit/get_token",
            None,
            &json!({
                "room_id": room,
                "slot_id": "m.call#ROOM",
                "openid_token": openid_token,
                "member": {
                    "id": member_id,
                    "claimed_user_id": session.user_id,
                    "claimed_device_id": session.device_id,
                },
            }),
        )
        .await
    }
}

/// `[rtc.livekit]` for the server under test, against `sfu`, with `extra`
/// lines in the section.
fn livekit(sfu: &MockSfu, extra: &str) -> String {
    format!(
        "[rtc.livekit]\nurl = \"{}\"\nkey = \"APIkey\"\nsecret = \"{SECRET}\"\n{extra}",
        sfu.url
    )
}

/// The minting server with a stand-in SFU, the remote user's server, a
/// room on the first that a user of the second has joined, and the remote
/// user's `OpenID` token from their own server.
struct Call {
    sfu: MockSfu,
    here: Instance,
    there: Instance,
    room: String,
    bob: Session,
    bob_openid: Value,
}

async fn call(full_access_there: bool) -> Call {
    let sfu = MockSfu::start();
    let (here, there) = (bind().await, bind().await);
    let extra = if full_access_there {
        format!("full_access_servers = [\"{}\"]\n", there.name)
    } else {
        String::new()
    };
    let here = Instance::launch(here, &livekit(&sfu, &extra));
    let there = Instance::launch(there, "");
    let alice = here.register("alice").await;
    let room = here.public_room(&alice).await;
    let bob = there.register("bob").await;
    there.join_via(&room, &bob, &here.name).await;
    let bob_openid = there.openid_token(&bob).await;
    assert_eq!(bob_openid["matrix_server_name"], there.name);
    Call {
        sfu,
        here,
        there,
        room,
        bob,
        bob_openid,
    }
}

/// A JWT's claims, after checking it is signed with `SECRET`.
fn claims(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWT: {jwt}");
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    assert!(
        mac.verify_slice(&base64url_decode(parts[2])).is_ok(),
        "signed with the SFU's secret"
    );
    serde_json::from_slice(&base64url_decode(parts[1])).unwrap()
}

fn base64url_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut accumulator = 0_u32;
        for (index, &symbol) in chunk.iter().enumerate() {
            let value = ALPHABET.iter().position(|&c| c == symbol).unwrap();
            accumulator |= u32::try_from(value).unwrap() << (18 - 6 * index);
        }
        out.extend_from_slice(&accumulator.to_be_bytes()[1..chunk.len()]);
    }
    out
}

/// A stand-in federation peer that answers `openid/userinfo` with `status`
/// and `body`, and counts how often it was asked.
struct Peer {
    name: String,
    hits: Arc<AtomicUsize>,
}

async fn peer(status: u16, body: Value) -> Peer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/_matrix/federation/v1/openid/userinfo",
        axum::routing::get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            let body = body.to_string();
            async move {
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    [("content-type", "application/json")],
                    body,
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Peer { name, hits }
}

/// The issue's case: a user of another server, joined to the room, gets a
/// token confirmed by their server that joins and subscribes but does not
/// publish, in the room `lk-jwt-service` would name -- and no room is made
/// on the SFU on their say-so. On both endpoints Element Call uses.
#[tokio::test]
async fn a_remote_participant_is_minted_a_subscribe_only_token() {
    let call = call(false).await;

    let (status, body) = call
        .here
        .sfu_get(&call.room, &call.bob_openid, &call.bob.device_id)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["url"], call.sfu.url);
    let legacy = claims(body["jwt"].as_str().unwrap());
    assert_eq!(legacy["iss"], "APIkey");
    assert_eq!(
        legacy["sub"],
        format!("{}:{}", call.bob.user_id, call.bob.device_id)
    );
    assert_eq!(
        legacy["video"],
        json!({
            "room": lk_hash(&[&call.room, "m.call#ROOM"]),
            "roomJoin": true,
            "roomCreate": false,
            "canPublish": false,
            "canSubscribe": true,
            "canUpdateOwnMetadata": true,
        }),
        "lk-jwt-service's grants for a user outside its full-access list"
    );

    let (status, body) = call
        .here
        .get_token(&call.room, &call.bob_openid, &call.bob, "bob-member")
        .await;
    assert_eq!(status, 200, "{body}");
    let matrix_2 = claims(body["jwt"].as_str().unwrap());
    assert_eq!(
        matrix_2["sub"],
        lk_hash(&[&call.bob.user_id, &call.bob.device_id, "bob-member"])
    );
    assert_eq!(matrix_2["video"]["canPublish"], false);
    assert_eq!(matrix_2["video"]["canSubscribe"], true);
    assert_eq!(
        matrix_2["video"]["room"],
        lk_hash(&[&call.room, "m.call#ROOM"])
    );

    assert!(
        call.sfu.created().is_empty(),
        "a remote user's token makes no room: {:?}",
        call.sfu.created()
    );
}

/// A server the operator trusts gets what this server's own users get:
/// publish, and the room made on the SFU.
#[tokio::test]
async fn a_full_access_server_publishes() {
    let call = call(true).await;

    let (status, body) = call
        .here
        .sfu_get(&call.room, &call.bob_openid, &call.bob.device_id)
        .await;

    assert_eq!(status, 200, "{body}");
    let claims = claims(body["jwt"].as_str().unwrap());
    assert_eq!(claims["video"]["canPublish"], true);
    let created = call.sfu.created();
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(created[0].name, lk_hash(&[&call.room, "m.call#ROOM"]));
}

/// Confirmed or not, a remote user is checked against the room like a
/// local one: not joined in this server's view, no token.
#[tokio::test]
async fn a_remote_user_not_in_the_room_is_refused() {
    let call = call(false).await;
    let carol = call.there.register("carol").await;
    let carol_openid = call.there.openid_token(&carol).await;

    let (status, body) = call
        .here
        .sfu_get(&call.room, &carol_openid, &carol.device_id)
        .await;

    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
}

/// The token is the credential, and its server is the judge of it: an
/// invented one and an expired one are both refused there, and refused
/// here in `lk-jwt-service`'s words.
#[tokio::test]
async fn an_unknown_or_expired_remote_token_is_refused() {
    let call = call(false).await;
    let expired = spindle_server::openid::OpenId::new(Arc::clone(&call.there.state.store))
        .issue_at(&call.bob.user_id, 0, 1_000)
        .unwrap();

    for (access_token, what) in [
        ("syo_invented_0000".to_owned(), "an invented token"),
        (expired.access_token, "an expired token"),
    ] {
        let mut openid = call.bob_openid.clone();
        openid["access_token"] = json!(access_token);
        let (status, body) = call
            .here
            .sfu_get(&call.room, &openid, &call.bob.device_id)
            .await;
        assert_eq!(status, 401, "{what}: {body}");
        assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{what}: {body}");
    }
}

/// A server vouches for its own users and nobody else's: a server that
/// confirms a token as belonging to a user of a different server is not
/// believed, even when that user is in the room.
#[tokio::test]
async fn a_server_naming_another_servers_user_is_refused() {
    let call = call(false).await;
    let liar = peer(200, json!({ "sub": call.bob.user_id })).await;
    let mut openid = call.bob_openid.clone();
    openid["matrix_server_name"] = json!(liar.name);

    let (status, body) = call
        .here
        .sfu_get(&call.room, &openid, &call.bob.device_id)
        .await;

    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{body}");
    assert_eq!(liar.hits.load(Ordering::SeqCst), 1, "it was asked");
}

/// The server name arrives in a request body from anyone. Names that
/// point this server inward are refused by the federation client's address
/// rules before a connection is made, and strings that are not server
/// names at all are refused before anything is asked; in every case the
/// listener on the inward address hears nothing.
#[tokio::test]
async fn server_names_that_point_inward_are_never_contacted() {
    let sfu = MockSfu::start();
    // No `allow_internal`: loopback is off limits, as in production.
    let here = Instance::launch_with(
        bind().await,
        &format!(
            "[ratelimit]\nenabled = false\n[federation]\ninsecure_http = true\n{}",
            livekit(&sfu, "")
        ),
    );
    let inward = peer(200, json!({ "sub": "@victim:whatever" })).await;
    let port = inward.name.rsplit_once(':').unwrap().1;
    let alice = here.register("alice").await;
    let room = here.public_room(&alice).await;

    for name in [
        inward.name.clone(),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
        "169.254.169.254".to_owned(),
        "10.0.0.1".to_owned(),
        format!("127.0.0.1:{port}/_matrix/federation/v1/openid/userinfo?x="),
        format!("user@127.0.0.1:{port}"),
        String::new(),
    ] {
        let openid = json!({
            "access_token": "anything",
            "token_type": "Bearer",
            "matrix_server_name": name,
            "expires_in": 3600,
        });
        let (status, body) = here.sfu_get(&room, &openid, "DEVICE").await;
        assert_eq!(status, 401, "{name:?}: {body}");
        assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{name:?}: {body}");
    }
    assert_eq!(
        inward.hits.load(Ordering::SeqCst),
        0,
        "nothing reached the inward listener"
    );
}

/// A server that could not be asked is not asked again for a while: every
/// request naming it in that time is refused at once rather than after
/// another attempt. A server that answered "no" is not remembered -- the
/// next token may be good.
#[tokio::test]
async fn an_unreachable_server_is_not_asked_again_at_once() {
    let call = call(false).await;
    let broken = peer(502, json!({})).await;
    let refusing = peer(401, json!({ "errcode": "M_UNKNOWN_TOKEN" })).await;

    for _ in 0..3 {
        for server in [&broken, &refusing] {
            let mut openid = call.bob_openid.clone();
            openid["matrix_server_name"] = json!(server.name);
            let (status, body) = call
                .here
                .sfu_get(&call.room, &openid, &call.bob.device_id)
                .await;
            assert_eq!(status, 401, "{body}");
        }
    }

    assert_eq!(
        broken.hits.load(Ordering::SeqCst),
        1,
        "a failing server is asked once"
    );
    assert_eq!(
        refusing.hits.load(Ordering::SeqCst),
        3,
        "an answering server is asked every time"
    );
}

/// Remote minting is limited per server, before that server is asked:
/// sixty a minute, and past them a 429 with nothing sent.
#[tokio::test]
async fn remote_minting_is_rate_limited_per_server() {
    let sfu = MockSfu::start();
    let here = Instance::launch_with(
        bind().await,
        &format!(
            "[federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n{}",
            livekit(&sfu, "")
        ),
    );
    let refusing = peer(401, json!({ "errcode": "M_UNKNOWN_TOKEN" })).await;
    let other = peer(401, json!({ "errcode": "M_UNKNOWN_TOKEN" })).await;
    let ask = |server: &str| {
        json!({
            "access_token": "anything",
            "matrix_server_name": server,
        })
    };

    for _ in 0..60 {
        let (status, body) = here
            .sfu_get("!room:elsewhere", &ask(&refusing.name), "DEVICE")
            .await;
        assert_eq!(status, 401, "{body}");
    }
    let (status, body) = here
        .sfu_get("!room:elsewhere", &ask(&refusing.name), "DEVICE")
        .await;

    assert_eq!(status, 429, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
    assert_eq!(
        refusing.hits.load(Ordering::SeqCst),
        60,
        "the refused request was not sent"
    );
    let (status, body) = here
        .sfu_get("!room:elsewhere", &ask(&other.name), "DEVICE")
        .await;
    assert_eq!(status, 401, "another server's budget is its own: {body}");
}

/// The federation twin (MSC4195) mints for whoever a signed origin vouches
/// for -- and what it mints is a remote user's token like the service's:
/// subscribe-only and making no room, unless the origin has full access.
#[tokio::test]
async fn the_federation_twin_grants_a_remote_users_token() {
    for full_access in [false, true] {
        let call = call(full_access).await;
        let path = "/_matrix/federation/v1/rtc/livekit/get_token";
        let body = json!({
            "room_id": call.room,
            "user_id": call.bob.user_id,
            "device_id": call.bob.device_id,
        });
        let authorization = call
            .there
            .state
            .federation
            .sign_request("POST", path, &call.here.name, Some(&body))
            .unwrap();

        let (status, answer) = call
            .here
            .request(
                reqwest::Method::POST,
                path,
                &[("authorization", &authorization)],
                Some(&body),
            )
            .await;

        assert_eq!(status, 200, "{answer}");
        let claims = claims(answer["jwt"].as_str().unwrap());
        assert_eq!(
            claims["video"]["canPublish"], full_access,
            "full access: {full_access}"
        );
        assert_eq!(
            claims["video"]["room"],
            lk_hash(&[&call.room, "m.call#ROOM"])
        );
        assert_eq!(
            call.sfu.created().len(),
            usize::from(full_access),
            "a room only for full access"
        );
    }
}
