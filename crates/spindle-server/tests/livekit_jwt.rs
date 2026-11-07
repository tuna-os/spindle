//! The built-in `LiveKit` JWT service (#38, MSC4195): who gets a token,
//! for what, and for how long.
//!
//! A token here is a credential for a server this one never talks to. The
//! SFU checks the signature and the grants and asks nobody, so everything
//! that scopes the token has to be decided at mint time, and this file is
//! that decision pinned: a token is minted only for a room the user is
//! joined to *now*, its identity is the user and device that asked, its
//! window is the one the operator set, and its signature is one the SFU's
//! secret would verify. A user who has left gets nothing -- the test #38
//! asks for by name -- and a token already minted is bounded, which is the
//! most a stateless credential can promise.
//!
//! The contract is `lk-jwt-service`'s, so a client cannot tell the two
//! apart, and the discovery test pins that the service advertises itself
//! the way the external one would be advertised. So are its room names and
//! Matrix 2.0 identities, and its habit of creating a full-access user's
//! room through the SFU's API: the harness runs a stand-in SFU for that.
//! Users of other servers are `livekit_remote.rs`'s.

#[path = "support/mock_sfu.rs"]
mod mock_sfu;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{KeyInit as _, Mac as _};
use mock_sfu::{MockSfu, lk_hash};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// The SFU address the configurations below name; the harness swaps it for
/// its stand-in's.
const SFU: &str = "wss://sfu.example.org";

const LIVEKIT: &str = r#"
[rtc]
foci = [
    { type = "livekit", livekit_service_url = "https://external.example.org/jwt" },
]
[rtc.livekit]
url = "wss://sfu.example.org"
key = "APIkey"
secret = "not-the-signing-key"
"#;

const SERVICE_URL: &str = "https://example.org/_spindle/rtc/livekit";
const SFU_GET: &str = "/_spindle/rtc/livekit/sfu/get";
const GET_TOKEN: &str = "/_spindle/rtc/livekit/get_token";

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
    sfu: MockSfu,
}

struct Session {
    user_id: String,
    device_id: String,
    access_token: String,
}

impl Harness {
    fn with(rtc: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let sfu = MockSfu::start();
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{}",
            rtc.replace(SFU, &sfu.url)
        ))
        .expect("the configuration is valid");
        let app =
            spindle_server::app(config, Arc::clone(&store)).expect("a signing key is established");
        Self {
            _dir: dir,
            store,
            app,
            sfu,
        }
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

    async fn post(&self, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.call(request.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn register(&self, username: &str) -> Session {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/register",
                None,
                json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Session {
            user_id: body["user_id"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
            access_token: body["access_token"].as_str().unwrap().to_owned(),
        }
    }

    async fn create_room(&self, session: &Session) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                Some(&session.access_token),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn invite(&self, room: &str, session: &Session, user_id: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                Some(&session.access_token),
                json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn membership(&self, room: &str, session: &Session, action: &str) {
        let (status, body) = self
            .post(
                &format!("/_matrix/client/v3/rooms/{room}/{action}"),
                Some(&session.access_token),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{action}: {body}");
    }

    /// The `OpenID` token as `/openid/request_token` hands it out, whole.
    async fn openid_token(&self, session: &Session) -> Value {
        let (status, body) = self
            .post(
                &format!(
                    "/_matrix/client/v3/user/{}/openid/request_token",
                    session.user_id
                ),
                Some(&session.access_token),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// What Element Call posts to the legacy endpoint, field for field.
    async fn sfu_get(
        &self,
        room: &str,
        openid_token: Value,
        device_id: &str,
    ) -> (StatusCode, Value) {
        self.post(
            SFU_GET,
            None,
            json!({
                "room": room,
                "openid_token": openid_token,
                "device_id": device_id,
            }),
        )
        .await
    }

    /// What Element Call posts to the Matrix 2.0 endpoint, field for field.
    async fn get_token(
        &self,
        room: &str,
        openid_token: Value,
        session: &Session,
        member_id: &str,
    ) -> (StatusCode, Value) {
        self.post(
            GET_TOKEN,
            None,
            json!({
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

    async fn transports(&self, token: &str) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/_matrix/client/v1/rtc/transports")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rtc_transports"].clone()
    }

    async fn well_known(&self) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/.well-known/matrix/client")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

/// A JWT taken apart: its header, its claims, and whether the signature
/// is the one `secret` produces over exactly those bytes.
struct Jwt {
    header: Value,
    claims: Value,
    signed: bool,
}

fn decode_jwt(jwt: &str, secret: &str) -> Jwt {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWT has three parts: {jwt}");
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    let signed = mac.verify_slice(&base64url_decode(parts[2])).is_ok();
    Jwt {
        header: serde_json::from_slice(&base64url_decode(parts[0])).unwrap(),
        claims: serde_json::from_slice(&base64url_decode(parts[1])).unwrap(),
        signed,
    }
}

/// RFC 7515's unpadded base64url, read back. Written here rather than
/// borrowed from the server, so the test does not agree with the code by
/// sharing its mistakes.
fn base64url_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let value = |symbol: u8| -> u32 {
        u32::try_from(
            ALPHABET
                .iter()
                .position(|&candidate| candidate == symbol)
                .unwrap_or_else(|| panic!("{symbol:?} is not base64url")),
        )
        .unwrap()
    };
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut accumulator = 0_u32;
        for (index, &symbol) in chunk.iter().enumerate() {
            accumulator |= value(symbol) << (18 - 6 * index);
        }
        let bytes = accumulator.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The service advertises itself as a transport, ahead of the operator's,
/// on both surfaces -- because a client that cannot find it cannot use it.
#[tokio::test]
async fn the_service_is_advertised_first_on_both_surfaces() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;

    let transports = harness.transports(&alice.access_token).await;
    let well_known = harness.well_known().await;

    assert_eq!(
        transports,
        json!([
            { "type": "livekit", "livekit_service_url": SERVICE_URL },
            { "type": "livekit", "livekit_service_url": "https://external.example.org/jwt" },
        ]),
        "the built-in service leads, the operator's list follows in its order"
    );
    assert_eq!(
        well_known["org.matrix.msc4143.rtc_foci"], transports,
        "well-known and the endpoint agree"
    );
}

/// The whole flow, as Element Call drives it: `OpenID` token, then the SFU
/// token, scoped to the room and the device that asked -- in the room
/// `lk-jwt-service` would have put the call in, which this server has made
/// on the SFU before handing the token over.
#[tokio::test]
async fn a_joined_member_is_minted_a_token_scoped_to_that_room() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let before = now_secs();
    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;
    let after = now_secs();

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["url"], harness.sfu.url, "the SFU's own address");
    let jwt = decode_jwt(body["jwt"].as_str().unwrap(), "not-the-signing-key");
    assert!(jwt.signed, "signed with LiveKit's secret and nothing else");
    assert_eq!(jwt.header, json!({ "alg": "HS256", "typ": "JWT" }));
    assert_eq!(jwt.claims["iss"], "APIkey");
    assert_eq!(
        jwt.claims["sub"],
        format!("{}:{}", alice.user_id, alice.device_id),
        "the identity Element Call matches participants by"
    );
    let alias = lk_hash(&[&room, "m.call#ROOM"]);
    assert_eq!(
        jwt.claims["video"]["room"], alias,
        "scoped to the room asked for, named as lk-jwt-service names it"
    );
    assert_eq!(jwt.claims["video"]["roomJoin"], true);
    assert_eq!(jwt.claims["video"]["canPublish"], true);
    assert_eq!(jwt.claims["video"]["canSubscribe"], true);
    assert_eq!(
        jwt.claims["video"]["roomCreate"], false,
        "creating is also deleting, and a participant may do neither"
    );
    let nbf = jwt.claims["nbf"].as_u64().unwrap();
    let exp = jwt.claims["exp"].as_u64().unwrap();
    assert!((before..=after).contains(&nbf), "not before now: {nbf}");
    assert_eq!(exp - nbf, 900, "the default window, fifteen minutes");

    let created = harness.sfu.created();
    assert_eq!(created.len(), 1, "the room is made on the SFU: {created:?}");
    assert_eq!(created[0].name, alias);
    assert_eq!(
        (
            &created[0].body["empty_timeout"],
            &created[0].body["departure_timeout"]
        ),
        (&json!(300), &json!(20)),
        "lk-jwt-service's timeouts"
    );
    let admin = decode_jwt(&created[0].bearer, "not-the-signing-key");
    assert!(admin.signed, "the room API is asked with the SFU's own key");
    assert_eq!(admin.claims["iss"], "APIkey");
    assert_eq!(
        admin.claims["video"],
        json!({ "room": alias, "roomCreate": true }),
        "the admin token creates that one room and does nothing else"
    );
}

/// The Matrix 2.0 endpoint Element Call asks first: the identity is the
/// hash of user, device and member ID the client computes for itself, and
/// the room is the slot's.
#[tokio::test]
async fn the_matrix_2_endpoint_mints_the_hashed_identity() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness
        .get_token(&room, openid.clone(), &alice, "member-1")
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let jwt = decode_jwt(body["jwt"].as_str().unwrap(), "not-the-signing-key");
    assert!(jwt.signed);
    assert_eq!(
        jwt.claims["sub"],
        lk_hash(&[&alice.user_id, &alice.device_id, "member-1"])
    );
    assert_eq!(
        jwt.claims["video"]["room"],
        lk_hash(&[&room, "m.call#ROOM"])
    );
    assert_eq!(jwt.claims["video"]["canPublish"], true);

    let mallory = Session {
        user_id: "@mallory:example.org".to_owned(),
        device_id: alice.device_id.clone(),
        access_token: alice.access_token.clone(),
    };
    let (status, body) = harness
        .get_token(&room, openid.clone(), &mallory, "member-1")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the member's claimed user must be the token's: {body}"
    );
    assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{body}");

    let (status, body) = harness
        .post(
            GET_TOKEN,
            None,
            json!({
                "room_id": room,
                "slot_id": "m.call#ROOM",
                "openid_token": openid,
                "member": { "id": "member-1", "claimed_user_id": alice.user_id },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no device: {body}");
    assert_eq!(body["errcode"], "M_BAD_JSON", "{body}");
}

/// Element Call hands the transport its delayed leave on a token request
/// (`delay_id`) once a delegation probe answered anything but 404, and
/// then stops restarting an hour-long leave: the hold must be recorded, or
/// a crashed participant stays in the call for that hour. A delay that is
/// not the caller's is refused, not held, and nothing is minted for it.
#[tokio::test]
async fn a_delayed_leave_handed_to_the_transport_is_held() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let (status, body) = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/send/m.room.message/t1?org.matrix.msc4140.delay=60000"
                ))
                .header("authorization", format!("Bearer {}", alice.access_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "msgtype": "m.text", "body": "x" }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let delay_id = body["delay_id"].as_str().unwrap().to_owned();
    let ask = |delay_id: &str, openid: Value| {
        json!({
            "room": room,
            "openid_token": openid,
            "device_id": alice.device_id,
            "delay_id": delay_id,
            "delay_timeout": 3_600_000,
        })
    };

    let (status, body) = harness
        .post(
            SFU_GET,
            None,
            ask("syd_not_hers", harness.openid_token(&alice).await),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM", "{body}");
    assert!(harness.sfu.created().is_empty(), "nothing was made");
    assert_eq!(spindle_server::livekit::held_count(&harness.store), 0);

    let (status, body) = harness
        .post(
            SFU_GET,
            None,
            ask(&delay_id, harness.openid_token(&alice).await),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        spindle_server::livekit::held_count(&harness.store),
        1,
        "the leave is held for the webhook to release"
    );

    // The participant drops off the SFU: the webhook releases the hold,
    // and the held event is *sent* -- not merely taken off the schedule.
    let left = json!({ "event": "participant_left", "participant": {
        "identity": format!("{}:{}", alice.user_id, alice.device_id),
    } })
    .to_string();
    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri("/_spindle/rtc/livekit/sfu/webhook")
                .header(
                    "authorization",
                    mock_sfu::webhook_authorization("APIkey", "not-the-signing-key", &left),
                )
                .body(Body::from(left))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["released"], 1, "{body}");
    let (status, body) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=5"
                ))
                .header("authorization", format!("Bearer {}", alice.access_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["content"]["body"] == "x"),
        "the released delayed event reached the room: {body}"
    );
}

/// The signature is bound to the secret: a token the SFU would honour is
/// one only that secret produces.
#[tokio::test]
async fn the_signature_is_over_livekits_secret() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (_, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    let jwt = decode_jwt(body["jwt"].as_str().unwrap(), "some-other-secret");
    assert!(!jwt.signed, "a different secret does not verify it");
}

/// #38's named test: a user who has left cannot mint.
#[tokio::test]
async fn a_user_who_has_left_cannot_mint() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;
    harness.invite(&room, &alice, &bob.user_id).await;
    harness.membership(&room, &bob, "join").await;

    let (status, body) = harness
        .sfu_get(&room, harness.openid_token(&bob).await, &bob.device_id)
        .await;
    assert_eq!(status, StatusCode::OK, "joined, so minted: {body}");

    harness.membership(&room, &bob, "leave").await;

    let (status, body) = harness
        .sfu_get(&room, harness.openid_token(&bob).await, &bob.device_id)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "left, so refused: {body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
}

/// Not "was once a member": a user who was never in the room, and one who
/// was only invited, are refused alike.
#[tokio::test]
async fn a_user_who_is_not_joined_cannot_mint() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .sfu_get(&room, harness.openid_token(&bob).await, &bob.device_id)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "never in the room: {body}");

    harness.invite(&room, &alice, &bob.user_id).await;

    let (status, body) = harness
        .sfu_get(&room, harness.openid_token(&bob).await, &bob.device_id)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "invited is not joined: {body}"
    );
}

/// A room that does not exist is indistinguishable from one the user is
/// not in: the refusal must not say which.
#[tokio::test]
async fn an_unknown_room_is_refused_the_same_way() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness
        .sfu_get("!nosuchroom:example.org", openid.clone(), &alice.device_id)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (_, refused_for_real_room) = {
        let bob = harness.register("bob").await;
        harness
            .sfu_get(&room, harness.openid_token(&bob).await, &bob.device_id)
            .await
    };
    assert_eq!(
        body["errcode"], refused_for_real_room["errcode"],
        "the same code whether the room exists or not"
    );
    assert_eq!(body["error"], refused_for_real_room["error"]);
}

/// The `OpenID` token is the credential, and an expired one is no credential.
#[tokio::test]
async fn an_expired_openid_token_is_refused() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let expired = spindle_server::openid::OpenId::new(Arc::clone(&harness.store))
        .issue_at(&alice.user_id, 0, 1_000)
        .unwrap();

    let (status, body) = harness
        .sfu_get(
            &room,
            json!({
                "access_token": expired.access_token,
                "token_type": "Bearer",
                "matrix_server_name": "example.org",
                "expires_in": 3600,
            }),
            &alice.device_id,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

/// Forged is refused, and refused without a membership check to leak from.
#[tokio::test]
async fn a_token_this_server_never_minted_is_refused() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .sfu_get(
            &room,
            json!({
                "access_token": "syo_ffffffffffffffff_0000",
                "token_type": "Bearer",
                "matrix_server_name": "example.org",
            }),
            &alice.device_id,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

/// A token naming another server is that server's to confirm, never this
/// one's: this server's own token, relabelled, is not redeemed here. (The
/// server named is one this server will not contact, so nothing confirms
/// it; `livekit_remote.rs` has the servers that do.)
#[tokio::test]
async fn a_token_for_another_server_is_not_redeemed_here() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let mut openid = harness.openid_token(&alice).await;
    openid["matrix_server_name"] = json!("127.0.0.1:1");

    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{body}");
    assert!(harness.sfu.created().is_empty(), "nothing was made");
}

/// An `OpenID` token is not consumed by minting: Element Call may ask twice
/// for one token, and lk-jwt-service would answer twice.
#[tokio::test]
async fn an_openid_token_can_mint_more_than_once_within_its_window() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (first, _) = harness
        .sfu_get(&room, openid.clone(), &alice.device_id)
        .await;
    let (second, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::OK, "{body}");
}

/// The window is the operator's, and it is the whole of what bounds a
/// token after the user leaves -- so the test holds `exp - nbf` to it
/// exactly, not approximately.
#[tokio::test]
async fn the_window_is_the_one_the_operator_set() {
    let harness = Harness::with(
        "[rtc.livekit]\nurl = \"wss://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\ntoken_ttl_seconds = 60\n",
    );
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let jwt = decode_jwt(body["jwt"].as_str().unwrap(), "s");
    let nbf = jwt.claims["nbf"].as_u64().unwrap();
    let exp = jwt.claims["exp"].as_u64().unwrap();
    assert_eq!(exp - nbf, 60);
    assert!(exp <= now_secs() + 60, "no token outlives its window");
}

/// The secret can be mounted rather than written into the config (#803):
/// `secret_file` is read at startup, its trailing newline dropped, and the
/// tokens are signed with what it holds, as `lk-jwt-service`'s
/// `LIVEKIT_SECRET_FROM_FILE` signs them.
#[tokio::test]
async fn the_secret_can_come_from_a_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("livekit-secret");
    std::fs::write(&path, "from-a-file\n").unwrap();
    let harness = Harness::with(&format!(
        "[rtc.livekit]\nurl = \"wss://sfu.example.org\"\nkey = \"APIkey\"\nsecret_file = \"{}\"\n",
        path.display()
    ));
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let jwt = body["jwt"].as_str().unwrap();
    assert!(
        decode_jwt(jwt, "from-a-file").signed,
        "signed with the file's secret"
    );
    assert!(
        !decode_jwt(jwt, "from-a-file\n").signed,
        "the trailing newline is not part of the secret"
    );
}

/// One way to give the secret, and a file that holds one: each mistake
/// stops the server at startup, names `rtc.livekit`, and never prints a
/// secret.
#[test]
fn the_secret_is_given_exactly_one_way() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("livekit-secret");
    std::fs::write(&file, "in-the-file\n").unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "\n").unwrap();
    let missing = dir.path().join("missing");
    let refused = |keys: &str| match spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[rtc.livekit]\nurl = \"wss://sfu.example.org\"\n\
         key = \"k\"\n{keys}"
    )) {
        Ok(_) => panic!("should have been refused:\n{keys}"),
        Err(error) => error.to_string(),
    };

    let both = refused(&format!(
        "secret = \"inline-secret\"\nsecret_file = \"{}\"\n",
        file.display()
    ));
    assert!(both.starts_with("rtc.livekit"), "{both}");
    assert!(both.contains("secret_file"), "{both}");
    assert!(
        !both.contains("inline-secret") && !both.contains("in-the-file"),
        "{both}"
    );

    let neither = refused("");
    assert!(neither.starts_with("rtc.livekit"), "{neither}");
    assert!(neither.contains("secret_file"), "{neither}");

    let unreadable = refused(&format!("secret_file = \"{}\"\n", missing.display()));
    assert!(
        unreadable.starts_with("rtc.livekit.secret_file"),
        "{unreadable}"
    );
    assert!(
        unreadable.contains(&missing.display().to_string()),
        "the error names the file: {unreadable}"
    );

    let blank = refused(&format!("secret_file = \"{}\"\n", empty.display()));
    assert!(blank.starts_with("rtc.livekit.secret_file"), "{blank}");
    assert!(blank.contains("empty"), "{blank}");
}

/// The request's shape is the external service's: a missing device is a
/// missing parameter, because the identity is user *and* device.
#[tokio::test]
async fn a_request_without_a_device_is_refused() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness.sfu_get(&room, openid, "").await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");
}

/// Off by default, and off means the endpoint does not exist rather than
/// refuses: a deployment running lk-jwt-service beside this server has one
/// minter, not one and a decoy.
#[tokio::test]
async fn unconfigured_the_endpoint_is_unrecognised_and_unadvertised() {
    let harness = Harness::with("");
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    assert_eq!(harness.transports(&alice.access_token).await, json!([]));
}

/// The configuration mistakes worth naming, refused at startup rather than
/// found during a call on somebody else's machine.
#[test]
fn misconfiguration_is_refused_at_startup() {
    let refused = |livekit: &str| match spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[rtc.livekit]\n{livekit}"
    )) {
        Ok(_) => panic!("should have been refused:\n{livekit}"),
        Err(error) => error.to_string(),
    };

    assert!(
        refused("url = \"https://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\n")
            .contains("ws(s)"),
        "the SFU is reached over a websocket"
    );
    assert!(
        refused("url = \"wss://sfu.example.org\"\nkey = \"\"\nsecret = \"s\"\n")
            .contains("key and secret"),
        "an empty key signs for nobody"
    );
    assert!(
        refused(
            "url = \"wss://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\ntoken_ttl_seconds = 0\n"
        )
        .contains("> 0"),
        "a zero window is not unlimited"
    );
    assert!(
        refused("url = \"wss://sfu.example.org\"\nkey = \"k\"\n").contains("secret"),
        "the secret is not optional"
    );
    assert!(
        refused(
            "url = \"wss://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\nfull_access_servers = [\"*\"]\n"
        )
        .contains("no wildcard"),
        "publishing on this SFU is granted server by server"
    );
}
