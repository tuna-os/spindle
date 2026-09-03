//! The built-in `LiveKit` JWT service (#38): who gets a token, for what,
//! and for how long.
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
//! the way the external one would be advertised.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::Mac as _;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

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

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
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
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{rtc}"
        ))
        .expect("the configuration is valid");
        let app =
            spindle_server::app(config, Arc::clone(&store)).expect("a signing key is established");
        Self {
            _dir: dir,
            store,
            app,
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

    /// What Element Call posts, field for field.
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
/// token, scoped to the room and the device that asked.
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
    assert_eq!(
        body["url"], "wss://sfu.example.org",
        "the SFU's own address"
    );
    let jwt = decode_jwt(body["jwt"].as_str().unwrap(), "not-the-signing-key");
    assert!(jwt.signed, "signed with LiveKit's secret and nothing else");
    assert_eq!(jwt.header, json!({ "alg": "HS256", "typ": "JWT" }));
    assert_eq!(jwt.claims["iss"], "APIkey");
    assert_eq!(
        jwt.claims["sub"],
        format!("{}:{}", alice.user_id, alice.device_id),
        "the identity Element Call matches participants by"
    );
    assert_eq!(
        jwt.claims["video"]["room"], room,
        "scoped to the room asked for"
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

/// This server mints for its own users. A token claiming another server
/// is not verified over federation; it is refused.
#[tokio::test]
async fn a_token_for_another_server_is_refused() {
    let harness = Harness::with(LIVEKIT);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let mut openid = harness.openid_token(&alice).await;
    openid["matrix_server_name"] = json!("elsewhere.example.org");

    let (status, body) = harness.sfu_get(&room, openid, &alice.device_id).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
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
}
