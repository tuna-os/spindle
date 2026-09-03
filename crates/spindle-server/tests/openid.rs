//! `OpenID` tokens: proving to a third party who you are, and nothing else.
//!
//! The round trip a `MatrixRTC` call depends on is minted here and redeemed
//! over federation: a client asks `/openid/request_token`, hands the result
//! to a JWT service, and the service asks `/openid/userinfo` who it is
//! talking to. Two things carry the weight and both are pinned: the token
//! answers with *that* user's ID and no one else's, and it stops answering
//! when it expires. A token that outlived its window would let a JWT
//! service keep vouching for a user long after the client that asked had
//! gone.
//!
//! The third property is the one that makes the first two safe to have:
//! an `OpenID` token is not an access token. Presented as a bearer credential
//! it opens nothing on this server.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        Self::with("[ratelimit]\nenabled = false\n")
    }

    fn with(extra: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config =
            spindle_server::Config::parse(&format!("[server]\nname = \"example.org\"\n{extra}"))
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

    async fn request_token(&self, user_id: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/_matrix/client/v3/user/{user_id}/openid/request_token"
            ))
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.call(request.body(Body::from("{}")).unwrap()).await
    }

    async fn userinfo(&self, query: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(format!("/_matrix/federation/v1/openid/userinfo{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn whoami(&self, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri("/_matrix/client/v3/account/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

const ALICE: &str = "@alice:example.org";

/// The round trip: a token minted for alice is answered with alice.
#[tokio::test]
async fn a_token_is_answered_by_userinfo_with_that_users_id() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, minted) = harness.request_token(ALICE, Some(&alice)).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    let openid = minted["access_token"].as_str().unwrap();

    let (status, info) = harness.userinfo(&format!("?access_token={openid}")).await;

    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info, json!({ "sub": ALICE }));
}

/// The response tells the redeemer where to come back to, and for how long
/// the token is good. Both are what `lk-jwt-service` reads.
#[tokio::test]
async fn the_response_names_this_server_and_a_bounded_lifetime() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (_, minted) = harness.request_token(ALICE, Some(&alice)).await;

    assert_eq!(minted["token_type"], "Bearer");
    assert_eq!(minted["matrix_server_name"], "example.org");
    assert_eq!(
        minted["expires_in"],
        spindle_server::openid::LIFETIME_SECONDS
    );
    assert!(
        minted["access_token"].as_str().unwrap().starts_with("syo_"),
        "an OpenID token is its own kind: {minted}"
    );
}

/// Expired is refused, and refused the same way as never-minted.
#[tokio::test]
async fn an_expired_token_is_refused_by_userinfo() {
    let harness = Harness::new();
    harness.register("alice").await;
    // Minted at the epoch, expired one second later: an hour's wait done
    // by hand, through the same store the endpoint reads.
    let expired = spindle_server::openid::OpenId::new(Arc::clone(&harness.store))
        .issue_at(ALICE, 0, 1_000)
        .unwrap();

    let (status, body) = harness
        .userinfo(&format!("?access_token={}", expired.access_token))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

/// A token this server never issued gets the same answer as an expired one:
/// the redeemer is not owed the difference.
#[tokio::test]
async fn an_unknown_token_is_refused_by_userinfo() {
    let harness = Harness::new();

    let (status, body) = harness
        .userinfo("?access_token=syo_0000000000000000_deadbeef")
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

#[tokio::test]
async fn userinfo_without_a_token_is_a_missing_param() {
    let harness = Harness::new();

    let (status, body) = harness.userinfo("").await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");
}

/// A token vouches for the caller and only the caller.
#[tokio::test]
async fn a_token_can_only_be_requested_for_yourself() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.register("bob").await;

    let (status, body) = harness
        .request_token("@bob:example.org", Some(&alice))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
}

#[tokio::test]
async fn request_token_needs_an_access_token() {
    let harness = Harness::new();

    let (status, body) = harness.request_token(ALICE, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_TOKEN", "{body}");
}

/// An `OpenID` token is not an access token. This is the property that makes
/// handing one to a third party safe, so it is asserted rather than assumed.
#[tokio::test]
async fn a_token_opens_no_other_endpoint() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, minted) = harness.request_token(ALICE, Some(&alice)).await;
    let openid = minted["access_token"].as_str().unwrap();

    let (status, body) = harness.whoami(openid).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

/// Two tokens for one user are two tokens: minting a second does not
/// invalidate the first, because a client may have two calls in flight.
#[tokio::test]
async fn tokens_are_independent() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, first) = harness.request_token(ALICE, Some(&alice)).await;
    let (_, second) = harness.request_token(ALICE, Some(&alice)).await;
    let first = first["access_token"].as_str().unwrap();
    let second = second["access_token"].as_str().unwrap();
    assert_ne!(first, second);

    for token in [first, second] {
        let (status, info) = harness.userinfo(&format!("?access_token={token}")).await;
        assert_eq!(status, StatusCode::OK, "{info}");
        assert_eq!(info["sub"], ALICE);
    }
}

/// Minting is a durable write on the caller's say-so and work for the
/// third party it is for, so it is the first authenticated rate this
/// server enforces.
#[tokio::test]
async fn minting_is_rate_limited_per_user() {
    let harness = Harness::with("[ratelimit]\nenabled = true\n");
    let alice = harness.register("alice").await;

    let limit = spindle_server::ratelimit::OPENID_TOKEN_PER_USER.max;
    for attempt in 0..limit {
        let (status, body) = harness.request_token(ALICE, Some(&alice)).await;
        assert_eq!(status, StatusCode::OK, "mint {attempt}: {body}");
    }

    let (status, body) = harness.request_token(ALICE, Some(&alice)).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
    assert!(body["retry_after_ms"].is_u64(), "{body}");
}
