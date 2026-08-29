//! TURN discovery: where to relay a call, and how to prove you may.
//!
//! The credential is the part worth testing hardest. This server mints it and
//! never sees it used -- the relay recomputes the same HMAC and decides on its
//! own -- so a wrong digest here fails at call time, on someone else's
//! machine, with nothing in this server's log. There is no feedback path, and
//! a test that only checked the shape of the response would not notice.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn with(turn: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{turn}"
        ))
        .expect("the configuration is valid");
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
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

    async fn turn(&self, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri("/_matrix/client/v3/voip/turnServer")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// No relay configured is a 200 and an empty object, not a 404.
///
/// The spec's answer, and the one clients are written for: a server without a
/// relay is a working server, and 404 would have every client log an error on
/// every call setup for a condition that is normal.
#[tokio::test]
async fn a_server_with_no_relay_answers_with_an_empty_object() {
    let harness = Harness::with("");
    let alice = harness.register("alice").await;
    let (status, body) = harness.turn(&alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({}), "{body}");
}

/// The username is `expiry:user_id`, which is the format the relay parses.
///
/// The digest itself is pinned against an externally computed vector in
/// `routes.rs`'s own tests, where the function is in scope -- see
/// `the_rest_credential_matches_an_independently_computed_hmac`.
#[tokio::test]
async fn the_username_carries_the_expiry_and_the_caller() {
    let harness = Harness::with(
        "[turn]\nuris = [\"turn:relay.example.org:3478\"]\nshared_secret = \"a-shared-secret\"\n",
    );
    let alice = harness.register("alice").await;
    let (status, body) = harness.turn(&alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let username = body["username"].as_str().unwrap();
    let (expiry, user) = username.split_once(':').expect("expiry:user_id");
    assert_eq!(user, "@alice:example.org", "{body}");
    assert!(expiry.parse::<u64>().is_ok(), "{body}");
    assert!(!body["password"].as_str().unwrap().is_empty(), "{body}");
}

/// The username carries an expiry in the future, and the reported `ttl`
/// agrees with it.
#[tokio::test]
async fn the_credential_expires_and_says_when() {
    let harness = Harness::with(
        "[turn]\nuris = [\"turn:relay.example.org:3478\"]\nshared_secret = \"s\"\nttl_seconds = 300\n",
    );
    let alice = harness.register("alice").await;
    let (_, body) = harness.turn(&alice).await;

    assert_eq!(body["ttl"], 300, "{body}");
    let expiry: u64 = body["username"]
        .as_str()
        .unwrap()
        .split_once(':')
        .unwrap()
        .0
        .parse()
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        expiry > now && expiry <= now + 300,
        "the credential expires at {expiry}, which is not within the next \
         300 seconds from {now}: {body}"
    );
}

/// Two callers get different credentials.
///
/// The username binds the credential to one Matrix ID, which is what lets a
/// relay operator tell whose call is using their bandwidth. Minting the same
/// string for everyone would pass every other test in this file.
#[tokio::test]
async fn each_caller_gets_their_own_credential() {
    let harness =
        Harness::with("[turn]\nuris = [\"turn:relay.example.org:3478\"]\nshared_secret = \"s\"\n");
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let (_, alice_body) = harness.turn(&alice).await;
    let (_, bob_body) = harness.turn(&bob).await;

    assert!(
        alice_body["username"]
            .as_str()
            .unwrap()
            .ends_with(":@alice:example.org"),
        "{alice_body}"
    );
    assert!(
        bob_body["username"]
            .as_str()
            .unwrap()
            .ends_with(":@bob:example.org"),
        "{bob_body}"
    );
    assert_ne!(
        alice_body["password"], bob_body["password"],
        "two callers were minted the same password"
    );
}

/// A relay that only speaks static credentials gets them verbatim.
#[tokio::test]
async fn a_static_pair_is_passed_through_unchanged() {
    let harness = Harness::with(
        "[turn]\nuris = [\"turn:relay.example.org:3478\"]\nusername = \"spindle\"\npassword = \"hunter2\"\n",
    );
    let alice = harness.register("alice").await;
    let (status, body) = harness.turn(&alice).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["username"], "spindle", "{body}");
    assert_eq!(body["password"], "hunter2", "{body}");
    assert_eq!(
        body["uris"],
        json!(["turn:relay.example.org:3478"]),
        "{body}"
    );
}

/// It needs a token, like everything else that names a user.
#[tokio::test]
async fn an_anonymous_caller_gets_no_relay() {
    let harness =
        Harness::with("[turn]\nuris = [\"turn:relay.example.org:3478\"]\nshared_secret = \"s\"\n");
    let (status, _) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/v3/voip/turnServer")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Configurations that would fail at call time are refused at startup.
///
/// Each of these produces a server that looks healthy and hands clients
/// something a relay will reject, with nothing in this server's log when it
/// does. Startup is the only place the operator is still watching.
#[test]
fn a_configuration_that_cannot_work_is_refused() {
    for (label, turn) in [
        (
            "relays with no credentials at all",
            "[turn]\nuris = [\"turn:relay.example.org:3478\"]\n",
        ),
        (
            "both credential schemes",
            "[turn]\nuris = [\"turn:r:3478\"]\nshared_secret = \"s\"\nusername = \"u\"\npassword = \"p\"\n",
        ),
        (
            "a username with no password",
            "[turn]\nuris = [\"turn:r:3478\"]\nusername = \"u\"\n",
        ),
        (
            "a password with no username",
            "[turn]\nuris = [\"turn:r:3478\"]\npassword = \"p\"\n",
        ),
    ] {
        let parsed = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{turn}"
        ));
        assert!(parsed.is_err(), "{label} was accepted");
    }
}
