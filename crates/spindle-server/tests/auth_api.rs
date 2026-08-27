//! The client-facing auth flow, end to end over HTTP.
//!
//! #11's exit criterion is that a client can discover, register, log in,
//! refresh and log out. This covers all but refresh, which needs refresh
//! tokens and is not built yet.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    /// One router for the whole harness, cloned per request.
    ///
    /// Building a fresh app per request would give every request its own rate
    /// limiter and its own in-process state, which no deployment does — and
    /// which quietly makes a rate-limit test unable to fail.
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = spindle_server::app(Self::config(), store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    /// A harness over storage that already exists, as a restart would open it.
    fn reopen(path: &std::path::Path) -> Self {
        let store = Arc::new(FjallStore::open(path).unwrap());
        let app = spindle_server::app(Self::config(), store).expect("a signing key is established");
        Self {
            _dir: TempDir::new().unwrap(),
            app,
        }
    }

    fn config() -> spindle_server::Config {
        spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap()
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.send(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
    }

    async fn get_auth(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.send(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str, password: &str) -> Value {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/register",
                &json!({
                    "username": username,
                    "password": password,
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "register failed: {body}");
        body
    }
}

/// The whole point: discover, register, log in, use the token, log out.
#[tokio::test]
async fn a_client_can_register_log_in_and_log_out() {
    let harness = Harness::new();

    let registered = harness.register("alice", "correct horse").await;
    assert_eq!(registered["user_id"], "@alice:example.org");
    assert!(registered["access_token"].is_string());

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/login",
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "alice" },
                "password": "correct horse",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(body["user_id"], "@alice:example.org");

    let (status, who) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["user_id"], "@alice:example.org");
    assert_eq!(who["device_id"], body["device_id"]);

    let (status, _) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/logout")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // And the token is dead immediately, not at some later expiry.
    let (status, body) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

/// Registration is a UIA flow. Clients implement UIA generically; a server that
/// skips the dance for registration makes them special-case it.
#[tokio::test]
async fn registration_without_auth_returns_the_uia_flows() {
    let harness = Harness::new();
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({ "username": "alice", "password": "hunter2" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Top level, not folded into an error string: generic UIA clients (and
    // Complement's RegisterUser) read `flows` and `session` from the body
    // of the 401 itself.
    assert_eq!(body["flows"][0]["stages"][0], "m.login.dummy");
    assert!(
        body["session"].is_string(),
        "the challenge names a session to resume: {body}"
    );
}

#[tokio::test]
async fn username_verdicts_outrank_the_uia_dance() {
    // A client should hear M_USER_IN_USE or M_INVALID_USERNAME on its first
    // request — not complete an auth flow to learn its username was never
    // going to work. And an auth dict naming no session has not completed
    // anything: it gets the challenge again, not an account.
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({ "username": "alice", "password": "hunter2" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_USER_IN_USE");

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({ "username": "not valid!", "password": "hunter2" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_USERNAME");

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({
                "username": "bob",
                "password": "hunter2",
                "auth": { "type": "m.login.dummy" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["session"].is_string(), "{body}");
}

#[tokio::test]
async fn capitals_downcase_instead_of_failing() {
    // The localpart grammar is lowercase; a client typing "Alice" means
    // alice, on registration and on the availability probe alike.
    let harness = Harness::new();
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({
                "username": "Alice",
                "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "register" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:example.org");

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/login",
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "ALICE" },
                "password": "hunter2",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "login folds the same way: {body}");
    assert_eq!(body["user_id"], "@alice:example.org");
}

#[tokio::test]
async fn availability_answers_without_registering() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let (status, body) = harness
        .get("/_matrix/client/v3/register/available?username=bob")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["available"], true);

    let (status, body) = harness
        .get("/_matrix/client/v3/register/available?username=alice")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_USER_IN_USE");

    // Answering "available" does not register: bob still does not exist.
    let (status, body) = harness
        .post(
            "/_matrix/client/v3/login",
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "bob" },
                "password": "hunter2",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn a_wrong_password_and_an_unknown_user_are_indistinguishable() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let attempt = |user: &'static str, password: &'static str| async move {
        let harness = Harness::new();
        harness.register("alice", "hunter2").await;
        harness
            .post(
                "/_matrix/client/v3/login",
                &json!({
                    "type": "m.login.password",
                    "identifier": { "type": "m.id.user", "user": user },
                    "password": password,
                }),
            )
            .await
    };

    let (wrong_status, wrong_body) = attempt("alice", "nope").await;
    let (unknown_status, unknown_body) = attempt("nobody", "nope").await;
    assert_eq!(wrong_status, StatusCode::FORBIDDEN);
    assert_eq!(
        (wrong_status, &wrong_body),
        (unknown_status, &unknown_body),
        "the two responses differ, which tells an attacker which usernames exist"
    );
}

#[tokio::test]
async fn a_taken_username_gets_the_errcode_a_client_can_act_on() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({
                "username": "alice",
                "password": "other",
                "auth": { "type": "m.login.dummy", "session": "register" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Not M_UNKNOWN: a client that sees this shows "pick another name" rather
    // than a generic failure.
    assert_eq!(body["errcode"], "M_USER_IN_USE");
}

#[tokio::test]
async fn an_authenticated_endpoint_refuses_a_missing_or_bogus_token() {
    let harness = Harness::new();

    let (status, body) = harness
        .send(
            Request::builder()
                .uri("/_matrix/client/v3/account/whoami")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");

    let (status, body) = harness
        .get_auth("/_matrix/client/v3/account/whoami", "syt_not_a_real_token")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

/// The deprecated `?access_token=` form is not read, deliberately: a bearer
/// credential in a query string lands in access logs, proxy logs and browser
/// history.
#[tokio::test]
async fn a_token_in_the_query_string_is_not_accepted() {
    let harness = Harness::new();
    let registered = harness.register("alice", "hunter2").await;
    let token = registered["access_token"].as_str().unwrap();

    let (status, body) = harness
        .send(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v3/account/whoami?access_token={token}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");
}

#[tokio::test]
async fn login_flows_advertise_only_password() {
    let harness = Harness::new();
    let (status, body) = harness
        .send(
            Request::builder()
                .uri("/_matrix/client/v3/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let flows = body["flows"].as_array().unwrap();
    assert_eq!(flows.len(), 1, "only what is implemented: {body}");
    assert_eq!(flows[0]["type"], "m.login.password");
}

/// Restart preserves accounts and devices — an exit criterion of #11.
#[tokio::test]
async fn accounts_survive_a_restart() {
    let dir = TempDir::new().unwrap();
    let token = {
        let harness = Harness::reopen(dir.path());
        let registered = harness.register("alice", "hunter2").await;
        registered["access_token"].as_str().unwrap().to_owned()
    };

    // A fresh handle over the same directory, as a restart would open.
    let harness = Harness::reopen(dir.path());
    let (status, who) = harness
        .get_auth("/_matrix/client/v3/account/whoami", &token)
        .await;
    assert_eq!(status, StatusCode::OK, "the session did not survive: {who}");
    assert_eq!(who["user_id"], "@alice:example.org");
}

/// #11's exit criterion in full: discover, register, log in, **refresh**, log out.
#[tokio::test]
async fn a_client_can_refresh_its_access_token() {
    let harness = Harness::new();

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/register",
            &json!({
                "username": "alice",
                "password": "hunter2",
                "refresh_token": true,
                "auth": { "type": "m.login.dummy", "session": "register" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh = body["refresh_token"]
        .as_str()
        .expect("asked for refresh")
        .to_owned();
    assert!(
        body["expires_in_ms"].is_number(),
        "a refreshing session must say when to renew: {body}"
    );

    let (status, refreshed) = harness
        .post(
            "/_matrix/client/v3/refresh",
            &json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let new_access = refreshed["access_token"].as_str().unwrap();
    assert_ne!(new_access, body["access_token"].as_str().unwrap());

    // The new access token is live and names the same user and device.
    let (status, who) = harness
        .get_auth("/_matrix/client/v3/account/whoami", new_access)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who["user_id"], "@alice:example.org");
    assert_eq!(who["device_id"], body["device_id"]);

    // Replaying the spent refresh token fails, with the code a client acts on.
    let (status, replayed) = harness
        .post(
            "/_matrix/client/v3/refresh",
            &json!({ "refresh_token": refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(replayed["errcode"], "M_UNKNOWN_TOKEN");
}

/// A client that did not ask for refresh gets neither key, rather than nulls:
/// clients check for the key's presence to decide whether to schedule renewal.
#[tokio::test]
async fn a_non_refreshing_login_omits_the_refresh_keys_entirely() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let (status, body) = harness
        .post(
            "/_matrix/client/v3/login",
            &json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": "alice" },
                "password": "hunter2",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let object = body.as_object().unwrap();
    assert!(!object.contains_key("refresh_token"), "{body}");
    assert!(!object.contains_key("expires_in_ms"), "{body}");
}

/// A password endpoint with no limit is a brute-force target. The limit has to
/// bite on repeated failures against one account.
#[tokio::test]
async fn repeated_failed_logins_against_one_account_are_refused() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let wrong = json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": "alice" },
        "password": "nope",
    });

    let mut refused = None;
    for attempt in 0..12 {
        let (status, body) = harness.post("/_matrix/client/v3/login", &wrong).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused = Some((attempt, body));
            break;
        }
        assert_eq!(status, StatusCode::FORBIDDEN, "attempt {attempt}: {body}");
    }

    let (attempt, body) = refused.expect("brute force was never refused");
    assert!(attempt <= 6, "took {attempt} attempts to trip the limit");
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED");
    // Without this a client backs off by guessing, and the usual guess is
    // "immediately, but again".
    let retry = body["retry_after_ms"]
        .as_u64()
        .expect("no retry hint: {body}");
    assert!(retry > 0, "a client told to wait 0ms retries now");
}

/// A correct login must not consume budget, or a busy shared address locks out
/// its own legitimate users before it inconveniences an attacker.
#[tokio::test]
async fn a_correct_login_does_not_count_against_the_limit() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;

    let right = json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": "alice" },
        "password": "hunter2",
    });

    // Comfortably more than the failure budget.
    for attempt in 0..15 {
        let (status, body) = harness.post("/_matrix/client/v3/login", &right).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "correct login {attempt} was refused: {body}"
        );
    }
}

/// Failing, then succeeding, then failing again must not carry the earlier
/// failures forward — the success cleared them.
#[tokio::test]
async fn a_success_clears_the_failures_that_preceded_it() {
    let harness = Harness::new();
    harness.register("alice", "hunter2").await;
    let attempt = |password: &'static str| {
        json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": "alice" },
            "password": password,
        })
    };

    for _ in 0..4 {
        let (status, _) = harness
            .post("/_matrix/client/v3/login", &attempt("nope"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _) = harness
        .post("/_matrix/client/v3/login", &attempt("hunter2"))
        .await;
    assert_eq!(status, StatusCode::OK);

    // The budget is whole again, so four more failures are still refusals
    // rather than rate-limit responses.
    for index in 0..4 {
        let (status, body) = harness
            .post("/_matrix/client/v3/login", &attempt("nope"))
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "failure {index} after a success was rate limited: {body}"
        );
    }
}

/// The mandatory first 401 of the UIA hand-shake is the server's own
/// requirement; spending the client's registration budget on it would let a
/// client be locked out by doing exactly what the server told it to.
#[tokio::test]
async fn the_uia_challenge_does_not_consume_the_registration_budget() {
    let harness = Harness::new();
    for index in 0..20 {
        let (status, _) = harness
            .post(
                "/_matrix/client/v3/register",
                &json!({ "username": "alice", "password": "hunter2" }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "challenge {index} was rate limited"
        );
    }
    // And a real registration still goes through afterwards.
    harness.register("alice", "hunter2").await;
}
