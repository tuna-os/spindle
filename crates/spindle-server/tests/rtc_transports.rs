//! `MatrixRTC` discovery: where a call is carried, and how a client finds out.
//!
//! Two surfaces answer the same question at different moments, and #37 is
//! mostly about them agreeing. `.well-known` is read before the client has
//! a token; `/rtc/transports` is read after it has one. Element Call uses
//! both, so a deployment whose two answers differ is one where a call works
//! or does not depending on which surface a client happened to believe --
//! and nothing in either response would say which was wrong.
//!
//! The other half is what an *unconfigured* server says. A 404 tells a
//! client the server has no such feature; an empty list tells it the server
//! has the feature and no backend. Those lead a client to different
//! behaviour, so the difference is asserted rather than assumed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// Two backends, deliberately *not* in the order a sort would produce.
///
/// MSC4143 has clients read the list as a priority ordering, so "we pass it
/// through" is a claim that has to fail when broken: with `zeta` first, any
/// tidying of the list by name or URL shows up as a reordering here.
const TWO_FOCI: &str = r#"
[rtc]
foci = [
    { type = "livekit", livekit_service_url = "https://zeta.example.org/jwt" },
    { type = "livekit", livekit_service_url = "https://alpha.example.org/jwt" },
]
"#;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn with(rtc: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{rtc}"
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

    async fn transports(&self, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.call(request.body(Body::empty()).unwrap()).await
    }

    async fn well_known(&self) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

const STABLE: &str = "/_matrix/client/v1/rtc/transports";
const UNSTABLE: &str = "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports";

/// A deployment with no backend still answers, and answers a list.
///
/// The distinction this asserts is the one #37 names: a 404 would tell a
/// client this server does not implement `MatrixRTC` discovery, when what is
/// true is that it implements it and has nothing to offer.
#[tokio::test]
async fn a_server_with_no_backend_answers_an_empty_list_rather_than_a_404() {
    let harness = Harness::with("");
    let token = harness.register("alice").await;

    let (status, body) = harness.transports(STABLE, Some(&token)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "rtc_transports": [] }),
        "an unconfigured server answers the empty list"
    );
}

/// The operator's order is the client's priority order, so it is preserved.
#[tokio::test]
async fn the_transports_are_served_in_the_order_the_operator_wrote() {
    let harness = Harness::with(TWO_FOCI);
    let token = harness.register("alice").await;

    let (status, body) = harness.transports(STABLE, Some(&token)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["rtc_transports"],
        json!([
            { "type": "livekit", "livekit_service_url": "https://zeta.example.org/jwt" },
            { "type": "livekit", "livekit_service_url": "https://alpha.example.org/jwt" },
        ]),
        "zeta was configured first and stays first"
    );
}

/// The unstable path is the one shipping clients ask for, so it has to be
/// the same endpoint and not a stub beside it.
#[tokio::test]
async fn the_unstable_path_answers_exactly_what_the_stable_one_does() {
    let harness = Harness::with(TWO_FOCI);
    let token = harness.register("alice").await;

    let (stable_status, stable) = harness.transports(STABLE, Some(&token)).await;
    let (unstable_status, unstable) = harness.transports(UNSTABLE, Some(&token)).await;

    assert_eq!(stable_status, StatusCode::OK, "{stable}");
    assert_eq!(unstable_status, StatusCode::OK, "{unstable}");
    assert_eq!(stable, unstable, "one endpoint, two paths");
}

/// Authenticated, as the MSC has it.
///
/// The unauthenticated half of discovery is `.well-known`; serving this one
/// openly would make that distinction meaningless.
#[tokio::test]
async fn the_endpoint_refuses_a_caller_with_no_token() {
    let harness = Harness::with(TWO_FOCI);

    let (status, body) = harness.transports(STABLE, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_TOKEN", "{body}");
}

/// The two surfaces name the same backends, which is the point of them.
#[tokio::test]
async fn well_known_names_the_same_transports_without_a_token() {
    let harness = Harness::with(TWO_FOCI);
    let token = harness.register("alice").await;

    let (_, endpoint) = harness.transports(STABLE, Some(&token)).await;
    let (status, discovery) = harness.well_known().await;

    assert_eq!(status, StatusCode::OK, "{discovery}");
    assert_eq!(
        discovery["org.matrix.msc4143.rtc_foci"], endpoint["rtc_transports"],
        "a client reading well-known before login and the endpoint after it \
         must find the same backends"
    );
}

/// Absent, not empty: the key's absence says "this server does not answer
/// that", where an empty array would be a positive claim to have no backend.
#[tokio::test]
async fn well_known_omits_the_key_when_no_backend_is_configured() {
    let harness = Harness::with("");

    let (status, body) = harness.well_known().await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("org.matrix.msc4143.rtc_foci").is_none(),
        "an unconfigured server says nothing here: {body}"
    );
    assert!(
        body.get("m.homeserver").is_some(),
        "and the rest of discovery is untouched: {body}"
    );
}

/// The flag is how a client decides whether to ask at all.
#[tokio::test]
async fn versions_advertises_msc4143() {
    let harness = Harness::with("");

    let (status, body) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["unstable_features"]["org.matrix.msc4143"],
        json!(true),
        "{body}"
    );
}

/// Both well-known documents say how long they may be reused (#37).
///
/// The design point the transports work left open. Neither document is
/// authenticated and both are read by things that cache: with no header a
/// peer follows the server-server spec's 24-hour default and a browser
/// picks a heuristic, so an operator who changes a setting and restarts
/// serves the new answer to nobody for up to a day. The header is how the
/// server chooses that number instead of inheriting it.
#[tokio::test]
async fn both_well_known_documents_carry_a_cache_lifetime() {
    let harness = Harness::with(TWO_FOCI);

    for path in ["/.well-known/matrix/client", "/.well-known/matrix/server"] {
        let response = harness
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let cache = response
            .headers()
            .get("cache-control")
            .unwrap_or_else(|| panic!("{path} says nothing about caching"))
            .to_str()
            .unwrap();
        assert_eq!(
            cache, "public, max-age=3600",
            "{path} publishes the lifetime this server chose"
        );
    }
}
