//! MSC4502 and MSC4512: what lk-jwt-service 0.7 and later need of a
//! homeserver to run beside it as an application service.
//!
//! The service claims `rtc/livekit` under the client and federation APIs
//! and is reached through the homeserver: a client's request there is
//! authenticated as usual and forwarded with the service's `hs_token` and
//! the caller's user ID; the service checks the caller's membership with
//! `/is_joined`, which needs a scope granted in its registration; and it
//! asks the homeserver to send the federation twin of a request to another
//! server (`fed_proxy`). Element Call decides from the homeserver path
//! whether its delayed leave can be held for it, so that path answering
//! anything but 404 is a claim with consequences.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const AS_TOKEN: &str = "lk_as_token_for_tests";
const HS_TOKEN: &str = "lk_hs_token_for_tests";
const CLIENT_PATH: &str = "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token";

/// What the service heard: method, path with query, headers that matter,
/// and the body.
#[derive(Clone, Default)]
struct Sidecar {
    heard: Arc<Mutex<Vec<Value>>>,
}

impl Sidecar {
    async fn serve() -> (Self, String) {
        let sidecar = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app = axum::Router::new()
            .fallback(record)
            .with_state(sidecar.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (sidecar, url)
    }

    fn heard(&self) -> Vec<Value> {
        self.heard.lock().unwrap().clone()
    }
}

/// The service's one handler: write down what arrived, answer as a token
/// service would.
async fn record(
    axum::extract::State(state): axum::extract::State<Sidecar>,
    request: Request<Body>,
) -> impl axum::response::IntoResponse {
    let (parts, body) = request.into_parts();
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .unwrap_or_default();
    state.heard.lock().unwrap().push(json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path_and_query().map(ToString::to_string),
        "authorization": header("authorization"),
        "user": header("x-matrix-user-identifier"),
        "origin": header("x-matrix-origin"),
        "custom": header("x-custom"),
        "body": serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
    }));
    (
        StatusCode::CREATED,
        [("x-sidecar", "yes"), ("connection", "close")],
        axum::Json(json!({ "jwt": "token", "url": "wss://sfu" })),
    )
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    /// A server with lk-jwt-service's registration, as its README writes it.
    fn with_sidecar(url: &str, scopes: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let registration = dir.path().join("lk-jwt-service.yaml");
        let scopes = if scopes {
            "io.element.msc4502.scopes: [ \"urn:matrix:client:io.element.msc4502:rooms:is_joined\" ]\n"
        } else {
            ""
        };
        std::fs::write(
            &registration,
            format!(
                "id: \"LiveKit JWT service\"\nas_token: \"{AS_TOKEN}\"\nhs_token: \"{HS_TOKEN}\"\n\
                 sender_localpart: \"_lk_jwt_service\"\nnamespaces:\n  users:\n    - exclusive: false\n      regex: \".*\"\n\
                 url: null\n{scopes}io.element.msc4512.proxy_prefix: \"rtc/livekit\"\n\
                 io.element.msc4512.proxy_url: \"{url}/\"\n"
            ),
        )
        .unwrap();
        Self::with_config(
            dir,
            &format!(
                "[appservices]\nregistrations = [\"{}\"]\n",
                registration.display()
            ),
        )
    }

    fn plain() -> Self {
        Self::with_config(TempDir::new().unwrap(), "")
    }

    fn with_config(dir: TempDir, extra: &str) -> Self {
        let store = Arc::new(FjallStore::open(dir.path().join("store")).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{extra}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value, axum::http::HeaderMap) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-custom", "kept");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            headers,
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body, _) = self
            .call(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_room(&self, token: &str) -> String {
        let (status, body, _) = self
            .call(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }
}

/// A client's request under the claimed prefix reaches the service as the
/// caller, with the service's own credential in place of the caller's, and
/// the service's answer comes back as it gave it.
#[tokio::test]
async fn a_claimed_client_request_is_forwarded_as_the_caller() {
    let (sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let alice = harness.register("alice").await;

    let (status, body, headers) = harness
        .call(
            "POST",
            &format!("{CLIENT_PATH}?member_id=m1"),
            Some(&alice),
            Some(json!({ "room_id": "!r:example.org", "slot_id": "m.call#ROOM" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["jwt"], "token");
    assert_eq!(
        headers["x-sidecar"], "yes",
        "the service's headers came back"
    );
    assert!(
        headers.get("connection").is_none(),
        "a hop-by-hop header crossed the proxy"
    );

    let heard = sidecar.heard();
    assert_eq!(heard.len(), 1, "{heard:?}");
    let heard = &heard[0];
    assert_eq!(heard["method"], "POST");
    assert_eq!(heard["path"], format!("{CLIENT_PATH}?member_id=m1"));
    assert_eq!(heard["authorization"], format!("Bearer {HS_TOKEN}"));
    assert_eq!(heard["user"], "@alice:example.org");
    assert_eq!(heard["custom"], "kept");
    assert_eq!(heard["body"]["slot_id"], "m.call#ROOM");
    assert!(heard["origin"].is_null());
}

/// Without a token nothing is forwarded, and the answer is not a 404 --
/// which is how Element Call's unauthenticated probe learns that this
/// homeserver can hold a delegated leave.
#[tokio::test]
async fn a_claimed_path_needs_authentication_and_is_not_a_404() {
    let (sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let (status, body, _) = harness
        .call(
            "POST",
            "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_TOKEN");
    assert!(sidecar.heard().is_empty());

    // A path outside the prefix, or one that merely shares its first
    // letters, is the server's own and unrecognised.
    for path in [
        "/_matrix/client/unstable/io.element.msc4195/rtc/livekitty/x",
        "/_matrix/client/unstable/io.element.msc4195/rtc",
        "/_matrix/client/r1/rtc/livekit/x",
    ] {
        let (status, body, _) = harness.call("POST", path, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{path}: {body}");
    }

    // And with no service claiming it, the probe is the plain 404 that
    // tells Element Call to keep its own short leave.
    let plain = Harness::plain();
    let (status, _, _) = plain
        .call(
            "POST",
            "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The stable version prefix is claimed the same way as the unstable one.
#[tokio::test]
async fn a_versioned_path_is_claimed_too() {
    let (sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let alice = harness.register("alice").await;
    let (status, body, _) = harness
        .call(
            "GET",
            "/_matrix/client/v1/rtc/livekit/anything",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        sidecar.heard()[0]["path"],
        "/_matrix/client/v1/rtc/livekit/anything"
    );
}

/// A federation request under the prefix needs a valid X-Matrix signature;
/// an unsigned one is refused before the service hears of it.
#[tokio::test]
async fn a_claimed_federation_request_needs_a_signature() {
    let (sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let (status, body, _) = harness
        .call(
            "POST",
            "/_matrix/federation/unstable/io.element.msc4195/rtc/livekit/get_token",
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(sidecar.heard().is_empty());
}

/// `/is_joined` answers for one user or one server, to a service holding
/// the scope, about a room it is not in.
#[tokio::test]
async fn the_membership_look_up_answers_a_scoped_service() {
    let (_sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;

    let base = format!("/_matrix/client/unstable/io.element.msc4502/rooms/{room}/is_joined");
    for (query, joined) in [
        ("mxid=%40alice%3Aexample.org", true),
        ("mxid=%40bob%3Aexample.org", false),
        ("server_name=example.org", true),
        ("server_name=elsewhere.example", false),
    ] {
        let (status, body, _) = harness
            .call("GET", &format!("{base}?{query}"), Some(AS_TOKEN), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        assert_eq!(body["joined"], joined, "{query}: {body}");
    }
    // A room nobody has heard of is "not joined", not an error.
    let (status, body, _) = harness
        .call(
            "GET",
            "/_matrix/client/v3/rooms/!nowhere:example.org/is_joined?mxid=%40alice%3Aexample.org",
            Some(AS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["joined"], false);

    // Exactly one subject.
    for query in ["", "?mxid=%40a%3Ab&server_name=b"] {
        let (status, body, _) = harness
            .call("GET", &format!("{base}{query}"), Some(AS_TOKEN), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(body["errcode"], "M_MISSING_PARAM");
    }
    let (status, body, _) = harness
        .call("GET", &format!("{base}?mxid=alice"), Some(AS_TOKEN), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");

    // An ordinary user may not ask, even about a room they are in.
    let (status, body, _) = harness
        .call(
            "GET",
            &format!("{base}?mxid=%40alice%3Aexample.org"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// A service without the scope in its registration may not ask either.
#[tokio::test]
async fn the_membership_look_up_needs_the_scope() {
    let (_sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, false);
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice).await;
    let (status, body, _) = harness
        .call(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room}/is_joined?server_name=example.org"),
            Some(AS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// `fed_proxy` is the service's alone, confined to its prefix, and never
/// aimed at this server.
#[tokio::test]
async fn fed_proxy_is_confined_to_the_services_prefix() {
    let (_sidecar, url) = Sidecar::serve().await;
    let harness = Harness::with_sidecar(&url, true);
    let alice = harness.register("alice").await;
    let path = "/_matrix/client/unstable/io.element.msc4512/appservice/fed_proxy";
    let good = json!({
        "destination": "elsewhere.example",
        "method": "POST",
        "path": "/_matrix/federation/unstable/io.element.msc4195/rtc/livekit/get_token",
        "body": {},
    });

    let (status, body, _) = harness
        .call("POST", path, Some(&alice), Some(good.clone()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a user used it: {body}");

    for (change, errcode) in [
        (
            json!({ "path": "/_matrix/federation/v1/send/txn" }),
            "IO.ELEMENT.MSC4512_FEDPROXY_PATH_NOT_ALLOWED",
        ),
        (
            json!({ "path": "/_matrix/federation/v1/rtc/livekit/../../send/txn" }),
            "IO.ELEMENT.MSC4512_FEDPROXY_PATH_NOT_ALLOWED",
        ),
        (
            json!({ "path": "/_matrix/client/v1/rtc/livekit/get_token" }),
            "IO.ELEMENT.MSC4512_FEDPROXY_PATH_NOT_ALLOWED",
        ),
        (
            json!({ "destination": "example.org" }),
            "IO.ELEMENT.MSC4512_FEDPROXY_DESTINATION_DENIED",
        ),
        (json!({ "method": "PATCH" }), "M_INVALID_PARAM"),
        (json!({ "method": "GET" }), "M_INVALID_PARAM"),
        (json!({ "destination": null }), "M_MISSING_PARAM"),
    ] {
        let mut request = good.clone();
        for (key, value) in change.as_object().unwrap() {
            request[key] = value.clone();
        }
        let (status, body, _) = harness
            .call("POST", path, Some(AS_TOKEN), Some(request))
            .await;
        assert_eq!(body["errcode"], errcode, "{change}: {status} {body}");
    }
}

/// A registration that names one of the two MSC4512 properties without the
/// other is refused at startup, not half-honoured.
#[test]
fn a_half_claim_is_refused_at_startup() {
    let dir = TempDir::new().unwrap();
    let registration = dir.path().join("half.yaml");
    std::fs::write(
        &registration,
        "id: half\nas_token: a\nhs_token: h\nsender_localpart: half\nurl: null\n\
         io.element.msc4512.proxy_prefix: \"rtc/livekit\"\n",
    )
    .unwrap();
    let store = Arc::new(FjallStore::open(dir.path().join("store")).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[appservices]\nregistrations = [\"{}\"]\n",
        registration.display()
    ))
    .unwrap();
    assert!(spindle_server::app(config, store).is_err());
}
