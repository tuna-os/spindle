//! MSC3861: authentication delegated to an OIDC provider — a real
//! Spindle instance over TCP against a mock Matrix Authentication
//! Service.
//!
//! What the suite pins: `/auth_metadata` relays the provider's own
//! discovery document (and 404s `M_UNRECOGNIZED` when nothing is
//! delegated); a provider-issued token becomes a real local identity —
//! account and device provisioned on first sight, introspection carrying
//! the client credentials; verdicts are cached so the provider is not in
//! every request's latency; an inactive token buys nothing; and the
//! legacy login/register surface answers 404 while appservice ghost
//! provisioning keeps working.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const AS_TOKEN: &str = "as_secret_token_for_tests";
const MAS_TOKEN: &str = "mat_alice_access_token";

/// The mock provider: a discovery document and a scripted introspection
/// endpoint that counts its calls.
#[derive(Clone, Default)]
struct Provider {
    url: Arc<Mutex<String>>,
    introspections: Arc<Mutex<Vec<(String, String)>>>,
}

impl Provider {
    async fn serve() -> (Self, String) {
        let provider = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        provider.url.lock().unwrap().clone_from(&url);
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(
                    |axum::extract::State(state): axum::extract::State<Provider>| async move {
                        let url = state.url.lock().unwrap().clone();
                        axum::Json(json!({
                            "issuer": url,
                            "authorization_endpoint": format!("{url}/oauth2/authorize"),
                            "token_endpoint": format!("{url}/oauth2/token"),
                            "introspection_endpoint": format!("{url}/oauth2/introspect"),
                        }))
                    },
                ),
            )
            .route(
                "/oauth2/introspect",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<Provider>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let body = axum::body::to_bytes(request.into_body(), 4096)
                            .await
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                            .unwrap_or_default();
                        state
                            .introspections
                            .lock()
                            .unwrap()
                            .push((authorization, body.clone()));
                        if body.contains(&format!("token={MAS_TOKEN}")) {
                            axum::Json(json!({
                                "active": true,
                                "username": "alice",
                                "scope": "urn:matrix:org.matrix.msc2967.client:api:* \
                                          urn:matrix:org.matrix.msc2967.client:device:MASDEV1",
                            }))
                        } else {
                            axum::Json(json!({ "active": false }))
                        }
                    },
                ),
            )
            .with_state(provider.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (provider, url)
    }

    fn introspections(&self) -> Vec<(String, String)> {
        self.introspections.lock().unwrap().clone()
    }
}

struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    /// `provider` of `None` starts a plain local-auth instance.
    async fn start(provider: Option<&str>) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(
            &reg_path,
            format!(
                "id: testbridge\nurl: null\nas_token: {AS_TOKEN}\n\
                 hs_token: hs_secret_token_for_tests\nsender_localpart: _bridge_bot\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
            ),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let auth = provider.map_or(String::new(), |url| {
            format!(
                "[auth.delegated]\nissuer = \"{url}\"\n\
                 introspection_endpoint = \"{url}/oauth2/introspect\"\n\
                 client_id = \"spindle\"\nclient_secret = \"hush\"\n"
            )
        });
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n{auth}",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            _reg_dir: reg_dir,
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
}

#[tokio::test]
async fn auth_metadata_relays_the_providers_document() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v1/auth_metadata",
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issuer"], url, "{body}");
    assert!(body["authorization_endpoint"].is_string(), "{body}");

    // And the well-known document names the issuer (MSC2965).
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/.well-known/matrix/client",
            None,
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["org.matrix.msc2965.authentication"]["issuer"], url);
}

#[tokio::test]
async fn a_plain_deployment_does_not_have_the_endpoint() {
    let server = Instance::start(None).await;
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v1/auth_metadata",
            None,
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
}

#[tokio::test]
async fn a_provider_token_becomes_a_real_local_identity() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let alice = format!("@alice:{}", server.name);
    assert_eq!(body["user_id"], alice.as_str(), "{body}");
    assert_eq!(body["device_id"], "MASDEV1", "the device scope named it");

    // Provisioned on first sight: the account and device are real.
    let (status, body) = server
        .request(
            reqwest::Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice}/displayname"),
            Some(MAS_TOKEN),
            Some(&json!({ "displayname": "Alice" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/devices/MASDEV1",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // The introspection carried our client credentials, and the verdict
    // was cached: all of the above cost exactly one call.
    let introspections = provider.introspections();
    assert_eq!(introspections.len(), 1, "cached after the first verdict");
    assert!(
        introspections[0].0.starts_with("Basic "),
        "client authenticates to the provider: {introspections:?}"
    );
}

#[tokio::test]
async fn device_deletion_needs_no_uia_the_user_cannot_complete() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    // First sight provisions the account and the device the provider
    // named. The user's local password is unguessable by construction,
    // so a password UIA challenge here would be unanswerable — the
    // provider's live vouching is the proof of identity instead.
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200);

    let (status, body) = server
        .request(
            reqwest::Method::DELETE,
            "/_matrix/client/v3/devices/MASDEV1",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "no UIA challenge under delegation: {body}");
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/devices/MASDEV1",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 404, "and the device is really gone");
}

#[tokio::test]
async fn an_inactive_token_buys_nothing() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some("mat_revoked"),
            None,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

#[tokio::test]
async fn legacy_auth_is_the_providers_business_now() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    let (status, body) = server
        .request(reqwest::Method::GET, "/_matrix/client/v3/login", None, None)
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    let (status, _) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(&json!({ "type": "m.login.password", "user": "alice", "password": "x" })),
        )
        .await;
    assert_eq!(status, 404);
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(&json!({
                "username": "bob", "password": "hunter2",
                "auth": { "type": "m.login.dummy", "session": "register" },
            })),
        )
        .await;
    assert_eq!(status, 404, "{body}");

    // The appservice door stays open: ghosts are the bridge's to mint,
    // delegation or not.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/register",
            Some(AS_TOKEN),
            Some(&json!({
                "type": "m.login.application_service",
                "username": "_bridge_ghost",
                "inhibit_login": true,
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
}
