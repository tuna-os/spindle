//! MSC3983/3984: for a user who exists only through an appservice, the
//! service's key store is the real one — so key claims and key queries
//! the homeserver cannot answer are proxied to it.
//!
//! What the suite pins: a one-time-key claim the store has nothing for
//! reaches the service (algorithms as a list, `hs_token` attached) and
//! its answer reaches the caller; a key query for an unknown ghost is
//! answered by the service; a locally stored key wins without a proxy
//! call; and an unclaimed user is never proxied at all.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const AS_TOKEN: &str = "as_secret_token_for_tests";
const HS_TOKEN: &str = "hs_secret_token_for_tests";

/// The mock bridge's key half: records what it was asked, answers from
/// a fixed script.
#[derive(Clone, Default)]
struct KeyService {
    claims: Arc<Mutex<Vec<(String, Value)>>>,
    queries: Arc<Mutex<Vec<(String, Value)>>>,
}

impl KeyService {
    async fn serve() -> (Self, String) {
        let service = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app = axum::Router::new()
            .route(
                "/_matrix/app/v1/unstable/org.matrix.msc3983/keys/claim",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<KeyService>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        let (authorization, body) = split(request).await;
                        state
                            .claims
                            .lock()
                            .unwrap()
                            .push((authorization, body.clone()));
                        // Answer a key for whatever was asked, bare-map
                        // shape per the MSC.
                        let mut out = serde_json::Map::new();
                        for (user, devices) in body.as_object().into_iter().flatten() {
                            let mut per_user = serde_json::Map::new();
                            for (device, _) in devices.as_object().into_iter().flatten() {
                                per_user.insert(
                                    device.clone(),
                                    json!({ "signed_curve25519:FROMAS": { "key": "as_key" } }),
                                );
                            }
                            out.insert(user.clone(), Value::Object(per_user));
                        }
                        axum::Json(Value::Object(out))
                    },
                ),
            )
            .route(
                "/_matrix/app/v1/unstable/org.matrix.msc3984/keys/query",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<KeyService>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        let (authorization, body) = split(request).await;
                        state
                            .queries
                            .lock()
                            .unwrap()
                            .push((authorization, body.clone()));
                        let mut out = serde_json::Map::new();
                        for (user, _) in body["device_keys"].as_object().into_iter().flatten() {
                            out.insert(
                                user.clone(),
                                json!({ "GHOSTDEV": {
                                    "user_id": user,
                                    "device_id": "GHOSTDEV",
                                    "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                                    "keys": { "curve25519:GHOSTDEV": "as_identity" },
                                    "signatures": {},
                                }}),
                            );
                        }
                        axum::Json(json!({ "device_keys": out }))
                    },
                ),
            )
            .with_state(service.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (service, url)
    }

    fn claims(&self) -> Vec<(String, Value)> {
        self.claims.lock().unwrap().clone()
    }

    fn queries(&self) -> Vec<(String, Value)> {
        self.queries.lock().unwrap().clone()
    }
}

async fn split(request: axum::http::Request<axum::body::Body>) -> (String, Value) {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    (
        authorization,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start(as_url: &str) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(
            &reg_path,
            format!(
                "id: testbridge\nurl: \"{as_url}\"\nas_token: {AS_TOKEN}\n\
                 hs_token: {HS_TOKEN}\nsender_localpart: _bridge_bot\n\
                 io.element.msc4190: true\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
            ),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n",
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

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (u16, Value) {
        let response = self
            .client
            .request(method, format!("http://{}{path}", self.name))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
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
            .send(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                "",
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    /// A ghost with an MSC4190-minted device, provisioned the bridge way.
    async fn ghost_with_device(&self, ghost: &str) {
        let (status, body) = self
            .send(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                AS_TOKEN,
                &json!({
                    "type": "m.login.application_service",
                    "username": ghost.strip_prefix('@').unwrap().split(':').next().unwrap(),
                }),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let (status, body) = self
            .send(
                reqwest::Method::PUT,
                &format!("/_matrix/client/v3/devices/GHOSTDEV?user_id={ghost}"),
                AS_TOKEN,
                &json!({}),
            )
            .await;
        assert_eq!(status, 201, "{body}");
    }
}

#[tokio::test]
async fn a_dry_claim_reaches_the_service_and_its_key_reaches_the_caller() {
    let (service, as_url) = KeyService::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_dry:{}", server.name);
    server.ghost_with_device(&ghost).await;
    let alice = server.register("alice").await;

    let (status, body) = server
        .send(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            &alice,
            &json!({ "one_time_keys": { &ghost: { "GHOSTDEV": "signed_curve25519" } } }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["one_time_keys"][&ghost]["GHOSTDEV"]["signed_curve25519:FROMAS"]["key"], "as_key",
        "the service's key came through: {body}"
    );

    let claims = service.claims();
    assert_eq!(claims.len(), 1, "exactly one proxy call");
    let (authorization, asked) = &claims[0];
    assert_eq!(authorization, &format!("Bearer {HS_TOKEN}"));
    assert_eq!(
        asked[&ghost]["GHOSTDEV"],
        json!(["signed_curve25519"]),
        "algorithms travel as a list, per the MSC: {asked}"
    );
}

#[tokio::test]
async fn a_query_for_an_unknown_ghost_is_answered_by_the_service() {
    let (service, as_url) = KeyService::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_blank:{}", server.name);
    server.ghost_with_device(&ghost).await;
    let alice = server.register("alice").await;

    let (status, body) = server
        .send(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            &alice,
            &json!({ "device_keys": { &ghost: [] } }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["device_keys"][&ghost]["GHOSTDEV"]["keys"]["curve25519:GHOSTDEV"], "as_identity",
        "the service answered for its ghost: {body}"
    );
    assert_eq!(service.queries().len(), 1);
}

#[tokio::test]
async fn a_locally_stored_key_wins_without_a_proxy_call() {
    let (service, as_url) = KeyService::serve().await;
    let server = Instance::start(&as_url).await;
    let ghost = format!("@_bridge_stocked:{}", server.name);
    server.ghost_with_device(&ghost).await;

    // The bridge stocks the homeserver the ordinary way (MSC3202 device
    // masquerade), so the store has both identity and one-time keys.
    let (status, body) = server
        .send(
            reqwest::Method::POST,
            &format!(
                "/_matrix/client/v3/keys/upload?user_id={ghost}&org.matrix.msc3202.device_id=GHOSTDEV"
            ),
            AS_TOKEN,
            &json!({
                "device_keys": {
                    "user_id": ghost, "device_id": "GHOSTDEV",
                    "algorithms": [], "keys": { "curve25519:GHOSTDEV": "local_identity" },
                    "signatures": {},
                },
                "one_time_keys": { "signed_curve25519:LOCAL": { "key": "local_key" } },
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let alice = server.register("alice").await;
    let (_, body) = server
        .send(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            &alice,
            &json!({ "one_time_keys": { &ghost: { "GHOSTDEV": "signed_curve25519" } } }),
        )
        .await;
    assert_eq!(
        body["one_time_keys"][&ghost]["GHOSTDEV"]["signed_curve25519:LOCAL"]["key"], "local_key",
        "{body}"
    );
    let (_, body) = server
        .send(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/query",
            &alice,
            &json!({ "device_keys": { &ghost: [] } }),
        )
        .await;
    assert_eq!(
        body["device_keys"][&ghost]["GHOSTDEV"]["keys"]["curve25519:GHOSTDEV"], "local_identity",
        "{body}"
    );
    assert!(
        service.claims().is_empty() && service.queries().is_empty(),
        "the store answered, so the service was never asked"
    );
}

#[tokio::test]
async fn an_unclaimed_user_is_never_proxied() {
    let (service, as_url) = KeyService::serve().await;
    let server = Instance::start(&as_url).await;
    let alice = server.register("alice").await;
    let bob = format!("@bob:{}", server.name);
    server.register("bob").await;

    let (status, body) = server
        .send(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/claim",
            &alice,
            &json!({ "one_time_keys": { &bob: { "SOMEDEV": "signed_curve25519" } } }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["one_time_keys"],
        json!({}),
        "no keys, honestly: {body}"
    );
    assert!(
        service.claims().is_empty(),
        "a user outside every namespace is nobody's to answer for"
    );
}
