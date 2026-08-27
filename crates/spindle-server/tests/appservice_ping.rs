//! MSC2659: the appservice ping — proof the homeserver can reach the
//! bridge before anything real depends on it.
//!
//! What the suite pins: the service's own token round-trips a ping (the
//! bridge sees the `hs_token` and the `transaction_id`, the caller gets a
//! duration); the path's appservice ID must be the caller's own; a user
//! token is a stranger here; a registration without a URL is told so; and
//! a bridge answering 500 comes back as `M_BAD_STATUS`, not success.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const AS_TOKEN: &str = "as_secret_token_for_tests";
const HS_TOKEN: &str = "hs_secret_token_for_tests";

/// A bridge that only answers `/ping`, recording what it heard.
#[derive(Clone, Default)]
struct PingSink {
    pings: Arc<Mutex<Vec<(String, Value)>>>,
    broken: Arc<Mutex<bool>>,
}

impl PingSink {
    async fn serve() -> (Self, String) {
        let sink = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app = axum::Router::new()
            .route(
                "/_matrix/app/v1/ping",
                axum::routing::post(
                    |axum::extract::State(state): axum::extract::State<PingSink>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        let bytes = axum::body::to_bytes(request.into_body(), 1024)
                            .await
                            .unwrap_or_default();
                        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        state.pings.lock().unwrap().push((authorization, body));
                        if *state.broken.lock().unwrap() {
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            axum::http::StatusCode::OK
                        }
                    },
                ),
            )
            .with_state(sink.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (sink, url)
    }
}

/// One homeserver on a real TCP listener; `as_url` of `None` writes a
/// registration whose `url` is null.
struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start(as_url: Option<&str>) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        let url_line = as_url.map_or("null".to_owned(), |url| format!("\"{url}\""));
        std::fs::write(
            &reg_path,
            format!(
                "id: testbridge\nurl: {url_line}\nas_token: {AS_TOKEN}\n\
                 hs_token: {HS_TOKEN}\nsender_localpart: _bridge_bot\n\
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

    async fn ping(&self, appservice_id: &str, token: &str, body: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!(
                "http://{}/_matrix/client/v1/appservice/{appservice_id}/ping",
                self.name
            ))
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
        let response = self
            .client
            .post(format!("http://{}/_matrix/client/v3/register", self.name))
            .header("content-type", "application/json")
            .body(
                json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn a_ping_round_trips_with_the_hs_token_and_transaction_id() {
    let (sink, as_url) = PingSink::serve().await;
    let server = Instance::start(Some(&as_url)).await;

    let (status, body) = server
        .ping("testbridge", AS_TOKEN, &json!({ "transaction_id": "t1" }))
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["duration_ms"].is_u64(),
        "a duration comes back: {body}"
    );

    let pings = sink.pings.lock().unwrap().clone();
    assert_eq!(pings.len(), 1);
    let (authorization, heard) = &pings[0];
    assert_eq!(authorization, &format!("Bearer {HS_TOKEN}"));
    assert_eq!(heard["transaction_id"], "t1");
}

#[tokio::test]
async fn only_the_service_itself_and_only_by_its_own_name() {
    let (_sink, as_url) = PingSink::serve().await;
    let server = Instance::start(Some(&as_url)).await;

    // The right token under somebody else's ID: forbidden.
    let (status, body) = server.ping("otherbridge", AS_TOKEN, &json!({})).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");

    // A human's token: not an appservice at all.
    let alice = server.register("alice").await;
    let (status, body) = server.ping("testbridge", &alice, &json!({})).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{body}");
}

#[tokio::test]
async fn a_registration_without_a_url_is_told_so() {
    let server = Instance::start(None).await;
    let (status, body) = server.ping("testbridge", AS_TOKEN, &json!({})).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_URL_NOT_SET", "{body}");
}

#[tokio::test]
async fn a_broken_bridge_answers_as_a_bad_status_not_a_success() {
    let (sink, as_url) = PingSink::serve().await;
    *sink.broken.lock().unwrap() = true;
    let server = Instance::start(Some(&as_url)).await;

    let (status, body) = server.ping("testbridge", AS_TOKEN, &json!({})).await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["errcode"], "M_BAD_STATUS", "{body}");
}
