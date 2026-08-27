//! The classic appservice existence queries — a real Spindle instance
//! over TCP, and a mock bridge that provisions what it is asked about.
//!
//! What the suite pins: a profile lookup of an unknown namespace user
//! asks the service (`GET /_matrix/app/v1/users/{userId}`), which
//! provisions the ghost through `m.login.application_service`
//! registration and answers 200 — and the lookup then succeeds instead
//! of 404ing; an alias in the service's namespace springs into being the
//! same way (`GET /_matrix/app/v1/rooms/{roomAlias}`); a user nobody
//! claims stays a 404 with no request made; and inviting a ghost asks
//! the service before the membership is written.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const AS_TOKEN: &str = "as_secret_token_for_tests";
const HS_TOKEN: &str = "hs_secret_token_for_tests";

/// The mock bridge: answers existence queries by provisioning the asked-
/// about thing through the homeserver's own client API, like a real one.
#[derive(Clone, Default)]
struct Bridge {
    /// The homeserver's address, set once it has started.
    hs: Arc<Mutex<Option<String>>>,
    user_queries: Arc<Mutex<Vec<String>>>,
    alias_queries: Arc<Mutex<Vec<String>>>,
}

impl Bridge {
    async fn serve() -> (Self, String) {
        let bridge = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app = axum::Router::new()
            .route(
                "/_matrix/app/v1/users/{user_id}",
                axum::routing::get(
                    |axum::extract::State(state): axum::extract::State<Bridge>,
                     axum::extract::Path(user_id): axum::extract::Path<String>| async move {
                        state.user_queries.lock().unwrap().push(user_id.clone());
                        let hs = state.hs.lock().unwrap().clone().unwrap();
                        let localpart = user_id
                            .strip_prefix('@')
                            .and_then(|rest| rest.split(':').next())
                            .unwrap()
                            .to_owned();
                        // Provision the ghost the way a real bridge does:
                        // appservice-typed registration, as_token as proof.
                        let response = reqwest::Client::new()
                            .post(format!("http://{hs}/_matrix/client/v3/register"))
                            .header("authorization", format!("Bearer {AS_TOKEN}"))
                            .header("content-type", "application/json")
                            .body(
                                json!({
                                    "type": "m.login.application_service",
                                    "username": localpart,
                                    "inhibit_login": true,
                                })
                                .to_string(),
                            )
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(response.status().as_u16(), 200, "provisioning works");
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .route(
                "/_matrix/app/v1/rooms/{alias}",
                axum::routing::get(
                    |axum::extract::State(state): axum::extract::State<Bridge>,
                     axum::extract::Path(alias): axum::extract::Path<String>| async move {
                        state.alias_queries.lock().unwrap().push(alias.clone());
                        let hs = state.hs.lock().unwrap().clone().unwrap();
                        let client = reqwest::Client::new();
                        // Create the room as the sender user, then map
                        // the asked-about alias onto it.
                        let response = client
                            .post(format!("http://{hs}/_matrix/client/v3/createRoom"))
                            .header("authorization", format!("Bearer {AS_TOKEN}"))
                            .header("content-type", "application/json")
                            .body(json!({}).to_string())
                            .send()
                            .await
                            .unwrap();
                        let body: Value =
                            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                        let room_id = body["room_id"].as_str().unwrap().to_owned();
                        let encoded = alias.replace('#', "%23");
                        let response = client
                            .put(format!(
                                "http://{hs}/_matrix/client/v3/directory/room/{encoded}"
                            ))
                            .header("authorization", format!("Bearer {AS_TOKEN}"))
                            .header("content-type", "application/json")
                            .body(json!({ "room_id": room_id }).to_string())
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(response.status().as_u16(), 200, "the alias maps");
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .with_state(bridge.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (bridge, url)
    }

    fn user_queries(&self) -> Vec<String> {
        self.user_queries.lock().unwrap().clone()
    }

    fn alias_queries(&self) -> Vec<String> {
        self.alias_queries.lock().unwrap().clone()
    }
}

struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start(as_url: &str, bridge: &Bridge) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(
            &reg_path,
            format!(
                "id: testbridge\nurl: \"{as_url}\"\nas_token: {AS_TOKEN}\n\
                 hs_token: {HS_TOKEN}\nsender_localpart: _bridge_bot\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n\
                 \x20 aliases:\n    - exclusive: true\n      regex: \"#_bridge_.*:.*\"\n"
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
        *bridge.hs.lock().unwrap() = Some(name.clone());
        Instance {
            _dir: dir,
            _reg_dir: reg_dir,
            name,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        let mut request = self.client.get(format!("http://{}{path}", self.name));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
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

    async fn post(&self, path: &str, token: &str, body: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!("http://{}{path}", self.name))
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
            .post(
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
}

#[tokio::test]
async fn a_ghost_profile_springs_into_being_when_queried() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url, &bridge).await;
    let ghost = format!("@_bridge_ghosty:{}", server.name);

    let (status, body) = server
        .get(&format!("/_matrix/client/v3/profile/{ghost}"), None)
        .await;
    assert_eq!(status, 200, "provisioned mid-lookup, not 404: {body}");
    assert_eq!(bridge.user_queries(), vec![ghost.clone()]);

    // A second lookup finds the account directly — no second query.
    let (status, _) = server
        .get(&format!("/_matrix/client/v3/profile/{ghost}"), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        bridge.user_queries().len(),
        1,
        "the ghost now simply exists"
    );
}

#[tokio::test]
async fn an_alias_in_the_namespace_springs_into_being() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url, &bridge).await;
    let alias = format!("#_bridge_room:{}", server.name);
    let encoded = alias.replace('#', "%23");

    let (status, body) = server
        .get(
            &format!("/_matrix/client/v3/directory/room/{encoded}"),
            None,
        )
        .await;
    assert_eq!(status, 200, "created mid-resolution, not 404: {body}");
    assert!(
        body["room_id"]
            .as_str()
            .is_some_and(|id| id.starts_with('!')),
        "a real room came back: {body}"
    );
    assert_eq!(bridge.alias_queries(), vec![alias]);
}

#[tokio::test]
async fn a_user_nobody_claims_stays_a_404_without_a_request() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url, &bridge).await;

    let (status, body) = server
        .get(
            &format!("/_matrix/client/v3/profile/@stranger:{}", server.name),
            None,
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
    assert!(
        bridge.user_queries().is_empty(),
        "no service claims it, so nobody was asked"
    );
}

#[tokio::test]
async fn inviting_a_ghost_asks_its_service_first() {
    let (bridge, as_url) = Bridge::serve().await;
    let server = Instance::start(&as_url, &bridge).await;
    let alice = server.register("alice").await;
    let ghost = format!("@_bridge_invitee:{}", server.name);

    let (status, body) = server
        .post("/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    assert_eq!(status, 200, "{body}");
    let room = body["room_id"].as_str().unwrap().to_owned();

    let (status, body) = server
        .post(
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            &alice,
            &json!({ "user_id": ghost }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        bridge.user_queries(),
        vec![ghost.clone()],
        "the service was asked before the membership was written"
    );
    // And the provisioned ghost is real: its profile answers.
    let (status, _) = server
        .get(&format!("/_matrix/client/v3/profile/{ghost}"), None)
        .await;
    assert_eq!(status, 200);
}
