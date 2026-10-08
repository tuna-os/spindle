//! The operator API contract (#457), over real TCP, with a real OIDC
//! login against a stand-in provider and an in-process driver that models
//! a deployment's state.
//!
//! Each acceptance criterion of the issue has a test here:
//! usable with both homeservers down, resume from durable checkpoints
//! without repeating mutations, persisted leases, a complete audit record,
//! server-side roles, no secrets on the way out, and the idempotency,
//! concurrency, restart, cancel and rollback contracts.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use spindle_operator::config::Config;
use spindle_operator::driver::{
    BoxFuture, Driver, DriverRequest, Evidence, Observation, StepOutput,
};
use spindle_operator::engine::Engine;
use spindle_operator::model::{Finding, Risk, Severity, StepSpec};
use tempfile::TempDir;

const PREFIX: &str = "/_spindle/operator/v1";
const CLIENT_SECRET: &str = "test-client-secret";

// ---- a stand-in OIDC provider ----------------------------------------------

/// An issued code: who signed in, the login's nonce, its PKCE challenge.
type Grant = (String, String, String);

#[derive(Clone, Default)]
struct Provider {
    issuer: Arc<Mutex<String>>,
    /// code → (user, nonce, PKCE challenge)
    codes: Arc<Mutex<HashMap<String, Grant>>>,
}

async fn discovery(State(provider): State<Provider>) -> Json<Value> {
    let issuer = provider.issuer.lock().unwrap().clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
    }))
}

/// Signs `user` in on the spot: the test names who is logging in with a
/// `user` parameter, standing in for a password page.
async fn authorize(
    State(provider): State<Provider>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(query["scope"].split(' ').any(|scope| scope == "openid"));
    let code = format!("code-{}", provider.codes.lock().unwrap().len());
    provider.codes.lock().unwrap().insert(
        code.clone(),
        (
            query["user"].clone(),
            query["nonce"].clone(),
            query["code_challenge"].clone(),
        ),
    );
    let location = format!(
        "{}?code={code}&state={}",
        query["redirect_uri"], query["state"]
    );
    (StatusCode::SEE_OTHER, [("location", location)]).into_response()
}

async fn token(State(provider): State<Provider>, headers: HeaderMap, body: String) -> Response {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("spindle-operator:{CLIENT_SECRET}"))
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let form: HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let Some((user, nonce, challenge)) = provider.codes.lock().unwrap().remove(&form["code"])
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let derived = URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(
        form["code_verifier"].as_bytes(),
    ));
    if derived != challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let groups: Vec<&str> = match user.as_str() {
        "alice" => vec!["ops"],
        "bob" => vec!["approvers"],
        "carol" => vec!["ops", "approvers"],
        "victor" => vec!["viewers"],
        _ => vec![],
    };
    let claims = json!({
        "iss": *provider.issuer.lock().unwrap(),
        "aud": "spindle-operator",
        "sub": user,
        "name": user,
        "nonce": nonce,
        "exp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 300,
        "groups": groups,
    });
    let id_token = format!(
        "{}.{}.unchecked",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    Json(json!({"access_token": "opaque", "token_type": "Bearer", "id_token": id_token}))
        .into_response()
}

async fn start_provider() -> String {
    let provider = Provider::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    provider.issuer.lock().unwrap().clone_from(&issuer);
    let app = Router::new()
        .route("/.well-known/openid-configuration", routing::get(discovery))
        .route("/authorize", routing::get(authorize))
        .route("/token", routing::post(token))
        .with_state(provider);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    issuer
}

// ---- a driver over a modelled deployment -----------------------------------

/// The deployment the driver changes: which mutations are in effect.
/// Shared across operator restarts, as a real cluster would be.
#[derive(Default)]
struct World {
    applied: HashSet<(String, String)>,
    executions: Vec<(String, String)>,
    compensations: Vec<(String, String)>,
    observations: Vec<(String, String)>,
    /// Steps whose execute hangs after applying its effect: a crash
    /// between the change and the checkpoint.
    hang: HashSet<String>,
    /// When set, observe cannot tell.
    blind: bool,
}

#[derive(Clone, Default)]
struct ModelDriver {
    world: Arc<Mutex<World>>,
}

fn spec(name: &str, risk: Risk, mutation: bool, compensable: bool) -> StepSpec {
    StepSpec {
        name: name.to_owned(),
        risk,
        mutation,
        compensable,
    }
}

fn step_key(request: &DriverRequest) -> (String, String) {
    (
        request.operation.clone().unwrap(),
        request.step.as_ref().unwrap().spec.name.clone(),
    )
}

impl Driver for ModelDriver {
    fn plan(&self, request: DriverRequest) -> BoxFuture<'_, Result<Vec<StepSpec>, String>> {
        Box::pin(async move {
            match request.action.as_str() {
                "migrate" => Ok(vec![
                    spec("inspect", Risk::Low, false, true),
                    spec("quiesce", Risk::Low, true, true),
                    spec("switch", Risk::High, true, false),
                    spec("verify", Risk::Low, false, true),
                ]),
                "reversible" => Ok(vec![
                    spec("scale-down", Risk::Low, true, true),
                    spec("patch", Risk::Low, true, true),
                ]),
                other => Err(format!("unknown action `{other}`")),
            }
        })
    }

    fn assess(&self, _request: DriverRequest) -> BoxFuture<'_, Result<Vec<Finding>, String>> {
        Box::pin(async {
            Ok(vec![Finding {
                code: "legacy_room_versions".to_owned(),
                severity: Severity::Blocker,
                summary: "5 rooms need state resolution".to_owned(),
            }])
        })
    }

    fn execute(&self, request: DriverRequest) -> BoxFuture<'_, Result<StepOutput, String>> {
        Box::pin(async move {
            let key = step_key(&request);
            let step = request.step.as_ref().unwrap();
            let fail_at = request.params.get("fail_at").and_then(Value::as_u64);
            let hang = {
                let mut world = self.world.lock().unwrap();
                world.executions.push(key.clone());
                if fail_at == Some(step.index as u64) {
                    return Err("the API server said no (token syt_leaked)".to_owned());
                }
                if step.spec.mutation {
                    world.applied.insert(key.clone());
                }
                world.hang.contains(&key.1)
            };
            if hang {
                std::future::pending::<()>().await;
            }
            Ok(StepOutput {
                checkpoint: json!({"done": key.1, "previous": request.checkpoints.len()}),
                evidence: vec![Evidence {
                    name: format!("{}-report", key.1),
                    content: json!({"replicas": 0, "admin_token": "syt_super_secret"}),
                }],
            })
        })
    }

    fn observe(&self, request: DriverRequest) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(async move {
            let key = step_key(&request);
            let mut world = self.world.lock().unwrap();
            world.observations.push(key.clone());
            Ok(if world.blind {
                Observation::Unknown {
                    detail: Some("the API server is unreachable".to_owned()),
                }
            } else if world.applied.contains(&key) {
                Observation::Applied {
                    checkpoint: json!({"observed": key.1}),
                }
            } else {
                Observation::NotApplied
            })
        })
    }

    fn compensate(&self, request: DriverRequest) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let key = step_key(&request);
            let mut world = self.world.lock().unwrap();
            world.compensations.push(key.clone());
            world.applied.remove(&key);
            Ok(())
        })
    }
}

// ---- the operator under test -----------------------------------------------

struct Operator {
    dir: Arc<TempDir>,
    base: String,
    issuer: String,
    driver: ModelDriver,
    engine: Arc<Engine>,
    server: tokio::task::JoinHandle<()>,
    http: reqwest::Client,
}

fn config_for(dir: &TempDir, issuer: &str, public_url: &str) -> Config {
    let secret = dir.path().join("oidc-secret");
    std::fs::write(&secret, format!("{CLIENT_SECRET}\n")).unwrap();
    Config::parse(&format!(
        r#"
[operator]
listen = "127.0.0.1:0"
public_url = "{public_url}"
data_dir = "{data}"

[oidc]
issuer = "{issuer}"
client_id = "spindle-operator"
client_secret_ref = "file:{secret}"

[oidc.roles]
viewer = ["group:viewers"]
operator = ["group:ops"]
approver = ["group:approvers"]
"#,
        data = dir.path().join("data").display(),
        secret = secret.display(),
    ))
    .unwrap()
}

impl Operator {
    async fn start() -> Operator {
        let issuer = start_provider().await;
        Self::start_on(
            Arc::new(TempDir::new().unwrap()),
            issuer,
            ModelDriver::default(),
        )
        .await
    }

    async fn start_on(dir: Arc<TempDir>, issuer: String, driver: ModelDriver) -> Operator {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let config = config_for(&dir, &issuer, &base);
        let drivers: BTreeMap<String, Arc<dyn Driver>> = BTreeMap::from([(
            "model".to_owned(),
            Arc::new(driver.clone()) as Arc<dyn Driver>,
        )]);
        let (engine, router) = spindle_operator::build(&config, drivers).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Operator {
            dir,
            base,
            issuer,
            driver,
            engine,
            server,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    /// What a crash does: runners stop mid-step, nothing more is recorded,
    /// and a new process opens the same journal.
    async fn crash_and_restart(self) -> Operator {
        // Runners stop mid-step, nothing more is written, and the data
        // directory's lock goes, as when a process dies.
        self.engine.shutdown();
        self.server.abort();
        let _ = self.server.await;
        let Operator {
            dir,
            issuer,
            driver,
            ..
        } = self;
        Self::start_on(dir, issuer, driver).await
    }

    async fn login(&self, user: &str) -> Result<Session, (StatusCode, Value)> {
        let start = self
            .http
            .get(format!(
                "{}{PREFIX}/session/login?return_to=/changes",
                self.base
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::SEE_OTHER);
        let login_cookie = start.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert!(login_cookie.contains("HttpOnly") && login_cookie.contains("Secure"));
        let login_cookie = login_cookie.split(';').next().unwrap().to_owned();
        let authorize = start.headers()["location"].to_str().unwrap().to_owned();
        let back = self
            .http
            .get(format!("{authorize}&user={user}"))
            .send()
            .await
            .unwrap();
        let callback = back.headers()["location"].to_str().unwrap().to_owned();
        let done = self
            .http
            .get(&callback)
            .header("cookie", &login_cookie)
            .send()
            .await
            .unwrap();
        if done.status() != StatusCode::OK {
            let status = done.status();
            return Err((status, done.json().await.unwrap()));
        }
        let session_cookie = done
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .find(|v| v.starts_with("__Host-spindle-operator="))
            .unwrap();
        for attribute in [
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Path=/",
            "Max-Age=1800",
        ] {
            assert!(
                session_cookie.contains(attribute),
                "{session_cookie} lacks {attribute}"
            );
        }
        assert!(done.text().await.unwrap().contains("url=/changes"));
        let cookie = session_cookie.split(';').next().unwrap().to_owned();
        let me: Value = self
            .http
            .get(format!("{}{PREFIX}/session", self.base))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        Ok(Session {
            cookie,
            csrf: me["csrf_token"].as_str().unwrap().to_owned(),
            subject: me["principal"]["subject"].as_str().unwrap().to_owned(),
        })
    }

    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        session: Option<&Session>,
    ) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .request(method, format!("{}{PREFIX}{path}", self.base));
        if let Some(session) = session {
            request = request
                .header("cookie", &session.cookie)
                .header("x-csrf-token", &session.csrf);
        }
        request
    }

    async fn get(&self, session: &Session, path: &str) -> (StatusCode, Value) {
        reply(self.call(reqwest::Method::GET, path, Some(session))).await
    }

    async fn post(
        &self,
        session: &Session,
        path: &str,
        key: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        reply(
            self.call(reqwest::Method::POST, path, Some(session))
                .header("idempotency-key", key)
                .json(body),
        )
        .await
    }

    async fn act(
        &self,
        session: &Session,
        op: &Value,
        verb: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        let id = op["id"].as_str().unwrap();
        let fresh = self.get(session, &format!("/operations/{id}")).await.1;
        reply(
            self.call(
                reqwest::Method::POST,
                &format!("/operations/{id}:{verb}"),
                Some(session),
            )
            .header(
                "idempotency-key",
                format!("{verb}-{id}-{}", fresh["version"]),
            )
            .header("if-match", format!("\"{}\"", fresh["version"]))
            .json(body),
        )
        .await
    }

    async fn approve(
        &self,
        session: &Session,
        id: &str,
        step: usize,
        confirmation: &str,
    ) -> (StatusCode, Value) {
        let fresh = self.get(session, &format!("/operations/{id}")).await.1;
        reply(
            self.call(
                reqwest::Method::POST,
                &format!("/operations/{id}/approvals"),
                Some(session),
            )
            .header(
                "idempotency-key",
                format!("approve-{id}-{}-{confirmation}", fresh["version"]),
            )
            .header("if-match", format!("\"{}\"", fresh["version"]))
            .json(&json!({"step": step, "confirmation": confirmation})),
        )
        .await
    }

    async fn wait_for(&self, session: &Session, id: &str, state: &str) -> Value {
        for _ in 0..500 {
            let (_, op) = self.get(session, &format!("/operations/{id}")).await;
            if op["state"] == state {
                return op;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (_, op) = self.get(session, &format!("/operations/{id}")).await;
        panic!("operation never reached {state}: {op:#}");
    }

    async fn deployment(&self, session: &Session) -> String {
        let (status, deployment) = self
            .post(
                session,
                "/deployments",
                &format!("dep-{}", rand_suffix()),
                &json!({"name": "prod", "driver": "model", "settings": {"namespace": "matrix", "admin_token_ref": "env:ADMIN"}}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{deployment}");
        deployment["id"].as_str().unwrap().to_owned()
    }

    fn journal(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("data/journal.jsonl")).unwrap()
    }
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

struct Session {
    cookie: String,
    csrf: String,
    subject: String,
}

async fn reply(request: reqwest::RequestBuilder) -> (StatusCode, Value) {
    let response = request.send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

// ---- sessions and roles ----------------------------------------------------

#[tokio::test]
async fn sessions_are_oidc_backed_and_roles_are_enforced_server_side() {
    let operator = Operator::start().await;

    // No role, no session.
    let (status, error) = operator.login("mallory").await.err().unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");

    let (status, _) = reply(operator.call(reqwest::Method::GET, "/view", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let viewer = operator.login("victor").await.unwrap();
    assert_eq!(operator.get(&viewer, "/view").await.0, StatusCode::OK);
    let (status, error) = operator
        .post(
            &viewer,
            "/connections",
            "v1",
            &json!({"name": "synapse", "base_url": "http://127.0.0.1:1"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");

    let alice = operator.login("alice").await.unwrap();
    // CSRF: an unsafe request without the token, or from another origin.
    let (status, _) = reply(
        operator
            .http
            .post(format!("{}{PREFIX}/connections", operator.base))
            .header("cookie", &alice.cookie)
            .header("idempotency-key", "no-csrf")
            .json(&json!({"name": "x", "base_url": "http://127.0.0.1:1"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = reply(
        operator
            .call(reqwest::Method::POST, "/connections", Some(&alice))
            .header("origin", "https://evil.example")
            .header("idempotency-key", "cross-origin")
            .json(&json!({"name": "x", "base_url": "http://127.0.0.1:1"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An operator cannot change policy; only an approver can.
    let (_, policy) = operator.get(&alice, "/policies/default").await;
    let (status, _) = reply(
        operator
            .call(reqwest::Method::PUT, "/policies/default", Some(&alice))
            .header("if-match", format!("\"{}\"", policy["version"]))
            .json(&json!({"approval_risks": [], "typed_confirmation": false})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A callback without the browser-binding cookie is refused.
    let start = operator
        .http
        .get(format!("{}{PREFIX}/session/login", operator.base))
        .send()
        .await
        .unwrap();
    let authorize = start.headers()["location"].to_str().unwrap().to_owned();
    let back = operator
        .http
        .get(format!("{authorize}&user=alice"))
        .send()
        .await
        .unwrap();
    let callback = back.headers()["location"].to_str().unwrap().to_owned();
    let (status, _) = reply(operator.http.get(&callback)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Logout ends the session for good.
    let (status, _) =
        reply(operator.call(reqwest::Method::POST, "/session/logout", Some(&alice))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        operator.get(&alice, "/view").await.0,
        StatusCode::UNAUTHORIZED
    );
}

// ---- availability while homeservers are down ------------------------------

#[tokio::test]
async fn the_console_answers_while_both_homeservers_are_down() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    // Two ports with nothing listening: Synapse and Spindle, both stopped.
    let mut ids = Vec::new();
    for name in ["synapse", "spindle"] {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        let (status, connection) = operator
            .post(
                &alice,
                "/connections",
                name,
                &json!({"name": name, "base_url": url, "credential": "env:ADMIN_TOKEN"}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{connection}");
        assert_eq!(
            connection["credential"], "env:ADMIN_TOKEN",
            "a reference, never a value"
        );
        ids.push(connection["id"].as_str().unwrap().to_owned());
    }
    for id in &ids {
        let (status, probed) = operator
            .post(
                &alice,
                &format!("/connections/{id}:probe"),
                &format!("probe-{id}"),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{probed}");
        assert_eq!(probed["last_probe"]["reachable"], false);
    }
    let (status, view) = operator.get(&alice, "/view").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["connections"].as_array().unwrap().len(), 2);
    let deployment = operator.deployment(&alice).await;
    let (status, assessment) = operator
        .post(
            &alice,
            "/assessments",
            "assess",
            &json!({"deployment": deployment}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{assessment}");
    assert_eq!(assessment["findings"][0]["severity"], "blocker");
}

// ---- idempotency and optimistic concurrency -------------------------------

#[tokio::test]
async fn idempotency_keys_replay_and_refuse_reuse() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let body = json!({"name": "synapse", "base_url": "https://synapse.example.org"});
    let (first_status, first) = operator.post(&alice, "/connections", "k1", &body).await;
    assert_eq!(first_status, StatusCode::CREATED);
    let replay = operator
        .call(reqwest::Method::POST, "/connections", Some(&alice))
        .header("idempotency-key", "k1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers()["idempotent-replayed"], "true");
    assert_eq!(replay.json::<Value>().await.unwrap()["id"], first["id"]);
    let (_, list) = operator.get(&alice, "/connections").await;
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "the retry created nothing"
    );

    let (status, error) = operator
        .post(
            &alice,
            "/connections",
            "k1",
            &json!({"name": "other", "base_url": "https://x.example"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["error"]["code"], "idempotency_key_reused");

    let (status, error) = reply(
        operator
            .call(reqwest::Method::POST, "/connections", Some(&alice))
            .json(&body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["error"]["code"], "idempotency_key_required");

    // Keys are per person: Bob's k1 is not Alice's.
    let carol = operator.login("carol").await.unwrap();
    assert_eq!(
        operator.post(&carol, "/connections", "k1", &body).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn acting_needs_the_current_etag() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let deployment = operator.deployment(&alice).await;
    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "op",
            &json!({"deployment": deployment, "action": "migrate"}),
        )
        .await;
    let id = op["id"].as_str().unwrap();
    let waiting = operator.wait_for(&alice, id, "awaiting_approval").await;

    let response = operator
        .call(
            reqwest::Method::GET,
            &format!("/operations/{id}"),
            Some(&alice),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["etag"],
        format!("\"{}\"", waiting["version"]).as_str()
    );

    let (status, _) = reply(
        operator
            .call(
                reqwest::Method::POST,
                &format!("/operations/{id}:pause"),
                Some(&alice),
            )
            .header("idempotency-key", "no-precondition"),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let (status, error) = reply(
        operator
            .call(
                reqwest::Method::POST,
                &format!("/operations/{id}:pause"),
                Some(&alice),
            )
            .header("idempotency-key", "stale")
            .header("if-match", "\"1\""),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{error}");
    let (status, paused) = operator.act(&alice, &op, "pause", &json!({})).await;
    assert_eq!(status, StatusCode::OK, "{paused}");
    assert_eq!(paused["state"], "paused");
}

// ---- leases, approvals, evidence and audit --------------------------------

#[tokio::test]
async fn a_persisted_lease_rejects_conflicting_operations() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let deployment = operator.deployment(&alice).await;
    let (_, first) = operator
        .post(
            &alice,
            "/operations",
            "first",
            &json!({"deployment": deployment, "action": "migrate"}),
        )
        .await;
    operator
        .wait_for(&alice, first["id"].as_str().unwrap(), "awaiting_approval")
        .await;

    let (status, error) = operator
        .post(
            &alice,
            "/operations",
            "second",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "lease_held");

    // The lease survives a restart: it is in the journal, not in memory.
    let operator = operator.crash_and_restart().await;
    let alice = operator.login("alice").await.unwrap();
    let (status, _) = operator
        .post(
            &alice,
            "/operations",
            "third",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, cancelled) = operator.act(&alice, &first, "cancel", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancelled["state"], "cancelled");
    let (status, _) = operator
        .post(
            &alice,
            "/operations",
            "fourth",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn high_risk_steps_need_an_independent_typed_approval_and_everything_is_audited() {
    let operator = Operator::start().await;
    let carol = operator.login("carol").await.unwrap();
    let bob = operator.login("bob").await.unwrap();
    let deployment = operator.deployment(&carol).await;
    let (status, op) = operator
        .post(
            &carol,
            "/operations",
            "migrate",
            &json!({"deployment": deployment, "action": "migrate"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{op}");
    let id = op["id"].as_str().unwrap();
    let waiting = operator.wait_for(&carol, id, "awaiting_approval").await;
    assert_eq!(waiting["steps"][1]["state"], "completed");
    assert_eq!(
        waiting["steps"][2]["state"], "pending",
        "the high-risk step has not run"
    );

    // Carol holds the approver role but asked for this herself.
    let (status, _) = operator
        .approve(&carol, id, 2, &format!("{id}/switch"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Bob must type what he is approving.
    let (status, error) = operator.approve(&bob, id, 2, "yes").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error["error"]["code"], "confirmation_mismatch");
    let (status, approved) = operator.approve(&bob, id, 2, &format!("{id}/switch")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let done = operator.wait_for(&carol, id, "succeeded").await;
    assert_eq!(done["approvals"][0]["approver"], bob.subject.as_str());
    let (_, view) = operator.get(&carol, "/view").await;
    assert!(
        view["deployments"][0]["lease"].is_null(),
        "a finished operation releases its lease"
    );

    // Evidence is stored redacted, and served until it expires.
    let artifact = done["steps"][1]["artifacts"][0].as_str().unwrap();
    let (status, evidence) = operator.get(&bob, &format!("/artifacts/{artifact}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(evidence["content"]["replicas"], 0);
    assert_eq!(evidence["content"]["admin_token"], "[redacted]");

    // The audit trail names actor, request, approval and every step.
    let (_, audit) = operator
        .get(&bob, &format!("/audit?operation={id}&limit=500"))
        .await;
    let changes: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["change"]["type"].as_str().unwrap())
        .collect();
    for expected in [
        "operation_created",
        "lease_acquired",
        "step_started",
        "step_completed",
        "artifact_stored",
        "approval_recorded",
        "lease_released",
    ] {
        assert!(
            changes.contains(&expected),
            "audit lacks {expected}: {changes:?}"
        );
    }
    let created = &audit["events"][0];
    assert_eq!(created["actor"]["subject"], carol.subject.as_str());
    let approval = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["change"]["type"] == "approval_recorded")
        .unwrap();
    assert_eq!(approval["actor"]["subject"], bob.subject.as_str());

    // No secret reached the audit output or the journal on disk: not the
    // driver's leaked token, not a session id.
    let (_, everything) = operator.get(&bob, "/audit?limit=500").await;
    let text = everything.to_string();
    assert!(!text.contains("syt_"), "{text}");
    let journal = operator.journal();
    assert!(!journal.contains("syt_"));
    assert!(!journal.contains(CLIENT_SECRET));
    let session_id = bob.cookie.split_once('=').unwrap().1;
    assert!(
        !journal.contains(session_id),
        "only session hashes are recorded"
    );
}

// ---- restart, cancel and rollback -----------------------------------------

#[tokio::test]
async fn a_restart_resumes_from_checkpoints_without_repeating_mutations() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let deployment = operator.deployment(&alice).await;
    // `patch` applies its change and then the process dies before the
    // checkpoint is written.
    operator
        .driver
        .world
        .lock()
        .unwrap()
        .hang
        .insert("patch".to_owned());
    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "op",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    let id = op["id"].as_str().unwrap().to_owned();
    for _ in 0..500 {
        let (_, now) = operator.get(&alice, &format!("/operations/{id}")).await;
        if now["steps"][1]["state"] == "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    operator.driver.world.lock().unwrap().hang.clear();
    let operator = operator.crash_and_restart().await;
    let alice = operator.login("alice").await.unwrap();
    let done = operator.wait_for(&alice, &id, "succeeded").await;
    assert_eq!(done["steps"][1]["checkpoint"], json!({"observed": "patch"}));

    let world = operator.driver.world.lock().unwrap();
    let ran = |name: &str| {
        world
            .executions
            .iter()
            .filter(|(_, step)| step == name)
            .count()
    };
    assert_eq!(ran("scale-down"), 1, "a completed step is never run again");
    assert_eq!(
        ran("patch"),
        1,
        "an applied mutation is observed, not repeated"
    );
    assert_eq!(world.observations, vec![(id.clone(), "patch".to_owned())]);
}

#[tokio::test]
async fn an_unobservable_interruption_stops_for_a_person() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let deployment = operator.deployment(&alice).await;
    operator
        .driver
        .world
        .lock()
        .unwrap()
        .hang
        .insert("scale-down".to_owned());
    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "op",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    let id = op["id"].as_str().unwrap().to_owned();
    while operator.get(&alice, &format!("/operations/{id}")).await.1["steps"][0]["state"]
        != "running"
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    {
        let mut world = operator.driver.world.lock().unwrap();
        world.hang.clear();
        world.blind = true;
    }
    let operator = operator.crash_and_restart().await;
    let alice = operator.login("alice").await.unwrap();
    let stuck = operator.wait_for(&alice, &id, "attention_required").await;
    assert!(
        stuck["reason"].as_str().unwrap().contains("unknown"),
        "{stuck}"
    );

    // A person checks the cluster and says the change did happen.
    operator.driver.world.lock().unwrap().blind = false;
    let (status, resumed) = operator
        .act(&alice, &stuck, "resume", &json!({"resolution": "applied"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{resumed}");
    operator.wait_for(&alice, &id, "succeeded").await;
    let world = operator.driver.world.lock().unwrap();
    assert_eq!(
        world
            .executions
            .iter()
            .filter(|(_, s)| s == "scale-down")
            .count(),
        1
    );
}

#[tokio::test]
async fn rollback_compensates_in_reverse_and_stops_at_the_write_boundary() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let bob = operator.login("bob").await.unwrap();
    let deployment = operator.deployment(&alice).await;

    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "rev",
            &json!({"deployment": deployment, "action": "reversible", "params": {"fail_at": 1}}),
        )
        .await;
    let id = op["id"].as_str().unwrap().to_owned();
    let failed = operator.wait_for(&alice, &id, "failed").await;
    assert!(
        !failed["steps"][1]["error"]
            .as_str()
            .unwrap()
            .contains("syt_"),
        "{failed}"
    );
    let (status, _) = operator.act(&alice, &failed, "rollback", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    operator.wait_for(&alice, &id, "rolled_back").await;
    {
        let world = operator.driver.world.lock().unwrap();
        let undone: Vec<&str> = world
            .compensations
            .iter()
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(
            undone,
            ["patch", "scale-down"],
            "newest first, including the failed step"
        );
        assert!(world.applied.is_empty());
    }

    // Past a step that cannot be undone, rollback is refused.
    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "mig",
            &json!({"deployment": deployment, "action": "migrate", "params": {"fail_at": 3}}),
        )
        .await;
    let id = op["id"].as_str().unwrap().to_owned();
    operator.wait_for(&alice, &id, "awaiting_approval").await;
    operator
        .approve(&bob, &id, 2, &format!("{id}/switch"))
        .await;
    let failed = operator.wait_for(&alice, &id, "failed").await;
    let (status, error) = operator.act(&alice, &failed, "rollback", &json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "write_boundary_crossed");
    let (status, cancelled) = operator.act(&alice, &failed, "cancel", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancelled["state"], "cancelled");
    let (status, error) = operator.act(&alice, &cancelled, "resume", &json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
}

// ---- the event stream ------------------------------------------------------

#[tokio::test]
async fn operation_events_stream_and_resume_from_last_event_id() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let deployment = operator.deployment(&alice).await;
    let (_, op) = operator
        .post(
            &alice,
            "/operations",
            "op",
            &json!({"deployment": deployment, "action": "reversible"}),
        )
        .await;
    let id = op["id"].as_str().unwrap();
    // Read live: the stream ends by itself at the terminal state.
    let stream = operator
        .call(
            reqwest::Method::GET,
            &format!("/operations/{id}/events"),
            Some(&alice),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stream.headers()["content-type"], "text/event-stream");
    let text = tokio::time::timeout(Duration::from_secs(10), stream.text())
        .await
        .unwrap()
        .unwrap();
    let ids: Vec<u64> = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix("id: ")
                .or_else(|| line.strip_prefix("id:"))
        })
        .map(|id| id.trim().parse().unwrap())
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    assert!(text.contains("\"succeeded\""), "{text}");

    // Reconnecting after the third event replays only what came after it.
    let resumed = operator
        .call(
            reqwest::Method::GET,
            &format!("/operations/{id}/events"),
            Some(&alice),
        )
        .header("last-event-id", ids[2].to_string())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let resumed_ids: Vec<u64> = resumed
        .lines()
        .filter_map(|line| {
            line.strip_prefix("id: ")
                .or_else(|| line.strip_prefix("id:"))
        })
        .map(|id| id.trim().parse().unwrap())
        .collect();
    assert_eq!(resumed_ids, ids[3..]);
}

#[tokio::test]
async fn inline_secrets_are_refused_at_the_door() {
    let operator = Operator::start().await;
    let alice = operator.login("alice").await.unwrap();
    let (status, error) = operator
        .post(&alice, "/deployments", "inline", &json!({"name": "prod", "driver": "model", "settings": {"db": {"password": "hunter2"}}}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("settings.db.password")
    );
    let deployment = operator.deployment(&alice).await;
    let (status, _) = operator
        .post(&alice, "/operations", "inline-op", &json!({"deployment": deployment, "action": "reversible", "params": {"token": "syt_abc"}}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = operator
        .post(
            &alice,
            "/connections",
            "inline-conn",
            &json!({"name": "x", "base_url": "https://x.example", "credential": "syt_abc"}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!operator.journal().contains("hunter2"));
}

// ---- the console (#458) and its homeserver views --------------------------

const ADMIN_TOKEN: &str = "syt_b3BlcmF0b3I_fakeadmintoken_0aBcD";

/// A stand-in homeserver serving the Synapse admin API the console reads.
/// It records every request so a test can see what the operator asked.
#[derive(Clone, Default)]
struct Homeserver {
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

async fn homeserver_admin(
    State(server): State<Homeserver>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    // Decoded, as a homeserver's router decodes it.
    let path = percent_decode(uri.path());
    let query = uri.query().unwrap_or_default().to_owned();
    server
        .seen
        .lock()
        .unwrap()
        .push((format!("{path}?{query}"), authorization.clone()));
    if authorization != format!("Bearer {ADMIN_TOKEN}") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"errcode": "M_UNKNOWN_TOKEN", "error": "no"})),
        )
            .into_response();
    }
    let alice = "@alice:hs.example";
    let room = "!ops:hs.example";
    let body = match path.as_str() {
        "/_synapse/admin/v2/users" => json!({
            "users": [{
                "name": alice, "displayname": "Alice", "admin": false, "deactivated": false,
                "locked": true, "suspended": false, "erased": false, "shadow_banned": false,
                "creation_ts": 1_700_000_000_000_u64, "last_seen_ts": null,
                "password_hash": "$argon2id$should-never-leave",
                "internal_note": "not for the browser",
            }],
            "total": 3,
            "next_token": "2",
        }),
        "/_synapse/admin/v2/users/@alice:hs.example" => json!({
            "name": alice, "displayname": "Alice", "admin": false, "deactivated": false,
            "locked": true, "suspended": false, "erased": false,
            "threepids": [{"medium": "email", "address": "alice@example.org"}],
            "external_ids": [],
            "password_hash": "$argon2id$should-never-leave",
        }),
        "/_synapse/admin/v2/users/@alice:hs.example/devices" => json!({
            "devices": [{"device_id": "PHONE", "display_name": "Phone",
                         "last_seen_ts": 1, "last_seen_ip": "203.0.113.7",
                         "last_seen_user_agent": "Element X"}],
            "total": 1,
        }),
        "/_synapse/admin/v1/users/@alice:hs.example/joined_rooms" => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"errcode": "M_UNKNOWN", "error": "boom"})),
            )
                .into_response();
        }
        "/_synapse/admin/v1/rooms" => json!({
            "rooms": [{"room_id": room, "name": "Ops", "canonical_alias": null,
                       "joined_members": 2, "joined_local_members": 1, "version": "11",
                       "creator": alice, "encryption": null, "federatable": true,
                       "public": false, "join_rules": "invite", "room_type": null,
                       "state_events": 9}],
            "offset": 0, "total_rooms": 1,
        }),
        "/_synapse/admin/v1/rooms/!ops:hs.example" => json!({
            "room_id": room, "name": "Ops", "topic": "on call", "canonical_alias": null,
            "joined_members": 2, "joined_local_members": 1, "joined_local_devices": 1,
            "version": "11", "creator": alice, "encryption": "m.megolm.v1.aes-sha2",
            "federatable": true, "public": false, "join_rules": "invite",
            "guest_access": null, "history_visibility": "shared", "state_events": 9,
            "room_type": null, "forgotten": false,
        }),
        "/_synapse/admin/v1/rooms/!ops:hs.example/members" => {
            json!({"members": [alice, "@bob:elsewhere.example"], "total": 2})
        }
        "/_synapse/admin/v1/rooms/!ops:hs.example/block" => {
            json!({"block": true, "user_id": "@root:hs.example"})
        }
        "/_synapse/admin/v1/scheduled_tasks" => json!({"scheduled_tasks": []}),
        "/_synapse/admin/v1/event_reports" => json!({
            "event_reports": [{"id": 4, "received_ts": 5, "room_id": room, "name": "Ops",
                               "event_id": "$e", "user_id": alice,
                               "sender": "@bob:elsewhere.example", "reason": "spam",
                               "score": -100}],
            "total": 1,
        }),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"errcode": "M_NOT_FOUND", "error": "no"})),
            )
                .into_response();
        }
    };
    Json(body).into_response()
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let Some(byte) = raw
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

impl Homeserver {
    async fn start() -> (Homeserver, String) {
        let server = Homeserver::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .fallback(homeserver_admin)
            .with_state(server.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (server, url)
    }

    fn seen(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Operator {
    /// A connection to `url` whose admin credential is the file `token`.
    async fn connection(&self, session: &Session, url: &str, token: Option<&str>) -> String {
        let mut body = json!({"name": "homeserver", "base_url": url});
        if let Some(token) = token {
            let path = self.dir.path().join(format!("token-{}", rand_suffix()));
            std::fs::write(&path, format!("{token}\n")).unwrap();
            body["credential"] = json!(format!("file:{}", path.display()));
        }
        let (status, connection) = self
            .post(
                session,
                "/connections",
                &format!("conn-{}", rand_suffix()),
                &body,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{connection}");
        connection["id"].as_str().unwrap().to_owned()
    }
}

/// People & access and Rooms & safety read the homeserver through the
/// operator: the browser gets fixed fields, never the credential, and a
/// viewer does not see contact details or addresses.
#[tokio::test]
async fn people_and_rooms_come_from_the_homeserver_without_its_credential() {
    let operator = Operator::start().await;
    let (homeserver, url) = Homeserver::start().await;
    let alice = operator.login("alice").await.unwrap();
    let victor = operator.login("victor").await.unwrap();
    let id = operator.connection(&alice, &url, Some(ADMIN_TOKEN)).await;

    let (status, people) = operator
        .get(
            &victor,
            &format!("/connections/{id}/people?search=ali&limit=1000"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{people}");
    assert_eq!(people["total"], 3);
    assert_eq!(people["next"], 2, "an offset, as a number");
    let person = &people["people"][0];
    assert_eq!(person["name"], "@alice:hs.example");
    assert_eq!(person["locked"], true);
    assert!(person.get("password_hash").is_none(), "{person}");
    assert!(person.get("internal_note").is_none(), "{person}");
    let (asked, authorization) = &homeserver.seen()[0];
    assert!(asked.contains("name=ali"), "{asked}");
    assert!(
        asked.contains("limit=100"),
        "the page size is capped: {asked}"
    );
    assert_eq!(authorization, &format!("Bearer {ADMIN_TOKEN}"));

    // A viewer's person page: devices, no address, no email; the rooms
    // lookup failed and says so rather than blanking the page.
    let path = format!("/connections/{id}/people/%40alice%3Ahs.example");
    let (status, page) = operator.get(&victor, &path).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["devices"][0]["device_id"], "PHONE");
    assert!(page["devices"][0].get("last_seen_ip").is_none(), "{page}");
    assert!(page["person"].get("threepids").is_none(), "{page}");
    assert!(page["person"].get("password_hash").is_none(), "{page}");
    assert_eq!(page["joined_rooms"], Value::Null);
    assert_eq!(page["unavailable"][0]["part"], "joined_rooms");
    assert_eq!(page["unavailable"][0]["code"], "homeserver_error");
    // An operator sees them.
    let (_, page) = operator.get(&alice, &path).await;
    assert_eq!(page["devices"][0]["last_seen_ip"], "203.0.113.7");
    assert_eq!(
        page["person"]["threepids"][0]["address"],
        "alice@example.org"
    );

    let (status, rooms) = operator
        .get(
            &victor,
            &format!("/connections/{id}/rooms?search=op&order_by=joined_members"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rooms}");
    assert_eq!(rooms["rooms"][0]["room_id"], "!ops:hs.example");
    assert_eq!(rooms["total"], 1);
    assert_eq!(rooms["next"], Value::Null);
    let (status, _) = operator
        .get(
            &victor,
            &format!("/connections/{id}/rooms?order_by=password"),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, room) = operator
        .get(
            &victor,
            &format!("/connections/{id}/rooms/%21ops%3Ahs.example"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    assert_eq!(room["room"]["topic"], "on call");
    assert_eq!(room["block"]["block"], true);
    assert_eq!(room["members"]["total"], 2);
    assert_eq!(room["reports"][0]["reason"], "spam");
    assert_eq!(room["tasks"], json!([]));
    assert_eq!(room["unavailable"], json!([]));

    let (status, reports) = operator
        .get(&victor, &format!("/connections/{id}/reports"))
        .await;
    assert_eq!(status, StatusCode::OK, "{reports}");
    assert_eq!(reports["reports"][0]["id"], 4);

    // The credential reached the homeserver and nowhere else.
    let (_, view) = operator.get(&victor, "/view").await;
    let (_, audit) = operator.get(&alice, "/audit").await;
    for text in [view.to_string(), audit.to_string(), operator.journal()] {
        assert!(!text.contains(ADMIN_TOKEN), "the admin token leaked");
    }
    // Reads need a session.
    let (status, _) = reply(operator.call(
        reqwest::Method::GET,
        &format!("/connections/{id}/people"),
        None,
    ))
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Every way the homeserver side can fail has its own code, so the console
/// can say what is wrong instead of showing an empty table.
#[tokio::test]
async fn homeserver_failures_are_named_not_blank() {
    let operator = Operator::start().await;
    let (_, url) = Homeserver::start().await;
    let alice = operator.login("alice").await.unwrap();

    let without = operator.connection(&alice, &url, None).await;
    let (status, error) = operator
        .get(&alice, &format!("/connections/{without}/people"))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["error"]["code"], "no_credential");

    let wrong = operator
        .connection(&alice, &url, Some("syt_not_the_right_token"))
        .await;
    let (status, error) = operator
        .get(&alice, &format!("/connections/{wrong}/rooms"))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{error}");
    assert_eq!(error["error"]["code"], "homeserver_refused");
    assert!(!error.to_string().contains("syt_not_the_right_token"));

    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let down = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let stopped = operator.connection(&alice, &down, Some(ADMIN_TOKEN)).await;
    let (status, error) = operator
        .get(&alice, &format!("/connections/{stopped}/reports"))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{error}");
    assert_eq!(error["error"]["code"], "homeserver_unreachable");

    let (status, error) = operator
        .post(
            &alice,
            "/connections",
            "missing-secret",
            &json!({"name": "gone", "base_url": url, "credential": "file:/nonexistent/spindle-token"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{error}");
    let gone = error["id"].as_str().unwrap();
    let (status, error) = operator
        .get(&alice, &format!("/connections/{gone}/people"))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{error}");
    assert_eq!(error["error"]["code"], "credential_unavailable");

    let (status, _) = operator.get(&alice, "/connections/nope/people").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The console is three static files on the operator's own origin, with a
/// policy that lets them load and call nothing else.
#[tokio::test]
async fn the_console_is_served_from_the_operator_with_a_strict_policy() {
    let operator = Operator::start().await;
    let root = operator
        .http
        .get(format!("{}/", operator.base))
        .send()
        .await
        .unwrap();
    assert!(root.status().is_redirection());
    assert_eq!(root.headers()["location"], "/console/");

    let page = operator
        .http
        .get(format!("{}/console/", operator.base))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let policy = page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(policy.contains("script-src 'self'"), "{policy}");
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert!(!policy.contains("unsafe-inline"), "{policy}");
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    let html = page.text().await.unwrap();
    // The accessibility skeleton: a language, a skip link, landmarks, a
    // live region, and no inline script.
    for needle in [
        "<html lang=\"en\"",
        "class=\"skip-link\" href=\"#main\"",
        "<nav aria-label=\"Primary\">",
        "<main id=\"main\"",
        "aria-live=\"polite\"",
        "<script src=\"/console/app.js\" defer></script>",
    ] {
        assert!(html.contains(needle), "{needle} missing");
    }
    for (path, kind) in [
        ("/console/app.js", "text/javascript"),
        ("/console/app.css", "text/css"),
    ] {
        let asset = operator
            .http
            .get(format!("{}{path}", operator.base))
            .send()
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert!(
            asset.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(kind)
        );
    }
    // The script reads only the operator API and never stores anything.
    let script = operator
        .http
        .get(format!("{}/console/app.js", operator.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(script.contains("const API = \"/_spindle/operator/v1\""));
    for forbidden in [
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "innerHTML",
        "/_synapse",
        "/_matrix",
    ] {
        assert!(!script.contains(forbidden), "the console uses {forbidden}");
    }
    // The API keeps its own closed policy.
    let (status, _) = reply(operator.call(reqwest::Method::GET, "/view", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let api = operator
        .http
        .get(format!("{}{PREFIX}/view", operator.base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        api.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
}

/// A refused request is not remembered under its key: the refusal changed
/// nothing, and storing it would let anyone grow the journal.
#[tokio::test]
async fn refusals_are_not_stored_under_their_key() {
    let operator = Operator::start().await;
    let victor = operator.login("victor").await.unwrap();
    let before = operator.journal().lines().count();
    for _ in 0..3 {
        let response = operator
            .call(reqwest::Method::POST, "/connections", Some(&victor))
            .header("idempotency-key", "viewer-key")
            .json(&json!({"name": "x", "base_url": "https://x.example"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("idempotent-replayed").is_none());
    }
    assert_eq!(operator.journal().lines().count(), before);
}
