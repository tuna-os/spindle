//! The RTC SFU program: the switch, the two models, and the minter gaps
//! MSC4195 and `lk-jwt-service` 0.7 name.
//!
//! What this pins, claim by claim: the program is on exactly when
//! `[rtc.livekit]` is set unless the operator flipped the switch; the
//! switch lives in the store (a restart reads it back, the config file is
//! never rewritten); off reads as unconfigured everywhere — `sfu/get`,
//! `get_token`, the delegation probe and the webhook answer 404
//! `M_UNRECOGNIZED`, and both discovery surfaces drop the built-in
//! transport; the minter checks and grants are identical on the local
//! (supervised-sidecar) and remote models; MSC4195's homeserver
//! `get_token` mints over the caller's access token; the federation twin
//! refuses unsigned callers; the delegation probe records the hold and the
//! SFU webhook releases it; the sidecar config generates with the SFU's
//! keys and never beside the operator's files; and the supervised binary
//! is pinned at v1.13.5.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const REMOTE: &str = r#"
[rtc.livekit]
url = "wss://sfu.example.org"
key = "APIkey"
secret = "not-the-signing-key"
"#;

const LOCAL: &str = r#"
[rtc.livekit]
url = "wss://127.0.0.1:7880"
key = "APIkey"
secret = "not-the-signing-key"
binary = "/nonexistent/livekit-server"
"#;

const SFU_GET: &str = "/_spindle/rtc/livekit/sfu/get";
const GET_TOKEN: &str = "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token";
const GET_TOKEN_STABLE: &str = "/_matrix/client/v3/rtc/livekit/get_token";
const FED_TOKEN: &str = "/_matrix/federation/v1/rtc/livekit/get_token";
const DELEGATE: &str =
    "/_matrix/client/unstable/io.element.msc4195/rtc/livekit/delegate_delayed_leave";
const WEBHOOK: &str = "/_spindle/rtc/livekit/sfu/webhook";
const ADMIN: &str = "/_spindle/admin/v1/rtc/sfu";

struct Harness {
    _dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

struct Session {
    user_id: String,
    device_id: String,
    access_token: String,
}

impl Harness {
    fn with(rtc: &str) -> Self {
        let dir = TempDir::new().unwrap();
        Self::rebuild_in(dir, rtc)
    }

    fn rebuild_in(dir: TempDir, rtc: &str) -> Self {
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = Self::app_for(rtc, Arc::clone(&store));
        Self {
            _dir: dir,
            store,
            app,
        }
    }

    fn app_for(rtc: &str, store: Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{rtc}"
        ))
        .expect("the configuration is valid");
        spindle_server::app(config, store).expect("a signing key is established")
    }

    /// A new app over the same store: what a restart sees.
    fn restart(&mut self, rtc: &str) {
        self.app = Self::app_for(rtc, Arc::clone(&self.store));
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

    async fn post(&self, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.call(request.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn get(&self, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder().method("GET").uri(uri);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        self.call(request.body(Body::empty()).unwrap()).await
    }

    async fn put(&self, uri: &str, token: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> Session {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/register",
                None,
                json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Session {
            user_id: body["user_id"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
            access_token: body["access_token"].as_str().unwrap().to_owned(),
        }
    }

    fn make_admin(&self, session: &Session) {
        let localpart = session
            .user_id
            .trim_start_matches('@')
            .split(':')
            .next()
            .unwrap();
        spindle_server::accounts::Accounts::new(self.store.as_ref(), "example.org")
            .set_admin(localpart, true)
            .unwrap();
    }

    async fn create_room(&self, session: &Session) -> String {
        let (status, body) = self
            .post(
                "/_matrix/client/v3/createRoom",
                Some(&session.access_token),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn openid_token(&self, session: &Session) -> Value {
        let (status, body) = self
            .post(
                &format!(
                    "/_matrix/client/v3/user/{}/openid/request_token",
                    session.user_id
                ),
                Some(&session.access_token),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn transports(&self, token: &str) -> Value {
        let (status, body) = self
            .get("/_matrix/client/v1/rtc/transports", Some(token))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["rtc_transports"].clone()
    }
}

/// The program is on exactly when configured, until the switch says otherwise.
#[tokio::test]
async fn status_reports_the_model_and_defaults_to_the_config() {
    let harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);

    let (status, body) = harness.get(ADMIN, Some(&alice.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["configured"], true);
    assert_eq!(body["model"], "remote");
    assert_eq!(body["switch"], Value::Null, "never flipped");
    assert_eq!(body["sfu_url"], "wss://sfu.example.org");
    assert_eq!(body["version_pin"], "v1.13.5");
    assert_eq!(body["supervised"]["health"], "remote");

    let bare = Harness::with("");
    let bob = bare.register("bob").await;
    bare.make_admin(&bob);
    let (status, body) = bare.get(ADMIN, Some(&bob.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false, "unconfigured is off");
    assert_eq!(body["model"], Value::Null);
}

/// The admin switch turns the whole program off: every minter path answers
/// the absent endpoint's 404, and discovery drops the transport.
#[tokio::test]
async fn switching_off_silences_everything_and_on_restores_it() {
    let harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);
    let room = harness.create_room(&alice).await;
    let openid = harness.openid_token(&alice).await;

    let (status, body) = harness
        .put(ADMIN, &alice.access_token, json!({ "enabled": false }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["switch"], false);

    let sfu_body = json!({
        "room": room,
        "openid_token": openid.clone(),
        "device_id": alice.device_id,
    });
    let (status, body) = harness.post(SFU_GET, None, sfu_body).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");

    for path in [GET_TOKEN, GET_TOKEN_STABLE] {
        let (status, body) = harness
            .post(path, Some(&alice.access_token), json!({ "room_id": room }))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{path}: {body}");
    }
    let (status, body) = harness
        .post(
            DELEGATE,
            Some(&alice.access_token),
            json!({ "delay_id": "d1" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness.post(WEBHOOK, None, json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = harness
        .post(
            FED_TOKEN,
            None,
            json!({ "room_id": room, "user_id": "@x:other.org", "device_id": "D" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the gate runs first: {body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");

    assert_eq!(harness.transports(&alice.access_token).await, json!([]));
    let (status, well_known) = harness.get("/.well-known/matrix/client", None).await;
    assert_eq!(status, StatusCode::OK, "{well_known}");
    assert!(
        well_known.get("org.matrix.msc4143.rtc_foci").is_none(),
        "unadvertised when off: {well_known}"
    );

    let (status, body) = harness
        .put(ADMIN, &alice.access_token, json!({ "enabled": true }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .post(
            SFU_GET,
            None,
            json!({
                "room": room,
                "openid_token": harness.openid_token(&alice).await,
                "device_id": alice.device_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "minting again: {body}");
    assert_eq!(
        harness.transports(&alice.access_token).await,
        json!([{ "type": "livekit", "livekit_service_url": "https://example.org/_spindle/rtc/livekit" }])
    );
}

/// The switch survives a restart, and the config file is never rewritten.
#[tokio::test]
async fn the_switch_persists_across_restarts() {
    let mut harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);

    let (status, _) = harness
        .put(ADMIN, &alice.access_token, json!({ "enabled": false }))
        .await;
    assert_eq!(status, StatusCode::OK);

    harness.restart(REMOTE);
    let (status, body) = harness.get(ADMIN, Some(&alice.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false, "the store remembered off");
    assert_eq!(body["switch"], false);

    let room = harness.create_room(&alice).await;
    let (status, body) = harness
        .post(
            SFU_GET,
            None,
            json!({
                "room": room,
                "openid_token": harness.openid_token(&alice).await,
                "device_id": alice.device_id,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
}

/// `on` with nothing configured is refused: there is no program to start.
#[tokio::test]
async fn enabling_an_unconfigured_server_is_refused() {
    let harness = Harness::with("");
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);

    let (status, body) = harness
        .put(ADMIN, &alice.access_token, json!({ "enabled": true }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The switch is behind admin auth on both spellings.
#[tokio::test]
async fn the_switch_refuses_non_admins() {
    let harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    for path in [ADMIN, "/_synapse/admin/v1/rtc/sfu"] {
        let (status, _) = harness.get(path, Some(&bob.access_token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        let (status, _) = harness
            .put(path, &bob.access_token, json!({ "enabled": false }))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    let (status, body) = harness.get(ADMIN, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let _ = alice;
}

/// The local model mints exactly like the remote one, and reports itself.
#[tokio::test]
async fn the_local_model_mints_identically_and_reports_supervision() {
    let harness = Harness::with(LOCAL);
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);
    let room = harness.create_room(&alice).await;

    let (status, body) = harness.get(ADMIN, Some(&alice.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["model"], "local");
    assert_eq!(body["supervised"]["model"], "local");
    assert_eq!(body["supervised"]["binary"], "/nonexistent/livekit-server");
    assert_eq!(body["supervised"]["health"], "missing-binary");
    assert_eq!(body["supervised"]["version_pin"], "v1.13.5");
    assert_eq!(body["supervised"]["running"], false);

    let (status, body) = harness
        .post(
            SFU_GET,
            None,
            json!({
                "room": room,
                "openid_token": harness.openid_token(&alice).await,
                "device_id": alice.device_id,
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "same minter, supervised or not: {body}"
    );
    assert_eq!(body["url"], "wss://127.0.0.1:7880");
    assert!(
        body["jwt"]
            .as_str()
            .is_some_and(|jwt| jwt.split('.').count() == 3)
    );

    let (status, body) = harness
        .post(
            GET_TOKEN,
            Some(&alice.access_token),
            json!({ "room_id": room }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["url"], "wss://127.0.0.1:7880");
}

/// MSC4195's homeserver endpoint: the access token is the credential, the
/// device defaults to the caller's, and the shape matches `sfu/get`.
#[tokio::test]
async fn get_token_mints_over_the_access_token() {
    let harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_room(&alice).await;

    for path in [GET_TOKEN, GET_TOKEN_STABLE] {
        let (status, body) = harness
            .post(path, Some(&alice.access_token), json!({ "room_id": room }))
            .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(body["url"], "wss://sfu.example.org", "{path}");
        let jwt = body["jwt"].as_str().expect("a jwt");
        let claims: Value =
            serde_json::from_slice(&base64url_decode(jwt.split('.').nth(1).unwrap())).unwrap();
        assert_eq!(claims["video"]["room"], room);
        assert_eq!(
            claims["sub"],
            format!("{}:{}", alice.user_id, alice.device_id),
            "the caller's device, unsaid"
        );
    }

    let (status, body) = harness
        .post(
            GET_TOKEN,
            Some(&alice.access_token),
            json!({ "room_id": room, "device_id": "EXTRA" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims: Value = serde_json::from_slice(&base64url_decode(
        body["jwt"].as_str().unwrap().split('.').nth(1).unwrap(),
    ))
    .unwrap();
    assert_eq!(claims["sub"], format!("{}:EXTRA", alice.user_id));

    let (status, body) = harness
        .post(
            GET_TOKEN,
            Some(&bob.access_token),
            json!({ "room_id": room }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not a member: {body}");

    let (status, body) = harness
        .post(GET_TOKEN, None, json!({ "room_id": room }))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = harness
        .post(GET_TOKEN, Some(&alice.access_token), json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_MISSING_PARAM", "{body}");
}

/// The federation twin authenticates the origin; an unsigned caller gets
/// nothing, whichever state the program is in.
#[tokio::test]
async fn the_federation_twin_refuses_unsigned_callers() {
    let harness = Harness::with(REMOTE);
    let (status, body) = harness
        .post(
            FED_TOKEN,
            None,
            json!({ "room_id": "!r:example.org", "user_id": "@x:other.org", "device_id": "D" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED", "{body}");

    let (status, body) = harness
        .post(
            "/_matrix/federation/unstable/io.element.msc4195/rtc/livekit/get_token",
            None,
            json!({ "room_id": "!r:example.org", "user_id": "@x:other.org", "device_id": "D" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// The delegation probe is 404 exactly when nothing can hold the leave,
/// and records the hold otherwise; the webhook releases it.
#[tokio::test]
async fn delegation_is_held_then_released_by_sfu_events() {
    let harness = Harness::with(REMOTE);
    let alice = harness.register("alice").await;
    harness.make_admin(&alice);
    let room = harness.create_room(&alice).await;

    let (status, body) = harness
        .post(
            DELEGATE,
            Some(&alice.access_token),
            json!({ "room_id": room, "delay_id": "hold-1" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held"], true);

    let (status, body) = harness
        .post(DELEGATE, None, json!({ "delay_id": "hold-2" }))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = harness.get(ADMIN, Some(&alice.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held_delegations"], 1);

    // A stranger's key releases nothing.
    let (status, _) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri(WEBHOOK)
                .header("authorization", "wrong-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "event": "participant_left",
                            "participant": { "identity": format!("{}:{}", alice.user_id, alice.device_id) } })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = harness
        .call(
            Request::builder()
                .method("POST")
                .uri(WEBHOOK)
                .header("authorization", "APIkey")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "events": [
                        { "event": "participant_joined",
                          "participant": { "identity": format!("{}:{}", alice.user_id, alice.device_id) } },
                        { "event": "participant_left",
                          "participant": { "identity": format!("{}:{}", alice.user_id, alice.device_id) } },
                    ]})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["released"], 1,
        "the left event released the hold: {body}"
    );

    let (status, body) = harness.get(ADMIN, Some(&alice.access_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held_delegations"], 0);
}

/// Unconfigured, the delegation probe is the 404 Element Call reads as
/// "hold it yourself".
#[tokio::test]
async fn unconfigured_the_probe_is_a_404() {
    let harness = Harness::with("");
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .post(
            DELEGATE,
            Some(&alice.access_token),
            json!({ "delay_id": "hold-1" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
}

/// The generated sidecar config carries the SFU's keys, self-creating
/// rooms and the webhook — and lands away from the operator's files.
#[test]
fn sidecar_config_generation_carries_the_keys_and_the_webhook() {
    let dir = TempDir::new().unwrap();
    let generated = dir.path().join("gen").join("livekit.yaml");
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\npublic_base_url = \"https://matrix.example.org\"\n\
         [storage]\npath = \"{}\"\n\
         [rtc.livekit]\nurl = \"wss://127.0.0.1:7880\"\nkey = \"APIkey\"\nsecret = \"not-the-signing-key\"\n\
         binary = \"/usr/local/bin/livekit-server\"\nsidecar_config_path = \"{}\"\n",
        dir.path().display(),
        generated.display(),
    ))
    .unwrap();
    let operator_config = dir.path().join("spindle.toml");
    std::fs::write(&operator_config, "operator bytes").unwrap();

    let path = spindle_server::livekit::SfuSupervisor::generate_config_for(&config).unwrap();
    assert_eq!(path, generated);
    let rendered = std::fs::read_to_string(&generated).unwrap();
    assert!(rendered.contains("APIkey"), "{rendered}");
    assert!(rendered.contains("not-the-signing-key"), "{rendered}");
    assert!(rendered.contains("auto_create: true"), "{rendered}");
    assert!(
        rendered.contains("https://matrix.example.org/_spindle/rtc/livekit/sfu/webhook"),
        "{rendered}"
    );
    assert!(rendered.contains("v1.13.5"), "{rendered}");
    assert_eq!(
        std::fs::read_to_string(&operator_config).unwrap(),
        "operator bytes",
        "operator files are never rewritten"
    );

    assert_eq!(
        spindle_server::livekit::generated_config_path(&config),
        generated
    );
}

/// The default generated path is the storage directory, not the config's.
#[test]
fn sidecar_config_defaults_under_storage() {
    let dir = TempDir::new().unwrap();
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n\
         [rtc.livekit]\nurl = \"wss://127.0.0.1:7880\"\nkey = \"k\"\nsecret = \"s\"\nbinary = \"/bin/true\"\n",
        dir.path().display(),
    ))
    .unwrap();
    assert_eq!(
        spindle_server::livekit::generated_config_path(&config),
        dir.path().join("livekit.yaml")
    );
}

/// The supervised binary is pinned at ESS parity, and the new fields are
/// refused empty at startup rather than found during a call.
#[test]
fn pin_and_sidecar_validation() {
    assert_eq!(spindle_server::livekit::LIVEKIT_SERVER_PIN, "v1.13.5");
    let refused = |livekit: &str| match spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[rtc.livekit]\n{livekit}"
    )) {
        Ok(_) => panic!("should have been refused:\n{livekit}"),
        Err(error) => error.to_string(),
    };
    assert!(
        refused("url = \"wss://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\nbinary = \"\"\n")
            .contains("binary"),
        "an empty binary supervises nothing"
    );
    assert!(
        refused("url = \"wss://sfu.example.org\"\nkey = \"k\"\nsecret = \"s\"\nsidecar_config_path = \"\"\n")
            .contains("sidecar_config_path"),
        "an empty generated path is not a default"
    );
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[rtc.livekit]\nurl = \"wss://sfu.example.org\"\n\
         key = \"k\"\nsecret = \"s\"\nbinary = \"/usr/local/bin/livekit-server\"\n",
    )
    .unwrap();
    assert_eq!(config.rtc.livekit.as_ref().unwrap().model(), "local");
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[rtc.livekit]\nurl = \"wss://sfu.example.org\"\n\
         key = \"k\"\nsecret = \"s\"\n",
    )
    .unwrap();
    assert_eq!(config.rtc.livekit.as_ref().unwrap().model(), "remote");
}

/// `spindle sfu` usage, status, and the on/off round trip — through the
/// binary, against a real store, with the config file byte-identical after.
#[test]
fn operator_cli_switch_and_status() {
    use std::process::Command;
    let work = TempDir::new().unwrap();
    let config_path = work.path().join("spindle.toml");
    let config_text = format!(
        "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n{}",
        work.path().join("data").display(),
        REMOTE,
    );
    std::fs::write(&config_path, &config_text).unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_spindle"))
            .args(args)
            .output()
            .expect("the spindle binary runs")
    };
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();

    let output = run(&["sfu"]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("usage: spindle sfu"));

    let output = run(&["sfu", "status", config_path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("\"enabled\": true"), "{stdout}");
    assert!(stdout.contains("\"remote\""), "{stdout}");

    let output = run(&["sfu", "off", config_path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let output = run(&["sfu", "status", config_path.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert!(stdout.contains("\"enabled\": false"), "{stdout}");

    let output = run(&["sfu", "on", config_path.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let output = run(&["sfu", "status", config_path.to_str().unwrap()]);
    assert!(text(&output.stdout).contains("\"enabled\": true"));

    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        config_text,
        "the switch never rewrites operator files"
    );

    // `on` with nothing configured is refused.
    let bare_path = work.path().join("bare.toml");
    std::fs::write(
        &bare_path,
        format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n",
            work.path().join("bare-data").display()
        ),
    )
    .unwrap();
    let output = run(&["sfu", "on", bare_path.to_str().unwrap()]);
    assert!(!output.status.success());
}

fn base64url_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let value = |symbol: u8| -> u32 {
        u32::try_from(
            ALPHABET
                .iter()
                .position(|&candidate| candidate == symbol)
                .unwrap_or_else(|| panic!("{symbol:?} is not base64url")),
        )
        .unwrap()
    };
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in text.as_bytes().chunks(4) {
        let mut accumulator = 0_u32;
        for (index, &symbol) in chunk.iter().enumerate() {
            accumulator |= value(symbol) << (18 - 6 * index);
        }
        let bytes = accumulator.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}
