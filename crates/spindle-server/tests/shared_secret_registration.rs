//! Synapse's shared-secret registration API, used by integration fixtures.
//!
//! The endpoint is intentionally absent unless configured. Its secret can
//! create an administrator, so the acceptance test covers the proof, nonce
//! consumption and the account/session/profile result together.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde_json::{Value, json};
use sha1::Sha1;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt as _;

const PATH: &str = "/_synapse/admin/v1/register";
const SECRET: &str = "test_shared_secret_for_local_dev_only";

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new(enabled: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let registration = if enabled {
            format!("[registration]\nshared_secret = {SECRET:?}\n")
        } else {
            String::new()
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{registration}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).unwrap();
        Self { _dir: dir, app }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let body = body.map_or_else(String::new, Value::to_string);
        if !body.is_empty() {
            request = request.header("content-type", "application/json");
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    async fn nonce(&self) -> String {
        let (status, body) = self.request("GET", PATH, None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["nonce"].as_str().unwrap().to_owned()
    }
}

fn mac(nonce: &str, username: &str, password: &str, admin: bool) -> String {
    use std::fmt::Write as _;
    let mut mac = Hmac::<Sha1>::new_from_slice(SECRET.as_bytes()).unwrap();
    for (index, part) in [
        nonce,
        username,
        password,
        if admin { "admin" } else { "notadmin" },
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            mac.update(&[0]);
        }
        mac.update(part.as_bytes());
    }
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn registration(nonce: &str, valid_mac: bool) -> Value {
    let signed = mac(nonce, "alice", "correct horse", true);
    json!({
        "nonce": nonce,
        "username": "alice",
        "password": "correct horse",
        "displayname": "Alice Example",
        "admin": true,
        "mac": if valid_mac { signed } else { "00".repeat(20) },
    })
}

#[tokio::test]
async fn the_endpoint_is_absent_without_an_explicit_secret() {
    let harness = Harness::new(false);
    let (status, body) = harness.request("GET", PATH, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_valid_mac_creates_the_account_profile_admin_and_session() {
    let harness = Harness::new(true);
    let nonce = harness.nonce().await;
    let request = registration(&nonce, true);
    let (status, body) = harness.request("POST", PATH, None, Some(&request)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:example.org");
    assert_eq!(body["home_server"], "example.org");
    let token = body["access_token"].as_str().unwrap();

    let (status, whoami) = harness
        .request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{whoami}");
    assert_eq!(whoami["user_id"], "@alice:example.org");

    let (status, profile) = harness
        .request(
            "GET",
            "/_matrix/client/v3/profile/@alice:example.org",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{profile}");
    assert_eq!(profile["displayname"], "Alice Example");

    let (status, users) = harness
        .request("GET", "/_synapse/admin/v2/users", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{users}");
}

#[tokio::test]
async fn every_nonce_is_single_use_even_after_a_bad_mac() {
    let harness = Harness::new(true);
    let nonce = harness.nonce().await;

    let (status, body) = harness
        .request("POST", PATH, None, Some(&registration(&nonce, false)))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = harness
        .request("POST", PATH, None, Some(&registration(&nonce, true)))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}
