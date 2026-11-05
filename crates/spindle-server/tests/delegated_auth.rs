//! MSC3861: authentication delegated to an OIDC provider — a real
//! Spindle instance over TCP against a mock Matrix Authentication
//! Service, with the MSC2967 API scopes and the MSC2965 metadata
//! discovery a client needs to find it.
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
const BOB_TOKEN: &str = "mat_bob_access_token";
const SHORT_LIVED_TOKEN: &str = "mat_short_lived_access_token";
const ADMIN_TOKEN: &str = "mat_admin_access_token";

/// The mock provider: a discovery document and a scripted introspection
/// endpoint that counts its calls.
#[derive(Clone, Default)]
struct Provider {
    url: Arc<Mutex<String>>,
    introspections: Arc<Mutex<Vec<(String, String)>>>,
    /// Tokens whose session the provider has ended: introspected inactive.
    revoked: Arc<Mutex<std::collections::HashSet<String>>>,
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
                        let token = form_urlencoded::parse(body.as_bytes())
                            .find(|(key, _)| key == "token").map(|(_, value)| value.into_owned()).unwrap_or_default();
                        if state.revoked.lock().unwrap().contains(&token) {
                            return axum::Json(json!({ "active": false }));
                        }
                        let scopes = match token.as_str() {
                            "mat_admin_access_token" => Some("urn:matrix:org.matrix.msc2967.client:api:* urn:synapse:admin:* urn:mas:admin"),
                            "mat_stable_admin_access_token" => Some("urn:matrix:client:api:* urn:synapse:admin:* urn:mas:admin"),
                            "mat_stable_access_token" => Some("urn:matrix:client:api:* urn:matrix:client:device:STABLEDEV"),
                            "mat_multiple_devices" => Some("urn:matrix:client:api:* urn:matrix:client:device:ONE urn:matrix:client:device:TWO"),
                            "mat_mas_admin_only" => Some("urn:matrix:client:api:* urn:mas:admin"),
                            "mat_empty_device" => Some("urn:matrix:client:api:* urn:matrix:client:device:"),
                            _ => None,
                        };
                        if token == "mat_compatibility_access_token" {
                            axum::Json(json!({ "active": true, "username": "alice", "scope": "urn:matrix:client:api:*", "device_id": "COMPATDEV" }))
                        } else if token == BOB_TOKEN {
                            axum::Json(json!({ "active": true, "username": "bob", "scope": "urn:matrix:client:api:* urn:matrix:client:device:BOBDEV" }))
                        } else if token == SHORT_LIVED_TOKEN {
                            // A token at the end of its life: MAS's access
                            // tokens carry `expires_in`, as Synapse reads it.
                            axum::Json(json!({ "active": true, "username": "alice", "scope": "urn:matrix:client:api:* urn:matrix:client:device:SHORTDEV", "expires_in": 0 }))
                        } else if let Some(scope) = scopes {
                            axum::Json(json!({ "active": true, "username": "alice", "scope": scope }))
                        } else if token == MAS_TOKEN {
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

    /// End a session the way MAS does: its token introspects inactive.
    fn revoke(&self, token: &str) {
        self.revoked.lock().unwrap().insert(token.to_owned());
    }
}

struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    store: Arc<FjallStore>,
    client: reqwest::Client,
}

impl Instance {
    /// `provider` of `None` starts a plain local-auth instance.
    async fn start(provider: Option<&str>) -> Instance {
        Self::start_with(
            provider,
            "client_id = \"spindle\"\nclient_secret = \"hush\"\n",
        )
        .await
    }

    /// As [`Self::start`], with `credentials` as the `[auth.delegated]`
    /// lines that say how introspection authenticates.
    async fn start_with(provider: Option<&str>, credentials: &str) -> Instance {
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
                 introspection_endpoint = \"{url}/oauth2/introspect\"\n{credentials}"
            )
        });
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n{auth}",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store.clone()).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            _reg_dir: reg_dir,
            name,
            store,
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
    // The device is really gone, and so is the cached verdict that named
    // it: a token bound to a deleted device is refused on sight, the check
    // Synapse makes on every request (#615), rather than serving on until
    // the introspection cache expires.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/devices/MASDEV1",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    // And it stays ended. The provider was never told and still says
    // active, so a re-introspection that provisioned the device again
    // would bring the deleted session back on the request after.
    for _ in 0..2 {
        let (status, body) = whoami(&server, MAS_TOKEN).await;
        assert_eq!(status, 401, "a deleted device stays deleted: {body}");
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    }
    let accounts = spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name);
    assert!(accounts.device("alice", "MASDEV1").unwrap().is_none());
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

#[tokio::test]
async fn introspection_can_present_the_homeserver_secret_the_way_synapse_does() {
    // Synapse's `matrix_authentication_service` section has no client of
    // its own at MAS: it introspects with the shared `matrix.secret` as a
    // bearer token, and MAS accepts that from its homeserver. A MAS set up
    // that way (Element Server Suite's default) must work unchanged.
    let (provider, url) = Provider::serve().await;
    let server =
        Instance::start_with(Some(&url), "homeserver_secret = \"shared-matrix-secret\"\n").await;
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["device_id"], "MASDEV1", "{body}");
    let introspections = provider.introspections();
    assert_eq!(introspections.len(), 1);
    assert_eq!(introspections[0].0, "Bearer shared-matrix-secret");
}

#[test]
fn introspection_needs_some_credential() {
    let base = "[server]\nname = \"example.org\"\n[auth.delegated]\n\
                issuer = \"http://mas/\"\nintrospection_endpoint = \"http://mas/oauth2/introspect\"\n";
    // Neither a client pair nor the homeserver secret: nothing to present.
    assert!(spindle_server::Config::parse(base).is_err());
    // Half a client pair is a typo, not a choice.
    assert!(
        spindle_server::Config::parse(&format!(
            "{base}client_id = \"x\"\nhomeserver_secret = \"s\"\n"
        ))
        .is_err()
    );
    assert!(spindle_server::Config::parse(&format!("{base}homeserver_secret = \"s\"\n")).is_ok());
    assert!(
        spindle_server::Config::parse(&format!("{base}client_id = \"x\"\nclient_secret = \"y\"\n"))
            .is_ok()
    );
}

#[tokio::test]
async fn delegated_admin_scope_is_a_token_capability_without_a_device() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    let admin = "mat_admin_access_token";
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_synapse/admin/v1/server_version",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let accounts = spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name);
    assert!(!accounts.account("alice").unwrap().unwrap().admin);
    assert!(accounts.devices_of("alice").unwrap().is_empty());
    // Reusing the cached verdict on a client endpoint cannot invent a device.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(admin),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_synapse/admin/v1/server_version",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(provider.introspections().len(), 1);
    // A different token for this same user cannot inherit the first token's scope.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_synapse/admin/v1/server_version",
            Some(MAS_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert!(!accounts.account("alice").unwrap().unwrap().admin);
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_synapse/admin/v2/users",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    accounts.set_locked("alice", true).unwrap();
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_synapse/admin/v1/server_version",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(
        status, 403,
        "account hold applies to a cached admin token: {body}"
    );
}

#[tokio::test]
async fn delegated_scopes_accept_stable_names_and_reject_ambiguous_devices() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some("mat_stable_access_token"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["device_id"], "STABLEDEV");
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some("mat_compatibility_access_token"),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["device_id"], "COMPATDEV");
    for token in [
        "mat_multiple_devices",
        "mat_empty_device",
        "mat_mas_admin_only",
    ] {
        let (status, body) = server
            .request(
                reqwest::Method::GET,
                "/_synapse/admin/v1/server_version",
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 401, "{token}: {body}");
    }
}

#[tokio::test]
async fn delegated_admin_whoami_identifies_an_account_without_inventing_a_device() {
    for token in ["mat_admin_access_token", "mat_stable_admin_access_token"] {
        let (provider, url) = Provider::serve().await;
        let server = Instance::start(Some(&url)).await;
        let (status, body) = server
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/account/whoami",
                Some(token),
                None,
            )
            .await;
        assert_eq!(
            status, 200,
            "Element Admin reads whoami before opening its console: {body}"
        );
        assert_eq!(body["user_id"], format!("@alice:{}", server.name));
        assert!(
            body.get("device_id").is_none(),
            "whoami must omit an absent device: {body}"
        );
        let accounts = spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name);
        assert!(accounts.devices_of("alice").unwrap().is_empty());
        assert!(!accounts.account("alice").unwrap().unwrap().admin);
        let (status, body) = server
            .request(
                reqwest::Method::POST,
                "/_matrix/client/v3/keys/upload",
                Some(token),
                Some(&json!({})),
            )
            .await;
        assert_eq!(
            status, 401,
            "account-only authentication cannot upload device keys: {body}"
        );
        let (status, body) = server
            .request(
                reqwest::Method::GET,
                "/_synapse/admin/v2/users",
                Some(token),
                None,
            )
            .await;
        assert_eq!(
            status, 200,
            "the same token still grants admin routes: {body}"
        );
        assert_eq!(
            provider.introspections().len(),
            1,
            "one shared cached verdict"
        );
    }
}

#[tokio::test]
async fn delegated_account_identity_checks_scopes_and_cached_account_holds() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    for token in [
        "inactive",
        "mat_mas_admin_only",
        "mat_multiple_devices",
        "mat_empty_device",
    ] {
        let (status, body) = server
            .request(
                reqwest::Method::GET,
                "/_matrix/client/v3/account/whoami",
                Some(token),
                None,
            )
            .await;
        assert_eq!(status, 401, "bad account scope must remain invalid: {body}");
    }
    let token = "mat_admin_access_token";
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let accounts = spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name);
    accounts.set_locked("alice", true).unwrap();
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await;
    assert_eq!(
        status, 401,
        "a cached provider verdict cannot bypass a local lock: {body}"
    );
    assert_eq!(body["errcode"], "M_USER_LOCKED");
    accounts.set_locked("alice", false).unwrap();
    accounts.set_deactivated("alice", true).unwrap();
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await;
    assert_eq!(
        status, 401,
        "a cached provider verdict cannot bypass deactivation: {body}"
    );
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert!(accounts.devices_of("alice").unwrap().is_empty());
}

const MAS_SECRET: &str = "shared-matrix-secret-for-revocation";

async fn whoami(server: &Instance, token: &str) -> (u16, Value) {
    server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(token),
            None,
        )
        .await
}

/// #615: a logout this server serves ends the token here at once, not when
/// the introspection cache would have let the verdict expire.
#[tokio::test]
async fn a_logout_evicts_the_cached_verdict() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    assert_eq!(provider.introspections().len(), 1);

    // The provider ends the session as part of the logout; the verdict
    // cached a moment ago still says active.
    provider.revoke(MAS_TOKEN);
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/logout",
            Some(MAS_TOKEN),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = whoami(&server, MAS_TOKEN).await;
    assert_eq!(status, 401, "a logged-out token must stop working: {body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(
        provider.introspections().len(),
        2,
        "the provider was asked again rather than the cache trusted"
    );
}

/// #615, the production path: MAS serves the logout itself, ends the
/// session and calls `delete_device`. That call is the only word of it this
/// server gets, and it must end every cached verdict for the device.
#[tokio::test]
async fn mas_deleting_the_device_evicts_its_tokens() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start_with(
        Some(&url),
        &format!("client_id = \"spindle\"\nclient_secret = \"hush\"\nhomeserver_secret = \"{MAS_SECRET}\"\n"),
    )
    .await;

    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    // A second, unrelated session of the same user on another device.
    assert_eq!(whoami(&server, "mat_stable_access_token").await.0, 200);
    assert_eq!(provider.introspections().len(), 2);

    provider.revoke(MAS_TOKEN);
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_synapse/mas/delete_device",
            Some(MAS_SECRET),
            Some(&json!({ "localpart": "alice", "device_id": "MASDEV1" })),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = whoami(&server, MAS_TOKEN).await;
    assert_eq!(
        status, 401,
        "the deleted device's token must stop working: {body}"
    );
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");

    // The other device's verdict is untouched and still served from cache.
    let before = provider.introspections().len();
    assert_eq!(whoami(&server, "mat_stable_access_token").await.0, 200);
    assert_eq!(provider.introspections().len(), before, "still cached");
}

/// The belt to the braces above: a cached verdict whose device row has gone
/// by any route at all is refused, as Synapse refuses it.
#[tokio::test]
async fn a_cached_verdict_for_a_vanished_device_is_refused() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;

    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name)
        .delete_device("alice", "MASDEV1")
        .unwrap();

    let (status, body) = whoami(&server, MAS_TOKEN).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
}

async fn post(server: &Instance, path: &str, token: &str, body: &Value) -> (u16, Value) {
    server
        .request(reqwest::Method::POST, path, Some(token), Some(body))
        .await
}

/// The token is refused on the very next request, and on the ones after,
/// which no longer have a cached verdict to refuse and ask the provider.
/// `/devices` as well as `/whoami`: `/whoami` refuses a deactivated
/// account on its own, and an ordinary endpoint must refuse it as well.
async fn assert_ended(server: &Instance, token: &str, why: &str) {
    for attempt in ["next", "following"] {
        for path in [
            "/_matrix/client/v3/account/whoami",
            "/_matrix/client/v3/devices",
        ] {
            let (status, body) = server
                .request(reqwest::Method::GET, path, Some(token), None)
                .await;
            assert_eq!(status, 401, "{why} ({attempt} request, {path}): {body}");
            assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{why}: {body}");
        }
    }
}

/// #615: a logout served here ends the token even when the provider is
/// never told of it -- it goes on answering "active" -- because the logout
/// ends the device, as the spec says a logout does.
#[tokio::test]
async fn a_logout_the_provider_never_hears_of_still_ends_the_token() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    assert_eq!(whoami(&server, "mat_stable_access_token").await.0, 200);

    let (status, body) = post(&server, "/_matrix/client/v3/logout", MAS_TOKEN, &json!({})).await;
    assert_eq!(status, 200, "{body}");

    assert_ended(&server, MAS_TOKEN, "a logged-out token").await;
    assert_eq!(
        whoami(&server, "mat_stable_access_token").await.0,
        200,
        "the user's other session is not this logout's business"
    );
}

/// #615: `/logout/all` ends every provider session of the user, not only
/// the cached verdicts that a re-introspection would vouch for again.
#[tokio::test]
async fn logout_all_ends_every_provider_session_of_the_user() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    for token in [MAS_TOKEN, "mat_stable_access_token", BOB_TOKEN] {
        assert_eq!(whoami(&server, token).await.0, 200);
    }

    let (status, body) = post(
        &server,
        "/_matrix/client/v3/logout/all",
        MAS_TOKEN,
        &json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_ended(&server, MAS_TOKEN, "the session that logged out").await;
    assert_ended(
        &server,
        "mat_stable_access_token",
        "the user's other session",
    )
    .await;
    assert_eq!(whoami(&server, BOB_TOKEN).await.0, 200, "another user");
}

/// #615: MAS deactivates through `delete_user`. Every session of the user
/// ends with it, the device-less admin-scoped one included, even before
/// the provider's own introspection catches up; reactivation lifts it.
#[tokio::test]
async fn mas_deleting_the_user_ends_every_session() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start_with(
        Some(&url),
        &format!("client_id = \"spindle\"\nclient_secret = \"hush\"\nhomeserver_secret = \"{MAS_SECRET}\"\n"),
    )
    .await;
    for token in [MAS_TOKEN, "mat_stable_access_token", ADMIN_TOKEN] {
        assert_eq!(whoami(&server, token).await.0, 200);
    }

    let (status, body) = post(
        &server,
        "/_synapse/mas/delete_user",
        MAS_SECRET,
        &json!({ "localpart": "alice", "erase": false }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_ended(&server, MAS_TOKEN, "a deactivated user's session").await;
    assert_ended(
        &server,
        "mat_stable_access_token",
        "a deactivated user's session",
    )
    .await;
    assert_ended(&server, ADMIN_TOKEN, "a deactivated user's admin token").await;

    let (status, body) = post(
        &server,
        "/_synapse/mas/reactivate_user",
        MAS_SECRET,
        &json!({ "localpart": "alice" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200, "reactivated");
}

/// #615: MAS's recovery path, `sync_devices`, deletes the devices it no
/// longer has; their tokens end at once, the kept device's stay cached.
#[tokio::test]
async fn mas_syncing_a_device_away_ends_its_tokens() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start_with(
        Some(&url),
        &format!("client_id = \"spindle\"\nclient_secret = \"hush\"\nhomeserver_secret = \"{MAS_SECRET}\"\n"),
    )
    .await;
    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    assert_eq!(whoami(&server, "mat_stable_access_token").await.0, 200);

    provider.revoke(MAS_TOKEN);
    let (status, body) = post(
        &server,
        "/_synapse/mas/sync_devices",
        MAS_SECRET,
        &json!({ "localpart": "alice", "devices": ["STABLEDEV"] }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_ended(&server, MAS_TOKEN, "a device MAS no longer has").await;
    let before = provider.introspections().len();
    assert_eq!(whoami(&server, "mat_stable_access_token").await.0, 200);
    assert_eq!(provider.introspections().len(), before, "still cached");
}

/// #615: an administrator's deactivation is not reported to the provider,
/// which goes on vouching for the user's sessions. They end here anyway.
#[tokio::test]
async fn an_admin_deactivation_ends_the_users_sessions() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    assert_eq!(whoami(&server, BOB_TOKEN).await.0, 200);

    let (status, body) = post(
        &server,
        &format!("/_synapse/admin/v1/deactivate/@bob:{}", server.name),
        ADMIN_TOKEN,
        &json!({}),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_ended(&server, BOB_TOKEN, "a deactivated user's session").await;
}

/// #615: an administrator's device deletion, single or bulk, ends the
/// session although the provider was not told; the provider brings the
/// device back only by provisioning it again, as it would on Synapse.
#[tokio::test]
async fn an_admin_device_deletion_ends_the_session_until_the_provider_provisions_it() {
    let (_provider, url) = Provider::serve().await;
    let server = Instance::start_with(
        Some(&url),
        &format!("client_id = \"spindle\"\nclient_secret = \"hush\"\nhomeserver_secret = \"{MAS_SECRET}\"\n"),
    )
    .await;
    assert_eq!(whoami(&server, BOB_TOKEN).await.0, 200);

    let (status, body) = server
        .request(
            reqwest::Method::DELETE,
            &format!(
                "/_synapse/admin/v2/users/@bob:{}/devices/BOBDEV",
                server.name
            ),
            Some(ADMIN_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_ended(&server, BOB_TOKEN, "a device an admin deleted").await;

    let upsert = json!({ "localpart": "bob", "device_id": "BOBDEV" });
    let (status, body) = post(&server, "/_synapse/mas/upsert_device", MAS_SECRET, &upsert).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(whoami(&server, BOB_TOKEN).await.0, 200, "provisioned again");

    let (status, body) = post(
        &server,
        &format!(
            "/_synapse/admin/v2/users/@bob:{}/delete_devices",
            server.name
        ),
        ADMIN_TOKEN,
        &json!({ "devices": ["BOBDEV"] }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_ended(&server, BOB_TOKEN, "a device an admin bulk-deleted").await;
}

/// #615: the window a verdict is trusted for is the operator's to set; 0
/// puts the provider in every request, so its revocation is immediate.
#[tokio::test]
async fn the_introspection_cache_window_is_configurable() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start_with(
        Some(&url),
        "client_id = \"spindle\"\nclient_secret = \"hush\"\nintrospection_cache_ttl_secs = 0\n",
    )
    .await;
    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    assert_eq!(whoami(&server, MAS_TOKEN).await.0, 200);
    assert_eq!(provider.introspections().len(), 2, "nothing cached");

    provider.revoke(MAS_TOKEN);
    assert_ended(&server, MAS_TOKEN, "a token the provider revoked").await;
}

/// #615, Synapse parity: a verdict is not trusted past the `expires_in`
/// the provider gave the token, whatever the configured window.
#[tokio::test]
async fn a_verdict_is_not_trusted_past_the_tokens_expiry() {
    let (provider, url) = Provider::serve().await;
    let server = Instance::start(Some(&url)).await;
    assert_eq!(whoami(&server, SHORT_LIVED_TOKEN).await.0, 200);
    assert_eq!(whoami(&server, SHORT_LIVED_TOKEN).await.0, 200);
    assert_eq!(
        provider.introspections().len(),
        2,
        "a token at the end of its life is asked about again"
    );
}
