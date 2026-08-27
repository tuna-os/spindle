//! The built-in OIDC provider (#159) — a real Spindle over TCP, driven
//! the way matrix-js-sdk drives a provider: discovery, dynamic client
//! registration, the authorization page, PKCE code exchange, refresh,
//! revocation. The request and response shapes here mirror what the
//! js-sdk's validators demand (`src/oauth/` upstream), because those
//! validators are what actually kills a login when a provider is wrong.

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::Digest;
use spindle_store::FjallStore;
use tempfile::TempDir;

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start(builtin: bool) -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let auth = if builtin {
            "[auth]\nbuiltin_oidc = true\n"
        } else {
            ""
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\npublic_base_url = \"http://{name}\"\n\
             [ratelimit]\nenabled = false\n{auth}"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    async fn register_user(&self, username: &str) {
        let response = self
            .client
            .post(format!("http://{}/_matrix/client/v3/register", self.name))
            .header("content-type", "application/json")
            .body(
                json!({
                    "username": username, "password": "hunter2hunter2",
                    "auth": { "type": "m.login.dummy", "session": "s" },
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }

    /// Register an OAuth client the way js-sdk's `registerOAuthClient`
    /// does, returning its `client_id`.
    async fn register_client(&self, redirect_uri: &str) -> String {
        let response = self
            .client
            .post(format!("http://{}/oauth2/registration", self.name))
            .header("content-type", "application/json")
            .body(
                json!({
                    "client_name": "Test Element",
                    "client_uri": "https://element.example/",
                    "redirect_uris": [redirect_uri],
                    "response_types": ["code"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "none",
                    "application_type": "web",
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
        let body: Value = read_json(response).await;
        body["client_id"].as_str().unwrap().to_owned()
    }

    /// The whole front half of the flow: GET the login page, POST the
    /// credentials, return the `code` from the redirect.
    async fn login_for_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        challenge: &str,
    ) -> String {
        let authorize = format!(
            "http://{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state=st4te&code_challenge_method=S256&code_challenge={}",
            self.name,
            client_id,
            urlencode(redirect_uri),
            urlencode(scope),
            challenge,
        );
        let page = self.client.get(&authorize).send().await.unwrap();
        assert_eq!(page.status().as_u16(), 200, "the login page renders");
        let html = page.text().await.unwrap();
        assert!(html.contains("Test Element"), "names the asking client");

        let response = self
            .client
            .post(format!("http://{}/oauth2/authorize", self.name))
            .form(&[
                ("username", "alice"),
                ("password", "hunter2hunter2"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("scope", scope),
                ("state", "st4te"),
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
                ("response_mode", "query"),
                ("response_type", "code"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 303, "a redirect, not a page");
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .to_owned();
        assert!(
            location.starts_with(redirect_uri),
            "back to the client: {location}"
        );
        assert!(location.contains("state=st4te"), "state echoes: {location}");
        location
            .split_once("code=")
            .map(|(_, rest)| rest.split('&').next().unwrap().to_owned())
            .expect("a code in the redirect")
    }

    async fn exchange(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code: &str,
        verifier: &str,
    ) -> (u16, Value) {
        let response = self
            .client
            .post(format!("http://{}/oauth2/token", self.name))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("redirect_uri", redirect_uri),
                ("code", code),
            ])
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, read_json(response).await)
    }

    async fn whoami(&self, token: &str) -> (u16, Value) {
        let response = self
            .client
            .get(format!(
                "http://{}/_matrix/client/v3/account/whoami",
                self.name
            ))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, read_json(response).await)
    }
}

async fn read_json(response: reqwest::Response) -> Value {
    response
        .bytes()
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

fn urlencode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// PKCE per RFC 7636: challenge = BASE64URL(SHA256(verifier)).
fn pkce(verifier: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = sha2::Sha256::digest(verifier.as_bytes());
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for slot in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[((triple >> (18 - 6 * slot)) & 0x3f) as usize],
            ));
        }
    }
    out
}

const REDIRECT: &str = "https://element.example/callback";
const STABLE_SCOPE: &str = "urn:matrix:client:api:* urn:matrix:client:device:TESTDEV01";
const LEGACY_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:api:* \
    urn:matrix:org.matrix.msc2967.client:device:LEGACYDEV1";

/// Discovery must pass js-sdk's `isValidAuthMetadata`: every required
/// field, and the required members of each array — and `auth_metadata`
/// must relay the same document.
async fn assert_discovery_is_valid(server: &Instance) {
    let response = server
        .client
        .get(format!(
            "http://{}/.well-known/openid-configuration",
            server.name
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let metadata: Value = read_json(response).await;
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "revocation_endpoint",
        "registration_endpoint",
    ] {
        assert!(metadata[field].is_string(), "{field}: {metadata}");
    }
    for (array, member) in [
        ("response_modes_supported", "query"),
        ("response_modes_supported", "fragment"),
        ("response_types_supported", "code"),
        ("grant_types_supported", "authorization_code"),
        ("grant_types_supported", "refresh_token"),
        ("code_challenge_methods_supported", "S256"),
    ] {
        assert!(
            metadata[array]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == member)),
            "{array} must contain {member}: {metadata}"
        );
    }
    // And auth_metadata relays the same document.
    let relayed: Value = read_json(
        server
            .client
            .get(format!(
                "http://{}/_matrix/client/v1/auth_metadata",
                server.name
            ))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(relayed, metadata);
}

#[tokio::test]
async fn the_whole_flow_ends_in_a_native_session() {
    let server = Instance::start(true).await;
    server.register_user("alice").await;
    assert_discovery_is_valid(&server).await;

    let client_id = server.register_client(REDIRECT).await;
    let verifier = "a-code-verifier-of-sufficient-length-for-rfc7636";
    let code = server
        .login_for_code(&client_id, REDIRECT, STABLE_SCOPE, &pkce(verifier))
        .await;

    let (status, body) = server.exchange(&client_id, REDIRECT, &code, verifier).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer", "{body}");
    assert!(body["expires_in"].is_u64(), "{body}");
    assert!(body["access_token"].is_string(), "{body}");
    assert!(
        body["refresh_token"].is_string(),
        "present and a string — never null: {body}"
    );

    // The minted token is a native session: whoami resolves it with the
    // device the scope named, through the ordinary auth path.
    let access = body["access_token"].as_str().unwrap();
    let (status, who) = server.whoami(access).await;
    assert_eq!(status, 200, "{who}");
    assert_eq!(who["user_id"], format!("@alice:{}", server.name));
    assert_eq!(who["device_id"], "TESTDEV01", "{who}");

    // The refresh grant rotates, old access token dies at its expiry —
    // and the response omits scope rather than misquoting it.
    let refresh = body["refresh_token"].as_str().unwrap();
    let response = server
        .client
        .post(format!("http://{}/oauth2/token", server.name))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("refresh_token", refresh),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let rotated: Value = read_json(response).await;
    assert!(rotated["access_token"].is_string());
    assert!(rotated.get("scope").is_none(), "{rotated}");
    let (status, _) = server
        .whoami(rotated["access_token"].as_str().unwrap())
        .await;
    assert_eq!(status, 200);

    // Revoking the new access token ends it.
    let response = server
        .client
        .post(format!("http://{}/oauth2/revoke", server.name))
        .form(&[
            ("token", rotated["access_token"].as_str().unwrap()),
            ("client_id", &client_id),
            ("token_type_hint", "access_token"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let (status, _) = server
        .whoami(rotated["access_token"].as_str().unwrap())
        .await;
    assert_eq!(status, 401, "revoked means gone");
}

#[tokio::test]
async fn the_legacy_scope_spelling_still_works() {
    let server = Instance::start(true).await;
    server.register_user("alice").await;
    let client_id = server.register_client(REDIRECT).await;
    let verifier = "another-code-verifier-of-sufficient-length-0";
    let code = server
        .login_for_code(&client_id, REDIRECT, LEGACY_SCOPE, &pkce(verifier))
        .await;
    let (status, body) = server.exchange(&client_id, REDIRECT, &code, verifier).await;
    assert_eq!(status, 200, "{body}");
    let (status, who) = server.whoami(body["access_token"].as_str().unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(who["device_id"], "LEGACYDEV1", "{who}");
}

#[tokio::test]
async fn what_must_be_refused_is_refused() {
    let server = Instance::start(true).await;
    server.register_user("alice").await;
    let client_id = server.register_client(REDIRECT).await;
    let verifier = "the-honest-verifier-with-plenty-of-length-00";
    let challenge = pkce(verifier);

    // A code redeems once; the wrong verifier does not redeem at all.
    let code = server
        .login_for_code(&client_id, REDIRECT, STABLE_SCOPE, &challenge)
        .await;
    let (status, body) = server
        .exchange(
            &client_id,
            REDIRECT,
            &code,
            "the-wrong-verifier-entirely-0000000000000000",
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // The failed PKCE attempt consumed the code: the honest verifier
    // now finds nothing. Stolen-code replay dies the same way.
    let (status, body) = server.exchange(&client_id, REDIRECT, &code, verifier).await;
    assert_eq!(status, 400, "{body}");

    let code = server
        .login_for_code(&client_id, REDIRECT, STABLE_SCOPE, &challenge)
        .await;
    let (status, _) = server.exchange(&client_id, REDIRECT, &code, verifier).await;
    assert_eq!(status, 200);
    let (status, body) = server.exchange(&client_id, REDIRECT, &code, verifier).await;
    assert_eq!(status, 400, "single use: {body}");

    // An unregistered redirect_uri never renders a login page.
    let authorize = format!(
        "http://{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge_method=S256&code_challenge={}",
        server.name,
        client_id,
        urlencode("https://evil.example/steal"),
        urlencode(STABLE_SCOPE),
        challenge,
    );
    let response = server.client.get(&authorize).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 400);

    // A wrong password re-renders the form instead of redirecting.
    let response = server
        .client
        .post(format!("http://{}/oauth2/authorize", server.name))
        .form(&[
            ("username", "alice"),
            ("password", "not-her-password"),
            ("client_id", &client_id),
            ("redirect_uri", REDIRECT),
            ("scope", STABLE_SCOPE),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("response_type", "code"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    assert!(
        response.text().await.unwrap().contains("did not match"),
        "the human sees why"
    );

    // PKCE `plain` is not negotiable down to.
    let authorize = format!(
        "http://{}/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge_method=plain&code_challenge=plaintext",
        server.name,
        client_id,
        urlencode(REDIRECT),
        urlencode(STABLE_SCOPE),
    );
    let response = server.client.get(&authorize).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn an_unconfigured_server_has_no_provider_surface() {
    let server = Instance::start(false).await;
    for path in [
        "/.well-known/openid-configuration",
        "/_matrix/client/v1/auth_metadata",
    ] {
        let response = server
            .client
            .get(format!("http://{}{path}", server.name))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 404, "{path}");
    }
    let response = server
        .client
        .post(format!("http://{}/oauth2/registration", server.name))
        .header("content-type", "application/json")
        .body(json!({ "redirect_uris": [REDIRECT] }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn the_well_known_names_the_issuer() {
    let server = Instance::start(true).await;
    let body: Value = read_json(
        server
            .client
            .get(format!("http://{}/.well-known/matrix/client", server.name))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        body["org.matrix.msc2965.authentication"]["issuer"],
        format!("http://{}/", server.name),
        "{body}"
    );
}
