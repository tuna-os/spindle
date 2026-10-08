//! The built-in provider's account management (#607) — a real Spindle over
//! TCP, driven the way a browser drives it: cookies kept by hand, forms
//! posted with the CSRF tokens the pages rendered, redirects read rather
//! than followed. What it pins: the MSC4191 advertisement, the browser
//! session the authorization page starts and "Continue as …" reuses, the
//! sign-in gate and its open-redirect guard, each page's change landing
//! exactly where the client API would put it, CSRF and the password
//! re-check on every change, the shared attempt budget, the page headers,
//! and the metrics each of those moves.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use sha2::Digest;
use spindle_server::metrics::{AccountAction, LoginMethod, LoginResult, Metrics};
use spindle_store::FjallStore;
use tempfile::TempDir;

const PASSWORD: &str = "hunter2hunter2";
const REDIRECT: &str = "https://element.example/callback";

struct Instance {
    _dir: TempDir,
    name: String,
    metrics: Arc<Metrics>,
    client: reqwest::Client,
}

impl Instance {
    async fn start(extra: &str) -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\npublic_base_url = \"http://{name}\"\n{extra}"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let app = spindle_server::app_with_metrics(config, store, Arc::clone(&metrics))
            .expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            metrics,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    async fn builtin() -> Instance {
        Self::start("[ratelimit]\nenabled = false\n[auth]\nbuiltin_oidc = true\n").await
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.name)
    }

    fn user(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.name)
    }

    async fn api(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.client.request(method, self.url(path));
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .api(
                reqwest::Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(json!({
                    "username": username, "password": PASSWORD,
                    "auth": { "type": "m.login.dummy", "session": "s" },
                })),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn password_login(&self, username: &str, password: &str, device: &str) -> (u16, Value) {
        self.api(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": username },
                "password": password,
                "device_id": device,
            })),
        )
        .await
    }

    async fn register_client(&self) -> String {
        let (status, body) = self
            .api(
                reqwest::Method::POST,
                "/oauth2/registration",
                None,
                Some(json!({ "client_name": "Test Element", "redirect_uris": [REDIRECT] })),
            )
            .await;
        assert_eq!(status, 201, "{body}");
        body["client_id"].as_str().unwrap().to_owned()
    }
}

/// A browser: a cookie jar kept by hand, so the test sees exactly which
/// cookies the server set and with which attributes.
#[derive(Default)]
struct Browser {
    jar: HashMap<String, String>,
    /// Every `Set-Cookie` header seen, verbatim.
    seen: Vec<String>,
}

struct Page {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Page {
    fn location(&self) -> &str {
        self.headers
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    /// The value of the first hidden field called `name`.
    fn field(&self, name: &str) -> String {
        let marker = format!("name=\"{name}\" value=\"");
        let start = self
            .body
            .find(&marker)
            .unwrap_or_else(|| panic!("no {name} field in {}", self.body))
            + marker.len();
        let end = self.body[start..].find('"').unwrap() + start;
        self.body[start..end].replace("&amp;", "&")
    }
}

impl Browser {
    fn cookie_header(&self) -> String {
        self.jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn absorb(&mut self, headers: &reqwest::header::HeaderMap) {
        for value in headers.get_all("set-cookie") {
            let text = value.to_str().unwrap().to_owned();
            let pair = text.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            let expired = text.contains("Max-Age=0");
            if expired || value.is_empty() {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
            self.seen.push(text);
        }
    }

    async fn get(&mut self, server: &Instance, path: &str) -> Page {
        let response = server
            .client
            .get(server.url(path))
            .header("cookie", self.cookie_header())
            .send()
            .await
            .unwrap();
        self.read(response).await
    }

    async fn post(&mut self, server: &Instance, path: &str, form: &[(&str, &str)]) -> Page {
        let response = server
            .client
            .post(server.url(path))
            .header("cookie", self.cookie_header())
            .form(form)
            .send()
            .await
            .unwrap();
        self.read(response).await
    }

    async fn read(&mut self, response: reqwest::Response) -> Page {
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        self.absorb(&headers);
        let body = response.text().await.unwrap();
        Page {
            status,
            headers,
            body,
        }
    }

    /// Sign in on the account pages; returns where the server sent us.
    async fn sign_in(&mut self, server: &Instance, username: &str, password: &str) -> Page {
        let page = self.get(server, "/account/login").await;
        assert_eq!(page.status, 200, "{}", page.body);
        let csrf = page.field("csrf");
        self.post(
            server,
            "/account/login",
            &[
                ("username", username),
                ("password", password),
                ("csrf", &csrf),
                ("next", "/account/"),
            ],
        )
        .await
    }
}

fn urlencode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

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

fn authorize_query(client_id: &str, device: &str, challenge: &str) -> Vec<(String, String)> {
    vec![
        ("response_type".into(), "code".into()),
        ("client_id".into(), client_id.into()),
        ("redirect_uri".into(), REDIRECT.into()),
        (
            "scope".into(),
            format!("urn:matrix:client:api:* urn:matrix:client:device:{device}"),
        ),
        ("state".into(), "st4te".into()),
        ("code_challenge_method".into(), "S256".into()),
        ("code_challenge".into(), challenge.into()),
        ("response_mode".into(), "query".into()),
    ]
}

fn code_of(location: &str) -> String {
    assert!(location.starts_with(REDIRECT), "{location}");
    location
        .split_once("code=")
        .map(|(_, rest)| rest.split('&').next().unwrap().to_owned())
        .expect("a code")
}

async fn exchange(server: &Instance, client_id: &str, code: &str, verifier: &str) -> Value {
    let response = server
        .client
        .post(server.url("/oauth2/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code_verifier", verifier),
            ("redirect_uri", REDIRECT),
            ("code", code),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

fn query_string(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[tokio::test]
async fn discovery_and_well_known_advertise_the_account_pages() {
    let server = Instance::builtin().await;
    let (status, metadata) = server
        .api(
            reqwest::Method::GET,
            "/_matrix/client/v1/auth_metadata",
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{metadata}");
    assert_eq!(
        metadata["account_management_uri"],
        server.url("/account/"),
        "{metadata}"
    );
    let actions = metadata["account_management_actions_supported"]
        .as_array()
        .unwrap();
    for action in [
        "org.matrix.profile",
        "org.matrix.sessions_list",
        "org.matrix.session_view",
        "org.matrix.session_end",
        "org.matrix.account_deactivate",
        "org.matrix.cross_signing_reset",
        "org.matrix.devices_list",
        "org.matrix.device_view",
        "org.matrix.device_delete",
    ] {
        assert!(actions.iter().any(|value| value == action), "{action}");
    }
    let (_, well_known) = server
        .api(
            reqwest::Method::GET,
            "/.well-known/matrix/client",
            None,
            None,
        )
        .await;
    assert_eq!(
        well_known["org.matrix.msc2965.authentication"]["account"],
        server.url("/account/"),
        "{well_known}"
    );
}

#[tokio::test]
async fn an_unconfigured_server_serves_no_account_pages() {
    let server = Instance::start("").await;
    let mut browser = Browser::default();
    for path in ["/account/", "/account/login"] {
        assert_eq!(browser.get(&server, path).await.status, 404, "{path}");
    }
}

/// Signing in on the authorization page starts a browser session; the
/// next client's authorization offers "Continue as …", which issues a
/// code on the session alone, with its CSRF secret and nothing else.
#[tokio::test]
async fn a_browser_session_lets_the_next_client_continue() {
    let server = Instance::builtin().await;
    server.register("alice").await;
    let client_id = server.register_client().await;
    let mut browser = Browser::default();

    let verifier = "the-first-verifier-with-plenty-of-length-000";
    let query = query_string(&authorize_query(&client_id, "FIRSTDEV", &pkce(verifier)));
    let page = browser
        .get(&server, &format!("/oauth2/authorize?{query}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("element.example"),
        "names the redirect host"
    );
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(page.headers["x-frame-options"], "DENY");
    let login_csrf = page.field("login_csrf");
    let mut form: Vec<(String, String)> = authorize_query(&client_id, "FIRSTDEV", &pkce(verifier));
    form.push(("username".into(), "alice".into()));
    form.push(("password".into(), PASSWORD.into()));
    form.push(("login_csrf".into(), login_csrf));
    let borrowed: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let page = browser.post(&server, "/oauth2/authorize", &borrowed).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let session_cookie = browser
        .seen
        .iter()
        .find(|cookie| cookie.starts_with("spindle_session="))
        .expect("a browser session")
        .clone();
    for attribute in ["HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(session_cookie.contains(attribute), "{session_cookie}");
    }
    let body = exchange(&server, &client_id, &code_of(page.location()), verifier).await;
    assert!(body["access_token"].is_string());

    // The second client: no password, "Continue as".
    let verifier = "the-second-verifier-with-plenty-of-length-00";
    let query = query_string(&authorize_query(&client_id, "SECONDDEV", &pkce(verifier)));
    let page = browser
        .get(&server, &format!("/oauth2/authorize?{query}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Continue as"), "{}", page.body);
    assert!(page.body.contains(&server.user("alice")), "{}", page.body);
    let csrf = page.field("csrf");
    let mut form: Vec<(String, String)> = authorize_query(&client_id, "SECONDDEV", &pkce(verifier));
    form.push(("csrf".into(), "not-the-sessions-secret".into()));
    let borrowed: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let refused = browser.post(&server, "/oauth2/authorize", &borrowed).await;
    assert_eq!(refused.status, 403, "a forged consent is refused");
    form.pop();
    form.push(("csrf".into(), csrf.clone()));
    let borrowed: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    // Without the cookie, the CSRF secret alone is nothing.
    let mut stranger = Browser::default();
    let refused = stranger.post(&server, "/oauth2/authorize", &borrowed).await;
    assert_eq!(refused.status, 401);
    let page = browser.post(&server, "/oauth2/authorize", &borrowed).await;
    assert_eq!(page.status, 303, "{}", page.body);
    let body = exchange(&server, &client_id, &code_of(page.location()), verifier).await;
    let (status, who) = server
        .api(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            body["access_token"].as_str(),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(who["device_id"], "SECONDDEV");

    // prompt=login asks for the password regardless.
    let page = browser
        .get(&server, &format!("/oauth2/authorize?{query}&prompt=login"))
        .await;
    assert!(page.body.contains("name=\"password\""), "{}", page.body);

    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::Oidc, LoginResult::Success),
        1
    );
    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::OidcSession, LoginResult::Success),
        1
    );
    assert_eq!(
        server.metrics.token_grant_count(
            spindle_server::metrics::TokenGrant::AuthorizationCode,
            spindle_server::metrics::GrantResult::Success
        ),
        2
    );
}

/// The pages sit behind a sign-in whose `next` can only ever be a page of
/// this server's, and whose form needs its double-submit token.
#[tokio::test]
async fn the_sign_in_gate_and_its_redirects() {
    let server = Instance::builtin().await;
    server.register("alice").await;
    let mut browser = Browser::default();

    let page = browser
        .get(&server, "/account/?action=org.matrix.sessions_list")
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(
        page.location(),
        "/account/login?next=%2Faccount%2F%3Faction%3Dorg.matrix.sessions_list"
    );

    // No CSRF cookie: refused before any password is checked.
    let mut bare = Browser::default();
    let page = bare
        .post(
            &server,
            "/account/login",
            &[("username", "alice"), ("password", PASSWORD), ("csrf", "x")],
        )
        .await;
    assert_eq!(page.status, 403);

    let page = browser.sign_in(&server, "alice", "wrong-password").await;
    assert_eq!(page.status, 401);
    assert!(page.body.contains("did not match"));

    // An off-site `next` is replaced, not followed.
    let login = browser.get(&server, "/account/login").await;
    let csrf = login.field("csrf");
    let page = browser
        .post(
            &server,
            "/account/login",
            &[
                ("username", "@alice:ignored"),
                ("password", PASSWORD),
                ("csrf", &csrf),
                ("next", "//evil.example/account/"),
            ],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(page.location(), "/account/");

    let page = browser.get(&server, "/account/").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&server.user("alice")));
    assert_eq!(page.headers["cache-control"], "no-store");
    let csp = page.headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("form-action 'self'"), "{csp}");

    // Signing out ends the session server-side, not just in the browser.
    let csrf = page.field("csrf");
    let kept = browser.cookie_header();
    let page = browser
        .post(&server, "/account/logout", &[("csrf", &csrf)])
        .await;
    assert_eq!(page.status, 303);
    let replay = server
        .client
        .get(server.url("/account/"))
        .header("cookie", kept)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status().as_u16(), 303, "the old cookie is dead");

    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::Account, LoginResult::BadPassword),
        1
    );
    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::Account, LoginResult::Success),
        1
    );
}

#[tokio::test]
async fn profile_changes_land_where_the_client_api_reads_them() {
    let server = Instance::builtin().await;
    let token = server.register("alice").await;
    let mut browser = Browser::default();
    browser.sign_in(&server, "alice", PASSWORD).await;
    let page = browser
        .get(&server, "/account/?action=org.matrix.profile")
        .await;
    let csrf = page.field("csrf");

    let page = browser
        .post(
            &server,
            "/account/profile",
            &[("displayname", "Mallory"), ("avatar_url", "")],
        )
        .await;
    assert_eq!(page.status, 403, "no CSRF, no change");
    let page = browser
        .post(
            &server,
            "/account/profile",
            &[
                ("csrf", &csrf),
                ("displayname", "Alice"),
                ("avatar_url", "https://not.mxc/a.png"),
            ],
        )
        .await;
    assert_eq!(page.status, 400);
    let page = browser
        .post(
            &server,
            "/account/profile",
            &[
                ("csrf", &csrf),
                ("displayname", "Alice <b>A</b>"),
                ("avatar_url", "mxc://example.org/abc"),
            ],
        )
        .await;
    assert_eq!(page.status, 303);
    let user = server.user("alice");
    let (status, profile) = server
        .api(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{user}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(profile["displayname"], "Alice <b>A</b>");
    assert_eq!(profile["avatar_url"], "mxc://example.org/abc");
    let page = browser.get(&server, "/account/").await;
    assert!(
        page.body.contains("Alice &lt;b&gt;A&lt;/b&gt;"),
        "rendered escaped: {}",
        page.body
    );
    assert_eq!(
        server.metrics.account_action_count(AccountAction::Profile),
        1
    );
}

#[tokio::test]
async fn changing_the_password_needs_the_current_one() {
    let server = Instance::builtin().await;
    let old_token = server.register("alice").await;
    let mut browser = Browser::default();
    browser.sign_in(&server, "alice", PASSWORD).await;
    let csrf = browser
        .get(&server, "/account/?action=password")
        .await
        .field("csrf");
    let attempt = |current: &'static str, new: &'static str, confirm: &'static str| {
        vec![
            ("csrf", csrf.clone()),
            ("current_password", current.to_owned()),
            ("new_password", new.to_owned()),
            ("confirm_password", confirm.to_owned()),
            ("sign_out_others", "yes".to_owned()),
        ]
    };
    for (form, status) in [
        (attempt("wrong", "brand-new-pass", "brand-new-pass"), 401),
        (attempt(PASSWORD, "brand-new-pass", "different-pass"), 400),
        (attempt(PASSWORD, "short", "short"), 400),
        (attempt(PASSWORD, "brand-new-pass", "brand-new-pass"), 303),
    ] {
        let borrowed: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let page = browser.post(&server, "/account/password", &borrowed).await;
        assert_eq!(page.status, status, "{}", page.body);
    }
    let (status, _) = server.password_login("alice", PASSWORD, "D1").await;
    assert_eq!(status, 403, "the old password is gone");
    let (status, _) = server.password_login("alice", "brand-new-pass", "D2").await;
    assert_eq!(status, 200);
    let (status, _) = server
        .api(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&old_token),
            None,
        )
        .await;
    assert_eq!(status, 401, "the other sessions were signed out");
    // This browser stays signed in.
    assert_eq!(browser.get(&server, "/account/").await.status, 200);
    assert_eq!(
        server
            .metrics
            .account_action_count(AccountAction::PasswordChange),
        1
    );
}

/// A password changed anywhere — here, the client API — ends every
/// browser session that predates it, so a stolen one cannot outlive the
/// change and keep minting codes through "Continue as".
#[tokio::test]
async fn a_password_change_elsewhere_ends_browser_sessions() {
    let server = Instance::builtin().await;
    let token = server.register("alice").await;
    let mut browser = Browser::default();
    browser.sign_in(&server, "alice", PASSWORD).await;
    assert_eq!(browser.get(&server, "/account/").await.status, 200);
    let (status, body) = server
        .api(
            reqwest::Method::POST,
            "/_matrix/client/v3/account/password",
            Some(&token),
            Some(json!({
                "new_password": "changed-elsewhere",
                "logout_devices": false,
                "auth": { "type": "m.login.password", "session": "s", "password": PASSWORD,
                          "identifier": { "type": "m.id.user", "user": "alice" } },
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        browser.get(&server, "/account/").await.status,
        303,
        "the browser session died with the old password"
    );
}

#[tokio::test]
async fn devices_are_listed_viewed_and_signed_out() {
    let server = Instance::builtin().await;
    server.register("alice").await;
    let (status, phone) = server.password_login("alice", PASSWORD, "PHONE").await;
    assert_eq!(status, 200, "{phone}");
    let phone_token = phone["access_token"].as_str().unwrap().to_owned();
    let mut browser = Browser::default();
    browser.sign_in(&server, "alice", PASSWORD).await;

    let page = browser
        .get(&server, "/account/?action=org.matrix.sessions_list")
        .await;
    assert!(page.body.contains("PHONE"), "{}", page.body);
    for action in ["org.matrix.session_view", "org.matrix.device_view"] {
        let page = browser
            .get(
                &server,
                &format!("/account/?action={action}&device_id=PHONE"),
            )
            .await;
        assert_eq!(page.status, 200);
        assert!(page.body.contains("Sign out this device"), "{}", page.body);
    }
    let page = browser
        .get(
            &server,
            "/account/?action=org.matrix.session_end&device_id=PHONE",
        )
        .await;
    assert!(page.body.contains("Sign this device out?"), "{}", page.body);
    let csrf = page.field("csrf");
    let page = browser
        .post(
            &server,
            "/account/sessions/end",
            &[("csrf", &csrf), ("device_id", "PHONE")],
        )
        .await;
    assert_eq!(page.status, 303);
    let (status, _) = server
        .api(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&phone_token),
            None,
        )
        .await;
    assert_eq!(status, 401, "the device's token died with it");
    let page = browser
        .get(&server, "/account/?action=org.matrix.sessions_list")
        .await;
    assert!(!page.body.contains("PHONE"), "{}", page.body);
    assert_eq!(
        server
            .metrics
            .account_action_count(AccountAction::SessionEnd),
        1
    );

    // Cross-signing reset needs no approval here, and the page says so.
    let page = browser
        .get(&server, "/account/?action=org.matrix.cross_signing_reset")
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("does not need any further approval"));
    // An unknown action falls back to the profile page.
    let page = browser.get(&server, "/account/?action=nonsense").await;
    assert!(page.body.contains("Display name"), "{}", page.body);
}

#[tokio::test]
async fn deactivation_needs_the_password_and_a_confirmation() {
    let server = Instance::builtin().await;
    let token = server.register("alice").await;
    let mut browser = Browser::default();
    browser.sign_in(&server, "alice", PASSWORD).await;
    let csrf = browser
        .get(&server, "/account/?action=org.matrix.account_deactivate")
        .await
        .field("csrf");

    let page = browser
        .post(
            &server,
            "/account/deactivate",
            &[("csrf", &csrf), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(page.status, 400, "no confirmation");
    let page = browser
        .post(
            &server,
            "/account/deactivate",
            &[("csrf", &csrf), ("password", "wrong"), ("confirm", "yes")],
        )
        .await;
    assert_eq!(page.status, 401);
    let page = browser
        .post(
            &server,
            "/account/deactivate",
            &[
                ("csrf", &csrf),
                ("password", PASSWORD),
                ("confirm", "yes"),
                ("erase", "yes"),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("deactivated"));

    let (status, _) = server
        .api(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 401);
    let (status, _) = server.password_login("alice", PASSWORD, "D").await;
    assert_eq!(status, 403, "a deactivated account cannot sign in");
    assert_eq!(browser.get(&server, "/account/").await.status, 303);
    assert_eq!(
        server
            .metrics
            .account_action_count(AccountAction::Deactivate),
        1
    );
}

/// The pages spend the same attempt budget as the client login: five
/// wrong passwords for one account and the sixth try is refused before
/// the password is even checked, whichever door it comes through.
#[tokio::test]
async fn password_attempts_share_the_login_budget() {
    let server = Instance::start("[auth]\nbuiltin_oidc = true\n").await;
    server.register("alice").await;
    let mut browser = Browser::default();
    for _ in 0..5 {
        let page = browser.sign_in(&server, "alice", "wrong-password").await;
        assert_eq!(page.status, 401);
    }
    let page = browser.sign_in(&server, "alice", PASSWORD).await;
    assert_eq!(page.status, 429, "even the right password waits");
    let (status, body) = server.password_login("alice", PASSWORD, "D").await;
    assert_eq!(status, 429, "the client API shares the budget: {body}");
    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::Account, LoginResult::RateLimited),
        1
    );
    assert_eq!(
        server
            .metrics
            .login_count(LoginMethod::Password, LoginResult::RateLimited),
        1
    );
    let text = server.metrics.render();
    assert!(
        text.contains("spindle_auth_logins_total{method=\"account\",result=\"bad_password\"} 5"),
        "{text}"
    );
    assert!(!text.contains("alice"), "no username in any label");
}
