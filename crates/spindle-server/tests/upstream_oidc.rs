//! Upstream identity providers (#610) — a real Spindle over TCP, signing in
//! through a mock OIDC provider served in the same process: discovery, a
//! JWKS, and a token endpoint that checks the client's secret, the PKCE
//! verifier and the redirect URI before it signs an ID token. The browser
//! is played by hand, cookies included; the upstream's own login page is
//! skipped by minting the code the callback receives.
//!
//! What it pins: first sign-in creates an account from the claims and a
//! returning identity finds it by its link (not its name), the built-in
//! provider's authorization page and the client API's `m.login.sso` both
//! end signed in, and every forged, misaddressed, stale or replayed answer
//! is refused without an account or a session coming of it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RsaKeyPair};
use serde_json::{Value, json};
use sha2::Digest;
use spindle_store::FjallStore;
use tempfile::TempDir;

const CLIENT_ID: &str = "spindle";
const CLIENT_SECRET: &str = "s3cret";

fn b64url(bytes: &[u8]) -> String {
    ruma::serde::Base64::<ruma::serde::base64::UrlSafe, _>::new(bytes.to_vec()).encode()
}

fn b64url_decode(text: &str) -> Vec<u8> {
    ruma::serde::Base64::<ruma::serde::base64::UrlSafe>::parse(text)
        .unwrap()
        .into_inner()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// RFC 7515 Appendix A.2's RSA key — published test material, so no key of
/// this repository's own is checked in — for an RS256 sign-in, the
/// algorithm Keycloak and Authelia sign with by default.
fn rfc7515_rsa_key() -> (RsaKeyPair, Value) {
    let part = |text: &str| b64url_decode(&text.split_whitespace().collect::<String>());
    // spellchecker:off
    let n = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx
        HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs
        D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH
        SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV
        MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8
        NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    let components = ring::rsa::KeyPairComponents {
        public_key: ring::rsa::PublicKeyComponents {
            n: part(n),
            e: part("AQAB"),
        },
        d: part(
            "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I
             jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0
             BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn
             439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT
             CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh
             BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
        ),
        p: part(
            "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi
             YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
             BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
        ),
        q: part(
            "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa
             ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA
             -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
        ),
        dP: part(
            "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q
             CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb
             34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
        ),
        dQ: part(
            "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa
             7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky
             NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
        ),
        qInv: part(
            "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o
             y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU
             W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
        ),
    };
    let pair = RsaKeyPair::from_components(&components).unwrap();
    let jwk = json!({
        "kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256",
        "n": n.split_whitespace().collect::<String>(), "e": "AQAB",
    });
    // spellchecker:on
    (pair, jwk)
}

fn ec_key() -> EcdsaKeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}

/// Which key signs an ID token.
#[derive(Clone, Copy)]
enum Signer {
    /// The published ES256 key.
    Ec,
    /// The published RS256 key.
    Rsa,
    /// An ES256 key the JWKS does not hold.
    Rogue,
}

/// What the mock's token endpoint will answer for one code.
struct Grant {
    challenge: String,
    redirect_uri: String,
    id_token_claims: Value,
    userinfo: Value,
    signer: Signer,
}

struct Idp {
    issuer: String,
    ec: EcdsaKeyPair,
    rogue: EcdsaKeyPair,
    rsa: RsaKeyPair,
    rsa_jwk: Value,
    grants: Mutex<HashMap<String, Grant>>,
    userinfo: Mutex<HashMap<String, Value>>,
}

impl Idp {
    fn sign(&self, claims: &Value, signer: Signer) -> String {
        let (alg, kid) = match signer {
            Signer::Rsa => ("RS256", "rsa1"),
            Signer::Ec | Signer::Rogue => ("ES256", "ec1"),
        };
        let header = b64url(
            json!({ "alg": alg, "kid": kid, "typ": "JWT" })
                .to_string()
                .as_bytes(),
        );
        let payload = b64url(claims.to_string().as_bytes());
        let message = format!("{header}.{payload}");
        let rng = ring::rand::SystemRandom::new();
        let signature = match signer {
            Signer::Ec => self
                .ec
                .sign(&rng, message.as_bytes())
                .unwrap()
                .as_ref()
                .to_vec(),
            Signer::Rogue => self
                .rogue
                .sign(&rng, message.as_bytes())
                .unwrap()
                .as_ref()
                .to_vec(),
            Signer::Rsa => {
                let mut out = vec![0; self.rsa.public().modulus_len()];
                self.rsa
                    .sign(
                        &ring::signature::RSA_PKCS1_SHA256,
                        &rng,
                        message.as_bytes(),
                        &mut out,
                    )
                    .unwrap();
                out
            }
        };
        format!("{message}.{}", b64url(&signature))
    }
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    let issuer = &idp.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
    }))
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Json<Value> {
    let point = idp.ec.public_key().as_ref();
    Json(json!({ "keys": [
        { "kty": "EC", "kid": "ec1", "use": "sig", "alg": "ES256", "crv": "P-256",
          "x": b64url(&point[1..33]), "y": b64url(&point[33..]) },
        idp.rsa_jwk,
        // A key this server cannot use sits in real sets too.
        { "kty": "oct", "kid": "sym", "k": "c2VjcmV0" },
    ] }))
}

/// The token endpoint: client authentication (Basic or in the body), the
/// code once, PKCE and the redirect URI, as a real provider checks them.
async fn token(
    State(idp): State<Arc<Idp>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let refuse = |code: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": code })));
    // Decoded rather than compared as text: padding is the encoder's choice.
    let by_header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| {
            ruma::serde::Base64::<ruma::serde::base64::Standard>::parse(encoded).ok()
        })
        .is_some_and(|decoded| {
            decoded.as_bytes() == format!("{CLIENT_ID}:{CLIENT_SECRET}").as_bytes()
        });
    let by_body = form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET);
    if !by_header && !by_body {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_client" })),
        ));
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return Err(refuse("unsupported_grant_type"));
    }
    let code = form.get("code").cloned().unwrap_or_default();
    let grant = idp
        .grants
        .lock()
        .unwrap()
        .remove(&code)
        .ok_or_else(|| refuse("invalid_grant"))?;
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if b64url(&sha2::Sha256::digest(verifier.as_bytes())) != grant.challenge
        || form.get("redirect_uri") != Some(&grant.redirect_uri)
    {
        return Err(refuse("invalid_grant"));
    }
    let access_token = format!("at-{code}");
    idp.userinfo
        .lock()
        .unwrap()
        .insert(access_token.clone(), grant.userinfo);
    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "id_token": idp.sign(&grant.id_token_claims, grant.signer),
    })))
}

async fn userinfo(
    State(idp): State<Arc<Idp>>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    idp.userinfo
        .lock()
        .unwrap()
        .get(token)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn start_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (rsa, rsa_jwk) = rfc7515_rsa_key();
    let idp = Arc::new(Idp {
        issuer: format!("http://{}", listener.local_addr().unwrap()),
        ec: ec_key(),
        rogue: ec_key(),
        rsa,
        rsa_jwk,
        grants: Mutex::new(HashMap::new()),
        userinfo: Mutex::new(HashMap::new()),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .with_state(Arc::clone(&idp));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    idp
}

struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
    idp: Arc<Idp>,
    store: Arc<FjallStore>,
    config: spindle_server::Config,
}

impl Instance {
    async fn start() -> Instance {
        Self::start_with(false, "").await
    }

    /// `extra` is appended to the configuration: more providers.
    async fn start_with(rate_limited: bool, extra: &str) -> Instance {
        let idp = start_idp().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let provider = |id: &str, extra: &str| {
            format!(
                "[[auth.upstream_oidc]]\nid = \"{id}\"\nname = \"Mock {id}\"\n\
                 issuer = \"{issuer}\"\nclient_id = \"{CLIENT_ID}\"\n\
                 client_secret = \"{CLIENT_SECRET}\"\n{extra}",
                issuer = idp.issuer,
            )
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\npublic_base_url = \"http://{name}\"\n\
             [ratelimit]\nenabled = {rate_limited}\n[auth]\nbuiltin_oidc = true\n{}{}{}{}",
            provider("mock", ""),
            provider("trusting", "link_existing_by_email = true\n"),
            provider(
                "info",
                "token_endpoint_auth_method = \"client_secret_post\"\nfetch_userinfo = true\n"
            ),
            extra.replace("{issuer}", &idp.issuer),
        ))
        .unwrap();
        let app = spindle_server::app(config.clone(), Arc::clone(&store)).expect("the app builds");
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
            idp,
            store,
            config,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.name)
    }

    fn user(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.name)
    }

    async fn api(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self.client.request(method, self.url(path));
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

    async fn available(&self, localpart: &str) -> bool {
        let (status, _) = self
            .api(
                reqwest::Method::GET,
                &format!("/_matrix/client/v3/register/available?username={localpart}"),
                None,
            )
            .await;
        status == 200
    }
}

#[derive(Default)]
struct Browser {
    jar: HashMap<String, String>,
    /// Every binding cookie the server set, to replay one by hand.
    bindings: Vec<String>,
}

struct Page {
    status: u16,
    location: String,
    body: String,
}

impl Browser {
    async fn get(&mut self, server: &Instance, url: &str) -> Page {
        let cookies = self
            .jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let response = server
            .client
            .get(url)
            .header("cookie", cookies)
            .send()
            .await
            .unwrap();
        for value in response.headers().get_all("set-cookie") {
            let text = value.to_str().unwrap();
            let (name, value) = text.split(';').next().unwrap().split_once('=').unwrap();
            if value.is_empty() || text.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                if name == "spindle_upstream" {
                    self.bindings.push(value.to_owned());
                }
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        Page {
            status: response.status().as_u16(),
            location: response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
            body: response.text().await.unwrap(),
        }
    }

    fn signed_in(&self) -> bool {
        self.jar.contains_key("spindle_session")
    }
}

/// What the upstream says about the person, given the flow's nonce.
struct Answer {
    claims: Value,
    userinfo: Value,
    signer: Signer,
}

fn person(sub: &str, username: &str) -> Value {
    json!({
        "sub": sub, "aud": CLIENT_ID, "exp": now() + 300, "iat": now(),
        "preferred_username": username, "name": format!("{username} Example"),
    })
}

/// Start a sign-in at `start` (a path on Spindle), play the upstream's part
/// with `answer`, and return the callback URL and what it answered.
async fn sign_in(
    server: &Instance,
    browser: &mut Browser,
    start: &str,
    answer: impl FnOnce(&Instance, &str) -> Answer,
) -> (String, Page) {
    let page = browser.get(server, &server.url(start)).await;
    assert_eq!(page.status, 303, "{start}: {}", page.body);
    let authorize = page.location;
    assert!(
        authorize.starts_with(&format!("{}/authorize?", server.idp.issuer)),
        "{authorize}"
    );
    let query: HashMap<String, String> =
        form_urlencoded::parse(authorize.split_once('?').unwrap().1.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(query["scope"].split(' ').any(|scope| scope == "openid"));
    let mut answer = answer(server, &query["nonce"]);
    if answer.claims.get("nonce").is_none() {
        answer.claims["nonce"] = json!(query["nonce"]);
    }
    if answer.claims.get("iss").is_none() {
        answer.claims["iss"] = json!(server.idp.issuer);
    }
    let code = format!("code-{}", query["state"]);
    server.idp.grants.lock().unwrap().insert(
        code.clone(),
        Grant {
            challenge: query["code_challenge"].clone(),
            redirect_uri: query["redirect_uri"].clone(),
            id_token_claims: answer.claims,
            userinfo: answer.userinfo,
            signer: answer.signer,
        },
    );
    let callback = format!(
        "{}?code={code}&state={}",
        query["redirect_uri"], query["state"]
    );
    let page = browser.get(server, &callback).await;
    (callback, page)
}

/// The upstream's part of one sign-in, boxed so cases can be listed.
type Respond = Box<dyn FnOnce(&Instance, &str) -> Answer>;

fn plain(claims: Value) -> impl FnOnce(&Instance, &str) -> Answer {
    move |_, _| Answer {
        claims,
        userinfo: Value::Null,
        signer: Signer::Ec,
    }
}

#[tokio::test]
async fn first_sign_in_makes_the_account_and_the_next_finds_it_by_its_link() {
    let server = Instance::start().await;
    let mut browser = Browser::default();
    let mut claims = person("subject-1", "Ursula");
    claims["email"] = json!("ursula@example.org");
    claims["email_verified"] = json!(true);
    let (callback, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock?next=%2Faccount%2F%3Faction%3Dorg.matrix.profile",
        plain(claims),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert_eq!(page.location, "/account/?action=org.matrix.profile");
    assert!(callback.starts_with(&server.url("/upstream/callback/mock?")));
    assert!(browser.signed_in(), "the callback starts a browser session");
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("ursula")), "{}", home.body);
    let (_, profile) = server
        .api(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/{}", server.user("ursula")),
            None,
        )
        .await;
    assert_eq!(profile["displayname"], "Ursula Example", "{profile}");

    // The same subject again, under another name: the link decides, the
    // name does not, and no second account appears.
    let mut browser = Browser::default();
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock",
        plain(person("subject-1", "renamed")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("ursula")), "{}", home.body);
    assert!(server.available("renamed").await);
}

#[tokio::test]
async fn the_authorization_page_offers_the_provider_and_returns_to_the_request() {
    let server = Instance::start().await;
    let (status, client) = server
        .api(
            reqwest::Method::POST,
            "/oauth2/registration",
            Some(json!({ "redirect_uris": ["https://app.example/cb"], "client_name": "App" })),
        )
        .await;
    assert_eq!(status, 201);
    let authorize = format!(
        "/oauth2/authorize?response_type=code&client_id={}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb\
         &scope=urn%3Amatrix%3Aclient%3Aapi%3A*%20urn%3Amatrix%3Aclient%3Adevice%3ADEV1\
         &state=s&code_challenge_method=S256&code_challenge=abc",
        client["client_id"].as_str().unwrap()
    );
    let mut browser = Browser::default();
    let page = browser.get(&server, &server.url(&authorize)).await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("Sign in with Mock mock"),
        "{}",
        page.body
    );
    let start = page
        .body
        .split("href=\"")
        .find(|rest| rest.starts_with("/upstream/authorize/mock?"))
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .replace("&amp;", "&");

    let (_, page) = sign_in(
        &server,
        &mut browser,
        &start,
        plain(person("v-1", "victor")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(
        page.location.starts_with("/oauth2/authorize?"),
        "back to the authorization request: {}",
        page.location
    );
    let consent = browser.get(&server, &server.url(&page.location)).await;
    assert_eq!(consent.status, 200);
    assert!(
        consent
            .body
            .contains(&format!("Continue as {}", server.user("victor"))),
        "{}",
        consent.body
    );
}

#[tokio::test]
async fn the_client_api_signs_in_through_sso() {
    let server = Instance::start().await;
    let (status, flows) = server
        .api(reqwest::Method::GET, "/_matrix/client/v3/login", None)
        .await;
    assert_eq!(status, 200);
    let sso = flows["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["type"] == "m.login.sso")
        .expect("an m.login.sso flow");
    assert_eq!(
        sso["identity_providers"][0],
        json!({ "id": "mock", "name": "Mock mock" })
    );
    assert_eq!(sso["identity_providers"].as_array().unwrap().len(), 3);

    // Several providers and none named: a page to choose from.
    let mut browser = Browser::default();
    let page = browser
        .get(
            &server,
            &server.url("/_matrix/client/v3/login/sso/redirect?redirectUrl=https%3A%2F%2Fapp.example%2Fdone"),
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body
            .contains("/_matrix/client/v3/login/sso/redirect/trusting?redirectUrl="),
        "{}",
        page.body
    );

    // RS256, as Keycloak and Authelia sign by default.
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/_matrix/client/v3/login/sso/redirect/mock?redirectUrl=https%3A%2F%2Fapp.example%2Fdone",
        |_, _| Answer {
            claims: person("w-1", "wanda"),
            userinfo: Value::Null,
            signer: Signer::Rsa,
        },
    )
    .await;
    assert_eq!(
        page.status, 200,
        "a confirmation, not a redirect: {}",
        page.body
    );
    assert!(page.body.contains("app.example"), "{}", page.body);
    let marker = "href=\"https://app.example/done?loginToken=";
    let start = page.body.find(marker).expect("the link back") + marker.len();
    let token = &page.body[start..start + page.body[start..].find('"').unwrap()];
    let (status, body) = server
        .api(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            Some(json!({ "type": "m.login.token", "token": token })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user_id"], server.user("wanda"));
    let (status, _) = server
        .api(
            reqwest::Method::POST,
            "/_matrix/client/v3/login",
            Some(json!({ "type": "m.login.token", "token": token })),
        )
        .await;
    assert_eq!(status, 403, "a login token works once");
}

#[tokio::test]
async fn forged_misaddressed_and_stale_id_tokens_are_refused() {
    let server = Instance::start().await;
    let cases: Vec<(&str, Respond)> = vec![
        (
            "a signature by a key the provider does not publish",
            Box::new(|_, _| Answer {
                claims: person("bad-1", "mallory"),
                userinfo: Value::Null,
                signer: Signer::Rogue,
            }),
        ),
        ("an audience that is another client", {
            let mut claims = person("bad-2", "mallory");
            claims["aud"] = json!("another-client");
            Box::new(plain(claims))
        }),
        ("another issuer", {
            let mut claims = person("bad-3", "mallory");
            claims["iss"] = json!("https://evil.example");
            Box::new(plain(claims))
        }),
        ("an expired token", {
            let mut claims = person("bad-4", "mallory");
            claims["exp"] = json!(now() - 3600);
            Box::new(plain(claims))
        }),
        ("a nonce from another flow", {
            let mut claims = person("bad-5", "mallory");
            claims["nonce"] = json!("a-nonce-replayed-from-elsewhere");
            Box::new(plain(claims))
        }),
    ];
    for (why, answer) in cases {
        let mut browser = Browser::default();
        let (_, page) = sign_in(&server, &mut browser, "/upstream/authorize/mock", answer).await;
        assert_eq!(page.status, 502, "{why}: {}", page.body);
        assert!(!browser.signed_in(), "{why}");
    }
    assert!(
        server.available("mallory").await,
        "no account came of any of it"
    );
}

#[tokio::test]
async fn a_callback_works_once_and_only_in_the_browser_that_started_it() {
    let server = Instance::start().await;
    let mut browser = Browser::default();
    let (callback, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock",
        plain(person("r-1", "rhoda")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    // Replayed with the very cookie the flow was sealed in: the flow (its
    // state and nonce with it) was spent.
    let mut replay = Browser::default();
    replay.jar.insert(
        "spindle_upstream".to_owned(),
        browser.bindings.last().unwrap().clone(),
    );
    let page = replay.get(&server, &callback).await;
    assert_eq!(page.status, 400, "{}", page.body);
    assert!(!replay.signed_in());

    // Finished in a browser without the flow's cookie — the login-CSRF
    // shape, an attacker's flow handed to a victim — it is refused.
    let mut attacker = Browser::default();
    let page = attacker
        .get(&server, &server.url("/upstream/authorize/mock"))
        .await;
    let query: HashMap<String, String> =
        form_urlencoded::parse(page.location.split_once('?').unwrap().1.as_bytes())
            .into_owned()
            .collect();
    let mut victim = Browser::default();
    let page = victim
        .get(
            &server,
            &format!("{}?code=x&state={}", query["redirect_uri"], query["state"]),
        )
        .await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert!(!victim.signed_in());
}

#[tokio::test]
async fn a_taken_name_is_not_handed_over_and_linking_by_email_is_opt_in() {
    let server = Instance::start().await;
    let (status, _) = server
        .api(
            reqwest::Method::POST,
            "/_matrix/client/v3/register",
            Some(json!({ "username": "dave", "password": "hunter2hunter2",
                         "auth": { "type": "m.login.dummy" } })),
        )
        .await;
    assert_eq!(status, 200);
    let mut browser = Browser::default();
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock",
        plain(person("d-1", "dave")),
    )
    .await;
    assert_eq!(page.status, 409, "a local account's name: {}", page.body);
    assert!(!browser.signed_in());

    // carol arrives through the provider with a verified address, which
    // lands on her new account.
    let verified = |sub: &str, username: &str| {
        let mut claims = person(sub, username);
        claims["email"] = json!("carol@example.org");
        claims["email_verified"] = json!(true);
        claims
    };
    let mut browser = Browser::default();
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock",
        plain(verified("c-1", "carol")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);

    // Another identity with that address: off by default, it gets an
    // account of its own rather than carol's.
    let mut browser = Browser::default();
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/mock",
        plain(verified("c-2", "carla")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("carla")), "{}", home.body);

    // The provider configured to link by address signs it in as carol —
    // but only for an address it says it verified.
    let mut browser = Browser::default();
    let mut unverified = verified("c-3", "carlotta");
    unverified["email_verified"] = json!(false);
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/trusting",
        plain(unverified),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(
        home.body.contains(&server.user("carlotta")),
        "{}",
        home.body
    );
    let mut browser = Browser::default();
    let (_, page) = sign_in(
        &server,
        &mut browser,
        "/upstream/authorize/trusting",
        plain(verified("c-4", "someone-else")),
    )
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("carol")), "{}", home.body);
    assert!(server.available("someone-else").await);
}

/// Authelia's default: the ID token says who, userinfo says the rest. And
/// the client secret in the form body rather than Basic.
#[tokio::test]
async fn userinfo_fills_in_what_the_id_token_leaves_out() {
    let server = Instance::start().await;
    let mut browser = Browser::default();
    let (_, page) = sign_in(&server, &mut browser, "/upstream/authorize/info", |_, _| {
        Answer {
            claims: json!({ "sub": "i-1", "aud": CLIENT_ID, "exp": now() + 300 }),
            userinfo: json!({ "sub": "i-1", "preferred_username": "ivy", "name": "Ivy Example" }),
            signer: Signer::Ec,
        }
    })
    .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("ivy")), "{}", home.body);

    // Userinfo about somebody else is not merged.
    let mut browser = Browser::default();
    let (_, page) = sign_in(&server, &mut browser, "/upstream/authorize/info", |_, _| {
        Answer {
            claims: json!({ "sub": "i-2", "aud": CLIENT_ID, "exp": now() + 300 }),
            userinfo: json!({ "sub": "someone-else", "preferred_username": "imposter" }),
            signer: Signer::Ec,
        }
    })
    .await;
    assert_eq!(page.status, 502, "{}", page.body);
    assert!(server.available("imposter").await);
}

/// #610 review: starting a flow holds nothing on the server and spends no
/// budget, so nobody can use up sign-in for everyone behind the same
/// address by opening flows. Failed callbacks are what cost, and they
/// spend the per-source login budget.
#[tokio::test]
async fn starting_flows_is_free_and_failed_callbacks_are_counted() {
    let server = Instance::start_with(true, "").await;
    let mut redirect_uri = String::new();
    for attempt in 0..40 {
        let page = Browser::default()
            .get(&server, &server.url("/upstream/authorize/mock"))
            .await;
        assert_eq!(page.status, 303, "start {attempt}: {}", page.body);
        redirect_uri = form_urlencoded::parse(page.location.split_once('?').unwrap().1.as_bytes())
            .find(|(name, _)| name == "redirect_uri")
            .unwrap()
            .1
            .into_owned();
    }
    let mut statuses = Vec::new();
    for _ in 0..31 {
        let page = Browser::default()
            .get(&server, &format!("{redirect_uri}?code=x&state=forged"))
            .await;
        statuses.push(page.status);
    }
    assert!(
        statuses[..30].iter().all(|status| *status == 403),
        "{statuses:?}"
    );
    assert_eq!(statuses[30], 429, "the 31st failure in a minute is refused");
}

/// #797: a link `spindle import-mas` carried over from MAS's
/// `upstream_oauth_links` signs its identity in to the account MAS had
/// linked, which the name alone could not reach.
#[tokio::test]
async fn a_link_imported_from_mas_signs_in_to_the_account_mas_linked() {
    use spindle_server::import::mas;
    // The provider's id is the ULID MAS shows for the UUID it stores.
    const MAS_PROVIDER: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
    const ULID: &str = "01H455VB4PEX5VSKNK084SN02Q";
    let server = Instance::start_with(
        false,
        &format!(
            "[[auth.upstream_oidc]]\nid = \"{ULID}\"\nname = \"Company SSO\"\n\
             issuer = \"{{issuer}}\"\nclient_id = \"{CLIENT_ID}\"\n\
             client_secret = \"{CLIENT_SECRET}\"\n"
        ),
    )
    .await;
    // The account as MAS provisioned it under delegation.
    spindle_server::accounts::Accounts::new(server.store.as_ref(), &server.name)
        .register("olivia", "provisioned by MAS, never used")
        .unwrap();
    let start = format!("/upstream/authorize/{ULID}");
    let olivia = || plain(person("mas-subject-7", "olivia"));

    // Before the import the identity is a stranger: the name is taken, and
    // a name never hands over an existing account.
    let mut browser = Browser::default();
    let (_, page) = sign_in(&server, &mut browser, &start, olivia()).await;
    assert_eq!(page.status, 409, "{}", page.body);
    assert!(!browser.signed_in());

    let snapshot = mas::Snapshot {
        users: vec![mas::User {
            id: "u-olivia".to_owned(),
            username: "olivia".to_owned(),
            ..mas::User::default()
        }],
        providers: vec![mas::Provider {
            id: MAS_PROVIDER.to_owned(),
            issuer: Some(server.idp.issuer.clone()),
        }],
        links: vec![mas::Link {
            provider_id: MAS_PROVIDER.to_owned(),
            subject: "mas-subject-7".to_owned(),
            user_id: Some("u-olivia".to_owned()),
        }],
    };
    let report = mas::apply(
        server.store.as_ref(),
        &server.config,
        &snapshot,
        &mas::Schemes::default(),
        false,
    )
    .unwrap();
    assert_eq!(report.links.imported, 1, "{report:?}");
    assert!(report.refused.is_empty(), "{report:?}");

    let mut browser = Browser::default();
    let (_, page) = sign_in(&server, &mut browser, &start, olivia()).await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(browser.signed_in());
    let home = browser.get(&server, &server.url("/account/")).await;
    assert!(home.body.contains(&server.user("olivia")), "{}", home.body);
}
