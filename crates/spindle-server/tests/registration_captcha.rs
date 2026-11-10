//! `m.login.recaptcha`: with a CAPTCHA configured, registration needs the
//! provider to accept the client's token, and fails closed when it cannot ask.

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const SECRET: &str = "s3cr3t-key-do-not-log";

/// What the mock provider saw: each form body it was posted.
type Seen = Arc<Mutex<Vec<String>>>;

/// A stand-in for the provider's verify endpoint. The token `good` passes,
/// `boom` makes it fail with a 500, anything else is a wrong answer.
async fn provider() -> (String, Seen) {
    let seen = Seen::default();
    let recorded = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/siteverify",
        axum::routing::post(move |body: String| {
            let recorded = Arc::clone(&recorded);
            async move {
                let form: Vec<(String, String)> = form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect();
                recorded.lock().unwrap().push(body);
                let token = form
                    .iter()
                    .find(|(name, _)| name == "response")
                    .map(|(_, value)| value.as_str())
                    .unwrap_or_default()
                    .to_owned();
                match token.as_str() {
                    "good" => (
                        axum::http::StatusCode::OK,
                        json!({ "success": true }).to_string(),
                    ),
                    "boom" => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, String::new()),
                    _ => (
                        axum::http::StatusCode::OK,
                        json!({ "success": false, "error-codes": ["invalid-input-response"] })
                            .to_string(),
                    ),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/siteverify",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

struct Server {
    app: axum::Router,
    _dir: TempDir,
}

fn server(verify_url: &str, terms: bool) -> Server {
    let dir = TempDir::new().unwrap();
    let secret_file = dir.path().join("captcha_secret");
    std::fs::write(&secret_file, format!("{SECRET}\n")).unwrap();
    let store = Arc::new(FjallStore::open(dir.path().join("data")).unwrap());
    let terms = if terms {
        "terms_url = \"https://example.org/terms\"\n"
    } else {
        ""
    };
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[storage]\npath = \"{data}\"\n[ratelimit]\nenabled = false\n\
         [registration]\n{terms}\
         [registration.captcha]\nprovider = \"hcaptcha\"\nsite_key = \"site-key-1\"\n\
         secret_key_file = \"{secret}\"\nverify_url = \"{verify_url}\"\n\
         allow_internal = [\"127.0.0.0/8\"]\n",
        data = dir.path().join("data").display(),
        secret = secret_file.display(),
    ))
    .unwrap();
    Server {
        app: spindle_server::app(config, store).unwrap(),
        _dir: dir,
    }
}

async fn register(app: &axum::Router, auth: Option<Value>) -> (u16, Value) {
    let mut body = json!({ "username": "carol", "password": "hunter2hunter2" });
    if let Some(auth) = auth {
        body["auth"] = auth;
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn captcha(session: &str, token: &str) -> Value {
    json!({ "type": "m.login.recaptcha", "session": session, "response": token })
}

#[tokio::test]
async fn the_flows_list_the_captcha_stage_after_terms() {
    let (url, _) = provider().await;
    let (status, body) = register(&server(&url, true).app, None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        body["flows"],
        json!([{ "stages": ["m.login.terms", "m.login.recaptcha", "m.login.dummy"] }])
    );
    assert_eq!(
        body["params"]["m.login.recaptcha"]["public_key"],
        "site-key-1"
    );
    // Without a policy the CAPTCHA is the first stage.
    let (_, body) = register(&server(&url, false).app, None).await;
    assert_eq!(
        body["flows"],
        json!([{ "stages": ["m.login.recaptcha", "m.login.dummy"] }])
    );
}

#[tokio::test]
async fn a_registration_without_a_solved_captcha_is_refused() {
    let (url, seen) = provider().await;
    let app = server(&url, false).app;

    // The last stage alone, with or without a session, does not register.
    for auth in [
        json!({ "type": "m.login.dummy" }),
        json!({ "type": "m.login.dummy", "session": "register" }),
    ] {
        let (status, body) = register(&app, Some(auth)).await;
        assert_eq!(status, 401, "{body}");
    }
    // A wrong token is refused, says why and leaves the stage open.
    let (status, body) = register(&app, Some(captcha("register", "wrong"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED");
    assert!(body["completed"].is_null(), "{body}");
    // No token at all is refused too.
    let (status, _) = register(
        &app,
        Some(json!({ "type": "m.login.recaptcha", "session": "register" })),
    )
    .await;
    assert_eq!(status, 401);
    // Nothing the client sent can stand in for the proof.
    let (status, body) = register(
        &app,
        Some(json!({ "type": "m.login.dummy", "session": "0.2.deadbeef" })),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "only real tokens were checked"
    );
}

#[tokio::test]
async fn a_valid_captcha_registers_and_the_provider_got_the_secret() {
    let (url, seen) = provider().await;
    let app = server(&url, true).app;

    let (_, body) = register(
        &app,
        Some(json!({ "type": "m.login.terms", "session": "register" })),
    )
    .await;
    let session = body["session"].as_str().unwrap().to_owned();
    // The policy was accepted, but the CAPTCHA cannot be skipped.
    let (status, _) = register(
        &app,
        Some(json!({ "type": "m.login.dummy", "session": session })),
    )
    .await;
    assert_eq!(status, 401);

    let (status, body) = register(&app, Some(captcha(&session, "good"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        body["completed"],
        json!(["m.login.terms", "m.login.recaptcha"])
    );
    let session = body["session"].as_str().unwrap().to_owned();
    let (status, body) = register(
        &app,
        Some(json!({ "type": "m.login.dummy", "session": session })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user_id"], "@carol:example.org");

    let seen = seen.lock().unwrap();
    let form: Vec<(String, String)> = form_urlencoded::parse(seen[0].as_bytes())
        .into_owned()
        .collect();
    assert!(
        form.contains(&("secret".to_owned(), SECRET.to_owned())),
        "{form:?}"
    );
    assert!(form.contains(&("response".to_owned(), "good".to_owned())));
}

#[tokio::test]
async fn a_provider_that_errors_or_is_gone_fails_closed() {
    let (url, _) = provider().await;
    let app = server(&url, false).app;
    let (status, body) = register(&app, Some(captcha("register", "boom"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED");

    // Nothing listens here: connect fails, and the answer is still no.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!(
            "http://127.0.0.1:{}/siteverify",
            listener.local_addr().unwrap().port()
        )
    };
    let app = server(&closed, false).app;
    let (status, body) = register(&app, Some(captcha("register", "good"))).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["errcode"], "M_UNAUTHORIZED");

    // A verify URL outside the allowed ranges is never contacted.
    let (url, seen) = provider().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n[ratelimit]\nenabled = false\n\
         [registration.captcha]\nprovider = \"turnstile\"\nsite_key = \"k\"\n\
         secret_key = \"{SECRET}\"\nverify_url = \"{url}\"\n",
        dir.path().display()
    ))
    .unwrap();
    let app = spindle_server::app(config, store).unwrap();
    let (status, _) = register(&app, Some(captcha("register", "good"))).await;
    assert_eq!(status, 401);
    assert!(seen.lock().unwrap().is_empty());
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn the_secret_never_reaches_a_log_a_response_or_a_debug_print() {
    let captured = Captured::default();
    // A global subscriber, not a scoped one: the other tests in this file run
    // in parallel and hit the same warn! callsite, and a scoped subscriber
    // loses that race, leaving the log empty. This is the only test here that
    // installs one.
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(captured.clone())
            .finish(),
    )
    .expect("no other test installs a global subscriber");
    let (url, _) = provider().await;
    let app = server(&url, false).app;
    let mut everything = String::new();
    for token in ["boom", "wrong", "good"] {
        let (_, body) = register(&app, Some(captcha("register", token))).await;
        everything.push_str(&body.to_string());
    }
    // The failure was logged, and the log is not empty for want of trying.
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("captcha verification failed closed"), "{log}");
    assert!(!log.contains(SECRET), "{log}");
    assert!(!everything.contains(SECRET), "{everything}");

    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[registration.captcha]\nprovider = \"recaptcha\"\n\
         site_key = \"k\"\nsecret_key = \"{SECRET}\"\n"
    ))
    .unwrap();
    assert!(!format!("{config:?}").contains(SECRET));
}

#[test]
fn a_captcha_needs_exactly_one_secret_and_a_readable_file() {
    let parse = |extra: &str| {
        spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[registration.captcha]\nprovider = \"recaptcha\"\n\
             site_key = \"k\"\n{extra}"
        ))
    };
    assert!(parse("").is_err());
    assert!(parse("secret_key = \"a\"\nsecret_key_file = \"/b\"\n").is_err());
    assert!(parse("secret_key = \"a\"\n").is_ok());

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = parse("secret_key_file = \"/nonexistent/secret\"\n").unwrap();
    let error = spindle_server::app(config, store).expect_err("start-up refuses");
    assert!(error.to_string().contains("/nonexistent/secret"), "{error}");
}
