//! URL previews, and the server-side request forgery guard around them.
//!
//! The fixture is a real HTTP server on 127.0.0.1, because the thing under
//! test is precisely "what will the server connect to": a mocked client
//! would test the mock. The test harness allow-lists loopback explicitly —
//! the same config a deployment would use to preview an internal wiki —
//! and the refusal tests run with the allow-list empty, which is the
//! production default.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    /// `allow_private` is the harness's previews allow-list, verbatim.
    fn new(allow_private: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [previews]\nallow_private = [{allow_private}]\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "alice",
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn preview(&self, token: &str, url: &str) -> (StatusCode, Value) {
        let encoded: String = url
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        self.call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/preview_url?url={encoded}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// A page-serving fixture on a real loopback port.
async fn fixture() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_page = Arc::clone(&hits);
    let png: &[u8] = b"\x89PNG\r\n\x1a\nnot really a png but served as one";
    let router = axum::Router::new()
        .route(
            "/page",
            axum::routing::get(move || {
                let hits = Arc::clone(&hits_for_page);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    axum::response::Html(
                        r#"<html><head>
                        <title>Fallback</title>
                        <meta property="og:title" content="A &amp; B"/>
                        <meta property="og:description" content="described">
                        <meta property="og:image" content="/img.png">
                        </head><body>body text</body></html>"#,
                    )
                }
            }),
        )
        .route(
            "/img.png",
            axum::routing::get(move || async move { ([("content-type", "image/png")], png) }),
        )
        .route(
            "/huge",
            axum::routing::get(|| async { axum::response::Html("x".repeat(3 * 1024 * 1024)) }),
        )
        .route(
            "/htmlimg",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<head><meta property="og:title" content="H"/>
                    <meta property="og:image" content="/page"></head>"#,
                )
            }),
        )
        .route(
            "/noimg",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<head><meta property="og:title" content="T"/>
                    <meta property="og:image" content="/missing.png"></head>"#,
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (address, hits)
}

const LOOPBACK: &str = "\"127.0.0.0/8\"";

#[tokio::test]
async fn preview_extracts_open_graph_and_rehosts_the_image() {
    let (fixture, _) = fixture().await;
    let harness = Harness::new(LOOPBACK);
    let token = harness.register().await;

    let (status, og) = harness
        .preview(&token, &format!("http://{fixture}/page"))
        .await;
    assert_eq!(status, StatusCode::OK, "{og}");
    assert_eq!(og["og:title"], json!("A & B"));
    assert_eq!(og["og:description"], json!("described"));

    // The image URL is ours, not theirs: handing back the original would
    // leak every reader's IP to the previewed site.
    let mxc = og["og:image"].as_str().expect("an image was rehosted");
    assert!(mxc.starts_with("mxc://example.org/"), "{mxc}");
    assert!(og["matrix:image:size"].as_u64().unwrap() > 0);

    // And the mxc URI actually serves.
    let media_id = mxc.rsplit('/').next().unwrap();
    let (status, _) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/download/example.org/{media_id}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn private_addresses_are_refused_before_any_connection() {
    let (fixture, hits) = fixture().await;
    // Production default: no allow-list.
    let harness = Harness::new("");
    let token = harness.register().await;

    // The fixture is alive and reachable — and must not be reached.
    let (status, body) = harness
        .preview(&token, &format!("http://{fixture}/page"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no connection was made");

    // The classic: the cloud metadata service, as a literal.
    let (status, _) = harness
        .preview(&token, "http://169.254.169.254/latest/meta-data/")
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A hostname that resolves to loopback is the same refusal one layer
    // down (the resolver), surfacing as an unfetchable page.
    let (status, _) = harness
        .preview(&token, &format!("http://localhost:{}/page", fixture.port()))
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the resolver refused it");

    // And non-HTTP schemes never get anywhere.
    let (status, _) = harness.preview(&token, "file:///etc/passwd").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_redirect_cannot_smuggle_the_fetch_into_a_private_address() {
    // The redirect's *target* is alive on 127.0.0.2 and counting hits —
    // that is what proves refusal, since an unreachable target would fail
    // with the same 502 whether or not the guard exists.
    let target_hits = Arc::new(AtomicUsize::new(0));
    let hits_in_route = Arc::clone(&target_hits);
    let target_router = axum::Router::new().route(
        "/page",
        axum::routing::get(move || {
            let hits = Arc::clone(&hits_in_route);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                axum::response::Html("<meta property=\"og:title\" content=\"secret\">")
            }
        }),
    );
    let target = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(target, target_router).await.unwrap();
    });

    let hop_router = axum::Router::new().route(
        "/hop",
        axum::routing::get(move || async move {
            axum::response::Redirect::temporary(&format!("http://{target_address}/page"))
        }),
    );
    let hop = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop_address = hop.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(hop, hop_router).await.unwrap();
    });

    // Only the first hop's address is allow-listed; where it redirects is
    // not, reachable or no.
    let harness = Harness::new("\"127.0.0.1\"");
    let token = harness.register().await;
    let (status, body) = harness
        .preview(&token, &format!("http://{hop_address}/hop"))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(
        target_hits.load(Ordering::SeqCst),
        0,
        "the redirect target was never contacted"
    );
}

#[tokio::test]
async fn an_image_that_cannot_be_rehosted_is_stripped_not_leaked() {
    let (fixture, _) = fixture().await;
    let harness = Harness::new(LOOPBACK);
    let token = harness.register().await;
    let (status, og) = harness
        .preview(&token, &format!("http://{fixture}/noimg"))
        .await;
    assert_eq!(status, StatusCode::OK, "{og}");
    assert_eq!(og["og:title"], json!("T"));
    // The original URL must not come back: a client rendering it would
    // leak every reader's IP to the previewed site.
    assert!(og.get("og:image").is_none(), "{og}");

    // Same for an og:image that serves HTML rather than an image: the
    // rehost is refused (media inline-safety is the second line, this is
    // the first), and the pointer is stripped rather than passed through.
    let (status, og) = harness
        .preview(&token, &format!("http://{fixture}/htmlimg"))
        .await;
    assert_eq!(status, StatusCode::OK, "{og}");
    assert!(og.get("og:image").is_none(), "{og}");
}

#[tokio::test]
async fn oversized_pages_are_refused_not_buffered() {
    let (fixture, _) = fixture().await;
    let harness = Harness::new(LOOPBACK);
    let token = harness.register().await;
    let (status, body) = harness
        .preview(&token, &format!("http://{fixture}/huge"))
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
}

#[tokio::test]
async fn previews_are_cached_for_a_while() {
    let (fixture, hits) = fixture().await;
    let harness = Harness::new(LOOPBACK);
    let token = harness.register().await;
    let url = format!("http://{fixture}/page");

    let (status, first) = harness.preview(&token, &url).await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = harness.preview(&token, &url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, second);
    // One fetch of the page: the second preview came from the cache. (The
    // image fetch also hit the fixture, but on a different route.)
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the cache absorbed the repeat"
    );
}
