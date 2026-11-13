//! Built-in OIDC dynamic registration takes no credential, so it is bounded
//! by shape and by rate instead (#833).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView};
use tempfile::TempDir;
use tower::ServiceExt;

struct Server {
    app: axum::Router,
    store: Arc<FjallStore>,
    _dir: TempDir,
}

fn server() -> Server {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[auth]\nbuiltin_oidc = true\n",
    )
    .unwrap();
    let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
    Server {
        app,
        store,
        _dir: dir,
    }
}

impl Server {
    async fn register(&self, body: String) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri("/oauth2/registration")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let peer: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        self.app.clone().oneshot(request).await.unwrap().status()
    }

    async fn uris(&self, uris: Value) -> StatusCode {
        self.register(json!({ "redirect_uris": uris }).to_string())
            .await
    }

    fn stored(&self) -> usize {
        let prefix = keys::oidc_client("");
        ReadView::scan_prefix(self.store.as_ref(), &prefix)
            .unwrap()
            .len()
    }
}

#[tokio::test]
async fn hostile_redirects_are_refused_and_honest_ones_stored() {
    let server = server();
    for bad in [
        "javascript:alert(1)",
        "data:text/html,x",
        "http://evil.example/cb",
        "ftp://evil.example/cb",
        "/relative",
        "https://a.example/with space",
    ] {
        assert_eq!(
            server.uris(json!([bad])).await,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(server.stored(), 0, "a refused registration wrote a row");
    for good in [
        "https://element.example/callback",
        "http://localhost:8080/cb",
        "http://127.0.0.1:8080/cb",
        "io.element.android:/",
    ] {
        assert_eq!(
            server.uris(json!([good])).await,
            StatusCode::CREATED,
            "{good}"
        );
    }
    assert_eq!(server.stored(), 4);
}

#[tokio::test]
async fn oversized_registrations_are_refused() {
    let server = server();
    let many: Vec<String> = (0..9).map(|n| format!("https://a.example/{n}")).collect();
    assert_eq!(server.uris(json!(many)).await, StatusCode::BAD_REQUEST);
    let long = format!("https://a.example/{}", "x".repeat(3000));
    assert_eq!(server.uris(json!([long])).await, StatusCode::BAD_REQUEST);
    let name = "n".repeat(300);
    assert_eq!(
        server
            .register(
                json!({ "redirect_uris": ["https://a.example/cb"], "client_name": name })
                    .to_string()
            )
            .await,
        StatusCode::BAD_REQUEST
    );
    let huge = json!({
        "redirect_uris": ["https://a.example/cb"],
        "client_uri": "x".repeat(64 * 1024),
    })
    .to_string();
    assert_eq!(server.register(huge).await, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(server.stored(), 0);
}

#[tokio::test]
async fn one_source_cannot_register_without_end() {
    let server = server();
    // `OIDC_REGISTER_PER_SOURCE` allows this many an hour.
    for _ in 0..20 {
        assert_eq!(
            server.uris(json!(["https://a.example/cb"])).await,
            StatusCode::CREATED
        );
    }
    assert_eq!(
        server.uris(json!(["https://a.example/cb"])).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(server.stored(), 20, "the refused call wrote a row");
}
