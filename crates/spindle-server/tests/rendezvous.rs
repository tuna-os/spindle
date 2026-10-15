//! MSC4108's mailbox used by QR login through MAS.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::Value;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\npublic_base_url = \"https://matrix.example.org\"\n[ratelimit]\nenabled = false\n",
        ).unwrap();
        Self {
            _dir: dir,
            app: spindle_server::app(config, store).unwrap(),
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap()
            .to_vec();
        (status, headers, bytes)
    }

    async fn create(&self, body: &str) -> (String, HeaderMap) {
        let (status, headers, bytes) = self
            .request(
                "POST",
                spindle_server::rendezvous::CREATE_PATH,
                body,
                &[("content-type", "text/plain")],
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let url = value["url"].as_str().unwrap();
        let path = url
            .strip_prefix("https://matrix.example.org")
            .expect("public URL")
            .to_owned();
        (path, headers)
    }
}

fn metadata(headers: &HeaderMap) {
    for name in ["etag", "expires", "last-modified", "cache-control"] {
        assert!(headers.contains_key(name), "missing {name}: {headers:?}");
    }
    assert_eq!(headers["access-control-expose-headers"], "ETag");
}

#[tokio::test]
async fn two_devices_exchange_messages_with_conditional_reads_and_writes() {
    let h = Harness::new();
    let (path, created) = h.create("encrypted-offer").await;
    metadata(&created);
    let old = created["etag"].to_str().unwrap();
    let (status, headers, bytes) = h.request("GET", &path, "", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, b"encrypted-offer");
    metadata(&headers);
    let (status, headers, bytes) = h.request("GET", &path, "", &[("if-none-match", old)]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(bytes.is_empty());
    metadata(&headers);
    let (status, headers, _) = h
        .request(
            "PUT",
            &path,
            "encrypted-answer",
            &[("content-type", "text/plain"), ("if-match", old)],
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    metadata(&headers);
    assert_eq!(
        headers["expires"], created["expires"],
        "writes do not renew a session"
    );
    assert_ne!(headers["etag"], created["etag"]);
    let new_tag = headers["etag"].to_str().unwrap().to_owned();
    let (status, headers, bytes) = h
        .request(
            "PUT",
            &path,
            "stale-answer",
            &[("content-type", "text/plain"), ("if-match", old)],
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(headers["etag"], new_tag);
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["org.matrix.msc4108.errcode"], "M_CONCURRENT_WRITE");
    let (status, _, bytes) = h.request("GET", &path, "", &[("if-none-match", old)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, b"encrypted-answer");
    assert_eq!(
        h.request("DELETE", &path, "", &[]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.request("GET", &path, "", &[]).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        h.request(
            "PUT",
            &path,
            "x",
            &[("content-type", "text/plain"), ("if-match", &new_tag)]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn limits_refuse_bad_messages_and_evict_the_oldest_mailbox() {
    let h = Harness::new();
    let path = spindle_server::rendezvous::CREATE_PATH;
    assert_eq!(
        h.request("POST", path, "{}", &[("content-type", "application/json")])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.request(
            "POST",
            path,
            &"x".repeat(4097),
            &[("content-type", "text/plain")]
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let (first, _) = h.create("first").await;
    assert_eq!(
        h.request("PUT", &first, "new", &[("content-type", "text/plain")])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    for _ in 0..100 {
        h.create("x").await;
    }
    assert_eq!(
        h.request("GET", &first, "", &[]).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn browsers_can_use_the_conditional_headers_and_versions_advertises_it() {
    let h = Harness::new();
    let (path, _) = h.create("offer").await;
    let (status, headers, _) = h
        .request(
            "OPTIONS",
            &path,
            "",
            &[
                ("origin", "https://app.element.io"),
                ("access-control-request-method", "PUT"),
                ("access-control-request-headers", "if-match,content-type"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let allowed = headers["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allowed.contains("if-match") && allowed.contains("if-none-match"));
    let (status, _, bytes) = h.request("GET", "/_matrix/client/versions", "", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let versions: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(versions["unstable_features"]["org.matrix.msc4108"], true);
}
