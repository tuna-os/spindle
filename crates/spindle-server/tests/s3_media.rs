//! Media on an S3 backend, against an in-process S3 workalike.
//!
//! The stub implements exactly what the client speaks — PUT and GET on
//! `/{bucket}/{key}` — and *rejects unsigned requests*, because the thing
//! most worth testing about an S3 client is not the happy path but that
//! every request it makes would survive a real service's authentication.
//! (Signature correctness itself is pinned against an independent
//! implementation in the signer's unit tests; the stub checks the header's
//! shape and the signed-headers contract.)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// PUTs observed per key — dedup is observable as "one PUT for two uploads".
type PutLog = Arc<Mutex<HashMap<String, usize>>>;

struct Stub {
    address: SocketAddr,
    puts: PutLog,
    gets: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
}

async fn s3_stub() -> Stub {
    let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
    let puts: PutLog = Arc::default();
    let gets = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));

    let router = {
        let objects = Arc::clone(&objects);
        let puts = Arc::clone(&puts);
        let gets = Arc::clone(&gets);
        let rejected = Arc::clone(&rejected);
        axum::Router::new().route(
            "/{bucket}/{*key}",
            axum::routing::any(
                move |method: axum::http::Method,
                      axum::extract::Path((_bucket, key)): axum::extract::Path<(
                    String,
                    String,
                )>,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Bytes| {
                    let objects = Arc::clone(&objects);
                    let puts = Arc::clone(&puts);
                    let gets = Arc::clone(&gets);
                    let rejected = Arc::clone(&rejected);
                    async move {
                        // What a real service enforces before anything else.
                        let authorization = headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default();
                        // The declared payload hash must be the payload's
                        // actual hash — that binding is the one that stops a
                        // signed request being replayed with different bytes,
                        // and real S3 enforces it.
                        let declared_hash = headers
                            .get("x-amz-content-sha256")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default();
                        let actual_hash: String = {
                            use sha2::Digest;
                            use std::fmt::Write;
                            sha2::Sha256::digest(&body).iter().fold(
                                String::new(),
                                |mut out, byte| {
                                    let _ = write!(out, "{byte:02x}");
                                    out
                                },
                            )
                        };
                        let well_formed = authorization.starts_with("AWS4-HMAC-SHA256 Credential=")
                            && authorization
                                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
                            && authorization.contains(", Signature=")
                            && headers.contains_key("x-amz-date")
                            && declared_hash == actual_hash;
                        if !well_formed {
                            rejected.fetch_add(1, Ordering::SeqCst);
                            return (StatusCode::FORBIDDEN, Vec::new());
                        }
                        match method.as_str() {
                            "PUT" => {
                                *puts.lock().unwrap().entry(key.clone()).or_insert(0) += 1;
                                objects.lock().unwrap().insert(key, body.to_vec());
                                (StatusCode::OK, Vec::new())
                            }
                            "GET" => {
                                gets.fetch_add(1, Ordering::SeqCst);
                                match objects.lock().unwrap().get(&key) {
                                    Some(bytes) => (StatusCode::OK, bytes.clone()),
                                    None => (StatusCode::NOT_FOUND, Vec::new()),
                                }
                            }
                            _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
                        }
                    }
                },
            ),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Stub {
        address,
        puts,
        gets,
        rejected,
    }
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new(s3: SocketAddr) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [storage.s3]\nendpoint = \"http://{s3}\"\nbucket = \"blobs\"\n\
             access_key_id = \"test-access\"\nsecret_access_key = \"test-secret\"\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { _dir: dir, app }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, bytes.to_vec())
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
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn upload(&self, token: &str, bytes: &[u8], content_type: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/media/v3/upload")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", content_type)
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await;
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::OK, "{body}");
        body["content_uri"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned()
    }
}

/// A tiny but real PNG (1x1), so the thumbnailer has something to decode.
fn one_pixel_png() -> Vec<u8> {
    let mut bytes = Vec::new();
    image::DynamicImage::new_rgb8(1, 1)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
    bytes
}

#[tokio::test]
async fn media_round_trips_through_the_bucket() {
    let stub = s3_stub().await;
    let harness = Harness::new(stub.address);
    let token = harness.register().await;

    let payload = b"media bytes on s3";
    let media_id = harness.upload(&token, payload, "text/plain").await;

    let (status, served) = harness
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
    assert_eq!(served, payload);

    // A second, different upload must not disturb the first — this is what
    // catches a backend that keys objects by anything less than the full
    // content hash.
    let other = harness
        .upload(&token, b"entirely different bytes", "text/plain")
        .await;
    let (_, served_other) = harness
        .call(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/download/example.org/{other}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(served_other, b"entirely different bytes");
    let (_, first_again) = harness
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
    assert_eq!(first_again, payload, "the first upload is undisturbed");

    // Every request the stub saw was signed; none were turned away.
    assert_eq!(stub.rejected.load(Ordering::SeqCst), 0);
    assert!(stub.gets.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn identical_uploads_share_one_object() {
    let stub = s3_stub().await;
    let harness = Harness::new(stub.address);
    let token = harness.register().await;

    let payload = b"the very same bytes";
    let first = harness.upload(&token, payload, "text/plain").await;
    let second = harness.upload(&token, payload, "text/plain").await;
    assert_ne!(first, second, "distinct media IDs");

    // One object in the bucket: content addressing survives the backend
    // swap. (The client re-PUTs the same key — S3 has no cheap existence
    // probe worth a round trip — but it lands on the same object.)
    assert_eq!(
        stub.puts.lock().unwrap().len(),
        1,
        "one key for one content"
    );
}

#[tokio::test]
async fn thumbnails_cache_in_the_bucket_too() {
    let stub = s3_stub().await;
    let harness = Harness::new(stub.address);
    let token = harness.register().await;
    let media_id = harness.upload(&token, &one_pixel_png(), "image/png").await;

    let thumbnail = |token: String| {
        let uri = format!(
            "/_matrix/client/v1/media/thumbnail/example.org/{media_id}?width=32&height=32&method=scale"
        );
        Request::builder()
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };

    let (status, first) = harness.call(thumbnail(token.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let puts_after_first = stub.puts.lock().unwrap().len();
    assert_eq!(puts_after_first, 2, "the source and its cached thumbnail");

    let (status, second) = harness.call(thumbnail(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, second);
    // No third object: the second request read the cached thumbnail.
    assert_eq!(stub.puts.lock().unwrap().len(), 2);
}
