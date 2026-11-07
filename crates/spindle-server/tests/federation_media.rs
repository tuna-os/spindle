//! Media across servers — two real Spindle instances over TCP.
//!
//! An upload lives on one server; a user of another sees it by `mxc://`
//! URI. The download walks authenticated federation media (MSC3916,
//! multipart/mixed), lands in the local cache, and everything after —
//! repeat downloads, thumbnails — is served from local storage.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One full homeserver on a real TCP listener, named by its own address,
/// counting every request it is sent.
struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
    requests: Arc<AtomicUsize>,
}

impl Instance {
    async fn start() -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        // The storage path too, not only the store: uploads and fetched
        // remote media land under `<storage.path>/media`, and the default
        // `./data` is the crate's source tree.
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[storage]\npath = \"{}\"\n\
             [ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
            dir.path().display(),
        ))
        .unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let app = spindle_server::app(config, store)
            .expect("the app builds")
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    next.run(request)
                },
            ));
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Instance {
            _dir: dir,
            name,
            client: reqwest::Client::new(),
            requests,
        }
    }

    async fn register(&self, username: &str) -> String {
        let response = self
            .client
            .post(format!("http://{}/_matrix/client/v3/register", self.name))
            .header("content-type", "application/json")
            .body(
                json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn upload(&self, token: &str, content_type: &str, name: &str, bytes: &[u8]) -> String {
        let response = self
            .client
            .post(format!(
                "http://{}/_matrix/media/v3/upload?filename={name}",
                self.name
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", content_type)
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let mxc = body["content_uri"].as_str().unwrap();
        mxc.rsplit('/').next().unwrap().to_owned()
    }

    async fn download(&self, token: &str, server: &str, media_id: &str) -> (u16, String, Vec<u8>) {
        let response = self
            .client
            .get(format!(
                "http://{}/_matrix/client/v1/media/download/{server}/{media_id}",
                self.name
            ))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let bytes = response.bytes().await.unwrap().to_vec();
        (status, content_type, bytes)
    }

    /// An unauthenticated `GET` of `path`: status, the body parsed (or
    /// `Value::Null` when it is not JSON), and the raw bytes.
    async fn get(&self, path: &str) -> (u16, Value, Vec<u8>) {
        let response = self
            .client
            .get(format!("http://{}{path}", self.name))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap().to_vec();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body, bytes)
    }
}

fn small_png() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut image = image::RgbImage::new(8, 8);
    for pixel in image.pixels_mut() {
        *pixel = image::Rgb([0, 128, 255]);
    }
    image::DynamicImage::ImageRgb8(image)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
    bytes
}

#[tokio::test]
async fn remote_media_downloads_bit_for_bit_and_then_serves_from_cache() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;

    let payload = b"\x89PNG\r\n\x1a\n the exact bytes matter, all of them \x00\xff\r\n--tricky";
    let media_id = origin
        .upload(&alice, "image/png", "proof.png", payload)
        .await;

    // Bob's server has never seen this file; the download walks MSC3916
    // federation media and must return the exact bytes — the payload even
    // carries CRLF-dashes to catch a careless multipart parser.
    let (status, content_type, bytes) = mirror.download(&bob, &origin.name, &media_id).await;
    assert_eq!(status, 200);
    assert_eq!(content_type, "image/png");
    assert_eq!(bytes, payload, "bit-for-bit across the wire");

    // Again: served from the local cache, identically.
    let (status, _, bytes) = mirror.download(&bob, &origin.name, &media_id).await;
    assert_eq!(status, 200);
    assert_eq!(bytes, payload);
}

#[tokio::test]
async fn a_remote_image_thumbnails_locally_after_the_fetch() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;

    let media_id = origin
        .upload(&alice, "image/png", "photo.png", &small_png())
        .await;

    let response = mirror
        .client
        .get(format!(
            "http://{}/_matrix/client/v1/media/thumbnail/{}/{media_id}?width=32&height=32",
            mirror.name, origin.name
        ))
        .header("authorization", format!("Bearer {bob}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200, "a thumbnail comes back");
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.starts_with("image/"),
        "an image came back: {content_type}"
    );
    let bytes = response.bytes().await.unwrap();
    assert!(
        image::load_from_memory(&bytes).is_ok(),
        "and it decodes as one"
    );
}

#[tokio::test]
async fn media_nobody_has_stays_a_404_not_a_fabrication() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let bob = mirror.register("bob").await;

    let (status, _, _) = mirror
        .download(&bob, &origin.name, "0123456789abcdef")
        .await;
    assert_eq!(status, 404, "an unknown remote file is a clean 404");

    // A server that answers nothing at all is also a 404 here, not a hang
    // or a fabricated empty file.
    let (status, _, _) = mirror.download(&bob, "127.0.0.1:9", "whatever").await;
    assert_eq!(status, 404);
}

/// The frozen unauthenticated routes never fetch: remote media this server
/// has not cached is a plain 404 that names no peer, and the peer is not
/// asked. Once an authenticated download has cached it, they serve it.
#[tokio::test]
async fn the_legacy_routes_serve_cached_remote_media_and_never_fetch_it() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;
    let media_id = origin
        .upload(&alice, "image/png", "photo.png", &small_png())
        .await;
    let legacy = [
        format!("/_matrix/media/v3/download/{}/{media_id}", origin.name),
        format!(
            "/_matrix/media/v3/download/{}/{media_id}/photo.png",
            origin.name
        ),
        format!(
            "/_matrix/media/v3/thumbnail/{}/{media_id}?width=32&height=32",
            origin.name
        ),
    ];

    let before = origin.requests.load(Ordering::SeqCst);
    for path in &legacy {
        let (status, body, _) = mirror.get(path).await;
        assert_eq!(status, 404, "{path}: {body}");
        assert_eq!(body["errcode"], "M_NOT_FOUND", "{path}: {body}");
        assert!(
            !body["error"].as_str().unwrap().contains(&origin.name),
            "the answer names no peer: {body}"
        );
    }
    assert_eq!(
        origin.requests.load(Ordering::SeqCst),
        before,
        "an unauthenticated request made no federation request"
    );

    // A peer that is not there gets the same plain answer: no fetch is
    // tried, so there is no federation error to repeat.
    let (status, body, _) = mirror
        .get("/_matrix/media/v3/download/127.0.0.1:9/whatever")
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
    assert!(
        !body["error"].as_str().unwrap().contains("127.0.0.1:9"),
        "{body}"
    );

    // An authenticated download fetches the file and caches it...
    let (status, _, bytes) = mirror.download(&bob, &origin.name, &media_id).await;
    assert_eq!(status, 200);
    assert_eq!(bytes, small_png());
    let after_fetch = origin.requests.load(Ordering::SeqCst);
    assert!(after_fetch > before, "the authenticated route fetched");

    // ...and from then on the legacy routes serve it, from the cache.
    for path in &legacy[..2] {
        let (status, _, bytes) = mirror.get(path).await;
        assert_eq!(status, 200, "{path}");
        assert_eq!(bytes, small_png(), "{path}");
    }
    let (status, _, bytes) = mirror.get(&legacy[2]).await;
    assert_eq!(status, 200);
    image::load_from_memory(&bytes).expect("a decodable thumbnail");
    assert_eq!(
        origin.requests.load(Ordering::SeqCst),
        after_fetch,
        "the legacy routes served the cached copy"
    );
}
