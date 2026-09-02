//! Media across servers — two real Spindle instances over TCP.
//!
//! An upload lives on one server; a user of another sees it by `mxc://`
//! URI. The download walks authenticated federation media (MSC3916,
//! multipart/mixed), lands in the local cache, and everything after —
//! repeat downloads, thumbnails — is served from local storage.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

/// One full homeserver on a real TCP listener, named by its own address.
struct Instance {
    _dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\nretry_base_ms = 50\n",
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
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
