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
    store: Arc<FjallStore>,
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
        let app = spindle_server::app(config, Arc::clone(&store))
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
            store,
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

    /// Make `localpart` a server admin, as the CLI does offline.
    fn promote(&self, localpart: &str) {
        assert!(
            spindle_server::accounts::Accounts::new(self.store.as_ref(), &self.name)
                .set_admin(localpart, true)
                .unwrap()
        );
    }

    async fn admin_post(&self, token: &str, path: &str) -> (u16, Value) {
        let response = self
            .client
            .post(format!("http://{}{path}", self.name))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Value::Null);
        (status, body)
    }

    /// The status of every route that serves `server`/`media_id` to a
    /// client, authenticated and legacy, download and thumbnail.
    async fn client_statuses(&self, token: &str, server: &str, media_id: &str) -> Vec<u16> {
        let paths = [
            format!("/_matrix/client/v1/media/download/{server}/{media_id}"),
            format!("/_matrix/client/v1/media/download/{server}/{media_id}/n.png"),
            format!("/_matrix/client/v1/media/thumbnail/{server}/{media_id}?width=32&height=32"),
            format!("/_matrix/media/v3/download/{server}/{media_id}"),
            format!("/_matrix/media/v3/download/{server}/{media_id}/n.png"),
            format!("/_matrix/media/v3/thumbnail/{server}/{media_id}?width=32&height=32"),
        ];
        let mut out = Vec::new();
        for path in paths {
            let response = self
                .client
                .get(format!("http://{}{path}", self.name))
                .header("authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
            out.push(response.status().as_u16());
        }
        out
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

/// A quarantined item is a 404 on every route that serves it, including to
/// a peer over federation, and quarantining a remote item stops it being
/// fetched again.
#[tokio::test]
async fn quarantined_media_is_served_nowhere_and_never_refetched() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let root = origin.register("root").await;
    origin.promote("root");
    let bob = mirror.register("bob").await;
    let media_id = origin
        .upload(&alice, "image/png", "photo.png", &small_png())
        .await;
    assert_eq!(
        origin
            .client_statuses(&alice, &origin.name, &media_id)
            .await,
        [200; 6]
    );

    let (status, body) = origin
        .admin_post(
            &root,
            &format!(
                "/_synapse/admin/v1/media/quarantine/{}/{media_id}",
                origin.name
            ),
        )
        .await;
    assert_eq!((status, &body), (200, &json!({})));
    assert_eq!(
        origin
            .client_statuses(&alice, &origin.name, &media_id)
            .await,
        [404; 6],
        "the origin's own client routes"
    );
    // The peer asks over federation: the origin must not send it.
    let (status, _, _) = mirror.download(&bob, &origin.name, &media_id).await;
    assert_eq!(status, 404, "not sent again over federation");

    // Released, it is served again; then cached by the mirror.
    origin
        .admin_post(
            &root,
            &format!(
                "/_synapse/admin/v1/media/unquarantine/{}/{media_id}",
                origin.name
            ),
        )
        .await;
    let (status, _, _) = mirror.download(&bob, &origin.name, &media_id).await;
    assert_eq!(status, 200);

    // The mirror's admin quarantines its cached copy of the remote item.
    mirror.promote("bob");
    let (status, body) = mirror
        .admin_post(
            &bob,
            &format!(
                "/_synapse/admin/v1/media/quarantine/{}/{media_id}",
                origin.name
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        mirror.client_statuses(&bob, &origin.name, &media_id).await,
        [404; 6]
    );

    // An item never cached can be quarantined too, and is not fetched.
    let other = origin
        .upload(&alice, "image/png", "other.png", &small_png())
        .await;
    mirror
        .admin_post(
            &bob,
            &format!(
                "/_synapse/admin/v1/media/quarantine/{}/{other}",
                origin.name
            ),
        )
        .await;
    let before = origin.requests.load(Ordering::SeqCst);
    assert_eq!(
        mirror.client_statuses(&bob, &origin.name, &other).await,
        [404; 6]
    );
    assert_eq!(
        origin.requests.load(Ordering::SeqCst),
        before,
        "a quarantined remote item is not fetched"
    );
}

/// The cache purge removes cached remote media older than `before_ts` and
/// nothing else: not newer cache entries, not local uploads, and not a
/// quarantined item.
#[tokio::test]
async fn purging_the_cache_removes_only_old_remote_media() {
    let origin = Instance::start().await;
    let mirror = Instance::start().await;
    let alice = origin.register("alice").await;
    let bob = mirror.register("bob").await;
    mirror.promote("bob");
    let remote = origin
        .upload(&alice, "image/png", "photo.png", &small_png())
        .await;
    let held = origin
        .upload(&alice, "image/png", "held.png", &small_png())
        .await;
    let local = mirror
        .upload(&bob, "image/png", "mine.png", &small_png())
        .await;
    for id in [&remote, &held] {
        assert_eq!(mirror.download(&bob, &origin.name, id).await.0, 200);
    }
    mirror
        .admin_post(
            &bob,
            &format!("/_synapse/admin/v1/media/quarantine/{}/{held}", origin.name),
        )
        .await;

    let (status, body) = mirror
        .admin_post(&bob, "/_synapse/admin/v1/purge_media_cache")
        .await;
    assert_eq!(status, 400, "before_ts is required: {body}");
    // Nothing was cached before the epoch.
    let (_, body) = mirror
        .admin_post(&bob, "/_synapse/admin/v1/purge_media_cache?before_ts=1")
        .await;
    assert_eq!(body, json!({ "deleted": 0 }));
    assert_eq!(
        mirror.client_statuses(&bob, &origin.name, &remote).await,
        [200; 6]
    );

    let (_, body) = mirror
        .admin_post(
            &bob,
            "/_spindle/admin/v1/purge_media_cache?before_ts=99999999999999",
        )
        .await;
    assert_eq!(body, json!({ "deleted": 1 }), "only the unquarantined copy");
    // Legacy routes never fetch, so a 404 there means it is gone.
    let (status, _, _) = mirror
        .get(&format!(
            "/_matrix/media/v3/download/{}/{remote}",
            origin.name
        ))
        .await;
    assert_eq!(status, 404);
    assert_eq!(
        mirror.client_statuses(&bob, &mirror.name, &local).await,
        [200; 6],
        "this server's own upload stays"
    );
}
