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
        Self::with_ratelimit(allow_private, "enabled = false")
    }

    /// As [`Self::new`], with `ratelimit` as the body of `[ratelimit]`.
    fn with_ratelimit(allow_private: &str, ratelimit: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        // The storage path too, not only the store: a preview's image is
        // stored under `<storage.path>/media`, and the default `./data` is
        // the crate's source tree.
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n\
             [ratelimit]\n{ratelimit}\n\
             [previews]\nallow_private = [{allow_private}]\n",
            dir.path().display(),
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
                            "auth": { "type": "m.login.dummy", "session": "register" },
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
    let hits_for_pages = Arc::clone(&hits);
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
            "/p/{n}",
            axum::routing::get(move |axum::extract::Path(n): axum::extract::Path<u8>| {
                let hits = Arc::clone(&hits_for_pages);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    axum::response::Html(format!(
                        r#"<head><meta property="og:title" content="P{n}"/>
                    <meta property="og:image" content="/i/{n}"></head>"#
                    ))
                }
            }),
        )
        .route(
            "/i/{n}",
            axum::routing::get(
                |axum::extract::Path(n): axum::extract::Path<u8>| async move {
                    // 3000 bytes that differ per page, so each is its own blob.
                    ([("content-type", "image/png")], vec![n; 3000])
                },
            ),
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

#[tokio::test]
async fn a_bad_allow_list_entry_refuses_to_start() {
    // The federation list has this test already; the previews list is
    // parsed by the same guard and must fail the same way: a typo'd range
    // is a startup error, never a list that silently opens less (or more)
    // than the operator meant.
    for entry in ["127.0.0.0/33", "localhost", "127.0.0.0/8 "] {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[previews]\nallow_private = [\"{entry}\"]\n"
        ))
        .unwrap();
        let error = match spindle_server::app(config, store) {
            Ok(_) => panic!("allow_private = [{entry:?}] built an app"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("preview config"), "{entry:?}: {error}");
        assert!(
            error.contains(entry),
            "{entry:?}: {error} does not name the entry"
        );
    }
}

#[tokio::test]
async fn the_preview_after_the_budget_is_refused_with_a_rate_limit() {
    let (fixture, hits) = fixture().await;
    // A burst of 3 and a refill too slow to matter inside the test.
    let harness = Harness::with_ratelimit(
        LOOPBACK,
        "url_previews = { per_second = 0.0001, burst = 3 }",
    );
    let token = harness.register().await;

    let mut statuses = Vec::new();
    for n in 0..5 {
        let (status, body) = harness
            .preview(&token, &format!("http://{fixture}/p/{n}"))
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED", "{body}");
        }
        statuses.push(status);
    }
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        3,
        "{statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        2,
        "{statuses:?}"
    );
    // The refused ones never reached the network.
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "only allowed previews fetched"
    );
}

/// The cache fixture built directly, so each preview carries the time it
/// is made at and the oldest is not a matter of the wall clock.
struct Cache {
    dir: TempDir,
    store: Arc<FjallStore>,
    media: Arc<spindle_server::media::Media>,
    previews: spindle_server::previews::Previews,
}

impl Cache {
    fn new(cap: u64) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let media = Arc::new(spindle_server::media::Media::new(
            Arc::clone(&store),
            spindle_server::blobs::Blobs::Local {
                root: dir.path().join("media"),
            },
            "example.org",
        ));
        let previews = spindle_server::previews::Previews::new(
            Arc::clone(&store),
            Arc::clone(&media),
            &[LOOPBACK.trim_matches('"').to_owned()],
        )
        .unwrap()
        .with_cache_cap(cap);
        Self {
            dir,
            store,
            media,
            previews,
        }
    }

    /// Every preview row, and the bytes the cache holds for them: the row
    /// plus its image, as the cap counts it.
    fn held(&self) -> (usize, u64) {
        let prefix = vec![
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::UrlPreview as u8,
        ];
        let rows = spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix).unwrap();
        let mut bytes = 0;
        for (_, value) in &rows {
            let row: Value = serde_json::from_slice(value).unwrap();
            bytes += value.len() as u64;
            if let Some(id) = row["og"]["og:image"]
                .as_str()
                .and_then(|mxc| mxc.rsplit('/').next())
            {
                bytes += self.media.record(id).unwrap().map_or(0, |r| r.size as u64);
            }
        }
        (rows.len(), bytes)
    }

    fn blob_files(&self) -> usize {
        fn walk(path: &std::path::Path) -> usize {
            std::fs::read_dir(path).map_or(0, |entries| {
                entries
                    .flatten()
                    .map(|e| {
                        if e.path().is_dir() {
                            walk(&e.path())
                        } else {
                            1
                        }
                    })
                    .sum()
            })
        }
        walk(&self.dir.path().join("media"))
    }
}

#[tokio::test]
async fn the_preview_cache_stays_under_its_cap_and_evicts_the_oldest_first() {
    let (fixture, _) = fixture().await;
    // One preview is about 3,200 bytes: room for two, not three.
    let cache = Cache::new(7_000);

    let mut first_image = None;
    for n in 0..5_u64 {
        let og = cache
            .previews
            .preview(&format!("http://{fixture}/p/{n}"), 1_000 + n)
            .await
            .unwrap();
        if n == 0 {
            first_image = og["og:image"].as_str().map(str::to_owned);
        }
        let (rows, bytes) = cache.held();
        assert!(bytes <= 7_000, "preview {n}: cache holds {bytes} bytes");
        assert_eq!(rows, usize::try_from(n + 1).unwrap().min(2), "preview {n}");
    }

    // The two newest survive, so previewing them again is a cache hit; the
    // oldest went first, and its image went with its row.
    let first_id = first_image.unwrap().rsplit('/').next().unwrap().to_owned();
    assert!(cache.media.record(&first_id).unwrap().is_none());
    assert_eq!(cache.blob_files(), 2, "two images' bytes remain, no more");
    for n in [3_u64, 4] {
        let og = cache
            .previews
            .preview(&format!("http://{fixture}/p/{n}"), 2_000)
            .await
            .unwrap();
        let id = og["og:image"].as_str().unwrap().rsplit('/').next().unwrap();
        assert!(cache.media.record(id).unwrap().is_some(), "{n} survived");
    }
    assert_eq!(cache.held().0, 2);
}

/// The cap never removes a preview whose image is quarantined, even when it
/// is the oldest: the operator holds the image as evidence.
#[tokio::test]
async fn the_preview_cap_never_evicts_a_quarantined_image() {
    let (fixture, _) = fixture().await;
    let cache = Cache::new(7_000);

    let og = cache
        .previews
        .preview(&format!("http://{fixture}/p/0"), 1_000)
        .await
        .unwrap();
    let held_id = og["og:image"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        cache
            .media
            .set_quarantine(&held_id, Some("@admin:example.org"))
            .unwrap()
    );
    for n in 1..5_u64 {
        cache
            .previews
            .preview(&format!("http://{fixture}/p/{n}"), 1_000 + n)
            .await
            .unwrap();
    }

    let record = cache.media.record(&held_id).unwrap();
    assert!(
        record.is_some_and(|record| record.quarantined_by.is_some()),
        "the quarantined image is kept"
    );
    // The oldest preview and the newest remain; the ones between went.
    assert_eq!(cache.held().0, 2);
    assert_eq!(cache.blob_files(), 2);
}

/// A stale preview's old image may have been quarantined since it was made.
/// Replacing the row must not delete evidence: the image and its record stay.
#[tokio::test]
async fn refreshing_a_stale_preview_keeps_a_quarantined_old_image() {
    let (fixture, _) = fixture().await;
    let cache = Cache::new(1_000_000);
    let url = format!("http://{fixture}/p/1");

    let og = cache.previews.preview(&url, 1_000).await.unwrap();
    let old_id = og["og:image"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        cache
            .media
            .set_quarantine(&old_id, Some("@admin:example.org"))
            .unwrap()
    );

    cache.previews.preview(&url, 1_000 + 3_601).await.unwrap();

    let record = cache.media.record(&old_id).unwrap();
    assert!(
        record.is_some_and(|record| record.quarantined_by.is_some()),
        "the quarantined image survived the refresh"
    );
    assert_eq!(
        cache.media.records().unwrap().len(),
        2,
        "the kept evidence and the new image"
    );
    // Blobs are content-addressed and both fetches carry the same bytes, so
    // one file backs both records: it must still be there for the evidence.
    assert_eq!(
        cache.blob_files(),
        1,
        "the evidence bytes are still on disk"
    );
}

/// The cap never removes a preview whose image is protected either.
#[tokio::test]
async fn the_preview_cap_never_evicts_a_protected_image() {
    let (fixture, hits) = fixture().await;
    let cache = Cache::new(7_000);

    let og = cache
        .previews
        .preview(&format!("http://{fixture}/p/0"), 1_000)
        .await
        .unwrap();
    let kept_id = og["og:image"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert!(
        cache
            .media
            .set_protected(&kept_id, Some("@admin:example.org"))
            .unwrap()
    );
    for n in 1..5_u64 {
        cache
            .previews
            .preview(&format!("http://{fixture}/p/{n}"), 1_000 + n)
            .await
            .unwrap();
    }

    assert!(
        cache.media.record(&kept_id).unwrap().is_some(),
        "the protected image is kept"
    );
    // Its preview row is kept too: asked again inside the hour it is served
    // from the cache, with no new fetch of the page or the image.
    let before = hits.load(std::sync::atomic::Ordering::SeqCst);
    cache
        .previews
        .preview(&format!("http://{fixture}/p/0"), 1_010)
        .await
        .unwrap();
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "the protected preview is still cached"
    );
    assert_eq!(
        cache.held().0,
        2,
        "the oldest preview and the newest remain"
    );
}

#[tokio::test]
async fn refreshing_a_stale_preview_does_not_leave_the_old_image_behind() {
    let (fixture, _) = fixture().await;
    let cache = Cache::new(1_000_000);
    let url = format!("http://{fixture}/p/1");

    cache.previews.preview(&url, 1_000).await.unwrap();
    // An hour and a second later the row is stale and is fetched again,
    // and the image is re-hosted under a new ID.
    cache.previews.preview(&url, 1_000 + 3_601).await.unwrap();

    let uploads = cache.media.records().unwrap();
    assert_eq!(uploads.len(), 1, "the first image's record was removed");
    assert_eq!(cache.held().0, 1);
}
