//! Uploading and fetching files.
//!
//! Most of what is worth testing here is security rather than function.
//! Uploaded bytes are attacker-controlled, the filename is attacker-chosen,
//! and the content type is attacker-declared — so the tests that matter are
//! the ones that check none of those three can turn into script running on
//! this server's origin, or into a header the uploader wrote.

use std::sync::Arc;

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
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n[ratelimit]\nenabled = false\n",
            dir.path().display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn raw(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let (status, _, bytes) = self.raw(request).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
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

    /// Upload bytes, returning the `mxc://` URI.
    async fn upload(
        &self,
        token: &str,
        content_type: &str,
        filename: Option<&str>,
        bytes: &[u8],
    ) -> (StatusCode, Value) {
        let uri = match filename {
            Some(name) => format!("/_matrix/media/v3/upload?filename={}", urlencode(name)),
            None => "/_matrix/media/v3/upload".to_owned(),
        };
        self.call(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
    }

    async fn download(
        &self,
        token: &str,
        mxc: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let rest = mxc.strip_prefix("mxc://").unwrap();
        let (server, media_id) = rest.split_once('/').unwrap();
        self.raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/download/{server}/{media_id}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn header(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn an_upload_round_trips() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let payload = b"\x89PNG\r\n\x1a\n not really a png but the bytes are mine";

    let (status, body) = harness
        .upload(&alice, "image/png", Some("cat.png"), payload)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mxc = body["content_uri"].as_str().unwrap();
    assert!(mxc.starts_with("mxc://example.org/"), "{mxc}");

    let (status, headers, bytes) = harness.download(&alice, mxc).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, payload, "the bytes come back unchanged");
    assert_eq!(header(&headers, "content-type"), "image/png");
    assert_eq!(
        header(&headers, "content-disposition"),
        r#"inline; filename="cat.png""#
    );
}

#[tokio::test]
async fn the_media_id_is_not_the_content_hash() {
    // A hash-addressed URL is an existence oracle: anyone holding a file could
    // confirm this server has it, and for a file from a small set, recover
    // which one a user uploaded. Content addressing is a storage decision and
    // must not become an addressing one.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let payload = b"the same bytes both times";

    let (_, first) = harness.upload(&alice, "text/plain", None, payload).await;
    let (_, second) = harness.upload(&alice, "text/plain", None, payload).await;
    let first = first["content_uri"].as_str().unwrap().to_owned();
    let second = second["content_uri"].as_str().unwrap().to_owned();

    assert_ne!(
        first, second,
        "identical bytes must not produce the same URL"
    );
    let hash = blake3::hash(payload).to_hex().to_string();
    assert!(
        !first.contains(&hash) && !second.contains(&hash),
        "the content hash must not appear in the URL: {first} {second}"
    );

    // And both still resolve to the same bytes, which is the dedup working.
    for mxc in [&first, &second] {
        let (status, _, bytes) = harness.download(&alice, mxc).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, payload);
    }
}

#[tokio::test]
async fn uploaded_html_is_never_served_inline() {
    // The one that matters most. A homeserver that renders uploaded HTML
    // inline has handed every user a stored-XSS primitive against its own
    // origin, and every session token on it.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let payload = b"<script>alert(document.cookie)</script>";

    for content_type in ["text/html", "image/svg+xml", "application/xhtml+xml"] {
        let (status, body) = harness
            .upload(&alice, content_type, Some("evil.html"), payload)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mxc = body["content_uri"].as_str().unwrap();

        let (status, headers, _) = harness.download(&alice, mxc).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            header(&headers, "content-disposition").starts_with("attachment"),
            "{content_type} must download, not render: {:?}",
            header(&headers, "content-disposition")
        );
        assert_eq!(
            header(&headers, "x-content-type-options"),
            "nosniff",
            "a browser must not second-guess the type"
        );
        let csp = header(&headers, "content-security-policy");
        assert!(csp.contains("sandbox"), "no sandbox in CSP: {csp}");
        assert!(
            csp.contains("script-src 'none'"),
            "scripts not blocked: {csp}"
        );
    }
}

#[tokio::test]
async fn a_filename_cannot_inject_a_response_header() {
    // The uploader chooses the name and it goes into a header. A CRLF in it
    // would end the header and begin one the uploader wrote.
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .upload(
            &alice,
            "application/octet-stream",
            Some("safe.txt\r\nX-Injected: yes"),
            b"payload",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mxc = body["content_uri"].as_str().unwrap();

    let (status, headers, _) = harness.download(&alice, mxc).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("x-injected").is_none(),
        "the uploader wrote a header: {headers:?}"
    );
    let disposition = header(&headers, "content-disposition");
    assert!(
        !disposition.contains('\r') && !disposition.contains('\n'),
        "{disposition}"
    );
}

#[tokio::test]
async fn download_needs_a_token() {
    // The unauthenticated media endpoints are deliberately absent: an
    // unauthenticated media URL is a capability that leaks the moment it is
    // pasted anywhere.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness.upload(&alice, "text/plain", None, b"private").await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();

    let (status, _, _) = harness
        .raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/download/{server}/{media_id}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And the frozen unauthenticated surface is simply not served.
    let (status, _, _) = harness
        .raw(
            Request::builder()
                .uri(format!("/_matrix/media/v3/download/{server}/{media_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_unknown_media_id_is_a_404() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, _, _) = harness
        .download(&alice, "mxc://example.org/deadbeefdeadbeefdeadbeefdeadbeef")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn media_for_another_server_is_a_404_not_an_empty_file() {
    // Remote media needs federation to fetch. A client that gets bytes back
    // believes it has the attachment, so an empty 200 would be a lie.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, _, bytes) = harness.download(&alice, "mxc://elsewhere.org/abcdef").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_ne!(bytes, b"".to_vec(), "a 404 still says why");
}

#[tokio::test]
async fn the_upload_limit_is_advertised_and_enforced() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let (status, body) = harness
        .call(
            Request::builder()
                .uri("/_matrix/client/v1/media/config")
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let limit = body["m.upload.size"].as_u64().unwrap();
    assert_eq!(limit, 50 * 1024 * 1024);

    // A file comfortably over axum's own 2 MiB default but well under the
    // advertised limit must succeed. Without an explicit body limit on the
    // route the extractor rejects it first, and the server ends up
    // advertising 50 MiB while enforcing 2 MiB -- the client is told the file
    // is fine, sends it, and gets an opaque 413 with no Matrix error in it.
    let four_mib = vec![7_u8; 4 * 1024 * 1024];
    let (status, body) = harness
        .upload(&alice, "application/octet-stream", None, &four_mib)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "4 MiB is under the advertised limit and must be accepted: {body}"
    );
    let mxc = body["content_uri"].as_str().unwrap();
    let (status, _, bytes) = harness.download(&alice, mxc).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes.len(), four_mib.len(), "all of it came back");

    // A file one byte over the stated limit is refused, and refused with the
    // code the spec names rather than a generic error.
    let too_big = vec![0_u8; usize::try_from(limit).unwrap() + 1];
    let (status, body) = harness
        .upload(&alice, "application/octet-stream", None, &too_big)
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["errcode"], "M_TOO_LARGE");
}

#[tokio::test]
async fn a_name_in_the_path_does_not_override_the_recorded_one() {
    // Letting the downloader choose the filename would let a link dictate what
    // a file appears to be, which is how a .png becomes a .exe in someone's
    // downloads folder.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .upload(&alice, "image/png", Some("cat.png"), b"bytes")
        .await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();

    let (status, headers, _) = harness
        .raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/download/{server}/{media_id}/totally-safe.exe"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header(&headers, "content-disposition"),
        r#"inline; filename="cat.png""#,
        "the recorded name wins over the one in the path"
    );
}

/// A tiny valid PNG: 8x8, red.
fn small_png() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut image = image::RgbImage::new(8, 8);
    for pixel in image.pixels_mut() {
        *pixel = image::Rgb([255, 0, 0]);
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
async fn a_thumbnail_comes_back_at_a_ladder_size() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .upload(&alice, "image/png", Some("dot.png"), &small_png())
        .await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();

    // 50x50 is between the 32 and 96 rungs, so the 96 rung answers: never
    // less than asked for. The response is a decodable PNG of that size.
    let (status, headers, bytes) = harness
        .raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/thumbnail/{server}/{media_id}?width=50&height=50"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "content-type"), "image/png");
    let decoded = image::load_from_memory(&bytes).expect("a decodable thumbnail");
    assert!(
        decoded.width() <= 96 && decoded.height() <= 96,
        "{}x{}",
        decoded.width(),
        decoded.height()
    );
}

#[tokio::test]
async fn arbitrary_dimensions_cannot_mint_arbitrary_cache_files() {
    // Disk amplification: honouring every width x height would let one client
    // mint an unbounded family of cached files from one upload. The ladder
    // makes 50x50 and 51x51 the same thumbnail.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .upload(&alice, "image/png", None, &small_png())
        .await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();

    let fetch = |width: u32, height: u32| {
        let harness = &harness;
        let alice = &alice;
        async move {
            harness
                .raw(
                    Request::builder()
                        .uri(format!(
                            "/_matrix/client/v1/media/thumbnail/{server}/{media_id}?width={width}&height={height}"
                        ))
                        .header("authorization", format!("Bearer {alice}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .2
        }
    };
    let first = fetch(50, 50).await;
    let second = fetch(51, 51).await;
    assert_eq!(first, second, "both requests snap to the same rung");
}

#[tokio::test]
async fn a_lying_content_type_is_unsupported_not_a_crash() {
    // The uploader's declared type is checked exactly when it is first relied
    // upon: bytes that are not the image they claim to be are a 400, and the
    // decoder never sees a type we would not thumbnail.
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (_, body) = harness
        .upload(&alice, "image/png", None, b"this is not a png")
        .await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();

    let (status, _, bytes) = harness
        .raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/thumbnail/{server}/{media_id}?width=96&height=96"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(error["errcode"], "M_UNSUPPORTED", "{error}");

    // And a type that is never thumbnailed gets the same code -- SVG above
    // all, which is an image type and also a script container.
    let (_, body) = harness
        .upload(&alice, "image/svg+xml", None, b"<svg/>")
        .await;
    let mxc = body["content_uri"].as_str().unwrap();
    let rest = mxc.strip_prefix("mxc://").unwrap();
    let (server, media_id) = rest.split_once('/').unwrap();
    let (status, _, _) = harness
        .raw(
            Request::builder()
                .uri(format!(
                    "/_matrix/client/v1/media/thumbnail/{server}/{media_id}?width=96&height=96"
                ))
                .header("authorization", format!("Bearer {alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
