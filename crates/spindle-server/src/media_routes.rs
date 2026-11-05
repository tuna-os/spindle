//! Uploading and fetching media, over the client and federation APIs.

use crate::AppState;
use crate::auth::{AccountAuthenticated, Authenticated};
use crate::errors::MatrixError;
use crate::inbound::federation_origin;
use crate::ratelimit::{Budget, limit_write};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

/// Uploading and fetching files.
///
/// Only the authenticated surface. The unauthenticated `/media/v3/download`
/// endpoints are deliberately absent: the spec froze and deprecated them
/// because an unauthenticated media URL is a capability that leaks the moment
/// it is pasted anywhere, and serving them would undo the access control the
/// authenticated endpoints exist to impose. A client old enough to need them
/// gets a 404, which is the truthful answer for a surface this server does not
/// offer.
pub fn routes(max_upload_bytes: usize) -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/media/v3/upload",
            post(upload_media)
                // Axum's default body limit is 2 MiB, which would reject an
                // upload before the handler ever saw it -- with a bare 413 and
                // no Matrix error code. The server would then be advertising a
                // configured limit in `/config` and enforcing 2 MiB, which is the
                // worst kind of disagreement: the client is told the file is
                // fine, sends it, and gets an opaque failure.
                //
                // The extractor limit is set one byte above ours so that
                // `Media::put` is the thing that refuses, and refuses with
                // `M_TOO_LARGE`.
                .layer(axum::extract::DefaultBodyLimit::max(
                    max_upload_bytes.saturating_add(1),
                )),
        )
        .route("/_matrix/media/v1/create", post(create_media))
        .route(
            "/_matrix/media/v3/upload/{server_name}/{media_id}",
            axum::routing::put(upload_reserved_media).layer(axum::extract::DefaultBodyLimit::max(
                max_upload_bytes.saturating_add(1),
            )),
        )
        .route("/_matrix/media/v3/config", get(media_config))
        .route("/_matrix/client/v1/media/config", get(media_config))
        .route("/_matrix/client/v1/media/preview_url", get(preview_url))
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}",
            get(download_media),
        )
        .route(
            "/_matrix/client/v1/media/download/{server_name}/{media_id}/{file_name}",
            get(download_media_named),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}",
            get(thumbnail_media),
        )
        .route(
            "/_matrix/federation/v1/media/thumbnail/{media_id}",
            get(federation_media_thumbnail),
        )
        .route(
            "/_matrix/federation/v1/media/download/{media_id}",
            get(federation_media_download),
        )
}

/// `POST /_matrix/media/v3/upload`
async fn upload_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    limit_write(&state, Budget::MediaUpload, &identity.user_id)?;
    // The uploader's claim about the type, not a guess at it. Sniffing would
    // mean the server deciding a file is HTML and then having to be right
    // about that forever; taking the claim and refusing to render anything
    // risky inline is the safer half of the same problem.
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let media_id = state
        .media
        .put(
            &body,
            &content_type,
            query.filename.as_deref(),
            &identity.user_id,
            upload_quota(&state, &identity.user_id)?,
        )
        .await
        .map_err(|error| upload_error(&state, &error))?;
    Ok(Json(json!({
        "content_uri": format!("mxc://{}/{media_id}", state.config.server.name),
    })))
}

/// Whether `user_id`'s upload is held to the media quota: not when there is
/// none, and not for the accounts the write budgets exempt.
fn upload_quota(state: &AppState, user_id: &str) -> Result<crate::media::Quota, MatrixError> {
    if state.media.quota_bytes().is_none()
        || crate::ratelimit::exempt_from_write_limits(state, user_id)?
    {
        return Ok(crate::media::Quota::Exempt);
    }
    Ok(crate::media::Quota::Enforced)
}

/// [`media_error`], with the `admin_contact` the spec requires on
/// `M_RESOURCE_LIMIT_EXCEEDED` when `[server.support]` names someone: the
/// one thing a user over quota can usefully do is ask for more.
fn upload_error(state: &AppState, error: &crate::media::MediaError) -> MatrixError {
    let mut refusal = media_error(error);
    if matches!(error, crate::media::MediaError::QuotaExceeded { .. })
        && let Some(contact) = admin_contact(state)
    {
        let mut extra = serde_json::Map::new();
        extra.insert("admin_contact".to_owned(), Value::String(contact));
        refusal.extra = Some(Box::new(extra));
    }
    refusal
}

/// A URI for reaching this server's administrator, from
/// `[server.support]`: the support page, else an admin's address, else
/// anyone's.
fn admin_contact(state: &AppState) -> Option<String> {
    let support = state.config.server.support.as_ref()?;
    if let Some(page) = &support.support_page {
        return Some(page.clone());
    }
    let mut contacts: Vec<_> = support.contacts.iter().collect();
    // Admins first; a stable sort keeps the operator's order otherwise.
    contacts.sort_by_key(|contact| contact.role != "m.role.admin");
    contacts.iter().find_map(|contact| {
        contact
            .email_address
            .as_ref()
            .map(|address| format!("mailto:{address}"))
            .or_else(|| {
                contact
                    .matrix_id
                    .as_ref()
                    .map(|id| format!("https://matrix.to/#/{id}"))
            })
    })
}

#[derive(Debug, Deserialize)]
struct UploadQuery {
    filename: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PreviewQuery {
    url: String,
    // `ts` (the point in history to preview at) is accepted and ignored: we
    // keep no preview history, and serving the current preview for any ts
    // is within what the spec allows.
    #[allow(dead_code)]
    ts: Option<u64>,
}

/// `GET /_matrix/client/v1/media/preview_url`
async fn preview_url(
    State(state): State<AppState>,
    Authenticated(_identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<PreviewQuery>,
) -> Result<Json<Value>, MatrixError> {
    if !state.config.previews.enabled {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "URL previews are disabled on this server".to_owned(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    match state.previews.preview(&query.url, now).await {
        Ok(og) => Ok(Json(og)),
        // A refused URL and an unfetchable page must stay distinguishable:
        // the refusal is policy and retrying is pointless; the fetch failure
        // is the internet being the internet.
        Err(crate::previews::PreviewError::Refused(why)) => Err(MatrixError::forbidden(&why)),
        Err(crate::previews::PreviewError::Unfetchable(why)) => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("cannot preview that page: {why}"),
        )),
        Err(crate::previews::PreviewError::Storage(why)) => Err(MatrixError::internal(&why)),
    }
}

/// `GET /_matrix/media/v3/config` and its `/client/v1` twin.
async fn media_config(State(state): State<AppState>) -> Json<Value> {
    // Stated rather than discovered: a client that knows the limit can refuse
    // a file before spending a minute sending it.
    Json(json!({ "m.upload.size": state.media.max_upload_bytes() }))
}

/// `GET /_matrix/client/v1/media/download/{server_name}/{media_id}`
async fn download_media(
    State(state): State<AppState>,
    AccountAuthenticated(identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response, MatrixError> {
    serve_media(&state, &identity, &server_name, &media_id).await
}

/// The same, with a filename the client would like the browser to use.
///
/// The name in the path is ignored. The one that goes in the header is the one
/// recorded at upload: letting the *downloader* choose it would let a link
/// dictate what a file appears to be, which is how a `.png` turns into a
/// `.exe` in someone's downloads folder.
async fn download_media_named(
    State(state): State<AppState>,
    AccountAuthenticated(identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id, _file_name)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<axum::response::Response, MatrixError> {
    serve_media(&state, &identity, &server_name, &media_id).await
}

/// The identity is authenticated and then, by ADR 0003, not consulted:
/// possession of the URI is the capability, as the spec and every reference
/// server have it. The binding is what makes the route require a token at
/// all. `docs/architecture-decisions/0003-media-authorization.md` says why,
/// and what would supersede it.
async fn serve_media(
    state: &AppState,
    _identity: &crate::accounts::Identity,
    server_name: &str,
    media_id: &str,
) -> Result<axum::response::Response, MatrixError> {
    let media_id = if state.media.is_ours(server_name) {
        media_id.to_owned()
    } else {
        cached_remote_media(state, server_name, media_id).await?
    };
    let media_id = media_id.as_str();
    let (record, bytes) = state
        .media
        .bytes(media_id)
        .await
        .map_err(|error| media_error(&error))?;

    let mut response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, &record.content_type)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            record.content_disposition(),
        )
        // Without this a browser may decide for itself that an
        // `application/octet-stream` is really HTML, and run it.
        .header("x-content-type-options", "nosniff")
        // Belt and braces around the same risk: even if something renders,
        // it can load nothing, run nothing, and frame nothing.
        .header(
            "content-security-policy",
            "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; \
             style-src 'unsafe-inline'; object-src 'self';",
        )
        .header("cross-origin-resource-policy", "cross-origin");
    if let Some(headers) = response.headers_mut() {
        let _ = headers;
    }
    response
        .body(axum::body::Body::from(bytes))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

/// The local cache ID for a remote server's media, fetching and caching it
/// on first sight.
///
/// The fetch happens once: the blob is content-addressed and the record
/// write idempotent, so every later request — downloads and thumbnails
/// alike — is served from local storage.
async fn cached_remote_media(
    state: &AppState,
    server_name: &str,
    media_id: &str,
) -> Result<String, MatrixError> {
    let cache_id = crate::media::Media::remote_id(server_name, media_id);
    let cached = state
        .media
        .record(&cache_id)
        .map_err(|error| media_error(&error))?
        .is_some();
    if !cached {
        let (content_type, filename, bytes) = state
            .federation
            .remote_media_download(server_name, media_id)
            .await
            .map_err(|error| {
                MatrixError::new(
                    StatusCode::NOT_FOUND,
                    "M_NOT_FOUND",
                    format!("{server_name} did not yield {media_id}: {error}"),
                )
            })?;
        state
            .media
            .put_remote(
                server_name,
                media_id,
                &bytes,
                &content_type,
                filename.as_deref(),
            )
            .await
            .map_err(|error| media_error(&error))?;
    }
    Ok(cache_id)
}

/// `GET /_matrix/federation/v1/media/download/{mediaId}` (MSC3916).
///
/// Serves this server's own media to an authenticated peer, as
/// `multipart/mixed`: a JSON metadata part, then the file — the shape the
/// MSC fixes, and the one the outbound client parses.
async fn federation_media_download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(media_id): axum::extract::Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::response::Response, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    let (record, bytes) = state
        .media
        .bytes(&media_id)
        .await
        .map_err(|error| media_error(&error))?;
    multipart_media(
        &record.content_type,
        Some(&record.content_disposition()),
        &bytes,
    )
}

/// `GET /_matrix/federation/v1/media/thumbnail/{mediaId}` (spec v1.11)
///
/// The authenticated-media twin of the client thumbnail, in the same
/// `multipart/mixed` framing as the federation download.
async fn federation_media_thumbnail(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(media_id): axum::extract::Path<String>,
    // Every field optional so a missing one is refused after the
    // signature check, in the spec's JSON shape, not by the extractor.
    axum::extract::Query(query): axum::extract::Query<FederationThumbnailQuery>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<axum::response::Response, MatrixError> {
    let uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    federation_origin(&state, &headers, "GET", &uri, None).await?;
    let (Some(width), Some(height)) = (query.width, query.height) else {
        return Err(MatrixError::missing_param("width and height are required"));
    };
    if width == 0 || height == 0 {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "width and height must be positive",
        ));
    }
    let crop = query.method.as_deref() == Some("crop");
    let (content_type, bytes) = state
        .media
        .thumbnail(&media_id, width, height, crop)
        .await
        .map_err(|error| media_error(&error))?;
    multipart_media(&content_type, None, &bytes)
}

#[derive(Debug, Default, Deserialize)]
struct FederationThumbnailQuery {
    width: Option<u32>,
    height: Option<u32>,
    method: Option<String>,
}

/// The `multipart/mixed` body authenticated federation media travels in:
/// an empty JSON metadata part, then the bytes.
fn multipart_media(
    content_type: &str,
    disposition: Option<&str>,
    bytes: &[u8],
) -> Result<axum::response::Response, MatrixError> {
    // The boundary need only be absent from the payload's *framing*, and a
    // random 32-hex string followed by the exact dash-CRLF framing has no
    // way to occur inside the file; fixed randomness per response keeps
    // this simple and stateless.
    let boundary = {
        use std::fmt::Write as _;
        let mut raw = [0_u8; 16];
        crate::secrets::fill(&mut raw);
        raw.iter().fold(String::with_capacity(32), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    };
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + 512);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"content-type: application/json\r\n\r\n{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(format!("content-type: {content_type}\r\n").as_bytes());
    if let Some(disposition) = disposition {
        body.extend_from_slice(format!("content-disposition: {disposition}\r\n").as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={boundary}"),
        )
        .body(axum::body::Body::from(body))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

#[derive(Debug, Deserialize)]
struct ThumbnailQuery {
    width: u32,
    height: u32,
    method: Option<String>,
}

/// `GET /_matrix/client/v1/media/thumbnail/{server_name}/{media_id}`
///
/// Authenticated, and open to any account holding the URI, for the reason
/// [`serve_media`] gives (ADR 0003). An account-level session is enough —
/// Element Admin's device-less admin token renders avatars through this —
/// since reading media acts on no device.
async fn thumbnail_media(
    State(state): State<AppState>,
    AccountAuthenticated(_identity): AccountAuthenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<ThumbnailQuery>,
) -> Result<axum::response::Response, MatrixError> {
    let media_id = if state.media.is_ours(&server_name) {
        media_id
    } else {
        cached_remote_media(&state, &server_name, &media_id).await?
    };
    if query.width == 0 || query.height == 0 {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "width and height must be positive",
        ));
    }
    let crop = query.method.as_deref() == Some("crop");
    let (content_type, bytes) = state
        .media
        .thumbnail(&media_id, query.width, query.height, crop)
        .await
        .map_err(|error| media_error(&error))?;
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header("x-content-type-options", "nosniff")
        .header("cross-origin-resource-policy", "cross-origin")
        .body(axum::body::Body::from(bytes))
        .map_err(|error| MatrixError::internal(&error.to_string()))
}

fn media_error(error: &crate::media::MediaError) -> MatrixError {
    use crate::media::MediaError as Error;
    match error {
        Error::Unknown(_) | Error::Missing { .. } => {
            MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", error.to_string())
        }
        // 504, as the spec has it: the bytes are on their way from another
        // client, and the asker should try again rather than give up.
        Error::NotYetUploaded(_) => MatrixError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "M_NOT_YET_UPLOADED",
            error.to_string(),
        ),
        Error::AlreadyUploaded(_) => MatrixError::new(
            StatusCode::CONFLICT,
            "M_CANNOT_OVERWRITE_MEDIA",
            error.to_string(),
        ),
        Error::NotReserver(_) => MatrixError::forbidden(error.to_string()),
        Error::TooManyPending(_) => MatrixError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "M_LIMIT_EXCEEDED",
            error.to_string(),
        ),
        Error::TooLarge { .. } => MatrixError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            error.to_string(),
        ),
        // 403, because the spec's `/upload` lists "the user has reached a
        // quota for uploaded content" under 403 -- not 413 `M_TOO_LARGE`,
        // which says *this file* is too big and sends a client to
        // `/media/config` to learn a limit the file is already under.
        // `M_RESOURCE_LIMIT_EXCEEDED` rather than plain `M_FORBIDDEN` so a
        // client can tell "over quota" from "not allowed", and because it
        // is the code Synapse's `media_upload_limits` refuses with.
        Error::QuotaExceeded { .. } => MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_RESOURCE_LIMIT_EXCEEDED",
            error.to_string(),
        ),
        // The spec's own code for "this cannot be thumbnailed". Unreadable
        // bytes get the same answer as an unsupported type: either way the
        // uploader's declared type cannot be honoured, and the distinction
        // belongs in the message, not the status.
        Error::Unsupported(_) | Error::Unreadable(_) => {
            MatrixError::new(StatusCode::BAD_REQUEST, "M_UNSUPPORTED", error.to_string())
        }
        other => MatrixError::internal(&other.to_string()),
    }
}

/// `POST /_matrix/media/v1/create` (spec v1.7)
///
/// An `mxc://` URI ahead of its bytes, so a client can put the URI in an
/// event while the upload is still going.
async fn create_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    // Counted here, on the mint, and not again on the `PUT` that fills it:
    // a create and its fill are one upload, as `POST /upload` is.
    limit_write(&state, Budget::MediaUpload, &identity.user_id)?;
    let (media_id, unused_expires_at) = state
        .media
        .reserve(&identity.user_id)
        .map_err(|error| media_error(&error))?;
    Ok(Json(json!({
        "content_uri": state.media.mxc(&media_id),
        "unused_expires_at": unused_expires_at,
    })))
}

/// `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` (spec v1.7)
async fn upload_reserved_media(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    if !state.media.is_ours(&server_name) {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{server_name} is not this server"),
        ));
    }
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    state
        .media
        .put_reserved(
            &media_id,
            &body,
            &content_type,
            query.filename.as_deref(),
            &identity.user_id,
            upload_quota(&state, &identity.user_id)?,
        )
        .await
        .map_err(|error| upload_error(&state, &error))?;
    Ok(Json(json!({})))
}
