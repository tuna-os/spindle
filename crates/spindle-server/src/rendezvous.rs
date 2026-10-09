//! MSC4108's rendezvous channel: sign in on a new device with a QR code.
//!
//! The homeserver's whole part in "sign in with QR code" is a tiny mailbox.
//! The two devices encrypt everything end to end (the secure channel is
//! theirs), and the new device gets its token from the OAuth provider (MAS)
//! with the device authorization grant. What they need from the server is
//! a place both can reach, to leave a message and wait for the answer: a
//! session one device creates, the other reads, and both overwrite in turn,
//! each write guarded by the `ETag` of the version it last saw.
//!
//! This is the 2024 revision, the one Synapse serves with
//! `msc4108_enabled` and matrix-rust-sdk (Element X) and matrix-js-sdk
//! (Element Web's "link new device") speak, matched header for header:
//!
//! - `POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous` with a
//!   `text/plain` body creates a session and answers `201 {"url"}`, an
//!   absolute URL on the public base.
//! - `GET {url}` answers the body, or `304` when `If-None-Match` names the
//!   current version; `PUT {url}` with `If-Match` replaces it (`202`) or
//!   refuses a stale writer (`412`, `M_CONCURRENT_WRITE`); `DELETE` ends it.
//! - Every answer carries `ETag`, `Expires` and `Last-Modified`, which the
//!   SDKs require even on a `304`, and `Cache-Control: no-store`.
//!
//! Sessions are unauthenticated (the new device has no token yet, which is
//! the point), live 60 seconds from creation, hold at most 4 KiB, and at
//! most 100 are kept: Synapse's limits. They are in memory, in this
//! process: a session that outlives a restart would outlive its 60 seconds
//! anyway, and the devices start over.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde_json::json;

use crate::AppState;
use crate::errors::MatrixError;

/// The path a session is created on.
pub const CREATE_PATH: &str = "/_matrix/client/unstable/org.matrix.msc4108/rendezvous";

/// Where sessions live; Synapse's spelling, so the URL a client was handed
/// by either server has the same shape.
const SESSION_PREFIX: &str = "/_synapse/client/rendezvous";

/// How long a session lives, from creation; a write does not extend it.
const TTL: Duration = Duration::from_secs(60);

/// The most a session may hold.
const MAX_BODY: usize = 4096;

/// How many sessions are kept: past this, the oldest go first.
const CAPACITY: usize = 100;

struct Session {
    body: Bytes,
    content_type: HeaderValue,
    etag: String,
    created: SystemTime,
    modified: SystemTime,
}

impl Session {
    fn expires(&self) -> SystemTime {
        self.created + TTL
    }

    fn live(&self, now: SystemTime) -> bool {
        now < self.expires()
    }

    /// The headers every answer about this session carries.
    fn headers(&self, headers: &mut HeaderMap) {
        if let Ok(value) = HeaderValue::from_str(&self.etag) {
            headers.insert(header::ETAG, value);
        }
        for (name, at) in [
            (header::EXPIRES, self.expires()),
            (header::LAST_MODIFIED, self.modified),
        ] {
            if let Ok(value) = HeaderValue::from_str(&http_date(at)) {
                headers.insert(name, value);
            }
        }
        no_store(headers);
    }
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    // Browsers (Element Web) must be able to read the ETag cross-origin.
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("ETag"),
    );
}

/// The live rendezvous sessions.
#[derive(Default)]
pub struct Rendezvous {
    sessions: Mutex<HashMap<String, Session>>,
}

impl Rendezvous {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/unstable/org.matrix.msc4108/rendezvous",
            post(create),
        )
        .route(
            "/_synapse/client/rendezvous/{session_id}",
            axum::routing::get(read).put(write).delete(remove),
        )
}

/// The content a create or a write carries, checked the way Synapse checks
/// it: `text/plain` (the devices' messages are base64 text), and small.
fn content(headers: &HeaderMap, body: &Bytes) -> Result<HeaderValue, MatrixError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .filter(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.split(';').next())
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/plain"))
        })
        .cloned()
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "the Content-Type must be text/plain",
            )
        })?;
    if body.len() > MAX_BODY {
        return Err(MatrixError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            "a rendezvous message holds at most 4096 bytes",
        ));
    }
    Ok(content_type)
}

/// An entity tag that depends only on the content, as Synapse's does.
fn etag(body: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(body);
    format!("\"{}\"", crate::oidc::base64url_unpadded(&digest))
}

fn not_found() -> Response {
    let mut response = MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        "no such rendezvous session",
    )
    .into_response();
    no_store(response.headers_mut());
    response
}

/// `POST /_matrix/client/unstable/org.matrix.msc4108/rendezvous`
async fn create(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let content_type = match content(&headers, &body) {
        Ok(content_type) => content_type,
        Err(error) => return error.into_response(),
    };
    let now = SystemTime::now();
    let id = session_id();
    let session = Session {
        etag: etag(&body),
        body,
        content_type,
        created: now,
        modified: now,
    };
    let mut response = (
        StatusCode::CREATED,
        axum::Json(json!({
            "url": format!(
                "{}{SESSION_PREFIX}/{id}",
                state.config.client_base_url().trim_end_matches('/')
            ),
        })),
    )
        .into_response();
    session.headers(response.headers_mut());

    let mut sessions = state.rendezvous.sessions();
    sessions.retain(|_, session| session.live(now));
    while sessions.len() >= CAPACITY {
        let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, session)| session.created)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        sessions.remove(&oldest);
    }
    sessions.insert(id, session);
    response
}

/// `GET /_synapse/client/rendezvous/{id}`
async fn read(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let now = SystemTime::now();
    let mut sessions = state.rendezvous.sessions();
    let Some(session) = sessions.get(&id).filter(|session| session.live(now)) else {
        sessions.remove(&id);
        return not_found();
    };
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|tags| tags.split(',').any(|tag| tag.trim() == session.etag));
    let mut response = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut response = Response::new(Body::from(session.body.clone()));
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, session.content_type.clone());
        response
    };
    session.headers(response.headers_mut());
    response
}

/// `PUT /_synapse/client/rendezvous/{id}`
async fn write(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = match content(&headers, &body) {
        Ok(content_type) => content_type,
        Err(error) => return error.into_response(),
    };
    let Some(expected) = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(ToOwned::to_owned)
    else {
        return MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "a rendezvous write needs If-Match",
        )
        .into_response();
    };
    let now = SystemTime::now();
    let mut sessions = state.rendezvous.sessions();
    let Some(session) = sessions.get_mut(&id).filter(|session| session.live(now)) else {
        sessions.remove(&id);
        return not_found();
    };
    if expected != session.etag {
        let mut response = (
            StatusCode::PRECONDITION_FAILED,
            axum::Json(json!({
                "errcode": "M_UNKNOWN",
                "error": "ETag does not match",
                "org.matrix.msc4108.errcode": "M_CONCURRENT_WRITE",
            })),
        )
            .into_response();
        session.headers(response.headers_mut());
        return response;
    }
    session.etag = etag(&body);
    session.body = body;
    session.content_type = content_type;
    session.modified = now;
    let mut response = StatusCode::ACCEPTED.into_response();
    // Synapse's workaround, kept: some proxies drop the ETag of a response
    // with no content type, and the writer needs it for its next write.
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    session.headers(response.headers_mut());
    response
}

/// `DELETE /_synapse/client/rendezvous/{id}`
async fn remove(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let now = SystemTime::now();
    match state.rendezvous.sessions().remove(&id) {
        Some(session) if session.live(now) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            no_store(response.headers_mut());
            response
        }
        _ => not_found(),
    }
}

/// An unguessable session ID: whoever holds it can read and write the
/// session, so it is the session's only protection besides the devices'
/// own encryption.
fn session_id() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes: [u8; 16] = rand::random();
    bytes
        .into_iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

/// An IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), as `Expires` and
/// `Last-Modified` take.
fn http_date(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Howard Hinnant's civil-from-days.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    // 1970-01-01 was a Thursday.
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
        [usize::try_from(days.rem_euclid(7)).unwrap_or(0)];
    let month_name = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][usize::try_from(month - 1).unwrap_or(0)];
    format!(
        "{weekday}, {day:02} {month_name} {year} {:02}:{:02}:{:02} GMT",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{Session, TTL, http_date};

    #[test]
    fn an_expired_mailbox_is_not_live_and_a_write_does_not_extend_it() {
        let created = UNIX_EPOCH + Duration::from_secs(100);
        let mut session = Session {
            body: axum::body::Bytes::new(),
            content_type: axum::http::HeaderValue::from_static("text/plain"),
            etag: "\"x\"".to_owned(),
            created,
            modified: created,
        };
        assert!(session.live(created + TTL - Duration::from_millis(1)));
        assert!(!session.live(created + TTL));
        session.modified = created + Duration::from_secs(59);
        assert_eq!(session.expires(), created + TTL);
        assert!(!session.live(created + TTL));
    }

    #[test]
    fn dates_are_imf_fixdates() {
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(784_111_777)),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(1_709_251_199)),
            "Thu, 29 Feb 2024 23:59:59 GMT"
        );
    }
}
