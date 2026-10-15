//! Matrix API errors.
//!
//! The spec's shape is `{"errcode": ..., "error": ...}` with a status code, and
//! clients branch on `errcode`. Getting the code wrong is worse than getting
//! the message wrong: a client that sees `M_UNKNOWN` where it expected
//! `M_USER_IN_USE` shows the user a generic failure instead of "pick another
//! name".

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// A Matrix error response.
#[derive(Clone, Debug)]
pub struct MatrixError {
    pub status: StatusCode,
    pub errcode: &'static str,
    pub error: String,
    /// Present only on `M_LIMIT_EXCEEDED`, where the spec defines it.
    pub retry_after_ms: Option<u64>,
    /// `M_USER_LOCKED` carries `soft_logout: true`: the session is kept,
    /// the client is to stop using it until the lock lifts.
    pub soft_logout: bool,
    /// `M_INCOMPATIBLE_ROOM_VERSION` names the version the asker would have
    /// needed (federation `make_join`/`make_knock`).
    pub room_version: Option<String>,
    /// Further keys an error code defines beside `errcode` and `error`,
    /// such as the limit MSC4140's delay-too-large names.
    pub extra: Option<Box<serde_json::Map<String, serde_json::Value>>>,
}

impl MatrixError {
    #[must_use]
    pub fn new(status: StatusCode, errcode: &'static str, error: impl Into<String>) -> Self {
        Self {
            status,
            errcode,
            error: error.into(),
            retry_after_ms: None,
            soft_logout: false,
            room_version: None,
            extra: None,
        }
    }

    /// The account is locked by an administrator (spec v1.18). The token
    /// stays valid, which is what `soft_logout` tells the client.
    #[must_use]
    pub fn user_locked() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            errcode: "M_USER_LOCKED",
            error: "this account is locked".to_owned(),
            retry_after_ms: None,
            soft_logout: true,
            room_version: None,
            extra: None,
        }
    }

    /// `M_INCOMPATIBLE_ROOM_VERSION`, naming the room's version as the spec
    /// requires for that code.
    #[must_use]
    pub fn incompatible_room_version(version: &str) -> Self {
        Self {
            room_version: Some(version.to_owned()),
            ..Self::new(
                StatusCode::BAD_REQUEST,
                "M_INCOMPATIBLE_ROOM_VERSION",
                format!("this room is version {version}"),
            )
        }
    }

    #[must_use]
    pub fn forbidden(error: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "M_FORBIDDEN", error)
    }

    #[must_use]
    pub fn unknown_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "M_UNKNOWN_TOKEN",
            "the access token is not valid",
        )
    }

    #[must_use]
    pub fn missing_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "M_MISSING_TOKEN",
            "this endpoint needs an access token",
        )
    }

    #[must_use]
    pub fn user_in_use() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "M_USER_IN_USE",
            "that username is taken",
        )
    }

    #[must_use]
    pub fn invalid_username() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_USERNAME",
            "that username is not valid",
        )
    }

    /// `M_LIMIT_EXCEEDED`, with the wait a client should honour.
    ///
    /// `retry_after_ms` is not decoration: without it a client backs off by
    /// guessing, and the usual guess is "immediately, but again", which is the
    /// behaviour the limit exists to stop.
    #[must_use]
    pub fn limit_exceeded(retry_after_ms: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            errcode: "M_LIMIT_EXCEEDED",
            error: format!("too many requests; retry in {retry_after_ms}ms"),
            retry_after_ms: Some(retry_after_ms),
            soft_logout: false,
            room_version: None,
            extra: None,
        }
    }

    #[must_use]
    pub fn bad_json(error: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_BAD_JSON", error)
    }

    /// A required parameter was not sent.
    ///
    /// `M_MISSING_PARAM` rather than [`Self::bad_json`]: the spec keeps them
    /// apart because they tell a client different things. `M_BAD_JSON` says
    /// what was sent is malformed, which sends a developer looking at their
    /// serializer; this says something was left out, which is the actual
    /// fault when a query string is short a key.
    #[must_use]
    pub fn missing_param(error: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", error)
    }

    /// Something went wrong on our side.
    ///
    /// The message is deliberately generic: an internal error's detail is for
    /// the log, not for whoever sent the request.
    #[must_use]
    pub fn internal(detail: &str) -> Self {
        tracing::error!("internal error: {detail}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            "internal server error",
        )
    }
}

impl IntoResponse for MatrixError {
    fn into_response(self) -> Response {
        let mut body = serde_json::Map::new();
        body.insert("errcode".to_owned(), json!(self.errcode));
        body.insert("error".to_owned(), json!(self.error));
        if let Some(retry) = self.retry_after_ms {
            body.insert("retry_after_ms".to_owned(), json!(retry));
        }
        if self.soft_logout {
            body.insert("soft_logout".to_owned(), json!(true));
        }
        if let Some(version) = self.room_version {
            body.insert("room_version".to_owned(), json!(version));
        }
        if let Some(extra) = self.extra {
            for (key, value) in *extra {
                body.entry(key).or_insert(value);
            }
        }
        let mut response = (self.status, Json(serde_json::Value::Object(body))).into_response();
        // The header beside the body field: HTTP clients and proxies read
        // `Retry-After`, and MSC4140 names it for a refused schedule. Whole
        // seconds, rounded up, so a client that honours it is never early.
        if let Some(retry) = self.retry_after_ms
            && let Ok(value) = axum::http::HeaderValue::from_str(&retry.div_ceil(1000).to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}
