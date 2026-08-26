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
}

impl MatrixError {
    #[must_use]
    pub fn new(status: StatusCode, errcode: &'static str, error: impl Into<String>) -> Self {
        Self {
            status,
            errcode,
            error: error.into(),
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

    #[must_use]
    pub fn bad_json(error: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_BAD_JSON", error)
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
        (
            self.status,
            Json(json!({ "errcode": self.errcode, "error": self.error })),
        )
            .into_response()
    }
}
