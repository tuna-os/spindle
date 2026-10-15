//! The browser console (#458): three static files compiled into the
//! binary, so the console is up whenever the operator is, with nothing to
//! deploy beside it and nothing fetched from another origin.
//!
//! The pages hold no credential. They sign in through the session routes,
//! read only `/_spindle/operator/v1`, and send the session's CSRF token on
//! the one write they make (a connection probe). The policy below lets a
//! page load its own script and style and call its own origin, and
//! nothing else: no inline script, no third-party content, no framing.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Router, routing};

use crate::auth::AppState;

const INDEX: &str = include_str!("../console/index.html");
const SCRIPT: &str = include_str!("../console/app.js");
const STYLE: &str = include_str!("../console/app.css");

const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      connect-src 'self'; img-src 'self' data:; base-uri 'none'; \
                      form-action 'self'; frame-ancestors 'none'";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", routing::get(|| async { Redirect::to("/console/") }))
        .route(
            "/console",
            routing::get(|| async { Redirect::to("/console/") }),
        )
        .route(
            "/console/",
            routing::get(|| async { page(INDEX, "text/html; charset=utf-8") }),
        )
        .route(
            "/console/app.js",
            routing::get(|| async { page(SCRIPT, "text/javascript; charset=utf-8") }),
        )
        .route(
            "/console/app.css",
            routing::get(|| async { page(STYLE, "text/css; charset=utf-8") }),
        )
}

fn page(body: &'static str, content_type: &'static str) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(POLICY),
    );
    response
}
