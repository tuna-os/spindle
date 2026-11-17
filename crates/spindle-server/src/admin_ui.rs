//! The baked-in admin console: a small fork-and-reimplement starting
//! point served same-origin at `/_spindle/admin/ui`.
//!
//! Element Admin remains the full console; this page is the scaffold the
//! in-house direction grows from, and this round it covers onboarding plus
//! the one SFU switch page. The markup, script and stylesheet live in
//! `admin-ui/` next to this module and are embedded with `include_str!`,
//! so the console ships inside the binary with no new dependency and no
//! generated-file step.
//!
//! The console itself needs no auth: it is static text. Every state read
//! and every mutation goes through the admin API with the operator's
//! `Bearer` access token (kept in the tab's session storage), so the
//! [`AdminActor`](crate::admin::AdminActor) gate judges each call exactly
//! as if it came from any other admin tool.

use axum::Router;
use axum::http::{HeaderName, header};
use axum::response::{Html, IntoResponse};
use axum::routing::get;

use crate::AppState;

const INDEX_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/admin-ui/index.html"));
const APP_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/admin-ui/app.js"));
const STYLES_CSS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/admin-ui/styles.css"));

/// The console's three static routes, under the `/_spindle` namespace
/// only: the Synapse alias exists for API compatibility, not for pages.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_spindle/admin/ui", get(index))
        .route("/_spindle/admin/ui/app.js", get(script))
        .route("/_spindle/admin/ui/styles.css", get(stylesheet))
}

/// The headers every console response carries.
///
/// The page takes an admin access token and keeps it in session storage,
/// so it is the one page on the server whose script must be its own and
/// whose frame must not be someone else's: the CSP admits this origin's
/// script, stylesheet and API calls and nothing inline, and the page may
/// not be framed (a clickjacked "Turn off" is the SFU switch). The
/// script and stylesheet carry the same set, for `nosniff`.
const CONSOLE_HEADERS: [(HeaderName, &str); 4] = [
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
         form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ),
    (header::X_FRAME_OPTIONS, "DENY"),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::REFERRER_POLICY, "no-referrer"),
];

/// `GET /_spindle/admin/ui` — the onboarding skeleton and SFU toggle page.
async fn index() -> impl IntoResponse {
    (CONSOLE_HEADERS, Html(INDEX_HTML))
}

/// `GET /_spindle/admin/ui/app.js` — the console script.
async fn script() -> impl IntoResponse {
    (
        CONSOLE_HEADERS,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
}

/// `GET /_spindle/admin/ui/styles.css` — the console stylesheet.
async fn stylesheet() -> impl IntoResponse {
    (
        CONSOLE_HEADERS,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}
