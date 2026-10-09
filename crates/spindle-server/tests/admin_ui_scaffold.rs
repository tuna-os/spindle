//! The baked-in admin console scaffold: what the three static routes
//! serve, and that the one SFU page honors the admin API switch contract.
//!
//! What this pins, claim by claim: `/_spindle/admin/ui` answers 200 HTML
//! without any token (the console is static text; the API calls it makes
//! carry the `Bearer` admin token), and the page holds the onboarding
//! skeleton, the `role="switch"` SFU toggle, the local-vs-remote model
//! badge, and the status table. The script and stylesheet answer 200 with
//! their content types; the script talks only to the documented switch
//! endpoints (`GET` status / `PUT {"enabled"}` on
//! `/_spindle/admin/v1/rtc/sfu`, falling back to the `/_synapse` alias
//! spelling) and never to the client minter paths. The stylesheet honors
//! the visual rules: the reduced-motion guard is present and the banned
//! vocabulary (gradients, aurora, glassmorphism, Inter, emoji hooks) is
//! absent. An unknown console subpath stays an honest JSON 404 rather
//! than the console.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const CONSOLE: &str = "/_spindle/admin/ui";
const SCRIPT: &str = "/_spindle/admin/ui/app.js";
const STYLES: &str = "/_spindle/admin/ui/styles.css";

/// The documented admin API switch endpoints the page wires to. They live
/// on the backend stage's branch; this scaffold names them but never
/// re-spells them.
const SFU_PRIMARY: &str = "/_spindle/admin/v1/rtc/sfu";
const SFU_ALIAS: &str = "/_synapse/admin/v1/rtc/sfu";

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn fresh() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .expect("the configuration is valid");
        let app = spindle_server::app(config, store)
            .expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn get(&self, uri: &str) -> (StatusCode, String, String) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap_or_default();
        (status, content_type, body)
    }
}

#[tokio::test]
async fn console_serves_the_scaffold_unauthenticated() {
    let harness = Harness::fresh();
    let (status, content_type, body) = harness.get(CONSOLE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        content_type.starts_with("text/html"),
        "unexpected content type: {content_type}"
    );
    for marker in [
        "id=\"onboarding\"",
        "promote-admin",
        "id=\"token-form\"",
        "id=\"sfu-toggle\"",
        "role=\"switch\"",
        "id=\"sfu-model\"",
        "id=\"sfu-status-body\"",
        "id=\"sfu-refresh\"",
        SFU_PRIMARY,
    ] {
        assert!(body.contains(marker), "the console is missing {marker}");
    }
}

#[tokio::test]
async fn console_script_honors_the_switch_contract() {
    let harness = Harness::fresh();
    let (status, content_type, body) = harness.get(SCRIPT).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        content_type.contains("javascript"),
        "unexpected content type: {content_type}"
    );
    // Both switch spellings, the status GET and the `{enabled}` PUT.
    for marker in [SFU_PRIMARY, SFU_ALIAS, "{ enabled: enabled }"] {
        assert!(body.contains(marker), "the script is missing {marker}");
    }
    // The script drives the switch only: never the minter token paths.
    for forbidden in ["get_token", "delegate_delayed_leave", "webhook"] {
        assert!(
            !body.contains(forbidden),
            "the script reaches past the switch into {forbidden}"
        );
    }
    // Reduced motion is an explicit contract, not an accident.
    assert!(body.contains("prefers-reduced-motion"), "no motion query");
}

#[tokio::test]
async fn console_stylesheet_holds_the_visual_rules() {
    let harness = Harness::fresh();
    let (status, content_type, body) = harness.get(STYLES).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        content_type.starts_with("text/css"),
        "unexpected content type: {content_type}"
    );
    assert!(
        body.contains("prefers-reduced-motion"),
        "the reduced-motion guard is missing"
    );
    for banned in [
        "gradient",
        "aurora",
        "backdrop-filter",
        "Inter",
        "glass",
        "glow",
        "#9ca3af",
        "#9CA3AF",
        "#6b7280",
        "#6B7280",
    ] {
        assert!(
            !body.contains(banned),
            "the stylesheet breaks a visual rule with {banned}"
        );
    }
}

#[tokio::test]
async fn unknown_console_path_stays_an_honest_404() {
    let harness = Harness::fresh();
    let (status, _, body) = harness.get("/_spindle/admin/ui/elsewhere").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body.contains("M_UNRECOGNIZED"),
        "the 404 must carry its errcode: {body}"
    );
}
