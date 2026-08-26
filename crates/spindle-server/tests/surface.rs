//! #11's exit criterion: nothing unsupported is advertised.
//!
//! The mechanism under test is that the advertisement and the implementation
//! are not two lists that happen to agree. `surface` names the routes each
//! claim needs, `routes::MOUNTED` names what the router serves, and these tests
//! hold them against each other — so growing the advertisement without building
//! the endpoint fails here rather than in a client three weeks later.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use spindle_server::{Config, routes, surface};
use tower::ServiceExt;

fn config() -> Config {
    Config::parse(
        r#"
        [server]
        name = "example.org"
        "#,
    )
    .expect("the minimal configuration is valid")
}

async fn get(path: &str) -> (StatusCode, Value) {
    let app = spindle_server::app(config());
    let response = app
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("a GET request builds"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("the body is small");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("responses are JSON")
    };
    (status, value)
}

/// The load-bearing test. Every route an advertised spec version promises has
/// to be mounted.
#[test]
fn every_advertised_spec_version_is_backed_by_a_mounted_route() {
    for required in surface::required_routes() {
        assert!(
            routes::MOUNTED.contains(&required),
            "a spec version is advertised requiring {required}, which the router does not serve"
        );
    }
}

/// The same rule for room versions, which the first version of this file did
/// not cover: populating `ROOM_VERSIONS` with nothing built passed every check,
/// because the list had no evidence attached to it. A client reads a room
/// version from `/capabilities` and then tries to use it, so the endpoints it
/// will reach for have to exist before the claim is made.
#[test]
fn no_room_version_is_advertised_before_rooms_can_be_created_or_joined() {
    let claims_a_room_version =
        !surface::ROOM_VERSIONS.is_empty() || surface::DEFAULT_ROOM_VERSION.is_some();
    if !claims_a_room_version {
        return;
    }
    for required in surface::ROOM_VERSION_REQUIRES {
        assert!(
            routes::MOUNTED.contains(required),
            "a room version is advertised, but {required} is not served, so a client              that believes the advertisement cannot act on it"
        );
    }
}

/// ...and the router's own claim about itself has to be true, or the test above
/// is checking against a list rather than against reality.
#[tokio::test]
async fn every_route_the_table_claims_actually_answers() {
    for path in routes::MOUNTED {
        let (status, _) = get(path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{path} is in MOUNTED but the router does not serve it"
        );
    }
}

#[tokio::test]
async fn versions_reports_only_what_is_implemented() {
    let (status, body) = get("/_matrix/client/versions").await;
    assert_eq!(status, StatusCode::OK);

    let advertised: Vec<&str> = body["versions"]
        .as_array()
        .expect("versions is an array")
        .iter()
        .map(|value| value.as_str().expect("versions are strings"))
        .collect();
    assert_eq!(advertised, surface::spec_version_names());
    assert!(
        body["unstable_features"].is_object(),
        "clients branch on this key existing"
    );
}

/// A missing room-version capability means "unknown, assume the default". An
/// empty `available` map is a positive claim that no room version works, which
/// is a different and worse statement. Until rooms exist, say nothing.
#[tokio::test]
async fn capabilities_omits_room_versions_rather_than_claiming_none() {
    let (status, body) = get("/_matrix/client/v3/capabilities").await;
    assert_eq!(status, StatusCode::OK);

    let capabilities = body["capabilities"]
        .as_object()
        .expect("capabilities is an object");
    if surface::DEFAULT_ROOM_VERSION.is_none() {
        assert!(
            !capabilities.contains_key("m.room_versions"),
            "no room version is implemented, so none should be claimed either way"
        );
    } else {
        let versions = &capabilities["m.room_versions"];
        assert!(versions["default"].is_string());
        for version in surface::ROOM_VERSIONS {
            assert_eq!(versions["available"][version], "stable");
        }
    }
}

#[tokio::test]
async fn well_known_points_clients_at_the_configured_base_url() {
    let (status, body) = get("/.well-known/matrix/client").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["m.homeserver"]["base_url"], "https://example.org");

    let (status, body) = get("/.well-known/matrix/server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["m.server"], "example.org");
}

#[tokio::test]
async fn health_and_readiness_answer_separately() {
    assert_eq!(get("/health").await.0, StatusCode::OK);
    assert_eq!(get("/ready").await.0, StatusCode::OK);
}

#[tokio::test]
async fn an_unimplemented_endpoint_is_a_404_not_a_stub() {
    // Every endpoint SPEC 10.1 lists but this milestone has not built must be
    // absent. A stub answering 200 with an empty body is worse than a 404: a
    // client cannot distinguish it from success.
    for path in [
        "/_matrix/client/v3/sync",
        "/_matrix/client/v3/login",
        "/_matrix/client/v3/createRoom",
        "/_matrix/client/v3/register",
    ] {
        assert_eq!(
            get(path).await.0,
            StatusCode::NOT_FOUND,
            "{path} answers, but nothing in this milestone implements it"
        );
    }
}
