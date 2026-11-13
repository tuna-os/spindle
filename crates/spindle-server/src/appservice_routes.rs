//! The surface only an application service speaks.

use crate::AppState;
use crate::errors::MatrixError;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde_json::{Value, json};

/// The surface only an appservice speaks.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/_matrix/client/v1/appservice/{appservice_id}/ping",
        post(appservice_ping),
    )
}

/// MSC2659 (spec v1.7): an appservice asks to be pinged back, to prove the
/// homeserver can reach its push URL before anything real depends on it.
///
/// Authorization is the `as_token` itself, checked against the registration
/// the path names — not the authenticated identity, because a device ID is
/// client-chosen at login and anything derived from it can be worn as a
/// costume by an ordinary account.
async fn appservice_ping(
    State(state): State<AppState>,
    axum::extract::Path(appservice_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, MatrixError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();
    let registration = state.appservices.by_token(token).ok_or_else(|| {
        MatrixError::new(
            StatusCode::UNAUTHORIZED,
            "M_UNKNOWN_TOKEN",
            "only an appservice can ask for its own ping",
        )
    })?;
    if registration.id != appservice_id {
        return Err(MatrixError::new(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "an appservice can only ping itself",
        ));
    }
    let Some(url) = &registration.url else {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_URL_NOT_SET",
            "the registration has no url to ping",
        ));
    };
    let mut ping_body = json!({});
    if let Some(Json(body)) = &body
        && let Some(transaction_id) = body["transaction_id"].as_str()
    {
        ping_body["transaction_id"] = Value::String(transaction_id.to_owned());
    }
    let started = std::time::Instant::now();
    let response = reqwest::Client::new()
        .post(format!("{}/_matrix/app/v1/ping", url.trim_end_matches('/')))
        .header("authorization", format!("Bearer {}", registration.hs_token))
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(30))
        .body(ping_body.to_string())
        .send()
        .await;
    match response {
        Err(error) if error.is_timeout() => Err(MatrixError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "M_CONNECTION_TIMEOUT",
            "the appservice did not answer in time",
        )),
        Err(error) => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_CONNECTION_FAILED",
            format!("the appservice could not be reached: {error}"),
        )),
        Ok(response) if !response.status().is_success() => Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_BAD_STATUS",
            format!("the appservice answered {}", response.status()),
        )),
        Ok(_) => Ok(Json(json!({
            "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }))),
    }
}
