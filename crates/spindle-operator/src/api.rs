//! `/_spindle/operator/v1`: the one API the browser console and a future
//! `spindlectl` both use.
//!
//! Three contracts hold on every mutating route, so a client written once
//! behaves the same against all of them:
//!
//! - **`Idempotency-Key` is required on every `POST`.** A retry with the
//!   same key and body replays the first answer (`Idempotent-Replayed:
//!   true`) instead of doing the work twice; the same key with a different
//!   body is refused. A dropped connection during "start the cutover"
//!   must not start two cutovers.
//! - **`If-Match` is required to change an existing resource.** Every
//!   resource answers with an `ETag` of its version. Acting on a stale
//!   view is `412`; acting with no precondition at all is `428`.
//! - **Roles are checked here, on the server.** The UI may hide a button;
//!   the API is what refuses.
//!
//! Action routes use Google's custom-method style (`/operations/{id}:pause`),
//! which keeps verbs out of the resource path while staying one `POST`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::sse::{KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::auth::{AppState, Authenticated};
use crate::engine::{Engine, Verb, check_version, new_id, now, sha256_hex};
use crate::error::ApiError;
use crate::journal::{Change, Event};
use crate::model::{Connection, Deployment, OperationState, Policy, Risk, Role};
use crate::secret::{self, SecretRef};

const PREFIX: &str = "/_spindle/operator/v1";

pub fn routes() -> Router<AppState> {
    let route = |path: &str| format!("{PREFIX}{path}");
    Router::new()
        .route(&route("/view"), routing::get(view))
        .route(
            &route("/connections"),
            routing::get(list_connections).post(create_connection),
        )
        .route(
            &route("/connections/{target}"),
            routing::get(get_connection).post(connection_action),
        )
        .route(
            &route("/deployments"),
            routing::get(list_deployments).post(create_deployment),
        )
        .route(&route("/deployments/{id}"), routing::get(get_deployment))
        .route(
            &route("/assessments"),
            routing::get(list_assessments).post(create_assessment),
        )
        .route(&route("/assessments/{id}"), routing::get(get_assessment))
        .route(
            &route("/operations"),
            routing::get(list_operations).post(create_operation),
        )
        .route(
            &route("/operations/{target}"),
            routing::get(get_operation).post(operation_action),
        )
        .route(&route("/operations/{id}/approvals"), routing::post(approve))
        .route(
            &route("/operations/{id}/events"),
            routing::get(operation_events),
        )
        .route(&route("/artifacts/{id}"), routing::get(get_artifact))
        .route(
            &route("/policies/{id}"),
            routing::get(get_policy).put(put_policy),
        )
        .route(&route("/audit"), routing::get(audit))
}

// ---- shared contract helpers -------------------------------------------

fn etag(version: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{version}\"")).expect("a number is a valid header")
}

fn with_etag(status: StatusCode, body: Value) -> Response {
    let version = body.get("version").and_then(Value::as_u64);
    let mut response = (status, Json(body)).into_response();
    if let Some(version) = version {
        response.headers_mut().insert(header::ETAG, etag(version));
    }
    response
}

fn resource<T: serde::Serialize>(value: &T) -> Response {
    with_etag(
        StatusCode::OK,
        serde_json::to_value(value).unwrap_or(Value::Null),
    )
}

/// The version `If-Match` names.
fn if_match(headers: &HeaderMap) -> Result<u64, ApiError> {
    let raw = headers
        .get(header::IF_MATCH)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "send If-Match with the ETag you last saw",
            )
        })?
        .to_str()
        .unwrap_or_default();
    raw.trim()
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .and_then(|inner| inner.parse().ok())
        .ok_or_else(|| ApiError::invalid("If-Match must be a strong ETag such as \"3\""))
}

fn parse_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    let bytes: &[u8] = if body.is_empty() { b"{}" } else { body };
    serde_json::from_slice(bytes)
        .map_err(|error| ApiError::invalid(format!("invalid body: {error}")))
}

/// Run `work` at most once per `Idempotency-Key`. `work` is a future, and
/// futures do nothing until polled, so a replay never starts it.
async fn idempotent(
    engine: &Engine,
    who: &Authenticated,
    headers: &HeaderMap,
    path: &str,
    body: &Bytes,
    work: impl Future<Output = Result<(StatusCode, Value), ApiError>>,
) -> Response {
    let Some(key) = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|key| !key.is_empty() && key.len() <= 128)
    else {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "every POST needs an Idempotency-Key header (1–128 characters)",
        )
        .into_response();
    };
    let mut material = Vec::with_capacity(path.len() + body.len() + 8);
    material.extend_from_slice(b"POST\0");
    material.extend_from_slice(path.as_bytes());
    material.push(0);
    material.extend_from_slice(body);
    let fingerprint = sha256_hex(&material);
    let subject = &who.principal.subject;
    match engine.begin_idempotent(subject, key, &fingerprint) {
        Err(error) => return error.into_response(),
        Ok(Some(stored)) => {
            let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
            let mut response = with_etag(status, stored.body);
            response
                .headers_mut()
                .insert("idempotent-replayed", HeaderValue::from_static("true"));
            return response;
        }
        Ok(None) => {}
    }
    // Released if this future is dropped before it finishes: a client that
    // disconnects mid-request must not leave its key claimed until restart.
    let mut claim = Claim {
        engine,
        subject,
        key,
        finished: false,
    };
    let (status, body) = match work.await {
        Ok(done) => done,
        Err(error) => (
            error.status,
            json!({"error": {"code": error.code, "message": error.message}}),
        ),
    };
    claim.finished = true;
    engine.finish_idempotent(
        &who.context(),
        subject,
        key,
        &fingerprint,
        status.as_u16(),
        &body,
    );
    with_etag(status, body)
}

/// An idempotency key claimed for a request in progress.
struct Claim<'a> {
    engine: &'a Engine,
    subject: &'a str,
    key: &'a str,
    finished: bool,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.engine.release_idempotent(self.subject, self.key);
        }
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

// ---- view ---------------------------------------------------------------

/// The compact "Now" aggregate: what is leased, what is running, what
/// needs a person, and how each homeserver last answered. Built entirely
/// from the operator's own state, so it answers while both homeservers
/// are down.
async fn view(State(app): State<AppState>, who: Authenticated) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    Ok(Json(app.engine.read(|state| {
        let deployments: Vec<Value> = state
            .deployments
            .values()
            .map(|deployment| {
                let lease = state.leases.get(&deployment.id);
                let active = lease.and_then(|lease| state.operations.get(&lease.operation));
                let latest = state
                    .assessments
                    .values()
                    .filter(|assessment| assessment.deployment == deployment.id)
                    .max_by_key(|assessment| assessment.created_at);
                json!({
                    "deployment": deployment,
                    "lease": lease,
                    "active_operation": active.map(|op| json!({
                        "id": op.id, "action": op.action, "state": op.state, "reason": op.reason,
                    })),
                    "latest_assessment": latest,
                })
            })
            .collect();
        let attention: Vec<Value> = state
            .operations
            .values()
            .filter(|op| {
                matches!(
                    op.state,
                    OperationState::AwaitingApproval
                        | OperationState::AttentionRequired
                        | OperationState::Failed
                        | OperationState::Paused
                )
            })
            .map(|op| json!({"id": op.id, "deployment": op.deployment, "state": op.state, "reason": op.reason}))
            .collect();
        json!({
            "now": now(),
            "principal": who.principal,
            "deployments": deployments,
            "connections": state.connections.values().collect::<Vec<_>>(),
            "needs_attention": attention,
            "policy": state.policy(),
        })
    })))
}

// ---- connections ----------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewConnection {
    name: String,
    base_url: String,
    #[serde(default)]
    credential: Option<SecretRef>,
}

async fn list_connections(
    State(app): State<AppState>,
    who: Authenticated,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    Ok(Json(app.engine.read(
        |state| json!({"items": state.connections.values().collect::<Vec<_>>()}),
    )))
}

async fn create_connection(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/connections");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let input: NewConnection = parse_body(&body)?;
        let base_url = input.base_url.trim_end_matches('/').to_owned();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            return Err(ApiError::invalid("base_url must be an http or https URL"));
        }
        let connection = Connection {
            id: new_id("conn"),
            version: 1,
            name: input.name,
            base_url,
            credential: input.credential,
            last_probe: None,
            created_at: now(),
        };
        engine.transact(&who.context(), None, |_| {
            Ok((
                vec![Change::ConnectionCreated {
                    connection: connection.clone(),
                }],
                (),
            ))
        })?;
        Ok((StatusCode::CREATED, to_value(&connection)))
    };
    idempotent(&app.engine, &who, &headers, &path, &body, work).await
}

async fn get_connection(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    app.engine
        .read(|state| state.connections.get(&id).map(resource))
        .ok_or_else(|| ApiError::not_found("connection"))
}

async fn connection_action(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    Path(target): Path<String>,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/connections/{target}");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let Some(id) = target.strip_suffix(":probe") else {
            return Err(ApiError::not_found("connection action"));
        };
        let connection = engine.probe(&who.context(), id).await?;
        Ok((StatusCode::OK, to_value(&connection)))
    };
    idempotent(&app.engine, &who, &headers, &path, &body, work).await
}

// ---- deployments ----------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDeployment {
    name: String,
    driver: String,
    #[serde(default)]
    connections: Vec<String>,
    #[serde(default)]
    settings: Value,
}

async fn list_deployments(
    State(app): State<AppState>,
    who: Authenticated,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    Ok(Json(app.engine.read(
        |state| json!({"items": state.deployments.values().collect::<Vec<_>>()}),
    )))
}

async fn create_deployment(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/deployments");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let input: NewDeployment = parse_body(&body)?;
        secret::refuse_inline("settings", &input.settings).map_err(ApiError::invalid)?;
        if !engine.has_driver(&input.driver) {
            return Err(ApiError::invalid(format!(
                "no driver named `{}` is configured",
                input.driver
            )));
        }
        let deployment = Deployment {
            id: new_id("dep"),
            version: 1,
            name: input.name,
            driver: input.driver,
            connections: input.connections,
            settings: input.settings,
            created_at: now(),
        };
        engine.transact(&who.context(), None, |state| {
            if let Some(missing) = deployment
                .connections
                .iter()
                .find(|id| !state.connections.contains_key(*id))
            {
                return Err(ApiError::invalid(format!("no connection `{missing}`")));
            }
            Ok((
                vec![Change::DeploymentCreated {
                    deployment: deployment.clone(),
                }],
                (),
            ))
        })?;
        Ok((StatusCode::CREATED, to_value(&deployment)))
    };
    idempotent(&app.engine, &who, &headers, &path, &body, work).await
}

async fn get_deployment(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    app.engine
        .read(|state| state.deployments.get(&id).map(resource))
        .ok_or_else(|| ApiError::not_found("deployment"))
}

// ---- assessments ----------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAssessment {
    deployment: String,
}

async fn list_assessments(
    State(app): State<AppState>,
    who: Authenticated,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    Ok(Json(app.engine.read(
        |state| json!({"items": state.assessments.values().collect::<Vec<_>>()}),
    )))
}

async fn create_assessment(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/assessments");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let input: NewAssessment = parse_body(&body)?;
        let assessment = engine
            .assess(&who.context(), &who.principal, &input.deployment)
            .await?;
        Ok((StatusCode::CREATED, to_value(&assessment)))
    };
    Box::pin(idempotent(&app.engine, &who, &headers, &path, &body, work)).await
}

async fn get_assessment(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    app.engine
        .read(|state| state.assessments.get(&id).map(resource))
        .ok_or_else(|| ApiError::not_found("assessment"))
}

// ---- operations -----------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewOperation {
    deployment: String,
    action: String,
    #[serde(default)]
    params: Value,
}

async fn list_operations(
    State(app): State<AppState>,
    who: Authenticated,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    Ok(Json(app.engine.read(|state| {
        let mut items: Vec<_> = state.operations.values().collect();
        items.sort_by_key(|op| std::cmp::Reverse(op.created_at));
        json!({"items": items})
    })))
}

async fn create_operation(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/operations");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let input: NewOperation = parse_body(&body)?;
        let operation = engine
            .create_operation(
                &who.context(),
                &who.principal,
                &input.deployment,
                &input.action,
                input.params,
            )
            .await?;
        Ok((StatusCode::CREATED, to_value(&operation)))
    };
    Box::pin(idempotent(&app.engine, &who, &headers, &path, &body, work)).await
}

async fn get_operation(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    app.engine
        .read(|state| state.operations.get(&id).map(resource))
        .ok_or_else(|| ApiError::not_found("operation"))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ActionBody {
    /// Settles an interrupted mutation the driver could not observe:
    /// `"applied"` or `"not_applied"`. Only meaningful with `:resume`.
    #[serde(default)]
    resolution: Option<String>,
}

async fn operation_action(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    Path(target): Path<String>,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/operations/{target}");
    let engine = Arc::clone(&app.engine);
    let work = async {
        who.require(Role::Operator)?;
        let (id, verb) = target
            .rsplit_once(':')
            .and_then(|(id, verb)| Some((id, Verb::parse(verb)?)))
            .ok_or_else(|| ApiError::not_found("operation action"))?;
        let version = if_match(&headers)?;
        let input: ActionBody = parse_body(&body)?;
        let resolution = match input.resolution.as_deref() {
            None => None,
            Some("applied") => Some(true),
            Some("not_applied") => Some(false),
            Some(_) => {
                return Err(ApiError::invalid(
                    "resolution is `applied` or `not_applied`",
                ));
            }
        };
        if resolution.is_some() && verb != Verb::Resume {
            return Err(ApiError::invalid("a resolution goes with :resume"));
        }
        let operation = engine.act(&who.context(), id, version, verb, resolution)?;
        Ok((StatusCode::OK, to_value(&operation)))
    };
    idempotent(&app.engine, &who, &headers, &path, &body, work).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalBody {
    step: usize,
    #[serde(default)]
    confirmation: Option<String>,
}

async fn approve(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let path = format!("{PREFIX}/operations/{id}/approvals");
    let engine = Arc::clone(&app.engine);
    let work = async {
        let version = if_match(&headers)?;
        let input: ApprovalBody = parse_body(&body)?;
        let operation = engine.approve(
            &who.context(),
            &who.principal,
            &id,
            version,
            input.step,
            input.confirmation.as_deref(),
        )?;
        Ok((StatusCode::OK, to_value(&operation)))
    };
    idempotent(&app.engine, &who, &headers, &path, &body, work).await
}

/// One audit-safe rendering of an event, shared by `/audit` and the SSE
/// stream so the two can never disagree about what is shown.
fn render(event: &Event) -> Option<Value> {
    let mut change = event.change.audit_view()?;
    secret::redact(&mut change);
    Some(json!({
        "seq": event.seq,
        "at": event.at,
        "actor": event.actor,
        "request": event.request,
        "operation": event.operation,
        "change": change,
    }))
}

fn ends_stream(event: &Event) -> bool {
    matches!(&event.change, Change::OperationState { state, .. } if state.is_terminal())
}

/// Server-sent events for one operation: the history so far (after
/// `Last-Event-ID`, so a reconnecting client misses nothing), then live
/// changes, ending once the operation reaches a terminal state.
async fn operation_events(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    let after: u64 = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    // Subscribe before reading history, then skip anything already sent:
    // the other order loses events that land in between.
    let receiver = app.engine.subscribe();
    let (backlog, known) = app.engine.read(|state| {
        let backlog: Vec<Event> = state
            .events
            .iter()
            .filter(|event| event.seq > after && event.operation.as_deref() == Some(id.as_str()))
            .cloned()
            .collect();
        let terminal = state
            .operations
            .get(&id)
            .map(|operation| operation.state.is_terminal());
        (backlog, terminal)
    });
    let Some(terminal) = known else {
        return Err(ApiError::not_found("operation"));
    };
    // A terminal state is final, so nothing more will come. That holds
    // for a client reconnecting past the last event, whose backlog is
    // empty: it is told the stream is over instead of waiting forever.
    let done = terminal || backlog.iter().any(ends_stream);
    let last = backlog.last().map_or(after, |event| event.seq);
    let to_sse = |event: &Event| {
        render(event).map(|data| {
            axum::response::sse::Event::default()
                .id(event.seq.to_string())
                .event("change")
                .data(data.to_string())
        })
    };
    let history = futures_util::stream::iter(
        backlog
            .iter()
            .filter_map(to_sse)
            .map(Ok::<_, Infallible>)
            .collect::<Vec<_>>(),
    );
    let live = futures_util::stream::unfold(
        (receiver, last, done, id),
        move |(mut receiver, mut last, done, id)| async move {
            if done {
                return None;
            }
            loop {
                // A slow reader that fell behind the channel gets an
                // error here; ending the stream makes the client reconnect
                // with Last-Event-ID and replay from the journal.
                let Ok(event) = receiver.recv().await else {
                    return None;
                };
                if event.seq <= last || event.operation.as_deref() != Some(id.as_str()) {
                    continue;
                }
                last = event.seq;
                let finished = ends_stream(&event);
                if let Some(sse) = to_sse(&event) {
                    return Some((Ok(sse), (receiver, last, finished, id)));
                }
            }
        },
    );
    Ok(Sse::new(history.chain(live))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

// ---- artifacts, policy, audit ---------------------------------------------

async fn get_artifact(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    let (artifact, content) = app.engine.artifact(&id).await?;
    let mut body = to_value(&artifact);
    body["content"] = content;
    let mut response = with_etag(StatusCode::OK, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn get_policy(
    State(app): State<AppState>,
    who: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    who.require(Role::Viewer)?;
    if id != "default" {
        return Err(ApiError::not_found("policy"));
    }
    Ok(resource(&app.engine.read(crate::engine::State::policy)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBody {
    approval_risks: std::collections::BTreeSet<Risk>,
    typed_confirmation: bool,
}

/// Policy is changed with `PUT` and `If-Match` rather than `POST`: the
/// whole document is replaced, so a repeat is naturally idempotent.
async fn put_policy(
    State(app): State<AppState>,
    who: Authenticated,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    who.require(Role::Approver)?;
    if id != "default" {
        return Err(ApiError::not_found("policy"));
    }
    let version = if_match(&headers)?;
    let input: PolicyBody = parse_body(&body)?;
    let policy = app.engine.transact(&who.context(), None, |state| {
        let current = state.policy();
        check_version(current.version, version)?;
        let policy = Policy {
            id: current.id,
            version: current.version + 1,
            approval_risks: input.approval_risks,
            typed_confirmation: input.typed_confirmation,
        };
        Ok((
            vec![Change::PolicyUpdated {
                policy: policy.clone(),
            }],
            policy,
        ))
    })?;
    Ok(resource(&policy))
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    after: u64,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    operation: Option<String>,
}

async fn audit(
    State(app): State<AppState>,
    who: Authenticated,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    who.require(Role::Viewer)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(app.engine.read(|state| {
        let mut next = query.after;
        let events: Vec<Value> = state
            .events
            .iter()
            .filter(|event| event.seq > query.after)
            .filter(|event| query.operation.is_none() || event.operation == query.operation)
            .filter_map(|event| {
                next = event.seq;
                render(event)
            })
            .take(limit)
            .collect();
        json!({"events": events, "next": next})
    })))
}

/// Requests outside every route: one JSON 404, the same shape as every
/// other error, rather than axum's empty body.
pub async fn fallback(method: Method) -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("no {method} route here"),
    )
}
