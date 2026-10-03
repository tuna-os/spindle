//! The durable operation engine.
//!
//! State lives in memory and is rebuilt from the [journal](crate::journal)
//! at startup; every change goes to the journal first. The engine is the
//! only writer, behind one mutex that is never held across an `.await`,
//! so a check and the change it guards ("no lease on this deployment" →
//! "take the lease") are one atomic step.
//!
//! An operation runs as a task that walks its steps. Before a step's
//! driver call the task records `step_started`; after it, the checkpoint.
//! That pair is what makes a restart safe:
//!
//! - a step recorded as completed is never run again;
//! - a mutating step recorded as started but not finished is *observed*,
//!   and executed only if the driver reports its effect absent;
//! - if the driver cannot tell, the operation stops in
//!   `attention_required` for a person to decide.
//!
//! Exactly one task runs an operation. The set of running operations is
//! guarded by the same mutex as the state, and a runner leaves the set in
//! the same critical section as the commit that ends its run, so a
//! `:resume` racing a runner's exit cannot leave an operation `running`
//! with nobody running it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::driver::{Driver, DriverRequest, Evidence, Observation};
use crate::error::ApiError;
use crate::journal::{Change, Event, Journal};
use crate::model::{
    Actor, Approval, Artifact, Assessment, Connection, Deployment, Lease, Millis, Operation,
    OperationState, Policy, Principal, Probe, Role, Step, StepState,
};
use crate::secret;

/// How long a stored idempotent response is replayed. A client retrying
/// after a dropped connection does so within seconds; a day is generous
/// and keeps the table from growing without bound.
const IDEMPOTENCY_WINDOW_MS: Millis = 24 * 60 * 60 * 1000;

#[must_use]
pub fn now() -> Millis {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A fresh identifier: a type prefix and 128 random bits.
///
/// # Panics
///
/// If the OS entropy source is unreadable; an identifier that might
/// collide is worse than stopping.
#[must_use]
pub fn new_id(prefix: &str) -> String {
    use rand::TryRng as _;
    let mut bytes = [0_u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("the OS entropy source must be readable to mint identifiers");
    let mut id = String::with_capacity(prefix.len() + 33);
    id.push_str(prefix);
    id.push('_');
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Clone, Debug)]
pub struct Session {
    pub principal: Principal,
    pub expires_at: Millis,
}

#[derive(Clone, Debug)]
pub struct StoredResponse {
    pub fingerprint: String,
    pub status: u16,
    pub body: Value,
    pub at: Millis,
}

/// Everything the journal rebuilds.
#[derive(Default)]
pub struct State {
    pub connections: BTreeMap<String, Connection>,
    pub deployments: BTreeMap<String, Deployment>,
    pub assessments: BTreeMap<String, Assessment>,
    pub operations: BTreeMap<String, Operation>,
    pub artifacts: BTreeMap<String, Artifact>,
    pub policies: BTreeMap<String, Policy>,
    pub leases: BTreeMap<String, Lease>,
    pub sessions: HashMap<String, Session>,
    pub idempotency: HashMap<(String, String), StoredResponse>,
    pub events: Vec<Event>,
}

impl State {
    fn operation_mut(&mut self, event: &Event) -> Option<&mut Operation> {
        let operation = self.operations.get_mut(event.operation.as_deref()?)?;
        operation.version += 1;
        operation.updated_at = event.at;
        Some(operation)
    }

    fn step_mut(&mut self, event: &Event, index: usize) -> Option<&mut Step> {
        self.operation_mut(event)?.steps.get_mut(index)
    }

    #[allow(clippy::too_many_lines)] // one arm per change; splitting hides the mapping
    fn apply(&mut self, event: &Event) {
        match &event.change {
            Change::SessionOpened {
                session_hash,
                principal,
                expires_at,
            } => {
                self.sessions.insert(
                    session_hash.clone(),
                    Session {
                        principal: principal.clone(),
                        expires_at: *expires_at,
                    },
                );
            }
            Change::SessionClosed { session_hash } => {
                self.sessions.remove(session_hash);
            }
            Change::IdempotencyStored {
                subject,
                key,
                fingerprint,
                status,
                body,
            } => {
                self.idempotency.insert(
                    (subject.clone(), key.clone()),
                    StoredResponse {
                        fingerprint: fingerprint.clone(),
                        status: *status,
                        body: body.clone(),
                        at: event.at,
                    },
                );
            }
            Change::ConnectionCreated { connection } => {
                self.connections
                    .insert(connection.id.clone(), connection.clone());
            }
            Change::ConnectionProbed { id, probe } => {
                if let Some(connection) = self.connections.get_mut(id) {
                    connection.version += 1;
                    connection.last_probe = Some(probe.clone());
                }
            }
            Change::DeploymentCreated { deployment } => {
                self.deployments
                    .insert(deployment.id.clone(), deployment.clone());
            }
            Change::PolicyUpdated { policy } => {
                self.policies.insert(policy.id.clone(), policy.clone());
            }
            Change::AssessmentRecorded { assessment } => {
                self.assessments
                    .insert(assessment.id.clone(), assessment.clone());
            }
            Change::OperationCreated { operation } => {
                self.operations
                    .insert(operation.id.clone(), operation.clone());
            }
            Change::LeaseAcquired {
                deployment,
                operation,
            } => {
                self.leases.insert(
                    deployment.clone(),
                    Lease {
                        deployment: deployment.clone(),
                        operation: operation.clone(),
                        acquired_at: event.at,
                    },
                );
            }
            Change::LeaseReleased {
                deployment,
                operation,
            } => {
                if self
                    .leases
                    .get(deployment)
                    .is_some_and(|lease| &lease.operation == operation)
                {
                    self.leases.remove(deployment);
                }
            }
            Change::OperationState { state, reason } => {
                if let Some(operation) = self.operation_mut(event) {
                    operation.state = *state;
                    operation.reason.clone_from(reason);
                    if matches!(state, OperationState::Paused | OperationState::Running) {
                        operation.pause_requested = false;
                    }
                }
            }
            Change::PauseRequested => {
                if let Some(operation) = self.operation_mut(event) {
                    operation.pause_requested = true;
                }
            }
            Change::CancelRequested => {
                if let Some(operation) = self.operation_mut(event) {
                    operation.cancel_requested = true;
                }
            }
            Change::StepStarted { step } => {
                if let Some(step) = self.step_mut(event, *step) {
                    step.state = StepState::Running;
                    step.attempts += 1;
                    step.started_at = Some(event.at);
                    step.error = None;
                }
            }
            Change::StepObserved { step, applied } => {
                if let Some(step) = self.step_mut(event, *step)
                    && !applied
                {
                    step.state = StepState::Pending;
                }
            }
            Change::StepCompleted {
                step,
                checkpoint,
                artifacts,
            } => {
                if let Some(step) = self.step_mut(event, *step) {
                    step.state = StepState::Completed;
                    step.checkpoint = checkpoint.clone();
                    step.artifacts.extend(artifacts.iter().cloned());
                    step.finished_at = Some(event.at);
                    step.error = None;
                }
            }
            Change::StepFailed { step, error } => {
                if let Some(step) = self.step_mut(event, *step) {
                    step.state = StepState::Failed;
                    step.error = Some(error.clone());
                    step.finished_at = Some(event.at);
                }
            }
            Change::StepCompensationStarted { step } => {
                if let Some(step) = self.step_mut(event, *step) {
                    step.state = StepState::Compensating;
                }
            }
            Change::StepCompensated { step } => {
                if let Some(step) = self.step_mut(event, *step) {
                    step.state = StepState::Compensated;
                    step.finished_at = Some(event.at);
                }
            }
            Change::ApprovalRecorded { approval } => {
                if let Some(operation) = self.operation_mut(event) {
                    operation.approvals.push(approval.clone());
                }
            }
            Change::ArtifactStored { artifact } => {
                self.artifacts.insert(artifact.id.clone(), artifact.clone());
            }
            Change::ArtifactExpired { id } => {
                if let Some(artifact) = self.artifacts.get_mut(id) {
                    artifact.expired = true;
                    artifact.version += 1;
                }
            }
        }
        self.events.push(event.clone());
    }

    #[must_use]
    pub fn policy(&self) -> Policy {
        self.policies
            .get("default")
            .cloned()
            .unwrap_or_else(Policy::default_policy)
    }
}

struct Inner {
    journal: Journal,
    state: State,
    /// Operations a runner task currently owns.
    running: HashSet<String>,
    /// Idempotency keys whose first request has not answered yet.
    in_flight: HashSet<(String, String)>,
}

/// Who and why, for the audit trail.
#[derive(Clone, Debug)]
pub struct Context {
    pub actor: Actor,
    pub request: Option<String>,
}

impl Context {
    #[must_use]
    pub fn system() -> Self {
        Context {
            actor: Actor::System,
            request: None,
        }
    }
    #[must_use]
    pub fn of(principal: &Principal, request: Option<String>) -> Self {
        Context {
            actor: Actor::Principal {
                subject: principal.subject.clone(),
            },
            request,
        }
    }
}

pub struct Engine {
    inner: Mutex<Inner>,
    drivers: BTreeMap<String, Arc<dyn Driver>>,
    data_dir: PathBuf,
    artifact_ttl_ms: Millis,
    probe_timeout: Duration,
    events: broadcast::Sender<Event>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    http: reqwest::Client,
}

/// What a caller asks a running or stopped operation to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Pause,
    Resume,
    Cancel,
    Rollback,
}

impl Verb {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pause" => Some(Self::Pause),
            "resume" => Some(Self::Resume),
            "cancel" => Some(Self::Cancel),
            "rollback" => Some(Self::Rollback),
            _ => None,
        }
    }
}

impl Engine {
    /// Open the journal in `data_dir`, rebuild state, and restart every
    /// operation that was running when the process stopped.
    ///
    /// # Errors
    ///
    /// When the journal cannot be read.
    pub fn open(
        data_dir: PathBuf,
        drivers: BTreeMap<String, Arc<dyn Driver>>,
        artifact_ttl: Duration,
        probe_timeout: Duration,
    ) -> std::io::Result<Arc<Self>> {
        let (journal, events) = Journal::open(&data_dir)?;
        std::fs::create_dir_all(data_dir.join("artifacts"))?;
        let mut state = State::default();
        for event in &events {
            state.apply(event);
        }
        let (sender, _) = broadcast::channel(1024);
        let http = reqwest::Client::builder()
            .timeout(probe_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(std::io::Error::other)?;
        let engine = Arc::new(Engine {
            inner: Mutex::new(Inner {
                journal,
                state,
                running: HashSet::new(),
                in_flight: HashSet::new(),
            }),
            drivers,
            data_dir,
            artifact_ttl_ms: u64::try_from(artifact_ttl.as_millis()).unwrap_or(u64::MAX),
            probe_timeout,
            events: sender,
            tasks: Mutex::new(Vec::new()),
            http,
        });
        let resumable: Vec<String> = engine
            .lock()
            .state
            .operations
            .values()
            .filter(|operation| operation.state.is_active())
            .map(|operation| operation.id.clone())
            .collect();
        for id in resumable {
            tracing::info!(operation = %id, "resuming an operation interrupted by a restart");
            engine.spawn_runner(&id);
        }
        Ok(engine)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a panic mid-apply. The journal on disk is
        // still the truth; carrying on with the in-memory copy is what the
        // next restart would do anyway after replay.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read the state.
    pub fn read<T>(&self, read: impl FnOnce(&State) -> T) -> T {
        read(&self.lock().state)
    }

    /// Check and change in one critical section: `decide` sees the state
    /// and returns the changes to record (or refuses), and nothing else can
    /// change the state in between.
    ///
    /// # Errors
    ///
    /// Whatever `decide` refuses with, or a journal failure.
    pub fn transact<T>(
        &self,
        context: &Context,
        operation: Option<&str>,
        decide: impl FnOnce(&State) -> Result<(Vec<Change>, T), ApiError>,
    ) -> Result<T, ApiError> {
        let mut inner = self.lock();
        let (changes, value) = decide(&inner.state)?;
        Self::record(&mut inner, &self.events, context, operation, changes)?;
        Ok(value)
    }

    fn record(
        inner: &mut Inner,
        sender: &broadcast::Sender<Event>,
        context: &Context,
        operation: Option<&str>,
        changes: Vec<Change>,
    ) -> Result<(), ApiError> {
        if changes.is_empty() {
            return Ok(());
        }
        let events = inner.journal.append(
            now(),
            &context.actor,
            context.request.as_deref(),
            operation,
            changes,
        )?;
        for event in events {
            inner.state.apply(&event);
            // Nobody listening is the common case, not an error.
            let _ = sender.send(event);
        }
        Ok(())
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    #[must_use]
    pub fn has_driver(&self, name: &str) -> bool {
        self.drivers.contains_key(name)
    }

    fn driver(&self, name: &str) -> Result<Arc<dyn Driver>, ApiError> {
        self.drivers
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::invalid(format!("no driver named `{name}` is configured")))
    }

    /// Stop every runner task without recording anything: what a crash
    /// does. Tests use it to prove restart safety; `main` never calls it.
    pub fn abort_runners(&self) {
        for handle in self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            handle.abort();
        }
        self.lock().running.clear();
    }

    // ---- idempotency -------------------------------------------------

    /// Claim an idempotency key. `Ok(Some(..))` is a stored response to
    /// replay; `Ok(None)` means the caller should do the work and then call
    /// [`Engine::finish_idempotent`].
    ///
    /// # Errors
    ///
    /// When the key was used for a different request, or its first use is
    /// still in progress.
    pub fn begin_idempotent(
        &self,
        subject: &str,
        key: &str,
        fingerprint: &str,
    ) -> Result<Option<StoredResponse>, ApiError> {
        let mut inner = self.lock();
        let slot = (subject.to_owned(), key.to_owned());
        if let Some(stored) = inner.state.idempotency.get(&slot)
            && now().saturating_sub(stored.at) < IDEMPOTENCY_WINDOW_MS
        {
            if stored.fingerprint != fingerprint {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "idempotency_key_reused",
                    "this Idempotency-Key was already used for a different request",
                ));
            }
            return Ok(Some(stored.clone()));
        }
        if !inner.in_flight.insert(slot) {
            return Err(ApiError::conflict(
                "idempotency_in_progress",
                "a request with this Idempotency-Key is still being processed",
            ));
        }
        Ok(None)
    }

    /// Record the response to a claimed key. Error responses that leave no
    /// state behind (4xx) are stored too: a retry of a refused request is
    /// refused the same way rather than being re-judged against new state.
    /// A 5xx is not stored, so a retry can succeed once the fault clears.
    pub fn finish_idempotent(
        &self,
        context: &Context,
        subject: &str,
        key: &str,
        fingerprint: &str,
        status: u16,
        body: &Value,
    ) {
        let mut inner = self.lock();
        inner
            .in_flight
            .remove(&(subject.to_owned(), key.to_owned()));
        if status >= 500 {
            return;
        }
        let change = Change::IdempotencyStored {
            subject: subject.to_owned(),
            key: key.to_owned(),
            fingerprint: fingerprint.to_owned(),
            status,
            body: body.clone(),
        };
        if let Err(error) = Self::record(&mut inner, &self.events, context, None, vec![change]) {
            tracing::warn!(?error, "an idempotent response could not be stored");
        }
    }

    // ---- connections, deployments, assessments -----------------------

    /// Probe a connection's homeserver. Unreachable is a recorded result.
    ///
    /// # Errors
    ///
    /// When the connection does not exist, or the probe cannot be recorded.
    pub async fn probe(&self, context: &Context, id: &str) -> Result<Connection, ApiError> {
        let base = self
            .read(|state| state.connections.get(id).map(|c| c.base_url.clone()))
            .ok_or_else(|| ApiError::not_found("connection"))?;
        let started = Instant::now();
        // `/versions` needs no credential, so a probe never resolves one:
        // reachability is answerable without touching a secret.
        let url = format!("{}/_matrix/client/versions", base.trim_end_matches('/'));
        let result = self.http.get(&url).send().await;
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let probe = match result {
            Ok(response) => Probe {
                at: now(),
                reachable: response.status().is_success(),
                status: Some(response.status().as_u16()),
                detail: None,
                latency_ms,
            },
            Err(error) => Probe {
                at: now(),
                reachable: false,
                status: None,
                detail: Some(if error.is_timeout() {
                    format!("no answer within {}s", self.probe_timeout.as_secs())
                } else if error.is_connect() {
                    "connection refused or unreachable".to_owned()
                } else {
                    "request failed".to_owned()
                }),
                latency_ms,
            },
        };
        self.transact(context, None, |state| {
            if !state.connections.contains_key(id) {
                return Err(ApiError::not_found("connection"));
            }
            Ok((
                vec![Change::ConnectionProbed {
                    id: id.to_owned(),
                    probe,
                }],
                (),
            ))
        })?;
        self.read(|state| state.connections.get(id).cloned())
            .ok_or_else(|| ApiError::not_found("connection"))
    }

    /// Ask the deployment's driver for findings and record them.
    ///
    /// # Errors
    ///
    /// When the deployment or its driver is missing, or the driver fails.
    pub async fn assess(
        &self,
        context: &Context,
        principal: &Principal,
        deployment_id: &str,
    ) -> Result<Assessment, ApiError> {
        let deployment = self
            .read(|state| state.deployments.get(deployment_id).cloned())
            .ok_or_else(|| ApiError::not_found("deployment"))?;
        let driver = self.driver(&deployment.driver)?;
        let request = DriverRequest {
            deployment,
            action: "assess".to_owned(),
            params: Value::Null,
            operation: None,
            step: None,
            checkpoints: Vec::new(),
        };
        let mut findings = driver
            .assess(request)
            .await
            .map_err(|error| ApiError::new(StatusCode::BAD_GATEWAY, "driver_failed", error))?;
        for finding in &mut findings {
            let mut summary = Value::String(std::mem::take(&mut finding.summary));
            secret::redact(&mut summary);
            summary
                .as_str()
                .unwrap_or_default()
                .clone_into(&mut finding.summary);
        }
        let assessment = Assessment {
            id: new_id("asm"),
            version: 1,
            deployment: deployment_id.to_owned(),
            findings,
            requested_by: principal.subject.clone(),
            created_at: now(),
        };
        self.transact(context, None, |_| {
            Ok((
                vec![Change::AssessmentRecorded {
                    assessment: assessment.clone(),
                }],
                (),
            ))
        })?;
        Ok(assessment)
    }

    // ---- operations ---------------------------------------------------

    /// Plan an operation with the deployment's driver, take the
    /// deployment's lease, and start it.
    ///
    /// # Errors
    ///
    /// 404 for an unknown deployment, 409 when another operation holds the
    /// lease, 422 for parameters the driver or the secret check refuses.
    pub async fn create_operation(
        self: &Arc<Self>,
        context: &Context,
        principal: &Principal,
        deployment_id: &str,
        action: &str,
        params: Value,
    ) -> Result<Operation, ApiError> {
        secret::refuse_inline("params", &params).map_err(ApiError::invalid)?;
        let deployment = self.read(|state| {
            let deployment = state
                .deployments
                .get(deployment_id)
                .cloned()
                .ok_or_else(|| ApiError::not_found("deployment"))?;
            lease_free(state, deployment_id)?;
            Ok::<_, ApiError>(deployment)
        })?;
        let driver = self.driver(&deployment.driver)?;
        // Planning is read-only, so it runs outside the lock; the lease is
        // checked again below, atomically with taking it.
        let specs = driver
            .plan(DriverRequest {
                deployment,
                action: action.to_owned(),
                params: params.clone(),
                operation: None,
                step: None,
                checkpoints: Vec::new(),
            })
            .await
            .map_err(ApiError::invalid)?;
        if specs.is_empty() {
            return Err(ApiError::invalid(format!(
                "action `{action}` planned no steps"
            )));
        }
        let at = now();
        let operation = Operation {
            id: new_id("op"),
            version: 1,
            deployment: deployment_id.to_owned(),
            action: action.to_owned(),
            params,
            state: OperationState::Running,
            requested_by: principal.subject.clone(),
            steps: specs
                .into_iter()
                .enumerate()
                .map(|(index, spec)| Step {
                    index,
                    spec,
                    state: StepState::Pending,
                    attempts: 0,
                    checkpoint: Value::Null,
                    artifacts: Vec::new(),
                    error: None,
                    started_at: None,
                    finished_at: None,
                })
                .collect(),
            approvals: Vec::new(),
            pause_requested: false,
            cancel_requested: false,
            reason: None,
            created_at: at,
            updated_at: at,
        };
        let id = operation.id.clone();
        self.transact(context, Some(&id), |state| {
            lease_free(state, deployment_id)?;
            Ok((
                vec![
                    Change::OperationCreated {
                        operation: operation.clone(),
                    },
                    Change::LeaseAcquired {
                        deployment: deployment_id.to_owned(),
                        operation: id.clone(),
                    },
                ],
                (),
            ))
        })?;
        self.spawn_runner(&id);
        Ok(operation)
    }

    /// Pause, resume, cancel or roll back. `version` is the caller's
    /// `If-Match`; `resolution` settles an interrupted mutation whose
    /// outcome the driver could not observe (`true`: it took effect).
    ///
    /// # Errors
    ///
    /// 412 on a stale version, 409 when the verb does not apply to the
    /// operation's state or rollback would cross a write boundary.
    pub fn act(
        self: &Arc<Self>,
        context: &Context,
        id: &str,
        version: u64,
        verb: Verb,
        resolution: Option<bool>,
    ) -> Result<Operation, ApiError> {
        let spawn = self.transact(context, Some(id), |state| {
            let operation = state
                .operations
                .get(id)
                .ok_or_else(|| ApiError::not_found("operation"))?;
            check_version(operation.version, version)?;
            decide_verb(operation, verb, resolution)
        })?;
        if spawn {
            self.spawn_runner(id);
        }
        self.read(|state| state.operations.get(id).cloned())
            .ok_or_else(|| ApiError::not_found("operation"))
    }

    /// Approve the step an operation is waiting on.
    ///
    /// # Errors
    ///
    /// 403 when the approver requested the operation or lacks the role,
    /// 409 when nothing is awaiting approval, 422 on a wrong confirmation.
    pub fn approve(
        self: &Arc<Self>,
        context: &Context,
        principal: &Principal,
        id: &str,
        version: u64,
        step: usize,
        confirmation: Option<&str>,
    ) -> Result<Operation, ApiError> {
        if !principal.has(Role::Approver) {
            return Err(ApiError::forbidden("approving needs the approver role"));
        }
        self.transact(context, Some(id), |state| {
            let operation = state
                .operations
                .get(id)
                .ok_or_else(|| ApiError::not_found("operation"))?;
            check_version(operation.version, version)?;
            if operation.state != OperationState::AwaitingApproval {
                return Err(ApiError::conflict(
                    "not_awaiting_approval",
                    "the operation is not waiting for an approval",
                ));
            }
            let pending = next_step(operation)
                .ok_or_else(|| ApiError::conflict("not_awaiting_approval", "no step is waiting"))?;
            if pending.index != step {
                return Err(ApiError::conflict(
                    "wrong_step",
                    format!("step {} is the one waiting for approval", pending.index),
                ));
            }
            if operation.requested_by == principal.subject {
                return Err(ApiError::forbidden(
                    "an operation's requester cannot approve it; approval must be independent",
                ));
            }
            if state.policy().typed_confirmation {
                let expected = format!("{id}/{}", pending.spec.name);
                if confirmation != Some(expected.as_str()) {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "confirmation_mismatch",
                        format!("type `{expected}` to confirm this step"),
                    ));
                }
            }
            Ok((
                vec![
                    Change::ApprovalRecorded {
                        approval: Approval {
                            step,
                            approver: principal.subject.clone(),
                            at: now(),
                        },
                    },
                    Change::OperationState {
                        state: OperationState::Running,
                        reason: None,
                    },
                ],
                (),
            ))
        })?;
        self.spawn_runner(id);
        self.read(|state| state.operations.get(id).cloned())
            .ok_or_else(|| ApiError::not_found("operation"))
    }

    // ---- the runner ---------------------------------------------------

    fn spawn_runner(self: &Arc<Self>, id: &str) {
        if !self.lock().running.insert(id.to_owned()) {
            return;
        }
        let engine = Arc::clone(self);
        let id = id.to_owned();
        let handle = tokio::spawn(async move {
            Box::pin(engine.run(&id)).await;
        });
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    /// Record changes for a running operation. `exit` also releases the
    /// runner's claim in the same critical section (see the module docs).
    fn runner_commit(&self, id: &str, changes: Vec<Change>, exit: bool) -> bool {
        let mut inner = self.lock();
        let result = Self::record(
            &mut inner,
            &self.events,
            &Context::system(),
            Some(id),
            changes,
        );
        if exit || result.is_err() {
            inner.running.remove(id);
        }
        if let Err(error) = result {
            // Without the journal there is no checkpoint to stand on; stop
            // and let a restart replay what was recorded.
            tracing::error!(operation = %id, ?error, "runner stopped: journal write failed");
            return false;
        }
        !exit
    }

    async fn run(self: Arc<Self>, id: &str) {
        loop {
            let snapshot = self.read(|state| {
                let operation = state.operations.get(id)?.clone();
                let deployment = state.deployments.get(&operation.deployment)?.clone();
                Some((operation, deployment, state.policy()))
            });
            let Some((operation, deployment, policy)) = snapshot else {
                self.lock().running.remove(id);
                return;
            };
            let carry_on = match operation.state {
                OperationState::Running => {
                    Box::pin(self.forward(&operation, deployment, &policy)).await
                }
                OperationState::RollingBack => {
                    Box::pin(self.backward(&operation, deployment)).await
                }
                _ => {
                    self.lock().running.remove(id);
                    false
                }
            };
            if !carry_on {
                return;
            }
        }
    }

    fn release(
        operation: &Operation,
        state: OperationState,
        reason: Option<String>,
    ) -> Vec<Change> {
        // The lease goes first so that the terminal state is the last
        // event of an operation: an event stream can end on it.
        vec![
            Change::LeaseReleased {
                deployment: operation.deployment.clone(),
                operation: operation.id.clone(),
            },
            Change::OperationState { state, reason },
        ]
    }

    fn request_for(operation: &Operation, deployment: Deployment, step: &Step) -> DriverRequest {
        DriverRequest {
            deployment,
            action: operation.action.clone(),
            params: operation.params.clone(),
            operation: Some(operation.id.clone()),
            step: Some(step.clone()),
            checkpoints: operation.steps[..step.index]
                .iter()
                .map(|step| step.checkpoint.clone())
                .collect(),
        }
    }

    /// One forward move. Returns whether the runner should keep going.
    async fn forward(
        &self,
        operation: &Operation,
        deployment: Deployment,
        policy: &Policy,
    ) -> bool {
        let id = operation.id.as_str();
        if operation.cancel_requested {
            let changes = Self::release(
                operation,
                OperationState::Cancelled,
                Some("cancelled".to_owned()),
            );
            return self.runner_commit(id, changes, true);
        }
        if operation.pause_requested {
            let changes = vec![Change::OperationState {
                state: OperationState::Paused,
                reason: Some("paused".to_owned()),
            }];
            return self.runner_commit(id, changes, true);
        }
        let Some(step) = next_step(operation) else {
            return self.runner_commit(
                id,
                Self::release(operation, OperationState::Succeeded, None),
                true,
            );
        };
        let Ok(driver) = self.driver(&deployment.driver) else {
            let changes = vec![Change::OperationState {
                state: OperationState::AttentionRequired,
                reason: Some(format!("driver `{}` is not configured", deployment.driver)),
            }];
            return self.runner_commit(id, changes, true);
        };
        let request = Self::request_for(operation, deployment, step);
        if step.spec.mutation && matches!(step.state, StepState::Running | StepState::Failed) {
            return self.observe_interrupted(&*driver, id, step, request).await;
        }
        let approved = operation
            .approvals
            .iter()
            .any(|approval| approval.step == step.index);
        if policy.approval_risks.contains(&step.spec.risk) && !approved {
            let changes = vec![Change::OperationState {
                state: OperationState::AwaitingApproval,
                reason: Some(format!(
                    "step {} `{}` needs an independent approval",
                    step.index, step.spec.name
                )),
            }];
            return self.runner_commit(id, changes, true);
        }
        if !self.runner_commit(id, vec![Change::StepStarted { step: step.index }], false) {
            return false;
        }
        self.execute_step(&*driver, id, step, request).await
    }

    /// A mutation was started and never recorded as finished (or failed
    /// part-way): ask the driver what happened instead of running it again.
    async fn observe_interrupted(
        &self,
        driver: &dyn Driver,
        id: &str,
        step: &Step,
        request: DriverRequest,
    ) -> bool {
        let attention = |reason: String| {
            vec![Change::OperationState {
                state: OperationState::AttentionRequired,
                reason: Some(reason),
            }]
        };
        match driver.observe(request).await {
            Ok(Observation::Applied { checkpoint }) => {
                let changes = vec![
                    Change::StepObserved {
                        step: step.index,
                        applied: true,
                    },
                    Change::StepCompleted {
                        step: step.index,
                        checkpoint: redacted(checkpoint),
                        artifacts: Vec::new(),
                    },
                ];
                self.runner_commit(id, changes, false)
            }
            Ok(Observation::NotApplied) => {
                let changes = vec![Change::StepObserved {
                    step: step.index,
                    applied: false,
                }];
                self.runner_commit(id, changes, false)
            }
            Ok(Observation::Unknown { detail }) => {
                let reason = format!(
                    "step {} `{}` was interrupted and its effect is unknown{}",
                    step.index,
                    step.spec.name,
                    detail.map(|d| format!(": {d}")).unwrap_or_default()
                );
                self.runner_commit(id, attention(reason), true)
            }
            Err(error) => {
                let reason = format!(
                    "step {} could not be observed after an interruption: {error}",
                    step.index
                );
                self.runner_commit(id, attention(reason), true)
            }
        }
    }

    async fn execute_step(
        &self,
        driver: &dyn Driver,
        id: &str,
        step: &Step,
        request: DriverRequest,
    ) -> bool {
        match driver.execute(request).await {
            Ok(output) => match self.store_evidence(id, step.index, output.evidence).await {
                Ok((mut changes, artifacts)) => {
                    changes.push(Change::StepCompleted {
                        step: step.index,
                        checkpoint: redacted(output.checkpoint),
                        artifacts,
                    });
                    self.runner_commit(id, changes, false)
                }
                Err(error) => {
                    // The step ran but its evidence is not on disk. Leaving
                    // it `running` means a resume observes it rather than
                    // repeating it; a person decides whether to go on.
                    tracing::error!(operation = %id, %error, "step evidence was not stored");
                    let changes = vec![Change::OperationState {
                        state: OperationState::AttentionRequired,
                        reason: Some(format!(
                            "step {} ran but its evidence was not stored",
                            step.index
                        )),
                    }];
                    self.runner_commit(id, changes, true)
                }
            },
            Err(error) => {
                let mut message = Value::String(error);
                secret::redact(&mut message);
                let message = message.as_str().unwrap_or_default().to_owned();
                let changes = vec![
                    Change::StepFailed {
                        step: step.index,
                        error: message.clone(),
                    },
                    Change::OperationState {
                        state: OperationState::Failed,
                        reason: Some(format!("step {} failed: {message}", step.index)),
                    },
                ];
                self.runner_commit(id, changes, true)
            }
        }
    }

    /// One compensation move, newest mutation first.
    async fn backward(&self, operation: &Operation, deployment: Deployment) -> bool {
        let id = operation.id.as_str();
        let Some(step) = operation
            .steps
            .iter()
            .rev()
            .find(|step| step.spec.mutation && needs_compensation(step.state))
        else {
            let changes = Self::release(operation, OperationState::RolledBack, None);
            return self.runner_commit(id, changes, true);
        };
        let Ok(driver) = self.driver(&deployment.driver) else {
            let changes = vec![Change::OperationState {
                state: OperationState::AttentionRequired,
                reason: Some(format!("driver `{}` is not configured", deployment.driver)),
            }];
            return self.runner_commit(id, changes, true);
        };
        if !step.spec.compensable {
            let changes = vec![Change::OperationState {
                state: OperationState::AttentionRequired,
                reason: Some(format!("step {} cannot be undone", step.index)),
            }];
            return self.runner_commit(id, changes, true);
        }
        let started = vec![Change::StepCompensationStarted { step: step.index }];
        if step.state != StepState::Compensating && !self.runner_commit(id, started, false) {
            return false;
        }
        let request = Self::request_for(operation, deployment, step);
        match driver.compensate(request).await {
            Ok(()) => self.runner_commit(
                id,
                vec![Change::StepCompensated { step: step.index }],
                false,
            ),
            Err(error) => {
                let changes = vec![Change::OperationState {
                    state: OperationState::AttentionRequired,
                    reason: Some(format!("undoing step {} failed: {error}", step.index)),
                }];
                self.runner_commit(id, changes, true)
            }
        }
    }

    // ---- evidence -----------------------------------------------------

    async fn store_evidence(
        &self,
        operation: &str,
        step: usize,
        evidence: Vec<Evidence>,
    ) -> std::io::Result<(Vec<Change>, Vec<String>)> {
        let mut changes = Vec::new();
        let mut ids = Vec::new();
        for item in evidence {
            let mut content = item.content;
            secret::redact(&mut content);
            let bytes = serde_json::to_vec(&content)?;
            let id = new_id("art");
            let path = self.data_dir.join("artifacts").join(format!("{id}.json"));
            tokio::fs::write(&path, &bytes).await?;
            tokio::fs::File::open(&path).await?.sync_all().await?;
            let created_at = now();
            changes.push(Change::ArtifactStored {
                artifact: Artifact {
                    id: id.clone(),
                    version: 1,
                    operation: operation.to_owned(),
                    step,
                    name: item.name,
                    sha256: sha256_hex(&bytes),
                    created_at,
                    expires_at: created_at.saturating_add(self.artifact_ttl_ms),
                    expired: false,
                },
            });
            ids.push(id);
        }
        Ok((changes, ids))
    }

    /// An artifact's metadata and content, unless it has expired.
    ///
    /// # Errors
    ///
    /// 404 when unknown, 410 once expired.
    pub async fn artifact(&self, id: &str) -> Result<(Artifact, Value), ApiError> {
        let artifact = self
            .read(|state| state.artifacts.get(id).cloned())
            .ok_or_else(|| ApiError::not_found("artifact"))?;
        if artifact.expired || artifact.expires_at <= now() {
            return Err(ApiError::new(
                StatusCode::GONE,
                "expired",
                "this evidence has expired; its hash remains in the audit trail",
            ));
        }
        let path = self.data_dir.join("artifacts").join(format!("{id}.json"));
        let bytes = tokio::fs::read(&path).await?;
        if sha256_hex(&bytes) != artifact.sha256 {
            return Err(ApiError::internal(
                "evidence content does not match its recorded hash",
            ));
        }
        let content = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::internal("evidence is not JSON"))?;
        Ok((artifact, content))
    }

    /// Delete expired evidence content, keeping its record and hash.
    pub async fn sweep_artifacts(&self) {
        let at = now();
        let due: Vec<String> = self.read(|state| {
            state
                .artifacts
                .values()
                .filter(|artifact| !artifact.expired && artifact.expires_at <= at)
                .map(|artifact| artifact.id.clone())
                .collect()
        });
        for id in due {
            let path = self.data_dir.join("artifacts").join(format!("{id}.json"));
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(artifact = %id, %error, "expired evidence not deleted");
                    continue;
                }
            }
            let _ = self.transact(&Context::system(), None, |_| {
                Ok((vec![Change::ArtifactExpired { id: id.clone() }], ()))
            });
        }
    }
}

fn redacted(mut value: Value) -> Value {
    secret::redact(&mut value);
    value
}

fn needs_compensation(state: StepState) -> bool {
    matches!(
        state,
        StepState::Completed | StepState::Running | StepState::Failed | StepState::Compensating
    )
}

/// The first step not yet completed.
fn next_step(operation: &Operation) -> Option<&Step> {
    operation
        .steps
        .iter()
        .find(|step| step.state != StepState::Completed)
}

fn lease_free(state: &State, deployment: &str) -> Result<(), ApiError> {
    match state.leases.get(deployment) {
        Some(lease) => Err(ApiError::conflict(
            "lease_held",
            format!(
                "operation {} holds this deployment's lease; finish, cancel or roll it back first",
                lease.operation
            ),
        )),
        None => Ok(()),
    }
}

/// # Errors
/// 412 when the caller's version is not the current one.
pub fn check_version(current: u64, presented: u64) -> Result<(), ApiError> {
    if current == presented {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "stale",
            format!("the resource is at version {current}; reload before acting"),
        ))
    }
}

/// The changes a verb makes, and whether a runner must start.
fn decide_verb(
    operation: &Operation,
    verb: Verb,
    resolution: Option<bool>,
) -> Result<(Vec<Change>, bool), ApiError> {
    use OperationState as S;
    let refuse = || {
        Err(ApiError::conflict(
            "invalid_transition",
            format!("cannot {verb:?} an operation that is {:?}", operation.state).to_lowercase(),
        ))
    };
    match (verb, operation.state) {
        (Verb::Pause, S::Running) => Ok((vec![Change::PauseRequested], false)),
        (Verb::Pause, S::AwaitingApproval) => Ok((
            vec![Change::OperationState {
                state: S::Paused,
                reason: Some("paused".to_owned()),
            }],
            false,
        )),
        (Verb::Resume, S::Paused | S::Failed | S::AttentionRequired) => {
            let mut changes = Vec::new();
            if let Some(applied) = resolution {
                let step = next_step(operation).filter(|step| {
                    step.spec.mutation
                        && matches!(step.state, StepState::Running | StepState::Failed)
                });
                let Some(step) = step else {
                    return Err(ApiError::invalid("no interrupted mutation to resolve"));
                };
                changes.push(Change::StepObserved {
                    step: step.index,
                    applied,
                });
                if applied {
                    changes.push(Change::StepCompleted {
                        step: step.index,
                        checkpoint: json!({"resolved_by": "operator"}),
                        artifacts: Vec::new(),
                    });
                }
            }
            changes.push(Change::OperationState {
                state: S::Running,
                reason: None,
            });
            Ok((changes, true))
        }
        (Verb::Cancel, S::Running) => Ok((vec![Change::CancelRequested], false)),
        (Verb::Cancel, S::AwaitingApproval | S::Paused | S::Failed | S::AttentionRequired) => Ok((
            Engine::release(operation, S::Cancelled, Some("cancelled".to_owned())),
            false,
        )),
        (Verb::Rollback, S::AwaitingApproval | S::Paused | S::Failed | S::AttentionRequired) => {
            if let Some(boundary) = operation.steps.iter().find(|step| {
                step.spec.mutation && !step.spec.compensable && needs_compensation(step.state)
            }) {
                return Err(ApiError::conflict(
                    "write_boundary_crossed",
                    format!(
                        "step {} `{}` cannot be undone, so this operation cannot be rolled back; \
                         recovery is a new, forward operation",
                        boundary.index, boundary.spec.name
                    ),
                ));
            }
            Ok((
                vec![Change::OperationState {
                    state: S::RollingBack,
                    reason: Some("rollback requested".to_owned()),
                }],
                true,
            ))
        }
        _ => refuse(),
    }
}
