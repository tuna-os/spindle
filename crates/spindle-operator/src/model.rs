//! The operator's resources, as the API returns them and the journal
//! stores them.
//!
//! Every resource carries a `version` that the engine bumps on each change
//! it applies. The HTTP layer turns that into an `ETag`, and a mutation of
//! an existing resource must present it in `If-Match`: two operators
//! looking at the same paused operation cannot both act on what they saw.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::secret::SecretRef;

/// Milliseconds since the Unix epoch. One clock unit for every timestamp,
/// so that comparing an expiry with "now" never mixes units.
pub type Millis = u64;

/// What a principal may do. A principal holds a set of these; holding any
/// one of them includes viewing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read every view, resource and the audit trail.
    Viewer,
    /// Create connections, deployments, assessments and operations, and
    /// drive operations (pause, resume, cancel, rollback).
    Operator,
    /// Approve the high-risk steps of an operation someone else requested,
    /// and change policy.
    Approver,
}

/// Who did something. Recorded on every audit event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// `<issuer>#<sub>`: the OIDC subject is only unique per issuer.
    pub subject: String,
    /// A human-readable name from the ID token, for display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub roles: BTreeSet<Role>,
}

impl Principal {
    #[must_use]
    pub fn has(&self, role: Role) -> bool {
        role == Role::Viewer && !self.roles.is_empty() || self.roles.contains(&role)
    }
}

/// The actor on an audit event: a person, or the engine acting on a
/// person's earlier request (resuming after a restart, expiring evidence).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    Principal { subject: String },
    System,
}

/// A way to reach one homeserver or one control surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub version: u64,
    pub name: String,
    /// The base URL a probe reaches, e.g. `https://matrix.example.org`.
    pub base_url: String,
    /// The credential, by reference. The operator resolves it at the
    /// moment it calls out and never returns or records its value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe: Option<Probe>,
    pub created_at: Millis,
}

/// The outcome of one probe. A probe that cannot connect is a result, not
/// an error: answering "the homeserver is down" is the point of the
/// console while it is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Probe {
    pub at: Millis,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub latency_ms: u64,
}

/// One deployment the operator manages, and the driver that knows how to
/// discover and change it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub version: u64,
    pub name: String,
    pub driver: String,
    #[serde(default)]
    pub connections: Vec<String>,
    /// Driver-specific settings. Checked for inline secrets on the way in:
    /// a credential belongs in a `*_ref` field holding a [`SecretRef`].
    #[serde(default)]
    pub settings: Value,
    pub created_at: Millis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    /// A finding that blocks the operations it names. The driver decides
    /// which; the console shows it as a no-go, not as a warning.
    Blocker,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub summary: String,
}

/// A read-only look at a deployment, made by its driver.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub id: String,
    pub version: u64,
    pub deployment: String,
    pub findings: Vec<Finding>,
    pub requested_by: String,
    pub created_at: Millis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    High,
}

/// What a step of an operation is, as its driver planned it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepSpec {
    pub name: String,
    pub risk: Risk,
    /// Whether the step changes the deployment. Only mutations need the
    /// observe-before-retry rule after an interruption.
    pub mutation: bool,
    /// Whether the driver can undo the step. A completed mutation that
    /// cannot be undone is a boundary: past it, rollback is refused and
    /// recovery is a new, forward operation.
    pub compensable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    /// Started and not known to have finished. After a restart this is the
    /// state that must be observed, never blindly re-run.
    Running,
    Completed,
    Failed,
    Compensating,
    Compensated,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub index: usize,
    #[serde(flatten)]
    pub spec: StepSpec,
    pub state: StepState,
    pub attempts: u32,
    /// What the driver reported when the step completed. Fed back to the
    /// driver on later steps and on compensation.
    #[serde(default)]
    pub checkpoint: Value,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Millis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Millis>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Running,
    /// Stopped before a step whose risk the policy says needs approval.
    AwaitingApproval,
    Paused,
    /// The engine cannot tell whether an interrupted mutation happened.
    /// Someone has to look and say, through `:resume` with a resolution.
    AttentionRequired,
    Failed,
    RollingBack,
    Succeeded,
    Cancelled,
    RolledBack,
}

impl OperationState {
    /// Terminal states release the deployment's lease.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Cancelled | Self::RolledBack)
    }

    /// States in which the engine's runner owns the operation.
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::RollingBack)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub version: u64,
    pub deployment: String,
    /// The driver action, e.g. `quiesce` or `switch-traffic`.
    pub action: String,
    #[serde(default)]
    pub params: Value,
    pub state: OperationState,
    pub requested_by: String,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub pause_requested: bool,
    #[serde(default)]
    pub cancel_requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: Millis,
    pub updated_at: Millis,
}

/// One approver's sign-off on one step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub step: usize,
    pub approver: String,
    pub at: Millis,
}

/// Which steps need an independent approver, and how they confirm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub version: u64,
    /// Steps at these risks wait for approval before they run.
    pub approval_risks: BTreeSet<Risk>,
    /// When set, an approval must repeat the operation's id and the step's
    /// name, so nobody approves a destructive step by clicking through.
    pub typed_confirmation: bool,
}

impl Policy {
    #[must_use]
    pub fn default_policy() -> Self {
        Policy {
            id: "default".to_owned(),
            version: 1,
            approval_risks: BTreeSet::from([Risk::High]),
            typed_confirmation: true,
        }
    }
}

/// Evidence a step produced. The content lives in its own file so that it
/// can expire; the journal keeps only this record and the content's hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub version: u64,
    pub operation: String,
    pub step: usize,
    pub name: String,
    pub sha256: String,
    pub created_at: Millis,
    pub expires_at: Millis,
    #[serde(default)]
    pub expired: bool,
}

/// A deployment's lease: the one operation allowed to change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub deployment: String,
    pub operation: String,
    pub acquired_at: Millis,
}
