//! The driver interface: everything deployment-specific.
//!
//! The engine knows how to run an operation — order, checkpoints, leases,
//! approvals, compensation — and nothing about Kubernetes, systemd or
//! `PostgreSQL`. A driver knows one kind of deployment and nothing about
//! durability. The contract between them is five calls:
//!
//! - `plan`: turn an action and its parameters into steps. Read-only.
//! - `assess`: report findings about the deployment. Read-only.
//! - `execute`: perform one step and return a checkpoint and evidence.
//! - `observe`: after an interruption, say whether a step's effect is
//!   already in place. The engine calls this instead of re-running a
//!   mutation whose outcome it never recorded.
//! - `compensate`: undo one completed, compensable step. Must be
//!   idempotent, because an interrupted compensation is retried.
//!
//! [`ExecDriver`] speaks this contract to an external program over
//! stdin/stdout JSON, which is how a driver written in another language
//! (the ESS/Kubernetes driver of #460 is Python) plugs in without the
//! operator linking it.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;

use crate::model::{Deployment, Finding, Step, StepSpec};
use crate::secret::SecretRef;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything a driver call may need. Serialised as-is for out-of-process
/// drivers, so it holds secret references and never secret values.
#[derive(Clone, Debug, Serialize)]
pub struct DriverRequest {
    pub deployment: Deployment,
    pub action: String,
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<Step>,
    /// Checkpoints of the steps before this one, in order.
    pub checkpoints: Vec<Value>,
}

/// One piece of evidence a step produced.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub name: String,
    pub content: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StepOutput {
    #[serde(default)]
    pub checkpoint: Value,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Observation {
    /// The effect is in place; the step counts as completed with this
    /// checkpoint and is not executed again.
    Applied {
        #[serde(default)]
        checkpoint: Value,
    },
    /// Nothing happened; executing the step is safe.
    NotApplied,
    /// The driver cannot tell. The operation stops for a person.
    Unknown {
        #[serde(default)]
        detail: Option<String>,
    },
}

pub trait Driver: Send + Sync {
    /// # Errors
    /// When the action is unknown or its parameters are wrong.
    fn plan(&self, request: DriverRequest) -> BoxFuture<'_, Result<Vec<StepSpec>, String>>;
    /// # Errors
    /// When the deployment cannot be looked at.
    fn assess(&self, request: DriverRequest) -> BoxFuture<'_, Result<Vec<Finding>, String>>;
    /// # Errors
    /// When the step fails. The operation stops in `failed`.
    fn execute(&self, request: DriverRequest) -> BoxFuture<'_, Result<StepOutput, String>>;
    /// # Errors
    /// When observing fails; treated like [`Observation::Unknown`].
    fn observe(&self, request: DriverRequest) -> BoxFuture<'_, Result<Observation, String>>;
    /// # Errors
    /// When the undo fails. The operation stops in `attention_required`.
    fn compensate(&self, request: DriverRequest) -> BoxFuture<'_, Result<(), String>>;
}

/// Configuration of one out-of-process driver.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecDriverConfig {
    /// Program and arguments. Not run through a shell.
    pub command: Vec<String>,
    /// Upper bound on any one call. A step that legitimately takes longer
    /// should return and let a later step wait.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Environment the program receives, by reference. Resolved per call
    /// into the child's environment only: the values never enter the
    /// request document, the journal or the operator's own logs.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
}

fn default_timeout() -> u64 {
    300
}

/// Runs a driver program once per call: the request on stdin as
/// `{"api": "spindle.operator.driver/v1", "call": …, …request}`, and on
/// stdout either `{"ok": <result>}` or `{"error": "…"}`.
pub struct ExecDriver {
    config: ExecDriverConfig,
}

impl ExecDriver {
    /// # Errors
    /// When the command is empty.
    pub fn new(config: ExecDriverConfig) -> Result<Self, String> {
        if config.command.is_empty() {
            return Err("a driver command must name a program".to_owned());
        }
        Ok(ExecDriver { config })
    }

    async fn call(&self, call: &str, request: DriverRequest) -> Result<Value, String> {
        let mut document = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        if let Value::Object(map) = &mut document {
            map.insert("api".to_owned(), json!("spindle.operator.driver/v1"));
            map.insert("call".to_owned(), json!(call));
        }
        let mut command = tokio::process::Command::new(&self.config.command[0]);
        command
            .args(&self.config.command[1..])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // A timed-out or abandoned call must not leave a mutation
            // running behind the engine's back.
            .kill_on_drop(true);
        for (name, reference) in &self.config.secrets {
            command.env(name, reference.resolve()?);
        }
        let mut child = command.spawn().map_err(|error| {
            format!("driver `{}` did not start: {error}", self.config.command[0])
        })?;
        let input = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
        let mut stdin = child.stdin.take().ok_or("driver stdin unavailable")?;
        let run = async move {
            stdin
                .write_all(&input)
                .await
                .map_err(|error| error.to_string())?;
            drop(stdin);
            child
                .wait_with_output()
                .await
                .map_err(|error| error.to_string())
        };
        let output = tokio::time::timeout(Duration::from_secs(self.config.timeout_secs), run)
            .await
            .map_err(|_| format!("driver call `{call}` timed out"))??;
        let reply: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
            format!(
                "driver call `{call}` exited with {} and no JSON reply",
                output.status
            )
        })?;
        if let Some(error) = reply.get("error") {
            return Err(error
                .as_str()
                .map_or_else(|| error.to_string(), str::to_owned));
        }
        reply
            .get("ok")
            .cloned()
            .ok_or_else(|| format!("driver call `{call}` replied without `ok` or `error`"))
    }

    async fn typed<T: serde::de::DeserializeOwned>(
        &self,
        call: &str,
        request: DriverRequest,
    ) -> Result<T, String> {
        let value = self.call(call, request).await?;
        serde_json::from_value(value)
            .map_err(|error| format!("driver call `{call}` replied with the wrong shape: {error}"))
    }
}

impl Driver for ExecDriver {
    fn plan(&self, request: DriverRequest) -> BoxFuture<'_, Result<Vec<StepSpec>, String>> {
        Box::pin(self.typed("plan", request))
    }
    fn assess(&self, request: DriverRequest) -> BoxFuture<'_, Result<Vec<Finding>, String>> {
        Box::pin(self.typed("assess", request))
    }
    fn execute(&self, request: DriverRequest) -> BoxFuture<'_, Result<StepOutput, String>> {
        Box::pin(self.typed("execute", request))
    }
    fn observe(&self, request: DriverRequest) -> BoxFuture<'_, Result<Observation, String>> {
        Box::pin(self.typed("observe", request))
    }
    fn compensate(&self, request: DriverRequest) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { self.call("compensate", request).await.map(|_| ()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Risk;

    fn request() -> DriverRequest {
        DriverRequest {
            deployment: Deployment {
                id: "dep".to_owned(),
                version: 1,
                name: "prod".to_owned(),
                driver: "sh".to_owned(),
                connections: Vec::new(),
                settings: Value::Null,
                created_at: 0,
            },
            action: "quiesce".to_owned(),
            params: Value::Null,
            operation: None,
            step: None,
            checkpoints: Vec::new(),
        }
    }

    fn shell(script: &str, timeout_secs: u64) -> ExecDriver {
        let dir = std::env::temp_dir();
        ExecDriver::new(ExecDriverConfig {
            command: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
            timeout_secs,
            secrets: BTreeMap::from([(
                "FROM_FILE".to_owned(),
                SecretRef::File(dir.join("spindle-operator-missing").display().to_string()),
            )]),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_program_answers_on_stdout() {
        let mut config = shell("", 5).config;
        config.secrets.clear();
        config.command[2] = r#"read -r line; case "$line" in *'"call":"plan"'*) ;; *) exit 1;; esac
            [ -z "$HOME" ] || exit 1
            echo '{"ok": [{"name": "scale", "risk": "high", "mutation": true, "compensable": true}]}'"#
            .to_owned();
        let driver = ExecDriver::new(config).unwrap();
        let steps = driver.plan(request()).await.unwrap();
        assert_eq!(
            steps[0].risk,
            Risk::High,
            "the request arrived, and HOME did not"
        );
    }

    #[tokio::test]
    async fn errors_timeouts_and_missing_secrets_are_reported() {
        let mut config = shell("", 5).config;
        config.secrets.clear();
        config.command[2] = r#"cat >/dev/null; echo '{"error": "no such namespace"}'"#.to_owned();
        let failing = ExecDriver::new(config.clone()).unwrap();
        assert_eq!(
            failing.assess(request()).await.unwrap_err(),
            "no such namespace"
        );

        config.command[2] = "sleep 5".to_owned();
        config.timeout_secs = 1;
        let slow = ExecDriver::new(config).unwrap();
        assert!(
            slow.execute(request())
                .await
                .unwrap_err()
                .contains("timed out")
        );

        let unresolvable = shell("cat", 5);
        let error = unresolvable.observe(request()).await.unwrap_err();
        assert!(error.contains("spindle-operator-missing"), "{error}");
    }
}
