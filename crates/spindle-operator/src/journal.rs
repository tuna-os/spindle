//! The append-only journal: the operator's only durable state.
//!
//! Every change is an [`Event`] appended to `journal.jsonl` and synced to
//! disk before the engine applies it in memory or answers the request
//! that caused it. Startup replays the file. That one rule gives the
//! three properties the operator needs from storage:
//!
//! - **Checkpoints.** "Step 3 started" is on disk before the driver is
//!   called, so after a crash the engine knows to observe step 3 rather
//!   than run it again, and that steps 1–2 must not run again at all.
//! - **Audit.** The journal *is* the audit trail. Nothing rewrites it, so
//!   no code path can change history; the audit API is a filtered read.
//! - **Independence.** It is a local file. The operator needs neither
//!   homeserver nor their databases to remember what it was doing, which
//!   is the point of running it as its own process.
//!
//! An embedded database (fjall, as the homeserver uses) was the
//! alternative. The journal is smaller than any index over it, it is read
//! once at startup, and a text file an operator can `grep` during an
//! incident is worth more here than random access.
//!
//! A crash can tear the last line. Replay drops an unterminated final line
//! and truncates it away, because the write it represents was never
//! acknowledged; a malformed line anywhere else is corruption and stops
//! startup rather than guessing.

use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Seek as _, SeekFrom, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{
    Actor, Approval, Artifact, Assessment, Connection, Deployment, Millis, Operation,
    OperationState, Policy, Principal, Probe,
};

/// One line of the journal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub at: Millis,
    pub actor: Actor,
    /// The `X-Request-Id` of the request that caused the change, so an
    /// audit line can be joined to an access log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    pub change: Change,
}

/// Every kind of state change. Applying the same sequence always produces
/// the same state; that is what makes replay a restore.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    /// The session id is stored only as a SHA-256 hash, so a copy of the
    /// journal cannot be replayed as a login.
    SessionOpened {
        session_hash: String,
        principal: Principal,
        expires_at: Millis,
    },
    SessionClosed {
        session_hash: String,
    },
    IdempotencyStored {
        subject: String,
        key: String,
        fingerprint: String,
        status: u16,
        body: serde_json::Value,
    },
    ConnectionCreated {
        connection: Connection,
    },
    ConnectionProbed {
        id: String,
        probe: Probe,
    },
    DeploymentCreated {
        deployment: Deployment,
    },
    PolicyUpdated {
        policy: Policy,
    },
    AssessmentRecorded {
        assessment: Assessment,
    },
    OperationCreated {
        operation: Operation,
    },
    LeaseAcquired {
        deployment: String,
        operation: String,
    },
    LeaseReleased {
        deployment: String,
        operation: String,
    },
    OperationState {
        state: OperationState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    PauseRequested,
    CancelRequested,
    StepStarted {
        step: usize,
    },
    /// After an interruption: what the driver (or a person resolving an
    /// attention-required operation) found the step's effect to be.
    StepObserved {
        step: usize,
        applied: bool,
    },
    StepCompleted {
        step: usize,
        checkpoint: serde_json::Value,
        artifacts: Vec<String>,
    },
    StepFailed {
        step: usize,
        error: String,
    },
    StepCompensationStarted {
        step: usize,
    },
    StepCompensated {
        step: usize,
    },
    ApprovalRecorded {
        approval: Approval,
    },
    ArtifactStored {
        artifact: Artifact,
    },
    ArtifactExpired {
        id: String,
    },
}

impl Change {
    /// Whether the audit API shows this change. Sessions are shown (a login
    /// is an audit fact) but stripped of their hashes; stored idempotent
    /// responses are bookkeeping, not history.
    #[must_use]
    pub fn audit_view(&self) -> Option<serde_json::Value> {
        match self {
            Self::IdempotencyStored { .. } => None,
            Self::SessionOpened {
                principal,
                expires_at,
                ..
            } => Some(serde_json::json!({
                "type": "session_opened",
                "principal": principal,
                "expires_at": expires_at,
            })),
            Self::SessionClosed { .. } => Some(serde_json::json!({"type": "session_closed"})),
            other => serde_json::to_value(other).ok(),
        }
    }
}

pub struct Journal {
    file: File,
    next_seq: u64,
}

impl Journal {
    /// Open (creating if needed) the journal in `dir`, returning it with
    /// every event already recorded, in order.
    ///
    /// # Errors
    ///
    /// On I/O failure, or a malformed line before the last.
    pub fn open(dir: &Path) -> std::io::Result<(Self, Vec<Event>)> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("journal.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let mut events = Vec::new();
        let mut good_len: u64 = 0;
        let mut reader = BufReader::new(&file);
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break;
            }
            if !line.ends_with('\n') {
                // The torn tail of an unacknowledged write.
                tracing::warn!(bytes = read, "dropping an unterminated final journal line");
                break;
            }
            let event: Event = serde_json::from_str(&line).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("journal line {} is malformed: {error}", events.len() + 1),
                )
            })?;
            events.push(event);
            good_len += read as u64;
        }
        drop(reader);
        if file.metadata()?.len() != good_len {
            file.set_len(good_len)?;
            file.seek(SeekFrom::End(0))?;
            file.sync_all()?;
        }
        let next_seq = events.last().map_or(1, |event| event.seq + 1);
        Ok((Journal { file, next_seq }, events))
    }

    /// Append `changes` as consecutive events and sync them to disk. They
    /// are durable together or not at all as far as any caller knows: no
    /// caller sees success until the sync returns.
    ///
    /// # Errors
    ///
    /// On I/O failure. The engine treats that as fatal for the request.
    pub fn append(
        &mut self,
        at: Millis,
        actor: &Actor,
        request: Option<&str>,
        operation: Option<&str>,
        changes: Vec<Change>,
    ) -> std::io::Result<Vec<Event>> {
        let mut buffer = Vec::new();
        let mut events = Vec::with_capacity(changes.len());
        for change in changes {
            let event = Event {
                seq: self.next_seq + events.len() as u64,
                at,
                actor: actor.clone(),
                request: request.map(str::to_owned),
                operation: operation.map(str::to_owned),
                change,
            };
            serde_json::to_writer(&mut buffer, &event)?;
            buffer.push(b'\n');
            events.push(event);
        }
        self.file.write_all(&buffer)?;
        self.file.sync_data()?;
        self.next_seq += events.len() as u64;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_torn_tail_is_dropped_and_earlier_events_survive() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut journal, events) = Journal::open(dir.path()).unwrap();
            assert!(events.is_empty());
            journal
                .append(
                    1,
                    &Actor::System,
                    None,
                    Some("op"),
                    vec![Change::PauseRequested],
                )
                .unwrap();
        }
        let path = dir.path().join("journal.jsonl");
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"seq\":2,\"at\":").unwrap();
        drop(file);

        let (mut journal, events) = Journal::open(dir.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].change, Change::PauseRequested);
        let appended = journal
            .append(2, &Actor::System, None, None, vec![Change::CancelRequested])
            .unwrap();
        assert_eq!(appended[0].seq, 2);
        let (_, events) = Journal::open(dir.path()).unwrap();
        assert_eq!(
            events.len(),
            2,
            "the torn bytes were truncated before appending"
        );
    }

    #[test]
    fn a_malformed_line_before_the_end_stops_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("journal.jsonl"), "not json\n{}\n").unwrap();
        assert!(Journal::open(dir.path()).is_err());
    }
}
