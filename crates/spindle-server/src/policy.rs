//! Room policy-server participation (stable API and MSC4284 compatibility).
//! Policy keys come from room state, not the server-key notary. Networking
//! happens only after the caller releases its room guard.
use std::collections::BTreeMap;

use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::Value;

use crate::federation::Federation;
use crate::rooms::RoomError;

pub const STABLE_TYPE: &str = "m.room.policy";
pub const UNSTABLE_TYPE: &str = "org.matrix.msc4284.policy";
pub const KEY_ID: &str = "ed25519:policy_server";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyServer {
    pub server_name: String,
    pub public_key: String,
}

#[must_use]
pub fn exempt(event: &Value) -> bool {
    event["state_key"].as_str() == Some("")
        && matches!(event["type"].as_str(), Some(STABLE_TYPE | UNSTABLE_TYPE))
}

impl PolicyServer {
    /// Stable state takes precedence, even if its content disables the policy.
    #[must_use]
    pub fn from_content(content: &Value, unstable: bool, local: &str) -> Option<Self> {
        let server = content["via"].as_str()?;
        if server == local || ruma::ServerName::parse(server).is_err() {
            return None;
        }
        let key = if unstable {
            &content["public_key"]
        } else {
            &content["public_keys"]["ed25519"]
        };
        Some(Self {
            server_name: server.to_owned(),
            public_key: key.as_str()?.to_owned(),
        })
    }

    /// Verify the policy signature using the room's key and version's redaction.
    #[must_use]
    pub fn verifies(&self, event: &Value, version: &RoomVersionId) -> bool {
        let Ok(CanonicalJsonValue::Object(mut canonical)) =
            CanonicalJsonValue::try_from(event.clone())
        else {
            return false;
        };
        if spindle_core::version::names_events_by_hash(version) {
            canonical.remove("event_id");
        }
        let Ok(mut canonical) = spindle_core::version::redact(&canonical, version) else {
            return false;
        };
        let Some(signature) = event["signatures"][&self.server_name][KEY_ID].as_str() else {
            return false;
        };
        let Ok(signatures) = CanonicalJsonValue::try_from(
            serde_json::json!({self.server_name.clone(): {KEY_ID: signature}}),
        ) else {
            return false;
        };
        canonical.insert("signatures".to_owned(), signatures);
        let Ok(key) = ruma::serde::Base64::parse(&self.public_key) else {
            return false;
        };
        let keys = BTreeMap::from([(
            self.server_name.clone(),
            BTreeMap::from([(KEY_ID.to_owned(), key)]),
        )]);
        ruma::signatures::verify_json(&keys, &canonical).is_ok()
    }

    /// Obtain and verify a signature, preserving all existing signer keys.
    ///
    /// # Errors
    /// Returns a refusal on timeout, network/protocol errors or invalid signatures.
    pub async fn authorize(
        &self,
        event: &mut Value,
        version: &RoomVersionId,
        federation: &Federation,
    ) -> Result<(), RoomError> {
        if exempt(event) || self.verifies(event, version) {
            return Ok(());
        }
        let mut wire = event.clone();
        if spindle_core::version::names_events_by_hash(version)
            && let Some(object) = wire.as_object_mut()
        {
            object.remove("event_id");
        }
        let signatures = federation
            .policy_sign(&self.server_name, &wire)
            .await
            .map_err(|error| match error {
                crate::federation::FederationError::Answered { status, body } => {
                    RoomError::Policy(Box::new(policy_error(status, &body)))
                }
                error => RoomError::Forbidden(format!("policy server refused the event: {error}")),
            })?;
        let signature = signatures
            .get(&self.server_name)
            .and_then(|keys| keys.get(KEY_ID))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                RoomError::Forbidden("policy server returned no approval signature".to_owned())
            })?;
        let object = event
            .as_object_mut()
            .ok_or_else(|| RoomError::Build("policy event is not an object".to_owned()))?;
        let signers = object
            .entry("signatures")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| RoomError::Build("invalid signatures object".to_owned()))?;
        let keys = signers
            .entry(self.server_name.clone())
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| RoomError::Build("invalid signer keys".to_owned()))?;
        keys.insert(KEY_ID.to_owned(), Value::String(signature.to_owned()));
        if !self.verifies(event, version) {
            return Err(RoomError::Forbidden(
                "policy server returned an invalid approval signature".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Serialize concurrent retries of the same client transaction across policy I/O.
#[derive(Default)]
pub struct TransactionLocks {
    locks: std::sync::Mutex<BTreeMap<Vec<u8>, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}
impl TransactionLocks {
    pub(crate) async fn enter(&self, key: &[u8]) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self
                .locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(key).and_then(std::sync::Weak::upgrade) {
                lock
            } else {
                let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(key.to_vec(), std::sync::Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

/// Preserve actionable policy refusals without allowing a remote policy service
/// to invalidate a client's homeserver login.
fn policy_error(status: u16, body: &Value) -> crate::errors::MatrixError {
    use axum::http::StatusCode;
    let code = match body["errcode"].as_str() {
        Some("M_FORBIDDEN") => "M_FORBIDDEN",
        Some("M_LIMIT_EXCEEDED") => "M_LIMIT_EXCEEDED",
        Some("M_BAD_JSON") => "M_BAD_JSON",
        Some("M_NOT_FOUND") => "M_NOT_FOUND",
        Some("M_TOO_LARGE") => "M_TOO_LARGE",
        Some("M_UNRECOGNIZED") => "M_UNRECOGNIZED",
        _ => "M_UNKNOWN",
    };
    let unsafe_auth = matches!(
        body["errcode"].as_str(),
        Some("M_UNKNOWN_TOKEN" | "M_MISSING_TOKEN" | "M_USER_LOCKED")
    );
    let status = if unsafe_auth {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN)
    };
    let mut error = crate::errors::MatrixError::new(
        status,
        code,
        body["error"]
            .as_str()
            .unwrap_or("policy server refused the event"),
    );
    if code == "M_LIMIT_EXCEEDED" {
        error.retry_after_ms = body["retry_after_ms"].as_u64();
    }
    error
}
