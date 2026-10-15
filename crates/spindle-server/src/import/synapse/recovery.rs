//! Persist the opaque account material needed by a fresh encrypted client.

use serde_json::{Map, Value};

use super::postgres::RecoveryData;
use crate::{account_data::AccountData, backups::Backups, devices::Devices};

/// Counts from an isolated recovery-data restore.
#[derive(Debug, Eq, PartialEq)]
pub struct Outcome {
    pub account_data: usize,
    pub device_keys: usize,
    pub cross_signing_keys: usize,
    pub signatures: usize,
    pub skipped_signatures: usize,
    pub backup_versions: usize,
    pub backup_sessions: usize,
}

/// A recovery-data record could not be written to Spindle.
#[derive(Debug)]
pub enum Error {
    AccountData(crate::account_data::AccountDataError),
    Storage(spindle_store::StoreError),
}

impl From<crate::account_data::AccountDataError> for Error {
    fn from(error: crate::account_data::AccountDataError) -> Self {
        Self::AccountData(error)
    }
}

impl From<spindle_store::StoreError> for Error {
    fn from(error: spindle_store::StoreError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountData(error) => write!(formatter, "restoring account data: {error}"),
            Self::Storage(error) => write!(formatter, "restoring encrypted account data: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// Restore one user's opaque recovery material into an empty rehearsal store.
///
/// No value is decrypted here. Secret storage and backup session data remain
/// ciphertext whose key is known only to the user's client.
///
/// # Errors
///
/// Returns [`Error`] if any account, device, signature, or backup record
/// cannot be persisted.
pub fn restore(
    source: &RecoveryData,
    account_data: &AccountData,
    devices: &Devices,
    backups: &Backups,
) -> Result<Outcome, Error> {
    for row in &source.account_data {
        account_data.put(
            &source.user_id,
            &row.room_id,
            &row.event_type,
            &row.content,
            0,
        )?;
    }
    for row in &source.device_keys {
        devices.upload_device_keys(&source.user_id, &row.device_id, &row.keys)?;
    }
    for row in &source.cross_signing_keys {
        devices.upload_cross_signing(&source.user_id, &row.key_type, &row.keys)?;
    }

    let mut signatures = 0;
    let mut skipped_signatures = 0;
    for row in &source.signatures {
        let mut by_key = Map::new();
        by_key.insert(
            row.signer_key_id.clone(),
            Value::String(row.signature.clone()),
        );
        let mut by_user = Map::new();
        by_user.insert(row.signer_user_id.clone(), Value::Object(by_key));
        let signed = serde_json::json!({ "signatures": by_user });
        if devices.add_signatures(&row.target_user_id, &row.target_device_id, &signed)? {
            signatures += 1;
        } else {
            skipped_signatures += 1;
        }
    }

    for row in &source.backup_sessions {
        let _ = backups.put_key(
            &source.user_id,
            row.version,
            &row.room_id,
            &row.session_id,
            &row.data,
        )?;
    }
    for row in &source.backup_versions {
        backups.restore_version(
            &source.user_id,
            row.version,
            &row.algorithm,
            &row.auth_data,
            row.etag,
            row.deleted,
        )?;
    }

    Ok(Outcome {
        account_data: source.account_data.len(),
        device_keys: source.device_keys.len(),
        cross_signing_keys: source.cross_signing_keys.len(),
        signatures,
        skipped_signatures,
        backup_versions: source.backup_versions.len(),
        backup_sessions: source.backup_sessions.len(),
    })
}
