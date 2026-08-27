//! Device keys, one-time keys, and to-device messages — E2EE's transport.
//!
//! The server's role in end-to-end encryption is deliberately dumb: it holds
//! key material it cannot use and ferries ciphertext it cannot read. Every
//! subtlety here is about *delivery* semantics, not cryptography — the one
//! place the server could break E2EE is by losing or double-delivering the
//! messages that carry session setup.

use std::sync::Arc;

use serde_json::{Map, Value};
use spindle_core::keys::{self, Keyspace};
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// Key material and message queues, per device.
pub struct Devices {
    store: Arc<FjallStore>,
}

impl Devices {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Store a device's identity keys, replacing what was there.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn upload_device_keys(
        &self,
        user_id: &str,
        device_id: &str,
        device_keys: &Value,
    ) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::device_scoped(Keyspace::DeviceKeys, user_id, device_id, &[]),
            device_keys.to_string().as_bytes(),
        )
    }

    /// A device's identity keys, if it has uploaded any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read fails.
    pub fn device_keys(&self, user_id: &str, device_id: &str) -> Result<Option<Value>, StoreError> {
        let Some(bytes) = ReadView::get(
            self.store.as_ref(),
            &keys::device_scoped(Keyspace::DeviceKeys, user_id, device_id, &[]),
        )?
        else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    /// Every device of a user that has uploaded keys, as `{device_id: keys}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn all_device_keys(&self, user_id: &str) -> Result<Map<String, Value>, StoreError> {
        let prefix = keys::user_prefix(Keyspace::DeviceKeys, user_id);
        let mut out = Map::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Some(device_id) = device_suffix(&key, &prefix) else {
                continue;
            };
            if let Ok(value) = serde_json::from_slice(&bytes) {
                out.insert(device_id, value);
            }
        }
        Ok(out)
    }

    /// Add one-time keys, returning how many of each algorithm remain.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a write fails.
    pub fn upload_one_time_keys(
        &self,
        user_id: &str,
        device_id: &str,
        one_time_keys: &Map<String, Value>,
    ) -> Result<Map<String, Value>, StoreError> {
        for (key_id, key) in one_time_keys {
            Store::put(
                self.store.as_ref(),
                &keys::device_scoped(Keyspace::OneTimeKeys, user_id, device_id, key_id.as_bytes()),
                key.to_string().as_bytes(),
            )?;
        }
        self.one_time_key_counts(user_id, device_id)
    }

    /// How many one-time keys remain, by algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn one_time_key_counts(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Map<String, Value>, StoreError> {
        let prefix = keys::device_scoped(Keyspace::OneTimeKeys, user_id, device_id, &[]);
        let mut counts: Map<String, Value> = Map::new();
        for (key, _) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Some(key_id) = String::from_utf8(key[prefix.len()..].to_vec()).ok() else {
                continue;
            };
            // `signed_curve25519:AAAAHQ` counts under `signed_curve25519`.
            let algorithm = key_id.split(':').next().unwrap_or(&key_id).to_owned();
            let count = counts.get(&algorithm).and_then(Value::as_u64).unwrap_or(0);
            counts.insert(algorithm, Value::from(count + 1));
        }
        Ok(counts)
    }

    /// Take one one-time key of `algorithm`, deleting it as it is handed out.
    ///
    /// The delete is the point: a one-time key used twice is the compromise
    /// Olm's forward secrecy exists to prevent, so the hand-out and the
    /// removal are one operation, and a second claim gets a different key or
    /// none.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan or delete fails.
    pub fn claim_one_time_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>, StoreError> {
        let prefix = keys::device_scoped(
            Keyspace::OneTimeKeys,
            user_id,
            device_id,
            format!("{algorithm}:").as_bytes(),
        );
        let Some((key, bytes)) = ReadView::scan_prefix(self.store.as_ref(), &prefix)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        Store::delete(self.store.as_ref(), &key)?;
        let device_prefix = keys::device_scoped(Keyspace::OneTimeKeys, user_id, device_id, &[]);
        let key_id = String::from_utf8(key[device_prefix.len()..].to_vec()).unwrap_or_default();
        Ok(Some((
            key_id,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )))
    }

    /// Queue a to-device message under `seq`.
    ///
    /// The sequence number is the caller's, drawn from the same global stream
    /// counter `/sync` tokens position against — that identity is the whole
    /// deletion protocol (see [`Self::take_pending`]).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn queue_to_device(
        &self,
        user_id: &str,
        device_id: &str,
        seq: u64,
        message: &Value,
    ) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::device_scoped(Keyspace::ToDevice, user_id, device_id, &seq.to_be_bytes()),
            message.to_string().as_bytes(),
        )
    }

    /// Everything pending for a device, deleting what `since` acknowledges.
    ///
    /// A client presenting `since` has durably received every batch up to
    /// that position — that is what a sync token means — so every message
    /// with `seq <= since` was in a batch the client has, and is dropped.
    /// Everything newer is returned and *kept*: it is deleted only when a
    /// later request proves receipt. Crash between response and next request,
    /// and the messages are delivered again — at-least-once, which for
    /// session-establishment ciphertext is the correct side to err on.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan or a delete fails.
    pub fn take_pending(
        &self,
        user_id: &str,
        device_id: &str,
        since: Option<u64>,
    ) -> Result<Vec<Value>, StoreError> {
        let prefix = keys::device_scoped(Keyspace::ToDevice, user_id, device_id, &[]);
        let mut pending = Vec::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let seq = key[prefix.len()..]
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            if let Some(since) = since
                && seq <= since
            {
                Store::delete(self.store.as_ref(), &key)?;
                continue;
            }
            if let Ok(message) = serde_json::from_slice::<Value>(&bytes) {
                pending.push(message);
            }
        }
        Ok(pending)
    }
}

/// The device ID a [`keys::device_scoped`] key names, given its user prefix.
fn device_suffix(key: &[u8], user_prefix: &[u8]) -> Option<String> {
    let rest = key.strip_prefix(user_prefix)?;
    let len = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
    String::from_utf8(rest.get(2..2 + len)?.to_vec()).ok()
}
