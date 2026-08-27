//! Device keys, one-time keys, and to-device messages — E2EE's transport.
//!
//! The server's role in end-to-end encryption is deliberately dumb: it holds
//! key material it cannot use and ferries ciphertext it cannot read. Every
//! subtlety here is about *delivery* semantics, not cryptography — the one
//! place the server could break E2EE is by losing or double-delivering the
//! messages that carry session setup.

use std::sync::Arc;

use serde_json::{Map, Value, json};
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

    /// Store a device's fallback keys, one per algorithm, replacing any old.
    ///
    /// A re-upload resets the `used` flag: the client rotated the key, and
    /// the fresh one has been handed to nobody.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a write fails.
    pub fn upload_fallback_keys(
        &self,
        user_id: &str,
        device_id: &str,
        fallback_keys: &Map<String, Value>,
    ) -> Result<(), StoreError> {
        for (key_id, key) in fallback_keys {
            let algorithm = key_id.split(':').next().unwrap_or(key_id);
            Store::put(
                self.store.as_ref(),
                &keys::device_scoped(
                    Keyspace::FallbackKeys,
                    user_id,
                    device_id,
                    algorithm.as_bytes(),
                ),
                json!({ "key_id": key_id, "key": key, "used": false })
                    .to_string()
                    .as_bytes(),
            )?;
        }
        Ok(())
    }

    /// The algorithms whose fallback key has not yet been handed out.
    ///
    /// `/sync` reports this so a device knows when to rotate: a used
    /// fallback key still works, but every session built on it after the
    /// first shares its compromise.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn unused_fallback_algorithms(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        let prefix = keys::device_scoped(Keyspace::FallbackKeys, user_id, device_id, &[]);
        let mut algorithms = Vec::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Ok(record) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if record["used"] == Value::Bool(false)
                && let Ok(algorithm) = String::from_utf8(key[prefix.len()..].to_vec())
            {
                algorithms.push(algorithm);
            }
        }
        Ok(algorithms)
    }

    /// Claim a key: a one-time key if any remains, else the fallback.
    ///
    /// The two tiers have opposite lifetimes and that is the design. A
    /// one-time key is deleted as it is handed out; the fallback is *kept*
    /// and only marked used, because it exists for exactly the moment the
    /// deletable keys have run out — deleting it would turn "low on keys"
    /// into "unreachable for new sessions".
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan or write fails.
    pub fn claim_key(
        &self,
        user_id: &str,
        device_id: &str,
        algorithm: &str,
    ) -> Result<Option<(String, Value)>, StoreError> {
        if let Some(claimed) = self.claim_one_time_key(user_id, device_id, algorithm)? {
            return Ok(Some(claimed));
        }
        let key = keys::device_scoped(
            Keyspace::FallbackKeys,
            user_id,
            device_id,
            algorithm.as_bytes(),
        );
        let Some(bytes) = ReadView::get(self.store.as_ref(), &key)? else {
            return Ok(None);
        };
        let Ok(mut record) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(None);
        };
        record["used"] = Value::Bool(true);
        Store::put(self.store.as_ref(), &key, record.to_string().as_bytes())?;
        let key_id = record["key_id"].as_str().unwrap_or_default().to_owned();
        Ok(Some((key_id, record["key"].clone())))
    }

    /// Store one of a user's cross-signing keys (master, self, user).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn upload_cross_signing(
        &self,
        user_id: &str,
        key_type: &str,
        key: &Value,
    ) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::cross_signing(user_id, key_type),
            key.to_string().as_bytes(),
        )
    }

    /// One of a user's cross-signing keys, if uploaded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read fails.
    pub fn cross_signing_key(
        &self,
        user_id: &str,
        key_type: &str,
    ) -> Result<Option<Value>, StoreError> {
        let Some(bytes) =
            ReadView::get(self.store.as_ref(), &keys::cross_signing(user_id, key_type))?
        else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&bytes).ok())
    }

    /// Merge an uploaded signature into a stored key.
    ///
    /// `target` names either one of `user_id`'s devices or one of their
    /// cross-signing keys (by the key ID its `keys` map carries). Only the
    /// `signatures` object is touched: the signed key material itself is
    /// what the uploader attested to, and letting a signature upload alter
    /// it would let anyone "sign" a key into being a different key.
    ///
    /// Returns `false` if no such key exists to sign.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a read or write fails.
    pub fn add_signatures(
        &self,
        user_id: &str,
        target: &str,
        signed: &Value,
    ) -> Result<bool, StoreError> {
        // A device first: device IDs are the common case (self-verifying
        // one's own devices with the self-signing key).
        let device_key = keys::device_scoped(Keyspace::DeviceKeys, user_id, target, &[]);
        if let Some(bytes) = ReadView::get(self.store.as_ref(), &device_key)?
            && let Ok(stored) = serde_json::from_slice::<Value>(&bytes)
        {
            let merged = merge_signatures(stored, signed);
            Store::put(
                self.store.as_ref(),
                &device_key,
                merged.to_string().as_bytes(),
            )?;
            return Ok(true);
        }
        // Then the cross-signing keys, matched by the key ID inside them —
        // that is how the spec addresses them (e.g. signing another user's
        // master key with one's user-signing key).
        for key_type in ["master", "self_signing", "user_signing"] {
            let Some(stored) = self.cross_signing_key(user_id, key_type)? else {
                continue;
            };
            let holds_target = stored["keys"].as_object().is_some_and(|map| {
                map.keys()
                    .any(|id| id == target || id.ends_with(&format!(":{target}")))
            });
            if holds_target {
                let merged = merge_signatures(stored, signed);
                Store::put(
                    self.store.as_ref(),
                    &keys::cross_signing(user_id, key_type),
                    merged.to_string().as_bytes(),
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Forget a deleted device's E2E material: identity keys, one-time
    /// keys and fallback keys. Without this, `/keys/query` keeps
    /// advertising the dead device and peers keep encrypting to a key
    /// nobody will ever hold again.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a scan or delete fails.
    pub fn remove_device_material(&self, user_id: &str, device_id: &str) -> Result<(), StoreError> {
        Store::delete(
            self.store.as_ref(),
            &keys::device_scoped(Keyspace::DeviceKeys, user_id, device_id, &[]),
        )?;
        for keyspace in [Keyspace::OneTimeKeys, Keyspace::FallbackKeys] {
            let prefix = keys::device_scoped(keyspace, user_id, device_id, &[]);
            for (key, _) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
                Store::delete(self.store.as_ref(), &key)?;
            }
        }
        Ok(())
    }

    /// Record that `user_id`'s device list changed at stream position `seq`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn mark_device_list_changed(&self, user_id: &str, seq: u64) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::device_list_change(user_id),
            &seq.to_be_bytes(),
        )
    }

    /// Every user whose device list changed in `(since, until]`.
    ///
    /// A scan over one watermark row per key-holding user, not a change log:
    /// the caller only needs names, and a name that changed twice is still
    /// one name. Callers narrow this to users the asker shares a room with —
    /// that is an access decision, and it belongs beside the room data.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn device_lists_changed(
        &self,
        since: u64,
        until: Option<u64>,
    ) -> Result<Vec<String>, StoreError> {
        let mut changed = Vec::new();
        for (key, bytes) in
            ReadView::scan_prefix(self.store.as_ref(), &keys::device_list_change_prefix())?
        {
            let seq = bytes
                .as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            // Exclusive below, inclusive above — the same convention as sync
            // tokens, so a change lands in exactly one (from, to] window.
            if seq > since
                && until.is_none_or(|until| seq <= until)
                && let Some(user_id) = keys::device_list_change_user(&key)
            {
                changed.push(user_id);
            }
        }
        Ok(changed)
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

/// `stored` with `signed`'s signatures merged in, and nothing else changed.
fn merge_signatures(mut stored: Value, signed: &Value) -> Value {
    let Some(new_signatures) = signed["signatures"].as_object() else {
        return stored;
    };
    if !stored["signatures"].is_object() {
        stored["signatures"] = Value::Object(Map::new());
    }
    let existing = stored["signatures"]
        .as_object_mut()
        .expect("just made an object");
    for (signer, sigs) in new_signatures {
        let slot = existing
            .entry(signer.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let (Some(slot), Some(sigs)) = (slot.as_object_mut(), sigs.as_object()) {
            for (key_id, signature) in sigs {
                slot.insert(key_id.clone(), signature.clone());
            }
        }
    }
    stored
}

/// The device ID a [`keys::device_scoped`] key names, given its user prefix.
fn device_suffix(key: &[u8], user_prefix: &[u8]) -> Option<String> {
    let rest = key.strip_prefix(user_prefix)?;
    let len = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
    String::from_utf8(rest.get(2..2 + len)?.to_vec()).ok()
}
