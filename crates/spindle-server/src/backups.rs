//! Server-side key backup — encrypted room keys the server cannot read.
//!
//! The backup exists so a user who loses every device can still decrypt
//! their history: each megolm session key is encrypted to a recovery key the
//! server never sees, and stored here. The server's two jobs are custody and
//! the *replacement rule* — a stored key may only be overwritten by a
//! strictly better copy — so that a confused or malicious client with write
//! access cannot quietly degrade a backup into one that unlocks less.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// One user's backup versions and their contents.
pub struct Backups {
    store: Arc<FjallStore>,
}

/// A backup version's stored metadata.
#[derive(Debug)]
pub struct VersionInfo {
    pub version: u64,
    pub algorithm: String,
    pub auth_data: Value,
    pub etag: u64,
    pub count: u64,
}

impl Backups {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Create a new backup version and return its number.
    ///
    /// Versions count up and are never reused — a tombstoned version's
    /// number keeps meaning "gone" forever (see the keyspace comment).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan or write fails.
    pub fn create_version(
        &self,
        user_id: &str,
        algorithm: &str,
        auth_data: &Value,
    ) -> Result<u64, StoreError> {
        let version = self.highest_version(user_id)?.map_or(1, |v| v + 1);
        Store::put(
            self.store.as_ref(),
            &keys::key_backup_version(user_id, version),
            record(algorithm, auth_data, 0, false)
                .to_string()
                .as_bytes(),
        )?;
        Ok(version)
    }

    /// The latest live (non-deleted) version, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn latest_version(&self, user_id: &str) -> Result<Option<VersionInfo>, StoreError> {
        let prefix = keys::user_prefix(keys::Keyspace::KeyBackup, user_id);
        let mut latest = None;
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Some(version) = version_of(&key, &prefix) else {
                continue;
            };
            let Ok(stored) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if stored["deleted"] == Value::Bool(true) {
                continue;
            }
            latest = Some((version, stored));
        }
        let Some((version, stored)) = latest else {
            return Ok(None);
        };
        Ok(Some(self.info(user_id, version, &stored)?))
    }

    /// A specific version, live or not. Deleted versions return `None`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read fails.
    pub fn version(&self, user_id: &str, version: u64) -> Result<Option<VersionInfo>, StoreError> {
        let Some(bytes) = ReadView::get(
            self.store.as_ref(),
            &keys::key_backup_version(user_id, version),
        )?
        else {
            return Ok(None);
        };
        let Ok(stored) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(None);
        };
        if stored["deleted"] == Value::Bool(true) {
            return Ok(None);
        }
        Ok(Some(self.info(user_id, version, &stored)?))
    }

    /// Replace a version's auth data (same algorithm, re-encrypted secret).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read or write fails.
    pub fn update_version(
        &self,
        user_id: &str,
        version: u64,
        algorithm: &str,
        auth_data: &Value,
    ) -> Result<bool, StoreError> {
        let Some(info) = self.version(user_id, version)? else {
            return Ok(false);
        };
        Store::put(
            self.store.as_ref(),
            &keys::key_backup_version(user_id, version),
            record(algorithm, auth_data, info.etag, false)
                .to_string()
                .as_bytes(),
        )?;
        Ok(true)
    }

    /// Tombstone a version and delete its keys.
    ///
    /// The keys go now rather than lazily: they are ciphertext to us, but
    /// they are the user's history to whoever holds the recovery key, and
    /// "deleted" must not mean "still readable with the right request".
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if a read, write, or delete fails.
    pub fn delete_version(&self, user_id: &str, version: u64) -> Result<bool, StoreError> {
        let Some(info) = self.version(user_id, version)? else {
            return Ok(false);
        };
        Store::put(
            self.store.as_ref(),
            &keys::key_backup_version(user_id, version),
            record(&info.algorithm, &info.auth_data, info.etag, true)
                .to_string()
                .as_bytes(),
        )?;
        let prefix = data_prefix(user_id, version);
        for (key, _) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            Store::delete(self.store.as_ref(), &key)?;
        }
        Ok(true)
    }

    /// Store one session's backup data, subject to the replacement rule.
    ///
    /// Returns whether the write happened. A key is replaced only by a
    /// strictly better one: verified beats unverified, then a lower
    /// `first_message_index` (unlocks more), then a lower `forwarded_count`
    /// (closer to the original). Equal-or-worse uploads are dropped
    /// silently — the spec's shape, and the property the tests mutate.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read or write fails.
    pub fn put_key(
        &self,
        user_id: &str,
        version: u64,
        room_id: &str,
        session_id: &str,
        data: &Value,
    ) -> Result<bool, StoreError> {
        let key = keys::key_backup_data(user_id, version, room_id, session_id);
        if let Some(existing) = ReadView::get(self.store.as_ref(), &key)? {
            let Ok(existing) = serde_json::from_slice::<Value>(&existing) else {
                return Ok(false);
            };
            if !better(data, &existing) {
                return Ok(false);
            }
        }
        Store::put(self.store.as_ref(), &key, data.to_string().as_bytes())?;
        self.bump_etag(user_id, version)?;
        Ok(true)
    }

    /// Everything in a version, as `{room_id: {sessions: {session_id: data}}}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    ///
    /// # Panics
    ///
    /// Cannot in practice: the room entry is created with a `sessions`
    /// object two lines above the access.
    pub fn keys(&self, user_id: &str, version: u64) -> Result<Map<String, Value>, StoreError> {
        let prefix = data_prefix(user_id, version);
        let mut rooms: Map<String, Value> = Map::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Some((room_id, session_id)) = split_data_key(&key, &prefix) else {
                continue;
            };
            let Ok(data) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            rooms
                .entry(room_id)
                .or_insert_with(|| json!({ "sessions": {} }))["sessions"]
                .as_object_mut()
                .expect("sessions is always an object")
                .insert(session_id, data);
        }
        Ok(rooms)
    }

    /// Delete backed-up keys: everything, one room, or one session.
    ///
    /// Deletion is not subject to the replacement rule — the rule guards
    /// against *degrading* a key, and the owner erasing their own backup is
    /// not a degradation but a decision. Returns how many rows went.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan or a delete fails.
    pub fn delete_keys(
        &self,
        user_id: &str,
        version: u64,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<u64, StoreError> {
        let mut prefix = data_prefix(user_id, version);
        if let Some(room_id) = room_id {
            let bytes = room_id.as_bytes();
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            prefix.extend_from_slice(&len.to_be_bytes());
            prefix.extend_from_slice(&bytes[..len as usize]);
            if let Some(session_id) = session_id {
                let bytes = session_id.as_bytes();
                let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
                prefix.extend_from_slice(&len.to_be_bytes());
                prefix.extend_from_slice(&bytes[..len as usize]);
            }
        }
        let mut deleted = 0;
        for (key, _) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            Store::delete(self.store.as_ref(), &key)?;
            deleted += 1;
        }
        if deleted > 0 {
            self.bump_etag(user_id, version)?;
        }
        Ok(deleted)
    }

    fn highest_version(&self, user_id: &str) -> Result<Option<u64>, StoreError> {
        let prefix = keys::user_prefix(keys::Keyspace::KeyBackup, user_id);
        Ok(ReadView::scan_prefix(self.store.as_ref(), &prefix)?
            .iter()
            .filter_map(|(key, _)| version_of(key, &prefix))
            .max())
    }

    fn info(&self, user_id: &str, version: u64, stored: &Value) -> Result<VersionInfo, StoreError> {
        // Counted, not cached: the count exists so clients can tell whether
        // a backup is worth restoring, and a cached count that drifts from
        // the rows would answer that question wrongly.
        let count = ReadView::scan_prefix(self.store.as_ref(), &data_prefix(user_id, version))?
            .len() as u64;
        Ok(VersionInfo {
            version,
            algorithm: stored["algorithm"].as_str().unwrap_or_default().to_owned(),
            auth_data: stored["auth_data"].clone(),
            etag: stored["etag"].as_u64().unwrap_or(0),
            count,
        })
    }

    fn bump_etag(&self, user_id: &str, version: u64) -> Result<(), StoreError> {
        let key = keys::key_backup_version(user_id, version);
        let Some(bytes) = ReadView::get(self.store.as_ref(), &key)? else {
            return Ok(());
        };
        let Ok(mut stored) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(());
        };
        let etag = stored["etag"].as_u64().unwrap_or(0) + 1;
        stored["etag"] = Value::from(etag);
        Store::put(self.store.as_ref(), &key, stored.to_string().as_bytes())
    }
}

/// Is `candidate` strictly better backup data than `existing`?
///
/// The order of the three comparisons is the spec's: verification first,
/// then how far back the key reaches, then how many hands it passed through.
fn better(candidate: &Value, existing: &Value) -> bool {
    let verified = |v: &Value| v["is_verified"].as_bool().unwrap_or(false);
    if verified(candidate) != verified(existing) {
        return verified(candidate);
    }
    let index = |v: &Value| v["first_message_index"].as_u64().unwrap_or(u64::MAX);
    if index(candidate) != index(existing) {
        return index(candidate) < index(existing);
    }
    let forwarded = |v: &Value| v["forwarded_count"].as_u64().unwrap_or(u64::MAX);
    forwarded(candidate) < forwarded(existing)
}

fn record(algorithm: &str, auth_data: &Value, etag: u64, deleted: bool) -> Value {
    json!({
        "algorithm": algorithm,
        "auth_data": auth_data,
        "etag": etag,
        "deleted": deleted,
    })
}

fn data_prefix(user_id: &str, version: u64) -> Vec<u8> {
    let mut prefix = keys::user_prefix(keys::Keyspace::KeyBackupData, user_id);
    prefix.extend_from_slice(&version.to_be_bytes());
    prefix
}

fn version_of(key: &[u8], prefix: &[u8]) -> Option<u64> {
    key.strip_prefix(prefix)?
        .try_into()
        .map(u64::from_be_bytes)
        .ok()
}

fn split_data_key(key: &[u8], prefix: &[u8]) -> Option<(String, String)> {
    let mut rest = key.strip_prefix(prefix)?;
    let mut parts = Vec::new();
    for _ in 0..2 {
        let len = usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?));
        parts.push(String::from_utf8(rest.get(2..2 + len)?.to_vec()).ok()?);
        rest = rest.get(2 + len..)?;
    }
    Some((parts.remove(0), parts.remove(0)))
}

#[cfg(test)]
mod custody_tests {
    use std::sync::Arc;

    use serde_json::json;
    use spindle_store::{FjallStore, ReadView};

    use super::Backups;

    /// Deletion removes the rows, not merely the version's listing.
    ///
    /// The HTTP surface cannot distinguish this — every read of a dead
    /// version 404s whether the ciphertext lingers or not — but the
    /// promise is about data at rest, so the check reads the store.
    #[test]
    fn deleting_a_version_removes_its_rows_from_the_store() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let backups = Backups::new(Arc::clone(&store));

        let version = backups.create_version("@a:x", "alg", &json!({})).unwrap();
        backups
            .put_key(
                "@a:x",
                version,
                "!r:x",
                "s1",
                &json!({ "session_data": "ct" }),
            )
            .unwrap();
        let prefix = super::data_prefix("@a:x", version);
        assert_eq!(
            ReadView::scan_prefix(store.as_ref(), &prefix)
                .unwrap()
                .len(),
            1
        );

        backups.delete_version("@a:x", version).unwrap();
        assert!(
            ReadView::scan_prefix(store.as_ref(), &prefix)
                .unwrap()
                .is_empty(),
            "deleted must not mean 'still on disk under a hidden version'"
        );
    }
}

#[cfg(test)]
mod replacement_rule_tests {
    use super::better;
    use serde_json::json;

    #[test]
    fn verification_outranks_everything() {
        // A verified key with a worse index still wins…
        assert!(better(
            &json!({ "is_verified": true, "first_message_index": 9 }),
            &json!({ "is_verified": false, "first_message_index": 0 }),
        ));
        // …and an unverified one with a better index still loses.
        assert!(!better(
            &json!({ "is_verified": false, "first_message_index": 0 }),
            &json!({ "is_verified": true, "first_message_index": 9 }),
        ));
    }

    #[test]
    fn ties_fall_through_index_then_forwarding() {
        assert!(better(
            &json!({ "first_message_index": 1, "forwarded_count": 5 }),
            &json!({ "first_message_index": 2, "forwarded_count": 0 }),
        ));
        assert!(better(
            &json!({ "first_message_index": 1, "forwarded_count": 0 }),
            &json!({ "first_message_index": 1, "forwarded_count": 5 }),
        ));
        // A perfect tie is not better; the write is refused.
        assert!(!better(
            &json!({ "first_message_index": 1, "forwarded_count": 0 }),
            &json!({ "first_message_index": 1, "forwarded_count": 0 }),
        ));
    }
}
