//! Notification boundaries for exclusively opened, fresh offline imports.
//!
//! A started proof precedes every import write. Completion and the initial push
//! cursor share one atomic strict commit. Once complete, its highwater never
//! changes: checkpoint recovery cannot swallow events appended by a live server.

use std::io::Read as _;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{Durability, FjallStore, ReadView, Store};

use super::full::{Error, write_error};

/// Legacy and supplementary imports are explicitly unmanaged; absence of a
/// proof must never imply that historical notifications were fenced.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    UnmanagedLegacy,
    UnmanagedSupplementary,
    DryRun,
    ManagedFresh,
}

/// Durable provenance mirrored into the import checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Proof {
    pub version: u32,
    pub import_id: String,
    pub scope_sha256: String,
    /// Absent until all import phases finished and were durably synced.
    pub high_water: Option<u64>,
}

fn failure(message: &str) -> Error {
    Error::Checkpoint(format!("notification boundary: {message}"))
}

fn held(store: &FjallStore) -> Result<Option<Proof>, Error> {
    ReadView::get(store, &keys::import_notification_fence())
        .map_err(write_error)?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| failure("malformed durable proof")))
        .transpose()
}

fn cursor(store: &FjallStore) -> Result<Option<u64>, Error> {
    ReadView::get(store, &keys::push_cursor())
        .map_err(write_error)?
        .map(|raw| {
            let bytes: [u8; 8] = raw
                .try_into()
                .map_err(|_| failure("malformed push cursor"))?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

/// Start or resume a fresh import. Legacy checkpoints and supplementary imports
/// cannot acquire a fence. Must run before constructing target services.
///
/// # Errors
/// Refuses nonempty targets, mismatched provenance, and malformed metadata.
pub fn begin(
    store: &FjallStore,
    scope_sha256: &str,
    checkpoint: Option<&Proof>,
    resuming: bool,
    allow_nonempty: bool,
) -> Result<Option<Proof>, Error> {
    if allow_nonempty {
        // A supplementary import must not acquire, rewrite, or claim the base
        // target's fence, regardless of which checkpoint it was given.
        return Ok(None);
    }
    if let Some(proof) = checkpoint {
        if proof.version != 1 || proof.scope_sha256 != scope_sha256 {
            return Err(failure("checkpoint mode or scope differs"));
        }
        let durable = held(store)?.ok_or_else(|| failure("durable start proof missing"))?;
        if durable.version != proof.version
            || durable.import_id != proof.import_id
            || durable.scope_sha256 != proof.scope_sha256
            || (proof.high_water.is_some() && proof != &durable)
        {
            return Err(failure("checkpoint and durable proof differ"));
        }
        if durable.high_water.is_none() && cursor(store)?.is_some() {
            return Err(failure("cursor appeared before import completion"));
        }
        return Ok(Some(durable));
    }
    if resuming {
        if held(store)?.is_some() {
            return Err(failure(
                "durable proof exists but checkpoint proof is absent",
            ));
        }
        // Explicitly do not touch an existing live cursor or retrofit an old
        // checkpoint: neither establishes that the target started empty.
        return Ok(None);
    }
    let rows = ReadView::scan_prefix(store, &[]).map_err(write_error)?;
    if rows.iter().any(|(key, _)| *key != keys::store_marker()) {
        return Err(failure("fresh target is not empty"));
    }
    let mut entropy = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut entropy))
        .map_err(write_error)?;
    let proof = Proof {
        version: 1,
        import_id: entropy.iter().map(|byte| format!("{byte:02x}")).collect(),
        scope_sha256: scope_sha256.to_owned(),
        high_water: None,
    };
    Store::commit(
        store,
        &[(
            keys::import_notification_fence(),
            serde_json::to_vec(&proof)?,
        )],
        Durability::Strict,
    )
    .map_err(write_error)?;
    Ok(Some(proof))
}

/// Finish a successful offline import after every phase completed. The caller's
/// highwater is sampled only for an unfinished fence; a completed fence and its
/// cursor are never rewritten, even if live events have since advanced them.
///
/// # Errors
/// Refuses missing/mismatched proofs or an unexpected preexisting cursor.
pub fn complete(store: &FjallStore, proof: &Proof, high_water: u64) -> Result<Proof, Error> {
    let durable = held(store)?.ok_or_else(|| failure("durable start proof missing"))?;
    if durable.version != proof.version
        || durable.import_id != proof.import_id
        || durable.scope_sha256 != proof.scope_sha256
        || (proof.high_water.is_some() && proof != &durable)
    {
        return Err(failure("completion proof differs"));
    }
    if durable.high_water.is_some() {
        validate(store, &durable)?;
        return Ok(durable);
    }
    if cursor(store)?.is_some() {
        return Err(failure("existing cursor must not be overwritten"));
    }
    if high_water == u64::MAX {
        return Err(failure("highwater leaves no next live stream position"));
    }
    Store::sync(store, Durability::Strict).map_err(write_error)?;
    let completed = Proof {
        high_water: Some(high_water),
        ..durable
    };
    Store::commit(
        store,
        &[
            (
                keys::import_notification_fence(),
                serde_json::to_vec(&completed)?,
            ),
            (keys::push_cursor(), high_water.to_be_bytes().to_vec()),
        ],
        Durability::Strict,
    )
    .map_err(write_error)?;
    Ok(completed)
}

/// Read back the immutable proof and a cursor at or beyond its initial boundary.
///
/// # Errors
/// Returns an error if either durable row is missing, malformed, or regressed.
pub fn validate(store: &FjallStore, proof: &Proof) -> Result<(), Error> {
    if proof.version != 1 {
        return Err(failure("unsupported proof version"));
    }
    let boundary = proof
        .high_water
        .ok_or_else(|| failure("import is incomplete"))?;
    if boundary == u64::MAX {
        return Err(failure("highwater leaves no next live stream position"));
    }
    if held(store)?.as_ref() != Some(proof) || cursor(store)?.is_none_or(|v| v < boundary) {
        return Err(failure("durable boundary or cursor differs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_import_resumes_and_only_completion_creates_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let started = {
            let store = FjallStore::open(dir.path()).unwrap();
            let proof = begin(&store, "scope-a", None, false, false)
                .unwrap()
                .unwrap();
            Store::put(&store, b"fixture-import-row", b"history").unwrap();
            Store::sync(&store, Durability::Strict).unwrap();
            assert_eq!(cursor(&store).unwrap(), None);
            proof
        };
        let store = FjallStore::open(dir.path()).unwrap();
        let resumed = begin(&store, "scope-a", Some(&started), true, false)
            .unwrap()
            .unwrap();
        assert_eq!(resumed, started);
        let done = complete(&store, &resumed, 128).unwrap();
        assert_eq!(cursor(&store).unwrap(), Some(128));
        validate(&store, &done).unwrap();
    }

    #[test]
    fn completed_before_checkpoint_crash_never_resamples_new_events_or_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let started = {
            let store = FjallStore::open(dir.path()).unwrap();
            let proof = begin(&store, "scope-a", None, false, false)
                .unwrap()
                .unwrap();
            complete(&store, &proof, 128).unwrap();
            proof // The checkpoint still contains the pre-completion proof.
        };
        let store = FjallStore::open(dir.path()).unwrap();
        // Model live push processing after the completed store was enabled.
        Store::put(&store, &keys::push_cursor(), &130_u64.to_be_bytes()).unwrap();
        let resumed = begin(&store, "scope-a", Some(&started), true, false)
            .unwrap()
            .unwrap();
        let done = complete(&store, &resumed, 999).unwrap();
        assert_eq!(done.high_water, Some(128));
        assert_eq!(cursor(&store).unwrap(), Some(130));
        validate(&store, &done).unwrap();
    }

    #[test]
    fn legacy_and_supplementary_targets_preserve_existing_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        Store::put(&store, &keys::push_cursor(), &17_u64.to_be_bytes()).unwrap();
        assert!(begin(&store, "scope-a", None, false, false).is_err());
        assert!(
            begin(&store, "scope-a", None, true, false)
                .unwrap()
                .is_none()
        );
        assert!(
            begin(&store, "scope-a", None, false, true)
                .unwrap()
                .is_none()
        );
        assert_eq!(cursor(&store).unwrap(), Some(17));
        assert!(held(&store).unwrap().is_none());
    }

    #[test]
    fn supplementary_import_preserves_completed_base_fence_and_advanced_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let proof = begin(&store, "base-scope", None, false, false)
            .unwrap()
            .unwrap();
        let base = complete(&store, &proof, 100).unwrap();
        Store::put(&store, &keys::push_cursor(), &103_u64.to_be_bytes()).unwrap();
        assert!(
            begin(&store, "supplement-scope", None, false, true)
                .unwrap()
                .is_none()
        );
        assert!(
            begin(&store, "supplement-scope", Some(&base), true, true)
                .unwrap()
                .is_none()
        );
        assert_eq!(held(&store).unwrap(), Some(base));
        assert_eq!(cursor(&store).unwrap(), Some(103));
    }

    #[test]
    fn provenance_and_unexpected_cursor_fail_closed_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let proof = begin(&store, "scope-a", None, false, false)
            .unwrap()
            .unwrap();
        assert!(begin(&store, "scope-b", Some(&proof), true, false).is_err());
        assert!(
            begin(&store, "scope-b", Some(&proof), true, true)
                .unwrap()
                .is_none()
        );
        assert_eq!(held(&store).unwrap(), Some(proof.clone()));
        assert!(begin(&store, "scope-a", None, true, false).is_err());
        let mut wrong = proof.clone();
        wrong.import_id = "another-import".to_owned();
        assert!(complete(&store, &wrong, 42).is_err());
        Store::put(&store, &keys::push_cursor(), &7_u64.to_be_bytes()).unwrap();
        assert!(complete(&store, &proof, 42).is_err());
        assert_eq!(cursor(&store).unwrap(), Some(7));
        assert_eq!(held(&store).unwrap(), Some(proof));
    }

    #[test]
    fn consuming_last_side_stream_drawer_then_restart_cannot_skip_new_live_ids() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = std::sync::Arc::new(FjallStore::open(dir.path()).unwrap());
            let proof = begin(&store, "scope-a", None, false, false)
                .unwrap()
                .unwrap();
            let devices = crate::devices::Devices::new(std::sync::Arc::clone(&store));
            devices
                .queue_to_device(
                    "@fixture:example",
                    "DEVICE",
                    128,
                    &serde_json::json!({"type":"m.test", "content":{}}),
                )
                .unwrap();
            let rooms = crate::rooms::Rooms::new(std::sync::Arc::clone(&store), "example");
            assert_eq!(rooms.stream_position(), 128);
            complete(&store, &proof, rooms.stream_position()).unwrap();
            let prefix = [keys::KEY_SCHEMA_VERSION, keys::Keyspace::ToDevice as u8];
            for (key, _) in ReadView::scan_prefix(store.as_ref(), &prefix).unwrap() {
                Store::delete(store.as_ref(), &key).unwrap();
            }
            Store::sync(store.as_ref(), Durability::Strict).unwrap();
        }
        let store = std::sync::Arc::new(FjallStore::open(dir.path()).unwrap());
        let rooms = crate::rooms::Rooms::new(std::sync::Arc::clone(&store), "example");
        assert_eq!(rooms.stream_position(), 128);
        assert_eq!(rooms.allocate_stream_id(), 129);
    }

    #[test]
    fn boundary_overflow_fails_before_creating_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let proof = begin(&store, "scope-a", None, false, false)
            .unwrap()
            .unwrap();
        assert!(complete(&store, &proof, u64::MAX).is_err());
        assert!(cursor(&store).unwrap().is_none());
        assert_eq!(held(&store).unwrap(), Some(proof));
    }

    #[test]
    fn readback_rejects_incomplete_missing_corrupt_and_regressed_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let proof = begin(&store, "scope-a", None, false, false)
            .unwrap()
            .unwrap();
        assert!(validate(&store, &proof).is_err());
        let done = complete(&store, &proof, 50).unwrap();
        Store::delete(&store, &keys::push_cursor()).unwrap();
        assert!(validate(&store, &done).is_err());
        Store::put(&store, &keys::push_cursor(), &49_u64.to_be_bytes()).unwrap();
        assert!(validate(&store, &done).is_err());
        Store::put(&store, &keys::push_cursor(), b"not-u64").unwrap();
        assert!(validate(&store, &done).is_err());
        Store::put(&store, &keys::import_notification_fence(), b"not-json").unwrap();
        assert!(begin(&store, "scope-a", Some(&proof), true, false).is_err());
    }
}
