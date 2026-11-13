//! `spindle verify`: is this store intact? (#818)
//!
//! A normal room load checks the last few hundred state roots and the chain
//! tips, which is the right cost for a server start. After a crash, a restore
//! or a disk fault an operator wants the exhaustive answer for every room,
//! and a read error reported as an error rather than as a missing node.

use spindle_core::keys::{Keyspace, keyspace_prefix, room_from_prefixed};

use crate::{RoomStore, Store, StoreError};

/// What [`verify_store`] found.
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// Rooms checked.
    pub rooms: u64,
    /// Log entries read across those rooms.
    pub entries: u64,
    /// Rooms with entries whose state the log could not re-derive. Expected
    /// for backfilled ranges, so it is not a failure.
    pub unverified_rooms: u64,
    /// Every room that failed, with why. Empty means the store is intact.
    pub problems: Vec<(String, StoreError)>,
}

impl VerifyReport {
    /// Whether nothing was wrong.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Check every room exhaustively: each record, the whole chain and every
/// state root. Keeps going after a bad room, so one report lists them all.
///
/// # Errors
///
/// Only when the list of rooms cannot be read. A room that fails is in
/// [`VerifyReport::problems`].
pub fn verify_store<S: Store>(store: &S) -> Result<VerifyReport, StoreError> {
    let mut rooms = Vec::new();
    store.visit_prefix(&keyspace_prefix(Keyspace::RoomMeta), &mut |key, _| {
        rooms.extend(room_from_prefixed(key).map(str::to_owned));
        Ok(())
    })?;
    let mut report = VerifyReport::default();
    for room in rooms {
        report.rooms += 1;
        match RoomStore::new(store, room.as_str()).load_exhaustive() {
            Ok(Some(restored)) => {
                report.entries += restored.log.len() as u64;
                if let Some(first) = restored.broken_chain.first() {
                    report.problems.push((
                        room,
                        StoreError::Backend(format!(
                            "the chain breaks at {} entries, the first at index {}",
                            restored.broken_chain.len(),
                            first.get()
                        )),
                    ));
                } else if !restored.unverified.is_empty() {
                    report.unverified_rooms += 1;
                }
            }
            Ok(None) => report.problems.push((
                room,
                StoreError::Backend("the room has no metadata".to_owned()),
            )),
            Err(error) => report.problems.push((room, error)),
        }
    }
    Ok(report)
}
