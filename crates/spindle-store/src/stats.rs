//! `spindle stats`: what fills the store? (#891)
//!
//! An operator who sees the disk fill needs to know which kind of row did
//! it: state nodes, the log, the media index or an outbox. The engine only
//! reports one total for the whole database, so this reads every row once
//! and adds up the rows of each keyspace.

use std::collections::BTreeMap;

use spindle_core::keys::{KEY_SCHEMA_VERSION, Keyspace};

use crate::{ReadView, StoreError};

/// Rows and bytes of one keyspace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyspaceStats {
    /// Rows stored.
    pub rows: u64,
    /// Bytes of keys and values, before the engine compresses them. The
    /// size on disk is lower for compressible rows and higher while freed
    /// rows wait for a compaction.
    pub bytes: u64,
}

/// What [`store_stats`] found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreStats {
    /// One entry for each keyspace that holds a row.
    pub keyspaces: BTreeMap<u8, KeyspaceStats>,
    /// Rows whose second key byte names no keyspace of this version.
    pub unknown: KeyspaceStats,
}

impl StoreStats {
    /// All rows and bytes.
    #[must_use]
    pub fn total(&self) -> KeyspaceStats {
        self.keyspaces
            .values()
            .fold(self.unknown, |sum, one| KeyspaceStats {
                rows: sum.rows + one.rows,
                bytes: sum.bytes + one.bytes,
            })
    }

    /// The keyspaces with a name, largest first. Equal sizes keep tag order.
    #[must_use]
    pub fn by_size(&self) -> Vec<(Keyspace, KeyspaceStats)> {
        let mut rows: Vec<(Keyspace, KeyspaceStats)> = self
            .keyspaces
            .iter()
            .filter_map(|(tag, stats)| Keyspace::from_tag(*tag).map(|keyspace| (keyspace, *stats)))
            .collect();
        rows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
        rows
    }
}

/// Count the rows and bytes of every keyspace.
///
/// # Errors
///
/// Returns [`StoreError`] if a scan fails.
pub fn store_stats<S: ReadView>(store: &S) -> Result<StoreStats, StoreError> {
    let mut stats = StoreStats::default();
    store.visit_prefix(&[KEY_SCHEMA_VERSION], &mut |key, value| {
        let bytes = (key.len() + value.len()) as u64;
        let entry = match key.get(1) {
            Some(tag) if Keyspace::from_tag(*tag).is_some() => {
                stats.keyspaces.entry(*tag).or_default()
            }
            _ => &mut stats.unknown,
        };
        entry.rows += 1;
        entry.bytes += bytes;
        Ok(())
    })?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use spindle_core::keys::{Keyspace, keyspace_prefix};

    use super::{KeyspaceStats, store_stats};
    use crate::{FjallStore, Store};

    fn row(keyspace: Keyspace, suffix: &[u8]) -> Vec<u8> {
        let mut key = keyspace_prefix(keyspace);
        key.extend_from_slice(suffix);
        key
    }

    #[test]
    fn counts_rows_and_bytes_for_each_keyspace() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        store
            .put(&row(Keyspace::StateNode, b"a"), &[0; 10])
            .unwrap();
        store
            .put(&row(Keyspace::StateNode, b"b"), &[0; 20])
            .unwrap();
        store.put(&row(Keyspace::Media, b"m"), &[0; 5]).unwrap();

        let stats = store_stats(&store).unwrap();
        // Key is two prefix bytes and one suffix byte.
        assert_eq!(
            stats.keyspaces[&(Keyspace::StateNode as u8)],
            KeyspaceStats { rows: 2, bytes: 36 }
        );
        assert_eq!(
            stats.keyspaces[&(Keyspace::Media as u8)],
            KeyspaceStats { rows: 1, bytes: 8 }
        );
        assert_eq!(stats.unknown, KeyspaceStats::default());
        assert_eq!(stats.total().rows, 3);
        assert_eq!(stats.by_size()[0].0, Keyspace::StateNode);
    }

    #[test]
    fn a_tag_no_version_wrote_is_counted_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        store
            .put(&[spindle_core::keys::KEY_SCHEMA_VERSION, 0xfe, 1], b"xy")
            .unwrap();

        let stats = store_stats(&store).unwrap();
        assert!(stats.keyspaces.is_empty());
        assert_eq!(stats.unknown, KeyspaceStats { rows: 1, bytes: 5 });
    }
}
