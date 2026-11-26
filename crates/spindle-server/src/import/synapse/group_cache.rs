//! A per-snapshot cache of Synapse state groups.
//!
//! Synapse stores state as delta-compressed groups: a group holds a few rows
//! and names the group it extends. A repeatable-read snapshot never sees a
//! group change, so a group read once is right for the rest of the snapshot.
//! Events of one room share most of their chain, so the importer used to read
//! the same chain and the same base rows again for each event it resolved.
//! The cache reads each group's edge and rows once, and a later event reads
//! only the groups that are new to it.

use std::collections::{HashMap, HashSet};

use super::ReadError;
use crate::import::StateMap;

/// One `(type, state_key, event_id)` row of a state group.
pub(crate) type GroupRow = (String, String, String);

/// Most rows that the cache keeps. A room with tens of thousands of members
/// has a base group with one row for each member, and the earlier importer
/// ran out of memory when it kept every version of such a state. Groups that
/// do not fit are read again when needed, as before.
pub(crate) const MAX_CACHED_ROWS: usize = 250_000;

/// What the cache needs from the database.
pub(crate) trait GroupSource {
    /// The state group of an event, if Synapse holds one.
    fn root_group(&mut self, event_id: &str) -> Result<Option<i64>, ReadError>;
    /// `group` and each group behind it, newest first, with a flag that is
    /// true on the entry where the walk met a group again.
    fn chain_from(&mut self, group: i64) -> Result<Vec<(i64, bool)>, ReadError>;
    /// The rows of `groups`. With `keys`, only rows for those slots.
    fn rows(
        &mut self,
        room_id: &str,
        groups: &[i64],
        keys: Option<&[(String, String)]>,
    ) -> Result<Vec<(i64, GroupRow)>, ReadError>;
}

#[derive(Default)]
pub(crate) struct StateGroupCache {
    room: Option<String>,
    /// `Some(prev)` is the group that a group extends, `None` ends the chain.
    prev: HashMap<i64, Option<i64>>,
    rows: HashMap<i64, Vec<GroupRow>>,
    row_count: usize,
}

impl StateGroupCache {
    /// Groups belong to one room, so a new room starts an empty cache.
    fn enter(&mut self, room_id: &str) {
        if self.room.as_deref() != Some(room_id) {
            self.room = Some(room_id.to_owned());
            self.prev.clear();
            self.rows.clear();
            self.row_count = 0;
        }
    }

    /// The groups behind `event_id`'s state group, newest first.
    fn chain(
        &mut self,
        source: &mut impl GroupSource,
        room_id: &str,
        event_id: &str,
    ) -> Result<Vec<i64>, ReadError> {
        let Some(root) = source.root_group(event_id)? else {
            return Err(ReadError::MissingStateGroup {
                room_id: room_id.to_owned(),
                root: event_id.to_owned(),
            });
        };
        let cycle = |state_group| ReadError::StateGroupCycle {
            room_id: room_id.to_owned(),
            state_group,
        };
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = Some(root);
        while let Some(group) = current {
            if !seen.insert(group) {
                return Err(cycle(group));
            }
            chain.push(group);
            current = if let Some(prev) = self.prev.get(&group) {
                *prev
            } else {
                let mut ids = Vec::new();
                for (id, repeated) in source.chain_from(group)? {
                    if repeated {
                        return Err(cycle(id));
                    }
                    ids.push(id);
                }
                for pair in ids.windows(2) {
                    self.prev.insert(pair[0], Some(pair[1]));
                }
                if let Some(last) = ids.last() {
                    self.prev.insert(*last, None);
                }
                ids.get(1).copied()
            };
        }
        Ok(chain)
    }

    /// Synapse's state after `event_id`: the newest group's value wins for
    /// each slot. With `keys`, only those slots, and rows that are not
    /// cached already are read for those slots alone and are not kept.
    pub(crate) fn state_after(
        &mut self,
        source: &mut impl GroupSource,
        room_id: &str,
        event_id: &str,
        keys: Option<&[(String, String)]>,
    ) -> Result<StateMap, ReadError> {
        self.enter(room_id);
        let chain = self.chain(source, room_id, event_id)?;
        let missing: Vec<i64> = chain
            .iter()
            .copied()
            .filter(|group| !self.rows.contains_key(group))
            .collect();
        let mut fetched: HashMap<i64, Vec<GroupRow>> = HashMap::new();
        if !missing.is_empty() {
            for (group, row) in source.rows(room_id, &missing, keys)? {
                fetched.entry(group).or_default().push(row);
            }
            if keys.is_none() {
                // Cache whole groups only, an empty one included.
                for group in &missing {
                    let rows = fetched.remove(group).unwrap_or_default();
                    if self.row_count + rows.len() <= MAX_CACHED_ROWS {
                        self.row_count += rows.len();
                        self.rows.insert(*group, rows);
                    } else {
                        fetched.insert(*group, rows);
                    }
                }
            }
        }
        let wanted: Option<HashSet<(&str, &str)>> = keys.map(|keys| {
            keys.iter()
                .map(|(kind, key)| (kind.as_str(), key.as_str()))
                .collect()
        });
        let mut state = StateMap::new();
        for group in &chain {
            let rows = self.rows.get(group).or_else(|| fetched.get(group));
            for (kind, key, id) in rows.into_iter().flatten() {
                if wanted
                    .as_ref()
                    .is_some_and(|wanted| !wanted.contains(&(kind.as_str(), key.as_str())))
                {
                    continue;
                }
                state
                    .entry((kind.clone(), key.clone()))
                    .or_insert_with(|| id.clone());
            }
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Groups: 1 is a base with two rows, 2 extends 1, 3 extends 2.
    #[derive(Default)]
    struct Fake {
        events: HashMap<&'static str, i64>,
        prev: HashMap<i64, i64>,
        rows: HashMap<i64, Vec<GroupRow>>,
        chain_queries: usize,
        rows_read: usize,
    }

    fn row(kind: &str, key: &str, id: &str) -> GroupRow {
        (kind.to_owned(), key.to_owned(), id.to_owned())
    }

    fn fake() -> Fake {
        Fake {
            events: [("$a", 2), ("$b", 3), ("$orphan", 9)].into(),
            prev: [(3, 2), (2, 1)].into(),
            rows: [
                (
                    1,
                    vec![
                        row("m.room.create", "", "$c"),
                        row("m.room.name", "", "$n0"),
                    ],
                ),
                (2, vec![row("m.room.name", "", "$n1")]),
                (3, vec![row("m.room.topic", "", "$t")]),
            ]
            .into(),
            ..Fake::default()
        }
    }

    impl GroupSource for Fake {
        fn root_group(&mut self, event_id: &str) -> Result<Option<i64>, ReadError> {
            Ok(self.events.get(event_id).copied())
        }
        fn chain_from(&mut self, group: i64) -> Result<Vec<(i64, bool)>, ReadError> {
            self.chain_queries += 1;
            let mut out = vec![(group, false)];
            let mut at = group;
            while let Some(next) = self.prev.get(&at) {
                let repeated = out.iter().any(|(seen, _)| seen == next);
                out.push((*next, repeated));
                if repeated {
                    break;
                }
                at = *next;
            }
            Ok(out)
        }
        fn rows(
            &mut self,
            _: &str,
            groups: &[i64],
            keys: Option<&[(String, String)]>,
        ) -> Result<Vec<(i64, GroupRow)>, ReadError> {
            let mut out = Vec::new();
            for group in groups {
                for r in self.rows.get(group).into_iter().flatten() {
                    let wanted = keys.is_none_or(|keys| {
                        keys.iter().any(|(kind, key)| *kind == r.0 && *key == r.1)
                    });
                    if wanted {
                        out.push((*group, r.clone()));
                    }
                }
            }
            self.rows_read += out.len();
            Ok(out)
        }
    }

    #[test]
    fn a_second_event_reads_only_the_groups_it_adds() {
        let (mut cache, mut db) = (StateGroupCache::default(), fake());
        let a = cache.state_after(&mut db, "!r", "$a", None).unwrap();
        assert_eq!(a[&("m.room.name".to_owned(), String::new())], "$n1");
        assert_eq!((db.chain_queries, db.rows_read), (1, 3));
        let b = cache.state_after(&mut db, "!r", "$b", None).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(
            (db.chain_queries, db.rows_read),
            // One more edge query: group 3's edge is new. Rows are read for
            // group 3 alone.
            (2, 4),
            "only group 3 is new"
        );
        cache.state_after(&mut db, "!r", "$b", None).unwrap();
        assert_eq!(
            (db.chain_queries, db.rows_read),
            (2, 4),
            "a repeat reads nothing"
        );
    }

    #[test]
    fn a_key_read_uses_cached_groups_and_keeps_nothing_of_its_own() {
        let (mut cache, mut db) = (StateGroupCache::default(), fake());
        let keys = [("m.room.topic".to_owned(), String::new())];
        let state = cache.state_after(&mut db, "!r", "$b", Some(&keys)).unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(db.rows_read, 1);
        assert!(cache.rows.is_empty());
        cache.state_after(&mut db, "!r", "$a", None).unwrap();
        let rows_before = db.rows_read;
        cache.state_after(&mut db, "!r", "$b", Some(&keys)).unwrap();
        assert_eq!(db.rows_read - rows_before, 1, "only the uncached group 3");
    }

    #[test]
    fn the_cache_keeps_no_more_than_the_row_cap() {
        let (mut cache, mut db) = (StateGroupCache::default(), fake());
        cache.row_count = MAX_CACHED_ROWS - 2;
        let state = cache.state_after(&mut db, "!r", "$a", None).unwrap();
        assert_eq!(state.len(), 2, "the answer is complete without the cache");
        assert!(cache.row_count <= MAX_CACHED_ROWS);
    }

    #[test]
    fn a_new_room_starts_empty() {
        let (mut cache, mut db) = (StateGroupCache::default(), fake());
        cache.state_after(&mut db, "!r", "$a", None).unwrap();
        cache.state_after(&mut db, "!other", "$a", None).unwrap();
        assert_eq!(db.chain_queries, 2);
    }

    #[test]
    fn missing_and_cyclic_groups_are_errors() {
        let (mut cache, mut db) = (StateGroupCache::default(), fake());
        assert!(matches!(
            cache.state_after(&mut db, "!r", "$none", None),
            Err(ReadError::MissingStateGroup { .. })
        ));
        db.prev.insert(1, 3);
        assert!(matches!(
            cache.state_after(&mut db, "!r", "$a", None),
            Err(ReadError::StateGroupCycle { .. })
        ));
    }
}
