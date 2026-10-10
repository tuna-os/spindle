//! Interned room-state keys (#79).
//!
//! The state trie compares and hashes its keys on every descent, and it
//! used to hold `(Box<str>, Box<str>)` pairs in every leaf to do it. A
//! state key is now one `u64`: `(event_type, state_key)` is interned
//! once, and the trie orders, hashes and stores that id. Event ids still
//! use their string representation.
//!
//! The table is a trait rather than a map so the two owners can differ:
//! tests and benches use [`MemStateKeyTable`], an ordinary mutex-guarded
//! pair of maps, while the server persists its table in the store and
//! loads it at open. What matters is the contract, which is the same for
//! both:
//!
//! - One identity gets one id. Allocation is serialised inside the table,
//!   so concurrent `intern` calls cannot mint two ids for one pair.
//! - Ids are never reused and never change while the table lives. A trie
//!   node hashes its ids, so an id that changed meaning would silently
//!   repoint every node holding it.
//! - Id zero is reserved and never assigned. It reads as "absent" at
//!   every call site that holds an id in an `Option`-shaped slot.
//!
//! A fresh in-memory table assigns ids in first-seen order, so two tables
//! that intern the same pairs in a different order disagree on every id.
//! Snapshots built against different tables must never be diffed or
//! persisted together: in production every snapshot shares the store's
//! table, and a test shares one table across the snapshots it compares.
//! An empty snapshot holds no ids, so its table is never consulted.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// One allocated intern-table row: the id a pair was minted with, and the
/// pair. A name for the triple nesting, which otherwise trips
/// `type_complexity` at every use.
pub type AllocRecord = (u64, (Box<str>, Box<str>));

/// Who hands out and resolves interned state-key ids.
/// Object-safe so snapshots can share one table across owners.
pub trait StateKeyTable: Send + Sync + std::fmt::Debug {
    /// The id for a pair the table already holds, without allocating.
    ///
    /// Reads use this: a key the table never saw is absent from every
    /// trie built against the table, so missing here means missing,
    /// not "allocate then miss".
    fn id_of(&self, event_type: &str, state_key: &str) -> Option<u64>;

    /// The id for a pair, allocating the next one when it is new.
    ///
    /// Writes use this: the slot is about to be stored, so the pair
    /// belongs in the table whether or not it was there before.
    fn intern(&self, event_type: &str, state_key: &str) -> u64;

    /// The pair an id names, or `None` for an id the table never issued.
    fn resolve(&self, id: u64) -> Option<(Box<str>, Box<str>)>;

    /// Whether an id is present, without resolving its strings.
    fn contains_id(&self, id: u64) -> bool {
        self.resolve(id).is_some()
    }

    /// Every pair allocated since the last take, oldest first, draining
    /// the queue. The store encodes these into the same batch as the
    /// nodes that reference them: an id must never reach durable nodes
    /// without its row. Reads never add to the queue; only `intern` of a
    /// pair the table never saw does.
    fn take_allocated(&self) -> Vec<AllocRecord>;
}

/// An in-memory [`StateKeyTable`].
///
/// The forward map nests by event type so a lookup hashes borrowed
/// `&str` twice and allocates nothing: `Box<str>` borrows as `str`,
/// and neither level needs an owned key to read. Only the first sight
/// of a pair allocates, once per level. Allocation holds the mutex
/// across the re-read and the write, so one identity gets one id no
/// matter how the callers interleave. For persisted use the store owns
/// the same shape with a write-through; see the store crate.
#[derive(Debug, Default)]
pub struct MemStateKeyTable {
    inner: Mutex<MemTable>,
}

#[derive(Debug, Default)]
struct MemTable {
    forward: HashMap<Box<str>, HashMap<Box<str>, u64>>,
    reverse: Vec<(Box<str>, Box<str>)>,
    /// The first reverse-map row not yet taken for persistence. Allocations
    /// are dense and ordered, so a cursor avoids retaining a third copy of
    /// every pair while a batch is being assembled.
    pending_from: usize,
}

impl MemStateKeyTable {
    /// An empty table. Ids start at one; see the module docs on why two
    /// tables that see the same pairs in a different order disagree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A table shared by snapshots: the shape every test and bench wants.
    #[must_use]
    pub fn shared() -> Arc<dyn StateKeyTable> {
        Arc::new(Self::new())
    }

    /// Rebuild from persisted rows, which must arrive in id order starting
    /// at one. Returns the first gap or zero it finds instead of a table:
    /// ids index the reverse vec directly, so a gap would repoint every
    /// id after it, and refusing to open beats serving corrupt state.
    /// Nothing is pending afterwards: every pair here is already durable.
    ///
    /// # Errors
    ///
    /// Returns the first gap or zero found: ids index the reverse vec
    /// directly, so a gap would repoint every id after it.
    pub fn from_pairs(pairs: Vec<AllocRecord>) -> Result<Self, String> {
        let table = Self::new();
        let mut next = 1_u64;
        for (id, pair) in pairs {
            if id != next {
                return Err(format!("intern table jumps from {} to {id}", next - 1));
            }
            if table.id_of(&pair.0, &pair.1).is_some() {
                return Err(format!("intern table repeats a pair at id {id}"));
            }
            table.intern(&pair.0, &pair.1);
            next += 1;
        }
        table.take_allocated();
        Ok(table)
    }
}

impl StateKeyTable for MemStateKeyTable {
    fn id_of(&self, event_type: &str, state_key: &str) -> Option<u64> {
        // A poisoned mutex means a previous holder panicked mid-insert,
        // which for this map is an allocation failure the process cannot
        // survive anyway. Recovering the guard keeps a panic in unrelated
        // code from wedging every later state read.
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.forward.get(event_type)?.get(state_key).copied()
    }

    fn intern(&self, event_type: &str, state_key: &str) -> u64 {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(id) = inner
            .forward
            .get(event_type)
            .and_then(|keys| keys.get(state_key))
        {
            return *id;
        }
        let id = inner.reverse.len() as u64 + 1;
        inner
            .forward
            .entry(event_type.into())
            .or_default()
            .insert(state_key.into(), id);
        let pair: (Box<str>, Box<str>) = (event_type.into(), state_key.into());
        inner.reverse.push(pair);
        id
    }

    fn resolve(&self, id: u64) -> Option<(Box<str>, Box<str>)> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .reverse
            .get(usize::try_from(id.checked_sub(1)?).ok()?)
            .cloned()
    }

    fn contains_id(&self, id: u64) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        id != 0 && id <= inner.reverse.len() as u64
    }

    fn take_allocated(&self) -> Vec<AllocRecord> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = inner.pending_from;
        inner.pending_from = inner.reverse.len();
        inner
            .reverse
            .iter()
            .enumerate()
            .skip(first)
            .map(|(offset, pair)| (offset as u64 + 1, pair.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_identity_gets_one_id() {
        let table = MemStateKeyTable::new();
        let first = table.intern("m.room.member", "@a:x");
        assert_eq!(table.intern("m.room.member", "@a:x"), first);
        assert_eq!(table.id_of("m.room.member", "@a:x"), Some(first));
        assert_eq!(
            table.resolve(first),
            Some(("m.room.member".into(), "@a:x".into()))
        );
    }

    #[test]
    fn takes_drain_once_and_rebuilds_dense() {
        let table = MemStateKeyTable::new();
        table.intern("m.room.member", "@a:x");
        table.intern("m.room.create", "");
        table.intern("m.room.member", "@a:x");
        let taken = table.take_allocated();
        assert_eq!(taken.len(), 2);
        assert!(table.take_allocated().is_empty());
        let rebuilt = MemStateKeyTable::from_pairs(taken).expect("dense rows reload");
        assert_eq!(rebuilt.id_of("m.room.create", ""), Some(2));
        assert!(MemStateKeyTable::from_pairs(vec![(2, ("t".into(), "k".into()))]).is_err());
        assert!(MemStateKeyTable::from_pairs(vec![(0, ("t".into(), "k".into()))]).is_err());
    }

    #[test]
    fn persisted_pairs_must_be_unique() {
        assert!(
            MemStateKeyTable::from_pairs(vec![
                (1, ("t".into(), "k".into())),
                (2, ("t".into(), "k".into())),
            ])
            .is_err()
        );
    }

    #[test]
    fn unknown_ids_and_pairs_miss_without_allocating() {
        let table = MemStateKeyTable::new();
        assert_eq!(table.id_of("m.room.member", "@nobody:x"), None);
        assert_eq!(table.resolve(1), None);
        assert_eq!(table.resolve(0), None);
        // The misses above allocated nothing: the first real pair is id 1.
        assert_eq!(table.intern("m.room.member", "@a:x"), 1);
    }
}
