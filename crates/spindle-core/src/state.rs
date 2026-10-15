use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Weak},
};

use crate::state_table::StateKeyTable;

/// How the content addresses in this module are derived.
///
/// State roots and HAMT node addresses are BLAKE3 digests of state keys and
/// node contents. That derivation is a *third* way stored bytes can change
/// meaning, alongside the key layout and the record encoding — and it is the
/// one the store marker could not previously express (#78).
///
/// The failure it guards is quiet. Change a domain tag, a length width or a
/// field order here and the key layout is untouched, the record encoding is
/// untouched, so a store written under the old derivation opens cleanly and
/// **every node address is wrong**: `state_nodes` lookups miss, rooms cannot
/// be rebuilt, and each `LogEntry`'s recorded `state_root` no longer matches
/// what recomputing produces. Both surface far from the cause.
///
/// So: **any change to a digest below bumps this**, and the store marker
/// carries it, so a store written under a different derivation is refused
/// rather than misread. `the_domain_tags_carry_the_current_digest_version`
/// holds the two together — the tags all end in `-v{VERSION}`, and that is
/// asserted rather than trusted.
///
/// Version 3 is the interned-keys derivation (#79): leaves hold interned
/// `u64` ids rather than `(event_type, state_key)` strings, so the key
/// digest hashes eight bytes instead of two framed strings. A version-2
/// store is refused at open; `spindle migrate` carries it forward.
pub const CONTENT_DIGEST_VERSION: u8 = 3;

/// The domain tag separating each digest below from the others.
///
/// Named rather than written inline at the hasher, so each tag has exactly one
/// definition: the digest uses it and [`DOMAIN_TAGS`] lists it, instead of a
/// list that mirrors the literals and can drift from them.
///
/// The state-key tag is eight bytes, not a sentence, and the payload is
/// one `u64` (#79): eight plus eight bytes digest in one BLAKE3 block
/// with room to spare. Ordinary string keys already fit in one block;
/// interning primarily shrinks nodes and replaces string comparisons. The other three tags are hashed with
/// 32-byte digests and are never near one block anyway; they moved to
/// `-v3` with the version rather than for a saving.
const STATE_KEY_TAG: &[u8] = b"spsk-v3\0";
const EMPTY_STATE_TAG: &[u8] = b"spindle-empty-state-v3";
const HAMT_LEAF_TAG: &[u8] = b"spindle-hamt-leaf-v3\0";
const HAMT_BRANCH_TAG: &[u8] = b"spindle-hamt-branch-v3\0";

/// Every domain tag, for the test that binds them to
/// [`CONTENT_DIGEST_VERSION`]. A new digest belongs here, or it is not covered.
#[cfg(test)]
const DOMAIN_TAGS: &[&[u8]] = &[
    STATE_KEY_TAG,
    EMPTY_STATE_TAG,
    HAMT_LEAF_TAG,
    HAMT_BRANCH_TAG,
];

/// A Matrix event type used as one half of a room-state key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventType(Box<str>);

impl EventType {
    #[must_use]
    pub fn new(value: impl Into<Box<str>>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `(event_type, state_key)` tuple which identifies one state slot.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateKey {
    event_type: EventType,
    state_key: Box<str>,
}

impl StateKey {
    #[must_use]
    pub fn new(event_type: impl Into<Box<str>>, state_key: impl Into<Box<str>>) -> Self {
        Self {
            event_type: EventType::new(event_type),
            state_key: state_key.into(),
        }
    }

    #[must_use]
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    #[must_use]
    pub fn state_key(&self) -> &str {
        &self.state_key
    }
}

/// A key's placement digest from its interned id: tag plus eight bytes,
/// one BLAKE3 block with room to spare.
///
/// The id must come from the snapshot's own table. Two tables that saw
/// the same pairs in a different order place the same state differently,
/// which is why snapshots never cross tables.
fn digest_id(id: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STATE_KEY_TAG);
    hasher.update(&id.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// The content address of a complete materialized room state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StateRoot([u8; 32]);

impl StateRoot {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rebuild a root from its stored bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// An immutable, structurally shared room-state snapshot.
///
/// This is a bitmap-indexed 32-way HAMT. Updating one slot path-copies only the
/// nodes between the root and that slot. Nodes carry deterministic BLAKE3
/// content addresses, so a storage backend can persist each node exactly once.
///
/// Leaves hold interned key ids, not strings (#79): the trie orders, hashes
/// and stores `u64`s, and resolves them to [`StateKey`]s only where the
/// caller sees keys. The table lives beside the snapshot in an `Arc` so a
/// clone shares it. Two snapshots built against different tables place the
/// same state differently and must never be diffed or persisted together;
/// in production every snapshot shares the store's table.
#[derive(Clone, Debug)]
pub struct StateSnapshot {
    root: Option<Arc<Node>>,
    len: usize,
    table: Arc<dyn StateKeyTable>,
}

impl StateSnapshot {
    /// An empty snapshot against `table`: production passes the store's
    /// table, tests pass a shared [`crate::state_table::MemStateKeyTable`].
    #[must_use]
    pub fn new(table: Arc<dyn StateKeyTable>) -> Self {
        Self {
            root: None,
            len: 0,
            table,
        }
    }

    /// The same slots interned against `table`: the same state under the
    /// destination's numbering, with every pair pending there for the
    /// next persistence drain.
    ///
    /// The handoff a store boundary needs. A snapshot built against one
    /// table carries ids meaningless to another; persisting its nodes
    /// without re-interning writes rows the destination can never
    /// resolve. Rebuilding slot by slot reuses the ids the destination
    /// already has and allocates (hence persists) only what is new.
    #[must_use]
    pub fn with_table(self, table: &Arc<dyn StateKeyTable>) -> Self {
        if std::sync::Arc::ptr_eq(&self.table, table) {
            return self;
        }
        let mut rebased = Self::new(table.clone());
        self.for_each(|key, event_id| {
            rebased = rebased.apply(key, event_id);
        });
        rebased
    }

    /// The table this snapshot's ids belong to.
    #[must_use]
    pub fn table(&self) -> &Arc<dyn StateKeyTable> {
        &self.table
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn root(&self) -> StateRoot {
        self.root.as_ref().map_or(
            StateRoot(*blake3::hash(EMPTY_STATE_TAG).as_bytes()),
            |node| StateRoot(node.hash()),
        )
    }

    /// Intern `key` without allocating when the table already holds it:
    /// a key the table never saw is absent from every trie built against
    /// it, so reads miss here rather than minting an id to miss with.
    fn id_of(&self, key: &StateKey) -> Option<u64> {
        self.table.id_of(key.event_type.as_str(), &key.state_key)
    }

    #[must_use]
    pub fn get(&self, key: &StateKey) -> Option<&str> {
        let id = self.id_of(key)?;
        let digest = digest_id(id);
        self.root
            .as_deref()
            .and_then(|node| node.get(id, &digest, 0))
    }

    /// Return a new snapshot with `key` pointing at `event_id`.
    #[must_use]
    pub fn apply(&self, key: &StateKey, event_id: impl Into<Box<str>>) -> Self {
        let id = self.table.intern(key.event_type.as_str(), &key.state_key);
        let digest = digest_id(id);
        let event_id = event_id.into();
        let existed = self
            .root
            .as_deref()
            .and_then(|node| node.get(id, &digest, 0))
            .is_some();
        let leaf = Arc::new(Node::leaf(digest, id, event_id));
        let root = Some(match &self.root {
            Some(root) => root.insert(leaf, 0),
            None => leaf,
        });

        Self {
            root,
            len: self.len + usize::from(!existed),
            table: Arc::clone(&self.table),
        }
    }

    /// Visit every state slot in deterministic key order.
    /// Visit every entry, **in key order**.
    ///
    /// The order is part of the contract, not an accident of the walk: the
    /// trie places entries by digest, so an unsorted walk would return the
    /// same state in an order that shifts with the key set. Callers that
    /// render state to a client compare successive responses, and a set that
    /// reorders itself looks like a set that changed. The order is string
    /// order on the resolved keys, not id order: first-seen assignment has
    /// no relation to sort order.
    pub fn for_each(&self, mut visitor: impl FnMut(&StateKey, &str)) {
        let mut entries = Vec::with_capacity(self.len);
        if let Some(root) = &self.root {
            root.collect(&mut entries);
        }
        let mut resolved = Vec::with_capacity(entries.len());
        for (id, event_id) in entries {
            if let Some(pair) = self.table.resolve(id) {
                resolved.push((resolved_key(pair), event_id));
            }
        }
        resolved.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        for (key, event_id) in &resolved {
            visitor(key, event_id);
        }
    }

    /// Return a new snapshot without `key`, or an unchanged clone when the
    /// key is absent.
    ///
    /// State resolution can drop a slot: a key only some branches hold
    /// is conflicted, and when none of its candidates passes the
    /// authorization checks the resolved state has no value for it. The
    /// trie stays canonical -- a branch left holding one leaf collapses to
    /// it, exactly the shape inserting that leaf alone would have built --
    /// so a state reached by removing a key has the same root as the same
    /// state reached by never adding it.
    #[must_use]
    pub fn remove(&self, key: &StateKey) -> Self {
        let Some(root) = &self.root else {
            return self.clone();
        };
        let Some(id) = self.id_of(key) else {
            return self.clone();
        };
        match root.remove(id, &digest_id(id), 0) {
            Removal::Absent => self.clone(),
            Removal::Emptied => Self::new(Arc::clone(&self.table)),
            Removal::Replaced(root) => Self {
                root: Some(root),
                len: self.len.saturating_sub(1),
                table: Arc::clone(&self.table),
            },
        }
    }

    /// Every slot where `self` and `other` disagree, in key order, as
    /// `(key, ours, theirs)`. A slot only one side holds has `None` on the
    /// other.
    ///
    /// Two snapshots that share history share most of their trie: path
    /// copying keeps an untouched subtree at the same content address, so
    /// the walk skips every subtree whose hash matches and visits only the
    /// paths that changed. Diffing two states of a large room that differ
    /// in a few slots costs those few paths, not a pass over every member --
    /// which is what a fork merge or a state comparison needs.
    ///
    /// The keys come back owned, not borrowed: leaves hold ids, and the
    /// strings live in the table. Ids compare directly when both sides
    /// share one table; across tables the slots resolve to strings first,
    /// so a diff is always correct and only ever slow in a case the
    /// production server never constructs.
    #[must_use]
    pub fn diff<'a>(
        &'a self,
        other: &'a Self,
    ) -> Vec<(StateKey, Option<&'a str>, Option<&'a str>)> {
        if !Arc::ptr_eq(&self.table, &other.table) {
            let mut out = Vec::new();
            diff_resolved(self, other, &mut out);
            out.sort_unstable_by(|(left, ..), (right, ..)| left.cmp(right));
            return out;
        }
        let mut slots = Vec::new();
        diff_nodes(self.root.as_deref(), other.root.as_deref(), &mut slots);
        // Resolve only the slots that differ, not the whole state: a fork
        // merge that touches three slots pays for three resolutions.
        let mut out = Vec::with_capacity(slots.len());
        for (id, ours, theirs) in slots {
            if let Some(pair) = self.table.resolve(id) {
                out.push((resolved_key(pair), ours, theirs));
            }
        }
        out.sort_unstable_by(|(left, ..), (right, ..)| left.cmp(right));
        out
    }
}

/// A [`StateKey`] from a resolved table pair.
fn resolved_key((event_type, state_key): (Box<str>, Box<str>)) -> StateKey {
    StateKey {
        event_type: EventType(event_type),
        state_key,
    }
}

/// A slot both sides resolve the same way: `(key, ours, theirs)`.
type SlotDiff<'a> = (u64, Option<&'a str>, Option<&'a str>);

/// The slow but always-correct diff for snapshots built against different
/// tables: resolve every slot on both sides and compare strings. Only
/// tests construct this case; production shares one table per store.
fn diff_resolved<'a>(
    left: &'a StateSnapshot,
    right: &'a StateSnapshot,
    out: &mut Vec<(StateKey, Option<&'a str>, Option<&'a str>)>,
) {
    let mut ours = Vec::new();
    let mut theirs = Vec::new();
    if let Some(root) = left.root.as_deref() {
        root.collect(&mut ours);
    }
    if let Some(root) = right.root.as_deref() {
        root.collect(&mut theirs);
    }
    let resolve_all = |entries: Vec<(u64, &'a str)>, table: &Arc<dyn StateKeyTable>| {
        let mut resolved: Vec<(StateKey, &'a str)> = Vec::with_capacity(entries.len());
        for (id, value) in entries {
            if let Some(pair) = table.resolve(id) {
                resolved.push((resolved_key(pair), value));
            }
        }
        resolved.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        resolved
    };
    let ours = resolve_all(ours, &left.table);
    let theirs = resolve_all(theirs, &right.table);
    let (mut i, mut j) = (0, 0);
    loop {
        match (ours.get(i), theirs.get(j)) {
            (None, None) => break,
            (Some((key, value)), None) => {
                out.push((key.clone(), Some(*value), None));
                i += 1;
            }
            (None, Some((key, value))) => {
                out.push((key.clone(), None, Some(*value)));
                j += 1;
            }
            (Some((left_key, left_value)), Some((right_key, right_value))) => {
                match left_key.cmp(right_key) {
                    Ordering::Less => {
                        out.push((left_key.clone(), Some(*left_value), None));
                        i += 1;
                    }
                    Ordering::Greater => {
                        out.push((right_key.clone(), None, Some(*right_value)));
                        j += 1;
                    }
                    Ordering::Equal => {
                        if left_value != right_value {
                            out.push((left_key.clone(), Some(*left_value), Some(*right_value)));
                        }
                        i += 1;
                        j += 1;
                    }
                }
            }
        }
    }
}

/// Descend two tries in step, skipping subtrees with equal hashes.
///
/// Both tries place a key by the same digest bits, so a branch slot on one
/// side can only hold keys that the same slot holds on the other. Where the
/// shapes differ at a level (a leaf on one side, a branch on the other), the
/// two subtrees are small by construction -- a leaf sits where its slot has
/// one digest -- and are compared entry by entry.
/// Descend two tries built against one table, in step, skipping subtrees
/// with equal hashes. Ids compare directly: within one table equal ids
/// are equal keys, so no string leaves the table on this path.
fn diff_nodes<'a>(left: Option<&'a Node>, right: Option<&'a Node>, out: &mut Vec<SlotDiff<'a>>) {
    match (left, right) {
        (None, None) => {}
        (Some(left), Some(right)) if left.hash() == right.hash() => {}
        (
            Some(Node::Branch {
                bitmap: left_bitmap,
                children: left_children,
                ..
            }),
            Some(Node::Branch {
                bitmap: right_bitmap,
                children: right_children,
                ..
            }),
        ) => {
            let child = |bitmap: u32, children: &'a [Arc<Node>], bit: u32| -> Option<&'a Node> {
                if bitmap & bit == 0 {
                    return None;
                }
                let index = (bitmap & (bit - 1)).count_ones() as usize;
                children.get(index).map(AsRef::as_ref)
            };
            let mut slots = left_bitmap | right_bitmap;
            while slots != 0 {
                let bit = slots & slots.wrapping_neg();
                slots &= !bit;
                diff_nodes(
                    child(*left_bitmap, left_children, bit),
                    child(*right_bitmap, right_children, bit),
                    out,
                );
            }
        }
        (left, right) => {
            let mut ours = Vec::new();
            let mut theirs = Vec::new();
            if let Some(node) = left {
                node.collect(&mut ours);
            }
            if let Some(node) = right {
                node.collect(&mut theirs);
            }
            ours.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
            theirs.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
            let (mut i, mut j) = (0, 0);
            loop {
                match (ours.get(i), theirs.get(j)) {
                    (None, None) => break,
                    (Some((id, value)), None) => {
                        out.push((*id, Some(*value), None));
                        i += 1;
                    }
                    (None, Some((id, value))) => {
                        out.push((*id, None, Some(*value)));
                        j += 1;
                    }
                    (Some((left_id, left_value)), Some((right_id, right_value))) => {
                        match left_id.cmp(right_id) {
                            Ordering::Less => {
                                out.push((*left_id, Some(*left_value), None));
                                i += 1;
                            }
                            Ordering::Greater => {
                                out.push((*right_id, None, Some(*right_value)));
                                j += 1;
                            }
                            Ordering::Equal => {
                                if left_value != right_value {
                                    out.push((*left_id, Some(*left_value), Some(*right_value)));
                                }
                                i += 1;
                                j += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// What removing a key did to a node.
enum Removal {
    /// The key was not there; the node is unchanged.
    Absent,
    /// Nothing is left.
    Emptied,
    /// The node that replaces it.
    Replaced(Arc<Node>),
}

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        digest: [u8; 32],
        entries: Arc<[(u64, Box<str>)]>,
        hash: [u8; 32],
    },
    Branch {
        bitmap: u32,
        children: Arc<[Arc<Self>]>,
        hash: [u8; 32],
    },
}

impl Node {
    /// A leaf holds `(interned key id, event id)` pairs, sorted by id. The
    /// sort is by id, not by string: placement walks the digest, and within
    /// one digest the order only has to be canonical, which id order is.
    fn leaf(digest: [u8; 32], id: u64, event_id: Box<str>) -> Self {
        Self::leaf_from_entries(digest, vec![(id, event_id)])
    }

    fn leaf_from_entries(digest: [u8; 32], mut entries: Vec<(u64, Box<str>)>) -> Self {
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        let hash = hash_leaf(&digest, &entries);
        Self::Leaf {
            digest,
            entries: entries.into(),
            hash,
        }
    }

    fn branch(bitmap: u32, children: Vec<Arc<Self>>) -> Self {
        let hash = hash_branch(bitmap, &children);
        Self::Branch {
            bitmap,
            children: children.into(),
            hash,
        }
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Leaf { hash, .. } | Self::Branch { hash, .. } => *hash,
        }
    }

    fn get<'a>(&'a self, id: u64, digest: &[u8; 32], depth: usize) -> Option<&'a str> {
        match self {
            Self::Leaf {
                digest: leaf_digest,
                entries,
                ..
            } if leaf_digest == digest => entries
                .binary_search_by(|(candidate, _)| candidate.cmp(&id))
                .ok()
                .and_then(|index| entries.get(index))
                .map(|(_, value)| value.as_ref()),
            Self::Leaf { .. } => None,
            Self::Branch {
                bitmap, children, ..
            } => {
                let slot = digest_slot(digest, depth);
                let bit = 1_u32 << slot;
                if bitmap & bit == 0 {
                    return None;
                }
                let index = (bitmap & (bit - 1)).count_ones() as usize;
                children.get(index)?.get(id, digest, depth + 1)
            }
        }
    }

    fn insert(self: &Arc<Self>, incoming: Arc<Self>, depth: usize) -> Arc<Self> {
        match (self.as_ref(), incoming.as_ref()) {
            (
                Self::Leaf {
                    digest: current_digest,
                    entries,
                    ..
                },
                Self::Leaf {
                    digest: incoming_digest,
                    entries: incoming_entries,
                    ..
                },
            ) if current_digest == incoming_digest => {
                let mut merged = entries.to_vec();
                for (id, value) in incoming_entries.iter() {
                    match merged.binary_search_by(|(candidate, _)| candidate.cmp(id)) {
                        Ok(index) => {
                            if let Some(slot) = merged.get_mut(index) {
                                slot.1.clone_from(value);
                            }
                        }
                        Err(index) => merged.insert(index, (*id, value.clone())),
                    }
                }
                Arc::new(Self::leaf_from_entries(*current_digest, merged))
            }
            (Self::Leaf { digest: left, .. }, Self::Leaf { digest: right, .. }) => {
                join_nodes(Arc::clone(self), left, Arc::clone(&incoming), right, depth)
            }
            (
                Self::Branch {
                    bitmap, children, ..
                },
                Self::Leaf { digest, .. },
            ) => {
                let slot = digest_slot(digest, depth);
                let bit = 1_u32 << slot;
                let index = (bitmap & (bit - 1)).count_ones() as usize;
                let mut next = children.to_vec();
                if bitmap & bit == 0 {
                    next.insert(index, incoming);
                    Arc::new(Self::branch(bitmap | bit, next))
                } else {
                    if let Some(slot) = next.get_mut(index) {
                        *slot = slot.insert(incoming, depth + 1);
                    }
                    Arc::new(Self::branch(*bitmap, next))
                }
            }
            (Self::Branch { .. } | Self::Leaf { .. }, Self::Branch { .. }) => {
                unreachable!("only leaf nodes are inserted")
            }
        }
    }

    /// This node without `key`.
    ///
    /// A branch left with a single child that is a leaf becomes that leaf,
    /// because that is the shape an insert-only trie holding the same keys
    /// has; a single child that is a branch stays wrapped, because that
    /// shape is what two digests sharing this slot produce on insert too.
    fn remove(&self, id: u64, digest: &[u8; 32], depth: usize) -> Removal {
        match self {
            Self::Leaf {
                digest: leaf_digest,
                entries,
                ..
            } => {
                if leaf_digest != digest {
                    return Removal::Absent;
                }
                let Ok(index) = entries.binary_search_by(|(candidate, _)| candidate.cmp(&id))
                else {
                    return Removal::Absent;
                };
                let mut kept = entries.to_vec();
                kept.remove(index);
                if kept.is_empty() {
                    Removal::Emptied
                } else {
                    Removal::Replaced(Arc::new(Self::leaf_from_entries(*leaf_digest, kept)))
                }
            }
            Self::Branch {
                bitmap, children, ..
            } => {
                let slot = digest_slot(digest, depth);
                let bit = 1_u32 << slot;
                if bitmap & bit == 0 {
                    return Removal::Absent;
                }
                let index = (bitmap & (bit - 1)).count_ones() as usize;
                let Some(child) = children.get(index) else {
                    return Removal::Absent;
                };
                let mut next = children.to_vec();
                let mut bits = *bitmap;
                match child.remove(id, digest, depth + 1) {
                    Removal::Absent => return Removal::Absent,
                    Removal::Replaced(child) => {
                        if let Some(slot) = next.get_mut(index) {
                            *slot = child;
                        }
                    }
                    Removal::Emptied => {
                        next.remove(index);
                        bits &= !bit;
                    }
                }
                match next.as_slice() {
                    [] => Removal::Emptied,
                    [only] if matches!(only.as_ref(), Self::Leaf { .. }) => {
                        Removal::Replaced(Arc::clone(only))
                    }
                    _ => Removal::Replaced(Arc::new(Self::branch(bits, next))),
                }
            }
        }
    }

    fn collect<'a>(&'a self, output: &mut Vec<(u64, &'a str)>) {
        match self {
            Self::Leaf { entries, .. } => {
                output.extend(
                    entries
                        .iter()
                        .map(|(id, event_id)| (*id, event_id.as_ref())),
                );
            }
            Self::Branch { children, .. } => {
                for child in children.iter() {
                    child.collect(output);
                }
            }
        }
    }
}

fn join_nodes(
    left: Arc<Node>,
    left_digest: &[u8; 32],
    right: Arc<Node>,
    right_digest: &[u8; 32],
    depth: usize,
) -> Arc<Node> {
    let left_slot = digest_slot(left_digest, depth);
    let right_slot = digest_slot(right_digest, depth);
    match left_slot.cmp(&right_slot) {
        Ordering::Less => Arc::new(Node::branch(
            (1_u32 << left_slot) | (1_u32 << right_slot),
            vec![left, right],
        )),
        Ordering::Greater => Arc::new(Node::branch(
            (1_u32 << left_slot) | (1_u32 << right_slot),
            vec![right, left],
        )),
        Ordering::Equal => Arc::new(Node::branch(
            1_u32 << left_slot,
            vec![join_nodes(
                left,
                left_digest,
                right,
                right_digest,
                depth + 1,
            )],
        )),
    }
}

fn digest_slot(digest: &[u8; 32], depth: usize) -> u32 {
    debug_assert!(depth < 52, "different 256-bit digests must diverge");
    let bit_offset = depth * 5;
    let byte = bit_offset / 8;
    let shift = bit_offset % 8;
    // `get` rather than an index: `byte` is below 32 for every depth the
    // assertion above admits, and this is a hash-walk, not a place to bet
    // the process on an assertion that only fires in debug builds.
    let at = |index: usize| u16::from(digest.get(index).copied().unwrap_or(0));
    let mut window = at(byte) >> shift;
    if shift > 3 && byte + 1 < digest.len() {
        window |= at(byte + 1) << (8 - shift);
    }
    u32::from(window & 0x1f)
}

/// A leaf hashes its digest, its entry count, and one `u64` plus one
/// framed string per entry. Eight bytes where two framed strings stood:
/// fewer bytes per state change on the wire and in the store (#79).
fn hash_leaf(digest: &[u8; 32], entries: &[(u64, Box<str>)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HAMT_LEAF_TAG);
    hasher.update(digest);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for (id, event_id) in entries {
        hasher.update(&id.to_be_bytes());
        hash_bytes(&mut hasher, event_id.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hash_branch(bitmap: u32, children: &[Arc<Node>]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HAMT_BRANCH_TAG);
    hasher.update(&bitmap.to_be_bytes());
    for child in children {
        hasher.update(&child.hash());
    }
    *hasher.finalize().as_bytes()
}

/// Length-framed bytes: the frame is what keeps `("ab", "c")` and
/// `("a", "bc")` apart. `u32` rather than `u64` (#77): four bytes saved
/// twice is what brings an ordinary state key inside one BLAKE3 block, and
/// nothing hashed here can approach 4 GiB -- an event is capped at 64 KiB
/// by the protocol -- so the saturation below is unreachable, and named
/// only so the cast is not a silent truncation.
fn hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    hasher.update(&length.to_be_bytes());
    hasher.update(value);
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Tag bytes for the two node shapes. Part of the on-disk format, so they are
/// fixed rather than derived from enum ordering.
const TAG_LEAF: u8 = 0;
const TAG_BRANCH: u8 = 1;

/// The version-2 domain tags, kept for the migration read path only.
/// Version 2 is what the store on disk holds until `spindle migrate` runs;
/// nothing writes these and nothing serving reads them. They are repeated
/// here rather than derived because their whole job is to be exactly what
/// the old binary wrote -- a constant that updates itself is not a record
/// of anything.
const V2_HAMT_LEAF_TAG: &[u8] = b"spindle-hamt-leaf-v2\0";
const V2_HAMT_BRANCH_TAG: &[u8] = b"spindle-hamt-branch-v2\0";
const V2_EMPTY_STATE_TAG: &[u8] = b"spindle-empty-state-v2";

/// The deepest an honest trie goes.
///
/// [`digest_slot`] spends five bits of a 256-bit digest per level, so two
/// different digests must diverge within 52 of them -- the bound its own
/// `debug_assert` already states. A node deeper than that did not come from
/// [`encode_node`].
///
/// This is not belt-and-braces around the hash check in [`rebuild`]. That
/// check runs *after* the recursive descent, so on a trie that never bottoms
/// out it does not run at all: one corrupted child pointer aimed back at an
/// ancestor recurses until the stack is gone, and a stack overflow is not an
/// error a caller can catch -- it aborts the process. Refusing at a depth no
/// real trie reaches is what turns that into a [`RehydrateError::Malformed`].
const MAX_DEPTH: usize = 52;

/// Why a stored state trie could not be rebuilt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RehydrateError {
    /// A node the trie references is not in the store.
    MissingNode,
    /// A node's bytes do not hash to the address they were stored under.
    ///
    /// Content addressing makes this detectable, and it is always corruption:
    /// the alternative is serving state that silently is not what was written.
    HashMismatch,
    /// A node's encoding is truncated or uses an unknown tag.
    Malformed,
}

/// Verified immutable nodes, scoped to one cold log rebuild. A key includes
/// depth so a verified subtree cannot bypass the decoder's recursion bound.
/// Weak references share nodes already retained by the caller's snapshots;
/// the cache owns only a bounded index, never additional subtree graphs.
pub struct VerifiedNodeCache {
    nodes: HashMap<(StateRoot, usize), CachedNode>,
    order: BTreeMap<u64, (StateRoot, usize)>,
    clock: u64,
    bytes: usize,
    budget: usize,
}

#[derive(Clone)]
struct RebuiltNode {
    node: Arc<Node>,
    len: usize,
}

struct CachedNode {
    node: Weak<Node>,
    len: usize,
    stamp: u64,
    charge: usize,
}

impl VerifiedNodeCache {
    /// Create a cache whose index is bounded by `budget` bytes.
    #[must_use]
    pub fn new(budget: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            order: BTreeMap::new(),
            clock: 0,
            bytes: 0,
            budget,
        }
    }

    fn tick(&mut self) {
        if self.clock == u64::MAX {
            self.nodes.clear();
            self.order.clear();
            self.bytes = 0;
            self.clock = 0;
        }
        self.clock += 1;
    }

    fn get(&mut self, key: (StateRoot, usize)) -> Option<RebuiltNode> {
        self.tick();
        let cached = self.nodes.get_mut(&key)?;
        let Some(node) = cached.node.upgrade() else {
            self.order.remove(&cached.stamp);
            self.bytes = self.bytes.saturating_sub(cached.charge);
            self.nodes.remove(&key);
            return None;
        };
        self.order.remove(&cached.stamp);
        cached.stamp = self.clock;
        self.order.insert(self.clock, key);
        Some(RebuiltNode {
            node,
            len: cached.len,
        })
    }

    fn insert(&mut self, key: (StateRoot, usize), rebuilt: &RebuiltNode) {
        // Weak retains the dropped Arc's allocation until eviction. Charge its
        // full Node plus conservative lookup/order index and allocation framing;
        // no live subtree graph ownership is held here.
        let charge = std::mem::size_of::<Node>() + 512;
        if charge > self.budget {
            return;
        }
        self.tick();
        while self.bytes.saturating_add(charge) > self.budget {
            let Some((_, oldest)) = self.order.pop_first() else {
                return;
            };
            if let Some(removed) = self.nodes.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.charge);
            }
        }
        if let Some(previous) = self.nodes.remove(&key) {
            self.order.remove(&previous.stamp);
            self.bytes = self.bytes.saturating_sub(previous.charge);
        }
        self.bytes += charge;
        self.nodes.insert(
            key,
            CachedNode {
                node: Arc::downgrade(&rebuilt.node),
                len: rebuilt.len,
                stamp: self.clock,
                charge,
            },
        );
        self.order.insert(self.clock, key);
    }
}

/// Bounded verification memo for an offline migration's immutable v3 nodes.
///
/// Unlike snapshot rehydration, verification needs no retained subtree graphs.
/// Entries certify a whole subtree at a specific depth, against this table.
/// Do not reuse this cache after node deletion, mutation or a store change.
pub struct MigrationStateVerifier {
    table: Arc<dyn StateKeyTable>,
    verified: HashSet<(StateRoot, usize)>,
    max_nodes: usize,
}

impl MigrationStateVerifier {
    #[must_use]
    pub fn new(table: Arc<dyn StateKeyTable>, max_nodes: usize) -> Self {
        Self {
            table,
            verified: HashSet::new(),
            max_nodes,
        }
    }

    /// Verify every previously unseen subtree without constructing a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`RehydrateError`] for missing, malformed or incorrectly
    /// addressed nodes, or leaves naming unknown intern ids.
    pub fn verify(
        &mut self,
        root: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<(), RehydrateError> {
        if root.as_bytes() == blake3::hash(EMPTY_STATE_TAG).as_bytes() {
            return Ok(());
        }
        self.verify_node(root, load, 0)
    }

    fn verify_node(
        &mut self,
        address: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
        depth: usize,
    ) -> Result<(), RehydrateError> {
        if depth > MAX_DEPTH {
            return Err(RehydrateError::Malformed);
        }
        if self.verified.contains(&(address, depth)) {
            return Ok(());
        }
        let bytes = load(&address).ok_or(RehydrateError::MissingNode)?;
        let mut at = 1;
        match bytes.first().copied().ok_or(RehydrateError::Malformed)? {
            TAG_LEAF => {
                let digest = take_array::<32>(&bytes, &mut at)?;
                let count = take_count(&bytes, &mut at, 8 + 4)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = u64::from_be_bytes(take_array::<8>(&bytes, &mut at)?);
                    if !self.table.contains_id(id) {
                        return Err(RehydrateError::Malformed);
                    }
                    entries.push((id, take_string(&bytes, &mut at)?.into_boxed_str()));
                }
                if Node::leaf_from_entries(digest, entries).hash() != *address.as_bytes() {
                    return Err(RehydrateError::HashMismatch);
                }
            }
            TAG_BRANCH => {
                let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
                let count = take_count(&bytes, &mut at, 32)?;
                if count != bitmap.count_ones() as usize {
                    return Err(RehydrateError::Malformed);
                }
                let mut children = Vec::with_capacity(count);
                let mut hasher = blake3::Hasher::new();
                hasher.update(HAMT_BRANCH_TAG);
                hasher.update(&bitmap.to_be_bytes());
                for _ in 0..count {
                    let child = StateRoot(take_array::<32>(&bytes, &mut at)?);
                    hasher.update(child.as_bytes());
                    children.push(child);
                }
                if hasher.finalize().as_bytes() != address.as_bytes() {
                    return Err(RehydrateError::HashMismatch);
                }
                for child in children {
                    self.verify_node(child, load, depth + 1)?;
                }
            }
            _ => return Err(RehydrateError::Malformed),
        }
        if at != bytes.len() {
            return Err(RehydrateError::Malformed);
        }
        if self.max_nodes != 0 {
            if self.verified.len() >= self.max_nodes {
                self.verified.clear();
            }
            self.verified.insert((address, depth));
        }
        Ok(())
    }
}

impl StateSnapshot {
    /// Every node reachable from this snapshot that `previous` does not already
    /// contain, encoded and addressed by hash.
    ///
    /// Because nodes are content-addressed and updates path-copy, an unchanged
    /// subtree keeps its address — so the walk stops as soon as it reaches a
    /// node the previous snapshot held. That makes a state write O(log n) nodes
    /// rather than O(state), which is what SPEC §6.1 claims and what keeps a
    /// large room's state affordable to persist per event.
    #[must_use]
    pub fn delta_nodes(&self, previous: Option<&Self>) -> Vec<(StateRoot, Vec<u8>)> {
        let mut out = Vec::new();
        if let Some(root) = self.root.as_deref() {
            collect_new(
                root,
                previous.and_then(|state| state.root.as_deref()),
                &mut out,
            );
        }
        out
    }

    /// Rebuild a snapshot from stored nodes, verifying each one's address.
    ///
    /// The nodes hold ids, so decoding needs no strings -- but the
    /// snapshot must still know whose ids they are. Pass the table the
    /// nodes were written against: the store's table in production, a
    /// shared test table in tests. An empty root short-circuits before
    /// the table is consulted.
    ///
    /// # Errors
    ///
    /// Returns [`RehydrateError`] if a node is missing, malformed, or does not
    /// hash to the address it was stored under.
    pub fn rehydrate(
        root: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
        table: Arc<dyn StateKeyTable>,
    ) -> Result<Self, RehydrateError> {
        if root == Self::new(Arc::clone(&table)).root() {
            return Ok(Self::new(table));
        }
        let rebuilt = rebuild_verified(&root, load, 0, None, table.as_ref())?;
        Ok(Self {
            root: Some(rebuilt.node),
            len: rebuilt.len,
            table,
        })
    }

    /// Rehydrate with nodes already verified during this immutable log read.
    /// Shared subtrees retain their Arcs and cached entry counts, so a new root
    /// costs its changed paths rather than a walk of every membership slot.
    /// Rebuild a snapshot while reusing verified subtrees retained by earlier
    /// snapshots. Keep the most recent returned snapshot alive while rebuilding
    /// adjacent roots so their shared nodes remain available through weak refs.
    ///
    /// # Errors
    ///
    /// Returns [`RehydrateError`] if a node is missing, malformed, or does not
    /// hash to its stored address.
    pub fn rehydrate_cached(
        root: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
        cache: &mut VerifiedNodeCache,
        table: Arc<dyn StateKeyTable>,
    ) -> Result<Self, RehydrateError> {
        if root == Self::new(Arc::clone(&table)).root() {
            return Ok(Self::new(table));
        }
        let rebuilt = rebuild_verified(&root, load, 0, Some(cache), table.as_ref())?;
        Ok(Self {
            root: Some(rebuilt.node),
            len: rebuilt.len,
            table,
        })
    }

    /// Read one persisted state slot without materializing the other slots.
    ///
    /// # Errors
    ///
    /// Returns [`RehydrateError`] for missing, malformed or incorrectly addressed nodes.
    pub fn get_persisted(
        mut root: StateRoot,
        key: &StateKey,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
        table: &Arc<dyn StateKeyTable>,
    ) -> Result<Option<String>, RehydrateError> {
        if root == Self::new(Arc::clone(table)).root() {
            return Ok(None);
        }
        let Some(id) = table.id_of(key.event_type.as_str(), &key.state_key) else {
            return Ok(None);
        };
        let digest = digest_id(id);
        for depth in 0..=MAX_DEPTH {
            let bytes = load(&root).ok_or(RehydrateError::MissingNode)?;
            match bytes.first().copied() {
                Some(TAG_LEAF) => {
                    let leaf = rebuild(&root, &mut |_| Some(bytes.clone()), depth, table.as_ref())?;
                    return Ok(leaf.get(id, &digest, depth).map(str::to_owned));
                }
                Some(TAG_BRANCH) => {
                    if depth == MAX_DEPTH {
                        return Err(RehydrateError::Malformed);
                    }
                    let mut at = 1;
                    let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
                    let count = take_count(&bytes, &mut at, 32)?;
                    if count != bitmap.count_ones() as usize {
                        return Err(RehydrateError::Malformed);
                    }
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(HAMT_BRANCH_TAG);
                    hasher.update(&bitmap.to_be_bytes());
                    let bit = 1_u32 << digest_slot(&digest, depth);
                    let selected = (bitmap & (bit - 1)).count_ones() as usize;
                    let mut next = None;
                    for index in 0..count {
                        let address = take_array::<32>(&bytes, &mut at)?;
                        hasher.update(&address);
                        if bitmap & bit != 0 && index == selected {
                            next = Some(StateRoot(address));
                        }
                    }
                    if at != bytes.len() {
                        return Err(RehydrateError::Malformed);
                    }
                    if hasher.finalize().as_bytes() != root.as_bytes() {
                        return Err(RehydrateError::HashMismatch);
                    }
                    let Some(next) = next else {
                        return Ok(None);
                    };
                    root = next;
                }
                _ => return Err(RehydrateError::Malformed),
            }
        }
        Err(RehydrateError::Malformed)
    }
}

/// Rebuild the state at a version-2 root as a version-3 snapshot.
///
/// Version-2 leaves hold `(event_type, state_key)` strings placed by the
/// string digest; version 3 holds interned ids placed by the id digest, so
/// no node survives the move -- not even structurally, because the branch
/// bitmaps above a leaf were built for the old placement. This decodes
/// every slot and folds them into a fresh snapshot against `table`, which
/// marks each pair for the persistence drain.
///
/// Every node is verified with the version-2 tags on the way down, which
/// is also what tells a version-2 node from an already-migrated one: bytes
/// the new derivation wrote do not hash to their address under the old
/// tags. For `spindle migrate` only -- the serving paths never see
/// version-2 bytes.
///
/// # Errors
///
/// Returns [`RehydrateError`] for missing, malformed, corrupt, or
/// already-migrated nodes.
pub fn rehydrate_v2(
    root: StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    table: &Arc<dyn StateKeyTable>,
) -> Result<StateSnapshot, RehydrateError> {
    let (state, _) = rehydrate_v2_with_addresses(root, load, table)?;
    Ok(state)
}

/// Rebuild a version-2 snapshot and return every old node address reached
/// during the same verified walk.
///
/// Migrations need both the rebuilt state and the old addresses to delete.
/// Returning them together avoids traversing a large historical trie twice.
///
/// # Errors
///
/// Returns [`RehydrateError`] if any node is missing, malformed, or does not
/// match its version-2 content address.
pub fn rehydrate_v2_with_addresses(
    root: StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    table: &Arc<dyn StateKeyTable>,
) -> Result<(StateSnapshot, Vec<StateRoot>), RehydrateError> {
    let (slots, addresses) = walk_v2(&root, load)?;
    // Sorted, so the fresh numbering is a function of the content rather
    // than of whatever order the old trie happened to store it in.
    let mut slots = slots;
    slots.sort();
    let mut state = StateSnapshot::new(Arc::clone(table));
    for (event_type, state_key, event_id) in slots {
        state = state.apply(&StateKey::new(event_type, state_key), event_id);
    }
    Ok((state, addresses))
}

/// Every node address the version-2 trie at `root` occupies.
///
/// The migration deletes exactly these after the rewritten records land:
/// no scan can find them afterwards, because content addressing spreads one
/// room's old nodes across the whole keyspace. An empty root occupies
/// nothing. For `spindle migrate` only.
///
/// # Errors
///
/// As [`rehydrate_v2`]: a node this cannot verify is corruption, not an
/// already-migrated trie, and must stop the migration rather than be
/// deleted from under records that still name it.
pub fn v2_node_addresses(
    root: StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
) -> Result<Vec<StateRoot>, RehydrateError> {
    Ok(walk_v2(&root, load)?.1)
}

/// One version-2 slot: the `(event_type, state_key)` strings and the event
/// they name. A name for the triple nesting, as in [`AllocRecord`].
type V2Slot = (String, String, String);

fn walk_v2(
    root: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
) -> Result<(Vec<V2Slot>, Vec<StateRoot>), RehydrateError> {
    if root.as_bytes() == blake3::hash(V2_EMPTY_STATE_TAG).as_bytes() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut slots = Vec::new();
    let mut addresses = Vec::new();
    collect_v2_slots(root, load, 0, &mut slots, &mut addresses)?;
    Ok((slots, addresses))
}

enum V2Node {
    Leaf(Vec<V2Slot>),
    Branch(u32, Vec<StateRoot>),
}

fn collect_v2_slots(
    address: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    slots: &mut Vec<V2Slot>,
    addresses: &mut Vec<StateRoot>,
) -> Result<(), RehydrateError> {
    let node = read_v2_node(address, load, depth)?;
    addresses.push(*address);
    collect_v2_node(node, load, depth, slots, addresses)
}

fn collect_v2_node(
    node: V2Node,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    slots: &mut Vec<V2Slot>,
    addresses: &mut Vec<StateRoot>,
) -> Result<(), RehydrateError> {
    match node {
        V2Node::Leaf(entries) => slots.extend(entries),
        V2Node::Branch(_, children) => {
            for child in children {
                collect_v2_slots(&child, load, depth + 1, slots, addresses)?;
            }
        }
    }
    Ok(())
}

/// Convert the changes between two version-2 roots into an existing snapshot.
///
/// `previous` must be the conversion of the fully verified `previous_root`,
/// using the same table. The loader must keep previously verified nodes
/// immutable throughout the migration. Equal subtree addresses then need no
/// reads. Newly reached addresses are returned for eventual old-node deletion;
/// the caller must also retain addresses from the initial full conversion.
///
/// # Errors
///
/// Returns [`RehydrateError`] for missing, malformed or incorrectly addressed
/// nodes on changed paths. An invalid baseline violates the caller contract.
pub fn rehydrate_v2_incremental(
    root: StateRoot,
    previous_root: StateRoot,
    previous: &StateSnapshot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
) -> Result<(StateSnapshot, Vec<StateRoot>), RehydrateError> {
    let empty = StateRoot(*blake3::hash(V2_EMPTY_STATE_TAG).as_bytes());
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let mut addresses = Vec::new();
    diff_v2(
        (previous_root != empty).then_some(previous_root),
        (root != empty).then_some(root),
        load,
        0,
        &mut removed,
        &mut added,
        &mut addresses,
    )?;
    let mut state = previous.clone();
    for (event_type, state_key, _) in removed {
        state = state.remove(&StateKey::new(event_type, state_key));
    }
    // Keep first-seen intern ids identical to the full sorted conversion.
    added.sort();
    for (event_type, state_key, event_id) in added {
        state = state.apply(&StateKey::new(event_type, state_key), event_id);
    }
    Ok((state, addresses))
}

#[allow(clippy::too_many_arguments)]
fn diff_v2(
    old: Option<StateRoot>,
    new: Option<StateRoot>,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    removed: &mut Vec<V2Slot>,
    added: &mut Vec<V2Slot>,
    addresses: &mut Vec<StateRoot>,
) -> Result<(), RehydrateError> {
    if depth > MAX_DEPTH {
        return Err(RehydrateError::Malformed);
    }
    if old == new {
        return Ok(());
    }
    let old_node = old
        .map(|address| read_v2_node(&address, load, depth))
        .transpose()?;
    let new_node = new
        .map(|address| read_v2_node(&address, load, depth))
        .transpose()?;
    if let Some(address) = new {
        addresses.push(address);
    }
    match (old_node, new_node) {
        (
            Some(V2Node::Branch(old_bitmap, old_children)),
            Some(V2Node::Branch(new_bitmap, new_children)),
        ) => {
            for slot in 0..32 {
                let child = |bitmap: u32, children: &[StateRoot]| {
                    let bit = 1_u32 << slot;
                    if bitmap & bit == 0 {
                        None
                    } else {
                        children
                            .get((bitmap & (bit - 1)).count_ones() as usize)
                            .copied()
                    }
                };
                diff_v2(
                    child(old_bitmap, &old_children),
                    child(new_bitmap, &new_children),
                    load,
                    depth + 1,
                    removed,
                    added,
                    addresses,
                )?;
            }
        }
        (old_node, new_node) => {
            // A leaf/branch transition changes the local shape. Compare that
            // subtree in full; unrelated branches still stopped at equal hashes.
            if let Some(node) = old_node {
                collect_v2_node(node, load, depth, removed, &mut Vec::new())?;
            }
            if let Some(node) = new_node {
                collect_v2_node(node, load, depth, added, addresses)?;
            }
        }
    }
    Ok(())
}

fn read_v2_node(
    address: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
) -> Result<V2Node, RehydrateError> {
    if depth > MAX_DEPTH {
        return Err(RehydrateError::Malformed);
    }
    let bytes = load(address).ok_or(RehydrateError::MissingNode)?;
    let mut at = 0_usize;
    let tag = *bytes.first().ok_or(RehydrateError::Malformed)?;
    at += 1;
    match tag {
        TAG_LEAF => {
            let digest = take_array::<32>(&bytes, &mut at)?;
            let count = take_count(&bytes, &mut at, 3 * 4)?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let event_type = take_string(&bytes, &mut at)?;
                let state_key = take_string(&bytes, &mut at)?;
                let event_id = take_string(&bytes, &mut at)?;
                entries.push((event_type, state_key, event_id));
            }
            if at != bytes.len() {
                return Err(RehydrateError::Malformed);
            }
            // The old derivation over the old bytes: a version-3 node fails
            // here, which is how the migration tells migrated from corrupt.
            let mut hasher = blake3::Hasher::new();
            hasher.update(V2_HAMT_LEAF_TAG);
            hasher.update(&digest);
            hasher.update(&(entries.len() as u64).to_be_bytes());
            for (event_type, state_key, event_id) in &entries {
                hash_bytes(&mut hasher, event_type.as_bytes());
                hash_bytes(&mut hasher, state_key.as_bytes());
                hash_bytes(&mut hasher, event_id.as_bytes());
            }
            if hasher.finalize().as_bytes() != address.as_bytes() {
                return Err(RehydrateError::HashMismatch);
            }
            Ok(V2Node::Leaf(entries))
        }
        TAG_BRANCH => {
            let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
            let count = take_count(&bytes, &mut at, 32)?;
            if count != bitmap.count_ones() as usize {
                return Err(RehydrateError::Malformed);
            }
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(StateRoot(take_array::<32>(&bytes, &mut at)?));
            }
            if at != bytes.len() {
                return Err(RehydrateError::Malformed);
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(V2_HAMT_BRANCH_TAG);
            hasher.update(&bitmap.to_be_bytes());
            for child in &children {
                hasher.update(child.as_bytes());
            }
            if hasher.finalize().as_bytes() != address.as_bytes() {
                return Err(RehydrateError::HashMismatch);
            }
            Ok(V2Node::Branch(bitmap, children))
        }
        _ => Err(RehydrateError::Malformed),
    }
}

/// Emit the nodes `new` has that `old` did not, descending only where they
/// differ.
///
/// Path copying means an unchanged subtree keeps its content address, so a
/// matching hash ends the descent immediately. Walking both trees in step is
/// what makes this proportional to the changed path; collecting the old tree's
/// hashes up front would be proportional to the whole state, which is the cost
/// this exists to avoid.
fn collect_new(new: &Node, old: Option<&Node>, out: &mut Vec<(StateRoot, Vec<u8>)>) {
    if old.is_some_and(|old| old.hash() == new.hash()) {
        return;
    }
    if let Node::Branch {
        bitmap, children, ..
    } = new
    {
        for (index, child) in children.iter().enumerate() {
            let slot = nth_set_bit(*bitmap, index);
            collect_new(child, old.and_then(|old| child_at_slot(old, slot)), out);
        }
    }
    out.push((StateRoot(new.hash()), encode_node(new)));
}

/// Position of the `index`-th set bit, which is the trie slot that child
/// occupies.
fn nth_set_bit(bitmap: u32, index: usize) -> u32 {
    let mut remaining = bitmap;
    for _ in 0..index {
        remaining &= remaining - 1;
    }
    remaining.trailing_zeros()
}

fn child_at_slot(node: &Node, slot: u32) -> Option<&Node> {
    match node {
        Node::Branch {
            bitmap, children, ..
        } => {
            let bit = 1_u32 << slot;
            if bitmap & bit == 0 {
                return None;
            }
            let index = (bitmap & (bit - 1)).count_ones() as usize;
            children.get(index).map(AsRef::as_ref)
        }
        Node::Leaf { .. } => None,
    }
}

fn encode_node(node: &Node) -> Vec<u8> {
    let mut out = Vec::new();
    match node {
        Node::Leaf {
            digest, entries, ..
        } => {
            out.push(TAG_LEAF);
            out.extend_from_slice(digest);
            out.extend_from_slice(
                &u32::try_from(entries.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for (id, event_id) in entries.iter() {
                out.extend_from_slice(&id.to_be_bytes());
                put_field(&mut out, event_id.as_bytes());
            }
        }
        Node::Branch {
            bitmap, children, ..
        } => {
            out.push(TAG_BRANCH);
            out.extend_from_slice(&bitmap.to_be_bytes());
            out.extend_from_slice(
                &u32::try_from(children.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            for child in children.iter() {
                out.extend_from_slice(&child.hash());
            }
        }
    }
    out
}

fn put_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value);
}

fn rebuild(
    address: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    table: &dyn StateKeyTable,
) -> Result<Arc<Node>, RehydrateError> {
    Ok(rebuild_verified(address, load, depth, None, table)?.node)
}

fn rebuild_verified(
    address: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    mut cache: Option<&mut VerifiedNodeCache>,
    table: &dyn StateKeyTable,
) -> Result<RebuiltNode, RehydrateError> {
    if depth > MAX_DEPTH {
        return Err(RehydrateError::Malformed);
    }
    let key = (*address, depth);
    if let Some(cached) = cache.as_deref_mut().and_then(|cache| cache.get(key)) {
        return Ok(cached);
    }
    let bytes = load(address).ok_or(RehydrateError::MissingNode)?;
    let mut at = 0_usize;
    let tag = *bytes.first().ok_or(RehydrateError::Malformed)?;
    at += 1;

    let (node, len) = match tag {
        TAG_LEAF => {
            let digest = take_array::<32>(&bytes, &mut at)?;
            let count = take_count(&bytes, &mut at, 8 + 4)?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let id = u64::from_be_bytes(take_array::<8>(&bytes, &mut at)?);
                if !table.contains_id(id) {
                    return Err(RehydrateError::Malformed);
                }
                let event_id = take_string(&bytes, &mut at)?;
                entries.push((id, event_id.into_boxed_str()));
            }
            (Node::leaf_from_entries(digest, entries), count)
        }
        TAG_BRANCH => {
            let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
            let count = take_count(&bytes, &mut at, 32)?;
            let mut children = Vec::with_capacity(count);
            let mut len = 0_usize;
            for _ in 0..count {
                let child = StateRoot(take_array::<32>(&bytes, &mut at)?);
                let rebuilt =
                    rebuild_verified(&child, load, depth + 1, cache.as_deref_mut(), table)?;
                len = len
                    .checked_add(rebuilt.len)
                    .ok_or(RehydrateError::Malformed)?;
                children.push(rebuilt.node);
            }
            (Node::branch(bitmap, children), len)
        }
        _ => return Err(RehydrateError::Malformed),
    };

    // Never cache a partially decoded or incorrectly addressed node.
    if node.hash() != *address.as_bytes() {
        return Err(RehydrateError::HashMismatch);
    }
    let rebuilt = RebuiltNode {
        node: Arc::new(node),
        len,
    };
    if let Some(cache) = cache {
        cache.insert(key, &rebuilt);
    }
    Ok(rebuilt)
}

fn take_array<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], RehydrateError> {
    let end = at.checked_add(N).ok_or(RehydrateError::Malformed)?;
    let slice = bytes.get(*at..end).ok_or(RehydrateError::Malformed)?;
    *at = end;
    slice.try_into().map_err(|_| RehydrateError::Malformed)
}

fn take_len(bytes: &[u8], at: &mut usize) -> Result<usize, RehydrateError> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, at)?) as usize)
}

/// A count of framed items, refused when too few bytes remain to frame that
/// many. `each` is the smallest number of bytes one item can occupy.
///
/// `Vec::with_capacity` on a length straight off disk is an allocation the
/// input chooses, and a 37-byte leaf claiming `u32::MAX` entries is a request
/// for 206 GiB. That does not fail the way the rest of this decoder fails: a
/// failed allocation aborts the process rather than returning the
/// [`RehydrateError::Malformed`] this function exists to produce, so one
/// flipped bit in one node takes the server down instead of costing it that
/// node.
///
/// Refusing rather than clamping to what fits: a node claiming four billion
/// entries is corrupt whatever else it says, and reading it as one holding
/// none would hand back a plausible trie built from a broken one. The hash
/// check would catch that -- but only after the work, and only because it is
/// there; the decoder should not be relying on it to notice a length it could
/// see was impossible.
fn take_count(bytes: &[u8], at: &mut usize, each: usize) -> Result<usize, RehydrateError> {
    let claimed = take_len(bytes, at)?;
    if claimed > bytes.len().saturating_sub(*at) / each {
        return Err(RehydrateError::Malformed);
    }
    Ok(claimed)
}

fn take_string(bytes: &[u8], at: &mut usize) -> Result<String, RehydrateError> {
    let len = take_len(bytes, at)?;
    let end = at.checked_add(len).ok_or(RehydrateError::Malformed)?;
    let slice = bytes.get(*at..end).ok_or(RehydrateError::Malformed)?;
    *at = end;
    String::from_utf8(slice.to_vec()).map_err(|_| RehydrateError::Malformed)
}

#[cfg(test)]
mod digest_version_tests {
    use super::{CONTENT_DIGEST_VERSION, DOMAIN_TAGS};

    /// Every domain tag names the current digest version.
    ///
    /// This is what makes [`CONTENT_DIGEST_VERSION`] impossible to forget,
    /// which #78 asked for. The two can only drift apart in two ways, and
    /// this catches both:
    ///
    /// - a digest is changed and its tag bumped to `-v2`, but the constant
    ///   is left at 1 — so a store written under the old derivation would
    ///   still open, and every node address in it would be wrong;
    /// - the constant is bumped without any tag moving — so stores are
    ///   refused for a change that never happened.
    ///
    /// Bumping the version therefore means editing the tags *and* the
    /// constant together, which is the intent: a domain tag is what actually
    /// separates one derivation from another, and the constant is what the
    /// store marker can compare.
    #[test]
    fn the_domain_tags_carry_the_current_digest_version() {
        let expected = format!("-v{CONTENT_DIGEST_VERSION}");
        for tag in DOMAIN_TAGS {
            let text = std::str::from_utf8(tag)
                .expect("domain tags are ASCII")
                .trim_end_matches('\0');
            assert!(
                text.ends_with(&expected),
                "{text:?} does not end with {expected:?}; a digest and \
                 CONTENT_DIGEST_VERSION have drifted apart",
            );
        }
    }

    /// An interned id digests in one BLAKE3 block (#79). The bound is
    /// arithmetic on the tag and the eight id bytes, checked here so a
    /// wider payload cannot creep back in unnoticed.
    #[test]
    fn an_interned_id_digests_in_one_block() {
        let stream = super::STATE_KEY_TAG.len() + 8;
        assert!(stream <= 64, "{stream} bytes is more than one block");
    }

    /// The tags are distinct, so one digest cannot be mistaken for another.
    ///
    /// Domain separation is the entire reason the tags exist: without it a
    /// leaf and a branch with the same bytes would hash identically.
    #[test]
    fn the_domain_tags_are_distinct() {
        for (i, left) in DOMAIN_TAGS.iter().enumerate() {
            for right in &DOMAIN_TAGS[i + 1..] {
                assert_ne!(left, right, "two digests share a domain tag");
            }
        }
    }
}

#[cfg(test)]
mod cached_rehydrate_tests {
    use super::*;

    fn table() -> std::sync::Arc<dyn crate::state_table::StateKeyTable> {
        crate::state_table::MemStateKeyTable::shared()
    }

    fn state(
        count: usize,
        table: &std::sync::Arc<dyn crate::state_table::StateKeyTable>,
    ) -> StateSnapshot {
        let mut state = StateSnapshot::new(std::sync::Arc::clone(table));
        for index in 0..count {
            state = state.apply(
                &StateKey::new("m.room.member", format!("@u{index}:test")),
                format!("$e{index}"),
            );
        }
        state
    }

    fn nodes(state: &StateSnapshot) -> HashMap<StateRoot, Vec<u8>> {
        state.delta_nodes(None).into_iter().collect()
    }

    #[test]
    fn same_root_reuses_verified_arc_and_entry_count_without_storage_reads() {
        let table = table();
        let expected = state(512, &table);
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4 * 1024 * 1024);
        let first = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("verified first read");
        let second = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |_| panic!("same verified root must not reload"),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("cached root");
        assert_eq!(second.root(), expected.root());
        assert_eq!(second.len(), 512);
        assert!(Arc::ptr_eq(
            first.root.as_ref().expect("first root"),
            second.root.as_ref().expect("second root")
        ));
    }

    #[test]
    fn changed_root_loads_only_changed_paths_and_shares_unchanged_subtrees() {
        let table = table();
        let before = state(512, &table);
        let after = before.apply(&StateKey::new("m.room.member", "@u1:test"), "$updated");
        let changed = after.delta_nodes(Some(&before));
        let mut stored = nodes(&before);
        stored.extend(changed.iter().cloned());
        let mut cache = VerifiedNodeCache::new(4 * 1024 * 1024);
        let first = StateSnapshot::rehydrate_cached(
            before.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("before");
        let mut reads = 0;
        let second = StateSnapshot::rehydrate_cached(
            after.root(),
            &mut |root| {
                reads += 1;
                stored.get(root).cloned()
            },
            &mut cache,
            Arc::clone(&table),
        )
        .expect("after");
        assert_eq!(reads, changed.len());
        assert_eq!(second.root(), after.root());
        assert_eq!(second.len(), after.len());
        assert_eq!(
            second.get(&StateKey::new("m.room.member", "@u1:test")),
            Some("$updated")
        );
        if let (Some(left), Some(right)) = (&first.root, &second.root) {
            if let (
                Node::Branch { children: left, .. },
                Node::Branch {
                    children: right, ..
                },
            ) = (left.as_ref(), right.as_ref())
            {
                assert!(
                    left.iter()
                        .any(|old| right.iter().any(|new| Arc::ptr_eq(old, new)))
                );
            } else {
                panic!("fixture must have branch roots");
            }
        }
    }

    #[test]
    fn corrupt_nodes_never_enter_cache_and_a_fresh_read_still_detects_corruption() {
        let table = table();
        let expected = state(1, &table);
        let stored = nodes(&expected);
        let mut bytes = stored.get(&expected.root()).expect("leaf bytes").clone();
        bytes[1] ^= 1;
        let mut cache = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(bytes.clone()),
                &mut cache,
                Arc::clone(&table),
            ),
            Err(RehydrateError::HashMismatch)
        ));
        assert!(cache.nodes.is_empty());
        let _verified = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("valid read");
        let mut independent = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(bytes.clone()),
                &mut independent,
                Arc::clone(&table),
            ),
            Err(RehydrateError::HashMismatch)
        ));
    }

    #[test]
    fn missing_and_malformed_nodes_keep_original_error_semantics() {
        let table = table();
        let expected = state(1, &table);
        let mut cache = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| None,
                &mut cache,
                Arc::clone(&table)
            ),
            Err(RehydrateError::MissingNode)
        ));
        let mut encoded = nodes(&expected)
            .remove(&expected.root())
            .expect("leaf bytes");
        encoded[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(encoded.clone()),
                &mut cache,
                Arc::clone(&table),
            ),
            Err(RehydrateError::Malformed)
        ));
        assert!(cache.nodes.is_empty());
    }

    #[test]
    fn missing_descendant_cannot_publish_a_successful_cached_parent() {
        let table = table();
        let expected = state(128, &table);
        let stored = nodes(&expected);
        let missing = *stored
            .iter()
            .find(|(_, bytes)| bytes.first() == Some(&TAG_LEAF))
            .expect("leaf")
            .0;
        let mut cache = VerifiedNodeCache::new(4 * 1024 * 1024);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |root| {
                    if *root == missing {
                        None
                    } else {
                        stored.get(root).cloned()
                    }
                },
                &mut cache,
                Arc::clone(&table),
            ),
            Err(RehydrateError::MissingNode)
        ));
        assert!(!cache.nodes.contains_key(&(expected.root(), 0)));
        let recovered = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("complete source read");
        assert_eq!(recovered.root(), expected.root());
        assert_eq!(recovered.len(), 128);
    }

    #[test]
    fn expired_nodes_are_reloaded_and_verified_without_cache_graph_ownership() {
        let table = table();
        let expected = state(1, &table);
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4096);
        let held = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("first read");
        assert_eq!(Arc::strong_count(held.root.as_ref().expect("root")), 1);
        drop(held);
        let mut corrupt = stored.get(&expected.root()).expect("leaf").clone();
        corrupt[1] ^= 1;
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(corrupt.clone()),
                &mut cache,
                Arc::clone(&table),
            ),
            Err(RehydrateError::HashMismatch)
        ));
        assert!(cache.nodes.is_empty());
    }

    #[test]
    fn rehydration_refuses_nodes_with_missing_intern_rows() {
        let table = table();
        let expected = state(1, &table);
        let stored = nodes(&expected);
        assert!(matches!(
            StateSnapshot::rehydrate(
                expected.root(),
                &mut |root| stored.get(root).cloned(),
                crate::MemStateKeyTable::shared()
            ),
            Err(RehydrateError::Malformed)
        ));
    }

    #[test]
    fn cached_nodes_cannot_bypass_recursion_depth_bound() {
        let table = table();
        let expected = state(1, &table);
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4096);
        rebuild_verified(
            &expected.root(),
            &mut |root| stored.get(root).cloned(),
            MAX_DEPTH,
            Some(&mut cache),
            table.as_ref(),
        )
        .expect("leaf at depth limit");
        assert!(matches!(
            rebuild_verified(
                &expected.root(),
                &mut |_| panic!("reject before loader"),
                MAX_DEPTH + 1,
                Some(&mut cache),
                table.as_ref(),
            ),
            Err(RehydrateError::Malformed)
        ));
        let mut reads = 0;
        rebuild_verified(
            &expected.root(),
            &mut |root| {
                reads += 1;
                stored.get(root).cloned()
            },
            0,
            Some(&mut cache),
            table.as_ref(),
        )
        .expect("same address at distinct depth must verify separately");
        assert_eq!(reads, 1);
    }

    #[test]
    fn collision_leaf_preserves_all_entries_and_canonical_root() {
        // Collision buckets intentionally have several keys under one digest;
        // use the internal constructor to exercise that otherwise rare shape.
        let table = table();
        let leaf = Arc::new(Node::leaf_from_entries(
            [7; 32],
            vec![
                (table.intern("m.room.member", "@a:test"), "$a".into()),
                (table.intern("m.room.member", "@b:test"), "$b".into()),
            ],
        ));
        let expected = StateSnapshot {
            root: Some(leaf),
            len: 2,
            table: Arc::clone(&table),
        };
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4096);
        let plain = StateSnapshot::rehydrate(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            Arc::clone(&table),
        )
        .expect("plain collision");
        let cached = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
            Arc::clone(&table),
        )
        .expect("cached collision");
        let mut plain_rows = Vec::new();
        plain.for_each(|key, event| plain_rows.push((key.clone(), event.to_owned())));
        let mut cached_rows = Vec::new();
        cached.for_each(|key, event| cached_rows.push((key.clone(), event.to_owned())));
        assert_eq!(plain_rows, cached_rows);
        assert_eq!(cached.len(), 2);
        assert_eq!(cached.root(), expected.root());
    }

    #[test]
    fn large_seeded_roots_reuse_subtrees_with_the_runtime_budget() {
        let table = table();
        let mut expected = state(51_200, &table);
        let mut stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(64 * 1024 * 1024);
        let full_walk_nodes = stored.len();
        let mut reads = 0;
        let mut previous_held = None;
        for index in 0..100 {
            let before = expected.clone();
            expected = expected.apply(
                &StateKey::new("m.room.member", "@u1:test"),
                format!("$version{index}"),
            );
            stored.extend(expected.delta_nodes(Some(&before)));
            let held = StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |root| {
                    reads += 1;
                    stored.get(root).cloned()
                },
                &mut cache,
                Arc::clone(&table),
            )
            .expect("large seeded read");
            assert_eq!(held.root(), expected.root());
            assert_eq!(held.len(), 51_200);
            assert!(cache.bytes <= cache.budget);
            previous_held = Some(held);
        }
        assert!(previous_held.is_some());
        assert!(
            reads < full_walk_nodes * 10,
            "{reads} reads should be below ten full walks for one hundred roots"
        );
    }

    #[test]
    fn cache_ownership_and_order_indexes_remain_bounded_after_eviction() {
        let table = table();
        let mut expected = state(128, &table);
        let mut stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(32 * 1024);
        for index in 0..200 {
            expected = expected.apply(
                &StateKey::new("m.room.member", "@u1:test"),
                format!("$version{index}"),
            );
            stored.extend(expected.delta_nodes(None));
            let held = StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |root| stored.get(root).cloned(),
                &mut cache,
                Arc::clone(&table),
            )
            .expect("bounded read");
            assert_eq!(held.root(), expected.root());
            assert_eq!(held.len(), 128);
            assert!(cache.bytes <= cache.budget);
            assert_eq!(cache.nodes.len(), cache.order.len());
            assert_eq!(
                cache.bytes,
                cache
                    .nodes
                    .values()
                    .map(|entry| entry.charge)
                    .sum::<usize>()
            );
        }
    }
}
