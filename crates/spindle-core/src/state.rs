use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

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
pub const CONTENT_DIGEST_VERSION: u8 = 2;

/// The domain tag separating each digest below from the others.
///
/// Named rather than written inline at the hasher, so each tag has exactly one
/// definition: the digest uses it and [`DOMAIN_TAGS`] lists it, instead of a
/// list that mirrors the literals and can drift from them.
///
/// The state-key tag is eight bytes, not a sentence, and the lengths that
/// follow it are `u32`, not `u64` (#77): BLAKE3 compresses in 64-byte
/// blocks, and the version-1 stream for an ordinary member key ran to 69
/// bytes -- a second block for five bytes of payload, at roughly twice the
/// cost of one. At eight plus four plus four bytes of framing, a key with
/// up to 48 bytes of type and state key fits in one block, which covers
/// `m.room.member` for any user ID up to 35 bytes. The other three tags
/// are hashed with 32-byte digests and are never near one block anyway;
/// they moved to `-v2` with the version rather than for a saving.
const STATE_KEY_TAG: &[u8] = b"spsk-v2\0";
const EMPTY_STATE_TAG: &[u8] = b"spindle-empty-state-v2";
const HAMT_LEAF_TAG: &[u8] = b"spindle-hamt-leaf-v2\0";
const HAMT_BRANCH_TAG: &[u8] = b"spindle-hamt-branch-v2\0";

/// The most bytes of event type plus state key that still digest in one
/// BLAKE3 block under [`STATE_KEY_TAG`] and two `u32` lengths.
#[cfg(test)]
const ONE_BLOCK_KEY_BYTES: usize = 64 - STATE_KEY_TAG.len() - 2 * 4;

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

    fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STATE_KEY_TAG);
        hash_bytes(&mut hasher, self.event_type.as_str().as_bytes());
        hash_bytes(&mut hasher, self.state_key.as_bytes());
        *hasher.finalize().as_bytes()
    }
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
#[derive(Clone, Debug, Default)]
pub struct StateSnapshot {
    root: Option<Arc<Node>>,
    len: usize,
}

impl StateSnapshot {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    #[must_use]
    pub fn get(&self, key: &StateKey) -> Option<&str> {
        let digest = key.digest();
        self.root
            .as_deref()
            .and_then(|node| node.get(key, &digest, 0))
    }

    /// Return a new snapshot with `key` pointing at `event_id`.
    #[must_use]
    pub fn apply(&self, key: StateKey, event_id: impl Into<Box<str>>) -> Self {
        let digest = key.digest();
        let event_id = event_id.into();
        let existed = self.get(&key).is_some();
        let leaf = Arc::new(Node::leaf(digest, key, event_id));
        let root = Some(match &self.root {
            Some(root) => root.insert(leaf, 0),
            None => leaf,
        });

        Self {
            root,
            len: self.len + usize::from(!existed),
        }
    }

    /// Visit every state slot in deterministic key order.
    /// Visit every entry, **in key order**.
    ///
    /// The order is part of the contract, not an accident of the walk: the
    /// trie places entries by digest, so an unsorted walk would return the
    /// same state in an order that shifts with the key set. Callers that
    /// render state to a client compare successive responses, and a set that
    /// reorders itself looks like a set that changed.
    pub fn for_each(&self, mut visitor: impl FnMut(&StateKey, &str)) {
        let mut entries = Vec::with_capacity(self.len);
        if let Some(root) = &self.root {
            root.collect(&mut entries);
        }
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        for (key, event_id) in entries {
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
        match root.remove(key, &key.digest(), 0) {
            Removal::Absent => self.clone(),
            Removal::Emptied => Self::new(),
            Removal::Replaced(root) => Self {
                root: Some(root),
                len: self.len.saturating_sub(1),
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
    #[must_use]
    pub fn diff<'a>(
        &'a self,
        other: &'a Self,
    ) -> Vec<(&'a StateKey, Option<&'a str>, Option<&'a str>)> {
        let mut out = Vec::new();
        diff_nodes(self.root.as_deref(), other.root.as_deref(), &mut out);
        out.sort_unstable_by(|(left, ..), (right, ..)| left.cmp(right));
        out
    }
}

type SlotDiff<'a> = (&'a StateKey, Option<&'a str>, Option<&'a str>);

/// Descend two tries in step, skipping subtrees with equal hashes.
///
/// Both tries place a key by the same digest bits, so a branch slot on one
/// side can only hold keys that the same slot holds on the other. Where the
/// shapes differ at a level (a leaf on one side, a branch on the other), the
/// two subtrees are small by construction -- a leaf sits where its slot has
/// one digest -- and are compared entry by entry.
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
                    (Some((key, value)), None) => {
                        out.push((*key, Some(*value), None));
                        i += 1;
                    }
                    (None, Some((key, value))) => {
                        out.push((*key, None, Some(*value)));
                        j += 1;
                    }
                    (Some((left_key, left_value)), Some((right_key, right_value))) => {
                        match left_key.cmp(right_key) {
                            Ordering::Less => {
                                out.push((*left_key, Some(*left_value), None));
                                i += 1;
                            }
                            Ordering::Greater => {
                                out.push((*right_key, None, Some(*right_value)));
                                j += 1;
                            }
                            Ordering::Equal => {
                                if left_value != right_value {
                                    out.push((*left_key, Some(*left_value), Some(*right_value)));
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
        entries: Arc<[(StateKey, Box<str>)]>,
        hash: [u8; 32],
    },
    Branch {
        bitmap: u32,
        children: Arc<[Arc<Self>]>,
        hash: [u8; 32],
    },
}

impl Node {
    fn leaf(digest: [u8; 32], key: StateKey, event_id: Box<str>) -> Self {
        Self::leaf_from_entries(digest, vec![(key, event_id)])
    }

    fn leaf_from_entries(digest: [u8; 32], mut entries: Vec<(StateKey, Box<str>)>) -> Self {
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

    fn get<'a>(&'a self, key: &StateKey, digest: &[u8; 32], depth: usize) -> Option<&'a str> {
        match self {
            Self::Leaf {
                digest: leaf_digest,
                entries,
                ..
            } if leaf_digest == digest => entries
                .binary_search_by(|(candidate, _)| candidate.cmp(key))
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
                children.get(index)?.get(key, digest, depth + 1)
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
                for (key, value) in incoming_entries.iter() {
                    match merged.binary_search_by(|(candidate, _)| candidate.cmp(key)) {
                        Ok(index) => {
                            if let Some(slot) = merged.get_mut(index) {
                                slot.1.clone_from(value);
                            }
                        }
                        Err(index) => merged.insert(index, (key.clone(), value.clone())),
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
    fn remove(&self, key: &StateKey, digest: &[u8; 32], depth: usize) -> Removal {
        match self {
            Self::Leaf {
                digest: leaf_digest,
                entries,
                ..
            } => {
                if leaf_digest != digest {
                    return Removal::Absent;
                }
                let Ok(index) = entries.binary_search_by(|(candidate, _)| candidate.cmp(key))
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
                match child.remove(key, digest, depth + 1) {
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

    fn collect<'a>(&'a self, output: &mut Vec<(&'a StateKey, &'a str)>) {
        match self {
            Self::Leaf { entries, .. } => {
                output.extend(
                    entries
                        .iter()
                        .map(|(key, event_id)| (key, event_id.as_ref())),
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

fn hash_leaf(digest: &[u8; 32], entries: &[(StateKey, Box<str>)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HAMT_LEAF_TAG);
    hasher.update(digest);
    hasher.update(&(entries.len() as u64).to_be_bytes());
    for (key, event_id) in entries {
        hash_bytes(&mut hasher, key.event_type().as_str().as_bytes());
        hash_bytes(&mut hasher, key.state_key().as_bytes());
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
/// depth: a verified subtree cannot bypass the decoder's recursion bound when
/// referenced at another depth. Only successful, content-verified reads enter.
///
/// Estimated charges include each node's entire reachable subtree plus index overhead;
/// shared descendants are deliberately charged repeatedly. The bound limits
/// cache ownership, not snapshots the caller independently keeps resident.
pub(crate) struct VerifiedNodeCache {
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
    retained_bytes: usize,
}

struct CachedNode {
    rebuilt: RebuiltNode,
    stamp: u64,
    charge: usize,
}

impl VerifiedNodeCache {
    pub(crate) fn new(budget: usize) -> Self {
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
        self.order.remove(&cached.stamp);
        cached.stamp = self.clock;
        self.order.insert(self.clock, key);
        Some(cached.rebuilt.clone())
    }

    fn insert(&mut self, key: (StateRoot, usize), rebuilt: RebuiltNode) {
        // Conservative allowance for both lookup/order indexes and allocation
        // framing, in addition to the complete retained subtree's charge.
        let charge = rebuilt.retained_bytes.saturating_add(256);
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
        // A node can be reinserted only after eviction; successful lookups
        // already return before decoding. Still account for replacement.
        if let Some(previous) = self.nodes.remove(&key) {
            self.order.remove(&previous.stamp);
            self.bytes = self.bytes.saturating_sub(previous.charge);
        }
        self.bytes += charge;
        self.nodes.insert(
            key,
            CachedNode {
                rebuilt,
                stamp: self.clock,
                charge,
            },
        );
        self.order.insert(self.clock, key);
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
    /// # Errors
    ///
    /// Returns [`RehydrateError`] if a node is missing, malformed, or does not
    /// hash to the address it was stored under.
    pub fn rehydrate(
        root: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    ) -> Result<Self, RehydrateError> {
        if root == Self::new().root() {
            return Ok(Self::new());
        }
        let rebuilt = rebuild_verified(&root, load, 0, None)?;
        Ok(Self {
            root: Some(rebuilt.node),
            len: rebuilt.len,
        })
    }

    /// Rehydrate with nodes already verified during this immutable log read.
    /// Shared subtrees retain their Arcs and cached entry counts, so a new root
    /// costs its changed paths rather than a walk of every membership slot.
    pub(crate) fn rehydrate_cached(
        root: StateRoot,
        load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
        cache: &mut VerifiedNodeCache,
    ) -> Result<Self, RehydrateError> {
        if root == Self::new().root() {
            return Ok(Self::new());
        }
        let rebuilt = rebuild_verified(&root, load, 0, Some(cache))?;
        Ok(Self {
            root: Some(rebuilt.node),
            len: rebuilt.len,
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
    ) -> Result<Option<String>, RehydrateError> {
        if root == Self::new().root() {
            return Ok(None);
        }
        let digest = key.digest();
        for depth in 0..=MAX_DEPTH {
            let bytes = load(&root).ok_or(RehydrateError::MissingNode)?;
            match bytes.first().copied() {
                Some(TAG_LEAF) => {
                    let leaf = rebuild(&root, &mut |_| Some(bytes.clone()), depth)?;
                    return Ok(leaf.get(key, &digest, depth).map(str::to_owned));
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
            for (key, event_id) in entries.iter() {
                put_field(&mut out, key.event_type().as_str().as_bytes());
                put_field(&mut out, key.state_key().as_bytes());
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
) -> Result<Arc<Node>, RehydrateError> {
    Ok(rebuild_verified(address, load, depth, None)?.node)
}

fn rebuild_verified(
    address: &StateRoot,
    load: &mut impl FnMut(&StateRoot) -> Option<Vec<u8>>,
    depth: usize,
    mut cache: Option<&mut VerifiedNodeCache>,
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
    let overhead = std::mem::size_of::<Node>() + 128;

    let (node, len, retained_bytes) = match tag {
        TAG_LEAF => {
            let digest = take_array::<32>(&bytes, &mut at)?;
            let count = take_count(&bytes, &mut at, 3 * 4)?;
            let mut entries = Vec::with_capacity(count);
            let mut retained_bytes = overhead;
            for _ in 0..count {
                let event_type = take_string(&bytes, &mut at)?;
                let state_key = take_string(&bytes, &mut at)?;
                let event_id = take_string(&bytes, &mut at)?;
                retained_bytes = retained_bytes.saturating_add(
                    std::mem::size_of::<(StateKey, Box<str>)>()
                        + 128
                        + event_type.len()
                        + state_key.len()
                        + event_id.len(),
                );
                entries.push((
                    StateKey::new(event_type, state_key),
                    event_id.into_boxed_str(),
                ));
            }
            (
                Node::leaf_from_entries(digest, entries),
                count,
                retained_bytes,
            )
        }
        TAG_BRANCH => {
            let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
            let count = take_count(&bytes, &mut at, 32)?;
            let mut children = Vec::with_capacity(count);
            let mut len = 0_usize;
            let mut retained_bytes =
                overhead.saturating_add(count * std::mem::size_of::<Arc<Node>>());
            for _ in 0..count {
                let child = StateRoot(take_array::<32>(&bytes, &mut at)?);
                let rebuilt = rebuild_verified(&child, load, depth + 1, cache.as_deref_mut())?;
                len = len
                    .checked_add(rebuilt.len)
                    .ok_or(RehydrateError::Malformed)?;
                retained_bytes = retained_bytes.saturating_add(rebuilt.retained_bytes);
                children.push(rebuilt.node);
            }
            (Node::branch(bitmap, children), len, retained_bytes)
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
        retained_bytes,
    };
    if let Some(cache) = cache {
        cache.insert(key, rebuilt.clone());
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

    /// An ordinary state key digests in one BLAKE3 block (#77). The bound
    /// is arithmetic on the tag and the two length frames, checked here so
    /// a longer tag or wider length cannot creep back in unnoticed; the
    /// member key below is the shape the issue measured.
    #[test]
    fn an_ordinary_state_key_digests_in_one_block() {
        let key = super::StateKey::new("m.room.member", "@u25000:example.org");
        let stream = super::STATE_KEY_TAG.len()
            + 4
            + key.event_type().as_str().len()
            + 4
            + key.state_key().len();
        assert!(stream <= 64, "{stream} bytes is more than one block");
        assert_eq!(super::ONE_BLOCK_KEY_BYTES, 48);
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

    fn state(count: usize) -> StateSnapshot {
        let mut state = StateSnapshot::new();
        for index in 0..count {
            state = state.apply(
                StateKey::new("m.room.member", format!("@u{index}:test")),
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
        let expected = state(512);
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4 * 1024 * 1024);
        let first = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
        )
        .expect("verified first read");
        let second = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |_| panic!("same verified root must not reload"),
            &mut cache,
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
        let before = state(512);
        let after = before.apply(StateKey::new("m.room.member", "@u1:test"), "$updated");
        let changed = after.delta_nodes(Some(&before));
        let mut stored = nodes(&before);
        stored.extend(changed.iter().cloned());
        let mut cache = VerifiedNodeCache::new(4 * 1024 * 1024);
        let first = StateSnapshot::rehydrate_cached(
            before.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
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
        let expected = state(1);
        let stored = nodes(&expected);
        let mut bytes = stored.get(&expected.root()).expect("leaf bytes").clone();
        bytes[1] ^= 1;
        let mut cache = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(bytes.clone()),
                &mut cache
            ),
            Err(RehydrateError::HashMismatch)
        ));
        assert!(cache.nodes.is_empty());
        let _verified = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
        )
        .expect("valid read");
        let mut independent = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |_| Some(bytes.clone()),
                &mut independent
            ),
            Err(RehydrateError::HashMismatch)
        ));
    }

    #[test]
    fn missing_and_malformed_nodes_keep_original_error_semantics() {
        let expected = state(1);
        let mut cache = VerifiedNodeCache::new(4096);
        assert!(matches!(
            StateSnapshot::rehydrate_cached(expected.root(), &mut |_| None, &mut cache),
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
                &mut cache
            ),
            Err(RehydrateError::Malformed)
        ));
        assert!(cache.nodes.is_empty());
    }

    #[test]
    fn missing_descendant_cannot_publish_a_successful_cached_parent() {
        let expected = state(128);
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
                &mut cache
            ),
            Err(RehydrateError::MissingNode)
        ));
        assert!(!cache.nodes.contains_key(&(expected.root(), 0)));
        let recovered = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
        )
        .expect("complete source read");
        assert_eq!(recovered.root(), expected.root());
        assert_eq!(recovered.len(), 128);
    }

    #[test]
    fn cached_nodes_cannot_bypass_recursion_depth_bound() {
        let expected = state(1);
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4096);
        rebuild_verified(
            &expected.root(),
            &mut |root| stored.get(root).cloned(),
            MAX_DEPTH,
            Some(&mut cache),
        )
        .expect("leaf at depth limit");
        assert!(matches!(
            rebuild_verified(
                &expected.root(),
                &mut |_| panic!("reject before loader"),
                MAX_DEPTH + 1,
                Some(&mut cache)
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
        )
        .expect("same address at distinct depth must verify separately");
        assert_eq!(reads, 1);
    }

    #[test]
    fn collision_leaf_preserves_all_entries_and_canonical_root() {
        // Collision buckets intentionally have several keys under one digest;
        // use the internal constructor to exercise that otherwise rare shape.
        let leaf = Arc::new(Node::leaf_from_entries(
            [7; 32],
            vec![
                (StateKey::new("m.room.member", "@a:test"), "$a".into()),
                (StateKey::new("m.room.member", "@b:test"), "$b".into()),
            ],
        ));
        let expected = StateSnapshot {
            root: Some(leaf),
            len: 2,
        };
        let stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(4096);
        let plain =
            StateSnapshot::rehydrate(expected.root(), &mut |root| stored.get(root).cloned())
                .expect("plain collision");
        let cached = StateSnapshot::rehydrate_cached(
            expected.root(),
            &mut |root| stored.get(root).cloned(),
            &mut cache,
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
        let mut expected = state(51_200);
        let mut stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(64 * 1024 * 1024);
        let full_walk_nodes = stored.len();
        let mut reads = 0;
        for index in 0..100 {
            let before = expected.clone();
            expected = expected.apply(
                StateKey::new("m.room.member", "@u1:test"),
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
            )
            .expect("large seeded read");
            assert_eq!(held.root(), expected.root());
            assert_eq!(held.len(), 51_200);
            assert!(cache.bytes <= cache.budget);
        }
        assert!(
            reads < full_walk_nodes * 10,
            "{reads} reads should be below ten full walks for one hundred roots"
        );
    }

    #[test]
    fn cache_ownership_and_order_indexes_remain_bounded_after_eviction() {
        let mut expected = state(128);
        let mut stored = nodes(&expected);
        let mut cache = VerifiedNodeCache::new(32 * 1024);
        for index in 0..200 {
            expected = expected.apply(
                StateKey::new("m.room.member", "@u1:test"),
                format!("$version{index}"),
            );
            stored.extend(expected.delta_nodes(None));
            let held = StateSnapshot::rehydrate_cached(
                expected.root(),
                &mut |root| stored.get(root).cloned(),
                &mut cache,
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
