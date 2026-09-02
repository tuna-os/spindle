use std::{cmp::Ordering, sync::Arc};

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
        let node = rebuild(&root, load, 0)?;
        let len = count_entries(&node);
        Ok(Self {
            root: Some(node),
            len,
        })
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
    if depth > MAX_DEPTH {
        return Err(RehydrateError::Malformed);
    }
    let bytes = load(address).ok_or(RehydrateError::MissingNode)?;
    let mut at = 0_usize;
    let tag = *bytes.first().ok_or(RehydrateError::Malformed)?;
    at += 1;

    let node = match tag {
        TAG_LEAF => {
            let digest = take_array::<32>(&bytes, &mut at)?;
            // Three length-prefixed fields per entry, so four bytes each at
            // the very least.
            let count = take_count(&bytes, &mut at, 3 * 4)?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let event_type = take_string(&bytes, &mut at)?;
                let state_key = take_string(&bytes, &mut at)?;
                let event_id = take_string(&bytes, &mut at)?;
                entries.push((
                    StateKey::new(event_type, state_key),
                    event_id.into_boxed_str(),
                ));
            }
            Node::leaf_from_entries(digest, entries)
        }
        TAG_BRANCH => {
            let bitmap = u32::from_be_bytes(take_array::<4>(&bytes, &mut at)?);
            let count = take_count(&bytes, &mut at, 32)?;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                let child = StateRoot(take_array::<32>(&bytes, &mut at)?);
                children.push(rebuild(&child, load, depth + 1)?);
            }
            Node::branch(bitmap, children)
        }
        _ => return Err(RehydrateError::Malformed),
    };

    // Content addressing is only worth anything if it is checked.
    if node.hash() != *address.as_bytes() {
        return Err(RehydrateError::HashMismatch);
    }
    Ok(Arc::new(node))
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

fn count_entries(node: &Node) -> usize {
    match node {
        Node::Leaf { entries, .. } => entries.len(),
        Node::Branch { children, .. } => children.iter().map(|child| count_entries(child)).sum(),
    }
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
