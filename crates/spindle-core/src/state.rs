use std::{cmp::Ordering, sync::Arc};

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
        hasher.update(b"spindle-state-key-v1\0");
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
            StateRoot(*blake3::hash(b"spindle-empty-state-v1").as_bytes()),
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
                .map(|index| entries[index].1.as_ref()),
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
                children[index].get(key, digest, depth + 1)
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
                        Ok(index) => merged[index].1.clone_from(value),
                        Err(index) => merged.insert(index, (key.clone(), value.clone())),
                    }
                }
                Arc::new(Self::leaf_from_entries(*current_digest, merged))
            }
            (Self::Leaf { digest: left, .. }, Self::Leaf { digest: right, .. }) => {
                join_nodes(Arc::clone(self), left, incoming, right, depth)
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
                    next[index] = next[index].insert(incoming, depth + 1);
                    Arc::new(Self::branch(*bitmap, next))
                }
            }
            (Self::Branch { .. }, Self::Branch { .. }) => {
                unreachable!("only leaf nodes are inserted")
            }
            (Self::Leaf { .. }, Self::Branch { .. }) => {
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
    let mut window = u16::from(digest[byte]) >> shift;
    if shift > 3 && byte + 1 < digest.len() {
        window |= u16::from(digest[byte + 1]) << (8 - shift);
    }
    u32::from(window & 0x1f)
}

fn hash_leaf(digest: &[u8; 32], entries: &[(StateKey, Box<str>)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"spindle-hamt-leaf-v1\0");
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
    hasher.update(b"spindle-hamt-branch-v1\0");
    hasher.update(&bitmap.to_be_bytes());
    for child in children {
        hasher.update(&child.hash());
    }
    *hasher.finalize().as_bytes()
}

fn hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}
