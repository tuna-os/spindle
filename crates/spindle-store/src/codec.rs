//! Explicit, versioned record encoding.
//!
//! Hand-written rather than derived. The on-disk format is a compatibility
//! surface with the same status as a wire format: it needs to be readable,
//! reviewable, and stable across refactors of the in-memory types. A derived
//! encoding silently changes shape when a field is reordered.

use spindle_core::{EventId, LinearIndex, LogEntry, StateKey, keys::order_preserving};

/// Version of the record encodings below. Distinct from the key schema
/// version: keys and values can evolve independently.
pub const RECORD_VERSION: u8 = 1;

/// A log entry stripped to what durably identifies it. State is refolded on
/// restore rather than stored per entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryRecord {
    pub li: i64,
    pub event_id: String,
    pub prev_events: Vec<String>,
    pub depth: u64,
    pub state_key: Option<(String, String)>,
    /// The state root this entry produced when it was written.
    ///
    /// Not used to rebuild state — it is the check that the rebuild is right.
    /// A refold that disagrees with this is either corruption or a range whose
    /// state was supplied externally, and either way must be surfaced rather
    /// than silently accepted.
    pub state_root: [u8; 32],
    /// The chain value this server recorded when it sequenced the entry, absent
    /// for backfilled history it did not sequence.
    pub chain: Option<[u8; 32]>,
}

impl EntryRecord {
    #[must_use]
    pub fn from_entry(entry: &LogEntry) -> Self {
        Self {
            li: entry.li.get(),
            event_id: entry.event_id.as_str().to_owned(),
            prev_events: entry
                .prev_events
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            depth: entry.depth,
            state_key: entry.state_key.as_ref().map(|key| {
                (
                    key.event_type().as_str().to_owned(),
                    key.state_key().to_owned(),
                )
            }),
            state_root: *entry.state_root.as_bytes(),
            chain: entry.chain.map(|chain| *chain.as_bytes()),
        }
    }

    #[must_use]
    pub fn linear_index(&self) -> LinearIndex {
        LinearIndex::from_raw(self.li)
    }

    #[must_use]
    pub fn event(&self) -> EventId {
        EventId::new(self.event_id.as_str())
    }

    #[must_use]
    pub fn parents(&self) -> Vec<EventId> {
        self.prev_events
            .iter()
            .map(|id| EventId::new(id.as_str()))
            .collect()
    }

    #[must_use]
    pub fn slot(&self) -> Option<StateKey> {
        self.state_key
            .as_ref()
            .map(|(event_type, state_key)| StateKey::new(event_type.as_str(), state_key.as_str()))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION];
        out.extend_from_slice(&order_preserving(self.li));
        out.extend_from_slice(&self.depth.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        put_str(&mut out, &self.event_id);
        put_len(&mut out, self.prev_events.len());
        for parent in &self.prev_events {
            put_str(&mut out, parent);
        }
        match &self.state_key {
            Some((event_type, state_key)) => {
                out.push(1);
                put_str(&mut out, event_type);
                put_str(&mut out, state_key);
            }
            None => out.push(0),
        }
        match &self.chain {
            Some(chain) => {
                out.push(1);
                out.extend_from_slice(chain);
            }
            None => out.push(0),
        }
        out
    }

    /// # Errors
    ///
    /// Returns [`CodecError`] for an unknown version or a truncated record.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor { bytes, at: 0 };
        let version = cursor.byte()?;
        if version != RECORD_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let li = spindle_core::keys::from_order_preserving(cursor.array::<8>()?);
        let depth = u64::from_be_bytes(cursor.array::<8>()?);
        let state_root = cursor.array::<32>()?;
        let event_id = cursor.string()?;
        let parent_count = cursor.count()?;
        let mut prev_events = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            prev_events.push(cursor.string()?);
        }
        let state_key = match cursor.byte()? {
            0 => None,
            1 => Some((cursor.string()?, cursor.string()?)),
            other => return Err(CodecError::Malformed(other)),
        };
        let chain = match cursor.byte()? {
            0 => None,
            1 => Some(cursor.array::<32>()?),
            other => return Err(CodecError::Malformed(other)),
        };
        Ok(Self {
            li,
            event_id,
            prev_events,
            depth,
            state_key,
            state_root,
            chain,
        })
    }
}

impl EntryRecord {
    /// Decode a stored row straight into the form a restore consumes.
    ///
    /// Exactly [`Self::decode`]'s format and checks, without the
    /// intermediate record: every string is validated in place and copied
    /// once, into the type the log keeps, where `decode` followed by the
    /// conversions copies each twice. On the restore of a room of a million
    /// events that is several million allocations nobody needed.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for an unknown version or a truncated or
    /// malformed record, as [`Self::decode`] does.
    pub fn decode_restored(bytes: &[u8]) -> Result<spindle_core::RestoredEntry, CodecError> {
        let mut cursor = Cursor { bytes, at: 0 };
        let version = cursor.byte()?;
        if version != RECORD_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let li = spindle_core::keys::from_order_preserving(cursor.array::<8>()?);
        let depth = u64::from_be_bytes(cursor.array::<8>()?);
        let expected_state_root = cursor.array::<32>()?;
        let event_id = EventId::new(cursor.str()?);
        let parent_count = cursor.count()?;
        let mut prev_events = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            prev_events.push(EventId::new(cursor.str()?));
        }
        let state_key = match cursor.byte()? {
            0 => None,
            1 => {
                let event_type = cursor.str()?;
                Some(StateKey::new(event_type, cursor.str()?))
            }
            other => return Err(CodecError::Malformed(other)),
        };
        let chain = match cursor.byte()? {
            0 => None,
            1 => Some(cursor.array::<32>()?),
            other => return Err(CodecError::Malformed(other)),
        };
        Ok(spindle_core::RestoredEntry {
            li: LinearIndex::from_raw(li),
            event_id,
            prev_events,
            depth,
            state_key,
            expected_state_root,
            chain,
        })
    }
}

/// A soft-failed or rejected event held outside the timeline
/// (`spindle_core::SidelinedEntry`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidelinedRecord {
    pub event_id: String,
    pub prev_events: Vec<String>,
    pub depth: u64,
    pub state_key: Option<(String, String)>,
    /// 1 soft-failed, 2 rejected.
    pub kind: u8,
    pub state_root: [u8; 32],
}

impl SidelinedRecord {
    #[must_use]
    pub fn from_entry(entry: &spindle_core::SidelinedEntry) -> Self {
        Self {
            event_id: entry.event_id.as_str().to_owned(),
            prev_events: entry
                .prev_events
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            depth: entry.depth,
            state_key: entry.state_key.as_ref().map(|key| {
                (
                    key.event_type().as_str().to_owned(),
                    key.state_key().to_owned(),
                )
            }),
            kind: match entry.kind {
                spindle_core::Sideline::SoftFailed => 1,
                spindle_core::Sideline::Rejected => 2,
            },
            state_root: *entry.state_root.as_bytes(),
        }
    }

    /// The entry this record describes.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::Malformed`] for a verdict this version does not
    /// define.
    pub fn to_entry(&self) -> Result<spindle_core::SidelinedEntry, CodecError> {
        Ok(spindle_core::SidelinedEntry {
            event_id: EventId::new(self.event_id.as_str()),
            prev_events: self
                .prev_events
                .iter()
                .map(|id| EventId::new(id.as_str()))
                .collect(),
            depth: self.depth,
            state_key: self
                .state_key
                .as_ref()
                .map(|(event_type, key)| StateKey::new(event_type.as_str(), key.as_str())),
            kind: match self.kind {
                1 => spindle_core::Sideline::SoftFailed,
                2 => spindle_core::Sideline::Rejected,
                other => return Err(CodecError::Malformed(other)),
            },
            state_root: spindle_core::StateRoot::from_bytes(self.state_root),
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION, self.kind];
        out.extend_from_slice(&self.depth.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        put_str(&mut out, &self.event_id);
        put_len(&mut out, self.prev_events.len());
        for parent in &self.prev_events {
            put_str(&mut out, parent);
        }
        match &self.state_key {
            Some((event_type, state_key)) => {
                out.push(1);
                put_str(&mut out, event_type);
                put_str(&mut out, state_key);
            }
            None => out.push(0),
        }
        out
    }

    /// # Errors
    ///
    /// Returns [`CodecError`] for an unknown version or a truncated record.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor { bytes, at: 0 };
        let version = cursor.byte()?;
        if version != RECORD_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let kind = cursor.byte()?;
        let depth = u64::from_be_bytes(cursor.array::<8>()?);
        let state_root = cursor.array::<32>()?;
        let event_id = cursor.string()?;
        let parent_count = cursor.count()?;
        let mut prev_events = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            prev_events.push(cursor.string()?);
        }
        let state_key = match cursor.byte()? {
            0 => None,
            1 => Some((cursor.string()?, cursor.string()?)),
            other => return Err(CodecError::Malformed(other)),
        };
        Ok(Self {
            event_id,
            prev_events,
            depth,
            state_key,
            kind,
            state_root,
        })
    }
}

/// Per-room durable metadata: the counters and heads a reopen must recover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomRecord {
    pub next_forward: i64,
    pub next_backward: i64,
    pub forward_extremities: Vec<String>,
}

impl RoomRecord {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION];
        out.extend_from_slice(&order_preserving(self.next_forward));
        out.extend_from_slice(&order_preserving(self.next_backward));
        put_len(&mut out, self.forward_extremities.len());
        for extremity in &self.forward_extremities {
            put_str(&mut out, extremity);
        }
        out
    }

    /// # Errors
    ///
    /// Returns [`CodecError`] for an unknown version or a truncated record.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor { bytes, at: 0 };
        let version = cursor.byte()?;
        if version != RECORD_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let next_forward = spindle_core::keys::from_order_preserving(cursor.array::<8>()?);
        let next_backward = spindle_core::keys::from_order_preserving(cursor.array::<8>()?);
        let count = cursor.count()?;
        let mut forward_extremities = Vec::with_capacity(count);
        for _ in 0..count {
            forward_extremities.push(cursor.string()?);
        }
        Ok(Self {
            next_forward,
            next_backward,
            forward_extremities,
        })
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, value: &str) {
    put_len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CodecError> {
        let end = self.at.checked_add(count).ok_or(CodecError::Truncated)?;
        let bytes: &'a [u8] = self.bytes;
        let slice = bytes.get(self.at..end).ok_or(CodecError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        self.take(1)?.first().copied().ok_or(CodecError::Truncated)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    fn len(&mut self) -> Result<usize, CodecError> {
        Ok(u32::from_be_bytes(self.array::<4>()?) as usize)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    /// A count of framed items, bounded by what is left to frame them with.
    ///
    /// `Vec::with_capacity` on a length straight off disk is an allocation
    /// the input chooses, and `u32::MAX` items of `String` is a request for
    /// 103 GiB. That does not fail the way the rest of this module fails: a
    /// failed allocation aborts the process rather than returning a
    /// `CodecError` the caller could refuse, so a single flipped bit in one
    /// record takes the server down instead of costing it one row.
    ///
    /// Every item here costs at least the four bytes of its own length
    /// prefix, so the bytes remaining are a hard ceiling on how many can
    /// actually follow, and a record claiming more is truncated no matter
    /// what the rest of it says. Refusing on the count rather than clamping
    /// to the ceiling: clamping would read a record claiming four billion
    /// extremities as one holding none, which is a corrupt record silently
    /// becoming a plausible one -- the failure this whole module is shaped
    /// to avoid. An honest record never reaches the ceiling, so it still
    /// reserves exactly what it needs.
    fn count(&mut self) -> Result<usize, CodecError> {
        let claimed = self.len()?;
        if claimed > self.remaining() / 4 {
            return Err(CodecError::Truncated);
        }
        Ok(claimed)
    }

    fn string(&mut self) -> Result<String, CodecError> {
        self.str().map(str::to_owned)
    }

    /// A framed string, validated in place and borrowed from the record.
    fn str(&mut self) -> Result<&'a str, CodecError> {
        let len = self.len()?;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes).map_err(|_| CodecError::NotUtf8)
    }
}

/// A record that could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// Written by a different schema version than this binary understands.
    UnsupportedVersion(u8),
    /// The record ended mid-field.
    Truncated,
    /// A discriminant this version does not define.
    Malformed(u8),
    /// A string field was not valid UTF-8.
    NotUtf8,
}
