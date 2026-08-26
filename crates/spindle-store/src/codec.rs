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
            state_root: *entry.state_after.root().as_bytes(),
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
        let parent_count = cursor.len()?;
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
            li,
            event_id,
            prev_events,
            depth,
            state_key,
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
        let count = cursor.len()?;
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

impl Cursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], CodecError> {
        let end = self.at.checked_add(count).ok_or(CodecError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(CodecError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    fn len(&mut self) -> Result<usize, CodecError> {
        Ok(u32::from_be_bytes(self.array::<4>()?) as usize)
    }

    fn string(&mut self) -> Result<String, CodecError> {
        let len = self.len()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::NotUtf8)
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
