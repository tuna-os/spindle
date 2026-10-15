//! Synapse pagination positions, carried across a migration (#568).
//!
//! A client keeps Synapse's pagination tokens beside the gaps in its cached
//! timeline -- Element X's event cache stores them in `SQLite`, Element Web's
//! sync accumulator in `IndexedDB` -- and after the switch it sends them back
//! to fill those gaps. They name a place in Synapse's order,
//! `(topological_ordering, stream_ordering)`, which this server does not
//! keep. The importer does know, for every event it writes, both the stream
//! ordering Synapse gave it and the linear index it got here, so it records
//! the pair, and a Synapse token resolves to the gap after the newest
//! imported event at or below it.
//!
//! Topological tokens use the original `(depth, stream)` ordering. Stream
//! tokens use arrival order. Each index stores the greatest imported linear
//! index at or below its key, so back-pagination can repeat events when
//! arrival order differs from room order without skipping older history.
//!
//! A room with no recorded positions (one not imported, or imported before
//! this existed) has no answer here, and the caller falls back.

use spindle_core::EventId;

use super::{RoomError, Rooms};
use crate::tokens::SynapsePosition;

/// Where a Synapse token lands in a room's linear index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynapseGap {
    /// The gap just above the entry at this index minus one: page from
    /// `Pagination(gap)`.
    At(i64),
    /// The token is older than everything imported: nothing lies below it.
    BeforeAll,
}

impl Rooms {
    /// Record, for events the importer has written to `room_id`, the
    /// stream ordering Synapse gave each one.
    ///
    /// `positions` is `(stream_ordering, depth, event_id)`. Events not in this
    /// room's log (an outlier, a rejected event, a room excluded from the
    /// import) are skipped, and the count of rows written is returned.
    /// Writing a pair again is harmless, so a resumed import can record a
    /// room's events a second time.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the store refuses the
    /// write.
    pub fn record_synapse_positions<'a>(
        &self,
        room_id: &str,
        positions: impl IntoIterator<Item = (i64, i64, &'a str)>,
    ) -> Result<usize, RoomError> {
        let positions: Vec<(i64, i64, &str)> = positions.into_iter().collect();
        let positions: Vec<(i64, i64, i64)> = self.with_room_read(room_id, |_, log| {
            Ok(positions
                .iter()
                .filter_map(|(stream, depth, event_id)| {
                    let li = log.get(&EventId::new(*event_id))?.li.get();
                    Some((*stream, *depth, li))
                })
                .collect())
        })?;
        let count = positions.len();
        let mut rows = Vec::with_capacity(count * 2);
        for topological in [false, true] {
            let mut ordered: Vec<_> = positions
                .iter()
                .map(|(stream, depth, li)| {
                    let key = if topological {
                        spindle_core::keys::synapse_topological_position(room_id, *depth, *stream)
                    } else {
                        spindle_core::keys::synapse_position(room_id, *stream)
                    };
                    (key, *li)
                })
                .collect();
            ordered.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let mut highest = i64::MIN;
            for (key, li) in ordered {
                highest = highest.max(li);
                rows.push((key, highest.to_be_bytes().to_vec()));
            }
        }
        for chunk in rows.chunks(4096) {
            spindle_store::Store::commit(
                self.store.as_ref(),
                chunk,
                spindle_store::Durability::Group,
            )?;
        }
        Ok(count)
    }

    /// Where `position`, from a Synapse token, lands in `room_id`: the gap
    /// just after the newest imported event at or below it.
    ///
    /// `None` when the room has no recorded positions at all.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be read.
    pub fn synapse_gap(
        &self,
        room_id: &str,
        position: SynapsePosition,
    ) -> Result<Option<SynapseGap>, RoomError> {
        let topological = position.topological;
        let prefix = spindle_core::keys::room_prefix(
            if topological.is_some() {
                spindle_core::keys::Keyspace::SynapseTopologicalPosition
            } else {
                spindle_core::keys::Keyspace::SynapsePosition
            },
            room_id,
        );
        let key = |stream: i64| match topological {
            Some(depth) => spindle_core::keys::synapse_topological_position(room_id, depth, stream),
            None => spindle_core::keys::synapse_position(room_id, stream),
        };
        let li_of = |record: &spindle_store::Record| -> Option<i64> {
            Some(i64::from_be_bytes(record.1.as_slice().try_into().ok()?))
        };
        let stream = position.stream;
        // Signed stream keys sort in stream order. Appending a zero makes
        // the exclusive upper bound include the exact key, even at MAX.
        let mut end = key(stream);
        end.push(0);
        if let Some(record) =
            spindle_store::ReadView::last_before(self.store.as_ref(), &prefix, &end)?
        {
            let li = li_of(&record).ok_or_else(|| {
                RoomError::Build("an imported Synapse position has a malformed index".to_owned())
            })?;
            return Ok(Some(SynapseGap::At(li.saturating_add(1))));
        }
        let mut newest = if topological.is_some() {
            spindle_core::keys::synapse_topological_position(room_id, i64::MAX, i64::MAX)
        } else {
            key(i64::MAX)
        };
        newest.push(0);
        Ok(
            spindle_store::ReadView::last_before(self.store.as_ref(), &prefix, &newest)?
                .map(|_| SynapseGap::BeforeAll),
        )
    }
}
