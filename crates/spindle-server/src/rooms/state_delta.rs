//! What the room's current state became, as a client is told it (#819).
//!
//! A client folds the timeline into its state. That is right while every
//! event is the newest word on its key, and wrong when it is not: an event
//! on a stale parent is appended and then loses state resolution, a fork's
//! merge may put an older event back, and an event accepted across a gap
//! brings the peer's state with it. In each the room's *current* state
//! moves by more than the event, and nothing in the timeline says so.
//!
//! [`Keyspace::RoomStateDelta`](spindle_core::keys::Keyspace::RoomStateDelta)
//! records that move, written in the batch of the event that caused it and
//! only when it exceeded the event. A linear append has no row. A sync reads
//! the rows beside the room's events and answers with the current event of
//! every key either touched.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde_json::{Value, json};
use spindle_core::StateKey;

use super::{RoomError, Rooms};

/// A room's keys and the current event of each, with the log index at which
/// that was settled so a later change to the same key wins.
type Changes = BTreeMap<(String, String), (i64, String)>;

/// One stored delta: the log index of the event that caused it and each
/// `(type, state_key, event_id)` it set.
type DeltaRow = (i64, Vec<(String, String, String)>);

/// The row a delta is stored as: the log index of the event that caused it
/// and every key it set, with the event that key now holds.
pub(super) fn encode(li: i64, changes: &[(StateKey, String)]) -> Vec<u8> {
    let set: Vec<Value> = changes
        .iter()
        .map(|(key, event_id)| json!([key.event_type().as_str(), key.state_key(), event_id]))
        .collect();
    json!({ "li": li, "set": set }).to_string().into_bytes()
}

fn decode(raw: &[u8]) -> Option<DeltaRow> {
    let stored: Value = serde_json::from_slice(raw).ok()?;
    let li = stored["li"].as_i64()?;
    let set = stored["set"]
        .as_array()?
        .iter()
        .filter_map(|item| {
            Some((
                item.get(0)?.as_str()?.to_owned(),
                item.get(1)?.as_str()?.to_owned(),
                item.get(2)?.as_str()?.to_owned(),
            ))
        })
        .collect();
    Some((li, set))
}

/// The log index of the event a stored delta row belongs to.
pub(super) fn row_li(raw: &[u8]) -> Option<i64> {
    decode(raw).map(|(li, _)| li)
}

impl Rooms {
    /// The delta rows a room wrote in `(since, until]`, oldest first.
    ///
    /// One scan that starts at the client's token, so its cost is the
    /// room's traffic since then and not its history. The caller reads it
    /// only for a room that had events in the window, because a row shares
    /// its stream id with the event that wrote it.
    fn state_delta_rows(
        &self,
        room_id: &str,
        since: u64,
        until: u64,
    ) -> Result<Vec<DeltaRow>, RoomError> {
        let rows = spindle_store::ReadView::scan_from(
            self.store.as_ref(),
            &spindle_core::keys::room_state_delta_prefix(room_id),
            &spindle_core::keys::room_state_delta(room_id, since + 1),
        )?;
        let mut out = Vec::new();
        for (key, raw) in rows {
            // Past the watermark is the next sync's, as in `room_slice`.
            if spindle_core::keys::room_stream_from_key(&key).is_some_and(|id| id > until) {
                break;
            }
            out.extend(decode(&raw));
        }
        Ok(out)
    }

    /// Every event a current-state delta in `(since, until]` named.
    ///
    /// A sliding-sync client is sent the required state whose current event
    /// is among the events that changed. A key put back to an older event
    /// is a change the stream's events do not show.
    pub(super) fn state_delta_event_ids(
        &self,
        room_id: &str,
        since: u64,
        until: u64,
    ) -> Result<Vec<String>, RoomError> {
        Ok(self
            .state_delta_rows(room_id, since, until)?
            .into_iter()
            .flat_map(|(_, set)| set.into_iter().map(|(_, _, event_id)| event_id))
            .collect())
    }

    /// The current event of every state key the room's events `slice`
    /// (log indices, oldest first) or the deltas in `(since, until]` touched,
    /// ordered by when each was settled.
    ///
    /// A state event of the slice sets its key, unless it has a delta of its
    /// own: then the delta says what the key is, because the event may have
    /// lost. Among several settlements of one key the latest wins, whether
    /// it was an event or a delta, which is why both carry the log index.
    pub(super) fn current_state_changes(
        &self,
        room_id: &str,
        slice: &[i64],
        range: (u64, u64),
    ) -> Result<Vec<String>, RoomError> {
        if slice.is_empty() {
            return Ok(Vec::new());
        }
        let mut changes: Changes = BTreeMap::new();
        self.with_room_read(room_id, |_, log| {
            for &li in slice {
                if let Some(entry) = log.entry_at(li)
                    && let Some(key) = &entry.state_key
                {
                    changes.insert(
                        (
                            key.event_type().as_str().to_owned(),
                            key.state_key().to_owned(),
                        ),
                        (li, entry.event_id.as_str().to_owned()),
                    );
                }
            }
            Ok(())
        })?;
        for (li, set) in self.state_delta_rows(room_id, range.0, range.1)? {
            for (event_type, state_key, event_id) in set {
                match changes.entry((event_type, state_key)) {
                    Entry::Occupied(mut held) if li >= held.get().0 => {
                        held.insert((li, event_id));
                    }
                    Entry::Occupied(_) => {}
                    Entry::Vacant(slot) => {
                        slot.insert((li, event_id));
                    }
                }
            }
        }
        let mut ordered: Vec<(i64, String)> = changes.into_values().collect();
        ordered.sort();
        Ok(ordered.into_iter().map(|(_, event_id)| event_id).collect())
    }
}
