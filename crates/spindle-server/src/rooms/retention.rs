//! History retention: truncate a room's log below a watermark (#817,
//! SPEC §14.3).
//!
//! `purge_history` deletes message bodies and keeps every log entry, because
//! the hash chain covers the event IDs. A truncation removes the entries
//! too. It first records the chain value just before the watermark
//! ([`spindle_core::ChainCheckpoint`]) and then deletes, so the room loads,
//! verifies and appends as before.
//!
//! The order is the safety argument. One atomic batch writes the checkpoint,
//! the purge watermark and the rewritten kept entries. Every delete after
//! it is idempotent and keyed off what is still stored below the floor, so
//! a crash at any point leaves a room that loads as truncated, and the next
//! run finishes the work. The log rows go last: they are what a resumed run
//! uses to find the rest.
//!
//! What stays below the floor, on purpose:
//!
//! - the log entry of every event in the current state, and of every event a
//!   retained entry names as a parent, without a chain value;
//! - the body of every event in the auth chain of a retained or current
//!   event, so `/event_auth` and `send_join` stay complete;
//! - filled federation gaps and sidelined events, which this does not
//!   inspect. The floor stays below the lowest gap anchor to protect them.

use std::collections::{BTreeSet, HashSet};

use serde_json::Value;
use spindle_core::{EventId, LinearIndex, RoomLog};
use spindle_store::codec::{ChainCheckpointRecord, EntryRecord};
use spindle_store::{Durability, ReadView, Store};

use super::{INVITE_STR, JOIN_STR, RoomError, Rooms, current_state, event_body_key};

/// Keys deleted per store call.
const DELETE_BATCH: usize = 4096;

/// What one truncation did, or why it did nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TruncationReport {
    /// Why the room was left alone, if it was.
    pub refused: Option<&'static str>,
    /// The floor that took effect. It is never above what was asked.
    pub floor: i64,
    /// Log rows deleted.
    pub entries: u64,
    /// Event bodies deleted.
    pub bodies: u64,
    /// Index rows deleted: streams, relations, membership history.
    pub index_rows: u64,
}

impl TruncationReport {
    fn refused(reason: &'static str) -> Self {
        Self {
            refused: Some(reason),
            ..Self::default()
        }
    }
}

impl Rooms {
    /// Delete a room's log, indexes and bodies below `below_li`, keeping
    /// the chain verifiable from a checkpoint.
    ///
    /// The floor is lowered to what is safe: never above the head, an
    /// extremity, a pending gap or a filled gap's anchor. A room in hub
    /// mode, in a partial-state join or with several forward extremities
    /// is left alone, and the report says why. Calling it again with the
    /// same or a lower value finishes an interrupted run and otherwise
    /// does nothing.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not exist,
    /// or [`RoomError`] if the store cannot be read or written. A failed
    /// write evicts the open room, so the next read loads what is stored.
    pub fn truncate_room_log(
        &self,
        room_id: &str,
        below_li: i64,
    ) -> Result<TruncationReport, RoomError> {
        if self.is_partial_state(room_id) {
            return Ok(TruncationReport::refused(
                "the room has a partial-state join",
            ));
        }
        let anchors = self.gap_anchors(room_id)?;
        let hub = self.has_hub_rows(room_id)?;
        self.with_room(room_id, |rooms, log| {
            if hub
                || current_state(log)
                    .iter()
                    .any(|(key, _)| key.event_type().as_str() == "m.room.hub")
            {
                return Ok(TruncationReport::refused("the room is in hub mode"));
            }
            if log.is_forked() {
                return Ok(TruncationReport::refused(
                    "the room has several forward extremities",
                ));
            }
            let floor = safe_floor(log, below_li, &anchors);
            let resume = log.chain_checkpoint().map_or(i64::MIN, |point| point.floor);
            let delete_floor = floor.max(resume);
            if floor > resume
                && log
                    .entries()
                    .next()
                    .is_some_and(|first| first.li.get() < floor)
            {
                rooms.begin_truncation(room_id, log, floor)?;
            }
            rooms.finish_truncation(room_id, log, delete_floor)
        })
    }

    /// Lowest anchor among filled gaps and pending gap markers' events.
    fn gap_anchors(&self, room_id: &str) -> Result<BTreeSet<i64>, RoomError> {
        let mut anchors: BTreeSet<i64> = self.gap_spans(room_id)?.keys().copied().collect();
        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::FederationGap, room_id);
        let markers = ReadView::scan_prefix(self.store.as_ref(), &prefix)?;
        if !markers.is_empty() {
            let ids: Vec<String> = markers
                .iter()
                .filter_map(|(key, _)| {
                    String::from_utf8(key.strip_prefix(prefix.as_slice())?.to_vec()).ok()
                })
                .collect();
            let held = self.with_room_read(room_id, |_, log| {
                Ok(ids
                    .iter()
                    .filter_map(|id| log.get(&EventId::new(id.as_str())).map(|e| e.li.get()))
                    .collect::<Vec<_>>())
            })?;
            anchors.extend(held);
        }
        Ok(anchors)
    }

    /// Whether the room has a hub's attestations, which commit to the chain
    /// from the first entry.
    fn has_hub_rows(&self, room_id: &str) -> Result<bool, RoomError> {
        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::HubAttestation, room_id);
        let mut end = prefix.clone();
        end.extend_from_slice(&[0xff; 9]);
        Ok(ReadView::last_before(self.store.as_ref(), &prefix, &end)?.is_some())
    }

    /// Step one: move the log's floor in memory and make the checkpoint
    /// durable in one batch, before anything is deleted.
    fn begin_truncation(
        &self,
        room_id: &str,
        log: &mut RoomLog,
        floor: i64,
    ) -> Result<(), RoomError> {
        let keep = pinned_below(log, floor);
        let Some(truncation) = log.truncate_below(floor, &keep) else {
            return Ok(());
        };
        let mut writes = vec![(
            spindle_core::keys::chain_checkpoint(room_id),
            ChainCheckpointRecord {
                floor: truncation.checkpoint.floor,
                chain: *truncation.checkpoint.chain.as_bytes(),
            }
            .encode(),
        )];
        for entry in &truncation.kept {
            writes.push((
                spindle_core::keys::room_li(spindle_core::keys::Keyspace::Log, room_id, entry.li),
                EntryRecord::from_entry(entry).encode(),
            ));
        }
        let mark = self
            .purge_watermark(room_id)?
            .map_or(floor, |existing| existing.max(floor));
        writes.push((
            spindle_core::keys::purge_watermark(room_id),
            mark.to_be_bytes().to_vec(),
        ));
        Store::commit(self.store.as_ref(), &writes, Durability::Group)?;
        Ok(())
    }

    /// Step two: delete what the floor makes unreachable. Safe to repeat.
    fn finish_truncation(
        &self,
        room_id: &str,
        log: &RoomLog,
        floor: i64,
    ) -> Result<TruncationReport, RoomError> {
        let store = self.store.as_ref();
        let log_prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Log, room_id);
        let end = spindle_core::keys::room_li(
            spindle_core::keys::Keyspace::Log,
            room_id,
            LinearIndex::from_raw(floor),
        );
        let mut doomed = Vec::new();
        for (key, value) in ReadView::scan_until(store, &log_prefix, &log_prefix, &end)? {
            let record = EntryRecord::decode(&value).map_err(spindle_store::StoreError::from)?;
            if log.entry_at(record.li).is_none() {
                doomed.push((key, record));
            }
        }
        let mut report = TruncationReport {
            floor,
            ..TruncationReport::default()
        };
        if doomed.is_empty() {
            return Ok(report);
        }
        let keep = self.bodies_to_keep(room_id, log)?;
        let (mut bodies, mut reverse) = (Vec::new(), Vec::new());
        for (_, record) in &doomed {
            if !keep.contains(&record.event_id) {
                bodies.push(event_body_key(room_id, &record.event_id));
                reverse.push(spindle_core::keys::event_room(&record.event_id));
            }
        }
        report.bodies = delete_counting(store, &bodies)?;
        report.index_rows += delete_counting(store, &reverse)?;
        report.index_rows += self.delete_stream_rows(room_id, log, floor)?;
        report.index_rows += self.delete_state_delta_rows(room_id, log, floor)?;
        report.index_rows += self.delete_relation_rows(room_id, log, floor)?;
        let users: BTreeSet<&str> = doomed
            .iter()
            .filter_map(|(_, record)| match &record.state_key {
                Some((kind, user)) if kind == "m.room.member" => Some(user.as_str()),
                _ => None,
            })
            .collect();
        for user in users {
            report.index_rows += self.delete_member_history(room_id, user, floor)?;
        }
        let log_keys: Vec<Vec<u8>> = doomed.into_iter().map(|(key, _)| key).collect();
        report.entries = delete_counting(store, &log_keys)?;
        Store::sync(store, Durability::Group)?;
        Ok(report)
    }

    /// The events whose bodies outlive a truncation: the auth chain of
    /// everything the log still holds and of the current state.
    fn bodies_to_keep(&self, room_id: &str, log: &RoomLog) -> Result<HashSet<String>, RoomError> {
        let mut seen: HashSet<String> = log
            .entries()
            .map(|entry| entry.event_id.as_str().to_owned())
            .collect();
        seen.extend(current_state(log).into_iter().map(|(_, id)| id));
        let mut frontier: Vec<String> = seen.iter().cloned().collect();
        while let Some(id) = frontier.pop() {
            let body = match self.read_event(room_id, &EventId::new(id.as_str())) {
                Ok(body) => body,
                Err(RoomError::MissingBody(_)) => continue,
                Err(error) => return Err(error),
            };
            let Some(auth) = body.get("auth_events").and_then(Value::as_array) else {
                continue;
            };
            for cited in auth.iter().filter_map(Value::as_str) {
                if seen.insert(cited.to_owned()) {
                    frontier.push(cited.to_owned());
                }
            }
        }
        Ok(seen)
    }

    fn delete_stream_rows(
        &self,
        room_id: &str,
        log: &RoomLog,
        floor: i64,
    ) -> Result<u64, RoomError> {
        let store = self.store.as_ref();
        let mut keys = Vec::new();
        for (key, value) in
            ReadView::scan_prefix(store, &spindle_core::keys::room_stream_prefix(room_id))?
        {
            let Some(li) = value.get(..8).and_then(|raw| <[u8; 8]>::try_from(raw).ok()) else {
                continue;
            };
            let li = i64::from_be_bytes(li);
            if li >= floor || log.entry_at(li).is_some() {
                continue;
            }
            if let Some(stream_id) = spindle_core::keys::room_stream_from_key(&key) {
                keys.push(spindle_core::keys::stream(stream_id));
            }
            keys.push(key);
        }
        Ok(delete_counting(store, &keys)?)
    }

    /// Drop the current-state deltas (#819) of the entries the floor
    /// removed. A delta shares its stream id with the event that caused
    /// it, so it is dead weight once that event's stream row is gone.
    fn delete_state_delta_rows(
        &self,
        room_id: &str,
        log: &RoomLog,
        floor: i64,
    ) -> Result<u64, RoomError> {
        let store = self.store.as_ref();
        let keys: Vec<Vec<u8>> =
            ReadView::scan_prefix(store, &spindle_core::keys::room_state_delta_prefix(room_id))?
                .into_iter()
                .filter_map(|(key, value)| {
                    let li = super::state_delta::row_li(&value)?;
                    (li < floor && log.entry_at(li).is_none()).then_some(key)
                })
                .collect();
        Ok(delete_counting(store, &keys)?)
    }

    fn delete_relation_rows(
        &self,
        room_id: &str,
        log: &RoomLog,
        floor: i64,
    ) -> Result<u64, RoomError> {
        let store = self.store.as_ref();
        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Relation, room_id);
        let keys: Vec<Vec<u8>> = ReadView::scan_prefix(store, &prefix)?
            .into_iter()
            .filter_map(|(key, _)| {
                let li = spindle_core::keys::li_from_key(&key)?;
                (li < floor && log.entry_at(li).is_none()).then_some(key)
            })
            .collect();
        Ok(delete_counting(store, &keys)?)
    }

    /// Drop a user's membership rows below `floor`, except the newest one
    /// when it opens a stint that is still open at the floor.
    fn delete_member_history(
        &self,
        room_id: &str,
        user_id: &str,
        floor: i64,
    ) -> Result<u64, RoomError> {
        let store = self.store.as_ref();
        let prefix = spindle_core::keys::member_history_prefix(user_id, room_id);
        let mut below: Vec<(Vec<u8>, Vec<u8>)> = ReadView::scan_prefix(store, &prefix)?
            .into_iter()
            .filter(|(key, _)| {
                spindle_core::keys::member_history_li(user_id, room_id, key)
                    .is_some_and(|li| li < floor)
            })
            .collect();
        if let Some((_, value)) = below.last()
            && (value.as_slice() == JOIN_STR.as_bytes()
                || value.as_slice() == INVITE_STR.as_bytes())
        {
            below.pop();
        }
        let keys: Vec<Vec<u8>> = below.into_iter().map(|(key, _)| key).collect();
        Ok(delete_counting(store, &keys)?)
    }
}

/// The highest floor at or below `requested` that leaves the head, every
/// extremity and every gap anchor in the log.
fn safe_floor(log: &RoomLog, requested: i64, anchors: &BTreeSet<i64>) -> i64 {
    let head = log
        .entries()
        .next_back()
        .map_or(i64::MIN, |entry| entry.li.get());
    let mut floor = requested.min(head);
    for tip in log.forward_extremities() {
        if let Some(entry) = log.get(tip) {
            floor = floor.min(entry.li.get());
        }
    }
    if let Some(anchor) = anchors.first() {
        floor = floor.min(*anchor);
    }
    floor
}

/// Entries below `floor` the log keeps: those in the current state, which
/// readers look up by event ID, and those a retained entry names as a
/// parent.
fn pinned_below(log: &RoomLog, floor: i64) -> BTreeSet<LinearIndex> {
    let mut keep = BTreeSet::new();
    for (_, id) in current_state(log) {
        if let Some(entry) = log.get(&EventId::new(id.as_str()))
            && entry.li.get() < floor
        {
            keep.insert(entry.li);
        }
    }
    for entry in log.entries_in(floor..) {
        for parent in &entry.prev_events {
            if let Some(held) = log.get(parent)
                && held.li.get() < floor
            {
                keep.insert(held.li);
            }
        }
    }
    keep
}

/// Delete `keys` in batches and report how many were present.
fn delete_counting(store: &impl Store, keys: &[Vec<u8>]) -> Result<u64, spindle_store::StoreError> {
    let mut present = 0;
    for chunk in keys.chunks(DELETE_BATCH) {
        for key in chunk {
            if ReadView::get(store, key)?.is_some() {
                present += 1;
            }
        }
        store.delete_batch(chunk)?;
    }
    Ok(present)
}
