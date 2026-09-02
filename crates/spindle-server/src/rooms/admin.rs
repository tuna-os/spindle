//! What an operator does to a room that a member never can: list every
//! room the server holds, read a room's spine with purged bodies shown as
//! purged, read its state as of a point, block it, and purge its history
//! below a position.
//!
//! A child of `rooms`, like `unread`: it reads `Rooms`' private fields and
//! helpers, so this is a file split of one `impl Rooms` block (#311) and
//! not a new boundary yet. That these are the destructive methods is the
//! reason they get their own file first: a reader looking for what an
//! admin route can do finds all of it here.

use serde_json::Value;
use spindle_core::{EventId, LogEntry};

use super::{RoomError, Rooms, StateAtAnchor, event_body_key};
use crate::admin::AdminActor;

/// One log entry as the admin timeline shows it: the spine always, the
/// body only while it exists. `json: None` with the entry present is the
/// mark of a purge — the distinction #83 §3 says a purge must preserve.
#[derive(Clone, Debug)]
pub struct AdminTimelineEntry {
    pub li: i64,
    pub event_id: String,
    /// This server's chain attestation, `None` for backfilled history.
    pub chain: Option<[u8; 32]>,
    /// `None` when the body was purged.
    pub json: Option<Value>,
}

impl Rooms {
    /// Why an administrator blocked this room, if one did.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the row cannot be read.
    pub fn room_block(&self, room_id: &str) -> Result<Option<Value>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::room_block(room_id),
        )?
        .and_then(|raw| serde_json::from_slice(&raw).ok()))
    }

    /// The first `li` NOT covered by a history purge, if one ever ran.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the row cannot be read.
    pub fn purge_watermark(&self, room_id: &str) -> Result<Option<i64>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::purge_watermark(room_id),
        )?
        .and_then(|raw| raw.get(..8).map(|bytes| bytes.try_into().unwrap_or([0; 8])))
        .map(i64::from_be_bytes))
    }
}

/// A handle on the operations an operator may perform on a room.
///
/// The five methods here are the destructive and server-wide ones, and
/// they sit on this type rather than on [`Rooms`] so that reaching them
/// is a property of what a handler was given. [`Rooms::admin`] is the
/// only way to build one and it asks for an [`AdminActor`] — the token
/// the admin routes' extractor mints and nothing else can, since #311
/// asked for a compile-time fact in place of a review convention. A
/// client handler holds the same `Arc<Rooms>` as before and now cannot
/// name `purge_history` at all.
///
/// Borrowed rather than owned: the handle is made per request, at the
/// call, and outlives nothing.
pub struct RoomAdmin<'a> {
    rooms: &'a Rooms,
}

impl Rooms {
    /// The administrative view of these rooms, for a caller who has
    /// proven they are a server admin.
    ///
    /// The proof is taken by reference and never read: what matters is
    /// that the caller *had* one to give, which only an admin-gated
    /// handler does.
    #[must_use]
    pub fn admin(&self, _proof: &AdminActor) -> RoomAdmin<'_> {
        RoomAdmin { rooms: self }
    }
}

impl RoomAdmin<'_> {
    /// The room's state at a past point (#83 §4): the query the linear
    /// index turns from a forensic exercise into one seek.
    ///
    /// The anchor resolves to a log entry — the newest at or before an
    /// `li`, the entry of an event ID, or (for a timestamp) the last
    /// entry whose `origin_server_ts` is at or under it, found by binary
    /// search because in a linearized room the storage order *is* the
    /// temporal order. Every entry keeps its 32-byte `state_root`
    /// forever and the log records persist it, so the sparse per-`li`
    /// index #83 anticipated is unnecessary: any entry's state is the
    /// resident snapshot when the window still holds it, and a rehydrate
    /// of shared trie nodes when it does not — slower, never refused.
    ///
    /// Returns the resolved `(li, event_id, resident, state events)` so
    /// the caller can say exactly which point it answered for.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not
    /// exist, and [`RoomError::UnknownState`] when the log starts after
    /// the requested point or the event is not in this room.
    pub fn admin_state_at(
        &self,
        room_id: &str,
        anchor: &StateAtAnchor,
    ) -> Result<(i64, String, bool, Vec<Value>), RoomError> {
        let (li, event_id) = self.rooms.resolve_anchor(room_id, anchor)?;

        let root_or_resident = self.rooms.with_room_read(room_id, |_, log| {
            if let Some(snapshot) = log.state_after(spindle_core::LinearIndex::from_raw(li)) {
                let mut ids = Vec::with_capacity(snapshot.len());
                snapshot.for_each(|_, id| ids.push(id.to_owned()));
                Ok(Ok(ids))
            } else {
                let entry = log
                    .entry_at_or_before(li)
                    .ok_or_else(|| RoomError::UnknownState("that entry".into()))?;
                Ok(Err(entry.state_root))
            }
        })?;
        let (resident, state) = match root_or_resident {
            Ok(ids) => {
                let mut out = Vec::with_capacity(ids.len());
                for id in ids {
                    out.push(self.rooms.event(room_id, &id)?);
                }
                (true, out)
            }
            Err(root) => (false, self.rooms.state_at(room_id, root)?),
        };
        Ok((li, event_id, resident, state))
    }

    /// Every room this server holds, from the stored metadata rows.
    ///
    /// A scan of the `RoomMeta` keyspace rather than the open-rooms map,
    /// for the same reason `joined` reads storage: it is correct after a
    /// restart, when nothing is open yet. The admin listing is the caller;
    /// nothing on the client-serving hot path enumerates every room.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be scanned.
    pub fn all_room_ids(&self) -> Result<Vec<String>, RoomError> {
        let prefix = [
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::RoomMeta as u8,
        ];
        let records = spindle_store::ReadView::scan_prefix(self.rooms.store.as_ref(), &prefix)?;
        let mut out = Vec::with_capacity(records.len());
        for (key, _) in records {
            // Key layout per `keys::room_prefix`: version, keyspace,
            // u16 length, then the room ID bytes.
            let Some(len) = key
                .get(2..4)
                .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            else {
                continue;
            };
            if let Some(room) = key
                .get(4..4 + len)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
            {
                out.push(room.to_owned());
            }
        }
        Ok(out)
    }

    /// The admin view of the log: entries in `li` order, either direction,
    /// paginated by an exclusive `from` boundary.
    ///
    /// Unlike `/messages` this walks storage order both ways, because the
    /// operator's question is "what does the log say" rather than "what is
    /// new" — #83's table calls it out as the query the linear index makes
    /// trivial. The returned token re-includes nothing: pass it back as
    /// `from` verbatim to continue.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its records cannot
    /// be read.
    pub fn admin_timeline(
        &self,
        room_id: &str,
        from: Option<i64>,
        limit: usize,
        forward: bool,
    ) -> Result<(Vec<AdminTimelineEntry>, Option<i64>), RoomError> {
        let (wanted, next) = self.rooms.with_room_read(room_id, |_, log| {
            let mut wanted = Vec::new();
            let mut next = None;
            let mut visit = |entry: &LogEntry| {
                if wanted.len() == limit {
                    next = Some(entry.li.get());
                    return true;
                }
                wanted.push((
                    entry.li.get(),
                    entry.event_id.as_str().to_owned(),
                    entry.chain.map(|chain| *chain.as_bytes()),
                ));
                false
            };
            if forward {
                for entry in log.entries() {
                    if from.is_some_and(|from| entry.li.get() <= from) {
                        continue;
                    }
                    if visit(entry) {
                        break;
                    }
                }
                // Continuing forward from the last returned entry means
                // "everything above it", which is that entry's own `li`.
                next = next.map(|li| li - 1);
            } else {
                for entry in log.entries().rev() {
                    if from.is_some_and(|from| entry.li.get() >= from) {
                        continue;
                    }
                    if visit(entry) {
                        break;
                    }
                }
                next = next.map(|li| li + 1);
            }
            Ok((wanted, next))
        })?;

        let watermark = self.rooms.purge_watermark(room_id)?;
        let mut out = Vec::with_capacity(wanted.len());
        for (li, event_id, chain) in wanted {
            let json = match self
                .rooms
                .read_event(room_id, &EventId::new(event_id.as_str()))
            {
                Ok(json) => Some(json),
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| li < mark) => None,
                Err(error) => return Err(error),
            };
            out.push(AdminTimelineEntry {
                li,
                event_id,
                chain,
                json,
            });
        }
        Ok((out, next))
    }

    /// Record an administrative block. The row's presence is the block;
    /// the record says who and when for the audit trail.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the store cannot be written.
    pub fn set_room_block(&self, room_id: &str, record: &Value) -> Result<(), RoomError> {
        spindle_store::Store::put(
            self.rooms.store.as_ref(),
            &spindle_core::keys::room_block(room_id),
            serde_json::to_vec(record)
                .map_err(|error| RoomError::Codec(error.to_string()))?
                .as_slice(),
        )?;
        Ok(())
    }

    /// Purge history before `before_li`: delete the bodies, keep the spine.
    ///
    /// What is deleted is exactly the content-bearing records — the bodies
    /// of non-state events below the cutoff. Everything else survives on
    /// purpose (#83 §3): the log entries `(li, event_id, chain)`, because
    /// `ChainHash::extend` hashes event IDs and deleting an entry would
    /// break every chain value after it; state event bodies, because
    /// current state and `state_at` must keep folding from the log; and
    /// the trie nodes, which hold event IDs, never content. The watermark
    /// is written before the deletes so a crash between them leaves
    /// below-the-mark gaps reading as "purged", never as corruption.
    ///
    /// Returns how many event bodies were actually deleted.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] for a room that does not exist,
    /// or [`RoomError`] if the store cannot be written.
    pub fn purge_history(&self, room_id: &str, before_li: i64) -> Result<u64, RoomError> {
        let victims = self.rooms.with_room_read(room_id, |_, log| {
            Ok(log
                .entries()
                .take_while(|entry| entry.li.get() < before_li)
                .filter(|entry| entry.state_key.is_none())
                .map(|entry| entry.event_id.as_str().to_owned())
                .collect::<Vec<_>>())
        })?;
        // The watermark only moves forward: a second, shallower purge must
        // not un-mark entries the first one already deleted.
        let mark = self
            .rooms
            .purge_watermark(room_id)?
            .map_or(before_li, |existing| existing.max(before_li));
        spindle_store::Store::put(
            self.rooms.store.as_ref(),
            &spindle_core::keys::purge_watermark(room_id),
            &mark.to_be_bytes(),
        )?;
        let mut purged = 0;
        for event_id in &victims {
            let key = event_body_key(room_id, event_id);
            if spindle_store::ReadView::get(self.rooms.store.as_ref(), &key)?.is_some() {
                spindle_store::Store::delete(self.rooms.store.as_ref(), &key)?;
                purged += 1;
            }
        }
        Ok(purged)
    }
}
