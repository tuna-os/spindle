//! Read receipts, and the two counts they define: what a member is behind
//! on, and how much of that their push rules highlight.
//!
//! A child of `rooms` rather than a sibling, so it reads `Rooms`' private
//! fields (the store, the two caches) and its private helpers the way the
//! rest of the room code does: this is a file split of one `impl Rooms`
//! block (#311), not a new boundary. The receipt row format and the two
//! in-memory indexes live here with the methods that are their only users.

use std::collections::HashMap;

use serde_json::Value;
use spindle_core::EventId;

use super::{RoomError, Rooms, now_ms};

/// Per-room index answering "how many timeline events after `li`, and how
/// many of them are mine" without reading a single event body.
///
/// Exists because the unread count used to read every body after the
/// receipt floor to learn its sender — O(events since floor) store reads
/// per sync, which for a user with no receipt (every bot, every client
/// that doesn't send read receipts) meant the whole room, every time. The
/// M2 close-out benchmark caught it: the one column where a sibling was
/// faster, and the one whose curve grew with room size. Built once per
/// room per process (the one remaining full walk), updated on append,
/// queried by binary search.
#[derive(Default)]
pub(super) struct UnreadIndex {
    /// Linear indices of every timeline (non-state) entry, ascending.
    timeline: Vec<i64>,
    /// The same, per sender.
    by_sender: HashMap<String, Vec<i64>>,
}

impl UnreadIndex {
    pub(super) fn push(&mut self, li: i64, sender: &str) {
        // Appends arrive in li order, so pushing keeps both vectors sorted.
        // Backfill (negative indices, M3) must not use this path: it would
        // break the invariant — invalidate the room's cache instead.
        self.timeline.push(li);
        self.by_sender
            .entry(sender.to_owned())
            .or_default()
            .push(li);
    }

    /// Timeline events after `boundary` not sent by `user_id`.
    fn count_after(&self, boundary: i64, user_id: &str) -> usize {
        let after = |lis: &[i64]| lis.len() - lis.partition_point(|&li| li <= boundary);
        let own = self.by_sender.get(user_id).map_or(0, |lis| after(lis));
        after(&self.timeline) - own
    }
}

/// How far one reader's unread highlights in one room have been scored.
///
/// The count is arithmetic for notifications ([`UnreadIndex`]) and cannot
/// be for highlights: whether an event highlights is a push-rule question
/// answered against its body. Scoring every unread body on every sync would
/// bring back the walk #81 removed, so the tally remembers the position it
/// was scored to and only what came after it is read again. It is keyed on
/// the boundary it counted from: a receipt that moves, or a rejoin, starts
/// a fresh count over the new unread range.
#[derive(Clone, Copy)]
pub(super) struct HighlightTally {
    boundary: i64,
    upto: i64,
    count: usize,
}

/// The unread events one reader's highlight tally has not scored yet.
pub struct Unscored {
    /// Highlights already counted after the boundary.
    pub count: usize,
    /// Bodies after the scored position, oldest first, none the reader's
    /// own; the caller puts these to the reader's rules.
    pub events: Vec<Value>,
    /// The position the tally covers once `events` are scored.
    pub upto: i64,
}

/// A user's position in a room.
pub struct Receipt {
    pub event_id: String,
    pub li: i64,
    pub ts: u64,
}

/// What a client shows as a badge.
pub struct Unread {
    pub notification_count: usize,
    pub read_up_to: Option<String>,
    /// The position the count starts after: the reader's receipt or their
    /// join, whichever is later. `None` for someone who is not a member.
    pub boundary: Option<i64>,
}

impl Rooms {
    /// Record that `user_id` has read up to `event_id`.
    ///
    /// Members only. A receipt is not private bookkeeping the way a forget
    /// is: `m.read` is fanned out to everyone in the room, so accepting one
    /// from outside let any account put its name into a private room's
    /// receipt stream against any event ID it had learnt. Checked before the
    /// room is opened, so a stranger gets the same refusal whether or not
    /// the room exists (#268).
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::Forbidden`] if the user is not joined,
    /// [`RoomError::UnknownRoom`] if the room does not exist, or
    /// [`RoomError::MissingBody`] if the event is not one of its events — a
    /// receipt for an event the room does not have would set an unread
    /// boundary at a position that means nothing.
    pub fn set_receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
        event_id: &str,
    ) -> Result<(), RoomError> {
        if !self.is_joined(user_id, room_id)? {
            return Err(RoomError::Forbidden(format!(
                "{user_id} is not in {room_id}"
            )));
        }
        let li = self
            .with_room(room_id, |_, log| {
                Ok(log.get(&EventId::new(event_id)).map(|entry| entry.li.get()))
            })?
            .ok_or_else(|| RoomError::MissingBody(event_id.to_owned()))?;

        spindle_store::Store::put(
            self.store.as_ref(),
            &receipt_key(room_id, user_id, receipt_type),
            &ReceiptRecord {
                event_id: event_id.to_owned(),
                li,
                ts: now_ms(),
            }
            .encode(),
        )?;
        Ok(())
    }

    /// How many events a user has not read, and where they read up to.
    ///
    /// **The unread boundary is arithmetic, not a traversal.** Every accepted
    /// event holds a linear index, and the occupied range is contiguous --
    /// backfill fills `0, -1, -2, …` while live events fill `1, 2, 3, …`, so
    /// the two meet rather than leaving a hole. "Which events come after this
    /// one" is therefore `head - receipt`, exactly, including for a receipt on
    /// backfilled history. A DAG server answers the same question by ordering
    /// a graph first.
    ///
    /// The *count* still reads the events, because not everything in that
    /// range notifies: a user's own messages do not, and neither do state
    /// events. That is a scan of a contiguous range rather than a graph walk,
    /// and it is proportional to how far behind the user is -- which is a real
    /// cost for a long-absent one, and the reason SPEC §15's per-room executor
    /// eventually caches it.
    ///
    /// Push rules are not applied, because there are none yet (#7 lists them
    /// separately). Until then every message from somebody else counts, which
    /// is an over-count for a room with a mute rule and the honest behaviour
    /// for a server that has no rules to consult.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its events cannot be read.
    pub fn unread(&self, room_id: &str, user_id: &str) -> Result<Unread, RoomError> {
        let read_up_to = self.receipt(room_id, user_id, "m.read")?;
        // A user is not behind on what was said before they arrived, so the
        // count starts at their own membership event however far back the
        // room goes. Without that floor a user with no receipt -- which is
        // every new joiner -- has a boundary of `i64::MIN`, and the walk below
        // reads *every event body in the room* on their first sync. That was
        // #81, and it is the one operation that grew with room size while the
        // rest of the API stayed flat.
        //
        // With a receipt, the later of the two wins. A receipt can sit below
        // the join -- backfilled history carries negative indices, and the
        // spec does not stop a client acknowledging one -- and taking the
        // receipt alone there would walk back into history the user was never
        // present for.
        let joined_at = self.membership_event(room_id, user_id)?.map(|(_, li)| li);
        let boundary = match (read_up_to.as_ref().map(|receipt| receipt.li), joined_at) {
            (Some(receipt), Some(joined)) => receipt.max(joined),
            (Some(receipt), None) => receipt,
            (None, Some(joined)) => joined,
            // Neither a receipt nor a membership: not a member, so there is
            // nothing this user could be behind on, and no range to walk.
            (None, None) => {
                return Ok(Unread {
                    notification_count: 0,
                    read_up_to: None,
                    boundary: None,
                });
            }
        };

        // Two binary searches over the room's sender index: how many
        // timeline events sit after the boundary, minus how many of them are
        // the user's own. The index exists precisely so this never reads an
        // event body — the count is the operation every sync performs for
        // every room, and it used to read every body after the floor to
        // learn its sender (the M2 close-out benchmark's one loss).
        // Warm: a lookup, so it takes the registry *shared* and does not
        // stall any other request. This is the case every sync after the
        // first one hits, for every room, which is why it is worth
        // separating from the build below.
        let warm = self.with_room_read(room_id, |rooms, _| {
            let cache = rooms
                .unread_index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(cache
                .get(room_id)
                .map(|index| index.count_after(boundary, user_id)))
        })?;
        let notification_count = match warm {
            Some(count) => count,
            // Cold. The one remaining full walk: once per room per process,
            // and under the *exclusive* lock deliberately, so no append can
            // slip past unindexed while it runs.
            None => self.with_room(room_id, |rooms, log| {
                let mut cache = rooms
                    .unread_index
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !cache.contains_key(room_id) {
                    let mut index = UnreadIndex::default();
                    for entry in log.entries() {
                        if entry.state_key.is_some() {
                            continue;
                        }
                        let event = rooms.read_event(room_id, &entry.event_id)?;
                        index.push(entry.li.get(), event["sender"].as_str().unwrap_or(""));
                    }
                    cache.insert(room_id.to_owned(), index);
                }
                Ok(cache[room_id].count_after(boundary, user_id))
            })?,
        };

        Ok(Unread {
            notification_count,
            read_up_to: read_up_to.map(|receipt| receipt.event_id),
            boundary: Some(boundary),
        })
    }

    /// What `user_id`'s highlight tally in `room_id` has not scored yet:
    /// the count so far after `boundary`, and the bodies after the scored
    /// position that are not the reader's own. A tally counted from another
    /// boundary is stale, and the range starts over at `boundary`.
    ///
    /// Timeline entries only, as the notification count is; a purged body
    /// is nothing to score. The spine is read under the room's read lock and
    /// the bodies outside it, as `messages_visible` does. A room with
    /// nothing after the scored position reads no body at all, which is
    /// what keeps a sync flat across quiet rooms (`sync_cost.rs`).
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn unscored_highlights(
        &self,
        room_id: &str,
        user_id: &str,
        boundary: i64,
    ) -> Result<Unscored, RoomError> {
        let key = (room_id.to_owned(), user_id.to_owned());
        let tally = self
            .highlights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied()
            .filter(|tally| tally.boundary == boundary);
        let (count, from) = tally.map_or((0, boundary), |tally| (tally.count, tally.upto));
        let pending: Vec<(i64, String)> = self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries()
                .rev()
                .take_while(|entry| entry.li.get() > from)
                .filter(|entry| entry.state_key.is_none())
                .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                .collect())
        })?;
        let upto = pending.first().map_or(from, |(li, _)| *li);
        let watermark = self.purge_watermark(room_id)?;
        let mut events = Vec::with_capacity(pending.len());
        for (li, event_id) in pending.iter().rev() {
            match self.read_event(room_id, &EventId::new(event_id.as_str())) {
                Ok(json) => {
                    if json["sender"] != user_id {
                        events.push(json);
                    }
                }
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| *li < mark) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Unscored {
            count,
            events,
            upto,
        })
    }

    /// Remember that `user_id`'s highlights in `room_id` after `boundary`
    /// number `count`, scored up to `upto`.
    pub fn record_highlights(
        &self,
        room_id: &str,
        user_id: &str,
        boundary: i64,
        upto: i64,
        count: usize,
    ) {
        self.highlights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                (room_id.to_owned(), user_id.to_owned()),
                HighlightTally {
                    boundary,
                    upto,
                    count,
                },
            );
    }

    /// Drop every highlight tally of `user_id`: their rules changed, so
    /// what was scored under the old ones no longer says anything.
    pub fn forget_highlights(&self, user_id: &str) {
        self.highlights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(_, reader), _| reader != user_id);
    }

    /// One user's receipt of one type, if they have set it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the record cannot be read.
    pub fn receipt(
        &self,
        room_id: &str,
        user_id: &str,
        receipt_type: &str,
    ) -> Result<Option<Receipt>, RoomError> {
        let Some(raw) = spindle_store::ReadView::get(
            self.store.as_ref(),
            &receipt_key(room_id, user_id, receipt_type),
        )?
        else {
            return Ok(None);
        };
        Ok(ReceiptRecord::decode(&raw).map(|record| Receipt {
            event_id: record.event_id,
            li: record.li,
            ts: record.ts,
        }))
    }
}

/// Receipts live per room, per user, per type.
fn receipt_key(room_id: &str, user_id: &str, receipt_type: &str) -> Vec<u8> {
    let mut key = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Receipt, room_id);
    // Length-prefixed for the same reason room and user keys are: `@ab` must
    // not be read as `@a` followed by a type beginning `b`.
    let user = user_id.as_bytes();
    key.extend_from_slice(&u16::try_from(user.len()).unwrap_or(u16::MAX).to_be_bytes());
    key.extend_from_slice(user);
    key.extend_from_slice(receipt_type.as_bytes());
    key
}

struct ReceiptRecord {
    event_id: String,
    li: i64,
    ts: u64,
}

impl ReceiptRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.event_id.len());
        out.extend_from_slice(&self.li.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(self.event_id.as_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let li = i64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let ts = u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?);
        let event_id = String::from_utf8(bytes.get(16..)?.to_vec()).ok()?;
        Some(Self { event_id, li, ts })
    }
}
