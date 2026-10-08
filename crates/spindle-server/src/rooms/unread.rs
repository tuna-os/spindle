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
/// faster, and the one whose curve grew with room size. Updated on append,
/// queried by binary search.
///
/// **It covers a suffix of the room, not the room.** Every timeline entry
/// above [`Self::floor`] is indexed; nothing below it need be, because no
/// reader has asked about it. It is built from the head down to the lowest
/// boundary a reader has asked for, and extended further down only when a
/// reader asks about a boundary below that. It used to be built over the
/// whole room on first use, which read every body the room had ever held
/// -- a million point reads and JSON parses, under the room's exclusive
/// lock, for the first sync after a restart of an account in a room of a
/// million events, whose readers were a few events behind.
pub(super) struct UnreadIndex {
    /// Linear indices of every indexed timeline (non-state) entry, ascending.
    timeline: Vec<i64>,
    /// The same, per sender.
    by_sender: HashMap<String, Vec<i64>>,
    /// Everything above this position is indexed. Starts above every
    /// position, covering nothing.
    floor: i64,
}

impl Default for UnreadIndex {
    fn default() -> Self {
        Self {
            timeline: Vec::new(),
            by_sender: HashMap::new(),
            floor: i64::MAX,
        }
    }
}

impl UnreadIndex {
    pub(super) fn push(&mut self, li: i64, sender: &str) {
        // Appends arrive in li order above everything indexed, so pushing
        // keeps both vectors sorted. Backfill takes positions below the
        // whole room, which is below the floor of any index that could
        // have counted it: a reader asking about that range extends the
        // index down over it, and finds it there.
        self.timeline.push(li);
        self.by_sender
            .entry(sender.to_owned())
            .or_default()
            .push(li);
    }

    /// Whether a count after `boundary` can be answered from what is indexed.
    fn covers(&self, boundary: i64) -> bool {
        boundary >= self.floor
    }

    /// The position below which nothing is indexed yet.
    fn floor(&self) -> i64 {
        self.floor
    }

    /// Index the timeline entries in `(floor, self.floor]`, given as
    /// `(li, sender)` in ascending order. All of them sort below every
    /// position already indexed, so this is a prepend.
    fn extend_down(&mut self, floor: i64, below: Vec<(i64, String)>) {
        debug_assert!(floor < self.floor);
        let mut timeline = Vec::with_capacity(below.len() + self.timeline.len());
        let mut by_sender: HashMap<String, Vec<i64>> = HashMap::new();
        for (li, sender) in below {
            timeline.push(li);
            by_sender.entry(sender).or_default().push(li);
        }
        timeline.append(&mut self.timeline);
        for (sender, mut lis) in std::mem::take(&mut self.by_sender) {
            by_sender.entry(sender).or_default().append(&mut lis);
        }
        self.timeline = timeline;
        self.by_sender = by_sender;
        self.floor = floor;
    }

    /// Timeline events after `boundary` not sent by `user_id`. Only
    /// meaningful when the index [`covers`](Self::covers) `boundary`.
    fn count_after(&self, boundary: i64, user_id: &str) -> usize {
        let after = |lis: &[i64]| lis.len() - lis.partition_point(|&li| li <= boundary);
        let own = self.by_sender.get(user_id).map_or(0, |lis| after(lis));
        after(&self.timeline) - own
    }
}

/// How far one reader's unread events in one room have been scored
/// against their push rules.
///
/// The arithmetic index ([`UnreadIndex`]) says how many events sit after
/// the boundary; which of them *notify* or *highlight*, and which thread
/// each belongs to, is a push-rule question answered against the body.
/// Scoring every unread body on every sync would bring back the walk #81
/// removed, so the tally remembers the position it was scored to and only
/// what came after it is read again. It is keyed on the boundary it
/// counted from: a receipt that moves, or a rejoin, starts a fresh count
/// over the new unread range.
#[derive(Clone)]
pub(super) struct ScoreTally {
    boundary: i64,
    upto: i64,
    scored: Vec<Scored>,
}

/// One unread event, scored: whether the reader's rules notify or
/// highlight for it, and the thread it belongs to (`None` for the main
/// timeline). Kept per event rather than as counts so a receipt inside a
/// thread (MSC3771) can be answered without rescoring.
#[derive(Clone, Debug)]
pub struct Scored {
    pub li: i64,
    pub notifies: bool,
    pub highlights: bool,
    pub thread: Option<String>,
}

/// The unread events one reader's tally has not scored yet.
pub struct Unscored {
    /// Already scored after the boundary, oldest first.
    pub scored: Vec<Scored>,
    /// Bodies after the scored position, oldest first, none the reader's
    /// own, each with its position; the caller puts these to the reader's
    /// rules.
    pub events: Vec<(i64, Value)>,
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
        thread_id: Option<&str>,
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
            &receipt_key(room_id, user_id, receipt_type, thread_id),
            &ReceiptRecord {
                event_id: event_id.to_owned(),
                li,
                ts: now_ms(),
            }
            .encode(),
        )?;
        self.mark_receipt(room_id, user_id);
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
    /// This count is arithmetic: every timeline event after the boundary
    /// that is not the reader's own. It is the upper bound the badge starts
    /// from; which of those events notify under the reader's push rules is
    /// scored on top by the caller ([`Self::unscored`]), body by body, once.
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
                .filter(|index| index.covers(boundary))
                .map(|index| index.count_after(boundary, user_id)))
        })?;
        let notification_count = match warm {
            Some(count) => count,
            // Cold, or asked about a boundary below what is indexed: index
            // the range between, once. Under the room's *exclusive* lock
            // deliberately, so no append can slip past unindexed while it
            // runs -- but not under the index's own lock, which every
            // room's warm path takes and which must not wait on this
            // room's body reads.
            None => self.with_room(room_id, |rooms, log| {
                let floor = rooms
                    .unread_index
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(room_id)
                    .map_or(i64::MAX, UnreadIndex::floor);
                let mut below = Vec::new();
                if boundary < floor {
                    for entry in log.entries_in((
                        std::ops::Bound::Excluded(boundary),
                        std::ops::Bound::Included(floor),
                    )) {
                        if entry.state_key.is_some() {
                            continue;
                        }
                        below.push((entry.li.get(), rooms.read_sender(room_id, &entry.event_id)?));
                    }
                }
                let mut cache = rooms
                    .unread_index
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let index = cache.entry(room_id.to_owned()).or_default();
                // The room's exclusive lock has been held since `floor` was
                // read, so nothing has moved it.
                if boundary < index.floor() {
                    index.extend_down(boundary, below);
                }
                Ok(index.count_after(boundary, user_id))
            })?,
        };

        Ok(Unread {
            notification_count,
            read_up_to: read_up_to.map(|receipt| receipt.event_id),
            boundary: Some(boundary),
        })
    }

    /// What `user_id`'s tally in `room_id` has not scored yet: the events
    /// scored so far after `boundary`, and the bodies after the scored
    /// position that are not the reader's own. A tally counted from
    /// another boundary is stale, and the range starts over at `boundary`.
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
    pub fn unscored(
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
            .cloned()
            .filter(|tally| tally.boundary == boundary);
        let (scored, from) =
            tally.map_or((Vec::new(), boundary), |tally| (tally.scored, tally.upto));
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
                        events.push((*li, json));
                    }
                }
                Err(RoomError::MissingBody(_)) if watermark.is_some_and(|mark| *li < mark) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Unscored {
            scored,
            events,
            upto,
        })
    }

    /// Remember `user_id`'s scored events in `room_id` after `boundary`,
    /// scored up to `upto`.
    pub fn record_scores(
        &self,
        room_id: &str,
        user_id: &str,
        boundary: i64,
        upto: i64,
        scored: Vec<Scored>,
    ) {
        self.highlights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                (room_id.to_owned(), user_id.to_owned()),
                ScoreTally {
                    boundary,
                    upto,
                    scored,
                },
            );
    }

    /// Drop every tally of `user_id`: their rules changed, so what was
    /// scored under the old ones no longer says anything.
    pub fn forget_scores(&self, user_id: &str) {
        self.highlights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(_, reader), _| reader != user_id);
    }

    /// Where `user_id` has read up to inside each thread of `room_id`
    /// (MSC3771): thread root (or `main`) to the position of the later of
    /// their public and private receipt there. Unthreaded receipts are
    /// [`Self::receipt`]'s business and are not in this map.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the records cannot be read.
    pub fn thread_receipts(
        &self,
        room_id: &str,
        user_id: &str,
    ) -> Result<HashMap<String, i64>, RoomError> {
        let prefix = receipt_key(room_id, user_id, "", None);
        let mut floors = HashMap::new();
        for (key, value) in spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Ok(tail) = std::str::from_utf8(&key[prefix.len()..]) else {
                continue;
            };
            let Some((receipt_type, thread)) = tail.split_once('\0') else {
                continue;
            };
            if receipt_type != "m.read" && receipt_type != "m.read.private" {
                continue;
            }
            if let Some(record) = ReceiptRecord::decode(&value) {
                let floor = floors.entry(thread.to_owned()).or_insert(record.li);
                *floor = (*floor).max(record.li);
            }
        }
        Ok(floors)
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
            &receipt_key(room_id, user_id, receipt_type, None),
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

impl Rooms {
    /// Every receipt in a room, as `(user_id, receipt_type, event_id, ts,
    /// thread_id)`.
    ///
    /// What an `m.receipt` ephemeral event is built from. The private
    /// kind (`m.read.private`) is the reader's own business: the caller
    /// keeps those for their owner and hands the rest to everyone. A
    /// threaded receipt (MSC3771) names its thread; an unthreaded one has
    /// `None`.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the records cannot be read.
    #[allow(clippy::type_complexity, reason = "one row per receipt")]
    pub fn room_receipts(
        &self,
        room_id: &str,
    ) -> Result<Vec<(String, String, String, u64, Option<String>)>, RoomError> {
        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Receipt, room_id);
        let mut receipts = Vec::new();
        for (key, value) in spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let rest = &key[prefix.len()..];
            // The key's tail is what `receipt_key` wrote: a length-prefixed
            // user, then the type, then a NUL and the thread when threaded.
            let Some((len, rest)) = rest.split_first_chunk::<2>() else {
                continue;
            };
            let len = usize::from(u16::from_be_bytes(*len));
            if rest.len() < len {
                continue;
            }
            let (user, tail) = rest.split_at(len);
            let (Ok(user), Ok(tail)) = (std::str::from_utf8(user), std::str::from_utf8(tail))
            else {
                continue;
            };
            let (receipt_type, thread) = match tail.split_once('\0') {
                Some((receipt_type, thread)) => (receipt_type, Some(thread.to_owned())),
                None => (tail, None),
            };
            if let Some(record) = ReceiptRecord::decode(&value) {
                receipts.push((
                    user.to_owned(),
                    receipt_type.to_owned(),
                    record.event_id,
                    record.ts,
                    thread,
                ));
            }
        }
        Ok(receipts)
    }
}

/// Receipts live per room, per user, per type, and per thread when
/// threaded (MSC3771): the thread follows the type after a NUL, which no
/// type contains, so the unthreaded key is what it always was.
fn receipt_key(
    room_id: &str,
    user_id: &str,
    receipt_type: &str,
    thread_id: Option<&str>,
) -> Vec<u8> {
    let mut key = spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Receipt, room_id);
    // Length-prefixed for the same reason room and user keys are: `@ab` must
    // not be read as `@a` followed by a type beginning `b`.
    let user = user_id.as_bytes();
    key.extend_from_slice(&u16::try_from(user.len()).unwrap_or(u16::MAX).to_be_bytes());
    key.extend_from_slice(user);
    key.extend_from_slice(receipt_type.as_bytes());
    if let Some(thread_id) = thread_id {
        key.push(0);
        key.extend_from_slice(thread_id.as_bytes());
    }
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

#[cfg(test)]
mod tests {
    use super::UnreadIndex;

    /// An index built from the head down in steps, and appended to, answers
    /// every boundary it covers exactly as a count over the whole timeline.
    #[test]
    fn a_suffix_index_extended_downwards_counts_as_a_whole_one() {
        let senders = ["@a:t", "@b:t", "@c:t"];
        // Backfilled history below zero, live history above, a state event
        // (absent from the timeline) every seventh position.
        let mut timeline: Vec<(i64, &str)> = (-12_i64..=50)
            .filter(|li| li.rem_euclid(7) != 3)
            .map(|li| (li, senders[usize::try_from(li.rem_euclid(3)).unwrap()]))
            .collect();
        let naive = |timeline: &[(i64, &str)], boundary: i64, user: &str| {
            timeline
                .iter()
                .filter(|(li, sender)| *li > boundary && *sender != user)
                .count()
        };
        let mut index = UnreadIndex::default();
        assert!(!index.covers(50), "a new index covers nothing");
        for floor in [44, 43, 20, 0, -13] {
            let below: Vec<(i64, String)> = timeline
                .iter()
                .filter(|(li, _)| *li > floor && *li <= index.floor())
                .map(|(li, sender)| (*li, (*sender).to_owned()))
                .collect();
            index.extend_down(floor, below);
            assert!(index.covers(floor) && !index.covers(floor - 1));
            for boundary in floor..=55 {
                for user in ["@a:t", "@b:t", "@c:t", "@nobody:t"] {
                    assert_eq!(
                        index.count_after(boundary, user),
                        naive(&timeline, boundary, user),
                        "floor {floor}, boundary {boundary}, {user}"
                    );
                }
            }
        }
        for (li, sender) in [(51, "@a:t"), (52, "@b:t"), (54, "@a:t")] {
            index.push(li, sender);
            timeline.push((li, sender));
        }
        for boundary in -13..=56 {
            for user in ["@a:t", "@b:t", "@c:t"] {
                assert_eq!(
                    index.count_after(boundary, user),
                    naive(&timeline, boundary, user)
                );
            }
        }
    }
}
