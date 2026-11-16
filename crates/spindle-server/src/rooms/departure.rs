//! The rooms a user is out of, as MSC4186 sync lists them.
//!
//! MSC4186's room list holds a room the user was kicked or banned from,
//! and a room they left themselves only on the connection that already had
//! it, once, so the client learns of the leave. Both need to know how the
//! user came to be out: by their own hand or by somebody else's, and
//! whether they were ever in. That is the departure's sender and the
//! user's membership history, which a room left long ago would otherwise
//! be loaded from the store to answer on every request.
//!
//! A child of `rooms`, as `unread.rs` is: a file split of one `impl Rooms`
//! block, reading its private helpers.

use serde_json::Value;
use spindle_core::{EventId, LinearIndex};
use spindle_store::StoreError;

use super::{BAN, JOIN_STR, LEAVE, ReadScope, RoomError, Rooms, extremities};

/// How a user came to be out of a room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The position of the member event that put them out.
    pub li: i64,
    /// Its timestamp. MSC4186 dates a room the user is not in by the
    /// membership change, so this is the room's place in the list and its
    /// `bump_stamp`.
    pub ts: i64,
    /// They left themselves: a leave, a refused invite or a withdrawn
    /// knock. Not a kick, and not a ban.
    pub by_self: bool,
    /// They were joined to the room at some point.
    pub was_joined: bool,
}

impl Departure {
    /// Whether the room stays in the user's list whatever the connection
    /// holds: they were kicked or banned from a room they had been in.
    /// MSC4186 keeps such a room, because the user may not have seen it
    /// happen, and leaves out a ban from a room they were never in.
    #[must_use]
    pub fn listed_for_good(&self) -> bool {
        !self.by_self && self.was_joined
    }
}

/// One window of a room's timeline as a former member may see it, oldest
/// first: the events, whether older ones were left out, and the position
/// of the oldest one kept.
pub type DepartedWindow = (Vec<Value>, bool, Option<i64>);

impl Rooms {
    /// The rooms `user_id` left or was banned from, from their membership
    /// index.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn departed(&self, user_id: &str) -> Result<Vec<String>, RoomError> {
        Ok(self.memberships(user_id)?.departed)
    }

    /// How `user_id` came to be out of `room_id`, or `None` if they are not
    /// out of it, or the room has no log here to say (an invite from
    /// another server refused without joining).
    ///
    /// Read from the membership-history index and the departure's own
    /// event, with no room load, and kept until the user's membership in
    /// the room changes: sliding sync asks it for every room the user has
    /// left on every request.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index or the event cannot be read.
    pub fn departure_of(
        &self,
        user_id: &str,
        room_id: &str,
    ) -> Result<Option<Departure>, RoomError> {
        let key = (user_id.to_owned(), room_id.to_owned());
        if let Some(known) = self
            .departures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
        {
            return Ok(known.clone());
        }
        let found = self.read_departure(user_id, room_id)?;
        self.departures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, found.clone());
        Ok(found)
    }

    fn read_departure(&self, user_id: &str, room_id: &str) -> Result<Option<Departure>, RoomError> {
        let mut rows = self.member_history(room_id, user_id)?;
        if rows.is_empty() {
            // A room older than the history index: fill it once, by the
            // walk `membership_intervals` does for the same reason.
            match self.membership_intervals(room_id, user_id, false) {
                Ok(_) => rows = self.member_history(room_id, user_id)?,
                Err(RoomError::UnknownRoom(_)) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        let Some((li, membership)) = rows.last() else {
            return Ok(None);
        };
        if membership.as_bytes() != LEAVE && membership.as_bytes() != BAN {
            return Ok(None);
        }
        let Some(event_id) = self.stored_event_id(room_id, *li)? else {
            return Ok(None);
        };
        let event = match self.read_event(room_id, &EventId::new(event_id.as_str())) {
            Ok(event) => event,
            Err(RoomError::MissingBody(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(Departure {
            li: *li,
            ts: event["origin_server_ts"].as_i64().unwrap_or(0),
            by_self: event["sender"].as_str() == Some(user_id),
            was_joined: rows.iter().any(|(_, membership)| membership == JOIN_STR),
        }))
    }

    /// The ID of the event at `li` in a room's stored log, read without
    /// loading the room.
    fn stored_event_id(&self, room_id: &str, li: i64) -> Result<Option<String>, RoomError> {
        let key = spindle_core::keys::room_li(
            spindle_core::keys::Keyspace::Log,
            room_id,
            LinearIndex::from_raw(li),
        );
        let Some(value) = spindle_store::ReadView::get(self.store.as_ref(), &key)? else {
            return Ok(None);
        };
        let record = spindle_store::codec::EntryRecord::decode(&value).map_err(StoreError::from)?;
        Ok(Some(record.event_id))
    }

    /// Forget what [`Self::departure_of`] holds for `user_id` in `room_id`:
    /// their membership there just changed.
    pub(super) fn forget_departure(&self, user_id: &str, room_id: &str) {
        self.departures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(user_id.to_owned(), room_id.to_owned()));
    }

    /// Whether the room's event at `li` entered the stream in
    /// `(since, until]`: whether a connection current to `since` has yet to
    /// be told of it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the index cannot be read.
    pub fn in_stream_range(
        &self,
        room_id: &str,
        li: i64,
        since: u64,
        until: u64,
    ) -> Result<bool, RoomError> {
        Ok(self.room_slice(room_id, since, until)?.contains(&li))
    }

    /// The timeline of a room `user_id` is out of, as sliding sync sends
    /// it: the newest `limit` events up to and including `departure`, that
    /// they may see. `since` narrows it to the events after a stream
    /// position, for a connection that already holds the room; without it,
    /// the window reaches back from the departure as far as `limit` goes.
    ///
    /// Nothing after the departure: leaving is what stops a member being
    /// told what the room says, and the room goes on without them. What
    /// they may see before it is their read scope, as for `/messages`; one
    /// who was never joined (a refused invite) sees only the departure.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or an event cannot be read.
    pub fn departed_window(
        &self,
        user_id: &str,
        room_id: &str,
        departure: &Departure,
        since: Option<u64>,
        until: u64,
        limit: usize,
    ) -> Result<DepartedWindow, RoomError> {
        let scope = self
            .leave_read_scope(user_id, room_id)?
            .unwrap_or_else(|| ReadScope::Within(vec![(departure.li, departure.li)]));
        let readable = |li: i64| li <= departure.li && scope.admits(li);
        // Newest first.
        let positions: Vec<(i64, String)> = match since {
            Some(since) => {
                let slice = self.room_slice(room_id, since, until)?;
                self.with_room_read(room_id, |_, log| {
                    Ok(slice
                        .iter()
                        .rev()
                        .copied()
                        .filter(|li| readable(*li))
                        .filter_map(|li| {
                            log.entry_at(li)
                                .map(|entry| (li, entry.event_id.as_str().to_owned()))
                        })
                        .collect())
                })?
            }
            None => self.with_room_read(room_id, |_, log| {
                Ok(log
                    .entries()
                    .rev()
                    .skip_while(|entry| entry.li.get() > departure.li)
                    .filter(|entry| readable(entry.li.get()))
                    // Enough to fill the window past the dummy events it
                    // leaves out, and one more to say it was limited.
                    .take(limit + super::TIMELINE_DUMMY_SLACK + 1)
                    .map(|entry| (entry.li.get(), entry.event_id.as_str().to_owned()))
                    .collect())
            })?,
        };
        let mut kept = Vec::new();
        let mut limited = false;
        let mut first = None;
        for (li, event_id) in positions {
            let event = match self.event(room_id, &event_id) {
                Ok(event) => event,
                // Rejected or soft-failed: as absent here as anywhere.
                Err(RoomError::MissingBody(_)) => continue,
                Err(error) => return Err(error),
            };
            if extremities::is_dummy_event(&event) {
                continue;
            }
            if kept.len() == limit {
                limited = true;
                break;
            }
            first = Some(li);
            kept.push(event);
        }
        kept.reverse();
        Ok((kept, limited, first))
    }

    /// The state `user_id` may see of a room they are out of: as it stood
    /// at their departure, or, for one who was never joined, the departure
    /// alone.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its state cannot be read.
    pub fn departed_state(
        &self,
        user_id: &str,
        room_id: &str,
        departure: &Departure,
    ) -> Result<Vec<Value>, RoomError> {
        match self.leave_read_scope(user_id, room_id)? {
            Some(scope) => {
                let bound = scope
                    .bound()
                    .map_or(departure.li, |bound| bound.min(departure.li));
                self.state_as_of(room_id, bound)
            }
            None => Ok(self
                .membership_event(room_id, user_id)?
                .map(|(event, _)| vec![event])
                .unwrap_or_default()),
        }
    }
}
