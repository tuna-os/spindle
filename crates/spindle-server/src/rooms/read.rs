//! Who may read a room, and how much of it.
//!
//! The gate used to sit in `routes.rs` beside the handlers that called it,
//! which is why it could be forgotten: five handlers shipped that
//! authenticated a caller and then read a room without asking whether that
//! caller could see it (#258), and the semgrep rule in
//! `scripts/authorization-rule.py` exists because nothing in the type
//! system said they had to ask.
//!
//! So the gate lives here now, next to the reads it governs, and hands
//! back a [`RoomReader`] rather than a permission. A handler that wants
//! the room's state asks the reader for it; there is no unscoped spelling
//! of those reads left for it to reach (#311).

use serde_json::Value;

use super::{RoomError, Rooms};

/// How much of a room a caller may read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadScope {
    /// All of it: joined, or the room is world-readable.
    Whole,
    /// Up to and including this position: a former member of a `shared`
    /// room, reading what was said while they were there and before.
    UpTo(i64),
    /// Only these stretches, `(first, last)` inclusive: a former member of
    /// a `joined` or `invited` room, reading what was said while they were
    /// in it, one stint at a time (#268).
    Within(Vec<(i64, i64)>),
}

impl ReadScope {
    /// Whether position `li` is inside what the caller may read.
    #[must_use]
    pub fn admits(&self, li: i64) -> bool {
        match self {
            Self::Whole => true,
            Self::UpTo(bound) => li <= *bound,
            Self::Within(stints) => stints
                .iter()
                .any(|(first, last)| (*first..=*last).contains(&li)),
        }
    }

    /// The last position the caller may read, for the reads that answer
    /// with the room *as it stood* -- state and members -- rather than
    /// with a stretch of its timeline. `None` means the present.
    #[must_use]
    pub fn bound(&self) -> Option<i64> {
        match self {
            Self::Whole => None,
            Self::UpTo(bound) => Some(*bound),
            Self::Within(stints) => stints.last().map(|(_, last)| *last),
        }
    }
}

/// A room, and how much of it one caller may see.
///
/// Built only by [`Rooms::reader`], which runs the gate first, so holding
/// one is proof the gate ran. The reads on it answer for the scope it
/// carries rather than for the present: a former member asking for the
/// state gets the state as it stood when they were removed, and the
/// handler does not choose between the two spellings -- there is only
/// one, and it is this.
pub struct RoomReader<'a> {
    rooms: &'a Rooms,
    room_id: String,
    scope: ReadScope,
}

impl Rooms {
    /// The two ways in that never depend on when the caller asks: they are
    /// joined now, or the room is readable by anybody.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::Forbidden`] when neither holds, and a storage
    /// error if the membership index cannot be read. A room this server
    /// does not hold is refused the same way it is refused to a stranger:
    /// answering "no such room" to someone who may not see it is itself a
    /// disclosure.
    pub fn may_read(&self, user_id: &str, room_id: &str) -> Result<(), RoomError> {
        if self.is_joined(user_id, room_id)? {
            return Ok(());
        }
        if self
            .summary(room_id)
            .is_ok_and(|summary| summary.world_readable)
        {
            return Ok(());
        }
        Err(RoomError::Forbidden(format!(
            "{user_id} is not in {room_id}"
        )))
    }

    /// What `user_id` may read of `room_id`: everything, a bounded past,
    /// or nothing.
    ///
    /// [`Self::may_read`]'s two ways in, plus the third the spec has and
    /// #258 knowingly left out: **a former member reads up to their
    /// departure.** Under `shared` history visibility -- the default --
    /// someone who left, was kicked or was banned may still read what was
    /// said up to and including the event that removed them, and nothing
    /// after. The visibility that governs is the one in force *at* their
    /// departure, so a room that later tightened or relaxed it changes
    /// nothing for them.
    ///
    /// Under `joined` and `invited` the spec makes visibility a per-event
    /// question -- what the caller's membership was as of each event -- so
    /// a former member of such a room reads the stretches during which
    /// they were joined (or, under `invited`, invited or joined), one
    /// stint at a time, and nothing between or after them:
    /// [`ReadScope::Within`], from the membership-history index.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::Forbidden`] for a caller with no way in, and a
    /// storage error if the indexes cannot be read.
    pub fn read_scope(&self, user_id: &str, room_id: &str) -> Result<ReadScope, RoomError> {
        let refused = || RoomError::Forbidden(format!("{user_id} is not in {room_id}"));
        if self.may_read(user_id, room_id).is_ok() {
            return Ok(ReadScope::Whole);
        }
        // `departure` opens the room; a room this server does not hold is
        // the same refusal as one the caller may not see, for the reason
        // `may_read` gives.
        let Ok(Some(departure)) = self.departure(room_id, user_id) else {
            return Err(refused());
        };
        let visibility = self.history_visibility_at(room_id, departure)?;
        match visibility.as_str() {
            "shared" | "world_readable" => Ok(ReadScope::UpTo(departure)),
            "joined" | "invited" => {
                let stints =
                    self.membership_intervals(room_id, user_id, visibility == "invited")?;
                if stints.is_empty() {
                    return Err(refused());
                }
                Ok(ReadScope::Within(stints))
            }
            _ => Err(refused()),
        }
    }

    /// A handle on `room_id` for a scope already computed.
    ///
    /// For a caller reading many rooms at once -- search answers hits
    /// across every room they may see -- where running the gate once per
    /// room and carrying the answer is the whole point. The scope still
    /// has to have come from [`Self::read_scope`]; this only avoids
    /// asking twice.
    #[must_use]
    pub fn reader_with(&self, room_id: &str, scope: ReadScope) -> RoomReader<'_> {
        RoomReader {
            rooms: self,
            room_id: room_id.to_owned(),
            scope,
        }
    }

    /// One state event's content, read with no caller in mind.
    ///
    /// For the server's own decisions rather than for answering "show me
    /// this room": naming a room in a sync entry the caller is already
    /// entitled to, and reading the power levels the push rules ask
    /// about. A read that *is* answering a caller belongs on
    /// [`RoomReader`], which knows who is asking.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the event is not in
    /// its state.
    pub(crate) fn state_event_unscoped(
        &self,
        room_id: &str,
        event_type: &str,
        state_key: &str,
    ) -> Result<Value, RoomError> {
        self.state_event(room_id, event_type, state_key)
    }

    /// The room's current state, pre-serialized, with no caller in mind.
    ///
    /// Same rule as [`Self::state_event_unscoped`]: this renders the state
    /// block of a sync response for a member who is being sent their own
    /// rooms, not a room somebody asked to see.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its state cannot be
    /// read.
    pub(crate) fn state_serialized_unscoped(
        &self,
        room_id: &str,
    ) -> Result<std::sync::Arc<String>, RoomError> {
        self.state_serialized(room_id)
    }

    /// A handle on the part of `room_id` that `user_id` may read.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::read_scope`] refuses with: the caller gets
    /// a reader or a refusal, never an unscoped room.
    pub fn reader(&self, user_id: &str, room_id: &str) -> Result<RoomReader<'_>, RoomError> {
        Ok(RoomReader {
            rooms: self,
            room_id: room_id.to_owned(),
            scope: self.read_scope(user_id, room_id)?,
        })
    }
}

impl RoomReader<'_> {
    /// How much of the room this reader admits.
    #[must_use]
    pub fn scope(&self) -> &ReadScope {
        &self.scope
    }

    /// The room's state, already serialized, as this caller may see it.
    ///
    /// For a caller with the whole room this is the pre-serialized render
    /// kept per state root, so a hot room costs no reads, parses or
    /// serializing. For a former member it is the state at the position
    /// they were removed at, rendered here -- the cache only ever holds
    /// the present.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its state cannot be
    /// read.
    pub fn state_serialized(&self) -> Result<String, RoomError> {
        match self.scope.bound() {
            None => Ok(self
                .rooms
                .state_serialized(&self.room_id)?
                .as_str()
                .to_owned()),
            Some(bound) => {
                Ok(Value::Array(self.rooms.state_as_of(&self.room_id, bound)?).to_string())
            }
        }
    }

    /// One state event's content, as this caller may see it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the event is not in
    /// the state this caller may read.
    pub fn state_event(&self, event_type: &str, state_key: &str) -> Result<Value, RoomError> {
        match self.scope.bound() {
            None => self.rooms.state_event(&self.room_id, event_type, state_key),
            Some(bound) => {
                self.rooms
                    .state_event_as_of(&self.room_id, bound, event_type, state_key)
            }
        }
    }

    /// The room's `m.room.member` events, as this caller may see them.
    ///
    /// A former member sees the roster as it stood when they were removed,
    /// which is the same rule the state read follows and for the same
    /// reason: the members list is the room *as it stands*, so "as it
    /// stands" has to mean the last moment this caller was entitled to.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or its state cannot be
    /// read.
    pub fn members(&self) -> Result<Vec<Value>, RoomError> {
        match self.scope.bound() {
            None => self.rooms.state_where(&self.room_id, |key| {
                key.event_type().as_str() == "m.room.member"
            }),
            Some(bound) => Ok(self
                .rooms
                .state_as_of(&self.room_id, bound)?
                .into_iter()
                .filter(|event| event["type"] == "m.room.member")
                .collect()),
        }
    }
}
