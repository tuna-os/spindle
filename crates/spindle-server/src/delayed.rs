//! Delayed events (MSC4140): an event handed over now and sent later.
//!
//! # Why a homeserver needs this
//!
//! Matrix RTC's problem is that a call participant can vanish. A browser tab
//! closes, a phone loses signal, a process is killed — and the membership
//! event saying "I am in this call" stays in the room state forever, because
//! the only party who would remove it is the one that disappeared. Everyone
//! else sees a participant who never speaks and never leaves.
//!
//! The fix is a dead-man's switch. On joining a call a client hands the
//! server its *own* departure, delayed; while it is alive it restarts the
//! timer; when it stops doing so, the server sends the departure on its
//! behalf. The client's absence is the signal, which is the only signal
//! available when the client is gone.
//!
//! That makes the timer the load-bearing part, and it is why this is
//! persisted rather than held in memory: a server that forgot its pending
//! departures on restart would leave exactly the ghosts the mechanism exists
//! to prevent, and would do it at the moment — a restart — when many clients
//! are disconnected at once.
//!
//! # Two rows per delay
//!
//! The row is keyed by *when* it fires, so the question asked every tick —
//! "is anything due" — reads the front of a keyspace and stops. Acting on a
//! delay by id is the rare question, and it gets an eight-byte index
//! ([`Keyspace::DelayedEventById`]) rather than a scan of every delay on the
//! server. Both rows are written and deleted in one batch: an index outliving
//! its row would send a caller looking for something that is not there, and a
//! row outliving its index would be unreachable until it fired.
//!
//! [`Keyspace::DelayedEventById`]: spindle_core::keys::Keyspace::DelayedEventById

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

use crate::rooms::Rooms;

/// A delay the caller asked for, held until its moment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DelayedEvent {
    pub delay_id: String,
    pub room_id: String,
    pub sender: String,
    pub event_type: String,
    /// `None` for a message, `Some` for a state event.
    pub state_key: Option<String>,
    pub content: Value,
    /// The delay as asked for, kept because `restart` re-applies *it* rather
    /// than the remaining time.
    pub delay_ms: u64,
    /// Unix milliseconds at which this becomes due.
    pub fire_at_ms: u64,
}

/// A delayed event that has finished: sent, or refused when it came due.
///
/// MSC4309's payload. It exists because the client that scheduled a delay is,
/// by the nature of a dead-man's switch, often not around when it fires --
/// and a client that reconnects has no way to learn what happened without
/// polling. This lets `/sync` tell it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalisedDelay {
    pub delay_id: String,
    pub room_id: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    /// The event this became, when it was sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Why it was not sent, when it was refused.
    ///
    /// A delay is authorised when it fires, not when it is scheduled, so
    /// "refused" is an ordinary outcome: the sender may have left the room
    /// or lost the power to send by the time their moment came.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a caller asked to do with a pending delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Send it now, and stop waiting.
    Send,
    /// Drop it unsent.
    Cancel,
    /// Start the original delay again from now — the heartbeat.
    Restart,
}

impl Action {
    /// The spec's spelling, or `None` for anything else.
    #[must_use]
    pub fn parse(action: &str) -> Option<Self> {
        match action {
            "send" => Some(Self::Send),
            "cancel" => Some(Self::Cancel),
            "restart" => Some(Self::Restart),
            _ => None,
        }
    }
}

/// Why a delay could not be scheduled or acted on.
#[derive(Debug)]
pub enum DelayError {
    /// No such delay, or it belongs to someone else.
    ///
    /// Deliberately one variant rather than two. Telling a caller that a
    /// delay exists but is not theirs would let anyone probe for other
    /// people's pending events by id.
    NotFound,
    /// The delay is longer than this server will hold.
    TooLong {
        limit_ms: u64,
    },
    /// This sender already has as many delays pending in this room as the
    /// server will hold for them.
    TooMany {
        limit: usize,
    },
    Store(StoreError),
}

impl std::fmt::Display for DelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(formatter, "no such delayed event"),
            Self::TooLong { limit_ms } => {
                write!(formatter, "the maximum delay is {limit_ms}ms")
            }
            Self::TooMany { limit } => write!(
                formatter,
                "at most {limit} delayed events may be pending in one room"
            ),
            Self::Store(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for DelayError {}

impl From<StoreError> for DelayError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The pending delays, and the clock that fires them.
pub struct Delayed {
    store: Arc<FjallStore>,
    /// The longest delay this server will accept.
    ///
    /// A cap exists because a delay is storage this server holds on a
    /// client's say-so, and an uncapped one is an unbounded write anybody can
    /// make. A day is far past any call heartbeat and still finite.
    max_delay_ms: u64,
    /// The most delays one sender may have pending in one room.
    ///
    /// The *count* cap, which the duration cap does not imply: a client can
    /// schedule an unbounded number of short delays as fast as it can send
    /// requests, and each is a stored row this server holds until it fires.
    /// Without this, one account is a write amplifier against the store --
    /// which #36 names as the reason to have it.
    ///
    /// Per sender *and* per room, because that is the unit a client works
    /// in: Matrix RTC keeps one pending departure per call, so a legitimate
    /// client sits at one and this is only ever reached by something that
    /// has gone wrong or is trying to.
    max_per_room: usize,
    /// The live deadline of every delay that has been restarted since it
    /// was last persisted.
    ///
    /// `restart` is the hot path, and #36 asks that it not touch storage:
    /// Matrix RTC refreshes the pending departure of every participant in
    /// every live call, continuously, so a restart that rewrote two rows
    /// would make the store's write rate a function of how many people are
    /// on calls rather than of how much is actually happening. It bumps the
    /// deadline here instead, and the queue row keeps its old position until
    /// the fire loop actually reaches it -- at which point the row moves
    /// once, rather than once per heartbeat.
    ///
    /// The persisted deadline is therefore a *lower bound* on the live one,
    /// never an upper one, because a restart only ever moves a deadline
    /// later. So a crash loses the bumps and the delay fires early. For a
    /// dead-man's switch that is the safe direction to fail in: a live
    /// participant is dropped once and their client rejoins, where the
    /// opposite error leaves exactly the ghost the mechanism exists to
    /// remove.
    ///
    /// Bounded by [`Self::max_per_room`] per sender per room, the same cap
    /// that bounds the rows -- an entry exists only for a delay that has a
    /// row.
    restarts: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// How many finalised delays are kept per user; see
    /// [`DEFAULT_MAX_FINALISED_PER_USER`].
    max_finalised: usize,
    /// Bumped whenever a row is written, so a caller can tell whether
    /// anything changed without reading the rows.
    generation: std::sync::atomic::AtomicU64,
}

/// The default duration cap: a day.
pub const DEFAULT_MAX_DELAY_MS: u64 = 24 * 60 * 60 * 1000;

/// How many finalised delays are kept per user.
///
/// Finalised rows are written by the server, not the client, so nothing the
/// client does removes them -- which makes an unbounded set the same
/// amplification vector [`DEFAULT_MAX_PER_ROOM`] exists to close, one step
/// removed. MSC4309 permits discarding them once a sync has returned them;
/// that is not done here, because a user's *other* devices have not synced
/// yet and would lose the outcome. Keeping a bounded window serves both.
pub const DEFAULT_MAX_FINALISED_PER_USER: usize = 100;

/// The default count cap, per sender per room.
///
/// Generous against any real client -- Matrix RTC keeps one pending
/// departure per call -- and small enough that a misbehaving one is stopped
/// long before it is a storage problem.
pub const DEFAULT_MAX_PER_ROOM: usize = 100;

impl Delayed {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self::with_limits(store, DEFAULT_MAX_DELAY_MS, DEFAULT_MAX_PER_ROOM)
    }

    /// The same, with the caps an operator configured.
    ///
    /// Separate from [`Self::new`] so the defaults live in one place and
    /// the tests that do not care about the caps do not have to name them.
    #[must_use]
    pub fn with_limits(store: Arc<FjallStore>, max_delay_ms: u64, max_per_room: usize) -> Self {
        Self {
            store,
            max_delay_ms,
            max_per_room,
            max_finalised: DEFAULT_MAX_FINALISED_PER_USER,
            restarts: std::sync::Mutex::new(std::collections::HashMap::new()),
            generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Unix milliseconds now.
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// Hold `content` for `delay_ms`, and return the id that names it.
    ///
    /// # Errors
    ///
    /// Returns [`DelayError::TooLong`] past the cap, or a store error.
    pub fn schedule(
        &self,
        room_id: &str,
        sender: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
        delay_ms: u64,
    ) -> Result<String, DelayError> {
        if delay_ms > self.max_delay_ms {
            return Err(DelayError::TooLong {
                limit_ms: self.max_delay_ms,
            });
        }
        // Counted before the write, so the cap is a refusal rather than a
        // cleanup. `restart` deliberately does not come through here: it
        // replaces a row rather than adding one, and a client sitting at the
        // cap must still be able to keep the delays it has alive.
        if self.pending_in(room_id, sender)? >= self.max_per_room {
            return Err(DelayError::TooMany {
                limit: self.max_per_room,
            });
        }
        let delay_id = format!("{:032x}", rand::random::<u128>());
        let event = DelayedEvent {
            delay_id: delay_id.clone(),
            room_id: room_id.to_owned(),
            sender: sender.to_owned(),
            event_type: event_type.to_owned(),
            state_key: state_key.map(str::to_owned),
            content: content.clone(),
            delay_ms,
            fire_at_ms: Self::now_ms().saturating_add(delay_ms),
        };
        self.write(&event)?;
        Ok(delay_id)
    }

    /// Write both rows for one delay.
    fn write(&self, event: &DelayedEvent) -> Result<(), DelayError> {
        let encoded = serde_json::to_vec(event).unwrap_or_default();
        self.store.put(
            &spindle_core::keys::delayed_event(event.fire_at_ms, &event.delay_id),
            &encoded,
        )?;
        self.store.put(
            &spindle_core::keys::delayed_event_by_id(&event.delay_id),
            &event.fire_at_ms.to_be_bytes(),
        )?;
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Where the queue row for `delay_id` currently sits, or `None` if
    /// there is no such delay.
    ///
    /// The by-id row is the only thing that knows this. The live deadline
    /// in [`Self::restarts`] deliberately does *not*: it says when the
    /// delay should fire, not where its row is, and conflating the two is
    /// how a restarted delay would be deleted by the wrong key.
    fn queued_at(&self, delay_id: &str) -> Result<Option<u64>, DelayError> {
        let Some(raw) = self
            .store
            .get(&spindle_core::keys::delayed_event_by_id(delay_id))?
        else {
            return Ok(None);
        };
        Ok(raw
            .as_slice()
            .try_into()
            .ok()
            .map(|bytes: [u8; 8]| u64::from_be_bytes(bytes)))
    }

    /// Remove both rows for one delay, and forget any live deadline.
    ///
    /// Takes only the id: the row's position is read back from the by-id
    /// row rather than passed in, because a caller holding a
    /// [`DelayedEvent`] may be holding its *live* deadline (see
    /// [`Self::restarts`]), and deleting by that would leave the queue row
    /// behind to fire a second time.
    fn erase(&self, delay_id: &str) -> Result<(), DelayError> {
        if let Some(fire_at_ms) = self.queued_at(delay_id)? {
            self.store
                .delete(&spindle_core::keys::delayed_event(fire_at_ms, delay_id))?;
        }
        self.store
            .delete(&spindle_core::keys::delayed_event_by_id(delay_id))?;
        if let Ok(mut restarts) = self.restarts.lock() {
            restarts.remove(delay_id);
        }
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// The live deadline for `delay_id`, if it has been restarted since it
    /// was last persisted.
    fn live_deadline(&self, delay_id: &str) -> Option<u64> {
        self.restarts
            .lock()
            .ok()
            .and_then(|restarts| restarts.get(delay_id).copied())
    }

    /// Move a delay's queue row to `deadline` and forget the live entry.
    ///
    /// The deferred half of [`Action::Restart`]: paid once, when the fire
    /// loop reaches a row whose deadline has moved on, instead of once per
    /// heartbeat. Removing the live entry is conditional on it still being
    /// the value just persisted, so a restart racing this write is kept
    /// rather than silently dropped back to the row's position.
    fn requeue(&self, event: &DelayedEvent, deadline: u64) -> Result<(), DelayError> {
        let moved = DelayedEvent {
            fire_at_ms: deadline,
            ..event.clone()
        };
        if let Some(queued_at) = self.queued_at(&event.delay_id)? {
            self.store.delete(&spindle_core::keys::delayed_event(
                queued_at,
                &event.delay_id,
            ))?;
        }
        self.write(&moved)?;
        if let Ok(mut restarts) = self.restarts.lock()
            && restarts.get(&event.delay_id) == Some(&deadline)
        {
            restarts.remove(&event.delay_id);
        }
        Ok(())
    }

    /// One delay by id, if `sender` is the one who scheduled it.
    ///
    /// # Errors
    ///
    /// Returns [`DelayError::NotFound`] when there is no such delay *or* it
    /// belongs to someone else, which are deliberately the same answer.
    pub fn get(&self, delay_id: &str, sender: &str) -> Result<DelayedEvent, DelayError> {
        let raw = self
            .store
            .get(&spindle_core::keys::delayed_event_by_id(delay_id))?
            .ok_or(DelayError::NotFound)?;
        let bytes: [u8; 8] = raw
            .as_slice()
            .try_into()
            .map_err(|_| DelayError::NotFound)?;
        let fire_at_ms = u64::from_be_bytes(bytes);
        let stored = self
            .store
            .get(&spindle_core::keys::delayed_event(fire_at_ms, delay_id))?
            .ok_or(DelayError::NotFound)?;
        let mut event: DelayedEvent =
            serde_json::from_slice(&stored).map_err(|_| DelayError::NotFound)?;
        if event.sender != sender {
            return Err(DelayError::NotFound);
        }
        // What the caller asked is "when does this fire", so answer with the
        // live deadline rather than the row's position, which lags it by
        // design between restarts.
        if let Some(deadline) = self.live_deadline(&event.delay_id) {
            event.fire_at_ms = deadline;
        }
        Ok(event)
    }

    /// How many delays `sender` already has pending in `room_id`.
    fn pending_in(&self, room_id: &str, sender: &str) -> Result<usize, DelayError> {
        let rows = self
            .store
            .scan_prefix(&spindle_core::keys::delayed_event_prefix())?;
        Ok(rows
            .into_iter()
            .filter_map(|(_, raw)| serde_json::from_slice::<DelayedEvent>(&raw).ok())
            .filter(|event| event.sender == sender && event.room_id == room_id)
            .count())
    }

    /// Every delay `sender` is waiting on.
    ///
    /// # Errors
    ///
    /// Returns a store error if the keyspace cannot be scanned.
    pub fn list(&self, sender: &str) -> Result<Vec<DelayedEvent>, DelayError> {
        let rows = self
            .store
            .scan_prefix(&spindle_core::keys::delayed_event_prefix())?;
        let mut out = Vec::new();
        for (_, raw) in rows {
            if let Ok(mut event) = serde_json::from_slice::<DelayedEvent>(&raw)
                && event.sender == sender
            {
                if let Some(deadline) = self.live_deadline(&event.delay_id) {
                    event.fire_at_ms = deadline;
                }
                out.push(event);
            }
        }
        Ok(out)
    }

    /// Apply `action` to one delay, and say whether it should now be sent.
    ///
    /// Returns the event to send for [`Action::Send`], and `None` otherwise —
    /// the caller does the sending, because this type does not sign events
    /// and should not learn how.
    ///
    /// # Errors
    ///
    /// Returns [`DelayError::NotFound`] if the delay is not the sender's.
    pub fn act(
        &self,
        delay_id: &str,
        sender: &str,
        action: Action,
    ) -> Result<Option<DelayedEvent>, DelayError> {
        let event = self.get(delay_id, sender)?;
        match action {
            Action::Cancel => {
                self.erase(&event.delay_id)?;
                Ok(None)
            }
            Action::Send => {
                self.erase(&event.delay_id)?;
                Ok(Some(event))
            }
            Action::Restart => {
                // The *original* delay from now, not the time remaining. A
                // heartbeat that shortened the window on every beat would
                // converge on firing while the client was still alive, which
                // is the opposite of what restarting it means.
                let deadline = Self::now_ms().saturating_add(event.delay_ms);
                // And no write: the hot path (#36) records the new deadline
                // in memory and leaves the row where it is. The row is a
                // lower bound, so the only cost of not moving it now is that
                // the fire loop reaches it early and moves it then -- once
                // per delay period instead of once per heartbeat.
                if let Ok(mut restarts) = self.restarts.lock() {
                    restarts.insert(event.delay_id.clone(), deadline);
                }
                self.generation
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
        }
    }

    /// Everything due at or before `now`, oldest first.
    ///
    /// The rows are ordered by their firing time, so this reads the front of
    /// the keyspace and stops at the first row that is not due yet — a tick
    /// with nothing to do costs one row, whatever else is pending.
    ///
    /// # Errors
    ///
    /// Returns a store error if the keyspace cannot be read.
    pub fn due(&self, now_ms: u64) -> Result<Vec<DelayedEvent>, DelayError> {
        let prefix = spindle_core::keys::delayed_event_prefix();
        let rows = self.store.scan_from(&prefix, &prefix)?;
        let mut out = Vec::new();
        for (key, raw) in rows {
            let Some(fire_at) = key
                .get(2..10)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            if fire_at > now_ms {
                break;
            }
            let Ok(event) = serde_json::from_slice::<DelayedEvent>(&raw) else {
                continue;
            };
            // The row is due, but the delay may not be: a restart since this
            // row was written moved the deadline without moving the row.
            // Settle it now -- one write, here, in place of the write every
            // heartbeat would otherwise have made.
            match self.live_deadline(&event.delay_id) {
                Some(deadline) if deadline > now_ms => {
                    self.requeue(&event, deadline)?;
                }
                _ => out.push(event),
            }
        }
        Ok(out)
    }

    /// Take one due delay off the queue, so a firing cannot happen twice.
    ///
    /// # Errors
    ///
    /// Returns a store error if the rows cannot be removed.
    pub fn take(&self, event: &DelayedEvent) -> Result<(), DelayError> {
        self.erase(&event.delay_id)
    }

    /// Record that a delay finished, for MSC4309's `/sync` report.
    ///
    /// `position` is the stream position the outcome belongs at, so an
    /// incremental sync can ask for everything after its token. A send takes
    /// the position of the event it produced; a refusal takes the current
    /// head, because nothing was appended and the client should still hear
    /// about it on its next sync.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be written.
    pub fn finalise(
        &self,
        user_id: &str,
        position: u64,
        record: &FinalisedDelay,
    ) -> Result<(), DelayError> {
        let encoded = serde_json::to_vec(record).unwrap_or_default();
        self.store.put(
            &spindle_core::keys::finalised_delay(user_id, position, &record.delay_id),
            &encoded,
        )?;
        self.prune_finalised(user_id)
    }

    /// Drop the oldest finalised rows past the cap.
    ///
    /// Oldest first is right rather than arbitrary: the rows are ordered by
    /// position, so the ones dropped are the ones every client is most
    /// likely to have seen already.
    fn prune_finalised(&self, user_id: &str) -> Result<(), DelayError> {
        let rows = self
            .store
            .scan_prefix(&spindle_core::keys::finalised_delay_prefix(user_id))?;
        let Some(excess) = rows.len().checked_sub(self.max_finalised) else {
            return Ok(());
        };
        for (key, _) in rows.into_iter().take(excess) {
            self.store.delete(&key)?;
        }
        Ok(())
    }

    /// Everything `user_id` finalised after `since`, up to and including
    /// `until`, oldest first.
    ///
    /// The bounds are `/sync`'s own, so a client hears about an outcome
    /// exactly once: in the sync whose window contains it. A first sync
    /// passes `None` and gets everything still kept, which is what MSC4309
    /// asks for.
    ///
    /// # Errors
    ///
    /// Returns a store error if the keyspace cannot be scanned.
    pub fn finalised_between(
        &self,
        user_id: &str,
        since: Option<u64>,
        until: u64,
    ) -> Result<Vec<FinalisedDelay>, DelayError> {
        let rows = self
            .store
            .scan_prefix(&spindle_core::keys::finalised_delay_prefix(user_id))?;
        let mut out = Vec::new();
        for (key, raw) in rows {
            let Some(position) = spindle_core::keys::finalised_delay_position(user_id, &key) else {
                continue;
            };
            if position > until || since.is_some_and(|since| position <= since) {
                continue;
            }
            if let Ok(record) = serde_json::from_slice::<FinalisedDelay>(&raw) {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// How many times the pending set has changed since startup.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Send delays as they come due, for the life of the process.
///
/// Polls rather than sleeping until the next deadline, because the deadline
/// moves: a `restart` from any request handler can pull one earlier or push
/// it later, and a task parked on a timer would have to be woken by every
/// one of them. At one tick a second the cost is a single row read when
/// nothing is due, and a heartbeat's whole point is that a second of
/// imprecision does not matter.
///
/// **Nothing here recovers a missed firing specially, because there is
/// nothing to recover.** A row is due at a wall-clock time; a server that was
/// down when that time passed finds it due the moment it reads the keyspace,
/// and sends it then. That is the restart case working, not a special case
/// for it.
pub async fn fire_loop(
    delayed: Arc<Delayed>,
    rooms: Arc<Rooms>,
    key: Arc<crate::signing::ServerKey>,
    tick: Duration,
) {
    loop {
        tokio::time::sleep(tick).await;
        let now = Delayed::now_ms();
        let Ok(due) = delayed.due(now) else {
            continue;
        };
        for event in due {
            // Taken first, then sent. The other order fires twice if the
            // send succeeds and the delete does not; this one drops an
            // event if the send fails, which for a departure means the
            // participant stays listed until their client notices --
            // recoverable, where a duplicate departure is not.
            if delayed.take(&event).is_err() {
                continue;
            }
            let sent = match &event.state_key {
                Some(state_key) => rooms.set_state(
                    &event.room_id,
                    &event.sender,
                    key.pair(),
                    &event.event_type,
                    state_key,
                    &event.content,
                ),
                None => rooms.send(
                    &event.room_id,
                    &event.sender,
                    key.pair(),
                    &event.event_type,
                    &event.content,
                ),
            };
            // MSC4309: whatever happened, the client that scheduled this is
            // very likely not here -- that is what a dead-man's switch means
            // -- so the outcome is recorded for its next sync to carry.
            let record = FinalisedDelay {
                delay_id: event.delay_id.clone(),
                room_id: event.room_id.clone(),
                event_type: event.event_type.clone(),
                state_key: event.state_key.clone(),
                event_id: sent.as_ref().ok().cloned(),
                error: sent.as_ref().err().map(ToString::to_string),
            };
            // A send takes the position of the event it produced; a refusal
            // takes the head, because nothing was appended and there is no
            // position of its own to take.
            let position = rooms.stream_position();
            if let Err(error) = delayed.finalise(&event.sender, position, &record) {
                tracing::warn!(
                    delay_id = %event.delay_id,
                    "a delayed event finalised but its outcome was not recorded: {error}"
                );
            }
            if let Err(error) = sent {
                // Expected, not exceptional: by the time a departure comes
                // due the sender may have left the room, or been kicked, and
                // the rules refuse it. The delay is gone either way, which
                // is the outcome the caller wanted.
                tracing::debug!(
                    delay_id = %event.delay_id,
                    room_id = %event.room_id,
                    "a delayed event was refused when it came due: {error}"
                );
            }
        }
    }
}

#[cfg(test)]
mod restart_hot_path_tests {
    use super::*;

    /// A `Delayed` over its own store, with the directory kept alive.
    fn delayed() -> (tempfile::TempDir, Arc<FjallStore>, Delayed) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let delayed = Delayed::new(Arc::clone(&store));
        (dir, store, delayed)
    }

    fn schedule(delayed: &Delayed, delay_ms: u64) -> String {
        delayed
            .schedule(
                "!room:example.org",
                "@alice:example.org",
                "m.room.message",
                None,
                &serde_json::json!({ "body": "hi" }),
                delay_ms,
            )
            .unwrap()
    }

    /// These tests pass `now` to [`Delayed::due`] rather than sleeping, so
    /// what they assert is the ordering of deadlines and rows, not the speed
    /// of the machine running them. The one real-time dependency is that
    /// some milliseconds pass between scheduling and restarting, which the
    /// sleep below makes true by a wide margin.
    fn a_moment() {
        std::thread::sleep(Duration::from_millis(50));
    }

    /// The claim in one assertion: a restart writes nothing.
    #[test]
    fn a_restart_does_not_write() {
        let (_dir, store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let before = store.written();
        for _ in 0..1_000 {
            delayed
                .act(&id, "@alice:example.org", Action::Restart)
                .unwrap();
        }
        assert_eq!(
            store.written(),
            before,
            "a thousand restarts, no rows written"
        );
    }

    /// And the deadline really did move, so the previous test is not
    /// passing by doing nothing at all.
    #[test]
    fn a_restart_moves_the_deadline_it_did_not_write() {
        let (_dir, _store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let queued_at = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        a_moment();
        delayed
            .act(&id, "@alice:example.org", Action::Restart)
            .unwrap();

        let live = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        assert!(
            live > queued_at,
            "the reported deadline moved: {queued_at} -> {live}"
        );
        assert_eq!(
            delayed.queued_at(&id).unwrap(),
            Some(queued_at),
            "but the row did not: that is the whole saving"
        );
    }

    /// The row is due, the delay is not. Reaching it must move the row.
    #[test]
    fn a_row_whose_deadline_moved_is_requeued_rather_than_fired() {
        let (_dir, _store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let queued_at = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        a_moment();
        delayed
            .act(&id, "@alice:example.org", Action::Restart)
            .unwrap();
        let live = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;

        assert!(
            delayed.due(queued_at).unwrap().is_empty(),
            "the row came due, but the delay had been restarted past it"
        );
        assert_eq!(
            delayed.queued_at(&id).unwrap(),
            Some(live),
            "so the row was settled at the deadline it actually has"
        );
        assert_eq!(delayed.due(live).unwrap().len(), 1, "and it fires there");
    }

    /// Once, not once per tick: the deferred write is a saving only if
    /// reaching a moved row does not keep costing.
    #[test]
    fn the_row_is_settled_once_however_many_ticks_reach_it() {
        let (_dir, store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let queued_at = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        a_moment();
        delayed
            .act(&id, "@alice:example.org", Action::Restart)
            .unwrap();

        let before = store.written();
        delayed.due(queued_at).unwrap();
        let after_first = store.written();
        assert!(
            after_first > before,
            "the first tick to reach it pays for the move"
        );
        for _ in 0..10 {
            delayed.due(queued_at).unwrap();
        }
        assert_eq!(
            store.written(),
            after_first,
            "later ticks find nothing due and write nothing"
        );
    }

    /// The trade-off, stated as a test rather than only as a comment: the
    /// bumps live in memory, so a process restart loses them and the delay
    /// fires at its persisted deadline -- early, never late.
    ///
    /// Early is the direction a dead-man's switch should fail in. A
    /// participant is dropped once and their client rejoins; the opposite
    /// error leaves the ghost the mechanism exists to remove.
    #[test]
    fn a_restart_lost_to_a_crash_fires_early_never_late() {
        let (_dir, store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let queued_at = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        a_moment();
        delayed
            .act(&id, "@alice:example.org", Action::Restart)
            .unwrap();

        // A second `Delayed` over the same store is what a restart leaves.
        let reopened = Delayed::new(Arc::clone(&store));
        assert_eq!(
            reopened.get(&id, "@alice:example.org").unwrap().fire_at_ms,
            queued_at,
            "the surviving deadline is the persisted one"
        );
        assert_eq!(
            reopened.due(queued_at).unwrap().len(),
            1,
            "so it fires there, which is earlier than the client asked for"
        );
    }

    /// Erasing uses the row's position, not the deadline the caller sees.
    ///
    /// A cancel that deleted by the live deadline would delete a key that
    /// does not exist and leave the row behind, to fire an event the client
    /// had cancelled.
    #[test]
    fn cancelling_a_restarted_delay_removes_its_row() {
        let (_dir, _store, delayed) = delayed();
        let id = schedule(&delayed, 60_000);
        let queued_at = delayed.get(&id, "@alice:example.org").unwrap().fire_at_ms;
        a_moment();
        delayed
            .act(&id, "@alice:example.org", Action::Restart)
            .unwrap();
        delayed
            .act(&id, "@alice:example.org", Action::Cancel)
            .unwrap();

        assert_eq!(delayed.queued_at(&id).unwrap(), None, "the index is gone");
        assert!(
            delayed
                .due(queued_at.saturating_add(120_000))
                .unwrap()
                .is_empty(),
            "and no row survives to fire at any later time"
        );
        assert!(
            delayed.list("@alice:example.org").unwrap().is_empty(),
            "nothing is listed"
        );
    }
}
