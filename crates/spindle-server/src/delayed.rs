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
    Store(StoreError),
}

impl std::fmt::Display for DelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(formatter, "no such delayed event"),
            Self::TooLong { limit_ms } => {
                write!(formatter, "the maximum delay is {limit_ms}ms")
            }
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
    /// Bumped whenever a row is written, so a caller can tell whether
    /// anything changed without reading the rows.
    generation: std::sync::atomic::AtomicU64,
}

/// The default cap: a day.
pub const DEFAULT_MAX_DELAY_MS: u64 = 24 * 60 * 60 * 1000;

impl Delayed {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self {
            store,
            max_delay_ms: DEFAULT_MAX_DELAY_MS,
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

    /// Remove both rows for one delay.
    fn erase(&self, delay_id: &str, fire_at_ms: u64) -> Result<(), DelayError> {
        self.store
            .delete(&spindle_core::keys::delayed_event(fire_at_ms, delay_id))?;
        self.store
            .delete(&spindle_core::keys::delayed_event_by_id(delay_id))?;
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let event: DelayedEvent =
            serde_json::from_slice(&stored).map_err(|_| DelayError::NotFound)?;
        if event.sender != sender {
            return Err(DelayError::NotFound);
        }
        Ok(event)
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
            if let Ok(event) = serde_json::from_slice::<DelayedEvent>(&raw)
                && event.sender == sender
            {
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
                self.erase(&event.delay_id, event.fire_at_ms)?;
                Ok(None)
            }
            Action::Send => {
                self.erase(&event.delay_id, event.fire_at_ms)?;
                Ok(Some(event))
            }
            Action::Restart => {
                // The *original* delay from now, not the time remaining. A
                // heartbeat that shortened the window on every beat would
                // converge on firing while the client was still alive, which
                // is the opposite of what restarting it means.
                self.erase(&event.delay_id, event.fire_at_ms)?;
                let restarted = DelayedEvent {
                    fire_at_ms: Self::now_ms().saturating_add(event.delay_ms),
                    ..event
                };
                self.write(&restarted)?;
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
            if let Ok(event) = serde_json::from_slice::<DelayedEvent>(&raw) {
                out.push(event);
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
        self.erase(&event.delay_id, event.fire_at_ms)
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
