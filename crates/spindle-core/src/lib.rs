//! Executable core invariants for the Spindle homeserver.
//!
//! The storage order is linear even when the federation projection temporarily
//! forks. Those are deliberately separate concepts: [`RoomLog`] assigns one
//! monotonic [`LinearIndex`] to every accepted event, while retaining the real
//! signed `prev_events` graph required by Matrix federation.

mod log;
mod state;

pub use log::{AppendError, EventId, EventInput, LinearIndex, LogEntry, RoomLog};
pub use state::{EventType, StateKey, StateRoot, StateSnapshot};
