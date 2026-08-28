//! Executable core invariants for the Spindle homeserver.
//!
//! The storage order is linear even when the federation projection temporarily
//! forks. Those are deliberately separate concepts: [`RoomLog`] assigns one
//! monotonic [`LinearIndex`] to every accepted event, while retaining the real
//! signed `prev_events` graph required by Matrix federation.

pub mod keys;
mod log;
mod pdu;
mod state;

pub use log::{
    AppendError, ChainHash, DEFAULT_RESIDENT_WINDOW, EventId, EventInput, ForkWindow,
    ForkWindowError, LinearIndex, LogEntry, NodeLoader, RestoreError, RestoredEntry, RestoredLog,
    RoomLog,
};
pub use pdu::{Pdu, PduError};
pub use state::{
    CONTENT_DIGEST_VERSION, EventType, RehydrateError, StateKey, StateRoot, StateSnapshot,
};
