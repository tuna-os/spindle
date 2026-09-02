//! Executable core invariants for the Spindle homeserver.
//!
//! The storage order is linear even when the federation projection temporarily
//! forks. Those are deliberately separate concepts: [`RoomLog`] assigns one
//! monotonic [`LinearIndex`] to every accepted event, while retaining the real
//! signed `prev_events` graph required by Matrix federation.

// The parse-path lints #266 asks for on "the storage and event-parsing
// crates specifically". A homeserver that panics on a malformed PDU or a
// corrupt row is a remote denial of service, and the parse path is exactly
// where an index is tempting. `not(test)` because a Cargo `[lints]` table
// applies per crate rather than per target, and a unit test that cannot
// `unwrap` is a test nobody writes; integration tests are their own crates
// and never inherit this. Declared here rather than in `[lints]` for the
// same reason -- a lint table cannot say "except in tests".
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

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
