//! Presence: whether a user is around, and what they said about it.
//!
//! # What this is, and what it deliberately is not
//!
//! The CS-API's presence surface is two endpoints: a user sets their own
//! state, and someone who shares a room with them can read it. That is what
//! is served here, and it is complete for a single server.
//!
//! It is **not** wired into `/sync`'s `presence` block and it is **not**
//! federated. Both are real features and neither is pretended at: a client
//! polling `GET /presence/{user}/status` gets the truth, and a client
//! waiting for presence to arrive on `/sync` waits forever, which is why
//! `filters.rs` still says this server has no presence to filter. The
//! alternative -- an empty `presence` block on every sync -- would look like
//! "nobody is online" rather than "this server does not tell you", and a
//! client cannot distinguish those.
//!
//! # Why `last_active_ago` is computed rather than stored
//!
//! The spec asks for a duration, and a duration stored at write time is
//! wrong by however long it has been since. The row keeps the instant; the
//! answer is derived when it is asked for.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// How long after their last activity a user still counts as "currently
/// active".
///
/// The spec leaves this to the server. Five minutes is Synapse's, and
/// matching it means a client's idle indicator behaves the same way here as
/// on the server it was written against.
const CURRENTLY_ACTIVE_MS: u64 = 5 * 60 * 1000;

/// The three states the spec defines. Anything else is refused rather than
/// stored: a server that accepted `"busy"` and echoed it back would be
/// inventing protocol, and the client that sent it would have no way to
/// learn that nobody else understands it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Online,
    Offline,
    Unavailable,
}

impl State {
    /// The spec's spelling, or `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What is stored for one user.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Row {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_msg: Option<String>,
    /// Unix milliseconds when this was last set.
    at_ms: u64,
}

/// What a caller is told.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: State,
    pub status_msg: Option<String>,
    /// Milliseconds since this user was last active.
    pub last_active_ago: u64,
    pub currently_active: bool,
}

/// The presence store.
pub struct Presence {
    store: Arc<FjallStore>,
}

impl Presence {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    /// Record `user_id`'s presence.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be written.
    pub fn set(
        &self,
        user_id: &str,
        state: State,
        status_msg: Option<&str>,
    ) -> Result<(), StoreError> {
        let row = Row {
            state: state.as_str().to_owned(),
            // An empty message is the spec's way of clearing one, so it is
            // stored as absent rather than as "". Round-tripping "" would
            // make a cleared message indistinguishable from a blank one.
            status_msg: status_msg.filter(|msg| !msg.is_empty()).map(str::to_owned),
            at_ms: Self::now_ms(),
        };
        let encoded = serde_json::to_vec(&row).unwrap_or_default();
        self.store
            .put(&spindle_core::keys::presence(user_id), &encoded)
    }

    /// What `user_id`'s presence is now.
    ///
    /// A user who has never set one is offline, which is the spec's default
    /// and also the honest answer: this server has heard nothing from them.
    ///
    /// # Errors
    ///
    /// Returns a store error if the row cannot be read.
    pub fn get(&self, user_id: &str) -> Result<Status, StoreError> {
        let Some(raw) = self.store.get(&spindle_core::keys::presence(user_id))? else {
            return Ok(Status {
                state: State::Offline,
                status_msg: None,
                last_active_ago: 0,
                currently_active: false,
            });
        };
        let Ok(stored) = serde_json::from_slice::<Row>(&raw) else {
            return Ok(Status {
                state: State::Offline,
                status_msg: None,
                last_active_ago: 0,
                currently_active: false,
            });
        };
        let state = State::parse(&stored.state).unwrap_or(State::Offline);
        // Saturating rather than wrapping: a row written by a clock that has
        // since gone backwards should read as "just now", not as a duration
        // near u64::MAX.
        let last_active_ago = Self::now_ms().saturating_sub(stored.at_ms);
        Ok(Status {
            state,
            status_msg: stored.status_msg,
            last_active_ago,
            // Only "online" can be currently active. An idle or offline user
            // who set that state one second ago is recent, but recency is
            // not the question -- the question is whether they are there.
            currently_active: state == State::Online && last_active_ago < CURRENTLY_ACTIVE_MS,
        })
    }
}
