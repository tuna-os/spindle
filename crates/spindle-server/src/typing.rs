//! Who is typing, right now, in each room.
//!
//! Typing is the clearest case in the whole API of state that is **not** an
//! event: it has no linear index, never enters a room's log, and is worthless
//! a minute after it is set. So it lives in memory and nowhere else. A restart
//! forgets who was typing, which is correct — anyone still typing says so
//! again within seconds, and a typing notification restored from disk would be
//! a lie about the present.
//!
//! Entries expire by being *read* rather than by a timer. There is no sweeper
//! task and no clock thread: a notification that has outlived its timeout is
//! simply not returned, so a stale entry can never be observed. The cost is
//! that expired rows sit in the map until the room is next read, which is
//! bounded by the number of users who have ever typed in it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// The longest a client may claim to be typing.
///
/// A client that asks for longer is clamped rather than refused: the number is
/// a hint about a person's hands, not a protocol invariant, and a client
/// sending `timeout: 3600000` means "a long time" rather than an hour.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(120);

/// The default when a client sends no timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Who is typing where.
#[derive(Default)]
pub struct Typing {
    active: Mutex<HashMap<String, HashMap<String, Instant>>>,
    changed: Notify,
}

impl Typing {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start or stop `user_id` typing in `room_id`.
    ///
    /// Notifies waiters only when the set of typists actually changed, which
    /// is what keeps a long-polling `/sync` from spinning: a client that
    /// re-sends `typing: true` every few seconds -- as clients do, to refresh
    /// the timeout -- must not wake every other client in the room each time.
    pub fn set(&self, room_id: &str, user_id: &str, typing: bool, timeout: Duration) {
        let changed = {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let room = active.entry(room_id.to_owned()).or_default();
            let was_typing = room
                .get(user_id)
                .is_some_and(|expiry| *expiry > Instant::now());
            if typing {
                room.insert(
                    user_id.to_owned(),
                    Instant::now() + timeout.min(MAX_TIMEOUT),
                );
                !was_typing
            } else {
                room.remove(user_id);
                was_typing
            }
        };
        if changed {
            self.changed.notify_waiters();
        }
    }

    /// Everyone still typing in `room_id`, sorted.
    ///
    /// Sorted because a client diffs this list against the one it holds, and
    /// a `HashMap`'s order would make an unchanged set look changed on every
    /// read.
    #[must_use]
    pub fn active(&self, room_id: &str) -> Vec<String> {
        let now = Instant::now();
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(room) = active.get_mut(room_id) else {
            return Vec::new();
        };
        room.retain(|_, expiry| *expiry > now);
        let mut users: Vec<String> = room.keys().cloned().collect();
        users.sort();
        users
    }

    /// Wait until the set of typists changes anywhere, or `timeout` elapses.
    ///
    /// Only a *change* wakes a waiter, never the mere fact that someone is
    /// typing. A `/sync` that returned early whenever anyone was mid-sentence
    /// would answer instantly, be re-issued instantly, and burn a client's
    /// battery for as long as the conversation lasted.
    pub async fn wait(&self, timeout: Duration) {
        // Created before the caller re-reads, for the same reason
        // `Rooms::wait_for_event` does it: a change landing in between would
        // otherwise be missed and the client would wait out the full timeout.
        let notified = self.changed.notified();
        let _ = tokio::time::timeout(timeout, notified).await;
    }

    /// The `m.typing` event for a room, or `None` when nobody is typing.
    ///
    /// `None` rather than an event with an empty list, so a caller can leave
    /// the room out of a sync response entirely. An empty `user_ids` is still
    /// meaningful to *send* -- it is how "everyone stopped" is expressed -- so
    /// the decision of which to use belongs to the caller that knows whether
    /// the room is in the response for another reason.
    #[must_use]
    pub fn event(&self, room_id: &str) -> Option<serde_json::Value> {
        let users = self.active(room_id);
        if users.is_empty() {
            return None;
        }
        Some(serde_json::json!({
            "type": "m.typing",
            "content": { "user_ids": users },
        }))
    }
}
