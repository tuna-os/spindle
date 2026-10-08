//! The room-log half of MSC3995 hub mode (#22, SPEC section 12.6).
//!
//! Compiled only with the `hub-mode` feature. Everything here is a question
//! about one room's log, answered under that room's lock; the wire half --
//! routes, the capability probe, attestations -- is `crate::hub`.
//!
//! The one operation that is new rather than a view of the log is
//! [`Rooms::hub_sequence`]: compare-and-append. A participant builds its
//! event on what it believes the head is and the hub appends it only if
//! that is still the head, under the same lock its own appends take. That
//! single check is the whole of "the hub decides the order": every event
//! the hub accepts this way extends the one chain, so none of them can
//! fork, and the participant learns of a lost race instead of creating one.

use std::collections::BTreeSet;

use ruma::signatures::Ed25519KeyPair;
use serde_json::Value;
use spindle_core::EventId;

use super::{RoomError, Rooms, edge_ids};

/// The state event that names a room's hub (MSC3995).
pub const HUB_EVENT_TYPE: &str = "m.room.hub";

/// One live log entry as the hub attests it: position, event, the chain
/// value recorded when this server sequenced it, and the state root after
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEntry {
    pub li: i64,
    pub event_id: String,
    pub chain: [u8; 32],
    pub state_root: [u8; 32],
}

/// A handoff's check of the outgoing epoch's last entry, run under the
/// room lock with the head check.
pub type FinalGuard<'a> = &'a dyn Fn(Option<&ChainEntry>) -> bool;

/// What the hub did with a participant's event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sequenced {
    /// Appended at `li`, with the chain value this server recorded there.
    Appended { li: i64, chain: Option<[u8; 32]> },
    /// Not appended: the event did not name the head. `head` is what it
    /// is now, so the participant can catch up and build again.
    Stale { head: Vec<String> },
    /// Not appended: a handoff whose stated final entry is not the last
    /// entry this hub attests. `last` is what that entry is.
    WrongFinal { last: Option<ChainEntry> },
}

impl Rooms {
    /// The room's current `m.room.hub` event, stamped with its ID, if it
    /// has one. Whether it designates a hub is the overlay's judgement
    /// (`crate::hub`), which needs keys and attestations this does not.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or cannot be read.
    pub fn hub_event(&self, room_id: &str) -> Result<Option<Value>, RoomError> {
        match self.state_event_full(room_id, HUB_EVENT_TYPE, "") {
            Ok(event) => Ok(Some(event)),
            Err(RoomError::UnknownState(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The server of the room creator: MSC3995's hub when no `m.room.hub`
    /// has moved it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or has no create event.
    pub fn creator_server(&self, room_id: &str) -> Result<Option<String>, RoomError> {
        let create = self.state_event_full(room_id, "m.room.create", "")?;
        Ok(create["sender"]
            .as_str()
            .and_then(|sender| sender.split_once(':'))
            .map(|(_, domain)| domain.to_owned()))
    }

    /// Build, sign and authorize an event on this server's head, without
    /// appending it: what a participant submits to the hub.
    ///
    /// The event is ordinary in every respect -- `prev_events`,
    /// `auth_events`, hashes and the origin's signature all as the room
    /// version says -- which is what lets a server that knows nothing of
    /// hub mode accept it later exactly as it would any other.
    ///
    /// # Errors
    ///
    /// As the ordinary send: unknown room, or the auth rules refuse it.
    #[allow(clippy::too_many_arguments, reason = "an event is what it is")]
    pub(crate) fn build_for_hub(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
    ) -> Result<(String, Value), RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.build_event(
                log, room_id, sender, key, event_type, state_key, content, None,
            )
        })
    }

    /// Compare-and-append: take a participant's verified event into the
    /// log if, and only if, its `prev_events` are exactly the head this
    /// server would author on now.
    ///
    /// Run under the room's write lock, the same one a local append holds,
    /// so the check and the append are one step and the hub's own events
    /// and every participant's are serialized against each other. The
    /// event then goes through the ordinary receipt checks; the hub does
    /// not fan it out, because its origin does (SPEC section 12.6).
    ///
    /// # Errors
    ///
    /// As [`Self::receive_remote`]: unknown room, or the event is refused.
    pub(crate) fn hub_sequence(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
        final_guard: Option<FinalGuard<'_>>,
    ) -> Result<Sequenced, RoomError> {
        self.with_room(room_id, |rooms, log| {
            // A retried submission whose answer was lost: already in.
            if let Some(entry) = log.get(&EventId::new(event_id)) {
                return Ok(Sequenced::Appended {
                    li: entry.li.get(),
                    chain: entry.chain.map(|chain| *chain.as_bytes()),
                });
            }
            let head: BTreeSet<String> = log
                .authoring_extremities()
                .map(|id| id.as_str().to_owned())
                .collect();
            let named: BTreeSet<String> = edge_ids(&json["prev_events"]).into_iter().collect();
            if named != head {
                return Ok(Sequenced::Stale {
                    head: head.into_iter().collect(),
                });
            }
            // A handoff names the last entry of the outgoing epoch; under
            // the same lock as the head check, so nothing slips in between.
            if let Some(guard) = final_guard {
                let last = log.entries().rev().find_map(chain_entry);
                if !guard(last.as_ref()) {
                    return Ok(Sequenced::WrongFinal { last });
                }
            }
            rooms.ingest(log, room_id, event_id, json, false)?;
            let entry = log
                .get(&EventId::new(event_id))
                .ok_or_else(|| RoomError::Append(format!("{event_id} was not appended")))?;
            Ok(Sequenced::Appended {
                li: entry.li.get(),
                chain: entry.chain.map(|chain| *chain.as_bytes()),
            })
        })
    }

    /// Commit an event this server built and the hub placed (or could not
    /// place), and fan it out to the room like any event this server
    /// authors.
    ///
    /// The event may already be here: the hub's next event can name it, and
    /// dependency recovery then fetches it back from the hub before the
    /// hub's answer to the submission arrives. Ingest treats that as a
    /// redelivery and fans nothing out, so the fan-out is done here
    /// instead -- this server is the event's origin, and nobody else will
    /// send it to the room's other servers.
    ///
    /// # Errors
    ///
    /// As [`Self::commit_cosigned`].
    pub(crate) fn commit_placed(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        self.with_room(room_id, |rooms, log| {
            if log.get(&EventId::new(event_id)).is_some() {
                return rooms.enqueue_outbound(log, room_id, json);
            }
            rooms.ingest(log, room_id, event_id, json, true)
        })
    }

    /// The stored PDUs after the newest of `after` this server holds, oldest
    /// first, at most `limit`: what a participant whose head went stale is
    /// missing. With none of `after` held, the newest `limit` entries.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or a body cannot be read.
    pub(crate) fn hub_events_after(
        &self,
        room_id: &str,
        after: &[String],
        limit: usize,
    ) -> Result<Vec<Value>, RoomError> {
        self.with_room_read(room_id, |rooms, log| {
            let floor = after
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li.get())
                .max();
            let ids: Vec<EventId> = if let Some(floor) = floor {
                log.entries_in((floor + 1)..)
                    .take(limit)
                    .map(|entry| entry.event_id.clone())
                    .collect()
            } else {
                let mut newest: Vec<EventId> = log
                    .entries()
                    .rev()
                    .take(limit)
                    .map(|entry| entry.event_id.clone())
                    .collect();
                newest.reverse();
                newest
            };
            ids.iter().map(|id| rooms.read_event(room_id, id)).collect()
        })
    }

    /// The live entries after `after`, oldest first, at most `limit`, each
    /// with the chain value this server recorded when it sequenced it and
    /// the state root after it: what the hub attests and checkpoints (SPEC
    /// section 12.6). Entries without a chain value -- seeded or backfilled
    /// history -- are skipped; this server did not order them and does not
    /// vouch for their order.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown.
    pub(crate) fn hub_chain_since(
        &self,
        room_id: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<ChainEntry>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries_in((after.saturating_add(1))..)
                .filter_map(chain_entry)
                .take(limit)
                .collect())
        })
    }

    /// The entry at `li`, or the one holding `event_id`, as [`ChainEntry`],
    /// if this server sequenced it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown.
    pub(crate) fn hub_entry(
        &self,
        room_id: &str,
        li: Option<i64>,
        event_id: Option<&str>,
    ) -> Result<Option<ChainEntry>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            let entry = match (li, event_id) {
                (Some(li), _) => log.entry_at(li),
                (None, Some(id)) => log.get(&EventId::new(id)),
                (None, None) => log.entries().rev().find(|entry| entry.chain.is_some()),
            };
            Ok(entry.and_then(chain_entry))
        })
    }

    /// Where `event_id` sits in this server's log, if it is in it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown.
    pub(crate) fn hub_position(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<Option<i64>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log.get(&EventId::new(event_id)).map(|entry| entry.li.get()))
        })
    }

    /// The highest live position in the room's log: where an attestation
    /// stream starts when this server has none in memory for it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown.
    pub(crate) fn hub_last_position(&self, room_id: &str) -> Result<i64, RoomError> {
        self.with_room_read(room_id, |_, log| Ok(log.next_forward().saturating_sub(1)))
    }
}

/// A log entry as a [`ChainEntry`], when it carries a chain value.
fn chain_entry(entry: &spindle_core::LogEntry) -> Option<ChainEntry> {
    entry.chain.map(|chain| ChainEntry {
        li: entry.li.get(),
        event_id: entry.event_id.as_str().to_owned(),
        chain: *chain.as_bytes(),
        state_root: *entry.state_root.as_bytes(),
    })
}
