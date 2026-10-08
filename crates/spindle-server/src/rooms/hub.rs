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

/// Who hubs a room, as the overlay reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubDesignation {
    /// The hub: the server of the `m.room.hub` event's sender (MSC3995).
    pub server: String,
    /// `org.spindle.epoch` from the event's content, `0` when absent.
    /// Carried into every attestation; failover, which would advance it,
    /// is designed-only (SPEC section 13.2).
    pub epoch: u64,
    /// The `m.room.hub` event in force.
    pub event_id: String,
}

/// What the hub did with a participant's event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sequenced {
    /// Appended at `li`, with the chain value this server recorded there.
    Appended { li: i64, chain: Option<[u8; 32]> },
    /// Not appended: the event did not name the head. `head` is what it
    /// is now, so the participant can catch up and build again.
    Stale { head: Vec<String> },
}

impl Rooms {
    /// The room's hub, if hub mode is in force in it.
    ///
    /// MSC3995 makes the hub the server of the `m.room.hub` sender, and
    /// requires the event to be signed by the *current* hub -- the
    /// `m.room.create` sender's server while there is none. In an ordinary
    /// room version no peer enforces that rule, so the overlay does, in
    /// the narrowest form that needs no handoff: the designation counts
    /// only when the hub it names is the room creator's server, which
    /// signed it by sending it. Anything else -- a hub event from another
    /// server, i.e. a transfer -- leaves the room ordinary until handoff
    /// (dual signatures, epochs) is built (TODO(#22): SPEC section 13.2).
    ///
    /// Unlike the MSC's own room version, a room with no `m.room.hub` is
    /// not hubbed by its creator: in an ordinary room version hub mode is
    /// opt-in, per room, by sending the event.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or cannot be read.
    pub fn hub_designation(&self, room_id: &str) -> Result<Option<HubDesignation>, RoomError> {
        let hub = match self.state_event_full(room_id, HUB_EVENT_TYPE, "") {
            Ok(event) => event,
            Err(RoomError::UnknownState(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let create = self.state_event_full(room_id, "m.room.create", "")?;
        let server_of = |event: &Value| {
            event["sender"]
                .as_str()
                .and_then(|sender| sender.split_once(':'))
                .map(|(_, domain)| domain.to_owned())
        };
        let (Some(server), Some(creator)) = (server_of(&hub), server_of(&create)) else {
            return Ok(None);
        };
        if server != creator {
            return Ok(None);
        }
        Ok(Some(HubDesignation {
            server,
            epoch: hub["content"]["org.spindle.epoch"].as_u64().unwrap_or(0),
            event_id: hub["event_id"].as_str().unwrap_or_default().to_owned(),
        }))
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
    /// with the chain value this server recorded when it sequenced it:
    /// what the hub attests (SPEC section 12.5). Entries without a chain
    /// value -- seeded or backfilled history -- are skipped; this server
    /// did not order them and does not vouch for their order.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown.
    pub(crate) fn hub_chain_since(
        &self,
        room_id: &str,
        after: i64,
        limit: usize,
    ) -> Result<Vec<(i64, String, [u8; 32])>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log
                .entries_in((after.saturating_add(1))..)
                .filter_map(|entry| {
                    entry.chain.map(|chain| {
                        (
                            entry.li.get(),
                            entry.event_id.as_str().to_owned(),
                            *chain.as_bytes(),
                        )
                    })
                })
                .take(limit)
                .collect())
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
