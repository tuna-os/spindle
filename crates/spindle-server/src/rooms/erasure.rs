//! Serve an erased user's events pruned, as Synapse does (#576).
//!
//! Synapse's rule (`synapse/visibility.py`): an event whose sender is in
//! `erased_users` reaches a client in its redacted form unless the client
//! was joined at the event (`filter_events_for_client`), and reaches
//! another server in its redacted form always (`filter_events_for_server`
//! with `filter_out_erased_senders`, on `/event`, `/backfill` and
//! `/get_missing_events`). Room state is not filtered by either: the
//! current name, topic and encryption settings stay what the room says.
//! Stored PDUs are never rewritten; only the copy being served is.

use std::collections::HashSet;
use std::sync::Arc;

use ruma::CanonicalJsonValue;
use serde_json::Value;
use spindle_core::{EventId, StateKey, StateSnapshot};

use super::{RoomError, Rooms, canonical_to_json, stamp};
use crate::accounts::Accounts;

/// The erased local users' IDs, as of one erasure generation.
pub(crate) type ErasedUsers = Arc<HashSet<String>>;

/// [`Rooms::erased_users`]' cache. Generation 0 is "never erased", which
/// is never cached, so the default cannot answer a read.
#[derive(Default)]
pub(super) struct ErasedCache {
    generation: u64,
    users: ErasedUsers,
}

/// `MEMBERSHIP_PRIORITY` in Synapse's `visibility.py`, most joined first.
const MEMBERSHIP_PRIORITY: [&str; 5] = ["join", "invite", "knock", "leave", "ban"];

fn membership_rank(membership: &Value) -> usize {
    // Synapse reads an absent or unknown membership as `leave`.
    membership
        .as_str()
        .and_then(|membership| {
            MEMBERSHIP_PRIORITY
                .iter()
                .position(|known| *known == membership)
        })
        .unwrap_or(3)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "a `map_err` argument receives the error by value"
)]
fn build_error(error: impl ToString) -> RoomError {
    RoomError::Build(error.to_string())
}

impl Rooms {
    /// Every erased local user, or `None` when no account was ever erased.
    ///
    /// One marker read when the set is cached; the account scan runs once
    /// per change to any erasure flag, which is what makes asking it of
    /// every served event affordable on a server with thousands of erased
    /// bridge puppets.
    ///
    /// # Errors
    ///
    /// Returns a storage or account decoding error.
    pub(crate) fn erased_users(&self) -> Result<Option<ErasedUsers>, RoomError> {
        let accounts = Accounts::new(self.store.as_ref(), &self.server_name);
        let generation = accounts.erasure_generation().map_err(build_error)?;
        if generation == 0 {
            return Ok(None);
        }
        {
            let cache = self
                .erased
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache.generation == generation {
                return Ok(Some(Arc::clone(&cache.users)));
            }
        }
        // Scanned after the generation was read, so the set is at least as
        // new as the generation it is filed under; a change landing during
        // the scan moves the generation and the next read scans again.
        let users = Arc::new(accounts.erased_user_ids().map_err(build_error)?);
        let mut cache = self
            .erased
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.generation < generation {
            *cache = ErasedCache {
                generation,
                users: Arc::clone(&users),
            };
        }
        Ok(Some(users))
    }

    /// [`Self::prune_erased_with`] over a batch, reading the erased set
    /// once.
    ///
    /// # Errors
    ///
    /// As [`Self::prune_erased_with`].
    pub(crate) fn prune_erased_events(
        &self,
        user_id: &str,
        room_id: &str,
        events: Vec<Value>,
    ) -> Result<Vec<Value>, RoomError> {
        let Some(erased) = self.erased_users()? else {
            return Ok(events);
        };
        events
            .into_iter()
            .map(|event| self.prune_erased_with(&erased, user_id, room_id, event))
            .collect()
    }

    /// [`Self::prune_erased_with`] for one event, reading the erased set.
    ///
    /// # Errors
    ///
    /// As [`Self::prune_erased_with`].
    pub(crate) fn prune_erased_event(
        &self,
        user_id: &str,
        room_id: &str,
        event: Value,
    ) -> Result<Value, RoomError> {
        match self.erased_users()? {
            Some(erased) => self.prune_erased_with(&erased, user_id, room_id, event),
            None => Ok(event),
        }
    }

    /// The client copy of `event` that `user_id` may see: the event itself,
    /// or its redacted form when its sender is erased and the reader was
    /// not joined at it.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or a build error when the event cannot be
    /// redacted or the state at it cannot be read.
    pub(crate) fn prune_erased_with(
        &self,
        erased: &HashSet<String>,
        user_id: &str,
        room_id: &str,
        mut event: Value,
    ) -> Result<Value, RoomError> {
        // A later state event carries its predecessor's content in
        // `prev_content`, which would disclose an erased predecessor even
        // when the later sender is not erased.
        if event["unsigned"].get("prev_content").is_some() {
            // `prev_sender` answers from memory when it is there; only an
            // event without it pays a read to learn who sent the predecessor.
            let previous_erased = event["unsigned"]["prev_sender"]
                .as_str()
                .is_none_or(|sender| erased.contains(sender));
            // `None` keeps `prev_content`, `Some(None)` drops it.
            let replacement = match event["unsigned"]["replaces_state"].as_str() {
                Some(_) if !previous_erased => None,
                Some(previous) => match self.event(room_id, previous) {
                    Ok(previous) => Some(Some(
                        self.prune_erased_body(erased, user_id, room_id, previous)?["content"]
                            .clone(),
                    )),
                    Err(RoomError::MissingBody(_)) => Some(None),
                    Err(error) => return Err(error),
                },
                // No predecessor to judge it by: nothing shows the content
                // is not an erased user's.
                None => Some(None),
            };
            if let Some(replacement) = replacement
                && let Some(unsigned) = event["unsigned"].as_object_mut()
            {
                match replacement {
                    Some(content) => {
                        unsigned.insert("prev_content".to_owned(), content);
                    }
                    None => {
                        unsigned.remove("prev_content");
                    }
                }
            }
        }
        self.prune_erased_body(erased, user_id, room_id, event)
    }

    fn prune_erased_body(
        &self,
        erased: &HashSet<String>,
        user_id: &str,
        room_id: &str,
        event: Value,
    ) -> Result<Value, RoomError> {
        if !event["sender"]
            .as_str()
            .is_some_and(|sender| erased.contains(sender))
        {
            return Ok(event);
        }
        let Some(id) = event["event_id"].as_str().map(str::to_owned) else {
            return Err(build_error("client event has no event_id"));
        };
        if self.joined_at(user_id, room_id, &id, &event)? {
            return Ok(event);
        }
        // Synapse's `prune_event` keeps `replaces_state` (and `age_ts`,
        // which Spindle does not set) from `unsigned`; everything else
        // there -- bundled relations, `prev_content` -- can carry content.
        let replaces_state = event["unsigned"]["replaces_state"].clone();
        let CanonicalJsonValue::Object(mut object) =
            CanonicalJsonValue::try_from(event).map_err(build_error)?
        else {
            return Err(build_error("client event is not an object"));
        };
        object.remove("unsigned");
        let redacted = spindle_core::version::redact(&object, &self.room_version(room_id)?)
            .map_err(build_error)?;
        let mut redacted = stamp(canonical_to_json(&redacted), &id);
        if !replaces_state.is_null()
            && let Some(object) = redacted.as_object_mut()
        {
            object.insert(
                "unsigned".to_owned(),
                serde_json::json!({ "replaces_state": replaces_state }),
            );
        }
        Ok(redacted)
    }

    /// Whether `user_id` was joined at event `id`, by Synapse's
    /// `_check_membership`.
    fn joined_at(
        &self,
        user_id: &str,
        room_id: &str,
        id: &str,
        event: &Value,
    ) -> Result<bool, RoomError> {
        // The reader's own membership event counts as the more joined of
        // its new and previous membership, except that leaving a room one
        // was joined to or invited into never counts as joined. So a
        // joined member sees their ban in full and their kick redacted.
        if event["type"] == "m.room.member" && event["state_key"] == user_id {
            let new = membership_rank(&event["content"]["membership"]);
            let previous = membership_rank(&event["unsigned"]["prev_content"]["membership"]);
            if MEMBERSHIP_PRIORITY[new] == "leave" && previous <= 1 {
                return Ok(false);
            }
            return Ok(MEMBERSHIP_PRIORITY[new.min(previous)] == "join");
        }
        // Otherwise the membership in the state after the event, which is
        // the state Synapse reads (`get_state_for_events`).
        let (root, table) = self.with_room_read(room_id, |_, log| {
            Ok((
                log.get(&EventId::new(id)).map(|entry| entry.state_root),
                log.table().clone(),
            ))
        })?;
        // An event outside the log -- an auth-chain outlier, a gap event --
        // has no state to prove membership by.
        let Some(root) = root else {
            return Ok(false);
        };
        let membership_id = StateSnapshot::get_persisted(
            root,
            &StateKey::new("m.room.member", user_id),
            &mut |root| self.load_node(root),
            &table,
        )
        .map_err(|error| build_error(format!("cannot read membership at event: {error:?}")))?;
        Ok(match membership_id {
            Some(membership_id) => {
                self.read_event(room_id, &EventId::new(membership_id))?["content"]["membership"]
                    == "join"
            }
            None => false,
        })
    }

    /// The PDUs another server is sent from `/event`, `/backfill` and
    /// `/get_missing_events`: an erased local sender's event goes in its
    /// redacted form whatever that server's membership, as Synapse's
    /// `filter_events_for_server` sends it. The redacted form keeps its
    /// hashes and signatures, so it verifies and keeps its event ID; the
    /// receiver's content-hash check then stores it redacted.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or a build error when a PDU cannot be
    /// redacted under the room's version.
    pub(crate) fn prune_erased_pdus(
        &self,
        room_id: &str,
        pdus: Vec<Value>,
    ) -> Result<Vec<Value>, RoomError> {
        let Some(erased) = self.erased_users()? else {
            return Ok(pdus);
        };
        let mut version = None;
        pdus.into_iter()
            .map(|pdu| {
                if !pdu["sender"]
                    .as_str()
                    .is_some_and(|sender| erased.contains(sender))
                {
                    return Ok(pdu);
                }
                let version = match &version {
                    Some(version) => version,
                    None => version.insert(self.room_version(room_id)?),
                };
                let CanonicalJsonValue::Object(object) =
                    CanonicalJsonValue::try_from(pdu).map_err(build_error)?
                else {
                    return Err(build_error("PDU is not an object"));
                };
                let redacted =
                    spindle_core::version::redact(&object, version).map_err(build_error)?;
                Ok(canonical_to_json(&redacted))
            })
            .collect()
    }
}
