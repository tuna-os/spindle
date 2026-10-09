//! Apply account erasure to client copies, preserving stored PDUs (#576).

use ruma::CanonicalJsonValue;
use serde_json::Value;
use spindle_core::{EventId, StateKey, StateSnapshot};

use super::{RoomError, Rooms, canonical_to_json, stamp};
use crate::accounts::Accounts;

impl Rooms {
    pub(crate) fn erasure_active(&self) -> Result<bool, RoomError> {
        Accounts::new(self.store.as_ref(), &self.server_name)
            .erasure_active()
            .map_err(|error| RoomError::Build(error.to_string()))
    }

    pub(crate) fn summary_for(
        &self,
        user_id: &str,
        room_id: &str,
    ) -> Result<super::RoomSummary, RoomError> {
        let mut summary = self.summary(room_id)?;
        if !self.erasure_active()? {
            return Ok(summary);
        }
        let string = |event_type: &str, field: &str| -> Result<Option<String>, RoomError> {
            let event = match self.state_event_full(room_id, event_type, "") {
                Ok(event) => event,
                Err(RoomError::UnknownState(_)) => return Ok(None),
                Err(error) => return Err(error),
            };
            let event = self.prune_erased_event(user_id, room_id, event)?;
            Ok(event["content"][field].as_str().map(str::to_owned))
        };
        summary.name = string("m.room.name", "name")?;
        summary.topic = string("m.room.topic", "topic")?;
        summary.avatar_url = string("m.room.avatar", "url")?;
        summary.canonical_alias = string("m.room.canonical_alias", "alias")?;
        summary.join_rule = string("m.room.join_rules", "join_rule")?;
        summary.room_type = string("m.room.create", "type")?;
        summary.encryption = string("m.room.encryption", "algorithm")?;
        Ok(summary)
    }

    fn sender_erased(&self, event: &Value) -> Result<bool, RoomError> {
        let Some(sender) = event["sender"].as_str() else {
            return Ok(false);
        };
        let Some(localpart) = sender
            .strip_prefix('@')
            .and_then(|sender| sender.strip_suffix(&format!(":{}", self.server_name)))
        else {
            return Ok(false);
        };
        Ok(Accounts::new(self.store.as_ref(), &self.server_name)
            .account(localpart)
            .map_err(|error| RoomError::Build(error.to_string()))?
            .is_some_and(|account| account.erased))
    }

    pub(super) fn prune_erased_stripped(
        &self,
        events: Vec<Value>,
    ) -> Result<Vec<Value>, RoomError> {
        if !self.erasure_active()? {
            return Ok(events);
        }
        // Pending invites have no event IDs or state roots. Without proof
        // of membership, an erased local sender gets the redacted view.
        let version = events
            .iter()
            .find(|event| event["type"] == "m.room.create")
            .and_then(|event| event["content"]["room_version"].as_str())
            .unwrap_or("1");
        let version = ruma::RoomVersionId::try_from(version)
            .map_err(|error| RoomError::Build(error.to_string()))?;
        events
            .iter()
            .map(|event| {
                if !self.sender_erased(event)? {
                    return Ok(event.clone());
                }
                let CanonicalJsonValue::Object(object) =
                    CanonicalJsonValue::try_from(event.clone())
                        .map_err(|error| RoomError::Build(error.to_string()))?
                else {
                    return Err(RoomError::Build(
                        "stripped event is not an object".to_owned(),
                    ));
                };
                let redacted = spindle_core::version::redact(&object, &version)
                    .map_err(|error| RoomError::Build(error.to_string()))?;
                Ok(canonical_to_json(&redacted))
            })
            .collect()
    }

    pub(crate) fn prune_erased_events(
        &self,
        user_id: &str,
        room_id: &str,
        events: Vec<Value>,
    ) -> Result<Vec<Value>, RoomError> {
        if !self.erasure_active()? {
            return Ok(events);
        }
        events
            .into_iter()
            .map(|event| self.prune_erased_event(user_id, room_id, event))
            .collect()
    }

    pub(crate) fn prune_erased_event(
        &self,
        user_id: &str,
        room_id: &str,
        mut event: Value,
    ) -> Result<Value, RoomError> {
        // A later state event can disclose its erased predecessor through
        // prev_content even when the later sender has not been erased.
        if event["unsigned"].get("prev_content").is_some() {
            let previous = event["unsigned"]["replaces_state"]
                .as_str()
                .map(str::to_owned);
            let content = match previous {
                Some(previous) => match self.event(room_id, &previous) {
                    Ok(previous) => {
                        Some(self.prune_erased_body(user_id, room_id, previous)?["content"].clone())
                    }
                    Err(RoomError::MissingBody(_)) => None,
                    Err(error) => return Err(error),
                },
                None => None,
            };
            if let Some(unsigned) = event["unsigned"].as_object_mut() {
                match content {
                    Some(content) => {
                        unsigned.insert("prev_content".to_owned(), content);
                    }
                    None => {
                        unsigned.remove("prev_content");
                    }
                }
            }
        }
        self.prune_erased_body(user_id, room_id, event)
    }

    fn prune_erased_body(
        &self,
        user_id: &str,
        room_id: &str,
        event: Value,
    ) -> Result<Value, RoomError> {
        if !self.sender_erased(&event)? {
            return Ok(event);
        }
        let Some(id) = event["event_id"].as_str().map(str::to_owned) else {
            return Err(RoomError::Build("client event has no event_id".to_owned()));
        };
        let root = self.with_room_read(room_id, |_, log| {
            Ok(log
                .get(&EventId::new(id.as_str()))
                .map(|entry| entry.state_root))
        })?;
        let membership_id = match root {
            Some(root) => StateSnapshot::get_persisted(
                root,
                &StateKey::new("m.room.member", user_id),
                &mut |root| self.load_node(root),
            )
            .map_err(|error| {
                RoomError::Build(format!("cannot read membership at event: {error:?}"))
            })?,
            None => None,
        };
        if let Some(membership_id) = membership_id
            && self.read_event(room_id, &EventId::new(membership_id))?["content"]["membership"]
                == "join"
        {
            return Ok(event);
        }
        let CanonicalJsonValue::Object(mut object) = CanonicalJsonValue::try_from(event)
            .map_err(|error| RoomError::Build(error.to_string()))?
        else {
            return Err(RoomError::Build("client event is not an object".to_owned()));
        };
        // Client annotations can contain original content or relation bodies.
        object.remove("unsigned");
        let redacted = spindle_core::version::redact(&object, &self.room_version(room_id)?)
            .map_err(|error| RoomError::Build(error.to_string()))?;
        Ok(stamp(canonical_to_json(&redacted), &id))
    }
}
