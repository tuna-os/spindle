//! Prepare under the room guard, ask outside it, then recheck before commit.
use super::{Ed25519KeyPair, RoomError, RoomLog, Rooms, StateKey, Value};
use crate::policy::{PolicyServer, STABLE_TYPE, UNSTABLE_TYPE};
use std::sync::Arc;

impl Rooms {
    pub(crate) fn set_policy_federation(&self, federation: &Arc<crate::federation::Federation>) {
        *self
            .policy_federation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(federation));
    }

    pub(super) fn policy_in(
        &self,
        log: &RoomLog,
        room_id: &str,
    ) -> Result<Option<PolicyServer>, RoomError> {
        let Some(state) = log.current_state() else {
            return Ok(None);
        };
        let stable = state.get(&StateKey::new(STABLE_TYPE, ""));
        let (id, unstable) = match stable {
            Some(id) => (id, false),
            None => match state.get(&StateKey::new(UNSTABLE_TYPE, "")) {
                Some(id) => (id, true),
                None => return Ok(None),
            },
        };
        let event = self.read_event(room_id, &super::EventId::new(id))?;
        let policy = PolicyServer::from_content(&event["content"], unstable, &self.server_name);
        let domains = self.destinations_in(log, room_id)?;
        Ok(policy.filter(|policy| domains.iter().any(|domain| domain == &policy.server_name)))
    }

    /// The currently enabled policy, including the joined-server requirement.
    ///
    /// # Errors
    /// Returns a room/store error if current state cannot be read.
    pub fn policy_server(&self, room_id: &str) -> Result<Option<PolicyServer>, RoomError> {
        self.with_room_read(room_id, |rooms, log| rooms.policy_in(log, room_id))
    }

    pub(super) fn check_policy_in(
        &self,
        log: &RoomLog,
        room_id: &str,
        event: &Value,
    ) -> Result<(), RoomError> {
        if crate::policy::exempt(event) {
            return Ok(());
        }
        if let Some(policy) = self.policy_in(log, room_id)?
            && !policy.verifies(event, &self.version_in_log(log, room_id)?)
        {
            return Err(RoomError::Forbidden(
                "event has no valid approval from the room's policy server".to_owned(),
            ));
        }
        Ok(())
    }

    /// Check a live event asynchronously. Historical auth/backfill is separate.
    ///
    /// # Errors
    /// Returns a refusal when a configured policy cannot approve the event.
    pub async fn authorize_policy(
        &self,
        room_id: &str,
        event: &mut Value,
    ) -> Result<(), RoomError> {
        if crate::policy::exempt(event) {
            return Ok(());
        }
        let policy = match self.policy_server(room_id) {
            Ok(policy) => policy,
            Err(RoomError::UnknownRoom(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        if let Some(policy) = policy {
            let version = self.room_version(room_id)?;
            if policy.verifies(event, &version) {
                return Ok(());
            }
            let federation = self
                .policy_federation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .ok_or_else(|| RoomError::Forbidden("policy signing is unavailable".to_owned()))?;
            policy.authorize(event, &version, &federation).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_policy_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: Option<&str>,
        content: &Value,
        sticky_ms: Option<u64>,
    ) -> Result<String, RoomError> {
        // Preserve the single-lock path when no policy is active. Recheck
        // under the write guard so enabling a policy cannot race the send.
        let direct = self.with_room(room_id, |rooms, log| {
            if !crate::policy::exempt(
                &serde_json::json!({"type": event_type, "state_key": state_key}),
            ) && rooms.policy_in(log, room_id)?.is_some()
            {
                return Ok(None);
            }
            let mut content = content.clone();
            if event_type == "m.room.member" && content["membership"].as_str() == Some("join") {
                if rooms.room_block(room_id)?.is_some() {
                    return Err(RoomError::Forbidden(
                        "this room is blocked by a server administrator".to_owned(),
                    ));
                }
                if let Some(target) = state_key
                    && let Some(nominee) = rooms.restricted_join_nominee(log, room_id, target)?
                {
                    content["join_authorised_via_users_server"] = Value::String(nominee);
                }
            }
            rooms
                .append_with(
                    log, room_id, sender, key, event_type, state_key, &content, sticky_ms,
                )
                .map(Some)
        })?;
        if let Some(id) = direct {
            return Ok(id);
        }
        // Rebuild when room state changes while approval is in flight. A
        // timeline-only append can change parents without changing authorization;
        // keeping those signed parents lets a busy room make progress.
        for _ in 0..3 {
            let (event_id, mut event, head) = self.with_room(room_id, |rooms, log| {
                let mut content = content.clone();
                if event_type == "m.room.member" && content["membership"].as_str() == Some("join") {
                    if rooms.room_block(room_id)?.is_some() {
                        return Err(RoomError::Forbidden(
                            "this room is blocked by a server administrator".to_owned(),
                        ));
                    }
                    if let Some(target) = state_key
                        && let Some(nominee) =
                            rooms.restricted_join_nominee(log, room_id, target)?
                    {
                        content["join_authorised_via_users_server"] = Value::String(nominee);
                    }
                }
                let (id, event) = rooms.build_event(
                    log, room_id, sender, key, event_type, state_key, &content, sticky_ms,
                )?;
                Ok((
                    id,
                    event,
                    log.current_state().map(super::StateSnapshot::root),
                ))
            })?;
            self.authorize_policy(room_id, &mut event).await?;
            let done = self.with_room(room_id, |rooms, log| {
                if log.current_state().map(super::StateSnapshot::root) != head {
                    return Ok(None);
                }
                if event_type == "m.room.member"
                    && event["content"]["membership"].as_str() == Some("join")
                    && rooms.room_block(room_id)?.is_some()
                {
                    return Err(RoomError::Forbidden(
                        "this room is blocked by a server administrator".to_owned(),
                    ));
                }
                rooms
                    .commit_event(
                        log,
                        room_id,
                        sender,
                        event_type,
                        state_key,
                        &event["content"],
                        &event_id,
                        &event,
                    )
                    .map(Some)
            })?;
            if let Some(id) = done {
                return Ok(id);
            }
        }
        Err(RoomError::Forbidden(
            "room changed while obtaining policy approval; retry the event".to_owned(),
        ))
    }

    /// Send a timeline event with policy approval before persistence/publication.
    ///
    /// # Errors
    /// Returns authorization, policy, signing or storage errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_sticky_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        content: &Value,
        sticky_ms: Option<u64>,
    ) -> Result<String, RoomError> {
        self.append_policy_checked(room_id, sender, key, event_type, None, content, sticky_ms)
            .await
    }

    /// Send with room policy approval.
    ///
    /// # Errors
    /// Returns authorization, policy or storage errors.
    pub async fn send_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        content: &Value,
    ) -> Result<String, RoomError> {
        self.send_sticky_checked(room_id, sender, key, event_type, content, None)
            .await
    }

    /// Set state with room policy approval.
    ///
    /// # Errors
    /// Returns authorization, policy or storage errors.
    pub async fn set_state_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: &str,
        content: &Value,
    ) -> Result<String, RoomError> {
        self.set_state_sticky_checked(room_id, sender, key, event_type, state_key, content, None)
            .await
    }

    /// Set state through the same policy path as timeline events.
    ///
    /// # Errors
    /// Returns authorization, policy, signing or storage errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_state_sticky_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        event_type: &str,
        state_key: &str,
        content: &Value,
        sticky_ms: Option<u64>,
    ) -> Result<String, RoomError> {
        let content = super::sanitized_member_content(event_type, content);
        self.append_policy_checked(
            room_id,
            sender,
            key,
            event_type,
            Some(state_key),
            &content,
            sticky_ms,
        )
        .await
    }

    /// Change membership, retaining restricted-join nomination and room blocks.
    ///
    /// # Errors
    /// Returns authorization, policy, signing or storage errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_membership_with_checked(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        membership: &str,
        reason: Option<&str>,
        extra: &serde_json::Map<String, Value>,
        key: &Ed25519KeyPair,
    ) -> Result<String, RoomError> {
        let mut content = Value::Object(extra.clone());
        content["membership"] = Value::String(membership.to_owned());
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_owned());
        }
        self.append_policy_checked(
            room_id,
            sender,
            key,
            "m.room.member",
            Some(target),
            &content,
            None,
        )
        .await
    }

    /// Change membership without additional profile fields.
    ///
    /// # Errors
    /// Returns authorization, policy, signing or storage errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_membership_checked(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        membership: &str,
        reason: Option<&str>,
        key: &Ed25519KeyPair,
    ) -> Result<String, RoomError> {
        self.set_membership_with_checked(
            room_id,
            sender,
            target,
            membership,
            reason,
            &serde_json::Map::new(),
            key,
        )
        .await
    }

    /// Prepare the policy-approved invite before its remote co-signing handshake.
    ///
    /// # Errors
    /// Returns authorization, policy, signing or storage errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_invite_event_checked(
        &self,
        room_id: &str,
        sender: &str,
        target: &str,
        reason: Option<&str>,
        is_direct: bool,
        key: &Ed25519KeyPair,
    ) -> Result<(String, Value), RoomError> {
        let (id, mut event) =
            self.build_invite_event(room_id, sender, target, reason, is_direct, key)?;
        self.authorize_policy(room_id, &mut event).await?;
        Ok((id, event))
    }

    /// Redact only after policy approval and durable event commit.
    ///
    /// # Errors
    /// Returns missing-event, authorization, policy, signing or storage errors.
    pub async fn redact_checked(
        &self,
        room_id: &str,
        sender: &str,
        key: &Ed25519KeyPair,
        target: &str,
        reason: Option<&str>,
    ) -> Result<String, RoomError> {
        let known = self.with_room_read(room_id, |_, log| {
            Ok(log.get(&super::EventId::new(target)).is_some())
        })? || self.gap_position(room_id, target)?.is_some();
        if !known {
            return Err(RoomError::MissingBody(target.to_owned()));
        }
        let mut content = serde_json::json!({"redacts": target});
        if let Some(reason) = reason {
            content["reason"] = Value::String(reason.to_owned());
        }
        let id = self
            .append_policy_checked(
                room_id,
                sender,
                key,
                "m.room.redaction",
                None,
                &content,
                None,
            )
            .await?;
        self.apply_redaction(room_id, target, &id)?;
        Ok(id)
    }

    /// Commit a live remote event; approval is checked again under the guard.
    ///
    /// # Errors
    /// Returns policy or ordinary receipt errors.
    pub fn receive_live(
        &self,
        room_id: &str,
        event_id: &str,
        event: &Value,
    ) -> Result<(), RoomError> {
        match self.with_room(room_id, |rooms, log| {
            if log.get(&super::EventId::new(event_id)).is_some() {
                return Ok(());
            }
            rooms.ingest_checked(log, room_id, event_id, event, false, true)
        }) {
            Err(RoomError::UnknownRoom(_)) => self.receive_remote(room_id, event_id, event),
            result => result,
        }
    }
}
