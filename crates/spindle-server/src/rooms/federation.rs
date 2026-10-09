//! The room as a peer sees it: what this server serves to another server
//! and what it takes from one.
//!
//! Serving: whether a domain is in the room, the `make_join`/`make_knock`/
//! `make_leave` templates, backfill, missing events, the state at an event,
//! the stripped state an invite carries, and the domains to fan out to.
//! Taking: a remote room's events on join, a peer's PDU, and an event a
//! resident co-signed. The outbound client (`crate::federation`) does the
//! talking; the inbound handlers (`crate::inbound`) do the checking; this
//! is what either asks the room for.
//!
//! A child of `rooms`, like `unread` and `admin`: one `impl Rooms` block
//! reading the parent's private fields and helpers, so this is a file split
//! of that block (#311) and not a new boundary yet.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use serde_json::Value;
use spindle_core::{EventId, EventInput, LogEntry, Pdu, RoomLog, StateKey};
use spindle_store::RoomStore;

use super::{
    INVITE_STR, IdentifiedEvent, JOIN_STR, PersistInput, RoomError, Rooms, auth_events_for,
    event_body_key, version_in,
};

/// The `cause` a remote join's gap marker carries ([`Rooms::record_join_gap`]).
pub const JOIN_GAP_CAUSE: &str = "remote_join";

/// The most history events backfilled after a remote join: a bounded first
/// window, not the whole room. Far less than `gap_backfill_max_events`,
/// because every join of a large room would otherwise fetch that much.
pub const JOIN_HISTORY_EVENTS: u64 = 1_000;

impl Rooms {
    /// Whether `domain` has a joined member in the room right now.
    ///
    /// The federation read paths gate on this: room state and history
    /// belong to the servers in the room, and "in" means a joined member,
    /// not an invite and not a memory.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or its indexes cannot be read.
    pub fn server_in_room(&self, room_id: &str, domain: &str) -> Result<bool, RoomError> {
        let members = self.with_room_read(room_id, |_, log| {
            let Some(state) = log.current_state() else {
                return Ok(Vec::new());
            };
            let mut members = Vec::new();
            state.for_each(|state_key, _| {
                if state_key.event_type().as_str() == "m.room.member"
                    && state_key
                        .state_key()
                        .split_once(':')
                        .is_some_and(|(_, d)| d == domain)
                {
                    members.push(state_key.state_key().to_owned());
                }
            });
            Ok(members)
        })?;
        for user_id in members {
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    &user_id,
                    room_id,
                ),
            )?;
            if membership.as_deref() == Some(JOIN_STR.as_bytes()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Dependencies of a received event that this room does not hold yet.
    /// Predecessors need a position and state; auth events need a body only.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room or dependency bodies cannot be read.
    pub fn missing_remote_dependencies(
        &self,
        room_id: &str,
        event: &Value,
    ) -> Result<(Vec<String>, Vec<String>), RoomError> {
        self.with_room_read(room_id, |rooms, log| {
            let mut predecessors = super::edge_ids(&event["prev_events"]);
            if spindle_core::is_state_dag(&rooms.version_in_log(log, room_id)?) {
                predecessors.extend(super::edge_ids(&event["prev_state_events"]));
            }
            predecessors.sort();
            predecessors.dedup();
            predecessors.retain(|id| {
                let id = EventId::new(id.as_str());
                log.get(&id).is_none() && log.sidelined(&id).is_none()
            });
            let mut auth = Vec::new();
            for id in super::edge_ids(&event["auth_events"]) {
                match rooms.read_event(room_id, &EventId::new(id.as_str())) {
                    Ok(_) => {}
                    Err(RoomError::MissingBody(_)) => auth.push(id),
                    Err(error) => return Err(error),
                }
            }
            Ok((predecessors, auth))
        })
    }

    /// The current forward extremities to delimit a missing-event window.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room cannot be read.
    pub fn remote_recovery_heads(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log
                .forward_extremities()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect())
        })
    }

    /// Retain signature-verified auth dependencies without timeline or client
    /// indexes. The caller verifies signatures before this synchronous step;
    /// this step verifies IDs, room ownership and the cited auth rules.
    /// Existing bodies and Synapse rejection decisions are never overwritten.
    ///
    /// # Errors
    /// Returns [`RoomError`] for malformed, foreign-room or unauthorized
    /// dependencies, an incomplete/cyclic auth chain, or an atomic write failure.
    #[allow(
        clippy::too_many_lines,
        reason = "validate the entire auth batch before one atomic commit"
    )]
    pub fn retain_remote_auth(
        &self,
        room_id: &str,
        events: &[(String, Value)],
    ) -> Result<(), RoomError> {
        use ruma::state_res::events::Event as _;
        use spindle_store::Store as _;
        use std::collections::BTreeMap;

        self.with_room(room_id, |rooms, log| {
            let version = rooms.version_in_log(log, room_id)?;
            if spindle_core::is_state_dag(&version) {
                return Err(RoomError::Append(
                    "state-DAG dependencies require predecessor state".to_owned(),
                ));
            }
            let rules = rooms.rules_in(log, room_id)?;
            let create_id = log
                .current_state()
                .and_then(|state| state.get(&StateKey::new("m.room.create", "")))
                .ok_or_else(|| RoomError::Append("the room has no create event".to_owned()))?
                .to_owned();
            let mut pending = BTreeMap::new();
            for (id, body) in events {
                match rooms.read_event(room_id, &EventId::new(id.as_str())) {
                    Ok(_) => continue,
                    Err(RoomError::MissingBody(_)) => {}
                    Err(error) => return Err(error),
                }
                if let Some(held_room) = spindle_store::ReadView::get(
                    rooms.store.as_ref(),
                    &spindle_core::keys::event_room(id),
                )? && held_room != room_id.as_bytes()
                {
                    return Err(RoomError::Forbidden(
                        "auth event ID is already held in another room".to_owned(),
                    ));
                }
                let ruma::CanonicalJsonValue::Object(canonical) =
                    ruma::CanonicalJsonValue::try_from(body.clone())
                        .map_err(|error| RoomError::Build(error.to_string()))?
                else {
                    return Err(RoomError::Build("auth event is not an object".to_owned()));
                };
                let pdu = Pdu::from_remote(version.clone(), canonical)
                    .map_err(|error| RoomError::Build(format!("auth event: {error:?}")))?;
                if pdu.event_id().as_str() != id {
                    return Err(RoomError::Build(
                        "auth event ID does not match its body".to_owned(),
                    ));
                }
                let candidate = crate::authorize::StoredEvent::parse_in(id, room_id, body)
                    .map_err(RoomError::Build)?;
                if candidate.room_id().map(ruma::RoomId::as_str) != Some(room_id)
                    || candidate.state_key().is_none()
                {
                    return Err(RoomError::Forbidden(
                        "auth dependency is not state in this room".to_owned(),
                    ));
                }
                if candidate.event_type() == &ruma::events::TimelineEventType::RoomCreate
                    && id != &create_id
                {
                    return Err(RoomError::Forbidden(
                        "auth dependency replaces the room's create event".to_owned(),
                    ));
                }
                pending
                    .entry(id.clone())
                    .or_insert((body.clone(), candidate));
            }
            let mut accepted: BTreeMap<String, crate::authorize::StoredEvent> = BTreeMap::new();
            let mut writes = Vec::new();
            while !pending.is_empty() {
                let ready: Vec<String> = pending
                    .iter()
                    .filter(|(_, (_, event))| {
                        event
                            .auth_event_ids()
                            .iter()
                            .all(|auth| !pending.contains_key(auth.as_str()))
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                if ready.is_empty() {
                    return Err(RoomError::Forbidden(
                        "auth dependencies contain a cycle".to_owned(),
                    ));
                }
                for id in ready {
                    let (body, candidate) = pending
                        .remove(&id)
                        .ok_or_else(|| RoomError::Build("ready auth event is absent".to_owned()))?;
                    let fetch = |auth: &ruma::EventId| {
                        if let Some(event) = accepted.get(auth.as_str()) {
                            return Some(event.clone());
                        }
                        let body = rooms
                            .read_event(room_id, &EventId::new(auth.as_str()))
                            .ok()?;
                        let event = crate::authorize::StoredEvent::parse_auth_in(
                            auth.as_str(),
                            room_id,
                            &body,
                        )
                        .ok()?;
                        let rejected = log
                            .sidelined(&EventId::new(auth.as_str()))
                            .is_some_and(|entry| entry.kind == spindle_core::Sideline::Rejected);
                        Some(event.with_rejected(rejected).with_preserved_rejection(
                            log.historically_rejected(&EventId::new(auth.as_str())),
                        ))
                    };
                    ruma::state_res::check_state_independent_auth_rules(
                        &rules.authorization,
                        candidate.clone(),
                        fetch,
                    )
                    .map_err(|why| RoomError::Forbidden(format!("recovered auth events: {why}")))?;
                    let mut named = std::collections::HashMap::new();
                    for auth in candidate.auth_event_ids() {
                        let event =
                            fetch(auth).ok_or_else(|| RoomError::MissingBody(auth.to_string()))?;
                        if event.event_type() == &ruma::events::TimelineEventType::RoomCreate
                            && auth.as_str() != create_id
                        {
                            return Err(RoomError::Forbidden(
                                "auth chain uses another create event".to_owned(),
                            ));
                        }
                        if let Some(key) = event.state_key() {
                            named.insert(
                                (
                                    ruma::events::StateEventType::from(
                                        event.event_type().to_string(),
                                    ),
                                    key.to_owned(),
                                ),
                                event,
                            );
                        }
                    }
                    if rules.authorization.room_create_event_id_as_room_id {
                        let create = ruma::OwnedEventId::try_from(create_id.as_str())
                            .map_err(|error| RoomError::Build(error.to_string()))?;
                        let event = fetch(&create)
                            .ok_or_else(|| RoomError::MissingBody(create_id.clone()))?;
                        named.insert(
                            (ruma::events::StateEventType::RoomCreate, String::new()),
                            event,
                        );
                    }
                    crate::authorize::authorize(&rules.authorization, &candidate, |kind, key| {
                        named
                            .get(&(kind.clone(), key.to_owned()))
                            .filter(|event| !event.rejected())
                            .cloned()
                    })
                    .map_err(RoomError::Forbidden)?;
                    writes.push((event_body_key(room_id, &id), serde_json::to_vec(&body)?));
                    writes.push((
                        spindle_core::keys::event_room(&id),
                        room_id.as_bytes().to_vec(),
                    ));
                    accepted.insert(id, candidate);
                }
            }
            rooms
                .store
                .commit(&writes, spindle_store::Durability::Group)?;
            Ok(())
        })
    }

    /// Accept a verified remote event whose predecessors could not be
    /// recovered, on the state before it that a participating server named
    /// (`/state_ids`), as a forward event across a gap in this room's
    /// history.
    ///
    /// The caller has already fetched, verified and retained (via
    /// [`Self::retain_remote_auth`]) every state and auth-chain event that
    /// `state_before` names; this step is synchronous, under the room lock,
    /// and runs the same receipt checks as [`Self::receive_remote`] -- the
    /// event's own auth events, then the state before it (here the peer's,
    /// since its parents' states are not ours to compute), then the room's
    /// current state -- before placing it with
    /// [`RoomLog::append_across_gap`]. The room's existing head stays a
    /// forward extremity beside the new event, and [`Self::settle`]
    /// re-resolves the current state over both, so the peer's view of the
    /// room never simply replaces ours: it is merged by the room version's
    /// algorithm, as any fork is.
    ///
    /// Nothing is sidelined on a failed check: an event whose parents are
    /// unknown has nowhere to be kept outside the timeline. It is refused,
    /// and a redelivery is judged again.
    ///
    /// The gap itself -- the history between the predecessors this server
    /// lacks and what it holds -- is not filled here. A marker is written
    /// under [`spindle_core::keys::federation_gap`] naming the missing
    /// predecessors, for a later backfill to start from.
    ///
    /// The background backfill (`crate::inbound::backfill`) walks each
    /// marker's missing predecessors back with `/backfill` (SPEC §6.5: one
    /// `/state_ids` per chunk), stores that history as the gap's segment
    /// ([`Self::commit_gap_chunk`]), and clears the marker once the walk
    /// meets history this server already holds.
    ///
    /// Returns the predecessors the event named that this server does not
    /// hold, or `None` when nothing needed bridging -- the event was
    /// already held, or its parents arrived meanwhile and it took the
    /// ordinary path.
    ///
    /// # Errors
    ///
    /// [`RoomError::Forbidden`] when the state is malformed, names a
    /// rejected event or another create event, or the event fails a receipt
    /// check; [`RoomError::MissingBody`] for a state event the caller did
    /// not retain; [`RoomError::Append`] for a state-DAG room, whose state
    /// cannot be taken from `/state_ids`.
    #[allow(
        clippy::too_many_lines,
        reason = "the receipt checks and placement of one event, in order"
    )]
    pub fn accept_across_gap(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
        state_before: &[String],
        state_from: &str,
    ) -> Result<Option<Vec<String>>, RoomError> {
        use spindle_core::{Sideline, StateSnapshot};
        use spindle_store::Store as _;

        self.with_room(room_id, |rooms, log| {
            let id = EventId::new(event_id);
            if log.get(&id).is_some() {
                return Ok(None);
            }
            if log.historically_rejected(&id) {
                return Err(RoomError::Forbidden(format!(
                    "rejected: {event_id} was rejected before migration"
                )));
            }
            if let Some(sidelined) = log.sidelined(&id) {
                return Err(RoomError::Forbidden(match sidelined.kind {
                    Sideline::SoftFailed => format!("{event_id} was soft-failed"),
                    Sideline::Rejected => format!("{event_id} was rejected"),
                }));
            }
            let version = rooms.version_in_log(log, room_id)?;
            if spindle_core::is_state_dag(&version) {
                return Err(RoomError::Append(
                    "a state-DAG room's state cannot be taken from /state_ids".to_owned(),
                ));
            }
            let prev: Vec<EventId> = super::edge_ids(&json["prev_events"])
                .into_iter()
                .map(EventId::new)
                .collect();
            let missing: Vec<String> = prev
                .iter()
                .filter(|parent| !log.holds(parent))
                .map(|parent| parent.as_str().to_owned())
                .collect();
            if missing.is_empty() {
                // Recovery or another PDU filled the gap meanwhile: the
                // ordinary path, with our own state, is the right one.
                rooms.ingest(log, room_id, event_id, json, false)?;
                return Ok(None);
            }

            // The peer's state before the event, keyed by what each named
            // body says it is. Every body was verified and retained by the
            // caller; a rejected or foreign one is refused, not skipped,
            // because a state that silently loses entries is a different
            // state from the one the peer vouched for.
            let create_id = log
                .current_state()
                .and_then(|state| state.get(&StateKey::new("m.room.create", "")))
                .ok_or_else(|| RoomError::Append("the room has no create event".to_owned()))?
                .to_owned();
            let mut state = StateSnapshot::new();
            for state_id in state_before {
                if state_id == event_id {
                    continue;
                }
                let held = EventId::new(state_id.as_str());
                if log.historically_rejected(&held)
                    || log
                        .sidelined(&held)
                        .is_some_and(|entry| entry.kind == Sideline::Rejected)
                {
                    return Err(RoomError::Forbidden(format!(
                        "the peer's state names {state_id}, which this room rejected"
                    )));
                }
                let body = rooms.read_event(room_id, &held)?;
                let (Some(kind), Some(state_key)) =
                    (body["type"].as_str(), body["state_key"].as_str())
                else {
                    return Err(RoomError::Forbidden(format!(
                        "the peer's state names {state_id}, which is not a state event"
                    )));
                };
                if kind == "m.room.create" && state_id != &create_id {
                    return Err(RoomError::Forbidden(
                        "the peer's state names another create event".to_owned(),
                    ));
                }
                let key = StateKey::new(kind, state_key);
                if state.get(&key).is_some_and(|other| other != state_id) {
                    return Err(RoomError::Forbidden(format!(
                        "the peer's state names two events for {kind}/{state_key}"
                    )));
                }
                state = state.apply(key, state_id.as_str());
            }
            if state
                .get(&StateKey::new("m.room.create", ""))
                .is_none_or(|named| named != create_id)
            {
                return Err(RoomError::Forbidden(
                    "the peer's state does not name this room's create event".to_owned(),
                ));
            }

            // Check 3's "current state", as Synapse computes it across a
            // gap: our extremities' states resolved together with the
            // peer's. Our own current state is stale by the length of the
            // gap -- a member who joined in it is unknown to it -- while a
            // ban that reached either side still lands in the resolution,
            // so a gap manufactured to dodge one does not dodge it.
            let tips: Vec<EventId> = log.forward_extremities().iter().cloned().collect();
            let current = rooms.resolve_in(log, room_id, |log, resolver, load| {
                let mut states: Vec<StateSnapshot> = Vec::with_capacity(tips.len() + 1);
                for tip in &tips {
                    let tip_state = log.state_after_any(tip, load)?;
                    if !states.iter().any(|held| held.root() == tip_state.root()) {
                        states.push(tip_state);
                    }
                }
                if !states.iter().any(|held| held.root() == state.root()) {
                    states.push(state.clone());
                }
                if states.len() == 1 {
                    return Ok(states.pop().unwrap_or_default());
                }
                resolver.resolve(&states)
            })?;
            if let Some((kind, reason)) =
                rooms.receipt_checks(log, room_id, event_id, json, &state, &prev, Some(&current))?
            {
                return Err(RoomError::Forbidden(match kind {
                    Sideline::SoftFailed => {
                        format!("soft-failed against the current state: {reason}")
                    }
                    Sideline::Rejected => format!("rejected: {reason}"),
                }));
            }
            let redaction_target = rooms.redaction_target(log, room_id, json)?;

            let event_type = json["type"].as_str().unwrap_or_default().to_owned();
            let state_key = json["state_key"].as_str().map(str::to_owned);
            let sender = json["sender"].as_str().unwrap_or_default().to_owned();
            let input = EventInput::new(event_id, prev);
            let input = match &state_key {
                Some(state_key) => {
                    input.with_state_key(StateKey::new(event_type.as_str(), state_key.as_str()))
                }
                None => input,
            };
            let previous_current = log.current_state().cloned();
            let previous_tips = log.forward_extremities().clone();
            let entry = log
                .append_across_gap(input, state, json["depth"].as_u64().unwrap_or(0))
                .map_err(|error| rooms.append_error(&error))?
                .clone();
            rooms.metrics.record_append(
                crate::metrics::Origin::Federated,
                super::case_of(state_key.is_some(), false),
            );
            let content = json["content"].clone();
            rooms.persist_entry(
                log,
                room_id,
                &entry,
                event_id,
                &PersistInput {
                    event_type: &event_type,
                    state_key: state_key.as_deref(),
                    sender: &sender,
                    content: &content,
                    json,
                },
            )?;
            // Two extremities now, ours and the peer's: their resolution is
            // the room's current state, and every membership it moved is
            // re-indexed from it.
            rooms.settle(log, room_id, Some(&entry), previous_current, &previous_tips)?;
            if let Some(target) = redaction_target {
                if log.get(&EventId::new(target.as_str())).is_some()
                    || rooms.gap_position(room_id, &target)?.is_some()
                {
                    rooms.apply_redaction(room_id, &target, event_id)?;
                } else {
                    rooms.note_unheld_redaction(log, room_id, &target, event_id, json)?;
                }
            }

            // The marker is advisory -- the event is placed and durable
            // whether or not it lands -- so a failed write is reported, not
            // turned into a refusal of an event already in the timeline.
            let marker = serde_json::json!({
                "event_id": event_id,
                "missing_prev_events": missing,
                "state_from": state_from,
                "li": entry.li.get(),
                "accepted_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
            });
            if let Err(error) = rooms.store.put(
                &spindle_core::keys::federation_gap(room_id, event_id),
                marker.to_string().as_bytes(),
            ) {
                tracing::warn!(
                    room = room_id,
                    event_id,
                    "cannot record a federation gap marker: {error}"
                );
            }
            Ok(Some(missing))
        })
    }

    /// The federation gaps recorded in a room by
    /// [`Self::accept_across_gap`] and not yet filled: one marker per
    /// event accepted across a gap, naming the predecessors it lacked.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the markers cannot be read.
    pub fn federation_gaps(&self, room_id: &str) -> Result<Vec<Value>, RoomError> {
        let prefix =
            spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::FederationGap, room_id);
        Ok(
            spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?
                .into_iter()
                .filter_map(|(_, value)| serde_json::from_slice(&value).ok())
                .collect(),
        )
    }

    /// Record the history a remote join did not bring as a federation gap
    /// (#461), so the background backfill fills it.
    ///
    /// `send_join` carries the room's state and auth chain, not its
    /// timeline. The history before the join is filled the way an event
    /// accepted across a gap is filled (SPEC §6.6): a marker anchored at the
    /// join, and the backfill loop walks back from the join's
    /// `prev_events`. Unlike that gap, the walk passes through the events
    /// the join seeded ([`Self::gap_unheld_through`]): a predecessor that is
    /// current state, such as the joiner's own invite, is not the end of
    /// the history. The walk stops at the create event, or after
    /// [`JOIN_HISTORY_EVENTS`] events.
    ///
    /// Nothing is recorded when the seeded events are all the history
    /// there is: every `prev_event` is held, and the join is no deeper
    /// than the number of seeded events. A new room of state events only
    /// is like that, and asking a peer for its history would be a wasted
    /// request. Returns whether a gap was recorded.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room cannot be read, the join is not in
    /// its log, or the marker cannot be written.
    pub fn record_join_gap(
        &self,
        room_id: &str,
        join: &Value,
        join_id: &str,
        state_from: &str,
    ) -> Result<bool, RoomError> {
        use spindle_store::Store as _;

        let prev = super::edge_ids(&join["prev_events"]);
        let (li, state_dag, all_held) = self.with_room_read(room_id, |rooms, log| {
            let entry = log
                .get(&EventId::new(join_id))
                .ok_or_else(|| RoomError::UnknownState(format!("the join {join_id}")))?;
            let version = rooms.version_in_log(log, room_id)?;
            let all_held = prev
                .iter()
                .all(|id| log.get(&EventId::new(id.as_str())).is_some());
            Ok((
                entry.li.get(),
                spindle_core::is_state_dag(&version),
                all_held,
            ))
        })?;
        // A state-DAG room's history cannot be folded from `/state_ids`,
        // so the backfill loop could not fill the gap.
        if state_dag {
            return Ok(false);
        }
        // Every depth from 1 to the join's parents' depth has an event. If
        // the join seeded fewer events than that, some history is missing.
        let seeded = u64::try_from(li.saturating_sub(1)).unwrap_or(0);
        let parents_depth = join["depth"].as_u64().unwrap_or(0).saturating_sub(1);
        if all_held && parents_depth <= seeded {
            return Ok(false);
        }
        let frontier = self.gap_unheld_through(room_id, &prev, Some(li))?;
        if frontier.is_empty() {
            return Ok(false);
        }
        let marker = serde_json::json!({
            "event_id": join_id,
            "missing_prev_events": frontier,
            "state_from": state_from,
            "li": li,
            "cause": JOIN_GAP_CAUSE,
            "max_events": JOIN_HISTORY_EVENTS,
            "accepted_ts": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
        });
        self.store.put(
            &spindle_core::keys::federation_gap(room_id, join_id),
            marker.to_string().as_bytes(),
        )?;
        Ok(true)
    }

    /// A join-event template for a remote user, for `make_join`.
    ///
    /// The template is everything but the signature: the caller's server
    /// signs it and brings it back through `send_join`. Authorization is
    /// previewed here — public join rule, a standing invite, or a
    /// restricted room this server can vouch the joiner into — so a refused
    /// server learns at the cheap step, but the template is not a promise:
    /// the signed event is authorized again on the way in, against whatever
    /// the state is *then*.
    ///
    /// The restricted case is the one where the preview carries something
    /// the joining server could not have worked out: `restricted_join_nominee`
    /// puts the authorising user into the content, and that field is the
    /// entire basis on which the rules will accept the join.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the rules do not admit the user.
    pub fn make_join_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        if self.room_block(room_id)?.is_some() {
            return Err(RoomError::Forbidden(
                "this room is blocked by a server administrator".to_owned(),
            ));
        }
        self.with_room(room_id, |rooms, log| {
            // What this server would author on itself: the newest forward
            // extremities, and the state they resolve to.
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let parents: Vec<EventId> = log.authoring_extremities().cloned().collect();
            let (state, _) = rooms.state_for_parents(log, room_id, &parents)?;

            // `read_event`, not `event()`: the latter re-enters `with_room`
            // on a lock this closure already holds.
            let join_rule = state
                .get(&StateKey::new("m.room.join_rules", ""))
                .map(str::to_owned)
                .and_then(|id| rooms.read_event(room_id, &EventId::new(id.as_str())).ok())
                .and_then(|event| event["content"]["join_rule"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "invite".to_owned());
            let invited = spindle_store::ReadView::get(
                rooms.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    user_id,
                    room_id,
                ),
            )?
            .as_deref()
                == Some(INVITE_STR.as_bytes());
            // A restricted room is the third way in, and it was missing:
            // the joiner is in a room this room admits, and this server can
            // see that. The nomination is the *only* record of it, so it
            // goes into the template -- the joining server signs what we
            // hand back, and `send_join` and every peer after it check the
            // nomination rather than taking our word for the join.
            let nominee = rooms.restricted_join_nominee(log, room_id, user_id)?;
            if join_rule != "public" && !invited && nominee.is_none() {
                return Err(RoomError::Forbidden(
                    "the room is not public, and the user holds no invite and                      is in no room it admits"
                        .to_owned(),
                ));
            }

            let mut content = serde_json::json!({ "membership": "join" });
            if let Some(nominee) = nominee {
                content["join_authorised_via_users_server"] = Value::String(nominee);
            }
            let auth = auth_events_for(
                Some(&state),
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = parents.iter().map(|id| id.as_str().to_owned()).collect();
            let depth = head.depth.saturating_add(1);
            let mut template = serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            });
            rooms.link_template(log, room_id, &mut template, &prev, &auth, depth)?;
            Ok(template)
        })
    }

    /// A knock-event template for a remote user, for `make_knock`.
    ///
    /// The precondition mirrors the auth rule that will judge the signed
    /// event on the way back in: the room's join rule must be `knock`, or
    /// MSC3787's `knock_restricted`, which admits a knock on the same
    /// terms and a join on restricted ones. Anything else is refused here,
    /// at the cheap step.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the room does not accept knocks.
    pub fn make_knock_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        self.with_room(room_id, |rooms, log| {
            // Knocking arrived in v7. In an older room a `knock` join rule
            // is a value the rules do not know and a knock membership is
            // refused outright, so the template would be a promise the
            // version cannot keep -- refused here, as Synapse does, at the
            // cheap step.
            if !rooms.rules_in(log, room_id)?.authorization.knocking {
                return Err(RoomError::Forbidden(
                    "this room's version does not support knocking".to_owned(),
                ));
            }
            // What this server would author on itself: the newest forward
            // extremities, and the state they resolve to.
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let parents: Vec<EventId> = log.authoring_extremities().cloned().collect();
            let (state, _) = rooms.state_for_parents(log, room_id, &parents)?;
            let join_rule = state
                .get(&StateKey::new("m.room.join_rules", ""))
                .map(str::to_owned)
                .and_then(|id| rooms.read_event(room_id, &EventId::new(id.as_str())).ok())
                .and_then(|event| event["content"]["join_rule"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "invite".to_owned());
            if !matches!(join_rule.as_str(), "knock" | "knock_restricted") {
                return Err(RoomError::Forbidden(
                    "the room does not accept knocks".to_owned(),
                ));
            }

            let content = serde_json::json!({ "membership": "knock" });
            let auth = auth_events_for(
                Some(&state),
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = parents.iter().map(|id| id.as_str().to_owned()).collect();
            let depth = head.depth.saturating_add(1);
            let mut template = serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            });
            rooms.link_template(log, room_id, &mut template, &prev, &auth, depth)?;
            Ok(template)
        })
    }

    /// A leave-event template for a remote user, for `make_leave`.
    ///
    /// The mirror of [`Self::make_join_template`], with the mirrored
    /// precondition: there must be a membership to leave — an invite being
    /// rejected, a join being ended, a knock withdrawn. A template for a
    /// stranger would let any server manufacture departures for users who
    /// were never here.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] when the room is not here,
    /// [`RoomError::Forbidden`] when the user has nothing to leave.
    pub fn make_leave_template(&self, room_id: &str, user_id: &str) -> Result<Value, RoomError> {
        self.with_room(room_id, |rooms, log| {
            // What this server would author on itself: the newest forward
            // extremities, and the state they resolve to.
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let parents: Vec<EventId> = log.authoring_extremities().cloned().collect();
            let (state, _) = rooms.state_for_parents(log, room_id, &parents)?;
            let membership = spindle_store::ReadView::get(
                self.store.as_ref(),
                &spindle_core::keys::user_room(
                    spindle_core::keys::Keyspace::Membership,
                    user_id,
                    room_id,
                ),
            )?;
            let leavable = matches!(membership.as_deref(), Some(b"invite" | b"join" | b"knock"));
            if !leavable {
                return Err(RoomError::Forbidden(
                    "the user has no membership to leave".to_owned(),
                ));
            }

            let content = serde_json::json!({ "membership": "leave" });
            let auth = auth_events_for(
                Some(&state),
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = parents.iter().map(|id| id.as_str().to_owned()).collect();
            let depth = head.depth.saturating_add(1);
            let mut template = serde_json::json!({
                "type": "m.room.member",
                "sender": user_id,
                "state_key": user_id,
                "room_id": room_id,
                "content": content,
                "origin_server_ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            });
            rooms.link_template(log, room_id, &mut template, &prev, &auth, depth)?;
            Ok(template)
        })
    }

    /// History walking backwards from the given events, newest first —
    /// federation backfill.
    ///
    /// The linear log makes this a range read: the starting point is the
    /// newest of the named events, and "backwards" is the log itself. The
    /// named events are included, the way a paginating server expects.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for,
    /// [`RoomError::MissingBody`] when none of the named events are in it.
    pub fn backfill(
        &self,
        room_id: &str,
        from: &[String],
        limit: usize,
    ) -> Result<Vec<Value>, RoomError> {
        self.with_room(room_id, |rooms, log| {
            let start = from
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .max()
                .ok_or_else(|| RoomError::MissingBody(from.join(", ")))?;
            log.entries()
                .rev()
                .filter(|entry| entry.li <= start)
                .take(limit)
                // The stored PDU as signed: see `Rooms::pdu` for why no
                // `event_id` is added.
                .map(|entry| rooms.read_event(room_id, &entry.event_id))
                .collect()
        })
    }

    /// The events between `earliest` (theirs) and `latest` (the ones whose
    /// ancestry they are missing) — federation catch-up.
    ///
    /// Exclusive on both ends: they have `earliest`, and they are holding
    /// `latest`. When the gap is wider than `limit`, the events closest to
    /// `latest` win — those are the ones that let the requester connect the
    /// history they are actually holding; the rest they can backfill.
    /// Returned oldest first.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for.
    pub fn missing_events(
        &self,
        room_id: &str,
        earliest: &[String],
        latest: &[String],
        limit: usize,
        min_depth: u64,
        state_dag: bool,
    ) -> Result<Vec<Value>, RoomError> {
        if state_dag {
            return self.missing_state_events(room_id, earliest, latest);
        }
        self.with_room(room_id, |rooms, log| {
            let floor = earliest
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .max();
            let Some(ceiling) = latest
                .iter()
                .filter_map(|id| log.get(&EventId::new(id.as_str())))
                .map(|entry| entry.li)
                .min()
            else {
                // Nothing they name is ours: there is no gap to fill.
                return Ok(Vec::new());
            };
            let mut newest_first: Vec<Value> = log
                .entries()
                .rev()
                .filter(|entry| {
                    entry.li < ceiling
                        && floor.is_none_or(|floor| entry.li > floor)
                        && entry.depth >= min_depth
                })
                .take(limit)
                // The stored PDU as signed: see `Rooms::pdu` for why no
                // `event_id` is added.
                .map(|entry| rooms.read_event(room_id, &entry.event_id))
                .collect::<Result<_, RoomError>>()?;
            newest_first.reverse();
            Ok(newest_first)
        })
    }

    /// MSC4242's `/get_missing_events` with `state_dag: true`: the state
    /// DAG walked back from `latest` along `prev_state_events`, stopping at
    /// `earliest`, in the order the MSC fixes -- fewest hops first, then
    /// lexicographic -- and to completion rather than to a limit, because
    /// the asking server needs a path to the create event or nothing.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for.
    fn missing_state_events(
        &self,
        room_id: &str,
        earliest: &[String],
        latest: &[String],
    ) -> Result<Vec<Value>, RoomError> {
        // Bounded all the same: a state DAG with more events than this is
        // not a conference room, and the walk is a stored read per event.
        const CAP: usize = 5_000;
        self.with_room(room_id, |rooms, log| {
            let stop: std::collections::HashSet<&str> =
                earliest.iter().map(String::as_str).collect();
            let mut seen: std::collections::HashSet<String> = HashSet::new();
            let mut frontier: Vec<String> = latest
                .iter()
                .filter(|id| log.get(&EventId::new(id.as_str())).is_some())
                .cloned()
                .collect();
            frontier.sort();
            frontier.dedup();
            // `latest` are what the peer holds; it wants their ancestry.
            let mut found: Vec<Value> = Vec::new();
            let mut next: Vec<String> = Vec::new();
            for id in &frontier {
                seen.insert(id.clone());
            }
            while !frontier.is_empty() && found.len() < CAP {
                for id in &frontier {
                    let event = rooms.read_event(room_id, &EventId::new(id.as_str()))?;
                    for parent in event["prev_state_events"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        if stop.contains(parent) || !seen.insert(parent.to_owned()) {
                            continue;
                        }
                        if log.get(&EventId::new(parent)).is_some() {
                            next.push(parent.to_owned());
                        }
                    }
                }
                next.sort();
                for id in &next {
                    found.push(rooms.read_event(room_id, &EventId::new(id.as_str()))?);
                }
                frontier = std::mem::take(&mut next);
            }
            Ok(found)
        })
    }

    /// The `send_join` response of a state-DAG room (MSC4242): the whole
    /// state DAG -- every accepted state event, which in a room this
    /// server serializes is every state entry of the log -- and the tail
    /// of the timeline, so the joiner has context and the join's
    /// `prev_events` resolve.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server has no log for.
    pub fn state_dag_response(
        &self,
        room_id: &str,
        join_id: &str,
    ) -> Result<(Vec<Value>, Vec<Value>), RoomError> {
        const TIMELINE: usize = 20;
        self.with_room_read(room_id, |rooms, log| {
            let mut state_dag = Vec::new();
            for entry in log.entries().filter(|entry| entry.state_key.is_some()) {
                if entry.event_id.as_str() == join_id {
                    continue;
                }
                state_dag.push(rooms.read_event(room_id, &entry.event_id)?);
            }
            let mut timeline = Vec::new();
            for entry in log
                .entries()
                .rev()
                .filter(|entry| entry.event_id.as_str() != join_id)
                .take(TIMELINE)
            {
                timeline.push(rooms.read_event(room_id, &entry.event_id)?);
            }
            Ok((state_dag, timeline))
        })
    }

    /// Give a membership template its links: `prev_events` always, and
    /// then either the stock `auth_events` and `depth`, or -- in a
    /// state-DAG room (MSC4242) -- `prev_state_events`, the state DAG's
    /// forward extremities.
    fn link_template(
        &self,
        log: &RoomLog,
        room_id: &str,
        template: &mut Value,
        prev: &[String],
        auth: &[String],
        depth: u64,
    ) -> Result<(), RoomError> {
        let version = self.version_in_log(log, room_id)?;
        let Some(object) = template.as_object_mut() else {
            return Err(RoomError::Build("a template is an object".to_owned()));
        };
        object.insert("prev_events".to_owned(), serde_json::json!(prev));
        if spindle_core::is_state_dag(&version) {
            object.insert(
                "prev_state_events".to_owned(),
                serde_json::json!(self.state_dag_heads(log, room_id)?),
            );
        } else {
            object.insert("auth_events".to_owned(), serde_json::json!(auth));
            object.insert("depth".to_owned(), serde_json::json!(depth));
        }
        if !spindle_core::version::names_events_by_hash(&version) {
            // v1/v2: the references are `[id, hashes]` pairs, which only
            // the resident can write -- it holds the parents.
            let Ok(ruma::CanonicalJsonValue::Object(mut canonical)) =
                ruma::CanonicalJsonValue::try_from(template.clone())
            else {
                return Err(RoomError::Build("a template is canonical JSON".to_owned()));
            };
            self.link_edges(room_id, &version, &mut canonical)?;
            *template = serde_json::to_value(&canonical)?;
        }
        Ok(())
    }

    /// The room's state *before* `event_id`, with the auth chain, for
    /// federation's `/state` and `/state_ids`.
    ///
    /// Before rather than after, matching what a joining or backfilling
    /// server needs: the state its new event was authorized against. That
    /// is its parents' states, resolved when they differ
    /// ([`Self::state_before_event`]), which in a linear room is one
    /// content-addressed rehydration of the entry before it -- the read
    /// SPEC §18.1 is about. It used to be the linear predecessor's root
    /// whatever the event's parents, which after a fork is one branch's
    /// state (#16).
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::MissingBody`] for an event the room does not
    /// hold, or [`RoomError`] if the state or bodies cannot be read.
    pub fn federation_state(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<(Vec<IdentifiedEvent>, Vec<IdentifiedEvent>), RoomError> {
        let before = self.state_before_event(room_id, event_id)?;
        let pdus = self.state_pairs_of(room_id, &before)?;

        // The auth chain is every event the state transitively cites: a
        // walk over stored bodies, deduplicated, no network.
        let frontier: Vec<String> = pdus
            .iter()
            .flat_map(|(_, event)| cited_auth_events(event))
            .collect();
        let auth_chain = self.auth_chain_from(room_id, frontier);
        Ok((pdus, auth_chain))
    }

    /// The state the room was in just before `event_id`: its parents'
    /// states, resolved by the room version's algorithm when they differ
    /// (ADR 0005) -- exactly what the event was authorized against when it
    /// arrived, and what the live path computes for it.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::MissingBody`] for an event the room does not
    /// hold, or [`RoomError`] if a state cannot be read or resolved.
    pub fn state_before_event(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<spindle_core::StateSnapshot, RoomError> {
        self.with_room_read(room_id, |rooms, log| {
            if !log.holds(&EventId::new(event_id)) {
                return Err(RoomError::MissingBody(event_id.to_owned()));
            }
            rooms.resolve_in(log, room_id, |log, resolver, load| {
                log.state_before(&EventId::new(event_id), resolver, load)
            })
        })
    }

    /// The auth chain of one event (`GET /event_auth/{roomId}/{eventId}`):
    /// every event it cites, and every event those cite, to the create.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server is not in, and
    /// the event lookup's error when the room has no such event.
    pub fn auth_chain(&self, room_id: &str, event_id: &str) -> Result<Vec<Value>, RoomError> {
        let event = self.event(room_id, event_id)?;
        Ok(self
            .auth_chain_from(room_id, cited_auth_events(&event))
            .into_iter()
            .map(|(_, event)| event)
            .collect())
    }

    /// Walk `auth_events` from `frontier` to the create event, each event
    /// once, from stored bodies alone.
    fn auth_chain_from(&self, room_id: &str, mut frontier: Vec<String>) -> Vec<IdentifiedEvent> {
        let mut seen = std::collections::BTreeSet::new();
        let mut auth_chain = Vec::new();
        while let Some(id) = frontier.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let Ok(event) = self.pdu(room_id, &id) else {
                continue;
            };
            frontier.extend(cited_auth_events(&event));
            auth_chain.push((id, event));
        }
        auth_chain
    }

    /// Every remote domain with a live member in the room — the EDU
    /// audience, same liveness rule as event fan-out.
    ///
    /// Literally the same rule now. This and the fan-out in
    /// [`Self::enqueue_outbound`] were two copies of one computation, which
    /// is how one liveness rule becomes two that disagree. Both go through
    /// [`Self::destinations_in`], and so share its cache.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room or membership rows cannot be read.
    pub fn remote_domains(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        let domains = self.with_room(room_id, |rooms, log| rooms.destinations_in(log, room_id))?;
        Ok(domains.as_ref().clone())
    }

    /// The stripped state an invited user may see: enough to render the
    /// invite (what room, whose, how it admits), nothing they are not yet
    /// entitled to.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if state cannot be read; an unknown room is an
    /// empty list, because an invite can outlive this server's knowledge of
    /// the room behind it.
    pub fn stripped_state(&self, room_id: &str, user_id: &str) -> Result<Vec<Value>, RoomError> {
        const SHOWN: &[&str] = &[
            "m.room.create",
            "m.room.join_rules",
            "m.room.canonical_alias",
            "m.room.name",
            "m.room.avatar",
            "m.room.topic",
            "m.room.encryption",
        ];
        let ids = match self.with_room_read(room_id, |_, log| {
            let Some(state) = log.current_state() else {
                return Ok(Vec::new());
            };
            let mut ids: Vec<(String, String, String)> = Vec::new();
            state.for_each(|key, id| {
                let event_type = key.event_type().as_str();
                let shown = SHOWN.contains(&event_type)
                    || (event_type == "m.room.member" && key.state_key() == user_id);
                if shown {
                    ids.push((
                        event_type.to_owned(),
                        key.state_key().to_owned(),
                        id.to_owned(),
                    ));
                }
            });
            Ok(ids)
        }) {
            Ok(ids) => ids,
            // A room this server was never in still renders as an invite:
            // the inviting server handed over stripped state exactly for
            // this moment, and it was recorded beside the membership row.
            Err(RoomError::UnknownRoom(_)) => {
                // A knock is read the same way and from its own row. Invite
                // first: if both stand, the room answered, and the answer is
                // the newer truth.
                let stripped = match self
                    .pending_invite(user_id, room_id)?
                    .and_then(|record| record["invite_state"].as_array().cloned())
                {
                    Some(invite_state) => Some(invite_state),
                    None => self
                        .pending_knock(user_id, room_id)?
                        .and_then(|record| record["knock_state"].as_array().cloned()),
                };
                return self.prune_erased_stripped(stripped.unwrap_or_default());
            }
            Err(error) => return Err(error),
        };
        let erasure_active = self.erasure_active()?;
        let mut stripped = Vec::with_capacity(ids.len() + 1);
        let mut inviter: Option<String> = None;
        for (event_type, state_key, id) in ids {
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
            let event = if erasure_active {
                self.prune_erased_event(user_id, room_id, super::stamp(event, &id))?
            } else {
                event
            };
            if event_type == "m.room.member" && state_key == user_id {
                inviter = event["sender"].as_str().map(str::to_owned);
            }
            stripped.push(serde_json::json!({
                "type": event_type,
                "state_key": state_key,
                "sender": event["sender"],
                "content": event["content"],
            }));
        }
        // The inviter's own membership rides along, as Synapse's does: an
        // invite is rendered as "<name> invited you", and the name lives in
        // the inviter's member event. Without it a client has a sender it
        // cannot show -- matrix-rust-sdk's `invite_details` has no inviter,
        // and Element X renders the invite from a bare user ID.
        if let Some(inviter) = inviter.filter(|inviter| inviter != user_id) {
            let key = spindle_core::StateKey::new("m.room.member", inviter.as_str());
            let id = self.with_room_read(room_id, |_, log| {
                Ok(log
                    .current_state()
                    .and_then(|state| state.get(&key).map(str::to_owned)))
            })?;
            if let Some(id) = id {
                let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
                let event = if erasure_active {
                    self.prune_erased_event(user_id, room_id, super::stamp(event, &id))?
                } else {
                    event
                };
                stripped.push(serde_json::json!({
                    "type": "m.room.member",
                    "state_key": inviter,
                    "sender": event["sender"],
                    "content": event["content"],
                }));
            }
        }
        Ok(stripped)
    }

    /// Seed a room this server has never held from a `send_join` response,
    /// ending with our own join event — the receiving half of joining a
    /// room that lives on another server.
    ///
    /// The response carries the room's state before the join and its auth
    /// chain, but none of the history between those events: their parents
    /// live on the resident server. So the events are replayed in
    /// dependency order (depth, then timestamp) with each snapshot built by
    /// applying the event to its predecessor's — `append_seeded`, not a
    /// fold over parents this log does not hold.
    ///
    /// Every event's ID is **recomputed from its content**: v11 IDs are
    /// reference hashes, so the resident server cannot hand us a body that
    /// does not match the ID the rest of the room cites. Per-event origin
    /// signature verification is deliberately deferred to the roadmap's
    /// federation-hardening pass; the hash check is what keeps the seeded
    /// room internally consistent.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] when an event fails validation or the room is
    /// already held (join a room we are in through the local path instead).
    #[allow(clippy::too_many_lines, reason = "one seeding, in one place")]
    pub fn join_remote(
        &self,
        room_id: &str,
        state: &[Value],
        auth_chain: &[Value],
        join: &Value,
        join_id: &str,
    ) -> Result<(), RoomError> {
        let mut open = self
            .open
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_held = open.contains_key(room_id)
            || RoomStore::new(self.store.as_ref(), room_id)
                .load()?
                .is_some();
        if already_held {
            return Err(RoomError::Append(format!(
                "{room_id} is already on this server"
            )));
        }

        // The room's version is the create event's to state, and it
        // decides how every other event here is named. The old code hashed
        // under this build's default, which was right only by the accident
        // of v11 and v12 sharing a redaction.
        let create = state
            .iter()
            .chain(auth_chain)
            .find(|event| event["type"] == "m.room.create" && event["state_key"] == "")
            .ok_or_else(|| RoomError::Append("the response has no create event".to_owned()))?;
        let version = version_in(&create["content"])?;
        let state_dag = spindle_core::is_state_dag(&version);
        let identify = |event: &Value| -> Result<(String, Value), RoomError> {
            let ruma::CanonicalJsonValue::Object(canonical) =
                ruma::CanonicalJsonValue::try_from(event.clone())
                    .map_err(|error| RoomError::Append(error.to_string()))?
            else {
                return Err(RoomError::Append("event is not an object".to_owned()));
            };
            let pdu = Pdu::from_remote(version.clone(), canonical).map_err(|error| {
                let mut shown = event.to_string();
                shown.truncate(400);
                RoomError::Append(format!("seeded event refused: {error:?}: {shown}"))
            })?;
            Ok((pdu.event_id().as_str().to_owned(), event.clone()))
        };

        // State and auth chain overlap heavily; dedup by recomputed ID, then
        // order by dependency. Depth is the room's own topological measure;
        // the timestamp and ID only break ties deterministically.
        let mut events: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        for event in state.iter().chain(auth_chain) {
            let (id, body) = identify(event)?;
            events.insert(id, body);
        }
        if events.contains_key(join_id) {
            // A state-DAG resident answers with the DAG *after* the join,
            // in which the join is a head; a stock resident answers with
            // the state before it. The join is seeded last either way.
            if state_dag {
                events.remove(join_id);
            } else {
                return Err(RoomError::Append(
                    "the join must not be part of the state before it".to_owned(),
                ));
            }
        }
        let mut ordered: Vec<(String, Value)> = events.into_iter().collect();
        if state_dag {
            // MSC4242: the state DAG orders itself. Parents before children
            // along `prev_state_events`, ties by timestamp; the timeline
            // events, which carry no state, follow by timestamp. An event
            // for another room is a peer's mistake and is left out.
            ordered.retain(|(_, event)| {
                event["type"] == "m.room.create" || event["room_id"].as_str() == Some(room_id)
            });
            ordered = order_state_dag(ordered);
        } else {
            ordered.sort_by_key(|(id, event)| {
                (
                    event["depth"].as_u64().unwrap_or(0),
                    event["origin_server_ts"].as_u64().unwrap_or(0),
                    id.clone(),
                )
            });
        }

        let (computed_join_id, join_body) = identify(join)?;
        if computed_join_id != join_id {
            return Err(RoomError::Append(format!(
                "the join hashes to {computed_join_id}, not {join_id}"
            )));
        }

        let mut log = RoomLog::new();
        let mut snapshot = spindle_core::StateSnapshot::new();
        let room_store = RoomStore::new(self.store.as_ref(), room_id);
        let seed = |log: &mut RoomLog,
                    snapshot: &mut spindle_core::StateSnapshot,
                    id: &str,
                    event: &Value|
         -> Result<LogEntry, RoomError> {
            let state_key = event["state_key"].as_str().map(|state_key| {
                StateKey::new(event["type"].as_str().unwrap_or_default(), state_key)
            });
            if let Some(key) = state_key.clone() {
                *snapshot = snapshot.apply(key, id);
            }
            let prev: Vec<EventId> = super::edge_ids(&event["prev_events"])
                .into_iter()
                .map(EventId::new)
                .collect();
            let input = match state_key {
                Some(key) => EventInput::new(id, prev).with_state_key(key),
                None => EventInput::new(id, prev),
            };
            match log.append_seeded(
                input,
                snapshot.clone(),
                event["depth"].as_u64().unwrap_or(0),
            ) {
                Ok(entry) => Ok(entry.clone()),
                Err(error) => Err(RoomError::Append(format!("{error:?}"))),
            }
        };

        for (id, event) in &ordered {
            let entry = seed(&mut log, &mut snapshot, id, event)?;
            // Body and reverse index ride the entry's own commit, exactly as
            // on the ordinary receive path; seeded history takes no stream
            // row because it is not new activity on this server.
            spindle_store::Store::put(
                self.store.as_ref(),
                &event_body_key(room_id, id),
                &serde_json::to_vec(event)?,
            )?;
            let mut extra = vec![(
                spindle_core::keys::event_room(id),
                room_id.as_bytes().to_vec(),
            )];
            // MSC4354: a seeded sticky event is owed to this server's
            // syncing clients like any other, at a position every token
            // issued before the join precedes.
            if event.get(super::STICKY_KEY).is_some() {
                extra.extend(super::sticky_index_row(
                    room_id,
                    id,
                    event,
                    self.allocate_stream_id(),
                ));
            }
            room_store.journal_entry_with(&entry, &log, &extra)?;
        }

        // The join itself is new activity: it goes through the shared
        // persistence spine, so it gets a stream row (the joiner's sync must
        // surface the room), the membership index, and waiter notification.
        let join_entry = seed(&mut log, &mut snapshot, join_id, &join_body)?;
        let content = join_body["content"].clone();
        let sender = join_body["sender"].as_str().unwrap_or_default().to_owned();
        let state_key_owned = join_body["state_key"].as_str().map(str::to_owned);
        self.persist_entry(
            &mut log,
            room_id,
            &join_entry,
            join_id,
            &PersistInput {
                event_type: join_body["type"].as_str().unwrap_or_default(),
                state_key: state_key_owned.as_deref(),
                sender: &sender,
                content: &content,
                json: &join_body,
            },
        )?;

        // Membership rows for everyone already in the room, from the final
        // state: `/joined_members`, sync and the outbound queue all read
        // this index instead of walking state.
        let mut member_rows: Vec<(String, String)> = Vec::new();
        snapshot.for_each(|key, id| {
            if key.event_type().as_str() == "m.room.member" {
                member_rows.push((key.state_key().to_owned(), id.to_owned()));
            }
        });
        for (user, id) in member_rows {
            if user == sender {
                continue; // persist_entry indexed the join itself
            }
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
            let li = log
                .get(&EventId::new(id.as_str()))
                .map_or(0, |entry| entry.li.get());
            self.index_membership(room_id, Some(&user), &event["content"], li)?;
        }

        open.insert(room_id.to_owned(), Arc::new(RwLock::new(log)));
        Ok(())
    }

    /// Accept one event another server created, after the caller verified
    /// its signatures against the origin's published keys.
    ///
    /// The same authorization predicate local events pass, against the same
    /// materialized state — SPEC §5's whole point is that a received event
    /// costs an index lookup to authorize, not a state computation. A PDU
    /// that fails it soft-fails: refused with a reason the transaction
    /// response carries, poisoning nothing else in the batch. A PDU naming
    /// predecessors this server has never seen is refused too — filling
    /// that gap is `/get_missing_events` and backfill (#15), not guessing.
    ///
    /// # Errors
    ///
    /// [`RoomError::UnknownRoom`] for a room this server is not in,
    /// [`RoomError::Forbidden`] when authorization refuses, and
    /// [`RoomError::Append`] when the log cannot place the event.
    pub fn receive_remote(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        let received = self.with_room(room_id, |rooms, log| {
            rooms.ingest(log, room_id, event_id, json, false)
        });
        // An event for a room this server never held can still say one true
        // thing to us: our user's invite there ended. Without this, an
        // invite revoked or kicked from the other side would haunt the
        // user's sync forever — the resident server fans the leave out to
        // the invitee's domain, and this is the only door it arrives by.
        if let Err(RoomError::UnknownRoom(_)) = &received
            && json["type"].as_str() == Some("m.room.member")
            && matches!(
                json["content"]["membership"].as_str(),
                Some("leave" | "ban")
            )
            && let Some(target) = json["state_key"].as_str()
            && target.split_once(':').map(|(_, domain)| domain) == Some(self.server_name.as_str())
        {
            if self.leave_ends_pending_invite(target, room_id, json)? {
                self.clear_pending_invite(target, room_id)?;
            }
            return Ok(());
        }
        received
    }

    /// Whether a leave or ban that arrived for a room this server does
    /// not hold is about the invite standing for the user, rather than an
    /// earlier one. The resident server fans a rejection out to the
    /// invitee's domain after the rejecting server has already answered
    /// its user, so a fresh invite can be recorded before the old leave
    /// lands; that leave names the old invite among its auth and prev
    /// events and must not take the new one with it. A record written
    /// before the invite's id was kept yields to any leave, as before.
    fn leave_ends_pending_invite(
        &self,
        user_id: &str,
        room_id: &str,
        leave: &Value,
    ) -> Result<bool, RoomError> {
        let Some(pending) = self.pending_invite(user_id, room_id)? else {
            return Ok(false);
        };
        let Some(invite_id) = pending["event_id"].as_str() else {
            return Ok(true);
        };
        let names_invite = |key: &str| {
            super::edge_ids(&leave[key])
                .iter()
                .any(|id| id == invite_id)
        };
        Ok(names_invite("auth_events") || names_invite("prev_events"))
    }

    /// Accept a membership event another server's user made *through*
    /// this server -- the signed template a `send_join`, `send_knock` or
    /// `send_leave` handshake hands back -- and fan it out.
    ///
    /// The one exception to "each server fans out its own events". The
    /// event's origin is not in the room: a joiner is not yet, a knocker
    /// never will be until answered, a leaver just stopped being. None of
    /// them will be sent the room's traffic, and none can send this event
    /// to the room's other servers, so the resident that admitted it is the
    /// only server placed to. Complement's synthetic peer is joined to the
    /// room and waits five seconds for a knock brokered this way; through
    /// [`Self::receive_remote`] it never arrived (#229).
    ///
    /// # Errors
    ///
    /// As [`Self::receive_remote`].
    pub fn receive_brokered(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.ingest(log, room_id, event_id, json, true)
        })
    }

    /// Append an event this server authored but a peer completed.
    ///
    /// The federated invite is the one event with two authors: built and
    /// signed here, co-signed by the invited user's server, and only the
    /// co-signed version is worth storing — it is what proves to every other
    /// server in the room that the invitee's server took part. It fans out
    /// like any local event, because this server originated it; the invited
    /// server already holds it and absorbs the redelivery.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the room is unknown or the rules refuse the
    /// event — the log may have moved while the peer was co-signing, and the
    /// event is re-authorized against whatever the head is now.
    pub fn commit_cosigned(
        &self,
        room_id: &str,
        event_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        self.with_room(room_id, |rooms, log| {
            rooms.ingest(log, room_id, event_id, json, true)
        })
    }
}

/// Order a state-DAG room's events for seeding: state events in a
/// topological order of `prev_state_events` (ties by timestamp, then ID),
/// then the rest by timestamp. A state event whose parent is not in the
/// set is placed as if it had none: the resident vouched for the set, and
/// a hole in it is theirs.
fn order_state_dag(events: Vec<(String, Value)>) -> Vec<(String, Value)> {
    use std::collections::{BTreeSet, HashMap};
    let (state, timeline): (Vec<_>, Vec<_>) = events
        .into_iter()
        .partition(|(_, event)| event.get("state_key").is_some());
    let present: std::collections::HashSet<String> =
        state.iter().map(|(id, _)| id.clone()).collect();
    let mut parents: HashMap<String, Vec<String>> = HashMap::new();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut by_id: HashMap<String, Value> = HashMap::new();
    for (id, event) in state {
        let mine: Vec<String> = event["prev_state_events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|parent| present.contains(*parent))
            .map(str::to_owned)
            .collect();
        for parent in &mine {
            children.entry(parent.clone()).or_default().push(id.clone());
        }
        parents.insert(id.clone(), mine);
        by_id.insert(id, event);
    }
    let stamps: HashMap<String, u64> = by_id
        .iter()
        .map(|(id, event)| (id.clone(), event["origin_server_ts"].as_u64().unwrap_or(0)))
        .collect();
    let sort_key = |id: &str| (stamps.get(id).copied().unwrap_or(0), id.to_owned());
    let mut ready: BTreeSet<(u64, String)> = parents
        .iter()
        .filter(|(_, mine)| mine.is_empty())
        .map(|(id, _)| sort_key(id))
        .collect();
    let mut remaining: HashMap<String, usize> = parents
        .iter()
        .map(|(id, mine)| (id.clone(), mine.len()))
        .collect();
    let mut ordered = Vec::with_capacity(by_id.len());
    while let Some((_, id)) = ready.pop_first() {
        for child in children.get(&id).into_iter().flatten() {
            if let Some(left) = remaining.get_mut(child) {
                *left -= 1;
                if *left == 0 {
                    ready.insert(sort_key(child));
                }
            }
        }
        if let Some(event) = by_id.remove(&id) {
            ordered.push((id, event));
        }
    }
    // Anything left is in a cycle, which a hash-named DAG cannot have; keep
    // it anyway rather than lose state, in a fixed order.
    let mut leftover: Vec<(String, Value)> = by_id.into_iter().collect();
    leftover.sort_by_key(|(id, _)| id.clone());
    ordered.extend(leftover);
    let mut timeline = timeline;
    timeline
        .sort_by_key(|(id, event)| (event["origin_server_ts"].as_u64().unwrap_or(0), id.clone()));
    ordered.extend(timeline);
    ordered
}

/// The event ids an event's `auth_events` names.
fn cited_auth_events(event: &Value) -> Vec<String> {
    super::edge_ids(&event["auth_events"])
}
