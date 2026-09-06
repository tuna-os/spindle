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
use spindle_core::{AppendError, EventId, EventInput, LogEntry, Pdu, RoomLog, StateKey};
use spindle_store::RoomStore;

use super::{
    INVITE_STR, IdentifiedEvent, JOIN_STR, PersistInput, RoomError, Rooms, auth_events_for,
    event_body_key, version_in,
};

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
            let Some(state) = log
                .entries()
                .next_back()
                .map(|entry| entry.li)
                .and_then(|li| log.state_after(li))
            else {
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
            // What this server would author on itself: a template naming
            // a tip this server cannot fold hands the user an event
            // `send_*` then refuses.
            self.set_aside_contested(log, room_id)?;
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let state = log
                .state_after(head.li)
                .ok_or_else(|| RoomError::StateUnavailable("no head state".to_owned()))?;

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
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = log
                .authoring_extremities()
                .map(|id| id.as_str().to_owned())
                .collect();
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
            // What this server would author on itself: a template naming
            // a tip this server cannot fold hands the user an event
            // `send_*` then refuses.
            self.set_aside_contested(log, room_id)?;
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
            let state = log
                .state_after(head.li)
                .ok_or_else(|| RoomError::StateUnavailable("no head state".to_owned()))?;
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
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = log
                .authoring_extremities()
                .map(|id| id.as_str().to_owned())
                .collect();
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
            // What this server would author on itself: a template naming
            // a tip this server cannot fold hands the user an event
            // `send_*` then refuses.
            self.set_aside_contested(log, room_id)?;
            let head = log
                .entries()
                .next_back()
                .ok_or_else(|| RoomError::UnknownRoom(room_id.to_owned()))?;
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
                log,
                &rooms.rules_in(log, room_id)?.authorization,
                user_id,
                "m.room.member",
                Some(user_id),
                &content,
            )?;
            let prev: Vec<String> = log
                .authoring_extremities()
                .map(|id| id.as_str().to_owned())
                .collect();
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
                .map(|entry| {
                    let mut event = rooms.read_event(room_id, &entry.event_id)?;
                    if let Some(object) = event.as_object_mut() {
                        object.insert(
                            "event_id".to_owned(),
                            Value::String(entry.event_id.as_str().to_owned()),
                        );
                    }
                    Ok(event)
                })
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
                .map(|entry| {
                    let mut event = rooms.read_event(room_id, &entry.event_id)?;
                    if let Some(object) = event.as_object_mut() {
                        object.insert(
                            "event_id".to_owned(),
                            Value::String(entry.event_id.as_str().to_owned()),
                        );
                    }
                    Ok(event)
                })
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
        let Some(object) = template.as_object_mut() else {
            return Err(RoomError::Build("a template is an object".to_owned()));
        };
        object.insert("prev_events".to_owned(), serde_json::json!(prev));
        if spindle_core::is_state_dag(&self.version_in_log(log, room_id)?) {
            object.insert(
                "prev_state_events".to_owned(),
                serde_json::json!(self.state_dag_heads(log, room_id)?),
            );
        } else {
            object.insert("auth_events".to_owned(), serde_json::json!(auth));
            object.insert("depth".to_owned(), serde_json::json!(depth));
        }
        Ok(())
    }

    /// The room's state *before* `event_id`, with the auth chain, for
    /// federation's `/state` and `/state_ids`.
    ///
    /// Before rather than after, matching what a joining or backfilling
    /// server needs: the state its new event was authorized against. That
    /// is the fold of the event's parents (`RoomLog::state_before`), which
    /// in a linear room is one content-addressed rehydration of the entry
    /// before it -- the read SPEC §18.1 is about. It used to be *only*
    /// that, the linear predecessor's root whatever the event's parents,
    /// which after a fork is one branch's state: a peer asking at the
    /// event that merged two branches was told a state missing the other
    /// branch's writes, while a client of this server saw both. The
    /// federation fork tests compare the two reads, and that is what they
    /// found (#16).
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
        let before = self.with_room_read(room_id, |rooms, log| {
            let mut load = |address: &spindle_core::StateRoot| {
                spindle_store::ReadView::get(
                    rooms.store.as_ref(),
                    &spindle_core::keys::content_addressed(
                        spindle_core::keys::Keyspace::StateNode,
                        address.as_bytes(),
                    ),
                )
                .ok()
                .flatten()
            };
            log.state_before(&EventId::new(event_id), &mut load)
                .map_err(|error| match error {
                    AppendError::UnknownPredecessor(_) => {
                        RoomError::MissingBody(event_id.to_owned())
                    }
                    other => RoomError::Build(format!(
                        "cannot rebuild the state before {event_id}: {other:?}"
                    )),
                })
        })?;
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
            let Ok(event) = self.event(room_id, &id) else {
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
            let Some(head) = log.entries().next_back() else {
                return Ok(Vec::new());
            };
            let Some(state) = log.state_after(head.li) else {
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
                return Ok(stripped.unwrap_or_default());
            }
            Err(error) => return Err(error),
        };
        let mut stripped = Vec::with_capacity(ids.len() + 1);
        let mut inviter: Option<String> = None;
        for (event_type, state_key, id) in ids {
            let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
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
                let Some(head) = log.entries().next_back() else {
                    return Ok(None);
                };
                Ok(log
                    .state_after(head.li)
                    .and_then(|state| state.get(&key).map(str::to_owned)))
            })?;
            if let Some(id) = id {
                let event = self.read_event(room_id, &EventId::new(id.as_str()))?;
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
            let prev: Vec<EventId> = event["prev_events"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(Value::as_str)
                        .map(EventId::new)
                        .collect()
                })
                .unwrap_or_default();
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
            self.clear_pending_invite(target, room_id)?;
            return Ok(());
        }
        received
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
    event["auth_events"]
        .as_array()
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
