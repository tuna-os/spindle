//! Partial-state rooms: the joining half of faster joins (MSC3706, the
//! `omit_members` of spec v1.6; #746).
//!
//! A resident asked for `send_join` with `omit_members=true` may leave most
//! `m.room.member` events out of the state before the join, answering
//! `members_omitted` and naming the room's other servers in
//! `servers_in_room`. The join then costs the room's non-member state
//! rather than its roster, and the room is usable at once: our user is in
//! it, can read and can send. What it lacks is the members the resident
//! left out, and this module is how the room gets them back.
//!
//! **While partial**, the room behaves as Synapse's partial-state rooms do:
//!
//! - an incoming event whose authorization needs a member slot the room
//!   does not hold is judged with that slot taken from the event's own
//!   auth events, which check 1 of the receipt checks has already verified
//!   (`Rooms::receipt_checks`). Synapse state-resolves the claimed auth
//!   events against its partial state; filling only the empty slots is the
//!   same answer wherever the two agree, and a ban or leave this server
//!   *does* hold still wins, because a held slot is never replaced.
//!   Synapse's soft-fail check is skipped for the same reason this one is
//!   filled: the current state cannot say who is a member;
//! - events this server sends go to the resident's `servers_in_room` as
//!   well as to the servers of the members it knows (`destinations_in`),
//!   and a server named there counts as in the room (`server_in_room`), so
//!   its events' missing dependencies can be recovered from it;
//! - `/members` and `/joined_members` wait for the resync, as Synapse's
//!   do: an E2EE client takes the roster it is given as the list of users
//!   to encrypt for, and a partial roster would leave the omitted members
//!   unable to read what is said;
//! - a local membership change aimed at another server's user waits too:
//!   the rules read the target's membership, and an omitted ban reads as
//!   "never joined";
//! - this server does not serve the room's state to others, or broker a
//!   join, knock or leave into it: it cannot answer either completely.
//!
//! **The resync** (`inbound::resync`) asks a server for the state at the
//! join, fetches and verifies the member events it lacks, and folds them
//! into every snapshot from the join on ([`Rooms::complete_partial_state`],
//! `RoomLog::fill_partial_state`). Events placed while partial are not
//! judged again: Synapse re-runs their auth and may reject an event after
//! the fact, which a linear log that already handed the event to clients
//! has no way to take back (`docs/divergence.md`).
//!
//! The record of a partial join is persisted (`Keyspace::PartialStateRoom`)
//! before the room is seeded and deleted only once the fill is durable, so
//! a restart at any point resumes the resync rather than leaving a room
//! that silently stays partial.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spindle_core::{EventId, Sideline, StateKey, StateRoot};
use spindle_store::{FjallStore, ReadView as _, RoomStore, Store as _};

use super::{RoomError, Rooms};

/// What a `send_join` answered with `members_omitted` leaves to remember.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartialState {
    pub room_id: String,
    /// The join the resident accepted: the state *at* it is what the resync
    /// asks for.
    pub join_event_id: String,
    /// The server the join went through, asked first.
    pub via: String,
    /// The resident's `servers_in_room`: who else can answer, and who must
    /// be sent this server's events while it cannot tell from the state.
    pub servers_in_room: Vec<String>,
}

/// The partial-state rooms, mirrored in memory: asked on every received
/// PDU and every send, so a store read there would put one in front of
/// every event this server handles.
#[derive(Debug, Default)]
pub(super) struct PartialRooms {
    rooms: Mutex<HashMap<String, PartialState>>,
    /// Where each resync completed, for `/sync` (`Rooms::resynced_between`).
    resynced: Mutex<HashMap<String, u64>>,
    /// Woken when a room stops being partial.
    done: tokio::sync::Notify,
    /// Woken when a room becomes partial: the resync loop's doorbell. An
    /// `Arc` of its own, so the loop can hold it while idle without holding
    /// the registry -- and with it the store -- alive (#292).
    joined: std::sync::Arc<tokio::sync::Notify>,
}

impl PartialRooms {
    /// Everything persisted, read once at startup. A row that does not
    /// parse is skipped with a warning rather than failing the server: the
    /// room it names is then treated as fully joined, which is what it was
    /// before this record existed.
    pub(super) fn load(store: &FjallStore) -> Self {
        let scan = |keyspace: spindle_core::keys::Keyspace| -> Vec<Value> {
            let prefix = vec![spindle_core::keys::KEY_SCHEMA_VERSION, keyspace as u8];
            store
                .scan_prefix(&prefix)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(_, value)| match serde_json::from_slice(&value) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(?keyspace, "unreadable partial-state row: {error}");
                        None
                    }
                })
                .collect()
        };
        let rooms = scan(spindle_core::keys::Keyspace::PartialStateRoom)
            .into_iter()
            .filter_map(|value| serde_json::from_value::<PartialState>(value).ok())
            .map(|record| (record.room_id.clone(), record))
            .collect();
        let resynced = scan(spindle_core::keys::Keyspace::PartialStateResynced)
            .into_iter()
            .filter_map(|value| {
                Some((
                    value["room_id"].as_str()?.to_owned(),
                    value["position"].as_u64()?,
                ))
            })
            .collect();
        Self {
            rooms: Mutex::new(rooms),
            resynced: Mutex::new(resynced),
            done: tokio::sync::Notify::new(),
            joined: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn rooms(&self) -> std::sync::MutexGuard<'_, HashMap<String, PartialState>> {
        self.rooms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Rooms {
    /// Persist a partial join's record, before the room is seeded: a crash
    /// between the two leaves a record for a room this server does not
    /// hold, which the resync drops ([`Self::abandon_partial_state`]),
    /// rather than a seeded room nobody knows is partial.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the record cannot be made durable.
    pub(super) fn record_partial_state(&self, record: &PartialState) -> Result<(), RoomError> {
        self.store.commit(
            &[(
                spindle_core::keys::partial_state_room(&record.room_id),
                serde_json::to_vec(record)?,
            )],
            spindle_store::Durability::Strict,
        )?;
        self.partial
            .rooms()
            .insert(record.room_id.clone(), record.clone());
        self.partial.joined.notify_one();
        Ok(())
    }

    /// What the resync loop waits on between passes: rung by every partial
    /// join, so the resync starts as the join returns rather than at the
    /// next tick.
    #[must_use]
    pub fn partial_state_wake(&self) -> std::sync::Arc<tokio::sync::Notify> {
        std::sync::Arc::clone(&self.partial.joined)
    }

    /// The partial join `room_id` is still resyncing from, if it is.
    #[must_use]
    pub fn partial_state(&self, room_id: &str) -> Option<PartialState> {
        self.partial.rooms().get(room_id).cloned()
    }

    /// Whether `room_id` still lacks member events a resident omitted.
    #[must_use]
    pub fn is_partial_state(&self, room_id: &str) -> bool {
        self.partial.rooms().contains_key(room_id)
    }

    /// Every room still resyncing.
    #[must_use]
    pub fn partial_state_rooms(&self) -> Vec<PartialState> {
        self.partial.rooms().values().cloned().collect()
    }

    /// Wait until `room_id` is no longer partial. Returns at once for a
    /// room that never was.
    pub async fn await_full_state(&self, room_id: &str) {
        loop {
            // Registered before the check, so a resync completing between
            // the two still wakes this waiter.
            let done = self.partial.done.notified();
            if !self.is_partial_state(room_id) {
                return;
            }
            done.await;
        }
    }

    /// Wait for the full state before a membership change aimed at
    /// `target`, when the room is partial and `target` belongs to another
    /// server -- whose member event the resident may have omitted, so the
    /// rules would read an omitted ban as "never joined". A local target
    /// does not wait: Synapse draws the line at the same place
    /// (`StateFilter::must_await_full_state`), since a membership this
    /// server took part in is one it was sent.
    pub(super) async fn await_member_state(&self, room_id: &str, target: &str) {
        let remote = target
            .split_once(':')
            .is_some_and(|(_, domain)| domain != self.server_name);
        if remote {
            self.await_full_state(room_id).await;
        }
    }

    /// Whether `room_id`'s resync completed at a stream position in
    /// `(since, until]`: an incremental `/sync` spanning it owes the client
    /// the room afresh.
    #[must_use]
    pub fn resynced_between(&self, room_id: &str, since: u64, until: u64) -> bool {
        self.partial
            .resynced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(room_id)
            .is_some_and(|position| *position > since && *position <= until)
    }

    /// The resident's `servers_in_room`, while `room_id` is partial: the
    /// servers this one's events must reach although no member event it
    /// holds names them.
    pub(super) fn partial_servers(&self, room_id: &str) -> Vec<String> {
        self.partial
            .rooms()
            .get(room_id)
            .map(|record| record.servers_in_room.clone())
            .unwrap_or_default()
    }

    /// Drop the record of a partial join whose room this server does not
    /// hold -- the join's seeding failed or never ran -- so it is not
    /// resynced forever.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError`] if the record cannot be deleted.
    pub fn abandon_partial_state(&self, room_id: &str) -> Result<(), RoomError> {
        self.store
            .delete(&spindle_core::keys::partial_state_room(room_id))?;
        self.partial.rooms().remove(room_id);
        self.partial.done.notify_waiters();
        Ok(())
    }

    /// Fold the full state at the join into a partial-state room and end
    /// its partial state.
    ///
    /// `state_ids` is a server's `/state_ids` answer at the join: the
    /// state before it, every body already fetched, verified and retained
    /// by the caller (`Rooms::retain_remote_auth`). Its member events fill
    /// the member slots each snapshot from the join on lacks
    /// (`RoomLog::fill_partial_state`); the rewritten entries, their trie
    /// nodes and the resync's stream position land in one durable batch,
    /// the membership index follows, and the record is deleted last -- so a
    /// crash anywhere before that resyncs again, and the fill, which never
    /// replaces a held slot, makes the repeat a no-op.
    ///
    /// Returns how many member events the room did not hold before.
    ///
    /// # Errors
    ///
    /// [`RoomError::Forbidden`] for a state that cannot be this room's: one
    /// naming another create event or none, a rejected event, a non-state
    /// event, or two events for one slot. [`RoomError::MissingBody`] for a
    /// body the caller did not retain. Nothing changes on any error.
    pub fn complete_partial_state(
        &self,
        room_id: &str,
        state_ids: &[String],
    ) -> Result<usize, RoomError> {
        let Some(record) = self.partial_state(room_id) else {
            return Ok(0);
        };
        let room = self.room(room_id)?;
        let (stream_write, filled_members) = {
            let mut log = self.write_room(&room);
            let join = EventId::new(record.join_event_id.as_str());
            let join_li = log
                .get(&join)
                .ok_or_else(|| RoomError::MissingBody(record.join_event_id.clone()))?
                .li;
            let fill = self.omitted_members(&log, room_id, state_ids)?;
            let mut load = |root: &StateRoot| self.load_node(root);
            let filled = log
                .fill_partial_state(join_li, &fill, &mut load)
                .map_err(|error| Self::append_error(&error))?;
            let stream_write = self.reserve_stream_id();
            let resynced = (
                spindle_core::keys::partial_state_resynced(room_id),
                json!({ "room_id": room_id, "position": stream_write.id() })
                    .to_string()
                    .into_bytes(),
            );
            if let Err(error) = RoomStore::new(self.store.as_ref(), room_id).commit_filled(
                &filled,
                &log,
                &[resynced],
            ) {
                // The fill is in memory and not on disk: the store is the
                // record, so the room goes back to it.
                drop(log);
                self.evict(room_id, &room);
                return Err(error.into());
            }
            let mut filled_members = 0;
            if let Some(current) = log.current_state().cloned() {
                for (key, id) in &fill {
                    if current.get(key) != Some(id.as_str()) {
                        continue;
                    }
                    let event = self.read_event(room_id, id)?;
                    self.index_membership(room_id, Some(key.state_key()), &event["content"], 0)?;
                    filled_members += 1;
                }
            }
            (stream_write, filled_members)
        };
        self.store
            .delete(&spindle_core::keys::partial_state_room(room_id))?;
        self.partial
            .resynced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(room_id.to_owned(), stream_write.id());
        self.partial.rooms().remove(room_id);
        self.partial.done.notify_waiters();
        // Dropping the reservation publishes its position and wakes every
        // long-polling `/sync`, which now finds the room resynced.
        drop(stream_write);
        Ok(filled_members)
    }

    /// The member events of `state_ids`, keyed by their slot, after the
    /// checks that make the set a state of this room.
    fn omitted_members(
        &self,
        log: &spindle_core::RoomLog,
        room_id: &str,
        state_ids: &[String],
    ) -> Result<BTreeMap<StateKey, EventId>, RoomError> {
        let create_id = log
            .current_state()
            .and_then(|state| state.get(&StateKey::new("m.room.create", "")))
            .ok_or_else(|| RoomError::Append("the room has no create event".to_owned()))?
            .to_owned();
        let mut create_named = false;
        let mut fill = BTreeMap::new();
        for state_id in state_ids {
            let held = EventId::new(state_id.as_str());
            if log.historically_rejected(&held)
                || log
                    .sidelined(&held)
                    .is_some_and(|entry| entry.kind == Sideline::Rejected)
            {
                return Err(RoomError::Forbidden(format!(
                    "the full state names {state_id}, which this room rejected"
                )));
            }
            let body = self.read_event(room_id, &held)?;
            let (Some(kind), Some(state_key)) = (body["type"].as_str(), body["state_key"].as_str())
            else {
                return Err(RoomError::Forbidden(format!(
                    "the full state names {state_id}, which is not a state event"
                )));
            };
            if kind == "m.room.create" {
                if *state_id != create_id {
                    return Err(RoomError::Forbidden(
                        "the full state names another create event".to_owned(),
                    ));
                }
                create_named = true;
            }
            // Only member events are the resident's to omit; every other
            // slot came in the join's answer, and a resync peer is not
            // asked to overrule it.
            if kind != "m.room.member" {
                continue;
            }
            if fill.insert(StateKey::new(kind, state_key), held).is_some() {
                return Err(RoomError::Forbidden(format!(
                    "the full state names two events for m.room.member/{state_key}"
                )));
            }
        }
        if !create_named {
            return Err(RoomError::Forbidden(
                "the full state does not name this room's create event".to_owned(),
            ));
        }
        Ok(fill)
    }
}
