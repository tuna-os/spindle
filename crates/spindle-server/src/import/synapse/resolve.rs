//! The room version's state resolver, run over Synapse's events at import.
//!
//! Spindle's log folds a fork by its own rule (SPEC §9.2) and refuses one
//! that two branches contest. A Matrix room is defined by the room version's
//! resolver: state resolution v1 for room version 1 (`state_res_v1`) and v2
//! (ruma) for every later version. So at each event whose parents' states
//! differ, and at the room's head over several forward extremities, the
//! importer asks that resolver, and checks the answer against the state
//! Synapse resolved for the same event. That makes the import an
//! independent derivation of the room rather than a copy of Synapse's
//! answers, and a disagreement is a finding, not a silent overwrite.
//!
//! Only the slots the parent states disagree on are resolved: the rest is
//! the same in every parent and stays as it is. The resolver still sees
//! every slot its auth checks read (every non-member slot, and the
//! membership of every sender and target among the events it orders), so
//! the answer is the one the full state maps would give.
//!
//! Two details are Synapse's rather than the spec's prose:
//!
//! * **The auth chain of a state set includes the set's own events**
//!   (Synapse's `get_auth_chain_difference`).
//! * **A user ID ruma rejects is still a user.** Synapse accepted, and
//!   authorized, members such as `@telegram_…:*` and `@:vona.fsky.io`. ruma
//!   cannot parse them, and an event it cannot parse is dropped from the
//!   conflicted set, which changes the answer. The resolver's copy of such
//!   an event names a deterministic stand-in instead (same in `sender`,
//!   `state_key`, power-level `users` and `join_authorised_via_users_server`),
//!   so it is authorized exactly as the original was. Stored bodies are
//!   never changed.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;

use ruma::events::StateEventType;
use ruma::room_version_rules::{RoomVersionRules, StateResolutionVersion};
use ruma::state_res::utils::event_id_set::EventIdSet;
use ruma::{OwnedEventId, OwnedUserId, RoomVersionId};
use serde_json::Value;
use sha2::{Digest, Sha256};
use spindle_core::{StateKey, StateSnapshot};

use super::postgres::Snapshot;
use crate::authorize::StoredEvent;
use crate::import::Resolution;

/// The resolver for one room, with the room's auth DAG interned.
pub struct RoomResolver {
    room_id: String,
    rules: RoomVersionRules,
    rejected: HashSet<String>,
    ids: HashMap<String, u32>,
    names: Vec<String>,
    /// Auth events by interned ID. `None`: not read yet (no `event_auth` row).
    auth: Vec<Option<Vec<u32>>>,
    events: RefCell<HashMap<String, Option<StoredEvent>>>,
    /// User IDs ruma rejects that the resolver saw, with their stand-ins.
    pub stand_ins: BTreeSet<String>,
}

type RumaMap = ruma::state_res::StateMap<OwnedEventId>;

impl RoomResolver {
    /// Load a room's auth edges.
    ///
    /// # Errors
    ///
    /// A description when the version has no rules or the read fails.
    pub fn load(snapshot: &mut Snapshot<'_>, room_id: &str, version: &str) -> Result<Self, String> {
        let version = RoomVersionId::try_from(version).map_err(|error| error.to_string())?;
        let rules = spindle_core::rules_of(&version)
            .ok_or_else(|| format!("no rules for room version {version}"))?;
        let mut resolver = Self {
            room_id: room_id.to_owned(),
            rules,
            rejected: snapshot.query(
                "SELECT e.event_id FROM events e JOIN rejections r USING (event_id) WHERE e.room_id = $1",
                &[&room_id],
            ).map_err(|error| error.to_string())?.into_iter().map(|row| row.get(0)).collect(),
            ids: HashMap::new(),
            names: Vec::new(),
            auth: Vec::new(),
            events: RefCell::new(HashMap::new()),
            stand_ins: BTreeSet::new(),
        };
        let edges = snapshot
            .auth_edges(room_id)
            .map_err(|error| error.to_string())?;
        for (event_id, auth_id) in edges {
            let event = resolver.intern(&event_id);
            let auth = resolver.intern(&auth_id);
            if let Some(slot) = resolver.auth.get_mut(event as usize) {
                slot.get_or_insert_with(Vec::new).push(auth);
            }
        }
        Ok(resolver)
    }

    fn intern(&mut self, event_id: &str) -> u32 {
        if let Some(id) = self.ids.get(event_id) {
            return *id;
        }
        let id = u32::try_from(self.names.len()).unwrap_or(u32::MAX);
        self.ids.insert(event_id.to_owned(), id);
        self.names.push(event_id.to_owned());
        self.auth.push(None);
        id
    }

    /// The auth events of `id`, reading the body when `event_auth` had no
    /// row for it (a create event has none; anything else is read once).
    fn auth_of(&mut self, snapshot: &mut Snapshot<'_>, id: u32) -> Vec<u32> {
        if let Some(Some(auth)) = self.auth.get(id as usize) {
            return auth.clone();
        }
        let name = self.names.get(id as usize).cloned().unwrap_or_default();
        let named = Self::body(snapshot, &name)
            .map(|body| crate::rooms::edge_ids(&body["auth_events"]))
            .unwrap_or_default();
        let ids: Vec<u32> = named.iter().map(|auth| self.intern(auth)).collect();
        if let Some(slot) = self.auth.get_mut(id as usize) {
            *slot = Some(ids.clone());
        }
        ids
    }

    fn body(snapshot: &mut Snapshot<'_>, event_id: &str) -> Option<Value> {
        snapshot
            .event_bodies_for(&[event_id.to_owned()])
            .ok()?
            .remove(event_id)
    }

    /// Everything reachable from `start` through auth events, `start`
    /// included, as a bitset over interned IDs.
    fn chain(&mut self, snapshot: &mut Snapshot<'_>, start: &[u32]) -> Vec<u64> {
        let mut seen = vec![0_u64; self.names.len().div_ceil(64) + 1];
        let mut stack: Vec<u32> = start.to_vec();
        while let Some(id) = stack.pop() {
            let (word, bit) = ((id / 64) as usize, 1_u64 << (id % 64));
            if seen.len() <= word {
                seen.resize(word + 1, 0);
            }
            if seen[word] & bit != 0 {
                continue;
            }
            seen[word] |= bit;
            stack.extend(self.auth_of(snapshot, id));
        }
        seen
    }

    /// Parse (and cache) the resolver's copy of an event.
    fn prefetch(&mut self, snapshot: &mut Snapshot<'_>, wanted: &[String]) {
        let missing: Vec<String> = {
            let events = self.events.borrow();
            wanted
                .iter()
                .filter(|id| !events.contains_key(*id))
                .cloned()
                .collect()
        };
        if missing.is_empty() {
            return;
        }
        let bodies = snapshot.event_bodies_for(&missing).unwrap_or_default();
        for event_id in missing {
            let parsed = bodies
                .get(&event_id)
                .and_then(|body| self.parse(&event_id, body));
            self.events.borrow_mut().insert(event_id, parsed);
        }
    }

    fn parse(&mut self, event_id: &str, body: &Value) -> Option<StoredEvent> {
        let (body, replaced) = compat_body(body);
        self.stand_ins.extend(replaced);
        StoredEvent::parse_in(event_id, &self.room_id, &body)
            .ok()
            .map(|event| {
                let rejected = self.rejected.contains(event_id);
                event
                    .with_rejected(rejected)
                    .with_preserved_rejection(rejected)
            })
    }

    /// Resolve the states of an event's parents, or of a room's forward
    /// extremities, under the room version.
    ///
    /// Returns the slots on which the answer differs from `sets[0]`.
    ///
    /// # Errors
    ///
    /// A description when the resolver fails.
    #[allow(clippy::too_many_lines)]
    pub fn resolve(
        &mut self,
        snapshot: &mut Snapshot<'_>,
        sets: &[&StateSnapshot],
    ) -> Result<Resolution, String> {
        let Some((first, rest)) = sets.split_first() else {
            return Ok(Resolution::default());
        };
        let mut contested: BTreeSet<StateKey> = BTreeSet::new();
        for other in rest {
            for (key, _, _) in first.diff(other) {
                contested.insert(key.clone());
            }
        }
        if contested.is_empty() {
            return Ok(Resolution::default());
        }

        // Auth chains of each full set (its own events included), as
        // bitsets; the difference is what is in some and not all.
        let mut chains = Vec::with_capacity(sets.len());
        for set in sets {
            let mut ids = Vec::with_capacity(set.len());
            set.for_each(|_, event_id| ids.push(event_id.to_owned()));
            let ids: Vec<u32> = ids.iter().map(|id| self.intern(id)).collect();
            chains.push(self.chain(snapshot, &ids));
        }
        let width = chains.iter().map(Vec::len).max().unwrap_or(0);
        let mut difference = Vec::new();
        for word in 0..width {
            let mut union = 0_u64;
            let mut intersection = u64::MAX;
            for chain in &chains {
                let value = chain.get(word).copied().unwrap_or(0);
                union |= value;
                intersection &= value;
            }
            let mut bits = union & !intersection;
            while bits != 0 {
                let bit = bits.trailing_zeros();
                bits &= bits - 1;
                let id = u32::try_from(word * 64).unwrap_or(u32::MAX) + bit;
                if let Some(name) = self.names.get(id as usize) {
                    difference.push(name.clone());
                }
            }
        }

        // The conflicted state set: every value any set holds for a
        // contested slot.
        let mut conflicted: Vec<String> = Vec::new();
        for key in &contested {
            for set in sets {
                if let Some(value) = set.get(key) {
                    conflicted.push(value.to_owned());
                }
            }
        }
        conflicted.sort_unstable();
        conflicted.dedup();

        let subgraph = match &self.rules.state_res {
            StateResolutionVersion::V2(rules) if rules.consider_conflicted_state_subgraph => {
                self.conflicted_subgraph(snapshot, &conflicted)
            }
            _ => Vec::new(),
        };

        let mut involved: Vec<String> = difference
            .iter()
            .chain(&conflicted)
            .chain(&subgraph)
            .cloned()
            .collect();
        involved.sort_unstable();
        involved.dedup();
        self.prefetch(snapshot, &involved);

        // Slots the auth checks of the involved events can read: every
        // non-member slot, and the membership of each sender and target.
        let mut members: HashSet<String> = HashSet::new();
        {
            let events = self.events.borrow();
            for id in &involved {
                if let Some(Some(event)) = events.get(id) {
                    use ruma::state_res::Event as _;
                    members.insert(event.sender().to_string());
                    if let Some(state_key) = event.state_key() {
                        members.insert(state_key.to_owned());
                    }
                    if let Ok(content) = serde_json::from_str::<Value>(event.content().get())
                        && let Some(via) = content["join_authorised_via_users_server"].as_str()
                    {
                        members.insert(via.to_owned());
                    }
                }
            }
        }
        let wanted = |key: &StateKey| {
            contested.contains(key)
                || key.event_type().as_str() != "m.room.member"
                || members.contains(&stand_in(key.state_key()))
        };

        let mut maps: Vec<RumaMap> = Vec::with_capacity(sets.len());
        for set in sets {
            let mut map = RumaMap::new();
            let mut slots = Vec::new();
            set.for_each(|key, event_id| {
                if wanted(key) {
                    slots.push((key.clone(), event_id.to_owned()));
                }
            });
            for (key, event_id) in slots {
                let Ok(event_id) = OwnedEventId::try_from(event_id.as_str()) else {
                    continue;
                };
                let mut state_key = key.state_key().to_owned();
                if key.event_type().as_str() == "m.room.member" {
                    state_key = stand_in(&state_key);
                }
                map.insert(
                    (StateEventType::from(key.event_type().as_str()), state_key),
                    event_id,
                );
            }
            maps.push(map);
        }

        let all: Vec<String> = maps
            .iter()
            .flat_map(|map| map.values().map(ToString::to_string))
            .collect();
        self.prefetch(snapshot, &all);

        let snapshot_cell = RefCell::new(&mut *snapshot);
        let fetch = |id: &ruma::EventId| -> Option<StoredEvent> {
            if let Some(found) = self.events.borrow().get(id.as_str()) {
                return found.clone();
            }
            let body = snapshot_cell
                .borrow_mut()
                .event_bodies_for(&[id.to_string()])
                .ok()?
                .remove(id.as_str())?;
            let (body, _) = compat_body(&body);
            let parsed = StoredEvent::parse_in(id.as_str(), &self.room_id, &body)
                .ok()
                .map(|event| {
                    let rejected = self.rejected.contains(id.as_str());
                    event
                        .with_rejected(rejected)
                        .with_preserved_rejection(rejected)
                });
            self.events
                .borrow_mut()
                .insert(id.to_string(), parsed.clone());
            parsed
        };

        let resolved: RumaMap = match &self.rules.state_res {
            StateResolutionVersion::V1 => {
                crate::state_res_v1::resolve(&self.rules.authorization, &maps, |id| fetch(id))?
            }
            StateResolutionVersion::V2(rules) => {
                let difference: EventIdSet<OwnedEventId> = difference
                    .iter()
                    .filter_map(|id| OwnedEventId::try_from(id.as_str()).ok())
                    .collect();
                let subgraph: EventIdSet<OwnedEventId> = subgraph
                    .iter()
                    .filter_map(|id| OwnedEventId::try_from(id.as_str()).ok())
                    .collect();
                ruma::state_res::resolve_with_candidate_policy(
                    &self.rules.authorization,
                    rules,
                    maps.iter(),
                    vec![difference, EventIdSet::new()],
                    fetch,
                    |_| Some(subgraph.clone()),
                    |event| !event.preserved_rejection(),
                )
                .map_err(|error| error.to_string())?
            }
            other => return Err(format!("no resolver for {other:?}")),
        };

        let mut slots = Vec::new();
        for key in &contested {
            let mut state_key = key.state_key().to_owned();
            if key.event_type().as_str() == "m.room.member" {
                state_key = stand_in(&state_key);
            }
            let value = resolved
                .get(&(StateEventType::from(key.event_type().as_str()), state_key))
                .map(ToString::to_string);
            if first.get(key) != value.as_deref() {
                slots.push((key.clone(), value));
            }
        }
        Ok(Resolution {
            contested: contested.into_iter().collect(),
            slots,
        })
    }

    /// MSC4297 (v12): the events that are both auth descendants of one
    /// conflicted event and auth ancestors of another.
    fn conflicted_subgraph(
        &mut self,
        snapshot: &mut Snapshot<'_>,
        conflicted: &[String],
    ) -> Vec<String> {
        let starts: Vec<u32> = conflicted.iter().map(|id| self.intern(id)).collect();
        let targets: HashSet<u32> = starts.iter().copied().collect();
        // Ancestors of the conflicted events, in DFS post-order, so each
        // node's auth events are decided before it is.
        let mut order = Vec::new();
        let mut state: HashMap<u32, bool> = HashMap::new();
        let mut stack: Vec<(u32, bool)> = starts.iter().map(|id| (*id, false)).collect();
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                order.push(id);
                continue;
            }
            if state.contains_key(&id) {
                continue;
            }
            state.insert(id, false);
            stack.push((id, true));
            for auth in self.auth_of(snapshot, id) {
                if !state.contains_key(&auth) {
                    stack.push((auth, false));
                }
            }
        }
        let mut reaches: HashMap<u32, bool> = HashMap::new();
        for id in order {
            let below = self
                .auth
                .get(id as usize)
                .and_then(Option::as_ref)
                .is_some_and(|auth| {
                    auth.iter()
                        .any(|a| reaches.get(a).copied().unwrap_or(false))
                });
            reaches.insert(id, targets.contains(&id) || below);
        }
        reaches
            .into_iter()
            .filter(|(_, reaches)| *reaches)
            .filter_map(|(id, _)| self.names.get(id as usize).cloned())
            .collect()
    }
}

/// A user ID as the resolver should see it: the ID itself when ruma
/// accepts it, otherwise a deterministic stand-in on the same server (or on
/// `compat.invalid` when the server name is the part ruma rejects).
#[must_use]
pub fn stand_in(user_id: &str) -> String {
    if OwnedUserId::try_from(user_id).is_ok() {
        return user_id.to_owned();
    }
    let digest = Sha256::digest(user_id.as_bytes());
    let mut hex = String::with_capacity(20);
    for byte in digest.iter().take(10) {
        let _ = write!(hex, "{byte:02x}");
    }
    let server = user_id
        .split_once(':')
        .map(|(_, server)| server)
        .filter(|server| <&ruma::ServerName>::try_from(*server).is_ok())
        .unwrap_or("compat.invalid");
    format!("@spindle-compat-{hex}:{server}")
}

/// The resolver's copy of an event body, with every user ID ruma rejects
/// replaced by its [`stand_in`]. Returns the copy and the IDs replaced.
#[must_use]
pub fn compat_body(body: &Value) -> (Value, Vec<String>) {
    let mut copy = body.clone();
    let mut replaced = Vec::new();
    let mut swap = |slot: &mut Value| {
        if let Some(id) = slot.as_str() {
            let substitute = stand_in(id);
            if substitute != id {
                replaced.push(id.to_owned());
                *slot = Value::String(substitute);
            }
        }
    };
    swap(&mut copy["sender"]);
    let kind = copy["type"].as_str().unwrap_or_default().to_owned();
    if kind == "m.room.member" {
        if copy.get("state_key").is_some() {
            swap(&mut copy["state_key"]);
        }
        if copy["content"]
            .get("join_authorised_via_users_server")
            .is_some()
        {
            swap(&mut copy["content"]["join_authorised_via_users_server"]);
        }
    }
    if kind == "m.room.power_levels"
        && let Some(users) = copy["content"]["users"].as_object_mut()
    {
        let invalid: Vec<String> = users
            .keys()
            .filter(|id| stand_in(id) != **id)
            .cloned()
            .collect();
        for id in invalid {
            if let Some(level) = users.remove(&id) {
                users.insert(stand_in(&id), level);
                replaced.push(id);
            }
        }
    }
    (copy, replaced)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_user_id_is_its_own_stand_in() {
        assert_eq!(stand_in("@alice:example.org"), "@alice:example.org");
        assert_eq!(stand_in("@Alice:example.org"), "@Alice:example.org");
    }

    #[test]
    fn a_rejected_user_id_gets_a_stable_valid_stand_in() {
        for id in [
            "@telegram_7486524983:*",
            "@:vona.fsky.io",
            "@s p a c e:maunium.net",
        ] {
            let one = stand_in(id);
            assert_eq!(one, stand_in(id));
            assert!(OwnedUserId::try_from(one.as_str()).is_ok(), "{one}");
        }
        assert!(stand_in("@:vona.fsky.io").ends_with(":vona.fsky.io"));
        assert!(stand_in("@telegram_7486524983:*").ends_with(":compat.invalid"));
        assert_ne!(stand_in("@a b:x.org"), stand_in("@a  b:x.org"));
    }

    #[test]
    fn a_compat_body_replaces_the_id_everywhere_the_rules_read_it() {
        let body = serde_json::json!({
            "type": "m.room.member", "sender": "@telegram_1:*", "state_key": "@telegram_1:*",
            "content": {"membership": "join"},
        });
        let (copy, replaced) = compat_body(&body);
        assert_eq!(copy["sender"], copy["state_key"]);
        assert_ne!(copy["sender"], body["sender"]);
        assert_eq!(replaced.len(), 2);

        let levels = serde_json::json!({
            "type": "m.room.power_levels", "sender": "@a:x.org", "state_key": "",
            "content": {"users": {"@telegram_1:*": 50, "@a:x.org": 100}},
        });
        let (copy, _) = compat_body(&levels);
        assert_eq!(copy["content"]["users"][stand_in("@telegram_1:*")], 50);
        assert_eq!(copy["content"]["users"]["@a:x.org"], 100);
    }
}
