//! State resolution for room version 1 (the original algorithm).
//!
//! Room version 1 is the only stable version whose state resolution ruma
//! does not implement: ruma-state-res carries state resolution v2 and v2.1,
//! which every version from 2 up uses. A server that holds a v1 room needs
//! the original algorithm to agree with its peers on a fork, so it is here.
//!
//! The algorithm is the one the spec describes for room version 1
//! (<https://spec.matrix.org/v1.16/rooms/v1/#state-resolution>) and the one
//! Synapse runs (`synapse/state/v1.py`). Where the spec's prose is loose --
//! which key counts as conflicted, which auth events a conflicted event is
//! judged against, what happens when every candidate fails -- this follows
//! Synapse, because agreement with the server that holds the rest of the
//! world's v1 rooms is the point. The comments say where.
//!
//! Like `authorize`, this module decides no authorization of its own: every
//! "is this event allowed" question goes to ruma's
//! `check_state_dependent_auth_rules` under the version's rules. What is here
//! is only the ordering and the order of questions.
//!
//! In outline, for state sets that disagree:
//!
//! 1. A key is *conflicted* when two sets that both hold it hold different
//!    events. A key only some sets hold is not (Synapse's split step in `state/v1.py`).
//! 2. Unconflicted keys are taken as they are.
//! 3. Conflicted keys are resolved in a fixed order -- power levels, then
//!    join rules, then memberships, then everything else -- each step
//!    judging against the auth events the previous steps settled.
//! 4. Power levels, join rules and memberships take the *earliest* event
//!    and walk forward through the candidates while each next one is
//!    authorized; the first refusal stops the walk. Other keys take the
//!    *latest* candidate that is authorized at all.
//!
//! "Earliest" is by `depth`, ties broken by the SHA-1 of the event ID: the
//! ordering is `(-depth, sha1_hex(event_id))` ascending, walked in reverse
//! for the auth-event keys.

use std::collections::{BTreeSet, HashMap};

use ruma::OwnedEventId;
use ruma::events::StateEventType;
use ruma::room_version_rules::AuthorizationRules;
use ruma::state_res::events::Event;
use ruma::state_res::{auth_types_for_event, check_state_dependent_auth_rules};
use sha1::{Digest, Sha1};

use crate::authorize::StoredEvent;

/// `(type, state_key)` to a value, the shape every state set takes here.
pub type StateMap<T> = HashMap<(StateEventType, String), T>;

/// Resolve `state_sets` under room version 1's algorithm.
///
/// `fetch` supplies an event by ID. An event it cannot supply is left out of
/// the conflict it belongs to, as Synapse does; a key whose candidates all
/// vanish that way keeps nothing, and a key left with one candidate takes it.
///
/// # Errors
///
/// Returns a description when a candidate's auth-event types cannot be
/// computed (malformed content), which no stored, accepted event has.
pub fn resolve(
    rules: &AuthorizationRules,
    state_sets: &[StateMap<OwnedEventId>],
    fetch: impl Fn(&OwnedEventId) -> Option<StoredEvent>,
) -> Result<StateMap<OwnedEventId>, String> {
    let Some((first, rest)) = state_sets.split_first() else {
        return Ok(StateMap::new());
    };
    if rest.is_empty() {
        return Ok(first.clone());
    }

    let (mut unconflicted, conflicted_ids) = separate(first, rest);

    let mut conflicted: StateMap<Vec<StoredEvent>> = StateMap::new();
    for (key, ids) in conflicted_ids {
        let events: Vec<StoredEvent> = ids.iter().filter_map(&fetch).collect();
        match events.len() {
            0 => {}
            1 => {
                if let Some(event) = events.into_iter().next() {
                    unconflicted.insert(key, event.event_id().clone());
                }
            }
            _ => {
                conflicted.insert(key, events);
            }
        }
    }

    // The auth events conflicted candidates are judged against: for each
    // type a candidate's auth rules ask about, the *unconflicted* value
    // (Synapse's `_create_auth_events_from_maps`).
    let mut auth_events: StateMap<StoredEvent> = StateMap::new();
    for events in conflicted.values() {
        for event in events {
            for key in auth_keys(rules, event)? {
                if auth_events.contains_key(&key) {
                    continue;
                }
                if let Some(event) = unconflicted.get(&key).and_then(&fetch) {
                    auth_events.insert(key, event);
                }
            }
        }
    }

    let mut resolved: StateMap<StoredEvent> = StateMap::new();
    let power_key = (StateEventType::RoomPowerLevels, String::new());
    if let Some(events) = conflicted.get(&power_key) {
        let winner = resolve_auth_events(rules, events, &auth_events)?;
        resolved.insert(power_key.clone(), winner);
    }
    extend(&mut auth_events, &resolved);

    for kind in [StateEventType::RoomJoinRules, StateEventType::RoomMember] {
        let mut keys: Vec<&(StateEventType, String)> =
            conflicted.keys().filter(|key| key.0 == kind).collect();
        // Synapse walks a dict in insertion order; each key here is
        // resolved against the same `auth_events`, so the order among keys
        // of one kind does not change any answer. Sorted for determinism.
        keys.sort_by(|left, right| left.1.cmp(&right.1));
        for key in keys {
            if let Some(events) = conflicted.get(key) {
                let winner = resolve_auth_events(rules, events, &auth_events)?;
                resolved.insert(key.clone(), winner);
            }
        }
        extend(&mut auth_events, &resolved);
    }

    for (key, events) in &conflicted {
        if !resolved.contains_key(key)
            && let Some(winner) = resolve_normal_events(rules, events, &auth_events)
        {
            resolved.insert(key.clone(), winner);
        }
    }

    for (key, event) in resolved {
        unconflicted.insert(key, event.event_id().clone());
    }
    Ok(unconflicted)
}

/// Split the sets into the keys they agree on and the keys they do not.
///
/// A key some sets lack is not conflicted by that absence; only two
/// different events under one key are (Synapse's split step in `state/v1.py`).
fn separate(
    first: &StateMap<OwnedEventId>,
    rest: &[StateMap<OwnedEventId>],
) -> (StateMap<OwnedEventId>, StateMap<BTreeSet<OwnedEventId>>) {
    let mut unconflicted = first.clone();
    let mut conflicted: StateMap<BTreeSet<OwnedEventId>> = StateMap::new();
    for set in rest {
        for (key, value) in set {
            match unconflicted.get(key) {
                None => match conflicted.get_mut(key) {
                    Some(values) => {
                        values.insert(value.clone());
                    }
                    None => {
                        unconflicted.insert(key.clone(), value.clone());
                    }
                },
                Some(existing) if existing != value => {
                    let existing = existing.clone();
                    unconflicted.remove(key);
                    conflicted.insert(key.clone(), BTreeSet::from([existing, value.clone()]));
                }
                Some(_) => {}
            }
        }
    }
    (unconflicted, conflicted)
}

fn extend(auth_events: &mut StateMap<StoredEvent>, resolved: &StateMap<StoredEvent>) {
    for (key, event) in resolved {
        auth_events.insert(key.clone(), event.clone());
    }
}

/// The `(type, state_key)` pairs the auth rules read for `event`.
fn auth_keys(
    rules: &AuthorizationRules,
    event: &StoredEvent,
) -> Result<Vec<(StateEventType, String)>, String> {
    auth_types_for_event(
        event.event_type(),
        event.sender(),
        event.state_key(),
        event.content(),
        rules,
    )
}

/// Whether `event` passes the state-dependent auth rules against `auth`.
fn allowed(rules: &AuthorizationRules, event: &StoredEvent, auth: &StateMap<StoredEvent>) -> bool {
    check_state_dependent_auth_rules(rules, event.clone(), |kind, state_key| {
        auth.get(&(kind.clone(), state_key.to_owned())).cloned()
    })
    .is_ok()
}

/// `(-depth, sha1_hex(event_id))` ascending: deepest first.
fn ordered(events: &[StoredEvent]) -> Vec<StoredEvent> {
    let mut sorted: Vec<(i64, String, StoredEvent)> = events
        .iter()
        .map(|event| {
            (
                -event.depth(),
                sha1_hex(event.event_id().as_str()),
                event.clone(),
            )
        })
        .collect();
    sorted.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
    sorted.into_iter().map(|(_, _, event)| event).collect()
}

/// Lower-case hex SHA-1 of an event ID, as Python's `hexdigest()` gives it.
fn sha1_hex(event_id: &str) -> String {
    use std::fmt::Write;
    Sha1::digest(event_id.as_bytes())
        .iter()
        .fold(String::with_capacity(40), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// Power levels, join rules, memberships: start at the earliest candidate
/// and step forward while the next one is authorized against the one
/// before it; the first refusal ends the walk on the last that passed.
fn resolve_auth_events(
    rules: &AuthorizationRules,
    events: &[StoredEvent],
    auth_events: &StateMap<StoredEvent>,
) -> Result<StoredEvent, String> {
    let mut reverse = ordered(events);
    reverse.reverse();

    // Only the auth events these candidates' rules actually read.
    let mut wanted = BTreeSet::new();
    for event in events {
        for key in auth_keys(rules, event)? {
            wanted.insert((key.0.to_string(), key.1));
        }
    }
    let mut auth: StateMap<StoredEvent> = auth_events
        .iter()
        .filter(|((kind, state_key), _)| wanted.contains(&(kind.to_string(), state_key.clone())))
        .map(|(key, event)| (key.clone(), event.clone()))
        .collect();

    let mut candidates = reverse.into_iter();
    let Some(mut previous) = candidates.next() else {
        return Err("no candidates to resolve".to_owned());
    };
    for event in candidates {
        auth.insert(
            (
                StateEventType::from(previous.event_type().to_string()),
                previous.state_key().unwrap_or_default().to_owned(),
            ),
            previous.clone(),
        );
        if !allowed(rules, &event, &auth) {
            return Ok(previous);
        }
        previous = event;
    }
    Ok(previous)
}

/// Every other key: the latest candidate that is authorized; failing all,
/// the earliest (Synapse returns the last one it tried).
fn resolve_normal_events(
    rules: &AuthorizationRules,
    events: &[StoredEvent],
    auth_events: &StateMap<StoredEvent>,
) -> Option<StoredEvent> {
    let ordered = ordered(events);
    for event in &ordered {
        if allowed(rules, event, auth_events) {
            return Some(event.clone());
        }
    }
    ordered.last().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const ROOM: &str = "!r:a.example";
    const ALICE: &str = "@alice:a.example";
    const BOB: &str = "@bob:b.example";
    const MALLORY: &str = "@mallory:m.example";

    fn rules() -> AuthorizationRules {
        ruma::RoomVersionId::V1.rules().unwrap().authorization
    }

    /// A v1 event: `[id, hashes]` edges, as the room writes them.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "every call site builds the content inline"
    )]
    fn event(
        id: &str,
        kind: &str,
        sender: &str,
        state_key: &str,
        content: Value,
        depth: i64,
    ) -> StoredEvent {
        StoredEvent::parse(
            id,
            &json!({
                "event_id": id,
                "room_id": ROOM,
                "type": kind,
                "sender": sender,
                "state_key": state_key,
                "content": content,
                "depth": depth,
                "origin_server_ts": depth,
                "prev_events": [["$p:a.example", { "sha256": "x" }]],
                "auth_events": [],
            }),
        )
        .unwrap()
    }

    struct Room {
        events: HashMap<OwnedEventId, StoredEvent>,
    }

    impl Room {
        fn new(events: Vec<StoredEvent>) -> Self {
            Self {
                events: events
                    .into_iter()
                    .map(|event| (event.event_id().clone(), event))
                    .collect(),
            }
        }

        fn base(&self) -> StateMap<OwnedEventId> {
            let mut state = StateMap::new();
            for id in [
                "$create:a.example",
                "$alice:a.example",
                "$rules:a.example",
                "$bob:b.example",
            ] {
                let event = &self.events[&OwnedEventId::try_from(id).unwrap()];
                state.insert(
                    (
                        StateEventType::from(event.event_type().to_string()),
                        event.state_key().unwrap().to_owned(),
                    ),
                    event.event_id().clone(),
                );
            }
            state
        }

        fn with(&self, mut state: StateMap<OwnedEventId>, id: &str) -> StateMap<OwnedEventId> {
            let event = &self.events[&OwnedEventId::try_from(id).unwrap()];
            state.insert(
                (
                    StateEventType::from(event.event_type().to_string()),
                    event.state_key().unwrap().to_owned(),
                ),
                event.event_id().clone(),
            );
            state
        }

        fn resolve(&self, sets: &[StateMap<OwnedEventId>]) -> StateMap<OwnedEventId> {
            resolve(&rules(), sets, |id| self.events.get(id).cloned()).unwrap()
        }
    }

    fn fixture(extra: Vec<StoredEvent>) -> Room {
        let mut events = vec![
            event(
                "$create:a.example",
                "m.room.create",
                ALICE,
                "",
                json!({ "creator": ALICE }),
                1,
            ),
            event(
                "$alice:a.example",
                "m.room.member",
                ALICE,
                ALICE,
                json!({ "membership": "join" }),
                2,
            ),
            event(
                "$rules:a.example",
                "m.room.join_rules",
                ALICE,
                "",
                json!({ "join_rule": "public" }),
                3,
            ),
            event(
                "$bob:b.example",
                "m.room.member",
                BOB,
                BOB,
                json!({ "membership": "join" }),
                4,
            ),
            event(
                "$mallory:m.example",
                "m.room.member",
                MALLORY,
                MALLORY,
                json!({ "membership": "join" }),
                4,
            ),
        ];
        events.extend(extra);
        Room::new(events)
    }

    fn key(kind: &str, state_key: &str) -> (StateEventType, String) {
        (StateEventType::from(kind.to_owned()), state_key.to_owned())
    }

    fn id(id: &str) -> OwnedEventId {
        OwnedEventId::try_from(id).unwrap()
    }

    /// One set is the answer; a key only some sets hold is not conflicted.
    #[test]
    fn agreement_and_absence_are_not_conflict() {
        let room = fixture(vec![event(
            "$topic:a.example",
            "m.room.topic",
            ALICE,
            "",
            json!({ "topic": "t" }),
            5,
        )]);
        let base = room.base();
        assert_eq!(room.resolve(std::slice::from_ref(&base)), base);
        let with_topic = room.with(base.clone(), "$topic:a.example");
        let resolved = room.resolve(&[base, with_topic.clone()]);
        assert_eq!(resolved, with_topic);
    }

    /// Ordinary keys take the deepest candidate the rules allow.
    #[test]
    fn a_conflicted_topic_takes_the_deepest_authorized_candidate() {
        let room = fixture(vec![
            event(
                "$t1:a.example",
                "m.room.topic",
                ALICE,
                "",
                json!({ "topic": "one" }),
                5,
            ),
            event(
                "$t2:a.example",
                "m.room.topic",
                ALICE,
                "",
                json!({ "topic": "two" }),
                9,
            ),
            // Deeper still, but Mallory is not a member in the state the
            // candidates are judged against, so the rules refuse it.
            event(
                "$t3:m.example",
                "m.room.topic",
                MALLORY,
                "",
                json!({ "topic": "x" }),
                12,
            ),
        ]);
        let base = room.base();
        let one = room.with(base.clone(), "$t1:a.example");
        let two = room.with(base.clone(), "$t2:a.example");
        let three = room.with(base, "$t3:m.example");
        let resolved = room.resolve(&[one.clone(), two.clone()]);
        assert_eq!(resolved[&key("m.room.topic", "")], id("$t2:a.example"));
        let resolved = room.resolve(&[one, two, three]);
        assert_eq!(resolved[&key("m.room.topic", "")], id("$t2:a.example"));
    }

    /// Power levels walk forward from the *earliest* candidate while each
    /// next one is allowed against the one before; the first refusal stops.
    #[test]
    fn conflicted_power_levels_walk_forward_from_the_earliest() {
        let promote_bob = json!({ "users": { ALICE: 100, BOB: 100 }, "state_default": 50 });
        let bob_adds_carol = json!({
            "users": { ALICE: 100, BOB: 100, "@carol:a.example": 50 },
            "state_default": 50,
        });
        let mallory_takes_over = json!({ "users": { MALLORY: 100 }, "state_default": 50 });
        let room = fixture(vec![
            event(
                "$pl1:a.example",
                "m.room.power_levels",
                ALICE,
                "",
                promote_bob,
                5,
            ),
            event(
                "$pl2:b.example",
                "m.room.power_levels",
                BOB,
                "",
                bob_adds_carol,
                6,
            ),
            event(
                "$pl3:m.example",
                "m.room.power_levels",
                MALLORY,
                "",
                mallory_takes_over,
                7,
            ),
        ]);
        let base = room.base();
        let first = room.with(base.clone(), "$pl1:a.example");
        let second = room.with(base.clone(), "$pl2:b.example");
        let third = room.with(base, "$pl3:m.example");

        // pl1 then pl2: bob holds 100 under pl1, so pl2 is allowed.
        let resolved = room.resolve(&[first.clone(), second.clone()]);
        assert_eq!(
            resolved[&key("m.room.power_levels", "")],
            id("$pl2:b.example")
        );
        // pl1, pl2, then pl3: mallory holds nothing under pl2, so the walk
        // stops at pl2 -- the deeper event does not win just by depth.
        let resolved = room.resolve(&[first, second, third]);
        assert_eq!(
            resolved[&key("m.room.power_levels", "")],
            id("$pl2:b.example")
        );
    }

    /// Equal depths are ordered by the SHA-1 of the event ID, Synapse's
    /// tie-break: the candidate whose hash sorts first is the "deepest".
    #[test]
    fn equal_depths_break_on_the_sha1_of_the_event_id() {
        let room = fixture(vec![
            event(
                "$ta:a.example",
                "m.room.topic",
                ALICE,
                "",
                json!({ "topic": "a" }),
                5,
            ),
            event(
                "$tb:a.example",
                "m.room.topic",
                ALICE,
                "",
                json!({ "topic": "b" }),
                5,
            ),
        ]);
        let base = room.base();
        let a = room.with(base.clone(), "$ta:a.example");
        let b = room.with(base, "$tb:a.example");
        let expected = if sha1_hex("$ta:a.example") < sha1_hex("$tb:a.example") {
            "$ta:a.example"
        } else {
            "$tb:a.example"
        };
        assert_eq!(
            room.resolve(&[a.clone(), b.clone()])[&key("m.room.topic", "")],
            id(expected)
        );
        assert_eq!(
            room.resolve(&[b, a])[&key("m.room.topic", "")],
            id(expected),
            "the answer does not depend on the order of the sets"
        );
    }
}
