//! #34 / SPEC §19.2: our fast path against ruma's reference state resolver.
//!
//! SPEC §9.3 claims that window-bounded resolution produces exactly what full
//! state resolution would. That is a theorem, and this is the differential test
//! that treats it as one: build a fork, resolve it both ways, compare.
//!
//! The scope is deliberate and worth stating. Spindle only *claims* to skip
//! state resolution for §9.2's cases 1 and 2 — a fork whose sides touched
//! disjoint state slots. A genuine same-slot conflict is case 3, which we hand
//! to `ruma-state-res` and where agreement is therefore trivial. So the
//! interesting assertion is: **for every fork the fast path claims to handle
//! without state resolution, the reference resolver agrees.** A disagreement
//! here is a counterexample to §9.3 and a release blocker.

mod oracle;

use std::collections::BTreeMap;

use oracle::{ALICE, BOB, RoomBuilder, reference_resolve};
use ruma::state_res::StateMap;
use ruma::{OwnedEventId, events::TimelineEventType};
use serde_json::json;
use spindle_core::{EventInput, RoomLog, StateKey, StateSnapshot};

/// Both representations of one resolved state, keyed identically for comparison.
fn normalize(state: &StateMap<OwnedEventId>) -> BTreeMap<(String, String), String> {
    state
        .iter()
        .map(|((event_type, key), id)| {
            (
                (event_type.to_string(), key.clone()),
                id.as_str().to_owned(),
            )
        })
        .collect()
}

fn normalize_ours(state: &StateSnapshot) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    state.for_each(|key, event_id| {
        out.insert(
            (
                key.event_type().as_str().to_owned(),
                key.state_key().to_owned(),
            ),
            event_id.to_owned(),
        );
    });
    out
}

/// Replay a set of `(state_key, event_id)` writes into a `RoomLog` in the order
/// given, as a single chain, and return the head.
fn replay(log: &mut RoomLog, writes: &[(StateKey, String)], parent: Option<&str>) -> String {
    let mut head = parent.map(str::to_owned);
    for (key, event_id) in writes {
        let input = match &head {
            Some(parent) => EventInput::new(
                event_id.clone(),
                vec![spindle_core::EventId::new(parent.clone())],
            ),
            None => EventInput::new(event_id.clone(), vec![]),
        }
        .with_state_key(key.clone());
        log.append_remote(input).unwrap();
        head = Some(event_id.clone());
    }
    head.expect("at least one write")
}

/// One branch's divergent state writes, recorded as they are made so the same
/// events can be replayed into a `RoomLog` without restating their identifiers.
struct Branch {
    builder: RoomBuilder,
    writes: Vec<(StateKey, String)>,
}

impl Branch {
    fn fork(base: &RoomBuilder, label: &str) -> Self {
        Self {
            builder: base.fork(label),
            writes: Vec::new(),
        }
    }

    fn write(
        &mut self,
        sender: &str,
        event_type: &TimelineEventType,
        state_key: &str,
        content: &serde_json::Value,
    ) {
        let id = self.builder.add(
            sender,
            event_type.clone(),
            Some(state_key.to_owned()),
            content,
        );
        self.writes.push((
            StateKey::new(event_type.to_string(), state_key),
            id.as_str().to_owned(),
        ));
    }
}

/// Resolve a two-branch fork both ways and assert they agree.
///
/// Returns the resolved key count so a caller can assert the fork was
/// substantial, rather than trusting that it built what it meant to.
fn assert_equivalent(base: &RoomBuilder, left: &Branch, right: &Branch) -> usize {
    let mut graph = left.builder.fork("-g");
    graph.absorb(&right.builder);
    let reference = reference_resolve(
        &graph,
        &left.builder.state_map(),
        &right.builder.state_map(),
    );

    // The same fork through Spindle: shared history, then both branches, then
    // one local event to merge them.
    let mut log = RoomLog::new();
    let shared = base.state_map();
    let mut ordered: Vec<_> = shared.iter().collect();
    ordered.sort_by_key(|(_, id)| id.as_str().to_owned());
    let ancestry: Vec<(StateKey, String)> = ordered
        .iter()
        .map(|((event_type, key), id)| {
            (
                StateKey::new(event_type.to_string(), key.clone()),
                id.as_str().to_owned(),
            )
        })
        .collect();
    let ancestor = replay(&mut log, &ancestry, None);
    let left_head = replay(&mut log, &left.writes, Some(&ancestor));
    let right_head = replay(&mut log, &right.writes, Some(&ancestor));

    assert_eq!(
        log.forward_extremities().len(),
        2,
        "the fork must actually be a fork"
    );

    // Found by ancestry, and bounded by the fork rather than by the room.
    let window = log
        .fork_window(
            &[
                spindle_core::EventId::new(left_head),
                spindle_core::EventId::new(right_head),
            ],
            512,
        )
        .expect("this fork is well within the window");
    assert_eq!(
        window.events.len(),
        left.writes.len() + right.writes.len(),
        "the window must be exactly the divergent ancestry"
    );
    assert_eq!(window.nearest_common_ancestor.as_str(), ancestor);
    assert!(
        window.visited < log.len(),
        "visiting {} of {} entries is a full scan, not a bounded window",
        window.visited,
        log.len()
    );

    let merged = log.append_local("$merge", None).unwrap().li;
    let ours = normalize_ours(log.state_after(merged).expect("the head is resident"));
    let theirs = normalize(&reference);

    // Guard against a vacuous pass. Two empty maps are equal, and so are two
    // that only carry the shared ancestry -- neither would say anything about
    // the merge. Every divergent *slot* has to survive into the result, holding
    // the last event that wrote it: a branch that writes one slot twice should
    // contribute only its later event, so checking every write would demand
    // that a superseded one survive.
    let mut expected: BTreeMap<(String, String), String> = BTreeMap::new();
    for (key, event_id) in left.writes.iter().chain(&right.writes) {
        expected.insert(
            (
                key.event_type().as_str().to_owned(),
                key.state_key().to_owned(),
            ),
            event_id.clone(),
        );
    }
    for (key, event_id) in &expected {
        assert_eq!(
            theirs.get(key),
            Some(event_id),
            "the reference resolution dropped or superseded a divergent write at {key:?}"
        );
    }

    assert_eq!(
        ours, theirs,
        "window-bounded resolution disagreed with ruma-state-res"
    );
    theirs.len()
}

/// The load-bearing case: two forks touching different state slots.
///
/// Spindle merges these without invoking state resolution at all (SPEC 9.2
/// case 2). The reference resolver, which has no such shortcut, must still land
/// on the same map.
#[test]
fn a_disjoint_fork_resolves_the_same_way_as_the_reference_resolver() {
    let base = RoomBuilder::new();

    let mut left = Branch::fork(&base, "-l");
    left.write(
        ALICE,
        &TimelineEventType::RoomTopic,
        "",
        &json!({ "topic": "left" }),
    );

    let mut right = Branch::fork(&base, "-r");
    right.write(
        BOB,
        &TimelineEventType::RoomMember,
        BOB,
        &json!({ "membership": "join" }),
    );

    // create, alice, PL, join_rules + topic + bob.
    assert_eq!(assert_equivalent(&base, &left, &right), 6);
}

/// A one-event fork barely exercises a *window*. This one is several events
/// deep on both sides, so the reverse search has real ancestry to walk and the
/// merge has more than one slot per side to reconcile.
#[test]
fn a_deep_disjoint_fork_resolves_the_same_way_as_the_reference_resolver() {
    let base = RoomBuilder::new();

    let mut left = Branch::fork(&base, "-l");
    left.write(
        ALICE,
        &TimelineEventType::RoomTopic,
        "",
        &json!({ "topic": "first" }),
    );
    left.write(
        ALICE,
        &TimelineEventType::RoomName,
        "",
        &json!({ "name": "left" }),
    );
    // Rewriting a slot this branch already wrote: the later event wins, and it
    // must be the later one that survives the merge.
    left.write(
        ALICE,
        &TimelineEventType::RoomTopic,
        "",
        &json!({ "topic": "second" }),
    );

    let mut right = Branch::fork(&base, "-r");
    right.write(
        BOB,
        &TimelineEventType::RoomMember,
        BOB,
        &json!({ "membership": "join" }),
    );
    right.write(
        ALICE,
        &TimelineEventType::RoomGuestAccess,
        "",
        &json!({ "guest_access": "forbidden" }),
    );

    // create, alice, PL, join_rules + topic, name + bob, guest_access.
    assert_eq!(assert_equivalent(&base, &left, &right), 8);
}

/// A fork where both sides wrote the *same* slot is case 3. Spindle does not
/// claim to resolve it cheaply — it refuses and defers, which is the honest
/// behaviour and the one §9.2 specifies.
#[test]
fn a_conflicting_fork_is_deferred_rather_than_guessed() {
    let mut log = RoomLog::new();
    let root = log
        .append_local("$root", Some(StateKey::new("m.room.create", "")))
        .unwrap()
        .event_id
        .clone();

    for side in ["$left", "$right"] {
        log.append_remote(
            EventInput::new(side, vec![root.clone()])
                .with_state_key(StateKey::new("m.room.topic", "")),
        )
        .unwrap();
    }

    let error = log.append_local("$merge", None).unwrap_err();
    match error {
        spindle_core::AppendError::NeedsStateResolution { key, candidates } => {
            assert_eq!(key, StateKey::new("m.room.topic", ""));
            assert_eq!(candidates.len(), 2);
        }
        other => panic!("a same-slot conflict must defer, got {other:?}"),
    }
}
