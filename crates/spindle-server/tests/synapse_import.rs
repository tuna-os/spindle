//! Ordering a Synapse room into a Spindle log, and proving it is the same room (#20).
//!
//! Every test here drives the importer from an in-memory [`SourceRoom`] rather
//! than a database. That is deliberate and it is not a weaker test: the part
//! of an import that can quietly produce a *different room* is the ordering
//! and the exclusions, and those are decided from the shape of the DAG alone.
//! A three-event room where the reader can check the expected answer by eye
//! exercises them more sharply than a real database dump, where a wrong order
//! is a needle in ten thousand rows.
//!
//! What this cannot catch is Synapse storing something differently than its
//! schema suggests — the reader that fills a `SourceRoom` from real tables is
//! where that risk lives, and it is tested where it lives.

use spindle_server::import::{
    Excluded, ImportError, PlanError, SourceEvent, SourceRoom, StateMap, plan, replay,
};

fn message(id: &str, prev: &[&str]) -> SourceEvent {
    SourceEvent {
        event_id: id.to_owned(),
        event_type: "m.room.message".to_owned(),
        state_key: None,
        prev_events: prev.iter().map(|id| (*id).to_owned()).collect(),
        depth: 0,
        stream_ordering: 0,
        outlier: false,
        rejected: false,
    }
}

fn state(id: &str, event_type: &str, state_key: &str, prev: &[&str]) -> SourceEvent {
    SourceEvent {
        state_key: Some(state_key.to_owned()),
        event_type: event_type.to_owned(),
        ..message(id, prev)
    }
}

fn create(id: &str) -> SourceEvent {
    state(id, "m.room.create", "", &[])
}

/// `(depth, stream_ordering)`, the two fields the sort is only allowed to use
/// as a tie-break.
fn ranked(mut event: SourceEvent, depth: u64, stream_ordering: i64) -> SourceEvent {
    event.depth = depth;
    event.stream_ordering = stream_ordering;
    event
}

fn current_state(pairs: &[(&str, &str, &str)]) -> StateMap {
    pairs
        .iter()
        .map(|(event_type, state_key, event_id)| {
            (
                ((*event_type).to_owned(), (*state_key).to_owned()),
                (*event_id).to_owned(),
            )
        })
        .collect()
}

fn room(events: Vec<SourceEvent>, state: StateMap) -> SourceRoom {
    SourceRoom {
        room_id: "!r:example.org".to_owned(),
        events,
        current_state: state,
        state_after_root: None,
    }
}

fn order(room: &SourceRoom) -> Vec<String> {
    plan(room)
        .expect("the room orders")
        .steps
        .iter()
        .map(|step| step.input.event_id.as_str().to_owned())
        .collect()
}

/// The exit criterion, on the simplest room that can have one.
///
/// Spindle folds every state event forward from `m.room.create` and arrives at
/// the same state Synapse reports. Nothing here is seeded from the source, so
/// the agreement is two independent computations matching rather than one
/// value compared with itself.
#[test]
fn a_room_replays_with_no_divergence() {
    let source = room(
        vec![
            create("$create"),
            state("$join_a", "m.room.member", "@a:example.org", &["$create"]),
            message("$hello", &["$join_a"]),
            state("$join_b", "m.room.member", "@b:example.org", &["$hello"]),
        ],
        current_state(&[
            ("m.room.create", "", "$create"),
            ("m.room.member", "@a:example.org", "$join_a"),
            ("m.room.member", "@b:example.org", "$join_b"),
        ]),
    );

    let outcome = replay(&source).expect("the room imports");

    assert!(outcome.clean(), "{:?}", outcome.divergence);
    assert_eq!(outcome.imported, 4);
    assert!(outcome.excluded.is_empty(), "{:?}", outcome.excluded);
    assert!(
        !outcome.seeded_from_source,
        "a create-rooted import claimed it was seeded from the source"
    );
}

/// A child that claims a *lower* depth than its parent still comes out after it.
///
/// `depth` is a signed field chosen by whoever sent the event. A remote server
/// can set it to anything, and Synapse — which has never had to trust it for
/// ordering — has no reason to reject a bad one. An importer that sorts by
/// depth builds the room in the order an attacker picked.
#[test]
fn a_lying_depth_does_not_reorder_the_room() {
    let source = room(
        vec![
            ranked(create("$create"), 500, 0),
            ranked(message("$child", &["$create"]), 1, 1),
        ],
        current_state(&[("m.room.create", "", "$create")]),
    );

    assert_eq!(order(&source), vec!["$create", "$child"]);
    assert!(replay(&source).expect("the room imports").clean());
}

/// A backfilled parent arrives after the child that sent us looking for it.
///
/// `stream_ordering` is arrival order. Federation backfill is the ordinary
/// case where arrival order and causal order disagree, so this is not an edge
/// case — it is every room the server joined rather than created.
#[test]
fn arrival_order_does_not_reorder_the_room() {
    let source = room(
        vec![
            ranked(create("$create"), 0, 9_000),
            ranked(message("$child", &["$create"]), 1, 1),
        ],
        current_state(&[("m.room.create", "", "$create")]),
    );

    assert_eq!(order(&source), vec!["$create", "$child"]);
}

/// Two events with no causal relation come out the same way round every time.
///
/// Not aesthetics: an import is a thing operators re-run after fixing
/// something, and two runs that produce two different logs make "did the
/// second run change anything?" unanswerable.
#[test]
fn unordered_events_are_ordered_deterministically() {
    let fork = |first: SourceEvent, second: SourceEvent| {
        room(
            vec![create("$create"), first, second],
            current_state(&[("m.room.create", "", "$create")]),
        )
    };
    let left = ranked(message("$left", &["$create"]), 1, 7);
    let right = ranked(message("$right", &["$create"]), 1, 7);

    assert_eq!(
        order(&fork(left.clone(), right.clone())),
        order(&fork(right, left)),
        "the same room in a different row order produced a different log"
    );
}

/// Outliers are held for somebody else's auth chain, not for this room.
#[test]
fn outliers_are_left_out_and_named() {
    let mut outlier = message("$outlier", &["$create"]);
    outlier.outlier = true;
    let source = room(
        vec![create("$create"), outlier],
        current_state(&[("m.room.create", "", "$create")]),
    );

    let outcome = replay(&source).expect("the room imports");

    assert_eq!(outcome.imported, 1);
    assert_eq!(
        outcome.excluded,
        vec![Excluded::Outlier("$outlier".to_owned())]
    );
    assert!(outcome.clean(), "{:?}", outcome.divergence);
}

/// A rejected event never entered the room's state, and must not enter Spindle's.
///
/// The failure this prevents is silent and permanent: an event Synapse refused
/// on auth grounds becomes part of the imported room's state, and the room now
/// says something no server ever accepted.
#[test]
fn a_rejected_state_event_does_not_reach_the_state() {
    let mut rejected = state("$sneak", "m.room.power_levels", "", &["$create"]);
    rejected.rejected = true;
    let source = room(
        vec![create("$create"), rejected],
        current_state(&[("m.room.create", "", "$create")]),
    );

    let outcome = replay(&source).expect("the room imports");

    assert_eq!(
        outcome.excluded,
        vec![Excluded::Rejected("$sneak".to_owned())]
    );
    assert!(
        outcome.clean(),
        "a rejected event reached the state: {:?}",
        outcome.divergence
    );
}

/// An event naming a parent the import does not have takes its descendants with it.
///
/// Appending it would mean either rewriting its signed `prev_events` — which
/// destroys the signature the whole exercise exists to preserve — or claiming
/// a parent we cannot show.
#[test]
fn a_frayed_event_and_everything_behind_it_are_named() {
    let source = room(
        vec![
            create("$create"),
            // Merges the room with history we do not hold.
            message("$merge", &["$create", "$elsewhere"]),
            message("$after", &["$merge"]),
        ],
        current_state(&[("m.room.create", "", "$create")]),
    );

    let outcome = replay(&source).expect("the room imports what it can");

    assert_eq!(outcome.imported, 1);
    assert_eq!(
        outcome.excluded,
        vec![
            Excluded::Orphaned {
                event_id: "$after".to_owned(),
                behind: "$merge".to_owned(),
            },
            Excluded::Frayed {
                event_id: "$merge".to_owned(),
                missing: "$elsewhere".to_owned(),
            },
        ]
    );
}

/// Two disconnected starting points are refused, not half-imported.
///
/// Only one event can seed a log, so the second would name parents the log
/// does not hold. Dropping the smaller side instead would import part of a
/// room and report success — the partial cutover #20 says must never happen.
#[test]
fn disconnected_history_is_refused_rather_than_half_imported() {
    let source = room(
        vec![
            create("$create"),
            // Its own island: no path to `$create`.
            message("$island", &[]),
            message("$island_child", &["$island"]),
        ],
        current_state(&[("m.room.create", "", "$create")]),
    );

    let error = plan(&source).expect_err("two starting points were accepted");

    let PlanError::MultipleRoots { roots, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(roots, &["$create".to_owned(), "$island".to_owned()]);
    // The refusal has to say why importing the larger half would be worse.
    let message = error.to_string();
    assert!(
        message.contains("importing part of a room"),
        "the refusal does not say why it refused: {message}"
    );
}

/// A cycle terminates with an error rather than never returning.
///
/// Unreachable through honest Matrix events, which are hash-linked. Reachable
/// through a corrupt or hand-edited database, and the wrong outcome is not a
/// bad import — it is a `migrate` that hangs on a store somebody is waiting to
/// bring back up.
#[test]
fn a_cycle_is_refused_rather_than_walked_forever() {
    let source = room(
        vec![
            create("$create"),
            message("$a", &["$create", "$b"]),
            message("$b", &["$a"]),
        ],
        current_state(&[("m.room.create", "", "$create")]),
    );

    let error = plan(&source).expect_err("a cycle was ordered");

    let PlanError::Cycle { events, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(events, &["$a".to_owned(), "$b".to_owned()]);
}

/// State the two servers disagree about is reported, from both directions.
///
/// A comparison that only walks the keys both sides have misses the two ways
/// an import loses a room quietly: a slot Spindle dropped, and a slot Spindle
/// invented.
#[test]
fn divergence_is_reported_in_both_directions() {
    let source = room(
        vec![
            create("$create"),
            state("$topic", "m.room.topic", "", &["$create"]),
        ],
        current_state(&[
            ("m.room.create", "", "$create"),
            // Synapse says a different event holds the topic...
            ("m.room.topic", "", "$other_topic"),
            // ...and holds a slot Spindle never saw an event for.
            ("m.room.name", "", "$name"),
        ]),
    );

    let outcome = replay(&source).expect("the room imports");

    assert!(!outcome.clean());
    let reported: Vec<(String, Option<String>, Option<String>)> = outcome
        .divergence
        .iter()
        .map(|item| {
            (
                item.key.event_type().as_str().to_owned(),
                item.spindle.clone(),
                item.synapse.clone(),
            )
        })
        .collect();
    assert_eq!(
        reported,
        vec![
            ("m.room.name".to_owned(), None, Some("$name".to_owned())),
            (
                "m.room.topic".to_owned(),
                Some("$topic".to_owned()),
                Some("$other_topic".to_owned()),
            ),
        ]
    );
}

/// History starting at a backfill horizon needs the source's state, and says so.
#[test]
fn a_horizon_start_without_state_is_refused() {
    let source = room(
        vec![
            // No create event: this is a room joined over federation, and
            // Synapse holds nothing before the join.
            state("$join", "m.room.member", "@a:example.org", &["$before_us"]),
            message("$after", &["$join"]),
        ],
        current_state(&[("m.room.member", "@a:example.org", "$join")]),
    );

    let error = plan(&source).expect_err("a horizon start was ordered without state");

    assert!(matches!(error, PlanError::NoRootState { .. }), "{error:?}");
    assert!(
        error.to_string().contains("m.room.create"),
        "the refusal does not explain what is missing: {error}"
    );
}

/// With that state supplied it imports — and the outcome says the comparison
/// is the weaker one.
///
/// An import seeded from Synapse's own state and then compared against Synapse
/// is partly comparing a value with itself. That is still a legitimate import
/// and still catches divergence in everything after the horizon, but it is not
/// the same evidence as folding forward from `m.room.create`, and a report
/// that does not distinguish them overstates one of them.
#[test]
fn a_horizon_start_with_state_imports_and_says_the_check_is_weaker() {
    let mut source = room(
        vec![
            state("$join", "m.room.member", "@a:example.org", &["$before_us"]),
            state("$topic", "m.room.topic", "", &["$join"]),
        ],
        current_state(&[
            ("m.room.create", "", "$create_elsewhere"),
            ("m.room.member", "@a:example.org", "$join"),
            ("m.room.topic", "", "$topic"),
        ]),
    );
    source.state_after_root = Some(current_state(&[
        ("m.room.create", "", "$create_elsewhere"),
        ("m.room.member", "@a:example.org", "$join"),
    ]));

    let outcome = replay(&source).expect("the room imports");

    assert!(outcome.clean(), "{:?}", outcome.divergence);
    assert!(
        outcome.seeded_from_source,
        "an import seeded from the source did not say so"
    );
}

/// A fork over two different state slots replays and both writes survive.
///
/// Synapse rooms fork routinely, and this is the arrangement that regressed
/// once already (#225): two branches writing *different* keys that already
/// held values looked contested and were refused. An import is where that
/// surfaces as a room that cannot be moved at all.
#[test]
fn a_fork_on_separate_state_slots_replays() {
    let source = room(
        vec![
            create("$create"),
            state("$topic0", "m.room.topic", "", &["$create"]),
            state("$name0", "m.room.name", "", &["$topic0"]),
            // Two branches from the same parent, each moving its own slot.
            state("$topic1", "m.room.topic", "", &["$name0"]),
            state("$name1", "m.room.name", "", &["$name0"]),
            message("$merge", &["$topic1", "$name1"]),
        ],
        current_state(&[
            ("m.room.create", "", "$create"),
            ("m.room.topic", "", "$topic1"),
            ("m.room.name", "", "$name1"),
        ]),
    );

    let outcome = replay(&source).expect("a forked room imports");

    assert_eq!(outcome.imported, 6);
    assert!(outcome.clean(), "{:?}", outcome.divergence);
}

/// A room with nothing importable in it says so rather than reporting success.
#[test]
fn a_room_of_only_outliers_is_refused() {
    let mut outlier = create("$create");
    outlier.outlier = true;
    let source = room(vec![outlier], StateMap::new());

    let error = replay(&source).expect_err("an empty import reported success");

    assert!(
        matches!(error, ImportError::Plan(PlanError::NoEvents { .. })),
        "{error:?}"
    );
}
