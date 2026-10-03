//! Reading a room out of Synapse's tables (#20).
//!
//! Behind the `synapse-import` feature, so: `cargo test -p spindle-server
//! --features synapse-import --test synapse_reader`.
//!
//! Most of these build a **minimal** database carrying only the columns the
//! reader queries. That is not a weaker test than the real schema for what
//! they check: each one encodes a shape Synapse really produces and the reader
//! really has to survive, and building it by hand is what lets the wrong
//! answer be visible in six lines of setup rather than buried in 172 tables.
//!
//! The end-to-end test does use Synapse's own DDL, via
//! `scripts/synapse-fixture.py --populate`, and skips without a checkout --
//! because column *names* are exactly what a hand-built schema cannot check.

#![cfg(feature = "synapse-import")]

use rusqlite::Connection;
use spindle_server::import::replay;
use spindle_server::import::synapse::{ReadError, read_room, rooms};

const ROOM: &str = "!r:example.org";

/// Only the columns the reader reads, so a wrong answer is visible by eye.
fn minimal() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE rooms (room_id TEXT PRIMARY KEY, room_version TEXT);
             CREATE TABLE events (event_id TEXT, type TEXT, room_id TEXT, state_key TEXT,
                                  depth BIGINT, stream_ordering BIGINT, outlier BOOL,
                                  rejection_reason TEXT);
             CREATE TABLE event_edges (event_id TEXT, prev_event_id TEXT, room_id TEXT,
                                       is_state BOOL NOT NULL DEFAULT 0);
             CREATE TABLE current_state_events (event_id TEXT, room_id TEXT, type TEXT,
                                                state_key TEXT);
             CREATE TABLE event_to_state_groups (event_id TEXT, state_group BIGINT);
             CREATE TABLE state_group_edges (state_group BIGINT, prev_state_group BIGINT);
             CREATE TABLE state_groups_state (state_group BIGINT, room_id TEXT, type TEXT,
                                              state_key TEXT, event_id TEXT);",
        )
        .unwrap();
    connection
        .execute("INSERT INTO rooms VALUES (?, '11')", [ROOM])
        .unwrap();
    connection
}

fn event(connection: &Connection, id: &str, event_type: &str, state_key: Option<&str>, order: i64) {
    connection
        .execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, 0, NULL)",
            rusqlite::params![id, event_type, ROOM, state_key, order, order],
        )
        .unwrap();
}

/// `room_id` is passed explicitly because it is nullable in Synapse and the
/// tests need to write both cases.
fn edge(connection: &Connection, child: &str, parent: &str, room_id: Option<&str>, is_state: bool) {
    connection
        .execute(
            "INSERT INTO event_edges VALUES (?, ?, ?, ?)",
            rusqlite::params![child, parent, room_id, is_state],
        )
        .unwrap();
}

fn creation(connection: &Connection) {
    event(connection, "$create", "m.room.create", Some(""), 1);
}

fn parents_of(connection: &Connection, id: &str) -> Vec<String> {
    read_room(connection, ROOM)
        .expect("the room reads")
        .events
        .into_iter()
        .find(|event| event.event_id == id)
        .expect("the event is there")
        .prev_events
}

/// A legacy `is_state` edge is not a parent.
///
/// `event_edges` once held two sorts of edge, and the state ones are marked.
/// Synapse's removal of them is a background update that may never have
/// completed, so a live database can still carry one — and a reader that takes
/// it builds a merge that never happened. The wrong answer is *plausible data*,
/// not an error, which is what makes it worth a test.
#[test]
fn a_legacy_state_edge_is_not_treated_as_a_parent() {
    let connection = minimal();
    creation(&connection);
    event(&connection, "$rules", "m.room.join_rules", Some(""), 2);
    event(&connection, "$topic", "m.room.topic", Some(""), 3);
    edge(&connection, "$rules", "$create", Some(ROOM), false);
    edge(&connection, "$topic", "$rules", Some(ROOM), false);
    // The legacy one, pointing somewhere the real DAG does not.
    edge(&connection, "$topic", "$create", Some(ROOM), true);

    assert_eq!(parents_of(&connection, "$topic"), vec!["$rules".to_owned()]);
}

/// An edge whose `room_id` is NULL is still the room's edge.
///
/// The column was added to a table that already had rows, so scoping with
/// `WHERE event_edges.room_id = ?` drops every edge older than the backfill —
/// and the room then reads as a pile of disconnected roots. Synapse joins
/// `events` and filters that `room_id`; so must this.
#[test]
fn an_edge_predating_the_room_id_column_is_still_read() {
    let connection = minimal();
    creation(&connection);
    event(&connection, "$next", "m.room.message", None, 2);
    edge(&connection, "$next", "$create", None, false);

    assert_eq!(parents_of(&connection, "$next"), vec!["$create".to_owned()]);
}

/// Rejection is a column on `events`, not only the older `rejections` table.
#[test]
fn a_rejected_event_is_reported_as_rejected() {
    let connection = minimal();
    creation(&connection);
    connection
        .execute(
            "INSERT INTO events VALUES ('$no', 'm.room.power_levels', ?, '', 2, 2, 0, 'auth_error')",
            [ROOM],
        )
        .unwrap();

    let room = read_room(&connection, ROOM).unwrap();
    let rejected = room.events.iter().find(|e| e.event_id == "$no").unwrap();
    assert!(
        rejected.rejected,
        "the rejection_reason column was not read"
    );
}

#[test]
fn an_outlier_is_reported_as_one() {
    let connection = minimal();
    creation(&connection);
    connection
        .execute(
            "INSERT INTO events VALUES ('$out', 'm.room.member', ?, '@m:e.example', 2, 2, 1, NULL)",
            [ROOM],
        )
        .unwrap();

    let room = read_room(&connection, ROOM).unwrap();
    assert!(
        room.events
            .iter()
            .find(|e| e.event_id == "$out")
            .unwrap()
            .outlier
    );
}

/// Current state comes back keyed the way the comparison expects.
#[test]
fn current_state_is_read() {
    let connection = minimal();
    creation(&connection);
    connection
        .execute(
            "INSERT INTO current_state_events VALUES ('$create', ?, 'm.room.create', '')",
            [ROOM],
        )
        .unwrap();

    let room = read_room(&connection, ROOM).unwrap();
    assert_eq!(
        room.current_state
            .get(&("m.room.create".to_owned(), String::new())),
        Some(&"$create".to_owned())
    );
}

/// A room the database does not have is an error, not an empty room.
///
/// An empty `SourceRoom` would flow into `plan`, be refused for having no
/// events, and report a confusing failure about a room that was never there.
#[test]
fn an_absent_room_is_refused_by_name() {
    let connection = minimal();
    let error = read_room(&connection, "!nope:example.org").unwrap_err();
    assert!(matches!(error, ReadError::UnknownRoom(_)), "{error:?}");
}

/// Write one slot of a state group.
fn slot(connection: &Connection, group: i64, event_type: &str, state_key: &str, event_id: &str) {
    connection
        .execute(
            "INSERT INTO state_groups_state VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![group, ROOM, event_type, state_key, event_id],
        )
        .unwrap();
}

fn group_edge(connection: &Connection, group: i64, parent: i64) {
    connection
        .execute(
            "INSERT INTO state_group_edges VALUES (?, ?)",
            rusqlite::params![group, parent],
        )
        .unwrap();
}

/// A room Synapse joined over federation: its history starts at `$join`,
/// whose parent it never fetched, and the state after `$join` is group 3 --
/// a delta on group 2, itself a delta on the full state in group 1.
fn horizon() -> Connection {
    let connection = minimal();
    event(
        &connection,
        "$join",
        "m.room.member",
        Some("@c:e.example"),
        1,
    );
    event(&connection, "$after", "m.room.message", None, 2);
    edge(&connection, "$join", "$unfetched", Some(ROOM), false);
    edge(&connection, "$after", "$join", Some(ROOM), false);
    connection
        .execute("INSERT INTO event_to_state_groups VALUES ('$join', 3)", [])
        .unwrap();

    slot(&connection, 1, "m.room.create", "", "$create");
    slot(&connection, 1, "m.room.member", "@a:e.example", "$a");
    slot(&connection, 1, "m.room.join_rules", "", "$invite_only");
    group_edge(&connection, 2, 1);
    // Group 2 changes the join rules; group 1's value must not survive.
    slot(&connection, 2, "m.room.join_rules", "", "$public");
    group_edge(&connection, 3, 2);
    slot(&connection, 3, "m.room.member", "@c:e.example", "$join");

    for (event_type, state_key, event_id) in [
        ("m.room.create", "", "$create"),
        ("m.room.member", "@a:e.example", "$a"),
        ("m.room.join_rules", "", "$public"),
        ("m.room.member", "@c:e.example", "$join"),
    ] {
        connection
            .execute(
                "INSERT INTO current_state_events VALUES (?, ?, ?, ?)",
                rusqlite::params![event_id, ROOM, event_type, state_key],
            )
            .unwrap();
    }
    connection
}

fn key(event_type: &str, state_key: &str) -> (String, String) {
    (event_type.to_owned(), state_key.to_owned())
}

/// The state at a horizon root is the whole delta chain, newest value first.
///
/// Reading only the root's own group would give one slot -- `$join` -- and an
/// import seeded from it would start the room without its creator, its other
/// members or its join rules. Reading the chain oldest-wins would give the
/// join rules group 2 replaced. Both are plausible-looking states.
#[test]
fn a_horizon_root_reads_its_state_through_the_delta_chain() {
    let connection = horizon();
    let room = read_room(&connection, ROOM).expect("the horizon room reads");
    let state = room.state_after_root.expect("no state was attached");

    assert_eq!(state.len(), 4, "{state:?}");
    assert_eq!(state[&key("m.room.create", "")], "$create");
    assert_eq!(state[&key("m.room.member", "@a:e.example")], "$a");
    assert_eq!(state[&key("m.room.member", "@c:e.example")], "$join");
    assert_eq!(
        state[&key("m.room.join_rules", "")],
        "$public",
        "an older group's value overrode a newer one"
    );
}

/// With the state attached, the horizon room replays with no divergence --
/// and the outcome says the check was seeded from the source.
#[test]
fn a_horizon_room_replays_and_says_it_was_seeded() {
    let connection = horizon();
    let room = read_room(&connection, ROOM).unwrap();
    let outcome = replay(&room).expect("the horizon room replays");

    assert!(outcome.clean(), "{:?}", outcome.divergence);
    assert!(outcome.seeded_from_source);
    assert_eq!(outcome.imported, 2);
}

/// A create-rooted room gets no seeded state: it folds forward from nothing,
/// which is the stronger check, and reading state groups would weaken it.
#[test]
fn a_create_rooted_room_is_not_seeded() {
    let connection = minimal();
    creation(&connection);
    connection
        .execute(
            "INSERT INTO event_to_state_groups VALUES ('$create', 1)",
            [],
        )
        .unwrap();
    slot(&connection, 1, "m.room.create", "", "$create");

    let room = read_room(&connection, ROOM).unwrap();
    assert!(room.state_after_root.is_none());
}

/// A horizon root with no state group is refused, naming the root.
#[test]
fn a_horizon_root_without_a_state_group_is_refused() {
    let connection = minimal();
    event(
        &connection,
        "$join",
        "m.room.member",
        Some("@a:e.example"),
        1,
    );

    let error = read_room(&connection, ROOM).unwrap_err();
    let ReadError::MissingStateGroup { root, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(root, "$join");
    assert!(
        error.to_string().contains("event_to_state_groups"),
        "the refusal does not name where it looked: {error}"
    );
}

/// A chain that loops is refused rather than walked forever or cut short.
#[test]
fn a_state_group_cycle_is_refused() {
    let connection = horizon();
    connection
        .execute("DELETE FROM state_group_edges WHERE state_group = 2", [])
        .unwrap();
    group_edge(&connection, 2, 3);

    let error = read_room(&connection, ROOM).unwrap_err();
    assert!(
        matches!(error, ReadError::StateGroupCycle { .. }),
        "{error:?}"
    );
}

/// A group with two parents is refused rather than resolved by row order.
#[test]
fn a_state_group_with_two_parents_is_refused() {
    let connection = horizon();
    group_edge(&connection, 3, 1);

    let error = read_room(&connection, ROOM).unwrap_err();
    let ReadError::AmbiguousStateGroup {
        state_group,
        parents,
        ..
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(*state_group, 3);
    assert_eq!(parents.len(), 2);
}

#[test]
fn rooms_are_listed() {
    let connection = minimal();
    connection
        .execute("INSERT INTO rooms VALUES ('!a:example.org', '11')", [])
        .unwrap();
    assert_eq!(
        rooms(&connection).unwrap(),
        vec!["!a:example.org".to_owned(), ROOM.to_owned()]
    );
}

/// The whole path, against Synapse's own DDL: build the fixture, read both of
/// its rooms, replay them, and compare the result with what Synapse says each
/// room is.
///
/// This is the one that checks *column names*, which a hand-built schema
/// cannot. Skipped without a checkout; point `SYNAPSE_SOURCE` at one to run it.
#[test]
fn the_populated_fixture_reads_and_replays_without_divergence() {
    let Ok(source) = std::env::var("SYNAPSE_SOURCE") else {
        eprintln!("skipped: set SYNAPSE_SOURCE to a Synapse checkout to run this one");
        return;
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("fixture.db");
    let built = std::process::Command::new("python3")
        .arg(root.join("scripts/synapse-fixture.py"))
        .args(["--synapse", &source])
        .arg("--out")
        .arg(&fixture)
        .args(["--populate", "--quiet"])
        .output()
        .expect("python3 runs");
    assert!(
        built.status.success(),
        "building the fixture failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let connection = Connection::open(&fixture).unwrap();
    let listed = rooms(&connection).unwrap();
    assert_eq!(
        listed,
        vec![
            "!fixture:example.org".to_owned(),
            "!horizon:example.org".to_owned()
        ]
    );

    let fixture_room =
        read_room(&connection, "!fixture:example.org").expect("the fixture room reads");
    // The fixture carries a legacy is_state edge on $topic; if the reader took
    // it, $topic would have two parents and the DAG would hold a merge that
    // never happened.
    let topic = fixture_room
        .events
        .iter()
        .find(|event| event.event_id == "$topic")
        .unwrap();
    assert_eq!(
        topic.prev_events,
        vec!["$hello".to_owned()],
        "the legacy is_state edge was read as a parent"
    );

    let outcome = replay(&fixture_room).expect("the fixture room replays");
    assert!(
        outcome.clean(),
        "the fixture room diverged: {:?}",
        outcome.divergence
    );
    assert_eq!(outcome.imported, 8, "{:?}", outcome.excluded);

    // The horizon room: no m.room.create in its timeline, so its starting
    // state comes from a three-group delta chain in the real state tables.
    let horizon = read_room(&connection, "!horizon:example.org").expect("the horizon room reads");
    let state = horizon
        .state_after_root
        .as_ref()
        .expect("no state was read for the horizon root");
    assert_eq!(state.len(), 4, "{state:?}");
    assert_eq!(
        state[&("m.room.join_rules".to_owned(), String::new())],
        "$h_public",
        "an older state group's value overrode a newer one"
    );
    let outcome = replay(&horizon).expect("the horizon room replays");
    assert!(
        outcome.clean(),
        "the horizon room diverged: {:?}",
        outcome.divergence
    );
    assert!(outcome.seeded_from_source);
    assert_eq!(outcome.imported, 2, "{:?}", outcome.excluded);
}
