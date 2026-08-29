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
                                                state_key TEXT);",
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

/// History starting at a backfill horizon is refused, naming what would fix it.
///
/// The reader knows *why* the state is missing, so it says so rather than
/// handing `plan` a room it would refuse for a vaguer reason. Resolving it
/// means walking Synapse's state groups, which are deltas chained through
/// `state_group_edges`.
#[test]
fn a_room_without_a_create_event_names_state_groups() {
    let connection = minimal();
    event(
        &connection,
        "$join",
        "m.room.member",
        Some("@a:e.example"),
        1,
    );

    let error = read_room(&connection, ROOM).unwrap_err();
    let ReadError::NeedsStateGroups { root, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(root, "$join");
    assert!(
        error.to_string().contains("state_group_edges"),
        "the refusal does not name what would resolve it: {error}"
    );
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

/// The whole path, against Synapse's own DDL: build the fixture, read it,
/// replay it, and compare the result with what Synapse says the room is.
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
    assert_eq!(listed, vec!["!fixture:example.org".to_owned()]);

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
}
