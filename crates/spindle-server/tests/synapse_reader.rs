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

use std::sync::Arc;

use rusqlite::Connection;
use spindle_server::account_data::AccountData;
use spindle_server::backups::Backups;
use spindle_server::devices::Devices;
use spindle_server::import::synapse::postgres::Reader as PostgresReader;
use spindle_server::import::synapse::recovery::restore as restore_recovery;
use spindle_server::import::synapse::{ReadError, read_room, rooms};
use spindle_server::import::{ImportError, PlanError, persist_rehearsal, replay};
use spindle_server::rooms::Rooms;

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

/// A real Synapse room exported into the four tables this reader consumes.
///
/// This is deliberately opt-in: CI has no production database, while an
/// operator rehearsing a migration needs to run the exact reader and replay
/// against real rows rather than only the synthesized fixture below. The
/// export contains event metadata and current state, not message bodies.
#[test]
fn an_exported_live_room_reads_replays_and_matches_synapse_state() {
    let (Ok(database), Ok(room_id)) = (
        std::env::var("SPINDLE_LIVE_SYNAPSE_DB"),
        std::env::var("SPINDLE_LIVE_SYNAPSE_ROOM"),
    ) else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_DB and SPINDLE_LIVE_SYNAPSE_ROOM");
        return;
    };

    let connection = Connection::open(database).expect("the exported database opens");
    let source = read_room(&connection, &room_id).expect("the real room reads");
    let expected = source
        .events
        .iter()
        .filter(|event| !event.outlier && !event.rejected)
        .count();
    let outcome = replay(&source).expect("the real room replays");

    assert_eq!(
        outcome.imported, expected,
        "the replay dropped accepted events"
    );
    assert!(
        outcome.clean(),
        "the replay diverged from Synapse state: {:?}",
        outcome.divergence
    );
    assert!(
        !outcome.seeded_from_source,
        "the create-rooted rehearsal unexpectedly used source-seeded state"
    );
    eprintln!(
        "rehearsed {} accepted events; excluded {}; state slots match",
        outcome.imported,
        outcome.excluded.len()
    );
}

fn live_postgres_reader() -> Option<PostgresReader> {
    let Ok(config) = std::env::var("SPINDLE_LIVE_SYNAPSE_POSTGRES") else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_POSTGRES");
        return None;
    };
    let password = std::env::var("SPINDLE_LIVE_SYNAPSE_PASSWORD").ok();
    Some(
        PostgresReader::connect_no_tls(&config, password.as_deref())
            .expect("the live Synapse PostgreSQL database connects"),
    )
}

/// Read and replay one production room without first copying it to SQLite.
#[test]
fn a_live_postgres_room_reads_replays_and_matches_synapse_state() {
    let (Some(mut reader), Ok(room_id)) = (
        live_postgres_reader(),
        std::env::var("SPINDLE_LIVE_SYNAPSE_ROOM"),
    ) else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_ROOM");
        return;
    };
    let mut snapshot = reader.snapshot().expect("the source snapshot starts");
    let source = snapshot
        .read_room(&room_id)
        .expect("the production room reads directly from PostgreSQL");
    let expected = source
        .events
        .iter()
        .filter(|event| !event.outlier && !event.rejected)
        .count();
    let outcome = replay(&source).expect("the production room replays");

    assert_eq!(outcome.imported, expected);
    assert!(
        outcome.clean(),
        "the replay diverged from Synapse state: {:?}",
        outcome.divergence
    );
    eprintln!(
        "read and rehearsed {} accepted events directly from PostgreSQL",
        outcome.imported
    );
}

/// Classify every joined room in one consistent live PostgreSQL snapshot.
///
/// Known migration blockers are results, not reasons to stop the audit: the
/// point is to measure their prevalence before any cutover. Database errors,
/// corrupt cycles and append failures remain test failures.
#[test]
fn every_live_postgres_room_is_classified() {
    let (Some(mut reader), Ok(server_name)) = (
        live_postgres_reader(),
        std::env::var("SPINDLE_LIVE_SYNAPSE_SERVER_NAME"),
    ) else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_SERVER_NAME");
        return;
    };
    let mut snapshot = reader.snapshot().expect("the source snapshot starts");
    let rooms = snapshot
        .joined_rooms(&server_name)
        .expect("joined rooms are listed");

    let mut clean = 0usize;
    let mut divergent = 0usize;
    let mut needs_state_groups = 0usize;
    let mut multiple_roots = 0usize;
    let mut needs_state_resolution = 0usize;
    let mut accepted_events = 0usize;
    let mut replayed_events = 0usize;
    let mut excluded_events = 0usize;
    let mut unexpected = Vec::new();

    for (index, room_id) in rooms.iter().enumerate() {
        if index % 10 == 0 {
            eprintln!("auditing joined room {}/{}", index + 1, rooms.len());
        }
        let source = match snapshot.read_room(room_id) {
            Ok(source) => source,
            Err(ReadError::NeedsStateGroups { .. }) => {
                needs_state_groups += 1;
                continue;
            }
            Err(error) => {
                unexpected.push(format!("{room_id}: {error}"));
                continue;
            }
        };
        accepted_events += source
            .events
            .iter()
            .filter(|event| !event.outlier && !event.rejected)
            .count();
        match replay(&source) {
            Ok(outcome) => {
                replayed_events += outcome.imported;
                excluded_events += outcome.excluded.len();
                if outcome.clean() {
                    clean += 1;
                } else {
                    divergent += 1;
                }
            }
            Err(ImportError::Plan(PlanError::MultipleRoots { .. })) => multiple_roots += 1,
            Err(ImportError::Append {
                error: spindle_core::AppendError::NeedsStateResolution { .. },
                ..
            }) => needs_state_resolution += 1,
            Err(error) => unexpected.push(format!("{room_id}: {error}")),
        }
    }

    eprintln!(
        "live PostgreSQL audit: rooms={} clean={clean} divergent={divergent} \
         needs_state_groups={needs_state_groups} multiple_roots={multiple_roots} \
         needs_state_resolution={needs_state_resolution} \
         accepted_events={accepted_events} replayed_events={replayed_events} \
         excluded_events={excluded_events}",
        rooms.len()
    );
    assert!(
        unexpected.is_empty(),
        "unexpected live-read failures: {unexpected:#?}"
    );
    assert_eq!(
        clean + divergent + needs_state_groups + multiple_roots + needs_state_resolution,
        rooms.len(),
        "every joined room must have an explicit migration outcome"
    );
}

/// Persist a real user's opaque recovery material into an empty Spindle store
/// and read every category back without decrypting or logging any secret.
#[test]
fn a_live_users_encrypted_recovery_data_round_trips() {
    let (Some(mut reader), Ok(user_id)) = (
        live_postgres_reader(),
        std::env::var("SPINDLE_LIVE_SYNAPSE_USER"),
    ) else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_USER");
        return;
    };
    let mut snapshot = reader.snapshot().expect("the source snapshot starts");
    let source = snapshot
        .recovery_data(&user_id)
        .expect("the live recovery records read");

    let directory = tempfile::tempdir().expect("a rehearsal directory");
    let store = Arc::new(
        spindle_store::FjallStore::open(directory.path()).expect("the rehearsal store opens"),
    );
    let account_data = AccountData::new(Arc::clone(&store));
    let devices = Devices::new(Arc::clone(&store));
    let backups = Backups::new(store);
    let outcome = restore_recovery(&source, &account_data, &devices, &backups)
        .expect("the recovery records persist");

    for row in &source.account_data {
        let restored = account_data
            .get(&user_id, &row.room_id, &row.event_type)
            .expect("account data reads back");
        assert!(
            restored.as_ref() == Some(&row.content),
            "account data changed while restoring {}",
            row.event_type
        );
    }
    for row in &source.device_keys {
        let mut restored = devices
            .device_keys(&user_id, &row.device_id)
            .expect("device keys read back")
            .expect("the restored device exists");
        let mut source_keys = row.keys.clone();
        if let Some(object) = restored.as_object_mut() {
            object.remove("signatures");
        }
        if let Some(object) = source_keys.as_object_mut() {
            object.remove("signatures");
        }
        assert!(
            restored == source_keys,
            "device key material changed while restoring {}",
            row.device_id
        );
    }
    for version in &source.backup_versions {
        let restored = backups
            .version(&user_id, version.version)
            .expect("backup metadata reads back");
        if version.deleted {
            assert!(restored.is_none());
            continue;
        }
        let restored = restored.expect("the live backup version exists");
        assert_eq!(restored.algorithm, version.algorithm);
        assert!(
            restored.auth_data == version.auth_data,
            "backup authentication data changed for version {}",
            version.version
        );
        assert_eq!(restored.etag, version.etag);
        assert_eq!(
            restored.count,
            source
                .backup_sessions
                .iter()
                .filter(|session| session.version == version.version)
                .count() as u64
        );
    }
    assert_eq!(
        outcome.signatures + outcome.skipped_signatures,
        source.signatures.len()
    );
    eprintln!(
        "persisted opaque recovery data: account_data={} device_keys={} \
         cross_signing_keys={} signatures={} skipped_signatures={} \
         backup_versions={} backup_sessions={}",
        outcome.account_data,
        outcome.device_keys,
        outcome.cross_signing_keys,
        outcome.signatures,
        outcome.skipped_signatures,
        outcome.backup_versions,
        outcome.backup_sessions
    );
}

/// Persist a real room's original signed bodies and read its timeline back
/// after constructing a fresh `Rooms` facade over the same store.
#[test]
fn a_live_postgres_room_persists_with_its_message_bodies() {
    let (Some(mut reader), Ok(room_id)) = (
        live_postgres_reader(),
        std::env::var("SPINDLE_LIVE_SYNAPSE_ROOM"),
    ) else {
        eprintln!("skipped: set SPINDLE_LIVE_SYNAPSE_ROOM");
        return;
    };
    let mut snapshot = reader.snapshot().expect("the source snapshot starts");
    let source = snapshot.read_room(&room_id).expect("the live room reads");
    let bodies = snapshot
        .event_bodies(&room_id)
        .expect("the original signed bodies read");

    let directory = tempfile::tempdir().expect("a rehearsal directory");
    let store = Arc::new(
        spindle_store::FjallStore::open(directory.path()).expect("the rehearsal store opens"),
    );
    let server_name = std::env::var("SPINDLE_LIVE_SYNAPSE_SERVER_NAME")
        .unwrap_or_else(|_| "example.org".to_owned());
    let rooms = Rooms::new(Arc::clone(&store), &server_name);
    let outcome =
        persist_rehearsal(&rooms, &source, &bodies).expect("the room persists after validation");
    drop(rooms);

    let restarted = Rooms::new(store, &server_name);
    let (timeline, _) = restarted
        .messages(&room_id, None, outcome.imported + 1)
        .expect("the imported timeline reads after restart");
    assert_eq!(timeline.len(), outcome.imported);
    for event in &timeline {
        let expected = bodies
            .get(&event.event_id)
            .expect("every persisted event came from Synapse")
            .clone();
        assert!(
            event.json == expected,
            "stored event JSON changed for {}",
            event.event_id
        );
    }
    let messages = timeline
        .iter()
        .filter(|event| {
            matches!(
                event.json["type"].as_str(),
                Some("m.room.message" | "m.room.encrypted")
            )
        })
        .count();
    assert!(messages > 0, "the rehearsal room had no message history");
    eprintln!(
        "persisted and restarted {} original events, including {messages} message events",
        timeline.len()
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
