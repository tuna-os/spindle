//! The full importer's room writer: chunked, resumable, complete at a
//! retained-history horizon, and able to take Synapse's resolved state where
//! Spindle's log cannot fold its own (#563).
//!
//! `cargo test -p spindle-server --features synapse-import --test
//! synapse_full_import`

#![cfg(feature = "synapse-import")]

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::import::{
    MemorySource, PlanError, SourceEvent, SourceRoom, StateMap, finish_room, persist_chunk, plan,
    plan_resolving, redactions_in, replay_resolving,
};
use spindle_server::rooms::Rooms;

const ROOM: &str = "!full:example.org";
const ALICE: &str = "@alice:example.org";
const BOB: &str = "@bob:remote.example";

fn source(id: &str, event_type: &str, state_key: Option<&str>, prev: &[&str]) -> SourceEvent {
    SourceEvent {
        event_id: id.to_owned(),
        event_type: event_type.to_owned(),
        state_key: state_key.map(str::to_owned),
        prev_events: prev.iter().map(|id| (*id).to_owned()).collect(),
        depth: 0,
        stream_ordering: 0,
        outlier: false,
        rejected: false,
    }
}

#[allow(clippy::needless_pass_by_value, reason = "built inline at every call")]
fn body(event: &SourceEvent, sender: &str, content: Value) -> Value {
    let mut json = json!({
        "room_id": ROOM,
        "type": event.event_type,
        "sender": sender,
        "origin_server_ts": 1_700_000_000_000_u64,
        "prev_events": event.prev_events,
        "auth_events": [],
        "depth": 1,
        "hashes": {"sha256": "unchecked"},
        "signatures": {},
        "content": content,
    });
    if let Some(state_key) = &event.state_key {
        json["state_key"] = Value::String(state_key.clone());
    }
    json
}

fn state(entries: &[(&str, &str, &str)]) -> StateMap {
    entries
        .iter()
        .map(|(event_type, state_key, id)| {
            (
                ((*event_type).to_owned(), (*state_key).to_owned()),
                (*id).to_owned(),
            )
        })
        .collect()
}

fn topic_of(rooms: &Rooms) -> Value {
    rooms
        .state(ROOM)
        .expect("the room has state")
        .into_iter()
        .find(|event| event["type"] == "m.room.topic")
        .expect("the topic is state")
}

fn store() -> (tempfile::TempDir, Arc<spindle_store::FjallStore>) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(spindle_store::FjallStore::open(directory.path()).unwrap());
    (directory, store)
}

/// A create-rooted room with a redaction, as Synapse holds it.
fn create_rooted() -> (SourceRoom, MemorySource) {
    let events = vec![
        source("$create", "m.room.create", Some(""), &[]),
        source("$alice", "m.room.member", Some(ALICE), &["$create"]),
        source("$one", "m.room.message", None, &["$alice"]),
        source("$two", "m.room.message", None, &["$one"]),
        source("$topic", "m.room.topic", Some(""), &["$two"]),
        source("$three", "m.room.message", None, &["$topic"]),
        source("$redaction", "m.room.redaction", None, &["$three"]),
    ];
    let mut bodies = HashMap::new();
    for event in &events {
        let content = match event.event_type.as_str() {
            "m.room.create" => json!({"creator": ALICE, "room_version": "10"}),
            "m.room.member" => json!({"membership": "join"}),
            "m.room.topic" => json!({"topic": "imported"}),
            "m.room.redaction" => json!({}),
            _ => json!({"msgtype": "m.text", "body": event.event_id}),
        };
        let mut json = body(event, ALICE, content);
        if event.event_type == "m.room.redaction" {
            json["redacts"] = json!("$two");
        }
        bodies.insert(event.event_id.clone(), json);
    }
    let room = SourceRoom {
        room_id: ROOM.to_owned(),
        events,
        current_state: state(&[
            ("m.room.create", "", "$create"),
            ("m.room.member", ALICE, "$alice"),
            ("m.room.topic", "", "$topic"),
        ]),
        state_after_root: None,
        forward_extremities: Vec::new(),
    };
    (
        room,
        MemorySource {
            bodies,
            states: HashMap::new(),
        },
    )
}

#[test]
fn an_import_cut_short_resumes_where_it_stopped() {
    let (room, mut source) = create_rooted();
    let plan = plan(&room).expect("the room plans");
    assert_eq!(plan.steps.len(), 7);

    let (_directory, store) = store();
    {
        let rooms = Rooms::new(Arc::clone(&store), "example.org");
        let (written, _) = persist_chunk(&rooms, ROOM, &plan.steps[..3], None, &mut source)
            .expect("the first chunk lands");
        assert_eq!(written, 3);
        // The process stops here: no finish, no redactions.
    }

    // A new process runs the whole plan again, chunk by chunk.
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let mut written = 0;
    for chunk in plan.steps.chunks(2) {
        written += persist_chunk(&rooms, ROOM, chunk, None, &mut source)
            .expect("resumes")
            .0;
    }
    assert_eq!(
        written, 4,
        "the three events already held are not appended again"
    );
    let redactions = redactions_in(&plan.steps, &|id| source.bodies.get(id));
    assert_eq!(finish_room(&rooms, ROOM, &redactions).expect("finishes"), 1);
    // And a third, complete run changes nothing.
    assert_eq!(
        persist_chunk(&rooms, ROOM, &plan.steps, None, &mut source)
            .expect("idempotent")
            .0,
        0
    );
    assert_eq!(finish_room(&rooms, ROOM, &redactions).expect("again"), 1);
    drop(rooms);

    let rooms = Rooms::new(store, "example.org");
    let topic = topic_of(&rooms);
    assert_eq!(topic["content"]["topic"], "imported");
    let redacted = rooms.event(ROOM, "$two").expect("the target reads");
    assert_eq!(redacted["content"], json!({}));
    let three = rooms.event(ROOM, "$three").expect("the last message reads");
    assert_eq!(three["content"]["body"], "$three");
    assert!(rooms.is_joined(ALICE, ROOM).unwrap());
}

#[test]
fn a_room_seeded_at_a_horizon_holds_the_state_before_it() {
    // Synapse joined this room over federation: the create event and Bob's
    // membership are outliers, and history starts at Alice's join.
    let create = source("$create", "m.room.create", Some(""), &[]);
    let bob = source("$bob", "m.room.member", Some(BOB), &["$create"]);
    let alice = source("$alice", "m.room.member", Some(ALICE), &["$elsewhere"]);
    let message = source("$hello", "m.room.message", None, &["$alice"]);
    let mut bodies = HashMap::new();
    bodies.insert(
        "$create".to_owned(),
        body(&create, BOB, json!({"creator": BOB, "room_version": "10"})),
    );
    bodies.insert(
        "$bob".to_owned(),
        body(&bob, BOB, json!({"membership": "join"})),
    );
    bodies.insert(
        "$alice".to_owned(),
        body(&alice, ALICE, json!({"membership": "join"})),
    );
    bodies.insert(
        "$hello".to_owned(),
        body(&message, ALICE, json!({"msgtype": "m.text", "body": "hi"})),
    );
    let mut outlier_create = create;
    outlier_create.outlier = true;
    let mut outlier_bob = bob;
    outlier_bob.outlier = true;
    let full = state(&[
        ("m.room.create", "", "$create"),
        ("m.room.member", BOB, "$bob"),
        ("m.room.member", ALICE, "$alice"),
    ]);
    let room = SourceRoom {
        room_id: ROOM.to_owned(),
        events: vec![outlier_create, outlier_bob, alice, message],
        current_state: full.clone(),
        state_after_root: Some(full),
        forward_extremities: Vec::new(),
    };
    let plan = plan(&room).expect("a horizon room plans with its root state");
    assert!(plan.seeded_from_source);
    assert_eq!(plan.steps.len(), 2);

    let (_directory, store) = store();
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let mut source = MemorySource {
        bodies,
        states: HashMap::new(),
    };
    persist_chunk(
        &rooms,
        ROOM,
        &plan.steps,
        room.state_after_root.as_ref(),
        &mut source,
    )
    .expect("the room persists");
    finish_room(&rooms, ROOM, &[]).expect("finishes");
    drop(rooms);

    let rooms = Rooms::new(store, "example.org");
    let state = rooms.state(ROOM).expect("every slot has its event");
    assert_eq!(state.len(), 3);
    assert_eq!(
        rooms
            .room_version(ROOM)
            .expect("the create event reads")
            .as_str(),
        "10"
    );
    assert!(
        rooms.is_joined(BOB, ROOM).unwrap(),
        "a member from before the horizon"
    );
    assert!(rooms.is_joined(ALICE, ROOM).unwrap());
}

/// A room with a second starting point (an event whose parents Synapse
/// never fetched) and a contested fork Spindle's log cannot fold.
fn gapped_and_contested() -> (SourceRoom, MemorySource) {
    let events = vec![
        source("$create", "m.room.create", Some(""), &[]),
        source("$alice", "m.room.member", Some(ALICE), &["$create"]),
        // Two branches each set the topic.
        source("$topic_a", "m.room.topic", Some(""), &["$alice"]),
        source("$topic_b", "m.room.topic", Some(""), &["$alice"]),
        // The merge Synapse resolved to topic B.
        source("$merge", "m.room.message", None, &["$topic_a", "$topic_b"]),
        // An event whose only parent is outside the retained history...
        source("$island", "m.room.message", None, &["$never_fetched"]),
        // ...and one joining it back to the room.
        source("$rejoin", "m.room.message", None, &["$merge", "$island"]),
    ];
    let mut bodies = HashMap::new();
    for event in &events {
        let content = match event.event_type.as_str() {
            "m.room.create" => json!({"creator": ALICE, "room_version": "10"}),
            "m.room.member" => json!({"membership": "join"}),
            "m.room.topic" => json!({"topic": event.event_id}),
            _ => json!({"msgtype": "m.text", "body": event.event_id}),
        };
        bodies.insert(event.event_id.clone(), body(event, ALICE, content));
    }
    let resolved = state(&[
        ("m.room.create", "", "$create"),
        ("m.room.member", ALICE, "$alice"),
        ("m.room.topic", "", "$topic_b"),
    ]);
    let mut states = HashMap::new();
    for id in ["$merge", "$island", "$rejoin"] {
        states.insert(id.to_owned(), resolved.clone());
    }
    let room = SourceRoom {
        room_id: ROOM.to_owned(),
        events,
        current_state: resolved,
        state_after_root: None,
        forward_extremities: Vec::new(),
    };
    (room, MemorySource { bodies, states })
}

#[test]
fn gaps_and_contested_forks_take_synapses_resolved_state() {
    let (room, mut source) = gapped_and_contested();
    assert!(
        matches!(plan(&room), Err(PlanError::MultipleRoots { .. })),
        "the strict plan refuses a second starting point"
    );
    let plan = plan_resolving(&room).expect("the resolving plan keeps it");
    assert_eq!(plan.steps.len(), 7);
    assert_eq!(plan.steps[0].input.event_id.as_str(), "$create");
    assert!(plan.excluded.is_empty());

    let resolved = replay_resolving(&room, &mut source, false).expect("replays");
    assert!(
        resolved.outcome.clean(),
        "diverges: {:?}",
        resolved.outcome.divergence
    );
    let took: Vec<&str> = resolved
        .from_source
        .iter()
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(took.contains(&"$island"), "{took:?}");
    assert!(took.contains(&"$merge"), "{took:?}");

    let (_directory, store) = store();
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let (written, from_source) =
        persist_chunk(&rooms, ROOM, &plan.steps, None, &mut source).expect("persists");
    assert_eq!(written, 7);
    assert_eq!(from_source.len(), resolved.from_source.len());
    finish_room(&rooms, ROOM, &[]).expect("finishes");
    drop(rooms);

    let rooms = Rooms::new(store, "example.org");
    let topic = topic_of(&rooms);
    assert_eq!(topic["content"]["topic"], "$topic_b");
    let rejoin = rooms.event(ROOM, "$rejoin").expect("the last event reads");
    assert_eq!(rejoin["content"]["body"], "$rejoin");
}
