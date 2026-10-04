//! A redaction carried over from Synapse still redacts.
//!
//! Synapse keeps a redacted event's original JSON in `event_json` and
//! strips it when the event is read. An import that copies the bodies
//! verbatim therefore brings back what a sender deleted, readable by
//! anyone in the room on the new server. The E2EE migration rig found it:
//! all four redacted targets read back with their content after the import.
//!
//! `cargo test -p spindle-server --features synapse-import --test
//! synapse_rehearsal_redaction`

#![cfg(feature = "synapse-import")]

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::import::{SourceEvent, SourceRoom, StateMap, persist_rehearsal};
use spindle_server::rooms::Rooms;

const ROOM: &str = "!redact:example.org";
const ALICE: &str = "@alice:example.org";

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

fn body(id: &str, event: &SourceEvent, content: Value, extra: &[(&str, Value)]) -> Value {
    let mut json = json!({
        "event_id": id,
        "room_id": ROOM,
        "type": event.event_type,
        "sender": ALICE,
        "origin_server_ts": 1_700_000_000_000_u64,
        "prev_events": event.prev_events,
        "auth_events": [],
        "depth": 1,
        "hashes": {"sha256": "unchecked"},
        "signatures": {},
    });
    json["content"] = content;
    if let Some(state_key) = &event.state_key {
        json["state_key"] = Value::String(state_key.clone());
    }
    for (key, value) in extra {
        json[*key] = value.clone();
    }
    json
}

#[test]
fn an_imported_redaction_redacts_its_target() {
    let create = source("$create", "m.room.create", Some(""), &[]);
    let member = source("$member", "m.room.member", Some(ALICE), &["$create"]);
    let secret = source("$secret", "m.room.message", None, &["$member"]);
    let kept = source("$kept", "m.room.message", None, &["$secret"]);
    let redaction = source("$redaction", "m.room.redaction", None, &["$kept"]);

    let mut bodies = BTreeMap::new();
    bodies.insert(
        "$create".to_owned(),
        body(
            "$create",
            &create,
            json!({"creator": ALICE, "room_version": "10"}),
            &[],
        ),
    );
    bodies.insert(
        "$member".to_owned(),
        body("$member", &member, json!({"membership": "join"}), &[]),
    );
    bodies.insert(
        "$secret".to_owned(),
        body(
            "$secret",
            &secret,
            json!({"msgtype": "m.text", "body": "deleted by its sender"}),
            &[],
        ),
    );
    bodies.insert(
        "$kept".to_owned(),
        body(
            "$kept",
            &kept,
            json!({"msgtype": "m.text", "body": "still here"}),
            &[],
        ),
    );
    // Room v10: the target is the top-level `redacts`.
    bodies.insert(
        "$redaction".to_owned(),
        body(
            "$redaction",
            &redaction,
            json!({"reason": "oops"}),
            &[("redacts", json!("$secret"))],
        ),
    );

    let current: StateMap = [
        (
            ("m.room.create".to_owned(), String::new()),
            "$create".to_owned(),
        ),
        (
            ("m.room.member".to_owned(), ALICE.to_owned()),
            "$member".to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let room = SourceRoom {
        room_id: ROOM.to_owned(),
        events: vec![create, member, secret, kept, redaction],
        current_state: current,
        state_after_root: None,
        forward_extremities: Vec::new(),
    };

    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(spindle_store::FjallStore::open(directory.path()).unwrap());
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let outcome = persist_rehearsal(&rooms, &room, &bodies).expect("the room persists");
    assert_eq!(outcome.imported, 5);
    drop(rooms);

    // Read through a fresh facade: what a client gets after a restart.
    let rooms = Rooms::new(store, "example.org");
    let redacted = rooms.event(ROOM, "$secret").expect("the target reads");
    assert_eq!(
        redacted["content"],
        json!({}),
        "the redacted content came back: {redacted}"
    );
    assert_eq!(
        redacted["unsigned"]["redacted_because"]["event_id"],
        "$redaction"
    );
    let kept = rooms.event(ROOM, "$kept").expect("the other message reads");
    assert_eq!(kept["content"]["body"], "still here");
    let redaction = rooms
        .event(ROOM, "$redaction")
        .expect("the redaction reads");
    assert_eq!(redaction["redacts"], "$secret");
}

#[test]
fn imported_rejections_survive_reopen_without_entering_the_timeline() {
    let create = source("$create", "m.room.create", Some(""), &[]);
    let member = source("$member", "m.room.member", Some(ALICE), &["$create"]);
    let mut rejected = source("$rejected", "m.room.member", Some(ALICE), &["$member"]);
    rejected.rejected = true;
    let bodies = BTreeMap::from([
        (
            "$create".to_owned(),
            body(
                "$create",
                &create,
                json!({"creator": ALICE, "room_version": "10"}),
                &[],
            ),
        ),
        (
            "$member".to_owned(),
            body("$member", &member, json!({"membership": "join"}), &[]),
        ),
        (
            "$rejected".to_owned(),
            body("$rejected", &rejected, json!({"membership": "ban"}), &[]),
        ),
    ]);
    let room = SourceRoom {
        room_id: ROOM.to_owned(),
        events: vec![create, member, rejected],
        current_state: StateMap::from([
            (
                ("m.room.create".to_owned(), String::new()),
                "$create".to_owned(),
            ),
            (
                ("m.room.member".to_owned(), ALICE.to_owned()),
                "$member".to_owned(),
            ),
        ]),
        state_after_root: None,
        forward_extremities: Vec::new(),
    };
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(spindle_store::FjallStore::open(directory.path()).unwrap());
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    assert_eq!(
        persist_rehearsal(&rooms, &room, &bodies).unwrap().imported,
        2
    );
    drop(rooms);
    let restored = spindle_store::RoomStore::new(store.as_ref(), ROOM)
        .load()
        .unwrap()
        .unwrap();
    assert!(
        restored
            .log
            .historically_rejected(&spindle_core::EventId::new("$rejected"))
    );
    assert!(
        restored
            .log
            .get(&spindle_core::EventId::new("$rejected"))
            .is_none()
    );
    let rooms = Rooms::new(store, "example.org");
    assert!(rooms.event(ROOM, "$rejected").is_err());
    assert_eq!(
        rooms.pdu(ROOM, "$rejected").unwrap()["content"]["membership"],
        "ban"
    );
    assert_eq!(
        rooms
            .state_event_full(ROOM, "m.room.member", ALICE)
            .unwrap()["content"]["membership"],
        "join"
    );
}
