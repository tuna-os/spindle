//! Auth dependency retention is atomic and does not become room history.
//! Signature verification belongs to the inbound recovery transport; these
//! fixtures supply events signed by the known room creator.

use std::sync::Arc;

use ruma::CanonicalJsonValue;
use serde_json::{Value, json};
use spindle_core::Pdu;
use spindle_server::rooms::Rooms;
use spindle_server::signing::ServerKey;
use spindle_store::FjallStore;
use tempfile::TempDir;

const ALICE: &str = "@alice:example.org";

struct Fixture {
    dir: TempDir,
    rooms: Rooms,
    key: ServerKey,
    room: String,
    version: String,
}

impl Fixture {
    fn new(version: u8) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let key = ServerKey::load_or_create(store.as_ref()).unwrap();
        let rooms = Rooms::new(store, "example.org");
        let version = version.to_string();
        let room = rooms
            .create(
                ALICE,
                key.pair(),
                None,
                None,
                None,
                &[],
                &[],
                Some(&version),
                None,
                None,
                &serde_json::Map::new(),
            )
            .unwrap();
        Self {
            dir,
            rooms,
            key,
            room,
            version,
        }
    }

    fn power_body(&self) -> Value {
        let state = self.rooms.state(&self.room).unwrap();
        let powers = state
            .iter()
            .find(|event| event["type"] == "m.room.power_levels")
            .unwrap();
        self.rooms
            .pdu(&self.room, powers["event_id"].as_str().unwrap())
            .unwrap()
    }

    fn sign(&self, mut body: Value, tick: u64) -> (String, Value) {
        body["origin_server_ts"] = json!(body["origin_server_ts"].as_u64().unwrap() + tick);
        if let Some(object) = body.as_object_mut() {
            object.remove("event_id");
            object.remove("unsigned");
        }
        let CanonicalJsonValue::Object(canonical) = CanonicalJsonValue::try_from(body).unwrap()
        else {
            unreachable!()
        };
        let pdu = Pdu::sign(
            self.version.as_str().try_into().unwrap(),
            canonical,
            "example.org",
            self.key.pair(),
        )
        .unwrap();
        (
            pdu.event_id().as_str().to_owned(),
            serde_json::to_value(pdu.canonical()).unwrap(),
        )
    }

    fn valid_auth(&self) -> (String, Value) {
        let mut body = self.power_body();
        body["content"]["users_default"] = json!(1);
        self.sign(body, 1)
    }
}

#[test]
fn recovered_auth_is_available_after_reopen_without_changing_state_or_heads() {
    for version in 1..=12 {
        let fixture = Fixture::new(version);
        let before = fixture.rooms.state(&fixture.room).unwrap();
        let heads = fixture.rooms.remote_recovery_heads(&fixture.room).unwrap();
        let event = fixture.valid_auth();
        fixture
            .rooms
            .retain_remote_auth(&fixture.room, std::slice::from_ref(&event))
            .unwrap();
        assert_eq!(
            fixture.rooms.pdu(&fixture.room, &event.0).unwrap(),
            event.1,
            "version {version}"
        );
        assert_eq!(fixture.rooms.state(&fixture.room).unwrap(), before);
        assert_eq!(
            fixture.rooms.remote_recovery_heads(&fixture.room).unwrap(),
            heads
        );
        let (prev, auth) = fixture
            .rooms
            .missing_remote_dependencies(
                &fixture.room,
                &json!({"prev_events":[event.0],"auth_events":[event.0]}),
            )
            .unwrap();
        assert_eq!(prev, [event.0.clone()]);
        assert!(
            auth.is_empty(),
            "an auth body does not supply predecessor state"
        );
        let room = fixture.room.clone();
        let path = fixture.dir.path().to_owned();
        drop(fixture.rooms);
        let reopened = Rooms::new(Arc::new(FjallStore::open(path).unwrap()), "example.org");
        assert_eq!(reopened.pdu(&room, &event.0).unwrap(), event.1);
        assert_eq!(reopened.remote_recovery_heads(&room).unwrap(), heads);
    }
}

#[test]
fn one_unauthorized_dependency_prevents_every_write_in_the_batch() {
    let fixture = Fixture::new(11);
    let good = fixture.valid_auth();
    let mut body = fixture.power_body();
    body["sender"] = json!("@mallory:example.org");
    let bad = fixture.sign(body, 2);
    assert!(
        fixture
            .rooms
            .retain_remote_auth(&fixture.room, &[good.clone(), bad.clone()])
            .is_err()
    );
    assert!(fixture.rooms.pdu(&fixture.room, &good.0).is_err());
    assert!(fixture.rooms.pdu(&fixture.room, &bad.0).is_err());
}

#[test]
fn foreign_room_and_wrong_event_ids_are_refused() {
    let fixture = Fixture::new(11);
    let good = fixture.valid_auth();
    assert!(
        fixture
            .rooms
            .retain_remote_auth(&fixture.room, &[("$wrong".to_owned(), good.1.clone())])
            .is_err()
    );
    let mut body = fixture.power_body();
    body["room_id"] = json!("!foreign:example.org");
    let foreign = fixture.sign(body, 3);
    assert!(
        fixture
            .rooms
            .retain_remote_auth(&fixture.room, std::slice::from_ref(&foreign))
            .is_err()
    );
    assert!(fixture.rooms.pdu(&fixture.room, &foreign.0).is_err());
}

#[test]
fn an_existing_body_cannot_be_replaced_by_dependency_retrieval() {
    let fixture = Fixture::new(11);
    let event = fixture.valid_auth();
    fixture
        .rooms
        .retain_remote_auth(&fixture.room, std::slice::from_ref(&event))
        .unwrap();
    let mut replacement = event.1.clone();
    replacement["content"]["users_default"] = json!(100);
    fixture
        .rooms
        .retain_remote_auth(&fixture.room, &[(event.0.clone(), replacement)])
        .unwrap();
    assert_eq!(fixture.rooms.pdu(&fixture.room, &event.0).unwrap(), event.1);
}
