use ruma::{CanonicalJsonObject, CanonicalJsonValue, RoomVersionId, signatures::Ed25519KeyPair};
use spindle_core::{Pdu, PduError};

const PKCS8: &[u8] = &[
    48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 216, 232, 206, 247, 95, 110, 193,
    132, 183, 160, 195, 251, 181, 31, 224, 248, 137, 253, 139, 211, 53, 117, 118, 152, 131, 220,
    254, 208, 52, 79, 238, 173, 129, 33, 0, 221, 51, 235, 105, 55, 51, 86, 64, 207, 77, 22, 151,
    224, 175, 128, 125, 75, 178, 199, 179, 51, 171, 85, 26, 125, 53, 242, 166, 121, 116, 183, 105,
];

fn event() -> CanonicalJsonObject {
    serde_json::from_value(serde_json::json!({
        "auth_events": [],
        "content": {"body": "hello", "msgtype": "m.text"},
        "depth": 1,
        "origin_server_ts": 1_700_000_000_000_u64,
        "prev_events": ["$parent"],
        "room_id": "!room:example.org",
        "sender": "@alice:example.org",
        "type": "m.room.message"
    }))
    .unwrap()
}

#[test]
fn signs_and_derives_a_stable_reference_hash_id() {
    let key_pair = Ed25519KeyPair::from_der(PKCS8, "test".to_owned()).unwrap();
    let first = Pdu::sign(RoomVersionId::V11, event(), "example.org", &key_pair).unwrap();
    let second = Pdu::sign(RoomVersionId::V11, event(), "example.org", &key_pair).unwrap();

    assert_eq!(first.event_id(), second.event_id());
    assert!(first.event_id().as_str().starts_with('$'));
    assert!(first.canonical().contains_key("hashes"));
    assert!(first.canonical().contains_key("signatures"));
}

#[test]
fn enforces_the_room_version_reference_bounds_before_signing() {
    let key_pair = Ed25519KeyPair::from_der(PKCS8, "test".to_owned()).unwrap();
    let mut event = event();
    event.insert(
        "prev_events".to_owned(),
        CanonicalJsonValue::Array(
            (0..21)
                .map(|number| CanonicalJsonValue::String(format!("$event-{number}")))
                .collect(),
        ),
    );

    assert_eq!(
        Pdu::sign(RoomVersionId::V12, event, "example.org", &key_pair).unwrap_err(),
        PduError::TooManyReferences {
            field: "prev_events",
            limit: 20,
            count: 21
        }
    );
}
