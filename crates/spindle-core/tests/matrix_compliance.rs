use std::collections::BTreeMap;

use ruma::{
    CanonicalJsonObject, RoomVersionId,
    serde::Base64,
    signatures::{Ed25519KeyPair, PublicKeyMap, Verified, verify_event},
};
use spindle_core::Pdu;

const PKCS8: &[u8] = &[
    48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 216, 232, 206, 247, 95, 110, 193,
    132, 183, 160, 195, 251, 181, 31, 224, 248, 137, 253, 139, 211, 53, 117, 118, 152, 131, 220,
    254, 208, 52, 79, 238, 173, 129, 33, 0, 221, 51, 235, 105, 55, 51, 86, 64, 207, 77, 22, 151,
    224, 175, 128, 125, 75, 178, 199, 179, 51, 171, 85, 26, 125, 53, 242, 166, 121, 116, 183, 105,
];

fn event() -> CanonicalJsonObject {
    serde_json::from_value(serde_json::json!({
        "auth_events": [],
        "content": {"body": "spec fixture", "msgtype": "m.text"},
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
fn room_v12_event_passes_ruma_signature_and_content_hash_verification() {
    let key_pair = Ed25519KeyPair::from_der(PKCS8, "test".to_owned()).unwrap();
    let pdu = Pdu::sign(
        RoomVersionId::V12,
        event(),
        "example.org",
        &key_pair,
    )
    .unwrap();

    let mut server_keys = BTreeMap::new();
    server_keys.insert(
        "ed25519:test".into(),
        Base64::new(key_pair.public_key().to_vec()),
    );
    let mut public_keys = PublicKeyMap::new();
    public_keys.insert("example.org".into(), server_keys);
    let rules = RoomVersionId::V12.rules().unwrap();

    assert_eq!(
        verify_event(&public_keys, pdu.canonical(), &rules).unwrap(),
        Verified::All
    );
}
