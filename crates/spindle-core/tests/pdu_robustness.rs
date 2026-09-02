//! Part of #267, target 2: the first thing a peer's bytes become.
//!
//! `Pdu::from_remote` is the boundary where a stranger's JSON turns into an
//! event this server will hash, verify and authorize. Everything after it
//! is ruma's, and ruma has its own fuzzing; this is the hand-written part,
//! so it is the part that gets fed garbage here.

use proptest::prelude::*;
use ruma::{CanonicalJsonValue, RoomVersionId};
use serde_json::{Map, Value, json};
use spindle_core::Pdu;

/// Any JSON at all, a few levels deep.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|number| json!(number)),
        any::<u64>().prop_map(|number| json!(number)),
        any::<f64>().prop_map(|number| json!(number)),
        "\\PC{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(5, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("\\PC{0,12}", inner, 0..6)
                .prop_map(|fields| Value::Object(fields.into_iter().collect())),
        ]
    })
}

/// A PDU every check accepts, to mutate one field at a time.
fn honest_pdu() -> Map<String, Value> {
    let Value::Object(pdu) = json!({
        "type": "m.room.message",
        "sender": "@bob:peer.example",
        "room_id": "!room:example.org",
        "content": { "msgtype": "m.text", "body": "hello" },
        "origin_server_ts": 1_700_000_000_000_u64,
        "depth": 11,
        "prev_events": ["$prev"],
        "auth_events": ["$create", "$member"],
    }) else {
        unreachable!("a literal object")
    };
    pdu
}

/// What `receive_one_pdu` does with a value: canonicalise, then parse.
fn receive(value: Value) -> Option<Result<Pdu, spindle_core::PduError>> {
    match CanonicalJsonValue::try_from(value) {
        Ok(CanonicalJsonValue::Object(canonical)) => {
            Some(Pdu::from_remote(RoomVersionId::V11, canonical))
        }
        _ => None,
    }
}

#[test]
fn the_honest_pdu_is_accepted() {
    let pdu = receive(Value::Object(honest_pdu()))
        .expect("an object")
        .expect("a valid PDU");
    assert!(pdu.event_id().as_str().starts_with('$'));
}

proptest! {
    /// Any JSON value, whatever shape, decodes or refuses.
    #[test]
    fn arbitrary_json_parses_or_refuses(value in any_json()) {
        let _ = std::hint::black_box(receive(value));
    }

    /// The honest PDU with one field replaced by anything. Every field
    /// `validate` reads gets the wrong type, the wrong range, and the
    /// wrong shape in turn.
    #[test]
    fn one_wrong_field_parses_or_refuses(
        field in prop::sample::select(vec![
            "type", "sender", "room_id", "content", "origin_server_ts",
            "depth", "prev_events", "auth_events", "state_key", "hashes",
            "signatures", "unsigned",
        ]),
        replacement in any_json(),
    ) {
        let mut pdu = honest_pdu();
        pdu.insert(field.to_owned(), replacement);
        let _ = std::hint::black_box(receive(Value::Object(pdu)));
    }

    /// Reference lists at, around and past the bounds, holding anything.
    #[test]
    fn reference_lists_of_any_length_parse_or_refuse(
        field in prop::sample::select(vec!["prev_events", "auth_events"]),
        references in prop::collection::vec(any_json(), 0..40),
    ) {
        let mut pdu = honest_pdu();
        pdu.insert(field.to_owned(), Value::Array(references));
        let _ = std::hint::black_box(receive(Value::Object(pdu)));
    }

    /// Depth at every edge an `i64` has. Canonical JSON refuses integers
    /// past 2^53 before `from_remote` sees them, and `validate` refuses
    /// negatives after; either way the only accepted range is the spec's.
    #[test]
    fn any_depth_parses_or_refuses(depth: i64) {
        let mut pdu = honest_pdu();
        pdu.insert("depth".to_owned(), json!(depth));
        let accepted = receive(Value::Object(pdu)).is_some_and(|outcome| outcome.is_ok());
        prop_assert_eq!(accepted, (0..=(1_i64 << 53) - 1).contains(&depth));
    }
}
