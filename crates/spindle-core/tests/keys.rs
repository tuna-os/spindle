//! Part of #6: the durable key encoding must sort the way the log does.

use proptest::prelude::*;
use spindle_core::{
    EventInput, LinearIndex, RoomLog, StateSnapshot,
    keys::{Keyspace, from_order_preserving, li_from_key, order_preserving, room_li, room_prefix},
};

proptest! {
    /// The property everything else rests on.
    #[test]
    fn byte_order_matches_numeric_order(left: i64, right: i64) {
        prop_assert_eq!(
            order_preserving(left).cmp(&order_preserving(right)),
            left.cmp(&right)
        );
    }

    #[test]
    fn encoding_round_trips(value: i64) {
        prop_assert_eq!(from_order_preserving(order_preserving(value)), value);
    }

    #[test]
    fn keys_recover_their_index(li: i64) {
        let key = room_li(Keyspace::Log, "!room:example.org", LinearIndex::from_raw(li));
        prop_assert_eq!(li_from_key(&key), Some(li));
    }
}

/// The bug this encoding exists to prevent, pinned so nobody "simplifies" the
/// sign flip away later.
#[test]
fn a_naive_big_endian_encoding_would_sort_backfill_last() {
    let backfilled = -1_i64;
    let live = 1_i64;

    // Naive: two's complement puts the sign bit high, so negative sorts last.
    assert!(
        backfilled.to_be_bytes() > live.to_be_bytes(),
        "if this ever passes, the naive encoding became safe and this test is obsolete"
    );

    // Ours orders them correctly.
    assert!(order_preserving(backfilled) < order_preserving(live));
}

#[test]
fn a_rooms_keys_scan_in_log_order_across_the_sign_boundary() {
    let mut room = RoomLog::new();
    room.append_local("$join", None).unwrap();
    room.append_local("$live", None).unwrap();
    room.prepend_remote(EventInput::new("$older", vec![]), StateSnapshot::new(), 40)
        .unwrap();
    room.prepend_remote(EventInput::new("$oldest", vec![]), StateSnapshot::new(), 39)
        .unwrap();

    // Encode every entry, then sort by key alone — as a range scan would.
    let mut encoded: Vec<(Vec<u8>, String)> = room
        .entries()
        .map(|entry| {
            (
                room_li(Keyspace::Log, "!room:example.org", entry.li),
                entry.event_id.as_str().to_owned(),
            )
        })
        .collect();
    encoded.sort_by(|left, right| left.0.cmp(&right.0));

    let scanned: Vec<&str> = encoded.iter().map(|(_, id)| id.as_str()).collect();
    assert_eq!(scanned, vec!["$oldest", "$older", "$join", "$live"]);
}

#[test]
fn one_rooms_range_never_walks_into_another() {
    // The classic prefix bug: "!a" is a prefix of "!ab", so without a length
    // prefix a scan of the first would run into the second.
    let short = room_prefix(Keyspace::Log, "!a:example.org");
    let long = room_prefix(Keyspace::Log, "!ab:example.org");
    assert!(!long.starts_with(&short));

    let mut keys = [
        room_li(Keyspace::Log, "!ab:example.org", LinearIndex::from_raw(1)),
        room_li(
            Keyspace::Log,
            "!a:example.org",
            LinearIndex::from_raw(i64::MAX),
        ),
        room_li(
            Keyspace::Log,
            "!a:example.org",
            LinearIndex::from_raw(i64::MIN),
        ),
    ];
    keys.sort();

    // Both !a keys sort together, before every !ab key.
    assert!(keys[0].starts_with(&short));
    assert!(keys[1].starts_with(&short));
    assert!(keys[2].starts_with(&long));
}

#[test]
fn keyspaces_do_not_interleave() {
    let log = room_li(
        Keyspace::Log,
        "!room:example.org",
        LinearIndex::from_raw(i64::MAX),
    );
    let roots = room_li(
        Keyspace::StateRoot,
        "!room:example.org",
        LinearIndex::from_raw(i64::MIN),
    );
    assert!(log < roots, "keyspace byte must dominate the index");
}

#[test]
fn every_key_carries_the_schema_version() {
    let key = room_li(Keyspace::Log, "!room:example.org", LinearIndex::from_raw(7));
    assert_eq!(key[0], spindle_core::keys::KEY_SCHEMA_VERSION);
    assert_eq!(key[1], Keyspace::Log as u8);
}
