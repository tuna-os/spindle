//! #6: the on-disk format is frozen at schema version 1, and these bytes prove it.
//!
//! **The fixtures under `tests/fixtures/v1/` are the test.** They were produced
//! once, by the encoder as it stood when schema version 1 was declared, and
//! checked in. A test that generates its expectation from the current encoder
//! proves only that the encoder agrees with itself — it passes just as happily
//! after a format change that orphans every byte already on disk.
//!
//! So if one of these fails, **regenerating the fixture is the wrong fix.**
//! Either the change was unintended and belongs reverted, or it was intended and
//! needs a new version discriminant plus a migration for data written under the
//! old one. Quietly refreshing the bytes converts a caught incompatibility into
//! a corrupted deployment.
//!
//! Key encodings matter more here than record encodings, and less obviously: a
//! record that fails to decode is an error somebody sees, whereas a key that
//! encodes differently makes existing rows unreachable with no error at all.
//! The reader simply looks in the wrong place and finds nothing there.

use spindle_core::LinearIndex;
use spindle_core::keys::{
    KEY_SCHEMA_VERSION, Keyspace, content_addressed, order_preserving, room_li, room_prefix,
};
use spindle_store::codec::{EntryRecord, RECORD_VERSION, RoomRecord};

const ROOM: &str = "!r:example.org";

mod v1 {
    /// An entry with a state key, a chain value, and no predecessors.
    pub const ENTRY_MINIMAL: &[u8] = include_bytes!("fixtures/v1/entry-minimal.bin");
    /// Negative index, two predecessors, no state key, no chain.
    pub const ENTRY_BACKFILLED: &[u8] = include_bytes!("fixtures/v1/entry-backfilled.bin");
    pub const ROOM: &[u8] = include_bytes!("fixtures/v1/room.bin");
    pub const KEY_LOG_1: &[u8] = include_bytes!("fixtures/v1/key-log-1.bin");
    pub const KEY_LOG_NEG1: &[u8] = include_bytes!("fixtures/v1/key-log-neg1.bin");
    pub const KEY_ROOMMETA: &[u8] = include_bytes!("fixtures/v1/key-roommeta.bin");
    pub const KEY_STATENODE: &[u8] = include_bytes!("fixtures/v1/key-statenode.bin");
}

/// The versions the fixtures were written under. If either moves, every fixture
/// here describes a format the binary no longer speaks.
#[test]
fn the_fixtures_describe_the_current_schema_version() {
    assert_eq!(
        RECORD_VERSION, 1,
        "these fixtures are record version 1; a bump needs fixtures for the new \
         version *and* a migration for data written under the old one"
    );
    assert_eq!(KEY_SCHEMA_VERSION, 1, "as above, for keys");
}

#[test]
fn a_version_1_entry_still_decodes() {
    let decoded = EntryRecord::decode(v1::ENTRY_MINIMAL).expect("version 1 must decode");
    assert_eq!(decoded.li, 1);
    assert_eq!(decoded.event_id, "$create:example.org");
    assert!(decoded.prev_events.is_empty());
    assert_eq!(decoded.depth, 0);
    assert_eq!(
        decoded.state_key,
        Some(("m.room.create".to_owned(), String::new()))
    );
    assert_eq!(decoded.state_root, [0x11; 32]);
    assert_eq!(decoded.chain, Some([0x22; 32]));

    // And re-encodes to the same bytes, so the format is stable in both
    // directions rather than merely tolerant on the way in.
    assert_eq!(decoded.encode(), v1::ENTRY_MINIMAL);
}

#[test]
fn a_version_1_backfilled_entry_still_decodes() {
    let decoded = EntryRecord::decode(v1::ENTRY_BACKFILLED).expect("version 1 must decode");
    assert_eq!(decoded.li, -3, "backfill takes non-positive indices");
    assert_eq!(decoded.event_id, "$backfilled:example.org");
    assert_eq!(
        decoded.prev_events,
        vec!["$a:example.org".to_owned(), "$b:example.org".to_owned()]
    );
    assert_eq!(decoded.depth, 42);
    assert_eq!(decoded.state_key, None);
    assert_eq!(
        decoded.chain, None,
        "backfilled history carries no attestation from this server"
    );
    assert_eq!(decoded.encode(), v1::ENTRY_BACKFILLED);
}

#[test]
fn a_version_1_room_record_still_decodes() {
    let decoded = RoomRecord::decode(v1::ROOM).expect("version 1 must decode");
    assert_eq!(decoded.next_forward, 9);
    assert_eq!(decoded.next_backward, -2);
    assert_eq!(decoded.forward_extremities, vec!["$head:example.org"]);
    assert_eq!(decoded.encode(), v1::ROOM);
}

/// A changed key encoding does not fail loudly; it makes existing rows
/// unreachable. These are the exact bytes existing deployments are keyed by.
#[test]
fn version_1_key_encodings_are_unchanged() {
    assert_eq!(
        room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(1)),
        v1::KEY_LOG_1
    );
    assert_eq!(
        room_li(Keyspace::Log, ROOM, LinearIndex::from_raw(-1)),
        v1::KEY_LOG_NEG1
    );
    assert_eq!(room_prefix(Keyspace::RoomMeta, ROOM), v1::KEY_ROOMMETA);
    assert_eq!(
        content_addressed(Keyspace::StateNode, &[0x11; 32]),
        v1::KEY_STATENODE
    );

    // The ordering these keys exist to provide, asserted on the frozen bytes
    // themselves rather than on freshly encoded ones.
    assert!(
        v1::KEY_LOG_NEG1 < v1::KEY_LOG_1,
        "backfilled history must sort before live history"
    );
}

/// The property the whole key layout rests on: byte order equals numeric order,
/// across zero. Backfill takes descending non-positive indices, so if this
/// breaks, history sorts *after* live events and every range scan silently
/// returns the wrong page.
#[test]
fn order_preserving_encoding_survives_the_sign_boundary() {
    assert_eq!(order_preserving(i64::MIN), [0x00; 8]);
    assert_eq!(order_preserving(0), [0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(order_preserving(i64::MAX), [0xff; 8]);

    let ordered = [i64::MIN, -1_000_000, -1, 0, 1, 1_000_000, i64::MAX];
    let encoded: Vec<_> = ordered.iter().copied().map(order_preserving).collect();
    let mut sorted = encoded.clone();
    sorted.sort_unstable();
    assert_eq!(
        encoded, sorted,
        "byte order must equal numeric order or range scans return the wrong page"
    );
}

/// Keyspaces are discriminants written into every key. Reusing or reordering one
/// makes two record types collide in the same byte range.
#[test]
fn keyspace_discriminants_are_unchanged() {
    for (keyspace, expected) in [
        (Keyspace::Log, 0x01_u8),
        (Keyspace::EventIndex, 0x02),
        (Keyspace::StateNode, 0x03),
        (Keyspace::StateRoot, 0x04),
        (Keyspace::RoomMeta, 0x05),
        (Keyspace::Membership, 0x0b),
        (Keyspace::Stream, 0x0c),
        (Keyspace::Receipt, 0x0d),
        (Keyspace::Relation, 0x0e),
        (Keyspace::Forgotten, 0x0f),
        (Keyspace::AccountData, 0x10),
        (Keyspace::Alias, 0x11),
        (Keyspace::Filter, 0x12),
        (Keyspace::Media, 0x13),
        (Keyspace::Transaction, 0x14),
        (Keyspace::DeviceKeys, 0x15),
        (Keyspace::OneTimeKeys, 0x16),
        (Keyspace::ToDevice, 0x17),
        (Keyspace::FallbackKeys, 0x18),
        (Keyspace::DeviceListChange, 0x19),
        (Keyspace::KeyBackup, 0x1a),
        (Keyspace::KeyBackupData, 0x1b),
        (Keyspace::CrossSigning, 0x1c),
        (Keyspace::UrlPreview, 0x1d),
        (Keyspace::ServerKeys, 0x1e),
        (Keyspace::FederationTxn, 0x1f),
    ] {
        let key = room_prefix(keyspace, ROOM);
        assert_eq!(
            key[1], expected,
            "keyspace {keyspace:?} moved; existing rows are now read as another type"
        );
    }
}
