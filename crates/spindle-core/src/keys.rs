//! Order-preserving key encodings for the durable log.
//!
//! The storage engine is an ordered key-value store, so a range scan over a
//! room's history is only correct if **byte order equals numeric order**. That
//! is not free for `LinearIndex`: it is an `i64`, backfilled history is
//! negative, and two's-complement negative numbers have their high bit set, so
//! a naive big-endian encoding sorts every backfilled event *after* every live
//! one — silently, with no error, producing a room whose history pages
//! backwards.
//!
//! Flipping the sign bit fixes it: `i64::MIN` maps to all-zero bytes and
//! `i64::MAX` to all-ones, and the mapping is monotonic across zero.

use crate::LinearIndex;

/// On-disk key schema version.
///
/// Bumped whenever an encoding below changes shape, and written as the first
/// byte of every key so two layouts can never be confused for one another.
///
/// It does **not**, on its own, let a binary detect a version it does not
/// speak. A scan is a prefix scan: a binary looking under version 1 for a store
/// written at version 2 finds no keys, and reports an empty store rather than a
/// wrong one. That is a quieter failure than a misread, not a safer one — which
/// is why the store also carries a single version marker, read when it is
/// opened, so a mismatch is an error rather than an absence.
///
/// The marker key must never collide with a key produced here, which holds as
/// long as this constant is non-zero: [`store_marker`] is the all-zero prefix.
pub const KEY_SCHEMA_VERSION: u8 = 1;

/// The one key holding the store's schema versions.
///
/// Deliberately outside every [`Keyspace`]: it has to be readable *before* the
/// binary knows whether it understands the layout the rest of the store uses,
/// so it cannot itself be versioned by the scheme it describes. Its bytes are
/// frozen forever — a marker that moved between versions could not be found by
/// the binary that needs it most.
#[must_use]
pub fn store_marker() -> Vec<u8> {
    vec![0x00, 0x00]
}

/// The marker's non-collision is a compile-time property, so it is checked at
/// compile time: a zero `KEY_SCHEMA_VERSION` would put room keys in the
/// marker's range, and that must fail the build rather than a test run.
const _: () = assert!(
    KEY_SCHEMA_VERSION != 0,
    "the store marker relies on no key starting with a zero byte"
);

/// Which index a key belongs to. Distinct prefixes keep the keyspaces from
/// interleaving even when they share a backing tree.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Keyspace {
    /// `(room_id, li)` -> log entry.
    Log = 0x01,
    /// `event_id` -> `(room_id, li)`.
    EventIndex = 0x02,
    /// `node_hash` -> HAMT node.
    StateNode = 0x03,
    /// `(room_id, li)` -> state root, sparse.
    StateRoot = 0x04,
    /// `room_id` -> room metadata.
    RoomMeta = 0x05,
}

/// Map an `i64` onto `u64` so that big-endian byte order matches numeric order.
///
/// Flipping the sign bit shifts the signed range onto the unsigned one without
/// changing relative order.
#[must_use]
pub fn order_preserving(value: i64) -> [u8; 8] {
    #[expect(clippy::cast_sign_loss, reason = "reinterpreting bits, not converting")]
    let biased = (value as u64) ^ (1_u64 << 63);
    biased.to_be_bytes()
}

/// Inverse of [`order_preserving`].
#[must_use]
pub fn from_order_preserving(bytes: [u8; 8]) -> i64 {
    #[expect(
        clippy::cast_possible_wrap,
        reason = "reinterpreting bits, not converting"
    )]
    let value = (u64::from_be_bytes(bytes) ^ (1_u64 << 63)) as i64;
    value
}

/// The prefix every key for one room in one keyspace shares.
///
/// The room ID is length-prefixed rather than delimited: without that, a room
/// named `!a` and one named `!ab` would produce interleaving key ranges, and a
/// scan of the first would walk into the second.
#[must_use]
pub fn room_prefix(keyspace: Keyspace, room_id: &str) -> Vec<u8> {
    let room = room_id.as_bytes();
    let len = u16::try_from(room.len()).unwrap_or(u16::MAX);
    let mut key = Vec::with_capacity(4 + room.len());
    key.push(KEY_SCHEMA_VERSION);
    key.push(keyspace as u8);
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(&room[..len as usize]);
    key
}

/// `(room_id, li)` key, ordered by `li` within a room.
#[must_use]
pub fn room_li(keyspace: Keyspace, room_id: &str, li: LinearIndex) -> Vec<u8> {
    let mut key = room_prefix(keyspace, room_id);
    key.extend_from_slice(&order_preserving(li.get()));
    key
}

/// Recover the `li` from a key produced by [`room_li`].
#[must_use]
pub fn li_from_key(key: &[u8]) -> Option<i64> {
    let bytes: [u8; 8] = key.get(key.len().checked_sub(8)?..)?.try_into().ok()?;
    Some(from_order_preserving(bytes))
}

/// A content-addressed key: the hash is already uniformly distributed, so it
/// needs no length prefix.
#[must_use]
pub fn content_addressed(keyspace: Keyspace, hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(34);
    key.push(KEY_SCHEMA_VERSION);
    key.push(keyspace as u8);
    key.extend_from_slice(hash);
    key
}
