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
    /// `localpart` -> account record.
    Account = 0x06,
    /// `(localpart, device_id)` -> device record.
    Device = 0x07,
    /// `token_hash` -> access-token record.
    AccessToken = 0x08,
    /// `token_hash` -> refresh-token record.
    RefreshToken = 0x09,
    /// `key_id` -> this server's signing key.
    ServerKey = 0x0a,
    /// `stream_id` -> `(room_id, li)`.
    ///
    /// SPEC §10.2: `/sync` needs a total order *across* rooms, and the linear
    /// index only orders within one. This is the one index that exists purely
    /// because a per-room order is not a server order.
    Stream = 0x0c,
    /// `(room_id, user_id, receipt_type)` -> receipt.
    Receipt = 0x0d,
    /// `(room_id, target_event_id, rel_type, li)` -> `event_id` (SPEC §7).
    ///
    /// The key ends in `li`, so a scan returns a target's relations already in
    /// the order they were sent. Nothing sorts them: the ordering was decided
    /// once at write, which is the same property `/messages` rests on.
    Relation = 0x0e,
    /// `(user_id, room_id)` -> membership.
    ///
    /// Indexed by user rather than by room so that "which rooms is this user
    /// in" is a prefix scan over that user's rooms, not a walk of every room
    /// the server knows. `/joined_rooms` is the first call most clients make.
    Membership = 0x0b,
    /// `(user_id, room_id)` -> nothing; presence is the whole value.
    ///
    /// Forgetting is per-user and does not touch the room: the log keeps the
    /// leave event, so anyone else's view of who left is unchanged, and a
    /// later join simply deletes the marker. Kept out of [`Self::Membership`]
    /// so that forgetting cannot overwrite *why* the user is not in the room
    /// -- "left" and "banned" have to stay distinguishable underneath.
    ///
    /// 0x0f, not 0x0e: relations claimed that discriminant on a branch that
    /// had not landed when this was written, and a reused byte is a migration.
    Forgotten = 0x0f,
}

// Adding a discriminant is additive: every key already written keeps its bytes
// and its meaning, so it needs no `KEY_SCHEMA_VERSION` bump. Reusing or
// reordering one would need both a bump and a migration, which is what
// `keyspace_discriminants_are_unchanged` in spindle-store is there to stop.
const _: () = assert!(
    Keyspace::Account as u8 > Keyspace::RoomMeta as u8,
    "new keyspaces take fresh discriminants; they never reuse an existing one"
);

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

/// `stream_id` key, ordered numerically.
///
/// Big-endian over a `u64` rather than [`order_preserving`]: stream ids start
/// at 1 and only ever increase, so there is no negative range to fold and the
/// plain encoding already sorts correctly.
#[must_use]
pub fn stream(stream_id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(10);
    key.push(KEY_SCHEMA_VERSION);
    key.push(Keyspace::Stream as u8);
    key.extend_from_slice(&stream_id.to_be_bytes());
    key
}

/// The `stream_id` a [`stream`] key encodes.
#[must_use]
pub fn stream_from_key(key: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = key.get(2..10)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// The prefix every stream key shares, for scanning the whole stream.
#[must_use]
pub fn stream_prefix() -> Vec<u8> {
    vec![KEY_SCHEMA_VERSION, Keyspace::Stream as u8]
}

/// The prefix every relation of one event shares.
///
/// The target is length-prefixed for the reason [`room_prefix`] gives: without
/// it, `$ab` would scan into `$abc`.
#[must_use]
pub fn relation_prefix(room_id: &str, target: &str) -> Vec<u8> {
    let mut key = room_prefix(Keyspace::Relation, room_id);
    let target = target.as_bytes();
    key.extend_from_slice(
        &u16::try_from(target.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    key.extend_from_slice(target);
    key
}

/// One relation's key: its target, then where it sits in the log.
///
/// **`li` comes immediately after the target, and the relation type is not in
/// the key at all** — which is a deliberate departure from SPEC §7's
/// `(room_id, target_event_id, rel_type, li)`.
///
/// With `rel_type` in the key, a scan of everything related to an event is
/// ordered by relation type first and only then by `li`, so
/// `/relations/{eventId}` — the arity that takes no type — cannot return
/// timeline order, which is the order the spec requires of it. The type is
/// stored in the value and filtered on read instead: the narrowed arities cost
/// one extra comparison per row, and the unfiltered one is correct.
///
/// Worth stating because the ordering is otherwise invisible. A
/// length-prefixed `rel_type` sorts by *length* before bytes, so the original
/// key returned `m.thread`, `m.replace`, `m.annotation` in that order — not
/// alphabetical, not chronological, and stable enough to look deliberate.
#[must_use]
pub fn relation(room_id: &str, target: &str, li: LinearIndex) -> Vec<u8> {
    let mut key = relation_prefix(room_id, target);
    key.extend_from_slice(&order_preserving(li.get()));
    key
}

/// The prefix every key for one user in one keyspace shares.
///
/// Length-prefixed for the same reason as [`room_prefix`]: `@ab:x` must not
/// scan into `@abc:x`.
#[must_use]
pub fn user_prefix(keyspace: Keyspace, user_id: &str) -> Vec<u8> {
    let user = user_id.as_bytes();
    let len = u16::try_from(user.len()).unwrap_or(u16::MAX);
    let mut key = Vec::with_capacity(4 + user.len());
    key.push(KEY_SCHEMA_VERSION);
    key.push(keyspace as u8);
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(&user[..len as usize]);
    key
}

/// `(user_id, room_id)` key, ordered by room within a user.
#[must_use]
pub fn user_room(keyspace: Keyspace, user_id: &str, room_id: &str) -> Vec<u8> {
    let mut key = user_prefix(keyspace, user_id);
    key.extend_from_slice(room_id.as_bytes());
    key
}

/// The room ID a [`user_room`] key ends with, for `user_id`.
///
/// `None` unless the key really is that user's. Slicing at the prefix's
/// *length* would be enough for keys that came from a scan of this user, and
/// wrong for anything else: two users whose IDs are the same length produce
/// prefixes of the same length, so a mismatched key would decode to a
/// plausible room ID rather than to nothing. A lookup that quietly answers for
/// the wrong user is worse than one that fails.
#[must_use]
pub fn room_from_user_room(user_id: &str, key: &[u8]) -> Option<String> {
    let prefix = user_prefix(Keyspace::Membership, user_id);
    let room = key.strip_prefix(prefix.as_slice())?;
    String::from_utf8(room.to_vec()).ok()
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
