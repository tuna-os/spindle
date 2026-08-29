//! Part of #267: fuzz the key decoders.
//!
//! Every `*_from_key` here reads bytes that came back off disk. A panic in
//! one is not a wrong answer, it is the process going down on a truncated
//! row, a key from an older schema, or a scan that walked one keyspace into
//! the next. `None` is the only acceptable failure.
//!
//! This is property testing rather than `cargo-fuzz` because the workspace
//! pins a stable toolchain and `cargo-fuzz` needs nightly; adding a nightly
//! requirement to reach these functions is a worse trade than driving them
//! from `proptest`, which is already a dev-dependency here. The inputs below
//! are the three shapes a fuzzer would spend its budget rediscovering:
//! arbitrary bytes, real keys cut short, and real keys whose length prefix
//! lies about the tail.

use proptest::prelude::*;
use spindle_core::{
    LinearIndex,
    keys::{
        Keyspace, account_data, account_data_type, alias, alias_from_key, delayed_event,
        delayed_event_id_from_key, device_list_change, device_list_change_user, finalised_delay,
        finalised_delay_position, li_from_key, media, media_id, room_from_prefixed,
        room_from_user_room, room_li, room_prefix, room_stream, room_stream_from_key, stream,
        stream_from_key, user_room,
    },
};

/// Put every decoder over one byte string.
///
/// The point is the calls, not the answers: this returns nothing because a
/// decoder that says `None` to everything is still correct here, and the
/// round-trip properties below are what stop it being vacuous.
fn decode_every_way(key: &[u8]) {
    let user = "@alice:example.org";
    let room = "!room:example.org";

    let _ = std::hint::black_box(room_from_prefixed(key));
    let _ = std::hint::black_box(stream_from_key(key));
    let _ = std::hint::black_box(delayed_event_id_from_key(key));
    let _ = std::hint::black_box(room_stream_from_key(key));
    let _ = std::hint::black_box(li_from_key(key));
    let _ = std::hint::black_box(alias_from_key(key));
    let _ = std::hint::black_box(media_id(key));
    let _ = std::hint::black_box(device_list_change_user(key));
    let _ = std::hint::black_box(room_from_user_room(user, key));
    let _ = std::hint::black_box(account_data_type(user, room, key));
    let _ = std::hint::black_box(finalised_delay_position(user, key));
}

/// One of each key shape the store actually writes, so the truncation and
/// corruption properties chew on real layouts rather than on noise.
fn real_keys(user: &str, room: &str, text: &str, number: u64) -> Vec<Vec<u8>> {
    vec![
        room_prefix(Keyspace::Log, room),
        room_li(
            Keyspace::Log,
            room,
            LinearIndex::from_raw(number.cast_signed()),
        ),
        room_stream(room, number),
        stream(number),
        delayed_event(number, text),
        alias(text),
        media(text),
        device_list_change(user),
        user_room(Keyspace::Membership, user, room),
        account_data(user, room, text),
        finalised_delay(user, number, text),
    ]
}

proptest! {
    /// The blunt instrument: bytes off the floor.
    #[test]
    fn arbitrary_bytes_decode_or_refuse(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        decode_every_way(&bytes);
    }

    /// A row cut short -- a partial write, or a value read with the wrong
    /// length. Every prefix of a real key, including the empty one.
    #[test]
    fn truncated_keys_decode_or_refuse(
        user in "\\PC{0,32}",
        room in "\\PC{0,32}",
        text in "\\PC{0,32}",
        number: u64,
    ) {
        for key in real_keys(&user, &room, &text, number) {
            for cut in 0..=key.len() {
                decode_every_way(&key[..cut]);
            }
        }
    }

    /// A length prefix that lies. Bytes 2..4 are where every
    /// variable-length key states how long its next component is; overwrite
    /// them with an arbitrary `u16` and the tail no longer matches the claim.
    #[test]
    fn lying_length_prefixes_decode_or_refuse(
        user in "\\PC{0,32}",
        room in "\\PC{0,32}",
        text in "\\PC{0,32}",
        number: u64,
        claimed: u16,
    ) {
        for mut key in real_keys(&user, &room, &text, number) {
            if key.len() >= 4 {
                key[2..4].copy_from_slice(&claimed.to_be_bytes());
                decode_every_way(&key);
            }
        }
    }

    /// A scan that ran off the end of its keyspace and into the next one:
    /// two real keys spliced together. Neither half is a valid whole.
    #[test]
    fn spliced_keys_decode_or_refuse(
        user in "\\PC{0,32}",
        room in "\\PC{0,32}",
        text in "\\PC{0,32}",
        number: u64,
        cut in 0_usize..64,
    ) {
        let keys = real_keys(&user, &room, &text, number);
        for pair in keys.windows(2) {
            let mut spliced = pair[0].clone();
            let at = cut.min(pair[1].len());
            spliced.extend_from_slice(&pair[1][..at]);
            decode_every_way(&spliced);
        }
    }
}

proptest! {
    /// Every encoder's own decoder gets its input back. Without these the
    /// properties above would pass on a decoder that returned `None`
    /// unconditionally.
    #[test]
    fn encoders_round_trip(
        user in "\\PC{1,32}",
        room in "\\PC{1,32}",
        text in "\\PC{0,32}",
        number: u64,
        index: i64,
    ) {
        let room_key = room_prefix(Keyspace::Log, &room);
        prop_assert_eq!(room_from_prefixed(&room_key), Some(room.as_str()));
        prop_assert_eq!(stream_from_key(&stream(number)), Some(number));
        prop_assert_eq!(room_stream_from_key(&room_stream(&room, number)), Some(number));
        prop_assert_eq!(
            li_from_key(&room_li(Keyspace::Log, &room, LinearIndex::from_raw(index))),
            Some(index)
        );
        prop_assert_eq!(
            delayed_event_id_from_key(&delayed_event(number, &text)),
            Some(text.clone())
        );
        prop_assert_eq!(alias_from_key(&alias(&text)), Some(text.clone()));
        prop_assert_eq!(media_id(&media(&text)), Some(text.clone()));
        prop_assert_eq!(
            device_list_change_user(&device_list_change(&user)),
            Some(user.clone())
        );
        prop_assert_eq!(
            room_from_user_room(&user, &user_room(Keyspace::Membership, &user, &room)),
            Some(room.clone())
        );
        prop_assert_eq!(
            account_data_type(&user, &room, &account_data(&user, &room, &text)),
            Some(text.clone())
        );
        prop_assert_eq!(
            finalised_delay_position(&user, &finalised_delay(&user, number, &text)),
            Some(number)
        );
    }

    /// The promise `room_from_user_room` makes in its own doc comment: it
    /// answers for one user or not at all. Length-prefixing is what makes
    /// this hold -- without it `("@ab:x", "!c")` and `("@ab:x!c", "")` would
    /// produce the same bytes and one user would read the other's rooms.
    #[test]
    fn a_key_never_decodes_for_the_wrong_user(
        user in "\\PC{1,32}",
        other in "\\PC{1,32}",
        room in "\\PC{1,32}",
    ) {
        prop_assume!(user != other);
        prop_assert_eq!(
            room_from_user_room(&other, &user_room(Keyspace::Membership, &user, &room)),
            None
        );
        prop_assert_eq!(
            finalised_delay_position(&other, &finalised_delay(&user, 7, "d")),
            None
        );
    }

    /// The same promise for the second component: account data is keyed by
    /// user *and* room, and reading it back for a different room must fail
    /// rather than hand over a plausible-looking event type.
    #[test]
    fn account_data_never_decodes_for_the_wrong_room(
        user in "\\PC{1,32}",
        room in "\\PC{1,32}",
        other in "\\PC{1,32}",
        event_type in "\\PC{0,32}",
    ) {
        prop_assume!(room != other);
        prop_assert_eq!(
            account_data_type(&user, &other, &account_data(&user, &room, &event_type)),
            None
        );
    }
}

/// Inputs no caller can produce today, kept because "no caller can" is a fact
/// about callers and this is a test about the decoders.
///
/// Above `u16::MAX` bytes the length prefix saturates and the encoder
/// truncates, so two distinct 64 KiB IDs share a key. Matrix caps user IDs at
/// 255 bytes and room IDs not much above that, so nothing on the wire gets
/// close; what matters here is that the oversized path neither panics nor
/// slices through a multi-byte character.
#[test]
fn oversized_ids_are_truncated_rather_than_fatal() {
    let huge = "a".repeat(usize::from(u16::MAX) + 10);

    let key = room_prefix(Keyspace::Log, &huge);
    assert_eq!(key.len(), 4 + usize::from(u16::MAX));
    assert_eq!(
        room_from_prefixed(&key).map(str::len),
        Some(usize::from(u16::MAX))
    );

    decode_every_way(&key);
    decode_every_way(&user_room(Keyspace::Membership, &huge, &huge));
    decode_every_way(&alias(&huge));
    decode_every_way(&media(&huge));
}

/// A key from a keyspace that does not exist yet -- the shape a downgrade
/// produces, where a newer server wrote rows this build has no decoder for.
#[test]
fn unknown_keyspaces_decode_or_refuse() {
    for keyspace in 0..=u8::MAX {
        for schema in [0_u8, 1, 2, u8::MAX] {
            decode_every_way(&[schema, keyspace]);
            decode_every_way(&[schema, keyspace, 0xff, 0xff]);
            decode_every_way(&[schema, keyspace, 0xff, 0xff, b'x']);
        }
    }
}
