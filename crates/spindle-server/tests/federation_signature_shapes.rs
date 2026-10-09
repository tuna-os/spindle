//! What can make a correctly signed event fail to verify here.
//!
//! Production refused an `m.room.member` event from zoft.chat with
//! `ed25519 signature verification failed: signature error`. That message
//! is ruma reporting a signature *under a key ID it holds* that does not
//! match the bytes it checked -- not a missing or rotated key, which reads
//! `Could not find supported signature for entity`. So either the bytes
//! this server checks differ from the bytes the origin signed, or the
//! signature is genuinely bad. These tests pin down the first half:
//!
//! - the path a PDU takes here -- raw JSON text, `serde_json::Value`,
//!   canonical JSON, the version's redaction -- reproduces the signed bytes
//!   for awkward content: escapes, non-ASCII, `\u` spellings, integers at
//!   the canonical-JSON limit, unknown top-level keys, every room version
//!   an `m.room.member` event can be in;
//! - and two ways the bytes *do* differ produce exactly the production
//!   error: judging the event under another room version's redaction
//!   rules, and a top-level key added after signing.

use ruma::RoomVersionId;
use ruma::signatures::{Ed25519KeyPair, PublicKeyMap, Verified, hash_and_sign_event};
use serde_json::{Value, json};

const ORIGIN: &str = "zoft.example";

fn pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_der(&Ed25519KeyPair::generate(), "6ystl50l".to_owned()).unwrap()
}

fn keys(pair: &Ed25519KeyPair) -> PublicKeyMap {
    let mut map = PublicKeyMap::new();
    map.entry(ORIGIN.to_owned()).or_default().insert(
        "ed25519:6ystl50l".to_owned(),
        ruma::serde::Base64::new(pair.public_key().to_vec()),
    );
    map
}

/// `event`, hashed and signed by `ORIGIN` under `version`'s redaction, as
/// JSON text the way a peer puts it on the wire.
fn sign(pair: &Ed25519KeyPair, version: &RoomVersionId, event: &Value) -> String {
    let ruma::CanonicalJsonValue::Object(mut canonical) =
        ruma::CanonicalJsonValue::try_from(event.clone()).unwrap()
    else {
        unreachable!()
    };
    let rules = version.rules().unwrap();
    hash_and_sign_event(ORIGIN, pair, &mut canonical, &rules.redaction).unwrap();
    serde_json::to_string(&canonical).unwrap()
}

/// What this server does with a received PDU's text before judging it:
/// parse into a `Value` (the transaction body), canonicalize, verify
/// under the room's version.
fn verify_as_received(
    text: &str,
    map: &PublicKeyMap,
    version: &RoomVersionId,
) -> Result<Verified, String> {
    let value: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let ruma::CanonicalJsonValue::Object(canonical) =
        ruma::CanonicalJsonValue::try_from(value).map_err(|error| error.to_string())?
    else {
        return Err("not an object".to_owned());
    };
    spindle_core::version::verify(map, &canonical, version).map_err(|error| error.to_string())
}

/// A join with everything awkward in it. Authorised via a user of the
/// origin itself, so that the restricted-join rule (v8+) asks for no
/// signature but the origin's.
fn member() -> Value {
    json!({
        "type": "m.room.member",
        "state_key": format!("@zoftty:{ORIGIN}"),
        "sender": format!("@zoftty:{ORIGIN}"),
        "room_id": "!WkXpJtuGLWMIyiLsvY:matrix.org",
        "origin": ORIGIN,
        "origin_server_ts": 1_791_473_758_682_u64,
        "depth": 9_007_199_254_740_991_u64,
        "prev_events": ["$RU3YeeQg1OrOy4EOFLVkG3B-cCzMJmZeks2LgZBnxqg"],
        "auth_events": ["$TkE8rLdzybM4iYdTBB-v-S7oOjObeccOc-oe602mi-U"],
        "content": {
            "membership": "join",
            "displayname": "zoft \u{1F431} \"quoted\" back\\slash \u{2028} tab\t nul\u{0} é 日本",
            "avatar_url": "mxc://zoft.example/abc",
            "join_authorised_via_users_server": format!("@admin:{ORIGIN}"),
            "xyz.amorgan.blurhash": "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
            "big": 9_007_199_254_740_991_i64,
            "small": -9_007_199_254_740_991_i64,
            "nested": { "z": [1, { "b": "\u{FFFF}" }], "a": null, "m": true },
        },
        "unsigned": { "age": 12, "replaces_state": "$x" },
        "io.element.unknown_top_level": { "kept": "out of the redacted form" },
    })
}

fn member_versions() -> Vec<RoomVersionId> {
    vec![
        RoomVersionId::V4,
        RoomVersionId::V5,
        RoomVersionId::V6,
        RoomVersionId::V7,
        RoomVersionId::V8,
        RoomVersionId::V9,
        RoomVersionId::V10,
        RoomVersionId::V11,
    ]
}

#[test]
fn awkward_but_valid_events_verify_after_the_trip_through_this_server() {
    let pair = pair();
    let map = keys(&pair);
    for version in member_versions() {
        let text = sign(&pair, &version, &member());
        assert_eq!(
            verify_as_received(&text, &map, &version),
            Ok(Verified::All),
            "v{version}"
        );
        // The same event as another implementation might spell it: `\u`
        // escapes for non-ASCII and `/` escaped. JSON says these are the
        // same strings; canonical JSON must make them the same bytes.
        let respelled = text
            .replace('é', "\\u00e9")
            .replace("mxc://", "mxc:\\/\\/")
            .replace('日', "\\u65e5");
        assert_ne!(respelled, text);
        assert_eq!(
            verify_as_received(&respelled, &map, &version),
            Ok(Verified::All),
            "v{version}, respelled"
        );
    }
}

#[test]
fn an_integer_past_the_canonical_json_limit_is_refused_as_malformed_not_as_a_bad_signature() {
    let pair = pair();
    let map = keys(&pair);
    let version = RoomVersionId::V10;
    let text = sign(&pair, &version, &member())
        .replace("\"depth\":9007199254740991", "\"depth\":9007199254740992");
    let error = verify_as_received(&text, &map, &version).unwrap_err();
    assert!(
        !error.contains("ed25519 signature verification failed"),
        "{error}"
    );
}

/// The production error, reproduced: an event signed under one version's
/// redaction rules, judged under another's. v10 keeps a top-level `origin`
/// in the redacted form and v11 drops it; v8 drops the
/// `join_authorised_via_users_server` that v9 keeps.
#[test]
fn judging_under_the_wrong_room_version_is_exactly_the_production_error() {
    let pair = pair();
    let map = keys(&pair);
    for (signed, judged) in [
        (RoomVersionId::V10, RoomVersionId::V11),
        (RoomVersionId::V11, RoomVersionId::V10),
        (RoomVersionId::V9, RoomVersionId::V8),
    ] {
        let text = sign(&pair, &signed, &member());
        let error = verify_as_received(&text, &map, &judged).unwrap_err();
        assert!(
            error.contains("ed25519 signature verification failed: signature error"),
            "signed v{signed}, judged v{judged}: {error}"
        );
    }
}

/// The other way to the same error: a key the redacted form keeps, added
/// after signing -- here an `event_id` on a v10 event.
#[test]
fn a_kept_key_added_after_signing_is_exactly_the_production_error() {
    let pair = pair();
    let map = keys(&pair);
    let version = RoomVersionId::V10;
    let text = sign(&pair, &version, &member());
    let mut value: Value = serde_json::from_str(&text).unwrap();
    value["event_id"] = json!("$RU3YeeQg1OrOy4EOFLVkG3B-cCzMJmZeks2LgZBnxqg");
    let error = verify_as_received(&value.to_string(), &map, &version).unwrap_err();
    assert!(
        error.contains("ed25519 signature verification failed: signature error"),
        "{error}"
    );
    // `unsigned` is outside both the signature and the content hash.
    let mut value: Value = serde_json::from_str(&text).unwrap();
    value["unsigned"]["age"] = json!(99_999);
    assert_eq!(
        verify_as_received(&value.to_string(), &map, &version),
        Ok(Verified::All)
    );
    // A key outside the redacted form leaves the signature standing and
    // breaks only the content hash: the spec's answer is to redact, not to
    // refuse -- so it can never be the production error either.
    value["io.element.unknown_top_level"] = json!("changed");
    assert_eq!(
        verify_as_received(&value.to_string(), &map, &version),
        Ok(Verified::Signatures)
    );
}
