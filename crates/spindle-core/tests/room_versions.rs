//! What changes between room versions, stated per version (#456).
//!
//! Each served version is held to the rules the spec gives it for event IDs,
//! content hashes, signatures and redaction. The rules themselves are ruma's;
//! these tests pin that every version this server serves goes through them
//! under its *own* rules rather than a neighbour's, and they name the
//! differences a migration corpus actually contains, so a regression shows up
//! as "v6 kept `aliases`" rather than as a peer refusing an event.

use ruma::{
    CanonicalJsonObject, CanonicalJsonValue, RoomVersionId,
    signatures::{Ed25519KeyPair, PublicKeyMap, Verified},
};
use spindle_core::{Pdu, version};

/// The hash-named versions: event ID is the reference hash (v3+).
const HASH_NAMED: &[&str] = &["3", "4", "5", "6", "7", "8", "9", "10", "11", "12"];

fn key() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate();
    Ed25519KeyPair::from_der(&document, "1".to_owned()).unwrap()
}

fn key_map(key: &Ed25519KeyPair) -> PublicKeyMap {
    let mut map = PublicKeyMap::new();
    map.entry("example.org".to_owned()).or_default().insert(
        "ed25519:1".to_owned(),
        ruma::serde::Base64::new(key.public_key().to_vec()),
    );
    map
}

fn object(value: serde_json::Value) -> CanonicalJsonObject {
    match CanonicalJsonValue::try_from(value).unwrap() {
        CanonicalJsonValue::Object(object) => object,
        _ => unreachable!(),
    }
}

fn v(name: &str) -> RoomVersionId {
    RoomVersionId::try_from(name).unwrap()
}

fn state_event(event_type: &str, content: &serde_json::Value) -> CanonicalJsonObject {
    object(serde_json::json!({
        "type": event_type,
        "state_key": "",
        "sender": "@alice:example.org",
        "room_id": "!room:example.org",
        "origin": "example.org",
        "membership": "join",
        "prev_state": [],
        "content": content,
        "origin_server_ts": 1_700_000_000_000_u64,
        "depth": 3,
        "prev_events": ["$p"],
        "auth_events": ["$a"],
    }))
}

fn kept(object: &CanonicalJsonObject, version: &str) -> serde_json::Value {
    let redacted = version::redact(object, &v(version)).unwrap();
    serde_json::to_value(redacted).unwrap()
}

/// v3 names events by standard base64, which may contain `+` and `/`; v4
/// moved to the URL-safe alphabet so an event ID can sit in a URL path.
#[test]
fn v3_ids_use_standard_base64_and_v4_on_use_url_safe() {
    let key = key();
    // Enough distinct events that the standard alphabet shows `+` or `/`.
    let mut standard_marker = false;
    for n in 0..64 {
        let event = object(serde_json::json!({
            "type": "m.room.message",
            "sender": "@alice:example.org",
            "room_id": "!room:example.org",
            "content": { "body": format!("message {n}") },
            "origin_server_ts": 1_700_000_000_000_u64 + n,
            "depth": 2,
            "prev_events": ["$p"],
            "auth_events": [],
        }));
        let v3 = Pdu::sign(v("3"), event.clone(), "example.org", &key).unwrap();
        standard_marker |= v3.event_id().as_str().contains(['+', '/']);
        for later in &HASH_NAMED[1..] {
            let pdu = Pdu::sign(v(later), event.clone(), "example.org", &key).unwrap();
            assert!(
                !pdu.event_id().as_str().contains(['+', '/', '=']),
                "v{later} minted a non-URL-safe ID {}",
                pdu.event_id().as_str()
            );
        }
    }
    assert!(standard_marker, "v3 never used the standard alphabet");
}

/// Every hash-named version signs, verifies, and names an event by the hash
/// of its redacted form under its own rules.
#[test]
fn every_hash_named_version_signs_and_verifies_under_its_own_rules() {
    let key = key();
    let map = key_map(&key);
    for name in HASH_NAMED {
        let event = state_event("m.room.topic", &serde_json::json!({ "topic": "t" }));
        let pdu = Pdu::sign(v(name), event, "example.org", &key).unwrap();
        assert_eq!(
            version::verify(&map, pdu.canonical(), &v(name)).unwrap(),
            Verified::All,
            "v{name}"
        );
        // Received back, the ID is computed, not claimed, and agrees.
        let received = Pdu::from_remote(v(name), pdu.canonical().clone()).unwrap();
        assert_eq!(received.event_id(), pdu.event_id(), "v{name}");

        // Content altered after signing: the signature still holds over the
        // redacted form, the content hash does not.
        let mut altered = pdu.canonical().clone();
        altered.insert(
            "content".to_owned(),
            CanonicalJsonValue::Object(object(serde_json::json!({ "topic": "forged" }))),
        );
        assert_eq!(
            version::verify(&map, &altered, &v(name)).unwrap(),
            Verified::Signatures,
            "v{name}"
        );
    }
}

/// The top-level keys v1–v10 keep and v11 dropped (MSC2176).
#[test]
fn origin_membership_and_prev_state_survive_redaction_until_v11() {
    let event = state_event("m.room.topic", &serde_json::json!({ "topic": "t" }));
    for name in ["1", "6", "9", "10"] {
        let redacted = kept(&event, name);
        for key in ["origin", "membership", "prev_state"] {
            assert!(redacted.get(key).is_some(), "v{name} dropped {key}");
        }
    }
    let redacted = kept(&event, "11");
    for key in ["origin", "membership", "prev_state"] {
        assert!(redacted.get(key).is_none(), "v11 kept {key}");
    }
}

/// `m.room.aliases` content survives redaction only before v6 (MSC2432).
#[test]
fn aliases_content_survives_redaction_only_before_v6() {
    let event = state_event(
        "m.room.aliases",
        &serde_json::json!({ "aliases": ["#a:example.org"] }),
    );
    for name in ["1", "3", "5"] {
        assert_eq!(
            kept(&event, name)["content"]["aliases"],
            serde_json::json!(["#a:example.org"]),
            "v{name}"
        );
    }
    for name in ["6", "9", "10"] {
        assert_eq!(
            kept(&event, name)["content"],
            serde_json::json!({}),
            "v{name}"
        );
    }
}

/// The `allow` list of a restricted join rule survives redaction from v8,
/// the version that introduced it.
#[test]
fn join_rule_allow_survives_redaction_from_v8() {
    let event = state_event(
        "m.room.join_rules",
        &serde_json::json!({
            "join_rule": "restricted",
            "allow": [{ "type": "m.room_membership", "room_id": "!s:example.org" }],
        }),
    );
    for name in ["6", "7"] {
        assert!(
            kept(&event, name)["content"].get("allow").is_none(),
            "v{name}"
        );
    }
    for name in ["8", "9", "10"] {
        assert!(
            kept(&event, name)["content"].get("allow").is_some(),
            "v{name}"
        );
    }
}

/// The restricted join's authorising user survives redaction from v9 only
/// (MSC3375): a v8 join redacted afterwards loses it, which is why v9 exists.
#[test]
fn join_authorised_via_users_server_survives_redaction_from_v9() {
    let mut event = state_event(
        "m.room.member",
        &serde_json::json!({
            "membership": "join",
            "displayname": "Bob",
            "join_authorised_via_users_server": "@alice:example.org",
        }),
    );
    event.insert(
        "state_key".to_owned(),
        CanonicalJsonValue::String("@bob:example.org".to_owned()),
    );
    let v8 = kept(&event, "8");
    assert_eq!(v8["content"], serde_json::json!({ "membership": "join" }));
    for name in ["9", "10"] {
        assert_eq!(
            kept(&event, name)["content"],
            serde_json::json!({
                "membership": "join",
                "join_authorised_via_users_server": "@alice:example.org",
            }),
            "v{name}"
        );
    }
}

/// Before v11 the create event keeps only `creator` through redaction; the
/// room version itself is then implied (MSC2176 kept all of it from v11).
#[test]
fn create_content_keeps_only_the_creator_until_v11() {
    let event = state_event(
        "m.room.create",
        &serde_json::json!({ "creator": "@alice:example.org", "room_version": "6", "m.federate": true }),
    );
    for name in ["1", "6", "9", "10"] {
        assert_eq!(
            kept(&event, name)["content"],
            serde_json::json!({ "creator": "@alice:example.org" }),
            "v{name}"
        );
    }
    assert_eq!(
        kept(&event, "11")["content"]["room_version"],
        serde_json::json!("6")
    );
}

/// The version-level switches the authorization rules read, as a table: a
/// change to any of them for a served version is a change in what this
/// server accepts, and should be visible as one.
#[test]
fn the_authorization_switches_per_version() {
    // (version, knocking, restricted, knock_restricted, integer levels,
    //  special-case aliases, special-case redaction, key validity)
    let table = [
        ("1", false, false, false, false, true, true, false),
        ("2", false, false, false, false, true, true, false),
        ("3", false, false, false, false, true, false, false),
        ("4", false, false, false, false, true, false, false),
        ("5", false, false, false, false, true, false, true),
        ("6", false, false, false, false, false, false, true),
        ("7", true, false, false, false, false, false, true),
        ("8", true, true, false, false, false, false, true),
        ("9", true, true, false, false, false, false, true),
        ("10", true, true, true, true, false, false, true),
        ("11", true, true, true, true, false, false, true),
    ];
    for (name, knock, restricted, knock_restricted, integers, aliases, redaction, keys) in table {
        let rules = spindle_core::rules_of(&v(name)).unwrap();
        let auth = &rules.authorization;
        assert_eq!(auth.knocking, knock, "v{name} knocking");
        assert_eq!(auth.restricted_join_rule, restricted, "v{name} restricted");
        assert_eq!(
            auth.knock_restricted_join_rule, knock_restricted,
            "v{name} knock_restricted"
        );
        assert_eq!(auth.integer_power_levels, integers, "v{name} integers");
        assert_eq!(auth.special_case_room_aliases, aliases, "v{name} aliases");
        assert_eq!(
            auth.special_case_room_redaction, redaction,
            "v{name} redaction"
        );
        assert_eq!(rules.enforce_key_validity, keys, "v{name} key validity");
    }
}

fn v1_event(edges: &serde_json::Value) -> CanonicalJsonObject {
    object(serde_json::json!({
        "type": "m.room.message",
        "sender": "@alice:example.org",
        "room_id": "!room:example.org",
        "content": { "body": "hi" },
        "origin_server_ts": 1_700_000_000_000_u64,
        "depth": 2,
        "prev_events": edges,
        "auth_events": edges,
    }))
}

/// v1 and v2 events carry the ID their origin chose, `$opaque:origin`, and
/// that ID is what a receiver reads -- the hash is not the name.
#[test]
fn v1_and_v2_events_are_named_by_their_origin() {
    let key = key();
    let map = key_map(&key);
    let pair = serde_json::json!([["$parent:example.org", { "sha256": "aGFzaA" }]]);
    for name in ["1", "2"] {
        let signed = Pdu::sign(v(name), v1_event(&pair), "example.org", &key).unwrap();
        let id = signed.event_id().as_str().to_owned();
        assert!(
            id.starts_with('$') && id.ends_with(":example.org"),
            "v{name}: {id}"
        );
        assert_eq!(
            signed.canonical().get("event_id"),
            Some(&CanonicalJsonValue::String(id.clone())),
            "the ID is inside the signed bytes"
        );
        // Two events, two names, even with identical content.
        let again = Pdu::sign(v(name), v1_event(&pair), "example.org", &key).unwrap();
        assert_ne!(again.event_id(), signed.event_id(), "v{name}");

        let received = Pdu::from_remote(v(name), signed.canonical().clone()).unwrap();
        assert_eq!(received.event_id().as_str(), id, "v{name}");
        assert_eq!(
            version::verify(&map, signed.canonical(), &v(name)).unwrap(),
            Verified::All,
            "v{name}: signed by the server its ID names"
        );

        // A v1 event without its name, or with a malformed one, is refused.
        let mut nameless = signed.canonical().clone();
        nameless.remove("event_id");
        assert!(Pdu::from_remote(v(name), nameless).is_err(), "v{name}");
        let mut malformed = signed.canonical().clone();
        malformed.insert(
            "event_id".to_owned(),
            CanonicalJsonValue::String("$no-server".to_owned()),
        );
        assert!(Pdu::from_remote(v(name), malformed).is_err(), "v{name}");
    }
}

/// Each version's edges have exactly one shape: `[id, hashes]` pairs in v1
/// and v2, bare IDs from v3. The other shape is refused, not tolerated.
#[test]
fn edges_have_the_shape_their_version_requires() {
    let key = key();
    let pair = serde_json::json!([["$parent:example.org", { "sha256": "aGFzaA" }]]);
    let bare = serde_json::json!(["$parent"]);
    assert!(Pdu::sign(v("1"), v1_event(&bare), "example.org", &key).is_err());
    assert!(Pdu::sign(v("3"), v1_event(&pair), "example.org", &key).is_err());
    assert!(Pdu::sign(v("1"), v1_event(&pair), "example.org", &key).is_ok());
    assert!(Pdu::sign(v("3"), v1_event(&bare), "example.org", &key).is_ok());
}

/// A v1 reference pins its parent by the parent's reference hash, which is
/// standard base64 over the redacted form -- so redacting the parent later
/// does not break the child's reference.
#[test]
fn a_v1_edge_carries_the_parent_reference_hash() {
    let key = key();
    let parent = Pdu::sign(
        v("1"),
        v1_event(&serde_json::json!([])),
        "example.org",
        &key,
    )
    .unwrap();
    let edge = version::edge(parent.event_id().as_str(), parent.canonical(), &v("1")).unwrap();
    let rules = v("1").rules().unwrap();
    let expected = ruma::signatures::reference_hash(parent.canonical(), &rules).unwrap();
    assert_eq!(
        serde_json::to_value(&edge).unwrap(),
        serde_json::json!([parent.event_id().as_str(), { "sha256": expected }])
    );
    let redacted = version::redact(parent.canonical(), &v("1")).unwrap();
    assert_eq!(
        version::edge(parent.event_id().as_str(), &redacted, &v("1")).unwrap(),
        edge
    );
    // From v3 a reference is the bare ID.
    assert_eq!(
        version::edge("$x", parent.canonical(), &v("3")).unwrap(),
        CanonicalJsonValue::String("$x".to_owned())
    );
    assert_eq!(
        version::edge_ids(Some(&CanonicalJsonValue::Array(vec![edge]))),
        vec![parent.event_id().as_str().to_owned()]
    );
}
