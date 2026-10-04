//! What this server claims to support, and the routes that back each claim.
//!
//! #11's exit criterion is that no unsupported API or room version is
//! advertised. A hand-maintained list in a `/versions` handler cannot satisfy
//! that: it starts honest and drifts, and nothing notices, because the list and
//! the implementation have no relationship a compiler or a test can check.
//!
//! So the claim and its evidence live together here. Every advertised spec
//! version names the routes that make it true, [`routes::router`] is built from
//! the same table, and a test asserts every required route is actually mounted.
//! Advertising something unbuilt fails that test.
//!
//! [`routes::router`]: crate::routes::router

/// A Matrix spec version, and the endpoints a client may assume from it.
///
/// `requires` is not the full endpoint list of that spec version — it is the
/// subset this server must serve before the claim is honest. It grows as the
/// surface does.
pub struct SpecVersion {
    pub name: &'static str,
    pub requires: &'static [&'static str],
}

/// Spec versions this server implements enough of to claim.
///
/// Deliberately short. `/versions` is the first thing a client asks and the
/// answer it plans against; a longer list here buys nothing except clients
/// failing later, further from the cause.
pub const SPEC_VERSIONS: &[SpecVersion] = &[
    SpecVersion {
        name: "v1.1",
        requires: &["/_matrix/client/versions"],
    },
    // Refresh tokens are a v1.3 feature. Claimed only now that /refresh exists
    // and rotates, which is the rule this module is for.
    SpecVersion {
        name: "v1.3",
        requires: &[
            "/_matrix/client/versions",
            "/_matrix/client/v3/login",
            "/_matrix/client/v3/refresh",
        ],
    },
];

/// Room versions this server can create and join.
///
/// Staying silent here is not a safe default: a client that finds no
/// `m.room_versions` in `/capabilities` assumes room version 1 (the
/// spec's fallback), and a federated peer told to make a v1 room for us
/// hands back events our machinery rightly refuses — which is how
/// Complement's `TestJoinViaRoomIDAndServerName` found this.
///
/// # A version is listed only when it is served at that version
///
/// Creating a room at a version is not the same as *joining* one over
/// federation at it, and only the second is what advertising promises. An
/// earlier widening to v4–v10 was withdrawn because `send_join` refused a
/// v7 join (`M_BAD_JSON`) while `/createRoom` quietly substituted v11 for
/// every unlisted version, so knock and restricted-join tests passed on a
/// room of the wrong version.
///
/// Versions 6 to 10 are listed because each is exercised at its own
/// version: two-server joins and event exchange, redaction under the
/// version's own algorithm, the v7 knock and v8/v9 restricted-join
/// handshakes, and v1–v9 string power levels. The migration corpus tracked
/// by #456 holds real v6, v9 and v10 rooms. The differences between them are
/// ruma's per-version rules plus the three places this server makes a
/// version-dependent choice of its own: the redaction target's location
/// (top level before v11), the restricted-join nomination (v8+), and knock
/// templates (v7+).
///
/// Versions 1 to 5 add their own differences, each handled where it lives:
/// v1 and v2 name events `$opaque:server` and link them by
/// `[id, {"sha256": hash}]` pairs (`spindle_core::version::event_id`,
/// `edge`, `Rooms::link_edges`, `rooms::edge_ids`); v1 resolves state with
/// the original algorithm (`state_res_v1`); v1 and v2 let a server redact
/// its own events whatever its power (ruma, given the `redacts` target);
/// v3 names events in standard rather than URL-safe base64; and v5 starts
/// enforcing key validity (`PeerKeys::map_for`). The migration corpus holds
/// a real v1 room.
pub const ROOM_VERSIONS: &[&str] = &[
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    spindle_core::STATE_DAG_V12,
];

/// The default room version.
pub const DEFAULT_ROOM_VERSION: Option<&str> = Some("11");

/// Whether this server can speak a room version, by name.
///
/// The single place that question is answered, because it was previously
/// answered three different ways: `/createRoom` ignored the client's
/// requested version outright, `make_join` compared the peer's `ver` list
/// against a literal `"ver=11"`, and the federated invite compared the
/// body's version against `rooms::ROOM_VERSION`. Three spellings of one
/// question is how they drift apart — and each of the three was really
/// asking *is this in [`ROOM_VERSIONS`]*, which is the list
/// `/capabilities` already advertises.
///
/// Keeping it here rather than in `rooms.rs` is deliberate: this is a
/// statement about what the *server* advertises, not about what any
/// particular room is. A room's own version comes from its create event
/// (`Rooms::room_version`), and the two must not be confused — that
/// confusion is what made `make_join` tell a peer "this room is version
/// 11" about a room whose version it had never looked at.
#[must_use]
pub fn supports_room_version(version: &str) -> bool {
    ROOM_VERSIONS.contains(&version)
}

/// Routes that must be mounted before *any* room version may be advertised.
///
/// Without this, [`ROOM_VERSIONS`] is a bare list with nothing holding it to
/// the implementation — which is the drift this module exists to prevent, and
/// which it did not prevent until a mutation test pointed out that populating
/// the list with no rooms built passed every check.
///
/// A client that reads a room version from `/capabilities` will try to create
/// or join a room with it, so these are the endpoints that have to exist first.
/// Federation needs the published key, so claiming to federate before
/// `/_matrix/key/v2/server` answers would send a peer looking for a key it
/// cannot fetch.
pub const FEDERATION_REQUIRES: &[&str] = &["/_matrix/key/v2/server"];

pub const ROOM_VERSION_REQUIRES: &[&str] = &[
    "/_matrix/client/v3/createRoom",
    "/_matrix/client/v3/join/{room_id_or_alias}",
    "/_matrix/client/v3/rooms/{room_id}/join",
    "/_matrix/client/v3/rooms/{room_id}/leave",
    "/_matrix/client/v3/rooms/{room_id}/state",
    "/_matrix/client/v3/sync",
    "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
];

/// Unstable features. Same rule: nothing here that is not built.
pub const UNSTABLE_FEATURES: &[(&str, bool)] = &[
    // MSC4108 rendezvous for linking a new device through MAS.
    ("org.matrix.msc4108", true),
    // MSC3266's room summary. Advertised because the endpoint is served under
    // the unstable prefix as well as at `/v1/room_summary`, and a client that
    // checks this flag before probing the unstable path is doing the right
    // thing.
    ("im.nheko.summary", true),
    // MSC4222. Advertised because the flag is accepted under the unstable
    // name as well as the stable one, and a client that checks here before
    // sending it is doing the right thing.
    ("org.matrix.msc4222.use_state_after", true),
    // MSC4140's delayed events. This flag is how a Matrix RTC client decides
    // whether it may rely on the server to remove it from a call it can no
    // longer say it has left -- and a client that finds the flag absent is
    // expected to fall back to leaving a stale membership behind. So the
    // advertisement is not decoration: it changes what clients do.
    ("org.matrix.msc4140", true),
    // MSC4143's MatrixRTC discovery. Advertised unconditionally, because
    // the flag answers "does this server serve /rtc/transports", not "does
    // it have a backend to name": the endpoint is served either way and
    // answers an empty list when nothing is configured. Reporting `false`
    // for an unconfigured deployment would tell a client the server has not
    // implemented the MSC, which is a different and untrue thing -- and
    // would leave the client with no way to distinguish the two.
    ("org.matrix.msc4143", true),
    // MSC4354's sticky events: the `sticky_duration_ms` query parameter
    // on a send, the key on the event, and the section on `/sync`. What
    // MatrixRTC 2.0 makes `m.rtc.member`.
    ("org.matrix.msc4354", true),
    // MSC3814's dehydrated devices. Element X checks this flag before it
    // offers to keep room keys across the last device being lost.
    ("org.matrix.msc3814", true),
    // MSC3881: pushers carry `enabled` and `device_id` (under the
    // unstable and the plain names), and a disabled pusher receives
    // nothing. A client checks here before showing the toggle.
    ("org.matrix.msc3881", true),
    // MSC4186's simplified sliding sync, under the flag name it kept from
    // MSC3575. Not decoration: matrix-sdk's `DiscoverNative` -- what
    // Element X builds its client with at login -- reads exactly this flag,
    // and without it refuses the server as having no sliding sync at all.
    ("org.matrix.simplified_msc3575", true),
];

#[must_use]
pub fn spec_version_names() -> Vec<&'static str> {
    SPEC_VERSIONS.iter().map(|version| version.name).collect()
}

/// Every route path the advertised surface promises.
#[must_use]
pub fn required_routes() -> Vec<&'static str> {
    let mut routes: Vec<_> = SPEC_VERSIONS
        .iter()
        .flat_map(|version| version.requires.iter().copied())
        .collect();
    routes.sort_unstable();
    routes.dedup();
    routes
}

#[cfg(test)]
mod room_version_surface_tests {
    use super::{DEFAULT_ROOM_VERSION, ROOM_VERSIONS};

    /// Every advertised version names events the way its rules say, and
    /// names a received event the way it named the event it signed.
    ///
    /// The advertised set is a claim, and this is the part of it that is
    /// checkable without a running room. A version whose event ID format
    /// this server did not implement would fail the round trip here rather
    /// than in a federation trace weeks later.
    #[test]
    fn every_advertised_version_names_its_events_by_its_own_rules() {
        use ruma::room_version_rules::EventIdFormatVersion;
        let document = ruma::signatures::Ed25519KeyPair::generate();
        let key = ruma::signatures::Ed25519KeyPair::from_der(&document, "1".to_owned()).unwrap();
        for name in ROOM_VERSIONS {
            let version = ruma::RoomVersionId::try_from(*name)
                .unwrap_or_else(|error| panic!("v{name} is not a room version: {error}"));
            let rules = spindle_core::rules_of(&version)
                .unwrap_or_else(|| panic!("no rules for advertised v{name}"));
            if spindle_core::is_state_dag(&version) {
                // MSC4242's event shape (no `auth_events`) has its own
                // round-trip tests in `spindle_core::version`.
                continue;
            }
            let edges = if rules.event_id_format == EventIdFormatVersion::V1 {
                serde_json::json!([["$p:example.org", { "sha256": "abc" }]])
            } else {
                serde_json::json!(["$p"])
            };
            let ruma::CanonicalJsonValue::Object(event) =
                ruma::CanonicalJsonValue::try_from(serde_json::json!({
                    "type": "m.room.message",
                    "sender": "@a:example.org",
                    "room_id": "!r:example.org",
                    "content": { "body": "hi" },
                    "origin_server_ts": 1,
                    "depth": 2,
                    "prev_events": edges,
                    "auth_events": edges,
                }))
                .unwrap()
            else {
                unreachable!()
            };
            let signed = spindle_core::Pdu::sign(version.clone(), event, "example.org", &key)
                .unwrap_or_else(|error| panic!("v{name} cannot sign: {error:?}"));
            let id = signed.event_id().as_str();
            match rules.event_id_format {
                EventIdFormatVersion::V1 => assert!(id.ends_with(":example.org"), "v{name}: {id}"),
                EventIdFormatVersion::V2 => assert!(!id.contains(':'), "v{name}: {id}"),
                _ => assert!(!id.contains([':', '+', '/']), "v{name}: {id}"),
            }
            let received =
                spindle_core::Pdu::from_remote(version, signed.canonical().clone()).unwrap();
            assert_eq!(received.event_id(), signed.event_id(), "v{name}");
        }
    }

    /// Nothing advertised is a version `ruma` calls unstable, except the
    /// one this server advertises *as* unstable: MSC4242's state-DAG
    /// version, which `/capabilities` marks so, and which exists here to
    /// federate with a mesh that creates rooms under it.
    #[test]
    fn nothing_advertised_is_unstable() {
        for name in ROOM_VERSIONS {
            if *name == spindle_core::STATE_DAG_V12 {
                continue;
            }
            let rules = ruma::RoomVersionId::try_from(*name)
                .unwrap()
                .rules()
                .unwrap();
            assert_eq!(
                rules.disposition,
                ruma::room_version_rules::RoomVersionDisposition::Stable,
                "v{name} is advertised but {:?}",
                rules.disposition,
            );
        }
    }

    /// The default is one of the versions actually advertised.
    #[test]
    fn the_default_version_is_advertised() {
        let default = DEFAULT_ROOM_VERSION.expect("a default is set");
        assert!(
            ROOM_VERSIONS.contains(&default),
            "the default room version {default} is not in the advertised set",
        );
    }
}
