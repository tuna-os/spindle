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
/// # Where the line is, and why it is there
///
/// **v4 and up, because that is where the event ID format settles.**
/// `ruma` reports `event_id_format` per version:
///
/// | versions | event ID format |
/// |---|---|
/// | v1, v2 | `V1` — IDs are server-chosen, not hashes |
/// | v3 | `V2` |
/// | **v4 – v12** | **`V3` — what this server computes** |
///
/// Everything from v4 up mints and recognises the same event IDs this
/// implementation already produces. The differences that remain —
/// knocking (v7), restricted joins (v8), knock-restricted (v10), the v11
/// redaction changes, v12's create-event-derived room IDs — are all rule
/// flags `ruma` carries, and every one of them is read *per room* rather
/// than from a constant, which is what #195 and #203 were for.
///
/// v1–v3 are a different matter and deliberately absent: their event IDs
/// are not the reference hashes this server computes, so claiming them
/// would be claiming machinery that does not exist. That is the
/// distinction this module exists to keep honest.
///
/// The evidence is Complement. Thirty of its allowlisted tests create
/// rooms at v7, v8 and v9 to reach knocking and restricted joins; before
/// this they silently received a v11 room that happened to have those
/// features, and passed on the substitution. Now they get the version
/// they asked for, and the same tests are the check on whether that is
/// true.
pub const ROOM_VERSIONS: &[&str] = &["4", "5", "6", "7", "8", "9", "10", "11", "12"];

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
    // MSC3266's room summary. Advertised because the endpoint is served under
    // the unstable prefix as well as at `/v1/room_summary`, and a client that
    // checks this flag before probing the unstable path is doing the right
    // thing.
    ("im.nheko.summary", true),
    // MSC4222. Advertised because the flag is accepted under the unstable
    // name as well as the stable one, and a client that checks here before
    // sending it is doing the right thing.
    ("org.matrix.msc4222.use_state_after", true),
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

    /// Every advertised version mints the event IDs this server computes.
    ///
    /// The advertised set is a claim, and this is the part of it that is
    /// checkable without a running room: an event ID format other than `V3`
    /// means IDs this implementation does not produce, so advertising such a
    /// version would promise machinery that does not exist.
    ///
    /// It fails in both directions on purpose. Adding v3 or below fails here
    /// rather than in a federation trace weeks later; and if a future room
    /// version changes the format, adding it fails here too — which is the
    /// moment to decide deliberately rather than discover it from a peer.
    #[test]
    fn every_advertised_version_uses_the_event_id_format_this_server_computes() {
        for name in ROOM_VERSIONS {
            let version = ruma::RoomVersionId::try_from(*name)
                .unwrap_or_else(|error| panic!("v{name} is not a room version: {error}"));
            let rules = version
                .rules()
                .unwrap_or_else(|| panic!("ruma has no rules for advertised v{name}"));
            assert_eq!(
                rules.event_id_format,
                ruma::room_version_rules::EventIdFormatVersion::V3,
                "v{name} is advertised but mints event IDs in {:?}, not the V3 \
                 reference hashes this server computes",
                rules.event_id_format,
            );
        }
    }

    /// Nothing advertised is a version `ruma` calls unstable.
    ///
    /// Advertising an unstable version invites clients into rooms whose rules
    /// may still change under them.
    #[test]
    fn nothing_advertised_is_unstable() {
        for name in ROOM_VERSIONS {
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
