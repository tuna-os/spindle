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
/// # Why not the older versions, when they appear to work
///
/// They create. Driving `Rooms::create` at v6 through v12 with this list
/// widened, every one creates, authorizes and accepts messages, and
/// `ruma` reports `event_id_format = V3` for everything from v4 up — the
/// same event IDs this server computes. On that evidence v4–v12 looks
/// advertisable, and this list was briefly widened to say so.
///
/// **Complement says otherwise, and it is right.** With v7 actually
/// served, `make_join` truthfully answers "7", the peer builds a
/// v7-shaped join, and `send_join` rejects it:
///
/// ```text
/// MustJoinRoom: send_join failed: {"errcode":"M_BAD_JSON", …}
/// ```
///
/// Restricted joins fail the same way at v8–v10:
/// `TestRestrictedRooms*/Join_should_succeed_when_joined_to_allowed_room`.
///
/// So `ruma`'s per-version rules are necessary and not sufficient. The
/// federation join path carries v11-shaped assumptions that held only
/// because every room was quietly v11 — which is exactly what made those
/// thirty allowlisted tests pass on a substitution. Creating a room at a
/// version is not the same as *joining* one over federation at it, and
/// only the second is what advertising promises.
///
/// Advertising v4–v10 before that path is fixed would move the
/// substitution's dishonesty rather than remove it: clients would be told
/// the version is available and then fail to federate into it.
///
/// The work is real and tracked separately. This list moves when
/// Complement's knock and restricted-join tests pass at the versions they
/// ask for, and not before.
pub const ROOM_VERSIONS: &[&str] = &["11", "12"];

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
    // MSC4140's delayed events. This flag is how a Matrix RTC client decides
    // whether it may rely on the server to remove it from a call it can no
    // longer say it has left -- and a client that finds the flag absent is
    // expected to fall back to leaving a stale membership behind. So the
    // advertisement is not decoration: it changes what clients do.
    ("org.matrix.msc4140", true),
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
