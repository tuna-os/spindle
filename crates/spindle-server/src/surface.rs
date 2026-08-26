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
pub const SPEC_VERSIONS: &[SpecVersion] = &[SpecVersion {
    name: "v1.1",
    requires: &["/_matrix/client/versions"],
}];

/// Room versions this server can create and join.
///
/// Empty until rooms exist (#7). An empty list is a true statement; a populated
/// one would not be, and `/capabilities` is exactly where a client looks to
/// decide what to attempt.
pub const ROOM_VERSIONS: &[&str] = &[];

/// The default room version, once there is one.
pub const DEFAULT_ROOM_VERSION: Option<&str> = None;

/// Routes that must be mounted before *any* room version may be advertised.
///
/// Without this, [`ROOM_VERSIONS`] is a bare list with nothing holding it to
/// the implementation — which is the drift this module exists to prevent, and
/// which it did not prevent until a mutation test pointed out that populating
/// the list with no rooms built passed every check.
///
/// A client that reads a room version from `/capabilities` will try to create
/// or join a room with it, so these are the endpoints that have to exist first.
pub const ROOM_VERSION_REQUIRES: &[&str] = &[
    "/_matrix/client/v3/createRoom",
    "/_matrix/client/v3/join/{room_id_or_alias}",
];

/// Unstable features. Same rule: nothing here that is not built.
pub const UNSTABLE_FEATURES: &[(&str, bool)] = &[];

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
