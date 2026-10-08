//! HTTP route handlers organized by domain.
//!
//! This module decomposes the monolithic routes.rs into domain-scoped submodules,
//! making the codebase more navigable and reducing merge conflicts.
//!
//! See spindle#493 for the refactoring roadmap.

use axum::Router;
use crate::AppState;

pub mod routes_legacy;

// Phase 1: Establish module structure (this file)
// Phase 2: Extract submodules one at a time
//   - routes/accounts.rs (account + device endpoints)
//   - routes/rooms.rs (room creation, join, leave)
//   - routes/timeline.rs (events, state, redactions)
//   - routes/federation.rs (federation endpoints)
//   - routes/media.rs (upload, download, thumbnail)
//   - routes/discovery.rs (well-known, key endpoints)
//   - routes/admin.rs (admin endpoints)
//   etc.

/// Build the complete server router by merging domain-scoped route handlers.
///
/// In Phase 1, this still delegates to the original routes.rs file.
/// In Phase 2, each domain will have its own submodule that registers routes
/// on a provided sub-router.
///
/// The pattern will be:
/// ```ignore
/// pub fn router(state: AppState) -> Router {
///     Router::new()
///         .merge(accounts::routes(state.clone()))
///         .merge(rooms::routes(state.clone()))
///         .merge(timeline::routes(state.clone()))
///         .merge(federation::routes(state.clone()))
///         // ... etc
/// }
/// ```
pub fn router(state: AppState) -> Router {
    // Phase 1: Delegate to original routes.rs implementation.
    // Phase 2 will replace this with merging of extracted domain modules.
    routes_legacy::router(state)
}

/// List of all Matrix spec endpoints for documentation and testing.
///
/// This constant is moved here from the original routes.rs and kept for reference.
/// It can be used to verify that all endpoints have been properly registered.
pub const ENDPOINTS: &[&str] = &[
    "/_matrix/client/v3/account/password",
    "/_matrix/client/v3/account/password/email/requestToken",
    "/_matrix/client/v3/account/3pid",
    "/_matrix/client/v3/account/3pid/add",
    "/_matrix/client/v3/account/3pid/bind",
    "/_matrix/client/v3/account/3pid/delete",
    "/_matrix/client/v3/account/3pid/email/requestToken",
    "/_matrix/client/v3/account/3pid/msisdn/requestToken",
    "/_matrix/client/v3/account/whoami",
    "/_matrix/client/v3/account/deactivate",
    "/_matrix/client/v3/register",
    "/_matrix/client/v3/register/available",
    "/_matrix/client/v3/register/email/requestToken",
    "/_matrix/client/v3/register/msisdn/requestToken",
    "/_matrix/client/v3/login",
    "/_matrix/client/v3/logout",
    "/_matrix/client/v3/logout/all",
    "/_matrix/client/v3/devices",
    "/_matrix/client/v3/devices/{device_id}",
    "/_matrix/client/v3/profile/{user_id}",
    "/_matrix/client/v3/profile/{user_id}/displayname",
    "/_matrix/client/v3/profile/{user_id}/avatar_url",
    "/_matrix/client/v3/create_room",
    "/_matrix/client/v3/rooms/{room_id}/invite",
    "/_matrix/client/v3/rooms/{room_id}/leave",
    "/_matrix/client/v3/join/{room_id_or_alias}",
    "/_matrix/client/v3/knock/{room_id_or_alias}",
    "/_matrix/client/v3/sync",
    "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
    "/_matrix/client/v3/rooms/{room_id}/read_markers",
    "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
    "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
    "/_matrix/client/v1/rooms/{room_id}/threads",
    "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
    "/_matrix/client/v3/voip/turnServer",
    "/_matrix/client/v3/user/{user_id}/openid/request_token",
    "/_matrix/federation/v1/openid/userinfo",
    "/_spindle/rtc/livekit/sfu/get",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}",
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}",
    "/_matrix/client/v3/rooms/{room_id}/state",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
    "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
    "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
    "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
    "/_matrix/key/v2/server",
    "/_matrix/key/v2/query",
    "/_matrix/key/v2/query/{server_name}",
    "/_matrix/media/v1/create",
    "/_matrix/media/v3/upload/{server_name}/{media_id}",
    "/_matrix/client/v1/login/get_token",
    "/_matrix/client/v1/mutual_rooms",
    "/_matrix/federation/v1/media/thumbnail/{media_id}",
    "/_matrix/federation/v1/event_auth/{room_id}/{event_id}",
    "/_matrix/federation/v1/publicRooms",
    "/_matrix/federation/v1/hierarchy/{room_id}",
    "/_matrix/federation/v1/timestamp_to_event/{room_id}",
    "/_matrix/client/v1/register/m.login.registration_token/validity",
    "/.well-known/matrix/client",
    "/.well-known/matrix/server",
    "/health",
    "/ready",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoints_list_not_empty() {
        assert!(!ENDPOINTS.is_empty(), "ENDPOINTS list must contain at least one endpoint");
    }

    #[test]
    fn test_endpoints_follow_matrix_spec() {
        // All endpoints should start with either /_matrix, /.well-known, or /_spindle
        for endpoint in ENDPOINTS {
            assert!(
                endpoint.starts_with("/_matrix")
                    || endpoint.starts_with("/.well-known")
                    || endpoint.starts_with("/_spindle")
                    || endpoint.starts_with("/health")
                    || endpoint.starts_with("/ready"),
                "Endpoint {} does not follow expected prefix pattern",
                endpoint
            );
        }
    }
}
