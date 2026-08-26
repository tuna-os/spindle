//! Turning a bearer token into an identity.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::AppState;
use crate::accounts::{Accounts, Identity};
use crate::errors::MatrixError;

/// An authenticated caller.
///
/// Implemented as an extractor so an endpoint that needs authentication cannot
/// forget to check: the handler either takes this and is authenticated, or does
/// not and never sees a token at all. There is no third state where a handler
/// meant to check and did not.
pub struct Authenticated(pub Identity);

impl FromRequestParts<AppState> for Authenticated {
    type Rejection = MatrixError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer(parts).ok_or_else(MatrixError::missing_token)?;
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        match accounts.identify(&token) {
            Ok(Some(identity)) => Ok(Self(identity)),
            Ok(None) => Err(MatrixError::unknown_token()),
            Err(error) => Err(MatrixError::internal(&error.to_string())),
        }
    }
}

/// A caller who may or may not have presented a token.
///
/// A separate type rather than `Option<Authenticated>`, so that "this endpoint
/// works both ways" is a decision written into its signature. The distinction
/// matters most where it is easiest to get wrong: MSC3266's room summary is
/// meant to be readable by a client previewing a room it has not joined, and
/// an endpoint that accidentally required a token could never serve that.
///
/// A token that is *present and wrong* is still an error. Falling back to
/// anonymous there would quietly downgrade a caller whose session had expired,
/// showing them a stranger's view of a room they are actually in.
pub struct MaybeAuthenticated(pub Option<Identity>);

impl FromRequestParts<AppState> for MaybeAuthenticated {
    type Rejection = MatrixError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(parts) else {
            return Ok(Self(None));
        };
        let accounts = Accounts::new(state.store.as_ref(), &state.config.server.name);
        match accounts.identify(&token) {
            Ok(Some(identity)) => Ok(Self(Some(identity))),
            Ok(None) => Err(MatrixError::unknown_token()),
            Err(error) => Err(MatrixError::internal(&error.to_string())),
        }
    }
}

/// The `Authorization: Bearer` header.
///
/// The `?access_token=` query parameter is the deprecated alternative and is
/// deliberately not read: it lands in access logs, proxy logs and browser
/// history, which is exactly what a bearer credential must not do.
fn bearer(parts: &Parts) -> Option<String> {
    let value = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}
