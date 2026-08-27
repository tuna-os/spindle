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
            // Not a local session: an appservice's skeleton key, or —
            // under MSC3861 delegation — a token only the provider can
            // vouch for. The order is cheapest-check-first.
            Ok(None) if state.appservices.by_token(&token).is_some() => {
                appservice_identity(parts, state, &token).map(Self)
            }
            Ok(None) => match &state.delegated {
                Some(delegated) => delegated
                    .identify(state.store.as_ref(), &state.config.server.name, &token)
                    .await
                    .map(Self),
                None => Err(MatrixError::unknown_token()),
            },
            Err(error) => Err(MatrixError::internal(&error.to_string())),
        }
    }
}

/// Resolve an appservice's token into the identity it is acting as.
///
/// An appservice is a client with a skeleton key over its namespaces: the
/// token names the *service*, and `?user_id=` names who it speaks as this
/// request — its own sender user when absent. The authorization check is
/// namespace membership, not "is an appservice"; outside its namespaces
/// the service is a stranger and the spec's `M_EXCLUSIVE` says so.
///
/// Virtual users are provisioned on first use. A bridge's users exist
/// because the bridge speaks as them — demanding a registration round-trip
/// first would only make every bridge implement one, badly, with a forged
/// login. The account is created with an unguessable password nobody
/// holds, because these accounts are entered through this door only.
fn appservice_identity(
    parts: &Parts,
    state: &AppState,
    token: &str,
) -> Result<Identity, MatrixError> {
    let Some(registration) = state.appservices.by_token(token) else {
        return Err(MatrixError::unknown_token());
    };
    let server_name = &state.config.server.name;
    let user_id = parts
        .uri
        .query()
        .and_then(|query| {
            form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "user_id")
                .map(|(_, value)| value.into_owned())
        })
        .unwrap_or_else(|| registration.sender_user(server_name));
    if !registration.may_masquerade_as(&user_id, server_name) {
        return Err(MatrixError::new(
            axum::http::StatusCode::FORBIDDEN,
            "M_EXCLUSIVE",
            format!(
                "{user_id} is outside the {} appservice's namespaces",
                registration.id
            ),
        ));
    }
    let Some(localpart) = user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .filter(|(_, domain)| domain == server_name)
        .map(|(localpart, _)| localpart)
    else {
        return Err(MatrixError::forbidden(
            "an appservice may only act as users of this server",
        ));
    };
    // MSC3202 device masquerading: `?org.matrix.msc3202.device_id=` names
    // which of the masqueraded user's devices this request acts as, which
    // is what lets a bridge upload E2E keys for a ghost's device through
    // the ordinary `/keys/upload`. Absent, the stable synthetic ID stands.
    let device_id = parts
        .uri
        .query()
        .and_then(|query| {
            form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "org.matrix.msc3202.device_id")
                .map(|(_, value)| value.into_owned())
        })
        .unwrap_or_else(|| format!("appservice_{}", registration.id));
    let accounts = Accounts::new(state.store.as_ref(), server_name);
    let known = accounts
        .account(localpart)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some();
    if !known {
        accounts
            .register(localpart, &crate::accounts::unguessable_password())
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
    }
    Ok(Identity {
        user_id,
        // Without MSC3202's masquerade above, a stable synthetic ID keeps
        // everything keyed by device (transaction replay, to-device)
        // coherent.
        device_id,
    })
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
            Ok(None) => appservice_identity(parts, state, &token).map(|id| Self(Some(id))),
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
