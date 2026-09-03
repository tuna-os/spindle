//! `OpenID` tokens: a way for a client to prove to a third party who it is.
//!
//! # Why a homeserver mints these
//!
//! A `MatrixRTC` call needs a token for the media backend, and the backend
//! is not this server -- it is a `LiveKit` SFU behind a JWT service that
//! has never seen the user's access token and must not be handed it. So the
//! client asks *this* server for a short-lived, single-purpose credential
//! (`POST /user/{user_id}/openid/request_token`), passes it to the JWT
//! service, and the service redeems it here over federation
//! (`GET /_matrix/federation/v1/openid/userinfo`) to learn the user's ID.
//! The access token never leaves the client; the `OpenID` token proves
//! identity and nothing else -- it opens no other endpoint on this server.
//!
//! That is the whole of what the spec asks for, and it is what
//! `lk-jwt-service` calls back to. The built-in service in
//! [`livekit`](crate::livekit) redeems the same token without the round
//! trip, which is why the store, not the HTTP handler, is the unit here.
//!
//! # Storage
//!
//! One row per token, keyed by expiry then digest ([`Keyspace::OpenIdToken`]),
//! for the same reason a delayed event is keyed by its deadline: the row's
//! only lifecycle event is expiring, and with the expiry in front, "every
//! expired token" is a bounded range read from the start of the keyspace
//! that stops at the first live row. That sweep runs on every mint, so the
//! keyspace holds at most the tokens minted since the last one expired and
//! never needs a loop of its own. The token carries its expiry in clear so a
//! lookup can still address its row directly; the row holds only the user
//! ID, so the store is not a store of usable credentials.
//!
//! [`Keyspace::OpenIdToken`]: spindle_core::keys::Keyspace::OpenIdToken

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spindle_store::{FjallStore, ReadView, Store, StoreError};

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::ratelimit::OPENID_TOKEN_PER_USER;

/// How long a token lives, in seconds. Synapse's figure, and the one
/// `expires_in` reports: long enough to survive a slow JWT service, short
/// enough that a token which leaks is not a lasting claim to be someone.
pub const LIFETIME_SECONDS: u64 = 3600;

/// The prefix every token starts with, so one presented to the wrong
/// endpoint fails as "not one of ours" rather than as a near miss.
const PREFIX: &str = "syo";

/// The random half of a token, in bytes.
const TOKEN_BYTES: usize = 32;

/// What a token vouches for.
#[derive(Debug, Deserialize, Serialize)]
struct Record {
    user_id: String,
}

/// Why a token could not be minted or redeemed.
#[derive(Debug)]
pub enum OpenIdError {
    Store(StoreError),
    Codec(String),
}

impl std::fmt::Display for OpenIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "store: {error}"),
            Self::Codec(why) => write!(formatter, "record: {why}"),
        }
    }
}

impl std::error::Error for OpenIdError {}

impl From<StoreError> for OpenIdError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// A token as handed to the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issued {
    pub access_token: String,
    pub expires_at_ms: u64,
}

/// The `OpenID` tokens on top of the durable store.
pub struct OpenId {
    store: Arc<FjallStore>,
}

impl OpenId {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Mint a token for `user_id`, live for [`LIFETIME_SECONDS`] from now.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn issue(&self, user_id: &str) -> Result<Issued, OpenIdError> {
        let now = now_ms();
        self.issue_at(user_id, now, now + LIFETIME_SECONDS * 1000)
    }

    /// Mint a token with an explicit clock and expiry.
    ///
    /// Public so a test can mint a token that is already expired and watch
    /// `userinfo` refuse it, which is otherwise an hour's wait; the server
    /// itself only calls [`Self::issue`].
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn issue_at(
        &self,
        user_id: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Issued, OpenIdError> {
        // The sweep first, so the keyspace never holds more than one
        // lifetime's worth of tokens: every row expired by now sorts before
        // the bound, and the read stops at the first live one.
        self.evict_expired(now_ms)?;

        let mut random = [0_u8; TOKEN_BYTES];
        crate::secrets::fill(&mut random);
        let access_token = format!("{PREFIX}_{expires_at_ms:016x}_{}", hex(&random));
        let record = serde_json::to_vec(&Record {
            user_id: user_id.to_owned(),
        })
        .map_err(|error| OpenIdError::Codec(error.to_string()))?;
        self.store
            .put(&key_of(&access_token, expires_at_ms), &record)?;
        Ok(Issued {
            access_token,
            expires_at_ms,
        })
    }

    /// Who a token vouches for, if it is one of ours and still live.
    ///
    /// `None` for a token this server never minted, one whose row is gone,
    /// or one past its expiry -- and the three are deliberately not told
    /// apart: the caller is a third party redeeming a credential, and "not
    /// valid" is all it is owed.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn redeem(&self, access_token: &str) -> Result<Option<String>, OpenIdError> {
        self.redeem_at(access_token, now_ms())
    }

    /// [`Self::redeem`] against an explicit clock.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn redeem_at(
        &self,
        access_token: &str,
        now_ms: u64,
    ) -> Result<Option<String>, OpenIdError> {
        let Some(expires_at_ms) = expiry_of(access_token) else {
            return Ok(None);
        };
        // Strictly before: a token expiring at `now` is expired, which is
        // the same edge the eviction bound uses.
        if expires_at_ms <= now_ms {
            return Ok(None);
        }
        let Some(raw) = self.store.get(&key_of(access_token, expires_at_ms))? else {
            return Ok(None);
        };
        let record: Record =
            serde_json::from_slice(&raw).map_err(|error| OpenIdError::Codec(error.to_string()))?;
        Ok(Some(record.user_id))
    }

    /// Delete every row expired at `now_ms`.
    fn evict_expired(&self, now_ms: u64) -> Result<(), StoreError> {
        let prefix = spindle_core::keys::openid_token_prefix();
        let expired = self.store.scan_until(
            &prefix,
            &prefix,
            &spindle_core::keys::openid_token_expired_end(now_ms),
        )?;
        for (key, _) in expired {
            self.store.delete(&key)?;
        }
        Ok(())
    }
}

/// The row for a token: its expiry, then the digest of the whole token.
fn key_of(access_token: &str, expires_at_ms: u64) -> Vec<u8> {
    let digest = blake3::hash(access_token.as_bytes());
    spindle_core::keys::openid_token(expires_at_ms, digest.as_bytes())
}

/// The expiry a token carries, or `None` if it is not shaped like one of
/// ours.
///
/// The expiry in the token is *addressing*, not trust: it says which row to
/// look in, and a forged expiry addresses a row that was never written. A
/// token whose expiry has been edited forward therefore finds nothing, not
/// a longer life.
fn expiry_of(access_token: &str) -> Option<u64> {
    let mut parts = access_token.splitn(3, '_');
    if parts.next()? != PREFIX {
        return None;
    }
    let expiry = parts.next()?;
    let random = parts.next()?;
    if expiry.len() != 16 || random.len() != TOKEN_BYTES * 2 {
        return None;
    }
    u64::from_str_radix(expiry, 16).ok()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Unix milliseconds now.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The two `OpenID` routes: the client-facing mint and the federation-facing
/// redemption.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/user/{user_id}/openid/request_token",
            post(request_token),
        )
        .route("/_matrix/federation/v1/openid/userinfo", get(userinfo))
}

/// `POST /_matrix/client/v3/user/{user_id}/openid/request_token`
///
/// The body is `{}` by spec and is not read: there is nothing in it, and a
/// client that sends no body at all is not wrong enough to refuse.
///
/// Rate limited per user, because a mint is a durable write on the caller's
/// say-so and the third parties these are for -- a JWT service, an SFU --
/// do real work for each one. The limit is the first check so a caller
/// over it costs nothing further.
async fn request_token(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, MatrixError> {
    // A token vouches for exactly the user who asked for it. The path is
    // spec-mandated redundancy, and the one thing it can express is a
    // mismatch.
    if user_id != identity.user_id {
        return Err(MatrixError::forbidden(
            "an OpenID token can only be requested for yourself",
        ));
    }
    if let Err(retry) = state
        .limiter
        .check(&format!("openid:user:{user_id}"), OPENID_TOKEN_PER_USER)
    {
        return Err(MatrixError::limit_exceeded(retry.as_millis()));
    }
    let issued = OpenId::new(Arc::clone(&state.store))
        .issue(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "matrix_server_name": state.config.server.name,
        "expires_in": LIFETIME_SECONDS,
    })))
}

#[derive(Debug, Deserialize)]
struct UserinfoQuery {
    access_token: Option<String>,
}

/// `GET /_matrix/federation/v1/openid/userinfo?access_token=...`
///
/// Unauthenticated, by spec: the caller is whoever the client handed the
/// token to, and the token is the credential. It answers one question --
/// who is this -- and answers nothing for a token it does not recognise,
/// including one that has expired: the distinction between "never ours"
/// and "no longer live" is not the redeemer's to learn.
async fn userinfo(
    State(state): State<AppState>,
    Query(query): Query<UserinfoQuery>,
) -> Result<Json<Value>, MatrixError> {
    let Some(access_token) = query.access_token.filter(|token| !token.is_empty()) else {
        return Err(MatrixError::missing_param("access_token"));
    };
    match OpenId::new(Arc::clone(&state.store)).redeem(&access_token) {
        Ok(Some(user_id)) => Ok(Json(json!({ "sub": user_id }))),
        Ok(None) => Err(MatrixError::unknown_token()),
        Err(error) => Err(MatrixError::internal(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenId, expiry_of};
    use spindle_store::FjallStore;
    use std::sync::Arc;

    fn open() -> (tempfile::TempDir, OpenId) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        (dir, OpenId::new(store))
    }

    #[test]
    fn a_token_redeems_to_its_user_until_it_expires() {
        let (_dir, openid) = open();
        let issued = openid.issue_at("@alice:example.org", 1_000, 5_000).unwrap();

        assert_eq!(
            openid.redeem_at(&issued.access_token, 4_999).unwrap(),
            Some("@alice:example.org".to_owned())
        );
        assert_eq!(openid.redeem_at(&issued.access_token, 5_000).unwrap(), None);
    }

    #[test]
    fn a_forged_expiry_addresses_nothing() {
        let (_dir, openid) = open();
        let issued = openid.issue_at("@alice:example.org", 1_000, 5_000).unwrap();
        let random = issued.access_token.rsplit('_').next().unwrap();
        let forged = format!("syo_{:016x}_{random}", 50_000_u64);

        assert_eq!(openid.redeem_at(&forged, 10_000).unwrap(), None);
    }

    #[test]
    fn minting_sweeps_what_has_expired_and_keeps_what_has_not() {
        let (_dir, openid) = open();
        let old = openid.issue_at("@alice:example.org", 1_000, 2_000).unwrap();
        let live = openid.issue_at("@alice:example.org", 1_000, 9_000).unwrap();
        // A mint at 3_000 evicts `old` (expired at 2_000) and leaves `live`.
        let _ = openid.issue_at("@bob:example.org", 3_000, 9_000).unwrap();

        // Even against a clock that would accept it, the row is gone.
        assert_eq!(openid.redeem_at(&old.access_token, 1_500).unwrap(), None);
        assert_eq!(
            openid.redeem_at(&live.access_token, 3_000).unwrap(),
            Some("@alice:example.org".to_owned())
        );
    }

    #[test]
    fn only_our_shape_is_parsed() {
        assert_eq!(expiry_of("syt_notanopenidtoken"), None);
        assert_eq!(expiry_of("syo_short_x"), None);
        assert_eq!(expiry_of(""), None);
        let (_dir, openid) = open();
        let issued = openid.issue_at("@alice:example.org", 0, 7_000).unwrap();
        assert_eq!(expiry_of(&issued.access_token), Some(7_000));
    }
}
