//! MSC3861: authentication delegated to an OIDC provider.
//!
//! When delegation is configured, the provider — typically the Matrix
//! Authentication Service — owns identity. This server's whole job
//! shrinks to two things: tell clients where the provider is
//! (`/auth_metadata`), and turn the provider's access tokens into
//! identities by OAuth 2.0 token introspection. Accounts are provisioned
//! on first sight, exactly like appservice ghosts and for the same
//! reason: the account exists because the authority for it says so, and
//! a password nobody holds is the only password such an account should
//! have.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::accounts::{Accounts, Identity};
use crate::config::DelegatedAuthConfig;
use crate::errors::MatrixError;

/// How long one introspection verdict is trusted before the provider is
/// asked again. This is the revocation lag only for a revocation this
/// server is never told about: a logout it serves, and a device the
/// provider deletes through `/_synapse/mas/delete_device`, evict the
/// verdicts they end at once (#615), and a cached verdict whose device
/// has gone is refused on sight, the check Synapse's `MasDelegatedAuth`
/// makes for the same reason. Synapse ships the same two minutes.
const INTROSPECTION_TTL: Duration = Duration::from_secs(120);

/// The scope prefix MSC2967 uses to bind a token to one device.
const DEVICE_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:device:";

/// The scope that grants the client API at all.
const API_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:api:*";
const STABLE_API_SCOPE: &str = "urn:matrix:client:api:*";
const STABLE_DEVICE_SCOPE: &str = "urn:matrix:client:device:";
const ADMIN_SCOPE: &str = "urn:synapse:admin:*";

#[derive(Clone)]
struct Verdict {
    user_id: String,
    device_id: Option<String>,
    admin: bool,
}

/// The delegated provider, plus the caches that keep it off the hot path.
pub struct Delegated {
    config: DelegatedAuthConfig,
    client: reqwest::Client,
    /// Token-hash → verdict. Introspecting on every request would put
    /// the provider in every API call's latency; the hash keeps usable
    /// tokens out of process memory dumps, same as the token store.
    verdicts: Mutex<HashMap<[u8; 32], (Verdict, Instant)>>,
    /// Bumped by every eviction. An introspection that was in flight
    /// while one happened may be carrying the very verdict the eviction
    /// ended -- the provider answered before the session was revoked --
    /// so its answer serves the request it was made for and is not
    /// cached, and it provisions no device: re-creating the row a
    /// deletion just removed would bring the dead device back.
    evictions: AtomicU64,
    /// The provider's metadata document, fetched once on first ask.
    metadata: Mutex<Option<Value>>,
}

impl Delegated {
    #[must_use]
    pub fn new(config: DelegatedAuthConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            verdicts: Mutex::new(HashMap::new()),
            evictions: AtomicU64::new(0),
            metadata: Mutex::new(None),
        }
    }

    /// Forget the cached verdict for one token: it has been logged out.
    pub fn forget_token(&self, token: &str) {
        let key: [u8; 32] = *blake3::hash(token.as_bytes()).as_bytes();
        self.evict(|candidate, _| *candidate == key);
    }

    /// Forget every cached verdict bound to one device of one user: the
    /// device is gone, and with it every session the provider issued for it.
    pub fn forget_device(&self, user_id: &str, device_id: &str) {
        self.evict(|_, verdict| {
            verdict.user_id == user_id && verdict.device_id.as_deref() == Some(device_id)
        });
    }

    /// Forget every cached verdict for one user, device-bound or not:
    /// logged out everywhere, or deactivated.
    pub fn forget_user(&self, user_id: &str) {
        self.evict(|_, verdict| verdict.user_id == user_id);
    }

    /// How many verdicts are cached, for tests that assert an eviction.
    #[must_use]
    pub fn cached_verdicts(&self) -> usize {
        self.verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn evict(&self, matches: impl Fn(&[u8; 32], &Verdict) -> bool) {
        let mut verdicts = self
            .verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bumped under the lock, so an introspection cannot read the old
        // count, lose the race to this eviction, and still insert.
        self.evictions.fetch_add(1, Ordering::SeqCst);
        verdicts.retain(|key, (verdict, _)| !matches(key, verdict));
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// The provider's `OpenID Connect` discovery document, for
    /// `/auth_metadata` (MSC2965). Fetched lazily and cached for the
    /// life of the process — the document describes endpoints, which
    /// change on redeployments, not mid-flight.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError`] if the provider cannot be reached or
    /// answers something that is not a JSON object.
    pub async fn metadata(&self) -> Result<Value, MatrixError> {
        if let Some(cached) = self
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Ok(cached);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let document: Value = self
            .client
            .get(url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| MatrixError::internal(&format!("auth provider: {error}")))?
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(Value::is_object)
            .ok_or_else(|| MatrixError::internal("auth provider metadata is not a JSON object"))?;
        *self
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(document.clone());
        Ok(document)
    }

    /// Resolve a provider-issued access token into an identity,
    /// provisioning the local account on first sight.
    ///
    /// # Errors
    ///
    /// Returns `M_UNKNOWN_TOKEN` for anything the provider does not
    /// vouch for — inactive, unreachable, wrong scopes: from the
    /// caller's side these are all the same "this token buys nothing".
    pub async fn identify(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
    ) -> Result<Identity, MatrixError> {
        let verdict = self.resolve(store, server_name, token).await?;
        Ok(Identity {
            user_id: verdict.user_id,
            device_id: verdict.device_id.ok_or_else(MatrixError::unknown_token)?,
        })
    }

    /// Resolve an account identity for `/whoami`. Element Admin's OAuth scopes
    /// grant an account and admin capability without allocating a device.
    /// The empty internal device ID is omitted from that endpoint's response.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for inactive tokens or invalid scopes.
    pub async fn identify_account(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
    ) -> Result<Identity, MatrixError> {
        let verdict = self.resolve(store, server_name, token).await?;
        let accounts = Accounts::new(store, server_name);
        let localpart = verdict
            .user_id
            .strip_prefix('@')
            .and_then(|rest| rest.split_once(':'))
            .map(|(localpart, _)| localpart)
            .ok_or_else(MatrixError::unknown_token)?;
        if accounts
            .account(localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_none_or(|account| account.deactivated)
        {
            return Err(MatrixError::unknown_token());
        }
        Ok(Identity {
            user_id: verdict.user_id,
            device_id: verdict.device_id.unwrap_or_default(),
        })
    }

    /// Authenticate an admin token without provisioning a synthetic device.
    /// The capability belongs to the token; it never changes the account's flag.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for invalid tokens or missing admin scope.
    pub async fn identify_admin(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
    ) -> Result<Identity, MatrixError> {
        let verdict = self.resolve(store, server_name, token).await?;
        if !verdict.admin {
            return Err(MatrixError::forbidden("token does not grant the admin API"));
        }
        Ok(Identity {
            user_id: verdict.user_id,
            // Admin handlers use the identity for authorization and audit only.
            device_id: verdict.device_id.unwrap_or_default(),
        })
    }

    async fn resolve(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
    ) -> Result<Verdict, MatrixError> {
        let key: [u8; 32] = *blake3::hash(token.as_bytes()).as_bytes();
        let cached = self
            .verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned();
        if let Some((verdict, fresh_until)) = cached
            && fresh_until > Instant::now()
        {
            // The device the verdict names must still exist. A session the
            // provider ended has its device deleted here through the
            // provisioning API, so a missing row is a revocation this cache
            // has not heard about yet -- Synapse makes exactly this check on
            // every request for exactly this reason. Refused rather than
            // re-asked: the provider is the one that just said so.
            if let Some(device_id) = &verdict.device_id
                && !device_exists(store, server_name, &verdict.user_id, device_id)?
            {
                self.forget_token(token);
                return Err(MatrixError::unknown_token());
            }
            return Ok(verdict);
        }
        let generation = self.evictions.load(Ordering::SeqCst);
        let verdict = self
            .introspect(store, server_name, token, generation)
            .await?;
        let mut verdicts = self
            .verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.evictions.load(Ordering::SeqCst) == generation {
            verdicts.insert(key, (verdict.clone(), Instant::now() + INTROSPECTION_TTL));
        }
        Ok(verdict)
    }

    async fn introspect(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
        generation: u64,
    ) -> Result<Verdict, MatrixError> {
        let request = self
            .client
            .post(&self.config.introspection_endpoint)
            .header("X-MAS-Supports-Device-Id", "1");
        // A registered client's credentials when there are some; otherwise
        // the shared homeserver secret, which MAS accepts from the
        // homeserver it serves (Synapse's `matrix_authentication_service`
        // way). Config validation guarantees one or the other.
        let request = match (&self.config.client_id, &self.config.client_secret) {
            (Some(id), Some(secret)) => request.basic_auth(id, Some(secret)),
            _ => request.bearer_auth(self.config.homeserver_secret.as_deref().unwrap_or_default()),
        };
        let response = request
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| MatrixError::unknown_token())?;
        let verdict: Value = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        if verdict["active"] != Value::Bool(true) {
            return Err(MatrixError::unknown_token());
        }
        let scope = verdict["scope"].as_str().unwrap_or_default();
        let scopes: std::collections::HashSet<_> = scope.split_ascii_whitespace().collect();
        if !scopes.contains(API_SCOPE) && !scopes.contains(STABLE_API_SCOPE) {
            return Err(MatrixError::unknown_token());
        }
        let device_ids: std::collections::HashSet<_> = scopes
            .iter()
            .filter_map(|part| {
                part.strip_prefix(DEVICE_SCOPE)
                    .or_else(|| part.strip_prefix(STABLE_DEVICE_SCOPE))
            })
            .collect();
        if device_ids.len() > 1 {
            return Err(MatrixError::unknown_token());
        }
        let device_id = verdict["device_id"]
            .as_str()
            .or_else(|| device_ids.into_iter().next())
            .map(str::to_owned);
        if device_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 255)
        {
            return Err(MatrixError::unknown_token());
        }
        let admin = scopes.contains(ADMIN_SCOPE);
        if device_id.is_none() && !admin {
            return Err(MatrixError::unknown_token());
        }
        let localpart = verdict["username"]
            .as_str()
            .ok_or_else(MatrixError::unknown_token)?
            .to_lowercase();

        let accounts = Accounts::new(store, server_name);
        let known = accounts
            .account(&localpart)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_some();
        if !known {
            accounts
                .register(&localpart, &crate::accounts::unguessable_password())
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
        }
        // The device row exists because the provider bound the token to
        // it — MSC3861's account/device mapping, written down so device
        // lists and E2EE key uploads have something to hang off.
        if let Some(device_id) = &device_id
            && self.evictions.load(Ordering::SeqCst) == generation
            && accounts
                .device(&localpart, device_id)
                .map_err(|error| MatrixError::internal(&error.to_string()))?
                .is_none()
        {
            accounts
                .put_device(&localpart, device_id, None)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
        }
        Ok(Verdict {
            user_id: accounts.user_id(&localpart),
            device_id,
            admin,
        })
    }
}

/// Whether `device_id` of the local `user_id` still has its row.
fn device_exists(
    store: &spindle_store::FjallStore,
    server_name: &str,
    user_id: &str,
    device_id: &str,
) -> Result<bool, MatrixError> {
    let Some(localpart) = user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .map(|(localpart, _)| localpart)
    else {
        return Ok(false);
    };
    Ok(Accounts::new(store, server_name)
        .device(localpart, device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .is_some())
}
