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
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::accounts::{Accounts, Identity};
use crate::config::DelegatedAuthConfig;
use crate::errors::MatrixError;

/// How long one introspection verdict is trusted before the provider is
/// asked again. The window is the revocation lag: a token MAS revokes
/// keeps working here for at most this long. Synapse ships the same
/// order of magnitude for the same trade.
const INTROSPECTION_TTL: Duration = Duration::from_secs(120);

/// The scope prefix MSC2967 uses to bind a token to one device.
const DEVICE_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:device:";

/// The scope that grants the client API at all.
const API_SCOPE: &str = "urn:matrix:org.matrix.msc2967.client:api:*";

/// The delegated provider, plus the caches that keep it off the hot path.
pub struct Delegated {
    config: DelegatedAuthConfig,
    client: reqwest::Client,
    /// Token-hash → verdict. Introspecting on every request would put
    /// the provider in every API call's latency; the hash keeps usable
    /// tokens out of process memory dumps, same as the token store.
    verdicts: Mutex<HashMap<[u8; 32], (Identity, Instant)>>,
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
            metadata: Mutex::new(None),
        }
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
        let key: [u8; 32] = *blake3::hash(token.as_bytes()).as_bytes();
        if let Some((identity, fresh_until)) = self
            .verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned()
            && fresh_until > Instant::now()
        {
            return Ok(identity);
        }
        let identity = self.introspect(store, server_name, token).await?;
        self.verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, (identity.clone(), Instant::now() + INTROSPECTION_TTL));
        Ok(identity)
    }

    async fn introspect(
        &self,
        store: &spindle_store::FjallStore,
        server_name: &str,
        token: &str,
    ) -> Result<Identity, MatrixError> {
        let response = self
            .client
            .post(&self.config.introspection_endpoint)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .timeout(Duration::from_secs(10))
            .send()
            .await
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
        if !scope.split(' ').any(|part| part == API_SCOPE) {
            return Err(MatrixError::unknown_token());
        }
        let device_id = scope
            .split(' ')
            .find_map(|part| part.strip_prefix(DEVICE_SCOPE))
            .ok_or_else(MatrixError::unknown_token)?
            .to_owned();
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
        if accounts
            .device(&localpart, &device_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?
            .is_none()
        {
            accounts
                .put_device(&localpart, &device_id, None)
                .map_err(|error| MatrixError::internal(&error.to_string()))?;
        }
        Ok(Identity {
            user_id: accounts.user_id(&localpart),
            device_id,
        })
    }
}
