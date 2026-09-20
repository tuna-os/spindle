//! Registration tokens: the `m.login.registration_token` stage (spec
//! v1.2) and the admin rows behind it.
//!
//! A token is a row an admin minted: how many registrations it allows,
//! how many it has served, and when it lapses. Registration asks for one
//! when `[registration] require_token` is on, and spends it when the
//! account is created, not when the stage is presented, so a client that
//! fails later in the flow has not used a token up.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// The longest token the spec allows.
pub const MAX_TOKEN_LEN: usize = 64;

/// The length of a token minted without one being named.
pub const DEFAULT_TOKEN_LEN: usize = 16;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-";

/// One token, in the shape Synapse's admin API reports it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Token {
    pub token: String,
    /// `None` is unlimited.
    pub uses_allowed: Option<u64>,
    /// Registrations that have presented the token and not finished. This
    /// server spends a token at account creation, so this stays zero; the
    /// field is kept for the tooling that reads it.
    pub pending: u64,
    pub completed: u64,
    /// Milliseconds since the epoch; `None` never lapses.
    pub expiry_time: Option<u64>,
}

impl Token {
    /// Whether the token would be accepted at `now`.
    #[must_use]
    pub fn valid_at(&self, now: u64) -> bool {
        let unexpired = self.expiry_time.is_none_or(|until| until > now);
        let uses_left = self
            .uses_allowed
            .is_none_or(|allowed| self.pending + self.completed < allowed);
        unexpired && uses_left
    }
}

/// Why a token could not be minted.
#[derive(Debug)]
pub enum TokenError {
    /// A token by that name already exists.
    InUse,
    /// Not the spec's grammar: 1 to 64 characters of `[A-Za-z0-9._~-]`.
    Invalid,
    Storage(StoreError),
}

impl From<StoreError> for TokenError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InUse => formatter.write_str("a token by that name already exists"),
            Self::Invalid => formatter.write_str(
                "a token is 1 to 64 characters of letters, digits, '.', '_', '~' or '-'",
            ),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
        }
    }
}

/// The token rows.
pub struct RegistrationTokens {
    store: Arc<FjallStore>,
}

impl RegistrationTokens {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Mint a token: the one named, or a random one of `length`.
    ///
    /// # Errors
    ///
    /// [`TokenError::InUse`] for a name already taken, [`TokenError::Invalid`]
    /// for one outside the grammar, or the store's error.
    pub fn create(
        &self,
        token: Option<String>,
        uses_allowed: Option<u64>,
        expiry_time: Option<u64>,
        length: usize,
    ) -> Result<Token, TokenError> {
        let token = if let Some(token) = token {
            if !well_formed(&token) {
                return Err(TokenError::Invalid);
            }
            if self.get(&token)?.is_some() {
                return Err(TokenError::InUse);
            }
            token
        } else {
            if length == 0 || length > MAX_TOKEN_LEN {
                return Err(TokenError::Invalid);
            }
            loop {
                let candidate = random_token(length);
                if self.get(&candidate)?.is_none() {
                    break candidate;
                }
            }
        };
        let row = Token {
            token,
            uses_allowed,
            pending: 0,
            completed: 0,
            expiry_time,
        };
        self.put(&row)?;
        Ok(row)
    }

    /// One token's row.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn get(&self, token: &str) -> Result<Option<Token>, StoreError> {
        let Some(bytes) = ReadView::get(self.store.as_ref(), &keys::registration_token(token))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| StoreError::Backend(error.to_string()))
    }

    /// Every token, or only the valid or only the lapsed ones.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn list(&self, valid: Option<bool>) -> Result<Vec<Token>, StoreError> {
        let now = now_millis();
        let mut tokens = Vec::new();
        for (_, bytes) in
            ReadView::scan_prefix(self.store.as_ref(), &keys::registration_tokens_prefix())?
        {
            let token: Token = serde_json::from_slice(&bytes)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if valid.is_none_or(|wanted| token.valid_at(now) == wanted) {
                tokens.push(token);
            }
        }
        Ok(tokens)
    }

    /// Change a token's allowance or expiry. Each `Some(None)` clears the
    /// bound; `None` leaves it. Returns the row after the change, or
    /// `None` for an unknown token.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn update(
        &self,
        token: &str,
        uses_allowed: Option<Option<u64>>,
        expiry_time: Option<Option<u64>>,
    ) -> Result<Option<Token>, StoreError> {
        let Some(mut row) = self.get(token)? else {
            return Ok(None);
        };
        if let Some(uses_allowed) = uses_allowed {
            row.uses_allowed = uses_allowed;
        }
        if let Some(expiry_time) = expiry_time {
            row.expiry_time = expiry_time;
        }
        self.put(&row)?;
        Ok(Some(row))
    }

    /// Remove a token. `false` when there was none.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn delete(&self, token: &str) -> Result<bool, StoreError> {
        if self.get(token)?.is_none() {
            return Ok(false);
        }
        Store::delete(self.store.as_ref(), &keys::registration_token(token))?;
        Ok(true)
    }

    /// Whether `token` would be accepted now.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn is_valid(&self, token: &str) -> Result<bool, StoreError> {
        Ok(self
            .get(token)?
            .is_some_and(|row| row.valid_at(now_millis())))
    }

    /// Spend one use of `token`: an account was created with it.
    ///
    /// # Errors
    ///
    /// Returns the store's error.
    pub fn consume(&self, token: &str) -> Result<(), StoreError> {
        if let Some(mut row) = self.get(token)? {
            row.completed = row.completed.saturating_add(1);
            self.put(&row)?;
        }
        Ok(())
    }

    fn put(&self, row: &Token) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::registration_token(&row.token),
            &serde_json::to_vec(row).map_err(|error| StoreError::Backend(error.to_string()))?,
        )
    }
}

fn well_formed(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token.bytes().all(|byte| ALPHABET.contains(&byte))
}

fn random_token(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    crate::secrets::fill(&mut bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect()
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
