//! Local accounts, devices, and access tokens.
//!
//! Two decisions here are security-relevant and deliberate.
//!
//! **Access tokens are stored hashed, never in clear.** The token is a bearer
//! credential: whoever holds it is the user, without any further check. A
//! database that stores them verbatim turns any read — a leaked backup, a stray
//! log of a scan, a support engineer with query access — directly into live
//! sessions for every user on the server. Storing SHA-256 of the token means a
//! reader learns nothing usable, and costs one hash per authenticated request.
//!
//! **Passwords use Argon2id with a per-password salt**, which is the current
//! recommendation for password hashing and is deliberately slow. The cost is
//! paid on login, which is rare; the alternative is paid by every user whose
//! password is recovered from a stolen hash.

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use spindle_core::keys::{Keyspace, room_prefix};
use spindle_store::{Store, StoreError};

/// How many bytes of entropy an access token carries.
///
/// 32 bytes is 256 bits, which is not guessable by anyone, ever. The token is
/// the entire authentication for every request that carries it, so this is not
/// a place to economise.
const TOKEN_BYTES: usize = 32;

/// A registered local user.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Account {
    pub localpart: String,
    /// Argon2id PHC string, salt included.
    pub password_hash: String,
    /// Deactivated accounts keep their row — the localpart stays taken
    /// forever, because releasing it would let a stranger inherit the
    /// old user's identity — but no longer authenticate.
    #[serde(default)]
    pub deactivated: bool,
    /// Server administrator. A flag on an account rather than a shared
    /// secret, so the audit log can name who acted and revocation is
    /// per-operator (#83). Settable only by another admin through the
    /// API; the first admin is minted by the offline `promote-admin`
    /// subcommand against the store.
    #[serde(default)]
    pub admin: bool,
}

/// One logged-in device.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    pub localpart: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

/// What a presented access token resolves to.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenRecord {
    pub localpart: String,
    pub device_id: String,
}

/// A session's credentials, as handed to the client.
///
/// The tokens exist in clear exactly once, here. What the store holds is their
/// hashes.
#[derive(Clone, Debug)]
pub struct Session {
    pub access_token: String,
    /// Absent unless the client asked: handing a refresh token to a client that
    /// does not implement refresh creates a long-lived credential nobody will
    /// ever rotate or revoke.
    pub refresh_token: Option<String>,
    pub device: Device,
    /// How long the access token is good for, when refresh is in use.
    pub expires_in_ms: Option<u64>,
}

/// How long an access token lives when the client is refreshing.
///
/// Only meaningful with a refresh token. Expiring a token the client cannot
/// renew would log them out for no reason, so a non-refreshing session gets one
/// that does not expire -- which is why `expires_in_ms` is absent there rather
/// than merely large.
const ACCESS_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

/// The identity behind an authenticated request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub user_id: String,
    pub device_id: String,
}

/// Accounts, devices and tokens on top of the durable store.
pub struct Accounts<'a, S: Store> {
    store: &'a S,
    server_name: String,
}

impl<'a, S: Store> Accounts<'a, S> {
    pub fn new(store: &'a S, server_name: impl Into<String>) -> Self {
        Self {
            store,
            server_name: server_name.into(),
        }
    }

    /// `@localpart:server.name`
    #[must_use]
    pub fn user_id(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.server_name)
    }

    /// Would this localpart register? Valid grammar and not taken.
    ///
    /// # Errors
    ///
    /// [`AccountError::InvalidUsername`], [`AccountError::UserInUse`], or a
    /// storage error.
    pub fn availability(&self, localpart: &str) -> Result<(), AccountError> {
        validate_localpart(localpart)?;
        if self.account(localpart)?.is_some() {
            return Err(AccountError::UserInUse);
        }
        Ok(())
    }

    /// Register a new account.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::UserInUse`] if the localpart is taken, or a
    /// storage error.
    pub fn register(&self, localpart: &str, password: &str) -> Result<Account, AccountError> {
        validate_localpart(localpart)?;
        if self.account(localpart)?.is_some() {
            return Err(AccountError::UserInUse);
        }

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| AccountError::Hashing(error.to_string()))?
            .to_string();

        let account = Account {
            localpart: localpart.to_owned(),
            password_hash,
            deactivated: false,
            admin: false,
        };
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(account)
    }

    /// Flip an account's deactivation flag, leaving everything else.
    /// An unknown localpart is a no-op: deactivating a user who does
    /// not exist has nothing to do.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn set_deactivated(&self, localpart: &str, deactivated: bool) -> Result<(), AccountError> {
        let Some(mut account) = self.account(localpart)? else {
            return Ok(());
        };
        account.deactivated = deactivated;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn account(&self, localpart: &str) -> Result<Option<Account>, AccountError> {
        match self.store.get(&account_key(localpart))? {
            Some(raw) => Ok(Some(decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// Check a password against a stored account.
    ///
    /// Returns `false` for an unknown user as well as a wrong password, and
    /// does the same work either way: a caller that could tell the two apart by
    /// timing would have a user-enumeration oracle.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn verify_password(&self, localpart: &str, password: &str) -> Result<bool, AccountError> {
        let account = self.account(localpart)?;
        let hash = account.as_ref().map_or(DUMMY_HASH, |a| &a.password_hash);
        let parsed = PasswordHash::new(hash).map_err(|e| AccountError::Hashing(e.to_string()))?;
        let matches = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // A deactivated account keeps its hash (the row is the localpart
        // reservation) but no longer authenticates.
        Ok(matches && account.is_some_and(|account| !account.deactivated))
    }

    /// Create a device and an access token for it.
    ///
    /// Returns the token in clear — the only time it exists in that form. What
    /// is stored is its hash.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn create_session(
        &self,
        localpart: &str,
        device_id: Option<String>,
        display_name: Option<String>,
        with_refresh: bool,
    ) -> Result<Session, AccountError> {
        let device_id = device_id.unwrap_or_else(|| random_id("DEV"));
        let device = Device {
            localpart: localpart.to_owned(),
            device_id: device_id.clone(),
            display_name,
        };
        self.store
            .put(&device_key(localpart, &device_id), &encode(&device)?)?;

        let record = TokenRecord {
            localpart: localpart.to_owned(),
            device_id,
        };
        let access_token = random_token("syt");
        self.store.put(
            &token_key(Keyspace::AccessToken, &access_token),
            &encode(&record)?,
        )?;

        let refresh_token = if with_refresh {
            let refresh = random_token("syr");
            self.store.put(
                &token_key(Keyspace::RefreshToken, &refresh),
                &encode(&record)?,
            )?;
            Some(refresh)
        } else {
            None
        };

        Ok(Session {
            access_token,
            expires_in_ms: refresh_token.as_ref().map(|_| ACCESS_TOKEN_LIFETIME_MS),
            refresh_token,
            device,
        })
    }

    /// Exchange a refresh token for a fresh pair.
    ///
    /// The presented refresh token is consumed. Rotation is the point: a
    /// refresh token is long-lived by design, so one that stayed valid after
    /// use would let anyone who ever saw it -- a proxy log, a stale backup, a
    /// device that was later wiped -- mint access tokens indefinitely.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::UnknownToken`] if the token is not live, or a
    /// storage error.
    pub fn refresh(&self, refresh_token: &str) -> Result<Session, AccountError> {
        let key = token_key(Keyspace::RefreshToken, refresh_token);
        let raw = self.store.get(&key)?.ok_or(AccountError::UnknownToken)?;
        let record: TokenRecord = decode(&raw)?;

        // Consumed before the replacements are issued. Reversed, a process that
        // died between the two writes would leave the old token live alongside
        // a new one.
        self.store.delete(&key)?;

        let access_token = random_token("syt");
        self.store.put(
            &token_key(Keyspace::AccessToken, &access_token),
            &encode(&record)?,
        )?;
        let replacement = random_token("syr");
        self.store.put(
            &token_key(Keyspace::RefreshToken, &replacement),
            &encode(&record)?,
        )?;

        Ok(Session {
            access_token,
            refresh_token: Some(replacement),
            expires_in_ms: Some(ACCESS_TOKEN_LIFETIME_MS),
            device: Device {
                localpart: record.localpart,
                device_id: record.device_id,
                display_name: None,
            },
        })
    }

    /// Resolve a bearer token to an identity.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn identify(&self, token: &str) -> Result<Option<Identity>, AccountError> {
        match self.store.get(&token_key(Keyspace::AccessToken, token))? {
            Some(raw) => {
                let record: TokenRecord = decode(&raw)?;
                Ok(Some(Identity {
                    user_id: self.user_id(&record.localpart),
                    device_id: record.device_id,
                }))
            }
            None => Ok(None),
        }
    }

    /// Invalidate one token.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn logout(&self, token: &str) -> Result<(), AccountError> {
        self.store
            .delete(&token_key(Keyspace::AccessToken, token))?;
        Ok(())
    }

    /// Every device of one user, in stored (device-ID) order.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn devices_of(&self, localpart: &str) -> Result<Vec<Device>, AccountError> {
        let prefix = room_prefix(Keyspace::Device, localpart);
        let mut out = Vec::new();
        for (_, raw) in self.store.scan_prefix(&prefix)? {
            out.push(decode(&raw)?);
        }
        Ok(out)
    }

    /// One device of one user, if it exists.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn device(&self, localpart: &str, device_id: &str) -> Result<Option<Device>, AccountError> {
        match self.store.get(&device_key(localpart, device_id))? {
            Some(raw) => Ok(Some(decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// Write a device row, creating or replacing it.
    ///
    /// This is the sessionless half of MSC4190: an appservice mints a
    /// device *without* an access token, because the `as_token` is its
    /// credential and a token nobody will present is a credential nobody
    /// should hold.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn put_device(
        &self,
        localpart: &str,
        device_id: &str,
        display_name: Option<String>,
    ) -> Result<(), AccountError> {
        let device = Device {
            localpart: localpart.to_owned(),
            device_id: device_id.to_owned(),
            display_name,
        };
        self.store
            .put(&device_key(localpart, device_id), &encode(&device)?)?;
        Ok(())
    }

    /// Flip an account's admin flag. Returns whether the account
    /// existed — granting admin to a localpart that does not exist is a
    /// typo about to become a security incident, so the caller must be
    /// able to tell and refuse rather than silently no-op.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn set_admin(&self, localpart: &str, admin: bool) -> Result<bool, AccountError> {
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        account.admin = admin;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(true)
    }

    /// Replace an account's password.
    ///
    /// # Errors
    ///
    /// Returns a storage, decoding, or hashing error.
    pub fn set_password(&self, localpart: &str, password: &str) -> Result<bool, AccountError> {
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        let salt = SaltString::generate(&mut OsRng);
        account.password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| AccountError::Hashing(error.to_string()))?
            .to_string();
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(true)
    }

    /// Delete every access and refresh token of one user, ending all
    /// their sessions at once. Device rows stay — the devices still
    /// exist, they are just logged out.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn logout_everywhere(&self, localpart: &str) -> Result<(), AccountError> {
        for keyspace in [Keyspace::AccessToken, Keyspace::RefreshToken] {
            let prefix = [spindle_core::keys::KEY_SCHEMA_VERSION, keyspace as u8];
            for (key, raw) in self.store.scan_prefix(&prefix)? {
                let record: TokenRecord = decode(&raw)?;
                if record.localpart == localpart {
                    self.store.delete(&key)?;
                }
            }
        }
        Ok(())
    }

    /// Every account, in stored (localpart) order — the admin listing's
    /// backing scan. Bounded by the number of accounts on the server,
    /// which is the admin's own population.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn all_accounts(&self) -> Result<Vec<Account>, AccountError> {
        let prefix = [
            spindle_core::keys::KEY_SCHEMA_VERSION,
            Keyspace::Account as u8,
        ];
        let mut out = Vec::new();
        for (_, raw) in self.store.scan_prefix(&prefix)? {
            out.push(decode(&raw)?);
        }
        Ok(out)
    }

    /// Delete a device and every token that authenticates as it.
    ///
    /// The token keyspaces are keyed by token hash, so the sessions are
    /// found by scanning them — bounded by live sessions on the server,
    /// which is the price of never storing a usable token. A deleted
    /// device whose tokens survived would not be deleted at all.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn delete_device(&self, localpart: &str, device_id: &str) -> Result<(), AccountError> {
        self.store.delete(&device_key(localpart, device_id))?;
        for keyspace in [Keyspace::AccessToken, Keyspace::RefreshToken] {
            let prefix = [spindle_core::keys::KEY_SCHEMA_VERSION, keyspace as u8];
            for (key, raw) in self.store.scan_prefix(&prefix)? {
                let record: TokenRecord = decode(&raw)?;
                if record.localpart == localpart && record.device_id == device_id {
                    self.store.delete(&key)?;
                }
            }
        }
        Ok(())
    }
}

/// An Argon2id hash of nothing in particular, verified against when the user
/// does not exist so that a missing account costs the same as a wrong password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3BpbmRsZWR1bW15c2FsdA$\
    Zx8kM1kDBFqPuHRZ0M0MVXOaEfKMTL9dTgKtOJXHIWQ";

fn account_key(localpart: &str) -> Vec<u8> {
    room_prefix(Keyspace::Account, localpart)
}

fn device_key(localpart: &str, device_id: &str) -> Vec<u8> {
    let mut key = room_prefix(Keyspace::Device, localpart);
    key.extend_from_slice(device_id.as_bytes());
    key
}

/// Tokens are keyed by their hash, so the store never holds a usable one.
///
/// Access and refresh tokens live in separate keyspaces, so one cannot be
/// presented as the other. Sharing a keyspace would make them interchangeable,
/// which quietly turns the long-lived credential into a bearer token for the
/// whole API.
fn token_key(keyspace: Keyspace, token: &str) -> Vec<u8> {
    let digest = blake3::hash(token.as_bytes());
    let mut key = vec![spindle_core::keys::KEY_SCHEMA_VERSION, keyspace as u8];
    key.extend_from_slice(digest.as_bytes());
    key
}

/// A password for an account nobody logs into with one: appservice
/// ghosts, MSC3861-provisioned users. 256 bits of entropy that are
/// hashed, stored, and never seen again — the account is entered through
/// its own door (the `as_token`, the provider's introspection), and a
/// guessable password would be a second door nobody watches.
#[must_use]
pub fn unguessable_password() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", hex(&bytes))
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", hex(&bytes).to_uppercase())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AccountError> {
    serde_json::to_vec(value).map_err(|error| AccountError::Codec(error.to_string()))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AccountError> {
    serde_json::from_slice(bytes).map_err(|error| AccountError::Codec(error.to_string()))
}

/// Matrix localparts are a restricted grammar, and the restriction matters:
/// the localpart ends up inside a user ID that federates.
fn validate_localpart(localpart: &str) -> Result<(), AccountError> {
    if localpart.is_empty() || localpart.len() > 255 {
        return Err(AccountError::InvalidUsername);
    }
    let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "._=-/+".contains(c);
    if !localpart.chars().all(allowed) {
        return Err(AccountError::InvalidUsername);
    }
    Ok(())
}

/// Why an account operation failed.
#[derive(Debug)]
pub enum AccountError {
    UserInUse,
    /// A presented token is not live.
    UnknownToken,
    InvalidUsername,
    Storage(StoreError),
    Codec(String),
    Hashing(String),
}

impl From<StoreError> for AccountError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserInUse => write!(formatter, "that username is taken"),
            Self::UnknownToken => write!(formatter, "that token is not valid"),
            Self::InvalidUsername => write!(formatter, "that username is not valid"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Codec(message) => write!(formatter, "unreadable record: {message}"),
            Self::Hashing(message) => write!(formatter, "password hashing: {message}"),
        }
    }
}

impl std::error::Error for AccountError {}
