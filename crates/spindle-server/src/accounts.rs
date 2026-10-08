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

use crate::passwords::ReusableArgon2;
use argon2::password_hash::phc::{PasswordHash, Salt};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use spindle_core::keys::{self, Keyspace, room_prefix};
use spindle_store::{Store, StoreError};

static ERASURE_POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn erasure_policy_key() -> Vec<u8> {
    room_prefix(Keyspace::ErasurePolicy, "")
}

/// How many bytes of entropy an access token carries.
///
/// 32 bytes is 256 bits, which is not guessable by anyone, ever. The token is
/// the entire authentication for every request that carries it, so this is not
/// a place to economise.
const TOKEN_BYTES: usize = 32;

/// A registered local user.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "admin, deactivated, locked and suspended are independent flags"
)]
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
    /// Locked by an administrator (spec v1.18): every request answers
    /// `M_USER_LOCKED` with `soft_logout`, and the sessions survive the
    /// lock so that lifting it needs no re-login.
    #[serde(default)]
    pub locked: bool,
    /// Suspended by an administrator (spec v1.18): the account may read
    /// and log out, and nothing else; a write answers `M_USER_SUSPENDED`.
    #[serde(default)]
    pub suspended: bool,
    /// Erased (GDPR): the user asked for their data to be forgotten when
    /// the account was deactivated. Carried from Synapse's `erased_users`
    /// and set by a deactivation with `erase`. Spindle clears the profile
    /// on erasure; it does not yet hide an erased user's events from
    /// members who join later, which Synapse does (#576).
    #[serde(default)]
    pub erased: bool,
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

/// How long a `get_token` login token stays redeemable: the spec's two
/// minutes, enough to hand it to the other client and no more.
pub const LOGIN_TOKEN_TTL_MS: u64 = 2 * 60 * 1000;

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

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

        let salt = salt();
        let password_hash = ReusableArgon2
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map_err(|error| AccountError::Hashing(error.to_string()))?
            .to_string();

        let account = Account {
            localpart: localpart.to_owned(),
            password_hash,
            deactivated: false,
            admin: false,
            locked: false,
            suspended: false,
            erased: false,
        };
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(account)
    }

    /// Register a new account whose password hash the caller already holds.
    ///
    /// The Synapse importer creates over a thousand accounts that nobody
    /// signs in to with a password (the delegated identity provider owns
    /// sign-in). It hashes one unguessable password once and gives every
    /// such account that hash, rather than paying an Argon2 hash, and its
    /// 19 MiB working set, per account.
    ///
    /// # Errors
    ///
    /// Returns [`AccountError::UserInUse`] if the localpart is taken,
    /// [`AccountError::InvalidUsername`] for a bad localpart, or a storage
    /// error.
    pub fn register_hashed(
        &self,
        localpart: &str,
        password_hash: &str,
    ) -> Result<Account, AccountError> {
        validate_localpart(localpart)?;
        if self.account(localpart)?.is_some() {
            return Err(AccountError::UserInUse);
        }
        let account = Account {
            localpart: localpart.to_owned(),
            password_hash: password_hash.to_owned(),
            deactivated: false,
            admin: false,
            locked: false,
            suspended: false,
            erased: false,
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
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(());
        };
        account.deactivated = deactivated;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(())
    }

    /// Mark an account erased (or not), leaving everything else. An
    /// unknown localpart is a no-op.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn set_erased(&self, localpart: &str, erased: bool) -> Result<(), AccountError> {
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(());
        };
        account.erased = erased;
        let mut writes = vec![(account_key(localpart), encode(&account)?)];
        if erased {
            writes.push((erasure_policy_key(), vec![1]));
        }
        self.store
            .commit(&writes, spindle_store::Durability::Group)?;
        Ok(())
    }

    /// Whether client events may need erasure filtering. Once true, this
    /// marker stays true; each sender's current account flag still decides.
    ///
    /// # Errors
    ///
    /// Returns a storage or account decoding error.
    pub fn erasure_active(&self) -> Result<bool, AccountError> {
        let key = erasure_policy_key();
        if let Some(value) = self.store.get(&key)? {
            return Ok(value != [0]);
        }
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = self.store.get(&key)? {
            return Ok(value != [0]);
        }
        // Upgrade stores written before the marker existed. The same lock
        // protects erasure writes so initialization cannot overwrite one.
        let prefix = [keys::KEY_SCHEMA_VERSION, Keyspace::Account as u8];
        let mut active = false;
        for (_, bytes) in self.store.scan_prefix(&prefix)? {
            if decode::<Account>(&bytes)?.erased {
                active = true;
                break;
            }
        }
        self.store.put(&key, &[u8::from(active)])?;
        Ok(active)
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
        let matches = ReusableArgon2
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // A deactivated account keeps its hash (the row is the localpart
        // reservation) but no longer authenticates.
        Ok(matches && account.is_some_and(|account| !account.deactivated))
    }

    /// Mint a single-use login token for `localpart` (`POST
    /// /login/get_token`, spec v1.7), good for [`LOGIN_TOKEN_TTL_MS`].
    ///
    /// # Errors
    ///
    /// Returns [`AccountError`] if the row cannot be written.
    pub fn issue_login_token(&self, localpart: &str) -> Result<(String, u64), AccountError> {
        let token = format!("spt_{}", random_id(""));
        let expires_at = now_millis().saturating_add(LOGIN_TOKEN_TTL_MS);
        let row = serde_json::json!({ "localpart": localpart, "expires_at": expires_at });
        self.store
            .put(&keys::login_token(&token), row.to_string().as_bytes())?;
        Ok((token, LOGIN_TOKEN_TTL_MS))
    }

    /// Spend a login token: the localpart it logs in, once. A token that
    /// is unknown, already spent or lapsed is [`AccountError::UnknownToken`].
    ///
    /// # Errors
    ///
    /// Returns [`AccountError`] if the store cannot be read or written.
    pub fn redeem_login_token(&self, token: &str) -> Result<String, AccountError> {
        let key = keys::login_token(token);
        let Some(bytes) = self.store.get(&key)? else {
            return Err(AccountError::UnknownToken);
        };
        // Spent on sight, whether or not it is still good: a lapsed token
        // is not one to leave lying around.
        self.store.delete(&key)?;
        let row: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| AccountError::Codec(error.to_string()))?;
        let live = row["expires_at"]
            .as_u64()
            .is_some_and(|until| until > now_millis());
        match row["localpart"].as_str() {
            Some(localpart) if live => Ok(localpart.to_owned()),
            _ => Err(AccountError::UnknownToken),
        }
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
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        account.admin = admin;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(true)
    }

    /// Lock or unlock an account (spec v1.18). `false` for an account
    /// that does not exist.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn set_locked(&self, localpart: &str, locked: bool) -> Result<bool, AccountError> {
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        account.locked = locked;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(true)
    }

    /// Suspend or reinstate an account (spec v1.18). `false` for an
    /// account that does not exist.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn set_suspended(&self, localpart: &str, suspended: bool) -> Result<bool, AccountError> {
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        account.suspended = suspended;
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
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        let salt = salt();
        account.password_hash = ReusableArgon2
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map_err(|error| AccountError::Hashing(error.to_string()))?
            .to_string();
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        Ok(true)
    }

    /// Replace an account's password with a hash computed elsewhere
    /// (#611): the path a Matrix Authentication Service's users take
    /// into Spindle without anyone resetting a password. `false` for an
    /// account that does not exist.
    ///
    /// The hash is checked by [`validate_password_hash`] before anything
    /// is written, so a typo or a scheme this server cannot verify is a
    /// refusal now rather than a user who can never sign in later.
    ///
    /// # Errors
    ///
    /// [`AccountError::InvalidHash`] for a hash this server will not
    /// store, or a storage or decoding error.
    pub fn set_password_hash(
        &self,
        localpart: &str,
        password_hash: &str,
    ) -> Result<bool, AccountError> {
        validate_password_hash(password_hash)?;
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        password_hash.clone_into(&mut account.password_hash);
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

/// A fresh Argon2 salt, from the same source as every other secret here.
///
/// This used to be `SaltString::generate(&mut OsRng)`, over the `OsRng`
/// that `argon2` re-exports from its own `rand_core` 0.6. That name is
/// gated behind `password-hash/getrandom`, which nothing in this
/// workspace enables — it resolved only because `rand` 0.8 pulled the
/// same `rand_core` with `getrandom` on, and cargo unifies features
/// across the graph. Upgrading `rand` moved it to `rand_core` 0.10 and
/// the salt stopped compiling, having never actually depended on the
/// crate that appeared to provide it.
///
/// Reading the OS directly is what `generate` did anyway: 16 bytes —
/// [`Salt::RECOMMENDED_LENGTH`] — and the same b64 encoding. The
/// difference is that the entropy now comes from the one source this
/// module already uses for tokens, rather than from a second RNG that
/// happened to be reachable.
fn salt() -> [u8; Salt::RECOMMENDED_LENGTH] {
    let mut bytes = [0_u8; Salt::RECOMMENDED_LENGTH];
    crate::secrets::fill(&mut bytes);
    bytes
}

/// A password for an account nobody logs into with one: appservice
/// ghosts, MSC3861-provisioned users. 256 bits of entropy that are
/// hashed, stored, and never seen again — the account is entered through
/// its own door (the `as_token`, the provider's introspection), and a
/// guessable password would be a second door nobody watches.
#[must_use]
pub fn unguessable_password() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    crate::secrets::fill(&mut bytes);
    hex(&bytes)
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    crate::secrets::fill(&mut bytes);
    format!("{prefix}_{}", hex(&bytes))
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 8];
    crate::secrets::fill(&mut bytes);
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

/// The most memory, in KiB, a stored hash may ask each verification for:
/// 256 MiB. Verification keeps the largest workspace it has needed
/// (`passwords.rs`), so an imported hash with an absurd `m` would pin that
/// much memory for the life of the process; 13 times MAS's default (19 MiB)
/// is generous for any real deployment and refuses the absurd.
const MAX_HASH_MEMORY_KIB: u32 = 256 * 1024;

/// The most passes, and lanes, a stored hash may ask for. Each pass is
/// paid on every login; RFC 9106's recommendations sit far below this.
const MAX_HASH_TIME_COST: u32 = 16;
const MAX_HASH_LANES: u32 = 16;

/// Check a PHC password hash before it is stored (#611).
///
/// Accepted: Argon2 in any of its three variants (`argon2id`, `argon2i`,
/// `argon2d`), version 0x10 or 0x13, with exactly the `m`, `t` and `p`
/// parameters, a salt and a hash — which is what MAS, Synapse-adjacent
/// tooling and Spindle itself write. Refused, each for a reason:
///
/// - **Any other algorithm** (bcrypt, pbkdf2, scrypt…): verification here
///   is Argon2 only, and a stored hash nothing can check is an account
///   nobody can enter.
/// - **Keyed (`keyid=`) or associated-data (`data=`) hashes**: they were
///   computed with a secret pepper this server does not have, so they can
///   never verify. Note the converse: a hash computed with a pepper that
///   is *not* recorded in the string (MAS's `secret` scheme option) looks
///   ordinary and is accepted, and then never verifies. Nothing in the
///   string can reveal that; the operator has to know.
/// - **Costs beyond the bounds above**: a denial of service waiting for
///   the first login.
///
/// # Errors
///
/// [`AccountError::InvalidHash`] naming what was wrong. The message never
/// echoes the hash.
pub fn validate_password_hash(phc: &str) -> Result<(), AccountError> {
    let invalid = |why: &str| Err(AccountError::InvalidHash(why.to_owned()));
    let mut parts = phc.split('$');
    if parts.next() != Some("") {
        return invalid("not a PHC string: it must start with '$'");
    }
    let algorithm = parts.next().unwrap_or_default();
    if !matches!(algorithm, "argon2id" | "argon2i" | "argon2d") {
        return Err(AccountError::InvalidHash(format!(
            "unsupported algorithm {algorithm:?}: only argon2id, argon2i and argon2d \
             hashes can be verified here"
        )));
    }
    let mut next = parts.next().unwrap_or_default();
    if let Some(version) = next.strip_prefix("v=") {
        if !matches!(version, "16" | "19") {
            return invalid("unsupported Argon2 version: only v=16 and v=19 exist");
        }
        next = parts.next().unwrap_or_default();
    }
    let (mut memory, mut time, mut lanes) = (None, None, None);
    for pair in next.split(',') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let slot = match name {
            "m" => &mut memory,
            "t" => &mut time,
            "p" => &mut lanes,
            "keyid" | "data" => {
                return invalid(
                    "keyed or peppered Argon2 hashes (keyid/data) cannot be verified \
                     without the secret they were made with",
                );
            }
            _ => return invalid("unknown Argon2 parameter: only m, t and p are accepted"),
        };
        if slot.is_some() {
            return invalid("an Argon2 parameter is repeated");
        }
        let Ok(number) = value.parse::<u32>() else {
            return invalid("Argon2 parameters must be decimal numbers");
        };
        *slot = Some(number);
    }
    let (Some(memory), Some(time), Some(lanes)) = (memory, time, lanes) else {
        return invalid("an Argon2 hash needs all of m, t and p");
    };
    if memory > MAX_HASH_MEMORY_KIB || time > MAX_HASH_TIME_COST || lanes > MAX_HASH_LANES {
        return Err(AccountError::InvalidHash(format!(
            "Argon2 costs out of bounds: m <= {MAX_HASH_MEMORY_KIB}, \
             t <= {MAX_HASH_TIME_COST}, p <= {MAX_HASH_LANES}"
        )));
    }
    if argon2::Params::new(memory, time, lanes, None).is_err() {
        return invalid(
            "Argon2 parameters out of range (m must be at least 8 * p, t and p at least 1)",
        );
    }
    let (Some(salt), Some(hash), None) = (parts.next(), parts.next(), parts.next()) else {
        return invalid("a PHC string ends with exactly a salt and a hash");
    };
    let b64 = |text: &str| {
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    };
    // Unpadded base64: four characters carry three bytes.
    let decoded_len = |text: &str| text.len() * 3 / 4;
    if !b64(salt) || decoded_len(salt) < 8 {
        return invalid("the salt must be at least 8 bytes of unpadded base64");
    }
    if !b64(hash) || !(16..=64).contains(&decoded_len(hash)) {
        return invalid("the hash must be 16 to 64 bytes of unpadded base64");
    }
    PasswordHash::new(phc)
        .map(|_| ())
        .map_err(|_| AccountError::InvalidHash("not a well-formed PHC string".to_owned()))
}

/// Why an account operation failed.
#[derive(Debug)]
pub enum AccountError {
    UserInUse,
    /// A pre-computed password hash this server will not store; the
    /// message says why without repeating the hash.
    InvalidHash(String),
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
            Self::InvalidHash(why) => write!(formatter, "unusable password hash: {why}"),
            Self::UnknownToken => write!(formatter, "that token is not valid"),
            Self::InvalidUsername => write!(formatter, "that username is not valid"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Codec(message) => write!(formatter, "unreadable record: {message}"),
            Self::Hashing(message) => write!(formatter, "password hashing: {message}"),
        }
    }
}

impl std::error::Error for AccountError {}

/// The Argon2id hash [`Accounts::register`] would store for `password`.
///
/// # Errors
///
/// Returns [`AccountError::Hashing`] if hashing fails.
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    let salt = salt();
    Ok(ReusableArgon2
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|error| AccountError::Hashing(error.to_string()))?
        .to_string())
}

#[cfg(test)]
mod erasure_policy_tests {
    use super::*;
    use spindle_store::{FjallStore, ReadView};

    fn put_account(store: &FjallStore, localpart: &str, erased: bool) {
        let account: Account = serde_json::from_value(serde_json::json!({
            "localpart":localpart,"password_hash":"unused","erased":erased
        }))
        .unwrap();
        store
            .put(&account_key(localpart), &encode(&account).unwrap())
            .unwrap();
    }

    #[test]
    fn an_upgraded_store_discovers_existing_erased_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        put_account(&store, "alice", false);
        put_account(&store, "bob", true);
        let accounts = Accounts::new(&store, "example.org");
        assert!(accounts.erasure_active().unwrap());
        assert_eq!(store.get(&erasure_policy_key()).unwrap(), Some(vec![1]));
    }

    #[test]
    fn erasure_sets_a_durable_marker_without_clearing_it_on_restore() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = FjallStore::open(dir.path()).unwrap();
            put_account(&store, "alice", false);
            let accounts = Accounts::new(&store, "example.org");
            assert!(!accounts.erasure_active().unwrap());
            accounts.set_erased("alice", true).unwrap();
            assert!(accounts.erasure_active().unwrap());
            assert!(accounts.account("alice").unwrap().unwrap().erased);
            accounts.set_erased("alice", false).unwrap();
            assert!(accounts.erasure_active().unwrap());
            assert!(!accounts.account("alice").unwrap().unwrap().erased);
        }
        let store = FjallStore::open(dir.path()).unwrap();
        assert!(
            Accounts::new(&store, "example.org")
                .erasure_active()
                .unwrap()
        );
    }

    #[test]
    fn setting_an_unknown_account_does_not_activate_erasure() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.set_erased("missing", true).unwrap();
        assert!(!accounts.erasure_active().unwrap());
    }
}

#[cfg(test)]
mod password_hash_tests {
    use super::*;
    use spindle_store::FjallStore;

    /// A hash exactly as MAS writes it: argon2id with the `argon2` crate's
    /// defaults (m=19456, t=2, p=1, 16-byte salt, 32-byte output), here
    /// produced by an independent implementation (argon2-cffi) so the test
    /// is not this crate agreeing with itself.
    const MAS_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$bWFzLW1pZ3JhdGlvbi0xNg$\
        CEd7EMaeQK2QDHVNURFc/tH0y2Ja5MduCcmz5Gs8uIo";
    const MAS_PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn a_mas_hash_imports_and_verifies_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("alice", "the old password").unwrap();
        assert!(accounts.set_password_hash("alice", MAS_HASH).unwrap());
        assert!(accounts.verify_password("alice", MAS_PASSWORD).unwrap());
        assert!(
            !accounts
                .verify_password("alice", "the old password")
                .unwrap()
        );
        assert!(!accounts.verify_password("alice", "wrong").unwrap());
        // An unknown account is reported, not created.
        assert!(!accounts.set_password_hash("nobody", MAS_HASH).unwrap());
        assert!(accounts.account("nobody").unwrap().is_none());
    }

    #[test]
    fn every_argon2_variant_and_version_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("bob", "unused").unwrap();
        for hash in [
            "$argon2i$v=19$m=1024,t=1,p=1$YW5vdGhlci1zYWx0LXh5eg$0+BS7rvFj8+YQIHROOQAxEN4+A++MGK2rhIClVQuGcc",
            "$argon2d$v=19$m=1024,t=1,p=1$YW5vdGhlci1zYWx0LXh5eg$J+uc29iUySN8eBqcEre+bXDQeCIJv0JzmiJvPS/rZQY",
            "$argon2id$v=16$m=1024,t=1,p=1$YW5vdGhlci1zYWx0LXh5eg$GGrtU/NvDOgxP3krYVaBmBJb0RH3jhw91wzzc4skbwE",
        ] {
            assert!(accounts.set_password_hash("bob", hash).unwrap(), "{hash}");
            assert!(
                accounts.verify_password("bob", "hunter2hunter2").unwrap(),
                "{hash}"
            );
        }
    }

    #[test]
    fn unusable_hashes_are_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("carol", "her password").unwrap();
        let salt = "bWFzLW1pZ3JhdGlvbi0xNg";
        let out = "CEd7EMaeQK2QDHVNURFc/tH0y2Ja5MduCcmz5Gs8uIo";
        for hash in [
            String::new(),
            "plaintext".to_owned(),
            "$2b$12$abcdefghijklmnopqrstuuJ7nGq1k7h8yQ0e1lQ9n6S1d1x8Zb2K".to_owned(),
            format!("$pbkdf2-sha256$i=1000${salt}${out}"),
            format!("$scrypt$ln=16,r=8,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=19456,t=2,p=1,keyid=abc${salt}${out}"),
            format!("$argon2id$v=19$m=19456,t=2,p=1,data=abc${salt}${out}"),
            format!("$argon2id$v=18$m=19456,t=2,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=4194304,t=2,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=19456,t=100,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=19456,t=2${salt}${out}"),
            format!("$argon2id$v=19$m=19456,m=1,t=2,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=4,t=2,p=1${salt}${out}"),
            format!("$argon2id$v=19$m=19456,t=2,p=1$${out}"),
            format!("$argon2id$v=19$m=19456,t=2,p=1${salt}$"),
            format!("$argon2id$v=19$m=19456,t=2,p=1${salt}${out}$extra"),
            format!("$argon2id$v=19$m=19456,t=2,p=1${salt}$!!notbase64!!"),
        ] {
            let error = accounts.set_password_hash("carol", &hash).unwrap_err();
            assert!(matches!(error, AccountError::InvalidHash(_)), "{hash}");
            assert!(
                hash.is_empty() || !error.to_string().contains(&hash),
                "the refusal must not echo the hash"
            );
        }
        assert!(accounts.verify_password("carol", "her password").unwrap());
    }
}
