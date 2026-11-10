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

use crate::passwords;
use argon2::password_hash::phc::{PasswordHash, Salt};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use spindle_core::keys::{self, Keyspace, room_prefix};
use spindle_store::{Store, StoreError};

static ERASURE_POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn erasure_policy_key() -> Vec<u8> {
    room_prefix(Keyspace::ErasurePolicy, "")
}

/// The generation an erasure marker holds; 0 means no account was ever
/// erased. Stores written before generations existed hold one byte, `[0]`
/// or `[1]`, which read as generations 0 and 1.
fn erasure_generation_of(value: &[u8]) -> u64 {
    <[u8; 8]>::try_from(value).map_or_else(
        |_| value.first().copied().map_or(0, u64::from),
        u64::from_be_bytes,
    )
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
    /// Argon2 PHC string, salt included; or, imported from MAS or Synapse,
    /// a bcrypt hash (#797).
    pub password_hash: String,
    /// How `password_hash` is checked when MAS's scheme did more than hash
    /// the password as typed (#797). `None` for every hash made here, and
    /// cleared whenever the password changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_scheme: Option<PasswordScheme>,
    /// BLAKE3 of the last hash `import-mas` stored (#797). A password
    /// change leaves it on purpose: a rerun compares it with the current
    /// hash, which tells a password the user changed here (kept) from one
    /// still as imported (brought up to date).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_hash_digest: Option<String>,
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
    /// on erasure, and serves the user's events pruned to readers who were
    /// not joined when they were sent, as Synapse does (#576).
    #[serde(default)]
    pub erased: bool,
    /// Created by a service's own flow (appservice sender, server notices)
    /// with a password nobody holds. Only such an account may be adopted
    /// by the service later: a user who registered the name first holds a
    /// password and would otherwise keep a login to the service's identity.
    /// Cleared when a password is set, since someone then holds one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub service_owned: bool,
}

/// What a MAS password scheme adds to the plain hash (#797). MAS keeps it
/// in its configuration, not with the hash, so the importer copies it here:
/// without it the hash can never verify.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PasswordScheme {
    /// The scheme's `secret` (pepper), hex-encoded. bcrypt appends it to the
    /// password; Argon2 takes it as its secret input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pepper: Option<String>,
    /// NFKC-normalize the password before hashing it (MAS's
    /// `unicode_normalization`, which syn2mas sets for Synapse's hashes).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nfkc: bool,
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
    /// When an access token of a refreshing session was minted, in Unix
    /// milliseconds. Absent on rows written before expiry existed and on
    /// sessions without a refresh token: both never expire, because expiring
    /// a token its client cannot renew only logs the client out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_ms: Option<u64>,
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
pub const ACCESS_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

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

    /// Make the writes of this call survive a power loss (#810).
    ///
    /// `Store::put` and `Store::delete` reach the journal and no further, so
    /// without this a registration, a login or a logout becomes durable only
    /// when some unrelated room commit next syncs the journal: a logged-out
    /// token could work again after a crash, and a client could hold a token
    /// for an account that no longer exists. It is the grouped barrier the
    /// room log uses, so concurrent callers share one sync.
    fn durable(&self) -> Result<(), AccountError> {
        self.store.sync(spindle_store::Durability::Group)?;
        Ok(())
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
        self.register_with(localpart, password, false)
    }

    /// Register an account for a service's own identity (an appservice's
    /// sender or user, the server-notices account) with a password nobody
    /// holds, marked [`Account::service_owned`] so the service may later
    /// adopt it and nobody else's account.
    ///
    /// # Errors
    ///
    /// As [`Self::register`].
    pub fn register_service(&self, localpart: &str) -> Result<Account, AccountError> {
        self.register_with(localpart, &unguessable_password(), true)
    }

    fn register_with(
        &self,
        localpart: &str,
        password: &str,
        service_owned: bool,
    ) -> Result<Account, AccountError> {
        validate_localpart(localpart)?;
        if self.account(localpart)?.is_some() {
            return Err(AccountError::UserInUse);
        }

        let password_hash = hash_password(password)?;

        let account = Account {
            localpart: localpart.to_owned(),
            password_hash,
            password_scheme: None,
            imported_hash_digest: None,
            deactivated: false,
            admin: false,
            locked: false,
            suspended: false,
            erased: false,
            service_owned,
        };
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        self.durable()?;
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
            password_scheme: None,
            imported_hash_digest: None,
            deactivated: false,
            admin: false,
            locked: false,
            suspended: false,
            erased: false,
            service_owned: false,
        };
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        self.durable()?;
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
        self.durable()?;
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
        // Every change moves the generation, un-erasing included: readers
        // cache the erased set per generation, so a change that left it
        // alone would leave them serving a stale set. Nothing ever erased
        // and nothing erased now keeps the marker unwritten, which is what
        // lets an untouched server skip the policy entirely.
        let current = self
            .store
            .get(&erasure_policy_key())?
            .map_or(0, |value| erasure_generation_of(&value));
        if erased || current != 0 {
            writes.push((
                erasure_policy_key(),
                current.saturating_add(1).to_be_bytes().to_vec(),
            ));
        }
        self.store
            .commit(&writes, spindle_store::Durability::Group)?;
        Ok(())
    }

    /// Whether client events may need erasure filtering. Once true, this
    /// stays true; each sender's current account flag still decides.
    ///
    /// # Errors
    ///
    /// Returns a storage or account decoding error.
    pub fn erasure_active(&self) -> Result<bool, AccountError> {
        Ok(self.erasure_generation()? != 0)
    }

    /// How many times an erasure flag has changed, or 0 when no account has
    /// ever been erased. Two equal readings bracket no change to the set
    /// [`Self::erased_user_ids`] returns.
    ///
    /// # Errors
    ///
    /// Returns a storage or account decoding error.
    pub fn erasure_generation(&self) -> Result<u64, AccountError> {
        let key = erasure_policy_key();
        if let Some(value) = self.store.get(&key)? {
            return Ok(erasure_generation_of(&value));
        }
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = self.store.get(&key)? {
            return Ok(erasure_generation_of(&value));
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
        // The marker caches the scan. When the store has stopped taking
        // writes the put fails, and failing the read because a cache fill
        // failed would take reads down with writes (#21's disk-full
        // drill). Serve the computed answer and leave the marker
        // unwritten; the next read scans again.
        let generation = u64::from(active);
        match self.store.put(&key, &[u8::from(active)]) {
            Ok(()) => Ok(generation),
            Err(_) if !self.store.accepts_writes() => Ok(generation),
            Err(error) => Err(error.into()),
        }
    }

    /// The full user IDs of every erased local account.
    ///
    /// A scan of every account: read it once per
    /// [`Self::erasure_generation`], not per question.
    ///
    /// # Errors
    ///
    /// Returns a storage or account decoding error.
    pub fn erased_user_ids(&self) -> Result<std::collections::HashSet<String>, AccountError> {
        let prefix = [keys::KEY_SCHEMA_VERSION, Keyspace::Account as u8];
        let mut erased = std::collections::HashSet::new();
        for (_, bytes) in self.store.scan_prefix(&prefix)? {
            let account = decode::<Account>(&bytes)?;
            if account.erased {
                erased.insert(format!("@{}:{}", account.localpart, self.server_name));
            }
        }
        Ok(erased)
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
    /// Returns a storage or decoding error, or [`AccountError::Busy`] if
    /// every password-hashing workspace is in use and the queue for them is
    /// full. Busy is not `false`: the password was never checked.
    pub fn verify_password(&self, localpart: &str, password: &str) -> Result<bool, AccountError> {
        let account = self.account(localpart)?;
        let (hash, scheme) = account.as_ref().map_or((DUMMY_HASH, None), |a| {
            (a.password_hash.as_str(), a.password_scheme.as_ref())
        });
        let matches = verify_hash(hash, scheme, password)?;
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
        self.durable()?;
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
        // A login token is one-use: a spend that a crash undoes is a second use.
        self.durable()?;
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
            issued_at_ms: with_refresh.then(now_millis),
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
        self.durable()?;

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
        // The access tokens the device held go with it. Left alone, every
        // refresh would add one more token that stays good, and the expiry
        // would bound only the newest.
        self.delete_access_tokens(&record.localpart, &record.device_id)?;

        let record = TokenRecord {
            issued_at_ms: Some(now_millis()),
            ..record
        };
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
        self.durable()?;

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
        self.identify_at(token, now_millis())
    }

    /// [`Self::identify`] as of `now_ms` (Unix milliseconds), so a test can
    /// move the clock instead of sleeping through the token lifetime.
    ///
    /// An expired token answers `None`, as an unknown one does.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn identify_at(&self, token: &str, now_ms: u64) -> Result<Option<Identity>, AccountError> {
        match self.store.get(&token_key(Keyspace::AccessToken, token))? {
            Some(raw) => {
                let record: TokenRecord = decode(&raw)?;
                if record_expired(&record, now_ms) {
                    return Ok(None);
                }
                Ok(Some(Identity {
                    user_id: self.user_id(&record.localpart),
                    device_id: record.device_id,
                }))
            }
            None => Ok(None),
        }
    }

    /// Is `token` a stored access token whose lifetime has run out? The
    /// client is told so (`soft_logout`) and refreshes, rather than treating
    /// it as a credential that never existed.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn is_expired(&self, token: &str) -> Result<bool, AccountError> {
        match self.store.get(&token_key(Keyspace::AccessToken, token))? {
            Some(raw) => Ok(record_expired(&decode(&raw)?, now_millis())),
            None => Ok(false),
        }
    }

    /// The session a stored access or refresh token belongs to, whether or
    /// not the access token has expired: ending a session must work with
    /// either half of the pair.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn session_of(&self, token: &str) -> Result<Option<TokenRecord>, AccountError> {
        for keyspace in [Keyspace::AccessToken, Keyspace::RefreshToken] {
            if let Some(raw) = self.store.get(&token_key(keyspace, token))? {
                return Ok(Some(decode(&raw)?));
            }
        }
        Ok(None)
    }

    /// End the session an access or refresh token belongs to: its device and
    /// every token of it, the refresh token included. Deleting only the
    /// presented access token would leave the refresh token able to mint a
    /// new pair after the user signed out. An unknown token is a no-op.
    ///
    /// Returns the session that ended, if there was one.
    ///
    /// # Errors
    ///
    /// Returns a storage or decoding error.
    pub fn logout(&self, token: &str) -> Result<Option<TokenRecord>, AccountError> {
        let Some(record) = self.session_of(token)? else {
            return Ok(None);
        };
        self.delete_device(&record.localpart, &record.device_id)?;
        Ok(Some(record))
    }

    /// Delete the access tokens of one device, leaving its refresh token.
    fn delete_access_tokens(&self, localpart: &str, device_id: &str) -> Result<(), AccountError> {
        let prefix = [
            spindle_core::keys::KEY_SCHEMA_VERSION,
            Keyspace::AccessToken as u8,
        ];
        for (key, raw) in self.store.scan_prefix(&prefix)? {
            let record: TokenRecord = decode(&raw)?;
            if record.localpart == localpart && record.device_id == device_id {
                self.store.delete(&key)?;
            }
        }
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
    /// Writing the row lifts any [`Self::revoke_device`] marker: whoever
    /// writes it -- under delegation, the provider through
    /// `/_synapse/mas/upsert_device` -- has said the device lives again.
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
        self.store
            .delete(&revoked_device_key(localpart, device_id))?;
        self.durable()?;
        Ok(())
    }

    /// Mark a delegated user's device as ended by this server (#615), so a
    /// provider that was not told -- and so still vouches for the session --
    /// cannot have introspection provision the device again. Written
    /// *before* the row is deleted: an introspection that runs between the
    /// two then finds either the row or the marker, never neither.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn revoke_device(&self, localpart: &str, device_id: &str) -> Result<(), AccountError> {
        self.store
            .put(&revoked_device_key(localpart, device_id), &[])?;
        self.durable()?;
        Ok(())
    }

    /// Whether [`Self::revoke_device`] marked this device and nothing has
    /// written its row since.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub fn device_revoked(&self, localpart: &str, device_id: &str) -> Result<bool, AccountError> {
        Ok(self
            .store
            .get(&revoked_device_key(localpart, device_id))?
            .is_some())
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
        self.durable()?;
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
        self.durable()?;
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
        self.durable()?;
        Ok(true)
    }

    /// Replace an account's password.
    ///
    /// # Errors
    ///
    /// Returns a storage, decoding, or hashing error.
    pub fn set_password(&self, localpart: &str, password: &str) -> Result<bool, AccountError> {
        // Hashed before the erasure lock is taken: the hash may wait for a
        // workspace (#571), and every account update waits on that lock.
        let password_hash = hash_password(password)?;
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        account.password_hash = password_hash;
        account.password_scheme = None;
        account.service_owned = false;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        self.durable()?;
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
        account.password_scheme = None;
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        self.durable()?;
        Ok(true)
    }

    /// Store a password hash read from MAS, with the scheme it needs
    /// (#797), and remember which hash that was in
    /// [`Account::imported_hash_digest`]. `false` for an account that does
    /// not exist.
    ///
    /// # Errors
    ///
    /// [`AccountError::InvalidHash`] for a hash or pepper this server will
    /// not store, or a storage or decoding error.
    pub fn import_password_hash(
        &self,
        localpart: &str,
        password_hash: &str,
        scheme: Option<PasswordScheme>,
    ) -> Result<bool, AccountError> {
        validate_password_hash(password_hash)?;
        if let Some(pepper) = scheme.as_ref().and_then(|scheme| scheme.pepper.as_deref())
            && unhex(pepper).is_none()
        {
            return Err(AccountError::InvalidHash(
                "the pepper must be hex-encoded".to_owned(),
            ));
        }
        // All account updates share the erasure lock so a concurrent
        // flag/password write cannot restore an older erasure decision.
        let _guard = ERASURE_POLICY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut account) = self.account(localpart)? else {
            return Ok(false);
        };
        password_hash.clone_into(&mut account.password_hash);
        // A scheme that adds nothing is stored as none, so the account
        // reads the same as one whose hash was made here.
        account.password_scheme = scheme.filter(|scheme| *scheme != PasswordScheme::default());
        account.imported_hash_digest = Some(hash_digest(password_hash));
        self.store
            .put(&account_key(localpart), &encode(&account)?)?;
        self.durable()?;
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
        self.durable()?;
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
        self.durable()?;
        Ok(())
    }
}

/// An Argon2id hash of nothing in particular, verified against when the user
/// does not exist so that a missing account costs the same as a wrong password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3BpbmRsZWR1bW15c2FsdA$\
    Zx8kM1kDBFqPuHRZ0M0MVXOaEfKMTL9dTgKtOJXHIWQ";

/// Whether an access token minted at `record.issued_at_ms` is past its
/// lifetime at `now_ms`. A record without a timestamp never expires.
fn record_expired(record: &TokenRecord, now_ms: u64) -> bool {
    record
        .issued_at_ms
        .is_some_and(|issued| now_ms.saturating_sub(issued) >= ACCESS_TOKEN_LIFETIME_MS)
}

fn account_key(localpart: &str) -> Vec<u8> {
    room_prefix(Keyspace::Account, localpart)
}

fn device_key(localpart: &str, device_id: &str) -> Vec<u8> {
    let mut key = room_prefix(Keyspace::Device, localpart);
    key.extend_from_slice(device_id.as_bytes());
    key
}

fn revoked_device_key(localpart: &str, device_id: &str) -> Vec<u8> {
    let mut key = room_prefix(Keyspace::RevokedDevice, localpart);
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

/// The highest bcrypt cost a stored hash may ask for: four times the work
/// of the cost of 12 that MAS and Synapse use by default. bcrypt doubles
/// its work with each step, and each login pays it.
const MAX_BCRYPT_COST: u32 = 14;

/// BLAKE3 of a stored hash, hex: how [`Account::imported_hash_digest`]
/// remembers a hash without a second copy of it.
#[must_use]
pub fn hash_digest(password_hash: &str) -> String {
    blake3::hash(password_hash.as_bytes()).to_hex().to_string()
}

fn is_bcrypt(hash: &str) -> bool {
    ["$2a$", "$2b$", "$2y$"]
        .iter()
        .any(|prefix| hash.starts_with(prefix))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Check `password` against a stored hash and the scheme it was made
/// under. Both algorithms run in a workspace of the hashing pool, so a
/// bcrypt check waits in, and is refused by, the same queue as an Argon2
/// one (#571).
fn verify_hash(
    hash: &str,
    scheme: Option<&PasswordScheme>,
    password: &str,
) -> Result<bool, AccountError> {
    use unicode_normalization::UnicodeNormalization as _;
    let normalized: String;
    let password = if scheme.is_some_and(|scheme| scheme.nfkc) {
        normalized = password.nfkc().collect();
        normalized.as_str()
    } else {
        password
    };
    let pepper = match scheme.and_then(|scheme| scheme.pepper.as_deref()) {
        Some(text) => Some(
            unhex(text)
                .ok_or_else(|| AccountError::Hashing("the stored pepper is not hex".to_owned()))?,
        ),
        None => None,
    };
    if is_bcrypt(hash) {
        // MAS's bcrypt scheme, like Synapse's, appends the pepper. A bcrypt
        // check takes longer than the Argon2 dummy an unknown user costs, so
        // the time tells such an account exists: no more than
        // `/register/available` answers anyone.
        let mut input = password.as_bytes().to_vec();
        input.extend_from_slice(pepper.as_deref().unwrap_or_default());
        return Ok(passwords::with_workspace(|_| {
            bcrypt::verify(&input, hash).unwrap_or(false)
        })?);
    }
    let parsed = PasswordHash::new(hash).map_err(|e| AccountError::Hashing(e.to_string()))?;
    Ok(passwords::with_keyed_workspace(
        pepper.as_deref(),
        |argon| argon.verify_password(password.as_bytes(), &parsed).is_ok(),
    )?)
}

/// Check a password hash before it is stored (#611, #797).
///
/// Accepted: Argon2 in PHC form, in any of its three variants (`argon2id`,
/// `argon2i`, `argon2d`), version 0x10 or 0x13, with exactly the `m`, `t`
/// and `p` parameters, a salt and a hash — which is what MAS,
/// Synapse-adjacent tooling and Spindle itself write; and bcrypt (`$2a$`,
/// `$2b$`, `$2y$`), which Synapse writes and MAS keeps for users that
/// syn2mas moved. Refused, each for a reason:
///
/// - **Any other algorithm** (pbkdf2, scrypt…): nothing here can check
///   it, and a stored hash nothing can check is an account nobody can
///   enter.
/// - **Keyed (`keyid=`) or associated-data (`data=`) hashes**: they were
///   computed with a secret pepper this server does not have, so they can
///   never verify. Note the converse: a hash computed with a pepper that
///   is *not* recorded in the string (MAS's `secret` scheme option) looks
///   ordinary and is accepted, and then verifies only with the pepper that
///   `import-mas` stores beside it. Nothing in the string can reveal that.
/// - **Costs beyond the bounds above**: a denial of service waiting for
///   the first login.
///
/// # Errors
///
/// [`AccountError::InvalidHash`] naming what was wrong. The message never
/// echoes the hash.
pub fn validate_password_hash(phc: &str) -> Result<(), AccountError> {
    let invalid = |why: &str| Err(AccountError::InvalidHash(why.to_owned()));
    if is_bcrypt(phc) {
        return validate_bcrypt(phc);
    }
    let mut parts = phc.split('$');
    if parts.next() != Some("") {
        return invalid("not a PHC string: it must start with '$'");
    }
    let algorithm = parts.next().unwrap_or_default();
    if !matches!(algorithm, "argon2id" | "argon2i" | "argon2d") {
        return Err(AccountError::InvalidHash(format!(
            "unsupported algorithm {algorithm:?}: only argon2id, argon2i, argon2d \
             and bcrypt hashes can be verified here"
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

/// The shape of a bcrypt hash: `$2b$`, a two-digit cost, `$`, then 22
/// characters of salt and 31 of hash in bcrypt's base64 alphabet.
fn validate_bcrypt(hash: &str) -> Result<(), AccountError> {
    let invalid = |why: &str| Err(AccountError::InvalidHash(why.to_owned()));
    let (Some(cost), Some(body)) = (hash.get(4..6), hash.get(6..)) else {
        return invalid("a bcrypt hash needs a two-digit cost");
    };
    let Some(cost) = cost
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| cost.parse::<u32>().ok())
        .flatten()
    else {
        return invalid("a bcrypt hash needs a two-digit cost");
    };
    if !(4..=MAX_BCRYPT_COST).contains(&cost) {
        return Err(AccountError::InvalidHash(format!(
            "bcrypt cost out of bounds: 4 <= cost <= {MAX_BCRYPT_COST}"
        )));
    }
    let Some(rest) = body.strip_prefix('$') else {
        return invalid("a bcrypt hash has '$' after its cost");
    };
    if rest.len() != 53
        || !rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'/')
    {
        return invalid("a bcrypt hash ends with 53 characters of salt and hash");
    }
    Ok(())
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
    /// Every password-hashing workspace is in use and the queue for them
    /// is full (#571). Answered 429 `M_LIMIT_EXCEEDED`.
    Busy,
}

impl From<passwords::Busy> for AccountError {
    fn from(_: passwords::Busy) -> Self {
        Self::Busy
    }
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
            Self::Busy => write!(formatter, "too many passwords being checked; try again"),
        }
    }
}

impl std::error::Error for AccountError {}

/// The Argon2id hash [`Accounts::register`] would store for `password`.
///
/// # Errors
///
/// Returns [`AccountError::Hashing`] if hashing fails, or
/// [`AccountError::Busy`] if every workspace is in use and the queue for
/// them is full.
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    let salt = salt();
    passwords::with_workspace(|argon| {
        argon
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })?
    .map_err(|error| AccountError::Hashing(error.to_string()))
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

    /// Readers cache the erased set per generation, so every flag change
    /// must move it -- un-erasing too, or a cache would keep pruning an
    /// account that is no longer erased.
    #[test]
    fn every_erasure_change_moves_the_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        put_account(&store, "alice", false);
        put_account(&store, "bob", false);
        let accounts = Accounts::new(&store, "example.org");
        assert_eq!(accounts.erasure_generation().unwrap(), 0);
        // Un-erasing on a server that never erased writes nothing.
        accounts.set_erased("alice", false).unwrap();
        assert_eq!(accounts.erasure_generation().unwrap(), 0);
        accounts.set_erased("alice", true).unwrap();
        let erased = accounts.erasure_generation().unwrap();
        assert_ne!(erased, 0);
        assert_eq!(
            accounts.erased_user_ids().unwrap(),
            std::collections::HashSet::from(["@alice:example.org".to_owned()])
        );
        accounts.set_erased("alice", false).unwrap();
        let restored = accounts.erasure_generation().unwrap();
        assert!(restored > erased);
        assert!(accounts.erased_user_ids().unwrap().is_empty());
        // A store from before generations holds `[1]`; the next change
        // moves on from it.
        store.put(&erasure_policy_key(), &[1]).unwrap();
        accounts.set_erased("bob", true).unwrap();
        assert_eq!(accounts.erasure_generation().unwrap(), 2);
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
            "$2b$12$tooshort".to_owned(),
            "$2b$31$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLca".to_owned(),
            "$2b$1x$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLca".to_owned(),
            "$2b$10$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLc!".to_owned(),
            "$2x$10$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLca".to_owned(),
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

    // MAS's own outputs (#797): the insta snapshots of MAS 1.23.0's
    // `passwords.rs` tests, which hash "hunter2" with and without the pepper
    // "a-secret-pepper". MAS made them, so a pass here is this server
    // agreeing with MAS rather than with itself.
    const MAS_BCRYPT_PEPPERED: &str =
        "$2b$10$c/EX8bTbEMfTn4oCvcQyBOR1zPyLmGzZ2pMXoElLASqv2qpq5X15i";
    const MAS_BCRYPT: &str = "$2b$10$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLca";
    const MAS_ARGON2_PEPPERED: &str = "$argon2id$v=19$m=19456,t=2,p=1$eEi11xG8mIOZYxej+ckCaQ$\
        eBeygPqiuImQAaFQOkE6oVkPfqxIGgnqpQd/MwW4YX4";
    const MAS_ARGON2: &str = "$argon2id$v=19$m=19456,t=2,p=1$1WdxAF1UChkYSTnJ6NDbKg$\
        ajKAfwlUmkbxITSdh55j+Hvoxzppx20ArNUF44oV9Nk";

    fn pepper() -> PasswordScheme {
        PasswordScheme {
            pepper: Some(hex(b"a-secret-pepper")),
            nfkc: false,
        }
    }

    #[test]
    fn mas_bcrypt_and_peppered_hashes_verify_with_their_scheme_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("dave", "unused").unwrap();
        for (hash, scheme) in [
            (MAS_BCRYPT, None),
            (MAS_BCRYPT_PEPPERED, Some(pepper())),
            (MAS_ARGON2, None),
            (MAS_ARGON2_PEPPERED, Some(pepper())),
        ] {
            let peppered = scheme.is_some();
            assert!(accounts.import_password_hash("dave", hash, scheme).unwrap());
            assert!(
                accounts.verify_password("dave", "hunter2").unwrap(),
                "{hash}"
            );
            assert!(!accounts.verify_password("dave", "wrong-password").unwrap());
            // The same hash without its pepper never verifies: the scheme is
            // what carries it.
            accounts.set_password_hash("dave", hash).unwrap();
            assert_eq!(
                accounts.verify_password("dave", "hunter2").unwrap(),
                !peppered,
                "{hash}"
            );
        }
    }

    #[test]
    fn a_normalizing_scheme_folds_the_password_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("erin", "unused").unwrap();
        let fullwidth = "\u{ff48}\u{ff55}\u{ff4e}\u{ff54}\u{ff45}\u{ff52}\u{ff12}";
        accounts
            .import_password_hash("erin", MAS_BCRYPT, None)
            .unwrap();
        assert!(!accounts.verify_password("erin", fullwidth).unwrap());
        let nfkc = Some(PasswordScheme {
            pepper: None,
            nfkc: true,
        });
        accounts
            .import_password_hash("erin", MAS_BCRYPT, nfkc)
            .unwrap();
        assert!(accounts.verify_password("erin", fullwidth).unwrap());
        assert!(accounts.verify_password("erin", "hunter2").unwrap());
    }

    #[test]
    fn a_password_change_drops_the_scheme_and_keeps_the_import_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        accounts.register("fay", "unused").unwrap();
        accounts
            .import_password_hash("fay", MAS_ARGON2_PEPPERED, Some(pepper()))
            .unwrap();
        let imported = accounts.account("fay").unwrap().unwrap();
        assert_eq!(imported.password_scheme, Some(pepper()));
        assert_eq!(
            imported.imported_hash_digest.as_deref(),
            Some(hash_digest(MAS_ARGON2_PEPPERED).as_str())
        );
        accounts.set_password("fay", "a new one").unwrap();
        let changed = accounts.account("fay").unwrap().unwrap();
        assert_eq!(changed.password_scheme, None);
        assert_eq!(changed.imported_hash_digest, imported.imported_hash_digest);
        assert!(accounts.verify_password("fay", "a new one").unwrap());
        // A pepper that is not hex is refused before anything is written.
        let bad = Some(PasswordScheme {
            pepper: Some("not hex".to_owned()),
            nfkc: false,
        });
        assert!(matches!(
            accounts.import_password_hash("fay", MAS_BCRYPT, bad),
            Err(AccountError::InvalidHash(_))
        ));
        assert!(accounts.verify_password("fay", "a new one").unwrap());
    }
}

/// #810: `Store::put` and `Store::delete` reach the journal and no further, so
/// each write that starts or ends a session has to ask for a barrier itself.
/// Counted, not crashed: a barrier is what `barriers()` measures, and a time
/// or a power cut is not stable on a test host.
#[cfg(test)]
mod durability_tests {
    use super::*;
    use spindle_store::FjallStore;

    /// Run `step` and require that the store performed at least one barrier.
    fn barrier_during<T>(store: &FjallStore, what: &str, step: impl FnOnce() -> T) -> T {
        let before = store.barriers();
        let out = step();
        assert!(
            store.barriers() > before,
            "{what} returned without a barrier: a crash can undo it"
        );
        out
    }

    #[test]
    fn writes_that_start_or_end_a_session_reach_a_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let accounts = Accounts::new(&store, "example.org");

        barrier_during(&store, "register", || {
            accounts.register("alice", "correct horse battery").unwrap();
        });
        let session = barrier_during(&store, "create_session", || {
            accounts.create_session("alice", None, None, true).unwrap()
        });
        let refreshed = barrier_during(&store, "refresh", || {
            accounts
                .refresh(session.refresh_token.as_deref().unwrap())
                .unwrap()
        });
        barrier_during(&store, "logout", || {
            accounts.logout(&refreshed.access_token).unwrap();
        });
        let (token, _) = barrier_during(&store, "issue_login_token", || {
            accounts.issue_login_token("alice").unwrap()
        });
        barrier_during(&store, "redeem_login_token", || {
            accounts.redeem_login_token(&token).unwrap();
        });
        barrier_during(&store, "set_password", || {
            accounts
                .set_password("alice", "another passphrase")
                .unwrap();
        });
        barrier_during(&store, "delete_device", || {
            accounts
                .delete_device("alice", &refreshed.device.device_id)
                .unwrap();
        });
        barrier_during(&store, "logout_everywhere", || {
            accounts.logout_everywhere("alice").unwrap();
        });
    }
}
