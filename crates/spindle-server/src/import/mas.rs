//! Moving accounts from a Matrix Authentication Service into the built-in
//! provider (#797): `spindle import-mas`.
//!
//! Under `[auth.delegated]` MAS owns sign-in. Spindle has every account (MAS
//! provisions them), but not what signs them in: the password hashes, the
//! confirmed addresses and the links to upstream identity providers stay in
//! MAS's database. This carries them over, so that after the switch to
//! `builtin_oidc` the same password and the same upstream sign-in reach the
//! same account. Sessions do not move: MAS's tokens are MAS's.
//!
//! The work is split as the Synapse importer splits it. A [`Snapshot`] is
//! plain data; [`apply`] makes every decision from it and from the store.
//! The `PostgreSQL` reader that fills a snapshot is behind the `mas-import`
//! feature, and the tests drive [`apply`] with a snapshot built in memory.
//!
//! The rules, each chosen so a rerun is safe:
//!
//! - **MAS fills in; it does not overrule.** An account Spindle lacks is
//!   made. A lock and an admin grant MAS has are applied. Where Spindle is
//!   stricter (locked or deactivated here, but not in MAS), Spindle's state
//!   stays and the report says so. A MAS deactivation of an account that is
//!   active here cannot be finished offline (it ends devices and announces
//!   the change over federation), so the account is locked and the report
//!   asks for the admin API's deactivation.
//! - **A password changed here is not taken back.** The account remembers
//!   the digest of the hash the import stored; a later run replaces only a
//!   hash that is still that one.
//! - **Nothing is half-written on a dry run**: `dry_run` makes the same
//!   decisions and counts them, and writes nothing.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use spindle_store::Store;

use crate::accounts::{self, Account, AccountError, Accounts, PasswordScheme};
use crate::config::Config;

/// Reading a [`Snapshot`] out of MAS's `PostgreSQL` database.
#[cfg(feature = "mas-import")]
pub mod postgres;

/// What the importer reads from MAS, all from one moment.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub users: Vec<User>,
    pub providers: Vec<Provider>,
    pub links: Vec<Link>,
}

/// One row of MAS's `users`, with its current password and its addresses.
#[derive(Clone, Debug, Default)]
pub struct User {
    /// `users.user_id`, the UUID that links refer to.
    pub id: String,
    /// The localpart.
    pub username: String,
    /// `locked_at` is set.
    pub locked: bool,
    /// `deactivated_at` is set.
    pub deactivated: bool,
    /// `can_request_admin`: MAS lets the user ask for the homeserver's
    /// admin scope. The built-in provider has no such scope; the account's
    /// admin flag is what grants the same.
    pub can_request_admin: bool,
    /// The newest row of `user_passwords`, the one MAS verifies against.
    pub password: Option<Password>,
    /// `user_emails`. MAS 1.23 keeps only confirmed addresses there.
    pub emails: Vec<String>,
}

/// A stored MAS password: the hash and the version of the scheme in
/// MAS's `passwords.schemes` that made it.
#[derive(Clone, Debug)]
pub struct Password {
    pub hash: String,
    pub version: u16,
}

/// One row of `upstream_oauth_providers`.
#[derive(Clone, Debug)]
pub struct Provider {
    /// The UUID. MAS shows it, and its configuration names it, as a ULID.
    pub id: String,
    /// For the report only; MAS 1.23 allows a provider without one.
    pub issuer: Option<String>,
}

/// One row of `upstream_oauth_links`.
#[derive(Clone, Debug)]
pub struct Link {
    pub provider_id: String,
    pub subject: String,
    /// `None` while a first sign-in is still choosing its account.
    pub user_id: Option<String>,
}

/// The hashing algorithm of a MAS password scheme.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Bcrypt,
    #[default]
    Argon2id,
    Pbkdf2,
}

/// One entry of MAS's `passwords.schemes`, with its secret read.
#[derive(Clone, Debug, Default)]
pub struct Scheme {
    pub algorithm: Algorithm,
    /// `secret` or the contents of `secret_file`: the pepper.
    pub secret: Option<Vec<u8>>,
    pub unicode_normalization: bool,
}

impl Scheme {
    /// What the account must keep beside the hash so it can verify.
    fn password_scheme(&self) -> Option<PasswordScheme> {
        let scheme = PasswordScheme {
            pepper: self.secret.as_deref().map(hex),
            nfkc: self.unicode_normalization,
        };
        (scheme != PasswordScheme::default()).then_some(scheme)
    }
}

/// MAS's password schemes by version.
#[derive(Clone, Debug)]
pub struct Schemes {
    by_version: BTreeMap<u16, Scheme>,
    /// Whether they came from a MAS configuration or are MAS's defaults.
    from_config: bool,
}

impl Default for Schemes {
    /// MAS's default when its configuration has no `passwords.schemes`:
    /// version 1, Argon2id, no secret, no normalization.
    fn default() -> Self {
        Self {
            by_version: BTreeMap::from([(1, Scheme::default())]),
            from_config: false,
        }
    }
}

#[derive(Deserialize)]
struct MasConfig {
    #[serde(default)]
    passwords: Option<MasPasswords>,
}

#[derive(Deserialize)]
struct MasPasswords {
    #[serde(default)]
    schemes: Option<Vec<MasScheme>>,
}

#[derive(Deserialize)]
struct MasScheme {
    version: u16,
    #[serde(default)]
    algorithm: Algorithm,
    #[serde(default)]
    unicode_normalization: bool,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    secret_file: Option<std::path::PathBuf>,
}

impl Schemes {
    /// Read `passwords.schemes` from the text of MAS's `config.yaml`. A
    /// `secret_file` is read as MAS reads it: raw bytes, the path relative
    /// to the working directory.
    ///
    /// # Errors
    ///
    /// The YAML does not parse, a scheme has both `secret` and
    /// `secret_file`, two schemes share a version, or a secret file
    /// cannot be read.
    pub fn from_mas_config(yaml: &str) -> Result<Self, String> {
        let config: MasConfig =
            serde_saphyr::from_str(yaml).map_err(|error| format!("MAS config: {error}"))?;
        let Some(schemes) = config.passwords.and_then(|passwords| passwords.schemes) else {
            return Ok(Self {
                from_config: true,
                ..Self::default()
            });
        };
        let mut by_version = BTreeMap::new();
        for scheme in schemes {
            let secret = match (scheme.secret, scheme.secret_file) {
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "MAS config: password scheme {} has both secret and secret_file",
                        scheme.version
                    ));
                }
                (Some(secret), None) => Some(secret.into_bytes()),
                (None, Some(path)) => Some(std::fs::read(&path).map_err(|error| {
                    format!(
                        "MAS config: password scheme {} secret_file {}: {error}",
                        scheme.version,
                        path.display()
                    )
                })?),
                (None, None) => None,
            };
            let entry = Scheme {
                algorithm: scheme.algorithm,
                secret,
                unicode_normalization: scheme.unicode_normalization,
            };
            if by_version.insert(scheme.version, entry).is_some() {
                return Err(format!(
                    "MAS config: two password schemes have version {}",
                    scheme.version
                ));
            }
        }
        Ok(Self {
            by_version,
            from_config: true,
        })
    }

    /// Schemes given directly, as a test or a caller with its own reader
    /// builds them.
    #[must_use]
    pub fn new(by_version: BTreeMap<u16, Scheme>) -> Self {
        Self {
            by_version,
            from_config: true,
        }
    }
}

/// The ULID MAS shows for a UUID it stores: the same 128 bits in
/// Crockford's base32. `None` for text that is not a UUID.
#[must_use]
pub fn ulid(uuid: &str) -> Option<String> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let digits: String = uuid.chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let value = u128::from_str_radix(&digits, 16).ok()?;
    (0..26)
        .rev()
        .map(|index| {
            let digit = usize::try_from((value >> (5 * index)) & 31).ok()?;
            Some(char::from(ALPHABET[digit]))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// How many accounts the import found, made and changed.
#[derive(Clone, Debug, Default, Serialize)]
pub struct UserCounts {
    /// Users in MAS.
    pub seen: u64,
    /// Accounts made here, because Spindle had none.
    pub created: u64,
    /// Accounts made here already deactivated, as MAS has them.
    pub created_deactivated: u64,
    pub admin_granted: u64,
    pub locked: u64,
}

/// What happened to the passwords.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PasswordCounts {
    pub imported: u64,
    /// Already the hash and scheme MAS has.
    pub unchanged: u64,
    /// Changed here since the last import, and kept.
    pub kept_local: u64,
    pub refused: u64,
    /// Users with no password in MAS (an upstream sign-in only).
    pub none: u64,
}

/// What happened to the email addresses.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EmailCounts {
    pub bound: u64,
    pub unchanged: u64,
    pub refused: u64,
}

/// What happened to the upstream links.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LinkCounts {
    pub imported: u64,
    pub unchanged: u64,
    /// A first sign-in that never chose an account: nothing to carry.
    pub unclaimed: u64,
    /// Links of users the import refused or that are deactivated.
    pub skipped: u64,
    pub refused: u64,
}

/// One thing the report wants an operator to read.
#[derive(Clone, Debug, Serialize)]
pub struct Note {
    /// The user ID, or the provider's ULID.
    pub subject: String,
    pub reason: String,
}

/// The outcome of one run. `refused` lists what MAS has and this server
/// did not take; `kept` lists where this server's own state stayed.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub dry_run: bool,
    /// `"mas config"` or `"mas defaults"`: where the password schemes
    /// came from.
    pub password_schemes: &'static str,
    pub users: UserCounts,
    pub passwords: PasswordCounts,
    pub emails: EmailCounts,
    pub links: LinkCounts,
    pub refused: Vec<Note>,
    pub kept: Vec<Note>,
}

struct Importer<'a, S: Store> {
    store: &'a S,
    accounts: Accounts<'a, S>,
    dry_run: bool,
    report: Report,
    /// The hash every account made here gets until a password lands:
    /// one Argon2 computation for the run, not one per account.
    placeholder: Option<String>,
    /// Addresses this run bound, so a dry run catches two MAS users with
    /// one address as a real run would.
    claimed: HashMap<String, String>,
}

/// Bring the store in line with a MAS snapshot; see the module
/// documentation for the rules.
///
/// # Errors
///
/// A storage error, after which the store holds the work done so far: a
/// rerun picks up from there.
pub fn apply<S: Store>(
    store: &S,
    config: &Config,
    source: &Snapshot,
    schemes: &Schemes,
    dry_run: bool,
) -> Result<Report, String> {
    let mut run = Importer {
        store,
        accounts: Accounts::new(store, &config.server.name),
        dry_run,
        report: Report {
            dry_run,
            password_schemes: if schemes.from_config {
                "mas config"
            } else {
                "mas defaults"
            },
            ..Report::default()
        },
        placeholder: None,
        claimed: HashMap::new(),
    };
    let mut users: Vec<&User> = source.users.iter().collect();
    users.sort_by(|a, b| a.username.cmp(&b.username));
    // MAS user ID -> localpart, for the users whose links may land.
    let mut linkable: HashMap<&str, &str> = HashMap::new();
    for user in users {
        run.report.users.seen += 1;
        if run.user(user, schemes)? {
            linkable.insert(&user.id, &user.username);
        }
    }
    run.links(config, source, &linkable)?;
    Ok(run.report)
}

fn storage(error: &impl std::fmt::Display) -> String {
    format!("storage: {error}")
}

impl<S: Store> Importer<'_, S> {
    fn refuse(&mut self, subject: String, reason: impl Into<String>) {
        self.report.refused.push(Note {
            subject,
            reason: reason.into(),
        });
    }

    fn keep(&mut self, subject: String, reason: impl Into<String>) {
        self.report.kept.push(Note {
            subject,
            reason: reason.into(),
        });
    }

    /// Import one user. `true` when the account is active and its links
    /// may land.
    fn user(&mut self, user: &User, schemes: &Schemes) -> Result<bool, String> {
        let localpart = user.username.as_str();
        let user_id = self.accounts.user_id(localpart);
        let existing = self.accounts.account(localpart).map_err(|e| storage(&e))?;
        let created = existing.is_none();
        let mut account = if let Some(account) = existing {
            account
        } else if let Some(account) = self.create(localpart, user.deactivated)? {
            account
        } else {
            self.refuse(
                user_id,
                "not a valid localpart here: no account was made, nothing imported",
            );
            return Ok(false);
        };
        if user.can_request_admin && !account.admin {
            if !self.dry_run {
                self.accounts
                    .set_admin(localpart, true)
                    .map_err(|e| storage(&e))?;
            }
            account.admin = true;
            self.report.users.admin_granted += 1;
        }
        if user.deactivated && !account.deactivated {
            // Signing in must stop now; finishing the deactivation needs
            // the running server.
            self.lock(localpart, &mut account)?;
            self.refuse(
                user_id,
                "deactivated in MAS but active here: locked instead; deactivate it with \
                 POST /_spindle/admin/v1/users/{userId}/deactivate",
            );
            return Ok(false);
        }
        if user.locked && !account.locked {
            self.lock(localpart, &mut account)?;
        } else if !user.locked && account.locked {
            self.keep(user_id.clone(), "locked here but not in MAS: left locked");
        }
        if account.deactivated {
            if !created && !user.deactivated {
                self.keep(
                    user_id,
                    "deactivated here but active in MAS: left deactivated",
                );
            }
            return Ok(false);
        }
        self.password(user, &user_id, &account, created, schemes)?;
        self.emails(user, &user_id)?;
        Ok(true)
    }

    fn lock(&mut self, localpart: &str, account: &mut Account) -> Result<(), String> {
        if !account.locked {
            if !self.dry_run {
                self.accounts
                    .set_locked(localpart, true)
                    .map_err(|e| storage(&e))?;
            }
            account.locked = true;
            self.report.users.locked += 1;
        }
        Ok(())
    }

    /// Make the account Spindle lacks. `None` when the localpart is not
    /// one this server accepts.
    fn create(&mut self, localpart: &str, deactivated: bool) -> Result<Option<Account>, String> {
        match self.accounts.availability(localpart) {
            Ok(()) => {}
            Err(AccountError::InvalidUsername) => return Ok(None),
            Err(other) => return Err(storage(&other)),
        }
        let mut account = if self.dry_run {
            Account {
                localpart: localpart.to_owned(),
                password_hash: String::new(),
                password_scheme: None,
                imported_hash_digest: None,
                deactivated: false,
                admin: false,
                locked: false,
                suspended: false,
                erased: false,
            }
        } else {
            if self.placeholder.is_none() {
                let hash = accounts::hash_password(&accounts::unguessable_password())
                    .map_err(|e| storage(&e))?;
                self.placeholder = Some(hash);
            }
            let placeholder = self.placeholder.as_deref().unwrap_or_default();
            self.accounts
                .register_hashed(localpart, placeholder)
                .map_err(|e| storage(&e))?
        };
        if deactivated {
            if !self.dry_run {
                self.accounts
                    .set_deactivated(localpart, true)
                    .map_err(|e| storage(&e))?;
            }
            account.deactivated = true;
            self.report.users.created_deactivated += 1;
        } else {
            self.report.users.created += 1;
        }
        Ok(Some(account))
    }

    fn password(
        &mut self,
        user: &User,
        user_id: &str,
        account: &Account,
        created: bool,
        schemes: &Schemes,
    ) -> Result<(), String> {
        let Some(password) = &user.password else {
            self.report.passwords.none += 1;
            return Ok(());
        };
        let Some(scheme) = schemes.by_version.get(&password.version) else {
            self.report.passwords.refused += 1;
            self.refuse(
                user_id.to_owned(),
                format!(
                    "password scheme version {} is not in MAS's configuration; \
                     pass the config.yaml MAS runs with as --mas-config",
                    password.version
                ),
            );
            return Ok(());
        };
        if scheme.algorithm == Algorithm::Pbkdf2 {
            self.report.passwords.refused += 1;
            self.refuse(
                user_id.to_owned(),
                "a PBKDF2 password cannot be verified here; give the user a reset link",
            );
            return Ok(());
        }
        let wanted = scheme.password_scheme();
        if account.password_hash == password.hash && account.password_scheme == wanted {
            self.report.passwords.unchanged += 1;
            return Ok(());
        }
        let changed_here = account
            .imported_hash_digest
            .as_deref()
            .is_some_and(|digest| digest != accounts::hash_digest(&account.password_hash));
        if changed_here && !created {
            self.report.passwords.kept_local += 1;
            self.keep(
                user_id.to_owned(),
                "password changed here since the last import: kept",
            );
            return Ok(());
        }
        if let Err(error) = accounts::validate_password_hash(&password.hash) {
            self.report.passwords.refused += 1;
            self.refuse(user_id.to_owned(), error.to_string());
            return Ok(());
        }
        if !self.dry_run {
            self.accounts
                .import_password_hash(&account.localpart, &password.hash, wanted)
                .map_err(|e| storage(&e))?;
        }
        self.report.passwords.imported += 1;
        Ok(())
    }

    fn emails(&mut self, user: &User, user_id: &str) -> Result<(), String> {
        let localpart = user.username.as_str();
        for raw in &user.emails {
            let Some(address) = crate::email::normalize(raw) else {
                self.report.emails.refused += 1;
                self.refuse(
                    user_id.to_owned(),
                    format!("{raw:?} is not an address this server accepts (ASCII only)"),
                );
                continue;
            };
            let owner = match self.claimed.get(&address) {
                Some(owner) => Some(owner.clone()),
                None => {
                    crate::email::owner_in(self.store, &address).map_err(|e| storage(&e.error))?
                }
            };
            match owner {
                Some(owner) if owner == localpart => self.report.emails.unchanged += 1,
                Some(owner) => {
                    self.report.emails.refused += 1;
                    let holder = self.accounts.user_id(&owner);
                    self.refuse(
                        user_id.to_owned(),
                        format!("{address} is already confirmed on {holder}"),
                    );
                }
                None => {
                    if !self.dry_run {
                        crate::email::bind_in(self.store, localpart, &address)
                            .map_err(|e| storage(&e.error))?;
                    }
                    self.claimed.insert(address, localpart.to_owned());
                    self.report.emails.bound += 1;
                }
            }
        }
        Ok(())
    }

    fn links(
        &mut self,
        config: &Config,
        source: &Snapshot,
        linkable: &HashMap<&str, &str>,
    ) -> Result<(), String> {
        // MAS provider UUID -> the id of the [[auth.upstream_oidc]] entry
        // with its ULID, as that entry spells it.
        let mut configured: HashMap<&str, Option<&str>> = HashMap::new();
        for provider in &source.providers {
            let id = ulid(&provider.id).and_then(|ulid| {
                config
                    .auth
                    .upstream_oidc
                    .iter()
                    .find(|upstream| upstream.id.eq_ignore_ascii_case(&ulid))
                    .map(|upstream| upstream.id.as_str())
            });
            configured.insert(provider.id.as_str(), id);
        }
        let mut orphaned: BTreeMap<&str, u64> = BTreeMap::new();
        let mut links: Vec<&Link> = source.links.iter().collect();
        links.sort_by(|a, b| (&a.provider_id, &a.subject).cmp(&(&b.provider_id, &b.subject)));
        for link in links {
            let Some(user_id) = &link.user_id else {
                self.report.links.unclaimed += 1;
                continue;
            };
            let Some(localpart) = linkable.get(user_id.as_str()).copied() else {
                self.report.links.skipped += 1;
                continue;
            };
            let Some(provider) = configured.get(link.provider_id.as_str()).copied().flatten()
            else {
                self.report.links.refused += 1;
                *orphaned.entry(&link.provider_id).or_default() += 1;
                continue;
            };
            let current = crate::upstream::linked_account(self.store, provider, &link.subject)
                .map_err(|e| storage(&e))?;
            match current {
                Some(current) if current == localpart => self.report.links.unchanged += 1,
                Some(current) => {
                    self.report.links.refused += 1;
                    let holder = self.accounts.user_id(&current);
                    let user_id = self.accounts.user_id(localpart);
                    self.refuse(
                        user_id,
                        format!(
                            "the {provider} identity it is linked to in MAS is linked to \
                             {holder} here"
                        ),
                    );
                }
                None => {
                    if !self.dry_run {
                        crate::upstream::store_link(self.store, provider, &link.subject, localpart)
                            .map_err(|e| storage(&e))?;
                    }
                    self.report.links.imported += 1;
                }
            }
        }
        for (provider_id, count) in orphaned {
            let issuer = source
                .providers
                .iter()
                .find(|provider| provider.id == provider_id)
                .and_then(|provider| provider.issuer.clone())
                .unwrap_or_else(|| "no issuer".to_owned());
            let name = ulid(provider_id).unwrap_or_else(|| provider_id.to_owned());
            self.refuse(
                name.clone(),
                format!(
                    "{count} link(s) of the MAS provider at {issuer} not imported: no \
                     [[auth.upstream_oidc]] has id = \"{name}\""
                ),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uuid_reads_as_the_ulid_mas_shows() {
        // MAS's ULIDs are UUIDs in the database: 01ARZ3NDEKTSV4RRFFQ69G5FAV
        // (the ULID specification's example) is this UUID.
        assert_eq!(
            ulid("01563e3a-b5d3-d676-4c61-efb99302bd5b").as_deref(),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV")
        );
        assert_eq!(
            ulid("00000000-0000-0000-0000-000000000000").as_deref(),
            Some("00000000000000000000000000")
        );
        assert_eq!(
            ulid("ffffffff-ffff-ffff-ffff-ffffffffffff").as_deref(),
            Some("7ZZZZZZZZZZZZZZZZZZZZZZZZZ")
        );
        assert_eq!(ulid("not a uuid"), None);
    }

    #[test]
    fn mas_config_schemes_read_with_their_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("pepper");
        std::fs::write(&secret, b"from a file").unwrap();
        let yaml = format!(
            "http:\n  public_base: https://auth.example.org/\npasswords:\n  enabled: true\n  \
             schemes:\n  - version: 1\n    algorithm: bcrypt\n    unicode_normalization: true\n    \
             secret: synapse-pepper\n  - version: 2\n    algorithm: argon2id\n    \
             secret_file: {}\n  - version: 3\n",
            secret.display()
        );
        let schemes = Schemes::from_mas_config(&yaml).unwrap();
        assert!(schemes.from_config);
        let one = &schemes.by_version[&1];
        assert_eq!(one.algorithm, Algorithm::Bcrypt);
        assert_eq!(one.secret.as_deref(), Some(&b"synapse-pepper"[..]));
        assert!(one.unicode_normalization);
        assert_eq!(
            one.password_scheme(),
            Some(PasswordScheme {
                pepper: Some(hex(b"synapse-pepper")),
                nfkc: true,
            })
        );
        let two = &schemes.by_version[&2];
        assert_eq!(two.algorithm, Algorithm::Argon2id);
        assert_eq!(two.secret.as_deref(), Some(&b"from a file"[..]));
        assert_eq!(schemes.by_version[&3].password_scheme(), None);

        // No passwords section: MAS's own default.
        let defaults = Schemes::from_mas_config("http: {}\n").unwrap();
        assert_eq!(defaults.by_version.len(), 1);
        assert_eq!(defaults.by_version[&1].algorithm, Algorithm::Argon2id);

        for bad in [
            "passwords:\n  schemes:\n  - version: 1\n    secret: a\n    secret_file: /x\n",
            "passwords:\n  schemes:\n  - version: 1\n  - version: 1\n",
            "passwords:\n  schemes:\n  - version: 1\n    secret_file: /nonexistent/pepper\n",
        ] {
            assert!(Schemes::from_mas_config(bad).is_err(), "{bad}");
        }
    }
}
