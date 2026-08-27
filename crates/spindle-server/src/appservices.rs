//! Application services: bridges and bots with a skeleton key.
//!
//! An appservice is a client whose token authenticates *a namespace of
//! users* rather than one account. The registration file (YAML, by spec)
//! is the whole contract: the `as_token` the service presents to us, the
//! `hs_token` we will present to it, the localpart it acts as by default,
//! and the regex namespaces inside which it may masquerade as anyone.
//!
//! Registrations load once at startup and a bad file is startup-fatal —
//! a bridge that silently failed to register would look exactly like a
//! bridge receiving nothing, which is the failure mode worth the loudest
//! possible error.

use std::sync::Arc;

use regex::Regex;
use serde::Deserialize;

/// One namespace claim: a regex over full IDs, and whether the claim is
/// exclusive to this service.
#[derive(Debug, Clone, Deserialize)]
pub struct Namespace {
    #[serde(default)]
    pub exclusive: bool,
    pub regex: String,
    #[serde(skip)]
    compiled: Option<Regex>,
}

impl Namespace {
    fn compile(&mut self) -> Result<(), AppserviceError> {
        // Anchored per spec: a namespace regex matches the whole ID, and
        // an unanchored one would quietly claim every user whose name
        // merely *contains* the pattern.
        let anchored = format!("^(?:{})$", self.regex);
        self.compiled =
            Some(Regex::new(&anchored).map_err(|error| {
                AppserviceError::BadRegex(self.regex.clone(), error.to_string())
            })?);
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, id: &str) -> bool {
        self.compiled
            .as_ref()
            .is_some_and(|regex| regex.is_match(id))
    }
}

/// The three namespace families a registration may claim.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Namespaces {
    #[serde(default)]
    pub users: Vec<Namespace>,
    #[serde(default)]
    pub aliases: Vec<Namespace>,
    #[serde(default)]
    pub rooms: Vec<Namespace>,
}

/// One appservice, as its registration file declares it.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub id: String,
    /// Where transactions get pushed; `None` (or explicit null) means the
    /// service only ever acts through the CS API and receives nothing.
    #[serde(default)]
    pub url: Option<String>,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: Namespaces,
    /// `false` exempts the service from rate limits; the default is the
    /// spec's: limited like anyone else.
    #[serde(default = "default_rate_limited")]
    pub rate_limited: bool,
}

fn default_rate_limited() -> bool {
    true
}

impl Registration {
    /// The user the service acts as when it does not masquerade.
    #[must_use]
    pub fn sender_user(&self, server_name: &str) -> String {
        format!("@{}:{server_name}", self.sender_localpart)
    }

    /// Whether the service may act as `user_id`: its own sender, or
    /// anyone inside its user namespaces.
    #[must_use]
    pub fn may_masquerade_as(&self, user_id: &str, server_name: &str) -> bool {
        user_id == self.sender_user(server_name)
            || self
                .namespaces
                .users
                .iter()
                .any(|namespace| namespace.matches(user_id))
    }
}

/// Why registrations could not be loaded. All startup-fatal.
#[derive(Debug)]
pub enum AppserviceError {
    Unreadable(String, String),
    Invalid(String, String),
    BadRegex(String, String),
    /// Two registrations share an `id` or an `as_token` — either would
    /// make "which service is this?" ambiguous at auth time.
    Duplicate(String),
}

impl std::fmt::Display for AppserviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(path, error) => write!(f, "{path}: {error}"),
            Self::Invalid(path, error) => write!(f, "{path} does not parse: {error}"),
            Self::BadRegex(regex, error) => write!(f, "namespace regex {regex:?}: {error}"),
            Self::Duplicate(what) => write!(f, "duplicate registration {what}"),
        }
    }
}

/// Every registered appservice, indexed for the auth path.
#[derive(Default)]
pub struct Appservices {
    list: Vec<Arc<Registration>>,
}

impl Appservices {
    /// Load and validate every registration file named in the config.
    ///
    /// # Errors
    ///
    /// Returns [`AppserviceError`] on the first unreadable, unparseable or
    /// ambiguous registration — startup-fatal by design.
    pub fn load(paths: &[String]) -> Result<Self, AppserviceError> {
        let mut list: Vec<Arc<Registration>> = Vec::new();
        for path in paths {
            let raw = std::fs::read_to_string(path)
                .map_err(|error| AppserviceError::Unreadable(path.clone(), error.to_string()))?;
            let mut registration: Registration = serde_yaml::from_str(&raw)
                .map_err(|error| AppserviceError::Invalid(path.clone(), error.to_string()))?;
            for namespace in registration
                .namespaces
                .users
                .iter_mut()
                .chain(registration.namespaces.aliases.iter_mut())
                .chain(registration.namespaces.rooms.iter_mut())
            {
                namespace.compile()?;
            }
            if list.iter().any(|existing| {
                existing.id == registration.id || existing.as_token == registration.as_token
            }) {
                return Err(AppserviceError::Duplicate(registration.id));
            }
            list.push(Arc::new(registration));
        }
        Ok(Self { list })
    }

    /// The registration presenting `as_token`, if any.
    #[must_use]
    pub fn by_token(&self, token: &str) -> Option<&Arc<Registration>> {
        self.list
            .iter()
            .find(|registration| registration.as_token == token)
    }

    /// Every registration, for iteration by the transaction push.
    #[must_use]
    pub fn all(&self) -> &[Arc<Registration>] {
        &self.list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_regexes_match_the_whole_id_not_a_substring() {
        let mut namespace = Namespace {
            exclusive: true,
            regex: "@bot:server".to_owned(),
            compiled: None,
        };
        namespace.compile().unwrap();
        assert!(namespace.matches("@bot:server"));
        // Unanchored, both of these would match by containment — and a
        // namespace that matches by containment is a claim over IDs the
        // registration never wrote down.
        assert!(!namespace.matches("@bot:serverextra"));
        assert!(!namespace.matches("x@bot:server"));
    }
}
