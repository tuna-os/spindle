//! Secrets by reference, and the redaction every outbound value passes.
//!
//! The operator handles admin tokens, database passwords and OIDC client
//! secrets, and it must never hand one to a browser or write one into the
//! audit trail. The structural answer is that no resource holds a secret:
//! it holds a [`SecretRef`] — `env:NAME` or `file:/path` — which the
//! operator resolves only at the moment it calls out. The value never
//! enters a resource, so it cannot leave through one.
//!
//! References alone are a convention, and a convention fails the first
//! time someone pastes a token into a settings blob. So inbound driver
//! settings and operation parameters are refused if they carry anything
//! secret-shaped, and outbound evidence and audit data are redacted by the
//! same predicate. Refusing input rather than redacting it is deliberate:
//! a redacted setting would silently stop working, while a refused one
//! tells the operator to use a reference instead.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Where a secret lives. Serialises as the reference string, never as the
/// value.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// An environment variable of the operator process.
    Env(String),
    /// A file, typically a mounted Kubernetes Secret.
    File(String),
}

impl SecretRef {
    /// Parse `env:NAME` or `file:/absolute/path`.
    ///
    /// # Errors
    ///
    /// When the string is neither form, or names nothing.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if let Some(name) = raw.strip_prefix("env:") {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!(
                    "`{raw}` is not a valid environment variable reference"
                ));
            }
            return Ok(Self::Env(name.to_owned()));
        }
        if let Some(path) = raw.strip_prefix("file:") {
            if !path.starts_with('/') {
                return Err(format!("`{raw}` must name an absolute path"));
            }
            return Ok(Self::File(path.to_owned()));
        }
        Err(format!(
            "`{raw}` is not a secret reference; use `env:NAME` or `file:/path`"
        ))
    }

    /// Read the secret. Only the code that is about to use it calls this.
    ///
    /// # Errors
    ///
    /// When the variable is unset or the file unreadable. The error names
    /// the reference, never any content.
    pub fn resolve(&self) -> Result<String, String> {
        match self {
            Self::Env(name) => std::env::var(name).map_err(|_| format!("secret {self} is not set")),
            Self::File(path) => std::fs::read_to_string(path)
                .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(|error| format!("secret {self} is unreadable: {}", error.kind())),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(name) => write!(f, "env:{name}"),
            Self::File(path) => write!(f, "file:{path}"),
        }
    }
}

// Debug prints the reference too: there is nothing else in the type to
// print, and a derived Debug would invite someone to add a value field.
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRef({self})")
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

pub const REDACTED: &str = "[redacted]";

/// Key fragments that name a secret. Matched case-insensitively against
/// object keys; a key ending in `_ref` that holds a valid [`SecretRef`] is
/// the sanctioned way to name one and passes.
const SECRET_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passphrase",
    "recovery",
    "private",
    "signing_key",
    "credential",
    "cookie",
    "authorization",
    "access_key",
    "api_key",
];

/// Strings that are, or contain, a secret whatever key they sit under:
/// Matrix access tokens (`syt_`, and MAS's `mct_`), bearer credentials, PEM
/// private keys, and a Synapse signing key file's `ed25519 <id> <seed>`
/// line. Returns the scrubbed text, or `None` when there is nothing to
/// scrub. Tokens are cut out of the surrounding text rather than blanking
/// all of it, so a driver's error message stays readable.
fn scrub(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if text.contains("PRIVATE KEY-----") || (parts.len() == 3 && parts[0] == "ed25519") {
        return Some(REDACTED.to_owned());
    }
    let token_char = |c: char| c.is_ascii_alphanumeric() || "_-.~+/=".contains(c);
    let lower = text.to_ascii_lowercase();
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    for prefix in ["syt_", "mct_", "bearer "] {
        let mut from = 0;
        while let Some(found) = lower[from..].find(prefix) {
            let start = from + found;
            let boundary = lower[..start]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric());
            // A bearer token is what follows the scheme; a Matrix token
            // includes its prefix.
            let secret_start = if prefix == "bearer " {
                start + prefix.len()
            } else {
                start
            };
            let length = text[secret_start..]
                .find(|c: char| !token_char(c))
                .unwrap_or(text.len() - secret_start);
            if boundary && length > 0 && !text[secret_start..].starts_with(REDACTED) {
                cuts.push((secret_start, secret_start + length));
            }
            from = start + prefix.len();
        }
    }
    if cuts.is_empty() {
        return None;
    }
    cuts.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (start, end) in cuts {
        if start < at {
            continue;
        }
        out.push_str(&text[at..start]);
        out.push_str(REDACTED);
        at = end;
    }
    out.push_str(&text[at..]);
    Some(out)
}

fn secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|fragment| lower.contains(fragment))
}

fn sanctioned_reference(key: &str, value: &Value) -> bool {
    key.ends_with("_ref")
        && value
            .as_str()
            .is_some_and(|raw| SecretRef::parse(raw).is_ok())
}

/// Replace every secret-looking member of `value` with [`REDACTED`], and
/// report whether anything was replaced.
pub fn redact(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let mut changed = false;
            for (key, member) in map.iter_mut() {
                if sanctioned_reference(key, member) {
                    continue;
                }
                if secret_key(key) && !matches!(member, Value::Null | Value::Bool(_)) {
                    if member.as_str() != Some(REDACTED) {
                        *member = Value::String(REDACTED.to_owned());
                        changed = true;
                    }
                } else {
                    changed |= redact(member);
                }
            }
            changed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| redact(item) | changed),
        Value::String(text) => match scrub(text) {
            Some(clean) => {
                *text = clean;
                true
            }
            None => false,
        },
        _ => false,
    }
}

/// Refuse input that carries a secret inline.
///
/// # Errors
///
/// Names the first offending path, so the operator knows what to move into
/// a `*_ref` field.
pub fn refuse_inline(what: &str, value: &Value) -> Result<(), String> {
    fn walk(path: &str, value: &Value) -> Option<String> {
        match value {
            Value::Object(map) => map.iter().find_map(|(key, member)| {
                let here = format!("{path}.{key}");
                if sanctioned_reference(key, member) {
                    None
                } else if secret_key(key) && !matches!(member, Value::Null | Value::Bool(_)) {
                    Some(here)
                } else {
                    walk(&here, member)
                }
            }),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(index, item)| walk(&format!("{path}[{index}]"), item)),
            Value::String(text) if scrub(text).is_some() => Some(path.to_owned()),
            _ => None,
        }
    }
    match walk(what, value) {
        Some(path) => Err(format!(
            "{path} looks like an inline secret; store it outside the operator and name it \
             with a `*_ref` field holding `env:NAME` or `file:/path`"
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn references_serialise_as_the_reference() {
        let reference = SecretRef::parse("env:ADMIN_TOKEN").unwrap();
        assert_eq!(
            serde_json::to_value(&reference).unwrap(),
            json!("env:ADMIN_TOKEN")
        );
        assert_eq!(format!("{reference:?}"), "SecretRef(env:ADMIN_TOKEN)");
        assert!(SecretRef::parse("file:relative").is_err());
        assert!(SecretRef::parse("syt_abc").is_err());
    }

    #[test]
    fn redaction_catches_keys_and_shapes_and_spares_references() {
        let mut value = json!({
            "admin_token": "syt_x",
            "admin_token_ref": "env:ADMIN",
            "nested": [{"Password": "hunter2"}, "-----BEGIN PRIVATE KEY-----\nabc"],
            "note": "Bearer abc",
            "rooms": 115,
            "has_recovery": true,
        });
        assert!(redact(&mut value));
        assert_eq!(
            value,
            json!({
                "admin_token": REDACTED,
                "admin_token_ref": "env:ADMIN",
                "nested": [{"Password": REDACTED}, REDACTED],
                "note": "Bearer [redacted]",
                "rooms": 115,
                "has_recovery": true,
            })
        );
        assert!(!redact(&mut value), "redaction is idempotent");
    }

    #[test]
    fn tokens_are_cut_out_of_surrounding_text() {
        assert_eq!(
            scrub("the server said no (token syt_abc_123) twice").as_deref(),
            Some("the server said no (token [redacted]) twice")
        );
        assert_eq!(
            scrub("Authorization: Bearer abc.def").as_deref(),
            Some("Authorization: Bearer [redacted]")
        );
        assert_eq!(scrub("ed25519 a_AbCd c2VlZA").as_deref(), Some(REDACTED));
        assert_eq!(scrub("rsyt_ is part of a word, not a token"), None);
        assert_eq!(scrub("Bearer [redacted]"), None, "scrubbing is idempotent");
    }

    #[test]
    fn inline_secrets_are_refused_with_their_path() {
        let error = refuse_inline("settings", &json!({"db": {"password": "x"}})).unwrap_err();
        assert!(error.starts_with("settings.db.password"), "{error}");
        refuse_inline("settings", &json!({"db": {"password_ref": "file:/run/pg"}})).unwrap();
    }
}
