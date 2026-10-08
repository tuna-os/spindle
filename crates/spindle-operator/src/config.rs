//! `spindle-operator.toml`.
//!
//! The file names where the operator listens, where its journal lives,
//! which OIDC provider vouches for people and how their claims map to
//! roles, and which driver programs it may run. It holds no secret: the
//! OIDC client secret and every driver credential are references.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::driver::ExecDriverConfig;
use crate::secret::SecretRef;

/// The longest session the operator will issue. Sessions are bearer
/// credentials for infrastructure changes; a day-long one outlives the
/// shift of the person who opened it.
pub const MAX_SESSION_TTL_SECS: u64 = 8 * 60 * 60;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub operator: OperatorConfig,
    pub oidc: OidcConfig,
    #[serde(default)]
    pub drivers: BTreeMap<String, ExecDriverConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    pub listen: SocketAddr,
    /// The origin browsers use, e.g. `https://operator.example.org`. The
    /// OIDC redirect URI is built from it, and it is the only `Origin` an
    /// unsafe request may carry.
    pub public_url: String,
    pub data_dir: PathBuf,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_artifact_ttl")]
    pub artifact_ttl_secs: u64,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_ref: SecretRef,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// The ID-token claim holding group names, matched by `group:` entries.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    /// Who holds each role: `group:<name>` matches a value of the roles
    /// claim, `sub:<subject>` matches one person.
    pub roles: RoleMap,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMap {
    #[serde(default)]
    pub viewer: Vec<String>,
    #[serde(default)]
    pub operator: Vec<String>,
    #[serde(default)]
    pub approver: Vec<String>,
}

fn default_session_ttl() -> u64 {
    30 * 60
}
fn default_artifact_ttl() -> u64 {
    7 * 24 * 60 * 60
}
fn default_probe_timeout() -> u64 {
    5
}
fn default_scopes() -> Vec<String> {
    vec!["openid".to_owned(), "profile".to_owned()]
}
fn default_roles_claim() -> String {
    "groups".to_owned()
}

/// Plain HTTP is accepted only for loopback, where tests and a local
/// tunnel live. Anywhere else a session cookie or an authorization code
/// would cross the network in the clear.
fn secure_or_loopback(what: &str, url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(format!("{what} `{url}` must be an https URL"));
    };
    let host = rest.split(['/', '?']).next().unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
    if matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        Ok(())
    } else {
        Err(format!(
            "{what} `{url}` must be https (plain http only on loopback)"
        ))
    }
}

impl Config {
    /// # Errors
    /// On TOML errors and on settings that would be unsafe to run with.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut config: Config = toml::from_str(text).map_err(|error| error.to_string())?;
        config.operator.public_url = config.operator.public_url.trim_end_matches('/').to_owned();
        secure_or_loopback("operator.public_url", &config.operator.public_url)?;
        if config.operator.public_url.matches('/').count() != 2 {
            return Err("operator.public_url must be an origin, with no path".to_owned());
        }
        secure_or_loopback("oidc.issuer", &config.oidc.issuer)?;
        if config.operator.session_ttl_secs == 0
            || config.operator.session_ttl_secs > MAX_SESSION_TTL_SECS
        {
            return Err(format!(
                "operator.session_ttl_secs must be between 1 and {MAX_SESSION_TTL_SECS}"
            ));
        }
        if !config.oidc.scopes.iter().any(|scope| scope == "openid") {
            return Err("oidc.scopes must include `openid`".to_owned());
        }
        let roles = &config.oidc.roles;
        for entry in roles
            .viewer
            .iter()
            .chain(&roles.operator)
            .chain(&roles.approver)
        {
            if !(entry.starts_with("group:") || entry.starts_with("sub:")) {
                return Err(format!(
                    "role entry `{entry}` must start with `group:` or `sub:`"
                ));
            }
        }
        if roles.viewer.is_empty() && roles.operator.is_empty() && roles.approver.is_empty() {
            return Err("oidc.roles grants no role to anyone".to_owned());
        }
        for (name, driver) in &config.drivers {
            if driver.command.is_empty() {
                return Err(format!("drivers.{name}.command must name a program"));
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[operator]
listen = "127.0.0.1:8090"
public_url = "https://operator.example.org/"
data_dir = "/var/lib/spindle-operator"

[oidc]
issuer = "https://auth.example.org/"
client_id = "spindle-operator"
client_secret_ref = "env:OIDC_SECRET"

[oidc.roles]
viewer = ["group:ops"]
"#;

    #[test]
    fn a_minimal_config_parses_with_short_sessions() {
        let config = Config::parse(BASE).unwrap();
        assert_eq!(config.operator.public_url, "https://operator.example.org");
        assert_eq!(config.operator.session_ttl_secs, 1800);
    }

    #[test]
    fn the_shipped_example_parses() {
        let example = include_str!("../../../deploy/operator/spindle-operator.example.toml");
        let config = Config::parse(example).unwrap();
        assert!(config.drivers.contains_key("ess"));
    }

    #[test]
    fn unsafe_settings_are_refused() {
        let plain = BASE.replace("https://auth.example.org/", "http://auth.example.org/");
        assert!(Config::parse(&plain).unwrap_err().contains("https"));
        let loopback = BASE.replace("https://auth.example.org/", "http://127.0.0.1:9/");
        Config::parse(&loopback).unwrap();
        let inline = BASE.replace("\"env:OIDC_SECRET\"", "\"hunter2\"");
        assert!(Config::parse(&inline).is_err());
        let long = BASE.replace(
            "data_dir = \"/var/lib/spindle-operator\"",
            "data_dir = \"/x\"\nsession_ttl_secs = 86400",
        );
        assert!(
            Config::parse(&long)
                .unwrap_err()
                .contains("session_ttl_secs")
        );
        let path = BASE.replace("operator.example.org/", "operator.example.org/console");
        assert!(Config::parse(&path).is_err());
    }
}
