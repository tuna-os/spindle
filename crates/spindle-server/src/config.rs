//! Typed configuration, read from TOML.
//!
//! Every field is validated at load rather than at first use. A homeserver that
//! starts and then fails on its first request has already told its operator it
//! was healthy, and taken traffic on that promise.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The whole server configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// The name in every user and room ID this server mints. Permanent: it is
    /// baked into identifiers that federate, so it cannot be changed later
    /// without orphaning every room the server participates in.
    pub name: String,
    #[serde(default = "default_bind")]
    pub bind: String,
    /// What `.well-known` tells clients to connect to, when that differs from
    /// `name` — the ordinary case, since the delegation exists precisely so the
    /// server name need not be the hostname.
    #[serde(default)]
    pub public_base_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub path: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_data_dir(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing-subscriber` filter directive, e.g. `spindle=debug,warn`.
    #[serde(default)]
    pub filter: Option<String>,
}

fn default_bind() -> String {
    "127.0.0.1:8008".to_owned()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

impl Config {
    /// Parse and validate configuration from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the document does not parse or a field is
    /// unusable.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|error| ConfigError::Syntax {
            message: error.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Read and validate configuration from a file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, does not parse, or
    /// has an unusable field.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Unreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        Self::parse(&text)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let name = &self.server.name;
        if name.is_empty() {
            return Err(ConfigError::Invalid {
                field: "server.name",
                message: "must not be empty".to_owned(),
            });
        }
        // The URL case is checked first, before the general character rules it
        // would also trip. Both reject it; only this one tells the operator
        // which field does what they meant.
        if name.starts_with("http://") || name.starts_with("https://") {
            return Err(ConfigError::Invalid {
                field: "server.name",
                message: "is a hostname, not a URL; set server.public_base_url for delegation"
                    .to_owned(),
            });
        }
        // A server name ends up inside every user and room ID this server
        // mints, and those federate. Rejecting the obvious mistakes here is
        // cheaper than discovering them in a peer's signature check.
        if name.contains('/') || name.contains(' ') {
            return Err(ConfigError::Invalid {
                field: "server.name",
                message: format!("{name:?} is not a valid server name"),
            });
        }
        if self.server.bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::Invalid {
                field: "server.bind",
                message: format!("{:?} is not an address:port", self.server.bind),
            });
        }
        Ok(())
    }

    /// What clients should be told to connect to.
    #[must_use]
    pub fn client_base_url(&self) -> String {
        self.server
            .public_base_url
            .clone()
            .unwrap_or_else(|| format!("https://{}", self.server.name))
    }
}

/// Why a configuration could not be used.
#[derive(Debug)]
pub enum ConfigError {
    Unreadable {
        path: PathBuf,
        message: String,
    },
    Syntax {
        message: String,
    },
    Invalid {
        field: &'static str,
        message: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, message } => {
                write!(formatter, "cannot read {}: {message}", path.display())
            }
            Self::Syntax { message } => write!(formatter, "invalid configuration: {message}"),
            Self::Invalid { field, message } => write!(formatter, "{field} {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}
