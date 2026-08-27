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
    #[serde(default)]
    pub ratelimit: RateLimitConfig,
    #[serde(default)]
    pub previews: PreviewConfig,
    #[serde(default)]
    pub federation: FederationConfig,
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

/// Whether the rate limiter is in force.
///
/// On by default, because a server exposed to the internet without it is a
/// brute-force target (#66). Off is for the two contexts where the limiter is
/// measuring the harness rather than the server: Complement, which registers
/// users far faster than any human, and the API benchmark, whose whole job is
/// to issue requests as fast as the server will take them. Both would
/// otherwise report our own rate limit as the server's latency.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

const fn default_true() -> bool {
    true
}

/// Federation transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// Fetch peer keys and send requests over plain http instead of https.
    ///
    /// For test rigs whose "servers" are loopback stubs. A production
    /// deployment with this on has disabled federation authentication in
    /// all but name: anyone on the network path can answer the key fetch.
    #[serde(default)]
    pub insecure_http: bool,
    /// Base retry delay for outbound delivery, milliseconds. Doubles per
    /// consecutive failure per destination, capped at 64×. Tests shrink it;
    /// operators should not need to touch it.
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
    /// Where the federation TLS listener binds, e.g. `0.0.0.0:8448`. Unset
    /// means no federation listener: a deployment behind a reverse proxy
    /// terminates TLS there and serves federation on the main bind.
    #[serde(default)]
    pub bind: Option<String>,
    /// PEM certificate chain for the federation listener. Required with
    /// `bind`: federation peers speak https to port 8448 and a listener
    /// that cannot prove its name is unreachable in practice.
    #[serde(default)]
    pub tls_cert: Option<std::path::PathBuf>,
    /// PEM private key for `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<std::path::PathBuf>,
}

fn default_retry_base_ms() -> u64 {
    1000
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            insecure_http: false,
            retry_base_ms: default_retry_base_ms(),
            bind: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// URL preview fetching.
///
/// The preview endpoint makes the server fetch attacker-chosen URLs, which
/// is the textbook server-side request forgery vector: "preview this" must
/// never become a way to read the metadata service, the loopback admin
/// port, or anything else on the inside of the network the server sits in.
/// Private, loopback, link-local and otherwise non-global ranges are
/// therefore refused *by resolved address*, always. `allow_private` opens
/// named CIDR ranges back up — it exists for tests, which serve their
/// fixtures on 127.0.0.1, and for the rare deployment that genuinely wants
/// previews of an internal wiki and says so explicitly, range by range.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// CIDR ranges exempted from the private-address refusal, e.g.
    /// `["127.0.0.0/8"]`.
    #[serde(default)]
    pub allow_private: Vec<String>,
}

impl Default for PreviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_private: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub path: PathBuf,
    /// When present, media blobs live in this bucket instead of on disk.
    /// The metadata store stays local either way — it is the index, and an
    /// index a network hop away would put a round trip in front of every
    /// media request before a byte moves.
    #[serde(default)]
    pub s3: Option<S3Config>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: default_data_dir(),
            s3: None,
        }
    }
}

/// An S3-compatible object store for media blobs.
///
/// `endpoint` is explicit rather than derived from a region, because the
/// point of speaking the S3 protocol is that `MinIO`, Garage and friends
/// speak it too, and only AWS's endpoints are derivable.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

fn default_region() -> String {
    "us-east-1".to_owned()
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
