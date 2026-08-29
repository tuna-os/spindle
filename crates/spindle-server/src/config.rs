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
    #[serde(default)]
    pub appservices: AppservicesConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub delayed_events: DelayedEventsConfig,
    #[serde(default)]
    pub turn: TurnConfig,
}

/// The caps on MSC4140 delayed events (#36).
///
/// Both exist because a delayed event is storage this server holds on a
/// client's say-so, and #36 names the uncapped version as a
/// memory-amplification vector: a client can schedule delays as fast as it
/// can send requests and never refresh them. The defaults are generous
/// against any real client -- Matrix RTC keeps one pending departure per
/// call -- and finite against one that has gone wrong or is trying to.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct DelayedEventsConfig {
    /// The longest delay this server will accept, in milliseconds.
    ///
    /// A day: far past any call heartbeat, and still bounded.
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
    /// The most delays one sender may have pending in one room.
    ///
    /// Per sender *and* per room, because that is the unit a client works
    /// in: a legitimate Matrix RTC client sits at one.
    #[serde(default = "default_max_per_room")]
    pub max_per_room: usize,
}

impl Default for DelayedEventsConfig {
    fn default() -> Self {
        Self {
            max_delay_ms: default_max_delay_ms(),
            max_per_room: default_max_per_room(),
        }
    }
}

const fn default_max_delay_ms() -> u64 {
    crate::delayed::DEFAULT_MAX_DELAY_MS
}

const fn default_max_per_room() -> usize {
    crate::delayed::DEFAULT_MAX_PER_ROOM
}

/// The operational scrape surface (#166).
///
/// Off unless `bind` is set, and bound to loopback in every example,
/// because the exposition names peers this server talks to and the
/// volumes it carries. It is an operator's surface, not a public one —
/// so it gets its own listener rather than a path on the one the
/// internet reaches.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MetricsConfig {
    /// `address:port` to serve `/metrics` on. Absent means no listener,
    /// which is the default.
    pub bind: Option<String>,
}

/// TURN relays for calls that cannot connect peer-to-peer.
///
/// Empty by default, and an empty configuration is not a failure: a server
/// with no relay answers `/voip/turnServer` with an empty object, which is
/// what the spec says to do and what a client is prepared for. Most calls
/// never need a relay; the ones behind symmetric NAT do, and they fail
/// silently without one — so this is the setting an operator finds out
/// about *after* the complaint, which is why it is written down here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnConfig {
    /// The relay URIs handed to clients, e.g.
    /// `turn:turn.example.org:3478?transport=udp`.
    ///
    /// Nothing else here matters if this is empty: credentials for no relay
    /// are credentials for nothing, so an empty list short-circuits the
    /// endpoint.
    #[serde(default)]
    pub uris: Vec<String>,
    /// coturn's `static-auth-secret`, for time-limited credentials.
    ///
    /// The mechanism is the TURN REST API: the username is an expiry stamp
    /// and the caller's Matrix ID, and the password is an HMAC of it under
    /// this secret. The relay recomputes the same HMAC and needs no account
    /// database and no contact with this server -- which is the whole reason
    /// the scheme exists, and why it is preferred over
    /// [`Self::username`]/[`Self::password`].
    pub shared_secret: Option<String>,
    /// A fixed username, for a relay that does not do the REST scheme.
    ///
    /// Every client is handed the same credential, so it cannot be revoked
    /// for one caller and it does not expire. Present because some relays
    /// offer nothing else, not because it is a good idea.
    pub username: Option<String>,
    /// The password paired with [`Self::username`].
    pub password: Option<String>,
    /// How long an issued credential is valid, in seconds.
    ///
    /// Also what the response reports as `ttl`, which is a client's cue to
    /// come back for a fresh one. A day is coturn's own default.
    #[serde(default = "default_turn_ttl")]
    pub ttl_seconds: u64,
}

fn default_turn_ttl() -> u64 {
    86_400
}

/// How callers prove who they are.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// MSC3861 delegation: when set, an OIDC provider (typically the
    /// Matrix Authentication Service) owns identity, and this server
    /// validates its access tokens by introspection. Local password
    /// login and registration turn off — one identity provider is the
    /// point, and two is how accounts drift apart.
    #[serde(default)]
    pub delegated: Option<DelegatedAuthConfig>,
    /// The built-in OIDC provider (#159): this server issues its own
    /// authorization codes and sessions over the accounts it already
    /// holds, so Element X's OIDC-native login works from one binary
    /// with nothing else deployed. The floor, not a MAS replacement —
    /// upstream identity providers, SSO and account management are what
    /// `[auth.delegated]` and a real MAS are for.
    #[serde(default)]
    pub builtin_oidc: bool,
}

/// The delegated provider, named explicitly rather than discovered at
/// startup: a server that cannot start because an idP was briefly
/// unreachable is an outage nobody asked for. The metadata document is
/// still fetched (and cached) lazily for `/auth_metadata`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedAuthConfig {
    /// The OIDC issuer, e.g. `https://mas.example.org/`.
    pub issuer: String,
    /// The OAuth 2.0 token introspection endpoint. MAS serves it at
    /// `{issuer}/oauth2/introspect`.
    pub introspection_endpoint: String,
    /// Client credentials this server presents when introspecting.
    pub client_id: String,
    pub client_secret: String,
    /// The token the provider presents when calling *us* — MAS's
    /// `matrix.secret`, guarding the `/_synapse/mas/*` provisioning
    /// surface. Absent, that surface answers 404 and the provider
    /// cannot manage accounts here.
    #[serde(default)]
    pub homeserver_secret: Option<String>,
}

/// Which appservice registration files to load at startup.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppservicesConfig {
    /// Paths to YAML registration files, spec shape. Every file must load
    /// and validate or the server refuses to start — a bridge silently not
    /// registered looks exactly like a bridge receiving nothing.
    #[serde(default)]
    pub registrations: Vec<String>,
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
        // Both caps are the reason #36 asks for them: a zero here does not
        // mean "unlimited", it means every schedule is refused and the
        // dead-man's switch silently stops working. An operator who typed
        // it meant something else, so say so rather than starting.
        if self.delayed_events.max_delay_ms == 0 {
            return Err(ConfigError::Invalid {
                field: "delayed_events.max_delay_ms",
                message: "must be greater than zero; a zero cap refuses every delayed event"
                    .to_owned(),
            });
        }
        if self.delayed_events.max_per_room == 0 {
            return Err(ConfigError::Invalid {
                field: "delayed_events.max_per_room",
                message: "must be greater than zero; a zero cap refuses every delayed event"
                    .to_owned(),
            });
        }
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
        // One identity authority is the point of both modes; a server
        // with two would mint accounts nobody can say who owns.
        if self.auth.builtin_oidc && self.auth.delegated.is_some() {
            return Err(ConfigError::Invalid {
                field: "auth.builtin_oidc",
                message: "cannot be combined with auth.delegated — pick one identity authority"
                    .to_owned(),
            });
        }
        // Two credential schemes would mean the server picks one silently,
        // and an operator who configured both has already told us they are
        // unsure which their relay speaks. Refusing is the only answer that
        // does not leave calls failing for a reason nothing reports.
        if self.turn.shared_secret.is_some() && self.turn.username.is_some() {
            return Err(ConfigError::Invalid {
                field: "turn.shared_secret",
                message: "cannot be combined with turn.username — a relay takes \
                          time-limited credentials or a static pair, not both"
                    .to_owned(),
            });
        }
        // Relays configured with no way to authenticate to them would be
        // handed to clients that then cannot use them, and the call would
        // fail at connection time with nothing in this server's log.
        if !self.turn.uris.is_empty()
            && self.turn.shared_secret.is_none()
            && self.turn.username.is_none()
        {
            return Err(ConfigError::Invalid {
                field: "turn.uris",
                message: "relays are configured but no credentials are — set \
                          turn.shared_secret, or turn.username and turn.password"
                    .to_owned(),
            });
        }
        if self.turn.username.is_some() != self.turn.password.is_some() {
            return Err(ConfigError::Invalid {
                field: "turn.password",
                message: "turn.username and turn.password go together".to_owned(),
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
