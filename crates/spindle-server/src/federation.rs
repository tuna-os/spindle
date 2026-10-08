//! Federation identity: signing our requests, verifying theirs.
//!
//! The X-Matrix scheme is the root of all server-to-server trust: every
//! federation request carries a signature over `(method, uri, origin,
//! destination, content)` made with the origin's published ed25519 key.
//! Everything else federation does — accepting events, answering queries —
//! stands on this check, so it fails closed at every fork: an unparseable
//! header, an unfetchable key, a stale key, a destination that is not us,
//! all refuse rather than degrade.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use ruma::{CanonicalJsonObject, CanonicalJsonValue};
use serde_json::{Value, json};
use spindle_core::keys::{self};
use spindle_store::{FjallStore, ReadView, Store};

use crate::netguard::{Cidr, VettingResolver, permits};
use crate::signing::ServerKey;

mod srv;
use srv::Destination;

/// How long a fetched key document serves at most, whatever its own
/// `valid_until_ts` says. The spec's cap: a peer cannot mint a key valid
/// for years and have caches honour it — seven days is the ceiling, so a
/// compromised key ages out even if its owner claimed otherwise.
const MAX_KEY_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);

/// How long a failed key fetch is remembered before the origin is tried
/// again. Without it every miss refetched, so a stranger could make this
/// server connect to the same unreachable name as often as they could
/// send a header (#288). A minute bounds that at one connection per name
/// per minute, and a peer that was genuinely down retries within it.
const NEGATIVE_CACHE: Duration = Duration::from_secs(60);

/// How long a server's `.well-known/matrix/server` answer is used when the
/// response does not say (SPEC: server discovery, step 3: "24 hours is
/// recommended"), and the bounds a `Cache-Control: max-age` is held to.
const WELL_KNOWN_DEFAULT: Duration = Duration::from_secs(24 * 3600);
const WELL_KNOWN_MIN: Duration = Duration::from_secs(5 * 60);
const WELL_KNOWN_MAX: Duration = Duration::from_secs(48 * 3600);

/// How long a server whose `.well-known` could not be had is reached at
/// `name:8448` before its `.well-known` is asked again. Short, because a
/// peer whose web server was briefly down would otherwise be addressed at
/// a port nothing listens on for as long as this says; finite, because
/// every name a stranger puts in a room is one more fetch.
const WELL_KNOWN_FAILURE: Duration = Duration::from_secs(5 * 60);

/// The most of a `.well-known/matrix/server` body read. The document is
/// one short JSON object; anything larger is not one.
const WELL_KNOWN_MAX_BYTES: usize = 64 * 1024;

pub struct Federation {
    store: Arc<FjallStore>,
    server_name: String,
    key: Arc<ServerKey>,
    client: reqwest::Client,
    /// Where the outbox depth gauge is set; the server's one registry.
    metrics: Arc<crate::metrics::Metrics>,
    /// Peers reached by configuration rather than by name
    /// (`[federation] peers`), keyed by server name.
    peers: HashMap<String, Peer>,
    /// Fetch peer keys over plain http. For test rigs whose "servers" are
    /// loopback stubs; a production config leaving this on has disabled
    /// federation authentication in all but name, and the config comment
    /// says so.
    insecure_http: bool,
    /// Ranges a fetch may reach although they are not routable; every
    /// other non-global address is refused, by the resolver for names and
    /// by [`Federation::base_url`] for literals.
    allowed: Vec<Cidr>,
    /// Origins whose key fetch failed, and until when not to try again.
    negative: std::sync::Mutex<HashMap<String, Instant>>,
    /// EDUs waiting for the next transaction to each destination.
    ///
    /// In memory and nowhere else, deliberately: an EDU is ephemeral by
    /// contract, and one that failed to deliver is dropped rather than
    /// retried — stale typing redelivered late is a lie about the present,
    /// and whoever is still typing says so again within seconds.
    edu_queue: std::sync::Mutex<std::collections::HashMap<String, Vec<Value>>>,
    /// `[federation] enabled`. Off refuses every outbound request in
    /// [`Federation::base_url`], the one place each of them is addressed.
    enabled: bool,
    /// What each server name's `.well-known/matrix/server` said; shared
    /// with every [`Discovery`] handed out, so one fetch serves them all.
    delegations: Arc<Delegations>,
    /// The port `.well-known` is fetched from: 443, as the spec says. Tests
    /// that cannot bind 443 move it with [`Federation::with_well_known_port`].
    well_known_port: u16,
    destinations: Arc<std::sync::Mutex<HashMap<String, (Destination, Instant)>>>,
    srv_dns: Arc<std::sync::OnceLock<Result<hickory_resolver::TokioResolver, String>>>,
}

#[derive(Debug)]
pub enum FederationError {
    /// The request carries no usable X-Matrix authorization.
    Unauthorized(String),
    /// The origin's keys cannot be fetched or do not verify the signature.
    Refused(String),
    /// The peer answered, and the answer was no: a `4xx` with a Matrix
    /// error body, kept whole.
    ///
    /// Separate from [`Self::Refused`] because the two call for different
    /// things from a caller brokering a membership change. A resident's
    /// 403 to `make_join` or `make_knock` *is the room's answer* -- the
    /// join rule refused this user -- and the client asking most needs to
    /// be told exactly that. Folded into a transport error it reaches them
    /// as "no server could be reached", a transient fault inviting a retry
    /// of something that will be refused every time (#231). A `5xx`, a
    /// timeout, or an unparseable body stays [`Self::Refused`]: those are
    /// the peer failing to answer, not answering.
    Answered {
        status: u16,
        body: Value,
    },
    Storage(String),
}

/// A peer reached by configuration: see [`Federation::with_peers`].
#[derive(Clone, Debug)]
struct Peer {
    url: String,
    max_backoff: Option<Duration>,
}

/// What each server name's `.well-known/matrix/server` said, and until
/// when to believe it: `Some(server name)` for a delegation, `None` for no
/// usable answer (SRV discovery then uses the original name).
type Delegations = std::sync::Mutex<HashMap<String, (Option<String>, Instant)>>;

/// Where one request goes: see [`Federation::address`].
enum Address {
    /// Known without asking the network: a configured peer, a name with
    /// an explicit port, or an IP literal.
    Fixed(Destination),
    /// A bare hostname: `.well-known`, then SRV decide; `fallback`
    /// (`name:8448`) is used when neither provides a destination.
    Discover {
        name: String,
        fallback: String,
        discovery: Discovery,
    },
}

impl Address {
    /// The destination, discovering delegation and SRV if needed.
    async fn resolve(self) -> Result<Destination, FederationError> {
        match self {
            Self::Fixed(destination) => Ok(destination),
            Self::Discover {
                name,
                fallback,
                discovery,
            } => discovery.destination(&name, &fallback).await,
        }
    }
}

/// Server discovery, with what it needs and nothing else: no store, so it
/// can be held across the `.well-known` fetch by a task that must not keep
/// the store open (the outbox drain).
#[derive(Clone)]
struct Discovery {
    client: reqwest::Client,
    insecure_http: bool,
    allowed: Vec<Cidr>,
    delegations: Arc<Delegations>,
    well_known_port: u16,
    destinations: Arc<std::sync::Mutex<HashMap<String, (Destination, Instant)>>>,
    srv_dns: Arc<std::sync::OnceLock<Result<hickory_resolver::TokioResolver, String>>>,
}

impl Discovery {
    /// `base_url(name)`, with a literal address judged like a resolved one.
    fn vetted_url(&self, name: &str) -> Result<String, FederationError> {
        let url = base_url(name, self.insecure_http)?;
        if let Ok(server) = ruma::OwnedServerName::try_from(name)
            && let Ok(literal) = server.host().trim_matches(['[', ']']).parse::<IpAddr>()
            && !permits(&self.allowed, literal)
        {
            return Err(FederationError::Refused(format!(
                "{name} is not an address this server reaches"
            )));
        }
        Ok(url)
    }

    /// Where `name` delegated its federation traffic, if it did.
    ///
    /// The answer is cached for as long as the response allows (24 h by
    /// default, held between 5 min and 48 h), and a failure for
    /// [`WELL_KNOWN_FAILURE`], so a busy destination costs one fetch per
    /// period, not one per request.
    async fn delegation(&self, name: &str) -> Option<String> {
        let now = Instant::now();
        if let Some((delegated, until)) = self
            .delegations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            && *until > now
        {
            return delegated.clone();
        }
        let (delegated, ttl) = match self.fetch_well_known(name).await {
            Ok((server, ttl)) => match self.vetted_url(&server) {
                Ok(_) => (Some(server), ttl),
                Err(error) => {
                    tracing::debug!(%name, %server, %error, "unusable federation delegation");
                    (None, WELL_KNOWN_FAILURE)
                }
            },
            Err(error) => {
                tracing::debug!(%name, %error, "no federation delegation; checking SRV");
                (None, WELL_KNOWN_FAILURE)
            }
        };
        let mut delegations = self
            .delegations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Bounded: a stranger can name any number of servers, and each
        // one is an entry.
        if delegations.len() > 10_000 {
            delegations.retain(|_, (_, until)| *until > now);
        }
        delegations.insert(name.to_owned(), (delegated.clone(), now + ttl));
        delegated
    }

    async fn destination(
        &self,
        name: &str,
        fallback: &str,
    ) -> Result<Destination, FederationError> {
        let now = Instant::now();
        if let Some((destination, until)) = self
            .destinations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            && *until > now
        {
            return Ok(destination.clone());
        }
        let delegated = self.delegation(name).await;
        let delegation_until = self
            .delegations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .map_or(now, |(_, until)| *until);
        let logical = delegated.as_deref().unwrap_or(name);
        let server = ruma::OwnedServerName::try_from(logical)
            .map_err(|error| FederationError::Refused(error.to_string()))?;
        let (destination, until) = if server.port().is_none() && !server.is_ip_literal() {
            let resolver = self
                .srv_dns
                .get_or_init(|| {
                    hickory_resolver::Resolver::builder_tokio()
                        .and_then(|mut builder| {
                            builder.options_mut().ip_strategy =
                                hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
                            builder.build()
                        })
                        .map_err(|error| error.to_string())
                })
                .as_ref()
                .map_err(|error| FederationError::Refused(error.clone()))?;
            let (srv, until) = tokio::time::timeout(
                Duration::from_secs(10),
                srv::resolve(resolver, logical, &self.allowed, self.insecure_http),
            )
            .await
            .map_err(|_| FederationError::Refused("SRV discovery timed out".to_owned()))??;
            let url = if delegated.is_some() {
                self.vetted_url(logical)?
            } else {
                fallback.to_owned()
            };
            (
                srv.unwrap_or_else(|| {
                    Destination::fixed(url, Some(logical.to_owned()), self.client.clone())
                }),
                until,
            )
        } else {
            (
                Destination::fixed(
                    self.vetted_url(logical)?,
                    Some(logical.to_owned()),
                    self.client.clone(),
                ),
                now + WELL_KNOWN_MIN,
            )
        };
        let mut cache = self
            .destinations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A cached SRV destination owns TLS connection pools. Bound their
        // total count, rather than treating a hundred-target answer like
        // one entry with a negligible memory cost.
        cache.remove(name);
        cache.retain(|_, (_, until)| *until > now);
        while cache.values().map(|(d, _)| d.pool_size()).sum::<usize>() + destination.pool_size()
            > 128
        {
            let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, until))| *until)
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            cache.remove(&oldest);
        }
        // A DNS answer cannot extend a delegation beyond its own expiry.
        cache.insert(
            name.to_owned(),
            (destination.clone(), until.min(delegation_until)),
        );
        Ok(destination)
    }

    /// GET `https://<name>/.well-known/matrix/server` and return the
    /// delegated server name and how long to believe it.
    ///
    /// The fetch goes through the same vetting resolver and redirect
    /// policy as every other federation request, so a name that resolves
    /// inward, or a redirect into a private range, is refused here too.
    async fn fetch_well_known(&self, name: &str) -> Result<(String, Duration), FederationError> {
        let scheme = if self.insecure_http { "http" } else { "https" };
        let url = if self.well_known_port == 443 && !self.insecure_http {
            format!("{scheme}://{name}/.well-known/matrix/server")
        } else {
            format!(
                "{scheme}://{name}:{}/.well-known/matrix/server",
                self.well_known_port
            )
        };
        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("well-known: {error}")))?;
        if !response.status().is_success() {
            return Err(FederationError::Refused(format!(
                "well-known: {}",
                response.status()
            )));
        }
        let ttl = well_known_ttl(response.headers().get(reqwest::header::CACHE_CONTROL));
        if response
            .content_length()
            .is_some_and(|length| length > WELL_KNOWN_MAX_BYTES as u64)
        {
            return Err(FederationError::Refused("well-known: too large".to_owned()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("well-known body: {error}")))?;
        if body.len() > WELL_KNOWN_MAX_BYTES {
            return Err(FederationError::Refused("well-known: too large".to_owned()));
        }
        Ok((parse_well_known(&body)?, ttl))
    }
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(why) => write!(formatter, "unauthorized: {why}"),
            Self::Refused(why) => write!(formatter, "refused: {why}"),
            Self::Answered { status, body } => write!(formatter, "answered {status}: {body}"),
            Self::Storage(why) => write!(formatter, "storage: {why}"),
        }
    }
}

/// A peer's non-success response, sorted into the two errors above.
///
/// `what` names the request for the message, e.g. `make_join`.
fn peer_refusal(
    destination: &str,
    what: &str,
    status: reqwest::StatusCode,
    body: Value,
) -> FederationError {
    if status.is_client_error() && body.is_object() {
        FederationError::Answered {
            status: status.as_u16(),
            body,
        }
    } else {
        FederationError::Refused(format!("{destination} refused {what}: {status} {body}"))
    }
}

/// A parsed `Authorization: X-Matrix …` header.
#[derive(Debug, PartialEq)]
pub struct XMatrix {
    pub origin: String,
    pub destination: Option<String>,
    pub key_id: String,
    pub signature: String,
}

impl Federation {
    /// # Errors
    ///
    /// Returns [`FederationError::Refused`] if an `allow_internal` entry
    /// does not parse: a config error, surfaced at startup.
    pub fn new(
        store: Arc<FjallStore>,
        server_name: impl Into<String>,
        key: Arc<ServerKey>,
        insecure_http: bool,
        allow_internal: &[String],
    ) -> Result<Self, FederationError> {
        let allowed =
            crate::netguard::parse_allow_list(allow_internal).map_err(FederationError::Refused)?;
        // Every name this client connects to resolves through the vetting
        // resolver, so a peer whose name points inward is refused before a
        // socket is opened. Literal IPs never reach DNS; `base_url` vets
        // the first hop and the redirect policy every hop after it (#312):
        // a public peer that answers `302 Location: http://169.254.169.254/`
        // would otherwise be followed straight past the resolver.
        let client = client_builder(&allowed)
            .build()
            .map_err(|error| FederationError::Refused(error.to_string()))?;
        Ok(Self {
            store,
            server_name: server_name.into(),
            key,
            client,
            metrics: Arc::default(),
            peers: HashMap::new(),
            insecure_http,
            allowed,
            negative: std::sync::Mutex::new(HashMap::new()),
            edu_queue: std::sync::Mutex::new(std::collections::HashMap::new()),
            enabled: true,
            delegations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            well_known_port: 443,
            destinations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            srv_dns: Arc::new(std::sync::OnceLock::new()),
        })
    }

    /// Fetch `.well-known/matrix/server` from `port` instead of 443.
    ///
    /// For tests, which cannot bind 443; with `insecure_http` the fetch is
    /// plain http as well. A deployment has no reason to set this.
    #[doc(hidden)]
    #[must_use]
    pub fn with_well_known_port(mut self, port: u16) -> Self {
        self.well_known_port = port;
        self
    }

    /// Federate or not (`[federation] enabled`). Disabled, every outbound
    /// request is refused before its destination is resolved.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Whether this server federates at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Record into `metrics` rather than a registry of this client's own.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// The registry this client records into.
    #[must_use]
    pub fn metrics(&self) -> &crate::metrics::Metrics {
        &self.metrics
    }

    /// Reach the named peers at their configured URLs rather than by
    /// resolving their names (`[federation] peers`).
    #[must_use]
    pub fn with_peers(mut self, peers: &BTreeMap<String, crate::config::PeerConfig>) -> Self {
        self.peers = peers
            .iter()
            .map(|(name, peer)| {
                (
                    name.clone(),
                    Peer {
                        url: peer.url.trim_end_matches('/').to_owned(),
                        max_backoff: peer.max_backoff_ms.map(Duration::from_millis),
                    },
                )
            })
            .collect();
        self
    }

    /// The longest the outbox waits between attempts at `destination`,
    /// when the operator has said how patient to be with it.
    #[must_use]
    pub fn peer_max_backoff(&self, destination: &str) -> Option<Duration> {
        self.peers
            .get(destination)
            .and_then(|peer| peer.max_backoff)
    }

    /// The URL a request to `name` goes to, or a refusal.
    async fn request(
        &self,
        method: reqwest::Method,
        name: &str,
        uri: &str,
    ) -> Result<srv::Request, FederationError> {
        Ok(self.address(name)?.resolve().await?.request(method, uri))
    }

    /// Where a request to `name` goes, as far as can be said without the
    /// network: a refusal, a fixed URL, or a name whose `.well-known` must
    /// be asked first ([`Address::resolve`]).
    ///
    /// Grammar first (#286), then, for a name that is a literal address,
    /// the same judgement the resolver applies to a hostname: a literal
    /// never touches DNS, so this is the only place it can be vetted.
    /// Synchronous and free of the store, so the outbox can address a
    /// transaction while it plans and resolve it after it lets go.
    fn address(&self, name: &str) -> Result<Address, FederationError> {
        // Every outbound request is addressed here, so this is the one
        // switch that keeps a dark copy of a live server off the network:
        // refused before a name is resolved or a socket opened.
        if !self.enabled {
            return Err(FederationError::Refused(format!(
                "federation is disabled on this server; not contacting {name}"
            )));
        }
        // A configured peer goes where the operator said, and its host is
        // judged the same way a name's would be: a literal here, a hostname
        // by the resolver when the connection is made.
        if let Some(peer) = self.peers.get(name) {
            if let Some(host) = reqwest::Url::parse(&peer.url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                && let Ok(literal) = host.trim_matches(['[', ']']).parse::<IpAddr>()
                && !permits(&self.allowed, literal)
            {
                return Err(FederationError::Refused(format!(
                    "{name} is configured at an address this server does not reach"
                )));
            }
            return Ok(Address::Fixed(Destination::fixed(
                peer.url.clone(),
                None,
                self.client.clone(),
            )));
        }
        let discovery = self.discovery();
        let url = discovery.vetted_url(name)?;
        // Server discovery (SPEC: server-server API, "Resolving server
        // names"): a hostname with no port may have delegated its
        // federation traffic with `.well-known/matrix/server`. An IP
        // literal or an explicit port is used as it is.
        //
        // A test rig on plain http has nothing on 443 to ask, so it skips
        // discovery unless a test moved the port.
        let discover = !self.insecure_http || self.well_known_port != 443;
        if discover
            && let Ok(server) = ruma::OwnedServerName::try_from(name)
            && server.port().is_none()
            && !server.is_ip_literal()
        {
            return Ok(Address::Discover {
                name: name.to_owned(),
                fallback: url,
                discovery,
            });
        }
        Ok(Address::Fixed(Destination::fixed(
            url,
            Some(name.to_owned()),
            self.client.clone(),
        )))
    }

    fn discovery(&self) -> Discovery {
        Discovery {
            client: self.client.clone(),
            insecure_http: self.insecure_http,
            allowed: self.allowed.clone(),
            delegations: Arc::clone(&self.delegations),
            well_known_port: self.well_known_port,
            destinations: Arc::clone(&self.destinations),
            srv_dns: Arc::clone(&self.srv_dns),
        }
    }

    /// Queue one EDU for `destination`'s next transaction.
    ///
    /// Bounded per destination: past a hundred waiting, the oldest are
    /// dropped — the spec caps a transaction at a hundred EDUs, and an
    /// unreachable peer must not grow an unbounded queue of claims about
    /// a present it keeps missing.
    pub fn queue_edu(&self, destination: &str, edu: Value) {
        let mut queue = self
            .edu_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = queue.entry(destination.to_owned()).or_default();
        pending.push(edu);
        if pending.len() > 100 {
            let excess = pending.len() - 100;
            pending.drain(..excess);
        }
    }

    /// Take everything queued for `destination`, leaving it empty.
    #[must_use]
    pub fn take_edus(&self, destination: &str) -> Vec<Value> {
        self.edu_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(destination)
            .unwrap_or_default()
    }

    /// The destinations with EDUs waiting.
    #[must_use]
    pub fn edu_destinations(&self) -> Vec<String> {
        self.edu_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Sign an outbound request, returning the `Authorization` header value.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request JSON cannot be built or
    /// signed — which would mean our own key is unusable, so nothing sent.
    pub fn sign_request(
        &self,
        method: &str,
        uri: &str,
        destination: &str,
        content: Option<&Value>,
    ) -> Result<String, FederationError> {
        let mut object = request_object(method, uri, &self.server_name, destination, content)?;
        ruma::signatures::sign_json(&self.server_name, self.key.pair(), &mut object)
            .map_err(|error| FederationError::Refused(error.to_string()))?;
        let signature = object
            .get("signatures")
            .and_then(|s| s.as_object())
            .and_then(|s| s.get(&self.server_name))
            .and_then(|s| s.as_object())
            .and_then(|s| s.get(&self.key.key_id()))
            .and_then(|s| s.as_str())
            .ok_or_else(|| FederationError::Refused("signing produced no signature".to_owned()))?
            .to_owned();
        Ok(format!(
            "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"{}\",sig=\"{signature}\"",
            self.server_name,
            self.key.key_id(),
        ))
    }

    /// Verify an inbound request's X-Matrix authorization, returning the
    /// authenticated origin server name.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when anything along the chain fails: no
    /// header, a destination that is not us, unfetchable origin keys, or a
    /// signature that does not verify. The caller turns all of these into
    /// 401 `M_UNAUTHORIZED` — a federation peer gets no diagnostic gradient
    /// to probe.
    pub async fn verify_request(
        &self,
        authorization: Option<&str>,
        method: &str,
        uri: &str,
        content: Option<&Value>,
    ) -> Result<String, FederationError> {
        let header = authorization
            .ok_or_else(|| FederationError::Unauthorized("no authorization".to_owned()))?;
        let parsed = parse_x_matrix(header)?;
        // A missing destination is tolerated (older implementations omit
        // it); a present one must name us, or this is a replayed request
        // that was signed for somebody else.
        if let Some(destination) = &parsed.destination
            && destination != &self.server_name
        {
            return Err(FederationError::Unauthorized(format!(
                "request signed for {destination}, we are {}",
                self.server_name
            )));
        }

        let verify_key = self.server_key(&parsed.origin, &parsed.key_id).await?;

        let mut object = request_object(
            method,
            uri,
            &parsed.origin,
            // The signed object carries the destination the *origin* wrote.
            parsed.destination.as_deref().unwrap_or(&self.server_name),
            content,
        )?;
        object.insert(
            "signatures".to_owned(),
            CanonicalJsonValue::try_from(json!({
                parsed.origin.clone(): { parsed.key_id.clone(): parsed.signature.clone() }
            }))
            .map_err(|error| FederationError::Refused(error.to_string()))?,
        );

        let mut key_map = ruma::signatures::PublicKeyMap::new();
        key_map.entry(parsed.origin.clone()).or_default().insert(
            parsed.key_id.clone(),
            ruma::serde::Base64::parse(verify_key)
                .map_err(|error| FederationError::Refused(error.to_string()))?,
        );
        ruma::signatures::verify_json(&key_map, &object)
            .map_err(|error| FederationError::Unauthorized(format!("bad signature: {error}")))?;
        Ok(parsed.origin)
    }

    /// Every key the origin publishes, current and retired, for verifying
    /// whole events -- which may carry any key the origin held when it
    /// signed them. See [`PeerKeys`] for which key answers for which event.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the document cannot be fetched or is
    /// not credible.
    pub async fn peer_keys(&self, origin: &str) -> Result<PeerKeys, FederationError> {
        // A fetch-if-stale pass first: `server_key` refreshes the cache as
        // a side effect, and the throwaway id keeps "stale" and "missing"
        // from conflating.
        let _ = self.server_key(origin, "ed25519:_warm").await;
        let cache_key = server_keys_row(origin);
        let bytes = ReadView::get(self.store.as_ref(), &cache_key)
            .map_err(|error| FederationError::Storage(error.to_string()))?
            .ok_or_else(|| FederationError::Refused(format!("no keys for {origin}")))?;
        let cached: Value = serde_json::from_slice(&bytes)
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        let mut keys = PeerKeys::from_document(origin, &cached["document"])?;
        keys.valid_until = cached["fetched_valid_until"].as_u64();
        Ok(keys)
    }

    /// The origin's key document as it published it, from cache or
    /// fetched: what a notary hands on (`/_matrix/key/v2/query`), still
    /// carrying the origin's own signature so the asker can check it too.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the document cannot be fetched or is
    /// not credible.
    pub async fn peer_key_document(&self, origin: &str) -> Result<Value, FederationError> {
        let _ = self.server_key(origin, "ed25519:_warm").await;
        let bytes = ReadView::get(self.store.as_ref(), &server_keys_row(origin))
            .map_err(|error| FederationError::Storage(error.to_string()))?
            .ok_or_else(|| FederationError::Refused(format!("no keys for {origin}")))?;
        let cached: Value = serde_json::from_slice(&bytes)
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        Ok(cached["document"].clone())
    }

    /// The origin's public key (unpadded base64), from cache or fetched.
    async fn server_key(&self, origin: &str, key_id: &str) -> Result<String, FederationError> {
        let cache_key = server_keys_row(origin);
        let now = now_millis();
        if let Some(bytes) = ReadView::get(self.store.as_ref(), &cache_key)
            .map_err(|error| FederationError::Storage(error.to_string()))?
            && let Ok(cached) = serde_json::from_slice::<Value>(&bytes)
            && cached["fetched_valid_until"]
                .as_u64()
                .is_some_and(|until| now < until)
            && let Some(key) = cached["document"]["verify_keys"][key_id]["key"].as_str()
        {
            return Ok(key.to_owned());
        }

        // Cache miss, expiry, or an unknown key id (a peer that rotated):
        // all three refetch -- unless the last fetch failed a moment ago,
        // in which case the answer is still no and costs no connection.
        {
            let mut negative = self
                .negative
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let instant = Instant::now();
            negative.retain(|_, until| *until > instant);
            if negative.contains_key(origin) {
                return Err(FederationError::Refused(format!(
                    "{origin} could not be fetched from recently"
                )));
            }
        }
        let document = match self.fetch_key_document(origin).await {
            Ok(document) => document,
            Err(error) => {
                self.negative
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(origin.to_owned(), Instant::now() + NEGATIVE_CACHE);
                return Err(error);
            }
        };

        let claimed_until = document["valid_until_ts"].as_u64().unwrap_or(0);
        let ceiling = now + u64::try_from(MAX_KEY_VALIDITY.as_millis()).unwrap_or(u64::MAX);
        let capped = claimed_until.min(ceiling);
        let record = json!({ "document": document, "fetched_valid_until": capped });
        Store::put(
            self.store.as_ref(),
            &cache_key,
            record.to_string().as_bytes(),
        )
        .map_err(|error| FederationError::Storage(error.to_string()))?;

        record["document"]["verify_keys"][key_id]["key"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| FederationError::Unauthorized(format!("{origin} has no key {key_id}")))
    }
}

impl Federation {
    /// GET a peer's key document and check it vouches for itself.
    ///
    /// The name is resolved like every other destination
    /// ([`Federation::base_url`]): `.well-known` delegation first, then
    /// `name:8448`.
    async fn fetch_key_document(&self, origin: &str) -> Result<Value, FederationError> {
        let document: Value = self
            .request(reqwest::Method::GET, origin, "/_matrix/key/v2/server")
            .await?
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("key fetch: {error}")))?
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("key fetch body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("key document: {error}")))
            })?;

        // The document must be signed by the server it describes, with the
        // very key inside it — otherwise anyone on the path could hand us a
        // key of their own making.
        verify_self_signed(origin, &document)?;
        if document["server_name"].as_str() != Some(origin) {
            return Err(FederationError::Refused(
                "key document names a different server".to_owned(),
            ));
        }
        Ok(document)
    }
}

impl Federation {
    /// Ask a resident server for a join template — the client half of the
    /// handshake our own `make_join` route serves.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_make_join(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<Value, FederationError> {
        // Every version this server can actually join a room at, not one
        // literal. The resident answers with the room's real version and
        // refuses if it is absent from this list (#201 made it stop
        // guessing), so a hardcoded `ver=11` is this server declaring it
        // cannot speak a version it creates rooms at -- and it could not:
        // no Spindle server could federate into another's v12 room.
        let versions = crate::surface::ROOM_VERSIONS
            .iter()
            .map(|version| format!("ver={version}"))
            .collect::<Vec<_>>()
            .join("&");
        let uri = format!("/_matrix/federation/v1/make_join/{room_id}/{user_id}?{versions}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("make_join: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("make_join body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("make_join body: {error}")))
            })?;
        if !status.is_success() {
            return Err(peer_refusal(destination, "make_join", status, body));
        }
        Ok(body)
    }

    /// Ask a resident server for a knock template — the client half of the
    /// handshake our own `make_knock` route serves.
    ///
    /// Same version list as [`Self::remote_make_join`], for the same reason:
    /// the resident answers with the room's real version and refuses if this
    /// server did not name it. A refusal the resident chose comes back as
    /// [`FederationError::Answered`], because a 403 here is the room saying
    /// it does not take knocks, and the knocking client is owed that answer
    /// rather than a gateway error.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_make_knock(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<Value, FederationError> {
        let versions = crate::surface::ROOM_VERSIONS
            .iter()
            .map(|version| format!("ver={version}"))
            .collect::<Vec<_>>()
            .join("&");
        let uri = format!("/_matrix/federation/v1/make_knock/{room_id}/{user_id}?{versions}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("make_knock: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("make_knock body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("make_knock body: {error}")))
            })?;
        if !status.is_success() {
            return Err(peer_refusal(destination, "make_knock", status, body));
        }
        Ok(body)
    }

    /// Send the signed knock back — the client half of `send_knock`.
    ///
    /// What comes back is `knock_room_state`, not the room: a knock admits
    /// nobody, so there is no state block and no auth chain to seed from,
    /// only the stripped view the knocker is allowed to render while they
    /// wait to be answered. The resident re-authorizes the signed event, so
    /// a refusal here is still the room speaking and comes back as
    /// [`FederationError::Answered`].
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_send_knock(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        knock: &Value,
    ) -> Result<Value, FederationError> {
        let uri = format!(
            "/_matrix/federation/v1/send_knock/{room_id}/{}",
            path_segment(event_id)
        );
        let authorization = self.sign_request("PUT", &uri, destination, Some(knock))?;
        let response = self
            .request(reqwest::Method::PUT, destination, &uri)
            .await?
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(60))
            .body(knock.to_string())
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("send_knock: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("send_knock body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("send_knock body: {error}")))
            })?;
        if !status.is_success() {
            return Err(peer_refusal(destination, "send_knock", status, body));
        }
        Ok(body)
    }

    /// A signed request to a peer, answered as JSON. `body` makes it a
    /// POST; without one it is a GET.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or
    /// sent, or the peer refuses.
    async fn signed_json(
        &self,
        destination: &str,
        uri: &str,
        body: Option<&Value>,
        what: &'static str,
    ) -> Result<Value, FederationError> {
        self.signed_json_bounded(destination, uri, body, what, None)
            .await
    }

    async fn signed_json_bounded(
        &self,
        destination: &str,
        uri: &str,
        body: Option<&Value>,
        what: &'static str,
        maximum: Option<usize>,
    ) -> Result<Value, FederationError> {
        let method = if body.is_some() { "POST" } else { "GET" };
        let authorization = self.sign_request(method, uri, destination, body)?;
        let request = match body {
            Some(body) => self
                .request(reqwest::Method::POST, destination, uri)
                .await?
                .header("content-type", "application/json")
                .body(body.to_string()),
            None => self.request(reqwest::Method::GET, destination, uri).await?,
        };
        let mut response = request
            .header("authorization", authorization)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("{what}: {error}")))?;
        let status = response.status();
        let bytes: axum::body::Bytes = if let Some(maximum) = maximum {
            if response
                .content_length()
                .is_some_and(|length| length > maximum as u64)
            {
                return Err(FederationError::Refused(format!(
                    "{what} response is too large"
                )));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| FederationError::Refused(format!("{what} body: {error}")))?
            {
                if chunk.len() > maximum.saturating_sub(bytes.len()) {
                    return Err(FederationError::Refused(format!(
                        "{what} response is too large"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes.into()
        } else {
            response
                .bytes()
                .await
                .map_err(|error| FederationError::Refused(format!("{what} body: {error}")))?
        };
        let answer: Value = serde_json::from_slice(&bytes)
            .map_err(|error| FederationError::Refused(format!("{what} body: {error}")))?;
        if !status.is_success() {
            return Err(peer_refusal(destination, what, status, answer));
        }
        Ok(answer)
    }

    /// Fetch a bounded predecessor window. Returned PDUs still need event
    /// identity, signature and room authorization checks before storage.
    ///
    /// # Errors
    /// Returns [`FederationError`] for an invalid limit, a refused request,
    /// an oversized response, or an invalid response shape.
    pub async fn remote_missing_events(
        &self,
        destination: &str,
        room_id: &str,
        earliest: &[String],
        latest: &[String],
        limit: usize,
    ) -> Result<Vec<Value>, FederationError> {
        if !(1..=100).contains(&limit) {
            return Err(FederationError::Refused(
                "missing-event limit must be 1..=100".to_owned(),
            ));
        }
        let uri = format!(
            "/_matrix/federation/v1/get_missing_events/{}",
            path_segment(room_id)
        );
        let body = serde_json::json!({
            "earliest_events": earliest, "latest_events": latest,
            "limit": limit, "min_depth": 0,
        });
        let response = self
            .signed_json_bounded(
                destination,
                &uri,
                Some(&body),
                "get_missing_events",
                Some(16 * 1024 * 1024),
            )
            .await?;
        let events = response["events"].as_array().ok_or_else(|| {
            FederationError::Refused("get_missing_events response has no events array".to_owned())
        })?;
        if events.len() > limit || events.iter().any(|event| !event.is_object()) {
            return Err(FederationError::Refused(
                "get_missing_events returned an invalid event window".to_owned(),
            ));
        }
        Ok(events.clone())
    }

    /// Fetch history walking backwards from `from` (`GET /backfill`), for
    /// filling a recorded gap. Returned PDUs still need event identity,
    /// signature and room authorization checks before storage, and the
    /// caller keeps only the ones its walk actually asked for.
    ///
    /// # Errors
    /// Returns [`FederationError`] for an invalid request, a refusal, an
    /// oversized response, or an invalid response shape.
    pub async fn remote_backfill(
        &self,
        destination: &str,
        room_id: &str,
        from: &[String],
        limit: usize,
    ) -> Result<Vec<Value>, FederationError> {
        if !(1..=100).contains(&limit) || from.is_empty() || from.len() > 50 {
            return Err(FederationError::Refused(
                "backfill needs 1..=50 starting events and a limit of 1..=100".to_owned(),
            ));
        }
        // Built and dropped before the request: the serializer is not `Send`.
        let query = {
            let mut query = form_urlencoded::Serializer::new(String::new());
            for event_id in from {
                query.append_pair("v", event_id);
            }
            query.append_pair("limit", &limit.to_string());
            query.finish()
        };
        let uri = format!(
            "/_matrix/federation/v1/backfill/{}?{query}",
            path_segment(room_id),
        );
        let response = self
            .signed_json_bounded(destination, &uri, None, "backfill", Some(32 * 1024 * 1024))
            .await?;
        let pdus = response["pdus"].as_array().ok_or_else(|| {
            FederationError::Refused("backfill response has no pdus array".to_owned())
        })?;
        // A peer may include the starting events beside `limit` more; any
        // more than that is not a page.
        if pdus.len() > limit.saturating_add(from.len()) || pdus.iter().any(|pdu| !pdu.is_object())
        {
            return Err(FederationError::Refused(
                "backfill returned an invalid page".to_owned(),
            ));
        }
        Ok(pdus.clone())
    }

    /// Fetch one event body for dependency recovery. The requesting caller
    /// must verify its computed ID and signature against the requested ID.
    ///
    /// # Errors
    /// Returns [`FederationError`] if the peer refuses or returns anything
    /// other than one PDU in a bounded transaction response.
    pub async fn remote_event(
        &self,
        destination: &str,
        event_id: &str,
    ) -> Result<Value, FederationError> {
        let uri = format!("/_matrix/federation/v1/event/{}", path_segment(event_id));
        let response = self
            .signed_json_bounded(destination, &uri, None, "event", Some(16 * 1024 * 1024))
            .await?;
        let pdus = response["pdus"]
            .as_array()
            .filter(|pdus| pdus.len() == 1 && pdus[0].is_object())
            .ok_or_else(|| {
                FederationError::Refused("event response must contain exactly one PDU".to_owned())
            })?;
        Ok(pdus[0].clone())
    }

    /// Fetch the peer's auth chain. Bodies are untrusted until each event's
    /// identity, signature and auth dependencies have been checked.
    ///
    /// # Errors
    /// Returns [`FederationError`] if the request is refused or the response
    /// exceeds the byte budget or has an invalid auth chain.
    pub async fn remote_event_auth(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<Vec<Value>, FederationError> {
        let uri = format!(
            "/_matrix/federation/v1/event_auth/{}/{}",
            path_segment(room_id),
            path_segment(event_id)
        );
        let response = self
            .signed_json_bounded(
                destination,
                &uri,
                None,
                "event_auth",
                Some(16 * 1024 * 1024),
            )
            .await?;
        let events = response["auth_chain"]
            .as_array()
            .filter(|events| events.iter().all(Value::is_object))
            .ok_or_else(|| {
                FederationError::Refused("event_auth response has no valid auth chain".to_owned())
            })?;
        Ok(events.clone())
    }

    /// Fetch the IDs of state and auth events before a missing predecessor.
    /// The caller must fetch and validate the bodies before using that state.
    ///
    /// # Errors
    /// Returns [`FederationError`] for a refusal, an oversized response or
    /// invalid state/auth ID arrays.
    pub async fn remote_state_ids(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<Value, FederationError> {
        let encoded: String = form_urlencoded::byte_serialize(event_id.as_bytes()).collect();
        let uri = format!(
            "/_matrix/federation/v1/state_ids/{}?event_id={encoded}",
            path_segment(room_id),
        );
        let response = self
            .signed_json_bounded(destination, &uri, None, "state_ids", Some(16 * 1024 * 1024))
            .await?;
        for field in ["pdu_ids", "auth_chain_ids"] {
            if !response[field]
                .as_array()
                .is_some_and(|ids| ids.iter().all(Value::is_string))
            {
                return Err(FederationError::Refused(format!(
                    "state_ids response has no valid {field} array"
                )));
            }
        }
        Ok(response)
    }

    /// Ask a peer for its users' device keys (`user/keys/query`).
    ///
    /// # Errors
    ///
    /// As [`Self::signed_json`].
    pub async fn remote_keys_query(
        &self,
        destination: &str,
        device_keys: &serde_json::Map<String, Value>,
    ) -> Result<Value, FederationError> {
        self.signed_json(
            destination,
            "/_matrix/federation/v1/user/keys/query",
            Some(&serde_json::json!({ "device_keys": device_keys })),
            "keys/query",
        )
        .await
    }

    /// Claim one-time keys from a peer for its users (`user/keys/claim`).
    ///
    /// # Errors
    ///
    /// As [`Self::signed_json`].
    pub async fn remote_keys_claim(
        &self,
        destination: &str,
        one_time_keys: &serde_json::Map<String, Value>,
    ) -> Result<Value, FederationError> {
        self.signed_json(
            destination,
            "/_matrix/federation/v1/user/keys/claim",
            Some(&serde_json::json!({ "one_time_keys": one_time_keys })),
            "keys/claim",
        )
        .await
    }

    /// A peer's whole device list for one of its users (`user/devices`).
    ///
    /// # Errors
    ///
    /// As [`Self::signed_json`].
    pub async fn remote_user_devices(
        &self,
        destination: &str,
        user_id: &str,
    ) -> Result<Value, FederationError> {
        self.signed_json(
            destination,
            &format!("/_matrix/federation/v1/user/devices/{user_id}"),
            None,
            "user/devices",
        )
        .await
    }

    /// Resolve a room alias on the server that owns it — the client half
    /// of `query/directory`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_query_directory(
        &self,
        destination: &str,
        alias: &str,
    ) -> Result<Value, FederationError> {
        let encoded: String = form_urlencoded::byte_serialize(alias.as_bytes()).collect();
        let uri = format!("/_matrix/federation/v1/query/directory?room_alias={encoded}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("query/directory: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("directory body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("directory body: {error}")))
            })?;
        if !status.is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} refused query/directory: {status} {body}"
            )));
        }
        Ok(body)
    }

    /// Ask a peer for one of its users' profiles — the client half of
    /// `query/profile`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_query_profile(
        &self,
        destination: &str,
        user_id: &str,
    ) -> Result<Value, FederationError> {
        let encoded: String = form_urlencoded::byte_serialize(user_id.as_bytes()).collect();
        let uri = format!("/_matrix/federation/v1/query/profile?user_id={encoded}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("query/profile: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("profile body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("profile body: {error}")))
            })?;
        if !status.is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} refused query/profile: {status} {body}"
            )));
        }
        Ok(body)
    }

    /// Send the signed join back — the client half of `send_join`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_send_join(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        join: &Value,
    ) -> Result<Value, FederationError> {
        let uri = format!(
            "/_matrix/federation/v2/send_join/{room_id}/{}",
            path_segment(event_id)
        );
        let authorization = self.sign_request("PUT", &uri, destination, Some(join))?;
        let response = self
            .request(reqwest::Method::PUT, destination, &uri)
            .await?
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(60))
            .body(join.to_string())
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("send_join: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("send_join body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("send_join body: {error}")))
            })?;
        if !status.is_success() {
            return Err(peer_refusal(destination, "send_join", status, body));
        }
        Ok(body)
    }

    /// Ask the invited user's server to co-sign an invite — the client
    /// half of `v2/invite`.
    ///
    /// The body carries the signed invite event, the room version, and the
    /// stripped state the invited user may render the invite from. What
    /// comes back is the same event with the invitee's server's signature
    /// added, which is what makes the invite provable to every other
    /// server in the room.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses — a refusal here fails the invite, because an
    /// invite the target's server never co-signed is one its user will
    /// never see.
    pub async fn remote_invite(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        body: &Value,
    ) -> Result<Value, FederationError> {
        let uri = format!(
            "/_matrix/federation/v2/invite/{room_id}/{}",
            path_segment(event_id)
        );
        let authorization = self.sign_request("PUT", &uri, destination, Some(body))?;
        let response = self
            .request(reqwest::Method::PUT, destination, &uri)
            .await?
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(30))
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("invite: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("invite body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("invite body: {error}")))
            })?;
        if !status.is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} refused invite: {status} {body}"
            )));
        }
        Ok(body)
    }

    /// Ask the resident server for a leave template — the client half of
    /// `make_leave`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_make_leave(
        &self,
        destination: &str,
        room_id: &str,
        user_id: &str,
    ) -> Result<Value, FederationError> {
        let uri = format!("/_matrix/federation/v1/make_leave/{room_id}/{user_id}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("make_leave: {error}")))?;
        let status = response.status();
        let body: Value = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("make_leave body: {error}")))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|error| FederationError::Refused(format!("make_leave body: {error}")))
            })?;
        if !status.is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} refused make_leave: {status} {body}"
            )));
        }
        Ok(body)
    }

    /// Send the signed leave back — the client half of `send_leave`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer refuses.
    pub async fn remote_send_leave(
        &self,
        destination: &str,
        room_id: &str,
        event_id: &str,
        leave: &Value,
    ) -> Result<(), FederationError> {
        let uri = format!(
            "/_matrix/federation/v2/send_leave/{room_id}/{}",
            path_segment(event_id)
        );
        let authorization = self.sign_request("PUT", &uri, destination, Some(leave))?;
        let response = self
            .request(reqwest::Method::PUT, destination, &uri)
            .await?
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(30))
            .body(leave.to_string())
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("send_leave: {error}")))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.bytes().await.unwrap_or_default();
            return Err(FederationError::Refused(format!(
                "{destination} refused send_leave: {status} {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(())
    }

    /// Fetch a peer's media over authenticated federation (MSC3916),
    /// falling back to the legacy public endpoint for older peers.
    ///
    /// The modern response is `multipart/mixed`: a JSON metadata part, then
    /// the file. The legacy response is the file alone. Either way the
    /// caller gets `(content_type, filename, bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if neither endpoint yields the file, or
    /// the multipart body cannot be parsed.
    pub async fn remote_media_download(
        &self,
        destination: &str,
        media_id: &str,
    ) -> Result<(String, Option<String>, Vec<u8>), FederationError> {
        let uri = format!("/_matrix/federation/v1/media/download/{media_id}");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .request(reqwest::Method::GET, destination, &uri)
            .await?
            .header("authorization", authorization)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("media download: {error}")))?;
        if response.status().is_success() {
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = response
                .bytes()
                .await
                .map_err(|error| FederationError::Refused(format!("media body: {error}")))?;
            return parse_multipart_media(&content_type, &body);
        }
        let status = response.status();
        // `M_TOO_LARGE` is the peer's answer, not its failure to answer: a
        // peer that caps what it serves (a mesh homeserver at 256 KiB, say)
        // has said so, and the legacy endpoint would only say it again.
        let body: Value = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE || body["errcode"] == "M_TOO_LARGE" {
            return Err(FederationError::Answered {
                status: status.as_u16(),
                body,
            });
        }

        // Legacy fallback: the public v3 endpoint, no signature. Kept for
        // peers predating authenticated media; a 404 there is final.
        let legacy =
            format!("/_matrix/media/v3/download/{destination}/{media_id}?allow_redirect=false");
        let response = self
            .request(reqwest::Method::GET, destination, &legacy)
            .await?
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("legacy media: {error}")))?;
        if !response.status().is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} refused media {media_id}: {status} then {}",
                response.status()
            )));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let filename = response
            .headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok())
            .and_then(disposition_filename);
        let bytes = response
            .bytes()
            .await
            .map_err(|error| FederationError::Refused(format!("legacy media body: {error}")))?;
        Ok((content_type, filename, bytes.to_vec()))
    }

    /// Deliver one signed transaction to a peer.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed or sent,
    /// or the peer answers anything but success.
    pub async fn send_transaction(
        &self,
        destination: &str,
        txn_id: &str,
        body: &Value,
    ) -> Result<(), FederationError> {
        deliver(
            self.transaction_request(destination, txn_id, body)?,
            destination,
            &self.metrics,
        )
        .await
    }

    /// The signed request carrying one transaction, built but not sent.
    ///
    /// Split from the send so the outbox drain can build every request of
    /// a pass while it holds the store and the federation strongly, and
    /// send them once it has let go: what the builder carries is a client
    /// handle, the destination's address, a signature and the body, none of
    /// which the store's close waits on. A destination that must be looked
    /// up in its `.well-known` is looked up at send time.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the request cannot be signed, or the
    /// destination is not one this server reaches.
    fn transaction_request(
        &self,
        destination: &str,
        txn_id: &str,
        body: &Value,
    ) -> Result<PreparedTransaction, FederationError> {
        let uri = format!("/_matrix/federation/v1/send/{txn_id}");
        let authorization = self.sign_request("PUT", &uri, destination, Some(body))?;
        Ok(PreparedTransaction {
            address: self.address(destination)?,
            uri,
            authorization,
            body: body.to_string(),
        })
    }
}

/// One signed transaction, addressed but not yet resolved: the
/// destination's `.well-known` is asked (if it must be) when it is sent,
/// after the outbox has let go of the store.
struct PreparedTransaction {
    address: Address,
    uri: String,
    authorization: String,
    body: String,
}

/// Send one built transaction and read the peer's verdict, counting how it
/// ended and how long it took.
async fn deliver(
    prepared: PreparedTransaction,
    destination: &str,
    metrics: &crate::metrics::Metrics,
) -> Result<(), FederationError> {
    let started = Instant::now();
    let (result, outcome) = deliver_once(prepared, destination).await;
    metrics.observe_outbound_txn(result, started.elapsed());
    outcome
}

async fn deliver_once(
    prepared: PreparedTransaction,
    destination: &str,
) -> (crate::metrics::TxnResult, Result<(), FederationError>) {
    use crate::metrics::TxnResult;
    let destination_address = match prepared.address.resolve().await {
        Ok(address) => address,
        Err(error) => return (TxnResult::Error, Err(error)),
    };
    let response = match destination_address
        .request(reqwest::Method::PUT, &prepared.uri)
        .header("authorization", prepared.authorization)
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(30))
        .body(prepared.body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let result = if error.is_timeout() {
                TxnResult::Timeout
            } else {
                TxnResult::Error
            };
            return (
                result,
                Err(FederationError::Refused(format!("send: {error}"))),
            );
        }
    };
    if !response.status().is_success() {
        return (
            TxnResult::HttpError,
            Err(FederationError::Refused(format!(
                "{destination} answered {}",
                response.status()
            ))),
        );
    }
    (TxnResult::Success, Ok(()))
}

fn client_builder(allowed: &[Cidr]) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(VettingResolver {
            allowed: allowed.to_vec(),
        }))
        .redirect(crate::netguard::redirect_policy(
            allowed.to_vec(),
            "federatable",
        ))
}

/// One pending delivery: its store key and the PDU it carries.
type OutboxRow = (Vec<u8>, Vec<u8>);

/// One transaction a pass will send: where it goes, the rows it carries
/// -- deleted once the peer acknowledges -- and the request, or the reason
/// one could not be built, which backs the destination off like a refusal.
struct OutboundTransaction {
    destination: String,
    keys: Vec<Vec<u8>>,
    request: Result<PreparedTransaction, FederationError>,
}

/// Drain the outbound queue, forever.
///
/// A polling loop rather than a wakeup protocol: the scan of an empty
/// keyspace is a bounded prefix read, and the poll interval doubles as the
/// floor of the retry backoff. Rows are deleted only after the destination
/// acknowledged the transaction carrying them — a crash between send and
/// delete re-sends, and the transaction ID being derived from the first
/// row's sequence lets the peer's replay table absorb the duplicate.
///
/// Holds the store and the federation weakly and ends when they are gone,
/// for the reason `spawn_delivery_loops` gives. A pass upgrades them to
/// plan -- scan, group, sign -- and lets go before the first request is
/// sent, upgrading the store again for each acknowledgement. So neither
/// await this task can be cancelled at, the idle sleep or a send in
/// flight, finds it holding anything the store's close could wait on.
pub async fn drain_outbox(
    store: Weak<FjallStore>,
    federation: Weak<Federation>,
    retry_base: Duration,
) {
    let mut backoff: HashMap<String, (u32, Instant)> = HashMap::new();
    loop {
        tokio::time::sleep(
            retry_base
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
        )
        .await;
        let (transactions, metrics) = {
            let (Some(store), Some(federation)) = (store.upgrade(), federation.upgrade()) else {
                return;
            };
            // The registry is not something the store's close waits on,
            // so holding it across a send is as harmless as the request.
            (
                plan_transactions(&store, &federation, &backoff),
                Arc::clone(&federation.metrics),
            )
        };
        for OutboundTransaction {
            destination,
            keys,
            request,
        } in transactions
        {
            let sent = match request {
                Ok(request) => deliver(request, &destination, &metrics).await,
                Err(error) => {
                    metrics.observe_outbound_txn(crate::metrics::TxnResult::Error, Duration::ZERO);
                    Err(error)
                }
            };
            match sent {
                Ok(()) => {
                    // Acknowledged. The rows go through a fresh upgrade: the
                    // router may have gone while the request was in flight,
                    // and then the loop ends here and the rows wait for the
                    // next start to re-send them -- the at-least-once a
                    // crash between send and delete already promises.
                    let Some(store) = store.upgrade() else {
                        return;
                    };
                    for key in &keys {
                        let _ = Store::delete(store.as_ref(), key);
                    }
                    backoff.remove(&destination);
                }
                Err(error) => {
                    tracing::debug!("outbox to {destination}: {error}");
                    let failures = backoff.get(&destination).map_or(0, |(count, _)| *count) + 1;
                    let Some(federation) = federation.upgrade() else {
                        return;
                    };
                    let delay = backoff_delay(
                        retry_base,
                        failures,
                        federation.peer_max_backoff(&destination),
                    );
                    backoff.insert(destination, (failures, Instant::now() + delay));
                }
            }
        }
    }
}

/// How long to wait before the next attempt at a destination that has
/// failed `failures` times in a row.
///
/// Doubling from the base, capped at 64× -- about a minute at the default
/// base -- so an unreachable peer is retried often enough that its return
/// is noticed within a minute. A peer the operator has marked patient
/// (`[federation] peers` with `max_backoff_ms`) keeps doubling up to its
/// own cap instead: a homeserver on a phone, or a gateway on a venue
/// uplink, is expected to be dark for hours, and one connection attempt an
/// hour is the whole cost of waiting for it. Nothing is dropped in either
/// case; the rows wait in the outbox until the peer acknowledges them.
fn backoff_delay(retry_base: Duration, failures: u32, patient: Option<Duration>) -> Duration {
    match patient {
        Some(cap) => retry_base
            .saturating_mul(2_u32.saturating_pow(failures.min(30)))
            .min(cap),
        None => retry_base * 2_u32.saturating_pow(failures.min(6)),
    }
}

/// One pass's transactions: every destination owed one and not backing
/// off, its request signed and ready. Every read of the store and every
/// take from the EDU queue happens here, under the strong references the
/// caller holds for exactly this long; nothing here awaits.
fn plan_transactions(
    store: &FjallStore,
    federation: &Federation,
    backoff: &HashMap<String, (u32, Instant)>,
) -> Vec<OutboundTransaction> {
    let Ok(rows) = ReadView::scan_prefix(store, &keys::federation_outbox_all()) else {
        return Vec::new();
    };
    let mut by_destination: BTreeMap<String, Vec<OutboxRow>> = BTreeMap::new();
    for (key, value) in rows {
        if let Some(destination) = keys::federation_outbox_destination(&key) {
            by_destination
                .entry(destination)
                .or_default()
                .push((key, value));
        }
    }
    // A destination with only EDUs waiting still gets a transaction:
    // typing must not wait for the next event.
    for destination in federation.edu_destinations() {
        by_destination.entry(destination).or_default();
    }
    // The pass already holds the whole picture, so the gauge is set
    // from it rather than counted separately — a second traversal
    // could disagree with the one that actually delivers.
    federation.metrics().set_federation_queue(
        &by_destination
            .iter()
            .map(|(destination, rows)| (destination.clone(), rows.len() as u64))
            .collect::<Vec<_>>(),
    );
    let mut transactions = Vec::new();
    for (destination, rows) in by_destination {
        if let Some((_, until)) = backoff.get(&destination)
            && *until > Instant::now()
        {
            continue;
        }
        // At most fifty PDUs per transaction, by spec; the rest wait
        // for the next pass.
        let batch: Vec<_> = rows.into_iter().take(50).collect();
        let pdus: Vec<Value> = batch
            .iter()
            .filter_map(|(_, value)| serde_json::from_slice(value).ok())
            .collect();
        // EDUs ride whatever transaction goes out next; on failure they
        // are dropped, never retried — a stale ephemeral redelivered
        // late is a lie about the present.
        let edus = federation.take_edus(&destination);
        if pdus.is_empty() && edus.is_empty() {
            continue;
        }
        let txn_id = if let Some((key, _)) = batch.first() {
            let first_seq = key
                .get(key.len() - 8..)
                .and_then(|bytes| bytes.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            // Deterministic by content, not by attempt: a retry after a
            // crash reuses the same ID, which is what makes redelivery
            // a no-op on the peer.
            format!("o{first_seq}")
        } else {
            // EDU-only: fire-once by design, so uniqueness is all the
            // ID owes anyone.
            static EDU_TXN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "e{}-{}",
                now_millis(),
                EDU_TXN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        };
        let mut body = serde_json::json!({
            "origin": federation.server_name,
            "origin_server_ts": now_millis(),
            "pdus": pdus,
        });
        if !edus.is_empty() {
            body["edus"] = Value::Array(edus);
        }
        let request = federation.transaction_request(&destination, &txn_id, &body);
        transactions.push(OutboundTransaction {
            destination,
            keys: batch.into_iter().map(|(key, _)| key).collect(),
            request,
        });
    }
    transactions
}

/// The object the X-Matrix signature covers.
fn request_object(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&Value>,
) -> Result<CanonicalJsonObject, FederationError> {
    let mut value = json!({
        "method": method,
        "uri": uri,
        "origin": origin,
        "destination": destination,
    });
    if let Some(content) = content {
        value["content"] = content.clone();
    }
    match CanonicalJsonValue::try_from(value) {
        Ok(CanonicalJsonValue::Object(object)) => Ok(object),
        _ => Err(FederationError::Refused(
            "request cannot be canonicalized".to_owned(),
        )),
    }
}

/// Check a `/key/v2/server` document's self-signature, using the key the
/// document itself carries.
/// A peer's published signing keys, split the way the spec splits them.
///
/// `verify_keys` are what the peer signs with now. `old_verify_keys` are
/// keys it has retired, each with the `expired_ts` at which it stopped: an
/// event the peer signed before that moment still verifies with the retired
/// key, and one it claims to have signed after it does not -- otherwise a
/// rotation would change nothing (#296). A retired key published without an
/// `expired_ts` is not used at all: a key that keeps working forever is a
/// rotation that did not happen, and refusing is the safe reading of a
/// malformed entry.
///
/// Request signatures (`X-Matrix`) are checked against current keys only,
/// in [`Federation::server_key`]: a request is made now, and a key the peer
/// has retired has no business signing one.
#[derive(Clone, Debug, Default)]
pub struct PeerKeys {
    origin: String,
    current: BTreeMap<String, ruma::serde::Base64>,
    retired: BTreeMap<String, (ruma::serde::Base64, u64)>,
    /// Keys of *other* servers that must also verify the event -- the
    /// countersignature on a restricted join is ours, not the peer's.
    vouched: ruma::signatures::PublicKeyMap,
    /// How long the current keys answer for an event, for the versions
    /// that enforce it (v5+): the document's `valid_until_ts` capped at
    /// seven days after the fetch. `None` when unknown.
    valid_until: Option<u64>,
}

impl PeerKeys {
    fn from_document(origin: &str, document: &Value) -> Result<Self, FederationError> {
        let mut keys = Self {
            origin: origin.to_owned(),
            ..Self::default()
        };
        if let Some(entries) = document["verify_keys"].as_object() {
            for (key_id, entry) in entries {
                if let Some(key) = entry["key"].as_str() {
                    keys.current.insert(key_id.clone(), parse_key(key)?);
                }
            }
        }
        if let Some(entries) = document["old_verify_keys"].as_object() {
            for (key_id, entry) in entries {
                if let (Some(key), Some(expired_ts)) =
                    (entry["key"].as_str(), entry["expired_ts"].as_u64())
                {
                    keys.retired
                        .insert(key_id.clone(), (parse_key(key)?, expired_ts));
                }
            }
        }
        Ok(keys)
    }

    /// The map ruma verifies against, for an event that says it was signed
    /// at `origin_server_ts`: every current key, plus each retired key whose
    /// expiry is after that moment. An event with no timestamp gets current
    /// keys only.
    ///
    /// `enforce_key_validity` is room version 5's rule, kept by every later
    /// version: a current key answers only for events signed no later than
    /// the document's `valid_until_ts` (capped at seven days after it was
    /// fetched, which is what the cache stores). Versions 1 to 4 do not
    /// have the rule, and an old event there still verifies with a key
    /// whose document has lapsed.
    #[must_use]
    pub fn map_for(
        &self,
        origin_server_ts: Option<u64>,
        enforce_key_validity: bool,
    ) -> ruma::signatures::PublicKeyMap {
        let at = origin_server_ts.unwrap_or(u64::MAX);
        let lapsed = enforce_key_validity
            && origin_server_ts.is_some()
            && self.valid_until.is_some_and(|until| at > until);
        let mut set: ruma::signatures::PublicKeySet = if lapsed {
            ruma::signatures::PublicKeySet::new()
        } else {
            self.current.clone()
        };
        for (key_id, (key, expired_ts)) in &self.retired {
            if at < *expired_ts {
                set.entry(key_id.clone()).or_insert_with(|| key.clone());
            }
        }
        let mut map = self.vouched.clone();
        map.insert(self.origin.clone(), set);
        map
    }

    /// Add a key of another server, for an event that server also signed.
    pub fn vouch(&mut self, server: String, key_id: String, key: ruma::serde::Base64) {
        self.vouched.entry(server).or_default().insert(key_id, key);
    }
}

/// An identifier as one path segment of a federation URL.
///
/// A room v3 event ID is standard base64 and may contain `/`, which would
/// otherwise split the segment and send the request to a route that does
/// not exist. Only the characters that change a path's meaning are
/// escaped, so every ID from v4 on (URL-safe) and every v1/v2 ID goes out
/// byte for byte as it always did -- the request signature covers the URI,
/// and a needless change to it is a change both sides must agree on.
pub(crate) fn path_segment(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for character in id.chars() {
        match character {
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            other => out.push(other),
        }
    }
    out
}

fn parse_key(key: &str) -> Result<ruma::serde::Base64, FederationError> {
    ruma::serde::Base64::parse(key).map_err(|error| FederationError::Refused(error.to_string()))
}

fn verify_self_signed(origin: &str, document: &Value) -> Result<(), FederationError> {
    let Some(verify_keys) = document["verify_keys"].as_object() else {
        return Err(FederationError::Refused("no verify_keys".to_owned()));
    };
    let mut key_map = ruma::signatures::PublicKeyMap::new();
    let entry = key_map.entry(origin.to_owned()).or_default();
    for (key_id, key) in verify_keys {
        if let Some(key) = key["key"].as_str() {
            entry.insert(
                key_id.clone(),
                ruma::serde::Base64::parse(key)
                    .map_err(|error| FederationError::Refused(error.to_string()))?,
            );
        }
    }
    let Ok(CanonicalJsonValue::Object(object)) = CanonicalJsonValue::try_from(document.clone())
    else {
        return Err(FederationError::Refused(
            "unreadable key document".to_owned(),
        ));
    };
    ruma::signatures::verify_json(&key_map, &object)
        .map_err(|error| FederationError::Refused(format!("key document signature: {error}")))
}

/// The URL a server name resolves to, before any request path.
///
/// A name with no explicit port speaks federation on 8448 (SPEC: server
/// discovery's final fallback), not 443 — `https://hs1/` would knock on a
/// door nothing is behind. `.well-known` delegation is resolved before this
/// is reached ([`Federation::base_url`]); SRV records are not.
/// Where requests to `name` go, refusing anything that is not a server name.
///
/// The name is never this server's own. It comes from a peer's X-Matrix
/// header, from a room's member list, or from a client's `server_name`
/// path segment, and it is pasted into a URL. Without this gate a header
/// reading `origin="127.0.0.1:6379/x?"` is a request this server makes on
/// a stranger's behalf, to a host, port and path of their choosing, from
/// inside whatever network it sits in, before a single signature has been
/// checked -- because checking the signature is what the fetch is for.
///
/// A Matrix server name is a hostname or IP literal and an optional port,
/// nothing else. ruma's validator is the spec's grammar, so this is not a
/// second opinion on what a server name is; it is the first time one is
/// asked for here.
fn base_url(name: &str, insecure_http: bool) -> Result<String, FederationError> {
    let server = ruma::OwnedServerName::try_from(name).map_err(|error| {
        FederationError::Refused(format!("not a server name {name:?}: {error}"))
    })?;
    let scheme = if insecure_http { "http" } else { "https" };
    // The port question is asked of the parsed name, not of the string: a
    // bare IPv6 literal contains colons and still has no port.
    Ok(match server.port() {
        Some(_) => format!("{scheme}://{name}"),
        None => format!("{scheme}://{name}:8448"),
    })
}

/// The delegated server name in a `.well-known/matrix/server` body.
///
/// The value must itself be a server name (hostname or IP literal, with
/// an optional port): it becomes the host and port of every request that
/// follows, so it gets the same grammar check as a name from a header.
fn parse_well_known(body: &[u8]) -> Result<String, FederationError> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|error| FederationError::Refused(format!("well-known: {error}")))?;
    let server = document["m.server"]
        .as_str()
        .ok_or_else(|| FederationError::Refused("well-known has no m.server".to_owned()))?;
    ruma::OwnedServerName::try_from(server)
        .map(|server| server.to_string())
        .map_err(|error| {
            FederationError::Refused(format!("well-known m.server {server:?}: {error}"))
        })
}

/// How long to believe a `.well-known` answer, from its `Cache-Control`.
///
/// `max-age` is honoured within [`WELL_KNOWN_MIN`]..[`WELL_KNOWN_MAX`];
/// `no-store`/`no-cache` mean the minimum; anything else the default.
fn well_known_ttl(cache_control: Option<&reqwest::header::HeaderValue>) -> Duration {
    let Some(value) = cache_control.and_then(|value| value.to_str().ok()) else {
        return WELL_KNOWN_DEFAULT;
    };
    for directive in value.split(',').map(str::trim) {
        let directive = directive.to_ascii_lowercase();
        if directive == "no-store" || directive == "no-cache" {
            return WELL_KNOWN_MIN;
        }
        if let Some(seconds) = directive
            .strip_prefix("max-age=")
            .and_then(|seconds| seconds.trim_matches('"').parse::<u64>().ok())
        {
            return Duration::from_secs(seconds).clamp(WELL_KNOWN_MIN, WELL_KNOWN_MAX);
        }
    }
    WELL_KNOWN_DEFAULT
}

/// Pull `filename="..."` (or bare filename=) out of a Content-Disposition.
fn disposition_filename(header: &str) -> Option<String> {
    let (_, rest) = header.split_once("filename=")?;
    let rest = rest.trim();
    let name = rest
        .strip_prefix('"')
        .and_then(|inner| inner.split_once('"').map(|(name, _)| name))
        .unwrap_or_else(|| rest.split(';').next().unwrap_or(rest).trim());
    (!name.is_empty()).then(|| name.to_owned())
}

/// Take the file part out of an MSC3916 `multipart/mixed` media response.
///
/// The format is fixed by the MSC: a JSON metadata part first, the file
/// second. Parsed by boundary split rather than a multipart crate — two
/// known parts with known roles do not need a streaming parser, and the
/// body is already bounded by the media size cap.
fn parse_multipart_media(
    content_type: &str,
    body: &[u8],
) -> Result<(String, Option<String>, Vec<u8>), FederationError> {
    let boundary = content_type
        .split(';')
        .find_map(|param| param.trim().strip_prefix("boundary="))
        .map(|value| value.trim_matches('"').to_owned())
        .ok_or_else(|| {
            FederationError::Refused(format!("media response is not multipart: {content_type}"))
        })?;
    let marker = format!("--{boundary}");
    let marker = marker.as_bytes();
    // Split the body at each boundary marker.
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut cursor = 0;
    while let Some(at) = find(&body[cursor..], marker) {
        let start = cursor + at + marker.len();
        // The final marker is `--boundary--`.
        if body[start..].starts_with(b"--") {
            break;
        }
        let from = start
            + body[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(0, |i| i + 1);
        let end = find(&body[from..], marker).map_or(body.len(), |i| from + i);
        parts.push(&body[from..end]);
        cursor = end;
    }
    // The file is the last part: metadata first, file second, by the MSC.
    let part = parts
        .last()
        .ok_or_else(|| FederationError::Refused("multipart media had no parts".to_owned()))?;
    let split = find(part, b"\r\n\r\n")
        .map(|i| (&part[..i], &part[i + 4..]))
        .or_else(|| find(part, b"\n\n").map(|i| (&part[..i], &part[i + 2..])));
    let (headers, content) = split
        .ok_or_else(|| FederationError::Refused("multipart part had no header break".to_owned()))?;
    let headers = String::from_utf8_lossy(headers);
    let mut content_type = "application/octet-stream".to_owned();
    let mut filename = None;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-type" => value.trim().clone_into(&mut content_type),
            "content-disposition" => filename = disposition_filename(value),
            _ => {}
        }
    }
    // The part ends with the CRLF that precedes the next boundary.
    let content = content.strip_suffix(b"\r\n").unwrap_or(content);
    Ok((content_type, filename, content.to_vec()))
}

/// First position of `needle` in `haystack`, if any.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parse `X-Matrix origin="…",destination="…",key="…",sig="…"`.
///
/// # Errors
///
/// Returns [`FederationError::Unauthorized`] on any malformed header —
/// there is no lenient mode for the credential everything trusts.
pub fn parse_x_matrix(header: &str) -> Result<XMatrix, FederationError> {
    let rest = header
        .strip_prefix("X-Matrix ")
        .ok_or_else(|| FederationError::Unauthorized("not X-Matrix".to_owned()))?;
    let mut origin = None;
    let mut destination = None;
    let mut key_id = None;
    let mut signature = None;
    for part in rest.split(',') {
        let (name, value) = part
            .trim()
            .split_once('=')
            .ok_or_else(|| FederationError::Unauthorized("malformed parameter".to_owned()))?;
        let value = value.trim_matches('"').to_owned();
        match name {
            "origin" => origin = Some(value),
            "destination" => destination = Some(value),
            "key" => key_id = Some(value),
            "sig" => signature = Some(value),
            // Unknown parameters are ignored, per the header's extensibility.
            _ => {}
        }
    }
    Ok(XMatrix {
        origin: origin.ok_or_else(|| FederationError::Unauthorized("no origin".to_owned()))?,
        destination,
        key_id: key_id.ok_or_else(|| FederationError::Unauthorized("no key".to_owned()))?,
        signature: signature.ok_or_else(|| FederationError::Unauthorized("no sig".to_owned()))?,
    })
}

fn server_keys_row(server_name: &str) -> Vec<u8> {
    let mut key = vec![keys::KEY_SCHEMA_VERSION, keys::Keyspace::ServerKeys as u8];
    let bytes = server_name.as_bytes();
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(&bytes[..len as usize]);
    key
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod url_tests {
    use super::base_url;

    #[test]
    fn a_portless_name_gets_the_federation_port_not_443() {
        assert_eq!(base_url("hs1", false).unwrap(), "https://hs1:8448");
        assert_eq!(
            base_url("matrix.example.org", false).unwrap(),
            "https://matrix.example.org:8448"
        );
        // Colons inside an IPv6 literal are not a port.
        assert_eq!(base_url("[::1]", false).unwrap(), "https://[::1]:8448");
    }

    #[test]
    fn an_explicit_port_is_the_peer_telling_us_where_to_knock() {
        assert_eq!(base_url("hs1:443", false).unwrap(), "https://hs1:443");
        assert_eq!(
            base_url("127.0.0.1:8099", true).unwrap(),
            "http://127.0.0.1:8099"
        );
        assert_eq!(base_url("[::1]:8448", false).unwrap(), "https://[::1]:8448");
    }

    /// Every one of these parses as an X-Matrix `origin` and would have
    /// become a URL this server fetched from. None is a server name.
    #[test]
    fn a_name_that_is_not_a_server_name_becomes_no_url_at_all() {
        for hostile in [
            "127.0.0.1:6379/x?y=",
            "internal:8448/../admin",
            "attacker@internal:8448",
            "internal:8448#",
            "internal:8448?",
            "a b",
            ":8448",
            "",
            "internal:notaport",
        ] {
            assert!(base_url(hostile, true).is_err(), "{hostile:?} became a URL");
        }
    }
}

#[cfg(test)]
mod header_tests {
    use super::parse_x_matrix;

    #[test]
    fn a_full_header_round_trips() {
        let parsed = parse_x_matrix(
            "X-Matrix origin=\"other.org\",destination=\"us.example\",key=\"ed25519:0\",sig=\"abc\"",
        )
        .unwrap();
        assert_eq!(parsed.origin, "other.org");
        assert_eq!(parsed.destination.as_deref(), Some("us.example"));
        assert_eq!(parsed.key_id, "ed25519:0");
        assert_eq!(parsed.signature, "abc");
    }

    #[test]
    fn destination_is_optional_but_nothing_else_is() {
        assert!(
            parse_x_matrix("X-Matrix origin=\"a\",key=\"k\",sig=\"s\"")
                .unwrap()
                .destination
                .is_none()
        );
        for broken in [
            "Bearer token",
            "X-Matrix key=\"k\",sig=\"s\"",
            "X-Matrix origin=\"a\",sig=\"s\"",
            "X-Matrix origin=\"a\",key=\"k\"",
            "X-Matrix garbage",
        ] {
            assert!(parse_x_matrix(broken).is_err(), "{broken}");
        }
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn an_ordinary_peer_is_retried_within_a_minute_and_a_patient_one_within_its_cap() {
        let base = Duration::from_secs(1);
        assert_eq!(backoff_delay(base, 1, None), Duration::from_secs(2));
        assert_eq!(backoff_delay(base, 6, None), Duration::from_secs(64));
        // The ordinary cap holds however long the peer stays dark.
        assert_eq!(backoff_delay(base, 40, None), Duration::from_secs(64));
        let hour = Duration::from_secs(3600);
        assert_eq!(backoff_delay(base, 6, Some(hour)), Duration::from_secs(64));
        assert_eq!(
            backoff_delay(base, 11, Some(hour)),
            Duration::from_secs(2048)
        );
        assert_eq!(backoff_delay(base, 12, Some(hour)), hour);
        // Past the cap, the cap; and a huge failure count cannot overflow.
        assert_eq!(backoff_delay(base, u32::MAX, Some(hour)), hour);
    }
}

#[cfg(test)]
mod well_known_tests {
    use super::{
        WELL_KNOWN_DEFAULT, WELL_KNOWN_MAX, WELL_KNOWN_MIN, parse_well_known, well_known_ttl,
    };
    use std::time::Duration;

    fn ttl(header: &str) -> Duration {
        well_known_ttl(Some(
            &reqwest::header::HeaderValue::from_str(header).unwrap(),
        ))
    }

    #[test]
    fn the_delegated_name_is_read_and_checked() {
        assert_eq!(
            parse_well_known(br#"{"m.server": "matrix.reilly.asia:443"}"#).unwrap(),
            "matrix.reilly.asia:443"
        );
        assert_eq!(
            parse_well_known(br#"{"m.server": "matrix-federation.matrix.org"}"#).unwrap(),
            "matrix-federation.matrix.org"
        );
        for bad in [
            &br"{}"[..],
            br#"{"m.server": 443}"#,
            br#"{"m.server": "evil host"}"#,
            br#"{"m.server": "a:1/../admin"}"#,
            br"not json",
        ] {
            assert!(
                parse_well_known(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_cache_time_follows_cache_control_within_bounds() {
        assert_eq!(well_known_ttl(None), WELL_KNOWN_DEFAULT);
        assert_eq!(ttl("public, max-age=7200"), Duration::from_secs(7200));
        assert_eq!(ttl("max-age=1"), WELL_KNOWN_MIN);
        assert_eq!(ttl("max-age=99999999"), WELL_KNOWN_MAX);
        assert_eq!(ttl("no-store"), WELL_KNOWN_MIN);
        assert_eq!(ttl("private"), WELL_KNOWN_DEFAULT);
    }
}

#[cfg(test)]
mod key_validity_tests {
    use super::PeerKeys;
    use serde_json::json;

    fn keys() -> PeerKeys {
        let document = json!({
            "verify_keys": { "ed25519:new": { "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } },
            "old_verify_keys": {
                "ed25519:old": {
                    "key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                    "expired_ts": 500,
                },
            },
        });
        let mut keys = PeerKeys::from_document("peer.example", &document).unwrap();
        keys.valid_until = Some(1_000);
        keys
    }

    fn held(keys: &PeerKeys, ts: u64, enforce: bool) -> Vec<String> {
        keys.map_for(Some(ts), enforce)["peer.example"]
            .keys()
            .cloned()
            .collect()
    }

    /// Room version 5's rule: a current key answers only for events signed
    /// before its document's `valid_until_ts`. Versions 1–4 do not have it.
    #[test]
    fn a_lapsed_document_answers_only_where_the_version_does_not_enforce_validity() {
        let keys = keys();
        assert_eq!(held(&keys, 900, true), ["ed25519:new"]);
        assert!(
            held(&keys, 1_001, true).is_empty(),
            "v5+ refuses a lapsed key"
        );
        assert_eq!(held(&keys, 1_001, false), ["ed25519:new"], "v1–v4 do not");
        // A retired key is bounded by its own `expired_ts` in every version.
        assert_eq!(held(&keys, 400, true), ["ed25519:new", "ed25519:old"]);
        assert_eq!(held(&keys, 600, false), ["ed25519:new"]);
    }
}
