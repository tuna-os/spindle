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

pub struct Federation {
    store: Arc<FjallStore>,
    server_name: String,
    key: Arc<ServerKey>,
    client: reqwest::Client,
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
}

#[derive(Debug)]
pub enum FederationError {
    /// The request carries no usable X-Matrix authorization.
    Unauthorized(String),
    /// The origin's keys cannot be fetched or do not verify the signature.
    Refused(String),
    Storage(String),
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(why) => write!(formatter, "unauthorized: {why}"),
            Self::Refused(why) => write!(formatter, "refused: {why}"),
            Self::Storage(why) => write!(formatter, "storage: {why}"),
        }
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
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(VettingResolver {
                allowed: allowed.clone(),
            }))
            .redirect(crate::netguard::redirect_policy(
                allowed.clone(),
                "federatable",
            ))
            .build()
            .map_err(|error| FederationError::Refused(error.to_string()))?;
        Ok(Self {
            store,
            server_name: server_name.into(),
            key,
            client,
            insecure_http,
            allowed,
            negative: std::sync::Mutex::new(HashMap::new()),
            edu_queue: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The URL a request to `name` goes to, or a refusal.
    ///
    /// Grammar first (#286), then, for a name that is a literal address,
    /// the same judgement the resolver applies to a hostname: a literal
    /// never touches DNS, so this is the only place it can be vetted.
    fn base_url(&self, name: &str) -> Result<String, FederationError> {
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
        PeerKeys::from_document(origin, &cached["document"])
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
    /// Delegation (.well-known, SRV) is not resolved yet — the server name
    /// is used as the host directly, which the federation test rig
    /// satisfies and docs/dashboard record as a gap.
    async fn fetch_key_document(&self, origin: &str) -> Result<Value, FederationError> {
        let url = format!("{}/_matrix/key/v2/server", self.base_url(origin)?);
        let document: Value = self
            .client
            .get(&url)
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
            .client
            .get(format!("{}{uri}", self.base_url(destination)?))
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
            return Err(FederationError::Refused(format!(
                "{destination} refused make_join: {status} {body}"
            )));
        }
        Ok(body)
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
            .client
            .get(format!("{}{uri}", self.base_url(destination)?))
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
            .client
            .get(format!("{}{uri}", self.base_url(destination)?))
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
        let uri = format!("/_matrix/federation/v2/send_join/{room_id}/{event_id}");
        let authorization = self.sign_request("PUT", &uri, destination, Some(join))?;
        let response = self
            .client
            .put(format!("{}{uri}", self.base_url(destination)?))
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
            return Err(FederationError::Refused(format!(
                "{destination} refused send_join: {status} {body}"
            )));
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
        let uri = format!("/_matrix/federation/v2/invite/{room_id}/{event_id}");
        let authorization = self.sign_request("PUT", &uri, destination, Some(body))?;
        let response = self
            .client
            .put(format!("{}{uri}", self.base_url(destination)?))
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
            .client
            .get(format!("{}{uri}", self.base_url(destination)?))
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
        let uri = format!("/_matrix/federation/v2/send_leave/{room_id}/{event_id}");
        let authorization = self.sign_request("PUT", &uri, destination, Some(leave))?;
        let response = self
            .client
            .put(format!("{}{uri}", self.base_url(destination)?))
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
            .client
            .get(format!("{}{uri}", self.base_url(destination)?))
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

        // Legacy fallback: the public v3 endpoint, no signature. Kept for
        // peers predating authenticated media; a 404 there is final.
        let legacy = format!(
            "{}/_matrix/media/v3/download/{destination}/{media_id}?allow_redirect=false",
            self.base_url(destination)?
        );
        let response = self
            .client
            .get(legacy)
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
        let uri = format!("/_matrix/federation/v1/send/{txn_id}");
        let authorization = self.sign_request("PUT", &uri, destination, Some(body))?;
        let response = self
            .client
            .put(format!("{}{uri}", self.base_url(destination)?))
            .header("authorization", authorization)
            .header("content-type", "application/json")
            .timeout(Duration::from_secs(30))
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| FederationError::Refused(format!("send: {error}")))?;
        if !response.status().is_success() {
            return Err(FederationError::Refused(format!(
                "{destination} answered {}",
                response.status()
            )));
        }
        Ok(())
    }
}

/// One pending delivery: its store key and the PDU it carries.
type OutboxRow = (Vec<u8>, Vec<u8>);

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
/// for the reason `spawn_delivery_loops` gives. A pass holds them strongly
/// only from its upgrade to its end, so a cancellation at the idle sleep --
/// where a quiet server spends almost all of its time -- finds nothing to
/// drop.
pub async fn drain_outbox(
    store: Weak<FjallStore>,
    federation: Weak<Federation>,
    retry_base: Duration,
) {
    let mut backoff: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();
    loop {
        tokio::time::sleep(
            retry_base
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
        )
        .await;
        let (Some(store), Some(federation)) = (store.upgrade(), federation.upgrade()) else {
            return;
        };
        let Ok(rows) = ReadView::scan_prefix(store.as_ref(), &keys::federation_outbox_all()) else {
            continue;
        };
        let mut by_destination: std::collections::BTreeMap<String, Vec<OutboxRow>> =
            std::collections::BTreeMap::new();
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
        // The loop already holds the whole picture, so the gauge is set
        // from it rather than counted separately — a second traversal
        // could disagree with the one that actually delivers.
        crate::metrics::set_federation_queue(
            &by_destination
                .iter()
                .map(|(destination, rows)| (destination.clone(), rows.len() as u64))
                .collect::<Vec<_>>(),
        );
        if by_destination.is_empty() {
            continue;
        }
        for (destination, rows) in by_destination {
            if let Some((_, until)) = backoff.get(&destination)
                && *until > std::time::Instant::now()
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
            match federation
                .send_transaction(&destination, &txn_id, &body)
                .await
            {
                Ok(()) => {
                    for (key, _) in &batch {
                        let _ = Store::delete(store.as_ref(), key);
                    }
                    backoff.remove(&destination);
                }
                Err(error) => {
                    tracing::debug!("outbox to {destination}: {error}");
                    let failures = backoff.get(&destination).map_or(0, |(count, _)| *count) + 1;
                    let delay = retry_base * 2_u32.saturating_pow(failures.min(6));
                    backoff.insert(destination, (failures, std::time::Instant::now() + delay));
                }
            }
        }
    }
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
    #[must_use]
    pub fn map_for(&self, origin_server_ts: Option<u64>) -> ruma::signatures::PublicKeyMap {
        let at = origin_server_ts.unwrap_or(u64::MAX);
        let mut set: ruma::signatures::PublicKeySet = self.current.clone();
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
/// door nothing is behind. Delegation (.well-known, SRV) is still not
/// resolved; the name is the host, which docs/dashboard records as a gap.
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
