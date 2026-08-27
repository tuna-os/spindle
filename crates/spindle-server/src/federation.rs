//! Federation identity: signing our requests, verifying theirs.
//!
//! The X-Matrix scheme is the root of all server-to-server trust: every
//! federation request carries a signature over `(method, uri, origin,
//! destination, content)` made with the origin's published ed25519 key.
//! Everything else federation does — accepting events, answering queries —
//! stands on this check, so it fails closed at every fork: an unparseable
//! header, an unfetchable key, a stale key, a destination that is not us,
//! all refuse rather than degrade.

use std::sync::Arc;
use std::time::Duration;

use ruma::{CanonicalJsonObject, CanonicalJsonValue};
use serde_json::{Value, json};
use spindle_core::keys::{self};
use spindle_store::{FjallStore, ReadView, Store};

use crate::signing::ServerKey;

/// How long a fetched key document serves at most, whatever its own
/// `valid_until_ts` says. The spec's cap: a peer cannot mint a key valid
/// for years and have caches honour it — seven days is the ceiling, so a
/// compromised key ages out even if its owner claimed otherwise.
const MAX_KEY_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);

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
    #[must_use]
    pub fn new(
        store: Arc<FjallStore>,
        server_name: impl Into<String>,
        key: Arc<ServerKey>,
        insecure_http: bool,
    ) -> Self {
        Self {
            store,
            server_name: server_name.into(),
            key,
            client: reqwest::Client::new(),
            insecure_http,
            edu_queue: std::sync::Mutex::new(std::collections::HashMap::new()),
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

    /// Every verify key the origin currently publishes, as ruma's map —
    /// for verifying whole events, which may carry any of its keys.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] if the document cannot be fetched or is
    /// not credible.
    pub async fn public_key_map(
        &self,
        origin: &str,
    ) -> Result<ruma::signatures::PublicKeyMap, FederationError> {
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
        let mut key_map = ruma::signatures::PublicKeyMap::new();
        let entry = key_map.entry(origin.to_owned()).or_default();
        if let Some(keys) = cached["document"]["verify_keys"].as_object() {
            for (key_id, key) in keys {
                if let Some(key) = key["key"].as_str() {
                    entry.insert(
                        key_id.clone(),
                        ruma::serde::Base64::parse(key)
                            .map_err(|error| FederationError::Refused(error.to_string()))?,
                    );
                }
            }
        }
        Ok(key_map)
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
        // all three refetch. Delegation (.well-known, SRV) is not resolved
        // yet — the server name is used as the host directly, which the
        // federation test rig satisfies and docs/dashboard record as a gap.
        let url = format!(
            "{}/_matrix/key/v2/server",
            base_url(origin, self.insecure_http)
        );
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
        let uri = format!("/_matrix/federation/v1/make_join/{room_id}/{user_id}?ver=11");
        let authorization = self.sign_request("GET", &uri, destination, None)?;
        let response = self
            .client
            .get(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .get(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .get(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .put(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .put(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .get(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .put(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
            .put(format!(
                "{}{uri}",
                base_url(destination, self.insecure_http)
            ))
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
pub async fn drain_outbox(
    store: Arc<FjallStore>,
    federation: Arc<Federation>,
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
fn base_url(name: &str, insecure_http: bool) -> String {
    let scheme = if insecure_http { "http" } else { "https" };
    if name.contains(':') {
        format!("{scheme}://{name}")
    } else {
        format!("{scheme}://{name}:8448")
    }
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
        assert_eq!(base_url("hs1", false), "https://hs1:8448");
        assert_eq!(
            base_url("matrix.example.org", false),
            "https://matrix.example.org:8448"
        );
    }

    #[test]
    fn an_explicit_port_is_the_peer_telling_us_where_to_knock() {
        assert_eq!(base_url("hs1:443", false), "https://hs1:443");
        assert_eq!(base_url("127.0.0.1:8099", true), "http://127.0.0.1:8099");
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
