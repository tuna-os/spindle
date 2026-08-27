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
        }
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
        let scheme = if self.insecure_http { "http" } else { "https" };
        let url = format!("{scheme}://{origin}/_matrix/key/v2/server");
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
