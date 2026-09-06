//! Room versions this server speaks, including the one ruma does not.
//!
//! Ruma knows the stable versions and carries their rules. MSC4242 (State
//! DAGs, Hydra phase 2) is not one of them yet: it rides on v12's rules
//! with a different event shape -- `prev_state_events` on every event,
//! covered by the reference hash and the signature, and no `auth_events`
//! on the wire, because every server calculates them from the state DAG.
//! Until it is assigned a number (v13 is the expectation) it federates as
//! `org.matrix.msc4242.12`, which is what Neutrino creates rooms under.
//!
//! Everything that depends on the version -- redaction, the reference
//! hash, signing, verifying -- goes through this module, so the one
//! difference (which keys survive redaction) is stated once.

use ruma::{
    CanonicalJsonObject, CanonicalJsonValue, RoomVersionId,
    canonical_json::CanonicalJsonFieldError,
    room_version_rules::RoomVersionRules,
    signatures::{JsonError, KeyPair, PublicKeyMap, VerificationError, Verified},
};
use sha2::{Digest, Sha256};

/// The unstable identifier of MSC4242 over room version 12.
pub const STATE_DAG_V12: &str = "org.matrix.msc4242.12";

/// The key that MSC4242 adds to every event and that its reference hash
/// covers, so it must survive redaction where v12's keep-list does not
/// mention it.
const PREV_STATE_EVENTS: &str = "prev_state_events";

/// Whether `version` is a state-DAG room version (MSC4242).
#[must_use]
pub fn is_state_dag(version: &RoomVersionId) -> bool {
    version.as_str() == STATE_DAG_V12
}

/// The rules a version selects, for the versions this server knows.
///
/// A stock version answers with ruma's rules; the state-DAG version is
/// v12's rules, because MSC4242 changes the event shape and the state
/// machinery, not authorization or redaction.
#[must_use]
pub fn rules_of(version: &RoomVersionId) -> Option<RoomVersionRules> {
    if is_state_dag(version) {
        return RoomVersionId::V12.rules();
    }
    version.rules()
}

/// Redact `object` under `version`'s rules.
///
/// For a state-DAG version `prev_state_events` is kept: it is part of the
/// event's name, so a redaction that dropped it would rename the event.
///
/// # Errors
///
/// Returns [`VersionError`] when the object is not an event.
pub fn redact(
    object: &CanonicalJsonObject,
    version: &RoomVersionId,
) -> Result<CanonicalJsonObject, VersionError> {
    let rules = rules_of(version).ok_or_else(|| VersionError::Unsupported(version.to_string()))?;
    let mut redacted = ruma::canonical_json::redact(object.clone(), &rules.redaction, None)?;
    if is_state_dag(version)
        && let Some(kept) = object.get(PREV_STATE_EVENTS)
    {
        redacted.insert(PREV_STATE_EVENTS.to_owned(), kept.clone());
    }
    Ok(redacted)
}

/// The reference hash of `object` under `version`, base64 as the event ID
/// carries it (without the `$`).
///
/// # Errors
///
/// Returns [`VersionError`] when the version is unknown or the object
/// cannot be redacted or hashed.
pub fn reference_hash(
    object: &CanonicalJsonObject,
    version: &RoomVersionId,
) -> Result<String, VersionError> {
    let rules = rules_of(version).ok_or_else(|| VersionError::Unsupported(version.to_string()))?;
    if !is_state_dag(version) {
        return Ok(ruma::signatures::reference_hash(object, &rules)?);
    }
    // Ruma's own procedure, with this version's redaction in place of its
    // own: redact, drop what the hash never covers, canonicalize, hash.
    let mut redacted = redact(object, version)?;
    redacted.remove("signatures");
    redacted.remove("unsigned");
    let json = serde_json::to_string(&CanonicalJsonValue::Object(redacted))
        .map_err(|error| VersionError::Json(error.to_string()))?;
    let digest = Sha256::digest(json.as_bytes());
    Ok(ruma::serde::Base64::<ruma::serde::base64::UrlSafe, _>::new(digest.to_vec()).encode())
}

/// Add the content hash and this server's signature to an event.
///
/// # Errors
///
/// Returns [`VersionError`] when the version is unknown or ruma cannot hash
/// or sign the object.
pub fn hash_and_sign<K: KeyPair>(
    server_name: &str,
    key_pair: &K,
    object: &mut CanonicalJsonObject,
    version: &RoomVersionId,
) -> Result<(), VersionError> {
    let rules = rules_of(version).ok_or_else(|| VersionError::Unsupported(version.to_string()))?;
    if !is_state_dag(version) {
        ruma::signatures::hash_and_sign_event(server_name, key_pair, object, &rules.redaction)?;
        return Ok(());
    }
    ruma::signatures::add_content_hash_to_event(object)?;
    // The signature is over the redacted form; sign that, then carry the
    // signature block back onto the full event.
    let mut redacted = redact(object, version)?;
    ruma::signatures::sign_json(server_name, key_pair, &mut redacted)?;
    let Some(CanonicalJsonValue::Object(signed)) = redacted.remove("signatures") else {
        return Err(VersionError::Json(
            "signing produced no signatures".to_owned(),
        ));
    };
    let signatures = match object.remove("signatures") {
        Some(CanonicalJsonValue::Object(existing)) => existing,
        _ => CanonicalJsonObject::new(),
    };
    let mut merged = signatures;
    for (entity, keys) in signed {
        match (merged.get_mut(&entity), keys) {
            (Some(CanonicalJsonValue::Object(have)), CanonicalJsonValue::Object(add)) => {
                have.extend(add);
            }
            (_, keys) => {
                merged.insert(entity, keys);
            }
        }
    }
    object.insert("signatures".to_owned(), CanonicalJsonValue::Object(merged));
    Ok(())
}

/// Verify an event's signatures and content hash, ruma's way, under
/// `version`'s redaction.
///
/// The verdict is ruma's [`Verified`]: `All` when the hash matches too,
/// `Signatures` when the signature holds but the content was altered after
/// signing -- the case the spec answers by redacting.
///
/// # Errors
///
/// Returns [`VersionError`] when the version is unknown, a required
/// signature is missing or wrong, or the object is malformed.
pub fn verify(
    key_map: &PublicKeyMap,
    object: &CanonicalJsonObject,
    version: &RoomVersionId,
) -> Result<Verified, VersionError> {
    let rules = rules_of(version).ok_or_else(|| VersionError::Unsupported(version.to_string()))?;
    if !is_state_dag(version) {
        return Ok(ruma::signatures::verify_event(key_map, object, &rules)?);
    }
    let required =
        ruma::signatures::required_server_signatures_to_verify_event(object, &rules.signatures)?;
    let mut redacted = redact(object, version)?;
    // `verify_json` checks every entity that signed; only the ones the
    // rules require have to be present and verifiable here.
    let Some(CanonicalJsonValue::Object(signatures)) = object.get("signatures") else {
        return Err(VersionError::Json("no signatures".to_owned()));
    };
    let mut wanted = CanonicalJsonObject::new();
    for server in &required {
        match signatures.get(server.as_str()) {
            Some(block) => {
                wanted.insert(server.to_string(), block.clone());
            }
            None => return Err(VersionError::Json(format!("no signature by {server}"))),
        }
    }
    redacted.insert("signatures".to_owned(), CanonicalJsonValue::Object(wanted));
    ruma::signatures::verify_json(key_map, &redacted)?;

    let claimed = object
        .get("hashes")
        .and_then(|hashes| match hashes {
            CanonicalJsonValue::Object(hashes) => hashes.get("sha256"),
            _ => None,
        })
        .and_then(|hash| match hash {
            CanonicalJsonValue::String(hash) => Some(hash.clone()),
            _ => None,
        })
        .ok_or_else(|| VersionError::Json("no content hash".to_owned()))?;
    let computed = ruma::signatures::content_hash(object)?;
    let matches = ruma::serde::Base64::<ruma::serde::base64::Standard>::parse(claimed)
        .is_ok_and(|hash| hash.as_bytes() == computed.as_bytes());
    Ok(if matches {
        Verified::All
    } else {
        Verified::Signatures
    })
}

/// A version-dependent operation that could not be carried out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionError {
    /// No rules are known for this version.
    Unsupported(String),
    /// The object cannot be redacted as an event.
    Redaction(String),
    /// Hashing, signing or verifying failed.
    Signature(String),
    /// The object is not the shape the operation needs.
    Json(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(version) => write!(f, "unsupported room version {version}"),
            Self::Redaction(error) => write!(f, "redaction: {error}"),
            Self::Signature(error) => write!(f, "signature: {error}"),
            Self::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for VersionError {}

impl From<CanonicalJsonFieldError> for VersionError {
    fn from(error: CanonicalJsonFieldError) -> Self {
        Self::Redaction(error.to_string())
    }
}

impl From<JsonError> for VersionError {
    fn from(error: JsonError) -> Self {
        Self::Signature(error.to_string())
    }
}

impl From<VerificationError> for VersionError {
    fn from(error: VerificationError) -> Self {
        Self::Signature(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruma::signatures::Ed25519KeyPair;

    fn state_dag() -> RoomVersionId {
        RoomVersionId::try_from(STATE_DAG_V12).unwrap()
    }

    fn event(prev_state: &[&str]) -> CanonicalJsonObject {
        let value = serde_json::json!({
            "type": "m.room.message",
            "sender": "@a:example",
            "room_id": "!abc",
            "content": { "body": "hi", "msgtype": "m.text" },
            "origin_server_ts": 1,
            "prev_events": ["$p"],
            "prev_state_events": prev_state,
        });
        match CanonicalJsonValue::try_from(value).unwrap() {
            CanonicalJsonValue::Object(object) => object,
            _ => unreachable!(),
        }
    }

    fn key() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate();
        Ed25519KeyPair::from_der(&document, "1".to_owned()).unwrap()
    }

    #[test]
    fn the_state_dag_version_has_v12_rules() {
        assert!(is_state_dag(&state_dag()));
        assert_eq!(
            rules_of(&state_dag()).map(|rules| rules.event_id_format),
            RoomVersionId::V12
                .rules()
                .map(|rules| rules.event_id_format)
        );
        assert!(rules_of(&RoomVersionId::V11).is_some());
    }

    #[test]
    fn prev_state_events_is_part_of_the_name() {
        let a = reference_hash(&event(&["$s1"]), &state_dag()).unwrap();
        let b = reference_hash(&event(&["$s2"]), &state_dag()).unwrap();
        assert_ne!(a, b, "the state parents must change the event ID");
        // The stock hash, which redacts them away, cannot tell them apart.
        let rules = RoomVersionId::V12.rules().unwrap();
        assert_eq!(
            ruma::signatures::reference_hash(&event(&["$s1"]), &rules).unwrap(),
            ruma::signatures::reference_hash(&event(&["$s2"]), &rules).unwrap()
        );
    }

    #[test]
    fn signing_covers_prev_state_events_and_verifies() {
        let key = key();
        let mut object = event(&["$s1"]);
        hash_and_sign("example", &key, &mut object, &state_dag()).unwrap();
        let mut key_map = PublicKeyMap::new();
        key_map.entry("example".to_owned()).or_default().insert(
            "ed25519:1".to_owned(),
            ruma::serde::Base64::new(key.public_key().to_vec()),
        );
        assert_eq!(
            verify(&key_map, &object, &state_dag()).unwrap(),
            Verified::All
        );

        // Move the state parents: the signature no longer holds.
        let mut moved = object.clone();
        moved.insert(
            "prev_state_events".to_owned(),
            CanonicalJsonValue::Array(vec![CanonicalJsonValue::String("$s2".to_owned())]),
        );
        assert!(verify(&key_map, &moved, &state_dag()).is_err());

        // Alter the body: the signature holds, the hash does not.
        let mut altered = object.clone();
        altered.insert(
            "content".to_owned(),
            CanonicalJsonValue::Object(CanonicalJsonObject::new()),
        );
        assert_eq!(
            verify(&key_map, &altered, &state_dag()).unwrap(),
            Verified::Signatures
        );
    }

    #[test]
    fn stock_versions_go_through_ruma_unchanged() {
        let key = key();
        let mut object = event(&[]);
        object.remove("prev_state_events");
        object.insert("auth_events".to_owned(), CanonicalJsonValue::Array(vec![]));
        object.insert("depth".to_owned(), CanonicalJsonValue::Integer(1.into()));
        hash_and_sign("example", &key, &mut object, &RoomVersionId::V11).unwrap();
        let rules = RoomVersionId::V11.rules().unwrap();
        assert_eq!(
            reference_hash(&object, &RoomVersionId::V11).unwrap(),
            ruma::signatures::reference_hash(&object, &rules).unwrap()
        );
    }
}
