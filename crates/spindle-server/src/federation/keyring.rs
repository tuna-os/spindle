//! What this server knows of another server's signing keys, and how it
//! decides that a key document is credible.
//!
//! One record per server, stored under its `ServerKeys` row:
//!
//! ```json
//! { "document": {..}, "fetched_valid_until": 0,
//!   "history": [ { "document": {..}, "valid_until": 0, "source": "direct" } ],
//!   "checked_at": 0 }
//! ```
//!
//! `document` is the last one the server published itself, served on to
//! others by our notary endpoint; `history` is every verified document
//! kept, from the server or from a trusted notary, newest validity first.
//! A record written before history existed has only `document` and
//! `fetched_valid_until`, and reads as a history of one.
//!
//! History is the point. A server that rotates its key without listing the
//! old one under `old_verify_keys` -- Synapse's default -- would otherwise
//! leave every event it signed before the rotation unverifiable here the
//! moment the new document replaced the old, and a server that has gone
//! dark leaves nothing to fetch at all.

use std::collections::BTreeMap;

use ruma::CanonicalJsonValue;
use ruma::serde::Base64;
use ruma::signatures::{PublicKeyMap, PublicKeySet};
use serde_json::{Value, json};

use super::FederationError;

/// How long a fetched key document serves at most, whatever its own
/// `valid_until_ts` says. The spec's cap: a peer cannot mint a key valid
/// for years and have caches honour it -- seven days is the ceiling, so a
/// compromised key ages out even if its owner claimed otherwise.
pub(super) const MAX_KEY_VALIDITY_MS: u64 = 7 * 24 * 3600 * 1000;

/// The most documents kept per server, and the most taken from one notary
/// answer. A server rotating weekly for half a year fits; a notary
/// answering with thousands does not get to fill the store.
pub(super) const MAX_HISTORY: usize = 32;

/// Where a stored document came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Source {
    Direct,
    Notary,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Notary => "notary",
        }
    }
}

/// The documents a record holds as `(document, capped validity)`, newest
/// validity first.
fn documents(record: &Value) -> Vec<(&Value, u64)> {
    let mut out: Vec<(&Value, u64)> = match record["history"].as_array() {
        Some(history) => history
            .iter()
            .filter(|entry| entry["document"].is_object())
            .map(|entry| {
                (
                    &entry["document"],
                    entry["valid_until"].as_u64().unwrap_or(0),
                )
            })
            .collect(),
        None if record["document"].is_object() => vec![(
            &record["document"],
            record["fetched_valid_until"].as_u64().unwrap_or(0),
        )],
        None => Vec::new(),
    };
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

/// Whether a record holds any document at all.
pub(super) fn has_documents(record: &Value) -> bool {
    !documents(record).is_empty()
}

/// Whether some document in the record is still within its validity: the
/// record answers for the present without asking anyone.
pub(super) fn fresh(record: &Value, now: u64) -> bool {
    documents(record)
        .first()
        .is_some_and(|(_, until)| *until > now)
}

/// The two key maps of a document, as a stable string: two documents with
/// the same keys are one entry of history, however their validity differs.
fn fingerprint(document: &Value) -> String {
    let mut parts = BTreeMap::new();
    for (section, field) in [("v", "verify_keys"), ("o", "old_verify_keys")] {
        if let Some(entries) = document[field].as_object() {
            for (key_id, entry) in entries {
                parts.insert(
                    format!("{section}:{key_id}"),
                    format!(
                        "{}|{}",
                        entry["key"].as_str().unwrap_or_default(),
                        entry["expired_ts"].as_u64().unwrap_or_default()
                    ),
                );
            }
        }
    }
    serde_json::to_string(&parts).unwrap_or_default()
}

/// The validity a document is held to: its `valid_until_ts`, but never more
/// than seven days past `now`, when it was obtained.
pub(super) fn capped_validity(document: &Value, now: u64) -> u64 {
    document["valid_until_ts"]
        .as_u64()
        .unwrap_or(0)
        .min(now.saturating_add(MAX_KEY_VALIDITY_MS))
}

/// Fold a verified document into a record.
///
/// A direct document also becomes the one served on to others. A
/// document whose keys history already holds replaces that entry only if
/// it is valid for longer; otherwise it is added, and history is trimmed
/// to [`MAX_HISTORY`] by validity.
pub(super) fn merge(record: &mut Value, document: &Value, source: Source, now: u64) {
    if !record.is_object() {
        *record = json!({});
    }
    let capped = capped_validity(document, now);
    // A record from before history existed: its document is history's
    // first entry.
    if !record["history"].is_array() {
        let mut history = Vec::new();
        if record["document"].is_object() {
            history.push(json!({
                "document": record["document"].clone(),
                "valid_until": record["fetched_valid_until"].as_u64().unwrap_or(0),
                "source": Source::Direct.label(),
            }));
        }
        record["history"] = Value::Array(history);
    }
    if source == Source::Direct {
        record["document"] = document.clone();
        record["fetched_valid_until"] = json!(capped);
    }
    let print = fingerprint(document);
    let Some(history) = record["history"].as_array_mut() else {
        return;
    };
    match history
        .iter_mut()
        .find(|entry| fingerprint(&entry["document"]) == print)
    {
        Some(entry) => {
            if entry["valid_until"].as_u64().unwrap_or(0) <= capped {
                *entry = json!({
                    "document": document,
                    "valid_until": capped,
                    "source": source.label(),
                });
            }
        }
        None => history.push(json!({
            "document": document,
            "valid_until": capped,
            "source": source.label(),
        })),
    }
    history.sort_by(|a, b| {
        b["valid_until"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["valid_until"].as_u64().unwrap_or(0))
    });
    history.truncate(MAX_HISTORY);
}

/// One key of a server, as everything it has published says.
#[derive(Clone, Debug)]
struct KeyEntry {
    key: Base64,
    /// The latest moment any document listing it under `verify_keys` was
    /// valid until (capped). `None`: only ever seen retired.
    valid_until: Option<u64>,
    /// When it was retired, the latest any `old_verify_keys` said. `None`:
    /// never seen retired with an expiry.
    expired_ts: Option<u64>,
}

/// A peer's published signing keys, as of every document held for it.
///
/// `verify_keys` are what the peer signs with; each answers for an event
/// signed no later than its document's `valid_until_ts` (capped at seven
/// days past when it was obtained). `old_verify_keys` are keys it retired,
/// each with the `expired_ts` at which it stopped: an event the peer
/// signed before that moment still verifies with the retired key, and one
/// it claims to have signed after it does not -- otherwise a rotation would
/// change nothing (#296). A retired key published without an `expired_ts`
/// is not used at all: a key that keeps working forever is a rotation that
/// did not happen, and refusing is the safe reading of a malformed entry.
///
/// Request signatures (`X-Matrix`) are checked against keys valid now and
/// not retired: a request is made now.
#[derive(Clone, Debug, Default)]
pub struct PeerKeys {
    origin: String,
    keys: BTreeMap<String, KeyEntry>,
    /// Keys of *other* servers that must also verify the event -- the
    /// countersignature on a restricted join is ours, not the peer's.
    vouched: PublicKeyMap,
}

impl PeerKeys {
    /// No keys at all for `origin`.
    #[must_use]
    pub(super) fn empty(origin: &str) -> Self {
        Self {
            origin: origin.to_owned(),
            ..Self::default()
        }
    }

    /// The keys a stored record holds.
    ///
    /// Documents are read newest validity first, and the first to name a
    /// key ID decides its material: a document naming the same ID with a
    /// different key is ignored for that ID, rather than letting an older
    /// claim stand beside a newer one.
    pub(super) fn from_record(origin: &str, record: &Value) -> Self {
        let mut keys = Self::empty(origin);
        for (document, valid_until) in documents(record) {
            keys.absorb(document, valid_until);
        }
        keys
    }

    /// The keys of one document, valid until `valid_until`.
    #[cfg(test)]
    pub(super) fn from_document(origin: &str, document: &Value, valid_until: u64) -> Self {
        let mut keys = Self::empty(origin);
        keys.absorb(document, valid_until);
        keys
    }

    fn absorb(&mut self, document: &Value, valid_until: u64) {
        if let Some(entries) = document["verify_keys"].as_object() {
            for (key_id, entry) in entries {
                if let Some(slot) = self.slot(key_id, entry["key"].as_str()) {
                    slot.valid_until = Some(slot.valid_until.unwrap_or(0).max(valid_until));
                }
            }
        }
        if let Some(entries) = document["old_verify_keys"].as_object() {
            for (key_id, entry) in entries {
                let Some(expired_ts) = entry["expired_ts"].as_u64() else {
                    continue;
                };
                if let Some(slot) = self.slot(key_id, entry["key"].as_str()) {
                    slot.expired_ts = Some(slot.expired_ts.unwrap_or(0).max(expired_ts));
                }
            }
        }
    }

    /// The entry for `key_id` holding `key`, made if new; `None` when the
    /// key does not parse or contradicts the material already held.
    fn slot(&mut self, key_id: &str, key: Option<&str>) -> Option<&mut KeyEntry> {
        let key = Base64::parse(key?).ok()?;
        if key.as_bytes().len() != 32 {
            return None;
        }
        let entry = self
            .keys
            .entry(key_id.to_owned())
            .or_insert_with(|| KeyEntry {
                key: key.clone(),
                valid_until: None,
                expired_ts: None,
            });
        if entry.key.as_bytes() != key.as_bytes() {
            tracing::warn!(
                origin = %self.origin,
                key_id,
                "two key documents give one key ID different keys; keeping the newer"
            );
            return None;
        }
        Some(entry)
    }

    /// Whether `entry` answers for an event signed at `at`.
    ///
    /// `enforce` is room version 5's rule, kept by every later version: a
    /// key answers only for events signed no later than its document's
    /// validity. Versions 1 to 4 do not have the rule, and an old event
    /// there still verifies with a key whose document has lapsed -- but a
    /// retired key is bounded by its `expired_ts` in every version. An
    /// event with no timestamp gets the keys valid now, unretired.
    fn answers(entry: &KeyEntry, at: Option<u64>, enforce: bool, now: u64) -> bool {
        let Some(at) = at else {
            return entry.expired_ts.is_none() && entry.valid_until.is_some_and(|v| v > now);
        };
        match (entry.valid_until, entry.expired_ts) {
            (_, Some(expired)) if at < expired => true,
            (Some(until), Some(_)) => at <= until,
            (Some(until), None) => !enforce || at <= until,
            (None, _) => false,
        }
    }

    /// The map ruma verifies against, for an event that says it was signed
    /// at `origin_server_ts`: every key that answers for that moment.
    #[must_use]
    pub fn map_for(
        &self,
        origin_server_ts: Option<u64>,
        enforce_key_validity: bool,
    ) -> PublicKeyMap {
        let now = super::now_millis();
        let set: PublicKeySet = self
            .keys
            .iter()
            .filter(|(_, entry)| Self::answers(entry, origin_server_ts, enforce_key_validity, now))
            .map(|(key_id, entry)| (key_id.clone(), entry.key.clone()))
            .collect();
        let mut map = self.vouched.clone();
        map.insert(self.origin.clone(), set);
        map
    }

    /// Whether one of `key_ids` answers for an event signed at `at`.
    #[must_use]
    pub fn covers(&self, key_ids: &[String], at: Option<u64>, enforce: bool) -> bool {
        let now = super::now_millis();
        key_ids.iter().any(|key_id| {
            self.keys
                .get(key_id)
                .is_some_and(|entry| Self::answers(entry, at, enforce, now))
        })
    }

    /// Whether one of `key_ids` is held at all, valid or not.
    #[must_use]
    pub fn knows_any(&self, key_ids: &[String]) -> bool {
        key_ids.iter().any(|key_id| self.keys.contains_key(key_id))
    }

    /// Whether no key is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The key a request signed now with `key_id` verifies with: valid
    /// now, and not retired.
    pub(super) fn request_key(&self, key_id: &str, now: u64) -> Option<&Base64> {
        self.keys
            .get(key_id)
            .filter(|entry| {
                entry.expired_ts.is_none() && entry.valid_until.is_some_and(|until| until > now)
            })
            .map(|entry| &entry.key)
    }

    /// Every key valid now and not retired: what a notary's answers are
    /// checked against.
    pub(super) fn current_keys(&self, now: u64) -> PublicKeySet {
        self.keys
            .iter()
            .filter(|(_, entry)| {
                entry.expired_ts.is_none() && entry.valid_until.is_some_and(|until| until > now)
            })
            .map(|(key_id, entry)| (key_id.clone(), entry.key.clone()))
            .collect()
    }

    /// Add a key of another server, for an event that server also signed.
    pub fn vouch(&mut self, server: String, key_id: String, key: Base64) {
        self.vouched.entry(server).or_default().insert(key_id, key);
    }
}

/// The key IDs `server` signed `event` with.
#[must_use]
pub fn signing_key_ids(event: &Value, server: &str) -> Vec<String> {
    event["signatures"][server]
        .as_object()
        .map(|signatures| signatures.keys().cloned().collect())
        .unwrap_or_default()
}

/// Check that `entity` signed `document` with a key in `keys`.
///
/// Only that entity's signatures are looked at: a notary's answer carries
/// the origin's signature and the notary's, and each is checked against
/// its own keys. ruma's rule then applies -- at least one signature under
/// a key ID in `keys`, and every such signature verifies.
pub(super) fn verify_signed_by(
    entity: &str,
    keys: &PublicKeySet,
    document: &Value,
) -> Result<(), FederationError> {
    let Ok(CanonicalJsonValue::Object(mut object)) = CanonicalJsonValue::try_from(document.clone())
    else {
        return Err(FederationError::Refused(
            "unreadable key document".to_owned(),
        ));
    };
    let Some(CanonicalJsonValue::Object(signatures)) = object.get("signatures") else {
        return Err(FederationError::Refused(
            "key document is unsigned".to_owned(),
        ));
    };
    let Some(own) = signatures.get(entity).cloned() else {
        return Err(FederationError::Refused(format!(
            "key document is not signed by {entity}"
        )));
    };
    let mut wanted = ruma::CanonicalJsonObject::new();
    wanted.insert(entity.to_owned(), own);
    object.insert("signatures".to_owned(), CanonicalJsonValue::Object(wanted));
    let mut map = PublicKeyMap::new();
    map.insert(entity.to_owned(), keys.clone());
    ruma::signatures::verify_json(&map, &object).map_err(|error| {
        FederationError::Refused(format!("key document signature by {entity}: {error}"))
    })
}

/// Check a key document's self-signature, using the keys it carries under
/// `verify_keys`, and that it describes `origin`.
pub(super) fn verify_self_signed(origin: &str, document: &Value) -> Result<(), FederationError> {
    if document["server_name"].as_str() != Some(origin) {
        return Err(FederationError::Refused(
            "key document names a different server".to_owned(),
        ));
    }
    let Some(verify_keys) = document["verify_keys"].as_object() else {
        return Err(FederationError::Refused("no verify_keys".to_owned()));
    };
    let mut set = PublicKeySet::new();
    for (key_id, key) in verify_keys {
        if let Some(key) = key["key"].as_str() {
            set.insert(
                key_id.clone(),
                Base64::parse(key).map_err(|error| FederationError::Refused(error.to_string()))?,
            );
        }
    }
    verify_signed_by(origin, &set, document)
}

/// Check one document a notary handed on for `origin`: it names `origin`,
/// has a validity, is signed by the notary with one of `notary_keys`, and
/// by `origin` with a key inside it. Returns it carrying only the origin's
/// signature -- what is stored is the origin's own claim, which the notary
/// vouched for once.
pub(super) fn verify_notary_document(
    origin: &str,
    notary: &str,
    notary_keys: &PublicKeySet,
    document: &Value,
) -> Result<Value, FederationError> {
    if !document.is_object() {
        return Err(FederationError::Refused(
            "notary answer is not an object".to_owned(),
        ));
    }
    if document["valid_until_ts"].as_u64().is_none() {
        return Err(FederationError::Refused(
            "notary answer has no valid_until_ts".to_owned(),
        ));
    }
    verify_self_signed(origin, document)?;
    verify_signed_by(notary, notary_keys, document)?;
    let mut stored = document.clone();
    stored["signatures"] = json!({ origin: document["signatures"][origin].clone() });
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn keys() -> PeerKeys {
        let document = json!({
            "verify_keys": { "ed25519:new": { "key": KEY_A } },
            "old_verify_keys": {
                "ed25519:old": { "key": KEY_B, "expired_ts": 500 },
            },
        });
        PeerKeys::from_document("peer.example", &document, 1_000)
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

    /// Synapse rotates without listing the old key: the old document is
    /// history, and still answers for what was signed while it was valid.
    #[test]
    fn a_rotation_that_drops_the_old_key_keeps_it_for_history() {
        let mut record = json!({});
        let old = json!({
            "server_name": "peer.example",
            "valid_until_ts": 1_000,
            "verify_keys": { "ed25519:a": { "key": KEY_A } },
        });
        let new = json!({
            "server_name": "peer.example",
            "valid_until_ts": 5_000,
            "verify_keys": { "ed25519:b": { "key": KEY_B } },
        });
        merge(&mut record, &old, Source::Direct, 0);
        merge(&mut record, &new, Source::Direct, 2_000);
        assert_eq!(
            record["document"], new,
            "the newest direct document is served"
        );
        let keys = PeerKeys::from_record("peer.example", &record);
        let a = vec!["ed25519:a".to_owned()];
        let b = vec!["ed25519:b".to_owned()];
        assert!(keys.covers(&a, Some(900), true));
        assert!(
            !keys.covers(&a, Some(1_001), true),
            "lapsed with its document"
        );
        assert!(keys.covers(&b, Some(4_000), true));
        assert!(keys.request_key("ed25519:a", 2_000).is_none());
        assert!(keys.request_key("ed25519:b", 2_000).is_some());
    }

    /// A key ID is one key. A second document claiming other material for
    /// it is not believed for that ID.
    #[test]
    fn a_key_id_cannot_be_given_a_second_key() {
        let mut record = json!({});
        merge(
            &mut record,
            &json!({ "valid_until_ts": 9_000, "verify_keys": { "ed25519:a": { "key": KEY_A } } }),
            Source::Direct,
            0,
        );
        merge(
            &mut record,
            &json!({ "valid_until_ts": 1_000, "verify_keys": { "ed25519:a": { "key": KEY_B } } }),
            Source::Notary,
            0,
        );
        let keys = PeerKeys::from_record("peer.example", &record);
        let map = keys.map_for(Some(500), true);
        assert_eq!(
            map["peer.example"]["ed25519:a"].as_bytes(),
            Base64::<ruma::serde::base64::Standard>::parse(KEY_A)
                .unwrap()
                .as_bytes()
        );
    }

    /// The seven-day cap, and a record from before history existed.
    #[test]
    fn validity_is_capped_and_legacy_records_read() {
        let document = json!({ "valid_until_ts": u64::MAX, "verify_keys": {} });
        assert_eq!(capped_validity(&document, 10), 10 + MAX_KEY_VALIDITY_MS);
        let legacy = json!({
            "document": { "valid_until_ts": 50, "verify_keys": { "ed25519:a": { "key": KEY_A } } },
            "fetched_valid_until": 50,
        });
        assert!(fresh(&legacy, 49));
        assert!(!fresh(&legacy, 50));
        let keys = PeerKeys::from_record("peer.example", &legacy);
        assert!(keys.covers(&["ed25519:a".to_owned()], Some(50), true));
        let mut upgraded = legacy.clone();
        merge(
            &mut upgraded,
            &json!({ "valid_until_ts": 100, "verify_keys": { "ed25519:b": { "key": KEY_B } } }),
            Source::Notary,
            0,
        );
        assert_eq!(upgraded["history"].as_array().unwrap().len(), 2);
        assert_eq!(
            upgraded["document"], legacy["document"],
            "notary never served on"
        );
    }

    #[test]
    fn history_is_bounded() {
        let mut record = json!({});
        for i in 0..(MAX_HISTORY as u64 + 10) {
            let key = format!("{i:0>43}").replace('0', "A");
            merge(
                &mut record,
                &json!({ "valid_until_ts": i, "verify_keys": { format!("ed25519:{i}"): { "key": key } } }),
                Source::Notary,
                0,
            );
        }
        assert_eq!(record["history"].as_array().unwrap().len(), MAX_HISTORY);
    }
}
