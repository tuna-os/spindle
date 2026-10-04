//! Checking every imported event's signatures with the key valid when it
//! was signed.
//!
//! Synapse verified each event once, on arrival, with the key the origin
//! server published at the time, and never again. Some servers later
//! reused a key ID (`ed25519:0`, `ed25519:1`, `ed25519:a_pOGN`) for a new
//! key. Synapse's own cache (`server_keys_json`) keeps one row per key ID
//! and fetching server, so the old key survives only where another server
//! (a notary, usually `matrix.org`) answered for it before the rotation.
//!
//! The import re-checks every event it writes. For each key ID an event is
//! signed with, every key Synapse ever cached under that ID is a
//! candidate, the one whose validity covers the event's `origin_server_ts`
//! first; an event that verifies only with an older key is counted as
//! historical, not as a failure. An event whose sender ruma cannot parse
//! (a bridge ID such as `@telegram_…:*`) is checked against every signing
//! server whose key is known, over the version's redacted form, as ruma's
//! own check would after its sender lookup.

use std::collections::HashMap;

use ruma::CanonicalJsonValue;
use ruma::room_version_rules::RoomVersionRules;
use ruma::serde::Base64;
use ruma::signatures::{PublicKeyMap, Verified};
use serde_json::Value;

use super::ReadError;
use super::postgres::Snapshot;

/// One key Synapse cached under a key ID, and until when it answered.
#[derive(Clone, Debug)]
struct Candidate {
    key: Base64,
    valid_until: u64,
}

/// Every server key Synapse holds, by server and key ID.
#[derive(Debug, Default)]
pub struct KeyRing {
    keys: HashMap<String, HashMap<String, Vec<Candidate>>>,
}

/// What checking one event's signatures found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Verified with the key Synapse holds now, and the content hash
    /// matches.
    Verified,
    /// Verified, but only with an older key under a reused key ID.
    Historical,
    /// The signatures verify but the content hash does not: Synapse
    /// received this copy already redacted.
    RedactedCopy,
    /// Not verifiable; the reason.
    Unverifiable(String),
}

impl KeyRing {
    /// Read `server_keys_json`, and add this server's own key.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError`] if the query fails.
    pub fn load(
        snapshot: &mut Snapshot<'_>,
        own: Option<(&str, &str, &str)>,
    ) -> Result<Self, ReadError> {
        let mut ring = Self::default();
        let rows = snapshot.query(
            "SELECT server_name, ts_valid_until_ms, key_json FROM server_keys_json",
            &[],
        )?;
        for row in rows {
            let server: String = row.get(0);
            let valid_until = u64::try_from(row.get::<_, i64>(1)).unwrap_or(0);
            let Ok(document) = serde_json::from_slice::<Value>(&row.get::<_, Vec<u8>>(2)) else {
                continue;
            };
            ring.add_document(&server, &document, valid_until);
        }
        if let Some((server, key_id, key)) = own {
            ring.add(server, key_id, key, u64::MAX);
        }
        Ok(ring)
    }

    /// Add the keys of one `/_matrix/key/v2/server` document.
    pub fn add_document(&mut self, server: &str, document: &Value, valid_until: u64) {
        if let Some(keys) = document["verify_keys"].as_object() {
            for (key_id, entry) in keys {
                if let Some(key) = entry["key"].as_str() {
                    self.add(server, key_id, key, valid_until);
                }
            }
        }
        if let Some(keys) = document["old_verify_keys"].as_object() {
            for (key_id, entry) in keys {
                if let Some(key) = entry["key"].as_str() {
                    let expired = entry["expired_ts"].as_u64().unwrap_or(valid_until);
                    self.add(server, key_id, key, expired);
                }
            }
        }
    }

    /// Add one key; the same key under the same ID keeps its latest validity.
    pub fn add(&mut self, server: &str, key_id: &str, key: &str, valid_until: u64) {
        let Ok(key) = Base64::parse(key) else {
            return;
        };
        let candidates = self
            .keys
            .entry(server.to_owned())
            .or_default()
            .entry(key_id.to_owned())
            .or_default();
        if let Some(same) = candidates.iter_mut().find(|candidate| candidate.key == key) {
            same.valid_until = same.valid_until.max(valid_until);
        } else {
            candidates.push(Candidate { key, valid_until });
        }
    }

    /// The candidates for one key ID in the order to try them for an event
    /// signed at `ts`: those valid at `ts`, earliest window first, then the
    /// rest, newest first. The second value is the newest key, Synapse's
    /// current one.
    fn candidates(
        &self,
        server: &str,
        key_id: &str,
        ts: u64,
    ) -> (Vec<&Candidate>, Option<&Candidate>) {
        let Some(all) = self.keys.get(server).and_then(|ids| ids.get(key_id)) else {
            return (Vec::new(), None);
        };
        let newest = all.iter().max_by_key(|candidate| candidate.valid_until);
        let mut valid: Vec<&Candidate> = all.iter().filter(|c| c.valid_until >= ts).collect();
        valid.sort_by_key(|candidate| candidate.valid_until);
        let mut lapsed: Vec<&Candidate> = all.iter().filter(|c| c.valid_until < ts).collect();
        lapsed.sort_by_key(|candidate| std::cmp::Reverse(candidate.valid_until));
        valid.extend(lapsed);
        (valid, newest)
    }

    /// Check one event body under its room version's rules.
    #[must_use]
    pub fn verify(&self, body: &Value, rules: &RoomVersionRules) -> Verdict {
        let Ok(CanonicalJsonValue::Object(object)) = CanonicalJsonValue::try_from(body.clone())
        else {
            return Verdict::Unverifiable("not canonical JSON".to_owned());
        };
        let ts = body["origin_server_ts"].as_u64().unwrap_or(0);
        let Some(signatures) = body["signatures"].as_object() else {
            return Verdict::Unverifiable("no signatures".to_owned());
        };

        // Each (server, key ID) the event is signed with, and its candidates.
        let mut slots: Vec<(String, String, Vec<&Candidate>, Option<&Candidate>)> = Vec::new();
        for (server, keys) in signatures {
            for key_id in keys.as_object().into_iter().flatten().map(|(id, _)| id) {
                let (candidates, newest) = self.candidates(server, key_id, ts);
                if !candidates.is_empty() {
                    slots.push((server.clone(), key_id.clone(), candidates, newest));
                }
            }
        }
        if slots.is_empty() {
            return Verdict::Unverifiable("no key for any signing server".to_owned());
        }

        let sender_parses = body["sender"]
            .as_str()
            .is_some_and(|sender| ruma::OwnedUserId::try_from(sender).is_ok());
        let check = |choice: &[usize]| -> Result<Verified, String> {
            let mut map = PublicKeyMap::new();
            for ((server, key_id, candidates, _), index) in slots.iter().zip(choice) {
                if let Some(candidate) = candidates.get(*index) {
                    map.entry(server.clone())
                        .or_default()
                        .insert(key_id.clone(), candidate.key.clone());
                }
            }
            if sender_parses {
                ruma::signatures::verify_event(&map, &object, rules).map_err(|e| e.to_string())
            } else {
                // ruma cannot name the sender's server: check every signing
                // server it has a key for, over the redacted form.
                let mut redacted =
                    ruma::canonical_json::redact(object.clone(), &rules.redaction, None)
                        .map_err(|error| error.to_string())?;
                redacted.remove("unsigned");
                ruma::signatures::verify_json(&map, &redacted)
                    .map(|()| Verified::All)
                    .map_err(|error| error.to_string())
            }
        };

        let preferred = vec![0_usize; slots.len()];
        let mut outcome = check(&preferred);
        let mut choice = preferred.clone();
        if outcome.is_err() {
            // Try each alternative key on its own, then all at once.
            'search: for slot in 0..slots.len() {
                for alternative in 1..slots[slot].2.len() {
                    let mut trial = preferred.clone();
                    trial[slot] = alternative;
                    if let Ok(verified) = check(&trial) {
                        outcome = Ok(verified);
                        choice = trial;
                        break 'search;
                    }
                }
            }
        }
        match outcome {
            Err(error) => Verdict::Unverifiable(error),
            Ok(verified) => {
                let historical =
                    slots
                        .iter()
                        .zip(&choice)
                        .any(|((_, _, candidates, newest), index)| {
                            match (candidates.get(*index), newest) {
                                (Some(used), Some(newest)) => used.key != newest.key,
                                _ => false,
                            }
                        });
                match (verified, historical) {
                    (Verified::Signatures, _) => Verdict::RedactedCopy,
                    (_, true) => Verdict::Historical,
                    (_, false) => Verdict::Verified,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruma::signatures::Ed25519KeyPair;

    fn signed(pair: &Ed25519KeyPair, server: &str, ts: u64) -> Value {
        let mut object: ruma::CanonicalJsonObject = serde_json::from_value(serde_json::json!({
            "room_id": "!r:example.org",
            "type": "m.room.message",
            "sender": format!("@a:{server}"),
            "origin_server_ts": ts,
            "content": {"body": "hi", "msgtype": "m.text"},
            "prev_events": [], "auth_events": [], "depth": 3,
        }))
        .unwrap();
        let rules = ruma::RoomVersionId::V10.rules().unwrap();
        ruma::signatures::hash_and_sign_event(server, pair, &mut object, &rules.redaction).unwrap();
        serde_json::to_value(object).unwrap()
    }

    fn pair(version: &str) -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate();
        Ed25519KeyPair::from_der(&document, version.to_owned()).unwrap()
    }

    fn public(pair: &Ed25519KeyPair) -> String {
        Base64::<ruma::serde::base64::Standard, _>::new(pair.public_key().to_vec()).encode()
    }

    #[test]
    fn a_reused_key_id_verifies_old_events_with_the_old_key() {
        let rules = ruma::RoomVersionId::V10.rules().unwrap();
        let old = pair("0");
        let new = pair("0");
        let mut ring = KeyRing::default();
        // A notary cached the old key until t=1000; the server now serves
        // a new key under the same ID.
        ring.add("self.host", "ed25519:0", &public(&old), 1_000);
        ring.add("self.host", "ed25519:0", &public(&new), 10_000);

        assert_eq!(
            ring.verify(&signed(&old, "self.host", 500), &rules),
            Verdict::Historical
        );
        assert_eq!(
            ring.verify(&signed(&new, "self.host", 5_000), &rules),
            Verdict::Verified
        );
        // An old key past its window still verifies an event Synapse took.
        assert_eq!(
            ring.verify(&signed(&old, "self.host", 5_000), &rules),
            Verdict::Historical
        );
        let stranger = pair("0");
        assert!(matches!(
            ring.verify(&signed(&stranger, "self.host", 500), &rules),
            Verdict::Unverifiable(_)
        ));
    }

    #[test]
    fn a_content_change_is_a_redacted_copy_and_a_forgery_fails() {
        let rules = ruma::RoomVersionId::V10.rules().unwrap();
        let key = pair("1");
        let mut ring = KeyRing::default();
        ring.add("example.org", "ed25519:1", &public(&key), u64::MAX);
        let mut event = signed(&key, "example.org", 1);
        event["content"] = serde_json::json!({});
        assert_eq!(ring.verify(&event, &rules), Verdict::RedactedCopy);
        event["type"] = serde_json::json!("m.room.topic");
        assert!(matches!(
            ring.verify(&event, &rules),
            Verdict::Unverifiable(_)
        ));
    }
}
