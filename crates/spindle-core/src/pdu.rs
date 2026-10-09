use ruma::{CanonicalJsonObject, CanonicalJsonValue, RoomVersionId, signatures::KeyPair};

use crate::EventId;
use crate::version::{self, is_state_dag};

const MAX_PREV_EVENTS: usize = 20;
const MAX_AUTH_EVENTS: usize = 10;
/// MSC4242: "Servers MUST limit the number of `prev_state_events` to 20."
const MAX_PREV_STATE_EVENTS: usize = 20;
const MAX_DEPTH: i64 = (1_i64 << 53) - 1;

/// A canonical, room-version-tagged Matrix persistent data unit.
///
/// The room version travels with the event because redaction, authorization,
/// signing, and state resolution rules are version dependent.
#[derive(Clone, Debug)]
pub struct Pdu {
    room_version: RoomVersionId,
    event_id: EventId,
    canonical: CanonicalJsonObject,
}

impl Pdu {
    /// Validate, hash, sign, and derive the reference-hash event ID for a PDU.
    ///
    /// # Errors
    ///
    /// Returns [`PduError`] if required fields or protocol bounds are invalid,
    /// the room version is unknown, or Ruma cannot hash or sign the event.
    pub fn sign<K: KeyPair>(
        room_version: RoomVersionId,
        mut canonical: CanonicalJsonObject,
        server_name: &str,
        key_pair: &K,
    ) -> Result<Self, PduError> {
        // v1/v2: the event carries an ID its origin chose, inside the signed
        // bytes. A caller may have chosen it already (a template finished
        // here); otherwise this server mints one under its own name.
        if !version::names_events_by_hash(&room_version) && !canonical.contains_key("event_id") {
            canonical.insert(
                "event_id".to_owned(),
                CanonicalJsonValue::String(opaque_event_id(&canonical, server_name)),
            );
        }
        validate(&canonical, &room_version)?;
        version::hash_and_sign(server_name, key_pair, &mut canonical, &room_version)
            .map_err(PduError::from)?;
        let event_id = version::event_id(&canonical, &room_version).map_err(PduError::from)?;

        Ok(Self {
            room_version,
            event_id: EventId::new(event_id),
            canonical,
        })
    }

    /// Accept a received event: validate its shape and derive its ID.
    ///
    /// No signing — the event carries someone else's signatures, and the
    /// caller verifies them (with ruma, against the origin's published
    /// keys) before anything trusts this PDU. What this does establish is
    /// the event ID, by the same reference hash a signing path uses: an ID
    /// computed rather than claimed, so a peer cannot name its event
    /// whatever it likes.
    ///
    /// # Errors
    ///
    /// Returns [`PduError`] if required fields or protocol bounds are
    /// invalid, the room version is unknown, or the hash cannot be taken.
    pub fn from_remote(
        room_version: RoomVersionId,
        canonical: CanonicalJsonObject,
    ) -> Result<Self, PduError> {
        validate(&canonical, &room_version)?;
        let event_id = version::event_id(&canonical, &room_version).map_err(PduError::from)?;
        Ok(Self {
            room_version,
            event_id: EventId::new(event_id),
            canonical,
        })
    }

    #[must_use]
    pub fn room_version(&self) -> &RoomVersionId {
        &self.room_version
    }

    #[must_use]
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }

    #[must_use]
    pub fn canonical(&self) -> &CanonicalJsonObject {
        &self.canonical
    }
}

fn validate(event: &CanonicalJsonObject, room_version: &RoomVersionId) -> Result<(), PduError> {
    let event_type = required_string(event, "type")?;
    required_string(event, "sender")?;
    required_integer(event, "origin_server_ts")?;
    required_object(event, "content")?;
    bounded_event_ids(event, "prev_events", MAX_PREV_EVENTS)?;
    if is_state_dag(room_version) {
        // MSC4242: `auth_events` is calculated by every server and must not
        // be on the wire; `prev_state_events` is on every event but the
        // create event, which has nothing before it. `depth` is not part of
        // the shape (Neutrino omits it) and is bounded if it is there.
        if event.contains_key("auth_events") {
            return Err(PduError::InvalidField("auth_events"));
        }
        match event.get("prev_state_events") {
            None if event_type == "m.room.create" => {}
            _ => bounded_event_ids(event, "prev_state_events", MAX_PREV_STATE_EVENTS)?,
        }
        if event.contains_key("depth") {
            let depth = required_integer(event, "depth")?;
            if !(0..=MAX_DEPTH).contains(&depth) {
                return Err(PduError::InvalidDepth(depth));
            }
        }
        return bare(event, "prev_events");
    }
    let depth = required_integer(event, "depth")?;
    if !(0..=MAX_DEPTH).contains(&depth) {
        return Err(PduError::InvalidDepth(depth));
    }
    bounded_event_ids(event, "auth_events", MAX_AUTH_EVENTS)?;
    if version::names_events_by_hash(room_version) {
        bare(event, "prev_events")?;
        bare(event, "auth_events")?;
    } else {
        // v1/v2 references are `[event_id, {"sha256": hash}]` pairs.
        pairs(event, "prev_events")?;
        pairs(event, "auth_events")?;
    }
    Ok(())
}

/// A v1/v2 event ID for an event this server mints: `$opaque:server`.
///
/// Unique, not secret: the opaque part only has to differ from every other
/// event this server names, so it is a hash of the event's own bytes and
/// the moment it was named, rather than a draw from a random source the
/// core does not otherwise need.
fn opaque_event_id(canonical: &CanonicalJsonObject, server_name: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NAMED: AtomicU64 = AtomicU64::new(0);
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"spindle v1 event id");
    hasher.update(server_name.as_bytes());
    hasher.update(format!("{canonical:?}").as_bytes());
    hasher.update(&NAMED.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    hasher.update(&now.to_le_bytes());
    let opaque: String = hasher
        .finalize()
        .as_bytes()
        .iter()
        .take(18)
        .filter_map(|byte| ALPHABET.get(usize::from(*byte) % ALPHABET.len()))
        .map(|byte| char::from(*byte))
        .collect();
    format!("${opaque}:{server_name}")
}

fn required_string<'a>(
    event: &'a CanonicalJsonObject,
    field: &'static str,
) -> Result<&'a str, PduError> {
    match event.get(field) {
        Some(CanonicalJsonValue::String(value)) => Ok(value),
        _ => Err(PduError::InvalidField(field)),
    }
}

fn required_integer(event: &CanonicalJsonObject, field: &'static str) -> Result<i64, PduError> {
    match event.get(field) {
        Some(CanonicalJsonValue::Integer(value)) => Ok((*value).into()),
        _ => Err(PduError::InvalidField(field)),
    }
}

fn required_object<'a>(
    event: &'a CanonicalJsonObject,
    field: &'static str,
) -> Result<&'a CanonicalJsonObject, PduError> {
    match event.get(field) {
        Some(CanonicalJsonValue::Object(value)) => Ok(value),
        _ => Err(PduError::InvalidField(field)),
    }
}

fn bounded_event_ids(
    event: &CanonicalJsonObject,
    field: &'static str,
    limit: usize,
) -> Result<(), PduError> {
    let Some(CanonicalJsonValue::Array(values)) = event.get(field) else {
        return Err(PduError::InvalidField(field));
    };
    if values.len() > limit {
        return Err(PduError::TooManyReferences {
            field,
            limit,
            count: values.len(),
        });
    }
    // A bare ID (v3+) or an `[id, hashes]` pair (v1/v2); which one the
    // version requires is `pairs`'s question.
    let is_reference = |value: &CanonicalJsonValue| match value {
        CanonicalJsonValue::String(_) => true,
        CanonicalJsonValue::Array(pair) => matches!(
            pair.as_slice(),
            [CanonicalJsonValue::String(_), CanonicalJsonValue::Object(_)]
        ),
        _ => false,
    };
    if !values.iter().all(is_reference) {
        return Err(PduError::InvalidField(field));
    }
    Ok(())
}

/// Require every reference in `field` to be a v1/v2 `[id, hashes]` pair --
/// and every v3+ reference to be a bare ID, which `validate` checks by
/// calling this only for v1/v2 and `bare` otherwise.
fn pairs(event: &CanonicalJsonObject, field: &'static str) -> Result<(), PduError> {
    let Some(CanonicalJsonValue::Array(values)) = event.get(field) else {
        return Err(PduError::InvalidField(field));
    };
    if values
        .iter()
        .all(|value| matches!(value, CanonicalJsonValue::Array(_)))
    {
        Ok(())
    } else {
        Err(PduError::InvalidField(field))
    }
}

/// Require every reference in `field` to be a bare ID (v3+).
fn bare(event: &CanonicalJsonObject, field: &'static str) -> Result<(), PduError> {
    let Some(CanonicalJsonValue::Array(values)) = event.get(field) else {
        return Err(PduError::InvalidField(field));
    };
    if values
        .iter()
        .all(|value| matches!(value, CanonicalJsonValue::String(_)))
    {
        Ok(())
    } else {
        Err(PduError::InvalidField(field))
    }
}

/// A failure to construct a valid, signed Matrix PDU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PduError {
    InvalidField(&'static str),
    InvalidDepth(i64),
    TooManyReferences {
        field: &'static str,
        limit: usize,
        count: usize,
    },
    UnsupportedRoomVersion(String),
    Signing(String),
}

impl From<crate::version::VersionError> for PduError {
    fn from(error: crate::version::VersionError) -> Self {
        match error {
            crate::version::VersionError::Unsupported(version) => {
                Self::UnsupportedRoomVersion(version)
            }
            other => Self::Signing(other.to_string()),
        }
    }
}
