use ruma::{
    CanonicalJsonObject, CanonicalJsonValue, RoomVersionId,
    signatures::{KeyPair, hash_and_sign_event, reference_hash},
};

use crate::EventId;

const MAX_PREV_EVENTS: usize = 20;
const MAX_AUTH_EVENTS: usize = 10;
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
        validate(&canonical)?;
        let rules = room_version
            .rules()
            .ok_or_else(|| PduError::UnsupportedRoomVersion(room_version.to_string()))?;
        hash_and_sign_event(server_name, key_pair, &mut canonical, &rules.redaction)
            .map_err(|error| PduError::Signing(error.to_string()))?;
        let hash = reference_hash(&canonical, &rules)
            .map_err(|error| PduError::Signing(error.to_string()))?;

        Ok(Self {
            room_version,
            event_id: EventId::new(format!("${hash}")),
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
        validate(&canonical)?;
        let rules = room_version
            .rules()
            .ok_or_else(|| PduError::UnsupportedRoomVersion(room_version.to_string()))?;
        let hash = reference_hash(&canonical, &rules)
            .map_err(|error| PduError::Signing(error.to_string()))?;
        Ok(Self {
            room_version,
            event_id: EventId::new(format!("${hash}")),
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

fn validate(event: &CanonicalJsonObject) -> Result<(), PduError> {
    required_string(event, "type")?;
    required_string(event, "sender")?;
    required_integer(event, "origin_server_ts")?;
    required_object(event, "content")?;
    let depth = required_integer(event, "depth")?;
    if !(0..=MAX_DEPTH).contains(&depth) {
        return Err(PduError::InvalidDepth(depth));
    }
    bounded_event_ids(event, "prev_events", MAX_PREV_EVENTS)?;
    bounded_event_ids(event, "auth_events", MAX_AUTH_EVENTS)?;
    Ok(())
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
    if values
        .iter()
        .any(|value| !matches!(value, CanonicalJsonValue::String(_)))
    {
        return Err(PduError::InvalidField(field));
    }
    Ok(())
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
