//! This server's Ed25519 signing key.
//!
//! Every event a homeserver creates is signed, and its event ID is the
//! reference hash of the signed canonical JSON. That makes the key a
//! prerequisite for creating *any* event, not a federation concern that can
//! wait for M3 — an unsigned event is not a Matrix event, and one created
//! before the key existed could never be made valid afterwards, because its ID
//! is derived from content that would have to change.
//!
//! Two properties this module is careful about:
//!
//! **The key is generated once and never regenerated.** Its public half is
//! published, peers cache it, and every event ever signed with it refers to it
//! by ID. Minting a new one under the same ID would invalidate history; minting
//! one under a new ID silently orphans every signature made with the old one.
//! So a key that exists is loaded, never replaced.
//!
//! **The private half never leaves this module.** It is stored, loaded and used
//! here; what the rest of the server can obtain is the public key and the
//! ability to sign, never the bytes.

use ruma::signatures::Ed25519KeyPair;
use spindle_core::keys::{KEY_SCHEMA_VERSION, Keyspace};
use spindle_store::{Store, StoreError};

/// The key version a new Spindle mints.
///
/// Matrix key IDs are `ed25519:<version>`. The version is opaque; what matters
/// is that it is stable for the life of the key, because that is how a peer
/// refers to the key it cached.
const KEY_VERSION: &str = "0";

const ED25519_PKCS8_V1_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// This server's signing key.
pub struct ServerKey {
    pair: Ed25519KeyPair,
}

impl ServerKey {
    /// Load the stored key, or generate and store one on first start.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] if the key cannot be read, parsed or written.
    pub fn load_or_create<S: Store>(store: &S) -> Result<Self, SigningError> {
        let stored = store.scan_prefix(&storage_prefix())?;
        if stored.len() > 1 {
            return Err(SigningError::MultipleKeys(stored.len()));
        }
        if let Some((key, document)) = stored.first() {
            let version = version_of(key)?;
            let pair = Ed25519KeyPair::from_der(document, version)
                .map_err(|error| SigningError::Unreadable(error.to_string()))?;
            return Ok(Self { pair });
        }

        // First start. Generated once and then never again: see the module
        // comment on why regenerating is worse than either alternative.
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, KEY_VERSION.to_owned())
            .map_err(|error| SigningError::Unreadable(error.to_string()))?;
        store.put(&storage_key(KEY_VERSION), &document)?;
        Ok(Self { pair })
    }

    /// Install the signing seed from a Synapse `.signing.key` file.
    ///
    /// The file is the three-field format Synapse writes:
    /// `ed25519 <version> <unpadded-base64-seed>`. Installation is allowed
    /// only before any server key exists; overwriting a live key would make
    /// every event signed since that key was created unverifiable.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] if the file is malformed, a key is already
    /// installed, or the store cannot persist the imported key.
    pub fn install_synapse<S: Store>(store: &S, source: &str) -> Result<Self, SigningError> {
        if !store.scan_prefix(&storage_prefix())?.is_empty() {
            return Err(SigningError::AlreadyExists);
        }
        let mut fields = source.split_whitespace();
        let (Some(algorithm), Some(version), Some(seed), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(SigningError::InvalidSynapse(
                "expected exactly: ed25519 <version> <base64-seed>".to_owned(),
            ));
        };
        if algorithm != "ed25519" {
            return Err(SigningError::InvalidSynapse(format!(
                "unsupported signing algorithm {algorithm:?}"
            )));
        }
        if version.is_empty()
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(SigningError::InvalidSynapse(
                "the key version contains invalid characters".to_owned(),
            ));
        }
        let seed = decode_base64_unpadded(seed)?;
        if seed.len() != 32 {
            return Err(SigningError::InvalidSynapse(format!(
                "an Ed25519 seed is 32 bytes, not {}",
                seed.len()
            )));
        }
        let mut document = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + seed.len());
        document.extend_from_slice(ED25519_PKCS8_V1_PREFIX);
        document.extend_from_slice(&seed);
        let pair = Ed25519KeyPair::from_der(&document, version.to_owned())
            .map_err(|error| SigningError::Unreadable(error.to_string()))?;
        store.put(&storage_key(version), &document)?;
        Ok(Self { pair })
    }

    /// `ed25519:0`, as it appears in a signature block and in `/_matrix/key/v2/server`.
    #[must_use]
    pub fn key_id(&self) -> String {
        format!("ed25519:{}", self.pair.version())
    }

    /// The public half, unpadded base64 as Matrix publishes it.
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        base64_unpadded(&self.pair.public_key())
    }

    /// The key pair, for signing.
    ///
    /// Deliberately not a getter for the private bytes: callers sign through
    /// this, and there is no path that hands the secret out.
    #[must_use]
    pub fn pair(&self) -> &Ed25519KeyPair {
        &self.pair
    }
}

fn storage_prefix() -> Vec<u8> {
    vec![KEY_SCHEMA_VERSION, Keyspace::ServerKey as u8]
}

fn storage_key(version: &str) -> Vec<u8> {
    let mut key = storage_prefix();
    key.extend_from_slice(version.as_bytes());
    key
}

fn version_of(key: &[u8]) -> Result<String, SigningError> {
    let prefix = storage_prefix();
    String::from_utf8(key.get(prefix.len()..).unwrap_or_default().to_vec())
        .map_err(|_| SigningError::Unreadable("the stored key version is not UTF-8".to_owned()))
        .and_then(|version| {
            if version.is_empty() {
                Err(SigningError::Unreadable(
                    "the stored key has no version".to_owned(),
                ))
            } else {
                Ok(version)
            }
        })
}

fn decode_base64_unpadded(encoded: &str) -> Result<Vec<u8>, SigningError> {
    if encoded.contains('=') && !encoded.ends_with('=') {
        return Err(SigningError::InvalidSynapse(
            "invalid base64 padding".to_owned(),
        ));
    }
    let encoded = encoded.trim_end_matches('=');
    if encoded.len() % 4 == 1 {
        return Err(SigningError::InvalidSynapse(
            "invalid base64 length".to_owned(),
        ));
    }
    let value = |byte: u8| -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    for chunk in encoded.as_bytes().chunks(4) {
        let mut bits = 0u32;
        for &byte in chunk {
            let digit = value(byte).ok_or_else(|| {
                SigningError::InvalidSynapse("the seed is not valid base64".to_owned())
            })?;
            bits = (bits << 6) | u32::from(digit);
        }
        bits <<= 6 * (4 - chunk.len());
        for index in 0..chunk.len().saturating_sub(1) {
            output.push(((bits >> (16 - 8 * index)) & 0xff) as u8);
        }
    }
    Ok(output)
}

/// Matrix uses unpadded base64 throughout, and a padded value is not merely
/// ugly — it is a different string, so a peer comparing key bytes to a cached
/// copy would see a mismatch.
fn base64_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (b(0) << 16) | (b(1) << 8) | b(2);
        let take = chunk.len() + 1;
        for slot in 0..take {
            let index = (triple >> (18 - 6 * slot)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

/// Why the signing key could not be established.
#[derive(Debug)]
pub enum SigningError {
    Storage(StoreError),
    Unreadable(String),
    InvalidSynapse(String),
    AlreadyExists,
    MultipleKeys(usize),
}

impl From<StoreError> for SigningError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Unreadable(message) => write!(
                formatter,
                "the stored signing key could not be read: {message}"
            ),
            Self::InvalidSynapse(message) => {
                write!(formatter, "invalid Synapse signing key: {message}")
            }
            Self::AlreadyExists => write!(formatter, "a server signing key is already installed"),
            Self::MultipleKeys(count) => write!(
                formatter,
                "the store contains {count} active server signing keys; expected exactly one"
            ),
        }
    }
}

impl std::error::Error for SigningError {}
