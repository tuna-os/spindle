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

/// The key version this server mints.
///
/// Matrix key IDs are `ed25519:<version>`. The version is opaque; what matters
/// is that it is stable for the life of the key, because that is how a peer
/// refers to the key it cached.
const KEY_VERSION: &str = "0";

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
        let key = storage_key();
        if let Some(document) = store.get(&key)? {
            let pair = Ed25519KeyPair::from_der(&document, KEY_VERSION.to_owned())
                .map_err(|error| SigningError::Unreadable(error.to_string()))?;
            return Ok(Self { pair });
        }

        // First start. Generated once and then never again: see the module
        // comment on why regenerating is worse than either alternative.
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, KEY_VERSION.to_owned())
            .map_err(|error| SigningError::Unreadable(error.to_string()))?;
        store.put(&key, &document)?;
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

fn storage_key() -> Vec<u8> {
    let mut key = vec![KEY_SCHEMA_VERSION, Keyspace::ServerKey as u8];
    key.extend_from_slice(KEY_VERSION.as_bytes());
    key
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
        }
    }
}

impl std::error::Error for SigningError {}
