//! Nonces for Synapse-compatible shared-secret registration.
//!
//! The shared secret is powerful enough to create an administrator. Each MAC
//! therefore includes a random, short-lived, single-use nonce. Keeping those
//! nonces in memory is deliberate: they authorize no durable workflow, and a
//! restart should invalidate every outstanding one.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE_TTL_MS: u64 = 60_000;

/// Outstanding shared-secret registration challenges.
pub struct RegistrationNonces {
    live: Mutex<HashMap<String, u64>>,
}

impl RegistrationNonces {
    #[must_use]
    pub fn new() -> Self {
        Self {
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a challenge that expires after one minute.
    #[must_use]
    pub fn issue(&self) -> String {
        let mut bytes = [0_u8; 32];
        crate::secrets::fill(&mut bytes);
        let nonce = hex(&bytes);
        let now = now_ms();
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.retain(|_, expires| *expires > now);
        live.insert(nonce.clone(), now.saturating_add(NONCE_TTL_MS));
        nonce
    }

    /// Consume a challenge. A second use fails even when the first MAC did not.
    pub fn consume(&self, nonce: &str) -> bool {
        let now = now_ms();
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.retain(|_, expires| *expires > now);
        live.remove(nonce).is_some()
    }
}

impl Default for RegistrationNonces {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
