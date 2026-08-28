//! Entropy for the credentials this server mints.
//!
//! Access tokens, refresh tokens, media IDs, OIDC codes, room IDs and
//! password salts are all "fill these bytes from the OS and never look
//! back". Until `rand` 0.10 they each spelled that as
//! `rand::rngs::OsRng.fill_bytes(&mut bytes)` — an infallible call, so
//! there was no decision to make and nothing to keep consistent.
//!
//! 0.10 renamed `OsRng` to [`SysRng`] and, more usefully, stopped
//! pretending: reading the OS entropy source can fail, so it implements
//! `TryRng` and hands back a `Result`. That turns a non-question into a
//! question asked at eight call sites, and the answer has to be the same
//! at all eight — which is why it is answered here instead.
//!
//! The answer is that there is no answer: a token minted without entropy
//! is a token an attacker can predict, and every one of these values is
//! a bearer credential or an identifier that must not collide. Returning
//! an error would invite a caller to carry on with a degraded secret;
//! falling back to a seeded RNG would be worse still. If the kernel
//! cannot produce random bytes, the correct behaviour is to stop.
//!
//! [`SysRng`]: rand::rngs::SysRng

use rand::TryRng as _;

/// Fill `dst` with cryptographically secure bytes from the operating system.
///
/// # Panics
///
/// If the OS entropy source is unavailable. See the module docs: this is
/// deliberate, and it is the same outcome `rand` 0.8 produced — it simply
/// panicked inside `fill_bytes` where nothing named the decision.
pub fn fill(dst: &mut [u8]) {
    rand::rngs::SysRng
        .try_fill_bytes(dst)
        .expect("the OS entropy source must be readable to mint credentials");
}

#[cfg(test)]
mod tests {
    use super::fill;

    #[test]
    fn filling_produces_different_bytes_each_time() {
        // Not a randomness test — it cannot be, from inside. It catches
        // the failure that actually happens: a refactor that leaves the
        // buffer untouched, which would hand every user the same token.
        let mut first = [0_u8; 32];
        let mut second = [0_u8; 32];
        fill(&mut first);
        fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0_u8; 32]);
    }

    #[test]
    fn filling_an_empty_slice_is_allowed() {
        fill(&mut []);
    }
}
