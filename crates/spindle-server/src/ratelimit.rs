//! Rate limiting for the endpoints that are worth attacking.
//!
//! A password login endpoint with no limit is a brute-force target, and the
//! interesting part is *what* to key the limit on. Two obvious choices are each
//! individually useless:
//!
//! - **Per account only.** An attacker spreads one guess across ten thousand
//!   accounts and never trips it, which is credential stuffing exactly.
//! - **Per source only.** An attacker with a botnet gets one full budget per
//!   address, and a corporate NAT gets everyone behind it locked out together.
//!
//! So both are counted, and either tripping is a refusal. That is not belt and
//! braces; each covers the attack the other cannot see.
//!
//! Successful requests do not consume budget on the auth endpoints. A user
//! logging in correctly is not the traffic being defended against, and counting
//! them means a busy shared address locks out its legitimate users first.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A fixed-window counter.
///
/// Deliberately not a token bucket. The window's coarseness is the point: an
/// attacker cannot smooth their rate down to just under a refill and proceed
/// indefinitely, which is what a leaky bucket permits by construction.
#[derive(Clone, Copy, Debug)]
struct Window {
    started: Instant,
    count: u32,
}

/// One limit: `max` events per `window`.
#[derive(Clone, Copy, Debug)]
pub struct Limit {
    pub max: u32,
    pub window: Duration,
}

impl Limit {
    #[must_use]
    pub const fn new(max: u32, window: Duration) -> Self {
        Self { max, window }
    }
}

/// How long a caller should wait before trying again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryAfter(pub Duration);

impl RetryAfter {
    #[must_use]
    pub fn as_millis(self) -> u64 {
        u64::try_from(self.0.as_millis()).unwrap_or(u64::MAX)
    }
}

/// Counters keyed by an opaque string.
///
/// In-memory, which is correct for a single node and is what SPEC §15 assumes.
/// A multi-node deployment needs shared state, and that is #24's problem —
/// noted here rather than silently assumed away, because a per-node limit
/// behind a load balancer is N times the limit it claims to be.
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Count one event against `key`, or refuse it.
    ///
    /// # Errors
    ///
    /// Returns [`RetryAfter`] when the limit is already reached.
    pub fn check(&self, key: &str, limit: Limit) -> Result<(), RetryAfter> {
        self.check_at(key, limit, Instant::now())
    }

    /// As [`RateLimiter::check`], with the clock supplied.
    ///
    /// Exposed so a test can advance time rather than sleep through a window.
    /// A rate-limit test that sleeps is a test nobody runs.
    ///
    /// # Errors
    ///
    /// Returns [`RetryAfter`] when the limit is already reached.
    pub fn check_at(&self, key: &str, limit: Limit, now: Instant) -> Result<(), RetryAfter> {
        let mut windows = self.windows.lock().unwrap_or_else(|poisoned| {
            // A panic inside the critical section leaves counters, not
            // invariants, so the recovered state is usable. Refusing traffic
            // because a counter map was touched during a panic would turn a
            // small bug into an outage.
            poisoned.into_inner()
        });

        let entry = windows.entry(key.to_owned()).or_insert(Window {
            started: now,
            count: 0,
        });

        if now.duration_since(entry.started) >= limit.window {
            *entry = Window {
                started: now,
                count: 0,
            };
        }

        if entry.count >= limit.max {
            let elapsed = now.duration_since(entry.started);
            return Err(RetryAfter(limit.window.saturating_sub(elapsed)));
        }

        entry.count += 1;
        Ok(())
    }

    /// Forget a key's history, so a success does not leave the caller closer to
    /// a lockout than they started.
    pub fn forget(&self, key: &str) {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        windows.remove(key);
    }

    /// Drop windows that have fully elapsed.
    ///
    /// Without this the map grows once per distinct key seen — every address
    /// that ever tried to log in — which is a slow memory leak an attacker can
    /// drive deliberately by varying the key.
    pub fn evict_expired(&self, longest: Duration) {
        self.evict_expired_at(longest, Instant::now());
    }

    /// As [`RateLimiter::evict_expired`], with the clock supplied.
    pub fn evict_expired_at(&self, longest: Duration, now: Instant) {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        windows.retain(|_, window| now.duration_since(window.started) < longest);
    }

    /// How many keys are currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Failed authentication attempts, per account.
///
/// Low, because a legitimate user does not fail ten times a minute and an
/// attacker needs thousands of attempts for this to be worth doing.
pub const FAILED_LOGIN_PER_ACCOUNT: Limit = Limit::new(5, Duration::from_secs(60));

/// Failed authentication attempts, per source address.
///
/// Higher than the per-account limit, because one address legitimately carries
/// many users — an office, a university, a mobile carrier's NAT — and a limit
/// tight enough to stop a single attacker would lock all of them out together.
pub const FAILED_LOGIN_PER_SOURCE: Limit = Limit::new(30, Duration::from_secs(60));

/// Registrations per source address.
///
/// Account creation is the expensive one to allow: each is an Argon2 hash and a
/// durable write, and a bulk-registration flood is both a spam problem and a
/// cheap way to make the server do work.
pub const REGISTER_PER_SOURCE: Limit = Limit::new(5, Duration::from_secs(300));
