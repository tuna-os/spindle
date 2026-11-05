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
//!
//! The ordinary writes of an authenticated account -- sends, joins, invites,
//! room creation, uploads -- are the other half (#741), and the opposite case:
//! every request counts, success or not, because the cost being bounded is
//! the write itself. They are token buckets rather than windows, keyed per
//! user, for the reason [`Rate`] gives; [`limit_write`] says who is exempt.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::AppState;
use crate::config::{Rate, RateLimitConfig};
use crate::errors::MatrixError;

/// Bound attacker-controlled counter cardinality and identifier allocation.
const MAX_TRACKED_KEYS: usize = 65_536;
const MAX_KEY_BYTES: usize = 512;

/// A fixed-window counter.
///
/// Deliberately not a token bucket. The window's coarseness is the point: an
/// attacker cannot smooth their rate down to just under a refill and proceed
/// indefinitely, which is what a leaky bucket permits by construction.
#[derive(Clone, Copy, Debug)]
struct Window {
    started: Instant,
    expires: Instant,
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
    enabled: bool,
    windows: Mutex<HashMap<String, Window>>,
    /// Token buckets, as the moment each would be full again with the
    /// last request it took (GCRA's "theoretical arrival time"). One
    /// instant per key is the whole state: no counter, no refill task.
    buckets: Mutex<HashMap<String, Instant>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_enabled(true)
    }

    /// A limiter that lets everything through when `enabled` is false.
    ///
    /// Disabled is checked at the point of decision rather than by not
    /// wiring the limiter up, so the code path a test exercises is the one
    /// production runs -- a limiter that is absent in one build and present
    /// in another is two servers.
    #[must_use]
    pub fn with_enabled(enabled: bool) -> Self {
        Self {
            enabled,
            windows: Mutex::new(HashMap::new()),
            buckets: Mutex::new(HashMap::new()),
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
        if !self.enabled {
            return Ok(());
        }
        if key.len() > MAX_KEY_BYTES {
            return Err(RetryAfter(limit.window));
        }
        let mut windows = self.windows.lock().unwrap_or_else(|poisoned| {
            // A panic inside the critical section leaves counters, not
            // invariants, so the recovered state is usable. Refusing traffic
            // because a counter map was touched during a panic would turn a
            // small bug into an outage.
            poisoned.into_inner()
        });

        // Preserve existing budgets at saturation: evicting a live counter
        // would let an attacker reset it by flooding distinct identifiers.
        if windows.len() >= MAX_TRACKED_KEYS && !windows.contains_key(key) {
            windows.retain(|_, window| window.expires > now);
            if windows.len() >= MAX_TRACKED_KEYS {
                return Err(RetryAfter(limit.window));
            }
        }
        let entry = windows.entry(key.to_owned()).or_insert(Window {
            started: now,
            expires: now + limit.window,
            count: 0,
        });

        if now.duration_since(entry.started) >= limit.window {
            *entry = Window {
                started: now,
                expires: now + limit.window,
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

    /// Spend one request of `rate` against `key`, or refuse it.
    ///
    /// # Errors
    ///
    /// Returns [`RetryAfter`] -- how long until one request is earned
    /// back -- when the bucket is empty.
    pub fn check_rate(&self, key: &str, rate: Rate) -> Result<(), RetryAfter> {
        self.check_rate_at(key, rate, Instant::now())
    }

    /// As [`RateLimiter::check_rate`], with the clock supplied.
    ///
    /// A bucket of `burst` refilled every `interval` is the GCRA: keep the
    /// time `full` at which the bucket would be full again, admit a
    /// request when `full + interval` is no more than `burst` intervals
    /// away, and move `full` on by one interval. A refusal changes
    /// nothing, so a client hammering an empty bucket does not push its
    /// own recovery further away.
    ///
    /// # Errors
    ///
    /// Returns [`RetryAfter`] when the bucket is empty.
    pub fn check_rate_at(&self, key: &str, rate: Rate, now: Instant) -> Result<(), RetryAfter> {
        if !self.enabled {
            return Ok(());
        }
        let interval = rate.interval();
        if key.len() > MAX_KEY_BYTES {
            return Err(RetryAfter(interval));
        }
        let tolerance = interval.saturating_mul(rate.burst);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The same bound as the windows, for the same reason: a key is
        // only reclaimed once its bucket has refilled, so flooding fresh
        // keys cannot reset anyone's spent budget.
        if buckets.len() >= MAX_TRACKED_KEYS && !buckets.contains_key(key) {
            buckets.retain(|_, full| *full > now);
            if buckets.len() >= MAX_TRACKED_KEYS {
                return Err(RetryAfter(interval));
            }
        }
        let full = buckets.get(key).map_or(now, |full| (*full).max(now));
        let Some(next) = full.checked_add(interval) else {
            return Err(RetryAfter(interval));
        };
        let ahead = next.duration_since(now);
        if ahead > tolerance {
            return Err(RetryAfter(ahead.saturating_sub(tolerance)));
        }
        if let Some(full) = buckets.get_mut(key) {
            *full = next;
        } else {
            buckets.insert(key.to_owned(), next);
        }
        Ok(())
    }

    /// How many token buckets are currently tracked.
    #[must_use]
    pub fn tracked_rates(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// The per-user write budgets (#741), one per kind of write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Budget {
    /// `PUT /send`, `PUT /state`, `PUT /redact`.
    Message,
    /// A join or knock this server answers itself.
    JoinLocal,
    /// A join or knock carried to another server.
    JoinRemote,
    /// An invite, against its sender.
    Invite,
    /// An invite, against the user it is to.
    Invited,
    /// `POST /createRoom`.
    RoomCreation,
    /// A new media ID: `POST /upload` or `POST /media/v1/create`.
    MediaUpload,
}

impl Budget {
    fn rate(self, config: &RateLimitConfig) -> Rate {
        match self {
            Self::Message => config.messages,
            Self::JoinLocal => config.joins_local,
            Self::JoinRemote => config.joins_remote,
            Self::Invite => config.invites_per_issuer,
            Self::Invited => config.invites_per_target,
            Self::RoomCreation => config.room_creation,
            Self::MediaUpload => config.media_uploads,
        }
    }

    /// The key's namespace: every budget is its own, so a user who has
    /// spent their sends can still join.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::JoinLocal => "join",
            Self::JoinRemote => "join-remote",
            Self::Invite => "invite",
            Self::Invited => "invited",
            Self::RoomCreation => "create-room",
            Self::MediaUpload => "media",
        }
    }
}

/// Spend one of `actor`'s `class` budget, or refuse with 429
/// `M_LIMIT_EXCEEDED` and `retry_after_ms`.
///
/// # Errors
///
/// The refusal, or a storage error reading whether `actor` is exempt.
pub(crate) fn limit_write(state: &AppState, class: Budget, actor: &str) -> Result<(), MatrixError> {
    limit_write_on(state, class, actor, actor)
}

/// As [`limit_write`], with the budget keyed on `subject` rather than the
/// actor: the invitee's budget, spent by whoever invites them. Exemption
/// is still the actor's -- an exempt bridge inviting is not limited by
/// how many invites its target has had.
///
/// # Errors
///
/// As [`limit_write`].
pub(crate) fn limit_write_on(
    state: &AppState,
    class: Budget,
    actor: &str,
    subject: &str,
) -> Result<(), MatrixError> {
    let key = format!("{}:{subject}", class.prefix());
    let Err(retry) = state
        .limiter
        .check_rate(&key, class.rate(&state.config.ratelimit))
    else {
        return Ok(());
    };
    // Exemption is looked up only once the budget says no. The admin flag
    // is a store read, and every write paying it so that the rare exempt
    // account can skip a counter it would almost never exhaust is the
    // wrong way round. The cost is that an exempt account's own sends
    // still tick its bucket, which nothing ever reads but this branch.
    if exempt_from_write_limits(state, actor)? {
        return Ok(());
    }
    Err(MatrixError::limit_exceeded(retry.as_millis()))
}

/// Whether `user_id` is exempt from the write budgets and the media quota.
///
/// Synapse's rule for appservices, which is the spec's: a registration's
/// own sender is never limited, and the users in its namespaces are exempt
/// when the registration says `rate_limited: false`. A bridge relays a
/// whole other network's traffic through one registration, and its
/// operator is the one who has said whether that traffic is trusted.
///
/// Server admins too. Synapse gets there per account, through its
/// rate-limit override table; this server has no such table, and the
/// accounts an operator trusts with every room are the ones it would
/// hold. An admin locked out of redacting a spam wave by the send rate
/// would be the limit protecting the attack.
///
/// # Errors
///
/// A storage error reading the account.
pub(crate) fn exempt_from_write_limits(
    state: &AppState,
    user_id: &str,
) -> Result<bool, MatrixError> {
    let server_name = &state.config.server.name;
    let appservice = state.appservices.all().iter().any(|registration| {
        registration.sender_user(server_name) == user_id
            || (!registration.rate_limited && registration.may_masquerade_as(user_id, server_name))
    });
    if appservice {
        return Ok(true);
    }
    crate::admin::is_server_admin(state, user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))
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

/// `OpenID` token mints, per user.
///
/// The first authenticated rate, and it is here because a mint is not a
/// read: each is a durable row on the caller's say-so, and each exists to
/// make a third party -- a JWT service, an SFU -- do work. A client mints
/// one per call it joins, so twenty a minute is a busy user several times
/// over and a loop within a few seconds.
pub const OPENID_TOKEN_PER_USER: Limit = Limit::new(20, Duration::from_secs(60));

/// `LiveKit` token mints, per user, on the built-in JWT service.
///
/// Minting is an HMAC here and a room on the SFU there, which is the
/// asymmetry #38 names: cheap for this server, not for the one the token
/// is for. One token joins one call; a client needs a fresh one only when
/// it rejoins or its token's window closes.
pub const LIVEKIT_TOKEN_PER_USER: Limit = Limit::new(20, Duration::from_secs(60));

/// Confirmation emails one account may ask for (#608).
///
/// Each is a mail to an address the account only claims to own, so the
/// budget is what stops the add-address form being a way to send this
/// server's mail to strangers.
pub const EMAIL_PER_USER: Limit = Limit::new(5, Duration::from_secs(60 * 60));

/// Forgot-password requests per source address (#608).
pub const RESET_REQUEST_PER_SOURCE: Limit = Limit::new(5, Duration::from_secs(15 * 60));

/// Forgot-password requests per email address (#608), whether or not it
/// belongs to anyone — a limit that applied only to known addresses would
/// be the enumeration oracle the uniform page exists to deny.
pub const RESET_REQUEST_PER_ADDRESS: Limit = Limit::new(3, Duration::from_secs(60 * 60));

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn identifier_flood_cannot_allocate_or_reset_live_budgets() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let limit = Limit::new(1, Duration::from_secs(60));
        for number in 0..MAX_TRACKED_KEYS {
            assert!(limiter.check_at(&number.to_string(), limit, now).is_ok());
        }
        assert!(limiter.check_at("new", limit, now).is_err());
        assert!(limiter.check_at("0", limit, now).is_err());
        assert_eq!(limiter.tracked(), MAX_TRACKED_KEYS);
        assert!(limiter.check_at("new", limit, now + limit.window).is_ok());
        assert!(
            limiter
                .check_at(&"x".repeat(MAX_KEY_BYTES + 1), limit, now)
                .is_err()
        );
        assert_eq!(limiter.tracked(), 1);
    }

    /// `burst` at once, then one per interval; the wait reported is the
    /// time to the next one, and a refusal does not push it further away.
    #[test]
    fn a_bucket_admits_its_burst_then_refills_at_its_rate() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let rate = Rate::new(2.0, 3);
        let interval = Duration::from_millis(500);
        for _ in 0..3 {
            assert!(limiter.check_rate_at("alice", rate, now).is_ok());
        }
        assert_eq!(
            limiter.check_rate_at("alice", rate, now),
            Err(RetryAfter(interval))
        );
        assert_eq!(
            limiter.check_rate_at("alice", rate, now),
            Err(RetryAfter(interval)),
            "refusals spend nothing"
        );
        assert!(limiter.check_rate_at("bob", rate, now).is_ok(), "per key");
        let later = now + interval;
        assert!(limiter.check_rate_at("alice", rate, later).is_ok());
        assert!(limiter.check_rate_at("alice", rate, later).is_err());
        // Idle long enough and the whole burst is back, not more.
        let idle = now + interval * 10;
        for _ in 0..3 {
            assert!(limiter.check_rate_at("alice", rate, idle).is_ok());
        }
        assert!(limiter.check_rate_at("alice", rate, idle).is_err());
    }

    #[test]
    fn bucket_flood_cannot_reset_live_budgets() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let rate = Rate::new(1.0, 1);
        for number in 0..MAX_TRACKED_KEYS {
            assert!(
                limiter
                    .check_rate_at(&number.to_string(), rate, now)
                    .is_ok()
            );
        }
        assert!(limiter.check_rate_at("new", rate, now).is_err());
        assert!(limiter.check_rate_at("0", rate, now).is_err());
        assert_eq!(limiter.tracked_rates(), MAX_TRACKED_KEYS);
        // Refilled buckets are the ones reclaimed.
        let later = now + Duration::from_secs(1);
        assert!(limiter.check_rate_at("new", rate, later).is_ok());
        assert_eq!(limiter.tracked_rates(), 1);
    }

    #[test]
    fn a_disabled_limiter_has_no_buckets() {
        let limiter = RateLimiter::with_enabled(false);
        let rate = Rate::new(0.001, 1);
        for _ in 0..10 {
            assert!(limiter.check_rate("alice", rate).is_ok());
        }
        assert_eq!(limiter.tracked_rates(), 0);
    }
}
