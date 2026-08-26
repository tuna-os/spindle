//! Rate limiting on the endpoints worth attacking.

use std::time::Duration;

use spindle_server::ratelimit::{Limit, RateLimiter};

const LIMIT: Limit = Limit::new(3, Duration::from_secs(60));

#[test]
fn a_key_is_refused_once_it_reaches_the_limit() {
    let limiter = RateLimiter::new();
    for attempt in 0..3 {
        assert!(limiter.check("k", LIMIT).is_ok(), "attempt {attempt}");
    }
    let retry = limiter
        .check("k", LIMIT)
        .expect_err("the fourth is refused");
    assert!(
        retry.as_millis() > 0,
        "a client told to wait 0ms retries now"
    );
    assert!(retry.as_millis() <= 60_000);
}

#[test]
fn keys_are_counted_independently() {
    let limiter = RateLimiter::new();
    for _ in 0..3 {
        limiter.check("a", LIMIT).unwrap();
    }
    assert!(limiter.check("a", LIMIT).is_err());
    // A different account, or a different address, is unaffected.
    assert!(limiter.check("b", LIMIT).is_ok());
}

#[test]
fn the_window_elapses() {
    let limiter = RateLimiter::new();
    let start = std::time::Instant::now();
    for _ in 0..3 {
        limiter.check_at("k", LIMIT, start).unwrap();
    }
    assert!(limiter.check_at("k", LIMIT, start).is_err());

    // Just inside the window: still refused.
    let nearly = start + Duration::from_secs(59);
    assert!(limiter.check_at("k", LIMIT, nearly).is_err());

    // Past it: allowed again.
    let after = start + Duration::from_secs(61);
    assert!(limiter.check_at("k", LIMIT, after).is_ok());
}

/// A success must not leave the caller closer to a lockout than they started,
/// or a busy shared address locks out its own legitimate users.
#[test]
fn forgetting_a_key_restores_its_full_budget() {
    let limiter = RateLimiter::new();
    for _ in 0..3 {
        limiter.check("k", LIMIT).unwrap();
    }
    assert!(limiter.check("k", LIMIT).is_err());
    limiter.forget("k");
    for _ in 0..3 {
        assert!(limiter.check("k", LIMIT).is_ok());
    }
}

/// The map grows once per distinct key ever seen, which an attacker can drive
/// deliberately by varying the key. Expired windows have to go.
#[test]
fn expired_windows_are_evicted_so_the_map_does_not_grow_without_bound() {
    let limiter = RateLimiter::new();
    let start = std::time::Instant::now();
    for index in 0..1_000 {
        limiter
            .check_at(&format!("source:{index}"), LIMIT, start)
            .unwrap();
    }
    assert_eq!(limiter.tracked(), 1_000);

    // Nothing has expired yet, so nothing is dropped.
    limiter.evict_expired_at(Duration::from_secs(60), start + Duration::from_secs(30));
    assert_eq!(limiter.tracked(), 1_000);

    limiter.evict_expired_at(Duration::from_secs(60), start + Duration::from_secs(61));
    assert_eq!(
        limiter.tracked(),
        0,
        "an attacker can otherwise leak memory by varying the key"
    );
}

/// The retry hint has to shrink as the window elapses, or a client that honours
/// it waits a full window every time however long it already waited.
#[test]
fn the_retry_hint_counts_down() {
    let limiter = RateLimiter::new();
    let start = std::time::Instant::now();
    for _ in 0..3 {
        limiter.check_at("k", LIMIT, start).unwrap();
    }
    let immediately = limiter.check_at("k", LIMIT, start).unwrap_err();
    let later = limiter
        .check_at("k", LIMIT, start + Duration::from_secs(45))
        .unwrap_err();
    assert!(
        later.as_millis() < immediately.as_millis(),
        "{} is not less than {}",
        later.as_millis(),
        immediately.as_millis()
    );
}
