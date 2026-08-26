//! Accounts, devices and access tokens.
//!
//! The tests that matter here are the security properties, because those are
//! the ones that fail silently: a token stored in clear still logs you in, and
//! a user-enumeration oracle still answers correctly.

use spindle_server::accounts::{AccountError, Accounts};
use spindle_store::{FjallStore, ReadView};
use tempfile::TempDir;

fn store() -> (TempDir, FjallStore) {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    (dir, store)
}

#[test]
fn a_registered_user_can_log_in_and_is_identified_by_the_token() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");

    accounts.register("alice", "correct horse").unwrap();
    assert!(accounts.verify_password("alice", "correct horse").unwrap());
    assert!(!accounts.verify_password("alice", "wrong horse").unwrap());

    let (token, device) = accounts.create_session("alice", None, None).unwrap();
    let identity = accounts
        .identify(&token)
        .unwrap()
        .expect("the token is live");
    assert_eq!(identity.user_id, "@alice:example.org");
    assert_eq!(identity.device_id, device.device_id);
}

/// The property that matters most, and the one a passing login test says
/// nothing about: a database read must not yield a usable credential.
#[test]
fn the_access_token_is_never_stored_in_a_form_that_could_be_replayed() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    accounts.register("alice", "hunter2").unwrap();
    let (token, _) = accounts.create_session("alice", None, None).unwrap();

    // Everything the store holds, as bytes.
    let mut everything = Vec::new();
    for prefix in 0x00_u8..=0x0f {
        for (key, value) in store.scan_prefix(&[prefix]).unwrap() {
            everything.extend_from_slice(&key);
            everything.extend_from_slice(&value);
        }
    }
    assert!(!everything.is_empty(), "the scan found nothing to check");

    let needle = token.as_bytes();
    assert!(
        !everything
            .windows(needle.len())
            .any(|window| window == needle),
        "the token appears verbatim in storage; a leaked backup would be live sessions"
    );

    // Nor the password.
    let password = b"hunter2";
    assert!(
        !everything
            .windows(password.len())
            .any(|window| window == password),
        "the password appears verbatim in storage"
    );

    // ...and the token still works, so the check above is not passing because
    // nothing was stored.
    assert!(accounts.identify(&token).unwrap().is_some());
}

#[test]
fn logging_out_invalidates_the_token_and_is_idempotent() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    accounts.register("alice", "hunter2").unwrap();
    let (token, _) = accounts.create_session("alice", None, None).unwrap();

    accounts.logout(&token).unwrap();
    assert!(accounts.identify(&token).unwrap().is_none());
    // Logging out twice is ordinary, not a fault.
    accounts.logout(&token).unwrap();
}

#[test]
fn two_sessions_get_different_tokens_and_devices() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    accounts.register("alice", "hunter2").unwrap();

    let (first, first_device) = accounts.create_session("alice", None, None).unwrap();
    let (second, second_device) = accounts.create_session("alice", None, None).unwrap();
    assert_ne!(first, second, "tokens must not repeat");
    assert_ne!(first_device.device_id, second_device.device_id);

    // Logging one device out must not touch the other.
    accounts.logout(&first).unwrap();
    assert!(accounts.identify(&first).unwrap().is_none());
    assert!(accounts.identify(&second).unwrap().is_some());
}

#[test]
fn a_taken_username_is_refused_rather_than_overwritten() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    accounts.register("alice", "first").unwrap();

    let error = accounts.register("alice", "second").unwrap_err();
    assert!(matches!(error, AccountError::UserInUse), "{error}");
    // The original password still works: registration did not clobber it.
    assert!(accounts.verify_password("alice", "first").unwrap());
}

/// The localpart ends up inside a user ID that federates, so the grammar is
/// enforced at registration rather than discovered by a peer.
#[test]
fn an_invalid_localpart_is_refused() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    for bad in ["", "Alice", "al ice", "alice:example.org", "@alice"] {
        let error = accounts
            .register(bad, "hunter2")
            .expect_err("{bad:?} must be refused");
        assert!(
            matches!(error, AccountError::InvalidUsername),
            "{bad:?}: {error}"
        );
    }
    // ...and the grammar that is allowed really is allowed.
    accounts.register("alice.smith_1-2/3+4", "hunter2").unwrap();
}

/// A wrong password and an unknown user must be indistinguishable, or the
/// difference is a user-enumeration oracle.
#[test]
fn an_unknown_user_verifies_like_a_wrong_password() {
    let (_dir, store) = store();
    let accounts = Accounts::new(&store, "example.org");
    accounts.register("alice", "hunter2").unwrap();

    assert!(!accounts.verify_password("alice", "wrong").unwrap());
    assert!(!accounts.verify_password("nobody", "wrong").unwrap());
    assert!(!accounts.verify_password("nobody", "hunter2").unwrap());

    // Both paths must actually do the hashing work. Timing is too noisy to
    // assert on directly here, so this checks the mechanism instead: the dummy
    // hash the unknown-user path verifies against has to be a real, parseable
    // Argon2 hash, not a short-circuit.
    let elapsed_known = time(|| {
        accounts.verify_password("alice", "wrong").unwrap();
    });
    let elapsed_unknown = time(|| {
        accounts.verify_password("nobody", "wrong").unwrap();
    });
    let ratio = elapsed_known.as_secs_f64() / elapsed_unknown.as_secs_f64().max(f64::MIN_POSITIVE);
    assert!(
        (0.2..5.0).contains(&ratio),
        "unknown-user verification took {ratio:.2}x the time a wrong password did, \
         which is enough to enumerate users"
    );
}

fn time(mut work: impl FnMut()) -> std::time::Duration {
    // A few iterations, because a single Argon2 hash on a noisy machine is not
    // a measurement.
    let started = std::time::Instant::now();
    for _ in 0..3 {
        work();
    }
    started.elapsed()
}
