//! #412: the two offline subcommands nothing exercised end to end.
//!
//! `spindle promote-admin <config> <localpart>` mints the first admin
//! against the store with the server stopped (#83), and `spindle migrate
//! <config> [--dry-run]` moves a store forward to this binary's schema
//! (#20). `accounts.rs` and `spindle-store`'s `schema_migration` tests
//! cover the operations; these cover the command line around them, which
//! is what an operator actually types -- the usage refusals, the exit
//! codes, and the one coupling that matters most: a store one schema
//! behind makes *every* ordinary command refuse and name `migrate`.

use std::process::Command;

use spindle_store::Store as _;
use tempfile::TempDir;

/// Write a config naming a store directory under `work`.
fn config_for(work: &TempDir, data: &str) -> std::path::PathBuf {
    let config_path = work.path().join(format!("{data}.toml"));
    std::fs::write(
        &config_path,
        format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n",
            work.path().join(data).display()
        ),
    )
    .unwrap();
    config_path
}

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spindle"))
        .args(args)
        .output()
        .expect("the spindle binary runs")
}

fn os(value: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(value)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Open the store a config names, the way the command does.
fn store_of(config_path: &std::path::Path) -> spindle_store::FjallStore {
    let config = spindle_server::Config::load(config_path.to_str().unwrap()).unwrap();
    spindle_store::FjallStore::open(&config.storage.path).unwrap()
}

#[test]
fn promote_admin_without_its_arguments_prints_usage_and_fails() {
    let output = run(&[os("promote-admin")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("usage: spindle promote-admin"));
}

#[test]
fn promote_admin_refuses_an_account_that_does_not_exist() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    // Create the store so the failure is the account's, not the path's.
    drop(store_of(&config));

    let output = run(&[os("promote-admin"), config.as_os_str(), os("nobody")]);
    assert!(!output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("no account named nobody"), "{stderr}");
    assert!(stderr.contains("register it first"), "{stderr}");
}

#[test]
fn promote_admin_makes_a_registered_account_an_admin() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    {
        let store = store_of(&config);
        let accounts = spindle_server::accounts::Accounts::new(&store, "example.org");
        accounts.register("alice", "hunter2").unwrap();
        assert!(!accounts.account("alice").unwrap().unwrap().admin);
    }

    let output = run(&[os("promote-admin"), config.as_os_str(), os("alice")]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("alice is now a server admin"));

    let store = store_of(&config);
    let accounts = spindle_server::accounts::Accounts::new(&store, "example.org");
    assert!(accounts.account("alice").unwrap().unwrap().admin);
}

#[test]
fn migrate_without_a_config_prints_usage_and_fails() {
    let output = run(&[os("migrate")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("usage: spindle migrate"));
}

#[test]
fn migrate_on_a_current_store_has_nothing_to_do() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    drop(store_of(&config));

    for extra in [None, Some("--dry-run")] {
        let mut args = vec![os("migrate"), config.as_os_str()];
        if let Some(flag) = extra {
            args.push(os(flag));
        }
        let output = run(&args);
        assert!(output.status.success(), "{}", text(&output.stderr));
        assert!(
            text(&output.stdout).contains("already at this binary's schema"),
            "{}",
            text(&output.stdout)
        );
    }
}

/// A store one schema behind: the ordinary open refuses it and names
/// `migrate`, so `promote-admin` refuses too, and `migrate` itself --
/// with no step in this binary's table that reaches that version --
/// refuses rather than pretending. The store is left exactly as it was.
#[test]
fn a_store_behind_the_schema_is_refused_by_every_command_that_opens_it() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    let stale = {
        let current = spindle_store::SchemaMarker::current();
        spindle_store::SchemaMarker {
            record: current.record.wrapping_sub(1),
            ..current
        }
    };
    {
        let store = store_of(&config);
        store
            .put(&spindle_core::keys::store_marker(), &stale.encode())
            .unwrap();
    }

    let promoted = run(&[os("promote-admin"), config.as_os_str(), os("alice")]);
    assert!(!promoted.status.success());
    let stderr = text(&promoted.stderr);
    assert!(
        stderr.contains("migrate"),
        "the refusal names the way forward: {stderr}"
    );

    let migrated = run(&[os("migrate"), config.as_os_str()]);
    assert!(!migrated.status.success());
    assert!(
        text(&migrated.stderr).contains("migrate:"),
        "{}",
        text(&migrated.stderr)
    );

    // Nothing moved: the marker still says what it said.
    let config_loaded = spindle_server::Config::load(config.to_str().unwrap()).unwrap();
    let store = spindle_store::FjallStore::open_unchecked(&config_loaded.storage.path).unwrap();
    assert_eq!(spindle_store::migrate::marker_of(&store).unwrap(), stale);
}
