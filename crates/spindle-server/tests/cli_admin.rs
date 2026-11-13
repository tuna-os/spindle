//! #412: the two offline subcommands nothing exercised end to end.
//!
//! `spindle promote-admin <config> <localpart>` mints the first admin
//! against the store with the server stopped (#83), and `spindle migrate
//! <config> [--dry-run]` moves a store forward to this binary's schema
//! (#20), listing its steps with `--list` (#661) and reporting progress as
//! text or JSON (#656). `accounts.rs` and `spindle-store`'s
//! `schema_migration` tests cover the operations; these cover the command
//! line around them, which is what an operator actually types -- the usage
//! refusals, the exit codes, the output a script parses, and the one
//! coupling that matters most: a store one schema behind makes *every*
//! ordinary command refuse and name `migrate`.

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

/// A store stamped as the last schema-2 binary left it, with no rooms: the
/// real step runs over it end to end in milliseconds.
fn digest_two_store(work: &TempDir) -> std::path::PathBuf {
    let config = config_for(work, "data");
    let loaded = spindle_server::Config::load(config.to_str().unwrap()).unwrap();
    let store = spindle_store::FjallStore::open_unchecked(&loaded.storage.path).unwrap();
    let old = spindle_store::SchemaMarker {
        content_digest: 2,
        ..spindle_store::SchemaMarker::current()
    };
    store
        .put(&spindle_core::keys::store_marker(), &old.encode())
        .unwrap();
    config
}

/// Without a store, `--list` is the release's own list of steps (#661):
/// what an operator reads before choosing which binary to upgrade to.
#[test]
fn migrate_list_names_every_step_this_binary_carries() {
    let output = run(&[os("migrate"), os("--list")]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains("[intern-state-keys] 1/1/2 -> 1/1/3 [IRREVERSIBLE]"),
        "{stdout}"
    );
}

/// With a store, `--list` says where each step stands on it, and the dry
/// run names the step it would take.
#[test]
fn migrate_list_and_dry_run_show_the_steps_a_store_still_needs() {
    let work = TempDir::new().unwrap();
    let fresh = config_for(&work, "fresh");
    drop(store_of(&fresh));
    let listed = run(&[os("migrate"), os("--list"), fresh.as_os_str()]);
    assert!(listed.status.success(), "{}", text(&listed.stderr));
    assert!(
        text(&listed.stdout).contains("[intern-state-keys] 1/1/2 -> 1/1/3 [IRREVERSIBLE] "),
        "{}",
        text(&listed.stdout)
    );
    assert!(
        text(&listed.stdout).contains(": not needed by this store"),
        "{}",
        text(&listed.stdout)
    );

    let config = digest_two_store(&work);
    let listed = run(&[os("migrate"), os("--list"), config.as_os_str()]);
    assert!(
        text(&listed.stdout).contains("this store is at schema 1/1/2"),
        "{}",
        text(&listed.stdout)
    );
    assert!(
        text(&listed.stdout).contains("(#79): pending"),
        "{}",
        text(&listed.stdout)
    );
    let planned = run(&[os("migrate"), config.as_os_str(), os("--dry-run")]);
    assert!(planned.status.success(), "{}", text(&planned.stderr));
    assert!(
        text(&planned.stdout).contains("would apply [intern-state-keys] [IRREVERSIBLE]"),
        "{}",
        text(&planned.stdout)
    );
}

/// `--progress json` writes one object per stderr line (#656): the step,
/// each phase from start to end with its unit, a count and a total where
/// there is one, and the step's end. Afterwards the ledger records it.
#[test]
fn migrate_with_json_progress_reports_every_phase_and_records_the_step() {
    let work = TempDir::new().unwrap();
    let config = digest_two_store(&work);

    let output = run(&[
        os("migrate"),
        config.as_os_str(),
        os("--progress"),
        os("json"),
    ]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("CANNOT be undone"));
    let events: Vec<serde_json::Value> = text(&output.stderr)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect();
    assert_eq!(events[0]["event"], "started");
    assert_eq!(events[0]["step"], "intern-state-keys");
    assert_eq!(events[0]["from"], "1/1/2");
    assert_eq!(events[events.len() - 1]["event"], "applied");
    let phases: Vec<(&str, &str)> = events
        .iter()
        .filter(|event| event["event"] == "progress")
        .map(|event| {
            (
                event["phase"].as_str().unwrap(),
                event["stage"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        phases,
        [
            ("count", "started"),
            ("count", "finished"),
            ("convert", "started"),
            ("convert", "finished"),
            ("delete-v2-nodes", "started"),
            ("delete-v2-nodes", "finished"),
        ]
    );
    let count = &events[1];
    assert!(
        count["total"].is_null() && count["percent"].is_null() && count["eta_seconds"].is_null()
    );
    assert_eq!(count["unit"], "records");
    let converted = &events[4];
    assert_eq!(
        (
            &converted["done"],
            &converted["total"],
            &converted["percent"]
        ),
        (
            &serde_json::json!(0),
            &serde_json::json!(0),
            &serde_json::json!(100.0)
        )
    );

    let listed = run(&[os("migrate"), os("--list"), config.as_os_str()]);
    assert!(
        text(&listed.stdout).contains("(#79): applied at unix time"),
        "{}",
        text(&listed.stdout)
    );
    let again = run(&[os("migrate"), config.as_os_str()]);
    assert!(text(&again.stdout).contains("already at this binary's schema"));
}

/// The default progress is text an operator reads in a terminal or a pod
/// log, naming the step and phase on every line.
#[test]
fn migrate_reports_text_progress_on_stderr_by_default() {
    let work = TempDir::new().unwrap();
    let config = digest_two_store(&work);
    let output = run(&[os("migrate"), config.as_os_str()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    for line in [
        "migrate: [intern-state-keys] started: rewrite version-2 state tries",
        "migrate: [intern-state-keys] count started: 0 records so far, total unknown",
        "migrate: [intern-state-keys] count done: 0 records,",
        "migrate: [intern-state-keys] convert done: 0/0 records (100.0%)",
        "migrate: [intern-state-keys] applied: 0 rows in",
    ] {
        assert!(stderr.contains(line), "missing {line:?} in:\n{stderr}");
    }
}

#[test]
fn migrate_refuses_an_unknown_flag_or_progress_format() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    for extra in [["--verbose", "json"], ["--progress", "yaml"]] {
        let output = run(&[
            os("migrate"),
            config.as_os_str(),
            os(extra[0]),
            os(extra[1]),
        ]);
        assert!(!output.status.success());
        assert!(
            text(&output.stderr).contains("usage: spindle migrate"),
            "{}",
            text(&output.stderr)
        );
    }
}

const MAS_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$bWFzLW1pZ3JhdGlvbi0xNg$CEd7EMaeQK2QDHVNURFc/tH0y2Ja5MduCcmz5Gs8uIo";

fn run_with_stdin(args: &[&std::ffi::OsStr], stdin: &str) -> std::process::Output {
    use std::io::Write as _;
    let mut child = Command::new(env!("CARGO_BIN_EXE_spindle"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the spindle binary runs");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn set_password_hash_without_a_config_prints_usage_and_fails() {
    let output = run(&[os("set-password-hash")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("usage: spindle set-password-hash"));
}

/// #611, offline: one account's hash from stdin.
#[test]
fn set_password_hash_stores_one_hash_from_stdin() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    {
        let store = store_of(&config);
        spindle_server::accounts::Accounts::new(&store, "example.org")
            .register("alice", "before")
            .unwrap();
    }
    let output = run_with_stdin(
        &[os("set-password-hash"), config.as_os_str(), os("alice")],
        &format!("{MAS_HASH}\n"),
    );
    assert!(output.status.success(), "{}", text(&output.stderr));
    let store = store_of(&config);
    let accounts = spindle_server::accounts::Accounts::new(&store, "example.org");
    assert!(
        accounts
            .verify_password("alice", "correct horse battery staple")
            .unwrap()
    );
}

/// The bulk form a MAS migration uses: each line applied on its own,
/// refusals named by line and localpart without their hash, and a
/// non-zero exit while anything was refused.
#[test]
fn set_password_hash_in_bulk_reports_each_refusal() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    {
        let store = store_of(&config);
        let accounts = spindle_server::accounts::Accounts::new(&store, "example.org");
        accounts.register("alice", "before").unwrap();
        accounts.register("bob", "bob's own").unwrap();
    }
    let input = format!(
        "# localpart hash\n@alice:example.org {MAS_HASH}\nbob $2b$12$secretbcryptmaterial\nnobody {MAS_HASH}\n"
    );
    let output = run_with_stdin(&[os("set-password-hash"), config.as_os_str()], &input);
    assert!(!output.status.success(), "refusals make the exit non-zero");
    let stderr = text(&output.stderr);
    assert!(stderr.contains("line 3: bob"), "{stderr}");
    assert!(
        stderr.contains("line 4: no account named nobody"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("secretbcryptmaterial"),
        "a hash leaked: {stderr}"
    );
    assert!(
        text(&output.stdout).contains("stored 1"),
        "{}",
        text(&output.stdout)
    );

    let store = store_of(&config);
    let accounts = spindle_server::accounts::Accounts::new(&store, "example.org");
    assert!(
        accounts
            .verify_password("alice", "correct horse battery staple")
            .unwrap()
    );
    assert!(accounts.verify_password("bob", "bob's own").unwrap());
}

fn builtin_config(work: &TempDir) -> std::path::PathBuf {
    let config_path = work.path().join("builtin.toml");
    std::fs::write(
        &config_path,
        format!(
            "[server]\nname = \"example.org\"\npublic_base_url = \"https://matrix.example.org\"\n\
             [storage]\npath = \"{}\"\n[auth]\nbuiltin_oidc = true\n\
             oidc_issuer = \"https://auth.example.org/\"\n",
            work.path().join("data").display()
        ),
    )
    .unwrap();
    config_path
}

#[test]
fn issue_reset_link_without_arguments_prints_usage_and_fails() {
    let output = run(&[os("issue-reset-link")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("usage: spindle issue-reset-link"));
}

/// A link for a server that sends no mail: printed once, on the issuer,
/// for an existing account only, within the lifetime bounds.
#[test]
fn issue_reset_link_prints_a_link_on_the_issuer() {
    let work = TempDir::new().unwrap();
    let config = builtin_config(&work);
    {
        let store = store_of(&config);
        spindle_server::accounts::Accounts::new(&store, "example.org")
            .register("alice", "before")
            .unwrap();
    }
    let output = run(&[os("issue-reset-link"), config.as_os_str(), os("nobody")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("no account named nobody"));
    let output = run(&[
        os("issue-reset-link"),
        config.as_os_str(),
        os("alice"),
        os("--ttl"),
        os("8d"),
    ]);
    assert!(!output.status.success(), "a week at most");
    let output = run(&[
        os("issue-reset-link"),
        config.as_os_str(),
        os("@alice:example.org"),
        os("--ttl"),
        os("2h"),
    ]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    let url = text(&output.stdout);
    let token = url
        .trim()
        .strip_prefix("https://auth.example.org/account/password/reset?token=")
        .unwrap_or_else(|| panic!("{url}"));
    assert_eq!(token.len(), 64);
    assert!(text(&output.stderr).contains("120 minutes"));
    // The store holds a digest, not the token.
    let store = store_of(&config);
    let leaked =
        spindle_store::ReadView::scan_prefix(&store, &spindle_core::keys::email_token_prefix())
            .unwrap()
            .iter()
            .any(|(key, value)| {
                String::from_utf8_lossy(key).contains(token)
                    || String::from_utf8_lossy(value).contains(token)
            });
    assert!(!leaked, "the token is at rest in clear");
}

#[test]
fn issue_reset_link_needs_the_builtin_provider() {
    let work = TempDir::new().unwrap();
    let config = config_for(&work, "data");
    let output = run(&[os("issue-reset-link"), config.as_os_str(), os("alice")]);
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("builtin_oidc"));
}
