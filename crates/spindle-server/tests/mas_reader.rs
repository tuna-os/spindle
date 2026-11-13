//! `spindle import-mas` against MAS 1.23's own schema (#797).
//!
//! Behind the `mas-import` feature: `cargo test -p spindle-server
//! --features mas-import --test mas_reader`.
//!
//! The schema is not written here. CI runs `mas-cli database migrate` from
//! the MAS 1.23.0 image production runs, into a `PostgreSQL` it starts, and
//! names that database in `SPINDLE_MAS_TEST_POSTGRES`; without it the
//! database test says so and passes. Column names are what a schema
//! written by hand cannot check, so only MAS's migrations make it.

#![cfg(feature = "mas-import")]

use std::process::Command;

use serde_json::Value;
use spindle_server::accounts::Accounts;
use spindle_server::import::mas;

const MAS_ARGON2: &str = "$argon2id$v=19$m=19456,t=2,p=1$1WdxAF1UChkYSTnJ6NDbKg$\
    ajKAfwlUmkbxITSdh55j+Hvoxzppx20ArNUF44oV9Nk";
const MAS_ARGON2_PEPPERED: &str = "$argon2id$v=19$m=19456,t=2,p=1$eEi11xG8mIOZYxej+ckCaQ$\
    eBeygPqiuImQAaFQOkE6oVkPfqxIGgnqpQd/MwW4YX4";
const MAS_BCRYPT_PEPPERED: &str = "$2b$10$c/EX8bTbEMfTn4oCvcQyBOR1zPyLmGzZ2pMXoElLASqv2qpq5X15i";

const PROVIDER: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const PROVIDER_ULID: &str = "01H455VB4PEX5VSKNK084SN02Q";

fn spindle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spindle"))
        .args(args)
        .output()
        .expect("the spindle binary runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn import_mas_without_its_arguments_prints_usage_and_fails() {
    for args in [
        &["import-mas"][..],
        &["import-mas", "spindle.toml"],
        &["import-mas", "--mas-database", "host=localhost"],
    ] {
        let output = spindle(args);
        assert!(!output.status.success(), "{args:?}");
        assert!(
            text(&output.stderr).contains("usage: spindle import-mas <config>"),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
}

/// Fixture rows in MAS's tables, as MAS writes them: UUID keys, an
/// upgraded password (two rows, the newer one current), a lock, a
/// deactivation, an address and two upstream links, one never claimed.
const FIXTURE: &str = "
TRUNCATE users, upstream_oauth_providers CASCADE;
INSERT INTO users (user_id, username, created_at, can_request_admin)
  VALUES ('01890a5d-0000-7000-8000-00000000000a', 'mia', now(), true);
INSERT INTO users (user_id, username, created_at, locked_at)
  VALUES ('01890a5d-0000-7000-8000-00000000000b', 'noah', now(), now());
INSERT INTO users (user_id, username, created_at, deactivated_at)
  VALUES ('01890a5d-0000-7000-8000-00000000000c', 'oscar', now(), now());
INSERT INTO user_passwords (user_password_id, user_id, hashed_password, version, created_at)
  VALUES ('01890a5d-0000-7000-8000-0000000000a1', '01890a5d-0000-7000-8000-00000000000a',
          'BCRYPT', 2, now() - interval '1 day'),
         ('01890a5d-0000-7000-8000-0000000000a2', '01890a5d-0000-7000-8000-00000000000a',
          'ARGON2', 1, now()),
         ('01890a5d-0000-7000-8000-0000000000b1', '01890a5d-0000-7000-8000-00000000000b',
          'PEPPERED', 3, now());
UPDATE user_passwords SET upgraded_from_id = '01890a5d-0000-7000-8000-0000000000a1'
  WHERE user_password_id = '01890a5d-0000-7000-8000-0000000000a2';
INSERT INTO user_emails (user_email_id, user_id, email, created_at)
  VALUES ('01890a5d-0000-7000-8000-0000000000e1', '01890a5d-0000-7000-8000-00000000000a',
          'Mia@Example.org', now());
INSERT INTO upstream_oauth_providers
  (upstream_oauth_provider_id, issuer, scope, client_id, token_endpoint_auth_method, created_at)
  VALUES ('PROVIDER', 'https://idp.example.org/', 'openid', 'mas', 'client_secret_basic', now());
INSERT INTO upstream_oauth_links
  (upstream_oauth_link_id, upstream_oauth_provider_id, user_id, subject, created_at)
  VALUES ('01890a5d-0000-7000-8000-0000000000c1', 'PROVIDER',
          '01890a5d-0000-7000-8000-00000000000a', 'mia-at-idp', now()),
         ('01890a5d-0000-7000-8000-0000000000c2', 'PROVIDER', NULL, 'never-finished', now());
";

/// Write the fixture into MAS's tables, then check the reader returns it.
fn seed_and_read(database: &str) {
    let fixture = FIXTURE
        .replace("BCRYPT", MAS_BCRYPT_PEPPERED)
        .replace("ARGON2", MAS_ARGON2)
        .replace("PEPPERED", MAS_ARGON2_PEPPERED)
        .replace("PROVIDER", PROVIDER);
    let mut client = mas::postgres::connect_no_tls(database, None).unwrap();
    client.batch_execute(&fixture).unwrap();

    let snapshot = mas::postgres::read(&mut client).unwrap();
    let usernames: Vec<&str> = snapshot
        .users
        .iter()
        .map(|user| user.username.as_str())
        .collect();
    assert_eq!(usernames, ["mia", "noah", "oscar"]);
    let mia = &snapshot.users[0];
    assert!(mia.can_request_admin && !mia.locked && !mia.deactivated);
    let password = mia.password.as_ref().unwrap();
    assert_eq!(
        (password.hash.as_str(), password.version),
        (MAS_ARGON2, 1),
        "the newest row is the current password"
    );
    assert_eq!(mia.emails, ["Mia@Example.org"]);
    assert!(snapshot.users[1].locked);
    assert!(snapshot.users[2].deactivated);
    assert_eq!(snapshot.providers.len(), 1);
    assert_eq!(mas::ulid(&snapshot.providers[0].id).unwrap(), PROVIDER_ULID);
    assert_eq!(snapshot.links.len(), 2);
}

#[test]
fn a_mas_1_23_database_reads_and_imports_through_the_command() {
    let Ok(database) = std::env::var("SPINDLE_MAS_TEST_POSTGRES") else {
        eprintln!(
            "SPINDLE_MAS_TEST_POSTGRES is unset: no MAS database to read (CI migrates one \
             with MAS 1.23.0's own migrations)"
        );
        return;
    };
    seed_and_read(&database);

    let work = tempfile::TempDir::new().unwrap();
    let config = work.path().join("spindle.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nname = \"example.org\"\npublic_base_url = \"https://example.org\"\n\
             [storage]\npath = \"{}\"\n[auth]\nbuiltin_oidc = true\n\
             [[auth.upstream_oidc]]\nid = \"{PROVIDER_ULID}\"\n\
             issuer = \"https://idp.example.org/\"\nclient_id = \"spindle\"\n\
             client_secret = \"s3cret\"\n",
            work.path().join("data").display()
        ),
    )
    .unwrap();
    let mas_config = work.path().join("mas.yaml");
    std::fs::write(
        &mas_config,
        "passwords:\n  schemes:\n  - version: 1\n    algorithm: argon2id\n  \
         - version: 2\n    algorithm: bcrypt\n    secret: a-secret-pepper\n  \
         - version: 3\n    algorithm: argon2id\n    secret: a-secret-pepper\n",
    )
    .unwrap();
    let run = |dry_run: bool| {
        let mut args = vec![
            "import-mas",
            config.to_str().unwrap(),
            "--mas-database",
            database.as_str(),
            "--mas-config",
            mas_config.to_str().unwrap(),
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let output = spindle(&args);
        assert!(output.status.success(), "{}", text(&output.stderr));
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };

    let dry = run(true);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["users"]["created"], 2, "{dry:#}");
    assert_eq!(dry["users"]["created_deactivated"], 1, "{dry:#}");
    {
        let store = spindle_store::FjallStore::open(work.path().join("data")).unwrap();
        let accounts = Accounts::new(&store, "example.org");
        assert!(
            accounts.account("mia").unwrap().is_none(),
            "a dry run writes nothing"
        );
    }

    let report = run(false);
    assert_eq!(report["dry_run"], false);
    assert_eq!(report["password_schemes"], "mas config");
    assert_eq!(report["passwords"]["imported"], 2, "{report:#}");
    assert_eq!(report["emails"]["bound"], 1, "{report:#}");
    assert_eq!(report["links"]["imported"], 1, "{report:#}");
    assert_eq!(report["links"]["unclaimed"], 1, "{report:#}");
    assert_eq!(report["refused"], serde_json::json!([]), "{report:#}");

    let again = run(false);
    assert_eq!(again["users"]["created"], 0, "{again:#}");
    assert_eq!(again["passwords"]["unchanged"], 2, "{again:#}");
    assert_eq!(again["links"]["unchanged"], 1, "{again:#}");

    let store = spindle_store::FjallStore::open(work.path().join("data")).unwrap();
    let accounts = Accounts::new(&store, "example.org");
    assert!(accounts.verify_password("mia", "hunter2").unwrap());
    assert!(accounts.verify_password("noah", "hunter2").unwrap());
    let mia = accounts.account("mia").unwrap().unwrap();
    assert!(mia.admin);
    assert!(accounts.account("noah").unwrap().unwrap().locked);
    assert!(accounts.account("oscar").unwrap().unwrap().deactivated);
}
