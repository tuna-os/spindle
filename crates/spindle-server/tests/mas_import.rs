//! `spindle import-mas` (#797): MAS's accounts into the built-in provider.
//!
//! These drive the importer with a MAS snapshot built in memory, the reader
//! abstraction the `PostgreSQL` reader fills (`tests/mas_reader.rs` runs
//! that one against MAS 1.23's own schema). The hashes are MAS's: the
//! insta snapshots of MAS 1.23.0's password tests, "hunter2" with and
//! without the pepper "a-secret-pepper". A sign-in that works here is this
//! server agreeing with MAS, not with itself.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_server::Config;
use spindle_server::accounts::Accounts;
use spindle_server::import::mas::{
    self, Link, Password, Provider, Report, Schemes, Snapshot, User,
};
use spindle_store::{FjallStore, ReadView, Store};
use tempfile::TempDir;

const MAS_ARGON2: &str = "$argon2id$v=19$m=19456,t=2,p=1$1WdxAF1UChkYSTnJ6NDbKg$\
    ajKAfwlUmkbxITSdh55j+Hvoxzppx20ArNUF44oV9Nk";
const MAS_ARGON2_PEPPERED: &str = "$argon2id$v=19$m=19456,t=2,p=1$eEi11xG8mIOZYxej+ckCaQ$\
    eBeygPqiuImQAaFQOkE6oVkPfqxIGgnqpQd/MwW4YX4";
const MAS_BCRYPT_PEPPERED: &str = "$2b$10$c/EX8bTbEMfTn4oCvcQyBOR1zPyLmGzZ2pMXoElLASqv2qpq5X15i";
const MAS_BCRYPT: &str = "$2b$10$mqjtwG6w3GawhuQQdwBCqOt0TQ0V4vGhB.tMuCZO8WL.ycBHkOLca";

/// "hunter2" in fullwidth letters: NFKC folds it to "hunter2".
const FULLWIDTH: &str = "\u{ff48}\u{ff55}\u{ff4e}\u{ff54}\u{ff45}\u{ff52}\u{ff12}";

/// MAS's `passwords.schemes` as a syn2mas deployment has them: Synapse's
/// bcrypt hashes with Synapse's pepper and normalization, then Argon2id.
const MAS_CONFIG: &str = "\
passwords:
  enabled: true
  schemes:
  - version: 1
    algorithm: argon2id
  - version: 2
    algorithm: bcrypt
    unicode_normalization: true
    secret: a-secret-pepper
  - version: 3
    algorithm: argon2id
    secret: a-secret-pepper
  - version: 4
    algorithm: bcrypt
";

/// The MAS provider an `[[auth.upstream_oidc]]` entry names by its ULID.
const CONFIGURED: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const CONFIGURED_ULID: &str = "01H455VB4PEX5VSKNK084SN02Q";
/// A MAS provider no entry names.
const UNCONFIGURED: &str = "01890a5d-ac96-774b-bcce-b302099a8058";

fn config(dir: &TempDir, name: &str) -> Config {
    Config::parse(&format!(
        "[server]\nname = \"{name}\"\npublic_base_url = \"http://{name}\"\n\
         [storage]\npath = \"{path}\"\n[ratelimit]\nenabled = false\n\
         [auth]\nbuiltin_oidc = true\n\
         [[auth.upstream_oidc]]\nid = \"{CONFIGURED_ULID}\"\nissuer = \"http://127.0.0.1:9\"\n\
         client_id = \"spindle\"\nclient_secret = \"s3cret\"\n",
        path = dir.path().join("data").display(),
    ))
    .unwrap()
}

fn user(id: &str, username: &str) -> User {
    User {
        id: id.to_owned(),
        username: username.to_owned(),
        ..User::default()
    }
}

fn password(hash: &str, version: u16) -> Password {
    Password {
        hash: hash.to_owned(),
        version,
    }
}

/// A MAS that has seen everything the importer must decide about.
fn snapshot() -> Snapshot {
    let mut alice = user("u-alice", "alice");
    alice.can_request_admin = true;
    alice.password = Some(password(MAS_ARGON2, 1));
    alice.emails = vec!["Alice@Example.org".to_owned()];
    let mut bob = user("u-bob", "bob");
    bob.password = Some(password(MAS_BCRYPT_PEPPERED, 2));
    bob.emails = vec!["taken@example.org".to_owned()];
    let carol = user("u-carol", "carol");
    let mut dave = user("u-dave", "dave");
    dave.password = Some(password(MAS_ARGON2_PEPPERED, 3));
    dave.emails = vec!["dave@example.org".to_owned()];
    let mut eve = user("u-eve", "eve");
    eve.deactivated = true;
    let mut frank = user("u-frank", "frank");
    frank.deactivated = true;
    frank.password = Some(password(MAS_ARGON2, 1));
    let mut gina = user("u-gina", "gina");
    gina.locked = true;
    let henry = user("u-henry", "Henry");
    let mut ivan = user("u-ivan", "ivan");
    ivan.password = Some(password(MAS_ARGON2, 9));
    let judy = user("u-judy", "judy");
    let link = |provider: &str, subject: &str, user: Option<&str>| Link {
        provider_id: provider.to_owned(),
        subject: subject.to_owned(),
        user_id: user.map(str::to_owned),
    };
    Snapshot {
        users: vec![alice, bob, carol, dave, eve, frank, gina, henry, ivan, judy],
        providers: vec![
            Provider {
                id: CONFIGURED.to_owned(),
                issuer: Some("https://idp.example.org/".to_owned()),
            },
            Provider {
                id: UNCONFIGURED.to_owned(),
                issuer: Some("https://gone.example.org/".to_owned()),
            },
        ],
        links: vec![
            link(CONFIGURED, "alice-sub", Some("u-alice")),
            link(CONFIGURED, "frank-sub", Some("u-frank")),
            link(CONFIGURED, "pending-sub", None),
            link(CONFIGURED, "taken-sub", Some("u-dave")),
            link(UNCONFIGURED, "dave-sub", Some("u-dave")),
        ],
    }
}

/// The store as delegation left it: every MAS user MAS provisioned, with
/// a password nobody knows, and a few accounts in states of their own.
fn delegated_store(config: &Config) -> Arc<FjallStore> {
    let store = Arc::new(FjallStore::open(&config.storage.path).unwrap());
    let accounts = Accounts::new(store.as_ref(), &config.server.name);
    for localpart in [
        "alice", "bob", "carol", "frank", "gina", "ivan", "judy", "zed",
    ] {
        accounts
            .register(localpart, "provisioned by MAS, never used")
            .unwrap();
    }
    accounts.set_deactivated("carol", true).unwrap();
    accounts.set_locked("judy", true).unwrap();
    // Another account already holds bob's address and the identity MAS
    // links to dave.
    store
        .put(
            &spindle_core::keys::email_owner("taken@example.org"),
            b"zed",
        )
        .unwrap();
    store
        .put(
            &spindle_core::keys::upstream_link(CONFIGURED_ULID, "taken-sub"),
            &serde_json::to_vec(&json!({ "localpart": "zed", "linked_ms": 1 })).unwrap(),
        )
        .unwrap();
    store
}

fn email_owner(store: &FjallStore, address: &str) -> Option<String> {
    ReadView::get(store, &spindle_core::keys::email_owner(address))
        .unwrap()
        .map(|raw| String::from_utf8(raw).unwrap())
}

fn link_owner(store: &FjallStore, subject: &str) -> Option<String> {
    ReadView::get(
        store,
        &spindle_core::keys::upstream_link(CONFIGURED_ULID, subject),
    )
    .unwrap()
    .map(|raw| {
        serde_json::from_slice::<Value>(&raw).unwrap()["localpart"]
            .as_str()
            .unwrap()
            .to_owned()
    })
}

fn subjects(notes: &[mas::Note]) -> Vec<&str> {
    notes.iter().map(|note| note.subject.as_str()).collect()
}

fn assert_first_run(report: &Report, name: &str) {
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(
        json["users"],
        json!({ "seen": 10, "created": 1, "created_deactivated": 1, "admin_granted": 1,
                "locked": 2 }),
        "{json:#}"
    );
    assert_eq!(
        json["passwords"],
        json!({ "imported": 3, "unchanged": 0, "kept_local": 0, "refused": 1, "none": 2 }),
        "{json:#}"
    );
    assert_eq!(
        json["emails"],
        json!({ "bound": 2, "unchanged": 0, "refused": 1 }),
        "{json:#}"
    );
    assert_eq!(
        json["links"],
        json!({ "imported": 1, "unchanged": 0, "unclaimed": 1, "skipped": 1, "refused": 2 }),
        "{json:#}"
    );
    assert_eq!(report.password_schemes, "mas config");
    let user = |localpart: &str| format!("@{localpart}:{name}");
    assert_eq!(
        subjects(&report.refused),
        // Users in username order (an uppercase name sorts first), then
        // links, then one note per provider no entry names.
        [
            user("Henry"),
            user("bob"),
            user("frank"),
            user("ivan"),
            user("dave"),
            "01H455VB4PEX5VSKNK084SN02R".to_owned(),
        ],
        "{json:#}"
    );
    assert!(report.refused[1].reason.contains("taken@example.org"));
    assert!(report.refused[2].reason.contains("locked instead"));
    assert!(report.refused[3].reason.contains("version 9"));
    assert!(report.refused[4].reason.contains(&user("zed")));
    assert!(
        report.refused[5]
            .reason
            .contains("https://gone.example.org/")
    );
    assert_eq!(subjects(&report.kept), [user("carol"), user("judy")]);
}

#[test]
fn a_dry_run_reports_every_decision_and_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir, "example.org");
    let store = delegated_store(&config);
    let schemes = Schemes::from_mas_config(MAS_CONFIG).unwrap();
    let report = mas::apply(store.as_ref(), &config, &snapshot(), &schemes, true).unwrap();
    assert!(report.dry_run);
    assert_first_run(&report, "example.org");

    let accounts = Accounts::new(store.as_ref(), "example.org");
    assert!(accounts.account("dave").unwrap().is_none());
    assert!(accounts.account("eve").unwrap().is_none());
    assert!(!accounts.verify_password("alice", "hunter2").unwrap());
    assert!(!accounts.account("alice").unwrap().unwrap().admin);
    assert!(!accounts.account("gina").unwrap().unwrap().locked);
    assert!(!accounts.account("frank").unwrap().unwrap().locked);
    assert_eq!(email_owner(&store, "alice@example.org"), None);
    assert_eq!(link_owner(&store, "alice-sub"), None);
}

#[test]
fn an_import_lands_and_a_rerun_changes_nothing_it_should_not() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir, "example.org");
    let store = delegated_store(&config);
    let schemes = Schemes::from_mas_config(MAS_CONFIG).unwrap();
    let source = snapshot();
    let report = mas::apply(store.as_ref(), &config, &source, &schemes, false).unwrap();
    assert!(!report.dry_run);
    assert_first_run(&report, "example.org");

    let accounts = Accounts::new(store.as_ref(), "example.org");
    let account = |localpart: &str| accounts.account(localpart).unwrap().unwrap();
    // Each of MAS's schemes verifies its password, and only that one.
    assert!(accounts.verify_password("alice", "hunter2").unwrap());
    assert!(accounts.verify_password("bob", "hunter2").unwrap());
    assert!(
        accounts.verify_password("bob", FULLWIDTH).unwrap(),
        "bob's scheme normalizes, as MAS's does"
    );
    assert!(accounts.verify_password("dave", "hunter2").unwrap());
    assert!(!accounts.verify_password("dave", "wrong-password").unwrap());
    assert!(!accounts.verify_password("ivan", "hunter2").unwrap());
    // Flags: MAS's admin and lock land; a stricter state here stays.
    assert!(account("alice").admin);
    assert!(account("gina").locked);
    assert!(account("judy").locked);
    assert!(account("carol").deactivated);
    let frank = account("frank");
    assert!(frank.locked && !frank.deactivated);
    assert!(
        !accounts.verify_password("frank", "hunter2").unwrap(),
        "a MAS deactivation brings no password with it"
    );
    assert!(account("eve").deactivated);
    assert!(accounts.account("Henry").unwrap().is_none());
    // Addresses, folded; a taken one stays with its holder.
    assert_eq!(
        email_owner(&store, "alice@example.org").as_deref(),
        Some("alice")
    );
    assert_eq!(
        email_owner(&store, "dave@example.org").as_deref(),
        Some("dave")
    );
    assert_eq!(
        email_owner(&store, "taken@example.org").as_deref(),
        Some("zed")
    );
    // Links.
    assert_eq!(link_owner(&store, "alice-sub").as_deref(), Some("alice"));
    assert_eq!(link_owner(&store, "taken-sub").as_deref(), Some("zed"));
    assert_eq!(link_owner(&store, "frank-sub"), None);
    assert_eq!(link_owner(&store, "pending-sub"), None);

    // The same snapshot again: everything is already in place.
    let again = mas::apply(store.as_ref(), &config, &source, &schemes, false).unwrap();
    let json = serde_json::to_value(&again).unwrap();
    assert_eq!(
        json["users"],
        json!({ "seen": 10, "created": 0, "created_deactivated": 0, "admin_granted": 0,
                "locked": 0 }),
        "{json:#}"
    );
    assert_eq!(json["passwords"]["unchanged"], 3, "{json:#}");
    assert_eq!(json["passwords"]["imported"], 0, "{json:#}");
    assert_eq!(json["emails"]["unchanged"], 2, "{json:#}");
    assert_eq!(json["emails"]["bound"], 0, "{json:#}");
    assert_eq!(json["links"]["unchanged"], 1, "{json:#}");
    assert_eq!(json["links"]["imported"], 0, "{json:#}");

    // Alice changes her password here; MAS still has the old hash, and
    // bob's has changed in MAS since. The rerun keeps alice's and brings
    // bob's up to date.
    accounts.set_password("alice", "chosen here").unwrap();
    let mut later = source.clone();
    later.users[1].password = Some(password(MAS_BCRYPT, 4));
    let third = mas::apply(store.as_ref(), &config, &later, &schemes, false).unwrap();
    assert_eq!(third.passwords.kept_local, 1);
    assert_eq!(third.passwords.imported, 1);
    assert!(subjects(&third.kept).contains(&"@alice:example.org"));
    assert!(accounts.verify_password("alice", "chosen here").unwrap());
    assert!(accounts.verify_password("bob", "hunter2").unwrap());
    assert!(
        !accounts.verify_password("bob", FULLWIDTH).unwrap(),
        "bob's new scheme does not normalize"
    );
}

#[test]
fn without_mas_config_the_default_scheme_is_assumed_and_others_refused() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir, "example.org");
    let store = delegated_store(&config);
    let report = mas::apply(
        store.as_ref(),
        &config,
        &snapshot(),
        &Schemes::default(),
        false,
    )
    .unwrap();
    assert_eq!(report.password_schemes, "mas defaults");
    // Version 1 is MAS's default Argon2id; bob's version 2 and dave's 3
    // are unknown without the config, and refused rather than stored
    // without the pepper they need.
    assert_eq!(report.passwords.imported, 1);
    assert_eq!(report.passwords.refused, 3);
    let accounts = Accounts::new(store.as_ref(), "example.org");
    assert!(accounts.verify_password("alice", "hunter2").unwrap());
    assert!(!accounts.verify_password("bob", "hunter2").unwrap());
}

/// The client API's password login, against a server started on the
/// imported store.
#[tokio::test]
async fn imported_passwords_sign_in_through_the_client_api() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dir = TempDir::new().unwrap();
    let config = config(&dir, &name);
    let store = delegated_store(&config);
    let schemes = Schemes::from_mas_config(MAS_CONFIG).unwrap();
    mas::apply(store.as_ref(), &config, &snapshot(), &schemes, false).unwrap();
    let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let login = |user: &str, password: &str| {
        client
            .post(format!("http://{name}/_matrix/client/v3/login"))
            .header("content-type", "application/json")
            .body(
                json!({
                    "type": "m.login.password",
                    "identifier": { "type": "m.id.user", "user": user },
                    "password": password,
                })
                .to_string(),
            )
            .send()
    };
    for (user, password) in [
        ("alice", "hunter2"),
        ("bob", FULLWIDTH),
        ("dave", "hunter2"),
    ] {
        let response = login(user, password).await.unwrap();
        let status = response.status().as_u16();
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(status, 200, "{user}: {body}");
        assert_eq!(body["user_id"], format!("@{user}:{name}"));
    }
    let response = login("dave", "wrong-password").await.unwrap();
    assert_eq!(response.status().as_u16(), 403);
}
