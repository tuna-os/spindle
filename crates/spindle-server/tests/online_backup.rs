//! #813: a backup taken through the admin endpoint while the server runs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_server::metrics::Metrics;
use spindle_store::{Durability, FjallStore, ReadView, Store};
use tempfile::TempDir;

struct Instance {
    _dir: TempDir,
    backups: TempDir,
    name: String,
    store: Arc<FjallStore>,
    metrics: Arc<Metrics>,
    client: reqwest::Client,
}

impl Instance {
    async fn start(with_backup_dir: bool) -> Instance {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let backups = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let storage = if with_backup_dir {
            format!(
                "[storage]\npath = \"{}\"\nbackup_dir = \"{}\"\n",
                dir.path().display(),
                backups.path().display()
            )
        } else {
            String::new()
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n{storage}"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let app = spindle_server::app_with_metrics(config, Arc::clone(&store), metrics.clone())
            .expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            backups,
            name,
            store,
            metrics,
            client: reqwest::Client::new(),
        }
    }

    async fn register(&self, username: &str) -> String {
        let response = self
            .client
            .post(format!("http://{}/_matrix/client/v3/register", self.name))
            .header("content-type", "application/json")
            .body(
                json!({
                    "username": username, "password": "hunter2hunter2",
                    "auth": { "type": "m.login.dummy", "session": "s" },
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn backup(&self, token: &str) -> (u16, Value) {
        let response = self
            .client
            .post(format!("http://{}/_spindle/admin/v1/backup", self.name))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn admin(&self) -> String {
        let token = self.register("root").await;
        assert!(
            Accounts::new(self.store.as_ref(), &self.name)
                .set_admin("root", true)
                .unwrap()
        );
        token
    }
}

fn pair(prefix: &str, index: u32) -> Vec<u8> {
    format!("\u{ff}test/{prefix}/{index:08}").into_bytes()
}

fn count(view: &dyn ReadView, prefix: &str) -> Vec<u32> {
    view.scan_prefix(format!("\u{ff}test/{prefix}/").as_bytes())
        .unwrap()
        .iter()
        .map(|(key, _)| {
            String::from_utf8_lossy(key)
                .rsplit('/')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect()
}

/// Each commit writes `a/i` and `b/i` together, and the scan visits every
/// `a` row before any `b` row. A scan of the live store therefore finds
/// more `b` rows than `a` rows when writes land during it. A snapshot finds
/// the same set in both, a prefix of what was written.
#[tokio::test(flavor = "multi_thread")]
async fn a_backup_taken_during_writes_restores_to_one_moment() {
    let instance = Instance::start(true).await;
    let token = instance.admin().await;
    for index in 0..30_000 {
        instance
            .store
            .commit(
                &[
                    (pair("a", index), vec![0; 64]),
                    (pair("b", index), vec![0; 64]),
                ],
                Durability::Relaxed,
            )
            .unwrap();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (store, stop) = (Arc::clone(&instance.store), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut index = 30_000;
            while !stop.load(Ordering::Relaxed) {
                store
                    .commit(
                        &[
                            (pair("a", index), vec![0; 64]),
                            (pair("b", index), vec![0; 64]),
                        ],
                        Durability::Relaxed,
                    )
                    .unwrap();
                index += 1;
            }
            index
        })
    };

    let (status, body) = instance.backup(&token).await;
    stop.store(true, Ordering::Relaxed);
    let written = writer.join().unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(written > 30_000, "the writer ran while the backup did");

    let path = std::path::PathBuf::from(body["path"].as_str().unwrap());
    assert!(path.starts_with(instance.backups.path()));
    let restored_dir = TempDir::new().unwrap();
    let restored = FjallStore::open(restored_dir.path()).unwrap();
    let mut file = std::fs::File::open(&path).unwrap();
    spindle_store::backup::verify_backup(&mut file).unwrap();
    let mut file = std::fs::File::open(&path).unwrap();
    spindle_store::backup::read_backup(&mut file, &restored).unwrap();

    let (a, b) = (count(&restored, "a"), count(&restored, "b"));
    assert_eq!(a, b, "the restore holds one moment, not a smear");
    let expected: Vec<u32> = (0..u32::try_from(a.len()).unwrap()).collect();
    assert_eq!(a, expected, "and that moment is a prefix of the writes");
    assert!(a.len() >= 30_000);
    assert!(instance.metrics.last_backup() > 0);

    // The account the server held is in the file too.
    assert!(
        Accounts::new(&restored, &instance.name)
            .account("root")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn only_an_admin_may_back_up_and_it_needs_a_directory() {
    let instance = Instance::start(true).await;
    let admin = instance.admin().await;
    let user = instance.register("alice").await;
    assert_eq!(instance.backup(&user).await.0, 403);
    assert_eq!(instance.metrics.last_backup(), 0);
    assert_eq!(
        std::fs::read_dir(instance.backups.path()).unwrap().count(),
        0
    );
    assert_eq!(instance.backup(&admin).await.0, 200);
    let audit = instance
        .store
        .scan_prefix(&spindle_core::keys::keyspace_prefix(
            spindle_core::keys::Keyspace::AuditLog,
        ))
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|(_, value)| String::from_utf8_lossy(value).contains("\"backup\"")),
        "the backup is in the audit log"
    );

    let off = Instance::start(false).await;
    let admin = off.admin().await;
    assert_eq!(off.backup(&admin).await.0, 400);
}
