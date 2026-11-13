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

    async fn stream(&self, token: &str) -> reqwest::Response {
        self.client
            .get(format!(
                "http://{}/_spindle/admin/v1/backup/stream",
                self.name
            ))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap()
    }

    fn fill(&self, rows: u32, value_len: usize) {
        for index in 0..rows {
            self.store
                .commit(
                    &[(pair("a", index), vec![7; value_len])],
                    Durability::Relaxed,
                )
                .unwrap();
        }
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

/// The streamed body is the file format: it verifies, restores to one moment
/// while writes continue, and the stream is audited.
#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_backup_restores_to_one_moment_during_writes() {
    let instance = Instance::start(false).await;
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

    let response = instance.stream(&token).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    let body = response.bytes().await.unwrap();
    stop.store(true, Ordering::Relaxed);
    let written = writer.join().unwrap();
    assert!(written > 30_000, "the writer ran while the stream did");

    spindle_store::backup::verify_backup(&mut &body[..]).unwrap();
    let restored_dir = TempDir::new().unwrap();
    let restored = FjallStore::open(restored_dir.path()).unwrap();
    spindle_store::backup::read_backup(&mut &body[..], &restored).unwrap();
    let (a, b) = (count(&restored, "a"), count(&restored, "b"));
    assert_eq!(a, b, "the restore holds one moment, not a smear");
    let expected: Vec<u32> = (0..u32::try_from(a.len()).unwrap()).collect();
    assert_eq!(a, expected, "and that moment is a prefix of the writes");
    assert!(
        Accounts::new(&restored, &instance.name)
            .account("root")
            .unwrap()
            .is_some()
    );

    // The audit record is written as the write ends, which can follow the
    // last byte by a moment.
    let prefix = spindle_core::keys::keyspace_prefix(spindle_core::keys::Keyspace::AuditLog);
    for _ in 0..100 {
        let audit = instance.store.scan_prefix(&prefix).unwrap();
        if audit
            .iter()
            .any(|(_, value)| String::from_utf8_lossy(value).contains("backup_stream"))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the streamed backup is not in the audit log");
}

#[tokio::test]
async fn the_stream_is_admin_only_and_one_backup_runs_at_a_time() {
    let instance = Instance::start(true).await;
    let admin = instance.admin().await;
    let user = instance.register("alice").await;
    assert_eq!(instance.stream(&user).await.status(), 403);
    assert_eq!(
        instance
            .client
            .get(format!(
                "http://{}/_synapse/admin/v1/backup/stream",
                instance.name
            ))
            .header("authorization", format!("Bearer {admin}"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "Synapse has no such endpoint, so only /_spindle serves it"
    );

    let held = instance.metrics.begin_backup().expect("the slot is free");
    let response = instance.stream(&admin).await;
    assert_eq!(response.status(), 409);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert!(body["error"].as_str().unwrap().contains("another backup"));
    assert_eq!(instance.backup(&admin).await.0, 409);
    drop(held);
    assert_eq!(instance.stream(&admin).await.status(), 200);
}

/// A client that leaves mid-stream stops the writer and frees the slot.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_disconnects_frees_the_backup_slot() {
    let instance = Instance::start(false).await;
    let token = instance.admin().await;
    // Far more than the channel holds, so the writer is waiting when the
    // client leaves.
    instance.fill(20_000, 1024);
    let mut response = instance.stream(&token).await;
    assert!(response.chunk().await.unwrap().is_some());
    drop(response);
    for _ in 0..100 {
        if instance.metrics.begin_backup().is_some() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the writer kept the slot after the client left");
}

/// The channel never holds more than its bound, whatever is streamed, and
/// the slow reader does not make it grow.
#[tokio::test(flavor = "multi_thread")]
async fn the_stream_buffers_no_more_than_its_bound() {
    use spindle_server::backup_stream::{BackupStream, Limits};

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    for index in 0..4_000 {
        store
            .commit(&[(pair("a", index), vec![3; 2048])], Durability::Relaxed)
            .unwrap();
    }
    let metrics = Arc::new(Metrics::new());
    let limits = Limits {
        chunk_bytes: 4096,
        queued_chunks: 2,
    };
    let slot = metrics.begin_backup_owned().unwrap();
    let mut stream = BackupStream::start(Arc::clone(&store), slot, limits, |_, _| {});
    let stats = stream.stats();
    let mut received = Vec::new();
    while let Some(chunk) = stream.next_chunk().await {
        let chunk = chunk.unwrap();
        assert!(chunk.len() <= limits.chunk_bytes);
        received.extend_from_slice(&chunk);
        // Reading slowly lets the writer fill the channel to its bound.
        tokio::time::sleep(std::time::Duration::from_micros(200)).await;
    }
    assert!(received.len() > 8_000_000, "about 8 MB went through");
    assert!(
        received.len() > 100 * limits.max_buffered(),
        "far more than the bound was streamed"
    );
    assert_eq!(stats.total_sent(), received.len() as u64);
    assert!(
        stats.peak_buffered() <= limits.max_buffered(),
        "peak {} exceeded the bound {}",
        stats.peak_buffered(),
        limits.max_buffered()
    );
    spindle_store::backup::verify_backup(&mut &received[..]).unwrap();
}

/// The slot is free by the time the `done` callback runs. The callback used to
/// run first and the slot was dropped when the task ended, so anything that
/// acted on "done" (a test, an audit hook, the next request) could still find
/// the slot taken. Checked from inside the callback, so there is no race to
/// win: on the old code this is false every time.
#[tokio::test(flavor = "multi_thread")]
async fn the_slot_is_free_when_the_done_callback_runs() {
    use spindle_server::backup_stream::{BackupStream, Limits};

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    store
        .commit(&[(pair("a", 1), vec![1; 64])], Durability::Relaxed)
        .unwrap();
    let metrics = Arc::new(Metrics::new());
    let slot = metrics.begin_backup_owned().unwrap();
    let (free_tx, free_rx) = tokio::sync::oneshot::channel();
    let in_callback = Arc::clone(&metrics);
    let mut stream = BackupStream::start(
        Arc::clone(&store),
        slot,
        Limits {
            chunk_bytes: 4096,
            queued_chunks: 2,
        },
        move |_, _| {
            let _ = free_tx.send(in_callback.begin_backup().is_some());
        },
    );
    while stream.next_chunk().await.is_some() {}
    let free = tokio::time::timeout(std::time::Duration::from_secs(10), free_rx)
        .await
        .expect("the writer finished")
        .unwrap();
    assert!(free, "the slot was still taken when `done` ran");
}

/// Dropping the reader stops the writer within a few chunks: it does not scan
/// on to the end of the store.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_reader_stops_the_writer_early() {
    use spindle_server::backup_stream::{BackupStream, Limits};

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    for index in 0..4_000 {
        store
            .commit(&[(pair("a", index), vec![3; 2048])], Durability::Relaxed)
            .unwrap();
    }
    let metrics = Arc::new(Metrics::new());
    let limits = Limits {
        chunk_bytes: 4096,
        queued_chunks: 2,
    };
    let slot = metrics.begin_backup_owned().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let mut stream = BackupStream::start(Arc::clone(&store), slot, limits, move |result, _| {
        let _ = done_tx.send(result.is_err());
    });
    let stats = stream.stats();
    assert!(stream.next_chunk().await.is_some());
    drop(stream);
    let failed = tokio::time::timeout(std::time::Duration::from_secs(10), done_rx)
        .await
        .expect("the writer stopped")
        .unwrap();
    assert!(failed, "an abandoned stream is not a finished backup");
    assert!(
        stats.total_sent() <= 8 * limits.max_buffered() as u64,
        "it stopped after {} bytes, not at the end of 8 MB",
        stats.total_sent()
    );
    assert!(metrics.begin_backup().is_some(), "and it freed the slot");
}
