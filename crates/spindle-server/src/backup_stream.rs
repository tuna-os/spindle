//! Streams a backup as an HTTP body with bounded memory (#813).
//!
//! `write_backup` writes to a `Write`. A blocking task runs it against a
//! writer that cuts the bytes into fixed chunks and sends them through a
//! bounded channel. When the channel is full the task blocks, so a slow
//! client slows the scan instead of growing a buffer. When the client goes
//! away the receiver drops, the next send fails, and `write_backup` stops
//! with an I/O error. The task then ends and frees the backup slot.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use axum::body::Body;
use spindle_store::backup::BackupError;
use tokio::sync::mpsc;

use crate::metrics::OwnedBackupSlot;

/// Bytes per chunk.
pub const CHUNK_BYTES: usize = 64 * 1024;
/// Chunks the channel holds before the writer waits.
pub const QUEUED_CHUNKS: usize = 4;

/// Sizes for one stream. The defaults suit the endpoint; tests shrink them.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub chunk_bytes: usize,
    pub queued_chunks: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            chunk_bytes: CHUNK_BYTES,
            queued_chunks: QUEUED_CHUNKS,
        }
    }
}

impl Limits {
    /// The most bytes that can be in flight: the queue, the one chunk the
    /// writer holds while it waits for room, and the one the reader has taken
    /// but not yet finished with.
    #[must_use]
    pub fn max_buffered(&self) -> usize {
        self.chunk_bytes * (self.queued_chunks + 2)
    }
}

/// What the stream held and sent, for tests and for the audit record.
#[derive(Debug, Default)]
pub struct Stats {
    buffered: AtomicUsize,
    peak: AtomicUsize,
    total: AtomicU64,
}

impl Stats {
    /// Most bytes ever sent and not yet taken by the reader.
    #[must_use]
    pub fn peak_buffered(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Bytes handed to the channel.
    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

type Chunk = std::io::Result<Vec<u8>>;

struct ChannelWriter {
    tx: mpsc::Sender<Chunk>,
    chunk: Vec<u8>,
    limit: usize,
    stats: Arc<Stats>,
}

impl ChannelWriter {
    fn send(&mut self) -> std::io::Result<()> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::replace(&mut self.chunk, Vec::with_capacity(self.limit));
        let len = bytes.len();
        // Counted before the send, since the send is where the writer waits.
        let now = self.stats.buffered.fetch_add(len, Ordering::AcqRel) + len;
        self.stats.peak.fetch_max(now, Ordering::AcqRel);
        self.stats.total.fetch_add(len as u64, Ordering::Relaxed);
        self.tx.blocking_send(Ok(bytes)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the client went away")
        })
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let all = buf.len();
        while !buf.is_empty() {
            let room = self.limit - self.chunk.len();
            let take = room.min(buf.len());
            self.chunk.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
            if self.chunk.len() >= self.limit {
                self.send()?;
            }
        }
        Ok(all)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send()
    }
}

/// A backup being written by a blocking task and read as chunks.
pub struct BackupStream {
    rx: mpsc::Receiver<Chunk>,
    stats: Arc<Stats>,
}

impl BackupStream {
    /// Start writing a backup of one snapshot of `store`.
    ///
    /// The task owns `slot` and frees it before it calls `done`, or when it
    /// ends, however it ends.
    /// `done` gets the row count or the error, for the audit record.
    pub fn start(
        store: Arc<spindle_store::FjallStore>,
        slot: OwnedBackupSlot,
        limits: Limits,
        done: impl FnOnce(&Result<u64, BackupError>, &Stats) + Send + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::channel(limits.queued_chunks);
        let stats = Arc::new(Stats::default());
        let task_stats = Arc::clone(&stats);
        tokio::task::spawn_blocking(move || {
            let error_tx = tx.clone();
            let mut writer = ChannelWriter {
                tx,
                chunk: Vec::with_capacity(limits.chunk_bytes),
                limit: limits.chunk_bytes,
                stats: Arc::clone(&task_stats),
            };
            let result = match spindle_store::Store::snapshot(&*store) {
                Some(snapshot) => spindle_store::backup::write_backup(&*snapshot, &mut writer),
                None => Err(BackupError::Io(std::io::Error::other(
                    "the store has no snapshot, so it cannot be backed up while it runs",
                ))),
            };
            if let Err(error) = &result {
                // An error item makes the body fail, so the client sees an
                // aborted download rather than a short file that ends cleanly.
                let _ = error_tx.blocking_send(Err(std::io::Error::other(error.to_string())));
            }
            // Free the slot before `done` runs: "done" must mean the next backup
            // may start. Left to the end of the task, the slot was still
            // taken when the callback ran, and a request that acted on "done"
            // could get a 409.
            drop(slot);
            done(&result, &task_stats);
        });
        Self { rx, stats }
    }

    /// The counters, which outlive the stream.
    #[must_use]
    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }

    /// The next chunk, or `None` when the backup is complete.
    pub async fn next_chunk(&mut self) -> Option<Chunk> {
        let item = self.rx.recv().await?;
        if let Ok(bytes) = &item {
            self.stats.buffered.fetch_sub(bytes.len(), Ordering::AcqRel);
        }
        Some(item)
    }

    /// The stream as a response body. Dropping the body drops the receiver,
    /// which stops the writer.
    pub fn into_body(self) -> Body {
        Body::from_stream(futures_util::stream::unfold(
            self,
            |mut stream| async move { stream.next_chunk().await.map(|item| (item, stream)) },
        ))
    }
}
