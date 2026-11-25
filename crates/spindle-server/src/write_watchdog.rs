//! Exit when the store has refused writes for too long (#892).
//!
//! After a disk-full, fjall poisons its database and refuses every write
//! until the directory is reopened. Freeing space does not help a running
//! process. Reads keep answering and `/health` stays 200, so nothing
//! restarts the server: it sits there with a dead write path. This task
//! turns that state into an exit, so `restart: unless-stopped` (or a
//! systemd or Kubernetes restart policy) reopens the store.
//!
//! A grace period comes first, so one refused write does not bounce a
//! server whose operator is already freeing space. A restart onto a disk
//! that is still full fails at open and backs off under the supervisor,
//! which is the loud failure an operator needs to see.

use std::sync::Arc;
use std::time::Duration;

use spindle_store::Store;

/// Resolve once `store` has refused writes for `grace`.
///
/// `grace` of zero never resolves: the operator turned the watchdog off.
/// `poll` is how often the store is asked; it only bounds how late the
/// exit comes.
pub async fn write_refused_for<S: Store + ?Sized>(store: Arc<S>, grace: Duration, poll: Duration) {
    if grace.is_zero() {
        std::future::pending::<()>().await;
    }
    let mut refused_since: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(poll).await;
        if store.accepts_writes() {
            // The latch is one-way today. Resetting here keeps the
            // watchdog right if a store ever recovers in process.
            refused_since = None;
            continue;
        }
        let since = *refused_since.get_or_insert_with(tokio::time::Instant::now);
        if since.elapsed() >= grace {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_store::{Fault, FjallStore};

    fn store() -> (tempfile::TempDir, Arc<FjallStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        (dir, store)
    }

    #[tokio::test(start_paused = true)]
    async fn resolves_after_the_grace_once_writes_are_refused() {
        let (_dir, store) = store();
        let watch = write_refused_for(
            Arc::clone(&store),
            Duration::from_secs(30),
            Duration::from_secs(1),
        );
        tokio::pin!(watch);
        // A healthy store never trips it.
        assert!(
            tokio::time::timeout(Duration::from_secs(120), &mut watch)
                .await
                .is_err()
        );
        store.inject_fault(Fault::Now);
        let _ = Store::put(store.as_ref(), b"k", b"v");
        assert!(!store.accepts_writes());
        // Not before the grace ...
        assert!(
            tokio::time::timeout(Duration::from_secs(20), &mut watch)
                .await
                .is_err()
        );
        // ... and then it does.
        tokio::time::timeout(Duration::from_secs(20), &mut watch)
            .await
            .expect("the watchdog fires once the grace has passed");
    }

    #[tokio::test(start_paused = true)]
    async fn zero_grace_turns_it_off() {
        let (_dir, store) = store();
        store.inject_fault(Fault::Now);
        let _ = Store::put(store.as_ref(), b"k", b"v");
        let watch = write_refused_for(store, Duration::ZERO, Duration::from_secs(1));
        assert!(
            tokio::time::timeout(Duration::from_secs(3600), watch)
                .await
                .is_err()
        );
    }
}
