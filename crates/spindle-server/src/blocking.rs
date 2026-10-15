//! Keeping blocking work off the async worker threads (#614).
//!
//! The room layer is synchronous: a room's log sits behind a
//! `std::sync::RwLock`, a cold room is restored from the store by a
//! function that runs for as long as the room is big, and state resolution
//! is CPU work. Called from a handler, all of that runs on a Tokio worker,
//! and the runtime has as many workers as the deployment has cores --
//! four, in production. #614 is what happens when four requests at once
//! touch a room that is cold, or locked by an ingest working through a
//! backlog: every worker is parked, nothing else is polled, and the
//! liveness probe -- which does no work at all -- times out until the
//! kubelet kills a server that was only busy.
//!
//! Two tools, for two shapes of call:
//!
//! - [`offload`] runs a whole request's room work on the blocking pool
//!   (`spawn_blocking`). Used where a handler is a long synchronous stretch
//!   with an `.await` only at its edges: the sync endpoints.
//! - [`section`] marks a stretch *inside* synchronous code that may block
//!   for long -- a cold load, a wait on a contended room lock -- as
//!   blocking (`block_in_place`), so the runtime hands this worker's other
//!   tasks to a fresh thread while it waits. It is the tool for code that
//!   cannot be restructured into a closure the blocking pool can own,
//!   which is most of the room layer's callers.
//!
//! Either way the work still happens and still takes as long; what changes
//! is that it no longer takes the rest of the server with it.

use std::sync::Arc;

use axum::http::StatusCode;

use crate::errors::MatrixError;
use crate::metrics::{BlockingTask, Metrics};

/// Run `work` here, telling the runtime first that it may block.
///
/// On a worker of the multi-threaded runtime this is `block_in_place`:
/// the worker's queue moves to another thread for the duration. Anywhere
/// else -- a blocking-pool thread, a plain thread, the current-thread
/// runtime the unit tests use, where `block_in_place` would panic -- it is
/// a plain call, which is what blocking already meant there.
pub fn section<T>(metrics: &Metrics, task: BlockingTask, work: impl FnOnce() -> T) -> T {
    let on_worker = tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if !on_worker {
        return work();
    }
    let _in_flight = metrics.blocking_started(task);
    tokio::task::block_in_place(work)
}

/// Run `work` on the blocking pool and wait for it without holding a
/// worker.
///
/// On the current-thread runtime (the tests' default) it runs in place, as
/// it always did: there is no pool of workers to protect, and handing the
/// work to another thread would let the runtime's other tasks run in the
/// middle of a request -- which is how a background delivery loop's store
/// reads ended up counted against a sync in `sync_cost.rs`.
///
/// # Errors
///
/// Whatever `work` returns, or `M_UNKNOWN` 500 if it panicked -- the panic
/// stays in its thread rather than unwinding through the handler, which is
/// the answer the caller would have got had it run inline.
pub async fn offload<T: Send + 'static>(
    metrics: Arc<Metrics>,
    task: BlockingTask,
    work: impl FnOnce() -> Result<T, MatrixError> + Send + 'static,
) -> Result<T, MatrixError> {
    if tokio::runtime::Handle::current().runtime_flavor()
        != tokio::runtime::RuntimeFlavor::MultiThread
    {
        return work();
    }
    tokio::task::spawn_blocking(move || {
        let _in_flight = metrics.blocking_started(task);
        work()
    })
    .await
    .map_err(|error| {
        tracing::error!("blocking {task:?} work failed: {error}");
        MatrixError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            "internal error".to_owned(),
        )
    })?
}

/// Drive an async piece of work to completion on the blocking pool.
///
/// For work that is mostly synchronous room work with an `.await` here and
/// there -- an inbound federation transaction, which fetches keys and
/// missing events over the network between ingests that can hold a room
/// for seconds. The awaits still run on the runtime's drivers; the
/// synchronous stretches between them run on a blocking-pool thread rather
/// than a worker, so a backlog of transactions no longer occupies every
/// worker the server has (#614).
///
/// On the current-thread runtime there is no worker to protect and no
/// second thread to drive the I/O a blocking-pool `block_on` would need,
/// so the work is awaited in place.
///
/// # Errors
///
/// `M_UNKNOWN` 500 if the work panicked.
pub async fn offload_async<T, F>(
    metrics: Arc<Metrics>,
    task: BlockingTask,
    make: impl FnOnce() -> F + Send + 'static,
) -> Result<T, MatrixError>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send,
{
    let handle = tokio::runtime::Handle::current();
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Ok(make().await);
    }
    tokio::task::spawn_blocking(move || {
        let _in_flight = metrics.blocking_started(task);
        handle.block_on(make())
    })
    .await
    .map_err(|error| {
        tracing::error!("blocking {task:?} work failed: {error}");
        MatrixError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            "internal error".to_owned(),
        )
    })
}
