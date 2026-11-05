//! Password hashing in a bounded set of reusable Argon2 workspaces (#571).
//!
//! One Argon2 computation needs `m_cost` KiB of working memory: 19 MiB at
//! the default parameters. Allocated fresh for each hash, that memory was
//! not given back by glibc. The importer grew by about 16 MiB per account
//! and was OOM-killed after about a thousand accounts. A burst of password
//! logins takes the same path, and concurrent hashes add up.
//!
//! So a computation runs only in a [`Workspace`] of the [`HashPool`]. The
//! pool makes at most `at_once` workspaces, keeps them for the life of the
//! process, and lends each to one computation at a time. A caller that
//! finds every workspace in use waits for one, but only `waiting` callers
//! may wait; the next one gets [`Busy`] at once, which a route answers with
//! 429 `M_LIMIT_EXCEEDED`. A queue without a bound would add no memory, but
//! each waiter holds a thread, and a credential-stuffing run would then
//! hold all of them.
//!
//! The wait and the computation run in a blocking section, not as plain
//! calls on an async worker. A worker that waits for a workspace stops
//! every other request it would have answered (#614).

use std::cell::RefCell;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};

use argon2::password_hash::phc::{Output, ParamsString, PasswordHash, Salt};
use argon2::password_hash::{self, CustomizedPasswordHasher, PasswordHasher};
use argon2::{Algorithm, Argon2, Block, Params, Version};

use crate::config::{
    DEFAULT_PASSWORD_HASHES_AT_ONCE, DEFAULT_PASSWORD_HASHES_WAITING, LimitsConfig,
};

/// The `retry_after_ms` a [`Busy`] refusal carries: a few default-cost
/// hashes' worth, long enough for a full queue to have moved on.
pub const BUSY_RETRY_AFTER_MS: u64 = 1_000;

/// The process's one pool. Process-wide rather than per server, because
/// the memory it bounds is the process's.
static POOL: OnceLock<HashPool> = OnceLock::new();

/// Size the process's pool from `[limits]`, when a server is built.
///
/// The first size wins: workspaces already lent belong to the pool that
/// made them, and a second pool beside it would double the bound. Only a
/// process that builds two servers (a test binary) or hashed before it
/// built one meets a pool of another size. Commands that never build a
/// server (the importer, the admin CLI) hash at the defaults.
pub(crate) fn configure(limits: &LimitsConfig) {
    let (at_once, waiting) = (
        limits.password_hashes_at_once,
        limits.password_hashes_waiting,
    );
    let pool = POOL.get_or_init(|| HashPool::new(at_once, waiting));
    if pool.at_once != at_once || pool.waiting != waiting {
        tracing::warn!(
            "[limits] password_hashes_at_once and password_hashes_waiting apply only to the \
             first server this process builds; the pool already in use keeps its size"
        );
    }
}

/// Run `work` with a workspace of the process's pool.
///
/// # Errors
///
/// [`Busy`] when every workspace is in use and the queue is full.
pub(crate) fn with_workspace<T>(work: impl FnOnce(&Workspace<'_>) -> T) -> Result<T, Busy> {
    POOL.get_or_init(|| {
        HashPool::new(
            DEFAULT_PASSWORD_HASHES_AT_ONCE,
            DEFAULT_PASSWORD_HASHES_WAITING,
        )
    })
    .with_workspace(work)
}

/// Every workspace is in use and the queue for them is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

/// At most `at_once` Argon2 workspaces, and at most `waiting` callers
/// waiting for one.
pub(crate) struct HashPool {
    at_once: usize,
    waiting: usize,
    state: Mutex<PoolState>,
    freed: Condvar,
}

#[derive(Default)]
struct PoolState {
    /// Workspaces made and not lent. With `running`, every workspace the
    /// pool has made: one is made only when a computation starts and none
    /// is idle.
    idle: Vec<Vec<Block>>,
    running: usize,
    queued: usize,
    #[cfg(test)]
    peak_running: usize,
}

impl PoolState {
    fn lend(&mut self) -> Vec<Block> {
        self.running += 1;
        #[cfg(test)]
        {
            self.peak_running = self.peak_running.max(self.running);
        }
        self.idle.pop().unwrap_or_default()
    }
}

impl HashPool {
    fn new(at_once: usize, waiting: usize) -> Self {
        Self {
            // Config refuses a zero; a pool of none would refuse every hash.
            at_once: at_once.max(1),
            waiting,
            state: Mutex::new(PoolState::default()),
            freed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with_workspace<T>(&self, work: impl FnOnce(&Workspace<'_>) -> T) -> Result<T, Busy> {
        // Admitted or refused before the blocking section, so a refusal
        // costs no hand-off of this worker's queue to another thread.
        let lent = {
            let mut state = self.lock();
            if state.running < self.at_once {
                Some(state.lend())
            } else if state.queued < self.waiting {
                state.queued += 1;
                None
            } else {
                return Err(Busy);
            }
        };
        Ok(crate::blocking::unmetered_section(|| {
            let memory = lent.unwrap_or_else(|| self.wait());
            work(&Workspace {
                pool: self,
                memory: RefCell::new(memory),
            })
        }))
    }

    fn wait(&self) -> Vec<Block> {
        let mut state = self
            .freed
            .wait_while(self.lock(), |state| state.running >= self.at_once)
            .unwrap_or_else(PoisonError::into_inner);
        state.queued -= 1;
        state.lend()
    }
}

/// One lent workspace, which hashes and verifies through the
/// password-hash traits. The PHC format and verification remain the
/// password-hash crate's own.
pub(crate) struct Workspace<'a> {
    pool: &'a HashPool,
    memory: RefCell<Vec<Block>>,
}

impl Drop for Workspace<'_> {
    fn drop(&mut self) {
        let memory = std::mem::take(self.memory.get_mut());
        let mut state = self.pool.lock();
        state.idle.push(memory);
        state.running -= 1;
        drop(state);
        self.pool.freed.notify_one();
    }
}

impl CustomizedPasswordHasher<PasswordHash> for Workspace<'_> {
    type Params = Params;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        alg_id: Option<&str>,
        version: Option<u32>,
        params: Params,
    ) -> password_hash::Result<PasswordHash> {
        let algorithm = alg_id
            .map(Algorithm::try_from)
            .transpose()?
            .unwrap_or_default();
        let version = version
            .map(Version::try_from)
            .transpose()?
            .unwrap_or_default();
        let salt = Salt::new(salt)?;
        let output_len = params.output_len().unwrap_or(Params::DEFAULT_OUTPUT_LEN);
        let mut buffer = [0_u8; Output::MAX_LENGTH];
        let out = buffer
            .get_mut(..output_len)
            .ok_or(password_hash::Error::OutputSize)?;
        let encoded_params = ParamsString::try_from(&params)?;
        let block_count = params.block_count();
        let argon = Argon2::new(algorithm, version, params);
        {
            let mut memory = self.memory.borrow_mut();
            // Keep the largest trusted stored hash's workspace, so a
            // later computation at that cost does not allocate again.
            if memory.len() < block_count {
                let additional = block_count - memory.len();
                memory
                    .try_reserve_exact(additional)
                    .map_err(|_| password_hash::Error::OutOfMemory)?;
                memory.resize(block_count, Block::new());
            }
            let result = argon.hash_password_into_with_memory(
                password,
                &salt,
                out,
                &mut memory[..block_count],
            );
            memory[..block_count].fill(Block::new());
            result?;
        }
        Ok(PasswordHash {
            algorithm: algorithm.ident(),
            version: Some(version.into()),
            params: encoded_params,
            salt: Some(salt),
            hash: Some(Output::new(out)?),
        })
    }
}

impl PasswordHasher<PasswordHash> for Workspace<'_> {
    fn hash_password_with_salt(
        &self,
        password: &[u8],
        salt: &[u8],
    ) -> password_hash::Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, Params::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordVerifier;
    use std::sync::mpsc;
    use std::time::Duration;

    impl HashPool {
        fn running_and_queued(&self) -> (usize, usize) {
            let state = self.lock();
            (state.running, state.queued)
        }

        /// Workspaces made so far: lent ones plus idle ones.
        fn made(&self) -> usize {
            let state = self.lock();
            state.running + state.idle.len()
        }

        fn peak_running(&self) -> usize {
            self.lock().peak_running
        }

        fn wait_for(&self, running: usize, queued: usize) {
            while self.running_and_queued() != (running, queued) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn small() -> Params {
        Params::new(64, 2, 1, None).unwrap()
    }

    #[test]
    fn repeated_hashes_reuse_the_allocation() {
        let pool = HashPool::new(1, 0);
        let first = pool
            .with_workspace(|argon| {
                argon
                    .hash_password_with_salt(b"warmup", b"fixed test salt")
                    .unwrap();
                let memory = argon.memory.borrow();
                (memory.as_ptr() as usize, memory.capacity())
            })
            .unwrap();
        for i in 0_u8..32 {
            let now = pool
                .with_workspace(|argon| {
                    argon
                        .hash_password_customized(&[i; 16], b"fixed test salt", None, None, small())
                        .unwrap();
                    let memory = argon.memory.borrow();
                    (memory.as_ptr() as usize, memory.capacity())
                })
                .unwrap();
            assert_eq!(now, first);
        }
        assert_eq!(pool.made(), 1);
    }

    #[test]
    fn output_matches_argon2_for_stored_algorithms_and_parameters() {
        for algorithm in [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id] {
            for version in [Version::V0x10, Version::V0x13] {
                let params = Params::new(64, 2, 2, Some(24)).unwrap();
                let expected = Argon2::new(algorithm, version, params.clone())
                    .hash_password_with_salt(b"password", b"fixed test salt")
                    .unwrap();
                with_workspace(|argon| {
                    let actual = argon
                        .hash_password_customized(
                            b"password",
                            b"fixed test salt",
                            Some(algorithm.ident().as_str()),
                            Some(version.into()),
                            params,
                        )
                        .unwrap();
                    assert_eq!(actual.to_string(), expected.to_string());
                    argon.verify_password(b"password", &expected).unwrap();
                    assert!(argon.verify_password(b"wrong", &expected).is_err());
                })
                .unwrap();
            }
        }
    }

    /// Sixteen logins at once through a pool of three: never more than
    /// three computations at a time, never more than three workspaces
    /// made, and every login still answered, each with its own password
    /// and salt.
    #[test]
    fn concurrent_hashes_never_exceed_the_pool() {
        let pool = std::sync::Arc::new(HashPool::new(3, 16));
        let start = std::sync::Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0_u8..16)
            .map(|i| {
                let pool = std::sync::Arc::clone(&pool);
                let start = std::sync::Arc::clone(&start);
                std::thread::spawn(move || {
                    let password = [i; 16];
                    let salt = [i + 1; 16];
                    start.wait();
                    let hash = pool
                        .with_workspace(|argon| {
                            argon
                                .hash_password_customized(&password, &salt, None, None, small())
                                .unwrap()
                        })
                        .unwrap();
                    Argon2::default().verify_password(&password, &hash).unwrap();
                    assert!(
                        Argon2::default()
                            .verify_password(&[i + 1; 16], &hash)
                            .is_err()
                    );
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(pool.peak_running() <= 3, "peak {}", pool.peak_running());
        assert!(pool.made() <= 3, "made {}", pool.made());
        assert_eq!(pool.running_and_queued(), (0, 0));
    }

    /// With every workspace lent and the queue full, the next caller is
    /// refused at once rather than queued; once a workspace comes back,
    /// the queue drains through the same workspaces.
    #[test]
    fn a_full_queue_refuses_and_drains_through_the_same_workspaces() {
        let pool = std::sync::Arc::new(HashPool::new(2, 3));
        let (release, released) = mpsc::channel::<()>();
        let released = std::sync::Arc::new(Mutex::new(released));
        let hold = |pool: &std::sync::Arc<HashPool>| {
            let pool = std::sync::Arc::clone(pool);
            let released = std::sync::Arc::clone(&released);
            std::thread::spawn(move || {
                pool.with_workspace(|_| released.lock().unwrap().recv().unwrap())
                    .unwrap();
            })
        };
        let mut holders: Vec<_> = (0..2).map(|_| hold(&pool)).collect();
        pool.wait_for(2, 0);
        holders.extend((0..3).map(|_| hold(&pool)));
        pool.wait_for(2, 3);

        assert_eq!(pool.with_workspace(|_| ()), Err(Busy));

        for _ in 0..5 {
            release.send(()).unwrap();
        }
        for holder in holders {
            holder.join().unwrap();
        }
        assert_eq!(pool.running_and_queued(), (0, 0));
        assert_eq!(pool.peak_running(), 2);
        assert_eq!(pool.made(), 2);
        assert_eq!(pool.with_workspace(|_| ()), Ok(()));
    }
}
