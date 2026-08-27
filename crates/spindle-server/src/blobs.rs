//! Where media bytes live: a local directory, or an S3 bucket.
//!
//! One enum rather than a trait object because there are exactly two
//! backends and the set changes when an operator changes their deployment,
//! not at runtime. Everything above this file addresses blobs by content
//! hash and neither knows nor cares which arm answers.

use std::path::{Path, PathBuf};

use crate::s3::{S3Client, S3Error};

pub enum Blobs {
    Local { root: PathBuf },
    S3(S3Client),
}

#[derive(Debug)]
pub enum BlobError {
    Io(std::io::Error),
    S3(S3Error),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "blob io: {error}"),
            Self::S3(error) => write!(formatter, "{error}"),
        }
    }
}

impl Blobs {
    /// Store `bytes` under `hash`, if not already present.
    ///
    /// Content addressing makes "already present" a correctness fact, not a
    /// race: identical hash, identical bytes, so whichever writer wins wrote
    /// the same thing.
    ///
    /// # Errors
    ///
    /// Returns [`BlobError`] if the write fails.
    pub async fn put(&self, hash: &str, bytes: &[u8]) -> Result<(), BlobError> {
        match self {
            Self::Local { root } => {
                let path = local_path(root, hash);
                if path.exists() {
                    return Ok(());
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(BlobError::Io)?;
                }
                // Written beside and renamed, so a reader can never observe
                // a half-written blob under its final name. The name is the
                // content hash, so a truncated file under it would be a
                // permanent lie.
                let staging = path.with_extension("partial");
                std::fs::write(&staging, bytes).map_err(BlobError::Io)?;
                std::fs::rename(&staging, &path).map_err(BlobError::Io)?;
                Ok(())
            }
            // S3 PUTs are atomic per object, which is the same guarantee the
            // rename dance buys locally: readers see the old object or the
            // new, never a prefix.
            Self::S3(client) => client
                .put(&s3_key(hash), bytes)
                .await
                .map_err(BlobError::S3),
        }
    }

    /// The bytes under `hash`, or `None`.
    ///
    /// # Errors
    ///
    /// Returns [`BlobError`] only for S3 transport failures — a locally
    /// missing file is `None`, not an error, because "not there" is an
    /// answer and this layer cannot know whether it should have been.
    pub async fn get(&self, hash: &str) -> Result<Option<Vec<u8>>, BlobError> {
        match self {
            Self::Local { root } => Ok(std::fs::read(local_path(root, hash)).ok()),
            Self::S3(client) => client.get(&s3_key(hash)).await.map_err(BlobError::S3),
        }
    }
}

/// `ab/cd/abcdef…` — two shard levels, so no directory collects millions of
/// entries.
fn local_path(root: &Path, hash: &str) -> PathBuf {
    let first = hash.get(0..2).unwrap_or("xx");
    let second = hash.get(2..4).unwrap_or("xx");
    root.join(first).join(second).join(hash)
}

/// Flat under a prefix: S3 has no directories to overfill, and the prefix
/// leaves room for non-media objects in a shared bucket.
fn s3_key(hash: &str) -> String {
    format!("media/{hash}")
}
