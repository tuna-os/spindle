//! A consistent online backup, and a restore that refuses what it cannot read.
//!
//! #20 asks for "a consistent online checkpoint ... verification, restore".
//! Three properties, and each is a separate way a backup betrays the operator
//! who trusted it:
//!
//! **Consistent.** The stream is written through one [`ReadView`], so every
//! row in it is from the same moment. Taken row-by-row against the live store
//! instead, a commit landing mid-scan yields a backup whose metadata and log
//! disagree — and one direction of that disagreement is not merely wrong but
//! unsafe: metadata trailing the log means `next_forward` names an index the
//! log already holds, so the first append after the restore reissues it. That
//! is the fork storage ordering exists to prevent, reached through a backup
//! rather than a crash. `tests/checkpoint.rs` demonstrates the same hazard for
//! reads; this is why [`FjallStore::snapshot`] is what a backup must use.
//!
//! **Verified.** The trailer carries a row count and a BLAKE3 digest over
//! everything before it. A truncated or altered stream is refused rather than
//! restored into a store that then looks fine and is missing its tail — the
//! failure an operator discovers only when they need the data.
//!
//! **Refused when unreadable.** The header carries the [`SchemaMarker`], so a
//! backup written under a different key layout, record encoding or content
//! derivation is rejected by exactly the rule that governs opening a store
//! (#78). Restoring it would produce the same silent wrongness one directory
//! further from where anyone would look for it.
//!
//! The format is deliberately dull: a magic string, a version, framed
//! key/value pairs, a trailer. It is read by the binary that wrote it, and
//! anything cleverer would be a second on-disk format to keep compatible.

use std::io::{Read, Write};

use crate::codec::CodecError;
use crate::{ReadView, SchemaMarker, Store, StoreError};

/// Identifies the stream, so a wrong file is a clear error rather than a
/// confusing one.
const MAGIC: &[u8; 16] = b"SPINDLE-BACKUP\x00\x01";

/// The framing's own version, separate from anything the marker carries: the
/// stream's shape can change without the store's doing so, and vice versa.
const FORMAT_VERSION: u8 = 1;

/// Ends the row section. No key is this long, and a length is how a truncated
/// stream would otherwise be mistaken for a complete one.
const END_OF_ROWS: u32 = u32::MAX;

/// Write every row visible through `view` as a backup stream.
///
/// Pass a snapshot — [`crate::FjallStore::snapshot`] — for an online backup.
/// A live store works and is consistent only if nothing is writing.
///
/// # Errors
///
/// Returns [`StoreError`] if the scan fails, or [`BackupError::Io`] if the
/// stream cannot be written.
pub fn write_backup(view: &dyn ReadView, out: &mut dyn Write) -> Result<u64, BackupError> {
    let marker = SchemaMarker::current().encode();
    let mut sink = Digesting::new(out);

    sink.write_all(MAGIC)?;
    sink.write_all(&[FORMAT_VERSION])?;
    // A single byte of length: the marker is a handful of bytes and always
    // will be -- it has to be readable before anything else, so it cannot
    // grow into something that needs framing of its own.
    let marker_len = u8::try_from(marker.len()).map_err(|_| BackupError::RowTooLarge)?;
    sink.write_all(&[marker_len])?;
    sink.write_all(&marker)?;

    // The empty prefix is every key. Held in memory because the backing scan
    // already returns a Vec; streaming it is worth doing when a store is large
    // enough to care, and is a change to `ReadView`, not to this format.
    let rows = view.scan_prefix(&[])?;
    let mut written = 0_u64;
    for (key, value) in &rows {
        let key_len = u32::try_from(key.len()).map_err(|_| BackupError::RowTooLarge)?;
        if key_len == END_OF_ROWS {
            return Err(BackupError::RowTooLarge);
        }
        let value_len = u32::try_from(value.len()).map_err(|_| BackupError::RowTooLarge)?;
        sink.write_all(&key_len.to_be_bytes())?;
        sink.write_all(key)?;
        sink.write_all(&value_len.to_be_bytes())?;
        sink.write_all(value)?;
        written += 1;
    }

    sink.write_all(&END_OF_ROWS.to_be_bytes())?;
    sink.write_all(&written.to_be_bytes())?;
    let digest = sink.finish();
    out.write_all(digest.as_bytes())?;
    out.flush()?;
    Ok(written)
}

/// Read a backup stream into `store`.
///
/// Verifies the magic, the format version, the schema marker and the trailing
/// digest before reporting success. Rows are written as they are read, so a
/// stream that fails verification may have left rows behind — restore into a
/// fresh store, which is what a restore is.
///
/// # Errors
///
/// Returns [`BackupError`] if the stream is not a backup, was written under a
/// schema this binary does not speak, or does not match its own digest.
pub fn read_backup(source: &mut dyn Read, store: &dyn Store) -> Result<u64, BackupError> {
    let mut src = Digesting::new_read(source);

    let mut magic = [0_u8; 16];
    src.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(BackupError::NotABackup);
    }
    let mut version = [0_u8; 1];
    src.read_exact(&mut version)?;
    if version[0] != FORMAT_VERSION {
        return Err(BackupError::UnsupportedFormat(version[0]));
    }

    let mut marker_len = [0_u8; 1];
    src.read_exact(&mut marker_len)?;
    let mut marker = vec![0_u8; marker_len[0] as usize];
    src.read_exact(&mut marker)?;
    let found = SchemaMarker::decode(&marker)?;
    let supported = SchemaMarker::current();
    if found != supported {
        return Err(BackupError::UnsupportedSchema { found, supported });
    }

    let mut restored = 0_u64;
    loop {
        let key_len = src.read_u32()?;
        if key_len == END_OF_ROWS {
            break;
        }
        let mut key = vec![0_u8; key_len as usize];
        src.read_exact(&mut key)?;
        let value_len = src.read_u32()? as usize;
        let mut value = vec![0_u8; value_len];
        src.read_exact(&mut value)?;
        store.put(&key, &value)?;
        restored += 1;
    }

    let mut claimed = [0_u8; 8];
    src.read_exact(&mut claimed)?;
    let claimed = u64::from_be_bytes(claimed);
    let digest = src.finish();

    // The digest is read *after* finishing, so it is not part of what it
    // covers.
    let mut stored = [0_u8; 32];
    source.read_exact(&mut stored)?;
    if stored != *digest.as_bytes() {
        return Err(BackupError::DigestMismatch);
    }
    if claimed != restored {
        return Err(BackupError::CountMismatch {
            claimed,
            found: restored,
        });
    }
    store.flush()?;
    Ok(restored)
}

/// Wraps a stream and digests everything that passes through it.
struct Digesting<'a, T: ?Sized> {
    inner: &'a mut T,
    hasher: blake3::Hasher,
}

impl<'a, W: Write + ?Sized> Digesting<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        self.hasher.update(bytes);
        self.inner.write_all(bytes)?;
        Ok(())
    }
}

impl<T: ?Sized> Digesting<'_, T> {
    fn finish(self) -> blake3::Hash {
        self.hasher.finalize()
    }
}

impl<'a, R: Read + ?Sized> Digesting<'a, R> {
    fn new_read(inner: &'a mut R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn read_exact(&mut self, into: &mut [u8]) -> Result<(), BackupError> {
        self.inner.read_exact(into)?;
        self.hasher.update(into);
        Ok(())
    }

    fn read_u32(&mut self) -> Result<u32, BackupError> {
        let mut bytes = [0_u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
}

/// Why a backup could not be written or restored.
#[derive(Debug)]
pub enum BackupError {
    Io(std::io::Error),
    Store(StoreError),
    Codec(CodecError),
    /// The stream does not begin with the magic. A wrong file, not a corrupt one.
    NotABackup,
    /// A framing version this binary does not know.
    UnsupportedFormat(u8),
    /// Written under a schema this binary cannot read. Same rule as opening a
    /// store: refuse rather than misread.
    UnsupportedSchema {
        found: SchemaMarker,
        supported: SchemaMarker,
    },
    /// The stream does not match its own digest: truncated, or altered.
    DigestMismatch,
    /// The trailer's count disagrees with what was read.
    CountMismatch {
        claimed: u64,
        found: u64,
    },
    /// A key or value longer than the framing can express.
    RowTooLarge,
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "backup io: {error}"),
            Self::Store(error) => write!(formatter, "backup storage: {error}"),
            Self::Codec(error) => write!(formatter, "backup codec: {error:?}"),
            Self::NotABackup => write!(formatter, "this is not a Spindle backup"),
            Self::UnsupportedFormat(version) => {
                write!(formatter, "unknown backup format version {version}")
            }
            Self::UnsupportedSchema { found, supported } => write!(
                formatter,
                "backup was written under schema {found:?}, this binary speaks {supported:?}"
            ),
            Self::DigestMismatch => {
                write!(formatter, "the backup does not match its own digest")
            }
            Self::CountMismatch { claimed, found } => write!(
                formatter,
                "the backup claims {claimed} rows and holds {found}"
            ),
            Self::RowTooLarge => write!(formatter, "a row is too large for the backup format"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<std::io::Error> for BackupError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StoreError> for BackupError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<CodecError> for BackupError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}
