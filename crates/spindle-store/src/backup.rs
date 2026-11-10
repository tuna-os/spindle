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
use std::path::{Path, PathBuf};

use crate::codec::CodecError;
use crate::{Durability, ReadView, SchemaMarker, Store, StoreError};
use spindle_core::keys;

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

    // Streamed: each row is framed and written while the backend still owns
    // it, so the backup holds one row whatever the store's size (#743). The
    // `scan_prefix(&[])` this replaced copied the whole store into memory
    // before writing a byte -- on a large deployment, more RAM than the
    // server it is backing up, at a moment it is meant to stay up.
    let mut written = 0_u64;
    let mut failure = None;
    let scanned = view.visit_prefix(&[], &mut |key, value| {
        frame_row(&mut sink, key, value)
            .map(|()| written += 1)
            .map_err(|error| {
                failure = Some(error);
                // Only stops the scan; `failure` is what is reported.
                StoreError::Backend("backup stream stopped".to_owned())
            })
    });
    if let Some(error) = failure {
        return Err(error);
    }
    scanned?;

    sink.write_all(&END_OF_ROWS.to_be_bytes())?;
    sink.write_all(&written.to_be_bytes())?;
    let digest = sink.finish();
    out.write_all(digest.as_bytes())?;
    out.flush()?;
    Ok(written)
}

/// One row of the stream: big-endian `u32` key length, key, `u32` value
/// length, value. A key as long as [`END_OF_ROWS`] would read back as the
/// end of the stream, so it is refused rather than written.
fn frame_row<W: Write + ?Sized>(
    sink: &mut Digesting<'_, W>,
    key: &[u8],
    value: &[u8],
) -> Result<(), BackupError> {
    let key_len = u32::try_from(key.len()).map_err(|_| BackupError::RowTooLarge)?;
    if key_len == END_OF_ROWS {
        return Err(BackupError::RowTooLarge);
    }
    let value_len = u32::try_from(value.len()).map_err(|_| BackupError::RowTooLarge)?;
    sink.write_all(&key_len.to_be_bytes())?;
    sink.write_all(key)?;
    sink.write_all(&value_len.to_be_bytes())?;
    sink.write_all(value)
}

/// Read a backup stream into `store`.
///
/// Verifies the magic, the format version, the schema marker and the trailing
/// digest before reporting success. Rows are written as they are read, so a
/// stream that fails verification may have left rows behind. That is why the
/// restore marks the store first (#811): [`keys::restore_in_progress`] is
/// written and synced before the first row, and removed only after the last
/// row is synced, and a store that holds it refuses to open. Run
/// [`verify_backup`] on the same file first, so that a bad file is refused
/// before a row is written.
///
/// # Errors
///
/// Returns [`BackupError`] if the stream is not a backup, was written under a
/// schema this binary does not speak, or does not match its own digest.
pub fn read_backup(source: &mut dyn Read, store: &dyn Store) -> Result<u64, BackupError> {
    let sentinel = keys::restore_in_progress();
    store.put(&sentinel, b"1")?;
    store.sync(Durability::Strict)?;

    let restored = read_stream(source, &mut |key, value| {
        store.put(key, value).map_err(BackupError::from)
    })?;

    // The rows are durable before the marker that vouches for them is
    // removed; the other order is the partial store this exists to prevent.
    store.flush()?;
    store.reload_key_table()?;
    store.delete(&sentinel)?;
    store.flush()?;
    Ok(restored)
}

/// Check a backup stream end to end and write nothing.
///
/// The same checks as [`read_backup`] — magic, format, schema marker, row
/// count and digest — without a store. A restore reads the file twice, this
/// first, so a truncated or altered file is refused while the target is
/// still empty (#811).
///
/// # Errors
///
/// Returns the [`BackupError`] that [`read_backup`] would.
pub fn verify_backup(source: &mut dyn Read) -> Result<u64, BackupError> {
    read_stream(source, &mut |_, _| Ok(()))
}

/// What [`read_stream`] does with each row it has read.
type OnRow<'a> = dyn FnMut(&[u8], &[u8]) -> Result<(), BackupError> + 'a;

/// Parse and verify a backup stream, handing each row to `on_row`.
fn read_stream(source: &mut dyn Read, on_row: &mut OnRow<'_>) -> Result<u64, BackupError> {
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
        let key = src.read_framed(key_len as usize)?;
        let value_len = src.read_u32()? as usize;
        let value = src.read_framed(value_len)?;
        on_row(&key, &value)?;
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
    Ok(restored)
}

/// Write a backup to `path` so that "wrote N rows" means the file is on disk
/// (#812).
///
/// The stream goes to `<path>.partial`, which is synced, renamed over
/// nothing and followed by a sync of the directory. A failure removes the
/// partial file, so it neither passes for a backup nor blocks the retry. An
/// existing `path` is refused: a backup is never overwritten.
///
/// # Errors
///
/// Returns [`BackupError`] if `path` exists, the scan fails, or the file
/// cannot be written, synced or renamed.
pub fn write_backup_file(view: &dyn ReadView, path: &Path) -> Result<u64, BackupError> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);

    let written = (|| {
        if path.exists() {
            return Err(BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        // A leftover from an earlier run is replaced: it is never a backup.
        let _ = std::fs::remove_file(&partial);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        let mut out = std::io::BufWriter::new(file);
        let rows = write_backup(view, &mut out)?;
        out.into_inner()
            .map_err(std::io::IntoInnerError::into_error)?
            .sync_all()?;
        std::fs::rename(&partial, path)?;
        // The rename is a directory entry: without this a power cut can
        // leave the synced bytes under no name.
        let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
        std::fs::File::open(parent.unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(rows)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    written
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

    /// Read `len` bytes, growing the buffer as they arrive.
    ///
    /// `vec![0; len]` on a length read out of the stream is an allocation
    /// the file chooses: twenty-six bytes claiming `u32::MAX - 1` reserve
    /// four gibibytes before one byte behind that claim has been read. It
    /// survives today only where the kernel overcommits pages nothing goes
    /// on to touch, which is the kernel's decision rather than this
    /// format's, and `spindle restore` is a command an operator points at a
    /// file somebody else wrote.
    ///
    /// Growing in bounded steps costs one reallocation per chunk on an
    /// honest stream, and on a lying one costs a single chunk before
    /// `read_exact` reaches the end and refuses.
    fn read_framed(&mut self, len: usize) -> Result<Vec<u8>, BackupError> {
        const CHUNK: usize = 64 * 1024;
        let mut out = Vec::with_capacity(len.min(CHUNK));
        while out.len() < len {
            let at = out.len();
            let want = CHUNK.min(len - at);
            out.resize(at + want, 0);
            if let Some(tail) = out.get_mut(at..) {
                self.read_exact(tail)?;
            }
        }
        Ok(out)
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
