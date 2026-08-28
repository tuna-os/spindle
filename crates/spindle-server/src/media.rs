//! Uploaded files: where the bytes go, and who is allowed to see them.
//!
//! Blobs are **content-addressed** by BLAKE3, the same idea the state trie
//! rests on, applied to a different thing. Two users uploading the same image
//! store one copy, and a re-upload after a delete costs nothing.
//!
//! The **media ID is not the hash**, and that separation is load-bearing. A
//! hash-addressed URL would let anyone holding a file confirm whether this
//! server has it — and, for any file drawn from a small set, recover which of
//! that set a user uploaded. Content addressing is a storage decision; it must
//! not become an addressing one. The ID is random and opaque, and the mapping
//! from ID to hash lives in the store.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// The largest upload accepted, in bytes.
///
/// A limit the server states rather than discovers: `/config` advertises it,
/// so a client can refuse a file before spending a minute sending it.
pub const MAX_UPLOAD: usize = 50 * 1024 * 1024;

/// Content types safe to render inline in a browser.
///
/// Everything else is served as an attachment. The list is deliberately short
/// and deliberately does **not** include `text/html`, `image/svg+xml`, or
/// anything else that can execute script: a homeserver that renders uploaded
/// HTML inline has handed every user a stored-XSS primitive against its own
/// origin. SVG is an image and still excluded, because it is also a document
/// that can carry `<script>`.
const INLINE_SAFE: &[&str] = &[
    "image/jpeg",
    "image/gif",
    "image/png",
    "image/apng",
    "image/webp",
    "image/avif",
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/quicktime",
    "audio/mp4",
    "audio/webm",
    "audio/aac",
    "audio/mpeg",
    "audio/ogg",
    "audio/wave",
    "audio/wav",
    "audio/flac",
];

/// What is known about one uploaded file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaRecord {
    /// Hex BLAKE3 of the bytes. The blob's name on disk.
    pub hash: String,
    pub content_type: String,
    /// The name the uploader gave, already made safe to put in a header.
    pub filename: Option<String>,
    pub size: usize,
    pub uploaded_by: String,
}

impl MediaRecord {
    /// Whether a browser may render this inline, or must be made to download it.
    #[must_use]
    pub fn inline_safe(&self) -> bool {
        INLINE_SAFE.contains(&self.content_type.as_str())
    }

    /// The `Content-Disposition` header value.
    ///
    /// The filename is quoted and escaped rather than interpolated: a name
    /// containing a quote or a newline would otherwise let the uploader inject
    /// header content, and the uploader chooses the name.
    #[must_use]
    pub fn content_disposition(&self) -> String {
        let kind = if self.inline_safe() {
            "inline"
        } else {
            "attachment"
        };
        match &self.filename {
            Some(name) => format!("{kind}; filename=\"{}\"", escape_quoted(name)),
            None => kind.to_owned(),
        }
    }
}

/// Make a string safe inside a quoted HTTP header parameter.
///
/// Backslashes and quotes are escaped; control characters -- CR and LF above
/// all -- are dropped entirely rather than escaped, because there is no
/// escaping of them that a header parser is required to understand, and a
/// dropped byte is a worse filename where a kept one is a header injection.
fn escape_quoted(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_control())
        .flat_map(|character| {
            if character == '"' || character == '\\' {
                vec!['\\', character]
            } else {
                vec![character]
            }
        })
        .collect()
}

/// What [`Media::audit`] found: how many distinct blobs the store's records
/// require, and which of them are not there.
#[derive(Debug)]
pub struct MediaAudit {
    /// Distinct content hashes the records refer to.
    pub blobs: usize,
    /// How many of those the backend holds.
    pub present: usize,
    /// The rest, each with the media IDs that resolve to it.
    pub missing: Vec<MissingBlob>,
}

impl MediaAudit {
    /// Whether every blob the records need is there.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// One blob the store expects and the backend does not have.
#[derive(Debug)]
pub struct MissingBlob {
    pub hash: String,
    pub media_ids: Vec<String>,
}

/// Blobs in the configured backend, metadata in the store.
pub struct Media {
    store: Arc<FjallStore>,
    blobs: crate::blobs::Blobs,
    server_name: String,
}

impl Media {
    #[must_use]
    pub fn new(
        store: Arc<FjallStore>,
        blobs: crate::blobs::Blobs,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            store,
            blobs,
            server_name: server_name.into(),
        }
    }

    /// Store `bytes`, returning the new media ID.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::TooLarge`] past [`MAX_UPLOAD`], or
    /// [`MediaError`] if the blob or its record cannot be written.
    pub async fn put(
        &self,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
        uploaded_by: &str,
    ) -> Result<String, MediaError> {
        if bytes.len() > MAX_UPLOAD {
            return Err(MediaError::TooLarge {
                size: bytes.len(),
                limit: MAX_UPLOAD,
            });
        }
        let hash = blake3::hash(bytes).to_hex().to_string();
        // Identical bytes are one blob: the backend skips or overwrites with
        // the same content, whichever it finds cheaper.
        self.blobs.put(&hash, bytes).await?;

        let media_id = random_media_id();
        let record = MediaRecord {
            hash,
            content_type: content_type.to_owned(),
            filename: filename.map(str::to_owned),
            size: bytes.len(),
            uploaded_by: uploaded_by.to_owned(),
        };
        Store::put(
            self.store.as_ref(),
            &keys::media(&media_id),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(media_id)
    }

    /// The internal ID a remote server's media is cached under.
    ///
    /// Local IDs are 32 hex characters, so the `/` makes collision with a
    /// minted ID impossible by construction.
    #[must_use]
    pub fn remote_id(server_name: &str, media_id: &str) -> String {
        format!("{server_name}/{media_id}")
    }

    /// Cache a remote server's media under its [`Self::remote_id`].
    ///
    /// Re-fetching identical bytes is free twice over: the blob store is
    /// content-addressed, and the record write is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::TooLarge`] past [`MAX_UPLOAD`], or
    /// [`MediaError`] if the blob or its record cannot be written.
    pub async fn put_remote(
        &self,
        server_name: &str,
        media_id: &str,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
    ) -> Result<(), MediaError> {
        if bytes.len() > MAX_UPLOAD {
            return Err(MediaError::TooLarge {
                size: bytes.len(),
                limit: MAX_UPLOAD,
            });
        }
        let hash = blake3::hash(bytes).to_hex().to_string();
        self.blobs.put(&hash, bytes).await?;
        let record = MediaRecord {
            hash,
            content_type: content_type.to_owned(),
            filename: filename.map(str::to_owned),
            size: bytes.len(),
            uploaded_by: format!("federation:{server_name}"),
        };
        Store::put(
            self.store.as_ref(),
            &keys::media(&Self::remote_id(server_name, media_id)),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }

    /// Every blob this store's media records need, and which of them the
    /// backend actually holds.
    ///
    /// The two halves of media live in different places: the record is a
    /// row in the store, the bytes are a blob in a directory or a bucket.
    /// A backup carries rows. So a restore can report every row written and
    /// leave a server that answers 404 to every download, with nothing in
    /// the restore having said so -- the check was green about something
    /// narrower than the claim resting on it.
    ///
    /// This is that claim made checkable. Blobs are content-addressed, so
    /// identical uploads are one blob and the audit counts it once; the
    /// media IDs that need a missing blob are reported with it, because
    /// "some media is gone" is not an actionable sentence and "these four
    /// files are gone" is.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the store cannot be scanned, a record
    /// cannot be decoded, or the blob backend fails in a way that is not
    /// simply "absent".
    pub async fn audit(&self) -> Result<MediaAudit, MediaError> {
        // hash -> the media IDs that resolve to it, so a missing blob names
        // everything it takes down with it rather than just itself.
        let mut wanted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in ReadView::scan_prefix(self.store.as_ref(), &keys::media_all())? {
            let record: MediaRecord = serde_json::from_slice(&value)?;
            let id = keys::media_id(&key).unwrap_or_else(|| "<unreadable key>".to_owned());
            wanted.entry(record.hash).or_default().push(id);
        }
        let mut audit = MediaAudit {
            blobs: wanted.len(),
            present: 0,
            missing: Vec::new(),
        };
        for (hash, media_ids) in wanted {
            if self.blobs.has(&hash).await? {
                audit.present += 1;
            } else {
                audit.missing.push(MissingBlob { hash, media_ids });
            }
        }
        Ok(audit)
    }

    /// What is known about `media_id`, or `None`.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the record cannot be read or decoded.
    pub fn record(&self, media_id: &str) -> Result<Option<MediaRecord>, MediaError> {
        let Some(bytes) = ReadView::get(self.store.as_ref(), &keys::media(media_id))? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    /// The bytes of `media_id`.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Unknown`] if nothing is stored under that ID, or
    /// [`MediaError::Missing`] if the record exists but its blob does not --
    /// which means the store and the filesystem disagree, and is worth saying
    /// rather than reporting as "no such file".
    pub async fn bytes(&self, media_id: &str) -> Result<(MediaRecord, Vec<u8>), MediaError> {
        let record = self
            .record(media_id)?
            .ok_or_else(|| MediaError::Unknown(media_id.to_owned()))?;
        let bytes = self
            .blobs
            .get(&record.hash)
            .await?
            .ok_or_else(|| MediaError::Missing {
                media_id: media_id.to_owned(),
                hash: record.hash.clone(),
            })?;
        Ok((record, bytes))
    }

    /// A thumbnail of `media_id` at (or near) the requested size.
    ///
    /// Generated on first request and cached content-addressed, keyed by the
    /// *source hash* plus the normalized dimensions and method — so two media
    /// IDs sharing bytes share thumbnails too, and a regenerate is impossible
    /// by construction: the same inputs name the same blob.
    ///
    /// Dimensions are normalized to a small fixed set before anything else.
    /// Honouring arbitrary `width`x`height` would let one client mint an
    /// unbounded family of cached files from a single upload — a disk
    /// amplification the spec itself warns about, which is why it permits
    /// the server to return a size other than the one requested.
    ///
    /// Only image types are thumbnailed. A PDF or a video has no cheap safe
    /// thumbnail, and `M_UNSUPPORTED` is the truthful answer.
    ///
    /// # Errors
    ///
    /// [`MediaError::Unknown`] for an ID nothing is stored under,
    /// [`MediaError::Unsupported`] for a non-image type, and
    /// [`MediaError::Unreadable`] when the bytes do not decode as the format
    /// they were declared to be — the uploader's claim, checked exactly at
    /// the moment it is first relied upon.
    pub async fn thumbnail(
        &self,
        media_id: &str,
        width: u32,
        height: u32,
        crop: bool,
    ) -> Result<(String, Vec<u8>), MediaError> {
        let record = self
            .record(media_id)?
            .ok_or_else(|| MediaError::Unknown(media_id.to_owned()))?;
        if !record.content_type.starts_with("image/") || record.content_type == "image/svg+xml" {
            return Err(MediaError::Unsupported(record.content_type));
        }
        let (width, height) = normalize_dimensions(width, height);

        let cache_key = format!(
            "{}-{}x{}-{}",
            record.hash,
            width,
            height,
            if crop { "crop" } else { "scale" }
        );
        let cache_hash = blake3::hash(cache_key.as_bytes()).to_hex().to_string();
        if let Some(bytes) = self.blobs.get(&cache_hash).await? {
            return Ok(("image/png".to_owned(), bytes));
        }

        let source = self
            .blobs
            .get(&record.hash)
            .await?
            .ok_or_else(|| MediaError::Missing {
                media_id: media_id.to_owned(),
                hash: record.hash.clone(),
            })?;
        let decoded = image::load_from_memory(&source)
            .map_err(|error| MediaError::Unreadable(error.to_string()))?;
        let resized = if crop {
            decoded.resize_to_fill(width, height, image::imageops::FilterType::Triangle)
        } else {
            decoded.resize(width, height, image::imageops::FilterType::Triangle)
        };
        let mut bytes = Vec::new();
        resized
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .map_err(|error| MediaError::Unreadable(error.to_string()))?;

        // Cached exactly like an upload — the backend's atomicity story
        // (rename locally, atomic object PUT on S3) means a concurrent
        // request never reads a half-written thumbnail.
        self.blobs.put(&cache_hash, &bytes).await?;
        Ok(("image/png".to_owned(), bytes))
    }

    /// The `mxc://` URI for one of this server's media IDs.
    #[must_use]
    pub fn mxc(&self, media_id: &str) -> String {
        format!("mxc://{}/{media_id}", self.server_name)
    }

    /// Whether this server is the one that holds `server_name`'s media.
    #[must_use]
    pub fn is_ours(&self, server_name: &str) -> bool {
        server_name == self.server_name
    }
}

/// Snap requested dimensions to the ladder the spec suggests.
///
/// The smallest rung at least as large as the request wins, so a client never
/// gets less than it asked for unless it asked for more than the largest rung.
/// A fixed ladder bounds the cache at a handful of files per upload.
fn normalize_dimensions(width: u32, height: u32) -> (u32, u32) {
    const LADDER: [(u32, u32); 5] = [(32, 32), (96, 96), (320, 240), (640, 480), (800, 600)];
    for (rung_width, rung_height) in LADDER {
        if width <= rung_width && height <= rung_height {
            return (rung_width, rung_height);
        }
    }
    (800, 600)
}

/// An opaque, unguessable media ID.
///
/// Random rather than derived from the content, for the reason the module
/// header gives: a hash-addressed URL is an existence oracle. 32 hex
/// characters is 128 bits, which is not guessable by anyone.
fn random_media_id() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 16];
    crate::secrets::fill(&mut bytes);
    bytes
        .iter()
        .fold(String::with_capacity(32), |mut id, byte| {
            let _ = write!(id, "{byte:02x}");
            id
        })
}

/// What can go wrong with media.
#[derive(Debug)]
pub enum MediaError {
    Unknown(String),
    /// The record exists and the blob does not: the store and the filesystem
    /// disagree, which is a different fault from a missing upload.
    Missing {
        media_id: String,
        hash: String,
    },
    TooLarge {
        size: usize,
        limit: usize,
    },
    /// A type this server does not thumbnail.
    Unsupported(String),
    /// Bytes that do not decode as the format they were declared to be.
    Unreadable(String),
    Storage(StoreError),
    Io(String),
    Codec(String),
}

impl From<crate::blobs::BlobError> for MediaError {
    fn from(error: crate::blobs::BlobError) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<StoreError> for MediaError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for MediaError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<serde_json::Error> for MediaError {
    fn from(error: serde_json::Error) -> Self {
        Self::Codec(error.to_string())
    }
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(id) => write!(formatter, "no media with ID {id}"),
            Self::Missing { media_id, hash } => write!(
                formatter,
                "{media_id} is recorded but its blob {hash} is not on disk"
            ),
            Self::TooLarge { size, limit } => {
                write!(formatter, "{size} bytes exceeds the {limit}-byte limit")
            }
            Self::Unsupported(content_type) => {
                write!(formatter, "no thumbnails for {content_type}")
            }
            Self::Unreadable(message) => {
                write!(
                    formatter,
                    "the bytes do not decode as their declared type: {message}"
                )
            }
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Io(message) => write!(formatter, "filesystem: {message}"),
            Self::Codec(message) => write!(formatter, "unreadable: {message}"),
        }
    }
}

impl std::error::Error for MediaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filename_cannot_inject_a_header() {
        // The uploader chooses the name, so it is attacker-controlled input
        // going into a response header.
        let record = |name: &str| MediaRecord {
            hash: "abc".to_owned(),
            content_type: "application/octet-stream".to_owned(),
            filename: Some(name.to_owned()),
            size: 1,
            uploaded_by: "@a:b".to_owned(),
        };

        let injected = record("evil\r\nX-Evil: yes").content_disposition();
        assert!(
            !injected.contains('\r') && !injected.contains('\n'),
            "{injected}"
        );

        let quoted = record("say \"hello\"").content_disposition();
        assert_eq!(quoted, r#"attachment; filename="say \"hello\"""#);

        let backslash = record(r"back\slash").content_disposition();
        assert_eq!(backslash, r#"attachment; filename="back\\slash""#);
    }

    #[test]
    fn html_and_svg_are_never_inline() {
        // A homeserver that renders uploaded HTML inline has handed every user
        // a stored-XSS primitive against its own origin. SVG is an image and
        // also a document that can carry script.
        for dangerous in [
            "text/html",
            "image/svg+xml",
            "application/xhtml+xml",
            "text/javascript",
            "application/javascript",
        ] {
            let record = MediaRecord {
                hash: "abc".to_owned(),
                content_type: dangerous.to_owned(),
                filename: None,
                size: 1,
                uploaded_by: "@a:b".to_owned(),
            };
            assert!(!record.inline_safe(), "{dangerous} must not render inline");
            assert_eq!(record.content_disposition(), "attachment");
        }
    }

    #[test]
    fn ordinary_images_are_inline() {
        let record = MediaRecord {
            hash: "abc".to_owned(),
            content_type: "image/png".to_owned(),
            filename: Some("cat.png".to_owned()),
            size: 1,
            uploaded_by: "@a:b".to_owned(),
        };
        assert!(record.inline_safe());
        assert_eq!(
            record.content_disposition(),
            r#"inline; filename="cat.png""#
        );
    }
}
