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

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// The default largest upload accepted, in bytes.
///
/// A limit the server states rather than discovers: `/config` advertises it,
/// so a client can refuse a file before spending a minute sending it.
pub const MAX_UPLOAD: usize = 50 * 1024 * 1024;

/// How long a minted-but-empty media ID stays claimable: the spec's
/// recommended 24 hours, for uploaders on a poor connection.
pub const RESERVATION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Live reservations one user may hold at once.
pub const MAX_PENDING_UPLOADS: usize = 20;

/// A media ID minted ahead of its bytes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Reservation {
    pub user_id: String,
    pub expires_at: u64,
}

pub(crate) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

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
    /// When the bytes arrived, in milliseconds. Absent on records written
    /// before this was kept; the cache purge reads those as the oldest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ts: Option<u64>,
    /// The admin who quarantined it. A quarantined record is kept as
    /// evidence and never served; see [`Media::set_quarantine`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_by: Option<String>,
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

/// Whether an upload is held to the uploader's byte quota. The caller
/// decides, because who is exempt (appservice users, admins) is a question
/// about accounts and registrations this module does not hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Quota {
    Enforced,
    Exempt,
}

/// Blobs in the configured backend, metadata in the store.
pub struct Media {
    store: Arc<FjallStore>,
    blobs: crate::blobs::Blobs,
    server_name: String,
    max_upload_bytes: usize,
    /// `[media] max_bytes_per_user`; `None` is no quota.
    quota_bytes: Option<u64>,
    /// Bytes each local account's uploads hold, built from the media
    /// records the first time a quota is checked and kept in step by every
    /// upload and delete after that.
    ///
    /// Derived rather than persisted: the records are the truth, so a
    /// count rebuilt from them at each start cannot drift from them across
    /// a crash, an import or a restore, and there is no second keyspace to
    /// back up. One scan per process, and only on a server with a quota.
    usage: Mutex<Option<HashMap<String, u64>>>,
    /// `[media] max_thumbnail_pixels`: the most pixels a source image may
    /// declare before it is refused rather than decoded.
    max_thumbnail_pixels: u64,
    /// Bounds how many image decodes run at once. A decode holds a blocking
    /// thread and a pixel buffer, so unbounded concurrency lets a burst of
    /// requests for large images exhaust memory even under the pixel budget.
    decode_slots: Arc<tokio::sync::Semaphore>,
    /// Source hashes that failed to thumbnail, and when, so a bad image is
    /// refused from memory instead of being fetched and decoded again on
    /// every request. Only successes were cached before.
    decode_failures: Mutex<HashMap<String, (Instant, DecodeFailure)>>,
    /// Decodes that got as far as reading pixel data. Counted so a test can
    /// show an over-budget image never reached the decoder.
    decodes_started: Arc<AtomicU64>,
}

/// Most image decodes in flight at once.
const DECODE_CONCURRENCY: usize = 4;
/// How long a failed decode is remembered.
const DECODE_FAILURE_TTL: Duration = Duration::from_secs(300);
/// Most failures remembered; past it the map is pruned, then cleared.
const DECODE_FAILURE_CAP: usize = 1024;

/// Why a source image could not be thumbnailed, kept for the failure cache.
#[derive(Clone, Debug)]
enum DecodeFailure {
    TooManyPixels { pixels: u64, limit: u64 },
    Unreadable(String),
}

impl DecodeFailure {
    fn into_error(self) -> MediaError {
        match self {
            Self::TooManyPixels { pixels, limit } => MediaError::ImageTooLarge { pixels, limit },
            Self::Unreadable(message) => MediaError::Unreadable(message),
        }
    }
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
            max_upload_bytes: MAX_UPLOAD,
            quota_bytes: None,
            usage: Mutex::new(None),
            max_thumbnail_pixels: DEFAULT_MAX_THUMBNAIL_PIXELS,
            decode_slots: Arc::new(tokio::sync::Semaphore::new(DECODE_CONCURRENCY)),
            decode_failures: Mutex::new(HashMap::new()),
            decodes_started: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Refuse to thumbnail sources declaring more than `pixels` pixels.
    #[must_use]
    pub fn with_max_thumbnail_pixels(mut self, pixels: u64) -> Self {
        self.max_thumbnail_pixels = pixels;
        self
    }

    /// How many thumbnail decodes have started reading pixel data.
    #[must_use]
    pub fn decodes_started(&self) -> u64 {
        self.decodes_started.load(Ordering::Relaxed)
    }

    fn remembered_failure(&self, hash: &str) -> Option<DecodeFailure> {
        let failures = self
            .decode_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        failures
            .get(hash)
            .filter(|(at, _)| at.elapsed() < DECODE_FAILURE_TTL)
            .map(|(_, failure)| failure.clone())
    }

    fn remember_failure(&self, hash: &str, failure: DecodeFailure) {
        let mut failures = self
            .decode_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if failures.len() >= DECODE_FAILURE_CAP {
            failures.retain(|_, (at, _)| at.elapsed() < DECODE_FAILURE_TTL);
            if failures.len() >= DECODE_FAILURE_CAP {
                failures.clear();
            }
        }
        failures.insert(hash.to_owned(), (Instant::now(), failure));
    }

    /// Use the configured cap for uploads and remote media caching.
    #[must_use]
    pub fn with_max_upload_bytes(mut self, max_upload_bytes: usize) -> Self {
        self.max_upload_bytes = max_upload_bytes;
        self
    }

    /// Hold each account's uploads to `quota_bytes` in total; `None` is
    /// no quota.
    #[must_use]
    pub fn with_quota_bytes(mut self, quota_bytes: Option<u64>) -> Self {
        self.quota_bytes = quota_bytes;
        self
    }

    /// The configured per-account quota, if there is one.
    #[must_use]
    pub const fn quota_bytes(&self) -> Option<u64> {
        self.quota_bytes
    }

    /// The same limit advertised by the media configuration endpoints.
    #[must_use]
    pub const fn max_upload_bytes(&self) -> usize {
        self.max_upload_bytes
    }

    /// Store `bytes`, returning the new media ID.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::TooLarge`] past [`Self::max_upload_bytes`],
    /// [`MediaError::QuotaExceeded`] past the uploader's quota, or
    /// [`MediaError`] if the blob or its record cannot be written.
    pub async fn put(
        &self,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
        uploaded_by: &str,
        quota: Quota,
    ) -> Result<String, MediaError> {
        if bytes.len() > self.max_upload_bytes {
            return Err(MediaError::TooLarge {
                size: bytes.len(),
                limit: self.max_upload_bytes,
            });
        }
        let media_id = random_media_id();
        let record = MediaRecord {
            hash: blake3::hash(bytes).to_hex().to_string(),
            content_type: content_type.to_owned(),
            filename: filename.map(str::to_owned),
            size: bytes.len(),
            uploaded_by: uploaded_by.to_owned(),
            created_ts: Some(now_millis()),
            quarantined_by: None,
        };
        self.store_upload(&media_id, bytes, &record, quota).await?;
        Ok(media_id)
    }

    /// Charge an upload to its uploader's quota, then write its blob and
    /// its record, giving the charge back if either write fails.
    ///
    /// The quota is checked before a byte is written, not after: a check
    /// that ran once the blob was stored would refuse the upload and keep
    /// the bytes, which is a quota that fills the disk it exists to guard.
    async fn store_upload(
        &self,
        media_id: &str,
        bytes: &[u8],
        record: &MediaRecord,
        quota: Quota,
    ) -> Result<(), MediaError> {
        let charged = self.charge(&record.uploaded_by, record.size, quota)?;
        let written = self.write_upload(media_id, bytes, record).await;
        if written.is_err() && charged {
            self.refund(&record.uploaded_by, record.size);
        }
        written
    }

    async fn write_upload(
        &self,
        media_id: &str,
        bytes: &[u8],
        record: &MediaRecord,
    ) -> Result<(), MediaError> {
        // Identical bytes are one blob: the backend skips or overwrites with
        // the same content, whichever it finds cheaper.
        self.blobs.put(&record.hash, bytes).await?;
        Store::put(
            self.store.as_ref(),
            &keys::media(media_id),
            &serde_json::to_vec(record)?,
        )?;
        Ok(())
    }

    /// Count `size` bytes to `user_id`, refusing them under
    /// [`Quota::Enforced`] when they would take the account past its
    /// quota. Returns whether anything was counted.
    ///
    /// An exempt upload is still counted, so an account that stops being
    /// exempt is held to what it actually stores.
    fn charge(&self, user_id: &str, size: usize, quota: Quota) -> Result<bool, MediaError> {
        let Some(limit) = self.quota_bytes else {
            return Ok(false);
        };
        let size = u64::try_from(size).unwrap_or(u64::MAX);
        let mut usage = self.usage.lock().unwrap_or_else(PoisonError::into_inner);
        // Built under the lock, so two first uploads cannot both scan, and
        // an upload finishing meanwhile cannot land between the scan and
        // the map it should have been counted in.
        let totals = match usage.take() {
            Some(totals) => totals,
            None => self.usage_by_uploader()?,
        };
        let totals = usage.insert(totals);
        let used = totals.get(user_id).copied().unwrap_or(0);
        if quota == Quota::Enforced && used.saturating_add(size) > limit {
            return Err(MediaError::QuotaExceeded {
                used,
                size,
                quota: limit,
            });
        }
        if let Some(total) = totals.get_mut(user_id) {
            *total = total.saturating_add(size);
        } else {
            totals.insert(user_id.to_owned(), size);
        }
        Ok(true)
    }

    /// Give `size` bytes back to `user_id`: a failed write, or a delete.
    fn refund(&self, user_id: &str, size: usize) {
        let size = u64::try_from(size).unwrap_or(u64::MAX);
        let mut usage = self.usage.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(total) = usage.as_mut().and_then(|totals| totals.get_mut(user_id)) {
            *total = total.saturating_sub(size);
        }
    }

    /// Bytes held by each local uploader, from the records.
    fn usage_by_uploader(&self) -> Result<HashMap<String, u64>, MediaError> {
        let mut totals: HashMap<String, u64> = HashMap::new();
        for (media_id, record) in self.records()? {
            // A cached copy of remote media is nobody's upload here.
            if media_id.contains('/') {
                continue;
            }
            let size = u64::try_from(record.size).unwrap_or(u64::MAX);
            let total = totals.entry(record.uploaded_by).or_insert(0);
            *total = total.saturating_add(size);
        }
        Ok(totals)
    }

    /// Store `bytes` under a media ID another server already handed out.
    ///
    /// The Synapse importer uses this: every `mxc://` URI in the imported
    /// history names a media ID Synapse chose, and the import keeps those
    /// IDs so the URIs still resolve. The size cap does not apply, because
    /// the file was already accepted once and refusing it now would lose it.
    /// Repeating the call with the same bytes writes the same record.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the blob or its record cannot be written.
    #[cfg(feature = "synapse-import")]
    pub async fn put_imported(
        &self,
        media_id: &str,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
        uploaded_by: &str,
    ) -> Result<String, MediaError> {
        let hash = blake3::hash(bytes).to_hex().to_string();
        self.blobs.put(&hash, bytes).await?;
        let record = MediaRecord {
            hash: hash.clone(),
            content_type: content_type.to_owned(),
            filename: filename.map(str::to_owned),
            size: bytes.len(),
            uploaded_by: uploaded_by.to_owned(),
            created_ts: Some(now_millis()),
            quarantined_by: None,
        };
        Store::put(
            self.store.as_ref(),
            &keys::media(media_id),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(hash)
    }

    /// Mint a media ID ahead of its bytes (`POST /_matrix/media/v1/create`,
    /// spec v1.7). Returns the ID and the moment the reservation lapses.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::TooManyPending`] when the user already holds
    /// [`MAX_PENDING_UPLOADS`] live reservations, or [`MediaError`] if the
    /// row cannot be written.
    pub fn reserve(&self, user_id: &str) -> Result<(String, u64), MediaError> {
        let now = now_millis();
        let mut pending = 0;
        for (key, value) in
            ReadView::scan_prefix(self.store.as_ref(), &keys::media_reservation(""))?
        {
            let reservation: Reservation = serde_json::from_slice(&value)?;
            if reservation.expires_at <= now {
                // Lapsed: cleared on sight rather than by a sweeper.
                Store::delete(self.store.as_ref(), &key)?;
            } else if reservation.user_id == user_id {
                pending += 1;
            }
        }
        if pending >= MAX_PENDING_UPLOADS {
            return Err(MediaError::TooManyPending(MAX_PENDING_UPLOADS));
        }
        let media_id = random_media_id();
        let expires_at = now.saturating_add(RESERVATION_TTL_MS);
        let reservation = Reservation {
            user_id: user_id.to_owned(),
            expires_at,
        };
        Store::put(
            self.store.as_ref(),
            &keys::media_reservation(&media_id),
            &serde_json::to_vec(&reservation)?,
        )?;
        Ok((media_id, expires_at))
    }

    /// Whether `media_id` is reserved and waiting for its bytes. A lapsed
    /// reservation reads as none.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the row cannot be read.
    pub fn reservation(&self, media_id: &str) -> Result<Option<Reservation>, MediaError> {
        let Some(bytes) = ReadView::get(self.store.as_ref(), &keys::media_reservation(media_id))?
        else {
            return Ok(None);
        };
        let reservation: Reservation = serde_json::from_slice(&bytes)?;
        Ok((reservation.expires_at > now_millis()).then_some(reservation))
    }

    /// Fill a reserved media ID (`PUT /_matrix/media/v3/upload/{server}/{id}`).
    ///
    /// # Errors
    ///
    /// [`MediaError::AlreadyUploaded`] when the ID already has bytes,
    /// [`MediaError::Unknown`] when no live reservation stands,
    /// [`MediaError::NotReserver`] when someone else reserved it,
    /// [`MediaError::TooLarge`] past [`Self::max_upload_bytes`],
    /// [`MediaError::QuotaExceeded`] past the uploader's quota, or
    /// [`MediaError`] if the blob or its record cannot be written.
    pub async fn put_reserved(
        &self,
        media_id: &str,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
        uploaded_by: &str,
        quota: Quota,
    ) -> Result<(), MediaError> {
        if self.record(media_id)?.is_some() {
            return Err(MediaError::AlreadyUploaded(media_id.to_owned()));
        }
        let Some(reservation) = self.reservation(media_id)? else {
            return Err(MediaError::Unknown(media_id.to_owned()));
        };
        if reservation.user_id != uploaded_by {
            return Err(MediaError::NotReserver(media_id.to_owned()));
        }
        if bytes.len() > self.max_upload_bytes {
            return Err(MediaError::TooLarge {
                size: bytes.len(),
                limit: self.max_upload_bytes,
            });
        }
        let record = MediaRecord {
            hash: blake3::hash(bytes).to_hex().to_string(),
            content_type: content_type.to_owned(),
            filename: filename.map(str::to_owned),
            size: bytes.len(),
            uploaded_by: uploaded_by.to_owned(),
            created_ts: Some(now_millis()),
            quarantined_by: None,
        };
        self.store_upload(media_id, bytes, &record, quota).await?;
        Store::delete(self.store.as_ref(), &keys::media_reservation(media_id))?;
        Ok(())
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
    /// Returns [`MediaError::TooLarge`] past [`Self::max_upload_bytes`], or
    /// [`MediaError`] if the blob or its record cannot be written.
    pub async fn put_remote(
        &self,
        server_name: &str,
        media_id: &str,
        bytes: &[u8],
        content_type: &str,
        filename: Option<&str>,
    ) -> Result<(), MediaError> {
        if bytes.len() > self.max_upload_bytes {
            return Err(MediaError::TooLarge {
                size: bytes.len(),
                limit: self.max_upload_bytes,
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
            created_ts: Some(now_millis()),
            quarantined_by: None,
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
            // A tombstone holds no bytes to be missing.
            if record.hash.is_empty() {
                continue;
            }
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

    /// The record, or the reason there is none: a live reservation is
    /// [`MediaError::NotYetUploaded`], which the spec answers with 504 so
    /// a client can retry once the uploader finishes.
    fn record_or_pending(&self, media_id: &str) -> Result<MediaRecord, MediaError> {
        if let Some(record) = self.record(media_id)? {
            // Every read path -- download, thumbnail, and the federation
            // twins -- goes through here, so one check covers them all and
            // a new route cannot forget it. Not-found, not forbidden: a
            // 403 would tell the requester the item exists.
            if record.quarantined_by.is_some() {
                return Err(MediaError::Unknown(media_id.to_owned()));
            }
            return Ok(record);
        }
        if self.reservation(media_id)?.is_some() {
            return Err(MediaError::NotYetUploaded(media_id.to_owned()));
        }
        Err(MediaError::Unknown(media_id.to_owned()))
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
        let record = self.record_or_pending(media_id)?;
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
        let record = self.record_or_pending(media_id)?;
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
        let bytes = self
            .decode_thumbnail(&record.hash, source, width, height, crop)
            .await?;

        // Cached exactly like an upload — the backend's atomicity story
        // (rename locally, atomic object PUT on S3) means a concurrent
        // request never reads a half-written thumbnail.
        self.blobs.put(&cache_hash, &bytes).await?;
        Ok(("image/png".to_owned(), bytes))
    }

    /// Decode `source` and render the thumbnail, off the async workers and
    /// behind [`DECODE_CONCURRENCY`] slots. A failure is remembered by source
    /// hash for [`DECODE_FAILURE_TTL`].
    async fn decode_thumbnail(
        &self,
        hash: &str,
        source: Vec<u8>,
        width: u32,
        height: u32,
        crop: bool,
    ) -> Result<Vec<u8>, MediaError> {
        if let Some(failure) = self.remembered_failure(hash) {
            return Err(failure.into_error());
        }
        let permit = Arc::clone(&self.decode_slots)
            .acquire_owned()
            .await
            .map_err(|error| MediaError::Io(error.to_string()))?;
        let limit = self.max_thumbnail_pixels;
        let started = Arc::clone(&self.decodes_started);
        let outcome = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            render_thumbnail(&source, width, height, crop, limit, &started)
        })
        .await
        .map_err(|error| MediaError::Io(error.to_string()))?;
        match outcome {
            Ok(bytes) => Ok(bytes),
            Err(failure) => {
                self.remember_failure(hash, failure.clone());
                Err(failure.into_error())
            }
        }
    }

    /// Every media record, with its ID: what the admin API lists a user's
    /// uploads from. Remote media cached here is included, under its
    /// [`Self::remote_id`].
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the store cannot be scanned or a record
    /// cannot be decoded.
    pub fn records(&self) -> Result<Vec<(String, MediaRecord)>, MediaError> {
        let mut out = Vec::new();
        for (key, value) in ReadView::scan_prefix(self.store.as_ref(), &keys::media_all())? {
            if let Some(id) = keys::media_id(&key) {
                out.push((id, serde_json::from_slice(&value)?));
            }
        }
        Ok(out)
    }

    /// Delete `media_id`: its record, and its bytes and cached thumbnails
    /// unless another record holds the same bytes. Returns whether there
    /// was anything to delete.
    ///
    /// The record goes first, so from that moment the media is not served
    /// even if removing the bytes then fails; the bytes left behind are an
    /// orphan the media audit can find, never media that still answers.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the store or the blob backend fails.
    pub async fn delete(&self, media_id: &str) -> Result<bool, MediaError> {
        let Some(record) = self.record(media_id)? else {
            return Ok(false);
        };
        Store::delete(self.store.as_ref(), &keys::media(media_id))?;
        // The bytes stop counting with the record, whatever happens to the
        // blob: from here the upload is not the account's to serve.
        if !media_id.contains('/') {
            self.refund(&record.uploaded_by, record.size);
        }
        if record.hash.is_empty() {
            return Ok(true);
        }
        let shared = self
            .records()?
            .iter()
            .any(|(_, other)| other.hash == record.hash);
        if !shared {
            for (width, height) in THUMBNAIL_LADDER {
                for method in ["crop", "scale"] {
                    let cache_key = format!("{}-{width}x{height}-{method}", record.hash);
                    let cache_hash = blake3::hash(cache_key.as_bytes()).to_hex().to_string();
                    self.blobs.delete(&cache_hash).await?;
                }
            }
            self.blobs.delete(&record.hash).await?;
        }
        Ok(true)
    }

    /// Quarantine (`Some(admin)`) or release (`None`) the record under
    /// `media_id`. Returns whether the record exists.
    ///
    /// A quarantined item stays in the store and keeps its bytes, as
    /// evidence, and is not served or sent to a peer. Releasing an item
    /// that [`Self::quarantine_remote`] wrote as a tombstone removes the
    /// tombstone, so the next request fetches it afresh.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the record cannot be read or written.
    pub fn set_quarantine(&self, media_id: &str, by: Option<&str>) -> Result<bool, MediaError> {
        let Some(mut record) = self.record(media_id)? else {
            return Ok(false);
        };
        if by.is_none() && record.hash.is_empty() {
            Store::delete(self.store.as_ref(), &keys::media(media_id))?;
            return Ok(true);
        }
        record.quarantined_by = by.map(str::to_owned);
        Store::put(
            self.store.as_ref(),
            &keys::media(media_id),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(true)
    }

    /// Quarantine a remote server's media, cached here or not.
    ///
    /// An uncached item gets a record with no bytes, so the cache's "do I
    /// hold it" check finds it and the item is never fetched: a ban that
    /// only covered what happened to be cached would be undone by the next
    /// client that asked.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the record cannot be read or written.
    pub fn quarantine_remote(
        &self,
        server_name: &str,
        media_id: &str,
        by: &str,
    ) -> Result<(), MediaError> {
        let id = Self::remote_id(server_name, media_id);
        if self.set_quarantine(&id, Some(by))? {
            return Ok(());
        }
        let tombstone = MediaRecord {
            hash: String::new(),
            content_type: "application/octet-stream".to_owned(),
            filename: None,
            size: 0,
            uploaded_by: format!("federation:{server_name}"),
            created_ts: Some(now_millis()),
            quarantined_by: Some(by.to_owned()),
        };
        Store::put(
            self.store.as_ref(),
            &keys::media(&id),
            &serde_json::to_vec(&tombstone)?,
        )?;
        Ok(())
    }

    /// Delete cached remote media last cached before `before_ts`
    /// (milliseconds), and return the IDs removed. This server's own
    /// uploads are never touched, and neither is a quarantined item:
    /// purging it would release what the operator meant to hold.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError`] if the store or the blob backend fails.
    pub async fn purge_remote(&self, before_ts: u64) -> Result<Vec<String>, MediaError> {
        let mut purged = Vec::new();
        for (media_id, record) in self.records()? {
            let old = record.created_ts.is_none_or(|ts| ts < before_ts);
            if media_id.contains('/') && record.quarantined_by.is_none() && old {
                self.delete(&media_id).await?;
                purged.push(media_id);
            }
        }
        Ok(purged)
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

/// Remove cached remote media older than `days`, every `interval`.
///
/// Holds the media store weakly, like the other delivery loops, so the
/// last owner of the store is never this task.
pub async fn retention_loop(media: std::sync::Weak<Media>, days: u32, interval: Duration) {
    let max_age = u64::from(days).saturating_mul(24 * 60 * 60 * 1000);
    loop {
        let Some(live) = media.upgrade() else {
            return;
        };
        match live
            .purge_remote(now_millis().saturating_sub(max_age))
            .await
        {
            Ok(purged) if !purged.is_empty() => {
                tracing::info!(removed = purged.len(), "purged old cached remote media");
            }
            Ok(_) => {}
            Err(error) => tracing::warn!("remote media retention failed: {error}"),
        }
        drop(live);
        tokio::time::sleep(interval).await;
    }
}

/// Snap requested dimensions to the ladder the spec suggests.
///
/// The smallest rung at least as large as the request wins, so a client never
/// gets less than it asked for unless it asked for more than the largest rung.
/// A fixed ladder bounds the cache at a handful of files per upload.
fn normalize_dimensions(width: u32, height: u32) -> (u32, u32) {
    for (rung_width, rung_height) in THUMBNAIL_LADDER {
        if width <= rung_width && height <= rung_height {
            return (rung_width, rung_height);
        }
    }
    (800, 600)
}

/// The thumbnail sizes this server makes; every cached thumbnail is one.
const THUMBNAIL_LADDER: [(u32, u32); 5] = [(32, 32), (96, 96), (320, 240), (640, 480), (800, 600)];

/// Pixels a source image may declare unless `[media] max_thumbnail_pixels`
/// says otherwise: about 6000x6000, above any photo a phone takes.
pub const DEFAULT_MAX_THUMBNAIL_PIXELS: u64 = 40_000_000;

/// Read the declared size first and refuse past `max_pixels`, then decode
/// under limits that cap the allocation too.
///
/// The header is read before anything else because a small, highly
/// compressible file can declare a huge canvas; decoding it first would
/// allocate the canvas before any error. The decoder limits back that up for
/// formats whose header can lie about the allocation it needs.
fn render_thumbnail(
    source: &[u8],
    width: u32,
    height: u32,
    crop: bool,
    max_pixels: u64,
    started: &AtomicU64,
) -> Result<Vec<u8>, DecodeFailure> {
    let unreadable = |error: &dyn std::fmt::Display| DecodeFailure::Unreadable(error.to_string());
    let reader = || {
        image::ImageReader::new(std::io::Cursor::new(source))
            .with_guessed_format()
            .map_err(|error| unreadable(&error))
    };
    let (declared_width, declared_height) = reader()?
        .into_dimensions()
        .map_err(|error| unreadable(&error))?;
    let pixels = u64::from(declared_width) * u64::from(declared_height);
    if pixels > max_pixels {
        return Err(DecodeFailure::TooManyPixels {
            pixels,
            limit: max_pixels,
        });
    }

    let mut limits = image::Limits::default();
    let side = u32::try_from(max_pixels).unwrap_or(u32::MAX);
    limits.max_image_width = Some(side);
    limits.max_image_height = Some(side);
    // Eight bytes a pixel covers the widest sample layout the decoders emit.
    limits.max_alloc = Some(max_pixels.saturating_mul(8));
    let mut reader = reader()?;
    reader.limits(limits);
    started.fetch_add(1, Ordering::Relaxed);
    let decoded = reader.decode().map_err(|error| unreadable(&error))?;
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
        .map_err(|error| unreadable(&error))?;
    Ok(bytes)
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
    /// Reserved by `POST /media/v1/create` and not filled yet.
    NotYetUploaded(String),
    /// A reserved ID that already has its bytes.
    AlreadyUploaded(String),
    /// A reserved ID someone else minted.
    NotReserver(String),
    /// The user holds too many live reservations.
    TooManyPending(usize),
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
    /// The upload would take its account past `[media] max_bytes_per_user`.
    QuotaExceeded {
        used: u64,
        size: u64,
        quota: u64,
    },
    /// A type this server does not thumbnail.
    Unsupported(String),
    /// Bytes that do not decode as the format they were declared to be.
    Unreadable(String),
    /// An image declaring more pixels than `[media] max_thumbnail_pixels`.
    ImageTooLarge {
        pixels: u64,
        limit: u64,
    },
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
            Self::NotYetUploaded(id) => write!(formatter, "{id} is reserved but not uploaded"),
            Self::AlreadyUploaded(id) => write!(formatter, "{id} already has its content"),
            Self::NotReserver(id) => write!(formatter, "{id} was reserved by someone else"),
            Self::TooManyPending(limit) => {
                write!(formatter, "at most {limit} uploads may be pending at once")
            }
            Self::Missing { media_id, hash } => write!(
                formatter,
                "{media_id} is recorded but its blob {hash} is not on disk"
            ),
            Self::TooLarge { size, limit } => {
                write!(formatter, "{size} bytes exceeds the {limit}-byte limit")
            }
            Self::QuotaExceeded { used, size, quota } => write!(
                formatter,
                "{size} more bytes would take this account past its {quota}-byte media \
                 quota; its uploads already hold {used}"
            ),
            Self::Unsupported(content_type) => {
                write!(formatter, "no thumbnails for {content_type}")
            }
            Self::Unreadable(message) => {
                write!(
                    formatter,
                    "the bytes do not decode as their declared type: {message}"
                )
            }
            Self::ImageTooLarge { pixels, limit } => write!(
                formatter,
                "the image declares {pixels} pixels, over the {limit}-pixel thumbnail limit"
            ),
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

    /// Declares 5000x5000 with junk where the pixels should be.
    fn oversize_png() -> Vec<u8> {
        fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
            let mut body = kind.to_vec();
            body.extend_from_slice(data);
            let mut crc = !0_u32;
            for byte in &body {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(&(!crc).to_be_bytes());
        }
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut header = Vec::new();
        header.extend_from_slice(&5000_u32.to_be_bytes());
        header.extend_from_slice(&5000_u32.to_be_bytes());
        header.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(&mut out, b"IHDR", &header);
        chunk(&mut out, b"IDAT", &[0x78, 0x9c, 0x01, 0x02, 0x03]);
        out
    }

    #[tokio::test]
    async fn an_over_budget_image_never_reaches_the_decoder_and_is_remembered() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let blobs = crate::blobs::Blobs::Local {
            root: dir.path().join("media"),
        };
        let media = Media::new(store, blobs, "example.org").with_max_thumbnail_pixels(1_000_000);
        let id = media
            .put(
                &oversize_png(),
                "image/png",
                None,
                "@a:example.org",
                Quota::Exempt,
            )
            .await
            .unwrap();

        for _ in 0..3 {
            let error = media.thumbnail(&id, 32, 32, false).await.unwrap_err();
            assert!(matches!(
                error,
                MediaError::ImageTooLarge {
                    pixels: 25_000_000,
                    ..
                }
            ));
        }
        assert_eq!(media.decodes_started(), 0, "no pixel data was decoded");
        assert_eq!(
            media.decode_failures.lock().unwrap().len(),
            1,
            "one hash remembered"
        );
    }

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
            created_ts: Some(now_millis()),
            quarantined_by: None,
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
                created_ts: Some(now_millis()),
                quarantined_by: None,
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
            created_ts: Some(now_millis()),
            quarantined_by: None,
        };
        assert!(record.inline_safe());
        assert_eq!(
            record.content_disposition(),
            r#"inline; filename="cat.png""#
        );
    }
}
