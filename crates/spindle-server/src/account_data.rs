//! Per-user key-value data the server stores and never interprets.
//!
//! Account data is the one part of the client-server API where the server is
//! deliberately not a participant: `m.direct`, `m.push_rules`, a client's own
//! private settings — the server keeps the bytes, hands them back, and has no
//! opinion about what any of it means. So there is no validation here beyond
//! "it is JSON", and there deliberately never should be: a client inventing a
//! new `event_type` must work on a server that has never heard of it.
//!
//! Two kinds, global and per-room, in one keyspace. They differ only in
//! whether a room ID sits in the key, and `/sync` wants both.

use std::sync::Arc;

use serde_json::Value;
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// Reads and writes one user's account data.
pub struct AccountData {
    store: Arc<FjallStore>,
}

impl AccountData {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Store one entry, replacing whatever was there.
    ///
    /// Pass an empty `room_id` for the global kind.
    ///
    /// # Errors
    ///
    /// Returns [`AccountDataError`] if the write fails.
    pub fn put(
        &self,
        user_id: &str,
        room_id: &str,
        event_type: &str,
        content: &Value,
    ) -> Result<(), AccountDataError> {
        Store::put(
            self.store.as_ref(),
            &keys::account_data(user_id, room_id, event_type),
            content.to_string().as_bytes(),
        )?;
        Ok(())
    }

    /// How many entries `user_id` has, global and per-room together.
    ///
    /// A scan of the user's whole prefix, which is bounded by the cap the
    /// caller is about to enforce, so the cost is proportional to the limit
    /// and not to the server.
    ///
    /// # Errors
    ///
    /// Returns [`AccountDataError`] if the scan fails.
    pub fn count(&self, user_id: &str) -> Result<usize, AccountDataError> {
        Ok(ReadView::scan_prefix(
            self.store.as_ref(),
            &keys::user_prefix(keys::Keyspace::AccountData, user_id),
        )?
        .len())
    }

    /// One entry, or `None` if the user has never set it.
    ///
    /// # Errors
    ///
    /// Returns [`AccountDataError::Corrupt`] if the stored bytes are not
    /// JSON, which would mean the store itself is damaged: the only writer is
    /// [`Self::put`], and it writes what `serde_json` produced.
    pub fn get(
        &self,
        user_id: &str,
        room_id: &str,
        event_type: &str,
    ) -> Result<Option<Value>, AccountDataError> {
        let Some(bytes) = ReadView::get(
            self.store.as_ref(),
            &keys::account_data(user_id, room_id, event_type),
        )?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| AccountDataError::Corrupt(format!("{event_type}: {error}")))
    }

    /// Every entry of one kind, as `/sync` wants them: `{type, content}`.
    ///
    /// Pass an empty `room_id` for the global kind. Sorted by type, because a
    /// prefix scan is, and a stable order is worth having even where the spec
    /// does not require one.
    ///
    /// # Errors
    ///
    /// Returns [`AccountDataError`] if the scan fails or a stored value is
    /// not JSON.
    pub fn all(&self, user_id: &str, room_id: &str) -> Result<Vec<Value>, AccountDataError> {
        let prefix = keys::account_data_prefix(user_id, room_id);
        let mut out = Vec::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &prefix)? {
            let Some(event_type) = keys::account_data_type(user_id, room_id, &key) else {
                continue;
            };
            let content: Value = serde_json::from_slice(&bytes)
                .map_err(|error| AccountDataError::Corrupt(format!("{event_type}: {error}")))?;
            out.push(serde_json::json!({ "type": event_type, "content": content }));
        }
        Ok(out)
    }
}

/// What can go wrong reading or writing account data.
#[derive(Debug)]
pub enum AccountDataError {
    Storage(StoreError),
    /// Stored bytes that are not JSON.
    ///
    /// Its own variant rather than a `Backend` failure, because it is not one:
    /// the backend returned exactly what it was given, and what it was given
    /// is wrong. Reporting damaged data as a backend error would send whoever
    /// is debugging it to the storage engine, which is the one place the fault
    /// cannot be.
    Corrupt(String),
}

impl From<StoreError> for AccountDataError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for AccountDataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Corrupt(what) => write!(formatter, "stored account data is not JSON: {what}"),
        }
    }
}

impl std::error::Error for AccountDataError {}
