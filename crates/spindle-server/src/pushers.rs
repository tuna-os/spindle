//! Pushers: where a user's devices asked to be told about events.
//!
//! Stored and served here; driven by `push::deliver_loop`, which reads the
//! registrations back for every event a user's rules say to notify about.
//! What a client registers is kept faithfully, per user and per
//! `(app_id, pushkey)`; the one thing that removes a registration behind
//! the client's back is its gateway reporting the pushkey `rejected`.

use std::sync::Arc;

use serde_json::Value;
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

pub struct Pushers {
    store: Arc<FjallStore>,
}

impl Pushers {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// Every pusher `user_id` has registered, as the objects `/pushers`
    /// returns.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn list(&self, user_id: &str) -> Result<Vec<Value>, StoreError> {
        Ok(
            ReadView::scan_prefix(self.store.as_ref(), &keys::pusher_prefix(user_id))?
                .into_iter()
                .filter_map(|(_, bytes)| serde_json::from_slice(&bytes).ok())
                .collect(),
        )
    }

    /// How many pushers `user_id` holds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the scan fails.
    pub fn count(&self, user_id: &str) -> Result<usize, StoreError> {
        Ok(ReadView::scan_prefix(self.store.as_ref(), &keys::pusher_prefix(user_id))?.len())
    }

    /// Whether `user_id` already holds a pusher under `(app_id, pushkey)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the read fails.
    pub fn holds(&self, user_id: &str, app_id: &str, pushkey: &str) -> Result<bool, StoreError> {
        Ok(ReadView::get(self.store.as_ref(), &keys::pusher(user_id, app_id, pushkey))?.is_some())
    }

    /// Register or replace the pusher under `(app_id, pushkey)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the write fails.
    pub fn set(
        &self,
        user_id: &str,
        app_id: &str,
        pushkey: &str,
        pusher: &Value,
    ) -> Result<(), StoreError> {
        Store::put(
            self.store.as_ref(),
            &keys::pusher(user_id, app_id, pushkey),
            pusher.to_string().as_bytes(),
        )
    }

    /// Remove the pusher under `(app_id, pushkey)`, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the delete fails.
    pub fn remove(&self, user_id: &str, app_id: &str, pushkey: &str) -> Result<(), StoreError> {
        Store::delete(self.store.as_ref(), &keys::pusher(user_id, app_id, pushkey))
    }
}
