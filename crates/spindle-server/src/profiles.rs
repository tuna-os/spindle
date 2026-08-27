//! Global user profiles: display name and avatar.
//!
//! A profile is **not** room state. The spec has each room's member event
//! *copy* the profile at the moment membership is set, so this row is the
//! source and the member events are the propagation — which is why setting
//! a display name touches every joined room, and why reading one back
//! never does.
//!
//! Federation asks for these over `query/profile`, which is how a server
//! renders the name of a user it has never shared a room with.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// One user's profile, both fields optional the way the spec has them:
/// absent means "never set", and clearing writes an absence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

/// The server's profile store.
pub struct Profiles {
    store: Arc<FjallStore>,
}

impl Profiles {
    #[must_use]
    pub fn new(store: Arc<FjallStore>) -> Self {
        Self { store }
    }

    /// The stored profile, empty rather than absent for a user who never
    /// set one — the spec's `GET /profile` answers `{}` for them.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store cannot be read.
    pub fn get(&self, user_id: &str) -> Result<Profile, StoreError> {
        Ok(ReadView::get(self.store.as_ref(), &keys::profile(user_id))?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default())
    }

    /// Set one field, keeping the other.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store refuses the write.
    pub fn set(
        &self,
        user_id: &str,
        displayname: Option<Option<String>>,
        avatar_url: Option<Option<String>>,
    ) -> Result<Profile, StoreError> {
        let mut profile = self.get(user_id)?;
        if let Some(displayname) = displayname {
            profile.displayname = displayname;
        }
        if let Some(avatar_url) = avatar_url {
            profile.avatar_url = avatar_url;
        }
        Store::put(
            self.store.as_ref(),
            &keys::profile(user_id),
            serde_json::to_vec(&profile)
                .map_err(|error| StoreError::Backend(error.to_string()))?
                .as_slice(),
        )?;
        Ok(profile)
    }
}
