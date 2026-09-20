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
    /// Every other field (spec v1.16, MSC4133): a client may put any JSON
    /// under any key on its own profile, and the whole profile is capped
    /// at [`MAX_PROFILE_BYTES`].
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The spec's cap on a profile's serialized size.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// The spec's cap on a profile field's key.
pub const MAX_KEY_BYTES: usize = 255;

/// Why a profile field was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRefusal {
    KeyTooLarge,
    ProfileTooLarge,
    /// `displayname` and `avatar_url` are strings, or absent.
    NotAString,
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

    /// Set or clear one field by key (spec v1.16): `displayname` and
    /// `avatar_url` are the two the rest of the server reads, anything
    /// else is kept as given. `None` clears.
    ///
    /// # Errors
    ///
    /// Returns the [`FieldRefusal`] in the outer `Ok` when the key or the
    /// resulting profile is over the cap, and [`StoreError`] if the store
    /// cannot be read or written.
    pub fn set_field(
        &self,
        user_id: &str,
        key: &str,
        value: Option<serde_json::Value>,
    ) -> Result<Result<Profile, FieldRefusal>, StoreError> {
        if key.len() > MAX_KEY_BYTES {
            return Ok(Err(FieldRefusal::KeyTooLarge));
        }
        let mut profile = self.get(user_id)?;
        match key {
            "displayname" | "avatar_url" => {
                let text = match value {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(text)) => Some(text),
                    Some(_) => return Ok(Err(FieldRefusal::NotAString)),
                };
                if key == "displayname" {
                    profile.displayname = text;
                } else {
                    profile.avatar_url = text;
                }
            }
            _ => match value {
                Some(value) => {
                    profile.extra.insert(key.to_owned(), value);
                }
                None => {
                    profile.extra.remove(key);
                }
            },
        }
        let encoded =
            serde_json::to_vec(&profile).map_err(|error| StoreError::Backend(error.to_string()))?;
        if encoded.len() > MAX_PROFILE_BYTES {
            return Ok(Err(FieldRefusal::ProfileTooLarge));
        }
        Store::put(self.store.as_ref(), &keys::profile(user_id), &encoded)?;
        Ok(Ok(profile))
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
