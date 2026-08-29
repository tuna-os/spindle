//! Human-readable names for rooms.
//!
//! An alias is `#name:server`, and it is **not** room state. The room's own
//! `m.room.canonical_alias` records which alias a room prefers to be called
//! by, but the mapping from alias to room lives here, in the server's
//! directory, because it has to be answerable by a server that is not in the
//! room and has no state to read.
//!
//! That split is the spec's, and it has a consequence worth stating: an alias
//! can point at a room whose `m.room.canonical_alias` names something else, or
//! nothing at all. The two are kept in step by clients, not by the server, and
//! a server that enforced agreement would be inventing a rule.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// What an alias points at, and who put it there.
///
/// The creator is recorded because deletion is theirs: the spec lets the user
/// who created an alias remove it, which is a question about the past that no
/// amount of current room state can answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasRecord {
    pub room_id: String,
    pub created_by: String,
}

/// The server's alias directory.
pub struct Directory {
    store: Arc<FjallStore>,
    server_name: String,
}

impl Directory {
    #[must_use]
    pub fn new(store: Arc<FjallStore>, server_name: impl Into<String>) -> Self {
        Self {
            store,
            server_name: server_name.into(),
        }
    }

    /// Claim `room_alias` for `room_id`.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::NotOurs`] for an alias on another server,
    /// [`DirectoryError::Malformed`] if it is not `#name:server`, or
    /// [`DirectoryError::Taken`] if it already points somewhere. Taken rather
    /// than overwritten: silently repointing someone else's alias is how a
    /// room hijacks another's name.
    pub fn create(
        &self,
        room_alias: &str,
        room_id: &str,
        created_by: &str,
    ) -> Result<(), DirectoryError> {
        self.check_ours(room_alias)?;
        if self.resolve(room_alias)?.is_some() {
            return Err(DirectoryError::Taken(room_alias.to_owned()));
        }
        let record = AliasRecord {
            room_id: room_id.to_owned(),
            created_by: created_by.to_owned(),
        };
        Store::put(
            self.store.as_ref(),
            &keys::alias(room_alias),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }

    /// What `room_alias` points at, or `None` if nothing does.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the record cannot be read or decoded.
    pub fn resolve(&self, room_alias: &str) -> Result<Option<AliasRecord>, DirectoryError> {
        let Some(bytes) = ReadView::get(self.store.as_ref(), &keys::alias(room_alias))? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    /// Remove an alias, if `remover` is allowed to.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError::Unknown`] if nothing claims the alias, or
    /// [`DirectoryError::Forbidden`] if someone else created it.
    pub fn delete(&self, room_alias: &str, remover: &str) -> Result<String, DirectoryError> {
        self.check_ours(room_alias)?;
        let record = self
            .resolve(room_alias)?
            .ok_or_else(|| DirectoryError::Unknown(room_alias.to_owned()))?;
        if record.created_by != remover {
            return Err(DirectoryError::Forbidden(format!(
                "{room_alias} was created by someone else"
            )));
        }
        Store::delete(self.store.as_ref(), &keys::alias(room_alias))?;
        Ok(record.room_id)
    }

    /// Every alias pointing at `room_id`, sorted.
    ///
    /// A full scan of the directory, and deliberately so: the index is keyed
    /// by alias because resolving one is the hot direction -- every join by
    /// name is a point lookup. Listing a room's aliases is rare enough to pay
    /// for the scan, and a second index would be a second thing to keep in
    /// step with the first.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the scan fails or a record is undecodable.
    pub fn for_room(&self, room_id: &str) -> Result<Vec<String>, DirectoryError> {
        let mut aliases = Vec::new();
        for (key, bytes) in ReadView::scan_prefix(self.store.as_ref(), &keys::alias_prefix())? {
            let record: AliasRecord = serde_json::from_slice(&bytes)?;
            if record.room_id != room_id {
                continue;
            }
            if let Some(alias) = keys::alias_from_key(&key) {
                aliases.push(alias);
            }
        }
        aliases.sort();
        Ok(aliases)
    }

    /// Reject an alias this server cannot speak for.
    ///
    /// A directory only ever holds its own server's aliases. Accepting
    /// `#name:elsewhere.org` would let this server answer for a name it has no
    /// authority over, and every peer resolving it would get a different room
    /// depending on who they asked.
    fn check_ours(&self, room_alias: &str) -> Result<(), DirectoryError> {
        let Some(rest) = room_alias.strip_prefix('#') else {
            return Err(DirectoryError::Malformed(room_alias.to_owned()));
        };
        let Some((localpart, server)) = rest.split_once(':') else {
            return Err(DirectoryError::Malformed(room_alias.to_owned()));
        };
        if localpart.is_empty() {
            return Err(DirectoryError::Malformed(room_alias.to_owned()));
        }
        if server != self.server_name {
            return Err(DirectoryError::NotOurs(room_alias.to_owned()));
        }
        Ok(())
    }
}

/// What can go wrong with an alias.
#[derive(Debug)]
pub enum DirectoryError {
    /// Not `#localpart:server`.
    Malformed(String),
    /// A well-formed alias belonging to another server.
    NotOurs(String),
    /// Already claimed.
    Taken(String),
    /// Nothing claims it.
    Unknown(String),
    Forbidden(String),
    Storage(StoreError),
    Codec(String),
}

impl From<StoreError> for DirectoryError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<serde_json::Error> for DirectoryError {
    fn from(error: serde_json::Error) -> Self {
        Self::Codec(error.to_string())
    }
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(alias) => write!(formatter, "{alias} is not #localpart:server"),
            Self::NotOurs(alias) => write!(formatter, "{alias} belongs to another server"),
            Self::Taken(alias) => write!(formatter, "{alias} is already in use"),
            Self::Unknown(alias) => write!(formatter, "no room is called {alias}"),
            Self::Forbidden(why) => write!(formatter, "{why}"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Codec(message) => write!(formatter, "unreadable: {message}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// Who published a room to this server's directory, and when.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishedRecord {
    pub published_by: String,
    pub published_at: u64,
}

impl Directory {
    /// Publish a room in this server's directory.
    ///
    /// Visibility is deliberately **not** room state. A published room is one
    /// server's decision about its own directory, not a fact about the room:
    /// two servers sharing a room are each entitled to a different answer, and
    /// writing it into the room would broadcast one server's editorial choice
    /// to every other. The spec agrees -- `m.room.join_rules` governs who may
    /// enter, and the directory is a separate list.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the row cannot be written.
    pub fn publish(&self, room_id: &str, published_by: &str) -> Result<(), DirectoryError> {
        let record = PublishedRecord {
            published_by: published_by.to_owned(),
            published_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_default(),
        };
        Store::put(
            self.store.as_ref(),
            &keys::published_room(room_id),
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }

    /// Remove a room from this server's directory. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the row cannot be removed.
    pub fn unpublish(&self, room_id: &str) -> Result<(), DirectoryError> {
        Store::delete(self.store.as_ref(), &keys::published_room(room_id))?;
        Ok(())
    }

    /// Whether the room is in this server's directory.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the row cannot be read.
    pub fn is_published(&self, room_id: &str) -> Result<bool, DirectoryError> {
        Ok(ReadView::get(self.store.as_ref(), &keys::published_room(room_id))?.is_some())
    }

    /// Every published room, in room-ID order.
    ///
    /// Paging needs a *stable total order*, and the store's prefix scan
    /// already supplies one -- so the explicit sort is not what makes paging
    /// correct today. What it buys is independence from the key layout:
    /// `room_prefix` puts a big-endian length ahead of the ID, so raw store
    /// order groups by ID length before content, and any future change to
    /// that layout would silently re-order the directory under clients
    /// half-way through walking it. Sorting here means the order is a
    /// property of this function rather than of how keys happen to be built.
    ///
    /// A directory that reordered itself between two pages would show some
    /// rooms twice and skip others, and the skip is the invisible half.
    ///
    /// # Errors
    ///
    /// Returns [`DirectoryError`] if the scan fails.
    pub fn published(&self) -> Result<Vec<String>, DirectoryError> {
        let prefix = keys::published_rooms_prefix();
        let mut rooms: Vec<String> = ReadView::scan_prefix(self.store.as_ref(), &prefix)?
            .into_iter()
            .filter_map(|(key, _)| keys::room_from_prefixed(&key).map(str::to_owned))
            .collect();
        rooms.sort();
        rooms.dedup();
        Ok(rooms)
    }
}
