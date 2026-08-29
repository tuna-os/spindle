//! Reading a room out of Synapse's own tables (#20).
//!
//! The half of the importer with no judgement about *ordering* in it, and all
//! the judgement about *where the data actually lives*. [`super`] decides what
//! order a room's events go into the log and whether the result is the same
//! room; this decides what the room even is, and it is where an importer
//! quietly reads the wrong thing.
//!
//! Three shapes here are not what a reasonable person would assume, and each
//! was confirmed against Synapse's schema and its own queries rather than
//! inferred:
//!
//! 1. **`events` has no `prev_events` column.** The DAG lives only in
//!    `event_edges`.
//! 2. **`event_edges` carries `is_state`.** It once held two sorts of edge --
//!    the event DAG, and a link to the previous state event -- and Synapse's
//!    own queries still say `AND edge.is_state is FALSE`, noting the removal
//!    "is in a background update, [so] it's not necessarily safe to assume
//!    that it will have been completed". Selecting every row invents a parent
//!    and builds a DAG that is not the room's.
//! 3. **`event_edges.room_id` is nullable.** It was added to a table that
//!    already had rows, so scoping a query with `WHERE event_edges.room_id = ?`
//!    silently drops every edge predating the backfill. Synapse joins to
//!    `events` and filters *that* `room_id`; so does this.
//!
//! Each of the three is a silent wrong answer rather than an error, which is
//! why `scripts/synapse-fixture.py --populate` deliberately writes a legacy
//! `is_state` edge: a reader that gets (2) wrong fails against the fixture
//! instead of against somebody's deployment.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension};

use super::{SourceEvent, SourceRoom, StateMap};

/// Why a room could not be read.
#[derive(Debug)]
pub enum ReadError {
    Sqlite(rusqlite::Error),
    /// The database has no such room.
    UnknownRoom(String),
    /// The room's history starts at a backfill horizon.
    ///
    /// Reconstructing the state there means resolving a Synapse *state group*,
    /// which is a delta against a parent group threaded through
    /// `state_group_edges` -- a walk this reader does not do yet. Refused
    /// loudly, because the alternative is an import that starts from empty
    /// state and calls a room with different contents a success.
    NeedsStateGroups {
        room_id: String,
        root: String,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "reading Synapse: {error}"),
            Self::UnknownRoom(room) => write!(formatter, "no room {room} in this database"),
            Self::NeedsStateGroups { room_id, root } => write!(
                formatter,
                "{room_id} has no m.room.create -- its history starts at {root}, so its \
                 state has to come from Synapse's state groups, which this reader does \
                 not resolve yet (they are deltas chained through state_group_edges)"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<rusqlite::Error> for ReadError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

/// Every room the database holds, in a stable order.
///
/// # Errors
///
/// Returns [`ReadError`] if the query fails.
pub fn rooms(connection: &Connection) -> Result<Vec<String>, ReadError> {
    let mut statement = connection.prepare("SELECT room_id FROM rooms ORDER BY room_id")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Read one room into the shape [`super::plan`] and [`super::replay`] consume.
///
/// # Errors
///
/// Returns [`ReadError`] when the room is absent, a query fails, or the room's
/// history begins somewhere that needs state groups to reconstruct.
pub fn read_room(connection: &Connection, room_id: &str) -> Result<SourceRoom, ReadError> {
    let known: Option<String> = connection
        .query_row(
            "SELECT room_id FROM rooms WHERE room_id = ?",
            [room_id],
            |row| row.get(0),
        )
        .optional()?;
    if known.is_none() {
        return Err(ReadError::UnknownRoom(room_id.to_owned()));
    }

    // `rejection_reason` rather than the older `rejections` table: modern
    // Synapse writes the column, and a reader consulting only the table would
    // import events the server refused.
    let mut statement = connection.prepare(
        "SELECT event_id, type, state_key, depth, stream_ordering, outlier, \
                rejection_reason IS NOT NULL \
         FROM events WHERE room_id = ? ORDER BY stream_ordering",
    )?;
    let mut events: Vec<SourceEvent> = statement
        .query_map([room_id], |row| {
            Ok(SourceEvent {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                state_key: row.get(2)?,
                prev_events: Vec::new(),
                depth: row.get::<_, i64>(3)?.try_into().unwrap_or(0),
                stream_ordering: row.get(4)?,
                outlier: row.get(5)?,
                rejected: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // The edge query, and the two traps it steps around. Joining `events`
    // rather than filtering `event_edges.room_id` is what Synapse does, and
    // is required because that column is nullable on rows old enough to
    // predate it.
    let mut statement = connection.prepare(
        "SELECT edge.event_id, edge.prev_event_id \
         FROM event_edges AS edge \
         INNER JOIN events ON events.event_id = edge.event_id \
         WHERE events.room_id = ? AND edge.is_state = 0",
    )?;
    let mut parents: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in statement.query_map([room_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (child, parent) = row?;
        parents.entry(child).or_default().push(parent);
    }
    for event in &mut events {
        if let Some(found) = parents.remove(&event.event_id) {
            event.prev_events = found;
        }
    }

    let mut statement = connection
        .prepare("SELECT type, state_key, event_id FROM current_state_events WHERE room_id = ?")?;
    let mut current_state = StateMap::new();
    for row in statement.query_map([room_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (event_type, state_key, event_id) = row?;
        current_state.insert((event_type, state_key), event_id);
    }

    let room = SourceRoom {
        room_id: room_id.to_owned(),
        events,
        current_state,
        state_after_root: None,
    };

    // Refuse a horizon start here rather than handing `plan` a room it will
    // refuse anyway: this reader knows *why* the state is missing, and can
    // name the tables that would supply it.
    if !room
        .events
        .iter()
        .any(|event| event.event_type == "m.room.create" && !event.outlier && !event.rejected)
    {
        let earliest = room
            .events
            .iter()
            .find(|event| !event.outlier && !event.rejected)
            .map_or_else(|| "nothing".to_owned(), |event| event.event_id.clone());
        return Err(ReadError::NeedsStateGroups {
            room_id: room_id.to_owned(),
            root: earliest,
        });
    }

    Ok(room)
}
