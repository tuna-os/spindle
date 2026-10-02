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
//!
//! A fourth shape matters only for a room whose history starts at a backfill
//! horizon -- one Synapse joined over federation, with nothing before the
//! join. The state at that root is a Synapse *state group*, and a state group
//! is usually not a state: it is a delta against a parent group, threaded
//! through `state_group_edges`. Reading only the root's own group gives the
//! slots that changed at the root and silently loses every other one. See
//! [`state_after`].

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension};

use super::{PlanError, SourceEvent, SourceRoom, StateMap, plan};

/// Why a room could not be read.
#[derive(Debug)]
pub enum ReadError {
    Sqlite(rusqlite::Error),
    /// The database has no such room.
    UnknownRoom(String),
    /// The room's history starts at a backfill horizon, and Synapse records no
    /// state group for the event it starts at.
    ///
    /// Refused loudly, because the alternative is an import that starts from
    /// empty state and calls a room with different contents a success.
    MissingStateGroup {
        room_id: String,
        root: String,
    },
    /// The `state_group_edges` chain returns to a group it already passed
    /// through, so it never reaches a full state.
    StateGroupCycle {
        room_id: String,
        state_group: i64,
    },
    /// A state group names more than one parent.
    ///
    /// Synapse writes one parent per group and reads back whichever row comes
    /// first. Two rows means the database is not in a shape this reader
    /// understands, and choosing one would be a guess about which state the
    /// room is in.
    AmbiguousStateGroup {
        room_id: String,
        state_group: i64,
        parents: Vec<i64>,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "reading Synapse: {error}"),
            Self::UnknownRoom(room) => write!(formatter, "no room {room} in this database"),
            Self::MissingStateGroup { room_id, root } => write!(
                formatter,
                "{room_id} has no m.room.create -- its history starts at {root}, and \
                 event_to_state_groups has no state group for {root}, so there is no \
                 state to start the import from"
            ),
            Self::StateGroupCycle {
                room_id,
                state_group,
            } => write!(
                formatter,
                "{room_id}: the state_group_edges chain returns to state group \
                 {state_group} instead of reaching a full state"
            ),
            Self::AmbiguousStateGroup {
                room_id,
                state_group,
                parents,
            } => write!(
                formatter,
                "{room_id}: state group {state_group} has {} parents in \
                 state_group_edges ({parents:?}); Synapse writes one",
                parents.len()
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
/// history starts at a backfill horizon whose state groups cannot be resolved.
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

    let mut room = SourceRoom {
        room_id: room_id.to_owned(),
        events,
        current_state,
        state_after_root: None,
    };

    // A horizon start needs the state at its root. `plan` is asked where the
    // root is rather than this reader guessing: it is the one that decides
    // which events are in the import, and so which event the log is seeded
    // with. Any other refusal is left for `plan` to report to the caller,
    // because supplying state would not fix it.
    if let Err(PlanError::NoRootState { root, .. }) = plan(&room) {
        room.state_after_root = Some(state_after(connection, room_id, &root)?);
    }

    Ok(room)
}

/// The room's state after `event_id`, from Synapse's state groups.
///
/// `event_to_state_groups` maps an event to the group holding the state after
/// it. That group is usually a delta: `state_groups_state` holds only the slots
/// that changed relative to the parent named in `state_group_edges`, and so on
/// back to a group with no parent, which holds a full state. The walk goes
/// newest to oldest, so the first value seen for a slot is the one that wins
/// and an older group fills only the slots no newer group mentions. That is
/// the order Synapse's own `SQLite` path walks the chain in.
///
/// # Errors
///
/// Returns [`ReadError`] when the event has no state group, the chain loops or
/// forks, or a query fails.
pub fn state_after(
    connection: &Connection,
    room_id: &str,
    event_id: &str,
) -> Result<StateMap, ReadError> {
    let Some(mut group) = connection
        .query_row(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = ?",
            [event_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    else {
        return Err(ReadError::MissingStateGroup {
            room_id: room_id.to_owned(),
            root: event_id.to_owned(),
        });
    };

    let mut slots = connection.prepare(
        "SELECT type, state_key, event_id FROM state_groups_state WHERE state_group = ?",
    )?;
    let mut parent = connection
        .prepare("SELECT prev_state_group FROM state_group_edges WHERE state_group = ?")?;
    let mut state = StateMap::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(group) {
            return Err(ReadError::StateGroupCycle {
                room_id: room_id.to_owned(),
                state_group: group,
            });
        }
        for row in slots.query_map([group], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (event_type, state_key, event_id) = row?;
            state.entry((event_type, state_key)).or_insert(event_id);
        }

        let parents = parent
            .query_map([group], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        match parents.as_slice() {
            [] => return Ok(state),
            [next] => group = *next,
            _ => {
                return Err(ReadError::AmbiguousStateGroup {
                    room_id: room_id.to_owned(),
                    state_group: group,
                    parents,
                });
            }
        }
    }
}
