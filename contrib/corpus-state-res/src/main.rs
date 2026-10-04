//! Replay a Synapse database's contested forks through Spindle's live path.
//!
//! For #563's gate "State resolution matches peers on contested forks". For
//! every accepted event in a room whose `prev_events` carry different states
//! in Synapse -- every merge Spindle's resolver is now asked about -- this:
//!
//! 1. rebuilds each parent's state from Synapse's state groups (the state
//!    Synapse holds after that parent),
//! 2. seeds a Spindle room log with those parents at exactly those states,
//! 3. hands the merge event to `Rooms::receive_remote` -- the same ingest a
//!    federation transaction reaches: state resolution over the parents, the
//!    receipt checks, the append -- and
//! 4. compares the state Spindle resolved before the event
//!    (`Rooms::state_before_event`) with Synapse's state after it, excluding
//!    a state event's own slot: the database does not retain that slot before
//!    the overwrite. Compression ancestors are not semantic before-states.
//!
//! The database is opened read-only. Usage:
//!
//! ```text
//! DATABASE_URL=postgres://... corpus-state-res [room_id ...]
//! ```
//!
//! With no rooms named, every room with such a merge is replayed. One JSON
//! line per room on stdout, then a summary line.

mod oracle;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use postgres::fallible_iterator::FallibleIterator;
use postgres::{Client, NoTls};
use serde_json::{Value, json};
use spindle_core::{
    EventId, EventInput, RoomLog, Sideline, SidelinedEntry, StateKey, StateSnapshot,
};
use spindle_server::rooms::{RoomError, Rooms};

struct Merge {
    event_id: String,
    stream: i64,
    own_group: Option<i64>,
    prevs: Vec<String>,
    prev_groups: Vec<i64>,
}

#[derive(Default)]
struct Tally {
    merges: usize,
    skipped_outside_history: usize,
    compared: usize,
    masked_own_slot: usize,
    agree: usize,
    disagree: usize,
    conflicted: usize,
    conflicted_agree: usize,
    accepted: usize,
    soft_failed: usize,
    rejected: usize,
    errors: usize,
    durations: Vec<Duration>,
    examples: Vec<Value>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(filter) = std::env::var("RUST_LOG") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    let url = std::env::var("DATABASE_URL")?;
    let mut db = Client::connect(&url, NoTls)?;
    db.batch_execute("SET default_transaction_read_only = on")?;

    let named: Vec<String> = std::env::args().skip(1).collect();
    let rooms: Vec<(String, String)> = if named.is_empty() {
        db.query(
            "SELECT DISTINCT e.room_id, r.room_version
               FROM events e
               JOIN rooms r USING (room_id)
               JOIN event_edges ee ON ee.event_id = e.event_id
              WHERE NOT e.outlier
              GROUP BY e.room_id, r.room_version, e.event_id
             HAVING count(*) >= 2",
            &[],
        )?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
    } else {
        named
            .iter()
            .map(|room| {
                let version: String = db
                    .query_one("SELECT room_version FROM rooms WHERE room_id = $1", &[room])
                    .map(|row| row.get(0))
                    .unwrap_or_default();
                (room.clone(), version)
            })
            .collect()
    };

    drop(db);
    let mut total = Tally::default();
    for (room_id, version) in rooms {
        // A room's CPU replay can outlast an idle database connection. Start
        // a fresh read-only connection for each room rather than carrying it
        // across that work; include the room in any source-read error.
        let mut db = Client::connect(&url, NoTls)?;
        db.batch_execute("SET default_transaction_read_only = on")?;
        let started = Instant::now();
        let tally = replay_room(&mut db, &room_id)
            .map_err(|error| format!("replay room {room_id}: {error}"))?;
        let mut durations = tally.durations.clone();
        durations.sort();
        let quantile = |q: f64| {
            durations
                .get(((durations.len() as f64 - 1.0) * q).round() as usize)
                .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
        };
        println!(
            "{}",
            json!({
                "room_id": room_id,
                "room_version": version,
                "merges": tally.merges,
                "skipped_parent_outside_history": tally.skipped_outside_history,
                "compared": tally.compared,
                "masked_own_slot": tally.masked_own_slot,
                "preserve_historical_rejections": std::env::var_os("CORPUS_REEVALUATE_REJECTED").is_none(),
                "agree": tally.agree,
                "disagree": tally.disagree,
                "conflicted": tally.conflicted,
                "conflicted_agree": tally.conflicted_agree,
                "verdicts": {
                    "accepted": tally.accepted,
                    "soft_failed": tally.soft_failed,
                    "rejected": tally.rejected,
                    "error": tally.errors,
                },
                "ingest_ms": { "p50": quantile(0.5), "p99": quantile(0.99), "max": quantile(1.0) },
                "elapsed_s": started.elapsed().as_secs(),
                "examples": tally.examples,
            })
        );
        total.merges += tally.merges;
        total.skipped_outside_history += tally.skipped_outside_history;
        total.compared += tally.compared;
        total.masked_own_slot += tally.masked_own_slot;
        total.agree += tally.agree;
        total.disagree += tally.disagree;
        total.conflicted += tally.conflicted;
        total.conflicted_agree += tally.conflicted_agree;
        total.accepted += tally.accepted;
        total.soft_failed += tally.soft_failed;
        total.rejected += tally.rejected;
        total.errors += tally.errors;
    }
    println!(
        "{}",
        json!({
            "summary": true,
            "merges": total.merges,
            "skipped_parent_outside_history": total.skipped_outside_history,
            "compared": total.compared,
            "masked_own_slot": total.masked_own_slot,
            "agree": total.agree,
            "disagree": total.disagree,
            "conflicted": total.conflicted,
            "conflicted_agree": total.conflicted_agree,
            "verdicts": {
                "accepted": total.accepted,
                "soft_failed": total.soft_failed,
                "rejected": total.rejected,
                "error": total.errors,
            },
        })
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn replay_room(db: &mut Client, room_id: &str) -> Result<Tally, Box<dyn std::error::Error>> {
    let mut tally = Tally::default();
    let merges: Vec<Merge> = db
        .query(
            "SELECT e.event_id, e.stream_ordering, eg.state_group,
                    array_agg(ee.prev_event_id ORDER BY ee.prev_event_id),
                    array_agg(COALESCE(pg.state_group, -1) ORDER BY ee.prev_event_id)
               FROM events e
               JOIN event_edges ee ON ee.event_id = e.event_id
               LEFT JOIN event_to_state_groups pg ON pg.event_id = ee.prev_event_id
               LEFT JOIN event_to_state_groups eg ON eg.event_id = e.event_id
              WHERE e.room_id = $1 AND NOT e.outlier
                AND NOT EXISTS (SELECT 1 FROM rejections r WHERE r.event_id = e.event_id)
              GROUP BY e.event_id, e.stream_ordering, eg.state_group
             HAVING count(*) >= 2 AND count(DISTINCT pg.state_group) >= 2
              ORDER BY e.stream_ordering",
            &[&room_id],
        )?
        .iter()
        .map(|row| Merge {
            event_id: row.get(0),
            stream: row.get(1),
            own_group: row.get(2),
            prevs: row.get(3),
            prev_groups: row.get(4),
        })
        .collect();
    tally.merges = merges.len();
    if merges.is_empty() {
        return Ok(tally);
    }

    // Parent after-states and the merge after-state used for comparison.
    let mut needed: HashSet<i64> = HashSet::new();
    for merge in &merges {
        needed.extend(
            merge
                .prev_groups
                .iter()
                .copied()
                .filter(|group| *group >= 0),
        );
        needed.extend(merge.own_group);
    }
    // The delta closure: every ancestor group along state_group_edges.
    let needed_list: Vec<i64> = needed.iter().copied().collect();
    let closure: Vec<(i64, Option<i64>)> = db
        .query(
            "WITH RECURSIVE closure(state_group) AS (
                 SELECT unnest($1::bigint[])
                 UNION
                 SELECT e.prev_state_group FROM state_group_edges e
                   JOIN closure c ON e.state_group = c.state_group
             )
             SELECT c.state_group, e.prev_state_group
               FROM closure c LEFT JOIN state_group_edges e ON e.state_group = c.state_group
              ORDER BY c.state_group",
            &[&needed_list],
        )?
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let mut children: HashMap<i64, usize> = HashMap::new();
    for (_, prev) in &closure {
        if let Some(prev) = prev {
            *children.entry(*prev).or_default() += 1;
        }
    }
    let groups: Vec<i64> = closure.iter().map(|(group, _)| *group).collect();
    let prev_of: HashMap<i64, Option<i64>> = closure.iter().copied().collect();

    // Materialize the needed groups' states by walking deltas in group
    // order, sharing structure: a delta group is its parent plus its rows,
    // and a full snapshot is rebuilt against the last group built.
    let mut snaps: HashMap<i64, StateSnapshot> = HashMap::new();
    let mut last: StateSnapshot = StateSnapshot::new();
    {
        let mut rows = db.query_raw(
            "SELECT state_group, type, state_key, event_id FROM state_groups_state
              WHERE state_group = ANY($1) ORDER BY state_group",
            &[&groups],
        )?;
        let mut pending: Option<(i64, String, String, String)> = None;
        for group in &groups {
            let mut delta: Vec<(StateKey, String)> = Vec::new();
            loop {
                let row = match pending.take() {
                    Some(row) => row,
                    None => match rows.next()? {
                        Some(row) => (row.get(0), row.get(1), row.get(2), row.get(3)),
                        None => break,
                    },
                };
                if row.0 == *group {
                    delta.push((StateKey::new(row.1, row.2), row.3));
                } else {
                    pending = Some(row);
                    break;
                }
            }
            let snapshot = match prev_of.get(group).copied().flatten() {
                Some(prev) => {
                    let mut snapshot = snaps.get(&prev).cloned().unwrap_or_default();
                    for (key, id) in &delta {
                        if snapshot.get(key) != Some(id.as_str()) {
                            snapshot = snapshot.apply(key.clone(), id.as_str());
                        }
                    }
                    if let Some(left) = children.get_mut(&prev) {
                        *left -= 1;
                        if *left == 0 && !needed.contains(&prev) {
                            snaps.remove(&prev);
                        }
                    }
                    snapshot
                }
                None => {
                    let wanted: HashMap<&StateKey, &str> =
                        delta.iter().map(|(key, id)| (key, id.as_str())).collect();
                    let mut snapshot = last.clone();
                    let mut stale = Vec::new();
                    snapshot.for_each(|key, _| {
                        if !wanted.contains_key(key) {
                            stale.push(key.clone());
                        }
                    });
                    for key in stale {
                        snapshot = snapshot.remove(&key);
                    }
                    for (key, id) in &delta {
                        if snapshot.get(key) != Some(id.as_str()) {
                            snapshot = snapshot.apply(key.clone(), id.as_str());
                        }
                    }
                    snapshot
                }
            };
            last = snapshot.clone();
            if needed.contains(group) || children.get(group).is_some_and(|left| *left > 0) {
                snaps.insert(*group, snapshot);
            }
        }
    }

    // Bodies: every state event of the room (outliers included: auth chains
    // reach them), and the merges and their parents.
    let dir = tempfile::Builder::new()
        .prefix("corpus-state-res")
        .tempdir()?;
    let store = Arc::new(spindle_store::FjallStore::open(dir.path())?);
    let rooms = Rooms::new(Arc::clone(&store), "replay.invalid");
    let mut wanted_ids: Vec<String> = Vec::new();
    for merge in &merges {
        wanted_ids.push(merge.event_id.clone());
        wanted_ids.extend(merge.prevs.iter().cloned());
    }
    let mut bodies: HashMap<String, Value> = HashMap::new();
    for row in db.query(
        "SELECT e.event_id, j.json FROM events e JOIN event_json j USING (event_id)
          WHERE e.room_id = $1 AND (e.state_key IS NOT NULL OR e.event_id = ANY($2))",
        &[&room_id, &wanted_ids],
    )? {
        let id: String = row.get(0);
        let text: String = row.get(1);
        if let Ok(body) = serde_json::from_str::<Value>(&text) {
            bodies.insert(id, body);
        }
    }
    let batch: Vec<(String, Value)> = bodies
        .iter()
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    for chunk in batch.chunks(5_000) {
        rooms.store_replay_bodies(room_id, chunk)?;
    }
    let rejected: Vec<String> = db
        .query(
            "SELECT r.event_id FROM rejections r JOIN events e USING (event_id) WHERE e.room_id = $1",
            &[&room_id],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();

    for merge in &merges {
        if merge.prev_groups.iter().any(|group| *group < 0) {
            tally.skipped_outside_history += 1;
            continue;
        }
        let Some(body) = bodies.get(&merge.event_id) else {
            tally.errors += 1;
            continue;
        };
        let parents: Vec<&StateSnapshot> = merge
            .prev_groups
            .iter()
            .filter_map(|group| snaps.get(group))
            .collect();
        if parents.len() != merge.prev_groups.len() {
            tally.errors += 1;
            continue;
        }
        // #573's notion of a conflicted fork: two parents holding different
        // events under one key.
        let conflicted = parents.iter().enumerate().any(|(index, left)| {
            parents.iter().skip(index + 1).any(|right| {
                left.diff(right)
                    .iter()
                    .any(|(_, ours, theirs)| ours.is_some() && theirs.is_some())
            })
        });

        let mut log = RoomLog::new();
        for id in &rejected {
            if std::env::var_os("CORPUS_REEVALUATE_REJECTED").is_none() {
                log.preserve_historical_rejection(EventId::new(id.as_str()));
            }
            log.restore_sidelined(
                SidelinedEntry {
                    event_id: EventId::new(id.as_str()),
                    prev_events: Vec::new(),
                    depth: 0,
                    state_key: None,
                    kind: Sideline::Rejected,
                    state_root: StateSnapshot::new().root(),
                },
                StateSnapshot::new(),
            );
        }
        for (parent, snapshot) in merge.prevs.iter().zip(&parents) {
            let depth = bodies
                .get(parent)
                .and_then(|body| body["depth"].as_u64())
                .unwrap_or(0);
            log.append_seeded(
                EventInput::new(parent.as_str(), Vec::new()),
                (*snapshot).clone(),
                depth,
            )
            .map_err(|error| format!("{parent}: {error:?}"))?;
        }
        rooms.install_replay_log(room_id, log);

        let started = Instant::now();
        let verdict = rooms.receive_remote(room_id, &merge.event_id, body);
        tally.durations.push(started.elapsed());
        match &verdict {
            Ok(()) => tally.accepted += 1,
            Err(RoomError::Forbidden(why)) if why.starts_with("soft-failed") => {
                tally.soft_failed += 1
            }
            Err(RoomError::Forbidden(why)) if why.starts_with("rejected") => tally.rejected += 1,
            Err(_) => tally.errors += 1,
        }

        let ours = match rooms.state_before_event(room_id, &merge.event_id) {
            Ok(state) => state,
            Err(error) => {
                if tally.examples.len() < 20 {
                    tally.examples.push(json!({
                        "event_id": merge.event_id,
                        "error": error.to_string(),
                        "verdict": format!("{verdict:?}"),
                    }));
                }
                continue;
            }
        };

        // The group's compression ancestor is not necessarily the event's
        // before-state, even when its delta changes just the event's own slot.
        // Compare the after-state while masking that overwritten slot.
        let own_key: Option<StateKey> = body["state_key"]
            .as_str()
            .map(|state_key| StateKey::new(body["type"].as_str().unwrap_or_default(), state_key));
        let Some(own_group) = merge.own_group else {
            tally.errors += 1;
            continue;
        };
        let expected = snaps.get(&own_group);
        let ignore = own_key;
        let Some(expected) = expected else {
            tally.errors += 1;
            continue;
        };
        tally.compared += 1;
        tally.masked_own_slot += usize::from(ignore.is_some());
        let differences: Vec<_> = ours
            .diff(expected)
            .into_iter()
            .filter(|(key, _, _)| Some(*key) != ignore.as_ref())
            .collect();
        if conflicted {
            tally.conflicted += 1;
        }
        if differences.is_empty() {
            tally.agree += 1;
            if conflicted {
                tally.conflicted_agree += 1;
            }
        } else {
            tally.disagree += 1;
            if let Some(path) = std::env::var_os("CORPUS_SYNAPSE_FIXTURE") {
                let selected = std::env::var("CORPUS_SYNAPSE_FIXTURE_EVENT")
                    .map_or(true, |id| id == merge.event_id);
                if selected && !std::path::Path::new(&path).exists() {
                    let rows = |snapshot: &StateSnapshot| {
                        let mut rows = Vec::new();
                        snapshot.for_each(|key, id| {
                            rows.push(json!([key.event_type().as_str(), key.state_key(), id]))
                        });
                        rows
                    };
                    let fixture = json!({
                        "room_id": room_id, "event_id": merge.event_id,
                        "parents": parents.iter().map(|state| rows(state)).collect::<Vec<_>>(),
                        "expected": rows(expected), "live": rows(&ours),
                        "ignore": ignore.as_ref().map(|key| json!([
                            key.event_type().as_str(), key.state_key()
                        ])),
                        "bodies": bodies, "rejected": rejected,
                    });
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                    file.write_all(&serde_json::to_vec(&fixture)?)?;
                }
            }

            if tally.examples.len() < 20 {
                let shown: Vec<Value> = differences
                    .iter()
                    .take(10)
                    .map(|(key, ours, theirs)| {
                        json!({
                            "key": format!("{}|{}", key.event_type().as_str(), key.state_key()),
                            "spindle": ours,
                            "synapse": theirs,
                        })
                    })
                    .collect();
                tally.examples.push(json!({
                    "event_id": merge.event_id,
                    "stream": merge.stream,
                    "parents": merge.prevs,
                    "conflicted": conflicted,
                    "verdict": format!("{verdict:?}"),
                    "differences": differences.len(),
                    "first": shown,
                    "full_chain_oracle": if std::env::var_os("CORPUS_FULL_CHAIN_ORACLE").is_some() {
                        oracle::compare(room_id, &parents, &bodies, &rejected, expected, &ours, ignore.as_ref())
                    } else { Value::Null },
                }));
            }
        }
    }
    Ok(tally)
}
