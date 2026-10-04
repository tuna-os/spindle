//! The full Synapse import (#240, #563): every retained room, every local
//! user, and the per-user data a client expects to find after a cutover.
//!
//! [`super::postgres`] reads one room and one user's recovery material; this
//! module walks the whole server. It runs in phases, in an order chosen so
//! that each phase finds what it depends on already written:
//!
//! | Phase | Writes |
//! |---|---|
//! | `signing_key` | the Synapse signing key, under its own key ID |
//! | `users` | accounts and their flags, profiles |
//! | `devices` | devices, device keys, one-time and fallback keys, pending to-device messages |
//! | `cross_signing` | every key first, then every signature, so a signature never waits for a key a later user brings |
//! | `backups` | server-side key backup versions and sessions |
//! | `account_data` | global and room account data, room tags, push rules |
//! | `pushers` | pushers |
//! | rooms | every retained room, one checkpoint per room |
//! | `receipts` | read receipts, after the events they point at |
//! | `directory` | aliases, the published-room list, blocked rooms |
//! | `media` | the local media store, with Synapse's media IDs |
//!
//! **Restart-safe.** A JSON checkpoint beside the store records each finished
//! phase and room, and it is written only after the store has been synced,
//! so it never claims more than the store holds. Every phase can also be
//! repeated: rows are put rather than added, a room resumes at the first
//! event its log does not hold, and pending to-device messages are cleared
//! before they are queued again. A run that stops anywhere can be started
//! again with the same command.
//!
//! **Nothing is dropped silently.** A room that cannot be imported, because
//! of its room version, its shape, or a state divergence, is listed in the
//! report under `excluded_rooms` with the reason. So is every row a domain
//! skipped, counted by reason, and every Synapse table the import does not
//! carry, under `not_migrated`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use spindle_store::{FjallStore, ReadView, Store};

use super::ReadError;
use super::postgres::Snapshot;
use super::resolve::RoomResolver;
use super::signatures::{KeyRing, Verdict};
use crate::import::{
    Continuity, DISAGREED_REASON, ELSEWHERE_REASON, Excluded, GAP_REASON, HEAD_REASON,
    HEAD_RESOLVED_REASON, RESOLVED_REASON, Resolution, Settled, SourceRoom, SourceState, StateMap,
    SynapseSource, check_body, plan_resolving, redaction_target, replay_resolving,
};

/// How many planned events are read and written together.
const CHUNK: usize = 2_000;

/// Checkpoints before these rejection and continuity rules must replay again.
const REJECTION_POLICY_VERSION: u32 = 3;

/// How many events a room report samples for the body comparison.
const SAMPLES_PER_ROOM: usize = 5;

/// What to import and where.
pub struct Options {
    pub server_name: String,
    /// The JSON checkpoint that makes a run restartable.
    pub checkpoint: PathBuf,
    /// Synapse's `media_store_path`, read-only. `None` skips media and says so.
    pub media_root: Option<PathBuf>,
    /// Import only these rooms. `None` means every retained room.
    pub only_rooms: Option<BTreeSet<String>>,
    /// Import only these users. `None` means every local user.
    pub only_users: Option<BTreeSet<String>>,
    /// Rooms the operator excludes, with the reason to report.
    pub exclude_rooms: BTreeMap<String, String>,
    /// Read, plan and compare everything, and write nothing.
    pub dry_run: bool,
    /// Synapse's signing key file contents, `ed25519 <version> <seed>`.
    pub signing_key: Option<String>,
    /// A known login password for a localpart (the E2EE rig's users).
    /// Every other account gets an unguessable one: production logins go
    /// through the delegated identity provider.
    pub password_for: PasswordFor,
}

/// A known login password for a localpart, if there is one.
pub type PasswordFor = Box<dyn Fn(&str) -> Option<String>>;

/// One receipt row: type, user, event, thread.
type ReceiptRow = (String, String, String, Option<String>);

/// One data domain's counts.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Domain {
    /// Rows Synapse holds for this domain, within the import's scope.
    pub source: u64,
    /// Rows written to Spindle.
    pub imported: u64,
    /// Rows not written, counted by reason.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skipped: BTreeMap<String, u64>,
}

impl Domain {
    fn skip(&mut self, reason: &str) {
        *self.skipped.entry(reason.to_owned()).or_default() += 1;
    }
}

/// One state slot the two servers disagree on.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlotDivergence {
    pub event_type: String,
    pub state_key: String,
    pub spindle: Option<String>,
    pub synapse: Option<String>,
}

/// What happened to one imported room.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RoomReport {
    /// Historical rejection policy used for this replay and persisted store.
    #[serde(default)]
    pub rejection_policy_version: u32,
    /// Rejected PDUs retained for auth, outside the accepted timeline.
    #[serde(default)]
    pub preserved_rejections: u64,
    /// State PDUs outside the accepted timeline retained for auth context.
    #[serde(default)]
    pub retained_auth_pdus: u64,
    pub version: String,
    /// Rows in Synapse's `events` table for the room.
    pub source_events: u64,
    /// Events in the planned (and, unless a dry run, written) log.
    pub imported_events: u64,
    /// Imported events indexed for cached Synapse pagination tokens.
    #[serde(default)]
    pub pagination_positions: u64,
    pub outliers: u64,
    pub rejected: u64,
    pub frayed: u64,
    pub orphaned: u64,
    pub redactions_applied: u64,
    /// State at the start of retained history came from Synapse's state
    /// groups rather than from folding forward from `m.room.create`.
    pub seeded_from_source: bool,
    /// Events appended with the state Synapse resolved for them, because
    /// a parent was outside the retained history or the fork needed the
    /// Matrix state resolver. By reason, with a few examples.
    pub from_source: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub from_source_reasons: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_source_examples: Vec<String>,
    /// Forks (events whose parents' states differ, and the head over
    /// several forward extremities) the room version's resolver settled.
    #[serde(default)]
    pub resolved_forks: u64,
    /// Of those, the forks where the resolver gave Synapse's answer on
    /// every contested slot.
    #[serde(default)]
    pub resolver_agreed: u64,
    /// Forks where it did not, with the slots; Synapse's value was taken.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolver_disagreed: Vec<String>,
    /// Replay passes until the log's fold agreed with the derived state.
    #[serde(default)]
    pub replay_passes: u64,
    /// Every event's signatures, checked with the key valid when it was
    /// signed: counts by outcome.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub signatures: BTreeMap<String, u64>,
    /// A few events that verified only with an older key, or not at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_examples: Vec<String>,
    /// Events compared in full with Synapse's state, because Synapse's
    /// state groups do not show the state derived from the parents.
    #[serde(default)]
    pub full_checks: u64,
    /// User IDs ruma rejects that the resolver read through a stand-in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compat_user_ids: Vec<String>,
    pub state_slots: u64,
    /// Planned replay state against `current_state_events`. Empty to import.
    pub divergence: Vec<SlotDivergence>,
    pub body_bytes: u64,
    pub seconds: f64,
}

/// A room that was not imported, and why.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExcludedRoom {
    pub version: String,
    pub source_events: u64,
    pub local_joined: u64,
    pub reason: String,
}

/// The import's own account of what it did. Also the checkpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Report {
    pub server_name: String,
    pub dry_run: bool,
    pub runs: u32,
    pub seconds: f64,
    pub phases_done: BTreeSet<String>,
    pub domains: BTreeMap<String, Domain>,
    pub rooms: BTreeMap<String, RoomReport>,
    pub excluded_rooms: BTreeMap<String, ExcludedRoom>,
    /// Rooms with no local joined member: not retained by design.
    pub rooms_without_local_members: u64,
    /// Synapse data the import does not carry, by table, with the reason.
    pub not_migrated: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
}

impl Report {
    fn prepare_mode(&mut self, dry_run: bool) {
        if self.dry_run != dry_run {
            // A dry run wrote nothing. Its completed phases and room plans
            // must not suppress real writes; a new dry run checks again too.
            self.phases_done.clear();
            self.domains.clear();
            self.rooms.clear();
            self.excluded_rooms.clear();
            self.validation = None;
        }
        self.dry_run = dry_run;
    }
}

/// The check of the written store against Synapse.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Validation {
    pub rooms_checked: u64,
    /// Rooms whose persisted state does not match `current_state_events`.
    pub rooms_divergent: BTreeMap<String, Vec<SlotDivergence>>,
    /// Rooms whose persisted log does not hold the planned event count.
    pub rooms_short: BTreeMap<String, String>,
    pub events_sampled: u64,
    pub sample_mismatches: Vec<String>,
    /// A few of the sampled event IDs, for a reader to look up by hand.
    pub sample_event_ids: Vec<String>,
    /// Per domain: rows checked, and mismatches found.
    pub domains: BTreeMap<String, (u64, Vec<String>)>,
}

/// Why the import stopped.
#[derive(Debug)]
pub enum Error {
    Read(ReadError),
    Write(String),
    Checkpoint(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "{error}"),
            Self::Write(error) => write!(formatter, "writing Spindle: {error}"),
            Self::Checkpoint(error) => write!(formatter, "checkpoint: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ReadError> for Error {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

impl From<::postgres::Error> for Error {
    fn from(error: ::postgres::Error) -> Self {
        Self::Read(ReadError::Postgres(error))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Read(ReadError::Json(error))
    }
}

fn write_error(error: impl std::fmt::Display) -> Error {
    Error::Write(error.to_string())
}

/// Load the checkpoint, or start a fresh report.
///
/// # Errors
///
/// Returns [`Error::Checkpoint`] if the file exists but cannot be read.
pub fn load_checkpoint(path: &Path) -> Result<Option<Report>, Error> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| Error::Checkpoint(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Checkpoint(format!("{}: {error}", path.display()))),
    }
}

/// Write the checkpoint atomically: a temporary file, synced, then renamed.
///
/// # Errors
///
/// Returns [`Error::Checkpoint`] if the file cannot be written.
pub fn save_checkpoint(path: &Path, report: &Report) -> Result<(), Error> {
    let fail = |error: std::io::Error| Error::Checkpoint(format!("{}: {error}", path.display()));
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(report)?;
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&temporary).map_err(fail)?;
        file.write_all(&bytes).map_err(fail)?;
        file.sync_all().map_err(fail)?;
    }
    std::fs::rename(&temporary, path).map_err(fail)?;
    if let Some(parent) = path.parent()
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// The handles one run writes through.
struct Target {
    store: Arc<FjallStore>,
    rooms: crate::rooms::Rooms,
    account_data: crate::account_data::AccountData,
    devices: crate::devices::Devices,
    backups: crate::backups::Backups,
    profiles: crate::profiles::Profiles,
    pushers: crate::pushers::Pushers,
    directory: crate::directory::Directory,
    media: crate::media::Media,
}

/// Everything one run shares.
struct Run<'a, 'snapshot> {
    options: &'a Options,
    snapshot: &'a mut Snapshot<'snapshot>,
    target: &'a Target,
    report: Report,
    started: Instant,
    /// Local users in scope, by user ID.
    users: BTreeSet<String>,
    /// Rooms imported in this or an earlier run.
    imported_rooms: BTreeSet<String>,
    /// Every server key Synapse holds, for the signature check.
    keys: Option<KeyRing>,
}

/// Bodies and resolved state for one room, read from the Synapse snapshot.
///
/// Bodies come from the chunk already read, and any other body (an outlier
/// a seeded state names) is read on demand. Resolved states are cached for
/// the room, so the write reuses what the replay read.
struct SnapshotSource<'a, 'snapshot> {
    snapshot: &'a mut Snapshot<'snapshot>,
    room_id: &'a str,
    bodies: HashMap<String, Value>,
    states: &'a mut HashMap<String, StateMap>,
    /// The room version's resolver, for the replay.
    resolver: Option<&'a mut RoomResolver>,
    /// The states the replay settled, for the write.
    settled: Option<&'a HashMap<String, Settled>>,
    /// Each event's state group, and each group's `prev_state_group`.
    groups: Option<&'a super::postgres::StateGroupGraph>,
}

impl SourceState for SnapshotSource<'_, '_> {
    fn state_after(&mut self, event_id: &str) -> Result<StateMap, String> {
        if let Some(state) = self.states.get(event_id) {
            return Ok(state.clone());
        }
        let state = self
            .snapshot
            .state_after_event(self.room_id, event_id)
            .map_err(|error| error.to_string())?;
        // Not cached: a room with tens of thousands of members would hold
        // one full map per gap. The replay keeps what the write needs.
        Ok(state)
    }

    fn state_after_keys(
        &mut self,
        event_id: &str,
        keys: &[(String, String)],
    ) -> Result<StateMap, String> {
        if let Some(state) = self.states.get(event_id) {
            let mut state = state.clone();
            state.retain(|key, _| keys.contains(key));
            return Ok(state);
        }
        self.snapshot
            .state_after_event_keys(self.room_id, event_id, keys)
            .map_err(|error| error.to_string())
    }

    fn resolve(
        &mut self,
        sets: &[&spindle_core::StateSnapshot],
    ) -> Option<Result<Resolution, String>> {
        let resolver = self.resolver.as_deref_mut()?;
        Some(resolver.resolve(self.snapshot, sets))
    }

    fn replay_progress(&mut self, position: usize, total: usize) {
        if total > 10_000 {
            eprintln!("replay room={} events={position}/{total}", self.room_id);
        }
    }

    fn continuity(
        &mut self,
        event_id: &str,
        parents: &[spindle_core::EventId],
        is_state: bool,
    ) -> Continuity {
        let Some(graph) = self.groups else {
            return Continuity::Derived;
        };
        if graph.proves_derived(event_id, parents, is_state) {
            Continuity::Derived
        } else {
            // The database stores compression provenance, not semantic
            // before-state. Without a proof, compare the source state in full.
            Continuity::Unknown
        }
    }
}

impl SynapseSource for SnapshotSource<'_, '_> {
    fn body(&mut self, event_id: &str) -> Option<Value> {
        if let Some(body) = self.bodies.get(event_id) {
            return Some(body.clone());
        }
        self.snapshot
            .event_bodies_for(&[event_id.to_owned()])
            .ok()?
            .remove(event_id)
    }

    fn settled(&mut self, event_id: &str) -> Option<Settled> {
        self.settled?.get(event_id).cloned()
    }
}

fn is_local(user_id: &str, server_name: &str) -> bool {
    user_id
        .strip_suffix(server_name)
        .is_some_and(|rest| rest.ends_with(':'))
}

fn localpart(user_id: &str) -> &str {
    user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(':'))
        .map_or(user_id, |(localpart, _)| localpart)
}

/// Run the import against an opened store.
///
/// # Errors
///
/// Returns [`Error`] when a read fails, a write fails, or the checkpoint
/// cannot be written. Rows that are only skipped are reported, not errors.
#[allow(clippy::too_many_lines)]
pub fn run(
    options: &Options,
    snapshot: &mut Snapshot<'_>,
    store: &Arc<FjallStore>,
    blobs: crate::blobs::Blobs,
    previous: Option<Report>,
) -> Result<Report, Error> {
    let target = Target {
        store: Arc::clone(store),
        rooms: crate::rooms::Rooms::new(Arc::clone(store), &options.server_name),
        account_data: crate::account_data::AccountData::new(Arc::clone(store)),
        devices: crate::devices::Devices::new(Arc::clone(store)),
        backups: crate::backups::Backups::new(Arc::clone(store)),
        profiles: crate::profiles::Profiles::new(Arc::clone(store)),
        pushers: crate::pushers::Pushers::new(Arc::clone(store)),
        directory: crate::directory::Directory::new(Arc::clone(store), &options.server_name),
        media: crate::media::Media::new(Arc::clone(store), blobs, &options.server_name),
    };
    let mut report = previous.unwrap_or_default();
    if !report.server_name.is_empty() && report.server_name != options.server_name {
        return Err(Error::Checkpoint(
            "checkpoint belongs to another server name".to_owned(),
        ));
    }
    report.server_name.clone_from(&options.server_name);
    report.prepare_mode(options.dry_run);
    report.runs += 1;
    report
        .rooms
        .retain(|_, room| room.rejection_policy_version == REJECTION_POLICY_VERSION);
    let earlier_seconds = report.seconds;
    let mut run = Run {
        options,
        snapshot,
        target: &target,
        imported_rooms: report.rooms.keys().cloned().collect(),
        report,
        started: Instant::now(),
        users: BTreeSet::new(),
        keys: None,
    };

    run.discover_users()?;
    let rooms = run.discover_rooms()?;
    run.record_not_migrated();

    run.phase("signing_key", Run::signing_key)?;
    run.phase("users", Run::import_users)?;
    run.phase("devices", Run::import_devices)?;
    run.phase("cross_signing", Run::import_cross_signing)?;
    run.phase("backups", Run::import_backups)?;
    run.phase("account_data", Run::import_account_data)?;
    run.phase("pushers", Run::import_pushers)?;

    let own = options
        .signing_key
        .as_deref()
        .and_then(|source| crate::signing::ServerKey::parse_synapse(source).ok())
        .map(|key| (key.key_id(), key.public_key_base64()));
    run.keys = Some(KeyRing::load(
        run.snapshot,
        own.as_ref()
            .map(|(id, key)| (options.server_name.as_str(), id.as_str(), key.as_str())),
    )?);

    let total = rooms.len();
    for (index, room_id) in rooms.iter().enumerate() {
        if run.report.rooms.contains_key(room_id) {
            if !run.options.dry_run && run.report.rooms[room_id].imported_events > 0 {
                let count =
                    run.index_positions(room_id, run.report.rooms[room_id].imported_events)?;
                if let Some(room) = run.report.rooms.get_mut(room_id) {
                    room.pagination_positions = count as u64;
                }
                run.target.rooms.release_imported_room(room_id);
                run.sync()?;
                save_checkpoint(&run.options.checkpoint, &run.report)?;
            }
            continue;
        }
        run.import_room(room_id, index + 1, total)?;
    }

    run.phase("receipts", Run::import_receipts)?;
    run.phase("directory", Run::import_directory)?;
    run.phase("media", Run::import_media)?;

    run.report.seconds = earlier_seconds + run.started.elapsed().as_secs_f64();
    if !options.dry_run {
        run.sync()?;
    }
    save_checkpoint(&options.checkpoint, &run.report)?;
    Ok(run.report)
}

impl Run<'_, '_> {
    fn domain(&mut self, name: &str) -> &mut Domain {
        self.report.domains.entry(name.to_owned()).or_default()
    }

    fn reset(&mut self, names: &[&str]) {
        for name in names {
            self.report.domains.remove(*name);
        }
    }

    fn progress(&self, what: &str) {
        // Resident memory, so an operator watching a large import can see
        // it approach the container's limit before the kernel does.
        let rss = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .map(|line| line.trim_start_matches("VmRSS:").trim().to_owned())
            })
            .unwrap_or_default();
        eprintln!(
            "progress: {what} elapsed={:.0}s rss={rss}",
            self.started.elapsed().as_secs_f64()
        );
    }

    fn sync(&self) -> Result<(), Error> {
        Store::sync(
            self.target.store.as_ref(),
            spindle_store::Durability::Strict,
        )
        .map_err(write_error)
    }

    /// Run one phase unless an earlier run finished it, then checkpoint.
    fn phase(&mut self, name: &str, work: fn(&mut Self) -> Result<(), Error>) -> Result<(), Error> {
        if self.report.phases_done.contains(name) {
            eprintln!("phase {name}: done in an earlier run");
            return Ok(());
        }
        let started = Instant::now();
        work(self)?;
        if !self.options.dry_run {
            self.sync()?;
        }
        self.report.phases_done.insert(name.to_owned());
        save_checkpoint(&self.options.checkpoint, &self.report)?;
        eprintln!("phase {name}: {:.1}s", started.elapsed().as_secs_f64());
        Ok(())
    }

    fn user_in_scope(&self, user_id: &str) -> bool {
        self.users.contains(user_id)
    }

    fn room_in_target(&self, room_id: &str) -> bool {
        self.imported_rooms.contains(room_id)
    }

    // ----- discovery -------------------------------------------------------

    fn discover_users(&mut self) -> Result<(), Error> {
        let rows = self
            .snapshot
            .query("SELECT name FROM users ORDER BY name", &[])?;
        for row in rows {
            let user_id: String = row.get(0);
            if !is_local(&user_id, &self.options.server_name) {
                continue;
            }
            if let Some(only) = &self.options.only_users
                && !only.contains(&user_id)
            {
                continue;
            }
            self.users.insert(user_id);
        }
        Ok(())
    }

    /// The rooms to import, in order. Records every exclusion with its reason.
    fn discover_rooms(&mut self) -> Result<Vec<String>, Error> {
        let server_name = self.options.server_name.clone();
        let rows = self.snapshot.query(
            "SELECT room.room_id, COALESCE(room.room_version, '1'), \
                    (SELECT count(*) FROM events WHERE events.room_id = room.room_id), \
                    (SELECT count(*) FROM current_state_events AS state \
                       INNER JOIN room_memberships AS member ON member.event_id = state.event_id \
                      WHERE state.room_id = room.room_id AND state.type = 'm.room.member' \
                        AND right(state.state_key, length($1) + 1) = ':' || $1 \
                        AND member.membership = 'join') \
             FROM rooms AS room ORDER BY room.room_id",
            &[&server_name],
        )?;
        let mut rooms = Vec::new();
        let mut without_local = 0;
        for row in rows {
            let room_id: String = row.get(0);
            let version: String = row.get(1);
            let source_events = u64::try_from(row.get::<_, i64>(2)).unwrap_or(0);
            let local_joined = u64::try_from(row.get::<_, i64>(3)).unwrap_or(0);
            if local_joined == 0 {
                without_local += 1;
                continue;
            }
            if let Some(only) = &self.options.only_rooms
                && !only.contains(&room_id)
            {
                continue;
            }
            let reason = if let Some(reason) = self.options.exclude_rooms.get(&room_id) {
                Some(format!("excluded by the operator: {reason}"))
            } else if crate::surface::supports_room_version(&version) {
                None
            } else {
                Some(format!(
                    "room version {version} is not supported by this build (supported: {}); \
                     v1 is #456, v6 to v9 are #562",
                    crate::surface::ROOM_VERSIONS.join(", ")
                ))
            };
            if let Some(reason) = reason {
                self.report.excluded_rooms.insert(
                    room_id,
                    ExcludedRoom {
                        version,
                        source_events,
                        local_joined,
                        reason,
                    },
                );
                continue;
            }
            // A room excluded by an earlier run's plan or divergence check
            // stays excluded: the source is the same restore.
            if self.report.excluded_rooms.contains_key(&room_id) {
                continue;
            }
            rooms.push(room_id);
        }
        self.report.rooms_without_local_members = without_local;
        eprintln!(
            "discovered: users={} rooms={} excluded_rooms={} rooms_without_local_members={without_local}",
            self.users.len(),
            rooms.len(),
            self.report.excluded_rooms.len()
        );
        Ok(rooms)
    }

    /// Count what the import leaves behind, so the report can name it.
    fn record_not_migrated(&mut self) {
        let tables: [(&str, &str, &str); 14] = [
            (
                "access_tokens",
                "SELECT count(*) FROM access_tokens",
                "sessions belong to the delegated identity provider (MAS); clients sign in again or keep their MAS session",
            ),
            (
                "refresh_tokens",
                "SELECT count(*) FROM refresh_tokens",
                "as access_tokens",
            ),
            (
                "user_threepids",
                "SELECT count(*) FROM user_threepids",
                "third-party identifiers are held by MAS",
            ),
            (
                "user_external_ids",
                "SELECT count(*) FROM user_external_ids",
                "upstream identity links are held by MAS",
            ),
            (
                "user_filters",
                "SELECT count(*) FROM user_filters",
                "a client uploads its filter again after it signs in",
            ),
            (
                "event_reports",
                "SELECT count(*) FROM event_reports",
                "moderation reports are not carried; export them from the Synapse admin API before cutover",
            ),
            (
                "remote_media_cache",
                "SELECT count(*) FROM remote_media_cache",
                "a cache: Spindle fetches remote media from the origin server on demand",
            ),
            (
                "device_lists_remote_cache",
                "SELECT count(*) FROM device_lists_remote_cache",
                "a cache: remote device keys are fetched over federation on demand",
            ),
            (
                "e2e_cross_signing_keys (remote users)",
                "SELECT count(DISTINCT user_id) FROM e2e_cross_signing_keys",
                "a cache: remote cross-signing keys are fetched over federation; only keys a local user's signature needs are imported",
            ),
            (
                "server_keys_json",
                "SELECT count(*) FROM server_keys_json",
                "a cache of other servers' signing keys, fetched again on demand",
            ),
            (
                "user_ips",
                "SELECT count(*) FROM user_ips",
                "client IP history is not carried",
            ),
            (
                "presence_stream",
                "SELECT count(*) FROM presence_stream",
                "presence is ephemeral",
            ),
            (
                "event_push_actions",
                "SELECT count(*) FROM event_push_actions",
                "derived: notification counts are computed from push rules and receipts",
            ),
            (
                "user_directory",
                "SELECT count(*) FROM user_directory",
                "derived: Spindle searches users who share a room, or are in a public room, from memberships and profiles",
            ),
        ];
        for (table, sql, reason) in tables {
            let count = match self.snapshot.query(sql, &[]) {
                Ok(rows) => rows.first().map_or(0, |row| row.get::<_, i64>(0)),
                Err(error) => {
                    eprintln!("note: cannot count {table}: {error}");
                    -1
                }
            };
            self.report
                .not_migrated
                .insert(table.to_owned(), format!("{count} rows: {reason}"));
        }
    }

    // ----- phases ----------------------------------------------------------

    fn signing_key(&mut self) -> Result<(), Error> {
        let Some(source) = &self.options.signing_key else {
            self.domain("signing_key").skip("no key file given");
            return Ok(());
        };
        self.domain("signing_key").source = 1;
        if self.options.dry_run {
            return Ok(());
        }
        match crate::signing::ServerKey::install_synapse(self.target.store.as_ref(), source) {
            Ok(key) => {
                eprintln!("signing key installed: {}", key.key_id());
                self.domain("signing_key").imported = 1;
            }
            Err(crate::signing::SigningError::AlreadyExists) => {
                self.domain("signing_key").imported = 1;
            }
            Err(error) => return Err(write_error(error)),
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn import_users(&mut self) -> Result<(), Error> {
        self.reset(&[
            "users",
            "deactivated_users",
            "admins",
            "erased_users",
            "profiles",
        ]);
        let erased: BTreeSet<String> = self
            .snapshot
            .query("SELECT user_id FROM erased_users", &[])?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();
        let rows = self.snapshot.query(
            "SELECT name, COALESCE(is_guest, 0)::int, COALESCE(deactivated, 0)::int, COALESCE(admin, 0)::int, \
                    appservice_id, COALESCE(locked, FALSE), COALESCE(suspended, FALSE) \
             FROM users ORDER BY name",
            &[],
        )?;
        let accounts =
            crate::accounts::Accounts::new(self.target.store.as_ref(), &self.options.server_name);
        let mut imported = BTreeSet::new();
        // One unguessable password, hashed once and then forgotten, for every
        // account without a known password: sign-in goes through the
        // delegated identity provider, and nobody holds the password.
        let unguessable_hash = if self.options.dry_run {
            String::new()
        } else {
            crate::accounts::hash_password(&crate::accounts::unguessable_password())
                .map_err(write_error)?
        };
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let guest = row.get::<_, i32>(1) != 0;
            let deactivated = row.get::<_, i32>(2) != 0;
            let admin = row.get::<_, i32>(3) != 0;
            let appservice: Option<String> = row.get(4);
            let locked: bool = row.get(5);
            let suspended: bool = row.get(6);
            self.domain("users").source += 1;
            if guest {
                self.domain("users")
                    .skip("guest account: Spindle has no guest access");
                continue;
            }
            if deactivated {
                self.domain("deactivated_users").source += 1;
            }
            if admin {
                self.domain("admins").source += 1;
            }
            let is_erased = erased.contains(&user_id);
            if is_erased {
                self.domain("erased_users").source += 1;
            }
            if appservice.is_some() {
                *self
                    .domain("users")
                    .skipped
                    .entry("note: imported, appservice namespace (count only)".to_owned())
                    .or_default() += 1;
            }
            if self.options.dry_run {
                continue;
            }
            let localpart = localpart(&user_id).to_owned();
            let exists = accounts.account(&localpart).map_err(write_error)?.is_some();
            if !exists {
                let registered = match (self.options.password_for)(&localpart) {
                    Some(password) => accounts.register(&localpart, &password),
                    None => accounts.register_hashed(&localpart, &unguessable_hash),
                };
                match registered {
                    Ok(_) => {}
                    Err(crate::accounts::AccountError::InvalidUsername) => {
                        self.domain("users")
                            .skip("localpart not accepted by Spindle's grammar");
                        continue;
                    }
                    Err(error) => return Err(write_error(error)),
                }
            }
            accounts
                .set_deactivated(&localpart, deactivated)
                .map_err(write_error)?;
            accounts.set_admin(&localpart, admin).map_err(write_error)?;
            accounts
                .set_locked(&localpart, locked)
                .map_err(write_error)?;
            accounts
                .set_suspended(&localpart, suspended)
                .map_err(write_error)?;
            accounts
                .set_erased(&localpart, is_erased)
                .map_err(write_error)?;
            if is_erased {
                self.domain("erased_users").imported += 1;
            }
            self.domain("users").imported += 1;
            if deactivated {
                self.domain("deactivated_users").imported += 1;
            }
            if admin {
                self.domain("admins").imported += 1;
            }
            imported.insert(user_id);
        }
        if !self.options.dry_run {
            // A user the grammar refused is out of scope for every later phase.
            self.users.retain(|user_id| imported.contains(user_id));
        }

        let rows = self.snapshot.query(
            "SELECT full_user_id, displayname, avatar_url, fields::text FROM profiles \
             WHERE full_user_id IS NOT NULL ORDER BY full_user_id",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let displayname: Option<String> = row.get(1);
            let avatar_url: Option<String> = row.get(2);
            let fields: Option<String> = row.get(3);
            self.domain("profiles").source += 1;
            if self.options.dry_run {
                continue;
            }
            self.target
                .profiles
                .set(&user_id, Some(displayname), Some(avatar_url))
                .map_err(write_error)?;
            if let Some(fields) = fields
                && let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(&fields)
            {
                for (key, value) in fields {
                    if self
                        .target
                        .profiles
                        .set_field(&user_id, &key, Some(value))
                        .map_err(write_error)?
                        .is_err()
                    {
                        self.domain("profiles")
                            .skip("extra field refused by the profile cap");
                    }
                }
            }
            self.domain("profiles").imported += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn import_devices(&mut self) -> Result<(), Error> {
        self.reset(&[
            "devices",
            "device_keys",
            "one_time_keys",
            "fallback_keys",
            "to_device_pending",
        ]);
        let accounts =
            crate::accounts::Accounts::new(self.target.store.as_ref(), &self.options.server_name);
        let rows = self.snapshot.query(
            "SELECT user_id, device_id, display_name, COALESCE(hidden, FALSE) \
             FROM devices ORDER BY user_id, device_id",
            &[],
        )?;
        let mut known: BTreeSet<(String, String)> = BTreeSet::new();
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let device_id: String = row.get(1);
            let display_name: Option<String> = row.get(2);
            let hidden: bool = row.get(3);
            self.domain("devices").source += 1;
            if hidden {
                self.domain("devices")
                    .skip("hidden: Synapse's placeholder row for a cross-signing key");
                continue;
            }
            known.insert((user_id.clone(), device_id.clone()));
            if self.options.dry_run {
                continue;
            }
            accounts
                .put_device(localpart(&user_id), &device_id, display_name)
                .map_err(write_error)?;
            self.domain("devices").imported += 1;
        }

        let rows = self.snapshot.query(
            "SELECT user_id, device_id, key_json FROM e2e_device_keys_json \
             ORDER BY user_id, device_id",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let device_id: String = row.get(1);
            let keys: Value = serde_json::from_str(&row.get::<_, String>(2))?;
            self.domain("device_keys").source += 1;
            if !known.contains(&(user_id.clone(), device_id.clone())) {
                self.domain("device_keys")
                    .skip("no device row (the device was deleted)");
                continue;
            }
            if self.options.dry_run {
                continue;
            }
            self.target
                .devices
                .upload_device_keys(&user_id, &device_id, &keys)
                .map_err(write_error)?;
            self.domain("device_keys").imported += 1;
        }

        let rows = self.snapshot.query(
            "SELECT user_id, device_id, algorithm, key_id, key_json FROM e2e_one_time_keys_json \
             ORDER BY user_id, device_id, algorithm, key_id",
            &[],
        )?;
        let mut one_time: BTreeMap<(String, String), Map<String, Value>> = BTreeMap::new();
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let device_id: String = row.get(1);
            let algorithm: String = row.get(2);
            let key_id: String = row.get(3);
            let key: Value = serde_json::from_str(&row.get::<_, String>(4))?;
            self.domain("one_time_keys").source += 1;
            if !known.contains(&(user_id.clone(), device_id.clone())) {
                self.domain("one_time_keys").skip("no device row");
                continue;
            }
            one_time
                .entry((user_id, device_id))
                .or_default()
                .insert(format!("{algorithm}:{key_id}"), key);
        }
        for ((user_id, device_id), keys) in &one_time {
            if !self.options.dry_run {
                self.target
                    .devices
                    .upload_one_time_keys(user_id, device_id, keys)
                    .map_err(write_error)?;
            }
            self.domain("one_time_keys").imported += keys.len() as u64;
        }

        let rows = self.snapshot.query(
            "SELECT user_id, device_id, algorithm, key_id, key_json, used \
             FROM e2e_fallback_keys_json ORDER BY user_id, device_id, algorithm",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let device_id: String = row.get(1);
            let algorithm: String = row.get(2);
            let key_id: String = row.get(3);
            let key: Value = serde_json::from_str(&row.get::<_, String>(4))?;
            let used: bool = row.get(5);
            self.domain("fallback_keys").source += 1;
            if !known.contains(&(user_id.clone(), device_id.clone())) {
                self.domain("fallback_keys").skip("no device row");
                continue;
            }
            if self.options.dry_run {
                continue;
            }
            self.target
                .devices
                .restore_fallback_key(
                    &user_id,
                    &device_id,
                    &format!("{algorithm}:{key_id}"),
                    &key,
                    used,
                )
                .map_err(write_error)?;
            self.domain("fallback_keys").imported += 1;
        }

        // Undelivered to-device messages: Megolm keys a device has not
        // fetched yet. Cleared first, so a repeated phase does not queue
        // a message twice.
        if !self.options.dry_run {
            for (user_id, device_id) in &known {
                let prefix = spindle_core::keys::device_scoped(
                    spindle_core::keys::Keyspace::ToDevice,
                    user_id,
                    device_id,
                    &[],
                );
                for (key, _) in ReadView::scan_prefix(self.target.store.as_ref(), &prefix)
                    .map_err(write_error)?
                {
                    Store::delete(self.target.store.as_ref(), &key).map_err(write_error)?;
                }
            }
        }
        let rows = self.snapshot.query(
            "SELECT user_id, device_id, message_json FROM device_inbox ORDER BY stream_id",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let device_id: String = row.get(1);
            self.domain("to_device_pending").source += 1;
            if !known.contains(&(user_id.clone(), device_id.clone())) {
                self.domain("to_device_pending").skip("no device row");
                continue;
            }
            let mut message: Value = serde_json::from_str(&row.get::<_, String>(2))?;
            // Synapse keeps its own tracing id beside the event; a client
            // reads type, sender and content.
            if let Some(object) = message.as_object_mut() {
                object.retain(|key, _| matches!(key.as_str(), "type" | "sender" | "content"));
            }
            if self.options.dry_run {
                continue;
            }
            let seq = self.target.rooms.allocate_stream_id();
            self.target
                .devices
                .queue_to_device(&user_id, &device_id, seq, &message)
                .map_err(write_error)?;
            self.domain("to_device_pending").imported += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn import_cross_signing(&mut self) -> Result<(), Error> {
        self.reset(&[
            "cross_signing_keys",
            "cross_signing_signatures",
            "remote_cross_signing_keys",
        ]);
        let server_name = self.options.server_name.clone();
        let rows = self.snapshot.query(
            "SELECT user_id, key_id, target_user_id, target_device_id, signature \
             FROM e2e_cross_signing_signatures \
             WHERE right(user_id, length($1) + 1) = ':' || $1 \
                OR right(target_user_id, length($1) + 1) = ':' || $1 \
             ORDER BY target_user_id, target_device_id, user_id, key_id",
            &[&server_name],
        )?;
        let mut signatures = Vec::new();
        let mut remote_targets = BTreeSet::new();
        for row in rows {
            let signer: String = row.get(0);
            let target_user: String = row.get(2);
            if !self.user_in_scope(&signer) && !self.user_in_scope(&target_user) {
                continue;
            }
            if !is_local(&target_user, &server_name) {
                remote_targets.insert(target_user.clone());
            }
            signatures.push((
                signer,
                row.get::<_, String>(1),
                target_user,
                row.get::<_, String>(3),
                row.get::<_, String>(4),
            ));
        }

        // Every key before any signature: a signature by one user on
        // another's key needs the target key in place, and the per-user
        // order of a rehearsal run dropped those (#557).
        let rows = self.snapshot.query(
            "SELECT DISTINCT ON (user_id, keytype) user_id, keytype, keydata \
             FROM e2e_cross_signing_keys \
             WHERE right(user_id, length($1) + 1) = ':' || $1 OR user_id = ANY($2) \
             ORDER BY user_id, keytype, stream_id DESC",
            &[
                &server_name,
                &remote_targets.iter().cloned().collect::<Vec<_>>(),
            ],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            let key_type: String = row.get(1);
            let key: Value = serde_json::from_str(&row.get::<_, String>(2))?;
            let domain = if is_local(&user_id, &server_name) {
                if !self.user_in_scope(&user_id) {
                    continue;
                }
                "cross_signing_keys"
            } else {
                // A remote user's own signing keys only; their
                // user-signing key is private to them.
                if key_type == "user_signing" {
                    continue;
                }
                "remote_cross_signing_keys"
            };
            self.domain(domain).source += 1;
            if self.options.dry_run {
                continue;
            }
            self.target
                .devices
                .upload_cross_signing(&user_id, &key_type, &key)
                .map_err(write_error)?;
            self.domain(domain).imported += 1;
        }

        for (signer, key_id, target_user, target_device, signature) in signatures {
            self.domain("cross_signing_signatures").source += 1;
            if self.options.dry_run {
                continue;
            }
            let signed = json!({ "signatures": { signer: { key_id: signature } } });
            if self
                .target
                .devices
                .add_signatures(&target_user, &target_device, &signed)
                .map_err(write_error)?
            {
                self.domain("cross_signing_signatures").imported += 1;
            } else {
                self.domain("cross_signing_signatures").skip(
                    "the signed key is not in Synapse either (a deleted device or replaced key)",
                );
            }
        }
        Ok(())
    }

    fn import_backups(&mut self) -> Result<(), Error> {
        self.reset(&["key_backup_versions", "key_backup_sessions"]);
        let rows = self.snapshot.query(
            "SELECT user_id, room_id, session_id, version, first_message_index, \
                    forwarded_count, is_verified, session_data \
             FROM e2e_room_keys ORDER BY user_id, version, room_id, session_id",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            self.domain("key_backup_sessions").source += 1;
            if self.options.dry_run {
                continue;
            }
            let data = json!({
                "first_message_index": row.get::<_, i32>(4),
                "forwarded_count": row.get::<_, i32>(5),
                "is_verified": row.get::<_, bool>(6),
                "session_data": serde_json::from_str::<Value>(&row.get::<_, String>(7))?,
            });
            let _ = self
                .target
                .backups
                .put_key(
                    &user_id,
                    row.get::<_, i64>(3).try_into().unwrap_or(0),
                    &row.get::<_, String>(1),
                    &row.get::<_, String>(2),
                    &data,
                )
                .map_err(write_error)?;
            self.domain("key_backup_sessions").imported += 1;
        }
        let rows = self.snapshot.query(
            "SELECT user_id, version, algorithm, auth_data, deleted::int, etag \
             FROM e2e_room_keys_versions ORDER BY user_id, version",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            self.domain("key_backup_versions").source += 1;
            if self.options.dry_run {
                continue;
            }
            self.target
                .backups
                .restore_version(
                    &user_id,
                    row.get::<_, i64>(1).try_into().unwrap_or(0),
                    &row.get::<_, String>(2),
                    &serde_json::from_str::<Value>(&row.get::<_, String>(3))?,
                    row.get::<_, Option<i64>>(5)
                        .unwrap_or(0)
                        .try_into()
                        .unwrap_or(0),
                    row.get::<_, i32>(4) != 0,
                )
                .map_err(write_error)?;
            self.domain("key_backup_versions").imported += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn import_account_data(&mut self) -> Result<(), Error> {
        self.reset(&[
            "account_data_global",
            "account_data_room",
            "room_tags",
            "push_rules",
        ]);
        let rows = self.snapshot.query(
            "SELECT user_id, ''::text, account_data_type, content FROM account_data \
             UNION ALL \
             SELECT user_id, room_id, account_data_type, content FROM room_account_data \
             ORDER BY 1, 2, 3",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            let room_id: String = row.get(1);
            let domain = if room_id.is_empty() {
                "account_data_global"
            } else {
                "account_data_room"
            };
            self.domain(domain).source += 1;
            let event_type: String = row.get(2);
            let content: Value = serde_json::from_str(&row.get::<_, String>(3))?;
            if self.options.dry_run {
                continue;
            }
            self.target
                .account_data
                .put(&user_id, &room_id, &event_type, &content, 0)
                .map_err(write_error)?;
            self.domain(domain).imported += 1;
        }

        // Synapse keeps tags in their own table and assembles `m.tag` on read.
        let rows = self.snapshot.query(
            "SELECT user_id, room_id, tag, content FROM room_tags ORDER BY 1, 2, 3",
            &[],
        )?;
        let mut tags: BTreeMap<(String, String), Map<String, Value>> = BTreeMap::new();
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            self.domain("room_tags").source += 1;
            let content: Value =
                serde_json::from_str(&row.get::<_, String>(3)).unwrap_or_else(|_| json!({}));
            tags.entry((user_id, row.get(1)))
                .or_default()
                .insert(row.get(2), content);
        }
        for ((user_id, room_id), tags) in tags {
            let count = tags.len() as u64;
            if !self.options.dry_run {
                self.target
                    .account_data
                    .put(&user_id, &room_id, "m.tag", &json!({ "tags": tags }), 0)
                    .map_err(write_error)?;
            }
            self.domain("room_tags").imported += count;
        }

        self.import_push_rules()
    }

    /// Rebuild each user's ruleset the way Synapse would serve it.
    fn import_push_rules(&mut self) -> Result<(), Error> {
        let rows = self.snapshot.query(
            "SELECT user_name, rule_id, priority_class, priority, conditions, actions \
             FROM push_rules ORDER BY user_name, priority_class DESC, priority DESC",
            &[],
        )?;
        let mut rules: BTreeMap<String, Vec<(String, i16, String, String)>> = BTreeMap::new();
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            rules.entry(user_id).or_default().push((
                row.get(1),
                row.get(2),
                row.get(4),
                row.get(5),
            ));
        }
        let rows = self.snapshot.query(
            "SELECT user_name, rule_id, enabled FROM push_rules_enable ORDER BY 1, 2",
            &[],
        )?;
        let mut enabled: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            enabled
                .entry(user_id)
                .or_default()
                .push((row.get(1), row.get::<_, Option<i16>>(2).unwrap_or(1) != 0));
        }
        let users: BTreeSet<String> = rules.keys().chain(enabled.keys()).cloned().collect();
        for user_id in users {
            let (ruleset, outcome) = synapse_ruleset(
                &user_id,
                rules.get(&user_id).map_or(&[][..], Vec::as_slice),
                enabled.get(&user_id).map_or(&[][..], Vec::as_slice),
            );
            let domain = self.domain("push_rules");
            domain.source += outcome.source;
            domain.imported += outcome.imported;
            for (reason, count) in outcome.skipped {
                *domain.skipped.entry(reason).or_default() += count;
            }
            if !self.options.dry_run {
                self.target
                    .account_data
                    .put(&user_id, "", crate::push_rules::TYPE, &ruleset, 0)
                    .map_err(write_error)?;
            }
        }
        Ok(())
    }

    fn import_pushers(&mut self) -> Result<(), Error> {
        self.reset(&["pushers"]);
        let rows = self.snapshot.query(
            "SELECT user_name, app_id, pushkey, kind, app_display_name, device_display_name, \
                    profile_tag, lang, data, COALESCE(enabled, TRUE), device_id \
             FROM pushers ORDER BY user_name, app_id, pushkey",
            &[],
        )?;
        for row in rows {
            let user_id: String = row.get(0);
            if !self.user_in_scope(&user_id) {
                continue;
            }
            self.domain("pushers").source += 1;
            let app_id: String = row.get(1);
            let pushkey: String = row.get(2);
            let enabled: bool = row.get(9);
            let device_id: Option<String> = row.get(10);
            let data: Value = row
                .get::<_, Option<String>>(8)
                .and_then(|data| serde_json::from_str(&data).ok())
                .unwrap_or_else(|| json!({}));
            let pusher = json!({
                "pushkey": pushkey,
                "kind": row.get::<_, String>(3),
                "app_id": app_id,
                "app_display_name": row.get::<_, String>(4),
                "device_display_name": row.get::<_, String>(5),
                "profile_tag": row.get::<_, String>(6),
                "lang": row.get::<_, Option<String>>(7),
                "data": data,
                "enabled": enabled,
                "org.matrix.msc3881.enabled": enabled,
                "device_id": device_id,
                "org.matrix.msc3881.device_id": device_id,
            });
            if self.options.dry_run {
                continue;
            }
            self.target
                .pushers
                .set(&user_id, &app_id, &pushkey, &pusher)
                .map_err(write_error)?;
            self.domain("pushers").imported += 1;
        }
        Ok(())
    }

    // ----- rooms -----------------------------------------------------------

    fn exclude(
        &mut self,
        room_id: &str,
        source: &SourceRoom,
        version: &str,
        reason: String,
    ) -> Result<(), Error> {
        eprintln!("room {room_id}: excluded: {reason}");
        let local_joined = source
            .current_state
            .keys()
            .filter(|(event_type, state_key)| {
                event_type == "m.room.member" && is_local(state_key, &self.options.server_name)
            })
            .count() as u64;
        self.report.excluded_rooms.insert(
            room_id.to_owned(),
            ExcludedRoom {
                version: version.to_owned(),
                source_events: source.events.len() as u64,
                local_joined,
                reason,
            },
        );
        save_checkpoint(&self.options.checkpoint, &self.report)
    }

    fn index_positions(&mut self, room_id: &str, expected: u64) -> Result<usize, Error> {
        let rows = self.snapshot.query(
            "SELECT stream_ordering, depth, event_id FROM events WHERE room_id = $1",
            &[&room_id],
        )?;
        let positions: Vec<(i64, i64, String)> = rows
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect();
        let count = self
            .target
            .rooms
            .record_synapse_positions(
                room_id,
                positions
                    .iter()
                    .map(|(stream, depth, id)| (*stream, *depth, id.as_str())),
            )
            .map_err(write_error)?;
        if count as u64 != expected {
            return Err(write_error(format!(
                "{room_id}: indexed {count} pagination positions for {expected} imported events"
            )));
        }
        Ok(count)
    }

    #[allow(clippy::too_many_lines)]
    fn import_room(&mut self, room_id: &str, position: usize, total: usize) -> Result<(), Error> {
        let started = Instant::now();
        let version: String = self
            .snapshot
            .query(
                "SELECT COALESCE(room_version, '1') FROM rooms WHERE room_id = $1",
                &[&room_id],
            )?
            .first()
            .map_or_else(|| "1".to_owned(), |row| row.get(0));
        let source = self.snapshot.read_room(room_id)?;
        let mut room_report = RoomReport {
            rejection_policy_version: REJECTION_POLICY_VERSION,
            version: version.clone(),
            source_events: source.events.len() as u64,
            state_slots: source.current_state.len() as u64,
            ..RoomReport::default()
        };

        // Replay first, with no bodies and nothing written: a room whose
        // state would diverge is reported and never persisted. The replay
        // derives every event's state, with the room version's resolver at
        // each fork; the states it settled are kept for the write.
        let mut auth_engine = match RoomResolver::load(self.snapshot, room_id, &version) {
            Ok(resolver) => resolver,
            Err(error) => {
                return self.exclude(
                    room_id,
                    &source,
                    &version,
                    format!("no resolver for the room: {error}"),
                );
            }
        };
        let groups = self.snapshot.state_group_graph(room_id)?;
        let mut states = HashMap::new();
        let resolved = {
            let mut lookup = SnapshotSource {
                snapshot: &mut *self.snapshot,
                room_id,
                bodies: HashMap::new(),
                states: &mut states,
                resolver: Some(&mut auth_engine),
                settled: None,
                groups: Some(&groups),
            };
            replay_resolving(&source, &mut lookup, false)
        };
        room_report.compat_user_ids = auth_engine.stand_ins.iter().cloned().collect();
        drop(auth_engine);
        let resolved = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                return self.exclude(
                    room_id,
                    &source,
                    &version,
                    format!("cannot be replayed: {error}"),
                );
            }
        };
        room_report.replay_passes = resolved.passes as u64;
        room_report.full_checks = resolved.full_checks as u64;
        room_report.resolved_forks = resolved.forks.len() as u64;
        for fork in &resolved.forks {
            if fork.disagreements.is_empty() {
                room_report.resolver_agreed += 1;
            } else {
                room_report.resolver_disagreed.push(format!(
                    "{}: {}",
                    fork.event_id,
                    fork.disagreements
                        .iter()
                        .map(|slot| format!(
                            "({}, {:?}) resolver={} synapse={}",
                            slot.key.event_type().as_str(),
                            slot.key.state_key(),
                            slot.spindle.as_deref().unwrap_or("-"),
                            slot.synapse.as_deref().unwrap_or("-")
                        ))
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
        let settled = resolved.settled;
        let outcome = resolved.outcome;
        for excluded in &outcome.excluded {
            match excluded {
                Excluded::Outlier(_) => room_report.outliers += 1,
                Excluded::Rejected(_) => room_report.rejected += 1,
                Excluded::Frayed { .. } => room_report.frayed += 1,
                Excluded::Orphaned { .. } => room_report.orphaned += 1,
            }
        }
        room_report.from_source = resolved.from_source.len() as u64;
        for (event_id, reason) in &resolved.from_source {
            let kind = if reason == GAP_REASON {
                "parent outside retained history: Synapse's state".to_owned()
            } else if reason == RESOLVED_REASON {
                "resolver: the log's fold differs".to_owned()
            } else if reason == HEAD_RESOLVED_REASON {
                "head: resolver over the forward extremities".to_owned()
            } else if reason == DISAGREED_REASON {
                "resolver disagrees with Synapse: Synapse's slots".to_owned()
            } else if reason == ELSEWHERE_REASON {
                "source state differs from the derivation: Synapse's state".to_owned()
            } else if reason == HEAD_REASON {
                "head: Synapse's current state".to_owned()
            } else {
                reason
                    .split([' ', '{', '('])
                    .next()
                    .unwrap_or(reason)
                    .to_owned()
            };
            *room_report.from_source_reasons.entry(kind).or_default() += 1;
            if room_report.from_source_examples.len() < 5 {
                room_report
                    .from_source_examples
                    .push(format!("{event_id}: {reason}"));
            }
        }
        room_report.seeded_from_source = outcome.seeded_from_source;
        room_report.imported_events = outcome.imported as u64;
        room_report.divergence = outcome
            .divergence
            .iter()
            .map(|slot| SlotDivergence {
                event_type: slot.key.event_type().as_str().to_owned(),
                state_key: slot.key.state_key().to_owned(),
                spindle: slot.spindle.clone(),
                synapse: slot.synapse.clone(),
            })
            .collect();
        drop(outcome);
        if !room_report.divergence.is_empty() {
            let slots = room_report.divergence.len();
            let reason = format!(
                "{slots} state slots diverge from Synapse's current state: {}",
                room_report
                    .divergence
                    .iter()
                    .take(5)
                    .map(|slot| format!(
                        "({}, {:?}) spindle={} synapse={}",
                        slot.event_type,
                        slot.state_key,
                        slot.spindle.as_deref().unwrap_or("-"),
                        slot.synapse.as_deref().unwrap_or("-")
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            return self.exclude(room_id, &source, &version, reason);
        }

        let plan = plan_resolving(&source).map_err(|error| Error::Write(error.to_string()))?;
        let rules = ruma::RoomVersionId::try_from(version.as_str())
            .ok()
            .and_then(|version| spindle_core::rules_of(&version));
        // Every event's body is read and checked, and its signatures are
        // verified, in a dry run too; only the writes are skipped.
        {
            let events: HashMap<&str, &crate::import::SourceEvent> = source
                .events
                .iter()
                .map(|event| (event.event_id.as_str(), event))
                .collect();
            let mut redactions = Vec::new();
            let mut written = 0_usize;
            for (index, chunk) in plan.steps.chunks(CHUNK).enumerate() {
                let mut wanted: Vec<String> = chunk
                    .iter()
                    .map(|step| step.input.event_id.as_str().to_owned())
                    .collect();
                let seeding = index == 0 && chunk.first().is_some_and(|step| step.seed);
                if seeding && let Some(state) = &source.state_after_root {
                    wanted.extend(state.values().cloned());
                }
                let bodies = self.snapshot.event_bodies_for(&wanted)?;
                for step in chunk {
                    let event_id = step.input.event_id.as_str();
                    let body = bodies.get(event_id).ok_or_else(|| {
                        Error::Write(format!("{room_id}: no JSON body for {event_id}"))
                    })?;
                    let event = events
                        .get(event_id)
                        .ok_or_else(|| Error::Write(format!("{room_id}: no row for {event_id}")))?;
                    check_body(event, body).map_err(write_error)?;
                    if let Some(target) = redaction_target(body) {
                        redactions.push((target.to_owned(), event_id.to_owned()));
                    }
                    let verdict = match (&self.keys, &rules) {
                        (Some(keys), Some(rules)) => keys.verify(body, rules),
                        _ => Verdict::Unverifiable("no keys or no rules".to_owned()),
                    };
                    let label = match &verdict {
                        Verdict::Verified => "verified",
                        Verdict::Historical => "verified with an older key under a reused key ID",
                        Verdict::RedactedCopy => "signatures verify, received redacted",
                        Verdict::Unverifiable(_) => "unverifiable",
                    };
                    *room_report.signatures.entry(label.to_owned()).or_default() += 1;
                    if matches!(verdict, Verdict::Unverifiable(_) | Verdict::Historical)
                        && room_report.signature_examples.len() < 10
                    {
                        let why = match &verdict {
                            Verdict::Unverifiable(why) => why.clone(),
                            _ => "older key".to_owned(),
                        };
                        room_report.signature_examples.push(format!(
                            "{event_id} ({}): {why}",
                            body["sender"].as_str().unwrap_or("?")
                        ));
                    }
                }
                room_report.body_bytes += bodies
                    .values()
                    .map(|body| body.to_string().len() as u64)
                    .sum::<u64>();
                if self.options.dry_run {
                    continue;
                }
                let mut chunk_source = SnapshotSource {
                    snapshot: &mut *self.snapshot,
                    room_id,
                    bodies,
                    states: &mut states,
                    resolver: None,
                    settled: Some(&settled),
                    groups: None,
                };
                let (appended, _) = self
                    .target
                    .rooms
                    .persist_synapse_steps(
                        room_id,
                        chunk,
                        source.state_after_root.as_ref(),
                        &mut chunk_source,
                    )
                    .map_err(write_error)?;
                written += appended;
                if plan.steps.len() > CHUNK * 5 && (index + 1) % 25 == 0 {
                    self.progress(&format!(
                        "room {position}/{total} {room_id} events={}/{} bytes={}",
                        (index + 1) * CHUNK,
                        plan.steps.len(),
                        room_report.body_bytes
                    ));
                }
            }
            let accepted: BTreeSet<&str> = plan
                .steps
                .iter()
                .map(|step| step.input.event_id.as_str())
                .collect();
            let required_auth: BTreeSet<String> = self
                .snapshot
                .auth_edges(room_id)?
                .into_iter()
                .map(|(_, id)| id)
                .collect();
            let auth_ids: Vec<String> = source
                .events
                .iter()
                .filter(|event| {
                    (event.state_key.is_some() || required_auth.contains(&event.event_id))
                        && !accepted.contains(event.event_id.as_str())
                })
                .map(|event| event.event_id.clone())
                .collect();
            for ids in auth_ids.chunks(CHUNK) {
                let bodies = self.snapshot.event_bodies_for(ids)?;
                if bodies.len() != ids.len() {
                    return Err(Error::Write(format!(
                        "{room_id}: source auth PDU bodies are missing"
                    )));
                }
                if !self.options.dry_run {
                    room_report.retained_auth_pdus +=
                        self.target
                            .rooms
                            .persist_imported_auth_pdus(room_id, &bodies)
                            .map_err(write_error)? as u64;
                }
            }
            if self.options.dry_run {
                room_report.redactions_applied = redactions.len() as u64;
            } else {
                let rejected: Vec<String> = source
                    .events
                    .iter()
                    .filter(|event| event.rejected)
                    .map(|event| event.event_id.clone())
                    .collect();
                for ids in rejected.chunks(CHUNK) {
                    let bodies = self.snapshot.event_bodies_for(ids)?;
                    room_report.preserved_rejections +=
                        self.target
                            .rooms
                            .preserve_imported_rejections(room_id, ids, &bodies)
                            .map_err(write_error)? as u64;
                }
                room_report.redactions_applied = self
                    .target
                    .rooms
                    .finish_synapse_room(room_id, &redactions)
                    .map_err(write_error)? as u64;
                room_report.pagination_positions =
                    self.index_positions(room_id, room_report.imported_events)? as u64;
                self.target.rooms.release_imported_room(room_id);
                self.sync()?;
            }
            if !self.options.dry_run && written < plan.steps.len() {
                eprintln!(
                    "room {room_id}: resumed; {} events were already present",
                    plan.steps.len() - written
                );
            }
        }
        room_report.seconds = started.elapsed().as_secs_f64();
        eprintln!(
            "room {position}/{total} {room_id} v{version}: events={} outliers={} rejected={} \
             from_synapse_state={} redactions={} seeded={} bytes={} {:.1}s",
            room_report.imported_events,
            room_report.outliers,
            room_report.rejected,
            room_report.from_source,
            room_report.redactions_applied,
            room_report.seeded_from_source,
            room_report.body_bytes,
            room_report.seconds
        );
        self.report.rooms.insert(room_id.to_owned(), room_report);
        self.imported_rooms.insert(room_id.to_owned());
        save_checkpoint(&self.options.checkpoint, &self.report)?;
        let events: u64 = self
            .report
            .rooms
            .values()
            .map(|room| room.imported_events)
            .sum();
        let bytes: u64 = self.report.rooms.values().map(|room| room.body_bytes).sum();
        self.progress(&format!(
            "rooms={}/{total} events={events} bytes={bytes}",
            self.report.rooms.len()
        ));
        Ok(())
    }

    // ----- after the rooms ---------------------------------------------------

    fn import_receipts(&mut self) -> Result<(), Error> {
        self.reset(&["receipts"]);
        let rows = self.snapshot.query(
            "SELECT room_id, receipt_type, user_id, event_id, thread_id \
             FROM receipts_linearized ORDER BY room_id, user_id, receipt_type",
            &[],
        )?;
        let mut by_room: BTreeMap<String, Vec<ReceiptRow>> = BTreeMap::new();
        for row in rows {
            let room_id: String = row.get(0);
            let user_id: String = row.get(2);
            if is_local(&user_id, &self.options.server_name) && !self.user_in_scope(&user_id) {
                continue;
            }
            if self
                .options
                .only_rooms
                .as_ref()
                .is_some_and(|only| !only.contains(&room_id))
            {
                continue;
            }
            by_room
                .entry(room_id)
                .or_default()
                .push((row.get(1), user_id, row.get(3), row.get(4)));
        }
        for (room_id, receipts) in by_room {
            let in_target = self.room_in_target(&room_id);
            for (receipt_type, user_id, event_id, thread_id) in receipts {
                self.domain("receipts").source += 1;
                if !in_target {
                    self.domain("receipts").skip("room not imported");
                    continue;
                }
                if self.options.dry_run {
                    continue;
                }
                match self.target.rooms.set_receipt(
                    &room_id,
                    &user_id,
                    &receipt_type,
                    &event_id,
                    thread_id.as_deref(),
                ) {
                    Ok(()) => self.domain("receipts").imported += 1,
                    Err(crate::rooms::RoomError::Forbidden(_)) => self
                        .domain("receipts")
                        .skip("the user is no longer joined to the room"),
                    Err(crate::rooms::RoomError::MissingBody(_)) => self
                        .domain("receipts")
                        .skip("the event it points at was not imported (outlier or outside retained history)"),
                    Err(error) => return Err(write_error(error)),
                }
            }
            self.target.rooms.release_imported_room(&room_id);
        }
        Ok(())
    }

    fn import_directory(&mut self) -> Result<(), Error> {
        self.reset(&["room_aliases", "published_rooms", "blocked_rooms"]);
        let rows = self.snapshot.query(
            "SELECT room_alias, room_id, COALESCE(creator, '') FROM room_aliases ORDER BY 1",
            &[],
        )?;
        for row in rows {
            let alias: String = row.get(0);
            let room_id: String = row.get(1);
            let creator: String = row.get(2);
            self.domain("room_aliases").source += 1;
            if !self.room_in_target(&room_id) {
                self.domain("room_aliases")
                    .skip("its room was not imported");
                continue;
            }
            if self.options.dry_run {
                continue;
            }
            match self.target.directory.create(&alias, &room_id, &creator) {
                Ok(()) => self.domain("room_aliases").imported += 1,
                Err(crate::directory::DirectoryError::Taken(_))
                    if self
                        .target
                        .directory
                        .resolve(&alias)
                        .map_err(write_error)?
                        .is_some_and(|record| record.room_id == room_id) =>
                {
                    self.domain("room_aliases").imported += 1;
                }
                Err(error) => {
                    eprintln!("alias {alias}: {error}");
                    self.domain("room_aliases").skip("refused by the directory");
                }
            }
        }

        let rows = self
            .snapshot
            .query("SELECT room_id FROM rooms WHERE is_public ORDER BY 1", &[])?;
        for row in rows {
            let room_id: String = row.get(0);
            self.domain("published_rooms").source += 1;
            if !self.room_in_target(&room_id) {
                self.domain("published_rooms").skip("room not imported");
                continue;
            }
            if self.options.dry_run {
                continue;
            }
            self.target
                .directory
                .publish(&room_id, "synapse-import")
                .map_err(write_error)?;
            self.domain("published_rooms").imported += 1;
        }

        let rows = self
            .snapshot
            .query("SELECT room_id, user_id FROM blocked_rooms ORDER BY 1", &[])?;
        for row in rows {
            let room_id: String = row.get(0);
            let actor: String = row.get(1);
            self.domain("blocked_rooms").source += 1;
            if self.options.dry_run {
                continue;
            }
            Store::put(
                self.target.store.as_ref(),
                &spindle_core::keys::room_block(&room_id),
                json!({ "actor": actor, "source": "synapse-import" })
                    .to_string()
                    .as_bytes(),
            )
            .map_err(write_error)?;
            self.domain("blocked_rooms").imported += 1;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn import_media(&mut self) -> Result<(), Error> {
        self.reset(&["media", "media_bytes", "thumbnails", "remote_media"]);
        let remote = self
            .snapshot
            .query("SELECT count(*) FROM remote_media_cache", &[])?
            .first()
            .map_or(0, |row| row.get::<_, i64>(0));
        let domain = self.domain("remote_media");
        domain.source = u64::try_from(remote).unwrap_or(0);
        domain.skipped.insert(
            "a cache: fetched again from the origin server on demand".to_owned(),
            domain.source,
        );

        let rows = self.snapshot.query(
            "SELECT media_id, COALESCE(media_type, 'application/octet-stream'), media_length, \
                    upload_name, COALESCE(user_id, ''), quarantined_by, url_cache, sha256 \
             FROM local_media_repository ORDER BY created_ts, media_id",
            &[],
        )?;
        let Some(root) = self.options.media_root.clone() else {
            let domain = self.domain("media");
            domain.source = rows.len() as u64;
            domain
                .skipped
                .insert("no media store given".to_owned(), rows.len() as u64);
            return Ok(());
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(write_error)?;
        let mut images = BTreeSet::new();
        let total = rows.len();
        for (index, row) in rows.into_iter().enumerate() {
            let media_id: String = row.get(0);
            let content_type: String = row.get(1);
            let length: Option<i32> = row.get(2);
            let upload_name: Option<String> = row.get(3);
            let user_id: String = row.get(4);
            let quarantined: Option<String> = row.get(5);
            let url_cache: Option<String> = row.get(6);
            let sha256: Option<String> = row.get(7);
            self.domain("media").source += 1;
            if is_local(&user_id, &self.options.server_name)
                && self.options.only_users.is_some()
                && !self.user_in_scope(&user_id)
            {
                continue;
            }
            if url_cache.is_some() {
                self.domain("media").skip("URL-preview cache entry");
                continue;
            }
            if quarantined.is_some() {
                self.domain("media").skip("quarantined by an administrator");
                continue;
            }
            if media_id.len() < 5 || media_id.contains(['/', '.']) {
                self.domain("media").skip("media ID not usable as a path");
                continue;
            }
            let path = root
                .join("local_content")
                .join(&media_id[0..2])
                .join(&media_id[2..4])
                .join(&media_id[4..]);
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.domain("media")
                        .skip("file missing from the media store");
                    continue;
                }
                Err(error) => {
                    return Err(Error::Write(format!("reading {}: {error}", path.display())));
                }
            };
            if length.is_some_and(|length| usize::try_from(length).ok() != Some(bytes.len())) {
                self.domain("media")
                    .skip("file length differs from Synapse's record");
                continue;
            }
            if let Some(expected) = &sha256 {
                use sha2::Digest as _;
                let actual = hex_lower(&sha2::Sha256::digest(&bytes));
                if !expected.eq_ignore_ascii_case(&actual) {
                    self.domain("media")
                        .skip("file SHA-256 differs from Synapse's record");
                    continue;
                }
            }
            if content_type.starts_with("image/") {
                images.insert(media_id.clone());
            }
            if self.options.dry_run {
                self.domain("media_bytes").source += bytes.len() as u64;
                continue;
            }
            runtime
                .block_on(self.target.media.put_imported(
                    &media_id,
                    &bytes,
                    &content_type,
                    upload_name.as_deref(),
                    &user_id,
                ))
                .map_err(write_error)?;
            self.domain("media").imported += 1;
            let domain = self.domain("media_bytes");
            domain.source += bytes.len() as u64;
            domain.imported += bytes.len() as u64;
            if (index + 1) % 500 == 0 {
                self.progress(&format!("media {}/{total}", index + 1));
            }
        }

        // Thumbnails are derived. Spindle makes its own on first request and
        // caches them; generating the sizes Synapse had now means the first
        // client to scroll the history does not wait for them.
        let rows = self.snapshot.query(
            "SELECT media_id, thumbnail_width, thumbnail_height, thumbnail_method \
             FROM local_media_repository_thumbnails ORDER BY 1, 2, 3",
            &[],
        )?;
        for row in rows {
            let media_id: String = row.get(0);
            self.domain("thumbnails").source += 1;
            if !images.contains(&media_id) {
                self.domain("thumbnails")
                    .skip("its original was not imported or is not an image");
                continue;
            }
            if self.options.dry_run {
                continue;
            }
            let width = u32::try_from(row.get::<_, i32>(1)).unwrap_or(0);
            let height = u32::try_from(row.get::<_, i32>(2)).unwrap_or(0);
            let crop = row.get::<_, Option<String>>(3).as_deref() == Some("crop");
            match runtime.block_on(self.target.media.thumbnail(&media_id, width, height, crop)) {
                Ok(_) => self.domain("thumbnails").imported += 1,
                Err(crate::media::MediaError::Unsupported(_)) => self.domain("thumbnails").skip(
                    "Spindle does not thumbnail this type (served on request as the original)",
                ),
                Err(crate::media::MediaError::Unreadable(_)) => self
                    .domain("thumbnails")
                    .skip("the original does not decode as an image"),
                Err(error) => return Err(write_error(error)),
            }
        }
        Ok(())
    }
}

/// One domain's check: rows looked at, and what did not match.
#[derive(Default)]
struct Check {
    rows: u64,
    mismatches: Vec<String>,
}

impl Check {
    fn expect(&mut self, ok: bool, what: impl FnOnce() -> String) {
        self.rows += 1;
        if !ok && self.mismatches.len() < 50 {
            self.mismatches.push(what());
        }
    }
}

/// Strip what legitimately differs between Synapse's stored JSON and what
/// Spindle serves: the ID Spindle adds and the per-server `unsigned` block.
fn comparable(mut event: Value) -> Value {
    if let Some(object) = event.as_object_mut() {
        object.remove("event_id");
        object.remove("unsigned");
    }
    event
}

/// Check the written store against Synapse, domain by domain.
///
/// Read-only on both sides. Rooms are compared in full (state, event
/// count) and by sample (event bodies); the per-user domains are small
/// enough to compare every row.
///
/// # Errors
///
/// Returns [`Error`] if a read fails on either side.
#[allow(clippy::too_many_lines)]
pub fn validate(
    options: &Options,
    snapshot: &mut Snapshot<'_>,
    store: &Arc<FjallStore>,
    blobs: crate::blobs::Blobs,
    report: &mut Report,
) -> Result<(), Error> {
    let started = Instant::now();
    let rooms = crate::rooms::Rooms::new(Arc::clone(store), &options.server_name);
    let mut validation = Validation::default();
    let mut historical_rejections = Check::default();
    let mut auth_context = Check::default();

    let room_ids: Vec<String> = report.rooms.keys().cloned().collect();
    for room_id in &room_ids {
        validation.rooms_checked += 1;
        let target: BTreeMap<(String, String), String> = rooms
            .state(room_id)
            .map_err(write_error)?
            .into_iter()
            .map(|event| {
                (
                    (
                        event["type"].as_str().unwrap_or_default().to_owned(),
                        event["state_key"].as_str().unwrap_or_default().to_owned(),
                    ),
                    event["event_id"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let mut source = BTreeMap::new();
        for row in snapshot.query(
            "SELECT type, state_key, event_id FROM current_state_events WHERE room_id = $1",
            &[room_id],
        )? {
            source.insert(
                (row.get::<_, String>(0), row.get::<_, String>(1)),
                row.get::<_, String>(2),
            );
        }
        let keys: BTreeSet<&(String, String)> = target.keys().chain(source.keys()).collect();
        let divergence: Vec<SlotDivergence> = keys
            .into_iter()
            .filter(|key| target.get(*key) != source.get(*key))
            .map(|key| SlotDivergence {
                event_type: key.0.clone(),
                state_key: key.1.clone(),
                spindle: target.get(key).cloned(),
                synapse: source.get(key).cloned(),
            })
            .collect();
        if !divergence.is_empty() {
            validation
                .rooms_divergent
                .insert(room_id.clone(), divergence);
        }

        let held = ReadView::scan_prefix(
            store.as_ref(),
            &spindle_core::keys::room_prefix(spindle_core::keys::Keyspace::Log, room_id),
        )
        .map_err(write_error)?
        .len() as u64;
        let planned = report.rooms[room_id].imported_events;
        if held != planned {
            validation.rooms_short.insert(
                room_id.clone(),
                format!("log holds {held}, plan had {planned}"),
            );
        }

        let rejected: Vec<String> = snapshot.query(
            "SELECT e.event_id FROM events e JOIN rejections r USING (event_id) WHERE e.room_id = $1 ORDER BY e.event_id",
            &[room_id],
        )?.into_iter().map(|row| row.get(0)).collect();
        let markers = ReadView::scan_prefix(
            store.as_ref(),
            &spindle_core::keys::room_prefix(
                spindle_core::keys::Keyspace::HistoricalRejection,
                room_id,
            ),
        )
        .map_err(write_error)?;
        historical_rejections.expect(markers.len() == rejected.len(), || {
            format!(
                "{room_id}: stored rejection count {} differs from source {}",
                markers.len(),
                rejected.len()
            )
        });
        historical_rejections.expect(
            report.rooms[room_id].preserved_rejections == rejected.len() as u64,
            || format!("{room_id}: checkpoint rejection count differs from source"),
        );
        for ids in rejected.chunks(CHUNK) {
            let bodies = snapshot.event_bodies_for(ids)?;
            for id in ids {
                let marker = ReadView::get(
                    store.as_ref(),
                    &spindle_core::keys::historical_rejection(room_id, id),
                )
                .map_err(write_error)?;
                historical_rejections.expect(marker.as_deref() == Some(&[1]), || {
                    format!("{room_id} {id}: missing rejection marker")
                });
                let held = rooms.pdu(room_id, id).ok();
                historical_rejections.expect(
                    held.as_ref()
                        .is_some_and(|body| Some(body) == bodies.get(id)),
                    || format!("{room_id} {id}: rejected PDU differs from source"),
                );
                historical_rejections.expect(rooms.event(room_id, id).is_err(), || {
                    format!("{room_id} {id}: rejected PDU is exposed to clients")
                });
            }
        }

        for row in snapshot.query(
            "SELECT DISTINCT a.auth_id FROM event_auth a JOIN event_json j ON j.event_id = a.auth_id WHERE a.room_id = $1",
            &[room_id],
        )? {
            let id: String = row.get(0);
            auth_context.expect(rooms.pdu(room_id, &id).is_ok(), || {
                format!("{room_id} {id}: retained source auth PDU is missing")
            });
        }
        let auth_markers = ReadView::scan_prefix(
            store.as_ref(),
            &spindle_core::keys::room_prefix(
                spindle_core::keys::Keyspace::ImportedAuthOnly,
                room_id,
            ),
        )
        .map_err(write_error)?;
        auth_context.expect(auth_markers.iter().all(|(_, value)| value == &[1]), || {
            format!("{room_id}: corrupt auth marker")
        });
        auth_context.expect(
            auth_markers.len() as u64 == report.rooms[room_id].retained_auth_pdus,
            || format!("{room_id}: stored auth marker count differs from checkpoint"),
        );

        let excluded_here = report.rooms[room_id].frayed + report.rooms[room_id].orphaned;
        for row in snapshot.query(
            "SELECT event.event_id, body.json, \
                    EXISTS (SELECT 1 FROM redactions WHERE redactions.redacts = event.event_id) \
             FROM events AS event INNER JOIN event_json AS body USING (event_id) \
             WHERE event.room_id = $1 AND NOT event.outlier AND event.rejection_reason IS NULL \
             ORDER BY md5(event.event_id || 'spindle-563') LIMIT $2",
            &[room_id, &i64::try_from(SAMPLES_PER_ROOM).unwrap_or(5)],
        )? {
            let event_id: String = row.get(0);
            let body: Value = serde_json::from_str(&row.get::<_, String>(1))?;
            let redacted: bool = row.get(2);
            validation.events_sampled += 1;
            if validation.sample_event_ids.len() < 40 {
                validation.sample_event_ids.push(event_id.clone());
            }
            match rooms.event(room_id, &event_id) {
                Ok(served) => {
                    let served_redacted = served["unsigned"]["redacted_because"].is_object();
                    if redacted {
                        // A redaction Synapse holds may itself have been
                        // rejected or soft-failed; only a served redaction
                        // without a Synapse one is wrong.
                        if !served_redacted {
                            validation.sample_mismatches.push(format!(
                                "{room_id} {event_id}: Synapse holds a redaction, Spindle serves the original \
                                 (the redaction may be outside retained history)"
                            ));
                        }
                    } else if served_redacted || comparable(served) != comparable(body) {
                        validation
                            .sample_mismatches
                            .push(format!("{room_id} {event_id}: body differs"));
                    }
                }
                Err(error) => {
                    if excluded_here == 0 {
                        validation
                            .sample_mismatches
                            .push(format!("{room_id} {event_id}: not served: {error}"));
                    }
                }
            }
        }
        rooms.release_imported_room(room_id);
    }
    eprintln!(
        "validate: rooms={} divergent={} short={} sampled={} mismatches={} {:.0}s",
        validation.rooms_checked,
        validation.rooms_divergent.len(),
        validation.rooms_short.len(),
        validation.events_sampled,
        validation.sample_mismatches.len(),
        started.elapsed().as_secs_f64()
    );

    validation.domains.insert(
        "auth_context".to_owned(),
        (auth_context.rows, auth_context.mismatches),
    );
    validation.domains.insert(
        "historical_rejections".to_owned(),
        (historical_rejections.rows, historical_rejections.mismatches),
    );

    let server_name = options.server_name.as_str();
    let in_scope = |user_id: &str| {
        is_local(user_id, server_name)
            && options
                .only_users
                .as_ref()
                .is_none_or(|only| only.contains(user_id))
    };
    let accounts = crate::accounts::Accounts::new(store.as_ref(), server_name);
    let profiles = crate::profiles::Profiles::new(Arc::clone(store));
    let devices = crate::devices::Devices::new(Arc::clone(store));
    let account_data = crate::account_data::AccountData::new(Arc::clone(store));
    let backups = crate::backups::Backups::new(Arc::clone(store));
    let pushers = crate::pushers::Pushers::new(Arc::clone(store));
    let directory = crate::directory::Directory::new(Arc::clone(store), server_name);
    let media = crate::media::Media::new(Arc::clone(store), blobs, server_name);

    let mut users = Check::default();
    for row in snapshot.query(
        "SELECT name, COALESCE(deactivated, 0)::int, COALESCE(admin, 0)::int, \
                EXISTS (SELECT 1 FROM erased_users WHERE erased_users.user_id = users.name) \
         FROM users WHERE COALESCE(is_guest, 0) = 0 ORDER BY name",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let account = accounts.account(localpart(&user_id)).map_err(write_error)?;
        let deactivated = row.get::<_, i32>(1) != 0;
        let admin = row.get::<_, i32>(2) != 0;
        let erased: bool = row.get(3);
        users.expect(
            account.as_ref().is_some_and(|account| {
                account.deactivated == deactivated
                    && account.admin == admin
                    && account.erased == erased
            }),
            || format!("{user_id}: account missing or flags differ"),
        );
    }

    let mut profile_check = Check::default();
    for row in snapshot.query(
        "SELECT full_user_id, displayname, avatar_url FROM profiles WHERE full_user_id IS NOT NULL",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let profile = profiles.get(&user_id).map_err(write_error)?;
        profile_check.expect(
            profile.displayname == row.get::<_, Option<String>>(1)
                && profile.avatar_url == row.get::<_, Option<String>>(2),
            || format!("{user_id}: profile differs"),
        );
    }

    let mut device_check = Check::default();
    for row in snapshot.query(
        "SELECT user_id, device_id FROM devices WHERE NOT COALESCE(hidden, FALSE)",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let device_id: String = row.get(1);
        device_check.expect(
            accounts
                .device(localpart(&user_id), &device_id)
                .map_err(write_error)?
                .is_some(),
            || format!("{user_id} {device_id}: device missing"),
        );
    }

    let mut key_check = Check::default();
    for row in snapshot.query(
        "SELECT keys.user_id, keys.device_id, keys.key_json FROM e2e_device_keys_json AS keys \
         INNER JOIN devices USING (user_id, device_id)",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let device_id: String = row.get(1);
        let source: Value = serde_json::from_str(&row.get::<_, String>(2))?;
        let held = devices
            .device_keys(&user_id, &device_id)
            .map_err(write_error)?;
        key_check.expect(
            held.is_some_and(|held| held["keys"] == source["keys"]),
            || format!("{user_id} {device_id}: device keys differ"),
        );
    }

    let mut cross_check = Check::default();
    for row in snapshot.query(
        "SELECT DISTINCT ON (user_id, keytype) user_id, keytype, keydata \
         FROM e2e_cross_signing_keys WHERE right(user_id, length($1) + 1) = ':' || $1 \
         ORDER BY user_id, keytype, stream_id DESC",
        &[&server_name],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let key_type: String = row.get(1);
        let source: Value = serde_json::from_str(&row.get::<_, String>(2))?;
        let held = devices
            .cross_signing_key(&user_id, &key_type)
            .map_err(write_error)?;
        cross_check.expect(
            held.is_some_and(|held| held["keys"] == source["keys"]),
            || format!("{user_id} {key_type}: cross-signing key differs"),
        );
    }
    let mut signature_check = Check::default();
    // Synapse can hold more than one row for one (signer, key, target): a
    // client that signed the same key again. Any of them held is a match.
    let mut signatures: BTreeMap<(String, String, String, String), Vec<String>> = BTreeMap::new();
    for row in snapshot.query(
        "SELECT user_id, key_id, target_user_id, target_device_id, signature \
         FROM e2e_cross_signing_signatures \
         WHERE right(user_id, length($1) + 1) = ':' || $1",
        &[&server_name],
    )? {
        let signer: String = row.get(0);
        if !in_scope(&signer) {
            continue;
        }
        signatures
            .entry((signer, row.get(1), row.get(2), row.get(3)))
            .or_default()
            .push(row.get(4));
    }
    for ((signer, key_id, target_user, target), values) in signatures {
        let mut held = devices
            .device_keys(&target_user, &target)
            .map_err(write_error)?;
        if held.is_none() {
            for key_type in ["master", "self_signing", "user_signing"] {
                if let Some(key) = devices
                    .cross_signing_key(&target_user, key_type)
                    .map_err(write_error)?
                    && key["keys"].as_object().is_some_and(|keys| {
                        keys.keys().any(|id| id.ends_with(&format!(":{target}")))
                    })
                {
                    held = Some(key);
                }
            }
        }
        // A signature on a key Synapse no longer holds is skipped by the
        // import and reported there; it is not a mismatch here.
        if let Some(held) = held {
            let value = held["signatures"][&signer][&key_id]
                .as_str()
                .unwrap_or_default();
            signature_check.expect(values.iter().any(|candidate| candidate == value), || {
                format!("{signer} on {target_user} {target}: signature missing")
            });
        }
    }

    let mut account_check = Check::default();
    for row in snapshot.query(
        "SELECT user_id, ''::text, account_data_type, content FROM account_data \
         UNION ALL SELECT user_id, room_id, account_data_type, content FROM room_account_data",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let room_id: String = row.get(1);
        let event_type: String = row.get(2);
        let source: Value = serde_json::from_str(&row.get::<_, String>(3))?;
        let held = account_data
            .get(&user_id, &room_id, &event_type)
            .map_err(write_error)?;
        account_check.expect(held.as_ref() == Some(&source), || {
            format!("{user_id} {room_id} {event_type}: account data differs")
        });
    }

    let mut backup_check = Check::default();
    for row in snapshot.query(
        "SELECT user_id, version, count(*) FROM e2e_room_keys GROUP BY 1, 2",
        &[],
    )? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let version = u64::try_from(row.get::<_, i64>(1)).unwrap_or(0);
        let expected = u64::try_from(row.get::<_, i64>(2)).unwrap_or(0);
        let held: u64 = backups
            .keys(&user_id, version)
            .map_err(write_error)?
            .values()
            .map(|room| room["sessions"].as_object().map_or(0, |s| s.len() as u64))
            .sum();
        backup_check.expect(held == expected, || {
            format!("{user_id} backup v{version}: {held} sessions, Synapse {expected}")
        });
    }

    let mut push_check = Check::default();
    for row in snapshot.query("SELECT user_name, rule_id FROM push_rules", &[])? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        let rule_id: String = row.get(1);
        let Some((kind, id)) = split_rule_id(&rule_id) else {
            continue;
        };
        let ruleset = account_data
            .get(&user_id, "", crate::push_rules::TYPE)
            .map_err(write_error)?
            .unwrap_or(Value::Null);
        push_check.expect(
            crate::push_rules::position(&ruleset, kind, id).is_some(),
            || format!("{user_id} {rule_id}: push rule missing"),
        );
    }

    let mut pusher_check = Check::default();
    for row in snapshot.query("SELECT user_name, app_id, pushkey FROM pushers", &[])? {
        let user_id: String = row.get(0);
        if !in_scope(&user_id) {
            continue;
        }
        pusher_check.expect(
            pushers
                .holds(&user_id, &row.get::<_, String>(1), &row.get::<_, String>(2))
                .map_err(write_error)?,
            || format!("{user_id}: pusher missing"),
        );
    }

    let mut receipt_check = Check::default();
    for row in snapshot.query(
        "SELECT room_id, user_id, receipt_type, event_id FROM receipts_linearized \
         WHERE thread_id IS NULL",
        &[],
    )? {
        let room_id: String = row.get(0);
        let user_id: String = row.get(1);
        if !report.rooms.contains_key(&room_id)
            || (is_local(&user_id, server_name) && !in_scope(&user_id))
        {
            continue;
        }
        let receipt_type: String = row.get(2);
        let event_id: String = row.get(3);
        let joined = rooms.is_joined(&user_id, &room_id).map_err(write_error)?;
        if !joined {
            // Skipped by the import, counted there.
            continue;
        }
        let held = rooms
            .receipt(&room_id, &user_id, &receipt_type)
            .map_err(write_error)?;
        // A receipt on an event outside the imported history is skipped
        // by the import; a held receipt must point at the same event.
        if let Some(held) = held {
            receipt_check.expect(held.event_id == event_id, || {
                format!("{room_id} {user_id} {receipt_type}: receipt differs")
            });
        }
    }

    let mut directory_check = Check::default();
    for row in snapshot.query("SELECT room_alias, room_id FROM room_aliases", &[])? {
        let alias: String = row.get(0);
        let room_id: String = row.get(1);
        if !report.rooms.contains_key(&room_id) {
            continue;
        }
        directory_check.expect(
            directory
                .resolve(&alias)
                .map_err(write_error)?
                .is_some_and(|record| record.room_id == room_id),
            || format!("{alias}: does not resolve to {room_id}"),
        );
    }
    for row in snapshot.query("SELECT room_id FROM rooms WHERE is_public", &[])? {
        let room_id: String = row.get(0);
        if !report.rooms.contains_key(&room_id) {
            continue;
        }
        directory_check.expect(
            directory.is_published(&room_id).map_err(write_error)?,
            || format!("{room_id}: not published"),
        );
    }

    let mut media_check = Check::default();
    if let Some(root) = &options.media_root {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(write_error)?;
        for row in snapshot.query(
            "SELECT media_id FROM local_media_repository \
             WHERE url_cache IS NULL AND quarantined_by IS NULL",
            &[],
        )? {
            let media_id: String = row.get(0);
            if media_id.len() < 5 || media_id.contains(['/', '.']) {
                continue;
            }
            let path = root
                .join("local_content")
                .join(&media_id[0..2])
                .join(&media_id[2..4])
                .join(&media_id[4..]);
            let Ok(original) = std::fs::read(&path) else {
                // Missing from Synapse's store: skipped by the import.
                continue;
            };
            let served = runtime.block_on(media.bytes(&media_id));
            media_check.expect(served.is_ok_and(|(_, bytes)| bytes == original), || {
                format!("{media_id}: bytes differ or missing")
            });
        }
    }

    for (name, check) in [
        ("users", users),
        ("profiles", profile_check),
        ("devices", device_check),
        ("device_keys", key_check),
        ("cross_signing_keys", cross_check),
        ("cross_signing_signatures", signature_check),
        ("account_data", account_check),
        ("key_backup_sessions", backup_check),
        ("push_rules", push_check),
        ("pushers", pusher_check),
        ("receipts", receipt_check),
        ("directory", directory_check),
        ("media", media_check),
    ] {
        eprintln!(
            "validate {name}: rows={} mismatches={}",
            check.rows,
            check.mismatches.len()
        );
        validation
            .domains
            .insert(name.to_owned(), (check.rows, check.mismatches));
    }
    report.validation = Some(validation);
    save_checkpoint(&options.checkpoint, report)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// What converting one user's push rules did.
#[derive(Debug, Default)]
pub struct RulesOutcome {
    pub source: u64,
    pub imported: u64,
    pub skipped: BTreeMap<String, u64>,
}

/// Synapse's push rules for one user as a Spindle ruleset.
///
/// Synapse stores a user's own rules in `push_rules` (rule IDs prefixed
/// `global/<kind>/`, kind given by `priority_class`, a higher `priority`
/// first) and every enable switch, for the server's rules too, in
/// `push_rules_enable`. A server rule whose actions the user changed is a
/// `push_rules` row with `priority_class` -1. Spindle stores the whole
/// ruleset as one account-data entry, starting from its own defaults.
#[must_use]
pub fn synapse_ruleset(
    user_id: &str,
    rules: &[(String, i16, String, String)],
    enabled: &[(String, bool)],
) -> (Value, RulesOutcome) {
    let mut ruleset = crate::push_rules::defaults(user_id);
    let mut outcome = RulesOutcome::default();
    let skip = |outcome: &mut RulesOutcome, reason: &str| {
        *outcome.skipped.entry(reason.to_owned()).or_default() += 1;
    };
    // Kinds keep the order Synapse evaluates them in; within a kind the
    // rows arrive highest priority first, and each is appended in turn.
    let mut user_rules: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for (rule_id, class, conditions, actions) in rules {
        outcome.source += 1;
        let Some((kind, id)) = split_rule_id(rule_id) else {
            skip(&mut outcome, "rule ID without a global/<kind>/ prefix");
            continue;
        };
        let Ok(actions) = serde_json::from_str::<Value>(actions) else {
            skip(&mut outcome, "actions are not JSON");
            continue;
        };
        if *class < 0 || crate::push_rules::is_server_default(id) {
            // A server rule with the user's actions.
            if let Some(index) = crate::push_rules::position(&ruleset, kind, id) {
                ruleset[kind][index]["actions"] = actions;
                outcome.imported += 1;
            } else {
                skip(&mut outcome, "server rule Spindle does not define");
            }
            continue;
        }
        let conditions: Value = serde_json::from_str(conditions).unwrap_or_else(|_| json!([]));
        let mut rule = json!({
            "rule_id": id,
            "default": false,
            "enabled": true,
            "actions": actions,
        });
        match kind {
            "content" => {
                let pattern = conditions
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find_map(|condition| condition["pattern"].as_str());
                let Some(pattern) = pattern else {
                    skip(&mut outcome, "content rule without a pattern");
                    continue;
                };
                rule["pattern"] = json!(pattern);
            }
            "room" | "sender" => {}
            _ => rule["conditions"] = conditions,
        }
        user_rules.entry(kind).or_default().push(rule);
        outcome.imported += 1;
    }
    for (kind, rules) in user_rules {
        if let Some(existing) = ruleset[kind].as_array_mut() {
            // Synapse puts a user's rules before the server's in every kind,
            // except that `.m.rule.master` stays first among the overrides.
            let keep_first = usize::from(
                kind == "override"
                    && existing
                        .first()
                        .is_some_and(|rule| rule["rule_id"] == ".m.rule.master"),
            );
            let tail = existing.split_off(keep_first);
            existing.extend(rules);
            existing.extend(tail);
        }
    }
    for (rule_id, on) in enabled {
        let Some((kind, id)) = split_rule_id(rule_id) else {
            continue;
        };
        if let Some(index) = crate::push_rules::position(&ruleset, kind, id) {
            ruleset[kind][index]["enabled"] = Value::Bool(*on);
        } else if crate::push_rules::is_server_default(id) {
            skip(
                &mut outcome,
                "enable switch for a server rule Spindle does not define",
            );
        }
    }
    (ruleset, outcome)
}

fn split_rule_id(rule_id: &str) -> Option<(&'static str, &str)> {
    let rest = rule_id.strip_prefix("global/")?;
    let (kind, id) = rest.split_once('/')?;
    let kind = crate::push_rules::KINDS
        .iter()
        .find(|known| **known == kind)?;
    Some((kind, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_users_rules_land_before_the_defaults_with_their_switches() {
        let rules = vec![
            (
                "global/room/!a:example.org".to_owned(),
                3,
                "[]".to_owned(),
                r#"["dont_notify"]"#.to_owned(),
            ),
            (
                "global/content/hello".to_owned(),
                4,
                r#"[{"kind":"event_match","key":"content.body","pattern":"hello"}]"#.to_owned(),
                r#"["notify"]"#.to_owned(),
            ),
            (
                "global/override/.m.rule.suppress_notices".to_owned(),
                -1,
                "[]".to_owned(),
                r#"["notify"]"#.to_owned(),
            ),
            (
                "global/override/mine".to_owned(),
                5,
                r#"[{"kind":"event_match","key":"type","pattern":"m.call.invite"}]"#.to_owned(),
                r#"["notify"]"#.to_owned(),
            ),
        ];
        let enabled = vec![
            ("global/override/.m.rule.master".to_owned(), true),
            ("global/override/mine".to_owned(), true),
            ("global/room/!a:example.org".to_owned(), false),
            ("global/override/.m.rule.not_in_spindle".to_owned(), false),
        ];
        let (ruleset, outcome) = synapse_ruleset("@u:example.org", &rules, &enabled);
        assert_eq!(outcome.source, 4);
        assert_eq!(outcome.imported, 4);
        assert_eq!(ruleset["override"][0]["rule_id"], ".m.rule.master");
        assert_eq!(ruleset["override"][1]["rule_id"], "mine");
        assert_eq!(
            ruleset["override"][1]["conditions"][0]["pattern"],
            "m.call.invite"
        );
        assert_eq!(ruleset["room"][0]["rule_id"], "!a:example.org");
        assert_eq!(ruleset["room"][0]["enabled"], false);
        assert_eq!(ruleset["content"][0]["pattern"], "hello");
        let master = crate::push_rules::position(&ruleset, "override", ".m.rule.master")
            .expect("the master rule is a default");
        assert_eq!(ruleset["override"][master]["enabled"], true);
        let notices = crate::push_rules::position(&ruleset, "override", ".m.rule.suppress_notices")
            .expect("a default");
        assert_eq!(ruleset["override"][notices]["actions"], json!(["notify"]));
        assert_eq!(outcome.skipped.values().sum::<u64>(), 1);
    }

    #[test]
    fn local_means_the_whole_server_name_after_the_colon() {
        assert!(is_local("@a:reilly.asia", "reilly.asia"));
        assert!(!is_local("@a:notreilly.asia", "reilly.asia"));
        assert!(!is_local("@a:reilly.asia.evil", "reilly.asia"));
        assert_eq!(localpart("@a:reilly.asia"), "a");
    }

    #[test]
    fn switching_from_a_dry_run_cannot_skip_real_writes() {
        let mut report = Report {
            dry_run: true,
            ..Report::default()
        };
        report.phases_done.insert("users".to_owned());
        report
            .rooms
            .insert("!r:example.org".to_owned(), RoomReport::default());
        report.validation = Some(Validation::default());
        report.prepare_mode(false);
        assert!(!report.dry_run);
        assert!(report.phases_done.is_empty());
        assert!(report.rooms.is_empty());
        assert!(report.validation.is_none());
    }

    #[test]
    fn a_checkpoint_in_the_same_mode_keeps_completed_phases() {
        let mut report = Report {
            dry_run: true,
            ..Report::default()
        };
        report.phases_done.insert("users".to_owned());
        report.prepare_mode(true);
        assert!(report.phases_done.contains("users"));
    }

    #[test]
    fn a_checkpoint_round_trips_and_replaces_atomically() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("checkpoint.json");
        assert!(load_checkpoint(&path).expect("absent is fine").is_none());
        let mut report = Report::default();
        report.phases_done.insert("users".to_owned());
        report
            .rooms
            .insert("!r:x".to_owned(), RoomReport::default());
        save_checkpoint(&path, &report).expect("saved");
        report.phases_done.insert("devices".to_owned());
        save_checkpoint(&path, &report).expect("replaced");
        let loaded = load_checkpoint(&path).expect("read").expect("present");
        assert_eq!(loaded.phases_done.len(), 2);
        assert!(loaded.rooms.contains_key("!r:x"));
        assert!(!path.with_extension("tmp").exists());
    }
}
