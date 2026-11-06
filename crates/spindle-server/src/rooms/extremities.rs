//! Merging a room's forward extremities with `org.matrix.dummy_event`s
//! (#626), as Synapse's `_send_dummy_events_to_fill_extremities` does.
//!
//! A room's current state is the resolution of its forward extremities'
//! states. While there are several, every append re-resolves it
//! (`Rooms::settle`), and the resolution cache helps only while no
//! extremity's state moves: one remote state event gives the next resolution
//! inputs it has never seen. A fork normally merges itself, because the next
//! event anyone authors names every tip. A fork can also fail to merge. The
//! tips that came with a Synapse import, or that this server alone holds, are
//! never cited by peers. If no local user speaks in the room, nothing here
//! cites them either. The room then pays for a full resolution of the same
//! conflicted events on each remote state event, forever.
//!
//! The remedy is the one Synapse uses. A local member who may send authors an
//! `org.matrix.dummy_event` with empty content. It goes through the ordinary
//! local send path, which names the newest
//! [`spindle_core::MAX_AUTHORED_PREV_EVENTS`] tips and federates the result,
//! so the room has one extremity here and peers that receive it build on it.
//! A room is merged when it has more extremities than
//! `[rooms] max_forward_extremities`, or when an append left it forked and its
//! oldest extremity is older than `[rooms] stale_forward_extremity_secs`. The
//! second rule catches the stale two- or three-way fork the first never sees.
//! A fork that is merely concurrent, two peers speaking at once, is young and
//! merges by itself. Each room is merged at most once per
//! `dummy_event_interval_secs`, and a pass merges at most
//! [`ROOMS_PER_PASS`] rooms.
//!
//! A dummy event needs a local member who may send. A room where none may,
//! or where `dummy_events` is off, would still resolve against its stuck tips
//! on every remote state event. So each append also prunes, as Synapse's
//! `_prune_extremities` does: when the room's resolution equals the state of
//! some tips, the others lost and contribute nothing to the current state.
//! Those are forgotten if each is someone else's event and old, by Synapse's
//! measures. The current state does not move, and the next event on the
//! winning branch is linear again ([`Rooms::prune_stuck_extremities`]).
//!
//! A dummy event is a timeline event like any other, which is what Synapse
//! sends too, and clients hide it. It never counts toward a reader's unread
//! or notification counts here (`unread`, `push`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_core::{EventId, RoomLog};

use super::{RoomError, Rooms, now_ms};

/// The event type that merges extremities, as Synapse names it.
pub const DUMMY_EVENT_TYPE: &str = "org.matrix.dummy_event";

/// The most rooms one pass merges, as Synapse's five per minute.
pub const ROOMS_PER_PASS: usize = 5;

/// The most local members tried as a dummy event's sender before a room is
/// left for the next interval.
const SENDERS_TRIED: usize = 3;

/// A tip older than this, and [`PRUNE_DEPTH`] behind the event being
/// appended, may be dropped as stuck whoever sent it. Synapse's day.
const PRUNE_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// How far behind the appended event an old stuck tip must be, in depth.
const PRUNE_DEPTH: u64 = 100;

/// How far behind, in depth, a stuck tip from the appended event's own
/// server must be. That server has moved past it by this many events, so
/// it is not merely concurrent.
const PRUNE_SAME_SERVER_DEPTH: u64 = 20;

/// The server part of an event's sender, as Synapse's `get_domain_from_id`.
fn sender_server(event: &Value) -> Option<&str> {
    event["sender"]
        .as_str()?
        .split_once(':')
        .map(|(_, server)| server)
}

/// Whether a tip the resolution overrode is old enough to drop, by
/// Synapse's two rules: a day old and [`PRUNE_DEPTH`] behind, or from the
/// appended event's own server and [`PRUNE_SAME_SERVER_DEPTH`] behind.
/// Anything younger may be a branch that is still live and will merge.
fn stuck_long_enough(tip: &Value, appended: &Value, now: u64) -> bool {
    let depth = tip["depth"].as_u64().unwrap_or(0);
    let current_depth = appended["depth"].as_u64().unwrap_or(0);
    let old = tip["origin_server_ts"]
        .as_u64()
        .is_some_and(|ts| ts < now.saturating_sub(PRUNE_AFTER_MS))
        && depth.saturating_add(PRUNE_DEPTH) < current_depth;
    let same_server = sender_server(tip).is_some_and(|tip| sender_server(appended) == Some(tip))
        && depth.saturating_add(PRUNE_SAME_SERVER_DEPTH) < current_depth;
    old || same_server
}

/// Whether `tip` is an event of `own_server`'s, or a dummy event of ours
/// whose ancestry through other dummy events of ours reaches one. Such a tip
/// stays: the next local event must cite our events so that peers fetch
/// them, and a dummy event that only cites remote events is no such event.
/// A parent `read` cannot find is passed over, as Synapse does.
fn leads_to_own_event(tip: Value, own_server: &str, read: &dyn Fn(&str) -> Option<Value>) -> bool {
    let mut seen: HashSet<String> = HashSet::new();
    let mut pending = vec![tip];
    while let Some(event) = pending.pop() {
        if sender_server(&event) != Some(own_server) {
            continue;
        }
        if !is_dummy_event(&event) {
            return true;
        }
        for parent in super::edge_ids(&event["prev_events"]) {
            if seen.insert(parent.clone())
                && let Some(body) = read(&parent)
            {
                pending.push(body);
            }
        }
    }
    false
}

/// Whether `event` is an `org.matrix.dummy_event`.
#[must_use]
pub fn is_dummy_event(event: &Value) -> bool {
    event["type"].as_str() == Some(DUMMY_EVENT_TYPE)
}

/// When to merge a room's forward extremities.
#[derive(Clone, Copy, Debug)]
pub struct MergePolicy {
    /// Author dummy events at all. The census runs either way.
    pub enabled: bool,
    /// Merge any room with more extremities than this.
    pub max_forward_extremities: usize,
    /// Merge a room an append left forked once its oldest extremity is
    /// older than this.
    pub stale_after: Duration,
    /// The shortest time between two merges of one room.
    pub interval: Duration,
}

impl MergePolicy {
    /// The policy `[rooms]` configures.
    #[must_use]
    pub fn of(config: &crate::config::RoomsConfig) -> Self {
        Self {
            enabled: config.dummy_events,
            max_forward_extremities: config.max_forward_extremities,
            stale_after: Duration::from_secs(config.stale_forward_extremity_secs),
            interval: Duration::from_secs(config.dummy_event_interval_secs),
        }
    }
}

/// Merge bookkeeping shared by the append path and the pass.
#[derive(Debug, Default)]
pub(super) struct Tracker {
    /// Rooms an append left with several extremities since the last pass.
    forked: Mutex<HashSet<String>>,
    /// When each room was last merged or tried, in unix milliseconds.
    attempts: Mutex<HashMap<String, u64>>,
}

impl Tracker {
    pub(super) fn note_forked(&self, room_id: &str) {
        let mut forked = self
            .forked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !forked.contains(room_id) {
            forked.insert(room_id.to_owned());
        }
    }

    fn take_forked(&self) -> HashSet<String> {
        std::mem::take(
            &mut *self
                .forked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Claim `room_id` for a merge at `now`, unless it was claimed within
    /// `interval`.
    fn claim(&self, room_id: &str, now: u64, interval: Duration) -> bool {
        let interval = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Entries past their interval decide nothing, so they go: the map
        // holds only rooms claimed within the last interval.
        attempts.retain(|_, last| now.saturating_sub(*last) < interval);
        if attempts.contains_key(room_id) {
            return false;
        }
        attempts.insert(room_id.to_owned(), now);
        true
    }
}

/// What one pass found and did.
#[derive(Debug, Default)]
pub struct MergePass {
    /// Resident rooms by forward-extremity count, as
    /// [`crate::metrics::EXTREMITY_BUCKETS`].
    pub buckets: [u64; 4],
    /// `(room, dummy event)` for each room merged.
    pub merged: Vec<(String, String)>,
    /// Rooms a merge was due in and could not be made.
    pub failed: usize,
}

impl Rooms {
    /// How many forward extremities `room_id` has.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    pub fn forward_extremity_count(&self, room_id: &str) -> Result<usize, RoomError> {
        self.with_room_read(room_id, |_, log| Ok(log.forward_extremities().len()))
    }

    /// The forward extremities of `room_id`, for tests.
    ///
    /// # Errors
    ///
    /// Returns [`RoomError::UnknownRoom`] if the room does not exist.
    #[doc(hidden)]
    pub fn forward_extremity_ids(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log
                .forward_extremities()
                .iter()
                .map(|tip| tip.as_str().to_owned())
                .collect())
        })
    }

    /// One merge pass over the resident rooms: count them by forward
    /// extremities for the gauge, then merge the rooms `policy` says are due,
    /// most extremities first.
    ///
    /// Only resident rooms are looked at. A room that is not open receives
    /// nothing, so it resolves nothing, and the startup warm-up opens every
    /// room a local user is joined to. A room whose lock is busy is skipped
    /// rather than waited for, and if an append marked it forked, it stays
    /// marked for the next pass.
    #[must_use]
    pub async fn merge_extremities(
        &self,
        key: &Ed25519KeyPair,
        policy: &MergePolicy,
        now: u64,
    ) -> MergePass {
        let open: Vec<(String, Arc<std::sync::RwLock<spindle_core::RoomLog>>)> = self
            .registry_read()
            .iter()
            .map(|(room_id, room)| (room_id.clone(), Arc::clone(room)))
            .collect();
        let forked = self.extremities.take_forked();
        let stale_before =
            now.saturating_sub(u64::try_from(policy.stale_after.as_millis()).unwrap_or(u64::MAX));
        let mut pass = MergePass::default();
        let mut due: Vec<(String, usize)> = Vec::new();
        for (room_id, room) in open {
            let tips: Vec<EventId> = match room.try_read() {
                Ok(log) => log.forward_extremities().iter().cloned().collect(),
                Err(std::sync::TryLockError::Poisoned(log)) => log
                    .into_inner()
                    .forward_extremities()
                    .iter()
                    .cloned()
                    .collect(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if forked.contains(&room_id) {
                        self.extremities.note_forked(&room_id);
                    }
                    continue;
                }
            };
            pass.buckets[crate::metrics::extremity_bucket(tips.len())] += 1;
            if !policy.enabled || tips.len() < 2 {
                continue;
            }
            let crowded = tips.len() > policy.max_forward_extremities;
            let stale = !crowded
                && forked.contains(&room_id)
                && self
                    .oldest_tip_ts(&room_id, &tips)
                    .is_some_and(|ts| ts <= stale_before);
            if crowded || stale {
                due.push((room_id, tips.len()));
            }
        }
        self.metrics.set_extremity_buckets(pass.buckets);

        due.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        for (room_id, count) in due {
            if pass.merged.len() + pass.failed >= ROOMS_PER_PASS {
                break;
            }
            if !self.extremities.claim(&room_id, now, policy.interval) {
                continue;
            }
            match self.send_dummy_event(&room_id, key).await {
                Ok(Some((sender, event_id))) => {
                    self.metrics.record_dummy_event(true);
                    tracing::info!(
                        room = room_id,
                        sender,
                        event_id,
                        forward_extremities = count,
                        "merged forward extremities with a dummy event"
                    );
                    pass.merged.push((room_id, event_id));
                }
                Ok(None) => {
                    tracing::debug!(
                        room = room_id,
                        forward_extremities = count,
                        "no local member can merge this room's forward extremities"
                    );
                }
                Err(error) => {
                    self.metrics.record_dummy_event(false);
                    tracing::warn!(
                        room = room_id,
                        forward_extremities = count,
                        "cannot merge forward extremities: {error}"
                    );
                    pass.failed += 1;
                }
            }
        }
        pass
    }

    /// The `origin_server_ts` of the oldest of `tips` whose body this server
    /// holds, or `None` if it holds none of them.
    fn oldest_tip_ts(&self, room_id: &str, tips: &[EventId]) -> Option<u64> {
        tips.iter()
            .filter_map(|tip| self.read_event(room_id, tip).ok())
            .filter_map(|body| body["origin_server_ts"].as_u64())
            .min()
    }

    /// Author one `org.matrix.dummy_event` in `room_id` from a local joined
    /// member, through the ordinary local send path: the newest tips are its
    /// parents, and it is queued for every server in the room.
    ///
    /// Members are tried by power level, highest first, and a member the
    /// rules refuse makes way for the next. Returns the sender and the
    /// event, or `None` when no local member could send.
    async fn send_dummy_event(
        &self,
        room_id: &str,
        key: &Ed25519KeyPair,
    ) -> Result<Option<(String, String)>, RoomError> {
        let suffix = format!(":{}", self.server_name);
        let roster = self.roster(room_id)?;
        let power = self
            .state_event(room_id, "m.room.power_levels", "")
            .unwrap_or(Value::Null);
        let users_default = super::power_level(&power["users_default"]).unwrap_or(0);
        let mut local: Vec<(i64, &String)> = roster
            .joined
            .iter()
            .filter(|user| user.ends_with(&suffix))
            .map(|user| {
                let level =
                    super::power_level(&power["users"][user.as_str()]).unwrap_or(users_default);
                (level, user)
            })
            .collect();
        local.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
        for (_, sender) in local.into_iter().take(SENDERS_TRIED) {
            match self
                .send_checked(room_id, sender, key, DUMMY_EVENT_TYPE, &json!({}))
                .await
            {
                Ok(event_id) => return Ok(Some((sender.clone(), event_id))),
                Err(RoomError::Forbidden(why)) => {
                    tracing::debug!(
                        room = room_id,
                        sender,
                        "a local member may not send a dummy event: {why}"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Forget the forward extremities whose states lost the room's
    /// resolution, when each is someone else's and has been stuck long
    /// enough (#626), as Synapse's `_prune_extremities`.
    ///
    /// Called after `settle`, whose resolution of the same tips this asks
    /// for again, as a cache hit; asking rather than reading the recorded
    /// current state means a failed resolution cannot pass for this one.
    /// It must run after the append's batch is written: before it, the
    /// appended event's body is not in the store for the resolver to read.
    /// The smaller set reaches the store with the room's next commit, which
    /// writes the extremities; a restart before then brings the stuck tips
    /// back, and the next append drops them again.
    ///
    /// The current state does not move: the kept tips all hold the resolved
    /// state. All the losing tips go or none does, because resolving a
    /// subset could reach another answer.
    ///
    /// A tip that is our own event stays, and so does a dummy event of ours
    /// leading back to one: the next local event must cite it so that peers
    /// fetch it. Such a room has a local member to send one, which is what
    /// the merge pass is for.
    pub(super) fn prune_stuck_extremities(
        &self,
        log: &mut RoomLog,
        room_id: &str,
        appended: &EventId,
        json: &Value,
    ) {
        if log.forward_extremities().len() < 2 {
            return;
        }
        // A failure is `settle`'s to report: it asks the same question.
        let Ok(resolved) = self.resolve_in(log, room_id, |log, resolver, load| {
            log.resolve_current(resolver, load)
        }) else {
            return;
        };
        let root = resolved.root();
        let (keep, dropped): (BTreeSet<EventId>, BTreeSet<EventId>) =
            log.forward_extremities().iter().cloned().partition(|tip| {
                log.state_after_event(tip)
                    .is_some_and(|state| state.root() == root)
            });
        if keep.is_empty() || dropped.is_empty() || dropped.contains(appended) {
            return;
        }
        let now = now_ms();
        let read = |id: &str| self.read_event(room_id, &EventId::new(id)).ok();
        for tip in &dropped {
            let Some(body) = read(tip.as_str()) else {
                return;
            };
            if !stuck_long_enough(&body, json, now)
                || leads_to_own_event(body, &self.server_name, &read)
            {
                return;
            }
        }
        if log.retain_forward_extremities(&keep) {
            self.metrics
                .record_extremities_pruned(u64::try_from(dropped.len()).unwrap_or(u64::MAX));
            tracing::info!(
                room = room_id,
                dropped = dropped.len(),
                kept = keep.len(),
                "dropped stuck forward extremities whose states lost the resolution"
            );
        }
    }
}

/// Run [`Rooms::merge_extremities`] every `tick` for the life of the
/// process, off the async workers. Holds what it reads weakly, as every
/// delivery loop does, and looks every second for its sources being gone,
/// so it ends as promptly as the others once the router is dropped
/// (`delivery_loops.rs`) rather than up to a whole `tick` later.
pub async fn merge_loop(
    rooms: Weak<Rooms>,
    key: Weak<crate::signing::ServerKey>,
    policy: MergePolicy,
    tick: Duration,
) {
    let poll = tick.min(Duration::from_secs(1));
    let mut waited = Duration::ZERO;
    loop {
        tokio::time::sleep(poll).await;
        if rooms.strong_count() == 0 || key.strong_count() == 0 {
            return;
        }
        waited += poll;
        if waited < tick {
            continue;
        }
        waited = Duration::ZERO;
        let (rooms, key) = (rooms.clone(), key.clone());
        let pass = tokio::task::spawn_blocking(move || {
            let (Some(rooms), Some(key)) = (rooms.upgrade(), key.upgrade()) else {
                return false;
            };
            let _ = tokio::runtime::Handle::current().block_on(rooms.merge_extremities(
                key.pair(),
                &policy,
                now_ms(),
            ));
            true
        })
        .await;
        if !matches!(pass, Ok(true)) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::{DUMMY_EVENT_TYPE, Tracker, leads_to_own_event, stuck_long_enough};

    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn event(sender: &str, ts: u64, depth: u64) -> Value {
        json!({
            "type": "m.room.message",
            "sender": sender,
            "origin_server_ts": ts,
            "depth": depth,
            "prev_events": [],
        })
    }

    fn dummy(sender: &str, prev: &[&str]) -> Value {
        json!({ "type": DUMMY_EVENT_TYPE, "sender": sender, "prev_events": prev })
    }

    #[test]
    fn a_losing_tip_is_stuck_when_old_and_deep_or_left_behind_by_its_server() {
        let now = 10 * DAY;
        let appended = event("@p:peer.example", now, 200);
        let stuck = |tip: Value| stuck_long_enough(&tip, &appended, now);
        // Any server's: a day old and more than 100 behind.
        assert!(stuck(event("@o:other.example", now - DAY - 1, 99)));
        assert!(!stuck(event("@o:other.example", now - DAY + 1, 99)));
        assert!(!stuck(event("@o:other.example", now - 2 * DAY, 100)));
        // The appended event's own server: more than 20 behind, at any age.
        assert!(stuck(event("@q:peer.example", now, 179)));
        assert!(!stuck(event("@q:peer.example", now, 180)));
        assert!(!stuck(event("@o:other.example", now, 179)));
    }

    #[test]
    fn our_events_and_our_dummies_leading_to_them_are_ours() {
        let ours = "example.org";
        let bodies: HashMap<&str, Value> = [
            ("$ours", event("@a:example.org", 0, 1)),
            ("$theirs", event("@p:peer.example", 0, 1)),
            ("$dummy-theirs", dummy("@a:example.org", &["$theirs"])),
            (
                "$dummy-dummy",
                dummy("@a:example.org", &["$dummy-theirs", "$unheld"]),
            ),
            (
                "$dummy-ours",
                dummy("@a:example.org", &["$dummy-dummy", "$ours"]),
            ),
        ]
        .into_iter()
        .collect();
        let read = |id: &str| bodies.get(id).cloned();
        let own = |id: &str| leads_to_own_event(bodies[id].clone(), ours, &read);
        assert!(own("$ours"));
        assert!(!own("$theirs"));
        assert!(!own("$dummy-theirs"));
        assert!(!own("$dummy-dummy"), "an unheld parent is passed over");
        assert!(own("$dummy-ours"));
        // A peer's dummy event is the peer's, whatever it cites.
        assert!(!leads_to_own_event(
            dummy("@p:peer.example", &["$ours"]),
            ours,
            &read
        ));
    }

    #[test]
    fn a_room_is_claimed_once_per_interval() {
        let tracker = Tracker::default();
        let interval = Duration::from_secs(300);
        assert!(tracker.claim("!a:x", 1_000_000, interval));
        assert!(!tracker.claim("!a:x", 1_000_000 + 299_999, interval));
        assert!(tracker.claim("!b:x", 1_000_000 + 1, interval));
        assert!(tracker.claim("!a:x", 1_000_000 + 300_000, interval));
    }

    #[test]
    fn expired_claims_are_forgotten() {
        let tracker = Tracker::default();
        let interval = Duration::from_secs(1);
        for index in 0..100_u64 {
            assert!(tracker.claim(&format!("!{index}:x"), index * 1_000, interval));
        }
        assert_eq!(tracker.attempts.lock().unwrap().len(), 1);
    }

    #[test]
    fn forked_rooms_are_taken_once() {
        let tracker = Tracker::default();
        tracker.note_forked("!a:x");
        tracker.note_forked("!a:x");
        tracker.note_forked("!b:x");
        assert_eq!(tracker.take_forked().len(), 2);
        assert!(tracker.take_forked().is_empty());
    }
}
