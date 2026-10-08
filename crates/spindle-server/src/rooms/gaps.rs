//! Federation gaps, the room's half: where history backfilled into the
//! *middle* of a timeline lives, how `/messages` and `/context` stitch it
//! in, and how one verified chunk of it is checked and stored.
//!
//! An event accepted across a gap ([`Rooms::accept_across_gap`]) sits at
//! the next linear index above this server's old head; the history between
//! the two -- everything the room said while this server was away -- is
//! missing. SPEC §5.1 gives backfill the non-positive indices, *below* the
//! whole log, because backfill normally walks back from the earliest event
//! held. This history belongs between two held events instead, and the
//! linear index has no room there by construction: adjacent entries have
//! adjacent integers, and renumbering is what the design rules out.
//!
//! So a filled gap is a **segment**: its events are stored outside the
//! [`RoomLog`] -- they never become forward extremities, never move the
//! room's current state, never take a stream position (so `/sync` never
//! fans them out and push never sees them) -- under positions in a band
//! reserved far below every linear index ([`band`]). A segment is keyed by
//! its anchor, the linear index of the event accepted across the gap, and
//! its events take descending sequence numbers below the anchor as
//! backfill walks back, so one gap's positions are contiguous and in
//! order. `/messages` reads the room in a *stitched* order -- the log's,
//! with each segment spliced in directly below its anchor -- and a
//! pagination token is still `t{position}`: a token inside a segment
//! simply names a band position. A room with no segment pages exactly as
//! before; nothing here is consulted beyond one empty prefix read.
//!
//! What this costs: a segment's events are not in the log's DAG overlay,
//! so they are not served to peers over `/backfill` or
//! `/get_missing_events` (their bodies are, over `/event`), are not
//! searchable, and their relations are not indexed. Visibility is judged
//! at the anchor: a reader sees a segment only if they could see both the
//! old head's side of it and the gap event's.

use std::collections::{BTreeMap, HashMap, HashSet};

use ruma::events::StateEventType;
use ruma::state_res::events::Event as _;
use serde_json::{Value, json};
use spindle_core::{EventId, RoomLog, Sideline, StateKey, StateRoot, StateSnapshot};

use super::{RoomError, Rooms, canonical_to_json, current_state, event_body_key, power_level};
use crate::authorize::StoredEvent;

/// The band of positions segments live in.
///
/// `position = BASE + anchor * SPAN + seq`. The band starts at `-2^62` and
/// ends at `-2^61`, so it can never meet a backfilled linear index (those
/// count down from zero one event at a time) or a live one, and a position
/// decodes back to its anchor and sequence number without a lookup.
pub(crate) mod band {
    /// Positions per gap: the most events one gap's segment can hold.
    pub(crate) const SPAN: i64 = 1 << 20;
    const BASE: i64 = -(1 << 62);
    /// Anchors at or above this cannot be encoded. A room would need two
    /// trillion events first.
    const MAX_ANCHOR: i64 = 1 << 41;
    /// The sequence number of the event directly below the anchor; the
    /// one above it stays free, so "just above the newest segment event"
    /// is still a position in the band.
    pub(crate) const SEQ_TOP: u32 = (1 << 20) - 2;

    /// The position of the segment event `seq` below `anchor`.
    #[must_use]
    pub(crate) fn position(anchor: i64, seq: u32) -> Option<i64> {
        if !(1..MAX_ANCHOR).contains(&anchor) || i64::from(seq) >= SPAN {
            return None;
        }
        Some(BASE + anchor * SPAN + i64::from(seq))
    }

    /// The anchor and sequence number a band position names; `None` for
    /// a position outside the band, which is a linear index.
    #[must_use]
    pub(crate) fn decode(position: i64) -> Option<(i64, u32)> {
        if !(BASE + SPAN..BASE + MAX_ANCHOR * SPAN).contains(&position) {
            return None;
        }
        let offset = position - BASE;
        Some((offset / SPAN, u32::try_from(offset % SPAN).ok()?))
    }

    /// Where a position sorts in the stitched timeline: a linear index at
    /// `(li, 0)`, a segment event just below its anchor at
    /// `(anchor, seq - SPAN)`, which is above everything below the anchor.
    #[must_use]
    pub(crate) fn order(position: i64) -> (i64, i64) {
        match decode(position) {
            Some((anchor, seq)) => (anchor, i64::from(seq) - SPAN),
            None => (position, 0),
        }
    }
}

/// One gap's segment: the sequence numbers its events occupy, inclusive.
pub(crate) type Span = (u32, u32);

/// One event of the stitched timeline.
pub(super) struct Item {
    pub(super) position: i64,
    pub(super) event_id: String,
}

/// Rows read per store scan while walking a segment.
const SEGMENT_BATCH: u32 = 64;

/// A callback over the stitched timeline: `false` stops the walk.
pub(super) type Visit<'v> = dyn FnMut(Item) -> Result<bool, RoomError> + 'v;

/// The stitched order of one room, as one caller may see it.
pub(super) struct Stitch<'a> {
    pub(super) rooms: &'a Rooms,
    pub(super) room_id: &'a str,
    pub(super) log: &'a RoomLog,
    pub(super) spans: &'a BTreeMap<i64, Span>,
    pub(super) visible: &'a (dyn Fn(i64) -> bool + Sync),
}

impl Stitch<'_> {
    /// A segment is visible when both of its sides are: the stretch just
    /// below the anchor and the anchor itself.
    fn segment_visible(&self, anchor: i64) -> bool {
        (self.visible)(anchor.saturating_sub(1)) && (self.visible)(anchor)
    }

    /// Whether a segment event is shown: visible, and not also in the log
    /// (a late fork could place it there; the log's copy wins).
    fn shows(&self, anchor: i64, event_id: &str) -> bool {
        self.segment_visible(anchor) && self.log.get(&EventId::new(event_id)).is_none()
    }

    /// The token for the gap just above the item at `position`: where a
    /// backward page that could not take it resumes, and where a forward
    /// page that took it carries on.
    pub(super) fn above(&self, position: i64) -> i64 {
        if let Some((anchor, seq)) = band::decode(position)
            && self.spans.contains_key(&anchor)
            && let Some(next) = band::position(anchor, seq.saturating_add(1))
        {
            return next;
        }
        let next = position.saturating_add(1);
        // The item above a log entry is the bottom of the segment over it,
        // when the next index anchors one.
        match self.spans.get(&next) {
            Some(&(lo, _)) => band::position(next, lo).unwrap_or(next),
            None => next,
        }
    }

    /// Items strictly below the gap `from` (`None`: the head), newest
    /// first, down to and including the item at `floor`.
    pub(super) fn backward(
        &self,
        from: Option<i64>,
        floor: Option<i64>,
        visit: &mut Visit<'_>,
    ) -> Result<(), RoomError> {
        let floor = floor.map(band::order);
        let below_floor = |position: i64| floor.is_some_and(|floor| band::order(position) < floor);
        let (anchor, offset) = from.map_or((i64::MAX, 0), band::order);
        if let Some(&(lo, hi)) = self.spans.get(&anchor) {
            // A token inside the segment starts below its own item; a
            // token at the anchor starts at the segment's top.
            let top = if offset < 0 {
                u32::try_from(offset + band::SPAN)
                    .ok()
                    .and_then(|seq| seq.checked_sub(1))
            } else {
                Some(hi)
            };
            if let Some(top) = top
                && !self.segment_down(anchor, lo, top, &below_floor, visit)?
            {
                return Ok(());
            }
        }
        for entry in self.log.entries_in(..anchor).rev() {
            let li = entry.li.get();
            if below_floor(li) {
                return Ok(());
            }
            if (self.visible)(li)
                && !visit(Item {
                    position: li,
                    event_id: entry.event_id.as_str().to_owned(),
                })?
            {
                return Ok(());
            }
            if let Some(&(lo, hi)) = self.spans.get(&li)
                && !self.segment_down(li, lo, hi, &below_floor, visit)?
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Items at or above the gap `from` (`None`: the room's start), oldest
    /// first, stopping below the gap `ceiling`.
    pub(super) fn forward(
        &self,
        from: Option<i64>,
        ceiling: Option<i64>,
        visit: &mut Visit<'_>,
    ) -> Result<(), RoomError> {
        let ceiling = ceiling.map(band::order);
        let past_ceiling =
            |position: i64| ceiling.is_some_and(|ceiling| band::order(position) >= ceiling);
        let (anchor, offset) = from.map_or((i64::MIN, 0), band::order);
        if offset < 0
            && let Some(&(lo, hi)) = self.spans.get(&anchor)
        {
            let start = u32::try_from(offset + band::SPAN).unwrap_or(lo).max(lo);
            if !self.segment_up(anchor, start, hi, &past_ceiling, visit)? {
                return Ok(());
            }
        }
        for entry in self.log.entries_in(anchor..) {
            let li = entry.li.get();
            // A segment sits below its anchor, so it comes first -- unless
            // the walk started at the anchor's own gap, which is above it.
            if li > anchor
                && let Some(&(lo, hi)) = self.spans.get(&li)
                && !self.segment_up(li, lo, hi, &past_ceiling, visit)?
            {
                return Ok(());
            }
            if past_ceiling(li) {
                return Ok(());
            }
            if (self.visible)(li)
                && !visit(Item {
                    position: li,
                    event_id: entry.event_id.as_str().to_owned(),
                })?
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// A segment's events from `top` down to `lo`. `false` when the walk
    /// is over: the visitor stopped it, or it reached the floor.
    fn segment_down(
        &self,
        anchor: i64,
        lo: u32,
        top: u32,
        below_floor: &dyn Fn(i64) -> bool,
        visit: &mut Visit<'_>,
    ) -> Result<bool, RoomError> {
        if top < lo || !self.segment_visible(anchor) {
            return Ok(true);
        }
        let mut upper = top;
        loop {
            let lower = upper.saturating_sub(SEGMENT_BATCH - 1).max(lo);
            for (seq, event_id, _) in self
                .rooms
                .gap_rows(self.room_id, anchor, lower, upper)?
                .into_iter()
                .rev()
            {
                let position = band::position(anchor, seq).unwrap_or_default();
                if below_floor(position) {
                    return Ok(false);
                }
                if self.shows(anchor, &event_id) && !visit(Item { position, event_id })? {
                    return Ok(false);
                }
            }
            if lower == lo {
                return Ok(true);
            }
            upper = lower - 1;
        }
    }

    /// A segment's events from `start` up to `hi`.
    fn segment_up(
        &self,
        anchor: i64,
        start: u32,
        hi: u32,
        past_ceiling: &dyn Fn(i64) -> bool,
        visit: &mut Visit<'_>,
    ) -> Result<bool, RoomError> {
        if start > hi || !self.segment_visible(anchor) {
            return Ok(true);
        }
        let mut lower = start;
        loop {
            let upper = lower.saturating_add(SEGMENT_BATCH - 1).min(hi);
            for (seq, event_id, _) in self.rooms.gap_rows(self.room_id, anchor, lower, upper)? {
                let position = band::position(anchor, seq).unwrap_or_default();
                if past_ceiling(position) {
                    return Ok(false);
                }
                if self.shows(anchor, &event_id) && !visit(Item { position, event_id })? {
                    return Ok(false);
                }
            }
            if upper == hi {
                return Ok(true);
            }
            lower = upper + 1;
        }
    }
}

/// The window `/context` returns, in stitched order.
pub(super) struct StitchedContext {
    pub(super) before: Vec<String>,
    pub(super) after: Vec<String>,
    pub(super) start: i64,
    pub(super) end: i64,
    pub(super) root: StateRoot,
}

/// One verified chunk of a gap's history, ready to be checked and stored.
pub struct GapChunk<'a> {
    /// The event accepted across the gap: the marker's key.
    pub anchor_event: &'a str,
    /// The chunk's events, signature- and hash-verified, newest first in
    /// an order where every event comes before its predecessors.
    pub events: &'a [(String, Value)],
    /// `/state_ids` at the chunk's oldest event: the state before it.
    pub state_before: &'a [String],
    /// What the walk still has to fetch after this chunk; empty when every
    /// branch has met history this server holds.
    pub frontier: Vec<String>,
    /// For each frontier event, the depth of the newest event that named
    /// it: the ceiling a bridge over it may not reach above.
    pub bounds: BTreeMap<String, u64>,
    /// Frontier events no participating server would serve, walked over
    /// from what the peer's page held below them.
    pub skipped: Vec<String>,
}

/// What storing one chunk did.
#[derive(Debug, Default)]
pub struct GapChunkOutcome {
    pub inserted: usize,
    pub rejected: usize,
    /// The gap is closed; its marker is gone.
    pub complete: bool,
}

/// The backfill progress a gap marker carries under `"backfill"`.
#[derive(Clone, Debug)]
pub struct GapProgress {
    /// Event IDs the walk still has to fetch.
    pub frontier: Vec<String>,
    /// The sequence number the next segment event takes.
    pub next_seq: u32,
    pub filled: u64,
    pub rejected: u64,
    /// Consecutive failed chunks.
    pub attempts: u32,
    /// Not before this, in milliseconds since the epoch.
    pub next_attempt_ms: u64,
    /// `open`, `complete`, `truncated` or `failed`.
    pub status: String,
    pub last_error: Option<String>,
    /// For each frontier event, the depth of the newest event naming it.
    pub bounds: BTreeMap<String, u64>,
    /// Events the walk had to step over because no server would serve them.
    pub skipped: u64,
}

impl GapProgress {
    /// The progress a marker records, or a fresh walk from the
    /// predecessors it names.
    #[must_use]
    pub fn of(marker: &Value) -> Self {
        let progress = &marker["backfill"];
        let ids = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        if !progress.is_object() {
            return Self {
                frontier: ids(&marker["missing_prev_events"]),
                next_seq: band::SEQ_TOP,
                filled: 0,
                rejected: 0,
                attempts: 0,
                next_attempt_ms: 0,
                status: "open".to_owned(),
                last_error: None,
                bounds: BTreeMap::new(),
                skipped: 0,
            };
        }
        Self {
            frontier: ids(&progress["frontier"]),
            next_seq: progress["next_seq"]
                .as_u64()
                .and_then(|seq| u32::try_from(seq).ok())
                .unwrap_or(band::SEQ_TOP),
            filled: progress["filled"].as_u64().unwrap_or(0),
            rejected: progress["rejected"].as_u64().unwrap_or(0),
            attempts: progress["attempts"]
                .as_u64()
                .and_then(|attempts| u32::try_from(attempts).ok())
                .unwrap_or(0),
            next_attempt_ms: progress["next_attempt_ms"].as_u64().unwrap_or(0),
            status: progress["status"].as_str().unwrap_or("open").to_owned(),
            last_error: progress["last_error"].as_str().map(str::to_owned),
            bounds: progress["bounds"]
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(id, depth)| Some((id.clone(), depth.as_u64()?)))
                .collect(),
            skipped: progress["skipped"].as_u64().unwrap_or(0),
        }
    }

    /// This progress written into `marker`.
    #[must_use]
    pub fn into_marker(self, mut marker: Value) -> Value {
        marker["backfill"] = json!({
            "frontier": self.frontier,
            "next_seq": self.next_seq,
            "filled": self.filled,
            "rejected": self.rejected,
            "attempts": self.attempts,
            "next_attempt_ms": self.next_attempt_ms,
            "status": self.status,
            "last_error": self.last_error,
            "bounds": self.bounds,
            "skipped": self.skipped,
        });
        marker
    }
}

fn encode_span((lo, hi): Span) -> Vec<u8> {
    let mut out = lo.to_be_bytes().to_vec();
    out.extend_from_slice(&hi.to_be_bytes());
    out
}

fn decode_span(bytes: &[u8]) -> Option<Span> {
    Some((
        u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?),
        u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?),
    ))
}

fn encode_row(root: StateRoot, event_id: &str) -> Vec<u8> {
    let mut out = root.as_bytes().to_vec();
    out.extend_from_slice(event_id.as_bytes());
    out
}

fn decode_row(bytes: &[u8]) -> Option<(StateRoot, String)> {
    let root: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    let event_id = std::str::from_utf8(bytes.get(32..)?).ok()?.to_owned();
    Some((StateRoot::from_bytes(root), event_id))
}

/// The domain of a user ID.
fn domain_of(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, domain)| domain)
}

/// What a redaction waiting for its target records.
fn pending_record(redaction_id: &str, sender: &str, power_ok: bool) -> Vec<u8> {
    json!({"redaction": redaction_id, "sender": sender, "power_ok": power_ok})
        .to_string()
        .into_bytes()
}

/// Whether a redaction from `redaction_sender` takes effect on an event
/// from `target_sender`: the same server vouches for both, or the
/// redaction's sender had the power to redact (`power_ok`).
fn redaction_applies(power_ok: bool, redaction_sender: &str, target_sender: &str) -> bool {
    power_ok
        || domain_of(redaction_sender)
            .is_some_and(|domain| domain_of(target_sender) == Some(domain))
}

impl Rooms {
    /// The filled gaps of a room: each anchor's segment span. Empty for
    /// every room that never had a gap backfilled, which is one prefix
    /// read and the whole cost of this to a room without one.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the spans cannot be read.
    pub(crate) fn gap_spans(&self, room_id: &str) -> Result<BTreeMap<i64, Span>, RoomError> {
        let prefix = spindle_core::keys::room_prefix(
            spindle_core::keys::Keyspace::FederationGapSpan,
            room_id,
        );
        Ok(
            spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?
                .into_iter()
                .filter_map(|(key, value)| {
                    Some((spindle_core::keys::li_from_key(&key)?, decode_span(&value)?))
                })
                .collect(),
        )
    }

    /// The segment rows `lo..=hi` below `anchor`, by sequence number.
    fn gap_rows(
        &self,
        room_id: &str,
        anchor: i64,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, String, StateRoot)>, RoomError> {
        let (Some(start), Some(end)) = (
            band::position(anchor, lo),
            band::position(anchor, hi).and_then(|position| position.checked_add(1)),
        ) else {
            return Ok(Vec::new());
        };
        let prefix = spindle_core::keys::room_prefix(
            spindle_core::keys::Keyspace::FederationGapEvent,
            room_id,
        );
        Ok(spindle_store::ReadView::scan_until(
            self.store.as_ref(),
            &prefix,
            &spindle_core::keys::federation_gap_event(room_id, start),
            &spindle_core::keys::federation_gap_event(room_id, end),
        )?
        .into_iter()
        .filter_map(|(key, value)| {
            let position = spindle_core::keys::li_from_key(&key)?;
            let (_, seq) = band::decode(position)?;
            let (root, event_id) = decode_row(&value)?;
            Some((seq, event_id, root))
        })
        .collect())
    }

    /// The event IDs of one anchor's segment rows `lo..=hi`.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the rows cannot be read.
    pub(crate) fn gap_segment_ids(
        &self,
        room_id: &str,
        anchor: i64,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<String>, RoomError> {
        Ok(self
            .gap_rows(room_id, anchor, lo, hi)?
            .into_iter()
            .map(|(_, event_id, _)| event_id)
            .collect())
    }

    /// The depth of the newest event this room's log holds below `anchor`:
    /// the floor under a gap, which history walked across a missing event
    /// must stay above.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room cannot be read.
    pub fn gap_depth_floor(&self, room_id: &str, anchor: i64) -> Result<u64, RoomError> {
        self.with_room_read(room_id, |_, log| {
            Ok(log
                .entry_at_or_before(anchor.saturating_sub(1))
                .map_or(0, |entry| entry.depth))
        })
    }

    /// The band position of a backfilled gap event, if this room holds one.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the index cannot be read.
    pub(crate) fn gap_position(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<Option<i64>, RoomError> {
        Ok(spindle_store::ReadView::get(
            self.store.as_ref(),
            &spindle_core::keys::federation_gap_position(room_id, event_id),
        )?
        .and_then(|bytes| Some(i64::from_be_bytes(bytes.get(..8)?.try_into().ok()?))))
    }

    /// The anchor of the gap a backfilled event fills, if it is one.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the index cannot be read.
    pub(crate) fn gap_anchor_of(
        &self,
        room_id: &str,
        event_id: &str,
    ) -> Result<Option<i64>, RoomError> {
        Ok(self
            .gap_position(room_id, event_id)?
            .and_then(band::decode)
            .map(|(anchor, _)| anchor))
    }

    /// Whether a room has a recorded gap still open.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the markers cannot be read.
    pub fn has_open_gap(&self, room_id: &str) -> Result<bool, RoomError> {
        Ok(self
            .federation_gaps(room_id)?
            .iter()
            .any(|marker| GapProgress::of(marker).status == "open"))
    }

    /// Every recorded gap marker on the server, with its room. The
    /// backfill loop's work list; a handful of rows on any real server.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the markers cannot be read.
    pub fn all_federation_gaps(&self) -> Result<Vec<(String, Value)>, RoomError> {
        let prefix = vec![
            spindle_core::keys::KEY_SCHEMA_VERSION,
            spindle_core::keys::Keyspace::FederationGap as u8,
        ];
        Ok(
            spindle_store::ReadView::scan_prefix(self.store.as_ref(), &prefix)?
                .into_iter()
                .filter_map(|(key, value)| {
                    let room = spindle_core::keys::room_from_prefixed(&key)?.to_owned();
                    Some((room, serde_json::from_slice(&value).ok()?))
                })
                .collect(),
        )
    }

    /// Rewrite one gap marker -- its backfill progress after a chunk that
    /// failed, or a status the loop settled on.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the marker cannot be written.
    pub fn put_federation_gap(
        &self,
        room_id: &str,
        event_id: &str,
        marker: &Value,
    ) -> Result<(), RoomError> {
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::federation_gap(room_id, event_id),
            marker.to_string().as_bytes(),
        )?;
        Ok(())
    }

    /// Remove a gap marker whose backfill finished.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the marker cannot be deleted.
    pub fn delete_federation_gap(&self, room_id: &str, event_id: &str) -> Result<(), RoomError> {
        spindle_store::Store::delete(
            self.store.as_ref(),
            &spindle_core::keys::federation_gap(room_id, event_id),
        )?;
        Ok(())
    }

    /// The remote servers with a member joined to the room right now, the
    /// most-joined first (#620).
    ///
    /// Read from the current state's member events themselves, not from
    /// the membership index, and counting only `join` -- an invite is not
    /// a server in the room, and a server whose users all left answers a
    /// request about the room with 403. Ordered by how many members each
    /// has joined, because the server with the most is the likeliest to
    /// hold the room's history and to still be in it; ties by name, so the
    /// order is stable.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room or a member event cannot be read.
    pub fn participating_servers(&self, room_id: &str) -> Result<Vec<String>, RoomError> {
        let members = self.with_room_read(room_id, |rooms, log| {
            Ok(current_state(log)
                .into_iter()
                .filter(|(key, _)| {
                    key.event_type().as_str() == "m.room.member"
                        && domain_of(key.state_key())
                            .is_some_and(|domain| domain != rooms.server_name)
                })
                .map(|(key, event_id)| (key.state_key().to_owned(), event_id))
                .collect::<Vec<_>>())
        })?;
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (user_id, event_id) in members {
            let Ok(body) = self.read_event(room_id, &EventId::new(event_id.as_str())) else {
                continue;
            };
            if body["content"]["membership"].as_str() != Some(super::JOIN_STR) {
                continue;
            }
            if let Some(domain) = domain_of(&user_id) {
                *counts.entry(domain.to_owned()).or_default() += 1;
            }
        }
        let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        Ok(ranked.into_iter().map(|(domain, _)| domain).collect())
    }

    /// Of `ids`, the ones a gap walk still has to fetch: not in the log,
    /// not set aside there, not rejected before migration, and not already
    /// in a segment. What a walk meets that is held is where it stops.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the room or the segment index cannot be read.
    pub fn gap_unheld(&self, room_id: &str, ids: &[String]) -> Result<Vec<String>, RoomError> {
        let unlogged = self.with_room_read(room_id, |_, log| {
            Ok(ids
                .iter()
                .filter(|id| {
                    let id = EventId::new(id.as_str());
                    log.get(&id).is_none()
                        && log.sidelined(&id).is_none()
                        && !log.historically_rejected(&id)
                })
                .cloned()
                .collect::<Vec<_>>())
        })?;
        let mut out = Vec::with_capacity(unlogged.len());
        for id in unlogged {
            if self.gap_position(room_id, &id)?.is_none() && !out.contains(&id) {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// The stitched `/context` window around `event_id`, which may be a
    /// log entry or a segment event; `None` when the caller cannot see it.
    pub(super) fn stitched_context(
        &self,
        room_id: &str,
        event_id: &str,
        before_limit: usize,
        after_limit: usize,
        visible: &(dyn Fn(i64) -> bool + Sync),
        spans: &BTreeMap<i64, Span>,
    ) -> Result<Option<StitchedContext>, RoomError> {
        let segment = match self.gap_position(room_id, event_id)? {
            Some(position) => band::decode(position).and_then(|(anchor, seq)| {
                self.gap_rows(room_id, anchor, seq, seq)
                    .ok()?
                    .pop()
                    .map(|(_, _, root)| (position, anchor, root))
            }),
            None => None,
        };
        self.with_room_read(room_id, |rooms, log| {
            let stitch = Stitch {
                rooms,
                room_id,
                log,
                spans,
                visible,
            };
            let (target, root) = if let Some(entry) = log.get(&EventId::new(event_id)) {
                if !visible(entry.li.get()) {
                    return Ok(None);
                }
                (entry.li.get(), entry.state_root)
            } else if let Some((position, anchor, root)) = segment {
                if !stitch.segment_visible(anchor) {
                    return Ok(None);
                }
                (position, root)
            } else {
                return Ok(None);
            };
            let mut before: Vec<(i64, String)> = Vec::new();
            stitch.backward(Some(target), None, &mut |item| {
                if before.len() == before_limit {
                    return Ok(false);
                }
                before.push((item.position, item.event_id));
                Ok(true)
            })?;
            let mut after: Vec<(i64, String)> = Vec::new();
            stitch.forward(Some(stitch.above(target)), None, &mut |item| {
                if after.len() == after_limit {
                    return Ok(false);
                }
                after.push((item.position, item.event_id));
                Ok(true)
            })?;
            let start = before.last().map_or(target, |(position, _)| *position);
            let end = stitch.above(after.last().map_or(target, |(position, _)| *position));
            Ok(Some(StitchedContext {
                before: before.into_iter().map(|(_, id)| id).collect(),
                after: after.into_iter().map(|(_, id)| id).collect(),
                start,
                end,
                root,
            }))
        })
    }

    /// Whether `sender` may redact others' events in `state`: their power
    /// reaches the room's `redact` level, or they created the room.
    fn may_redact(
        &self,
        room_id: &str,
        state: &StateSnapshot,
        sender: &str,
        chunk: &HashMap<&str, &Value>,
    ) -> bool {
        let body = |kind: &str| {
            let id = state.get(&StateKey::new(kind, ""))?;
            match chunk.get(id) {
                Some(body) => Some((*body).clone()),
                None => self.read_event(room_id, &EventId::new(id)).ok(),
            }
        };
        if let Some(create) = body("m.room.create")
            && (create["sender"].as_str() == Some(sender)
                || create["content"]["additional_creators"]
                    .as_array()
                    .is_some_and(|creators| creators.iter().any(|user| user == sender)))
        {
            return true;
        }
        let Some(levels) = body("m.room.power_levels") else {
            return false;
        };
        let content = &levels["content"];
        let power = content["users"]
            .get(sender)
            .and_then(power_level)
            .or_else(|| content.get("users_default").and_then(power_level))
            .unwrap_or(0);
        let needed = content.get("redact").and_then(power_level).unwrap_or(50);
        power >= needed
    }

    /// Note a redaction whose target this server does not hold, in a room
    /// with a gap still open: backfill applies it when the target arrives,
    /// so history filled after its redaction is never served unredacted.
    /// A room with no open gap records nothing -- there is nowhere the
    /// target could still come from.
    pub(super) fn note_unheld_redaction(
        &self,
        log: &RoomLog,
        room_id: &str,
        target: &str,
        redaction_id: &str,
        json: &Value,
    ) -> Result<(), RoomError> {
        if !self.has_open_gap(room_id)? {
            return Ok(());
        }
        let sender = json["sender"].as_str().unwrap_or_default();
        let power_ok = log
            .current_state()
            .is_some_and(|state| self.may_redact(room_id, state, sender, &HashMap::new()));
        spindle_store::Store::put(
            self.store.as_ref(),
            &spindle_core::keys::pending_redaction(room_id, target),
            &pending_record(redaction_id, sender, power_ok),
        )?;
        Ok(())
    }

    /// `body` redacted by `redaction_id` under the room's version, with
    /// `unsigned.redacted_because` naming the redaction.
    pub(super) fn redacted_body(
        version: &ruma::RoomVersionId,
        body: &Value,
        redaction_id: &str,
    ) -> Result<Value, RoomError> {
        let ruma::CanonicalJsonValue::Object(object) =
            ruma::CanonicalJsonValue::try_from(body.clone())
                .map_err(|error| RoomError::Build(error.to_string()))?
        else {
            return Err(RoomError::Build(
                "a stored event is not an object".to_owned(),
            ));
        };
        let redacted = spindle_core::version::redact(&object, version)
            .map_err(|error| RoomError::Build(format!("cannot redact: {error}")))?;
        let mut json = canonical_to_json(&redacted);
        if let Some(map) = json.as_object_mut() {
            map.insert(
                "unsigned".to_owned(),
                json!({ "redacted_because": { "event_id": redaction_id } }),
            );
        }
        Ok(json)
    }

    /// The state the peer named before a chunk's oldest event, checked the
    /// way [`Self::accept_across_gap`] checks it: every entry a stored,
    /// unrejected state event of this room, one per key, and the room's
    /// own create event among them.
    fn gap_state(
        &self,
        log: &RoomLog,
        room_id: &str,
        state_before: &[String],
        create_id: &str,
    ) -> Result<StateSnapshot, RoomError> {
        let mut state = StateSnapshot::new();
        for state_id in state_before {
            let held = EventId::new(state_id.as_str());
            if log.historically_rejected(&held)
                || log
                    .sidelined(&held)
                    .is_some_and(|entry| entry.kind == Sideline::Rejected)
            {
                return Err(RoomError::Forbidden(format!(
                    "the peer's state names {state_id}, which this room rejected"
                )));
            }
            let body = self.read_event(room_id, &held)?;
            let (Some(kind), Some(state_key)) = (body["type"].as_str(), body["state_key"].as_str())
            else {
                return Err(RoomError::Forbidden(format!(
                    "the peer's state names {state_id}, which is not a state event"
                )));
            };
            if kind == "m.room.create" && state_id != create_id {
                return Err(RoomError::Forbidden(
                    "the peer's state names another create event".to_owned(),
                ));
            }
            let key = StateKey::new(kind, state_key);
            if state.get(&key).is_some_and(|other| other != state_id) {
                return Err(RoomError::Forbidden(format!(
                    "the peer's state names two events for {kind}/{state_key}"
                )));
            }
            state = state.apply(key, state_id.as_str());
        }
        if state
            .get(&StateKey::new("m.room.create", ""))
            .is_none_or(|named| named != create_id)
        {
            return Err(RoomError::Forbidden(
                "the peer's state does not name this room's create event".to_owned(),
            ));
        }
        Ok(state)
    }

    /// Judge one backfilled event against its own auth events and the
    /// state before it: `None` to place it, or why it is kept out.
    ///
    /// The first two of the spec's checks on receipt of a PDU. The third,
    /// against the room's current state, does not apply: history is not
    /// judged by what happened after it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the checks' inputs, each one named by the spec"
    )]
    fn gap_checks(
        &self,
        log: &RoomLog,
        room_id: &str,
        rules: &ruma::room_version_rules::RoomVersionRules,
        event_id: &str,
        json: &Value,
        state_before: &StateSnapshot,
        chunk: &HashMap<&str, &Value>,
        rejected: &HashSet<String>,
    ) -> Option<String> {
        let Ok(candidate) = StoredEvent::parse_in(event_id, room_id, json) else {
            return Some("malformed".to_owned());
        };
        if json["type"].as_str() == Some("m.room.create") {
            return Some("a second create event".to_owned());
        }
        let fetch = |id: &ruma::EventId| -> Option<StoredEvent> {
            let body = match chunk.get(id.as_str()) {
                Some(body) => (*body).clone(),
                None => self.read_event(room_id, &EventId::new(id.as_str())).ok()?,
            };
            let event = StoredEvent::parse_auth_in(id.as_str(), room_id, &body).ok()?;
            let held = EventId::new(id.as_str());
            let is_rejected = rejected.contains(id.as_str())
                || log
                    .sidelined(&held)
                    .is_some_and(|entry| entry.kind == Sideline::Rejected);
            Some(
                event
                    .with_rejected(is_rejected)
                    .with_preserved_rejection(log.historically_rejected(&held)),
            )
        };

        // 1. Its auth events.
        if let Err(why) = ruma::state_res::check_state_independent_auth_rules(
            &rules.authorization,
            candidate.clone(),
            fetch,
        ) {
            return Some(format!("auth events: {why}"));
        }
        let mut named: HashMap<(StateEventType, String), StoredEvent> = HashMap::new();
        for id in candidate.auth_event_ids() {
            let Some(event) = fetch(id) else {
                return Some(format!("auth event {id} is not held"));
            };
            if let Some(key) = event.state_key() {
                named.insert(
                    (
                        StateEventType::from(event.event_type().to_string()),
                        key.to_owned(),
                    ),
                    event,
                );
            }
        }
        if rules.authorization.room_create_event_id_as_room_id
            && let Some(hash) = room_id.strip_prefix('!')
            && let Ok(create_id) = ruma::OwnedEventId::try_from(format!("${hash}"))
            && let Some(create) = fetch(&create_id)
        {
            named.insert((StateEventType::RoomCreate, String::new()), create);
        }
        if let Err(why) =
            crate::authorize::authorize(&rules.authorization, &candidate, |kind, key| {
                named
                    .get(&(kind.clone(), key.to_owned()))
                    .filter(|event| !event.rejected())
                    .cloned()
            })
        {
            return Some(format!("auth events: {why}"));
        }

        // 2. The state before it.
        if let Err(why) =
            crate::authorize::authorize(&rules.authorization, &candidate, |kind, key| {
                let id = state_before.get(&StateKey::new(kind.to_string().as_str(), key))?;
                fetch(&ruma::OwnedEventId::try_from(id).ok()?).filter(|event| !event.rejected())
            })
        {
            return Some(why);
        }
        None
    }

    /// Check and store one verified chunk of a gap's history, below the
    /// event accepted across the gap, and record how far the walk got --
    /// in one atomic write, so a crash or a refusal leaves the previous
    /// chunk's progress exactly as it was.
    ///
    /// Each event is judged against its auth events and against the state
    /// before it, folded forward from the chunk's `/state_ids` (SPEC
    /// §6.5); one that fails is walked through but not shown. Nothing here
    /// touches the room's log: no extremity, no current state, no stream
    /// position, so nothing is fanned out, synced as new or pushed.
    ///
    /// Redactions are applied as they would have been live: a redaction in
    /// the chunk rewrites its target if the target is held (or in the
    /// chunk), and is otherwise kept until the target arrives; a held
    /// redaction waiting for an event in the chunk rewrites it before it
    /// is first stored. Either takes effect only if its sender had the
    /// power to redact or shares the target sender's server.
    ///
    /// # Errors
    /// [`RoomError::Forbidden`] when the peer's state is not a state of
    /// this room; [`RoomError::MissingBody`] for a state or auth event the
    /// caller did not retain; [`RoomError`] for a failed read or write.
    #[allow(
        clippy::too_many_lines,
        reason = "one chunk's checks, placement and atomic write, in order"
    )]
    pub fn commit_gap_chunk(
        &self,
        room_id: &str,
        chunk: &GapChunk<'_>,
    ) -> Result<GapChunkOutcome, RoomError> {
        let marker_key = spindle_core::keys::federation_gap(room_id, chunk.anchor_event);
        let marker: Value = spindle_store::ReadView::get(self.store.as_ref(), &marker_key)?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| RoomError::UnknownState("the gap marker".to_owned()))?;
        let anchor = marker["li"]
            .as_i64()
            .ok_or_else(|| RoomError::Build("the gap marker names no position".to_owned()))?;
        let mut progress = GapProgress::of(&marker);
        let span_key = spindle_core::keys::federation_gap_span(room_id, anchor);
        let purge_mark = self.purge_watermark(room_id)?;

        self.with_room_read(room_id, |rooms, log| {
            let version = rooms.version_in_log(log, room_id)?;
            if spindle_core::is_state_dag(&version) {
                return Err(RoomError::Append(
                    "a state-DAG room's history cannot be folded from /state_ids".to_owned(),
                ));
            }
            let rules = rooms.rules_in(log, room_id)?;
            let create_id = super::current_state_id(log, &StateKey::new("m.room.create", ""))
                .ok_or_else(|| RoomError::Append("the room has no create event".to_owned()))?;

            let mut outcome = GapChunkOutcome::default();
            let mut placed: Vec<(String, StateRoot)> = Vec::new();
            let mut writes: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut bodies: HashMap<String, Value> = HashMap::new();
            // Placed events whose body a redaction rewrote here.
            let mut rewritten: HashSet<String> = HashSet::new();
            if !chunk.events.is_empty() {
                let mut state = rooms.gap_state(log, room_id, chunk.state_before, &create_id)?;
                // Only the nodes the room's current state lacks: the
                // chunk's state is usually that state less a few changes.
                for (address, node) in state.delta_nodes(log.current_state()) {
                    writes.push((
                        spindle_core::keys::content_addressed(
                            spindle_core::keys::Keyspace::StateNode,
                            address.as_bytes(),
                        ),
                        node,
                    ));
                }
                let lookup: HashMap<&str, &Value> = chunk
                    .events
                    .iter()
                    .map(|(id, body)| (id.as_str(), body))
                    .collect();
                let mut rejected: HashSet<String> = HashSet::new();
                // Redactions this chunk carries: target -> (redaction, its
                // sender, whether that sender could redact anyone's event).
                let mut redactions: HashMap<String, (String, String, bool)> = HashMap::new();

                for (event_id, json) in chunk.events.iter().rev() {
                    let id = EventId::new(event_id.as_str());
                    if log.get(&id).is_some() || rooms.gap_position(room_id, event_id)?.is_some() {
                        continue;
                    }
                    if let Some(held_room) = spindle_store::ReadView::get(
                        rooms.store.as_ref(),
                        &spindle_core::keys::event_room(event_id),
                    )? && held_room != room_id.as_bytes()
                    {
                        rejected.insert(event_id.clone());
                        outcome.rejected += 1;
                        continue;
                    }
                    if let Some(why) = rooms.gap_checks(
                        log, room_id, &rules, event_id, json, &state, &lookup, &rejected,
                    ) {
                        tracing::debug!(
                            room = room_id,
                            event_id = %event_id,
                            "kept a backfilled event out of the timeline: {why}"
                        );
                        rejected.insert(event_id.clone());
                        outcome.rejected += 1;
                        continue;
                    }
                    if let Some(target) = rooms.redaction_target(log, room_id, json)? {
                        let sender = json["sender"].as_str().unwrap_or_default().to_owned();
                        let power_ok = rooms.may_redact(room_id, &state, &sender, &lookup);
                        redactions.insert(target, (event_id.clone(), sender, power_ok));
                    }
                    if let (Some(kind), Some(state_key)) =
                        (json["type"].as_str(), json["state_key"].as_str())
                    {
                        let before = state.clone();
                        state = state.apply(StateKey::new(kind, state_key), event_id.as_str());
                        for (address, node) in state.delta_nodes(Some(&before)) {
                            writes.push((
                                spindle_core::keys::content_addressed(
                                    spindle_core::keys::Keyspace::StateNode,
                                    address.as_bytes(),
                                ),
                                node,
                            ));
                        }
                    }
                    placed.push((event_id.clone(), state.root()));
                    bodies.insert(event_id.clone(), (*json).clone());
                }

                // Redactions: the chunk's own, then the ones held for it.
                for (target, (redaction_id, sender, power_ok)) in &redactions {
                    let target_body = match bodies.get(target) {
                        Some(body) => Some(body.clone()),
                        None => match rooms.read_event(room_id, &EventId::new(target.as_str())) {
                            Ok(body) => Some(body),
                            Err(RoomError::MissingBody(_)) => None,
                            Err(error) => return Err(error),
                        },
                    };
                    let Some(target_body) = target_body else {
                        writes.push((
                            spindle_core::keys::pending_redaction(room_id, target),
                            pending_record(redaction_id, sender, *power_ok),
                        ));
                        continue;
                    };
                    if !redaction_applies(
                        *power_ok,
                        sender,
                        target_body["sender"].as_str().unwrap_or_default(),
                    ) {
                        continue;
                    }
                    let redacted = Self::redacted_body(&version, &target_body, redaction_id)?;
                    if bodies.contains_key(target) {
                        bodies.insert(target.clone(), redacted);
                        rewritten.insert(target.clone());
                    } else {
                        writes.push((
                            event_body_key(room_id, target),
                            serde_json::to_vec(&redacted)?,
                        ));
                    }
                }
                for (event_id, _) in &placed {
                    let pending_key = spindle_core::keys::pending_redaction(room_id, event_id);
                    let Some(pending) =
                        spindle_store::ReadView::get(rooms.store.as_ref(), &pending_key)?
                            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    else {
                        continue;
                    };
                    let (Some(redaction_id), Some(sender)) =
                        (pending["redaction"].as_str(), pending["sender"].as_str())
                    else {
                        continue;
                    };
                    let Some(body) = bodies.get(event_id) else {
                        continue;
                    };
                    if redaction_applies(
                        pending["power_ok"].as_bool().unwrap_or(false),
                        sender,
                        body["sender"].as_str().unwrap_or_default(),
                    ) {
                        let redacted = Self::redacted_body(&version, body, redaction_id)?;
                        bodies.insert(event_id.clone(), redacted);
                        rewritten.insert(event_id.clone());
                    }
                    // Spent either way; an empty row is a tombstone until
                    // the delete after the commit.
                    writes.push((pending_key, Vec::new()));
                }
            }

            // Positions, newest first from where the last chunk stopped.
            let needed = u32::try_from(placed.len()).unwrap_or(u32::MAX);
            if needed > progress.next_seq.saturating_add(1) {
                return Err(RoomError::Append(
                    "the gap's segment has no positions left".to_owned(),
                ));
            }
            let mut seq = progress.next_seq;
            let mut lowest = None;
            for (event_id, root) in placed.iter().rev() {
                let position = band::position(anchor, seq).ok_or_else(|| {
                    RoomError::Append("the gap event's position cannot anchor a segment".to_owned())
                })?;
                writes.push((
                    spindle_core::keys::federation_gap_event(room_id, position),
                    encode_row(*root, event_id),
                ));
                writes.push((
                    spindle_core::keys::federation_gap_position(room_id, event_id),
                    position.to_be_bytes().to_vec(),
                ));
                writes.push((
                    spindle_core::keys::event_room(event_id),
                    room_id.as_bytes().to_vec(),
                ));
                let body = bodies.get(event_id).ok_or_else(|| {
                    RoomError::Build(format!("placed event {event_id} has no body"))
                })?;
                // A body already held -- a state event retained for a gap
                // acceptance's /state_ids -- is kept unless a redaction
                // rewrote it here.
                let held = spindle_store::ReadView::get(
                    rooms.store.as_ref(),
                    &event_body_key(room_id, event_id),
                )?
                .is_some();
                // History an operator purged up to here is not brought
                // back by a backfill that finishes afterwards: its message
                // bodies stay purged, as the log's below the watermark do.
                let purged = purge_mark.is_some_and(|mark| anchor <= mark)
                    && body.get("state_key").is_none();
                if !purged && (!held || rewritten.contains(event_id)) {
                    writes.push((event_body_key(room_id, event_id), serde_json::to_vec(body)?));
                }
                lowest = Some(seq);
                seq = seq.saturating_sub(1);
            }
            if let Some(lowest) = lowest {
                let span = spindle_store::ReadView::get(rooms.store.as_ref(), &span_key)?
                    .as_deref()
                    .and_then(decode_span)
                    .map_or((lowest, progress.next_seq), |(lo, hi)| (lo.min(lowest), hi));
                writes.push((span_key.clone(), encode_span(span)));
                progress.next_seq = lowest.saturating_sub(1);
            }

            outcome.inserted = placed.len();
            outcome.complete = chunk.frontier.is_empty();
            progress.filled = progress
                .filled
                .saturating_add(u64::try_from(placed.len()).unwrap_or(u64::MAX));
            progress.rejected = progress
                .rejected
                .saturating_add(u64::try_from(outcome.rejected).unwrap_or(u64::MAX));
            progress.frontier.clone_from(&chunk.frontier);
            progress.bounds = chunk
                .bounds
                .iter()
                .filter(|(id, _)| chunk.frontier.contains(id))
                .map(|(id, depth)| (id.clone(), *depth))
                .collect();
            progress.skipped = progress
                .skipped
                .saturating_add(u64::try_from(chunk.skipped.len()).unwrap_or(u64::MAX));
            progress.attempts = 0;
            progress.next_attempt_ms = 0;
            progress.last_error = None;
            if outcome.complete {
                "complete".clone_into(&mut progress.status);
            }
            writes.push((
                marker_key.clone(),
                progress
                    .into_marker(marker.clone())
                    .to_string()
                    .into_bytes(),
            ));
            spindle_store::Store::commit(
                rooms.store.as_ref(),
                &writes,
                spindle_store::Durability::Group,
            )?;
            // What a batch cannot do is delete: the spent pending rows and a
            // finished marker were written as tombstones above, and go now.
            // A crash before this leaves only rows the next pass ignores.
            for (key, value) in &writes {
                if value.is_empty() {
                    spindle_store::Store::delete(rooms.store.as_ref(), key)?;
                }
            }
            if outcome.complete {
                spindle_store::Store::delete(rooms.store.as_ref(), &marker_key)?;
            }
            Ok(outcome)
        })
    }

    /// The span of one anchor's segment, for tests and the admin view.
    ///
    /// # Errors
    /// Returns [`RoomError`] if the span cannot be read.
    pub fn gap_segment_len(&self, room_id: &str, anchor: i64) -> Result<usize, RoomError> {
        Ok(self
            .gap_spans(room_id)?
            .get(&anchor)
            .map_or(0, |&(lo, hi)| {
                usize::try_from(hi.saturating_sub(lo)).map_or(usize::MAX, |len| len + 1)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::band;

    /// A position decodes back to its anchor and sequence number, and the
    /// band never meets a linear index, live or backfilled.
    #[test]
    fn band_positions_round_trip_and_stay_clear_of_linear_indices() {
        for anchor in [1_i64, 2, 1_000, 9_999_999, (1 << 41) - 1] {
            for seq in [0_u32, 1, 500, band::SEQ_TOP, band::SEQ_TOP + 1] {
                let position = band::position(anchor, seq).unwrap();
                assert_eq!(band::decode(position), Some((anchor, seq)));
                assert!(position < -(1 << 61), "below every backfilled index");
            }
        }
        assert_eq!(band::position(0, 0), None, "li 0 is never an anchor");
        assert_eq!(band::position(1 << 41, 0), None);
        assert_eq!(band::position(1, 1 << 20), None);
        for li in [i64::MAX, 1, 0, -1, -1_000_000, -(1 << 61)] {
            assert_eq!(band::decode(li), None, "{li} is a linear index");
        }
    }

    /// The stitched order: a segment sorts below its anchor and above
    /// everything below the anchor, its own events in sequence order.
    #[test]
    fn a_segment_sorts_between_its_anchor_and_the_entry_below() {
        let anchor = 42;
        let low = band::order(band::position(anchor, 0).unwrap());
        let high = band::order(band::position(anchor, band::SEQ_TOP).unwrap());
        assert!(band::order(anchor - 1) < low);
        assert!(low < high);
        assert!(high < band::order(anchor));
        assert!(band::order(band::position(anchor - 1, band::SEQ_TOP).unwrap()) < low);
        assert!(band::order(anchor - 1) > band::order(band::position(anchor - 1, 7).unwrap()));
    }
}
