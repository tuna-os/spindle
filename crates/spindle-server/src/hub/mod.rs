//! MSC3995 linearized hub mode between Spindle peers (#22).
//!
//! Compiled only with the `hub-mode` cargo feature, and dormant even then
//! until `[federation.hub] enabled = true`. SPEC section 12.6 is the design;
//! this is the summary a reader of the code needs.
//!
//! **What a hub room is.** An ordinary room -- any room version, every peer
//! an ordinary homeserver to every other -- in which the room creator's
//! server has sent an `m.room.hub` state event naming itself (MSC3995: the
//! hub is the server of that event's sender). Hub mode is an overlay on
//! that room among the servers that speak it, never a property of the room
//! that a server which does not speak it has to know about.
//!
//! **Ordering** (`submit`). A participant builds its event exactly as it
//! would anyway and submits it to the hub before anyone else sees it. The
//! hub appends it only if it names the hub's current head
//! (`Rooms::hub_sequence`, under the room lock its own appends take);
//! otherwise it answers 409 with the events the participant is missing.
//! Once placed, the event's origin fans it out the ordinary way, so a server
//! that does not speak hub mode sees ordinary events, each with one parent.
//!
//! **Attestations and checkpoints** (`attest`). The hub signs `(room_id,
//! hub, epoch, li, event_id, chain[li])` for every entry it sequences, and
//! every `checkpoint_interval` entries a checkpoint that adds the state
//! root. Both go to hub-mode participants only, in an EDU. Participants
//! check each against its neighbours and keep two that cannot both be true
//! as a portable proof; a participant with no history anchors on a fresh
//! checkpoint instead of replaying the room.
//!
//! **Epochs** (`epoch`). Every `m.room.hub` after the first names the one
//! before it and states the outgoing hub's last attested entry. A planned
//! handoff carries the outgoing hub's co-signature. A failover, when the
//! hub is unreachable, may be claimed only by the first backup the outgoing
//! epoch listed. Either way, a server refuses an epoch that would drop an
//! entry it holds an attestation for, and keeps the claim and that
//! attestation as a proof: **failover cannot truncate an attested prefix**.
//!
//! **Failure.** A hub that cannot be reached costs a participant only the
//! hub's guarantee: the event it built is sent the ordinary way, and the
//! room heals as any room does. Liveness is never traded for ordering in
//! an ordinary room version (SPEC section 13.1).

mod attest;
mod epoch;
mod metrics;
mod submit;

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};

use crate::AppState;
use crate::federation::FederationError;

pub(crate) use attest::takes_edu;
pub use attest::{attestations, chain_step_holds, checkpoints, proofs};
pub use epoch::{Designation, designation, designation_explained};
pub use metrics::{HubCounts, HubMetrics};
pub(crate) use submit::{send_with_transaction, try_handoff, try_send};

/// Where every hub endpoint lives. Spindle's namespace, not the MSC's: the
/// MSC defines none of these endpoints, so none may squat its prefix.
pub const UNSTABLE_PREFIX: &str = "/_matrix/federation/unstable/org.spindle.msc3995";

/// The key the capability answer is under.
pub const CAPABILITY_KEY: &str = "org.spindle.msc3995";

/// The EDU a hub sends its attestations and checkpoints in.
pub const ATTESTATION_EDU: &str = "org.spindle.msc3995.attestations";

/// The hub's answer to an event that does not name its head.
pub const STALE_ERRCODE: &str = "ORG.SPINDLE.MSC3995_STALE_HEAD";

/// The answer of a server asked to sequence a room it does not hub.
pub const NOT_HUB_ERRCODE: &str = "ORG.SPINDLE.MSC3995_NOT_HUB";

/// The outgoing hub's answer to a handoff naming the wrong final entry.
pub const WRONG_FINAL_ERRCODE: &str = "ORG.SPINDLE.MSC3995_WRONG_FINAL";

/// `m.room.hub` content: the epoch this event opens.
pub const EPOCH_KEY: &str = "org.spindle.epoch";
/// `m.room.hub` content: the `m.room.hub` event of the epoch before.
pub const PREV_HUB_KEY: &str = "org.spindle.prev_hub_event";
/// `m.room.hub` content: the outgoing epoch's last attested entry,
/// `{li, event_id, chain}`, or `null` when it attested nothing.
pub const PREV_FINAL_KEY: &str = "org.spindle.prev_epoch_final";
/// `m.room.hub` content: `true` on a failover claim.
pub const FAILOVER_KEY: &str = "org.spindle.failover";
/// `m.room.hub` content: who may claim the next epoch if this hub fails,
/// in order; only the first may.
pub const BACKUPS_KEY: &str = "org.spindle.backups";

/// Hub mode's process state.
#[derive(Default)]
pub struct Hub {
    /// Peer -> (speaks hub mode, when that was learned, for how long).
    capable: Mutex<HashMap<String, (bool, Instant, Duration)>>,
    /// `(room, epoch)` -> the last position this server attested as that
    /// epoch's hub.
    attested: Mutex<HashMap<(String, u64), i64>>,
    /// Room -> when its hub stopped answering, since its last answer.
    unreachable: Mutex<HashMap<String, Instant>>,
    /// `m.room.hub` event -> whether the outgoing hub's co-signature on it
    /// verified. A signature does not change, so neither does the answer.
    cosigned: Mutex<HashMap<String, bool>>,
    /// `(room, epoch)` -> the highest attestation held, once read.
    highest: Mutex<HashMap<(String, u64), Value>>,
    /// `(room, epoch)` this server has asked the hub for a checkpoint for.
    anchored: Mutex<HashSet<(String, u64)>>,
}

impl Hub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// A poisoned lock still holds a usable map.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The server part of a user ID.
fn server_of(user_id: &str) -> Option<&str> {
    user_id.split_once(':').map(|(_, domain)| domain)
}

/// Whether this server holds `event_id` in `room_id`'s log.
fn holds(state: &AppState, room_id: &str, event_id: &str) -> bool {
    state
        .rooms
        .hub_position(room_id, event_id)
        .ok()
        .flatten()
        .is_some()
}

/// The hub endpoints. Mounted only with `[federation.hub] enabled`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/capabilities",
            get(capabilities),
        )
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/submit/{room_id}",
            post(submit::submit),
        )
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/handoff/{room_id}",
            post(submit::handoff),
        )
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/attested/{room_id}",
            get(attest::attested),
        )
        .route(
            "/_matrix/federation/unstable/org.spindle.msc3995/checkpoint/{room_id}",
            get(attest::checkpoint),
        )
}

/// `GET .../org.spindle.msc3995/capabilities`: "this server speaks hub
/// mode". Unauthenticated, like `/federation/v1/version`: it says what the
/// server is, nothing about any room.
///
/// MSC3995's own advertisement, `"m.linearized": true` on the key document,
/// means "not DAG-capable" -- the opposite of what Spindle is -- so it is
/// not used.
async fn capabilities() -> Json<Value> {
    Json(json!({
        CAPABILITY_KEY: {
            "hub": true,
            "participant": true,
            "ordering": "compare-and-append",
            "attestations": 1,
            "epochs": ["handoff", "failover"],
            "checkpoints": 1,
        }
    }))
}

/// Attest whatever this hub has sequenced in `room_id` since it last did,
/// to every hub-speaking server in the room, in the background.
pub(crate) fn after_local_send(state: &AppState, room_id: &str) {
    if state.config.federation.hub.enabled {
        attest::spawn_attestations(state, room_id);
    }
}

/// Whether `server` speaks hub mode, from the cache or by asking it.
///
/// A definite answer -- the capability document, or a refusal such as
/// Synapse's `404 M_UNRECOGNIZED` -- is believed for
/// `capability_ttl_ms`. No answer at all is believed for a few seconds,
/// as "no", so a peer that is down costs one probe per window rather than
/// one per event.
async fn is_capable(state: &AppState, server: &str) -> bool {
    const UNANSWERED_TTL: Duration = Duration::from_secs(10);
    if server == state.config.server.name {
        return true;
    }
    if let Some((capable, learned, ttl)) = lock(&state.hub.capable).get(server)
        && learned.elapsed() < *ttl
    {
        return *capable;
    }
    let config = &state.config.federation.hub;
    let probe = tokio::time::timeout(
        Duration::from_millis(config.submit_timeout_ms),
        state
            .federation
            .hub_request(server, &format!("{UNSTABLE_PREFIX}/capabilities"), None),
    )
    .await;
    let (capable, ttl) = match probe {
        Ok(Ok(answer)) => (
            answer[CAPABILITY_KEY]["hub"] == json!(true),
            Duration::from_millis(config.capability_ttl_ms),
        ),
        Ok(Err(FederationError::Answered { .. })) => {
            (false, Duration::from_millis(config.capability_ttl_ms))
        }
        _ => (false, UNANSWERED_TTL),
    };
    lock(&state.hub.capable).insert(server.to_owned(), (capable, Instant::now(), ttl));
    capable
}
