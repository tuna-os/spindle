//! `/sync` and the sliding sync entry point, and the assembly of their answers.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::routes::{
    RoomRuleContext, account_data_error, raw, room_error, ruleset_of, visible_device_changes,
    with_transaction_id,
};
use axum::{
    Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
    routing::post,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// `/sync` and sliding sync.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v3/sync", get(sync))
        // Element X speaks the unstable path; MSC4186 has no stable one yet.
        .route(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            post(sliding_sync),
        )
}

#[derive(Debug, Deserialize)]
struct SyncQuery {
    since: Option<String>,
    timeout: Option<u64>,
    #[serde(rename = "timeline_limit")]
    timeline_limit: Option<usize>,
    filter: Option<String>,
    /// Whether this sync speaks for its user's presence: `online` (the
    /// spec's default), `unavailable`, or `offline` for "it does not".
    set_presence: Option<String>,
    /// MSC4222. Accepted under the unstable name too, because the MSC shipped
    /// in clients before it was adopted and both spellings are in the wild.
    #[serde(rename = "use_state_after")]
    use_state_after: Option<bool>,
    #[serde(rename = "org.matrix.msc4222.use_state_after")]
    unstable_use_state_after: Option<bool>,
}

impl SyncQuery {
    /// Whether to send the state after the timeline (MSC4222).
    fn state_after(&self) -> bool {
        self.state_label() != "state"
    }

    /// The key the joined room's state block goes under.
    ///
    /// The response field is spelled the way the request flag was. A
    /// client that asked with the unstable flag reads only the unstable
    /// field: matrix-js-sdk, and so Element Web, sends
    /// `org.matrix.msc4222.use_state_after=true` on every sync and reads
    /// `org.matrix.msc4222.state_after`, falling back to `state`. Answering
    /// it with the stable `state_after` left it with no state at all: every
    /// room read as version 1, unnamed, and unencrypted, so its composer
    /// offered to send in plaintext into an encrypted room.
    fn state_label(&self) -> &'static str {
        if self.use_state_after == Some(true) {
            "state_after"
        } else if self.use_state_after.is_none() && self.unstable_use_state_after == Some(true) {
            "org.matrix.msc4222.state_after"
        } else {
            "state"
        }
    }
}

/// A room's badge for one reader: the unread events their push rules
/// notify for and the highlights among them, in total and split by
/// thread (MSC3773).
pub(crate) struct Badge {
    /// Everything after the unthreaded receipt, threads included.
    pub notification_count: usize,
    pub highlight_count: usize,
    /// The main timeline alone, after the later of the unthreaded and
    /// the `main` receipt.
    pub main: (usize, usize),
    /// Each thread root to its counts after the later of the unthreaded
    /// and that thread's receipt; threads with nothing unread are absent.
    pub threads: BTreeMap<String, (usize, usize)>,
}

impl Badge {
    const NONE: Self = Self {
        notification_count: 0,
        highlight_count: 0,
        main: (0, 0),
        threads: BTreeMap::new(),
    };
}

/// The reader's badge in `room_id`.
///
/// Scored through the reader's tally ([`crate::rooms::Rooms::unscored`]):
/// only the bodies after the position last scored are put to the rules,
/// and the ruleset, profile and room context are read only when there is
/// something to score. Nothing unread (by the arithmetic count, which
/// never reads a body) means nothing to score, before any of that.
fn badge(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    unread: &crate::rooms::Unread,
) -> Result<Badge, MatrixError> {
    let Some(boundary) = unread.boundary else {
        return Ok(Badge::NONE);
    };
    if unread.notification_count == 0 {
        return Ok(Badge::NONE);
    }
    let pending = state
        .rooms
        .unscored(room_id, &identity.user_id, boundary)
        .map_err(room_error)?;
    let mut scored = pending.scored;
    if !pending.events.is_empty() {
        let ruleset = ruleset_of(state, &identity.user_id)?;
        let profile = state
            .profiles
            .get(&identity.user_id)
            .map_err(|error| MatrixError::internal(&error.to_string()))?;
        let room = RoomRuleContext::of(state, room_id)?;
        let context = room.for_reader(&identity.user_id, profile.displayname.as_deref(), room_id);
        for (li, event) in &pending.events {
            let actions = crate::push_rules::evaluate(&ruleset, event, &context);
            let relation = &event["content"]["m.relates_to"];
            let thread = (relation["rel_type"] == "m.thread")
                .then(|| relation["event_id"].as_str().map(str::to_owned))
                .flatten();
            scored.push(crate::rooms::Scored {
                li: *li,
                notifies: actions.is_some(),
                highlights: actions
                    .as_deref()
                    .is_some_and(crate::push_rules::is_highlight),
                thread,
            });
        }
        state.rooms.record_scores(
            room_id,
            &identity.user_id,
            boundary,
            pending.upto,
            scored.clone(),
        );
    }
    let floors = state
        .rooms
        .thread_receipts(room_id, &identity.user_id)
        .map_err(room_error)?;
    let main_floor = floors.get("main").copied().unwrap_or(i64::MIN);
    let mut counts = Badge::NONE;
    for event in &scored {
        if !event.notifies {
            continue;
        }
        let highlight = usize::from(event.highlights);
        counts.notification_count += 1;
        counts.highlight_count += highlight;
        match &event.thread {
            None if event.li > main_floor => {
                counts.main.0 += 1;
                counts.main.1 += highlight;
            }
            Some(root) if event.li > floors.get(root).copied().unwrap_or(i64::MIN) => {
                let thread = counts.threads.entry(root.clone()).or_insert((0, 0));
                thread.0 += 1;
                thread.1 += highlight;
            }
            _ => {}
        }
    }
    Ok(counts)
}

/// The `unread_notifications` section of a room in `/sync`, and, when
/// the timeline filter asks (MSC3773), `unread_thread_notifications`:
/// then the badge is the main timeline alone and each thread has its
/// own; without it, one badge covers everything.
fn badge_sections(
    badge: &Badge,
    by_thread: bool,
) -> Result<Vec<(&'static str, Box<RawValue>)>, MatrixError> {
    let counts = |notifications: usize, highlights: usize| json!({ "notification_count": notifications, "highlight_count": highlights });
    if !by_thread {
        return Ok(vec![(
            "unread_notifications",
            raw(&counts(badge.notification_count, badge.highlight_count))?,
        )]);
    }
    let threads: serde_json::Map<String, Value> = badge
        .threads
        .iter()
        .map(|(root, (notifications, highlights))| {
            (root.clone(), counts(*notifications, *highlights))
        })
        .collect();
    Ok(vec![
        (
            "unread_notifications",
            raw(&counts(badge.main.0, badge.main.1))?,
        ),
        ("unread_thread_notifications", raw(&Value::Object(threads))?),
    ])
}

/// The filter a `/sync` request is asking for, in either of the two forms.
///
/// A client may send the JSON inline or the id of one it uploaded. Both end up
/// as the same parsed `Filter`, so a filter cannot mean one thing uploaded and
/// another inline.
///
/// An unknown id is an error rather than "no filter". Silently syncing
/// unfiltered would send a client on a slow connection everything it just
/// asked not to receive, which is the opposite of what it wanted and looks
/// like the server ignoring it.
fn requested_filter(
    state: &AppState,
    user_id: &str,
    raw: Option<&str>,
) -> Result<Option<crate::filters::Filter>, MatrixError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.starts_with('{') {
        return serde_json::from_str(raw)
            .map(Some)
            .map_err(|error| MatrixError::bad_json(error.to_string()));
    }
    state
        .filters
        .get(user_id, raw)
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .map(Some)
        .ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("no filter {raw}"),
            )
        })
}

#[derive(Debug, Deserialize)]
struct SlidingQuery {
    pos: Option<String>,
    timeout: Option<u64>,
}

/// MSC4186's answer to a `pos` this server does not hold, which a client
/// handles by dropping it and starting the connection over: one the
/// connection retired or expired, one a restart forgot, one issued to
/// another device or connection, and the one a client kept from the
/// homeserver this one replaced. Anything else -- a 400 `M_BAD_JSON` -- is
/// an error a client retries with the same `pos`, forever.
fn unknown_pos(identity: &crate::accounts::Identity, conn_id: &str) -> MatrixError {
    tracing::info!(
        user_id = %identity.user_id,
        conn_id,
        "sliding sync pos not held; answering M_UNKNOWN_POS"
    );
    MatrixError::new(
        StatusCode::BAD_REQUEST,
        "M_UNKNOWN_POS",
        "unknown position; start the connection over without `pos`",
    )
}

/// Where a `/sync` resumes from.
///
/// A token another homeserver minted (a client that synced against the
/// server this one replaced) is answered as an initial sync: every room in
/// full, timelines limited, so the client rebuilds rather than retrying a
/// position that no longer exists. See `tokens::Resume`.
fn sync_resume(
    identity: &crate::accounts::Identity,
    since: Option<&str>,
) -> Result<crate::tokens::Resume, MatrixError> {
    let resume = crate::tokens::Sync::resume(since)
        .map_err(|error| MatrixError::bad_json(error.to_string()))?;
    if resume == crate::tokens::Resume::Foreign {
        tracing::info!(
            user_id = %identity.user_id,
            "sync token from another server; answering as an initial sync"
        );
    }
    Ok(resume)
}

/// `POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync`
///
/// One request on a connection (`sliding.rs` explains them): `pos` names
/// what the connection held when it was answered, the request's parameters
/// merge over the ones it held, and the response sends each room the client
/// does not hold in full (`initial: true`) and each one it does as what
/// changed since the client last held it current.
async fn sliding_sync(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SlidingQuery>,
    Json(request): Json<crate::sliding::SlidingRequest>,
) -> Result<axum::response::Response, MatrixError> {
    let key = crate::sliding::ConnectionKey {
        user_id: identity.user_id.clone(),
        device_id: identity.device_id.clone(),
        conn_id: request.conn_id.clone().unwrap_or_default(),
    };
    let previous = match query.pos.as_deref().or(request.pos.as_deref()) {
        Some(pos) => Some(
            state
                .sliding
                .resume(&key, pos, std::time::Instant::now())
                .ok_or_else(|| unknown_pos(&identity, &key.conn_id))?,
        ),
        None => None,
    };
    let params = request
        .params(previous.as_ref().map(|held| &held.params))
        .map_err(MatrixError::bad_json)?;
    let since = previous.as_ref().map(|held| held.stream);

    // A request that changes what it asks for -- a window grown, a room
    // subscribed, a timeline lengthened -- wants the answer to that now, not
    // whenever the next event lands. MSC4186 says so for an expanded
    // timeline, and Element X grows its window one request after another.
    let reconfigured = previous.as_ref().is_some_and(|held| held.params != params);
    let timeout_ms = if reconfigured {
        0
    } else {
        request.timeout.or(query.timeout).unwrap_or(0).min(60_000)
    };
    // Timed apart from the rest (#625): a request that may wait its
    // timeout on purpose is not latency anybody should be paged about.
    let long_poll = since.is_some() && timeout_ms > 0;
    let position =
        sliding_long_poll(&state, since, timeout_ms, params.extensions.typing.on()).await;
    let to_device_since = request.extensions.to_device.since;
    let txn_id = request.txn_id;

    // Everything below is synchronous room work -- for a cold room, a load
    // from the store -- so it runs on the blocking pool, not on one of the
    // handful of async workers the whole server shares (#614).
    let worker_state = state.clone();
    crate::blocking::offload(
        std::sync::Arc::clone(&state.metrics),
        crate::metrics::BlockingTask::SlidingSync,
        move || {
            let (mut body, connection) = sliding_answer(
                &worker_state,
                &identity,
                SlidingInputs {
                    previous: previous.as_deref(),
                    params,
                    position,
                    to_device_since: to_device_since.as_deref(),
                },
            )?;
            let pos = worker_state.sliding.record(
                key,
                connection,
                previous.is_none(),
                std::time::Instant::now(),
            );
            body.insert("pos".to_owned(), json!(pos));
            if let Some(txn_id) = txn_id {
                body.insert("txn_id".to_owned(), json!(txn_id));
            }
            Ok(Json(Value::Object(body)))
        },
    )
    .await
    .map(|body| mark_long_poll(body.into_response(), long_poll))
}

/// Tag a sync response that was allowed to long-poll, so the request
/// middleware times it under its own series (#625).
fn mark_long_poll(
    mut response: axum::response::Response,
    long_poll: bool,
) -> axum::response::Response {
    if long_poll {
        response.extensions_mut().insert(crate::metrics::LongPoll);
    }
    response
}

/// How many cold rooms one sliding-sync request loads at once. Bounded:
/// a load is CPU and I/O on cores the rest of the server shares, and four
/// is past the two the production pod has.
const WINDOW_LOAD_PARALLELISM: usize = 4;

/// What [`sliding_answer`] needs beyond the state and the asker, decoded and
/// positioned by the handler.
struct SlidingInputs<'a> {
    /// What the connection held at the request's `pos`; `None` for a
    /// connection starting over.
    previous: Option<&'a crate::sliding::Connection>,
    params: crate::sliding::Params,
    position: u64,
    to_device_since: Option<&'a str>,
}

/// The body of a sliding-sync response, assembled synchronously, without
/// its `pos`; and what the connection holds once the client has it.
fn sliding_answer(
    state: &AppState,
    identity: &crate::accounts::Identity,
    inputs: SlidingInputs<'_>,
) -> Result<(serde_json::Map<String, Value>, crate::sliding::Connection), MatrixError> {
    let SlidingInputs {
        previous,
        params,
        position,
        to_device_since,
    } = inputs;
    state
        .rooms
        .checkpoint_stream_position(position)
        .map_err(room_error)?;

    // The sorted room list: every joined room, newest activity first. The
    // sort is recomputed per request because it is what the ranges index
    // into, and a stale order would make the client's window show the wrong
    // rooms — the exact bug sliding sync exists to avoid.
    let ordering = std::time::Instant::now();
    let (ordered, invited) = sliding_room_order(state, identity)?;
    state
        .metrics
        .observe_sync_phase(crate::metrics::SyncPhase::SlidingOrder, ordering.elapsed());
    let assembling = std::time::Instant::now();

    // Every room this request may be answered with. A list window can only
    // produce rooms out of `ordered`, which came from the caller's own
    // memberships -- but a *subscription* is an arbitrary room id lifted
    // straight out of the request body, and nothing downstream of here looks
    // at who is asking: `sliding_room_entry` takes an identity and never
    // consults it. Without this set, any account on the server could name any
    // room and be sent its name, its state and its whole timeline.
    let visible: std::collections::HashSet<&str> = ordered
        .iter()
        .map(|(room_id, _)| room_id.as_str())
        .collect();
    let selection = crate::sliding::select(&params, &ordered, &visible);
    let held_rooms = previous.map(|held| &held.rooms);
    let plan = sliding_plan(state, identity, &selection, held_rooms, &invited, position)?;
    let rooms_out = sliding_rooms(state, identity, plan, &invited, position)?;
    let lists_out: serde_json::Map<String, Value> = params
        .lists
        .keys()
        .map(|name| (name.clone(), json!({ "count": ordered.len() })))
        .collect();
    let (extensions, receipts_current) = sliding_extensions(
        state,
        identity,
        &params.extensions,
        ExtensionInputs {
            since: previous.map(|held| held.stream),
            position,
            to_device_since,
            selection: &selection,
            receipts: previous.map(|held| &held.receipts),
        },
    )?;
    state.metrics.observe_sync_phase(
        crate::metrics::SyncPhase::SlidingAssemble,
        assembling.elapsed(),
    );

    // What the client holds once it has this response. A room it can no
    // longer see is forgotten, so seeing it again -- a rejoin -- starts it
    // over in full; one merely out of view keeps the position it was last
    // current at, so its return is caught up from there.
    let mut rooms: std::collections::HashMap<String, crate::sliding::SentRoom> = held_rooms
        .into_iter()
        .flatten()
        .filter(|(room_id, _)| visible.contains(room_id.as_str()))
        .map(|(room_id, held)| (room_id.clone(), held.clone()))
        .collect();
    for (room_id, config) in &selection.wanted {
        let sent = crate::sliding::SentRoom {
            at: position,
            config: std::sync::Arc::clone(config),
            invite: invited.contains(room_id),
        };
        rooms.insert(room_id.clone(), sent);
    }
    let mut receipts: std::collections::HashMap<String, u64> = previous
        .map(|held| &held.receipts)
        .into_iter()
        .flatten()
        .filter(|(room_id, _)| visible.contains(room_id.as_str()))
        .map(|(room_id, at)| (room_id.clone(), *at))
        .collect();
    receipts.extend(
        receipts_current
            .into_iter()
            .map(|room_id| (room_id, position)),
    );

    let mut body = serde_json::Map::new();
    body.insert("lists".to_owned(), Value::Object(lists_out));
    body.insert("rooms".to_owned(), Value::Object(rooms_out));
    body.insert("extensions".to_owned(), extensions);
    let connection = crate::sliding::Connection {
        stream: position,
        params,
        rooms,
        receipts,
    };
    Ok((body, connection))
}

/// One room of a response to render, and how.
type PlannedRoom = (
    String,
    std::sync::Arc<crate::sliding::RoomConfig>,
    crate::sliding::Need,
);

/// The rooms of `selection` this response speaks about. One the client does
/// not hold goes in full; one it does goes if it changed since the client
/// last held it current, or if the client now asks for more of it. Silence
/// about the rest *is* the answer.
///
/// Whether a held room changed is asked once per distinct position the
/// client holds rooms at, which is one question in the common case -- every
/// room in view was current at the previous response -- and only the rooms
/// coming back into view after an absence add more. The question is about
/// the rooms this response could mention and nothing else: asking the
/// server's whole stream would price a client's sliding sync at everyone
/// else's traffic.
fn sliding_plan(
    state: &AppState,
    identity: &crate::accounts::Identity,
    selection: &crate::sliding::Selection,
    held: Option<&std::collections::HashMap<String, crate::sliding::SentRoom>>,
    invited: &std::collections::HashSet<String>,
    position: u64,
) -> Result<Vec<PlannedRoom>, MatrixError> {
    let needs: Vec<(
        &String,
        &std::sync::Arc<crate::sliding::RoomConfig>,
        crate::sliding::Need,
    )> = selection
        .wanted
        .iter()
        .map(|(room_id, config)| {
            let mut need = crate::sliding::Need::of(
                held.and_then(|held| held.get(room_id)),
                config,
                invited.contains(room_id),
            );
            // A partial-state room whose resync landed after the client
            // last held it (MSC3706) goes again in full: its filled roster
            // was never a timeline event, so only an initial rendering of
            // its state carries it.
            if let crate::sliding::Need::Since { since, .. } = need
                && state.rooms.resynced_between(room_id, since, position)
            {
                need = crate::sliding::Need::Initial;
            }
            (room_id, config, need)
        })
        .collect();
    let mut by_since: std::collections::BTreeMap<u64, Vec<&str>> =
        std::collections::BTreeMap::new();
    for (room_id, _, need) in &needs {
        if let crate::sliding::Need::Since { since, .. } = need {
            by_since.entry(*since).or_default().push(room_id.as_str());
        }
    }
    let mut changed = std::collections::HashSet::new();
    for (since, rooms) in by_since {
        changed.extend(
            state
                .rooms
                .changed_rooms(rooms.iter().copied(), since, position)
                .map_err(room_error)?,
        );
        // A room the reader just read is one whose counts moved for them,
        // event or no event; silence about it would hand back the unread
        // numbers the receipt has just made wrong.
        changed.extend(state.rooms.rooms_read_since(
            &identity.user_id,
            rooms.iter().copied(),
            since,
            position,
        ));
    }
    Ok(needs
        .into_iter()
        .filter(|(room_id, _, need)| need.forced() || changed.contains(room_id.as_str()))
        .map(|(room_id, config, need)| (room_id.clone(), std::sync::Arc::clone(config), need))
        .collect())
}

/// The `rooms` object: each planned room's entry.
fn sliding_rooms(
    state: &AppState,
    identity: &crate::accounts::Identity,
    plan: Vec<PlannedRoom>,
    invited: &std::collections::HashSet<String>,
    position: u64,
) -> Result<serde_json::Map<String, Value>, MatrixError> {
    // Every cold room about to be rendered is loaded first, several at once,
    // rather than one after another as the loop below reaches it: after a
    // restart a window of twenty cold rooms costs its slowest load, not the
    // sum of all twenty (#614). Rooms answered silently, and invites (which
    // have no log here to load), are left alone.
    let cold: Vec<String> = plan
        .iter()
        .map(|(room_id, ..)| room_id)
        .filter(|room_id| !invited.contains(*room_id) && !state.rooms.is_resident(room_id))
        .cloned()
        .collect();
    state.rooms.warm_all(&cold, WINDOW_LOAD_PARALLELISM);
    let mut rooms_out = serde_json::Map::new();
    for (room_id, config, need) in plan {
        let entry = if invited.contains(&room_id) {
            sliding_invite_entry(state, identity, &room_id)?
        } else {
            sliding_room_entry(
                state,
                identity,
                &RoomRender {
                    room_id: &room_id,
                    config: &config,
                    need: &need,
                    position,
                },
            )?
        };
        rooms_out.insert(room_id, entry);
    }
    Ok(rooms_out)
}

/// Long-poll before answering, not after assembling: an incremental request
/// with nothing new blocks here, and answers fresh when something lands.
/// Typing is not an event and has no stream position, so with the typing
/// extension on a change in who is typing ends the wait too, as it does for
/// classic sync. Returns the stream position to answer at.
async fn sliding_long_poll(
    state: &AppState,
    since: Option<u64>,
    timeout_ms: u64,
    typing_wakes: bool,
) -> u64 {
    let position = state.rooms.stream_position();
    let Some(since) = since else {
        return position;
    };
    if position > since || timeout_ms == 0 {
        return position;
    }
    let timeout = std::time::Duration::from_millis(timeout_ms);
    if typing_wakes {
        tokio::select! {
            () = state.rooms.wait_for_event(timeout) => {}
            () = state.typing.wait(timeout) => {}
        }
    } else {
        state.rooms.wait_for_event(timeout).await;
    }
    state.rooms.stream_position()
}

/// What [`sliding_extensions`] answers from.
#[derive(Clone, Copy)]
struct ExtensionInputs<'a> {
    /// The stream position the connection's previous response answered at.
    since: Option<u64>,
    position: u64,
    /// The to-device extension's token, from the request itself.
    to_device_since: Option<&'a str>,
    selection: &'a crate::sliding::Selection,
    /// The receipts the connection holds, by room.
    receipts: Option<&'a std::collections::HashMap<String, u64>>,
}

/// The `extensions` object of a sliding-sync response, and the rooms whose
/// receipts the client is current to once it has it.
///
/// Each room extension speaks about its own scope (see
/// [`crate::sliding::RoomExtension::scope`]). The account data and typing
/// extensions answer for every room in theirs, changed or not: neither an
/// account-data nor a typing change bumps a stream position, so there is
/// no "since" to ask from, and repeating a scope's worth is the answer that
/// cannot silently drop one -- the same trade classic sync makes for room
/// account data. Receipts do bump one (`Rooms::mark_receipt`), so their
/// extension is incremental: see [`receipts_extension`].
fn sliding_extensions(
    state: &AppState,
    identity: &crate::accounts::Identity,
    extensions: &crate::sliding::Extensions,
    inputs: ExtensionInputs<'_>,
) -> Result<(Value, Vec<String>), MatrixError> {
    let ExtensionInputs {
        since,
        position,
        to_device_since,
        selection,
        receipts,
    } = inputs;
    let mut out = serde_json::Map::new();
    let mut receipts_current = Vec::new();
    if !extensions.any() {
        return Ok((Value::Object(out), receipts_current));
    }

    if extensions.to_device.on() {
        out.insert(
            "to_device".to_owned(),
            to_device_extension(
                state,
                identity,
                to_device_since,
                extensions.to_device.limit,
                position,
            )?,
        );
    }
    if extensions.e2ee.on() {
        out.insert(
            "e2ee".to_owned(),
            e2ee_extension(state, identity, since, position)?,
        );
    }
    if extensions.account_data.on() {
        let scope = extensions
            .account_data
            .scope(&selection.windows, &selection.subscribed);
        out.insert(
            "account_data".to_owned(),
            account_data_extension(state, identity, &scope)?,
        );
    }
    if extensions.receipts.on() {
        let scope = extensions
            .receipts
            .scope(&selection.windows, &selection.subscribed);
        out.insert(
            "receipts".to_owned(),
            receipts_extension(state, identity, &scope, receipts, position)?,
        );
        receipts_current = scope.into_iter().map(str::to_owned).collect();
    }
    if extensions.typing.on() {
        let mut rooms = serde_json::Map::new();
        for room_id in extensions
            .typing
            .scope(&selection.windows, &selection.subscribed)
        {
            if let Some(event) = state.typing.event(room_id) {
                rooms.insert(room_id.to_owned(), event);
            }
        }
        out.insert("typing".to_owned(), json!({ "rooms": rooms }));
    }

    Ok((Value::Object(out), receipts_current))
}

/// The to-device extension: what is pending for this device, acknowledged
/// by the extension's own token rather than by `pos`. A client that restarts
/// its sliding sync from nothing must not lose the to-device messages it has
/// already decrypted, and one that lost its E2EE state must be able to ask
/// for them again.
fn to_device_extension(
    state: &AppState,
    identity: &crate::accounts::Identity,
    since: Option<&str>,
    limit: Option<usize>,
    position: u64,
) -> Result<Value, MatrixError> {
    // Another server's to-device token acknowledges nothing here: every
    // pending message is delivered, which is the side to err on.
    let acknowledged = crate::tokens::Sync::resume(since)
        .map_err(|error| MatrixError::bad_json(error.to_string()))?
        .position();
    let (events, delivered_until) = state
        .devices
        .take_pending_until(
            &identity.user_id,
            &identity.device_id,
            acknowledged,
            position,
            limit,
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(json!({
        "next_batch": crate::tokens::Sync(delivered_until).to_string(),
        "events": events,
    }))
}

/// The E2EE extension: the same three things classic sync carries at the
/// top level, for the same reasons.
fn e2ee_extension(
    state: &AppState,
    identity: &crate::accounts::Identity,
    since: Option<u64>,
    position: u64,
) -> Result<Value, MatrixError> {
    let changed = match since {
        Some(since) => visible_device_changes(state, identity, since, position)?,
        None => Vec::new(),
    };
    let key_counts = state
        .devices
        .one_time_key_counts(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let unused_fallback = state
        .devices
        .unused_fallback_algorithms(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(json!({
        "device_lists": { "changed": changed, "left": [] },
        "device_one_time_keys_count": key_counts,
        "device_unused_fallback_key_types": unused_fallback,
    }))
}

/// The account-data extension: the global events, and each room in scope
/// that has any.
fn account_data_extension(
    state: &AppState,
    identity: &crate::accounts::Identity,
    scope: &std::collections::BTreeSet<&str>,
) -> Result<Value, MatrixError> {
    let global = sync_account_data(state, identity, None, None, state.rooms.stream_position())?;
    let mut rooms = serde_json::Map::new();
    for &room_id in scope {
        let data = state
            .account_data
            .all(&identity.user_id, room_id)
            .map_err(|error| account_data_error(&error))?;
        if !data.is_empty() {
            rooms.insert(room_id.to_owned(), Value::Array(data));
        }
    }
    Ok(json!({ "global": global, "rooms": rooms }))
}

/// The receipts extension: one `m.receipt` event per room in scope that has
/// any, keyed by event then by type then by reader, as the spec shapes it.
/// A private receipt (and the `m.fully_read` marker) is shown to its owner
/// and nobody else. Receipts from other servers are in the same rows.
///
/// Incremental once the connection holds a room's receipts (#624): with
/// federated readers a large room holds a receipt per member, and resending
/// every one of them on every request priced each long-poll at the room's
/// size. A room whose receipts the connection does not hold -- the first
/// request, or the first time the room is in the extension's scope -- gets
/// the caller's own receipts and the newest
/// [`crate::receipts::MAX_INITIAL_RECEIPTS`] of everyone else's; after
/// that, the receipts of readers who moved since the client was last
/// current for that room, which for a room back in scope after an absence
/// is further back than the previous request.
fn receipts_extension(
    state: &AppState,
    identity: &crate::accounts::Identity,
    scope: &std::collections::BTreeSet<&str>,
    held: Option<&std::collections::HashMap<String, u64>>,
    position: u64,
) -> Result<Value, MatrixError> {
    let mut by_since: std::collections::BTreeMap<u64, Vec<&str>> =
        std::collections::BTreeMap::new();
    for &room_id in scope {
        if let Some(&since) = held.and_then(|held| held.get(room_id)) {
            by_since.entry(since).or_default().push(room_id);
        }
    }
    let mut moved = std::collections::HashMap::new();
    for (since, rooms) in by_since {
        moved.extend(state.rooms.receipt_readers_since(rooms, since, position));
    }
    let mut rooms = serde_json::Map::new();
    for &room_id in scope {
        let rows = if held.is_some_and(|held| held.contains_key(room_id)) {
            let Some(readers) = moved.get(room_id) else {
                continue;
            };
            readers_receipts(state, room_id, readers)?
        } else {
            crate::receipts::newest(
                state.rooms.room_receipts(room_id).map_err(room_error)?,
                &identity.user_id,
                crate::receipts::MAX_INITIAL_RECEIPTS,
            )
        };
        let content = crate::receipts::event_content(rows, &identity.user_id);
        if !content.is_empty() {
            rooms.insert(
                room_id.to_owned(),
                json!({ "type": "m.receipt", "content": content }),
            );
        }
    }
    Ok(json!({ "rooms": rooms }))
}

/// One room's sliding-sync entry.
/// `(rooms newest first with their recency, the invited ones among them)`.
type SlidingRoomOrder = (Vec<(String, i64)>, std::collections::HashSet<String>);

/// The sorted room list: every joined room and every invite, newest
/// activity first. Recomputed per request because it is what the ranges
/// index into, and a stale order would make the client's window show the
/// wrong rooms -- the exact bug sliding sync exists to avoid. The invited
/// set comes back too: those entries render differently.
fn sliding_room_order(
    state: &AppState,
    identity: &crate::accounts::Identity,
) -> Result<SlidingRoomOrder, MatrixError> {
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    // Invites are rooms in the list too (MSC4186), or a client has no way
    // to show one: there is no separate section, the way classic sync has.
    // The entry differs -- stripped state, no timeline -- so which rooms
    // are invites is remembered for the render below.
    let invited: std::collections::HashSet<String> = state
        .rooms
        .invited(&identity.user_id)
        .map_err(room_error)?
        .into_iter()
        .collect();
    let mut ordered: Vec<(String, i64)> = Vec::with_capacity(joined.len() + invited.len());
    for room_id in joined {
        let activity = state.rooms.last_activity(&room_id).map_err(room_error)?;
        ordered.push((room_id, activity));
    }
    for room_id in &invited {
        // A room this server holds has a newest event to date the invite
        // by. One it does not (a federated invite, no log here) is dated
        // now: the invite is the newest thing the invitee knows of it.
        let activity = state
            .rooms
            .last_activity(room_id)
            .unwrap_or_else(|_| now_ms());
        ordered.push((room_id.clone(), activity));
    }
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok((ordered, invited))
}

/// Milliseconds since the epoch, for dating what has no event to date it.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since_epoch| {
            i64::try_from(since_epoch.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The `rooms` entry for a room the asker is invited to: the stripped state
/// an invite is rendered from, and nothing an invitee is not yet entitled
/// to -- no timeline, no counts. Always `initial`, since there is nothing
/// incremental about an invite; and the name and heroes come from the
/// stripped events themselves, which is all the client would have had.
fn sliding_invite_entry(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
) -> Result<Value, MatrixError> {
    let events = state
        .rooms
        .stripped_state(room_id, &identity.user_id)
        .map_err(room_error)?;
    let mut entry = serde_json::Map::new();
    if let Some(name) = events
        .iter()
        .find(|event| event["type"] == "m.room.name")
        .and_then(|event| event["content"]["name"].as_str())
    {
        entry.insert("name".to_owned(), json!(name));
    }
    let heroes: Vec<Value> = events
        .iter()
        .filter(|event| {
            event["type"] == "m.room.member"
                && event["state_key"] != json!(identity.user_id)
                && event["content"]["membership"] == "join"
        })
        .take(5)
        .map(|event| {
            let mut hero = serde_json::Map::new();
            hero.insert("user_id".to_owned(), event["state_key"].clone());
            if let Some(name) = event["content"]["displayname"].as_str() {
                hero.insert("name".to_owned(), json!(name));
            }
            if let Some(avatar) = event["content"]["avatar_url"].as_str() {
                hero.insert("avatar".to_owned(), json!(avatar));
            }
            Value::Object(hero)
        })
        .collect();
    entry.insert("heroes".to_owned(), Value::Array(heroes));
    entry.insert("invite_state".to_owned(), Value::Array(events));
    entry.insert(
        "bump_stamp".to_owned(),
        json!(
            state
                .rooms
                .last_activity(room_id)
                .unwrap_or_else(|_| now_ms())
        ),
    );
    entry.insert("initial".to_owned(), json!(true));
    Ok(Value::Object(entry))
}

/// `required_state` with `$LAZY` (MSC4186's lazy-loaded members) made
/// concrete: the member events of whoever sent something in `window`,
/// which is what a client needs to render that timeline -- the sender
/// names and avatars -- and nothing more. Expanded before either state
/// path runs so neither need know about it. A window with no senders
/// wants no members.
fn lazy_members_expanded(
    required_state: &[(String, String)],
    window: &[Value],
) -> Vec<(String, String)> {
    let senders: std::collections::BTreeSet<&str> = window
        .iter()
        .filter_map(|event| event["sender"].as_str())
        .collect();
    required_state
        .iter()
        .flat_map(|(event_type, state_key)| {
            if state_key == "$LAZY" {
                senders
                    .iter()
                    .map(|sender| (event_type.clone(), (*sender).to_owned()))
                    .collect::<Vec<_>>()
            } else {
                vec![(event_type.clone(), state_key.clone())]
            }
        })
        .collect()
}

fn sliding_heroes(
    state: &AppState,
    reader: &crate::rooms::RoomReader<'_>,
    roster: &crate::rooms::Roster,
    viewer: &str,
) -> Result<Vec<Value>, MatrixError> {
    let mut heroes = roster.heroes.clone();
    if state.rooms.erasure_active().map_err(room_error)? {
        for hero in &mut heroes {
            let member = reader
                .state_event("m.room.member", &hero.user_id)
                .map_err(room_error)?;
            hero.displayname = member["displayname"].as_str().map(str::to_owned);
            hero.avatar_url = member["avatar_url"].as_str().map(str::to_owned);
        }
    }
    Ok(crate::sliding::heroes(&heroes, viewer))
}

fn sliding_required_state(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    required_state: &[(String, String)],
) -> Result<Vec<Value>, MatrixError> {
    // A wildcard has to be answered by looking at everything; a list of
    // named keys does not. Element X asks for a handful of concrete keys
    // and gets sent the whole room state to filter down — a stored-body
    // read and a JSON parse per state event, per room in the window, per
    // request, to return three of them.
    let concrete = !required_state.is_empty()
        && required_state
            .iter()
            .all(|(event_type, state_key)| event_type != "*" && state_key != "*");
    let state_events: Vec<Value> = if required_state.is_empty() {
        Vec::new()
    } else if concrete {
        // Deduplicated, because state is a map and the wildcard path reads
        // it as one: a client that names `m.room.name` twice must not be
        // sent the event twice merely because it asked twice.
        let mut seen = std::collections::HashSet::new();
        required_state
            .iter()
            .filter_map(|(event_type, state_key)| {
                let key = if state_key == "$ME" {
                    identity.user_id.as_str()
                } else {
                    state_key.as_str()
                };
                if !seen.insert((event_type.as_str(), key)) {
                    return None;
                }
                // Absent state is absent, not an error: a room with no
                // name simply has no m.room.name to send.
                state.rooms.state_event_full(room_id, event_type, key).ok()
            })
            .collect()
    } else {
        state
            .rooms
            .state(room_id)
            .map_err(room_error)?
            .into_iter()
            .filter(|event| {
                let event_type = event["type"].as_str().unwrap_or_default();
                let state_key = event["state_key"].as_str().unwrap_or_default();
                crate::sliding::wants_state(
                    required_state,
                    &identity.user_id,
                    event_type,
                    state_key,
                )
            })
            .collect()
    };
    state
        .rooms
        .prune_erased_events(&identity.user_id, room_id, state_events)
        .map_err(room_error)
}

/// One room entry to render: which room, with what config, how the client
/// holds it, and the stream position the response answers at.
struct RoomRender<'a> {
    room_id: &'a str,
    config: &'a crate::sliding::RoomConfig,
    need: &'a crate::sliding::Need,
    position: u64,
}

/// A room entry's timeline, and for a room the client holds, the IDs of
/// every event since it last held the room current -- what tells changed
/// state from state it already has.
fn sliding_timeline(
    state: &AppState,
    identity: &crate::accounts::Identity,
    render: &RoomRender<'_>,
) -> Result<
    (
        crate::sliding::Timeline,
        Option<std::collections::HashSet<String>>,
    ),
    MatrixError,
> {
    let RoomRender {
        room_id,
        config,
        need,
        position,
    } = *render;
    let limit = config.timeline_limit.min(50);
    let tail = || {
        if limit == 0 {
            Ok((Vec::new(), false, None))
        } else {
            state
                .rooms
                .timeline_tail_for_preview(room_id, limit)
                .map_err(room_error)
        }
    };
    let mut expanded = false;
    let mut changed_ids = None;
    let (events, limited, prev_batch) = match need {
        crate::sliding::Need::Initial => tail()?,
        crate::sliding::Need::Since {
            since,
            expanded_timeline,
            ..
        } => {
            // An expanded timeline is the tail at the new limit, so the
            // range is read for its IDs alone, no bodies.
            let delta_limit = if *expanded_timeline { 0 } else { limit };
            let delta = state
                .rooms
                .room_delta(room_id, *since, position, delta_limit)
                .map_err(room_error)?;
            changed_ids = Some(delta.event_ids);
            if *expanded_timeline {
                expanded = true;
                tail()?
            } else {
                (delta.events, delta.limited, delta.prev_batch)
            }
        }
    };
    let events = state
        .rooms
        .prune_erased_events(&identity.user_id, room_id, events)
        .map_err(room_error)?;
    let timeline = crate::sliding::Timeline {
        events: events
            .into_iter()
            .map(|event| with_transaction_id(state, identity, event))
            .collect(),
        limited,
        prev_batch: prev_batch.map(|li| crate::tokens::Pagination(li).to_string()),
        expanded,
    };
    Ok((timeline, changed_ids))
}

/// The `required_state` of a room the client already holds: the state it
/// asks for whose event is among `changed_ids` (it changed since), the state
/// it asks for now and did not before (`widened`), and the members of the
/// window's senders (`$LAZY`) -- a sender new to this client may have
/// joined long before the window, so their member event is not "changed",
/// and a client rendering the window needs it all the same.
fn sliding_state_delta(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    (config, widened): (&crate::sliding::RoomConfig, &[(String, String)]),
    window: &[Value],
    changed_ids: &std::collections::HashSet<String>,
) -> Result<Vec<Value>, MatrixError> {
    let (lazy, eager): (Vec<_>, Vec<_>) = config
        .required_state
        .iter()
        .cloned()
        .partition(|(_, state_key)| state_key == "$LAZY");
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut keep = |event: Value, out: &mut Vec<Value>| {
        if let Some(event_id) = event["event_id"].as_str()
            && seen.insert(event_id.to_owned())
        {
            out.push(event);
        }
    };
    if !changed_ids.is_empty() && !eager.is_empty() {
        for event in sliding_required_state(state, identity, room_id, &eager)? {
            if event["event_id"]
                .as_str()
                .is_some_and(|event_id| changed_ids.contains(event_id))
            {
                keep(event, &mut out);
            }
        }
    }
    let mut always = lazy;
    always.extend(widened.iter().cloned());
    let always = lazy_members_expanded(&always, window);
    if !always.is_empty() {
        for event in sliding_required_state(state, identity, room_id, &always)? {
            keep(event, &mut out);
        }
    }
    Ok(out)
}

fn sliding_room_entry(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room: &RoomRender<'_>,
) -> Result<Value, MatrixError> {
    let room_id = room.room_id;
    let reader = state
        .rooms
        .reader(&identity.user_id, room_id)
        .map_err(room_error)?;
    let name = reader
        .state_event("m.room.name", "")
        .ok()
        .and_then(|content| content["name"].as_str().map(str::to_owned));
    let (timeline, changed_ids) = sliding_timeline(state, identity, room)?;
    let state_events = if let (crate::sliding::Need::Since { widened, .. }, Some(changed_ids)) =
        (room.need, &changed_ids)
    {
        sliding_state_delta(
            state,
            identity,
            room_id,
            (room.config, widened),
            &timeline.events,
            changed_ids,
        )?
    } else {
        let required_state = lazy_members_expanded(&room.config.required_state, &timeline.events);
        sliding_required_state(state, identity, room_id, &required_state)?
    };
    let roster = state.rooms.roster(room_id).map_err(room_error)?;
    let avatar = reader
        .state_event("m.room.avatar", "")
        .ok()
        .and_then(|content| content["url"].as_str().map(str::to_owned));
    let heroes = sliding_heroes(state, &reader, &roster, &identity.user_id)?;
    let bump_stamp = state.rooms.last_activity(room_id).map_err(room_error)?;
    let unread = state
        .rooms
        .unread(room_id, &identity.user_id)
        .map_err(room_error)?;
    let badge = badge(state, identity, room_id, &unread)?;
    Ok(crate::sliding::room_entry(
        crate::sliding::Summary {
            name,
            avatar,
            joined_count: roster.joined.len(),
            invited_count: roster.invited.len(),
            heroes,
            bump_stamp,
        },
        state_events,
        timeline,
        crate::sliding::Counts {
            notification_count: badge.notification_count,
            highlight_count: badge.highlight_count,
        },
        *room.need == crate::sliding::Need::Initial,
    ))
}

/// The asker and everyone joined to a room the asker is joined to: the
/// widest device-list change set the asker may be told about, for a sync
/// that resumes from another server's token (`tokens::Resume::Foreign`).
fn everyone_sharing_a_room(
    state: &AppState,
    identity: &crate::accounts::Identity,
) -> Result<Vec<String>, MatrixError> {
    let mut everyone = std::collections::BTreeSet::new();
    everyone.insert(identity.user_id.clone());
    for room_id in state.rooms.joined(&identity.user_id).map_err(room_error)? {
        everyone.extend(
            state
                .rooms
                .joined_member_ids(&room_id)
                .map_err(room_error)?
                .iter()
                .cloned(),
        );
    }
    Ok(everyone.into_iter().collect())
}

/// The E2EE sections of a `/sync` response, fetched before assembly.
///
/// To-device messages come first and destructively (`since` acknowledges the
/// previous batch — devices.rs explains the shared-counter protocol), so a
/// crash after this point re-delivers rather than loses. Device-list changes
/// are a diff and so exist only for an incremental sync — an initial sync's
/// client queries every key it cares about anyway. Their window is capped at
/// this response's own token so a change landing mid-assembly is reported by
/// the sync that owns it, exactly once.
#[allow(clippy::type_complexity)]
fn sync_device_sections(
    state: &AppState,
    identity: &crate::accounts::Identity,
    resume: crate::tokens::Resume,
    next_batch: u64,
) -> Result<
    (
        Vec<Value>,
        Vec<String>,
        serde_json::Map<String, Value>,
        Vec<String>,
    ),
    MatrixError,
> {
    let to_device = state
        .devices
        .take_pending_until(
            &identity.user_id,
            &identity.device_id,
            resume.position(),
            next_batch,
            None,
        )
        .map_err(|error| MatrixError::internal(&error.to_string()))?
        .0;
    let device_changes = match resume {
        crate::tokens::Resume::From(since) => {
            visible_device_changes(state, identity, since, next_batch)?
        }
        crate::tokens::Resume::Start => Vec::new(),
        // The client believes this is an incremental sync, so it will not
        // re-query keys the way a fresh login does. Device changes made on
        // the old server between its last sync and the switch are in a
        // stream this server never saw; naming everyone it shares a room
        // with makes it re-query them, rather than encrypt to a stale list.
        crate::tokens::Resume::Foreign => everyone_sharing_a_room(state, identity)?,
    };
    let key_counts = state
        .devices
        .one_time_key_counts(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    let unused_fallback = state
        .devices
        .unused_fallback_algorithms(&identity.user_id, &identity.device_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((to_device, device_changes, key_counts, unused_fallback))
}

/// `GET /_matrix/client/v3/sync`
///
/// The token is a position in the server-global stream (SPEC §10.2), because
/// `/sync` is the one endpoint that needs an order *across* rooms and the
/// linear index only orders within one.
async fn sync(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<SyncQuery>,
) -> Result<axum::response::Response, MatrixError> {
    let resume = sync_resume(&identity, query.since.as_deref())?;
    // Before the read, so a sync that brings its user online carries that
    // change itself; held to the end, so a long-poll keeps them online.
    let _presence = sync_presence_start(&state, &identity, query.set_presence.as_deref()).await?;
    let since = resume.position();
    let filter = requested_filter(&state, &identity.user_id, query.filter.as_deref())?;
    // A filter's own timeline limit outranks the query parameter: the client
    // set both, and the filter is the more specific of the two.
    let timeline_limit = filter
        .as_ref()
        .and_then(|filter| filter.room.timeline.as_ref())
        .and_then(|timeline| timeline.limit)
        .or(query.timeline_limit)
        .unwrap_or(20)
        .clamp(1, 100);

    // Asked for in the read, not filtered out of the answer: see
    // `Rooms::sync`. The exact narrowing still happens in `sync_join`,
    // against the filtered timeline; this is what stops the roster being
    // read and parsed in the first place.
    let state_section = filter
        .as_ref()
        .and_then(|filter| filter.room.state.as_ref());
    let lazy_members = state_section.and_then(|state| state.lazy_load_members) == Some(true);
    // A client that asked for the whole state block and applied no filter to
    // it wants exactly the bytes the state-render cache already holds. In
    // that case nothing downstream narrows the block, so materializing it
    // into `Value`s only to serialize them straight back is work done to
    // arrive where we started -- `sync_join` splices the cached render
    // instead. Any state filter at all, however permissive, takes the
    // ordinary path: deciding which filters happen to be no-ops is a way to
    // be subtly wrong, and the win is in the unfiltered case anyway.
    let state_block = if since.is_some() {
        // An incremental sync carries no state block; the mode is moot, and
        // `Rendered` is the one that materializes nothing in that case.
        crate::rooms::StateBlock::Rendered
    } else if lazy_members {
        crate::rooms::StateBlock::LazyMembers
    } else if state_section.is_some() {
        crate::rooms::StateBlock::Rendered
    } else {
        crate::rooms::StateBlock::Deferred
    };
    let state_after = query.state_after();
    // The read and the assembly are synchronous room work -- a cold room
    // is a load from the store -- so both run on the blocking pool rather
    // than on an async worker (#614). The long-poll between them is the
    // one stretch that genuinely waits, and it stays async.
    let reader = identity.user_id.clone();
    let read = |since: Option<u64>| {
        let state = state.clone();
        let user_id = reader.clone();
        crate::blocking::offload(
            std::sync::Arc::clone(&state.metrics),
            crate::metrics::BlockingTask::Sync,
            move || {
                let started = std::time::Instant::now();
                let result = state
                    .rooms
                    .sync(&user_id, since, timeline_limit, state_block, state_after)
                    .map_err(room_error);
                state
                    .metrics
                    .observe_sync_phase(crate::metrics::SyncPhase::SyncRead, started.elapsed());
                result
            },
        )
    };
    let mut result = read(since).await?;

    // Long-poll, but only for an incremental sync: an initial sync always has
    // something to say, and blocking one would leave a first-time client
    // staring at nothing for the whole timeout.
    let long_poll = since.is_some() && query.timeout.unwrap_or(0) > 0;
    let timeout = std::time::Duration::from_millis(query.timeout.unwrap_or(0).min(60_000));
    let deadline = tokio::time::Instant::now() + timeout;
    let state_label = query.state_label();
    let identity = std::sync::Arc::new(identity);
    let filter = std::sync::Arc::new(filter);
    let assemble = |result: crate::rooms::SyncResult| {
        let worker_state = state.clone();
        let identity = std::sync::Arc::clone(&identity);
        let filter = std::sync::Arc::clone(&filter);
        crate::blocking::offload(
            std::sync::Arc::clone(&state.metrics),
            crate::metrics::BlockingTask::Sync,
            move || {
                let started = std::time::Instant::now();
                let answer = sync_answer(
                    &worker_state,
                    &identity,
                    result,
                    filter.as_ref().as_ref(),
                    state_label,
                    resume,
                );
                worker_state
                    .metrics
                    .observe_sync_phase(crate::metrics::SyncPhase::SyncAssemble, started.elapsed());
                answer
            },
        )
    };

    // The stream is server-global, so it moves for everyone's news: another
    // user's to-device message, their presence, a room this user is not in.
    // A long-poll answers when there is something for *this* user, not when
    // the stream merely moved, or the client is handed an empty response and
    // has to ask again. That is not just a wasted round trip: matrix-rust-sdk
    // sleeps a second before a sync that follows the last within a second,
    // taking the answer as a server ignoring its timeout. A room key sent in
    // that second waited it out, and a client that asked for the encrypted
    // event meanwhile could not decrypt it (#705). Synapse answers the same
    // way: it re-checks a woken sync for the user's news and keeps waiting
    // when there is none.
    let mut typing_moved = false;
    loop {
        let seen = result.next_batch;
        // Nothing at all since the client's token, rooms or side streams,
        // so there is no answer to assemble to find that out -- unless a
        // typing change woke the wait, which moves no position.
        let quiet = since == Some(seen) && result.is_empty() && !typing_moved;
        let expired = tokio::time::Instant::now() >= deadline;
        if !long_poll || expired || !quiet {
            let (response, news) = assemble(result).await?;
            if !long_poll || expired || news {
                return Ok(mark_long_poll(response, long_poll));
            }
        }
        // Either a stream move or a change in who is typing ends the wait.
        // Typing is not an event and has no stream position, so it cannot
        // be discovered by re-reading the log -- without this arm a client
        // would learn that someone started typing only when they stopped
        // and sent the message.
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        typing_moved = tokio::select! {
            () = state.rooms.wait_past(seen, left) => false,
            () = state.typing.wait(left) => true,
        };
        result = read(since).await?;
    }
}

/// What `/sync` does to its user's presence: online unless `set_presence`
/// says otherwise. The guard keeps the user from timing out while held.
async fn sync_presence_start(
    state: &AppState,
    identity: &crate::accounts::Identity,
    set_presence: Option<&str>,
) -> Result<Option<crate::presence::SyncGuard>, MatrixError> {
    let wanted = match set_presence {
        None => crate::presence::State::Online,
        Some(value) => crate::presence::State::parse(value).ok_or_else(|| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("set_presence must be 'online', 'offline' or 'unavailable', not {value:?}"),
            )
        })?,
    };
    if !state.presence.enabled() {
        return Ok(None);
    }
    // Telling peers means finding the rooms the user shares with them,
    // which can load a cold one: off the async workers.
    let worker_state = state.clone();
    let user_id = identity.user_id.clone();
    crate::blocking::offload(
        std::sync::Arc::clone(&state.metrics),
        crate::metrics::BlockingTask::Sync,
        move || {
            worker_state
                .presence
                .sync_started(crate::presence::Peers::of(&worker_state), &user_id, wanted)
                .map_err(|error| MatrixError::internal(&error.to_string()))
        },
    )
    .await
}

/// The body of a `/sync` response, assembled synchronously from what the
/// read found, and whether it tells its user anything: a room in any
/// section, a to-device message, a device-list change, account data,
/// presence or a finished delayed event. The one-time-key counts and the
/// fallback key types are in every answer, so they are not news on their
/// own.
fn sync_answer(
    state: &AppState,
    identity: &crate::accounts::Identity,
    result: crate::rooms::SyncResult,
    filter: Option<&crate::filters::Filter>,
    state_label: &'static str,
    resume: crate::tokens::Resume,
) -> Result<(axum::response::Response, bool), MatrixError> {
    let since = resume.position();
    let join = sync_join(
        state,
        identity,
        result.rooms,
        filter,
        state_label,
        (since, result.next_batch),
    )?;

    let invite = sync_invite(state, identity, result.invited, filter);
    let knock = sync_knock(state, identity, result.knocked, filter);
    let leave = sync_leave(result.left, filter);

    let (to_device, device_changes, key_counts, unused_fallback) =
        sync_device_sections(state, identity, resume, result.next_batch)?;

    let global = sync_account_data(state, identity, filter, since, result.next_batch)?;
    let mut news = !join.is_empty()
        || !invite.is_empty()
        || !knock.is_empty()
        || !leave.is_empty()
        || !to_device.is_empty()
        || !device_changes.is_empty()
        || !global.is_empty();

    // Assembled from pre-serialized parts rather than as one `Value`, so the
    // joined rooms' state blocks -- which `sync_join` may have taken straight
    // from the render cache -- reach the wire without a parse and a
    // re-serialize in between. Everything else is small and converted here.
    let mut rooms: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    rooms.insert("join", raw(&join)?);
    rooms.insert("invite", raw(&invite)?);
    rooms.insert("knock", raw(&knock)?);
    rooms.insert("leave", raw(&leave)?);

    let mut body: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    body.insert(
        "next_batch",
        raw(&crate::tokens::Sync(result.next_batch).to_string())?,
    );
    body.insert("rooms", raw(&rooms)?);
    body.insert("to_device", raw(&json!({ "events": to_device }))?);
    // `left` is honestly empty until room departures update the watermark; a
    // wrong name here would make clients drop sessions.
    body.insert(
        "device_lists",
        raw(&json!({ "changed": device_changes, "left": [] }))?,
    );
    body.insert("device_one_time_keys_count", raw(&key_counts)?);
    body.insert("device_unused_fallback_key_types", raw(&unused_fallback)?);
    body.insert("account_data", raw(&json!({ "events": global }))?);
    if let Some(presence) = sync_presence(state, identity, filter, since, result.next_batch)? {
        news |= !presence.is_empty();
        body.insert("presence", raw(&json!({ "events": presence }))?);
    }

    let window = (since, result.next_batch);
    if let Some(done) = finalised_delays(state, &identity.user_id, filter, window)? {
        news = true;
        body.insert("org.matrix.msc4140.finalised_delayed_events", raw(&done)?);
    }

    let text =
        serde_json::to_string(&body).map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            text,
        )
            .into_response(),
        news,
    ))
}

/// One room's entry in `rooms.join`, for every joined room the sync found.
///
/// Lifted out of the handler because the handler had four sections to
/// assemble and the joined one is by far the largest: it is the only one that
/// carries state, account data, ephemeral events and an unread count at once.
/// MSC4309's delayed events that finished in this sync's window.
///
/// `None` rather than an empty vector when there is nothing to report, so
/// the caller omits the key entirely as the MSC requires. The distinction
/// matters at this server's scale rather than in principle: almost nobody
/// has ever scheduled a delay, so an always-present key would be dead weight
/// on essentially every sync response this server writes.
fn finalised_delays(
    state: &AppState,
    user_id: &str,
    filter: Option<&crate::filters::Filter>,
    (since, next_batch): (Option<u64>, u64),
) -> Result<Option<Vec<Value>>, MatrixError> {
    if !filter.is_none_or(crate::filters::Filter::wants_finalised_delayed_events) {
        return Ok(None);
    }
    let finalised = state
        .delayed
        .finalised_between(user_id, since, next_batch)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok((!finalised.is_empty()).then(|| {
        finalised
            .iter()
            .map(crate::delayed::FinalisedDelay::sync_view)
            .collect()
    }))
}

/// The `presence` section: `None` with presence off, so the key is absent
/// rather than an empty list that would read as "nobody is online".
///
/// An initial sync carries everyone the user shares a room with who is not
/// offline, themselves included -- offline is what a client assumes of
/// anyone it has not been told about, so listing those would be bytes that
/// say nothing. An incremental one carries the changes in its window, to
/// the same audience.
fn sync_presence(
    state: &AppState,
    identity: &crate::accounts::Identity,
    filter: Option<&crate::filters::Filter>,
    since: Option<u64>,
    until: u64,
) -> Result<Option<Vec<Value>>, MatrixError> {
    if !state.presence.enabled() {
        return Ok(None);
    }
    let section = filter.and_then(|filter| filter.presence.as_ref());
    // A filter that excludes every presence event is common -- clients that
    // do not render presence say so -- and is honoured before any reading.
    if section.is_some_and(|section| {
        section.limit == Some(0) || section.types.as_ref().is_some_and(Vec::is_empty)
    }) {
        return Ok(Some(Vec::new()));
    }
    let store_error = |error: spindle_store::StoreError| MatrixError::internal(&error.to_string());
    let mut events = Vec::new();
    match since {
        None => {
            let around = state
                .presence
                .not_offline(everyone_sharing_a_room(state, identity)?)
                .map_err(store_error)?;
            for (user_id, status) in around {
                events.push(status.event(&user_id));
            }
        }
        Some(since) => {
            let changes = state.presence.changes(since, until).map_err(store_error)?;
            if !changes.is_empty() {
                let mine = state.rooms.joined(&identity.user_id).map_err(room_error)?;
                for (user_id, status) in changes {
                    let visible = user_id == identity.user_id
                        || state
                            .rooms
                            .joined(&user_id)
                            .map_err(room_error)?
                            .iter()
                            .any(|room_id| mine.contains(room_id));
                    if visible {
                        events.push(status.event(&user_id));
                    }
                }
            }
        }
    }
    Ok(Some(crate::filters::Filter::apply(section, events)))
}

/// The account-level account data a sync carries, defaults included.
///
/// Lifted out of the handler because it is the one section with a rule of
/// its own: a user who has never edited a push rule still has a ruleset, and
/// clients read it from here rather than from `/pushrules/`.
fn sync_account_data(
    state: &AppState,
    identity: &crate::accounts::Identity,
    filter: Option<&crate::filters::Filter>,
    since: Option<u64>,
    until: u64,
) -> Result<Vec<Value>, MatrixError> {
    let mut global = state
        .account_data
        .between(&identity.user_id, "", since, until)
        .map_err(|error| account_data_error(&error))?;
    // The ruleset is stored bare -- `/pushrules/` edits it a rule at a
    // time and wraps it in `global` on the way out -- but the account-data
    // event's content is `{"global": ruleset}` by the spec, and a client
    // that finds the kinds at the top level refuses the whole event:
    // matrix-rust-sdk logged "missing field `global`" and carried on with
    // no push rules at all, which is every notification count wrong.
    for event in &mut global {
        if event["type"] == crate::push_rules::TYPE {
            let ruleset = event["content"].take();
            event["content"] = json!({
                "global": crate::push_rules::with_defaults(ruleset, &identity.user_id),
            });
        }
    }
    // A user who has never edited a rule still has a ruleset, and a client
    // reads it from here rather than from `/pushrules/`. Injected rather than
    // written at registration for the reason `ruleset_of` gives: only an edit
    // freezes a ruleset, so an unedited one keeps tracking the defaults as the
    // spec adds rules.
    if since.is_none()
        && !global
            .iter()
            .any(|event| event["type"] == crate::push_rules::TYPE)
    {
        global.push(json!({
            "type": crate::push_rules::TYPE,
            "content": { "global": crate::push_rules::defaults(&identity.user_id) },
        }));
    }
    Ok(crate::filters::Filter::apply(
        filter.and_then(|filter| filter.account_data.as_ref()),
        global,
    ))
}

fn sync_invite(
    state: &AppState,
    identity: &crate::accounts::Identity,
    invited: Vec<String>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut invite = serde_json::Map::new();
    for room_id in invited {
        if filter.is_some_and(|f| !f.allows_room(&room_id)) {
            continue;
        }
        // An invited user is not in the room, so there is no timeline to
        // show them. `invite_state` is the stripped state a client renders
        // the invite from: what room, whose, how it admits — and nothing
        // they are not yet entitled to.
        let events = state
            .rooms
            .stripped_state(&room_id, &identity.user_id)
            .unwrap_or_default();
        invite.insert(room_id, json!({ "invite_state": { "events": events } }));
    }
    invite
}

/// The rooms this user has knocked on, with the state a client renders the
/// wait from.
///
/// Deliberately its own section and not folded into `invite`. An invite is
/// something to accept or decline; a knock is something to wait on, and a
/// client that showed them together would offer an accept button for a room
/// that has not agreed to let anyone in. The spec gives it `knock_state` for
/// the same reason it gives an invite `invite_state`: the knocker is not in
/// the room, so there is no timeline they are entitled to -- only enough to
/// know which room they are waiting on.
fn sync_knock(
    state: &AppState,
    identity: &crate::accounts::Identity,
    knocked: Vec<String>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut knock = serde_json::Map::new();
    for room_id in knocked {
        if filter.is_some_and(|f| !f.allows_room(&room_id)) {
            continue;
        }
        let events = state
            .rooms
            .stripped_state(&room_id, &identity.user_id)
            .unwrap_or_default();
        knock.insert(room_id, json!({ "knock_state": { "events": events } }));
    }
    knock
}

fn sync_leave(
    left: Vec<crate::rooms::SyncRoom>,
    filter: Option<&crate::filters::Filter>,
) -> serde_json::Map<String, Value> {
    let mut leave = serde_json::Map::new();
    for room in left {
        if filter.is_some_and(|f| !f.allows_room(&room.room_id)) {
            continue;
        }
        // No `state` block: the state of a room you are not in is not yours to
        // read, and the departure event in the timeline already says what a
        // client needs -- that you are out, and how you came to be.
        leave.insert(
            room.room_id,
            json!({
                "timeline": timeline_block(room.events, room.limited, room.prev_batch),
            }),
        );
    }
    leave
}

/// A joined room's timeline events as this device may see them: the
/// client's timeline filter applied, and its own transaction IDs on the
/// events it sent.
fn sync_timeline(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_filter: Option<&crate::filters::RoomFilter>,
    events: Vec<Value>,
) -> Vec<Value> {
    crate::filters::Filter::apply(room_filter.and_then(|room| room.timeline.as_ref()), events)
        .into_iter()
        .map(|event| with_transaction_id(state, identity, event))
        .collect()
}

/// A sync `timeline` block. `prev_batch` is where the window begins, as
/// the token `/messages?dir=b` pages back from (#331); absent only for an
/// empty window, since a client with no token cannot page back at all.
fn timeline_block(events: Vec<Value>, limited: bool, prev_batch: Option<i64>) -> Value {
    let mut block = serde_json::Map::new();
    block.insert("events".to_owned(), Value::Array(events));
    block.insert("limited".to_owned(), json!(limited));
    if let Some(li) = prev_batch {
        block.insert(
            "prev_batch".to_owned(),
            json!(crate::tokens::Pagination(li).to_string()),
        );
    }
    Value::Object(block)
}

/// MSC4354: the room's unexpired sticky events this client has not been
/// sent -- all of them on an initial sync or on joining, those since the
/// token otherwise -- minus what the timeline already carries, each
/// stamped with the time it has left. Not subject to the room filter, as
/// the MSC says. Empty when there is nothing to hand over, so the section
/// is left out.
fn sticky_section(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    timeline: &[Value],
    since: Option<u64>,
) -> Result<Vec<Value>, MatrixError> {
    let joined_now = timeline.iter().any(|event| {
        event["type"] == "m.room.member"
            && event["state_key"] == json!(user_id)
            && event["content"]["membership"] == json!("join")
    });
    let in_timeline: std::collections::HashSet<&str> = timeline
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect();
    let events = state
        .rooms
        .sticky_events(room_id, if joined_now { None } else { since })
        .map_err(room_error)?
        .into_iter()
        .filter(|(id, _, _)| !in_timeline.contains(id.as_str()))
        .map(|(_, mut event, ttl)| {
            event["unsigned"]["msc4354_sticky_duration_ttl_ms"] = json!(ttl);
            event
        })
        .collect();
    state
        .rooms
        .prune_erased_events(user_id, room_id, events)
        .map_err(room_error)
}

#[allow(
    clippy::too_many_lines,
    reason = "every section of one joined room, in the order the response holds them"
)]
fn sync_join(
    state: &AppState,
    identity: &crate::accounts::Identity,
    rooms: Vec<crate::rooms::SyncRoom>,
    filter: Option<&crate::filters::Filter>,
    state_label: &'static str,
    (since, until): (Option<u64>, u64),
) -> Result<BTreeMap<String, Box<RawValue>>, MatrixError> {
    let mut join: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    // Readers whose receipt moved inside this sync's window, local or
    // federated, per room: what an incremental sync owes as `m.receipt`.
    let moved_receipts = since.map(|since| {
        state
            .rooms
            .receipt_readers_since(joined.iter().map(String::as_str), since, until)
    });
    let receipts_for = |room_id: &str, timeline: &[Value]| {
        sync_receipts(
            state,
            identity,
            room_id,
            moved_receipts
                .as_ref()
                .map(|moved| moved.get(room_id).map_or(&[][..], Vec::as_slice)),
            timeline,
        )
    };
    for room in rooms {
        if filter.is_some_and(|f| !f.allows_room(&room.room_id)) {
            continue;
        }
        let unread = state
            .rooms
            .unread(&room.room_id, &identity.user_id)
            .map_err(room_error)?;
        let badge = badge(state, identity, &room.room_id, &unread)?;
        // Sent in full on every sync, incremental ones included, rather than
        // only when it changed. Account data has no stream position of its
        // own -- the sync token counts room events, and a `PUT` to
        // `/account_data` appends nothing -- so sending only the delta would
        // need a second cursor. Until there is one, repeating it is the
        // answer that cannot silently drop a change.
        let room_data = state
            .account_data
            .all(&identity.user_id, &room.room_id)
            .map_err(|error| account_data_error(&error))?;
        let typing = state.typing.event(&room.room_id);
        let room_filter = filter.map(|filter| &filter.room);
        let events = sync_timeline(state, identity, room_filter, room.events);
        let receipts = receipts_for(&room.room_id, &events)?;
        let mut room_state = crate::filters::Filter::apply(
            room_filter.and_then(|room| room.state.as_ref()),
            room.state,
        );
        // Lazy-loaded members: send only the membership events this response
        // makes the client need -- the senders in its timeline -- instead of
        // the whole roster. In a 10,000-member room the roster *is* the
        // initial sync, and a client renders none of it until someone speaks.
        //
        // The syncing user's own membership is always kept: the spec permits
        // redundant members, and a client that cannot find itself in the
        // state it was sent tends to conclude it is not in the room.
        if room_filter
            .and_then(|room| room.state.as_ref())
            .and_then(|state| state.lazy_load_members)
            == Some(true)
        {
            let needed: std::collections::HashSet<&str> = events
                .iter()
                .filter_map(|event| event["sender"].as_str())
                .chain(std::iter::once(identity.user_id.as_str()))
                .collect();
            room_state.retain(|event| {
                event["type"] != "m.room.member"
                    || event["state_key"]
                        .as_str()
                        .is_some_and(|member| needed.contains(member))
            });
        }
        let room_data = crate::filters::Filter::apply(
            room_filter.and_then(|room| room.account_data.as_ref()),
            room_data,
        );
        let sticky = sticky_section(state, &identity.user_id, &room.room_id, &events, since)?;
        let mut entry: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
        entry.insert(
            "timeline",
            raw(&timeline_block(events, room.limited, room.prev_batch))?,
        );
        if !sticky.is_empty() {
            entry.insert("msc4354_sticky", raw(&json!({ "events": sticky }))?);
        }
        // `state` is the state before the window and `state_after` (MSC4222)
        // the state after it; `Rooms::sync` read whichever the flag asked
        // for, so here the flag only picks the label. The cached case:
        // `Rooms::sync` materialized nothing because the window holds no
        // state event, so the render of the state *now* is exactly the
        // bytes this block should carry either way. Spliced rather than
        // parsed and re-serialized -- which is the whole point, since
        // parsing it only to serialize it back is the cost this avoids.
        let state_json = if room.cached_state {
            let rendered = state
                .rooms
                .state_serialized_unscoped(&room.room_id)
                .map_err(room_error)?;
            RawValue::from_string(format!(r#"{{"events":{rendered}}}"#))
                .map_err(|error| MatrixError::internal(&error.to_string()))?
        } else {
            raw(&json!({ "events": room_state }))?
        };
        entry.insert(state_label, state_json);
        entry.insert("account_data", raw(&json!({ "events": room_data }))?);
        entry.insert(
            "ephemeral",
            raw(&json!({
                "events": crate::filters::Filter::apply(
                    room_filter.and_then(|room| room.ephemeral.as_ref()),
                    typing.into_iter().chain(receipts).collect(),
                ),
            }))?,
        );
        let by_thread = room_filter
            .and_then(|room| room.timeline.as_ref())
            .and_then(|timeline| timeline.unread_thread_notifications)
            .unwrap_or(false);
        for (key, value) in badge_sections(&badge, by_thread)? {
            entry.insert(key, value);
        }
        join.insert(room.room_id, raw(&entry)?);
    }

    sync_ephemeral_only(
        state,
        identity,
        filter,
        &joined,
        moved_receipts.as_ref(),
        &mut join,
    )?;
    Ok(join)
}

/// A room where the only news is that someone is typing, or that a
/// receipt moved, has no timeline events, so `Rooms::sync` leaves it out
/// -- correctly, since it knows nothing about either. Adding it back here
/// is what keeps both out of the log layer entirely.
fn sync_ephemeral_only(
    state: &AppState,
    identity: &crate::accounts::Identity,
    filter: Option<&crate::filters::Filter>,
    joined: &[String],
    moved_receipts: Option<&std::collections::HashMap<String, Vec<String>>>,
    join: &mut BTreeMap<String, Box<RawValue>>,
) -> Result<(), MatrixError> {
    for room_id in joined {
        if join.contains_key(room_id) || filter.is_some_and(|f| !f.allows_room(room_id)) {
            continue;
        }
        // An initial sync spoke about every room already; only an
        // incremental one has receipt-only rooms to add.
        let receipts = match moved_receipts.and_then(|moved| moved.get(room_id)) {
            Some(readers) => sync_receipts(state, identity, room_id, Some(readers), &[])?,
            None => None,
        };
        let events: Vec<Value> = state
            .typing
            .event(room_id)
            .into_iter()
            .chain(receipts)
            .collect();
        let events = crate::filters::Filter::apply(
            filter.and_then(|filter| filter.room.ephemeral.as_ref()),
            events,
        );
        if events.is_empty() {
            continue;
        }
        join.insert(
            room_id.clone(),
            raw(&json!({ "ephemeral": { "events": events } }))?,
        );
    }
    Ok(())
}

/// The `m.receipt` event one room's `/sync` entry carries, if any.
///
/// Incrementally (`moved` is `Some`), the receipts of every reader whose
/// receipt moved in the window -- local or from another server. On an
/// initial sync, the receipts on the events in the timeline being sent
/// plus the caller's own (others capped at the newest
/// [`crate::receipts::MAX_INITIAL_RECEIPTS`]): what a client draws read
/// markers on, without shipping a ten-thousand-member room's whole receipt
/// table on login.
fn sync_receipts(
    state: &AppState,
    identity: &crate::accounts::Identity,
    room_id: &str,
    moved: Option<&[String]>,
    timeline: &[Value],
) -> Result<Option<Value>, MatrixError> {
    let rows: Vec<crate::receipts::ReceiptRow> = match moved {
        Some([]) => return Ok(None),
        Some(readers) => readers_receipts(state, room_id, readers)?,
        None => {
            let shown: std::collections::HashSet<&str> = timeline
                .iter()
                .filter_map(|event| event["event_id"].as_str())
                .collect();
            crate::receipts::newest(
                state
                    .rooms
                    .room_receipts(room_id)
                    .map_err(room_error)?
                    .into_iter()
                    .filter(|(user, _, event_id, _, _)| {
                        *user == identity.user_id || shown.contains(event_id.as_str())
                    }),
                &identity.user_id,
                crate::receipts::MAX_INITIAL_RECEIPTS,
            )
        }
    };
    let content = crate::receipts::event_content(rows, &identity.user_id);
    Ok((!content.is_empty()).then(|| json!({ "type": "m.receipt", "content": content })))
}

/// Every receipt the named readers hold in a room, as rows.
fn readers_receipts(
    state: &AppState,
    room_id: &str,
    readers: &[String],
) -> Result<Vec<crate::receipts::ReceiptRow>, MatrixError> {
    let mut rows = Vec::new();
    for reader in readers {
        for (receipt_type, event_id, ts, thread) in state
            .rooms
            .user_receipts(room_id, reader)
            .map_err(room_error)?
        {
            rows.push((reader.clone(), receipt_type, event_id, ts, thread));
        }
    }
    Ok(rows)
}
