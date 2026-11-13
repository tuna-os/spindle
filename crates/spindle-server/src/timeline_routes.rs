//! Reading and writing a room's timeline: sending, history, context,
//! receipts, relations, threads and redaction.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::ratelimit::{Budget, limit_write};
use crate::rooms::ClientTransaction;
use crate::routes::{
    DelayQuery, TimestampToEventQuery, as_seen_by, delay_error, may_read_room, optional_body,
    room_error, timestamp_lookup, with_transaction_id,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};

/// Everything that reads or writes a room's log, and its state.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
            axum::routing::put(send_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/messages",
            get(room_messages),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
            post(set_receipt),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/read_markers",
            post(read_markers),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
            axum::routing::put(redact_event),
        )
        // Three arities, because the spec has three and a client may use any.
        // `/v1` rather than `/v3`: relations arrived on the versioned path
        // (MSC2675) and that is where clients look for them.
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
            get(relations_all),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
            get(relations_by_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
            get(relations_by_event_type),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/threads",
            get(room_threads),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
            get(room_timestamp_to_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
            get(room_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
            get(room_context),
        )
}

/// `POST /_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}`
///
/// The body may name a thread (MSC3771, spec v1.4): `main` for the main
/// timeline or a thread root's event ID. A receipt with no thread is
/// unthreaded and covers everything.
async fn set_receipt(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, receipt_type, event_id)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    let request: ReceiptRequest = optional_body(&body)?;
    state
        .rooms
        .set_receipt(
            &room_id,
            &identity.user_id,
            &receipt_type,
            &event_id,
            request.thread_id.as_deref(),
        )
        .map_err(room_error)?;
    // The room's other servers hear about a public receipt in their next
    // transaction (#624); a private one never leaves.
    crate::receipts::federate(
        &state,
        &room_id,
        &identity.user_id,
        &receipt_type,
        &event_id,
        request.thread_id.as_deref(),
    );
    Ok(Json(json!({})))
}

#[derive(Debug, Default, Deserialize)]
struct ReceiptRequest {
    thread_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReadMarkers {
    #[serde(rename = "m.fully_read")]
    fully_read: Option<String>,
    #[serde(rename = "m.read")]
    read: Option<String>,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/read_markers`
///
/// Two markers with different jobs: `m.fully_read` is private and is where the
/// client puts its "jump to first unread" line, while `m.read` is public and
/// is what other people see and what the unread count is measured from. A
/// client may set either or both, so neither is required.
async fn read_markers(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(markers): Json<ReadMarkers>,
) -> Result<Json<Value>, MatrixError> {
    for (receipt_type, event_id) in [
        ("m.fully_read", markers.fully_read.as_deref()),
        ("m.read", markers.read.as_deref()),
    ] {
        if let Some(event_id) = event_id {
            state
                .rooms
                .set_receipt(&room_id, &identity.user_id, receipt_type, event_id, None)
                .map_err(room_error)?;
            // `m.read` federates; `m.fully_read` is the reader's own.
            crate::receipts::federate(
                &state,
                &room_id,
                &identity.user_id,
                receipt_type,
                event_id,
                None,
            );
        }
    }
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct RedactRequest {
    reason: Option<String>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}`
///
/// Replayed like `/send`. A duplicated redaction is the mildest duplicate --
/// it redacts an already-redacted event -- but it still mints a second
/// event into the log, and the log is forever.
async fn redact_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, txn_id)): axum::extract::Path<(String, String, String)>,
    Json(request): Json<RedactRequest>,
) -> Result<Json<Value>, MatrixError> {
    let transaction = ClientTransaction {
        user_id: &identity.user_id,
        device_id: &identity.device_id,
        txn_id: &txn_id,
    };
    with_transaction(&state, &transaction, || async {
        // Inside the mint, so a replayed transaction spends nothing.
        limit_write(&state, Budget::Message, &identity.user_id)?;
        state
            .rooms
            .redact_checked(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                &event_id,
                request.reason.as_deref(),
                Some(&transaction),
            )
            .await
            .map_err(room_error)
    })
    .await
}

#[derive(Debug, Deserialize)]
struct RelationsQuery {
    from: Option<String>,
    limit: Option<usize>,
}

async fn relations_all(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        None,
        None,
        &query,
    )
}

async fn relations_by_type(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, rel_type)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        Some(&rel_type),
        None,
        &query,
    )
}

async fn relations_by_event_type(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id, rel_type, event_type)): axum::extract::Path<(
        String,
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<RelationsQuery>,
) -> Result<Json<Value>, MatrixError> {
    relations(
        &state,
        &identity.user_id,
        &room_id,
        &event_id,
        Some(&rel_type),
        Some(&event_type),
        &query,
    )
}

/// `GET /_matrix/client/v1/rooms/{room_id}/relations/{event_id}[/{rel_type}[/{event_type}]]`
fn relations(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    event_id: &str,
    rel_type: Option<&str>,
    event_type: Option<&str>,
    query: &RelationsQuery,
) -> Result<Json<Value>, MatrixError> {
    // Every edit, reply, reaction and thread reply hanging off an event --
    // and an `m.replace` carries the replacement's whole new body, so this
    // reads as much of a private room as `/messages` does.
    may_read_room(state, user_id, room_id)?;
    // The same `t`-tagged pagination token `/messages` uses, because it is the
    // same thing: a position in this room's linear index. A Synapse token
    // this room cannot place starts again from the newest (#568).
    let from = match query.from.as_deref() {
        Some(token) => room_page_token(state, room_id, token)?,
        None => None,
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let (chunk, next) = state
        .rooms
        .relations(room_id, event_id, rel_type, event_type, from, limit)
        .map_err(room_error)?;

    let chunk = state
        .rooms
        .prune_erased_events(user_id, room_id, chunk)
        .map_err(room_error)?;
    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    // Absent when there is nothing more, which is how a client stops.
    if let Some(next) = next {
        body.insert(
            "next_batch".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

#[derive(Debug, Deserialize)]
struct ThreadsQuery {
    from: Option<String>,
    limit: Option<usize>,
    include: Option<String>,
}

/// `GET /_matrix/client/v1/rooms/{room_id}/timestamp_to_event`
///
/// Jump-to-date: the client has a calendar date and wants somewhere in the
/// timeline to start paginating from. It asks for the event nearest a
/// timestamp on one side, then pages from there with `/messages`.
///
/// `dir` is required and has no default. `f` and `b` are opposite answers to
/// the same question, and a client that omitted it by mistake would get a
/// plausible event from the wrong side of the date and page away from what it
/// was looking for -- a silently wrong answer, which is worse than a 400.
///
/// The room is subject to the same read rule as every other room read.
async fn room_timestamp_to_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<TimestampToEventQuery>,
) -> Result<Json<Value>, MatrixError> {
    may_read_room(&state, &identity.user_id, &room_id)?;
    timestamp_lookup(&state, &room_id, &query)
}

/// `GET /_matrix/client/v1/rooms/{room_id}/threads`
///
/// The chunk is thread *roots*, each carrying the `m.thread` aggregate in
/// `unsigned.m.relations` — so a client renders the list, with each thread's
/// reply count and latest reply, from this one response.
///
/// `include` is `all` or `participated`; anything else is a 400 rather than a
/// silent fallback to `all`, because the two answers differ and a client that
/// misspells the value would otherwise be shown other people's threads and
/// never learn why.
async fn room_threads(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<ThreadsQuery>,
) -> Result<Json<Value>, MatrixError> {
    // `threads` already takes the viewer, which is what made this one look
    // guarded. It is not: the viewer decides the `participated` filter, and
    // the only access check underneath is that the room exists.
    may_read_room(&state, &identity.user_id, &room_id)?;
    let participated_only = match query.include.as_deref() {
        None | Some("all") => false,
        Some("participated") => true,
        Some(other) => {
            return Err(MatrixError::bad_json(format!(
                "include must be 'all' or 'participated', not {other:?}"
            )));
        }
    };
    // The same `t`-tagged token the rest of the room's pagination uses: this
    // is a position in the same linear index. Synapse's `/threads` tokens
    // are `{depth}_{stream}`; one kept across the migration starts the
    // list again from the newest thread rather than failing (#568).
    let synapse_threads_token = |token: &str| {
        token.split_once('_').is_some_and(|(depth, stream)| {
            [depth, stream]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    let from = match query.from.as_deref() {
        Some(token) if synapse_threads_token(token) => None,
        Some(token) => room_page_token(&state, &room_id, token)?,
        None => None,
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let (roots, next) = state
        .rooms
        .threads(&room_id, &identity.user_id, participated_only, from, limit)
        .map_err(room_error)?;

    let roots = state
        .rooms
        .prune_erased_events(&identity.user_id, &room_id, roots)
        .map_err(room_error)?;
    let chunk: Vec<Value> = roots
        .into_iter()
        .map(|root| as_seen_by(&state, &room_id, &identity, root))
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    if let Some(next) = next {
        body.insert(
            "next_batch".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/event/{event_id}`
async fn room_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    let event = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.event(&event_id))
        .map_err(room_error)?
        .ok_or_else(|| MatrixError::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", "no such event"))?;
    Ok(Json(as_seen_by(&state, &room_id, &identity, event)))
}

#[derive(Debug, Deserialize)]
struct ContextQuery {
    limit: Option<usize>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/context/{event_id}`
///
/// What a permalink resolves to: the event, a symmetric window either side of
/// it, and the room's state as it stood there.
async fn room_context(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<ContextQuery>,
) -> Result<Json<Value>, MatrixError> {
    // The spec's limit is the total window. It is split the way Synapse
    // splits it -- the floor before, the rest after -- because that is the
    // split clients have learned: matrix-rust-sdk's permalink timeline asks
    // for one context event and lays out a window of two, and an extra
    // neighbour on the earlier side shifted every item it then indexed.
    // Zero is a real ask, the event alone with tokens to page out from.
    let limit = query.limit.unwrap_or(10).min(100);
    let before = limit / 2;
    let after = limit - before;

    let context = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.context(&event_id, before, after))
        .map_err(room_error)?;

    Ok(Json(json!({
        "event": as_seen_by(&state, &room_id, &identity, context.event),
        "events_before": context
            .events_before
            .into_iter()
            .map(|event| with_transaction_id(&state, &identity, event))
            .collect::<Vec<_>>(),
        "events_after": context
            .events_after
            .into_iter()
            .map(|event| with_transaction_id(&state, &identity, event))
            .collect::<Vec<_>>(),
        "state": context.state,
        // The same `t`-tagged tokens `/messages` pages with, because they are
        // positions in the same index -- so a client can carry on paginating
        // outwards from either edge of the window.
        "start": crate::tokens::Pagination(context.start).to_string(),
        "end": crate::tokens::Pagination(context.end).to_string(),
    })))
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}`
/// Replay a transaction if this device has already sent it, or run `mint`,
/// which records the transaction in its event's own batch.
///
/// The check-then-record is not atomic, and deliberately so: the race it
/// leaves open is two *concurrent* retries of the same transaction, which can
/// both mint. Closing it would mean a lock held across `append`. The failure
/// the spec's idempotency exists for is the sequential retry -- a client that
/// timed out, cannot know whether its send landed, and asks again -- and that
/// case a durable read-then-write handles completely, including across a
/// server restart, which an in-memory lock would not.
///
/// Only an event that landed is recorded. A refused send must stay
/// refusable: recording a failure would replay the *error* forever, and
/// recording nothing means the retry gets a fresh chance, which is what a
/// client expects of a 429 or an auth refusal that a later state change
/// resolves. A send whose event landed and whose response is still an
/// error -- a sync the full disk refused -- is replayed with its event,
/// not sent again (#779).
async fn with_transaction<F: Future<Output = Result<String, MatrixError>>>(
    state: &AppState,
    transaction: &ClientTransaction<'_>,
    mint: impl FnOnce() -> F,
) -> Result<Json<Value>, MatrixError> {
    let key = transaction.key();
    let _turn = state.transactions.enter(&key).await;
    if let Ok(Some(stored)) = spindle_store::ReadView::get(state.store.as_ref(), &key)
        && let Ok(event_id) = String::from_utf8(stored)
    {
        return Ok(Json(json!({ "event_id": event_id })));
    }
    let event_id = mint().await?;
    Ok(Json(json!({ "event_id": event_id })))
}

/// The budgets a `PUT /send` spends before anything else looks at it.
///
/// A ring has a budget of its own (#39): it is the one event that makes
/// every phone in the room sound, so it is counted per sender, delayed or
/// not. Counted on the attempt, so a sender the room refuses still spends
/// budget; the budget is against the trying. Every send, ring or not, also
/// spends the account's message budget (#741) -- except a retried
/// transaction, which is answered from what it recorded and mints nothing,
/// so a client retrying after a lost response is not refused for having
/// already succeeded.
fn limit_send(
    state: &AppState,
    identity: &crate::accounts::Identity,
    event_type: &str,
    txn_id: &str,
) -> Result<(), MatrixError> {
    if crate::push::is_ring(event_type) {
        let limit = crate::ratelimit::Limit::new(
            state.config.ratelimit.rings_per_minute,
            std::time::Duration::from_secs(60),
        );
        if let Err(retry) = state
            .limiter
            .check(&format!("ring:{}", identity.user_id), limit)
        {
            return Err(MatrixError::limit_exceeded(retry.as_millis()));
        }
    }
    let key = spindle_core::keys::transaction(&identity.user_id, &identity.device_id, txn_id);
    if matches!(
        spindle_store::ReadView::get(state.store.as_ref(), &key),
        Ok(Some(_))
    ) {
        return Ok(());
    }
    limit_write(state, Budget::Message, &identity.user_id)
}

async fn send_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, txn_id)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    limit_send(&state, &identity, &event_type, &txn_id)?;
    // MSC4140 rides the existing send rather than adding a parallel one: the
    // event, its authorization and its transaction handling are identical,
    // and only *when* it is appended changes. A separate endpoint would be a
    // second copy of all of that, drifting.
    if let Some(delay_ms) = query.delay {
        // The room is checked now, not when it fires: a client that cannot
        // send here should be told so while it is still listening, rather
        // than have its event silently refused an hour later.
        if !state
            .rooms
            .is_joined(&identity.user_id, &room_id)
            .unwrap_or(false)
        {
            return Err(MatrixError::forbidden(format!(
                "{} is not in {room_id}",
                identity.user_id
            )));
        }
        let delay_id = state
            .delayed
            .schedule(
                &room_id,
                &identity.user_id,
                &event_type,
                None,
                &content,
                delay_ms,
                query.sticky,
            )
            .map_err(delay_error)?;
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    // MSC3995 hub mode (#22): in a room another Spindle hubs, the event is
    // sequenced there first. `None` is "not a hub room here" or "the hub
    // could not be used before anything was built", and the ordinary path
    // below runs exactly as it would in a build without the feature.
    #[cfg(feature = "hub-mode")]
    if query.sticky.is_none()
        && let Some(response) = Box::pin(crate::hub::send_with_transaction(
            &state,
            &identity,
            &txn_id,
            &room_id,
            &event_type,
            None,
            &content,
        ))
        .await?
    {
        return Ok(response);
    }
    let transaction = ClientTransaction {
        user_id: &identity.user_id,
        device_id: &identity.device_id,
        txn_id: &txn_id,
    };
    let response = with_transaction(&state, &transaction, || async {
        state
            .rooms
            .send_sticky_checked(
                &room_id,
                &identity.user_id,
                state.key.pair(),
                &event_type,
                &content,
                query.sticky,
                Some(&transaction),
            )
            .await
            .map_err(room_error)
    })
    .await?;
    #[cfg(feature = "hub-mode")]
    crate::hub::after_local_send(&state, &room_id);
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    from: Option<String>,
    to: Option<String>,
    dir: Option<String>,
    limit: Option<usize>,
}

/// What a room-pagination token names, as a gap in `room_id`'s linear
/// index: ours directly, a Synapse one through the positions the importer
/// recorded (#568).
///
/// `Ok(None)` is a Synapse token this room has no positions for -- a room
/// that was not imported, or one imported before positions were kept. The
/// caller decides what that falls back to; it is not a 400, because the
/// client kept the token honestly, and refusing it leaves the client unable
/// to scroll past what it had cached, every time it tries.
fn room_page_token(
    state: &AppState,
    room_id: &str,
    token: &str,
) -> Result<Option<i64>, MatrixError> {
    match crate::tokens::Pagination::resume(token)
        .map_err(|error| MatrixError::bad_json(error.to_string()))?
    {
        crate::tokens::PageFrom::Ours(position) => Ok(Some(position)),
        crate::tokens::PageFrom::Synapse(position) => {
            match state
                .rooms
                .synapse_gap(room_id, position)
                .map_err(room_error)?
            {
                Some(crate::rooms::SynapseGap::At(gap)) => Ok(Some(gap)),
                Some(crate::rooms::SynapseGap::BeforeAll) => Ok(Some(i64::MIN)),
                None => Ok(None),
            }
        }
    }
}

/// `GET /_matrix/client/v3/rooms/{room_id}/messages`
///
/// The pagination token is the linear index, which is what SPEC 10.2's
/// "tokens are opaque to clients" buys: the ordering already exists, so there
/// is nothing to sort at read time and nothing to maintain alongside.
///
/// A token is a gap: `t{p}` sits just below the entry at `p`. `dir=b` pages
/// down from it and `dir=f` up from it, so `/context`'s `end` and a forward
/// page's `end` are where the next forward page starts, and the two
/// directions agree on what one token means. Forward paging is what a
/// client does from a permalink, a reply, a search hit or a notification:
/// Element X's focused timeline is `/context` and then `dir=f` (#568).
async fn room_messages(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MessagesQuery>,
) -> Result<Json<Value>, MatrixError> {
    let reader = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .map_err(room_error)?;
    // The spec requires `dir`; a request without one is still read as
    // backward, which is what every caller that left it out meant.
    let direction = match query.dir.as_deref() {
        Some("f") => crate::rooms::Direction::Forward,
        Some("b") | None => crate::rooms::Direction::Backward,
        Some(other) => {
            return Err(MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                format!("dir must be 'f' or 'b', not {other:?}"),
            ));
        }
    };
    let from = match query.from.as_deref() {
        Some(token) => match room_page_token(&state, &room_id, token)? {
            Some(position) => Some(position),
            // A Synapse token with no recorded position. Going back, page
            // from the head: the client is handed events it may already
            // hold, drops them, and carries on with our `end` from there
            // -- a longer scroll, never a lost one. Going forward, there
            // is no telling where it was, so the page is empty and says
            // it has reached the live end, which a forward walk then
            // follows from `/sync`.
            None => match direction {
                crate::rooms::Direction::Backward => None,
                crate::rooms::Direction::Forward => Some(i64::MAX),
            },
        },
        None => None,
    };
    // `to` bounds the page; one this room cannot place bounds nothing.
    let to = match query.to.as_deref() {
        Some(token) => room_page_token(&state, &room_id, token)?,
        None => None,
    };
    let limit = query.limit.unwrap_or(10).clamp(1, 100);
    // Paging back into a room whose history has a gap still being filled:
    // put that room first in the backfill loop's queue (#619). The page
    // itself is served from what is held now; it does not wait.
    if matches!(direction, crate::rooms::Direction::Backward)
        && state.rooms.has_open_gap(&room_id).unwrap_or(false)
    {
        state.backfill.poke(&room_id);
    }

    let (events, next) = reader
        .page(
            crate::rooms::Page {
                from,
                to,
                direction,
            },
            limit,
        )
        .map_err(room_error)?;

    let chunk: Vec<Value> = events
        .iter()
        .map(|event| {
            let mut json = event.json.clone();
            if let Some(object) = json.as_object_mut() {
                object.insert("event_id".to_owned(), json!(event.event_id));
            }
            as_seen_by(&state, &room_id, &identity, json)
        })
        .collect();

    let mut body = serde_json::Map::new();
    body.insert("chunk".to_owned(), Value::Array(chunk));
    // Where this chunk began. Without a `from` that is the room's head, which
    // is one past the newest event -- not the literal string "end", which is
    // what this sent before and which no client could page from. Forward,
    // it is the room's beginning. With a `from`, it is that token as the
    // client sent it, which the spec asks for and which keeps a Synapse
    // token the client's own.
    let start = match query.from {
        Some(token) => token,
        None => crate::tokens::Pagination(match direction {
            crate::rooms::Direction::Backward => {
                events.first().map_or(0, |event| event.li.saturating_add(1))
            }
            crate::rooms::Direction::Forward => events.first().map_or(0, |event| event.li),
        })
        .to_string(),
    };
    body.insert("start".to_owned(), json!(start));
    // Absent when there is nothing more, which is how a client knows to stop.
    if let Some(next) = next {
        body.insert(
            "end".to_owned(),
            json!(crate::tokens::Pagination(next).to_string()),
        );
    }
    Ok(Json(Value::Object(body)))
}
