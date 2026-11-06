//! Room lifecycle: creating a room, getting in and out of it, its members,
//! its state, and its place in a space.

use crate::AppState;
use crate::auth::Authenticated;
use crate::errors::MatrixError;
use crate::inbound::{join_candidates, merge_returned_signatures, sign_membership_template};
use crate::ratelimit::{Budget, limit_write, limit_write_on};
use crate::routes::{
    DelayQuery, chunk_of, delay_error, directory_error, may_read_room, optional_body, room_error,
    space_children,
};
use axum::{
    Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Creating a room, getting in and out of one, and who else is there.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_matrix/client/v1/mutual_rooms", get(mutual_rooms))
        .route("/_matrix/client/v3/joined_rooms", get(joined_rooms))
        .route("/_matrix/client/v3/createRoom", post(create_room))
        .route(
            "/_matrix/client/v3/rooms/{room_id}/invite",
            post(invite_to_room),
        )
        .route("/_matrix/client/v3/rooms/{room_id}/join", post(join_room))
        .route("/_matrix/client/v3/rooms/{room_id}/leave", post(leave_room))
        .route(
            "/_matrix/client/v3/rooms/{room_id}/kick",
            post(kick_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/ban",
            post(ban_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/unban",
            post(unban_from_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/forget",
            post(forget_room),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/joined_members",
            get(room_joined_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/members",
            get(room_members),
        )
        .route(
            "/_matrix/client/v3/join/{room_id_or_alias}",
            post(join_room_by_id_or_alias),
        )
        .route(
            "/_matrix/client/v3/knock/{room_id_or_alias}",
            post(knock_room),
        )
        .route(
            "/_matrix/client/v1/rooms/{room_id}/hierarchy",
            get(room_hierarchy),
        )
        // Two paths for one endpoint. MSC3266 shipped under the unstable
        // prefix long enough that clients still ask for it there, and it
        // became `/v1/room_summary` in Matrix 1.15. Serving both costs one
        // route and spares every client a version probe.
        .route(
            "/_matrix/client/v1/room_summary/{room_id_or_alias}",
            get(room_summary),
        )
        .route(
            "/_matrix/client/unstable/im.nheko.summary/rooms/{room_id_or_alias}/summary",
            get(room_summary),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/typing/{user_id}",
            axum::routing::put(set_typing),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/upgrade",
            post(upgrade_room),
        )
        .route("/_matrix/client/v3/rooms/{room_id}/state", get(room_state))
        // Two routes, because the spec has two forms and a router cannot
        // match an empty trailing segment: `/state/m.room.topic` means the
        // same as `/state/m.room.topic/""`, and a client may send either.
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
            get(room_state_event_default).put(set_room_state_default),
        )
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
            get(room_state_event).put(set_room_state),
        )
        // …and the trailing-slash spelling: matrix-bot-sdk — hookshot
        // and most Node bots — writes the empty state key as an empty
        // final segment, which axum matches to neither pattern above.
        .route(
            "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/",
            get(room_state_event_default).put(set_room_state_default),
        )
}

#[derive(Debug, Default, Deserialize)]
struct CreateRoomRequest {
    name: Option<String>,
    topic: Option<String>,
    preset: Option<String>,
    #[serde(default)]
    invite: Vec<String>,
    /// The invites carry `is_direct: true`, which is how the invitee's
    /// client knows to file the room under direct chats (and, by the
    /// spec, to write its own `m.direct`). Not a room property here: the
    /// server keeps no notion of a DM beyond what the member events say.
    #[serde(default)]
    is_direct: bool,
    #[serde(default)]
    initial_state: Vec<InitialStateEvent>,
    room_alias_name: Option<String>,
    room_version: Option<String>,
    /// `"public"` publishes the new room in this server's directory.
    ///
    /// Defaults to private, which is what the spec asks for and also the
    /// safer way round: a client that forgets the field gets an unlisted
    /// room rather than an advertised one.
    visibility: Option<String>,
    /// Extra `m.room.create` content -- `type: "m.space"`, `m.federate`.
    ///
    /// The server keeps `room_version` and `creator` for itself; see
    /// [`crate::rooms::Rooms::create`].
    creation_content: Option<serde_json::Map<String, Value>>,
    /// Applied on top of the default `m.room.power_levels` content.
    ///
    /// The field every Element client uses to make a room one where a
    /// call can happen: `events` naming the call membership type at 0.
    /// See `power_levels_content` in the rooms module for the rules.
    power_level_content_override: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct InitialStateEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    state_key: String,
    content: Value,
}

/// `POST /_matrix/client/v3/createRoom`
async fn create_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    Json(request): Json<CreateRoomRequest>,
) -> Result<Json<Value>, MatrixError> {
    limit_write(&state, Budget::RoomCreation, &identity.user_id)?;
    let initial_state: Vec<(String, String, Value)> = request
        .initial_state
        .into_iter()
        .map(|event| (event.event_type, event.state_key, event.content))
        .collect();
    let room_id = state
        .rooms
        .create(
            &identity.user_id,
            state.key.pair(),
            request.name.as_deref(),
            request.topic.as_deref(),
            request.preset.as_deref(),
            &request.invite,
            &initial_state,
            // The version asked for, refused with M_UNSUPPORTED_ROOM_VERSION
            // when this server does not serve it. This used to substitute
            // v11 for any unlisted version, which let Complement's v7 knock
            // and v8 restricted-join tests pass on a room of the wrong
            // version; with those versions served there is nothing left
            // that the substitution kept working, and the spec asks for
            // the refusal.
            request.room_version.as_deref(),
            request.creation_content.as_ref(),
            request.power_level_content_override.as_ref(),
            &member_profile(&state, &identity.user_id),
        )
        .map_err(room_error)?;
    // Invites after the room stands, refused invites failing the create the
    // way the spec asks (the room still exists; the error names why).
    for target in &request.invite {
        invite_user(
            &state,
            &identity.user_id,
            &room_id,
            target,
            None,
            request.is_direct,
        )
        .await?;
    }
    if request.visibility.as_deref() == Some("public") {
        // The creator is joined by construction, so `may_advertise` would pass;
        // calling it anyway would be a round-trip to re-learn that.
        state
            .directory
            .publish(&room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?;
    }
    if let Some(localpart) = request.room_alias_name.as_deref() {
        let alias = format!("#{localpart}:{}", state.config.server.name);
        state
            .directory
            .create(&alias, &room_id, &identity.user_id)
            .map_err(|error| directory_error(&error))?;
        // The spec has the server write `m.room.canonical_alias` for a
        // room created with an alias, unless the client set one itself in
        // `initial_state`. Claiming an alias later through the directory
        // writes nothing (`aliases.rs`); this is the one place the server
        // speaks for the room, and only because the spec says it does.
        let client_set_one = initial_state
            .iter()
            .any(|(event_type, _, _)| event_type == "m.room.canonical_alias");
        if !client_set_one {
            state
                .rooms
                .set_state_checked(
                    &room_id,
                    &identity.user_id,
                    state.key.pair(),
                    "m.room.canonical_alias",
                    "",
                    &json!({ "alias": alias }),
                )
                .await
                .map_err(room_error)?;
        }
    }
    // A client's sync loop may already be long-polling while createRoom is
    // assembling the room. The room only becomes visible after `create`
    // installs its completed log, so wake once the whole operation (including
    // invites and aliases) is observable. Without this, Element Web leaves a
    // freshly-created DM on "We're creating a room" until its 30-second poll
    // happens to expire.
    state.rooms.wake_sync_waiters();
    Ok(Json(json!({ "room_id": room_id })))
}

/// `GET /_matrix/client/v3/joined_rooms`
async fn joined_rooms(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
) -> Result<Json<Value>, MatrixError> {
    let rooms = state
        .rooms
        .joined(&identity.user_id)
        .map_err(|error| MatrixError::internal(&error.to_string()))?;
    Ok(Json(json!({ "joined_rooms": rooms })))
}

/// The body every membership endpoint that names a target shares.
///
/// `/invite`, `/kick`, `/ban` and `/unban` differ only in the membership they
/// end up writing, so they differ only in the handler, not in the shape they
/// parse. `reason` is optional everywhere, including on `/invite`, where the
/// spec allows it even though few clients send one.
#[derive(Debug, Deserialize)]
struct TargetedMembershipRequest {
    user_id: String,
    reason: Option<String>,
}

/// The body of `/leave` and `/forget`, neither of which names a target.
#[derive(Debug, Default, Deserialize)]
struct SelfMembershipRequest {
    reason: Option<String>,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/invite`
async fn invite_to_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Both budgets: the sender's, and the invitee's, which is what stops a
    // handful of accounts taking turns at one person. Here rather than in
    // `invite_user`, so `createRoom`'s own `invite` list is not counted:
    // the room creation it rides on already was, as in Synapse.
    limit_write(&state, Budget::Invite, &identity.user_id)?;
    limit_write_on(&state, Budget::Invited, &identity.user_id, &request.user_id)?;
    invite_user(
        &state,
        &identity.user_id,
        &room_id,
        &request.user_id,
        request.reason.as_deref(),
        false,
    )
    .await?;
    Ok(Json(json!({})))
}

/// Invite one user, wherever their server is.
///
/// A local target is one membership event. A remote target is the spec's
/// invite handshake: build and sign the event here, hand it to the target's
/// server to co-sign over `v2/invite`, and only then append it — the
/// co-signed event is the one every other server in the room will accept as
/// proof the invitee's server was told. A refusal from that server fails
/// the invite, because an invite it never co-signed is one its user would
/// never see.
async fn invite_user(
    state: &AppState,
    sender: &str,
    room_id: &str,
    target: &str,
    reason: Option<&str>,
    is_direct: bool,
) -> Result<(), MatrixError> {
    let Some((_, domain)) = target.split_once(':') else {
        return Err(MatrixError::bad_json(format!("{target} is not a user ID")));
    };
    if domain == state.config.server.name {
        // An invite is the event that most often names a ghost that does
        // not exist yet; the user query gives its service the chance to
        // provision before the membership is written. The verdict is
        // deliberately unchecked — inviting an unclaimed unknown user is
        // still legal Matrix, and only IDs a service claims cost a request.
        let _ = state
            .appservices
            .query_user(target, &state.config.server.name)
            .await;
        let mut extra = member_profile(state, target);
        if is_direct {
            extra.insert("is_direct".to_owned(), json!(true));
        }
        state
            .rooms
            .set_membership_with_checked(
                room_id,
                sender,
                target,
                "invite",
                reason,
                &extra,
                state.key.pair(),
            )
            .await
            .map_err(room_error)?;
        return Ok(());
    }

    let (event_id, event) = state
        .rooms
        .build_invite_event_checked(room_id, sender, target, reason, is_direct, state.key.pair())
        .await
        .map_err(room_error)?;
    // The stripped state the invited user renders the invite from — plus
    // the invite itself, which is not yet state anywhere and is exactly the
    // line "who asked you in" a client shows first.
    let mut invite_state = state
        .rooms
        .stripped_state(room_id, target)
        .map_err(room_error)?;
    invite_state.push(json!({
        "type": "m.room.member",
        "state_key": target,
        "sender": event["sender"],
        "content": event["content"],
    }));
    // The room's version, not this build's default: the invitee hashes
    // the event under what this names.
    let version = state.rooms.room_version(room_id).map_err(room_error)?;
    let body = json!({
        "event": event,
        "invite_room_state": invite_state,
        "room_version": version.as_str(),
    });
    let response = state
        .federation
        .remote_invite(domain, room_id, &event_id, &body)
        .await
        .map_err(|error| {
            MatrixError::new(
                StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("{domain} did not accept the invite: {error}"),
            )
        })?;

    // What comes back must be the same event, co-signature aside — and the
    // reference hash proves it, because signatures are outside the hash.
    // (A v1/v2 ID is not the hash, so the hash is compared to the hash of
    // what was sent, and the ID to the ID.)
    let mut cosigned = response["event"].clone();
    let object = |value: &Value| match ruma::CanonicalJsonValue::try_from(value.clone()) {
        Ok(ruma::CanonicalJsonValue::Object(object)) => Some(object),
        _ => None,
    };
    let same = match (object(&cosigned), object(&event)) {
        (Some(theirs), Some(ours)) => {
            spindle_core::version::same_event(&theirs, &ours, &version)
                && spindle_core::version::event_id(&ours, &version).is_ok_and(|id| id == event_id)
        }
        _ => false,
    };
    if !same {
        return Err(MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("{domain} returned a different event than it was asked to sign"),
        ));
    }
    // The peer may return only its own signature; keep our approved proof.
    merge_returned_signatures(&mut cosigned, &event);
    state
        .rooms
        .commit_cosigned(room_id, &event_id, &cosigned)
        .map_err(room_error)?;
    state.rooms.wake_sync_waiters();
    Ok(())
}

/// `POST /_matrix/client/v3/rooms/{room_id}/kick`
///
/// A kick is a `leave` the target did not send, which is why it needs no
/// membership of its own: the spec's auth rules read the sender against the
/// target and decide whether the power levels allow it. That check is ruma's
/// (`docs/divergence.md` §3), so a member without kick power gets `M_FORBIDDEN`
/// from the same code path that refuses any other unauthorized state event.
async fn kick_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "leave").await
}

/// `POST /_matrix/client/v3/rooms/{room_id}/ban`
///
/// Ban is its own membership rather than a leave with a flag, because it has
/// to survive the target trying to rejoin: the auth rules refuse a join whose
/// current membership is `ban`, and they can only do that if the state says
/// `ban`.
async fn ban_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "ban").await
}

/// `POST /_matrix/client/v3/rooms/{room_id}/unban`
///
/// Unbanning writes `leave`, not "no membership": the room has no way to spell
/// "never here", and `leave` is the state a user who is not banned and not in
/// the room is in.
async fn unban_from_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<TargetedMembershipRequest>,
) -> Result<Json<Value>, MatrixError> {
    targeted_membership(&state, &identity.user_id, &room_id, &request, "leave").await
}

async fn targeted_membership(
    state: &AppState,
    sender: &str,
    room_id: &str,
    request: &TargetedMembershipRequest,
    membership: &str,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .set_membership_checked(
            room_id,
            sender,
            &request.user_id,
            membership,
            request.reason.as_deref(),
            state.key.pair(),
        )
        .await
        .map_err(room_error)?;
    // The spec's response is an empty object, not the event ID. A client that
    // wanted the event reads it from the timeline.
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/join`
async fn join_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Value>, MatrixError> {
    join(
        &state,
        &identity.user_id,
        &room_id,
        &server_name_params(query.as_deref()),
    )
    .await
}

/// The repeatable `server_name` query parameters a join may carry.
fn server_name_params(query: Option<&str>) -> Vec<String> {
    form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "server_name" || key == "via")
        .map(|(_, value)| value.into_owned())
        .collect()
}

/// `POST /_matrix/client/v3/knock/{roomIdOrAlias}`
///
/// Asking to be let into a room that will not simply admit you. For a room
/// this server holds, `m.room.member` with `membership: knock` goes through
/// the same append as any other membership, and the authorization rules
/// refuse it unless the join rule is `knock` or `knock_restricted` -- which
/// is why knocking on an invite-only room comes back 403 without a line
/// here saying so. For a room somewhere else, the knock is carried there
/// over `make_knock`/`send_knock` by [`knock_remote`].
///
/// Re-knocking is deliberately not special-cased. The rules allow
/// knock -> knock, so a user who knocks twice gets a second event and a
/// second chance to be noticed, which is what the spec's "may knock again"
/// amounts to.
async fn knock_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    let request: SelfMembershipRequest = optional_body(&body)?;
    let mut servers = server_name_params(query.as_deref());
    let room_id = resolve_room_target(&state, &room_id_or_alias, &mut servers).await?;
    // A knock is a request to join and costs what a join costs: one event
    // here, or a `make_knock`/`send_knock` handshake with another server.
    limit_write(&state, Budget::JoinLocal, &identity.user_id)?;
    match state
        .rooms
        .set_membership_with_checked(
            &room_id,
            &identity.user_id,
            &identity.user_id,
            "knock",
            request.reason.as_deref(),
            &member_profile(&state, &identity.user_id),
            state.key.pair(),
        )
        .await
    {
        Ok(_) => {
            state.rooms.wake_sync_waiters();
            Ok(Json(json!({ "room_id": room_id })))
        }
        // A room this server does not hold is knocked on through a server
        // that does.
        Err(crate::rooms::RoomError::UnknownRoom(_)) => {
            limit_write(&state, Budget::JoinRemote, &identity.user_id)?;
            knock_remote(
                &state,
                &identity.user_id,
                &room_id,
                request.reason.as_deref(),
                &servers,
            )
            .await
        }
        Err(error) => Err(room_error(error)),
    }
}

/// Walk the `make_knock`/`send_knock` handshake as the knocking server.
///
/// Deliberately not a smaller [`join_remote`]. A join ends with this server
/// holding the room: `send_join` hands back the state and the auth chain to
/// seed it from. A knock ends with this server holding *nothing* -- the
/// knocker is not a member, so no peer will send us the room's events, and
/// `send_knock` hands back only the stripped view the knocker may render
/// while they wait. What is recorded is therefore a side row, not a log.
///
/// The federated half of knocking was written once before (#224) and lost:
/// it merged into the branch it was stacked on after that branch had
/// already merged, so `main` never carried it, and every federated knock
/// subtest in Complement failed on the 404 this route used to answer with
/// (#231). This is that slice, on today's code.
async fn knock_remote(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    reason: Option<&str>,
    servers: &[String],
) -> Result<Json<Value>, MatrixError> {
    let candidates = join_candidates(
        &state.config.server.name,
        room_id,
        servers,
        knock_origin(state, user_id, room_id).as_deref(),
    );
    if candidates.is_empty() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{room_id} is not on this server and no server_name was given"),
        ));
    }

    let mut last_refusal = String::new();
    // A status a resident *chose* outranks anything a later candidate does,
    // because it is the room's own answer. Without this, a room that says
    // "no" and a network that says nothing reach the client identically,
    // and only one of them is worth retrying.
    let mut answered: Option<MatrixError> = None;
    for server in &candidates {
        let (mut template, version) = match state
            .federation
            .remote_make_knock(server, room_id, user_id)
            .await
        {
            Ok(body) => {
                let named = body["room_version"].as_str().unwrap_or_default();
                match ruma::RoomVersionId::try_from(named) {
                    Ok(version) if crate::surface::supports_room_version(named) => {
                        (body["event"].clone(), version)
                    }
                    _ => {
                        last_refusal =
                            format!("{server}: the room is version {named}, which we do not speak");
                        continue;
                    }
                }
            }
            Err(crate::federation::FederationError::Answered { status, body }) => {
                answered.get_or_insert_with(|| relayed_refusal(status, &body));
                last_refusal = format!("{server} refused make_knock: {status} {body}");
                continue;
            }
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        // The reason and the profile are the knocker's, so they go on after
        // the template. A resident server has no way to know either, and a
        // template that came back already carrying a reason would be the
        // resident putting words in the knocker's mouth.
        for (field, value) in member_profile(state, user_id) {
            template["content"][field] = value;
        }
        if let Some(reason) = reason {
            template["content"]["reason"] = json!(reason);
        }

        let (knock_id, knock) = match sign_membership_template(state, &template, &version) {
            Ok(signed) => signed,
            Err(error) => {
                last_refusal = format!("{server}: {error}");
                continue;
            }
        };

        let response = match state
            .federation
            .remote_send_knock(server, room_id, &knock_id, &knock)
            .await
        {
            Ok(body) => body,
            Err(crate::federation::FederationError::Answered { status, body }) => {
                answered.get_or_insert_with(|| relayed_refusal(status, &body));
                last_refusal = format!("{server} refused send_knock: {status} {body}");
                continue;
            }
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        let knock_state = response["knock_room_state"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        state
            .rooms
            .record_pending_knock(user_id, room_id, server, &knock_state)
            .map_err(room_error)?;
        state.rooms.wake_sync_waiters();
        return Ok(Json(json!({ "room_id": room_id })));
    }

    Err(answered.unwrap_or_else(|| {
        MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("no server admitted the knock: {last_refusal}"),
        )
    }))
}

/// A resident server's refusal, relayed to the client as its own.
///
/// The brokering server has nothing to add: it asked on the user's behalf
/// and the room said no. Re-coding that as a 502 would tell the client to
/// retry something that will be refused every time (#231).
fn relayed_refusal(status: u16, body: &Value) -> MatrixError {
    // `errcode` is a `&'static str` precisely so a code cannot be invented,
    // and a peer's string is not static -- so it is matched against the
    // codes this path can produce rather than passed through. Anything else
    // becomes M_FORBIDDEN, which is what a refusal without a recognised code
    // amounts to: the room said no and would not say why in a way we speak.
    const RELAYED: &[&str] = &[
        "M_FORBIDDEN",
        "M_NOT_FOUND",
        "M_UNSUPPORTED_ROOM_VERSION",
        "M_INCOMPATIBLE_ROOM_VERSION",
        "M_BAD_JSON",
        "M_UNKNOWN",
    ];
    let theirs = body["errcode"].as_str().unwrap_or_default();
    let errcode = RELAYED
        .iter()
        .find(|known| **known == theirs)
        .copied()
        .unwrap_or("M_FORBIDDEN");
    MatrixError::new(
        StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
        errcode,
        body["error"]
            .as_str()
            .unwrap_or("the room refused the request")
            .to_owned(),
    )
}

/// The server a standing knock was brokered through, if one stands: the
/// knock's twin of [`invite_origin`], and the one server that certainly
/// holds the room when the user knocks again or withdraws.
fn knock_origin(state: &AppState, user_id: &str, room_id: &str) -> Option<String> {
    state
        .rooms
        .pending_knock(user_id, room_id)
        .ok()
        .flatten()
        .and_then(|record| record["origin"].as_str().map(ToOwned::to_owned))
}

/// A room ID, or the room an alias names -- appending every server the
/// resolution turns up to `servers`.
///
/// A remote alias is the owning server's to resolve, exactly as on the join
/// path, and the servers it names are the ones that can broker the request:
/// without them a knock on `#room:elsewhere` would resolve and then have
/// nowhere to send the knock.
async fn resolve_room_target(
    state: &AppState,
    room_id_or_alias: &str,
    servers: &mut Vec<String>,
) -> Result<String, MatrixError> {
    if !room_id_or_alias.starts_with('#') {
        return Ok(room_id_or_alias.to_owned());
    }
    if let Some(record) = state
        .directory
        .resolve(room_id_or_alias)
        .map_err(|error| directory_error(&error))?
    {
        return Ok(record.room_id);
    }
    if let Some((_, domain)) = room_id_or_alias.split_once(':')
        && domain != state.config.server.name
        && let Ok(answer) = state
            .federation
            .remote_query_directory(domain, room_id_or_alias)
            .await
        && let Some(room_id) = answer["room_id"].as_str()
    {
        for named in answer["servers"].as_array().into_iter().flatten() {
            if let Some(named) = named.as_str()
                && !servers.iter().any(|server| server == named)
            {
                servers.push(named.to_owned());
            }
        }
        return Ok(room_id.to_owned());
    }
    Err(MatrixError::new(
        StatusCode::NOT_FOUND,
        "M_NOT_FOUND",
        format!("no room is called {room_id_or_alias}"),
    ))
}

/// `POST /_matrix/client/v3/join/{room_id_or_alias}`
///
/// Takes either form. An alias is resolved through the directory first; a room
/// ID is used as it stands.
///
/// The two are told apart by their sigil rather than by trying one and falling
/// back to the other. A fallback would turn "this alias points nowhere" into
/// "no such room", which is a different fault with a different fix: one is a
/// directory that needs an entry, the other is a room that does not exist.
async fn join_room_by_id_or_alias(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Value>, MatrixError> {
    let mut servers = server_name_params(query.as_deref());
    let room_id = if room_id_or_alias.starts_with('#') {
        let local = state
            .directory
            .resolve(&room_id_or_alias)
            .map_err(|error| directory_error(&error))?;
        // An alias another server owns is that server's to resolve: ask its
        // directory over federation, and remember the servers it names —
        // they are the ones that can vouch for the room.
        let alias_domain = room_id_or_alias
            .split_once(':')
            .map(|(_, domain)| domain.to_owned());
        let resolved = match (local, alias_domain) {
            (Some(record), _) => Some(record.room_id),
            (None, Some(domain)) if domain != state.config.server.name => {
                match state
                    .federation
                    .remote_query_directory(&domain, &room_id_or_alias)
                    .await
                {
                    Ok(answer) => {
                        for named in answer["servers"].as_array().into_iter().flatten() {
                            if let Some(named) = named.as_str()
                                && !servers.iter().any(|server| server == named)
                            {
                                servers.push(named.to_owned());
                            }
                        }
                        answer["room_id"].as_str().map(str::to_owned)
                    }
                    Err(error) => {
                        tracing::debug!("remote alias resolution failed: {error}");
                        None
                    }
                }
            }
            (None, _) => None,
        };
        resolved.ok_or_else(|| {
            MatrixError::new(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                format!("no room is called {room_id_or_alias}"),
            )
        })?
    } else {
        room_id_or_alias
    };
    join(&state, &identity.user_id, &room_id, &servers).await
}

async fn join(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    servers: &[String],
) -> Result<Json<Value>, MatrixError> {
    // #342: a server with no joined member in a room is not a resident of
    // it, even when it still holds a copy because everyone local left. The
    // copy's state is one no resident will defend (peers fan out only to
    // servers with a joined or invited member), so answering the join from
    // it authorizes against stale rules. A known-but-unresident room goes
    // remote like an unknown one; an unknown room reads back no members
    // and takes the same path. A pending invite is the exception: it is a
    // live grant from a resident, so the local path that honors it stays.
    // A locally blocked room is answered locally too: the block is this
    // server's own administrative state, which no resident across
    // federation knows or enforces, so asking one could let a blocked
    // user back in wherever the resident admits.
    let resident = state
        .rooms
        .joined_member_ids(room_id)
        .map(|ids| {
            ids.iter().any(|id| {
                id.split_once(':').map(|(_, domain)| domain)
                    == Some(state.config.server.name.as_str())
            })
        })
        .unwrap_or(false);
    // Either record counts: the pending index feeds `/sync`, while the
    // room's own member event is what authorization reads, and the two
    // can disagree mid-flight.
    let invited = state
        .rooms
        .pending_invite(user_id, room_id)
        .map(|invite| invite.is_some())
        .unwrap_or(false)
        || state
            .rooms
            .state_event_full(room_id, "m.room.member", user_id)
            .map(|event| event["content"]["membership"] == "invite")
            .unwrap_or(false);
    let blocked = state
        .rooms
        .room_block(room_id)
        .map(|record| record.is_some())
        .unwrap_or(false);
    if !resident && !invited && !blocked {
        limit_write(state, Budget::JoinRemote, user_id)?;
        return join_remote(state, user_id, room_id, servers).await;
    }
    limit_write(state, Budget::JoinLocal, user_id)?;
    match state
        .rooms
        .set_membership_with_checked(
            room_id,
            user_id,
            user_id,
            "join",
            None,
            &member_profile(state, user_id),
            state.key.pair(),
        )
        .await
    {
        Ok(_) => Ok(Json(json!({ "room_id": room_id }))),
        // A room this server has never held may still be joinable: through
        // the servers the client named, or the one in the room ID itself.
        Err(crate::rooms::RoomError::UnknownRoom(_)) => {
            limit_write(state, Budget::JoinRemote, user_id)?;
            join_remote(state, user_id, room_id, servers).await
        }
        Err(error) => Err(room_error(error)),
    }
}

/// The server a pending invite for `user_id` to `room_id` came from, if
/// there is one: the one server certain to hold the room.
fn invite_origin(state: &AppState, user_id: &str, room_id: &str) -> Option<String> {
    state
        .rooms
        .pending_invite(user_id, room_id)
        .ok()
        .flatten()
        .and_then(|record| record["origin"].as_str().map(ToOwned::to_owned))
}

/// Walk the `make_join`/`send_join` handshake as the joining server.
async fn join_remote(
    state: &AppState,
    user_id: &str,
    room_id: &str,
    servers: &[String],
) -> Result<Json<Value>, MatrixError> {
    let candidates = join_candidates(
        &state.config.server.name,
        room_id,
        servers,
        invite_origin(state, user_id, room_id).as_deref(),
    );
    if candidates.is_empty() {
        return Err(MatrixError::new(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            format!("{room_id} is not on this server and no server_name was given"),
        ));
    }

    let mut last_refusal = String::new();
    // A refusal a resident *chose* is the room's own answer -- the join rule
    // refused this user -- and outranks whatever a later candidate does. See
    // `knock_remote`, which has the same loop for the same reason.
    let mut answered: Option<MatrixError> = None;
    for server in &candidates {
        let (template, version) = match state
            .federation
            .remote_make_join(server, room_id, user_id)
            .await
        {
            Ok(body) => {
                // The resident names the room's version, and this server
                // asked only for versions it speaks -- but a peer is not
                // obliged to answer with one of them, and signing under a
                // version we cannot parse would mint an unnameable event.
                let named = body["room_version"].as_str().unwrap_or_default();
                match ruma::RoomVersionId::try_from(named) {
                    Ok(version) if crate::surface::supports_room_version(named) => {
                        (body["event"].clone(), version)
                    }
                    _ => {
                        last_refusal =
                            format!("{server}: the room is version {named}, which we do not speak");
                        continue;
                    }
                }
            }
            Err(crate::federation::FederationError::Answered { status, body }) => {
                answered.get_or_insert_with(|| relayed_refusal(status, &body));
                last_refusal = format!("{server} refused make_join: {status} {body}");
                continue;
            }
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        // Finish the template: timestamp, content hash, our signature —
        // exactly what a resident server's send_join will verify.
        let (join_id, join) = match sign_membership_template(state, &template, &version) {
            Ok(signed) => signed,
            Err(error) => {
                last_refusal = format!("{server}: {error}");
                continue;
            }
        };

        let response = match state
            .federation
            .remote_send_join(server, room_id, &join_id, &join, true)
            .await
        {
            Ok(body) => body,
            Err(crate::federation::FederationError::Answered { status, body }) => {
                answered.get_or_insert_with(|| relayed_refusal(status, &body));
                last_refusal = format!("{server} refused send_join: {status} {body}");
                continue;
            }
            Err(error) => {
                last_refusal = error.to_string();
                continue;
            }
        };

        let mut join = join;
        merge_returned_signatures(&mut join, &response["event"]);

        // #342: the room may already be held here with a stale copy, which
        // is exactly how an unresident join reaches this path. The seeder
        // below only takes fresh rooms, while the resident has already
        // made the decision, so a held room records through the local
        // path instead.
        if let Some(answer) = record_held_join(state, user_id, room_id).await {
            return answer;
        }

        let (seed_state, seed_rest) = join_seeds(&response);
        let partial = partial_join(server, room_id, &join_id, &version, &response);
        state
            .rooms
            .join_remote(
                room_id,
                &seed_state,
                &seed_rest,
                &join,
                &join_id,
                partial.as_ref(),
            )
            .map_err(room_error)?;
        record_join_history(state, room_id, &join, &join_id, server);
        state.rooms.wake_sync_waiters();
        return Ok(Json(json!({ "room_id": room_id })));
    }

    Err(answered.unwrap_or_else(|| {
        MatrixError::new(
            StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("no server admitted the join: {last_refusal}"),
        )
    }))
}

/// The events a `send_join` answer seeds the room from: what becomes its
/// state, and the rest.
fn join_seeds(response: &Value) -> (Vec<Value>, Vec<Value>) {
    let arrays =
        |key: &str| -> Vec<Value> { response[key].as_array().cloned().unwrap_or_default() };
    // A stock room answers with `state` and `auth_chain`; a state-DAG
    // room (MSC4242) with `state_dag` and `timeline`. Both are the
    // events to seed from, and the seeding tells them apart by the
    // room's version.
    let mut seed_state = arrays("state");
    seed_state.extend(arrays("state_dag"));
    let mut seed_rest = arrays("auth_chain");
    seed_rest.extend(arrays("timeline"));
    // MSC4354: a Spindle resident adds the room's unexpired sticky
    // events, which a joiner that backfills nothing could not
    // otherwise hold -- their predecessors are history it never sees.
    seed_rest.extend(arrays("msc4354_sticky"));
    (seed_state, seed_rest)
}

/// The partial-state record of a join the resident answered with
/// `members_omitted` (MSC3706), or `None` for a full answer.
///
/// A state-DAG room (MSC4242) is never taken as partial: its answer is the
/// whole state DAG, and Synapse does not offer partial joins there either.
/// `servers_in_room` is the resident's to give; whatever it names that is
/// not a server name is dropped, and the resident itself is always kept,
/// because it is the one server certain to hold the room.
fn partial_join(
    via: &str,
    room_id: &str,
    join_id: &str,
    version: &ruma::RoomVersionId,
    response: &Value,
) -> Option<crate::rooms::PartialState> {
    if response["members_omitted"] != json!(true) || spindle_core::is_state_dag(version) {
        return None;
    }
    let mut servers: Vec<String> = response["servers_in_room"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|server| ruma::ServerName::parse(server).is_ok())
        .map(str::to_owned)
        .collect();
    if !servers.iter().any(|server| server == via) {
        servers.insert(0, via.to_owned());
    }
    Some(crate::rooms::PartialState {
        room_id: room_id.to_owned(),
        join_event_id: join_id.to_owned(),
        via: via.to_owned(),
        servers_in_room: servers,
    })
}

/// `send_join` brings state, not history. Record the history before the
/// join as a federation gap, which the backfill loop fills in the
/// background (#461). The join stands whether or not this works.
fn record_join_history(state: &AppState, room_id: &str, join: &Value, join_id: &str, server: &str) {
    match state.rooms.record_join_gap(room_id, join, join_id, server) {
        Ok(true) => state.backfill.poke(room_id),
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(%error, %room_id, %server, "cannot record the history a join left out");
        }
    }
}

/// #342: record a resident-accepted remote join through the local path
/// when this server already holds the room. The outcomes equal today's
/// local answer wherever the resident admits, while a refusal already
/// returned to the caller above. `None` means the room is not held here
/// and the caller should seed it fresh from the resident's answer.
async fn record_held_join(
    state: &AppState,
    user_id: &str,
    room_id: &str,
) -> Option<Result<Json<Value>, MatrixError>> {
    if state.rooms.joined_member_ids(room_id).is_err() {
        return None;
    }
    Some(
        match state
            .rooms
            .set_membership_with_checked(
                room_id,
                user_id,
                user_id,
                "join",
                None,
                &member_profile(state, user_id),
                state.key.pair(),
            )
            .await
        {
            Ok(_) => {
                state.rooms.wake_sync_waiters();
                Ok(Json(json!({ "room_id": room_id })))
            }
            Err(error) => Err(room_error(error)),
        },
    )
}

/// `POST /_matrix/client/v3/rooms/{room_id}/leave`
async fn leave_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, MatrixError> {
    let request: SelfMembershipRequest = optional_body(&body)?;
    match state
        .rooms
        .set_membership_checked(
            &room_id,
            &identity.user_id,
            &identity.user_id,
            "leave",
            request.reason.as_deref(),
            state.key.pair(),
        )
        .await
    {
        Ok(_) => Ok(Json(json!({}))),
        // A room this server holds no log for can still be left in the one
        // way that matters here: rejecting the pending invite that named it.
        Err(crate::rooms::RoomError::UnknownRoom(_))
            if state
                .rooms
                .pending_invite(&identity.user_id, &room_id)
                .ok()
                .flatten()
                .is_some() =>
        {
            leave_remote(
                &state,
                &identity.user_id,
                &room_id,
                invite_origin(&state, &identity.user_id, &room_id).as_deref(),
            )
            .await;
            state
                .rooms
                .clear_pending_invite(&identity.user_id, &room_id)
                .map_err(room_error)?;
            Ok(Json(json!({})))
        }
        // Or withdrawing a knock made through another server: the same
        // handshake, against the server that took the knock.
        Err(crate::rooms::RoomError::UnknownRoom(_))
            if state
                .rooms
                .pending_knock(&identity.user_id, &room_id)
                .ok()
                .flatten()
                .is_some() =>
        {
            leave_remote(
                &state,
                &identity.user_id,
                &room_id,
                knock_origin(&state, &identity.user_id, &room_id).as_deref(),
            )
            .await;
            state
                .rooms
                .clear_pending_knock(&identity.user_id, &room_id)
                .map_err(room_error)?;
            Ok(Json(json!({})))
        }
        Err(error) => Err(room_error(error)),
    }
}

/// Walk `make_leave`/`send_leave` against whoever holds the room, `origin`
/// first: the server that sent the invite or took the knock being left.
///
/// Best-effort by design, which is Synapse's behavior too: the user must be
/// able to clear an invite even when the inviting server is gone, so a
/// handshake that fails on every candidate is logged and the local record
/// is cleared anyway. The room's own state ends up stale on the resident
/// side only in the case where the resident is unreachable — the one case
/// where it cannot be helped.
async fn leave_remote(state: &AppState, user_id: &str, room_id: &str, origin: Option<&str>) {
    for server in join_candidates(&state.config.server.name, room_id, &[], origin) {
        let (template, version) = match state
            .federation
            .remote_make_leave(&server, room_id, user_id)
            .await
        {
            Ok(body) => {
                let named = body["room_version"].as_str().unwrap_or_default();
                match ruma::RoomVersionId::try_from(named) {
                    Ok(version) if crate::surface::supports_room_version(named) => {
                        (body["event"].clone(), version)
                    }
                    _ => {
                        tracing::debug!("make_leave via {server}: room version {named}");
                        continue;
                    }
                }
            }
            Err(error) => {
                tracing::debug!("make_leave via {server}: {error}");
                continue;
            }
        };
        let (event_id, leave) = match sign_membership_template(state, &template, &version) {
            Ok(signed) => signed,
            Err(error) => {
                tracing::debug!("leave template via {server}: {error}");
                continue;
            }
        };
        match state
            .federation
            .remote_send_leave(&server, room_id, &event_id, &leave)
            .await
        {
            Ok(()) => return,
            Err(error) => tracing::debug!("send_leave via {server}: {error}"),
        }
    }
    tracing::debug!("no server accepted the rejection of {room_id}; clearing locally");
}

#[derive(Debug, Deserialize)]
struct MembersQuery {
    membership: Option<String>,
    not_membership: Option<String>,
    /// A sync token: the roster as it stood when that token was issued,
    /// rather than the room's present. The two differ whenever someone
    /// joined after the client's last sync, and an E2EE client that shares
    /// a room key with the present roster then encrypts for a device its
    /// sync never told it about.
    at: Option<String>,
}

/// `GET /_matrix/client/v3/rooms/{room_id}/members`
///
/// The room's member events, whole, optionally filtered by membership.
/// Read through [`crate::rooms::Rooms::read_scope`]: a member sees the roster as it is, a former
/// member of a `shared`-visibility room sees it as it stood when they left
/// (#268), and a stranger sees nothing -- this is the membership oracle
/// `/joined_members` guards against, one route over.
async fn room_members(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<MembersQuery>,
) -> Result<Json<Value>, MatrixError> {
    // A Synapse stream token kept across the migration (Element Web keeps
    // its sync accumulator's tokens) asks about a point this server cannot
    // place; the members as they are now is the honest nearest answer, and
    // a 400 would leave the room's member list empty (#568).
    let at = crate::tokens::Sync::resume(query.at.as_deref())
        .map_err(|error| {
            MatrixError::new(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                error.to_string(),
            )
        })?
        .position();
    let reader = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .map_err(room_error)?;
    // A partial-state room (MSC3706) knows few of its members until its
    // resync lands, and an E2EE client encrypts for the roster it is given:
    // the roster waits, as Synapse's does (`rooms::partial`).
    state.rooms.await_full_state(&room_id).await;
    let events = match at {
        Some(position) => reader.members_at(position),
        None => reader.members(),
    }
    .map_err(room_error)?;
    let chunk: Vec<Value> = events
        .into_iter()
        .filter(|event| {
            let membership = event["content"]["membership"].as_str().unwrap_or_default();
            query
                .membership
                .as_deref()
                .is_none_or(|wanted| wanted == membership)
                && query
                    .not_membership
                    .as_deref()
                    .is_none_or(|unwanted| unwanted != membership)
        })
        .collect();
    Ok(Json(json!({ "chunk": chunk })))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/joined_members`
///
/// Restricted to those who may read the room: its members, and anybody
/// at all when the room is world-readable. The roster is the room's
/// state, and the spec lets a world-readable room's state be read by
/// anyone; a preview of such a room (matrix-rust-sdk's `RoomPreview`)
/// reads `/state` and this together, and a 403 here made the whole
/// preview fail. Handing the roster to a non-member of any other room
/// would leak who is in a room they cannot see, which `may_read` refuses.
async fn room_joined_members(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    may_read_room(&state, &identity.user_id, &room_id)?;
    // As `/members`: the roster of a partial-state room waits for its
    // resync.
    state.rooms.await_full_state(&room_id).await;
    let members = if state.rooms.erasure_active().map_err(room_error)? {
        state
            .rooms
            .reader(&identity.user_id, &room_id)
            .map_err(room_error)?
            .members()
            .map_err(room_error)?
            .into_iter()
            .filter(|event| event["content"]["membership"] == "join")
            .filter_map(|event| {
                event["state_key"].as_str().map(|user| {
                    (
                        user.to_owned(),
                        json!({
                            "display_name": event["content"]["displayname"],
                            "avatar_url": event["content"]["avatar_url"]
                        }),
                    )
                })
            })
            .collect()
    } else {
        state.rooms.joined_members(&room_id).map_err(room_error)?
    };
    Ok(Json(json!({ "joined": members })))
}

/// `POST /_matrix/client/v3/rooms/{room_id}/forget`
///
/// Nothing is appended: forgetting is one user's bookkeeping, so the room's
/// log is untouched and every other member's view of it is unchanged. The
/// spec's own wording is that the room is removed from the user's view, not
/// from the server.
async fn forget_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    state
        .rooms
        .forget(&identity.user_id, &room_id)
        .map_err(room_error)?;
    Ok(Json(json!({})))
}

#[derive(Debug, Deserialize)]
struct TypingRequest {
    typing: bool,
    /// Milliseconds. Absent means the server's default; the spec makes it
    /// optional and clients frequently omit it when stopping.
    timeout: Option<u64>,
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/typing/{user_id}`
///
/// Nothing is appended. Typing has no linear index and never enters the log:
/// it is the clearest case in the API of state that is not an event, and
/// writing it down would mean a restart could restore a claim about the
/// present that is no longer true.
async fn set_typing(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, user_id)): axum::extract::Path<(String, String)>,
    Json(request): Json<TypingRequest>,
) -> Result<Json<Value>, MatrixError> {
    // Only about yourself. The path carries a user ID because the endpoint's
    // shape allows an application service to type as a user it owns; for
    // anyone else it can only ever be their own.
    if identity.user_id != user_id {
        return Err(MatrixError::forbidden(
            "you can only say that you are typing",
        ));
    }
    let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    if !joined.iter().any(|room| room == &room_id) {
        return Err(MatrixError::forbidden(format!(
            "{user_id} is not in {room_id}"
        )));
    }
    let timeout = request
        .timeout
        .map_or(crate::typing::DEFAULT_TIMEOUT, |ms| {
            std::time::Duration::from_millis(ms)
        });
    state
        .typing
        .set(&room_id, &user_id, request.typing, timeout);
    // The room's remote members hear about it as an m.typing EDU on the
    // next transaction out — and a start or stop with no event traffic
    // still goes, because the drain sends EDU-only transactions. The caller
    // was checked against the joined list above, which is stricter than
    // `may_read_room`: typing needs membership now, not history.
    // nosemgrep: room-read-without-authorization
    if let Ok(domains) = state.rooms.remote_domains(&room_id) {
        for destination in domains {
            state.federation.queue_edu(
                &destination,
                json!({
                    "edu_type": "m.typing",
                    "content": {
                        "room_id": room_id,
                        "user_id": user_id,
                        "typing": request.typing,
                    },
                }),
            );
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v1/room_summary/{room_id_or_alias}` (MSC3266)
///
/// Optionally authenticated, which is the whole point: a client showing a
/// preview of a room it has not joined has no membership to offer, and a
/// summary that required one could never be used for a preview.
///
/// Who may see it is decided by the room, not by the caller: a room is
/// summarisable if its join rules invite strangers to look (`public` or
/// `knock`) or its history is `world_readable`. A member may always see their
/// own room's summary whatever the rules say -- they can read the state
/// directly anyway, so refusing here would protect nothing.
async fn room_summary(
    State(state): State<AppState>,
    crate::auth::MaybeAuthenticated(viewer): crate::auth::MaybeAuthenticated,
    axum::extract::Path(room_id_or_alias): axum::extract::Path<String>,
) -> Result<Json<Value>, MatrixError> {
    let room_id = if room_id_or_alias.starts_with('#') {
        state
            .directory
            .resolve(&room_id_or_alias)
            .map_err(|error| directory_error(&error))?
            .ok_or_else(|| {
                MatrixError::new(
                    StatusCode::NOT_FOUND,
                    "M_NOT_FOUND",
                    format!("no room is called {room_id_or_alias}"),
                )
            })?
            .room_id
    } else {
        room_id_or_alias
    };

    let user_id = viewer
        .as_ref()
        .map_or("", |identity| identity.user_id.as_str());
    let summary = state
        .rooms
        .summary_for(user_id, &room_id)
        .map_err(room_error)?;
    let membership = match viewer {
        Some(identity) => {
            let joined = state.rooms.joined(&identity.user_id).map_err(room_error)?;
            joined
                .iter()
                .any(|room| room == &room_id)
                .then(|| "join".to_owned())
        }
        None => None,
    };

    let open =
        matches!(summary.join_rule.as_deref(), Some("public" | "knock")) || summary.world_readable;
    if !open && membership.is_none() {
        // M_FORBIDDEN rather than M_NOT_FOUND: the room ID came from
        // somewhere, so pretending it does not exist tells a caller who
        // already has the ID nothing it did not know, and misleads a caller
        // who mistyped one.
        return Err(MatrixError::forbidden(format!(
            "{room_id} does not publish a summary"
        )));
    }

    let mut body = serde_json::Map::new();
    body.insert("room_id".to_owned(), json!(summary.room_id));
    body.insert(
        "num_joined_members".to_owned(),
        json!(summary.num_joined_members),
    );
    body.insert("world_readable".to_owned(), json!(summary.world_readable));
    body.insert("guest_can_join".to_owned(), json!(summary.guest_can_join));
    // Absent rather than null for everything the room never set: MSC3266's
    // fields are optional, and a client distinguishing "no topic" from "an
    // empty topic" needs the key to be missing rather than null.
    for (field, value) in [
        ("name", summary.name),
        ("topic", summary.topic),
        ("avatar_url", summary.avatar_url),
        ("canonical_alias", summary.canonical_alias),
        ("join_rule", summary.join_rule),
        ("room_type", summary.room_type),
        ("encryption", summary.encryption),
        ("membership", membership),
    ] {
        if let Some(value) = value {
            body.insert(field.to_owned(), json!(value));
        }
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state`
async fn room_state(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, MatrixError> {
    let body = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.state_serialized())
        .map_err(room_error)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response())
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}`
///
/// Returns the event's *content*, not the event — which is what the spec says
/// and what surprises people, so it is worth stating here rather than leaving
/// to the reader.
async fn room_state_event(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, state_key)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<Value>, MatrixError> {
    // Also a membership oracle without this: `…/state/m.room.member/@someone`
    // answers whether a named user is in a named room, to anyone who asks.
    let content = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .and_then(|reader| reader.state_event(&event_type, &state_key))
        .map_err(room_error)?;
    Ok(Json(content))
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}`
///
/// Also the MSC4140 entry point that Matrix RTC actually uses: a call
/// participant's *departure* is a state event, and delaying one is how a
/// client arranges to be removed from a call it can no longer say it has
/// left.
async fn set_room_state(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path((room_id, event_type, state_key)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
    axum::extract::Query(query): axum::extract::Query<DelayQuery>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    limit_write(&state, Budget::Message, &identity.user_id)?;
    if let Some(delay_ms) = query.delay {
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
                Some(&state_key),
                &content,
                delay_ms,
                query.sticky,
            )
            .map_err(delay_error)?;
        return Ok(Json(json!({ "delay_id": delay_id })));
    }
    // A new `m.room.hub` in a room that has a hub is a handoff (#22).
    #[cfg(feature = "hub-mode")]
    if query.sticky.is_none()
        && event_type == crate::rooms::HUB_EVENT_TYPE
        && state_key.is_empty()
        && let Some(event_id) = Box::pin(crate::hub::try_handoff(
            &state,
            &identity.user_id,
            &room_id,
            &content,
        ))
        .await?
    {
        return Ok(Json(json!({ "event_id": event_id })));
    }
    #[cfg(feature = "hub-mode")]
    if query.sticky.is_none()
        && let Some(event_id) = Box::pin(crate::hub::try_send(
            &state,
            &identity.user_id,
            &room_id,
            &event_type,
            Some(&state_key),
            &content,
            None,
        ))
        .await?
    {
        return Ok(Json(json!({ "event_id": event_id })));
    }
    let event_id = state
        .rooms
        .set_state_sticky_checked(
            &room_id,
            &identity.user_id,
            state.key.pair(),
            &event_type,
            &state_key,
            &content,
            query.sticky,
        )
        .await
        .map_err(room_error)?;
    #[cfg(feature = "hub-mode")]
    crate::hub::after_local_send(&state, &room_id);
    Ok(Json(json!({ "event_id": event_id })))
}

/// `GET /_matrix/client/v3/rooms/{room_id}/state/{event_type}`
///
/// The state key is empty, which is what the two-segment form means.
async fn room_state_event_default(
    state: State<AppState>,
    identity: Authenticated,
    axum::extract::Path((room_id, event_type)): axum::extract::Path<(String, String)>,
) -> Result<Json<Value>, MatrixError> {
    room_state_event(
        state,
        identity,
        axum::extract::Path((room_id, event_type, String::new())),
    )
    .await
}

/// `PUT /_matrix/client/v3/rooms/{room_id}/state/{event_type}`
async fn set_room_state_default(
    state: State<AppState>,
    identity: Authenticated,
    axum::extract::Path((room_id, event_type)): axum::extract::Path<(String, String)>,
    query: axum::extract::Query<DelayQuery>,
    content: Json<Value>,
) -> Result<Json<Value>, MatrixError> {
    set_room_state(
        state,
        identity,
        axum::extract::Path((room_id, event_type, String::new())),
        query,
        content,
    )
    .await
}

/// The fields of `user_id`'s profile that a join or an invite carries in
/// its member event: `displayname` and `avatar_url`, each only if set
/// (#317). A client shows the roster from member events, so a joiner
/// without them is shown by ID until they next change their profile.
fn member_profile(state: &AppState, user_id: &str) -> serde_json::Map<String, Value> {
    let mut fields = serde_json::Map::new();
    let Ok(profile) = state.profiles.get(user_id) else {
        return fields;
    };
    if let Some(name) = profile.displayname {
        fields.insert("displayname".to_owned(), Value::String(name));
    }
    if let Some(url) = profile.avatar_url {
        fields.insert("avatar_url".to_owned(), Value::String(url));
    }
    fields
}

#[derive(Debug, Default, Deserialize)]
struct HierarchyQuery {
    from: Option<String>,
    limit: Option<usize>,
    max_depth: Option<usize>,
    #[serde(default)]
    suggested_only: bool,
}

/// How many rooms one hierarchy page returns, and the ceiling on a walk.
///
/// `max_depth` has no default in the spec, and an uncapped recursive walk over
/// a graph strangers can extend is a denial of service against your own
/// server: one request, arbitrarily many room-state reads. So the cap is the
/// server's, not the client's, and a client asking for more gets this.
const HIERARCHY_PAGE: usize = 50;

const HIERARCHY_PAGE_MAX: usize = 100;

const HIERARCHY_DEPTH_MAX: usize = 8;

/// May `user` see this room in a hierarchy at all?
///
/// The same shape as the directory's rule and for the same reason: a
/// hierarchy is a list handed to somebody who may be in none of these rooms,
/// so it must not become a way to enumerate private ones. A room is included
/// when the user is joined -- they can already see it -- or when it is
/// world-readable, public or knockable, which are the ways a room says it
/// expects to be found by strangers.
///
/// A room this server holds no log for is *not* an error: over federation the
/// tree crosses servers, and the honest answer is to leave out what we cannot
/// speak for rather than to fail the page.
fn hierarchy_visible(
    state: &AppState,
    user: &str,
    room_id: &str,
) -> Option<crate::rooms::RoomSummary> {
    let summary = state.rooms.summary_for(user, room_id).ok()?;
    if state.rooms.is_joined(user, room_id).unwrap_or(false) {
        return Some(summary);
    }
    let open =
        summary.world_readable || matches!(summary.join_rule.as_deref(), Some("public" | "knock"));
    open.then_some(summary)
}

/// The state a room upgrade carries across.
///
/// Everything here is a room-level *setting* rather than a record of who
/// did what: the new room is the same room continued, so it should look and
/// behave the same the moment it opens. Deliberately absent:
///
/// - `m.room.member` — the whole point of an upgrade is that members rejoin
///   through the tombstone, which is what re-runs the join rules against
///   the new version's own rules rather than trusting the old room's.
/// - `m.room.create` — the new room has its own, carrying `predecessor`.
/// - `m.room.tombstone` — the old room gets one; a new room born with one
///   would be dead on arrival.
/// - Anything not listed: an unknown state event is room content whose
///   meaning this server does not know, and copying it blind could carry a
///   stale reference to the old room across.
const UPGRADE_CARRIES: &[&str] = &[
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.join_rules",
    "m.room.guest_access",
    "m.room.history_visibility",
    "m.room.encryption",
    "m.room.server_acl",
    "m.space.parent",
];

#[derive(Debug, Deserialize)]
struct UpgradeRequest {
    new_version: String,
}

/// `POST /_matrix/client/v3/rooms/{room_id}/upgrade`
///
/// The room continues at a new version. This is the path that matters for
/// #178's v12 work: a room created at 11 has no other way to reach 12, and
/// v12 exists because the old state-resolution behaviour was exploitable.
///
/// The order is deliberate and is the part worth getting right. The new
/// room is built *first*, and the tombstone in the old room is written
/// last, because the tombstone is what tells clients where to go. A
/// tombstone written before the replacement exists points at nothing, and
/// there is no way to withdraw it -- every client in the room would follow
/// it into a room that is not there.
async fn upgrade_room(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Json(request): Json<UpgradeRequest>,
) -> Result<Json<Value>, MatrixError> {
    if !crate::surface::supports_room_version(&request.new_version) {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_UNSUPPORTED_ROOM_VERSION",
            format!(
                "this server does not support room version {}",
                request.new_version
            ),
        ));
    }
    let old_state = state
        .rooms
        .reader(&identity.user_id, &room_id)
        .map_err(room_error)?
        .state()
        .map_err(room_error)?;

    // Whether this user may end the room, asked of the old room before
    // anything is built. The tombstone is a real state event and faces the
    // real power-level check when it is sent; asking first means a refusal
    // does not leave an orphaned replacement room behind.
    let carried: Vec<(String, String, Value)> = old_state
        .iter()
        .filter_map(|event| {
            let event_type = event["type"].as_str()?;
            if !UPGRADE_CARRIES.contains(&event_type) {
                return None;
            }
            Some((
                event_type.to_owned(),
                event["state_key"].as_str().unwrap_or_default().to_owned(),
                event["content"].clone(),
            ))
        })
        .collect();

    // The old room's power levels come across too, but only after the
    // creator has been able to write the rest: a copied ruleset that
    // already forbids the creator from sending would freeze the new room
    // half-built. So it is applied as the last state write, not carried in
    // the initial state.
    let power_levels = old_state
        .iter()
        .find(|event| event["type"] == "m.room.power_levels")
        .map(|event| event["content"].clone());

    let mut creation_content = serde_json::Map::new();
    creation_content.insert(
        "predecessor".to_owned(),
        json!({ "room_id": room_id.clone() }),
    );
    let replacement = state
        .rooms
        .create(
            &identity.user_id,
            state.key.pair(),
            None,
            None,
            None,
            &[],
            &carried,
            Some(&request.new_version),
            Some(&creation_content),
            None,
            &member_profile(&state, &identity.user_id),
        )
        .map_err(room_error)?;

    if let Some(levels) = power_levels {
        // Best effort, and said so: a ruleset the new room refuses is a
        // ruleset the old room should not have had either, and failing the
        // whole upgrade over it would strand the user in a room they have
        // already been told is being replaced.
        if let Err(error) = state
            .rooms
            .set_state_checked(
                &replacement,
                &identity.user_id,
                state.key.pair(),
                "m.room.power_levels",
                "",
                &levels,
            )
            .await
        {
            tracing::warn!(
                %room_id, %replacement,
                "the upgraded room kept default power levels: {error}"
            );
        }
    }

    // Last, and the reason for the whole ordering above.
    state
        .rooms
        .set_state_checked(
            &room_id,
            &identity.user_id,
            state.key.pair(),
            "m.room.tombstone",
            "",
            &json!({
                "body": "this room has been replaced",
                "replacement_room": replacement.clone(),
            }),
        )
        .await
        .map_err(room_error)?;

    Ok(Json(json!({ "replacement_room": replacement })))
}

/// `GET /_matrix/client/v1/rooms/{room_id}/hierarchy`
///
/// A breadth-first walk of `m.space.child`, which is a *graph* and not a tree:
/// a space may contain itself, directly or through a cycle, and nothing stops
/// two spaces containing each other. The visited set is therefore not an
/// optimisation -- without it this endpoint never returns.
async fn room_hierarchy(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<HierarchyQuery>,
) -> Result<Json<Value>, MatrixError> {
    let limit = query
        .limit
        .unwrap_or(HIERARCHY_PAGE)
        .clamp(1, HIERARCHY_PAGE_MAX);
    let max_depth = query
        .max_depth
        .unwrap_or(HIERARCHY_DEPTH_MAX)
        .min(HIERARCHY_DEPTH_MAX);
    let offset: usize = match query.from.as_deref() {
        Some(token) => token.parse().map_err(|_| {
            MatrixError::bad_json("from is not a hierarchy token this server issued")
        })?,
        None => 0,
    };

    // The root itself has to be visible, and a root nobody may see is a 403
    // rather than an empty page: an empty page would say "this space is
    // empty", which is a different and false claim.
    if hierarchy_visible(&state, &identity.user_id, &room_id).is_none() {
        return Err(MatrixError::forbidden(
            "you are not allowed to view this room's hierarchy",
        ));
    }

    // Visibility is decided ONCE, as a room enters the walk. Filtering again
    // at render time would look like belt and braces and is actually a bug:
    // `ordered` would count rooms the caller cannot see, so `total` -- and
    // therefore `next_batch` -- would be computed from a number that does not
    // match what is returned, and `take(limit)` would hand back a SHORT page
    // whenever an invisible room fell inside it. A client paging by counting
    // would then mis-page. So nothing invisible is ever put in the list.
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut ordered: Vec<(crate::rooms::RoomSummary, Vec<Value>)> = Vec::new();
    let mut frontier = vec![(room_id.clone(), 0_usize)];
    visited.insert(room_id.clone());

    while !frontier.is_empty() {
        let (current, depth) = frontier.remove(0);
        // The ONE visibility check, and it is deliberately here rather than at
        // enqueue time. `continue` skips the child expansion below too, so an
        // invisible room is neither returned nor descended into -- a second
        // check on the way in would be pure optimisation, and a second check
        // at render time is the bug described above. One check, one place.
        let Some(summary) = hierarchy_visible(&state, &identity.user_id, &current) else {
            continue;
        };
        let children = space_children(&state, &current, query.suggested_only);
        ordered.push((summary, children.clone()));
        if depth >= max_depth {
            continue;
        }
        for child in &children {
            let Some(child_id) = child["state_key"].as_str() else {
                continue;
            };
            if !visited.insert(child_id.to_owned()) {
                continue;
            }
            frontier.push((child_id.to_owned(), depth + 1));
        }
    }

    let total = ordered.len();
    let mut rooms = Vec::new();
    for (summary, children) in ordered.into_iter().skip(offset).take(limit) {
        let Value::Object(mut entry) = chunk_of(&summary) else {
            continue;
        };
        entry.insert("children_state".to_owned(), Value::Array(children));
        rooms.push(Value::Object(entry));
    }

    let mut body = serde_json::Map::new();
    body.insert("rooms".to_owned(), Value::Array(rooms));
    if offset + limit < total {
        body.insert("next_batch".to_owned(), json!((offset + limit).to_string()));
    }
    Ok(Json(Value::Object(body)))
}

#[derive(Debug, Deserialize)]
struct MutualRoomsQuery {
    user_id: String,
    /// Accepted for the shape of the spec: every answer fits one page.
    #[allow(dead_code)]
    from: Option<String>,
}

/// `GET /_matrix/client/v1/mutual_rooms?user_id=` (MSC2666)
///
/// The rooms both the caller and `user_id` are joined to. Nothing the
/// caller could not learn from their own rooms' member lists, one query
/// instead of many.
async fn mutual_rooms(
    State(state): State<AppState>,
    Authenticated(identity): Authenticated,
    axum::extract::Query(query): axum::extract::Query<MutualRoomsQuery>,
) -> Result<Json<Value>, MatrixError> {
    if query.user_id == identity.user_id {
        return Err(MatrixError::new(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "mutual rooms are with someone else",
        ));
    }
    let mine = state.rooms.joined(&identity.user_id).map_err(room_error)?;
    let joined: Vec<String> = mine
        .into_iter()
        .filter(|room_id| {
            state
                .rooms
                .is_joined(&query.user_id, room_id)
                .unwrap_or(false)
        })
        .collect();
    Ok(Json(json!({ "joined": joined, "count": joined.len() })))
}
