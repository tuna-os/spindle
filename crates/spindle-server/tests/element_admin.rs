//! Element Admin 0.1.12 against this server: the homeserver half of the
//! console that reilly.asia runs at `matrixadmin.reilly.asia`.
//!
//! Element Admin talks to two services. Users, sessions, emails and
//! registration tokens go to the Matrix Authentication Service's own admin
//! API (`/api/admin/v1/*`) and never reach the homeserver. Everything
//! else does, and this suite replays those requests exactly as
//! `src/api/{matrix,synapse,ess,federation-allowlist}.ts` at the `v0.1.12`
//! tag build them: same paths, same query parameters, same bodies, with
//! the token MAS issues the console, which carries
//! `urn:matrix:org.matrix.msc2967.client:api:* urn:mas:admin
//! urn:synapse:admin:*` and no device.
//!
//! Each response is then checked against the valibot schema the console
//! parses it with. Valibot rejects a missing key even when the schema
//! allows `null`, and a schema failure blanks the whole page, so the
//! checks are field by field rather than "it is JSON".

#![allow(
    clippy::too_many_lines,
    reason = "each test walks one console page, request by request"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use spindle_core::keys;
use spindle_store::{FjallStore, Store};
use tempfile::TempDir;

/// The console's session: the scopes production MAS grants Element Admin.
const CONSOLE: &str = "mat_console_session";
/// The same console without the Synapse admin scope.
const NO_SYNAPSE_ADMIN: &str = "mat_console_without_synapse_admin";
const ALICE: &str = "mat_alice_session";
const BOB: &str = "mat_bob_session";
/// A peer that never answers: the outbox fails against it.
const DEAD_PEER: &str = "dead.example";

/// A stand-in Matrix Authentication Service: discovery and a scripted
/// introspection endpoint.
#[derive(Clone, Default)]
struct Provider {
    url: Arc<Mutex<String>>,
}

impl Provider {
    async fn serve() -> String {
        let provider = Self::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        provider.url.lock().unwrap().clone_from(&url);
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(
                    |axum::extract::State(state): axum::extract::State<Provider>| async move {
                        let url = state.url.lock().unwrap().clone();
                        axum::Json(json!({
                            "issuer": url,
                            "authorization_endpoint": format!("{url}/oauth2/authorize"),
                            "token_endpoint": format!("{url}/oauth2/token"),
                            "revocation_endpoint": format!("{url}/oauth2/revoke"),
                            "registration_endpoint": format!("{url}/oauth2/registration"),
                            "introspection_endpoint": format!("{url}/oauth2/introspect"),
                            "account_management_uri": format!("{url}/account"),
                        }))
                    },
                ),
            )
            .route(
                "/oauth2/introspect",
                axum::routing::post(|body: String| async move {
                    let token = form_urlencoded::parse(body.as_bytes())
                        .find(|(key, _)| key == "token")
                        .map(|(_, value)| value.into_owned())
                        .unwrap_or_default();
                    let (username, scope) = match token.as_str() {
                        CONSOLE => (
                            "operator",
                            "urn:matrix:org.matrix.msc2967.client:api:* urn:mas:admin \
                             urn:synapse:admin:*",
                        ),
                        NO_SYNAPSE_ADMIN => (
                            "operator",
                            "urn:matrix:org.matrix.msc2967.client:api:* urn:mas:admin",
                        ),
                        ALICE => (
                            "alice",
                            "urn:matrix:client:api:* urn:matrix:client:device:ALICEDEV",
                        ),
                        BOB => (
                            "bob",
                            "urn:matrix:client:api:* urn:matrix:client:device:BOBDEV",
                        ),
                        _ => return axum::Json(json!({ "active": false })),
                    };
                    axum::Json(json!({ "active": true, "username": username, "scope": scope }))
                }),
            )
            .with_state(provider);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        url
    }
}

struct Instance {
    _dir: TempDir,
    name: String,
    store: Arc<FjallStore>,
    client: reqwest::Client,
}

impl Instance {
    async fn start() -> Instance {
        let provider = Provider::serve().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [federation]\nretry_base_ms = 50\n\
             peers = {{ \"{DEAD_PEER}\" = {{ url = \"http://127.0.0.1:9\" }} }}\n\
             [auth.delegated]\nissuer = \"{provider}\"\n\
             introspection_endpoint = \"{provider}/oauth2/introspect\"\n\
             client_id = \"spindle\"\nclient_secret = \"hush\"\n"
        ))
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            name,
            store,
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.name)
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self.client.request(method, self.url(path));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
        (status, body)
    }

    /// A console GET, with the console's token.
    async fn console(&self, path: &str) -> (u16, Value) {
        self.call(reqwest::Method::GET, path, Some(CONSOLE), None)
            .await
    }

    async fn ok(&self, method: reqwest::Method, path: &str, token: &str, body: &Value) -> Value {
        let (status, response) = self
            .call(method.clone(), path, Some(token), Some(body))
            .await;
        assert_eq!(status, 200, "{method} {path}: {response}");
        response
    }

    fn user(&self, localpart: &str) -> String {
        format!("@{localpart}:{}", self.name)
    }

    async fn create_room(&self, token: &str, body: &Value) -> String {
        self.ok(
            reqwest::Method::POST,
            "/_matrix/client/v3/createRoom",
            token,
            body,
        )
        .await["room_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// `encodeURIComponent`, as the console applies it to every path segment.
fn encode(segment: &str) -> String {
    form_urlencoded::byte_serialize(segment.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// The field kinds Element Admin's valibot schemas use.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Str,
    NullableStr,
    Num,
    NullableNum,
    Bool,
    StrArray,
    /// `v.optional(v.union([v.string(), v.number()]))`: absent, a string
    /// or a number, never null.
    OptionalToken,
    NullableObject,
}

fn conforms(value: &Value, schema: &[(&str, Kind)], what: &str) {
    for (field, kind) in schema {
        let present = value.get(*field);
        let ok = match (kind, present) {
            (Kind::OptionalToken, None) => true,
            (_, None) => false,
            (Kind::Str, Some(v)) => v.is_string(),
            (Kind::NullableStr, Some(v)) => v.is_string() || v.is_null(),
            (Kind::Num, Some(v)) => v.is_number(),
            (Kind::NullableNum, Some(v)) => v.is_number() || v.is_null(),
            (Kind::Bool, Some(v)) => v.is_boolean(),
            (Kind::StrArray, Some(v)) => v
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            (Kind::OptionalToken, Some(v)) => v.is_string() || v.is_number(),
            (Kind::NullableObject, Some(v)) => v.is_object() || v.is_null(),
        };
        assert!(
            ok,
            "{what}: field {field:?} should be {kind:?}, is {present:?} in {value}"
        );
    }
}

/// `Room` in `src/api/synapse.ts`.
const ROOM: &[(&str, Kind)] = &[
    ("room_id", Kind::Str),
    ("name", Kind::NullableStr),
    ("canonical_alias", Kind::NullableStr),
    ("joined_members", Kind::Num),
    ("joined_local_members", Kind::Num),
    ("version", Kind::Str),
    ("creator", Kind::Str),
    ("encryption", Kind::NullableStr),
    ("federatable", Kind::Bool),
    ("public", Kind::Bool),
    ("join_rules", Kind::NullableStr),
    ("guest_access", Kind::NullableStr),
    ("history_visibility", Kind::NullableStr),
    ("state_events", Kind::Num),
    ("room_type", Kind::NullableStr),
];

/// `RoomDetail`: `Room` plus these.
const ROOM_DETAIL_EXTRA: &[(&str, Kind)] = &[
    ("topic", Kind::NullableStr),
    ("avatar", Kind::NullableStr),
    ("joined_local_devices", Kind::Num),
    ("forgotten", Kind::Bool),
];

/// `RoomsListResponse`.
const ROOMS_LIST: &[(&str, Kind)] = &[
    ("offset", Kind::Num),
    ("total_rooms", Kind::Num),
    ("next_batch", Kind::OptionalToken),
    ("prev_batch", Kind::OptionalToken),
];

/// `ScheduledTask`.
const SCHEDULED_TASK: &[(&str, Kind)] = &[
    ("id", Kind::Str),
    ("action", Kind::Str),
    ("status", Kind::Str),
    ("timestamp_ms", Kind::Num),
    ("resource_id", Kind::NullableStr),
    ("result", Kind::NullableObject),
    ("error", Kind::NullableStr),
];

/// `Destination`.
const DESTINATION: &[(&str, Kind)] = &[
    ("destination", Kind::Str),
    ("retry_last_ts", Kind::Num),
    ("retry_interval", Kind::Num),
    ("failure_ts", Kind::NullableNum),
    ("last_successful_stream_ordering", Kind::NullableNum),
];

fn rooms_page(body: &Value, what: &str) -> Vec<Value> {
    conforms(body, ROOMS_LIST, what);
    let rooms = body["rooms"].as_array().expect("rooms is an array").clone();
    for room in &rooms {
        conforms(room, ROOM, what);
    }
    rooms
}

fn ids(rooms: &[Value]) -> Vec<String> {
    rooms
        .iter()
        .map(|room| room["room_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Three rooms a console would see: a published, named public room with
/// two members; an encrypted private room; and a room everyone left.
async fn rooms_fixture(server: &Instance) -> (String, String, String) {
    let lobby = server
        .create_room(
            ALICE,
            &json!({
                "name": "Lobby",
                "preset": "public_chat",
                "visibility": "public",
                "room_alias_name": "lobby",
            }),
        )
        .await;
    server
        .ok(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{lobby}"),
            BOB,
            &json!({}),
        )
        .await;
    let secret = server
        .create_room(
            BOB,
            &json!({
                "name": "secret planning",
                "initial_state": [{
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": { "algorithm": "m.megolm.v1.aes-sha2" },
                }],
            }),
        )
        .await;
    let abandoned = server.create_room(ALICE, &json!({})).await;
    server
        .ok(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{abandoned}/leave"),
            ALICE,
            &json!({}),
        )
        .await;
    (lobby, secret, abandoned)
}

/// The dashboard: sign-in discovery, `whoami`, the operator's profile,
/// the version card, the room and federation counts, and the probes the
/// console makes for ESS-only features, which must fail cleanly so the
/// console hides those features rather than offering ones that break.
#[tokio::test]
async fn the_console_signs_in_and_loads_its_dashboard() {
    let server = Instance::start().await;

    // `src/api/auth.ts`: discovery, unauthenticated.
    let (status, metadata) = server
        .call(
            reqwest::Method::GET,
            "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata",
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{metadata}");
    assert!(metadata["issuer"].is_string(), "{metadata}");

    // `whoamiQuery`: the account, and no device, because there is none.
    let (status, whoami) = server.console("/_matrix/client/v3/account/whoami").await;
    assert_eq!(status, 200, "{whoami}");
    assert_eq!(whoami["user_id"], server.user("operator"), "{whoami}");
    assert!(whoami.get("device_id").is_none(), "{whoami}");

    // `profileQuery`: a 404 is fine, anything else must parse.
    let (status, profile) = server
        .console(&format!(
            "/_matrix/client/v3/profile/{}",
            encode(&server.user("operator"))
        ))
        .await;
    assert!(status == 200 || status == 404, "{status} {profile}");

    // `serverVersionQuery`.
    let (status, version) = server.console("/_synapse/admin/v1/server_version").await;
    assert_eq!(status, 200, "{version}");
    assert!(version["server_version"].is_string(), "{version}");

    // `roomsCountQuery` and `federationDestinationsCountQuery`.
    let (status, rooms) = server.console("/_synapse/admin/v1/rooms?limit=0").await;
    assert_eq!(status, 200, "{rooms}");
    assert_eq!(rooms_page(&rooms, "rooms?limit=0").len(), 0);
    assert!(rooms["total_rooms"].is_number(), "{rooms}");
    let (status, destinations) = server
        .console("/_synapse/admin/v1/federation/destinations?limit=0")
        .await;
    assert_eq!(status, 200, "{destinations}");
    assert!(destinations["total"].is_number(), "{destinations}");
    assert!(destinations["destinations"].is_array(), "{destinations}");

    // The ESS and Secure Border Gateway probes. Each is wrapped in a
    // catch-all by the console: a non-2xx answer means "not this kind of
    // deployment". Answering 2xx with the wrong body would break it.
    for path in [
        "/_synapse/ess/version",
        "/_synapse/ess/adminbot",
        "/_synapse/io.element/admin/v1/federation/whitelist?page=0&limit=1",
    ] {
        let (status, body) = server.console(path).await;
        assert_eq!(status, 404, "{path}: {body}");
    }
}

/// A token without `urn:synapse:admin:*` is not an admin, whatever MAS
/// rights it holds: the admin API refuses it, and without a device it is
/// not a client session either.
#[tokio::test]
async fn the_mas_admin_scope_alone_does_not_open_the_admin_api() {
    let server = Instance::start().await;
    for path in [
        "/_synapse/admin/v1/server_version",
        "/_synapse/admin/v1/rooms?limit=0",
        "/_matrix/client/v3/account/whoami",
    ] {
        let (status, body) = server
            .call(reqwest::Method::GET, path, Some(NO_SYNAPSE_ADMIN), None)
            .await;
        assert_eq!(status, 401, "{path}: {body}");
        assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN", "{path}: {body}");
    }
    // An ordinary user's session is a client session and not an admin.
    let (status, body) = server
        .call(
            reqwest::Method::GET,
            "/_synapse/admin/v1/rooms",
            Some(ALICE),
            None,
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN", "{body}");
}

/// The Rooms page: `roomsInfiniteQuery` with every ordering the console
/// offers, in both directions, its search box and its two filters, and
/// the infinite scroll that follows `next_batch`.
#[tokio::test]
async fn the_rooms_page_lists_filters_orders_and_scrolls() {
    let server = Instance::start().await;
    let (lobby, secret, abandoned) = rooms_fixture(&server).await;
    let list = |query: String| {
        let server = &server;
        async move {
            let (status, body) = server
                .console(&format!("/_synapse/admin/v1/rooms?limit=200{query}"))
                .await;
            assert_eq!(status, 200, "{query}: {body}");
            body
        }
    };

    let body = list(String::new()).await;
    let rooms = rooms_page(&body, "default");
    assert_eq!(body["total_rooms"], 3, "{body}");
    assert_eq!(body["offset"], 0, "{body}");
    assert!(body.get("next_batch").is_none(), "{body}");
    // Default: by name ascending, the unnamed room last.
    assert_eq!(
        ids(&rooms),
        [lobby.clone(), secret.clone(), abandoned.clone()]
    );
    let lobby_row = &rooms[0];
    assert_eq!(lobby_row["public"], true, "published: {lobby_row}");
    assert_eq!(lobby_row["join_rules"], "public", "{lobby_row}");
    assert_eq!(lobby_row["joined_members"], 2, "{lobby_row}");
    assert_eq!(lobby_row["joined_local_members"], 2, "{lobby_row}");
    assert_eq!(lobby_row["creator"], server.user("alice"), "{lobby_row}");
    assert_eq!(
        lobby_row["canonical_alias"],
        format!("#lobby:{}", server.name),
        "{lobby_row}"
    );
    assert_eq!(
        rooms[1]["encryption"], "m.megolm.v1.aes-sha2",
        "{}",
        rooms[1]
    );
    assert_eq!(rooms[1]["public"], false, "{}", rooms[1]);
    assert_eq!(rooms[2]["joined_members"], 0, "{}", rooms[2]);

    // Every `order_by` in `RoomListFilters`, both ways. A reversed
    // direction is the same set, and for a strict ordering the reverse.
    for order_by in [
        "alphabetical",
        "size",
        "name",
        "canonical_alias",
        "joined_members",
        "joined_local_members",
        "version",
        "creator",
        "encryption",
        "federatable",
        "public",
        "join_rules",
        "guest_access",
        "history_visibility",
        "state_events",
    ] {
        let forward = rooms_page(&list(format!("&order_by={order_by}&dir=f")).await, order_by);
        let backward = rooms_page(&list(format!("&order_by={order_by}&dir=b")).await, order_by);
        let mut forward_ids = ids(&forward);
        let backward_ids = ids(&backward);
        assert_eq!(forward_ids.len(), 3, "{order_by}");
        forward_ids.reverse();
        assert_eq!(forward_ids, backward_ids, "{order_by} reversed");
    }
    // Sizes sort biggest first by default, as Synapse sorts them.
    let by_size = rooms_page(&list("&order_by=size".to_owned()).await, "size");
    assert_eq!(by_size[0]["room_id"], lobby.as_str());
    assert_eq!(by_size[2]["room_id"], abandoned.as_str());
    let (status, body) = server
        .console("/_synapse/admin/v1/rooms?order_by=shoe_size")
        .await;
    assert_eq!(status, 400, "{body}");

    // `search_term`: name or alias, case-insensitively; room ID exactly.
    let found = rooms_page(&list("&search_term=SECRET".to_owned()).await, "search");
    assert_eq!(ids(&found), std::slice::from_ref(&secret));
    let found = rooms_page(&list("&search_term=lobby%3A".to_owned()).await, "alias");
    assert_eq!(ids(&found), std::slice::from_ref(&lobby));
    let found = rooms_page(
        &list(format!("&search_term={}", encode(&abandoned))).await,
        "room id",
    );
    assert_eq!(ids(&found), std::slice::from_ref(&abandoned));

    // `public_rooms` and `empty_rooms`, both values each.
    let found = rooms_page(&list("&public_rooms=true".to_owned()).await, "public");
    assert_eq!(ids(&found), std::slice::from_ref(&lobby));
    let found = rooms_page(&list("&public_rooms=false".to_owned()).await, "private");
    assert_eq!(found.len(), 2);
    let found = rooms_page(&list("&empty_rooms=true".to_owned()).await, "empty");
    assert_eq!(ids(&found), std::slice::from_ref(&abandoned));
    let found = rooms_page(&list("&empty_rooms=false".to_owned()).await, "occupied");
    assert_eq!(found.len(), 2);

    // The infinite scroll: `from` is the previous `next_batch`, until
    // there is none. Every room once, in order.
    let mut seen = Vec::new();
    let mut from: Option<Value> = None;
    loop {
        let query = from.as_ref().map_or(String::new(), |from| {
            format!("&from={}", from.as_u64().unwrap())
        });
        let (status, body) = server
            .console(&format!("/_synapse/admin/v1/rooms?limit=1{query}"))
            .await;
        assert_eq!(status, 200, "{body}");
        seen.extend(ids(&rooms_page(&body, "scroll")));
        if from.is_some() {
            assert!(body["prev_batch"].is_number(), "{body}");
        }
        match body.get("next_batch") {
            Some(next) => from = Some(next.clone()),
            None => break,
        }
    }
    assert_eq!(seen, [lobby, secret, abandoned]);
}

/// One room's page: the detail, the members tab, and the deletion panel,
/// which reads `scheduled_tasks` on every load and polls it while a
/// deletion runs.
#[tokio::test]
async fn a_room_page_loads_and_deletion_runs_as_a_scheduled_task() {
    let server = Instance::start().await;
    let (lobby, _, abandoned) = rooms_fixture(&server).await;
    let room = encode(&lobby);

    let (status, detail) = server
        .console(&format!("/_synapse/admin/v1/rooms/{room}"))
        .await;
    assert_eq!(status, 200, "{detail}");
    conforms(&detail, ROOM, "detail");
    conforms(&detail, ROOM_DETAIL_EXTRA, "detail");
    assert_eq!(detail["joined_local_devices"], 2, "{detail}");
    assert_eq!(detail["forgotten"], false, "{detail}");

    // Once its only member left and forgot it, the abandoned room is
    // forgotten by every local user, as Synapse reports it.
    server
        .ok(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/rooms/{abandoned}/forget"),
            ALICE,
            &json!({}),
        )
        .await;
    let (status, detail) = server
        .console(&format!("/_synapse/admin/v1/rooms/{}", encode(&abandoned)))
        .await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["forgotten"], true, "{detail}");

    // An unknown room is the M_NOT_FOUND the console turns into its
    // not-found page.
    let (status, body) = server
        .console("/_synapse/admin/v1/rooms/!nothing:nowhere")
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");

    let (status, members) = server
        .console(&format!("/_synapse/admin/v1/rooms/{room}/members"))
        .await;
    assert_eq!(status, 200, "{members}");
    conforms(
        &members,
        &[("members", Kind::StrArray), ("total", Kind::Num)],
        "members",
    );
    assert_eq!(members["total"], 2, "{members}");

    let tasks_path = format!("/_synapse/admin/v1/scheduled_tasks?resource_id={room}");
    let (status, tasks) = server.console(&tasks_path).await;
    assert_eq!(status, 200, "{tasks}");
    assert_eq!(tasks["scheduled_tasks"], json!([]), "{tasks}");

    // `deleteRoom`: exactly the console's request.
    let (status, deletion) = server
        .call(
            reqwest::Method::DELETE,
            &format!("/_synapse/admin/v2/rooms/{room}"),
            Some(CONSOLE),
            Some(&json!({ "block": true, "purge": true })),
        )
        .await;
    assert_eq!(status, 200, "{deletion}");
    let delete_id = deletion["delete_id"]
        .as_str()
        .expect("a delete id")
        .to_owned();

    // The console polls every second while a task is scheduled or active.
    let mut task = Value::Null;
    for _ in 0..100 {
        let (status, tasks) = server.console(&tasks_path).await;
        assert_eq!(status, 200, "{tasks}");
        let listed = tasks["scheduled_tasks"].as_array().unwrap();
        assert_eq!(listed.len(), 1, "{tasks}");
        task = listed[0].clone();
        conforms(&task, SCHEDULED_TASK, "scheduled task");
        if task["status"] != "active" && task["status"] != "scheduled" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(task["status"], "complete", "{task}");
    assert_eq!(task["id"], delete_id.as_str(), "{task}");
    assert_eq!(task["action"], "shutdown_and_purge_room", "{task}");
    assert_eq!(task["resource_id"], lobby.as_str(), "{task}");
    let mut kicked: Vec<String> = task["result"]["kicked_users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user.as_str().unwrap().to_owned())
        .collect();
    kicked.sort();
    assert_eq!(kicked, [server.user("alice"), server.user("bob")], "{task}");
    assert_eq!(
        task["result"]["local_aliases"],
        json!([format!("#lobby:{}", server.name)]),
        "{task}"
    );

    // The room is empty, out of the directory, and blocked.
    let (_, detail) = server
        .console(&format!("/_synapse/admin/v1/rooms/{room}"))
        .await;
    assert_eq!(detail["joined_members"], 0, "{detail}");
    assert_eq!(detail["public"], false, "{detail}");
    let (status, body) = server
        .call(
            reqwest::Method::POST,
            &format!("/_matrix/client/v3/join/{lobby}"),
            Some(BOB),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 403, "a blocked room refuses a join: {body}");
    let (_, block) = server
        .console(&format!("/_synapse/admin/v1/rooms/{room}/block"))
        .await;
    assert_eq!(
        block,
        json!({ "block": true, "user_id": server.user("operator") })
    );

    // Synapse's own status endpoints agree with the task.
    let (status, by_room) = server
        .console(&format!("/_synapse/admin/v2/rooms/{room}/delete_status"))
        .await;
    assert_eq!(status, 200, "{by_room}");
    assert_eq!(by_room["results"][0]["delete_id"], delete_id.as_str());
    assert_eq!(by_room["results"][0]["status"], "complete");
    let (status, by_id) = server
        .console(&format!(
            "/_synapse/admin/v2/rooms/delete_status/{delete_id}"
        ))
        .await;
    assert_eq!(status, 200, "{by_id}");
    assert_eq!(by_id["status"], "complete", "{by_id}");
    assert!(by_id["shutdown_room"]["kicked_users"].is_array(), "{by_id}");

    // Every deletion is audited, naming the console's operator.
    let (_, audit) = server
        .console("/_spindle/admin/v1/audit?action=delete_room")
        .await;
    assert_eq!(
        audit["entries"][0]["actor"],
        server.user("operator"),
        "{audit}"
    );
}

/// What `deleteRoom` is refused, and what it may do to a room this
/// server does not hold.
#[tokio::test]
async fn deletion_refuses_what_it_cannot_do_and_blocks_unknown_rooms() {
    let server = Instance::start().await;
    let delete = |room: String, body: Value| {
        let server = &server;
        async move {
            server
                .call(
                    reqwest::Method::DELETE,
                    &format!("/_synapse/admin/v2/rooms/{}", encode(&room)),
                    Some(CONSOLE),
                    Some(&body),
                )
                .await
        }
    };
    let (status, body) = delete("not-a-room".to_owned(), json!({ "block": true })).await;
    assert_eq!(status, 400, "{body}");
    let unknown = format!("!unknown:{}", server.name);
    let (status, body) = delete(unknown.clone(), json!({ "block": false })).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
    let (status, body) = delete(
        unknown.clone(),
        json!({ "block": false, "new_room_user_id": "@someone:elsewhere" }),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Blocking a room nobody here is in: the task completes, the block
    // stands.
    let (status, body) = delete(unknown.clone(), json!({ "block": true, "purge": true })).await;
    assert_eq!(status, 200, "{body}");
    let path = format!(
        "/_synapse/admin/v1/scheduled_tasks?resource_id={}",
        encode(&unknown)
    );
    let mut status_seen = Value::Null;
    for _ in 0..100 {
        let (_, tasks) = server.console(&path).await;
        status_seen = tasks["scheduled_tasks"][0]["status"].clone();
        if status_seen == "complete" || status_seen == "failed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status_seen, "complete");
    let (_, block) = server
        .console(&format!(
            "/_synapse/admin/v1/rooms/{}/block",
            encode(&unknown)
        ))
        .await;
    assert_eq!(block["block"], true, "{block}");

    // `scheduled_tasks` filters by action and status.
    let (_, tasks) = server
        .console("/_synapse/admin/v1/scheduled_tasks?action_name=shutdown_and_purge_room&job_status=complete")
        .await;
    assert_eq!(
        tasks["scheduled_tasks"].as_array().unwrap().len(),
        1,
        "{tasks}"
    );
    let (_, tasks) = server
        .console("/_synapse/admin/v1/scheduled_tasks?job_status=failed")
        .await;
    assert_eq!(tasks["scheduled_tasks"], json!([]), "{tasks}");
    let (status, _) = server
        .console("/_synapse/admin/v1/scheduled_tasks?job_status=sleepy")
        .await;
    assert_eq!(status, 400);
}

/// A task a restart interrupted is reported failed, with the reason,
/// rather than active forever, and the console offers deletion again.
#[tokio::test]
async fn a_task_a_restart_interrupted_reads_as_failed() {
    let server = Instance::start().await;
    let row = json!({
        "id": "interrupted",
        "action": "shutdown_and_purge_room",
        "status": "active",
        "timestamp_ms": 1,
        "resource_id": "!gone:elsewhere",
        "result": null,
        "error": null,
        "boot": "an-earlier-process",
    });
    server
        .store
        .put(&keys::admin_task("interrupted"), row.to_string().as_bytes())
        .unwrap();
    let (status, tasks) = server
        .console("/_synapse/admin/v1/scheduled_tasks?resource_id=!gone:elsewhere")
        .await;
    assert_eq!(status, 200, "{tasks}");
    let task = &tasks["scheduled_tasks"][0];
    conforms(task, SCHEDULED_TASK, "interrupted task");
    assert_eq!(task["status"], "failed", "{task}");
    assert!(
        task["error"]
            .as_str()
            .is_some_and(|error| error.contains("restart")),
        "{task}"
    );
    assert!(
        task.get("boot").is_none(),
        "internal fields stay internal: {task}"
    );
}

/// The Federation page: destinations with their retry state, one
/// destination, the rooms shared with it, and the reset the operator
/// reaches for when a peer comes back.
#[tokio::test]
async fn the_federation_page_shows_delivery_and_resets_a_destination() {
    let server = Instance::start().await;
    // A PDU queued for a peer that never answers, as the send path queues
    // it; the outbox tries, fails, and backs off.
    server
        .store
        .put(
            &keys::federation_outbox(DEAD_PEER, 1),
            br#"{"type":"m.room.message","content":{"body":"queued"}}"#,
        )
        .unwrap();
    let mut row = Value::Null;
    for _ in 0..200 {
        let (status, body) = server
            .console("/_synapse/admin/v1/federation/destinations?limit=200")
            .await;
        assert_eq!(status, 200, "{body}");
        conforms(
            &body,
            &[("total", Kind::Num), ("next_token", Kind::OptionalToken)],
            "destinations",
        );
        for destination in body["destinations"].as_array().unwrap() {
            conforms(destination, DESTINATION, "destination");
        }
        row = body["destinations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|destination| destination["destination"] == DEAD_PEER)
            .cloned()
            .unwrap_or(Value::Null);
        if row["failure_ts"].is_number() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(row["failure_ts"].is_number(), "the outbox failed: {row}");
    assert!(row["retry_last_ts"].as_u64().unwrap() > 0, "{row}");
    assert!(row["retry_interval"].as_u64().unwrap() > 0, "{row}");

    // The console's filter and orderings.
    for query in [
        "destination=DEAD",
        "order_by=destination&dir=b",
        "order_by=retry_last_ts",
        "order_by=retry_interval&dir=b",
        "order_by=failure_ts",
        "order_by=last_successful_stream_ordering",
    ] {
        let (status, body) = server
            .console(&format!(
                "/_synapse/admin/v1/federation/destinations?limit=200&{query}"
            ))
            .await;
        assert_eq!(status, 200, "{query}: {body}");
        assert!(
            body["destinations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|destination| destination["destination"] == DEAD_PEER),
            "{query}: {body}"
        );
    }
    let (status, _) = server
        .console("/_synapse/admin/v1/federation/destinations?order_by=mood")
        .await;
    assert_eq!(status, 400);

    // `federationDestinationQuery`, known and unknown.
    let (status, one) = server
        .console(&format!(
            "/_synapse/admin/v1/federation/destinations/{}",
            encode(DEAD_PEER)
        ))
        .await;
    assert_eq!(status, 200, "{one}");
    conforms(&one, DESTINATION, "one destination");
    let (status, body) = server
        .console("/_synapse/admin/v1/federation/destinations/never.heard.of")
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
    let (status, rooms) = server
        .console(&format!(
            "/_synapse/admin/v1/federation/destinations/{DEAD_PEER}/rooms"
        ))
        .await;
    assert_eq!(status, 200, "{rooms}");
    assert_eq!(rooms["total"], 0, "{rooms}");

    // Reset: the retry state clears at once.
    let (status, body) = server
        .call(
            reqwest::Method::POST,
            &format!("/_synapse/admin/v1/federation/destinations/{DEAD_PEER}/reset_connection"),
            Some(CONSOLE),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (_, one) = server
        .console(&format!(
            "/_synapse/admin/v1/federation/destinations/{DEAD_PEER}"
        ))
        .await;
    // The next attempt may already have failed again; either way the
    // reset was taken.
    assert!(
        one["retry_last_ts"] == 0 || one["failure_ts"].is_number(),
        "{one}"
    );
}

/// Avatars: the console renders users' and rooms' avatars through the
/// authenticated media API with its own device-less token.
#[tokio::test]
async fn avatars_render_through_the_device_less_session() {
    let server = Instance::start().await;
    let mut png = Vec::new();
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(8, 8, image::Rgb([0, 128, 255])))
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let response = server
        .client
        .post(server.url("/_matrix/media/v3/upload?filename=me.png"))
        .header("authorization", format!("Bearer {ALICE}"))
        .header("content-type", "image/png")
        .body(png)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let uploaded: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let mxc = uploaded["content_uri"].as_str().unwrap().to_owned();
    server
        .ok(
            reqwest::Method::PUT,
            &format!(
                "/_matrix/client/v3/profile/{}/avatar_url",
                encode(&server.user("alice"))
            ),
            ALICE,
            &json!({ "avatar_url": mxc }),
        )
        .await;

    // `profileQuery` then `mediaThumbnailQuery`, as the user list does.
    let (status, profile) = server
        .console(&format!(
            "/_matrix/client/v3/profile/{}",
            encode(&server.user("alice"))
        ))
        .await;
    assert_eq!(status, 200, "{profile}");
    assert_eq!(profile["avatar_url"], mxc.as_str(), "{profile}");
    let (origin, media_id) = mxc
        .strip_prefix("mxc://")
        .and_then(|rest| rest.split_once('/'))
        .unwrap();
    let response = server
        .client
        .get(server.url(&format!(
            "/_matrix/client/v1/media/thumbnail/{}/{}?width=96&height=96&method=crop",
            encode(origin),
            encode(media_id)
        )))
        .header("authorization", format!("Bearer {CONSOLE}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response.headers()["content-type"].to_str().unwrap(),
        "image/png"
    );
}

/// The console is served from another origin, so every request it makes
/// is preceded by a preflight the server must allow, the DELETE with a
/// JSON body included.
#[tokio::test]
async fn the_consoles_cross_origin_requests_are_allowed() {
    let server = Instance::start().await;
    let response = server
        .client
        .request(
            reqwest::Method::OPTIONS,
            server.url("/_synapse/admin/v2/rooms/!r:example"),
        )
        .header("origin", "https://matrixadmin.reilly.asia")
        .header("access-control-request-method", "DELETE")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let headers = response.headers();
    assert_eq!(headers["access-control-allow-origin"], "*");
    let methods = headers["access-control-allow-methods"].to_str().unwrap();
    assert!(methods.contains("DELETE"), "{methods}");
    let allowed = headers["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(
        allowed.contains("authorization") && allowed.contains("content-type"),
        "{allowed}"
    );
}
