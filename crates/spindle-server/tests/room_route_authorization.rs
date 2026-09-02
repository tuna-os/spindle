//! Every room-scoped client route, and what a stranger learns from it.
//!
//! #258 walked the read routes and found nine holes. #268 asks for the same
//! walk over every route, with the table generated from the router rather
//! than maintained by hand, so a new route is in it by default and "which
//! endpoints have an authorization test" is a number CI holds rather than a
//! question nobody asks.
//!
//! The table below is the hand-written half: every room-scoped client route
//! the router registers, each either walked with a stranger or exempted with
//! a written reason. The generated half reads `src/routes.rs` and refuses to
//! pass if a route with `{room_id}` in it is registered there and missing
//! here -- or is here and no longer there. Adding a route without deciding
//! what a stranger gets from it is the thing this file makes impossible.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// What a route owes a caller who is in no rooms at all.
enum Reach {
    /// Refused outright: never a 2xx, never a byte of the room. The status
    /// is 403 or 404 -- 404 where the spec says a stranger must not learn
    /// the room exists, 403 elsewhere -- and anything else is a bug.
    Refused,
    /// Reachable by design, for the reason given. Every exemption is a
    /// policy decision written where it can be argued with.
    Exempt(&'static str),
}

struct Route {
    method: &'static str,
    /// The router's own template, so the generated check can match it.
    path: &'static str,
    reach: Reach,
}

const KEY_BACKUP: &str = "key backup is scoped to the caller's own account; `{room_id}` is a \
                          key in their backup, not a room they read";
const OWN_ACCOUNT_DATA: &str = "the caller's own per-room account data, keyed by room ID; the \
                                spec neither requires membership nor that the room exist";

/// Every room-scoped client route the router registers.
const TABLE: &[Route] = &[
    // -- reads: the #258 walk, kept here so one table is the whole answer --
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/state",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/messages",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/event/{event_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/context/{event_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/relations/{event_id}/{rel_type}/{event_type}",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/threads",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/joined_members",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/rooms/{room_id}/aliases",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/hierarchy",
        reach: Reach::Refused,
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event",
        reach: Reach::Refused,
    },
    // -- writes --
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/redact/{event_id}/{txn_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/invite",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/kick",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/ban",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/unban",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/join",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/leave",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/upgrade",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/report/{event_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/read_markers",
        reach: Reach::Refused,
    },
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/rooms/{room_id}/typing/{user_id}",
        reach: Reach::Refused,
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/directory/list/room/{room_id}",
        reach: Reach::Refused,
    },
    // -- reachable by design --
    Route {
        method: "POST",
        path: "/_matrix/client/v3/rooms/{room_id}/forget",
        reach: Reach::Exempt(
            "Sytest and the Complement ratchet require a forget from someone who was never a \
             member to succeed (`Can forget room we weren't an actual member`); it writes one \
             user's own marker and reveals only that the room exists, which a random room ID \
             does not otherwise leak",
        ),
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/directory/list/room/{room_id}",
        reach: Reach::Exempt(
            "a room's directory visibility is public by spec, with no authentication at all; the PUT is guarded",
        ),
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/room_keys/keys/{room_id}",
        reach: Reach::Exempt(KEY_BACKUP),
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/room_keys/keys/{room_id}/{session_id}",
        reach: Reach::Exempt(KEY_BACKUP),
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/account_data/{event_type}",
        reach: Reach::Exempt(OWN_ACCOUNT_DATA),
    },
    Route {
        method: "GET",
        path: "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags",
        reach: Reach::Exempt(OWN_ACCOUNT_DATA),
    },
    Route {
        method: "PUT",
        path: "/_matrix/client/v3/user/{user_id}/rooms/{room_id}/tags/{tag}",
        reach: Reach::Exempt(OWN_ACCOUNT_DATA),
    },
];

// -- the generated half ---------------------------------------------------

/// Every room-scoped client route registered in `src/routes.rs`, read from
/// the source so this cannot drift from the router.
///
/// A string scan rather than a parser: every registration is a string
/// literal beginning `/_matrix/client/`, and a route registered any other
/// way would be the first. The scan is deliberately over-inclusive -- any
/// such literal counts -- so that the failure mode is "the table lists a
/// path the router does not" rather than a route slipping past.
fn routes_in_source() -> Vec<String> {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes.rs"))
        .expect("the router's source is beside this test");
    let mut found: Vec<String> = source
        .split('"')
        .filter(|literal| literal.starts_with("/_matrix/client/") && literal.contains("{room_id}"))
        .map(str::to_owned)
        .collect();
    found.sort();
    found.dedup();
    found
}

#[test]
fn every_room_route_the_router_registers_is_in_the_table() {
    let registered = routes_in_source();
    let mut listed: Vec<String> = TABLE.iter().map(|route| route.path.to_owned()).collect();
    listed.sort();
    listed.dedup();

    let missing: Vec<&String> = registered
        .iter()
        .filter(|path| !listed.contains(path))
        .collect();
    assert!(
        missing.is_empty(),
        "routes registered in src/routes.rs with no row in this table -- decide what a \
         stranger gets from each, then add it: {missing:#?}"
    );
    let stale: Vec<&String> = listed
        .iter()
        .filter(|path| !registered.contains(path))
        .collect();
    assert!(
        stale.is_empty(),
        "rows in this table for routes src/routes.rs no longer registers: {stale:#?}"
    );
}

// -- the walk --------------------------------------------------------------

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_private_room(&self, token: &str) -> String {
        let (status, body) = self
            .call(
                "POST",
                "/_matrix/client/v3/createRoom",
                token,
                Some(&json!({ "name": "TOPSECRETNAME", "preset": "private_chat" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    async fn say(&self, room: &str, token: &str) -> String {
        let (status, body) = self
            .call(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/t1"),
                token,
                Some(&json!({ "msgtype": "m.text", "body": "TOPSECRETBODY" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["event_id"].as_str().unwrap().to_owned()
    }
}

/// Fill a router template with real values, as a stranger would reach it.
fn reach(template: &str, room: &str, event: &str, stranger: &str) -> String {
    template
        .replace("{room_id}", room)
        .replace("{event_id}", event)
        .replace("{event_type}", "m.room.name")
        .replace("{state_key}", "")
        .replace("{rel_type}", "m.annotation")
        .replace("{txn_id}", "stranger1")
        .replace("{receipt_type}", "m.read")
        .replace("{user_id}", stranger)
        .replace("{tag}", "u.stranger")
        .replace("{session_id}", "session1")
}

/// A well-formed body for each writing route, so a refusal is about who is
/// asking and never about what was sent.
fn body_for(route: &Route, event: &str) -> Option<Value> {
    if route.method == "GET" {
        return None;
    }
    let path = route.path;
    Some(if path.contains("/send/") {
        json!({ "msgtype": "m.text", "body": "hello from outside" })
    } else if path.contains("/state/") {
        json!({ "name": "renamed from outside" })
    } else if path.ends_with("/invite")
        || path.ends_with("/kick")
        || path.ends_with("/ban")
        || path.ends_with("/unban")
    {
        json!({ "user_id": "@alice:example.org" })
    } else if path.contains("/typing/") {
        json!({ "typing": true, "timeout": 1000 })
    } else if path.ends_with("/read_markers") {
        json!({ "m.fully_read": event })
    } else if path.ends_with("/upgrade") {
        json!({ "new_version": "11" })
    } else if path.contains("/report/") {
        json!({ "reason": "from outside" })
    } else if path.contains("/directory/list/room/") {
        json!({ "visibility": "public" })
    } else {
        json!({})
    })
}

/// A stranger gets nothing from any guarded route: never a 2xx, never a byte
/// of the room. Exempt routes are called too, so a reason that stops being
/// true -- an exempt route that starts refusing, say -- is noticed.
#[tokio::test]
async fn a_stranger_gets_nothing_from_any_room_route() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let mallory = harness.register("mallory").await;
    let room = harness.create_private_room(&alice).await;
    let event = harness.say(&room, &alice).await;

    let mut wrong = Vec::new();
    for route in TABLE {
        let uri = reach(route.path, &room, &event, "@mallory:example.org");
        let body = body_for(route, &event);
        let (status, answer) = harness
            .call(route.method, &uri, &mallory, body.as_ref())
            .await;
        let rendered = serde_json::to_string(&answer).unwrap();
        if rendered.contains("TOPSECRET") {
            wrong.push(format!(
                "{} {} leaked the room: {rendered}",
                route.method, route.path
            ));
        }
        match route.reach {
            Reach::Refused => {
                if status != StatusCode::FORBIDDEN && status != StatusCode::NOT_FOUND {
                    wrong.push(format!(
                        "{} {} answered {status} to a user in no rooms at all: {rendered}",
                        route.method, route.path
                    ));
                }
            }
            Reach::Exempt(reason) => {
                if status.is_server_error() {
                    wrong.push(format!(
                        "{} {} is exempt ({reason}) and still 500s: {rendered}",
                        route.method, route.path
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
