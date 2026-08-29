//! #7's exit criterion, at its smallest: a room outlives the process that
//! created it.
//!
//! The failure this guards against is not "the data was lost" — the log is
//! durable and always was. It is subtler and worse: the log survived while the
//! registry of open rooms did not, so a restarted server served a room's
//! history happily and refused every write to it with `M_NOT_FOUND`. A room
//! you can read but never write to is a state no client can recover from, and
//! nothing in the API distinguishes it from a room that never existed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A server that can be rebuilt over the same store.
struct Restartable {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Restartable {
    fn start() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = Self::build(&store);
        Self { dir, store, app }
    }

    fn build(store: &Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap();
        spindle_server::app(config, Arc::clone(store)).expect("a signing key is established")
    }

    /// Everything the *server* held in memory goes away; the store stays.
    ///
    /// It used to reopen the directory, which is closer to a process restart
    /// and which fjall 3 refuses: it locks a data directory for as long as
    /// any handle to it lives, and a running server's delivery loops hold one
    /// for the life of the process. That is right for a server -- two writers
    /// over one directory is corruption -- so an in-process restart shares
    /// the store instead.
    ///
    /// What that costs is small and worth naming: this no longer proves the
    /// bytes made a round trip through the filesystem. Every room registry,
    /// counter and index here is still rebuilt from stored rows by the new
    /// server, which is what these tests are about; the on-disk round trip
    /// is carried by `spindle-store`'s `backend_compatibility` suite, which
    /// drops a store and reopens the directory with nothing else running.
    fn restart(&mut self) {
        self.app = Self::build(&self.store);
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .call(
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
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn a_room_is_still_writable_after_a_restart() {
    let mut server = Restartable::start();
    let token = server.register("alice").await;

    let (_, created) = server
        .post("/_matrix/client/v3/createRoom", &token, &json!({}))
        .await;
    let room_id = created["room_id"].as_str().unwrap().to_owned();
    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/before"),
            &token,
            &json!({ "msgtype": "m.text", "body": "before" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    server.restart();

    // The room is still the user's.
    let (status, body) = server.get("/_matrix/client/v3/joined_rooms", &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["joined_rooms"], json!([room_id]));

    // And still writable, which is the half that used to be missing.
    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/after"),
            &token,
            &json!({ "msgtype": "m.text", "body": "after" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The two halves are one room: the event sent after the restart continues
    // the log rather than starting a second one, so both messages page back in
    // order with the linear index unbroken.
    let (status, body) = server
        .get(
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?limit=100"),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bodies: Vec<&str> = body["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["content"]["body"].as_str())
        .collect();
    assert_eq!(bodies, vec!["after", "before"], "{body}");
    assert_eq!(body["chunk"].as_array().unwrap().len(), 6, "{body}");
}

#[tokio::test]
async fn a_restart_does_not_hand_a_room_to_somebody_who_was_never_in_it() {
    let mut server = Restartable::start();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;

    let (_, created) = server
        .post("/_matrix/client/v3/createRoom", &alice, &json!({}))
        .await;
    let room_id = created["room_id"].as_str().unwrap().to_owned();

    server.restart();

    // The membership index is per user, so rebuilding it must not smear one
    // user's rooms across another's.
    let (status, body) = server.get("/_matrix/client/v3/joined_rooms", &bob).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["joined_rooms"], json!([]));

    // Nor may loading the room on demand hand bob write access to it.
    let (status, body) = server
        .put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/t1"),
            &bob,
            &json!({ "msgtype": "m.text", "body": "let me in" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn a_room_that_was_never_created_is_still_unknown_after_a_restart() {
    let mut server = Restartable::start();
    let token = server.register("alice").await;
    server.restart();

    // Loading on demand must not turn "no such room" into an empty room: a
    // server that invents rooms on first mention would accept writes into
    // anything a client cared to name.
    let (status, body) = server
        .put(
            "/_matrix/client/v3/rooms/!invented:example.org/send/m.room.message/t1",
            &token,
            &json!({ "msgtype": "m.text", "body": "hello?" }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}
