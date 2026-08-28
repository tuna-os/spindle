//! #20's exit criterion, run as a drill: **an automated backup and restore
//! produces an independently verified equivalent server.**
//!
//! Every other test around backup checks a part — the format round-trips,
//! the CLI refuses an overwrite, the media audit names what is absent. None
//! of them answers the question an operator actually has, which is whether
//! the thing they can bring up from a backup is the server they lost.
//!
//! So this one builds a server, uses it the way a deployment is used, takes
//! the backup exactly as `spindle backup` does — through a snapshot — and
//! brings up a *second, separate* server from it. The assertions are then
//! made through the client API against both, because that is the surface the
//! equivalence is supposed to hold at. Reading the store back and finding
//! the same bytes would prove the format works and nothing about the server.
//!
//! What "equivalent" is taken to mean here, and why each is checked:
//!
//! - **the same identity** — the signing key lives in the store, so a
//!   restored server that minted a new one would be a different server to
//!   every peer, and every event it had ever signed would stop verifying;
//! - **the same rooms, with the same event IDs** — an event ID is a hash, so
//!   equal IDs mean equal bytes, which is the strongest statement available;
//! - **the same state**, including a v12 room, whose create event carries no
//!   `room_id` and is the event most likely to be lost in a round trip;
//! - **the same accounts** — a token minted before the backup still works
//!   after it, which is what makes a restore a restore rather than a reset;
//! - **the same media**, once the blobs are carried across, which the backup
//!   file deliberately does not do.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// One server over a store directory this test controls, so a second one can
/// later be opened over the restored copy.
struct Server {
    app: axum::Router,
}

impl Server {
    fn open(root: &std::path::Path) -> Self {
        let store = Arc::new(FjallStore::open(root).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [storage]\npath = \"{}\"\n",
            root.display()
        ))
        .unwrap();
        Self {
            app: spindle_server::app(config, store).expect("the app builds"),
        }
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        self.call(builder.body(Body::from(body.to_string())).unwrap())
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

    async fn register(&self, username: &str) -> String {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/register",
                None,
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn create_room(&self, token: &str, body: &Value) -> String {
        let (status, response) = self
            .send("POST", "/_matrix/client/v3/createRoom", Some(token), body)
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        response["room_id"].as_str().unwrap().to_owned()
    }

    /// Every event in a room, newest first, as `(event_id, type)`.
    ///
    /// Event IDs are reference hashes, so comparing them across two servers
    /// compares the bytes without having to spell out which bytes matter.
    async fn timeline(&self, room: &str, token: &str) -> Vec<(String, String)> {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=100"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| {
                (
                    event["event_id"].as_str().unwrap_or_default().to_owned(),
                    event["type"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }

    async fn state_event(&self, room: &str, token: &str, event_type: &str) -> Value {
        let (status, body) = self
            .get(
                &format!("/_matrix/client/v3/rooms/{room}/state/{event_type}"),
                token,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{event_type} in {room}: {body}");
        body
    }

    async fn whoami(&self, token: &str) -> Value {
        let (status, body) = self.get("/_matrix/client/v3/account/whoami", token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// The server's published signing key, which is its identity to peers.
    async fn server_key(&self) -> Value {
        let (status, body) = self
            .call(
                Request::builder()
                    .uri("/_matrix/key/v2/server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["verify_keys"].clone()
    }

    async fn upload(&self, token: &str, bytes: &[u8]) -> String {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/media/v3/upload?filename=note.txt")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "text/plain")
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["content_uri"].as_str().unwrap().to_owned()
    }

    async fn download(&self, mxc: &str, token: &str) -> (StatusCode, Vec<u8>) {
        let id = mxc.rsplit('/').next().unwrap();
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/_matrix/client/v1/media/download/example.org/{id}"
                    ))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }
}

/// Copy the media tree, which the backup file deliberately does not carry.
///
/// Doing it explicitly is the point: this is the second half of a restore,
/// and #219 exists because leaving it out produces a server that looks
/// restored. The drill does what an operator does, in the order they do it.
fn copy_media(from: &std::path::Path, to: &std::path::Path) {
    let from = from.join("media");
    if !from.is_dir() {
        return;
    }
    let mut pending = vec![from.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
                continue;
            }
            let relative = entry.path().strip_prefix(&from).unwrap().to_path_buf();
            let target = to.join("media").join(&relative);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one drill, run end to end")]
async fn a_restored_server_is_the_server_that_was_backed_up() {
    let work = TempDir::new().unwrap();
    let source_root = work.path().join("source");
    let target_root = work.path().join("target");

    // --- a deployment, used ---------------------------------------------
    let alice_token;
    let bob_token;
    let room;
    let v12_room;
    let mxc;
    let source_timeline;
    let source_v12_timeline;
    let source_key;
    let source_topic;
    {
        let source = Server::open(&source_root);
        alice_token = source.register("alice").await;
        bob_token = source.register("bob").await;

        room = source
            .create_room(
                &alice_token,
                &json!({ "preset": "public_chat", "name": "Ops" }),
            )
            .await;
        source
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
                Some(&alice_token),
                &json!({ "topic": "the topic that must survive" }),
            )
            .await;
        for index in 0..5 {
            let (status, body) = source
                .send(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/txn{index}"),
                    Some(&alice_token),
                    &json!({ "msgtype": "m.text", "body": format!("message {index}") }),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let (status, body) = source
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                Some(&bob_token),
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // MSC4291: the create event of a v12 room carries no `room_id` at
        // all, which makes it the event most likely to be dropped or
        // mis-keyed by anything that round-trips the store.
        v12_room = source
            .create_room(
                &alice_token,
                &json!({ "preset": "public_chat", "room_version": "12" }),
            )
            .await;
        source
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{v12_room}/send/m.room.message/v12"),
                Some(&alice_token),
                &json!({ "msgtype": "m.text", "body": "in a v12 room" }),
            )
            .await;

        mxc = source.upload(&alice_token, b"the bytes of an upload").await;

        source_timeline = source.timeline(&room, &alice_token).await;
        source_v12_timeline = source.timeline(&v12_room, &alice_token).await;
        source_key = source.server_key().await;
        source_topic = source
            .state_event(&room, &alice_token, "m.room.topic")
            .await;

        // --- the backup, taken as `spindle backup` takes it --------------
        let store = FjallStore::open(&source_root).unwrap();
        let view = spindle_store::Store::snapshot(&store).expect("fjall snapshots");
        let mut archive = Vec::new();
        let rows = spindle_store::backup::write_backup(view.as_ref(), &mut archive).unwrap();
        assert!(rows > 0, "the backup captured nothing to restore");

        let restored = FjallStore::open(&target_root).unwrap();
        let read = spindle_store::backup::read_backup(&mut archive.as_slice(), &restored).unwrap();
        assert_eq!(rows, read, "the restore wrote a different number of rows");
    }
    copy_media(&source_root, &target_root);

    // --- a second, separate server over the restored copy ----------------
    let target = Server::open(&target_root);

    // Identity. A restored server that minted a fresh key would be a
    // different server to every peer, and every event it ever signed would
    // stop verifying — a failure that surfaces nowhere near the restore.
    assert_eq!(
        target.server_key().await,
        source_key,
        "the restored server has a different signing key"
    );

    // Accounts, proven by a token minted before the backup still working.
    // This is what separates a restore from a reset.
    assert_eq!(
        target.whoami(&alice_token).await["user_id"],
        "@alice:example.org"
    );

    // Rooms, by event ID. An event ID is a reference hash, so equal IDs are
    // equal bytes; nothing else has to be enumerated.
    assert_eq!(
        target.timeline(&room, &alice_token).await,
        source_timeline,
        "the restored room's timeline differs"
    );
    assert!(
        source_timeline.len() >= 8,
        "the drill did not build a room worth comparing: {source_timeline:?}"
    );
    assert_eq!(
        target.timeline(&v12_room, &alice_token).await,
        source_v12_timeline,
        "the restored v12 room's timeline differs"
    );
    assert_eq!(
        target
            .state_event(&room, &alice_token, "m.room.topic")
            .await,
        source_topic
    );
    assert_eq!(
        target
            .state_event(&v12_room, &alice_token, "m.room.create")
            .await["room_version"],
        "12",
        "the v12 create event did not survive the round trip"
    );

    // Bob's membership, and Bob's own token, both of which the room and the
    // account rows have to agree about.
    let (status, members) = target
        .get(
            &format!("/_matrix/client/v3/rooms/{room}/joined_members"),
            &bob_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{members}");
    assert!(
        members["joined"]["@bob:example.org"].is_object(),
        "{members}"
    );

    // Media, now that the blobs have been carried across.
    let (status, bytes) = target.download(&mxc, &alice_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, b"the bytes of an upload");
}

#[tokio::test]
async fn a_restore_without_the_media_tree_serves_rows_and_not_files() {
    let work = TempDir::new().unwrap();
    let source_root = work.path().join("source");
    let target_root = work.path().join("target");

    let (token, mxc, archive) = {
        let source = Server::open(&source_root);
        let token = source.register("alice").await;
        let mxc = source.upload(&token, b"bytes that stay behind").await;
        let store = FjallStore::open(&source_root).unwrap();
        let view = spindle_store::Store::snapshot(&store).expect("fjall snapshots");
        let mut archive = Vec::new();
        spindle_store::backup::write_backup(view.as_ref(), &mut archive).unwrap();
        (token, mxc, archive)
    };

    let restored = FjallStore::open(&target_root).unwrap();
    spindle_store::backup::read_backup(&mut archive.as_slice(), &restored).unwrap();
    drop(restored);

    // Deliberately no `copy_media`. This is the state #219's audit exists to
    // name, and pinning it here says what the backup file does *not* carry:
    // the account is back, the media record is back, the bytes are not.
    let target = Server::open(&target_root);
    assert_eq!(
        target.whoami(&token).await["user_id"],
        "@alice:example.org",
        "the rows did not restore"
    );
    let (status, _) = target.download(&mxc, &token).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "media served from a restore that never received the blobs"
    );
}
