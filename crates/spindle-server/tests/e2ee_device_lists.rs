//! Fallback keys and device-list change tracking.
//!
//! Two halves of the same failure mode — encrypting to the wrong key set.
//! The fallback key is what keeps a device *reachable* when its one-time
//! keys run out; `device_lists.changed` is what stops a client encrypting
//! to a device set that no longer exists. Both err on the chatty side:
//! a stale "changed" notice costs a redundant `/keys/query`, a missed one
//! costs a message someone cannot read.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

struct Device {
    token: String,
    device_id: String,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let app = Self::build(&store);
        Self { dir, store, app }
    }

    fn build(store: &Arc<FjallStore>) -> axum::Router {
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        spindle_server::app(config, Arc::clone(store)).expect("a signing key is established")
    }

    /// A second server over the same store.
    ///
    /// It shares the store handle rather than reopening the directory, which
    /// fjall 3 would refuse -- it locks a data directory for as long as any
    /// handle lives, and a running server's delivery loops hold one. The
    /// claim survives intact: what this test is about is that a *fresh
    /// server* resumes its counter from the stored rows rather than from
    /// memory, and every counter is re-read from the store when the server is
    /// built, whichever handle it is built over.
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

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method(method)
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
                .method("GET")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn register(&self, username: &str) -> Device {
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
        Device {
            token: body["access_token"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn login(&self, username: &str) -> Device {
        let (status, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "type": "m.login.password",
                            "identifier": { "type": "m.id.user", "user": username },
                            "password": "hunter2",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Device {
            token: body["access_token"].as_str().unwrap().to_owned(),
            device_id: body["device_id"].as_str().unwrap().to_owned(),
        }
    }

    async fn upload_identity(&self, user_id: &str, device: &Device) {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/keys/upload",
                &device.token,
                &json!({
                    "device_keys": {
                        "user_id": user_id,
                        "device_id": device.device_id,
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn create_public_room(&self, token: &str) -> String {
        let (status, body) = self
            .send("POST", "/_matrix/client/v3/createRoom", token, &json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["room_id"].as_str().unwrap().to_owned();
        self.send(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.join_rules"),
            token,
            &json!({ "join_rule": "public" }),
        )
        .await;
        room
    }

    async fn join(&self, room: &str, token: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/join"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn leave(&self, room: &str, token: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/leave"),
                token,
                &json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn invite(&self, room: &str, token: &str, user_id: &str) {
        let (status, body) = self
            .send(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room}/invite"),
                token,
                &json!({ "user_id": user_id }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn sync(&self, device: &Device, since: Option<&str>) -> Value {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?since={since}"),
            None => "/_matrix/client/v3/sync".to_owned(),
        };
        let (status, body) = self.get(&path, &device.token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn changed(sync: &Value) -> Vec<String> {
    users(&sync["device_lists"]["changed"])
}

fn left(sync: &Value) -> Vec<String> {
    users(&sync["device_lists"]["left"])
}

fn users(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap_or_else(|| panic!("a list of users: {list}"))
        .iter()
        .map(|user| user.as_str().unwrap().to_owned())
        .collect()
}

fn next_batch(sync: &Value) -> String {
    sync["next_batch"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn fallback_key_serves_after_one_time_keys_run_out_and_survives() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "one_time_keys": { "signed_curve25519:OTK1": { "key": "one-time" } },
                "fallback_keys": { "signed_curve25519:FB1": { "key": "fallback" } },
            }),
        )
        .await;

    let claim = json!({
        "one_time_keys": { "@alice:example.org": { alice.device_id.clone(): "signed_curve25519" } },
    });
    let mut claimed = Vec::new();
    for _ in 0..3 {
        let (status, body) = harness
            .send("POST", "/_matrix/client/v3/keys/claim", &bob.token, &claim)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let keys = body["one_time_keys"]["@alice:example.org"][&alice.device_id]
            .as_object()
            .unwrap()
            .clone();
        claimed.push(keys.keys().next().unwrap().clone());
    }
    // First claim spends the one-time key — the deletable tier goes first.
    assert_eq!(claimed[0], "signed_curve25519:OTK1");
    // Then the fallback serves, and *keeps* serving: it exists for exactly
    // the moment the one-time keys have run out, so unlike them it is not
    // deleted on hand-out.
    assert_eq!(claimed[1], "signed_curve25519:FB1");
    assert_eq!(claimed[2], "signed_curve25519:FB1");
}

#[tokio::test]
async fn sync_reports_unused_fallback_types_until_claimed() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "one_time_keys": { "signed_curve25519:OTK1": { "key": "one-time" } },
                "fallback_keys": { "signed_curve25519:FB1": { "key": "fallback" } },
            }),
        )
        .await;

    let sync = harness.sync(&alice, None).await;
    assert_eq!(
        sync["device_unused_fallback_key_types"],
        json!(["signed_curve25519"])
    );
    assert_eq!(
        sync["device_one_time_keys_count"]["signed_curve25519"],
        json!(1)
    );

    // Spend the one-time key, then the fallback.
    let claim = json!({
        "one_time_keys": { "@alice:example.org": { alice.device_id.clone(): "signed_curve25519" } },
    });
    harness
        .send("POST", "/_matrix/client/v3/keys/claim", &bob.token, &claim)
        .await;
    harness
        .send("POST", "/_matrix/client/v3/keys/claim", &bob.token, &claim)
        .await;

    // The used fallback disappears from the unused list — that is the rotate
    // signal — and the count reads zero.
    let sync = harness.sync(&alice, None).await;
    assert_eq!(sync["device_unused_fallback_key_types"], json!([]));
    assert_eq!(sync["device_one_time_keys_count"], json!({}));

    // Rotating the fallback restores it.
    harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({ "fallback_keys": { "signed_curve25519:FB2": { "key": "rotated" } } }),
        )
        .await;
    let sync = harness.sync(&alice, None).await;
    assert_eq!(
        sync["device_unused_fallback_key_types"],
        json!(["signed_curve25519"])
    );
}

#[tokio::test]
async fn device_list_changes_reach_room_sharers_and_nobody_else() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let room = harness.create_public_room(&alice.token).await;
    harness.join(&room, &bob.token).await;
    // Carol shares no room with anyone.

    let token = harness.sync(&alice, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness.upload_identity("@bob:example.org", &bob).await;
    harness.upload_identity("@carol:example.org", &carol).await;

    let sync = harness.sync(&alice, Some(&token)).await;
    let seen = changed(&sync);
    assert!(seen.contains(&"@bob:example.org".to_owned()), "{seen:?}");
    // Carol changed too, but alice shares no room with her: telling alice
    // would leak when a stranger reprovisions a device.
    assert!(!seen.contains(&"@carol:example.org".to_owned()), "{seen:?}");
    // Nor is she in `left`, which would leak the same thing.
    assert!(left(&sync).is_empty(), "{sync}");

    // Consumed: a sync from the new position reports nothing.
    let next = sync["next_batch"].as_str().unwrap().to_owned();
    let seen = changed(&harness.sync(&alice, Some(&next)).await);
    assert!(seen.is_empty(), "{seen:?}");
}

#[tokio::test]
async fn own_devices_are_always_visible_even_with_no_rooms() {
    let harness = Harness::new();
    let dave1 = harness.register("dave").await;
    let dave2 = harness.login("dave").await;

    let token = harness.sync(&dave1, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    harness.upload_identity("@dave:example.org", &dave2).await;

    // Dave is in no room at all, but his first device must still hear that
    // his second one appeared — that is how a client knows to offer
    // verification.
    let seen = changed(&harness.sync(&dave1, Some(&token)).await);
    assert_eq!(seen, vec!["@dave:example.org".to_owned()]);
}

#[tokio::test]
async fn keys_changes_reports_the_asked_window() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let room = harness.create_public_room(&alice.token).await;
    harness.join(&room, &bob.token).await;

    let from = harness.sync(&alice, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();
    harness.upload_identity("@bob:example.org", &bob).await;
    let to = harness.sync(&alice, Some(&from)).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/keys/changes?from={from}&to={to}"),
            &alice.token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], json!(["@bob:example.org"]));

    // A window that starts where the change already happened is empty —
    // exclusive below, like every sync token.
    let (_, body) = harness
        .get(
            &format!("/_matrix/client/v3/keys/changes?from={to}&to={to}"),
            &alice.token,
        )
        .await;
    assert_eq!(body["changed"], json!([]));
}

#[tokio::test]
async fn restart_cannot_hide_a_device_change_behind_an_old_token() {
    let mut harness = Harness::new();
    let dave1 = harness.register("dave").await;
    let dave2 = harness.login("dave").await;

    // No rooms: the watermark is the only row recording how far the counter
    // got. Dave's first device then holds a token at that position.
    harness.upload_identity("@dave:example.org", &dave2).await;
    let token = harness.sync(&dave1, None).await["next_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    harness.restart();

    // A counter resumed below the watermark would stamp this change at a
    // sequence the token already covers — and dave's first device would
    // never hear about it, and keep encrypting to a stale device set.
    harness.upload_identity("@dave:example.org", &dave2).await;
    let seen = changed(&harness.sync(&dave1, Some(&token)).await);
    assert_eq!(seen, vec!["@dave:example.org".to_owned()]);
}

const HENRY: &str = "@henry:example.org";

/// #904: a user who joins a room alice is in is a user whose keys alice's
/// client must fetch, or it never shares the room key with their devices
/// and they cannot decrypt alice's messages. So they are in `changed`,
/// though their keys did not change, as Synapse sends it. When they leave
/// the last room they share with alice, they are in `left`. `/keys/changes`
/// answers the same over its window.
#[tokio::test]
async fn a_user_who_comes_to_share_a_room_is_changed_and_one_who_stops_is_left() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let henry = harness.register("henry").await;
    let room = harness.create_public_room(&alice.token).await;
    let start = next_batch(&harness.sync(&alice, None).await);

    harness.join(&room, &henry.token).await;
    let joined = harness.sync(&alice, Some(&start)).await;
    assert_eq!(changed(&joined), vec![HENRY.to_owned()], "{joined}");
    assert!(left(&joined).is_empty(), "{joined}");
    let keys_changes = |from: String, to: String| {
        let harness = &harness;
        let token = alice.token.clone();
        async move {
            let (status, body) = harness
                .get(
                    &format!("/_matrix/client/v3/keys/changes?from={from}&to={to}"),
                    &token,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    assert_eq!(
        keys_changes(start.clone(), next_batch(&joined)).await,
        json!({ "changed": [HENRY], "left": [] })
    );

    harness.leave(&room, &henry.token).await;
    let parted = harness.sync(&alice, Some(&next_batch(&joined))).await;
    assert!(changed(&parted).is_empty(), "{parted}");
    assert_eq!(left(&parted), vec![HENRY.to_owned()], "{parted}");
    assert_eq!(
        keys_changes(next_batch(&joined), next_batch(&parted)).await,
        json!({ "changed": [], "left": [HENRY] })
    );

    // Consumed: nothing more after that.
    let quiet = harness.sync(&alice, Some(&next_batch(&parted))).await;
    assert!(
        changed(&quiet).is_empty() && left(&quiet).is_empty(),
        "{quiet}"
    );
}

/// `left` makes a client drop a user's sessions, so it names only users who
/// share no room with alice at all: henry, who leaves one of two shared
/// rooms, stays tracked, and as on Synapse he is not `changed` either. The
/// same when alice leaves a room whose members she still meets elsewhere.
/// An invitee shares the room too.
#[tokio::test]
async fn left_names_nobody_who_still_shares_a_room() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let henry = harness.register("henry").await;
    harness.register("erin").await;
    let one = harness.create_public_room(&alice.token).await;
    let two = harness.create_public_room(&alice.token).await;
    let three = harness.create_public_room(&alice.token).await;
    for room in [&one, &two, &three] {
        harness.join(room, &henry.token).await;
    }
    let start = next_batch(&harness.sync(&alice, None).await);

    harness.leave(&one, &henry.token).await;
    harness
        .invite(&two, &alice.token, "@erin:example.org")
        .await;
    let sync = harness.sync(&alice, Some(&start)).await;
    assert!(left(&sync).is_empty(), "{sync}");
    assert_eq!(
        changed(&sync),
        vec!["@erin:example.org".to_owned()],
        "an invitee is someone to share room keys with: {sync}"
    );

    harness.leave(&three, &alice.token).await;
    let parted = harness.sync(&alice, Some(&next_batch(&sync))).await;
    assert!(
        changed(&parted).is_empty() && left(&parted).is_empty(),
        "alice and henry still share `two`: {parted}"
    );
}

/// When alice joins a room, everyone in it may be new to her: all of them
/// are in `changed`. When she leaves, everyone she then stops sharing a
/// room with is in `left` -- but nobody who joined the room after she left,
/// which would tell her who is in a room she is no longer in. And a
/// stranger's membership in a room alice is not in is never named.
#[tokio::test]
async fn alice_joining_and_leaving_names_the_room_as_she_saw_it() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let carol = harness.register("carol").await;
    let dave = harness.register("dave").await;
    let room = harness.create_public_room(&bob.token).await;
    harness.join(&room, &carol.token).await;
    let start = next_batch(&harness.sync(&alice, None).await);

    harness.join(&room, &alice.token).await;
    // A room alice is not in: dave's join there is none of her business.
    let elsewhere = harness.create_public_room(&carol.token).await;
    harness.join(&elsewhere, &dave.token).await;
    let joined = harness.sync(&alice, Some(&start)).await;
    let mut seen = changed(&joined);
    seen.sort();
    assert_eq!(
        seen,
        vec![
            "@bob:example.org".to_owned(),
            "@carol:example.org".to_owned()
        ],
        "{joined}"
    );
    assert!(left(&joined).is_empty(), "{joined}");

    harness.leave(&room, &alice.token).await;
    harness.join(&room, &dave.token).await;
    let parted = harness.sync(&alice, Some(&next_batch(&joined))).await;
    let mut gone = left(&parted);
    gone.sort();
    assert_eq!(
        gone,
        vec![
            "@bob:example.org".to_owned(),
            "@carol:example.org".to_owned()
        ],
        "{parted}"
    );
    assert!(changed(&parted).is_empty(), "{parted}");
}
