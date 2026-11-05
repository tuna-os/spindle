//! Per-account budgets on ordinary writes, and the media quota (#741).
//!
//! Each budget is configured small here so the test can spend it: the
//! claim is that the request after the burst is refused 429
//! `M_LIMIT_EXCEEDED` with a `retry_after_ms` the client can wait out, and
//! that the accounts Synapse exempts -- appservice users whose registration
//! says so, an appservice's own sender, server admins -- are not refused.
//! The refill rates are slow enough that no test can earn a request back
//! while it runs.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const LIMITED_AS_TOKEN: &str = "as_token_limited";
const FREE_AS_TOKEN: &str = "as_token_free";

struct Harness {
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Harness {
    fn new(extra: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path().join("store")).unwrap());
        let app = Self::app_on(&dir, &store, extra);
        Self { dir, store, app }
    }

    /// An app over `store`; a second one over the same store is a restart
    /// with a different configuration.
    fn app_on(dir: &TempDir, store: &Arc<FjallStore>, extra: &str) -> axum::Router {
        let limited = dir.path().join("limited.yaml");
        std::fs::write(
            &limited,
            format!(
                "id: limited\nurl: null\nas_token: {LIMITED_AS_TOKEN}\nhs_token: hs_limited\n\
                 sender_localpart: _limited_bot\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_limited_.*:.*\"\n"
            ),
        )
        .unwrap();
        let free = dir.path().join("free.yaml");
        std::fs::write(
            &free,
            format!(
                "id: free\nurl: null\nas_token: {FREE_AS_TOKEN}\nhs_token: hs_free\n\
                 sender_localpart: _free_bot\nrate_limited: false\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_free_.*:.*\"\n"
            ),
        )
        .unwrap();
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[storage]\npath = \"{}\"\n\
             [appservices]\nregistrations = [\"{}\", \"{}\"]\n{extra}",
            dir.path().display(),
            limited.display(),
            free.display(),
        ))
        .expect("the configuration is valid");
        spindle_server::app(config, Arc::clone(store)).expect("the app builds")
    }

    async fn call(&self, request: Request<Body>) -> Answer {
        Self::call_on(&self.app, request).await
    }

    async fn call_on(app: &axum::Router, request: Request<Body>) -> Answer {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        Answer {
            status,
            headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    /// At most five per harness: registration is itself rate limited per
    /// source, and every request here comes from the same nowhere.
    async fn register(&self, username: &str) -> String {
        let answer = self
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
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        answer.body["access_token"].as_str().unwrap().to_owned()
    }

    fn promote(&self, localpart: &str) {
        assert!(
            Accounts::new(self.store.as_ref(), "example.org")
                .set_admin(localpart, true)
                .unwrap()
        );
    }

    fn request(method: &str, path: &str, token: &str, body: &Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> Answer {
        self.call(Self::request("POST", path, token, body)).await
    }

    async fn put(&self, path: &str, token: &str, body: &Value) -> Answer {
        self.call(Self::request("PUT", path, token, body)).await
    }

    async fn create_room(&self, token: &str, query: &str) -> String {
        let answer = self
            .post(
                &format!("/_matrix/client/v3/createRoom{query}"),
                token,
                &json!({ "preset": "public_chat" }),
            )
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        answer.body["room_id"].as_str().unwrap().to_owned()
    }

    async fn send(&self, token: &str, room_id: &str, txn: &str, query: &str) -> Answer {
        self.put(
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}{query}"),
            token,
            &json!({ "msgtype": "m.text", "body": txn }),
        )
        .await
    }

    async fn upload_on(app: &axum::Router, token: &str, bytes: &[u8]) -> Answer {
        Self::call_on(
            app,
            Request::builder()
                .method("POST")
                .uri("/_matrix/media/v3/upload")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
    }

    async fn upload(&self, token: &str, bytes: &[u8]) -> Answer {
        Self::upload_on(&self.app, token, bytes).await
    }

    async fn invite(&self, token: &str, room_id: &str, target: &str) -> Answer {
        self.post(
            &format!("/_matrix/client/v3/rooms/{room_id}/invite"),
            token,
            &json!({ "user_id": format!("@{target}:example.org") }),
        )
        .await
    }
}

/// The refusal a spent budget gets: 429, the spec's code, how long to
/// wait in the body, and the same in whole seconds in `Retry-After`.
#[track_caller]
fn assert_limited(answer: &Answer) {
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.body
    );
    assert_eq!(
        answer.body["errcode"], "M_LIMIT_EXCEEDED",
        "{}",
        answer.body
    );
    let retry = answer.body["retry_after_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("no retry_after_ms: {}", answer.body));
    assert!(retry > 0, "{}", answer.body);
    let header: u64 = answer.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(header, retry.div_ceil(1000));
}

#[track_caller]
fn assert_ok(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
}

/// Sends, state and redactions share one budget; a retried transaction
/// spends nothing, so it still answers once the budget is gone.
#[tokio::test]
async fn the_message_after_the_burst_is_refused() {
    let harness = Harness::new("[ratelimit]\nmessages = { per_second = 0.001, burst = 3 }\n");
    let alice = harness.register("alice").await;
    let room = harness.create_room(&alice, "").await;

    let sent = harness.send(&alice, &room, "one", "").await;
    assert_ok(&sent);
    let event_id = sent.body["event_id"].as_str().unwrap().to_owned();
    assert_ok(
        &harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
                &alice,
                &json!({ "topic": "budgets" }),
            )
            .await,
    );
    assert_ok(
        &harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/redact/{event_id}/r1"),
                &alice,
                &json!({}),
            )
            .await,
    );

    assert_limited(&harness.send(&alice, &room, "four", "").await);
    assert_limited(
        &harness
            .put(
                &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
                &alice,
                &json!({ "name": "spent" }),
            )
            .await,
    );
    let replay = harness.send(&alice, &room, "one", "").await;
    assert_ok(&replay);
    assert_eq!(replay.body["event_id"], event_id.as_str());
}

/// Joins answered here have their own budget, apart from sends.
#[tokio::test]
async fn the_local_join_after_the_burst_is_refused() {
    let harness = Harness::new(
        "[ratelimit]\njoins_local = { per_second = 0.001, burst = 2 }\n\
         room_creation = { per_second = 1.0, burst = 10 }\n",
    );
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    let rooms = [
        harness.create_room(&alice, "").await,
        harness.create_room(&alice, "").await,
        harness.create_room(&alice, "").await,
    ];

    for room in &rooms[..2] {
        assert_ok(
            &harness
                .post(&format!("/_matrix/client/v3/join/{room}"), &bob, &json!({}))
                .await,
        );
    }
    assert_limited(
        &harness
            .post(
                &format!("/_matrix/client/v3/rooms/{}/join", rooms[2]),
                &bob,
                &json!({}),
            )
            .await,
    );
}

/// A join this server has to ask another for spends the remote budget
/// whether or not the handshake then succeeds; here it cannot, because
/// federation is off, and the second attempt is refused before it tries.
#[tokio::test]
async fn the_remote_join_after_the_burst_is_refused() {
    let harness = Harness::new(
        "[ratelimit]\njoins_remote = { per_second = 0.001, burst = 1 }\n\
         [federation]\nenabled = false\n",
    );
    let alice = harness.register("alice").await;
    let path = "/_matrix/client/v3/join/!elsewhere:remote.example?server_name=remote.example";

    let first = harness.post(path, &alice, &json!({})).await;
    assert_ne!(
        first.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        first.body
    );
    assert_limited(&harness.post(path, &alice, &json!({})).await);
}

/// Invites spend the inviter's budget.
#[tokio::test]
async fn the_invite_after_the_inviters_burst_is_refused() {
    let harness =
        Harness::new("[ratelimit]\ninvites_per_issuer = { per_second = 0.001, burst = 2 }\n");
    let alice = harness.register("alice").await;
    for name in ["bob", "carol", "dave"] {
        harness.register(name).await;
    }
    let room = harness.create_room(&alice, "").await;

    assert_ok(&harness.invite(&alice, &room, "bob").await);
    assert_ok(&harness.invite(&alice, &room, "carol").await);
    assert_limited(&harness.invite(&alice, &room, "dave").await);
}

/// ...and the invitee's, which is what one inviter's budget cannot see:
/// the same person invited again is refused while someone else is not.
#[tokio::test]
async fn the_invite_after_the_invitees_burst_is_refused() {
    let harness = Harness::new(
        "[ratelimit]\ninvites_per_target = { per_second = 0.001, burst = 1 }\n\
         room_creation = { per_second = 1.0, burst = 10 }\n",
    );
    let alice = harness.register("alice").await;
    harness.register("bob").await;
    harness.register("carol").await;
    let first = harness.create_room(&alice, "").await;
    let second = harness.create_room(&alice, "").await;

    assert_ok(&harness.invite(&alice, &first, "bob").await);
    assert_limited(&harness.invite(&alice, &second, "bob").await);
    assert_ok(&harness.invite(&alice, &second, "carol").await);
}

#[tokio::test]
async fn the_room_created_after_the_burst_is_refused() {
    let harness = Harness::new("[ratelimit]\nroom_creation = { per_second = 0.001, burst = 2 }\n");
    let alice = harness.register("alice").await;
    harness.create_room(&alice, "").await;
    harness.create_room(&alice, "").await;
    assert_limited(
        &harness
            .post("/_matrix/client/v3/createRoom", &alice, &json!({}))
            .await,
    );
}

/// `POST /upload` and `POST /create` mint from one budget; filling a
/// created ID is the same upload and is not counted again.
#[tokio::test]
async fn the_upload_after_the_burst_is_refused() {
    let harness = Harness::new("[ratelimit]\nmedia_uploads = { per_second = 0.001, burst = 2 }\n");
    let alice = harness.register("alice").await;

    assert_ok(&harness.upload(&alice, b"first").await);
    let created = harness
        .post("/_matrix/media/v1/create", &alice, &json!({}))
        .await;
    assert_ok(&created);
    let media_id = created.body["content_uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let filled = harness
        .call(
            Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/media/v3/upload/example.org/{media_id}"))
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from("second"))
                .unwrap(),
        )
        .await;
    assert_ok(&filled);

    assert_limited(&harness.upload(&alice, b"third").await);
    assert_limited(
        &harness
            .post("/_matrix/media/v1/create", &alice, &json!({}))
            .await,
    );
}

/// A registration with `rate_limited: false` exempts its users; one
/// without it exempts only its own sender, as the spec has it.
#[tokio::test]
async fn appservice_users_are_exempt_when_their_registration_says_so() {
    let harness = Harness::new(
        "[ratelimit]\nmessages = { per_second = 0.001, burst = 2 }\n\
         room_creation = { per_second = 0.001, burst = 1 }\n",
    );
    let ghost = "?user_id=@_free_ghost:example.org";
    let room = harness.create_room(FREE_AS_TOKEN, ghost).await;
    harness.create_room(FREE_AS_TOKEN, ghost).await;
    for txn in ["a", "b", "c", "d"] {
        assert_ok(&harness.send(FREE_AS_TOKEN, &room, txn, ghost).await);
    }

    let sender = "?user_id=@_limited_bot:example.org";
    let room = harness.create_room(LIMITED_AS_TOKEN, sender).await;
    for txn in ["a", "b", "c", "d"] {
        assert_ok(&harness.send(LIMITED_AS_TOKEN, &room, txn, sender).await);
    }

    let ghost = "?user_id=@_limited_ghost:example.org";
    let room = harness.create_room(LIMITED_AS_TOKEN, ghost).await;
    assert_ok(&harness.send(LIMITED_AS_TOKEN, &room, "a", ghost).await);
    assert_ok(&harness.send(LIMITED_AS_TOKEN, &room, "b", ghost).await);
    assert_limited(&harness.send(LIMITED_AS_TOKEN, &room, "c", ghost).await);
}

/// Server admins are exempt from every budget, and only admins: the same
/// requests from an ordinary account beside them are refused.
#[tokio::test]
async fn server_admins_are_exempt() {
    let harness = Harness::new(
        "[ratelimit]\nmessages = { per_second = 0.001, burst = 1 }\n\
         room_creation = { per_second = 0.001, burst = 1 }\n\
         media_uploads = { per_second = 0.001, burst = 1 }\n",
    );
    let admin = harness.register("root").await;
    let alice = harness.register("alice").await;
    harness.promote("root");

    let room = harness.create_room(&admin, "").await;
    harness.create_room(&admin, "").await;
    for txn in ["a", "b", "c"] {
        assert_ok(&harness.send(&admin, &room, txn, "").await);
    }
    assert_ok(&harness.upload(&admin, b"one").await);
    assert_ok(&harness.upload(&admin, b"two").await);

    let room = harness.create_room(&alice, "").await;
    assert_limited(
        &harness
            .post("/_matrix/client/v3/createRoom", &alice, &json!({}))
            .await,
    );
    assert_ok(&harness.send(&alice, &room, "a", "").await);
    assert_limited(&harness.send(&alice, &room, "b", "").await);
    assert_ok(&harness.upload(&alice, b"one").await);
    assert_limited(&harness.upload(&alice, b"two").await);
}

/// Over quota is 403 `M_RESOURCE_LIMIT_EXCEEDED` with the contact the
/// support config names, on both upload paths; the bytes held before
/// the quota was configured count; deleting media gives its bytes back;
/// an admin is not held to it.
#[tokio::test]
async fn an_upload_past_the_quota_is_refused() {
    let harness = Harness::new("[ratelimit]\nenabled = false\n");
    let alice = harness.register("alice").await;
    let admin = harness.register("root").await;
    harness.promote("root");
    // Stored before the quota existed, under a configuration without one.
    let early = harness.upload(&alice, b"123456").await;
    assert_ok(&early);
    let early_id = early.body["content_uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();

    let quota = Harness::app_on(
        &harness.dir,
        &harness.store,
        "[ratelimit]\nenabled = false\n[media]\nmax_bytes_per_user = 10\n\
         [server.support]\nsupport_page = \"https://example.org/help\"\n",
    );
    let refused = Harness::upload_on(&quota, &alice, b"12345").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(refused.body["errcode"], "M_RESOURCE_LIMIT_EXCEEDED");
    assert_eq!(refused.body["admin_contact"], "https://example.org/help");
    assert_ok(&Harness::upload_on(&quota, &alice, b"1234").await);

    let created = Harness::call_on(
        &quota,
        Harness::request("POST", "/_matrix/media/v1/create", &alice, &json!({})),
    )
    .await;
    assert_ok(&created);
    let reserved = created.body["content_uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let fill = || {
        Harness::call_on(
            &quota,
            Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/media/v3/upload/example.org/{reserved}"))
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from("1"))
                .unwrap(),
        )
    };
    let refused = fill().await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(refused.body["errcode"], "M_RESOURCE_LIMIT_EXCEEDED");

    let deleted = Harness::call_on(
        &quota,
        Harness::request(
            "DELETE",
            &format!("/_synapse/admin/v1/media/example.org/{early_id}"),
            &admin,
            &json!({}),
        ),
    )
    .await;
    assert_ok(&deleted);
    assert_ok(&fill().await);

    assert_ok(&Harness::upload_on(&quota, &admin, b"0123456789abcdef").await);
}
