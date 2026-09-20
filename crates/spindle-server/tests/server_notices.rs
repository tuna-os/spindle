//! Server notices: an admin's message to one user, as a real event in a
//! room this server opens for the two of them.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_server::accounts::Accounts;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    store: Arc<FjallStore>,
    app: axum::Router,
}

impl Harness {
    fn new(configured: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let notices = if configured {
            "[server_notices]\nlocalpart = \"notices\"\ndisplay_name = \"The Management\"\n"
        } else {
            ""
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n{notices}"
        ))
        .unwrap();
        let app = spindle_server::app(config, Arc::clone(&store)).expect("the app builds");
        Self { dir, store, app }
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        payload: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let body = match payload {
            Some(payload) => {
                builder = builder.header("content-type", "application/json");
                Body::from(payload.to_string())
            }
            None => Body::empty(),
        };
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
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
            .send(
                "POST",
                "/_matrix/client/v3/register",
                None,
                Some(&json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["access_token"].as_str().unwrap().to_owned()
    }

    async fn admin(&self) -> String {
        let token = self.register("root").await;
        Accounts::new(self.store.as_ref(), "example.org")
            .set_admin("root", true)
            .unwrap();
        token
    }

    async fn notice(&self, admin: &str, user_id: &str, body: &str) -> (StatusCode, Value) {
        self.send(
            "POST",
            "/_synapse/admin/v1/send_server_notice",
            Some(admin),
            Some(&json!({
                "user_id": user_id,
                "content": { "msgtype": "m.text", "body": body },
            })),
        )
        .await
    }
}

#[tokio::test]
async fn a_notice_opens_a_tagged_room_and_later_ones_reuse_it() {
    let server = Harness::new(true);
    let admin = server.admin().await;
    let alice = server.register("alice").await;

    let (status, body) = server
        .notice(&admin, "@alice:example.org", "the disk is nearly full")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first = body["event_id"].as_str().unwrap().to_owned();

    // Alice is invited to a room named as configured, by the notices
    // account, and the notice is in it.
    let (status, sync) = server
        .send("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    let invites = sync["rooms"]["invite"].as_object().unwrap();
    assert_eq!(invites.len(), 1, "{sync}");
    let (room_id, invite) = invites.iter().next().unwrap();
    let names: Vec<&str> = invite["invite_state"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "m.room.name")
        .filter_map(|event| event["content"]["name"].as_str())
        .collect();
    assert_eq!(names, vec!["Server Notices"], "{invite}");

    let (status, body) = server
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .notice(&admin, "@alice:example.org", "and now it is full")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = body["event_id"].as_str().unwrap().to_owned();

    let (status, messages) = server
        .send(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=20"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{messages}");
    let chunk = messages["chunk"].as_array().unwrap();
    let ids: Vec<&str> = chunk
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect();
    assert!(
        ids.contains(&first.as_str()) && ids.contains(&second.as_str()),
        "{messages}"
    );
    let sender = chunk
        .iter()
        .find(|event| event["event_id"] == second)
        .map(|event| event["sender"].clone())
        .unwrap();
    assert_eq!(sender, "@notices:example.org");

    // Filed under the tag Element looks for, and the sender wears the
    // configured name.
    let (status, tags) = server
        .send(
            "GET",
            &format!("/_matrix/client/v3/user/@alice:example.org/rooms/{room_id}/tags"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tags}");
    assert!(tags["tags"]["m.server_notice"].is_object(), "{tags}");
    let (status, profile) = server
        .send(
            "GET",
            "/_matrix/client/v3/profile/@notices:example.org",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{profile}");
    assert_eq!(profile["displayname"], "The Management");

    // Leaving does not lose the thread: the next notice invites again.
    let (status, body) = server
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .notice(&admin, "@alice:example.org", "we miss you")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, sync) = server
        .send("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
    assert!(sync["rooms"]["invite"][room_id].is_object(), "{sync}");
}

#[tokio::test]
async fn unconfigured_unknown_and_unprivileged_are_refused() {
    let quiet = Harness::new(false);
    let admin = quiet.admin().await;
    quiet.register("alice").await;
    let (status, body) = quiet.notice(&admin, "@alice:example.org", "hello").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let server = Harness::new(true);
    let admin = server.admin().await;
    let alice = server.register("alice").await;
    let (status, body) = server.notice(&admin, "@nobody:example.org", "hello").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = server.notice(&admin, "@bob:elsewhere.test", "hello").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = server.notice(&alice, "@alice:example.org", "hello").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}
