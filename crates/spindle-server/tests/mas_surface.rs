//! The `/_synapse/mas/*` provisioning surface — a real Spindle instance
//! over TCP, driven the way the Matrix Authentication Service drives a
//! homeserver it manages.
//!
//! What the suite pins: the surface exists only for a deployment with a
//! `homeserver_secret`, and only for the caller holding it; provisioning
//! creates-then-updates with the 201/200 distinction MAS reads;
//! availability answers with the same Matrix errors registration would
//! give, appservice reservations included; device sync reconciles to
//! exactly the provider's set; and `delete_user` is a deactivation — the
//! localpart stays reserved, every session dies, and `reactivate_user`
//! brings the account (not the sessions) back.

use std::sync::Arc;

use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;

const AS_TOKEN: &str = "as_secret_token_for_tests";
const MAS_SECRET: &str = "mas_matrix_secret_for_tests";

struct Instance {
    _dir: TempDir,
    _reg_dir: TempDir,
    name: String,
    client: reqwest::Client,
}

impl Instance {
    /// `managed` controls whether `[auth.delegated]` (with a
    /// `homeserver_secret`) is configured. The provider itself is never
    /// contacted: this surface is inbound.
    async fn start(managed: bool) -> Instance {
        let reg_dir = TempDir::new().unwrap();
        let reg_path = reg_dir.path().join("bridge.yaml");
        std::fs::write(
            &reg_path,
            format!(
                "id: testbridge\nurl: null\nas_token: {AS_TOKEN}\n\
                 hs_token: hs_secret_token_for_tests\nsender_localpart: _bridge_bot\n\
                 namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n"
            ),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let name = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let auth = if managed {
            format!(
                "[auth.delegated]\nissuer = \"http://127.0.0.1:1/\"\n\
                 introspection_endpoint = \"http://127.0.0.1:1/introspect\"\n\
                 client_id = \"spindle\"\nclient_secret = \"hush\"\n\
                 homeserver_secret = \"{MAS_SECRET}\"\n"
            )
        } else {
            String::new()
        };
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"{name}\"\n[ratelimit]\nenabled = false\n\
             [appservices]\nregistrations = [\"{}\"]\n{auth}",
            reg_path.display()
        ))
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Instance {
            _dir: dir,
            _reg_dir: reg_dir,
            name,
            client: reqwest::Client::new(),
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("http://{}{path}", self.name));
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

    async fn mas_post(&self, endpoint: &str, body: Value) -> (u16, Value) {
        self.request(
            reqwest::Method::POST,
            &format!("/_synapse/mas/{endpoint}"),
            Some(MAS_SECRET),
            Some(&body),
        )
        .await
    }

    async fn mas_get(&self, endpoint: &str, localpart: &str) -> (u16, Value) {
        self.request(
            reqwest::Method::GET,
            &format!("/_synapse/mas/{endpoint}?localpart={localpart}"),
            Some(MAS_SECRET),
            None,
        )
        .await
    }
}

#[tokio::test]
async fn the_surface_is_the_secret_holders_alone() {
    // Without delegation there is no surface at all.
    let unmanaged = Instance::start(false).await;
    let (status, body) = unmanaged.mas_get("query_user", "alice").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");

    // With it, the secret is the whole admission ticket.
    let managed = Instance::start(true).await;
    let (status, body) = managed
        .request(
            reqwest::Method::POST,
            "/_synapse/mas/provision_user",
            Some("not_the_secret"),
            Some(&json!({ "localpart": "mallory" })),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    let (status, _) = managed
        .request(
            reqwest::Method::POST,
            "/_synapse/mas/provision_user",
            None,
            Some(&json!({ "localpart": "mallory" })),
        )
        .await;
    assert_eq!(status, 403, "no token is not a better token");
}

#[tokio::test]
async fn provision_creates_then_updates() {
    let server = Instance::start(true).await;

    let (status, body) = server
        .mas_post(
            "provision_user",
            json!({ "localpart": "alice", "set_displayname": "Alice" }),
        )
        .await;
    assert_eq!(status, 201, "first sight creates: {body}");

    let (status, body) = server.mas_get("query_user", "alice").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user_id"], format!("@alice:{}", server.name));
    assert_eq!(body["display_name"], "Alice", "{body}");
    assert_eq!(body["is_deactivated"], false, "{body}");

    // The profile is world-readable through the ordinary client API too.
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            &format!("/_matrix/client/v3/profile/@alice:{}", server.name),
            None,
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["displayname"], "Alice", "{body}");

    let (status, body) = server
        .mas_post(
            "provision_user",
            json!({ "localpart": "alice", "unset_displayname": true }),
        )
        .await;
    assert_eq!(status, 200, "second sight updates: {body}");
    let (_, body) = server.mas_get("query_user", "alice").await;
    assert!(body["display_name"].is_null(), "{body}");

    let (status, body) = server.mas_get("query_user", "nobody").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND", "{body}");
}

#[tokio::test]
async fn availability_honours_every_reservation() {
    let server = Instance::start(true).await;

    let (status, body) = server.mas_get("is_localpart_available", "fresh").await;
    assert_eq!(status, 200, "{body}");

    server
        .mas_post("provision_user", json!({ "localpart": "taken" }))
        .await;
    let (_, body) = server.mas_get("is_localpart_available", "taken").await;
    assert_eq!(body["errcode"], "M_USER_IN_USE", "{body}");

    let (_, body) = server
        .mas_get("is_localpart_available", "_bridge_ghost")
        .await;
    assert_eq!(
        body["errcode"], "M_EXCLUSIVE",
        "the bridge got there first: {body}"
    );

    let (_, body) = server.mas_get("is_localpart_available", "Alice").await;
    assert_eq!(body["errcode"], "M_INVALID_USERNAME", "{body}");
}

#[tokio::test]
async fn sync_devices_reconciles_to_the_providers_set() {
    let server = Instance::start(true).await;
    server
        .mas_post("provision_user", json!({ "localpart": "alice" }))
        .await;
    for device in ["OLD1", "KEPT"] {
        let (status, body) = server
            .mas_post(
                "upsert_device",
                json!({ "localpart": "alice", "device_id": device }),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }

    let (status, body) = server
        .mas_post(
            "sync_devices",
            json!({ "localpart": "alice", "devices": ["KEPT", "NEW1"] }),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Renaming is the probe: it 404s for a device that does not exist.
    let rename = |device: &str| {
        server.mas_post(
            "update_device_display_name",
            json!({ "localpart": "alice", "device_id": device, "display_name": "probe" }),
        )
    };
    let (status, body) = rename("OLD1").await;
    assert_eq!(status, 404, "synced away: {body}");
    let (status, _) = rename("KEPT").await;
    assert_eq!(status, 200);
    let (status, _) = rename("NEW1").await;
    assert_eq!(status, 200, "sync created it");

    let (status, body) = server
        .mas_post(
            "delete_device",
            json!({ "localpart": "alice", "device_id": "NEW1" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = rename("NEW1").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn delete_user_is_a_deactivation_not_an_erasure_of_the_name() {
    let server = Instance::start(true).await;

    // A live session to kill: the appservice door still works under
    // delegation, and unlike login it hands out a local access token.
    let (status, body) = server
        .request(
            reqwest::Method::POST,
            "/_matrix/client/v3/register",
            Some(AS_TOKEN),
            Some(&json!({
                "type": "m.login.application_service",
                "username": "_bridge_doomed",
            })),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap().to_owned();
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 200);

    let (status, body) = server
        .mas_post(
            "delete_user",
            json!({ "localpart": "_bridge_doomed", "erase": true }),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Logged out everywhere…
    let (status, body) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    // …the name still reserved…
    let (_, body) = server.mas_get("query_user", "_bridge_doomed").await;
    assert_eq!(body["is_deactivated"], true, "{body}");
    // …and reactivation brings the account back without the sessions.
    let (status, body) = server
        .mas_post("reactivate_user", json!({ "localpart": "_bridge_doomed" }))
        .await;
    assert_eq!(status, 200, "{body}");
    let (_, body) = server.mas_get("query_user", "_bridge_doomed").await;
    assert_eq!(body["is_deactivated"], false, "{body}");
    let (status, _) = server
        .request(
            reqwest::Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, 401, "the dead session stays dead");
}

#[tokio::test]
async fn displayname_and_cross_signing_asks_are_answered() {
    let server = Instance::start(true).await;
    server
        .mas_post("provision_user", json!({ "localpart": "alice" }))
        .await;

    let (status, body) = server
        .mas_post(
            "set_displayname",
            json!({ "localpart": "alice", "displayname": "Alice Prime" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (_, body) = server.mas_get("query_user", "alice").await;
    assert_eq!(body["display_name"], "Alice Prime", "{body}");

    let (status, body) = server
        .mas_post("unset_displayname", json!({ "localpart": "alice" }))
        .await;
    assert_eq!(status, 200, "{body}");
    let (_, body) = server.mas_get("query_user", "alice").await;
    assert!(body["display_name"].is_null(), "{body}");

    let (status, body) = server
        .mas_post("allow_cross_signing_reset", json!({ "localpart": "alice" }))
        .await;
    assert_eq!(status, 200, "acknowledged, not refused: {body}");
}
