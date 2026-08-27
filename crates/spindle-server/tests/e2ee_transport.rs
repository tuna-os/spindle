//! E2EE's transport: key upload/query/claim and to-device delivery.
//!
//! None of this is cryptography — the server holds keys it cannot use and
//! ferries ciphertext it cannot read. What it *can* break is delivery: hand
//! the same one-time key out twice and two sessions share Olm state; lose a
//! to-device message and a session never establishes; deliver one twice after
//! deleting too eagerly and... nothing, actually, clients dedupe — which is
//! why every ambiguity here resolves toward re-delivery and away from loss.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A server that can be stopped and started again over the same directory —
/// the restart is what the counter-resume test is about.
struct Harness {
    dir: TempDir,
    app: axum::Router,
}

/// One logged-in device: the token to act as it, the ID the server minted.
struct Device {
    token: String,
    device_id: String,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let app = Self::build(dir.path());
        Self { dir, app }
    }

    fn build(path: &std::path::Path) -> axum::Router {
        let store = Arc::new(FjallStore::open(path).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        spindle_server::app(config, store).expect("a signing key is established")
    }

    /// Everything in memory goes away; the directory stays.
    fn restart(&mut self) {
        self.app = Self::build(self.dir.path());
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
                            "auth": { "type": "m.login.dummy" },
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

    /// A further device for an already-registered account.
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

    /// Upload identity keys naming the device itself, as a real client would.
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
                        "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                        "keys": { format!("curve25519:{}", device.device_id): "fakekey" },
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// The to-device events a sync at `since` delivers (`None` = initial),
    /// alongside the `next_batch` token.
    async fn sync_to_device(&self, device: &Device, since: Option<&str>) -> (Vec<Value>, String) {
        let path = match since {
            Some(since) => format!("/_matrix/client/v3/sync?since={since}"),
            None => "/_matrix/client/v3/sync".to_owned(),
        };
        let (status, body) = self.get(&path, &device.token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["to_device"]["events"].as_array().unwrap().clone(),
            body["next_batch"].as_str().unwrap().to_owned(),
        )
    }
}

#[tokio::test]
async fn upload_counts_by_algorithm_and_query_round_trips() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    harness.upload_identity("@alice:example.org", &alice).await;

    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "one_time_keys": {
                    "signed_curve25519:AAAAHQ": { "key": "k1" },
                    "signed_curve25519:AAAAHR": { "key": "k2" },
                    "ed25519:AAAAHS": "unsigned-key",
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `signed_curve25519:AAAAHQ` counts under `signed_curve25519`: the count
    // a client acts on is per algorithm, not per key ID.
    assert_eq!(body["one_time_key_counts"]["signed_curve25519"], json!(2));
    assert_eq!(body["one_time_key_counts"]["ed25519"], json!(1));

    // An upload with nothing in it is how clients poll their counts.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["one_time_key_counts"]["signed_curve25519"], json!(2));

    // Bob queries alice: an empty device list means every device.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &bob.token,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let keys = &body["device_keys"]["@alice:example.org"][&alice.device_id];
    assert_eq!(keys["user_id"], json!("@alice:example.org"));
    assert_eq!(keys["device_id"], json!(alice.device_id));

    // A non-empty list narrows: naming a device that uploaded nothing
    // returns an empty map for the user, not an error.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &bob.token,
            &json!({ "device_keys": { "@alice:example.org": ["NOSUCHDEVICE"] } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_keys"]["@alice:example.org"], json!({}));
}

#[tokio::test]
async fn claim_hands_each_key_out_exactly_once() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;
    harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "one_time_keys": {
                    "signed_curve25519:AAAAHQ": { "key": "k1" },
                    "signed_curve25519:AAAAHR": { "key": "k2" },
                },
            }),
        )
        .await;

    let claim = json!({
        "one_time_keys": { "@alice:example.org": { alice.device_id.clone(): "signed_curve25519" } },
    });
    let mut handed_out = Vec::new();
    for _ in 0..2 {
        let (status, body) = harness
            .send("POST", "/_matrix/client/v3/keys/claim", &bob.token, &claim)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let keys = body["one_time_keys"]["@alice:example.org"][&alice.device_id]
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(keys.len(), 1);
        handed_out.push(keys.keys().next().unwrap().clone());
    }
    // Two claims, two *different* keys: a one-time key used twice is the
    // compromise Olm's forward secrecy exists to prevent.
    assert_ne!(handed_out[0], handed_out[1]);

    // Both spent: a third claim finds the device absent from the response,
    // which is the spec's shape for "no key left".
    let (status, body) = harness
        .send("POST", "/_matrix/client/v3/keys/claim", &bob.token, &claim)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["one_time_keys"].as_object().unwrap().is_empty(),
        "{body}"
    );

    // And the count agrees with what claiming consumed.
    let (_, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({}),
        )
        .await;
    assert_eq!(body["one_time_key_counts"], json!({}));
}

#[tokio::test]
async fn upload_refuses_keys_naming_another_identity() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.register("bob").await;

    // Naming another user: accepted, this would let any account plant keys
    // on another's identity, and verification downstream trusts the mapping.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "device_keys": {
                    "user_id": "@bob:example.org",
                    "device_id": alice.device_id,
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], json!("M_FORBIDDEN"));

    // Naming another device of one's own account is refused the same way:
    // the session token authenticates *this* device, not the account.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({
                "device_keys": {
                    "user_id": "@alice:example.org",
                    "device_id": "SOMEOTHERDEVICE",
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // And nothing was stored by either refusal.
    let (_, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &alice.token,
            &json!({ "device_keys": { "@alice:example.org": [], "@bob:example.org": [] } }),
        )
        .await;
    assert_eq!(body["device_keys"]["@alice:example.org"], json!({}));
    assert_eq!(body["device_keys"]["@bob:example.org"], json!({}));
}

#[tokio::test]
async fn to_device_messages_deliver_and_since_acknowledges() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    // Bob's position *before* the message exists: syncing from here must
    // deliver it.
    let (_, before) = harness.sync_to_device(&bob, None).await;

    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.room.encrypted/txn1",
            &alice.token,
            &json!({
                "messages": {
                    "@bob:example.org": { bob.device_id.clone(): { "ciphertext": "..." } },
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (events, after) = harness.sync_to_device(&bob, Some(&before)).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["type"], json!("m.room.encrypted"));
    assert_eq!(events[0]["sender"], json!("@alice:example.org"));
    assert_eq!(events[0]["content"]["ciphertext"], json!("..."));

    // Same token again: the batch was never acknowledged, so it comes again.
    // At-least-once — a client that crashed before persisting gets another
    // chance at the session-establishment ciphertext.
    let (events, _) = harness.sync_to_device(&bob, Some(&before)).await;
    assert_eq!(events.len(), 1, "re-delivery until acknowledged");

    // Advancing past the message acknowledges it...
    let (events, _) = harness.sync_to_device(&bob, Some(&after)).await;
    assert!(events.is_empty(), "{events:?}");

    // ...and the acknowledgement *deleted* it: even rewinding to the old
    // token finds nothing, which is what distinguishes deletion from mere
    // filtering.
    let (events, _) = harness.sync_to_device(&bob, Some(&before)).await;
    assert!(events.is_empty(), "acknowledged messages are gone");
}

#[tokio::test]
async fn wildcard_fans_out_to_devices_that_uploaded_keys() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob1 = harness.register("bob").await;
    let bob2 = harness.login("bob").await;
    let bob3 = harness.login("bob").await;
    // Two of bob's three devices announce themselves; the third never
    // uploads keys, and `*` resolves against uploaded keys — a device that
    // cannot decrypt anything gains nothing from ciphertext.
    harness.upload_identity("@bob:example.org", &bob1).await;
    harness.upload_identity("@bob:example.org", &bob2).await;

    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.room_key_request/txnw",
            &alice.token,
            &json!({
                "messages": { "@bob:example.org": { "*": { "action": "request" } } },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for device in [&bob1, &bob2] {
        let (events, _) = harness.sync_to_device(device, None).await;
        assert_eq!(events.len(), 1, "each announced device gets its copy");
    }
    let (events, _) = harness.sync_to_device(&bob3, None).await;
    assert!(events.is_empty(), "no keys uploaded, no copy");
}

#[tokio::test]
async fn send_to_device_replays_are_not_delivered_twice() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let message = json!({
        "messages": { "@bob:example.org": { bob.device_id.clone(): { "n": 1 } } },
    });
    for _ in 0..2 {
        // The retry that matters: the client timed out, cannot know whether
        // the batch landed, and asks again with the same transaction ID.
        let (status, body) = harness
            .send(
                "PUT",
                "/_matrix/client/v3/sendToDevice/m.test/txn9",
                &alice.token,
                &message,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (events, _) = harness.sync_to_device(&bob, None).await;
    assert_eq!(events.len(), 1, "a retried batch delivers once: {events:?}");

    // A different transaction ID is a different batch, not a replay.
    harness
        .send(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.test/txn10",
            &alice.token,
            &message,
        )
        .await;
    let (events, _) = harness.sync_to_device(&bob, None).await;
    assert_eq!(events.len(), 2, "{events:?}");
}

#[tokio::test]
async fn restart_resumes_the_counter_past_pending_to_device_messages() {
    let mut harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    // No rooms exist, so the global counter has no stream rows to recover
    // from — the pending message's sequence is recorded *only* in the
    // to-device queue, which is exactly the case that once lost messages.
    harness
        .send(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.test/before-restart",
            &alice.token,
            &json!({
                "messages": { "@bob:example.org": { bob.device_id.clone(): { "n": 1 } } },
            }),
        )
        .await;

    harness.restart();

    // A counter resumed below the pending message would hand its sequence
    // out again here, and the second write would overwrite the first —
    // silent loss of session-establishment ciphertext.
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.test/after-restart",
            &alice.token,
            &json!({
                "messages": { "@bob:example.org": { bob.device_id.clone(): { "n": 2 } } },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (events, _) = harness.sync_to_device(&bob, None).await;
    assert_eq!(
        events.len(),
        2,
        "both messages survive the restart: {events:?}"
    );
}
