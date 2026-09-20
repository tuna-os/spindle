//! MSC3814 dehydrated devices: a device parked on the server so that room
//! keys sent while every real device is gone are still there on return.
//!
//! The properties: the record round-trips and is gone after a delete; the
//! dehydrated device is a real device to everyone else (its keys answer
//! `/keys/query`, its one-time keys are claimable); what is sent to it
//! waits in batches that stay until acknowledged by the token that
//! delivered them; and putting a second one replaces the first outright.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

const PREFIX: &str = "/_matrix/client/unstable/org.matrix.msc3814.v1";

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

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
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

    /// Registers, and returns the token and the session's device id.
    async fn register(&self, username: &str) -> (String, String) {
        let (status, body) = self
            .request(
                "POST",
                "/_matrix/client/v3/register",
                "",
                &json!({
                    "username": username,
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy", "session": "register" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["access_token"].as_str().unwrap().to_owned(),
            body["device_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn dehydrate(&self, token: &str, device_id: &str, otk: &str) -> Value {
        let (status, body) = self
            .request(
                "PUT",
                &format!("{PREFIX}/dehydrated_device"),
                token,
                &json!({
                    "device_id": device_id,
                    "device_data": { "algorithm": "org.matrix.msc3814.v2", "account": "opaque" },
                    "initial_device_display_name": "Dehydrated",
                    "device_keys": {
                        "user_id": "@alice:example.org",
                        "device_id": device_id,
                        "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                        "keys": { format!("curve25519:{device_id}"): "identity" },
                    },
                    "one_time_keys": { format!("signed_curve25519:{otk}"): { "key": otk } },
                    "fallback_keys": { "signed_curve25519:FB": { "key": "fallback" } },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

#[tokio::test]
async fn the_record_round_trips_and_is_gone_after_a_delete() {
    let harness = Harness::new();
    let (alice, _) = harness.register("alice").await;

    let (status, body) = harness
        .request(
            "GET",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], "M_NOT_FOUND");

    let put = harness.dehydrate(&alice, "DEHYDRATED1", "AAAAAQ").await;
    assert_eq!(put["device_id"], "DEHYDRATED1");

    let (status, body) = harness
        .request(
            "GET",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], "DEHYDRATED1");
    assert_eq!(body["device_data"]["algorithm"], "org.matrix.msc3814.v2");
    assert_eq!(body["device_data"]["account"], "opaque");

    let (status, body) = harness
        .request(
            "DELETE",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], "DEHYDRATED1");
    let (status, _) = harness
        .request(
            "GET",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = harness
        .request(
            "DELETE",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleting nothing is a 404, not a success"
    );
}

#[tokio::test]
async fn the_dehydrated_device_is_a_real_device_to_everyone_else() {
    let harness = Harness::new();
    let (alice, _) = harness.register("alice").await;
    let (bob, _) = harness.register("bob").await;
    harness.dehydrate(&alice, "DEHYDRATED1", "AAAAAQ").await;

    // Bob finds its identity keys where he finds every device's.
    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/keys/query",
            &bob,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["device_keys"]["@alice:example.org"]["DEHYDRATED1"]["keys"]["curve25519:DEHYDRATED1"],
        "identity",
        "{body}"
    );

    // And claims a one-time key from it, which is how he starts an Olm
    // session to send it room keys.
    let (status, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/keys/claim",
            &bob,
            &json!({ "one_time_keys": { "@alice:example.org": { "DEHYDRATED1": "signed_curve25519" } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["one_time_keys"]["@alice:example.org"]["DEHYDRATED1"]["signed_curve25519:AAAAAQ"]["key"],
        "AAAAAQ",
        "{body}"
    );

    // Alice's own session learns the device list moved.
    let (status, sync) = harness
        .request("GET", "/_matrix/client/v3/sync", &bob, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{sync}");
}

#[tokio::test]
async fn events_wait_in_batches_until_acknowledged_by_their_token() {
    let harness = Harness::new();
    let (alice, _) = harness.register("alice").await;
    let (bob, _) = harness.register("bob").await;
    harness.dehydrate(&alice, "DEHYDRATED1", "AAAAAQ").await;

    for (txn, body) in [("t1", "first"), ("t2", "second")] {
        let (status, response) = harness
            .request(
                "PUT",
                &format!("/_matrix/client/v3/sendToDevice/m.room.encrypted/{txn}"),
                &bob,
                &json!({ "messages": { "@alice:example.org": { "DEHYDRATED1": { "ciphertext": body } } } }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
    }

    let path = format!("{PREFIX}/dehydrated_device/DEHYDRATED1/events");
    let (status, first) = harness.request("POST", &path, &alice, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let events = first["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "{first}");
    assert_eq!(events[0]["content"]["ciphertext"], "first");
    assert_eq!(events[0]["sender"], "@bob:example.org");
    let next_batch = first["next_batch"].as_str().unwrap().to_owned();

    // Not acknowledged: the same batch again, for the client that crashed
    // between reading and rehydrating.
    let (_, again) = harness.request("POST", &path, &alice, &json!({})).await;
    assert_eq!(again["events"].as_array().unwrap().len(), 2, "{again}");

    // Acknowledged by the token: nothing left.
    let (status, after) = harness
        .request("POST", &path, &alice, &json!({ "next_batch": next_batch }))
        .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["events"], json!([]), "{after}");

    // The wrong device id, or somebody else's, is a 404: the queue is the
    // owner's, and the id is not a secret.
    let (status, _) = harness
        .request(
            "POST",
            &format!("{PREFIX}/dehydrated_device/OTHER/events"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = harness.request("POST", &path, &bob, &json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_second_dehydrated_device_replaces_the_first_outright() {
    let harness = Harness::new();
    let (alice, _) = harness.register("alice").await;
    let (bob, _) = harness.register("bob").await;
    harness.dehydrate(&alice, "DEHYDRATED1", "AAAAAQ").await;
    let (status, response) = harness
        .request(
            "PUT",
            "/_matrix/client/v3/sendToDevice/m.room.encrypted/t1",
            &bob,
            &json!({ "messages": { "@alice:example.org": { "DEHYDRATED1": { "ciphertext": "old" } } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    harness.dehydrate(&alice, "DEHYDRATED2", "AAAAAg").await;

    let (status, body) = harness
        .request(
            "GET",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], "DEHYDRATED2");

    // The first device's keys are gone from the world...
    let (_, body) = harness
        .request(
            "POST",
            "/_matrix/client/v3/keys/query",
            &bob,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    assert!(
        body["device_keys"]["@alice:example.org"]["DEHYDRATED1"].is_null(),
        "{body}"
    );
    assert!(
        body["device_keys"]["@alice:example.org"]["DEHYDRATED2"].is_object(),
        "{body}"
    );

    // ...and so is its queue: the old id answers 404, and nothing of the
    // old queue is handed to the new device.
    let (status, _) = harness
        .request(
            "POST",
            &format!("{PREFIX}/dehydrated_device/DEHYDRATED1/events"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, fresh) = harness
        .request(
            "POST",
            &format!("{PREFIX}/dehydrated_device/DEHYDRATED2/events"),
            &alice,
            &json!({}),
        )
        .await;
    assert_eq!(fresh["events"], json!([]), "{fresh}");
}

#[tokio::test]
async fn the_requesting_session_cannot_be_the_dehydrated_device() {
    let harness = Harness::new();
    let (alice, session_device) = harness.register("alice").await;
    let (status, body) = harness
        .request(
            "PUT",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({
                "device_id": session_device,
                "device_data": { "algorithm": "org.matrix.msc3814.v2" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // And a body without the algorithm is refused rather than stored.
    let (status, body) = harness
        .request(
            "PUT",
            &format!("{PREFIX}/dehydrated_device"),
            &alice,
            &json!({ "device_id": "DEHYDRATED1", "device_data": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}
