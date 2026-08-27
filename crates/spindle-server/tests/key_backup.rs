//! Key backup and cross-signing — the recovery half of E2EE.
//!
//! The backup is the user's history encrypted to a key the server never
//! sees; cross-signing is the trust tree other users verify against. The
//! server's obligations are custodial: never degrade a stored key, never
//! resurrect a deleted version's number, never hand one user's signing
//! authority to another.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Harness {
    _dir: TempDir,
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
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("a signing key is established");
        Self { _dir: dir, app }
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

    async fn create_backup(&self, token: &str) -> String {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/room_keys/version",
                token,
                &json!({
                    "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                    "auth_data": { "public_key": "abcdef" },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["version"].as_str().unwrap().to_owned()
    }
}

fn session(verified: bool, index: u64, forwarded: u64, blob: &str) -> Value {
    json!({
        "first_message_index": index,
        "forwarded_count": forwarded,
        "is_verified": verified,
        "session_data": { "ciphertext": blob },
    })
}

#[tokio::test]
async fn version_numbers_advance_and_are_never_reused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    let first = harness.create_backup(&alice.token).await;
    assert_eq!(first, "1");

    // Delete it, then create again: the new version must NOT reuse "1" — a
    // client still holding the deleted version's number must keep getting
    // "gone", not someone new wearing it.
    let (status, _) = harness
        .send(
            "DELETE",
            "/_matrix/client/v3/room_keys/version/1",
            &alice.token,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let second = harness.create_backup(&alice.token).await;
    assert_eq!(second, "2");

    // The deleted version answers 404 everywhere…
    let (status, body) = harness
        .get("/_matrix/client/v3/room_keys/version/1", &alice.token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // …and the latest is the live one.
    let (status, body) = harness
        .get("/_matrix/client/v3/room_keys/version", &alice.token)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], json!("2"));
}

#[tokio::test]
async fn no_backup_at_all_is_a_404_not_an_empty_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let (status, body) = harness
        .get("/_matrix/client/v3/room_keys/version", &alice.token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], json!("M_NOT_FOUND"));
}

#[tokio::test]
async fn writes_to_a_superseded_version_are_refused_with_the_current_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.create_backup(&alice.token).await;
    harness.create_backup(&alice.token).await;

    // A client writing to version 1 missed the reset: accepting the write
    // would strand keys where no restore will look.
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/room_keys/keys?version=1",
            &alice.token,
            &json!({ "rooms": { "!r:example.org": { "sessions": {
                "s1": session(false, 0, 0, "x"),
            } } } }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], json!("M_WRONG_ROOM_KEYS_VERSION"));
    assert!(
        body["error"].as_str().unwrap().contains('2'),
        "the refusal names the current version: {body}"
    );
}

#[tokio::test]
async fn keys_round_trip_at_every_granularity() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let version = harness.create_backup(&alice.token).await;

    let (status, body) = harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/room_keys/keys?version={version}"),
            &alice.token,
            &json!({ "rooms": {
                "!a:example.org": { "sessions": {
                    "s1": session(false, 0, 0, "a1"),
                    "s2": session(false, 0, 0, "a2"),
                } },
                "!b:example.org": { "sessions": {
                    "s3": session(false, 0, 0, "b1"),
                } },
            } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], json!(3));

    let (_, all) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys?version={version}"),
            &alice.token,
        )
        .await;
    assert_eq!(
        all["rooms"]["!a:example.org"]["sessions"]["s1"]["session_data"]["ciphertext"],
        json!("a1")
    );

    let (_, room) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys/!b:example.org?version={version}"),
            &alice.token,
        )
        .await;
    assert_eq!(
        room["sessions"]["s3"]["session_data"]["ciphertext"],
        json!("b1")
    );

    let (status, one) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys/!a:example.org/s2?version={version}"),
            &alice.token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(one["session_data"]["ciphertext"], json!("a2"));

    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys/!a:example.org/nope?version={version}"),
            &alice.token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_stored_key_is_only_replaced_by_a_strictly_better_one() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let version = harness.create_backup(&alice.token).await;
    let path = format!("/_matrix/client/v3/room_keys/keys/!r:example.org/s1?version={version}");

    let (_, first) = harness_put(
        &harness,
        &path,
        &alice.token,
        session(false, 5, 2, "original"),
    )
    .await;
    let etag_after_first = first["etag"].clone();

    // Worse on every axis: dropped, and the etag says nothing happened —
    // clients poll the etag to know whether to re-fetch, and an etag that
    // moves on a refused write cries wolf.
    let (_, second) =
        harness_put(&harness, &path, &alice.token, session(false, 9, 4, "worse")).await;
    assert_eq!(second["etag"], etag_after_first);
    let current = fetch_session(&harness, &alice.token, &version).await;
    assert_eq!(current["session_data"]["ciphertext"], json!("original"));

    // Verified beats unverified even with a worse index.
    let (_, third) = harness_put(
        &harness,
        &path,
        &alice.token,
        session(true, 9, 4, "verified"),
    )
    .await;
    assert_ne!(third["etag"], etag_after_first);
    let current = fetch_session(&harness, &alice.token, &version).await;
    assert_eq!(current["session_data"]["ciphertext"], json!("verified"));

    // And an unverified key can no longer displace it, whatever its index.
    harness_put(
        &harness,
        &path,
        &alice.token,
        session(false, 0, 0, "downgrade"),
    )
    .await;
    let current = fetch_session(&harness, &alice.token, &version).await;
    assert_eq!(current["session_data"]["ciphertext"], json!("verified"));
}

async fn harness_put(
    harness: &Harness,
    path: &str,
    token: &str,
    data: Value,
) -> (StatusCode, Value) {
    let (status, body) = harness.send("PUT", path, token, &data).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (status, body)
}

async fn fetch_session(harness: &Harness, token: &str, version: &str) -> Value {
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys/!r:example.org/s1?version={version}"),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn changing_a_versions_algorithm_is_refused() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    harness.create_backup(&alice.token).await;

    // New auth_data under the same algorithm is fine (rotated recovery key).
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/room_keys/version/1",
            &alice.token,
            &json!({
                "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                "auth_data": { "public_key": "rotated" },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, info) = harness
        .get("/_matrix/client/v3/room_keys/version/1", &alice.token)
        .await;
    assert_eq!(info["auth_data"]["public_key"], json!("rotated"));

    // A different algorithm would leave entries no one recipe decrypts.
    let (status, body) = harness
        .send(
            "PUT",
            "/_matrix/client/v3/room_keys/version/1",
            &alice.token,
            &json!({ "algorithm": "m.something.else", "auth_data": {} }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn deleting_a_version_deletes_its_keys_not_just_its_listing() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let version = harness.create_backup(&alice.token).await;
    harness
        .send(
            "PUT",
            &format!("/_matrix/client/v3/room_keys/keys?version={version}"),
            &alice.token,
            &json!({ "rooms": { "!r:example.org": { "sessions": {
                "s1": session(false, 0, 0, "secret"),
            } } } }),
        )
        .await;
    harness
        .send(
            "DELETE",
            &format!("/_matrix/client/v3/room_keys/version/{version}"),
            &alice.token,
            &json!({}),
        )
        .await;

    // "Deleted" must not mean "still readable with the right request".
    let (status, body) = harness
        .get(
            &format!("/_matrix/client/v3/room_keys/keys?version={version}"),
            &alice.token,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn cross_signing_uploads_publish_and_hide_the_right_keys() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;
    let bob = harness.register("bob").await;

    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            &alice.token,
            &json!({
                "master_key": {
                    "user_id": "@alice:example.org",
                    "usage": ["master"],
                    "keys": { "ed25519:masterkey": "mk" },
                },
                "self_signing_key": {
                    "user_id": "@alice:example.org",
                    "usage": ["self_signing"],
                    "keys": { "ed25519:selfkey": "sk" },
                },
                "user_signing_key": {
                    "user_id": "@alice:example.org",
                    "usage": ["user_signing"],
                    "keys": { "ed25519:userkey": "uk" },
                },
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Bob sees the master and self-signing keys — they are how he verifies
    // alice. The user-signing key exists to sign *other people*, which is
    // nobody's business but alice's: absent from bob's view.
    let (_, seen_by_bob) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &bob.token,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    assert_eq!(
        seen_by_bob["master_keys"]["@alice:example.org"]["keys"]["ed25519:masterkey"],
        json!("mk")
    );
    assert_eq!(
        seen_by_bob["self_signing_keys"]["@alice:example.org"]["keys"]["ed25519:selfkey"],
        json!("sk")
    );
    assert!(
        seen_by_bob["user_signing_keys"]
            .as_object()
            .unwrap()
            .is_empty(),
        "{seen_by_bob}"
    );

    // Alice sees all three of her own.
    let (_, seen_by_alice) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &alice.token,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    assert_eq!(
        seen_by_alice["user_signing_keys"]["@alice:example.org"]["keys"]["ed25519:userkey"],
        json!("uk")
    );

    // And planting a key on someone else's identity is refused.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            &bob.token,
            &json!({ "master_key": {
                "user_id": "@alice:example.org",
                "usage": ["master"],
                "keys": { "ed25519:evil": "e" },
            } }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let _ = bob.device_id;
}

#[tokio::test]
async fn signature_uploads_merge_and_cannot_alter_the_signed_key() {
    let harness = Harness::new();
    let alice = harness.register("alice").await;

    harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/upload",
            &alice.token,
            &json!({ "device_keys": {
                "user_id": "@alice:example.org",
                "device_id": alice.device_id,
                "keys": { format!("curve25519:{}", alice.device_id): "devkey" },
            } }),
        )
        .await;

    // A signature over the device, as the self-signing key would produce —
    // note the body also tries to smuggle a different device key.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/signatures/upload",
            &alice.token,
            &json!({ "@alice:example.org": { alice.device_id.clone(): {
                "keys": { format!("curve25519:{}", alice.device_id): "TAMPERED" },
                "signatures": { "@alice:example.org": { "ed25519:selfkey": "sig1" } },
            } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["failures"].as_object().unwrap().is_empty(), "{body}");

    let (_, queried) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/query",
            &alice.token,
            &json!({ "device_keys": { "@alice:example.org": [] } }),
        )
        .await;
    let device = &queried["device_keys"]["@alice:example.org"][&alice.device_id];
    // The signature merged…
    assert_eq!(
        device["signatures"]["@alice:example.org"]["ed25519:selfkey"],
        json!("sig1")
    );
    // …and the signed key material did not move: a signature upload that
    // could alter the key would let anyone "sign" a key into a different key.
    assert_eq!(
        device["keys"][&format!("curve25519:{}", alice.device_id)],
        json!("devkey")
    );

    // A target that names nothing lands in failures, not in an error.
    let (status, body) = harness
        .send(
            "POST",
            "/_matrix/client/v3/keys/signatures/upload",
            &alice.token,
            &json!({ "@alice:example.org": { "NOSUCHTARGET": {
                "signatures": { "@alice:example.org": { "ed25519:selfkey": "sig2" } },
            } } }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["failures"]["@alice:example.org"]["NOSUCHTARGET"]["errcode"],
        json!("M_NOT_FOUND")
    );
}
