//! The server's signing key.
//!
//! Two properties, both of which fail silently if they break: a key that is
//! quietly regenerated invalidates history, and a private key that reaches a
//! response is a total compromise that still returns 200.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use spindle_server::signing::ServerKey;
use spindle_store::{FjallStore, ReadView};
use tempfile::TempDir;
use tower::ServiceExt;

fn config() -> spindle_server::Config {
    spindle_server::Config::parse("[server]\nname = \"example.org\"\n").unwrap()
}

async fn get(store: &Arc<FjallStore>, path: &str) -> (StatusCode, Value) {
    let app = spindle_server::app(config(), Arc::clone(store)).expect("a key is established");
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The key is published, peers cache it, and every event ever signed refers to
/// it by ID. Regenerating under the same ID invalidates history; regenerating
/// under a new one orphans every signature made with the old.
#[test]
fn the_key_is_generated_once_and_then_loaded_forever() {
    let dir = TempDir::new().unwrap();

    let (first_id, first_public) = {
        let store = FjallStore::open(dir.path()).unwrap();
        let key = ServerKey::load_or_create(&store).unwrap();
        (key.key_id(), key.public_key_base64())
    };

    // Reopened, as a restart would.
    let store = FjallStore::open(dir.path()).unwrap();
    let key = ServerKey::load_or_create(&store).unwrap();
    assert_eq!(key.key_id(), first_id);
    assert_eq!(
        key.public_key_base64(),
        first_public,
        "the key changed across a restart; every signature made before it is now unverifiable"
    );

    // And loading repeatedly within one process is stable too.
    let again = ServerKey::load_or_create(&store).unwrap();
    assert_eq!(again.public_key_base64(), first_public);
}

/// Two servers must not share a key, or either can forge the other's events.
#[test]
fn separate_servers_get_separate_keys() {
    let first_dir = TempDir::new().unwrap();
    let second_dir = TempDir::new().unwrap();
    let first = ServerKey::load_or_create(&FjallStore::open(first_dir.path()).unwrap()).unwrap();
    let second = ServerKey::load_or_create(&FjallStore::open(second_dir.path()).unwrap()).unwrap();
    assert_ne!(first.public_key_base64(), second.public_key_base64());
}

/// The load-bearing one. A private key in a published response is a total
/// compromise that still returns 200, so nothing about the response looks
/// wrong.
#[tokio::test]
async fn the_published_keys_contain_no_private_material() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (status, body) = get(&store, "/_matrix/key/v2/server").await;
    assert_eq!(status, StatusCode::OK);

    let key = ServerKey::load_or_create(store.as_ref()).unwrap();
    let published = serde_json::to_string(&body).unwrap();

    // The public half is there, which is the point of the endpoint.
    assert!(
        published.contains(&key.public_key_base64()),
        "the public key is not published: {published}"
    );

    // The stored DER document contains the private half. None of it may appear
    // in the response, in any encoding a JSON body could carry it in.
    //
    // The encodings matter more than they look. An earlier version of this test
    // compared raw bytes only — which a JSON response cannot contain anyway, so
    // it was checking for the one form a leak could never take. Injecting a
    // hex dump of the key document passed it. A real leak arrives encoded.
    let stored = store
        .scan_prefix(&[spindle_core::keys::KEY_SCHEMA_VERSION, 0x0a])
        .unwrap();
    let document = &stored.first().expect("the key is stored").1;
    assert!(document.len() > 32, "a PKCS#8 document is not this short");

    // Only the *private* part is secret. A PKCS#8 v2 document embeds the public
    // key too, and this one places it at an offset divisible by three — so
    // base64 of the whole document contains base64 of the public key exactly
    // aligned. Checking the whole document therefore flags the public key we
    // are deliberately publishing. Everything before it is what must not appear.
    let public = key.pair().public_key();
    let split = document
        .windows(public.len())
        .position(|window| window == public)
        .expect("a PKCS#8 v2 document embeds its public key");
    let private = &document[..split];
    assert!(
        private.len() >= 32,
        "the private region is too short to hold the seed: {} bytes",
        private.len()
    );

    for (label, encoded) in [
        ("raw", private.to_vec()),
        ("hex", hex(private).into_bytes()),
        ("HEX", hex(private).to_uppercase().into_bytes()),
        ("base64", base64_padded(private).into_bytes()),
        (
            "base64-unpadded",
            base64_padded(private)
                .trim_end_matches('=')
                .as_bytes()
                .to_vec(),
        ),
    ] {
        // A 16-byte run is long enough that a coincidental match is not a
        // thing, and short enough that a partial leak is still caught.
        let window = 16.min(encoded.len());
        assert!(
            !encoded
                .windows(window)
                .any(|needle| published.as_bytes().windows(window).any(|w| w == needle)),
            "the private key material appears in the published response, {label}-encoded"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn base64_padded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (b(0) << 16) | (b(1) << 8) | b(2);
        for slot in 0..4 {
            if slot <= chunk.len() {
                let index = (triple >> (18 - 6 * slot)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test]
async fn the_published_keys_have_the_shape_a_peer_reads() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let (_, body) = get(&store, "/_matrix/key/v2/server").await;

    assert_eq!(body["server_name"], "example.org");
    assert!(
        body["valid_until_ts"].as_u64().is_some_and(|ts| ts > 0),
        "a peer uses this to decide when to re-fetch: {body}"
    );

    let key = ServerKey::load_or_create(store.as_ref()).unwrap();
    let verify = &body["verify_keys"][key.key_id()]["key"];
    assert_eq!(verify, &Value::String(key.public_key_base64()));
    assert!(key.key_id().starts_with("ed25519:"), "{}", key.key_id());

    // Present and empty, not absent: a peer reads this to decide whether a
    // signature made with a retired key should still be honoured.
    assert!(body["old_verify_keys"].is_object());
}

/// Matrix uses unpadded base64 throughout. A padded value is a different
/// string, so a peer comparing it to a cached copy sees a mismatch.
#[test]
fn the_published_key_is_unpadded_base64() {
    let dir = TempDir::new().unwrap();
    let store = FjallStore::open(dir.path()).unwrap();
    let key = ServerKey::load_or_create(&store).unwrap();
    let published = key.public_key_base64();

    assert!(!published.contains('='), "padded: {published}");
    // An Ed25519 public key is 32 bytes, which is 43 unpadded base64 chars.
    assert_eq!(published.len(), 43, "{published}");
}
