//! A stand-in for a `LiveKit` SFU's room API, for the minter tests.
//!
//! The built-in minter creates a call's room through the SFU's API
//! (`CreateRoom`, over Twirp) before it hands a full-access user their
//! token, as `lk-jwt-service` does, so every test that mints for a local
//! user needs something answering there. This answers `CreateRoom` and
//! keeps what it was asked -- the room name and the bearer token -- so a
//! test can check both; it does not judge the token itself, because the
//! tests that care decode it with the secret they configured.

#![allow(dead_code, reason = "shared by test binaries that each use a part")]

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};

/// One `CreateRoom` the SFU was asked for.
#[derive(Clone, Debug)]
pub struct Created {
    pub name: String,
    pub bearer: String,
    pub body: Value,
}

pub struct MockSfu {
    /// The SFU's websocket address, as `[rtc.livekit] url` names it.
    pub url: String,
    created: Arc<Mutex<Vec<Created>>>,
}

impl MockSfu {
    /// Listen on a loopback port. Synchronous, so a test harness that is
    /// itself built synchronously inside a Tokio test can start one.
    pub fn start() -> MockSfu {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let created: Arc<Mutex<Vec<Created>>> = Arc::default();
        let record = Arc::clone(&created);
        let app = axum::Router::new().route(
            "/twirp/livekit.RoomService/CreateRoom",
            post(move |headers: HeaderMap, body: String| {
                let record = Arc::clone(&record);
                async move {
                    let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let bearer = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .unwrap_or_default()
                        .to_owned();
                    let name = body["name"].as_str().unwrap_or_default().to_owned();
                    record.lock().unwrap().push(Created {
                        name: name.clone(),
                        bearer,
                        body,
                    });
                    (
                        StatusCode::OK,
                        [("content-type", "application/json")],
                        json!({ "sid": "RM_stand_in", "name": name }).to_string(),
                    )
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockSfu {
            url: format!("ws://127.0.0.1:{port}"),
            created,
        }
    }

    /// Every `CreateRoom` so far, in order.
    pub fn created(&self) -> Vec<Created> {
        self.created.lock().unwrap().clone()
    }
}

/// `lk-jwt-service`'s hash, written out from its source (0.7,
/// `helper.rs`) rather than borrowed from the server, so a test does not
/// agree with the code by sharing its mistakes: SHA-256 over the strings'
/// JSON array, in unpadded standard base64. Its room names and Matrix 2.0
/// identities are this.
pub fn lk_hash(parts: &[&str]) -> String {
    use sha2::Digest as _;
    base64_standard(
        &sha2::Sha256::digest(serde_json::to_vec(parts).unwrap()),
        false,
    )
}

/// Standard-alphabet base64, padded or not.
pub fn base64_standard(bytes: &[u8], pad: bool) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut triple = 0_u32;
        for (index, &byte) in chunk.iter().enumerate() {
            triple |= u32::from(byte) << (16 - 8 * index);
        }
        for slot in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[((triple >> (18 - 6 * slot)) & 0x3f) as usize],
            ));
        }
        if pad {
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

/// The `Authorization` `LiveKit` sends with a webhook: an HS256 JWT under
/// the API secret, issued by the API key, carrying the body's SHA-256 in
/// padded standard base64 (`sha256`) -- built here from `LiveKit`'s
/// documented format, not from the server's verifier.
pub fn webhook_authorization(key: &str, secret: &str, body: &str) -> String {
    let base64url = |bytes: &[u8]| {
        base64_standard(bytes, false)
            .replace('+', "-")
            .replace('/', "_")
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": key,
        "nbf": now,
        "exp": now + 300,
        "sha256": base64_standard(&<sha2::Sha256 as sha2::Digest>::digest(body.as_bytes()), true),
    });
    let signing_input = format!(
        "{}.{}",
        base64url(
            json!({ "alg": "HS256", "typ": "JWT" })
                .to_string()
                .as_bytes()
        ),
        base64url(claims.to_string().as_bytes())
    );
    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
    hmac::Mac::update(&mut mac, signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        base64url(&hmac::Mac::finalize(mac).into_bytes())
    )
}
