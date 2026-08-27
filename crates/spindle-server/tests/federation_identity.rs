//! X-Matrix request authentication, against a real signing peer.
//!
//! The "peer" is an in-process HTTP server with its own ed25519 key,
//! serving a self-signed `/key/v2/server` and signing requests exactly as
//! a homeserver would (via ruma's own signer — the same implementation
//! the reference servers use, per ADR 0002's judge-don't-build rule).
//! What this suite must establish is that the trust chain fails closed at
//! every link: no header, tampered signature, wrong destination, forged
//! key document — all 401, all indistinguishable to the caller.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A federating peer: a name, a key, and a key server that counts fetches.
struct Peer {
    name: String,
    pair: Ed25519KeyPair,
    fetches: Arc<AtomicUsize>,
}

#[derive(Default)]
struct PeerOptions {
    /// Sign the key document with a key it does not list.
    forge_document_signature: bool,
    /// The `server_name` the document claims, when not the peer's own.
    claim_name: Option<&'static str>,
    /// A `valid_until_ts` already in the past.
    expired: bool,
}

impl Peer {
    async fn start(options: PeerOptions) -> Peer {
        let forge_document_signature = options.forge_document_signature;
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let fetches = Arc::new(AtomicUsize::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        // The served key document: self-signed, unless this peer is the
        // dishonest one whose document is signed by a key it does not list.
        let signing_pair = if forge_document_signature {
            let other = Ed25519KeyPair::generate();
            Ed25519KeyPair::from_der(&other, "0".to_owned()).unwrap()
        } else {
            Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap()
        };
        let mut key_document = json!({
            "server_name": options.claim_name.map_or_else(|| name.clone(), str::to_owned),
            "valid_until_ts": if options.expired {
                now_millis() - 60_000
            } else {
                now_millis() + 60_000
            },
            "verify_keys": {
                "ed25519:0": { "key": unpadded(&pair.public_key()) }
            },
        });
        sign_value(&name, &signing_pair, &mut key_document);

        let fetches_in_route = Arc::clone(&fetches);
        let router = axum::Router::new().route(
            "/_matrix/key/v2/server",
            axum::routing::get(move || {
                let fetches = Arc::clone(&fetches_in_route);
                let body = key_document.clone();
                async move {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    axum::Json(body)
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer {
            name,
            pair,
            fetches,
        }
    }

    /// Sign a request the way the spec says a homeserver must.
    fn authorization(&self, method: &str, uri: &str, destination: &str) -> String {
        let mut object = json!({
            "method": method,
            "uri": uri,
            "origin": self.name,
            "destination": destination,
        });
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap()
            .to_owned();
        format!(
            "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"ed25519:0\",sig=\"{signature}\"",
            self.name
        )
    }
}

fn sign_value(entity: &str, pair: &Ed25519KeyPair, value: &mut Value) {
    let ruma::CanonicalJsonValue::Object(mut object) =
        ruma::CanonicalJsonValue::try_from(value.clone()).unwrap()
    else {
        unreachable!()
    };
    ruma::signatures::sign_json(entity, pair, &mut object).unwrap();
    *value = serde_json::to_value(&object).unwrap();
}

fn unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte = |index: usize| -> u32 { chunk.get(index).copied().unwrap_or(0).into() };
        let triple = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for position in 0..=chunk.len() {
            out.push(ALPHABET[((triple >> (18 - 6 * position)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap()
}

struct Harness {
    _dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
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

    /// Register alice and point an alias at a fresh room.
    async fn alias_target(&self) -> String {
        let (_, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "alice",
                            "password": "hunter2",
                            "auth": { "type": "m.login.dummy", "session": "register" },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        let token = body["access_token"].as_str().unwrap().to_owned();
        let (_, body) = self
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/_matrix/client/v3/createRoom")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        let room_id = body["room_id"].as_str().unwrap().to_owned();
        let (status, body) = self
            .call(
                Request::builder()
                    .method("PUT")
                    .uri("/_matrix/client/v3/directory/room/%23here%3Aexample.org")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "room_id": room_id }).to_string()))
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        room_id
    }

    async fn query_directory(&self, authorization: Option<&str>) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("GET")
            .uri("/_matrix/federation/v1/query/directory?room_alias=%23here%3Aexample.org");
        if let Some(header) = authorization {
            request = request.header("authorization", header);
        }
        self.call(request.body(Body::empty()).unwrap()).await
    }
}

const QUERY_URI: &str = "/_matrix/federation/v1/query/directory?room_alias=%23here%3Aexample.org";

#[tokio::test]
async fn version_is_public_and_names_the_software() {
    let harness = Harness::new();
    let (status, body) = harness
        .call(
            Request::builder()
                .uri("/_matrix/federation/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["server"]["name"], json!("spindle"));
}

#[tokio::test]
async fn a_properly_signed_query_resolves_and_the_key_is_cached() {
    let peer = Peer::start(PeerOptions::default()).await;
    let harness = Harness::new();
    let room_id = harness.alias_target().await;

    let header = peer.authorization("GET", QUERY_URI, "example.org");
    let (status, body) = harness.query_directory(Some(&header)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], json!(room_id));
    assert_eq!(body["servers"], json!(["example.org"]));

    // A second signed request rides the cached key document: the peer's
    // key server is not consulted per request.
    let (status, _) = harness.query_directory(Some(&header)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        peer.fetches.load(Ordering::SeqCst),
        1,
        "one fetch, then cache"
    );
}

#[tokio::test]
async fn every_broken_credential_gets_the_same_401() {
    let peer = Peer::start(PeerOptions::default()).await;
    let harness = Harness::new();
    harness.alias_target().await;

    // No header at all.
    let (status, body) = harness.query_directory(None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], json!("M_UNAUTHORIZED"));

    // A tampered signature.
    let good = peer.authorization("GET", QUERY_URI, "example.org");
    let tampered = good.replace("sig=\"", "sig=\"AAAA");
    let (status, body) = harness.query_directory(Some(&tampered)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["errcode"], json!("M_UNAUTHORIZED"));

    // Signed for somebody else: a replay of a request meant for another
    // server, header and signature both naming the wrong destination.
    let elsewhere = peer.authorization("GET", QUERY_URI, "elsewhere.org");
    let (status, body) = harness.query_directory(Some(&elsewhere)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Signed for the right URI but a different method's object.
    let wrong_method = peer.authorization("PUT", QUERY_URI, "example.org");
    let (status, _) = harness.query_directory(Some(&wrong_method)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_forged_key_document_authenticates_nothing() {
    // This peer's key document is signed by a key it does not list — what
    // an on-path attacker would serve. The fetch must refuse it, and with
    // it every request the "peer" signs.
    let peer = Peer::start(PeerOptions {
        forge_document_signature: true,
        ..PeerOptions::default()
    })
    .await;
    let harness = Harness::new();
    harness.alias_target().await;

    let header = peer.authorization("GET", QUERY_URI, "example.org");
    let (status, body) = harness.query_directory(Some(&header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn an_unknown_alias_is_a_404_only_after_authentication() {
    let peer = Peer::start(PeerOptions::default()).await;
    let harness = Harness::new();
    // No alias registered at all.
    let header = peer.authorization("GET", QUERY_URI, "example.org");
    let (status, body) = harness.query_directory(Some(&header)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["errcode"], json!("M_NOT_FOUND"));
}

#[tokio::test]
async fn a_key_document_for_another_server_authenticates_nothing() {
    // Self-signed correctly, but claiming to describe a different server —
    // a stolen document re-served from a new address. The name inside must
    // match the server it was fetched from.
    let peer = Peer::start(PeerOptions {
        claim_name: Some("evil.example"),
        ..PeerOptions::default()
    })
    .await;
    let harness = Harness::new();
    harness.alias_target().await;
    let header = peer.authorization("GET", QUERY_URI, "example.org");
    let (status, body) = harness.query_directory(Some(&header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn an_expired_key_document_is_refetched_not_reused() {
    // valid_until_ts already in the past: each request must consult the
    // peer's key server again. A cache honouring expired documents would
    // keep trusting a key its owner has disowned; a cap that stretches
    // peer-chosen validity would do the same for seven days.
    let peer = Peer::start(PeerOptions {
        expired: true,
        ..PeerOptions::default()
    })
    .await;
    let harness = Harness::new();
    harness.alias_target().await;
    let header = peer.authorization("GET", QUERY_URI, "example.org");
    for _ in 0..2 {
        let (status, body) = harness.query_directory(Some(&header)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(
        peer.fetches.load(Ordering::SeqCst),
        2,
        "an expired document does not serve from cache"
    );
}

#[tokio::test]
async fn the_signed_object_binds_the_real_method() {
    // Exercised at the library level because the router exposes only GET
    // federation endpoints so far: a signature over PUT must verify for a
    // PUT and only a PUT — a verifier that hardcodes the method breaks
    // exactly when the first PUT endpoint (/send) arrives.
    let peer = Peer::start(PeerOptions::default()).await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    let federation =
        spindle_server::federation::Federation::new(Arc::clone(&store), "example.org", key, true);

    let header = peer.authorization("PUT", "/_matrix/federation/v1/send/txn1", "example.org");
    federation
        .verify_request(
            Some(&header),
            "PUT",
            "/_matrix/federation/v1/send/txn1",
            None,
        )
        .await
        .expect("a PUT signature verifies for a PUT");
    let refused = federation
        .verify_request(
            Some(&header),
            "GET",
            "/_matrix/federation/v1/send/txn1",
            None,
        )
        .await;
    assert!(refused.is_err(), "the same signature must not cover a GET");
}
