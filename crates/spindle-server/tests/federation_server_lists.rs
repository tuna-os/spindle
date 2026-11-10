//! `[federation] allow` and `deny`: the server-wide lists.
//!
//! A server the lists refuse is turned away after its signature verifies,
//! with `403 M_FORBIDDEN`, and nothing it sent is stored. Outbound, a
//! refused destination is never addressed, so no socket opens.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_server::metrics::{ListedDirection, Metrics};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

struct Peer {
    name: String,
    pair: Ed25519KeyPair,
}

impl Peer {
    async fn start() -> Peer {
        let document = Ed25519KeyPair::generate();
        let pair = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let name = format!("127.0.0.1:{}", address.port());

        let signing = Ed25519KeyPair::from_der(&document, "0".to_owned()).unwrap();
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 60_000,
            "verify_keys": { "ed25519:0": { "key": unpadded(&public_key(&pair)) } },
        });
        sign_value(&name, &signing, &mut key_document);
        let router = axum::Router::new()
            .route(
                "/_matrix/key/v2/server",
                axum::routing::get(move || {
                    let body = key_document.clone();
                    async move { axum::Json(body) }
                }),
            )
            // The invite handshake's other half: the harness invites this
            // peer's user, and the inviting server will not append the
            // invite until the peer answers. Echoing the event back is a
            // valid answer — the reference hash is what the inviter
            // checks, and signatures sit outside it.
            .route(
                "/_matrix/federation/v2/invite/{_room_id}/{_event_id}",
                axum::routing::put(
                    |axum::extract::Json(body): axum::extract::Json<Value>| async move {
                        axum::Json(json!({ "event": body["event"] }))
                    },
                ),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer { name, pair }
    }

    fn transaction_header(&self, txn_id: &str, body: &Value) -> String {
        let mut object = json!({
            "method": "PUT",
            "uri": format!("/_matrix/federation/v1/send/{txn_id}"),
            "origin": self.name,
            "destination": "example.org",
            "content": body,
        });
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{signature}\"",
            self.name
        )
    }
}

fn public_key(pair: &Ed25519KeyPair) -> Vec<u8> {
    pair.public_key().to_vec()
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
    metrics: Arc<Metrics>,
}

impl Harness {
    fn new(lists: &str) -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(&format!(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n{lists}"
        ))
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let (app, _) = spindle_server::app_with_state(config, store, Arc::clone(&metrics))
            .expect("the app builds");
        Self {
            _dir: dir,
            app,
            metrics,
        }
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

    /// A signed, empty transaction from `peer`.
    async fn deliver(&self, peer: &Peer, txn_id: &str) -> (StatusCode, Value) {
        let body = json!({ "origin": peer.name, "origin_server_ts": now_millis(), "pdus": [] });
        let header = peer.transaction_header(txn_id, &body);
        self.call(
            Request::builder()
                .method("PUT")
                .uri(format!("/_matrix/federation/v1/send/{txn_id}"))
                .header("authorization", header)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn a_denied_server_is_forbidden_and_a_listed_in_server_is_not() {
    let peer = Peer::start().await;

    let open = Harness::new("");
    let (status, body) = open.deliver(&peer, "t1").await;
    assert_eq!(status, StatusCode::OK, "control, no lists: {body}");

    let denied = Harness::new("deny = [\"127.0.0.*\"]\n");
    let (status, body) = denied.deliver(&peer, "t1").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_FORBIDDEN");
    assert_eq!(
        denied
            .metrics
            .federation_listed_count(ListedDirection::Inbound),
        1
    );
}

#[tokio::test]
async fn an_allow_list_refuses_every_other_server() {
    let peer = Peer::start().await;

    let closed = Harness::new("allow = [\"friend.example\"]\n");
    let (status, body) = closed.deliver(&peer, "t1").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let listed = Harness::new("allow = [\"127.0.0.1\"]\n");
    let (status, body) = listed.deliver(&peer, "t1").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The deny list wins over the allow list.
    let both = Harness::new("allow = [\"127.0.0.1\"]\ndeny = [\"127.*\"]\n");
    let (status, _) = both.deliver(&peer, "t1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A peer that counts every request it is sent.
async fn counting_peer() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().fallback(axum::routing::get(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async { "{}" }
    }));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, hits)
}

#[tokio::test]
async fn outbound_requests_to_a_denied_destination_open_no_socket() {
    let (url, hits) = counting_peer().await;
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    let peers = std::collections::BTreeMap::from([(
        "peer.example".to_owned(),
        spindle_server::config::PeerConfig {
            url,
            max_backoff_ms: None,
        },
    )]);
    let federation = |deny: &[String]| {
        spindle_server::federation::Federation::new(
            Arc::clone(&store),
            "example.org",
            Arc::clone(&key),
            false,
            &["127.0.0.0/8".to_owned()],
        )
        .unwrap()
        .with_peers(&peers)
        .with_server_lists(&[], deny)
    };

    let _ = federation(&[]).peer_keys("peer.example").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the control reached the peer"
    );

    let denied = federation(&["*.example".to_owned()]);
    assert!(denied.peer_keys("peer.example").await.is_err());
    assert!(
        denied
            .remote_media_download("peer.example", "abc")
            .await
            .is_err()
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a denied destination is not contacted"
    );
    assert!(
        denied
            .metrics()
            .federation_listed_count(ListedDirection::Outbound)
            >= 2
    );
}
