//! The second wave of endpoints filled in from `docs/spec-gaps.md`:
//! media minted ahead of its bytes (MSC2246, spec v1.7), login tokens
//! (MSC3882, spec v1.7), mutual rooms (MSC2666), and the read-side
//! federation surface: event auth, the public directory, the space
//! hierarchy, timestamp lookups, authenticated thumbnails (MSC3916), and
//! the key notary.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ruma::signatures::Ed25519KeyPair;
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tempfile::TempDir;
use tower::ServiceExt;

/// A federating peer with its own key and a key server this server can
/// fetch, so its signed requests authenticate.
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
        let mut key_document = json!({
            "server_name": name,
            "valid_until_ts": now_millis() + 60_000,
            "verify_keys": { "ed25519:0": { "key": unpadded(&pair.public_key()) } },
        });
        sign_value(&name, &pair, &mut key_document);
        let router = axum::Router::new().route(
            "/_matrix/key/v2/server",
            axum::routing::get(move || {
                let body = key_document.clone();
                async move { axum::Json(body) }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Peer { name, pair }
    }

    fn authorization(&self, method: &str, uri: &str, content: Option<&Value>) -> String {
        let mut object = json!({
            "method": method,
            "uri": uri,
            "origin": self.name,
            "destination": "example.org",
        });
        if let Some(content) = content {
            object["content"] = content.clone();
        }
        sign_value(&self.name, &self.pair, &mut object);
        let signature = object["signatures"][&self.name]["ed25519:0"]
            .as_str()
            .unwrap()
            .to_owned();
        format!(
            "X-Matrix origin=\"{}\",destination=\"example.org\",key=\"ed25519:0\",sig=\"{signature}\"",
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

fn small_png() -> Vec<u8> {
    let mut bytes = Vec::new();
    let image = image::RgbImage::from_pixel(8, 8, image::Rgb([0, 128, 255]));
    image::DynamicImage::ImageRgb8(image)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
    bytes
}

struct Harness {
    #[allow(dead_code, reason = "keeps the data directory alive for the store")]
    dir: TempDir,
    app: axum::Router,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(FjallStore::open(dir.path()).unwrap());
        let config = spindle_server::Config::parse(
            "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
             [federation]\ninsecure_http = true\nallow_internal = [\"127.0.0.0/8\"]\n",
        )
        .unwrap();
        let app = spindle_server::app(config, store).expect("the app builds");
        Self { dir, app }
    }

    async fn raw(&self, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let (status, _, bytes) = self.raw(request).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
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
        self.call(builder.body(body).unwrap()).await
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

    async fn create_room(&self, token: &str, payload: &Value) -> String {
        let (status, body) = self
            .send(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(token),
                Some(payload),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["room_id"].as_str().unwrap().to_owned()
    }

    /// A peer's signed GET, as a homeserver would send it.
    async fn peer_get(
        &self,
        peer: &Peer,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        self.raw(
            Request::builder()
                .uri(uri)
                .header("authorization", peer.authorization("GET", uri, None))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn peer_json(&self, peer: &Peer, uri: &str) -> (StatusCode, Value) {
        let (status, _, bytes) = self.peer_get(peer, uri).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn put_bytes(
        &self,
        path: &str,
        token: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> (StatusCode, Value) {
        self.call(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(bytes.to_vec()))
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn a_media_id_is_minted_first_and_filled_later() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;

    let (status, body) = server
        .send("POST", "/_matrix/media/v1/create", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let uri = body["content_uri"].as_str().unwrap().to_owned();
    assert!(uri.starts_with("mxc://example.org/"), "{uri}");
    assert!(body["unused_expires_at"].as_u64().unwrap() > now_millis());
    let media_id = uri.rsplit('/').next().unwrap().to_owned();
    let download = format!("/_matrix/client/v1/media/download/example.org/{media_id}");
    let upload = format!("/_matrix/media/v3/upload/example.org/{media_id}");

    // Minted, not filled: a reader is told to come back, not that it is gone.
    let (status, body) = server.send("GET", &download, Some(&bob), None).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["errcode"], "M_NOT_YET_UPLOADED");

    // Only the minter fills it.
    let (status, body) = server.put_bytes(&upload, &bob, "text/plain", b"mine").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = server
        .put_bytes(&upload, &alice, "text/plain", b"hello from later")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, bytes) = server
        .raw(
            Request::builder()
                .uri(&download)
                .header("authorization", format!("Bearer {bob}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, b"hello from later");

    // Filled once.
    let (status, body) = server
        .put_bytes(&upload, &alice, "text/plain", b"again")
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["errcode"], "M_CANNOT_OVERWRITE_MEDIA");

    // Never minted.
    let (status, body) = server
        .put_bytes(
            "/_matrix/media/v3/upload/example.org/neverminted",
            &alice,
            "text/plain",
            b"x",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_login_token_logs_a_second_client_in_once() {
    let server = Harness::new();
    let alice = server.register("alice").await;

    let (status, body) = server
        .send("GET", "/_matrix/client/v3/capabilities", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["capabilities"]["m.get_login_token"]["enabled"], true);

    let (status, body) = server
        .send("GET", "/_matrix/client/v3/login", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token_flow = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|flow| flow["type"] == "m.login.token")
        .expect("the token flow is advertised");
    assert_eq!(token_flow["get_login_token"], true);

    // UIA first: the token is as good as a password.
    let (status, body) = server
        .send(
            "POST",
            "/_matrix/client/v1/login/get_token",
            Some(&alice),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let session = body["session"].as_str().unwrap().to_owned();

    let (status, body) = server
        .send(
            "POST",
            "/_matrix/client/v1/login/get_token",
            Some(&alice),
            Some(&json!({ "auth": {
                "type": "m.login.password",
                "session": session,
                "password": "hunter2",
            } })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let login_token = body["login_token"].as_str().unwrap().to_owned();
    assert!(body["expires_in_ms"].as_u64().unwrap() > 0);

    let login = json!({ "type": "m.login.token", "token": login_token });
    let (status, body) = server
        .send("POST", "/_matrix/client/v3/login", None, Some(&login))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], "@alice:example.org");
    let second = body["access_token"].as_str().unwrap().to_owned();
    let (status, body) = server
        .send(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&second),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Single use.
    let (status, body) = server
        .send("POST", "/_matrix/client/v3/login", None, Some(&login))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn mutual_rooms_are_the_rooms_both_are_joined_to() {
    let server = Harness::new();
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let shared = server
        .create_room(&alice, &json!({ "invite": ["@bob:example.org"] }))
        .await;
    let (status, body) = server
        .send(
            "POST",
            &format!("/_matrix/client/v3/rooms/{shared}/join"),
            Some(&bob),
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let _alone = server.create_room(&alice, &json!({})).await;

    let (status, body) = server
        .send(
            "GET",
            "/_matrix/client/v1/mutual_rooms?user_id=%40bob%3Aexample.org",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["joined"], json!([shared]));
    assert_eq!(body["count"], 1);

    let (status, body) = server
        .send(
            "GET",
            "/_matrix/client/v1/mutual_rooms?user_id=%40alice%3Aexample.org",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn the_notary_hands_on_its_own_document_signed() {
    let server = Harness::new();
    let (status, body) = server
        .send("GET", "/_matrix/key/v2/query/example.org", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let document = &body["server_keys"][0];
    assert_eq!(document["server_name"], "example.org");
    assert!(document["signatures"]["example.org"].is_object(), "{body}");
    assert!(document["verify_keys"].is_object());

    let (status, batch) = server
        .send(
            "POST",
            "/_matrix/key/v2/query",
            None,
            Some(&json!({ "server_keys": { "example.org": {} } })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{batch}");
    assert_eq!(batch["server_keys"][0]["server_name"], "example.org");
}

#[tokio::test]
async fn a_peer_reads_the_directory_the_hierarchy_and_a_thumbnail() {
    let server = Harness::new();
    let peer = Peer::start().await;
    let alice = server.register("alice").await;

    // A published space with one public child and one private one.
    let space = server
        .create_room(
            &alice,
            &json!({
                "creation_content": { "type": "m.space" },
                "preset": "public_chat",
                "visibility": "public",
                "name": "the commons",
            }),
        )
        .await;
    let open = server
        .create_room(&alice, &json!({ "preset": "public_chat", "name": "open" }))
        .await;
    let closed = server
        .create_room(
            &alice,
            &json!({ "preset": "private_chat", "name": "closed" }),
        )
        .await;
    for child in [&open, &closed] {
        let (status, body) = server
            .send(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{space}/state/m.space.child/{child}"),
                Some(&alice),
                Some(&json!({ "via": ["example.org"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let (status, body) = server
        .peer_json(&peer, "/_matrix/federation/v1/publicRooms?limit=10")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<&str> = body["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|room| room["room_id"].as_str())
        .collect();
    assert_eq!(listed, vec![space.as_str()], "{body}");

    let (status, body) = server
        .peer_json(&peer, &format!("/_matrix/federation/v1/hierarchy/{space}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room"]["room_id"], space);
    assert_eq!(body["room"]["children_state"].as_array().unwrap().len(), 2);
    assert_eq!(body["children"][0]["room_id"], open, "{body}");
    assert_eq!(body["children"].as_array().unwrap().len(), 1);
    assert_eq!(body["inaccessible_children"], json!([closed]));

    // The private room is nobody's business over federation either.
    let (status, body) = server
        .peer_json(&peer, &format!("/_matrix/federation/v1/hierarchy/{closed}"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A room the peer has no member in refuses timestamp lookups and auth
    // chains alike, the way state does.
    let ts = format!("/_matrix/federation/v1/timestamp_to_event/{open}?ts=1&dir=f");
    let (status, body) = server.peer_json(&peer, &ts).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = server
        .peer_json(
            &peer,
            &format!("/_matrix/federation/v1/event_auth/{open}/$nothing"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Unsigned, nothing at all.
    let (status, body) = server
        .send("GET", "/_matrix/federation/v1/publicRooms", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn a_peer_reads_a_thumbnail_in_the_multipart_framing() {
    // The same framing as the federation download, so a peer's one
    // multipart reader serves both.
    let server = Harness::new();
    let peer = Peer::start().await;
    let alice = server.register("alice").await;
    let (status, body) = server
        .call(
            Request::builder()
                .method("POST")
                .uri("/_matrix/media/v3/upload?filename=dot.png")
                .header("authorization", format!("Bearer {alice}"))
                .header("content-type", "image/png")
                .body(Body::from(small_png()))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let media_id = body["content_uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let (status, headers, bytes) = server
        .peer_get(
            &peer,
            &format!(
                "/_matrix/federation/v1/media/thumbnail/{media_id}?width=4&height=4&method=scale"
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let content_type = headers["content-type"].to_str().unwrap();
    assert!(
        content_type.starts_with("multipart/mixed; boundary="),
        "{content_type}"
    );
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
    assert!(has(b"content-type: application/json\r\n\r\n{}"));
    assert!(has(b"content-type: image/png\r\n\r\n\x89PNG"));
}

#[test]
fn an_events_auth_chain_reaches_the_create_event() {
    // At the room layer, where membership is not in the way: the chain
    // behind a member event cites the create, the power levels and the
    // join rules, each once.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap();
    let rooms = spindle_server::rooms::Rooms::new(Arc::clone(&store), "example.org");
    let room = rooms
        .create(
            "@alice:example.org",
            key.pair(),
            None,
            None,
            Some("public_chat"),
            &[],
            &[],
            None,
            None,
            None,
            &serde_json::Map::new(),
        )
        .unwrap();
    let state = rooms.state(&room).unwrap();
    let member = state
        .iter()
        .find(|event| event["type"] == "m.room.member")
        .unwrap();
    let chain = rooms
        .auth_chain(&room, member["event_id"].as_str().unwrap())
        .unwrap();
    let mut kinds: Vec<&str> = chain
        .iter()
        .filter_map(|event| event["type"].as_str())
        .collect();
    kinds.sort_unstable();
    assert!(kinds.contains(&"m.room.create"), "{kinds:?}");
    let ids: std::collections::BTreeSet<&str> = chain
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect();
    assert_eq!(ids.len(), chain.len(), "each event once");
}
