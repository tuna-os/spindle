//! Signed outbound dependency retrieval. These responses remain untrusted;
//! this suite checks transport, budgets and shapes, not event acceptance.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use serde_json::{Value, json};
use spindle_server::federation::Federation;
use spindle_store::FjallStore;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct Received {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

async fn peer(response: Value, status: StatusCode) -> (String, Arc<Mutex<Vec<Received>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = listener.local_addr().unwrap().to_string();
    let received = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::clone(&received);
    let app = axum::Router::new().fallback(
        move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
            requests.lock().unwrap().push(Received {
                method,
                uri,
                headers,
                body,
            });
            let response = response.clone();
            async move { (status, axum::Json(response)) }
        },
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (name, received)
}

fn federation(dir: &TempDir) -> Federation {
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    Federation::new(store, "sender.test", key, true, &["127.0.0.0/8".to_owned()]).unwrap()
}

#[tokio::test]
async fn dependency_requests_sign_the_actual_encoded_uri_and_body() {
    let (name, received) = peer(
        json!({
            "events": [{"type":"m.room.message"}],
            "pdus": [{"type":"m.room.message"}],
            "auth_chain": [{"type":"m.room.create"}],
            "pdu_ids": ["$state"], "auth_chain_ids": ["$auth"],
        }),
        StatusCode::OK,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir);
    let room = "!room:sender.test";
    let event = "$base/64+id";
    federation
        .remote_missing_events(&name, room, &["$held".to_owned()], &[event.to_owned()], 2)
        .await
        .unwrap();
    federation.remote_event(&name, event).await.unwrap();
    federation
        .remote_event_auth(&name, room, event)
        .await
        .unwrap();
    federation
        .remote_state_ids(&name, room, event)
        .await
        .unwrap();
    let requests = received.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[0].uri.path(),
        "/_matrix/federation/v1/get_missing_events/!room:sender.test"
    );
    assert_eq!(
        requests[1].uri.path(),
        "/_matrix/federation/v1/event/$base%2F64+id"
    );
    assert_eq!(
        requests[2].uri.path(),
        "/_matrix/federation/v1/event_auth/!room:sender.test/$base%2F64+id"
    );
    assert_eq!(requests[3].uri.query(), Some("event_id=%24base%2F64%2Bid"));
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({
            "earliest_events": ["$held"], "latest_events": [event], "limit": 2, "min_depth": 0,
        })
    );
    for request in requests.iter() {
        let body = (!request.body.is_empty())
            .then(|| serde_json::from_slice::<Value>(&request.body).unwrap());
        let signed = federation
            .sign_request(
                request.method.as_str(),
                &request.uri.to_string(),
                &name,
                body.as_ref(),
            )
            .unwrap();
        assert_eq!(request.headers["authorization"].to_str().unwrap(), signed);
        assert_eq!(
            request.method,
            if body.is_some() {
                Method::POST
            } else {
                Method::GET
            }
        );
    }
}

#[tokio::test]
async fn malformed_or_oversized_event_windows_are_refused() {
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir);
    for response in [
        json!({}),
        json!({"events":[null]}),
        json!({"events":[{},{}]}),
    ] {
        let (name, _) = peer(response, StatusCode::OK).await;
        assert!(
            federation
                .remote_missing_events(&name, "!r:sender.test", &[], &[], 1)
                .await
                .is_err()
        );
    }
    let (name, received) = peer(json!({"events":[]}), StatusCode::OK).await;
    for limit in [0, 101] {
        assert!(
            federation
                .remote_missing_events(&name, "!r:sender.test", &[], &[], limit)
                .await
                .is_err()
        );
    }
    assert!(
        received.lock().unwrap().is_empty(),
        "invalid limits never issue requests"
    );
}

#[tokio::test]
async fn event_auth_and_state_responses_require_their_complete_shapes() {
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir);
    let (name, _) = peer(
        json!({"pdus":[{},{}],"auth_chain":[null],"pdu_ids":["$x"],"auth_chain_ids":[7]}),
        StatusCode::OK,
    )
    .await;
    assert!(federation.remote_event(&name, "$x").await.is_err());
    assert!(
        federation
            .remote_event_auth(&name, "!r:sender.test", "$x")
            .await
            .is_err()
    );
    assert!(
        federation
            .remote_state_ids(&name, "!r:sender.test", "$x")
            .await
            .is_err()
    );
    let (name, _) = peer(json!({"pdus":[{}]}), StatusCode::FORBIDDEN).await;
    assert!(
        federation.remote_event(&name, "$x").await.is_err(),
        "a valid shape cannot turn a refusal into success"
    );
}

#[tokio::test]
async fn declared_oversized_responses_are_refused_before_reading_the_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        federation.remote_event(&name, "$x"),
    )
    .await
    .unwrap();
    assert!(result.unwrap_err().to_string().contains("too large"));
    server.abort();
}

#[tokio::test]
async fn chunked_responses_are_bounded_without_a_content_length() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let name = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let mut chunk = b"100000\r\n".to_vec();
        chunk.extend(vec![b'a'; 1024 * 1024]);
        chunk.extend_from_slice(b"\r\n");
        for _ in 0..17 {
            if stream.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    let dir = TempDir::new().unwrap();
    let federation = federation(&dir);
    let result = federation.remote_event(&name, "$x").await.unwrap_err();
    assert!(result.to_string().contains("too large"));
    server.await.unwrap();
}
