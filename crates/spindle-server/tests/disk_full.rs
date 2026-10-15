//! #21's disk-full drill, server half: when the disk fills, `/ready` goes
//! to 503 and stays there, `/health` stays 200, and reads keep working.
//!
//! The store half (`spindle-store/tests/disk_full.rs`) proves nothing
//! acknowledged is lost and that a restart with space recovers. This half
//! is what an orchestrator sees. A server that answers `/sync` and fails
//! every `/send` with a 500 must stop being routed to. It must not be
//! restarted in a loop onto the same full disk, which a failing liveness
//! probe would cause.
//!
//! Like the store half it fills a real filesystem, so it is `#[ignore]`d
//! and run by `just drill-disk-full`, which mounts a small tmpfs at
//! `SPINDLE_DISK_FULL_DIR`.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use spindle_store::FjallStore;
use tower::ServiceExt;

const DIR_VAR: &str = "SPINDLE_DISK_FULL_DIR";

/// The same guard as the store half: 256 MiB.
const MAX_FREE_BYTES: u64 = 256 * 1024 * 1024;

/// Each message body. Under the 64 KiB event limit with room for the
/// envelope, and noise, so compression cannot stretch the disk.
const BODY_CHARS: usize = 32 * 1024;

/// More sends than [`MAX_FREE_BYTES`] can hold: twice it, in bodies.
const ATTEMPTS: usize = 2 * 256 * 1024 * 1024 / BODY_CHARS;

/// The directory to fill, checked to be on a small filesystem by filling
/// it once with zeroes and deleting them. `own` is this drill's
/// subdirectory, cleared first. The server's delivery loops keep its store
/// open until the process ends, so the server half cannot clean up after
/// itself, and the next run does it.
fn small_filesystem(own: &str) -> PathBuf {
    use std::io::Write as _;
    let root = PathBuf::from(
        std::env::var_os(DIR_VAR)
            .unwrap_or_else(|| panic!("{DIR_VAR} names a directory on a small filesystem")),
    );
    // A run that failed part way leaves its directory, and its ballast,
    // filling the space this one is about to measure.
    let _ = std::fs::remove_dir_all(root.join(own));
    let _ = std::fs::remove_file(root.join("ballast"));
    let probe = root.join("probe");
    let mut file = std::fs::File::create(&probe).unwrap();
    let chunk = vec![0_u8; 1024 * 1024];
    let mut free = 0_u64;
    while free < MAX_FREE_BYTES {
        match file.write(&chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => free += n as u64,
        }
    }
    drop(file);
    std::fs::remove_file(&probe).unwrap();
    assert!(
        free < MAX_FREE_BYTES,
        "{} has {free} bytes free; the drill fills it, so it wants under {MAX_FREE_BYTES}",
        root.display(),
    );
    root
}

/// Message `n`'s body: printable xorshift noise seeded by `n`.
fn body(n: usize) -> String {
    let mut state = (n as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (0..BODY_CHARS)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(b'!' + u8::try_from(state % 94).unwrap())
        })
        .collect()
}

async fn call(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn probe(app: &axum::Router, path: &str) -> StatusCode {
    call(app, Request::get(path).body(Body::empty()).unwrap())
        .await
        .0
}

async fn authed(
    app: &axum::Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    call(app, request).await
}

#[tokio::test]
#[ignore = "fills a filesystem: run it through `just drill-disk-full`"]
async fn a_full_disk_takes_the_server_out_of_rotation_and_keeps_it_alive() {
    let root = small_filesystem("server");
    let dir = root.join("server");
    let store = Arc::new(FjallStore::open(&dir).unwrap());
    // The limiter is off for the same reason the benchmark turns it off:
    // the drill sends as fast as the server takes them, and a 429 is not
    // the refusal under test.
    let config = spindle_server::Config::parse(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n",
    )
    .unwrap();
    let app = spindle_server::app(config, Arc::clone(&store)).unwrap();

    let (status, registered) = call(
        &app,
        Request::post("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "username": "alice",
                    "password": "hunter2",
                    "auth": { "type": "m.login.dummy" },
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    let token = registered["access_token"].as_str().unwrap().to_owned();
    let (status, created) = authed(
        &app,
        "POST",
        "/_matrix/client/v3/createRoom",
        &token,
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let room_id = created["room_id"].as_str().unwrap().to_owned();

    assert_eq!(probe(&app, "/ready").await, StatusCode::OK);
    assert_eq!(probe(&app, "/health").await, StatusCode::OK);

    let mut sent = 0;
    let mut refused = None;
    for n in 0..ATTEMPTS {
        let (status, response) = authed(
            &app,
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn{n}"),
            &token,
            Some(&json!({ "msgtype": "m.text", "body": body(n) })),
        )
        .await;
        if status == StatusCode::OK {
            sent += 1;
        } else {
            refused = Some((status, response));
            break;
        }
    }
    let (status, response) =
        refused.expect("the filesystem refuses a send before the attempts run out");
    assert!(sent > 0, "the filesystem is meant to fill a working server");
    assert!(
        status.is_server_error(),
        "a full disk is the server's failure, not the client's: {status} {response}",
    );

    assert_eq!(
        probe(&app, "/ready").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "a server that cannot write takes itself out of rotation",
    );
    assert_eq!(
        probe(&app, "/health").await,
        StatusCode::OK,
        "and stays alive: a restart onto the same full disk is a crash loop",
    );

    // Reads keep working: the history up to the full disk is still served.
    let (status, messages) = authed(
        &app,
        "GET",
        &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=1"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{messages}");
    assert_eq!(
        messages["chunk"][0]["content"]["body"],
        json!(body(sent - 1)),
        "the last acknowledged message is the newest one served",
    );
}
