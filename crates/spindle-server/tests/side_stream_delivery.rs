//! Sync positions must not acknowledge a side-stream row before it exists.
use std::sync::Arc;

use serde_json::json;
use spindle_server::{devices::Devices, rooms::Rooms};
use spindle_store::FjallStore;

#[test]
fn a_paused_writer_cannot_publish_or_lose_its_message() {
    let directory = tempfile::TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let rooms = Rooms::new(Arc::clone(&store), "example.org");
    let devices = Devices::new(store);
    let writer = rooms.reserve_stream_id();
    let seq = writer.id();
    let token_before_write = rooms.stream_position();
    assert!(token_before_write < seq);
    assert!(
        devices
            .take_pending_until("@a:example.org", "D", None, token_before_write, None)
            .unwrap()
            .0
            .is_empty()
    );
    devices
        .queue_to_device(
            "@a:example.org",
            "D",
            seq,
            &json!({"type": "m.room.encrypted", "content": {"key": "fixture"}}),
        )
        .unwrap();
    // Even after persistence, another sync cannot see past the watermark.
    assert!(
        devices
            .take_pending_until(
                "@a:example.org",
                "D",
                Some(token_before_write),
                token_before_write,
                None
            )
            .unwrap()
            .0
            .is_empty()
    );
    drop(writer);
    let published = rooms.stream_position();
    assert_eq!(published, seq);
    let delivered = devices
        .take_pending_until(
            "@a:example.org",
            "D",
            Some(token_before_write),
            published,
            None,
        )
        .unwrap()
        .0;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["content"]["key"], "fixture");
    assert!(
        devices
            .take_pending_until("@a:example.org", "D", Some(published), published, None)
            .unwrap()
            .0
            .is_empty()
    );
}

#[test]
fn a_limited_batch_does_not_acknowledge_omitted_messages() {
    let directory = tempfile::TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let devices = Devices::new(store);
    for seq in 1..=3 {
        devices
            .queue_to_device(
                "@a:example.org",
                "D",
                seq,
                &json!({"content": {"seq": seq}}),
            )
            .unwrap();
    }
    let (first, cursor) = devices
        .take_pending_until("@a:example.org", "D", None, 3, Some(1))
        .unwrap();
    assert_eq!(first[0]["content"]["seq"], 1);
    assert_eq!(cursor, 1);
    let (second, cursor) = devices
        .take_pending_until("@a:example.org", "D", Some(cursor), 3, Some(1))
        .unwrap();
    assert_eq!(second[0]["content"]["seq"], 2);
    assert_eq!(cursor, 2);
    let (third, cursor) = devices
        .take_pending_until("@a:example.org", "D", Some(cursor), 3, Some(1))
        .unwrap();
    assert_eq!(third[0]["content"]["seq"], 3);
    assert_eq!(cursor, 3);
}

#[test]
fn aborted_and_out_of_order_writers_cannot_stall_the_watermark() {
    let directory = tempfile::TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(directory.path()).unwrap());
    let rooms = Rooms::new(store, "example.org");
    let first = rooms.reserve_stream_id();
    let second = rooms.reserve_stream_id();
    let last = second.id();
    drop(second);
    assert!(rooms.stream_position() < first.id());
    drop(first);
    assert_eq!(rooms.stream_position(), last);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _writer = rooms.reserve_stream_id();
        panic!("simulate a writer that unwinds");
    }));
    assert!(result.is_err());
    assert_eq!(rooms.stream_position(), last + 1);
}
