//! The delivery loops do not own what they read (#292).
//!
//! `spindle_server::app` spawns four loops that run for the life of the
//! process: delayed-event firing, the federation outbox drain, the
//! appservice push and push-gateway delivery. A runtime tears its tasks down as it shuts down, and a
//! task dropped that way is the wrong place for the store to close: fjall's
//! close joins its worker threads, and #292 caught it waiting forever there,
//! in a test whose assertions had all passed. So the loops hold their
//! sources weakly: the store closes where its last owner -- the router --
//! is dropped, and each loop returns on its next pass.

use std::sync::{Arc, Weak};
use std::time::Duration;

use spindle_store::FjallStore;
use tempfile::TempDir;

/// A router with all four loops running: the appservice push only starts
/// for a registration with a URL, so one is supplied (nothing listens on
/// it, and nothing is ever queued for it).
fn app_with_every_loop(dir: &TempDir, store: Arc<FjallStore>) -> axum::Router {
    let registration = dir.path().join("bridge.yaml");
    std::fs::write(
        &registration,
        "id: bridge\nurl: \"http://127.0.0.1:9\"\nas_token: as_token\n\
         hs_token: hs_token\nsender_localpart: _bridge\n\
         namespaces:\n  users:\n    - exclusive: true\n      regex: \"@_bridge_.*:.*\"\n",
    )
    .unwrap();
    let config = spindle_server::Config::parse(&format!(
        "[server]\nname = \"example.org\"\n[ratelimit]\nenabled = false\n\
         [federation]\nretry_base_ms = 50\n\
         [appservices]\nregistrations = [\"{}\"]\n",
        registration.display()
    ))
    .unwrap();
    spindle_server::app(config, store).expect("the app builds")
}

#[tokio::test]
async fn dropping_the_router_closes_the_store_and_ends_every_loop() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let observer: Weak<FjallStore> = Arc::downgrade(&store);
    let app = app_with_every_loop(&dir, store);
    let tasks = tokio::runtime::Handle::current().metrics();
    assert_eq!(tasks.num_alive_tasks(), 4, "the four delivery loops");

    // Every loop has taken at least one pass with the router alive, which
    // is where a loop that upgraded once and kept the result would show.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(tasks.num_alive_tasks(), 4, "the loops outlive a pass");

    drop(app);
    assert!(
        observer.upgrade().is_none(),
        "the router was the store's last owner; a loop is holding it"
    );

    // Each loop notices on its next pass; the slowest ticks once a second.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        tasks.num_alive_tasks(),
        0,
        "a loop is still running after its sources are gone"
    );
}
