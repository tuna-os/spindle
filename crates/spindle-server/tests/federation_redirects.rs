//! A redirect is a second destination, and it is vetted like the first.
//!
//! #288 gates the address a federation fetch *starts* at: the resolver
//! judges every name it looks up, and `base_url` judges a name that is a
//! literal. Neither sees hop two. `VettingResolver` is a DNS hook, so a
//! `Location:` carrying a literal IP never reaches it, and reqwest's
//! default policy follows ten of those — which is a fixed-path GET to an
//! address of the redirecting host's choosing, from inside whatever
//! network this server sits in.
//!
//! `fetch_key_document` is driven by the `origin` of an inbound `X-Matrix`
//! header, so "the redirecting host" means anyone who can point a public
//! name at a server they run. That is the same reach #288 closed, reopened
//! one hop later.
//!
//! What must hold: a hop outside the allow-list opens no socket at all,
//! and a hop inside it is still followed. The first is asserted with a
//! real listener that counts accepted connections rather than with the
//! fetch's error, because a refused connection and a refused *hop* both
//! surface as "the fetch failed" and only one of them is the guarantee.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::response::Redirect;
use axum::routing::get;
use spindle_store::FjallStore;
use tempfile::TempDir;

/// A key server whose only answer is "look over there".
async fn redirector(to: String) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let target = to.clone();
            async move { Redirect::temporary(&target) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    address
}

/// A `Federation` that may reach `allow_internal` and nothing else local.
fn federation(
    store: &Arc<FjallStore>,
    allow_internal: &[String],
) -> spindle_server::federation::Federation {
    let key = Arc::new(spindle_server::signing::ServerKey::load_or_create(store.as_ref()).unwrap());
    spindle_server::federation::Federation::new(
        Arc::clone(store),
        "example.org",
        key,
        // The peers below are plain HTTP; TLS would test the peer's
        // certificate handling, which is not what this suite is about.
        true,
        allow_internal,
    )
    .unwrap()
}

#[tokio::test]
async fn a_hop_outside_the_allow_list_opens_no_socket() {
    // A bare listener rather than a server: it never speaks HTTP, it only
    // records that something knocked. 127.0.0.2 is loopback and therefore
    // refused by default, and the allow-list below opens 127.0.0.1 alone —
    // so the peer is reachable and its redirect target is not.
    let trap = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let trap_address = trap.local_addr().unwrap();
    let knocks = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&knocks);
    tokio::spawn(async move {
        while let Ok((stream, _)) = trap.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let peer = redirector(format!("http://{trap_address}/")).await;

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let federation = federation(&store, &["127.0.0.1/32".to_owned()]);

    let outcome = federation.peer_keys(&peer.to_string()).await;

    assert!(
        outcome.is_err(),
        "a key fetch that only ever redirected somewhere unreachable cannot succeed"
    );
    assert_eq!(
        knocks.load(Ordering::SeqCst),
        0,
        "the redirect target was connected to; the hop was not vetted"
    );
}

#[tokio::test]
async fn a_hop_inside_the_allow_list_is_still_followed() {
    // The other half, and the reason the policy is a vet rather than a
    // refusal: an operator who opens a range means it for redirects too,
    // and a gate that blocked every hop would pass the test above while
    // breaking every peer behind a redirect.
    let visits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&visits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/_matrix/key/v2/server",
        get(move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                // Well-formed JSON, no signatures: the fetch still fails,
                // one link further along than this test cares about. What
                // is being asserted is that the request arrived.
                "{}"
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let peer = redirector(format!("http://{destination}/_matrix/key/v2/server")).await;

    let dir = TempDir::new().unwrap();
    let store = Arc::new(FjallStore::open(dir.path()).unwrap());
    let federation = federation(&store, &["127.0.0.0/8".to_owned()]);

    let _ = federation.peer_keys(&peer.to_string()).await;

    assert_eq!(
        visits.load(Ordering::SeqCst),
        1,
        "a redirect into an allowed range must be followed"
    );
}
