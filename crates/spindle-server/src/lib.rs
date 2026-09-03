//! The Spindle homeserver's HTTP surface.
//!
//! What this crate is careful about, beyond wiring: **it does not advertise
//! anything it has not implemented.** See [`surface`] — the list of spec
//! versions and features `/versions` reports is derived from the same route
//! table that builds the router, so claiming something unbuilt is a
//! compile-or-test failure rather than a documentation drift.

pub mod account_data;
pub mod accounts;
pub mod admin;
pub mod appservices;
pub mod auth;
pub mod authorize;
pub mod backups;
pub mod blobs;
pub mod config;
pub mod delayed;
pub mod delegated;
pub mod devices;
pub mod directory;
pub mod errors;
pub mod federation;
pub mod filters;
pub mod import;
pub mod inbound;
pub mod livekit;
pub mod mas;
pub mod media;
pub mod metrics;
pub mod netguard;
pub mod oidc;
pub mod openid;
pub mod presence;
pub mod previews;
pub mod profiles;
pub mod push;
pub mod push_rules;
pub mod pushers;
pub mod ratelimit;
pub mod rooms;
pub mod routes;
pub mod s3;
pub mod secrets;
pub mod signing;
pub mod sliding;
pub mod stream;
pub mod surface;
pub mod tokens;
pub mod typing;

use std::sync::Arc;

use axum::Router;
use spindle_store::FjallStore;

pub use config::{Config, ConfigError};

/// Everything a handler needs.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<FjallStore>,
    pub limiter: Arc<ratelimit::RateLimiter>,
    pub key: Arc<signing::ServerKey>,
    pub rooms: Arc<rooms::Rooms>,
    pub typing: Arc<typing::Typing>,
    pub account_data: Arc<account_data::AccountData>,
    pub directory: Arc<directory::Directory>,
    pub filters: Arc<filters::Filters>,
    pub pushers: Arc<pushers::Pushers>,
    pub media: Arc<media::Media>,
    pub devices: Arc<devices::Devices>,
    pub backups: Arc<backups::Backups>,
    pub presence: Arc<presence::Presence>,
    pub previews: Arc<previews::Previews>,
    pub profiles: Arc<profiles::Profiles>,
    pub appservices: Arc<appservices::Appservices>,
    /// Present exactly when MSC3861 delegation is configured; its
    /// absence is what "local auth" means everywhere else.
    pub delegated: Option<Arc<delegated::Delegated>>,
    /// Present exactly when the built-in OIDC provider is configured
    /// (#159): this server is then its own MSC3861 issuer.
    pub oidc: Option<Arc<oidc::BuiltinOidc>>,
    pub federation: Arc<federation::Federation>,
    /// The one registry every counter in this server records into, and
    /// the one `/metrics` renders.
    pub metrics: Arc<metrics::Metrics>,
    pub delayed: Arc<delayed::Delayed>,
    /// The push gateway client, and the judgement on which gateways it
    /// reaches; `set_pusher` asks it before storing a URL.
    pub push: Arc<push::Gateway>,
}

/// Why the application cannot be built. Both are startup-fatal on purpose:
/// a server without a signing key cannot create a single valid event, and a
/// preview allow-list that failed to parse must not fail *open*.
#[derive(Debug)]
pub enum AppError {
    Signing(signing::SigningError),
    PreviewConfig(String),
    FederationConfig(String),
    PushConfig(String),
    Appservice(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signing(error) => write!(formatter, "signing key: {error}"),
            Self::PreviewConfig(why) => write!(formatter, "preview config: {why}"),
            Self::FederationConfig(why) => write!(formatter, "federation config: {why}"),
            Self::PushConfig(why) => write!(formatter, "push config: {why}"),
            Self::Appservice(why) => write!(formatter, "appservice registration: {why}"),
        }
    }
}

impl std::error::Error for AppError {}

/// The blob backend a config asks for.
///
/// Shared with the offline commands rather than inlined in [`app`]: a
/// media audit run from the CLI has to look in exactly the place the
/// server would, and a second copy of this `match` is a second chance to
/// point one of them at the wrong directory.
#[must_use]
pub fn blobs_for(config: &Config) -> blobs::Blobs {
    match &config.storage.s3 {
        Some(s3) => blobs::Blobs::S3(s3::S3Client::new(
            s3.endpoint.clone(),
            s3.bucket.clone(),
            s3.region.clone(),
            s3.access_key_id.clone(),
            s3.secret_access_key.clone(),
        )),
        None => blobs::Blobs::Local {
            root: config.storage.path.join("media"),
        },
    }
}

/// Build the HTTP application.
///
/// # Errors
///
/// Returns [`AppError`] if the server's signing key can be neither loaded
/// nor created, or if the preview allow-list does not parse. Fatal rather
/// than degraded in both cases — see [`AppError`].
pub fn app(config: Config, store: Arc<FjallStore>) -> Result<Router, AppError> {
    app_with_metrics(config, store, Arc::new(metrics::Metrics::new()))
}

/// [`app`], recording into `metrics` -- the handle `main` serves on the
/// scrape listener, and a test reads its assertions from.
///
/// # Errors
///
/// As [`app`].
pub fn app_with_metrics(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
) -> Result<Router, AppError> {
    let key =
        Arc::new(signing::ServerKey::load_or_create(store.as_ref()).map_err(AppError::Signing)?);
    let rooms = Arc::new(rooms::Rooms::with_metrics(
        Arc::clone(&store),
        config.server.name.clone(),
        Arc::clone(&metrics),
    ));
    let limiter = Arc::new(ratelimit::RateLimiter::with_enabled(
        config.ratelimit.enabled,
    ));
    let store_for_filters = Arc::clone(&store);
    let store_for_devices = Arc::clone(&store);
    let store_for_delayed = Arc::clone(&store);
    let store_for_presence = Arc::clone(&store);
    let store_for_backups = Arc::clone(&store);
    let account_data = Arc::new(account_data::AccountData::new(Arc::clone(&store)));
    let blobs = blobs_for(&config);
    let media = Arc::new(media::Media::new(
        Arc::clone(&store),
        blobs,
        config.server.name.clone(),
    ));
    let directory = Arc::new(directory::Directory::new(
        Arc::clone(&store),
        config.server.name.clone(),
    ));
    let profiles = Arc::new(profiles::Profiles::new(Arc::clone(&store)));
    let appservices = Arc::new(
        appservices::Appservices::load(&config.appservices.registrations)
            .map_err(|error| AppError::Appservice(error.to_string()))?,
    );
    let previews = Arc::new(
        previews::Previews::new(
            Arc::clone(&store),
            Arc::clone(&media),
            &config.previews.allow_private,
        )
        .map_err(|error| AppError::PreviewConfig(error.to_string()))?,
    );
    let federation = Arc::new(
        federation::Federation::new(
            Arc::clone(&store),
            config.server.name.clone(),
            Arc::clone(&key),
            config.federation.insecure_http,
            &config.federation.allow_internal,
        )
        .map_err(|error| AppError::FederationConfig(error.to_string()))?
        .with_metrics(Arc::clone(&metrics)),
    );
    let delegated = config
        .auth
        .delegated
        .clone()
        .map(|delegated| Arc::new(delegated::Delegated::new(delegated)));
    let oidc_provider = config
        .auth
        .builtin_oidc
        .then(|| Arc::new(oidc::BuiltinOidc::new()));
    let push =
        Arc::new(push::Gateway::new(&config.push.allow_internal).map_err(AppError::PushConfig)?);
    let delayed_caps = config.delayed_events.clone();
    let state = AppState {
        config: Arc::new(config),
        store,
        limiter,
        key,
        rooms,
        typing: Arc::new(typing::Typing::new()),
        account_data,
        directory,
        filters: Arc::new(filters::Filters::new(Arc::clone(&store_for_filters))),
        pushers: Arc::new(pushers::Pushers::new(Arc::clone(&store_for_filters))),
        media,
        devices: Arc::new(devices::Devices::new(store_for_devices)),
        backups: Arc::new(backups::Backups::new(store_for_backups)),
        presence: Arc::new(presence::Presence::new(Arc::clone(&store_for_presence))),
        previews,
        profiles,
        appservices,
        delegated,
        oidc: oidc_provider,
        federation,
        delayed: Arc::new(delayed::Delayed::with_limits(
            Arc::clone(&store_for_delayed),
            delayed_caps.max_delay_ms,
            delayed_caps.max_per_room,
        )),
        push,
        metrics,
    };
    spawn_delivery_loops(&state);
    Ok(routes::router(state))
}

/// The delivery loops that run for the life of the process. Spawned only
/// when a runtime is running — which is every real caller; a build
/// outside one gets a router that serves but never sends, and the
/// absence of a runtime is that caller's own statement of intent.
///
/// Each loop holds what it reads weakly and ends once the router is
/// gone, so the last reference to the store is never the one a loop
/// holds. A runtime tears its tasks down as it shuts down, and a task
/// dropped that way is the wrong place for the store to close: fjall's
/// close joins its worker threads, and #292 caught it waiting forever
/// there. With the loops holding only weak references the store closes
/// where its last owner is dropped -- the router, on the thread that
/// served it -- and the loops notice on their next pass and return.
///
/// The same holds inside a pass: a loop upgrades to read and to write,
/// never across a request in flight, so a cancellation mid-send finds
/// nothing to drop either. `delivery_loops.rs` pins both -- the router
/// dropped while every loop is idle, and while each is mid-request.
fn spawn_delivery_loops(state: &AppState) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    // A second is far below any heartbeat a client would set and far above
    // the cost of the tick: when nothing is due it reads one row, because
    // the rows are ordered by when they fire.
    tokio::spawn(delayed::fire_loop(
        Arc::downgrade(&state.delayed),
        Arc::downgrade(&state.rooms),
        Arc::downgrade(&state.key),
        std::time::Duration::from_secs(1),
    ));
    tokio::spawn(federation::drain_outbox(
        Arc::downgrade(&state.store),
        Arc::downgrade(&state.federation),
        std::time::Duration::from_millis(state.config.federation.retry_base_ms),
    ));
    // Push delivery shares the outbox's retry base for the same reason
    // the appservice push does, below.
    if state.config.push.enabled {
        tokio::spawn(push::deliver_loop(
            push::Sources {
                store: Arc::downgrade(&state.store),
                rooms: Arc::downgrade(&state.rooms),
                pushers: Arc::downgrade(&state.pushers),
                account_data: Arc::downgrade(&state.account_data),
                profiles: Arc::downgrade(&state.profiles),
                gateway: Arc::downgrade(&state.push),
            },
            std::time::Duration::from_millis(state.config.federation.retry_base_ms),
        ));
    }
    // The appservice push shares the outbox's retry base: both are
    // at-least-once delivery loops, and one knob for "how patient is
    // this server with a peer" is one knob to explain.
    if state
        .appservices
        .all()
        .iter()
        .any(|registration| registration.url.is_some())
    {
        tokio::spawn(appservices::push_loop(
            Arc::downgrade(&state.store),
            Arc::downgrade(&state.appservices),
            Arc::downgrade(&state.rooms),
            Arc::downgrade(&state.typing),
            Arc::downgrade(&state.devices),
            state.config.server.name.clone(),
            std::time::Duration::from_millis(state.config.federation.retry_base_ms),
        ));
    }
}
