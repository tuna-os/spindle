//! The Spindle homeserver's HTTP surface.
//!
//! What this crate is careful about, beyond wiring: **it does not advertise
//! anything it has not implemented.** See [`surface`] — the list of spec
//! versions and features `/versions` reports is derived from the same route
//! table that builds the router, so claiming something unbuilt is a
//! compile-or-test failure rather than a documentation drift.

pub mod account;
pub mod account_data;
pub mod accounts;
pub mod admin;
pub mod admin_federation;
pub mod admin_media;
pub mod admin_tasks;
pub mod admin_ui;
pub mod appservice_proxy;
pub mod appservices;
pub mod auth;
pub mod authorize;
pub mod backups;
pub mod blobs;
pub mod blocking;
pub mod config;
pub mod dehydrated;
pub mod delayed;
pub mod delegated;
pub mod devices;
pub mod directory;
pub mod e2ee_federation;
pub mod email;
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
pub mod presence_routes;
pub mod previews;
pub mod profiles;
pub mod push;
pub mod push_rules;
pub mod pushers;
pub mod ratelimit;
pub mod receipts;
pub mod recovery;
pub mod registration_tokens;
pub mod rendezvous;
pub mod rooms;
pub mod routes;
pub mod s3;
pub mod secrets;
pub mod server_notices;
pub mod shared_secret_registration;
pub mod signing;
pub mod sliding;
pub mod state_res;
pub mod state_res_v1;
pub mod stream;
pub mod surface;
pub mod telemetry;
pub mod tokens;
pub mod typing;
pub mod web;

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
    /// Single-use challenges for Synapse-compatible shared-secret account
    /// creation. Process-local because a restart invalidates them.
    pub registration_nonces: Arc<shared_secret_registration::RegistrationNonces>,
    pub rendezvous: Arc<rendezvous::Rendezvous>,
    /// One dependency recovery per room at a time, and the peers resting
    /// after a 429 (`inbound::recovery`).
    pub recovery: Arc<inbound::RecoveryGate>,
    /// The background fill of recorded federation gaps, which a client
    /// paging into one wakes (`inbound::backfill`).
    pub backfill: Arc<inbound::GapBackfill>,
    /// Where the built-in provider's mail goes (#608): the SMTP relay
    /// `[email]` names, or what a test supplied. Absent, nothing is mailed
    /// and the pages that would need it are not offered.
    pub mailer: Option<Arc<dyn email::Mailer>>,
    /// The SFU sidecar supervisor: the local model's child process, watched
    /// and restarted. Present in every state — the remote model and the
    /// unconfigured server simply report through it rather than spawn.
    pub sfu: Arc<livekit::SfuSupervisor>,
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
    Email(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signing(error) => write!(formatter, "signing key: {error}"),
            Self::PreviewConfig(why) => write!(formatter, "preview config: {why}"),
            Self::FederationConfig(why) => write!(formatter, "federation config: {why}"),
            Self::PushConfig(why) => write!(formatter, "push config: {why}"),
            Self::Appservice(why) => write!(formatter, "appservice registration: {why}"),
            Self::Email(why) => write!(formatter, "email: {why}"),
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
    let state = app_state(config, store, metrics)?;
    spawn_delivery_loops(&state);
    Ok(routes::router(state))
}

/// [`app_with_metrics`], also handing back the state the router serves,
/// for tests that need to reach behind the HTTP surface -- to hold a
/// room's lock, or ask which rooms are resident.
///
/// # Errors
///
/// As [`app`].
#[doc(hidden)]
pub fn app_with_state(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
) -> Result<(Router, AppState), AppError> {
    let state = app_state(config, store, metrics)?;
    spawn_delivery_loops(&state);
    Ok((routes::router(state.clone()), state))
}

/// [`app_with_metrics`], plus the startup warm-up `[storage]
/// warm_concurrency` asks for: what the server binary runs.
///
/// Separate so that a test building an app gets exactly the rooms it
/// touched resident and no background loads racing its assertions.
///
/// # Errors
///
/// As [`app`].
pub fn app_warming(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
) -> Result<Router, AppError> {
    let concurrency = config.storage.warm_concurrency;
    let state = app_state(config, store, metrics)?;
    spawn_delivery_loops(&state);
    spawn_room_warmup(&state.rooms, &state.metrics, concurrency);
    Ok(routes::router(state))
}

/// Load every room a local user is joined to in the background, newest
/// activity first, `concurrency` at a time, on the blocking pool (#614).
///
/// Readiness does not wait for this. A room of a million events takes
/// minutes to load on the hardware this runs on, and a readiness gate
/// on it would hold a single-replica deployment out of service for all
/// of them -- an outage to avoid a slow first request. Requests for a
/// room the warm-up has not reached yet still work: they load it
/// themselves, off the async workers, and the warm-up skips it.
/// `spindle_room_warmup_pending` says how far it has got.
///
/// Holds the rooms weakly between loads, so a shutdown is held up by at
/// most the loads already in progress.
pub fn spawn_room_warmup(
    rooms: &Arc<rooms::Rooms>,
    metrics: &Arc<metrics::Metrics>,
    concurrency: usize,
) {
    if concurrency == 0 || tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let rooms = Arc::downgrade(rooms);
    let metrics = Arc::clone(metrics);
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let candidates = {
            let rooms = rooms.clone();
            tokio::task::spawn_blocking(move || {
                rooms
                    .upgrade()
                    .map_or_else(|| Ok(Vec::new()), |rooms| rooms.warm_candidates())
            })
            .await
        };
        let candidates = match candidates {
            Ok(Ok(candidates)) => candidates,
            Ok(Err(error)) => {
                tracing::warn!("room warm-up cannot list rooms: {error}");
                return;
            }
            Err(error) => {
                tracing::warn!("room warm-up failed: {error}");
                return;
            }
        };
        let total = candidates.len();
        metrics.set_warmup_pending(total as u64);
        tracing::info!(rooms = total, concurrency, "warming rooms");
        let queue = Arc::new(std::sync::Mutex::new(
            candidates
                .into_iter()
                .collect::<std::collections::VecDeque<_>>(),
        ));
        let workers: Vec<_> = (0..concurrency.min(total.max(1)))
            .map(|_| {
                let queue = Arc::clone(&queue);
                let rooms = rooms.clone();
                let metrics = Arc::clone(&metrics);
                tokio::task::spawn_blocking(move || warm_from(&queue, &rooms, &metrics))
            })
            .collect();
        for worker in workers {
            let _ = worker.await;
        }
        tracing::info!(
            rooms = total,
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "room warm-up finished"
        );
    });
}

/// One warm-up worker: load rooms off the shared queue until it is empty
/// or the server is gone.
fn warm_from(
    queue: &std::sync::Mutex<std::collections::VecDeque<String>>,
    rooms: &std::sync::Weak<rooms::Rooms>,
    metrics: &metrics::Metrics,
) {
    loop {
        let Some(room_id) = queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
        else {
            return;
        };
        let Some(rooms) = rooms.upgrade() else {
            return;
        };
        let _in_flight = metrics.blocking_started(metrics::BlockingTask::RoomWarmup);
        match rooms.warm(&room_id) {
            Ok(()) => metrics.warmup_loaded(),
            Err(error) => {
                tracing::warn!(room = room_id, "room warm-up cannot load: {error}");
                metrics.warmup_failed();
            }
        }
    }
}

/// The federation client `[federation]` describes.
fn federation_client(
    config: &Config,
    store: &Arc<FjallStore>,
    key: &Arc<signing::ServerKey>,
    metrics: &Arc<metrics::Metrics>,
) -> Result<Arc<federation::Federation>, AppError> {
    let client = federation::Federation::new(
        Arc::clone(store),
        config.server.name.clone(),
        Arc::clone(key),
        config.federation.insecure_http,
        &config.federation.allow_internal,
    )
    .and_then(|client| client.with_trusted_key_servers(&config.federation.trusted_key_servers()))
    .map_err(|error| AppError::FederationConfig(error.to_string()))?;
    Ok(Arc::new(
        client
            .with_peers(&config.federation.peers)
            .with_enabled(config.federation.enabled)
            .with_metrics(Arc::clone(metrics)),
    ))
}

/// Everything a handler needs, built from configuration.
#[allow(
    clippy::too_many_lines,
    reason = "one construction of the shared state, a field per subsystem"
)]
fn app_state(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
) -> Result<AppState, AppError> {
    let mailer = match &config.email {
        Some(email) => Some(Arc::new(
            email::SmtpMailer::new(email, &config.server.name).map_err(AppError::Email)?,
        ) as Arc<dyn email::Mailer>),
        None => None,
    };
    app_state_with(config, store, metrics, mailer)
}

/// [`app_with_metrics`], with the mail transport supplied rather than
/// built from `[email]` — a test's [`email::MemoryMailer`], typically.
/// The pages that send mail are offered whenever a mailer is present.
///
/// # Errors
///
/// As [`app`].
pub fn app_with_mailer(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
    mailer: Arc<dyn email::Mailer>,
) -> Result<Router, AppError> {
    let state = app_state_with(config, store, metrics, Some(mailer))?;
    spawn_delivery_loops(&state);
    Ok(routes::router(state))
}

fn app_state_with(
    config: Config,
    store: Arc<FjallStore>,
    metrics: Arc<metrics::Metrics>,
    mailer: Option<Arc<dyn email::Mailer>>,
) -> Result<AppState, AppError> {
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
    let media = Arc::new(
        media::Media::new(Arc::clone(&store), blobs, config.server.name.clone())
            .with_max_upload_bytes(config.media.max_upload_bytes),
    );
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
    let federation = federation_client(&config, &store, &key, &metrics)?;
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
    let config_for_sfu = config.clone();
    let store_for_sfu = Arc::clone(&store);
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
        delayed: Arc::new(
            delayed::Delayed::with_limits(
                Arc::clone(&store_for_delayed),
                delayed_caps.max_delay_ms,
                delayed_caps.max_per_room,
            )
            .with_user_cap(delayed_caps.max_per_user),
        ),
        push,
        registration_nonces: Arc::new(shared_secret_registration::RegistrationNonces::new()),
        rendezvous: Arc::new(rendezvous::Rendezvous::new()),
        recovery: Arc::new(inbound::RecoveryGate::new()),
        backfill: Arc::new(inbound::GapBackfill::new()),
        metrics,
        mailer,
        sfu: livekit::SfuSupervisor::new(config_for_sfu, store_for_sfu),
    };
    // Resident rooms are counted at scrape time, from the registry itself,
    // rather than kept as a counter every admission path would have to
    // remember to move. Weakly, so the registry never outlives the server.
    let resident = Arc::downgrade(&state.rooms);
    state
        .metrics
        .set_resident_rooms_probe(move || resident.upgrade()?.resident_count());
    Ok(state)
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
    // A tenth of a second, the push loop's tick, so a call's departure and
    // its ring land with the same delay. It was a second until #36's
    // comparison against Synapse measured what that cost: a delay landed
    // half a second late at the median, where Synapse's timer landed it in
    // sixty milliseconds. The idle tick reads one row (#350), so ten of
    // them a second cost microseconds.
    tokio::spawn(delayed::fire_loop(
        Arc::downgrade(&state.delayed),
        Arc::downgrade(&state.rooms),
        Arc::downgrade(&state.key),
        std::time::Duration::from_millis(100),
    ));
    // Forks no event merges are merged with dummy events, and the census
    // behind `spindle_rooms_by_forward_extremities` is taken, once a minute
    // -- Synapse's cadence for the same job (#626).
    tokio::spawn(rooms::extremities::merge_loop(
        Arc::downgrade(&state.rooms),
        Arc::downgrade(&state.key),
        rooms::extremities::MergePolicy::of(&state.config.rooms),
        std::time::Duration::from_secs(60),
    ));
    // Disabled federation leaves queued rows in the outbox and never starts
    // the drain that would only be refused, row by row.
    if state.config.federation.enabled {
        tokio::spawn(federation::drain_outbox(
            Arc::downgrade(&state.store),
            Arc::downgrade(&state.federation),
            std::time::Duration::from_millis(state.config.federation.retry_base_ms),
        ));
    }
    // Recorded federation gaps fill in the background, a chunk at a time
    // (`inbound::backfill`); nothing to do with federation off.
    if state.config.federation.enabled && state.config.federation.gap_backfill {
        tokio::spawn(inbound::run_backfill(
            inbound::BackfillSources {
                rooms: Arc::downgrade(&state.rooms),
                federation: Arc::downgrade(&state.federation),
                key: Arc::downgrade(&state.key),
                metrics: Arc::downgrade(&state.metrics),
                recovery: Arc::downgrade(&state.recovery),
                backfill: Arc::downgrade(&state.backfill),
                server_name: state.config.server.name.clone(),
            },
            inbound::BackfillSettings::of(&state.config.federation),
        ));
    }
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

mod passwords;
