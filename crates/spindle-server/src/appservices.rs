//! Application services: bridges and bots with a skeleton key.
//!
//! An appservice is a client whose token authenticates *a namespace of
//! users* rather than one account. The registration file (YAML, by spec)
//! is the whole contract: the `as_token` the service presents to us, the
//! `hs_token` we will present to it, the localpart it acts as by default,
//! and the regex namespaces inside which it may masquerade as anyone.
//!
//! Registrations load once at startup and a bad file is startup-fatal —
//! a bridge that silently failed to register would look exactly like a
//! bridge receiving nothing, which is the failure mode worth the loudest
//! possible error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use spindle_store::{FjallStore, ReadView, Store};

use crate::rooms::Rooms;

/// One namespace claim: a regex over full IDs, and whether the claim is
/// exclusive to this service.
#[derive(Debug, Clone, Deserialize)]
pub struct Namespace {
    #[serde(default)]
    pub exclusive: bool,
    pub regex: String,
    #[serde(skip)]
    compiled: Option<Regex>,
}

impl Namespace {
    fn compile(&mut self) -> Result<(), AppserviceError> {
        // Anchored per spec: a namespace regex matches the whole ID, and
        // an unanchored one would quietly claim every user whose name
        // merely *contains* the pattern.
        let anchored = format!("^(?:{})$", self.regex);
        self.compiled =
            Some(Regex::new(&anchored).map_err(|error| {
                AppserviceError::BadRegex(self.regex.clone(), error.to_string())
            })?);
        Ok(())
    }

    #[must_use]
    pub fn matches(&self, id: &str) -> bool {
        self.compiled
            .as_ref()
            .is_some_and(|regex| regex.is_match(id))
    }
}

/// The three namespace families a registration may claim.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Namespaces {
    #[serde(default)]
    pub users: Vec<Namespace>,
    #[serde(default)]
    pub aliases: Vec<Namespace>,
    #[serde(default)]
    pub rooms: Vec<Namespace>,
}

/// One appservice, as its registration file declares it.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub id: String,
    /// Where transactions get pushed; `None` (or explicit null) means the
    /// service only ever acts through the CS API and receives nothing.
    #[serde(default)]
    pub url: Option<String>,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: Namespaces,
    /// `false` exempts the service from rate limits; the default is the
    /// spec's: limited like anyone else.
    #[serde(default = "default_rate_limited")]
    pub rate_limited: bool,
}

fn default_rate_limited() -> bool {
    true
}

impl Registration {
    /// The user the service acts as when it does not masquerade.
    #[must_use]
    pub fn sender_user(&self, server_name: &str) -> String {
        format!("@{}:{server_name}", self.sender_localpart)
    }

    /// Whether the service may act as `user_id`: its own sender, or
    /// anyone inside its user namespaces.
    #[must_use]
    pub fn may_masquerade_as(&self, user_id: &str, server_name: &str) -> bool {
        user_id == self.sender_user(server_name)
            || self
                .namespaces
                .users
                .iter()
                .any(|namespace| namespace.matches(user_id))
    }

    /// Whether the service hears about an event: its sender or any joined
    /// member inside the user namespaces (the sender user included), or
    /// the room itself inside the room namespaces.
    ///
    /// Alias namespaces deliberately do not gate the push — deciding
    /// interest by alias would mean resolving every event's room against
    /// the directory on the hot path, and a service that cares about a
    /// room it aliased is in that room through a namespace user anyway.
    #[must_use]
    pub fn wants_event(
        &self,
        room_id: &str,
        sender: &str,
        members: &[String],
        server_name: &str,
    ) -> bool {
        self.may_masquerade_as(sender, server_name)
            || self
                .namespaces
                .rooms
                .iter()
                .any(|namespace| namespace.matches(room_id))
            || members
                .iter()
                .any(|member| self.may_masquerade_as(member, server_name))
    }
}

/// Why registrations could not be loaded. All startup-fatal.
#[derive(Debug)]
pub enum AppserviceError {
    Unreadable(String, String),
    Invalid(String, String),
    BadRegex(String, String),
    /// Two registrations share an `id` or an `as_token` — either would
    /// make "which service is this?" ambiguous at auth time.
    Duplicate(String),
}

impl std::fmt::Display for AppserviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(path, error) => write!(f, "{path}: {error}"),
            Self::Invalid(path, error) => write!(f, "{path} does not parse: {error}"),
            Self::BadRegex(regex, error) => write!(f, "namespace regex {regex:?}: {error}"),
            Self::Duplicate(what) => write!(f, "duplicate registration {what}"),
        }
    }
}

/// Every registered appservice, indexed for the auth path.
#[derive(Default)]
pub struct Appservices {
    list: Vec<Arc<Registration>>,
}

impl Appservices {
    /// Load and validate every registration file named in the config.
    ///
    /// # Errors
    ///
    /// Returns [`AppserviceError`] on the first unreadable, unparseable or
    /// ambiguous registration — startup-fatal by design.
    pub fn load(paths: &[String]) -> Result<Self, AppserviceError> {
        let mut list: Vec<Arc<Registration>> = Vec::new();
        for path in paths {
            let raw = std::fs::read_to_string(path)
                .map_err(|error| AppserviceError::Unreadable(path.clone(), error.to_string()))?;
            let mut registration: Registration = serde_yaml::from_str(&raw)
                .map_err(|error| AppserviceError::Invalid(path.clone(), error.to_string()))?;
            for namespace in registration
                .namespaces
                .users
                .iter_mut()
                .chain(registration.namespaces.aliases.iter_mut())
                .chain(registration.namespaces.rooms.iter_mut())
            {
                namespace.compile()?;
            }
            if list.iter().any(|existing| {
                existing.id == registration.id || existing.as_token == registration.as_token
            }) {
                return Err(AppserviceError::Duplicate(registration.id));
            }
            list.push(Arc::new(registration));
        }
        Ok(Self { list })
    }

    /// The registration presenting `as_token`, if any.
    #[must_use]
    pub fn by_token(&self, token: &str) -> Option<&Arc<Registration>> {
        self.list
            .iter()
            .find(|registration| registration.as_token == token)
    }

    /// Every registration, for iteration by the transaction push.
    #[must_use]
    pub fn all(&self) -> &[Arc<Registration>] {
        &self.list
    }
}

/// At most this many events ride one transaction; the rest wait for the
/// next pass. The cap bounds the request the receiving bridge has to
/// swallow, not our scan — `stream_events` stops reading at the cap too.
const TRANSACTION_LIMIT: usize = 100;

/// One computed-but-unacknowledged transaction: its ID, its events, and
/// the stream position an acknowledgement advances the cursor to.
///
/// Held in memory until delivered so that every retry re-sends *this*
/// batch under *this* ID — recomputing on retry would fold newly arrived
/// events into the batch and change the ID, and the service's replay
/// table can only absorb a duplicate that is actually a duplicate. A
/// crash loses the struct and recomputes from the durable cursor, which
/// re-delivers under a fresh ID: at-least-once, exactly as promised.
struct PendingPush {
    txn_id: String,
    events: Vec<Value>,
    advance_to: u64,
}

/// The acknowledged stream position for one service, 0 for never-pushed.
fn read_cursor(store: &FjallStore, appservice_id: &str) -> u64 {
    ReadView::get(store, &spindle_core::keys::appservice_cursor(appservice_id))
        .ok()
        .flatten()
        .and_then(|raw| raw.get(..8).and_then(|bytes| bytes.try_into().ok()))
        .map_or(0, u64::from_be_bytes)
}

fn write_cursor(store: &FjallStore, appservice_id: &str, position: u64) {
    let _ = Store::put(
        store,
        &spindle_core::keys::appservice_cursor(appservice_id),
        &position.to_be_bytes(),
    );
}

/// The next batch for one service: interested events in
/// `(cursor, position]`, and the stream position the batch covers.
fn collect_batch(
    rooms: &Rooms,
    registration: &Registration,
    server_name: &str,
    cursor: u64,
    position: u64,
) -> Result<(Vec<Value>, u64), crate::rooms::RoomError> {
    let (records, advance_to) = rooms.stream_events(cursor, position, TRANSACTION_LIMIT)?;
    // Membership is asked once per room per batch, not once per event —
    // a busy room would otherwise pay a full member scan per message.
    let mut members_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut events = Vec::new();
    for (room_id, event) in records {
        let members = match members_of.entry(room_id.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                rooms
                    .joined_members(&room_id)
                    .map(|members| members.keys().cloned().collect())
                    .unwrap_or_default(),
            ),
        };
        let sender = event["sender"].as_str().unwrap_or_default();
        if registration.wants_event(&room_id, sender, members, server_name) {
            events.push(event);
        }
    }
    Ok((events, advance_to))
}

/// Deliver one transaction to the service's push URL.
async fn deliver(
    client: &reqwest::Client,
    url: &str,
    hs_token: &str,
    push: &PendingPush,
) -> Result<(), String> {
    let target = format!(
        "{}/_matrix/app/v1/transactions/{}",
        url.trim_end_matches('/'),
        push.txn_id
    );
    let response = client
        .put(target)
        .header("authorization", format!("Bearer {hs_token}"))
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(30))
        .body(serde_json::json!({ "events": push.events }).to_string())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("answered {}", response.status()));
    }
    Ok(())
}

/// Push transactions to every service with a URL, forever.
///
/// The same polling shape as the federation outbox drain, and for the
/// same reason: the empty-case scan is a bounded read, and the poll
/// interval doubles as the floor of the retry backoff. The cursor row
/// advances only on acknowledgement; a batch nothing in which interested
/// the service still advances the cursor durably — otherwise a service
/// whose rooms went quiet would re-scan the same dead range every pass,
/// forever.
pub async fn push_loop(
    store: Arc<FjallStore>,
    appservices: Arc<Appservices>,
    rooms: Arc<Rooms>,
    server_name: String,
    retry_base: Duration,
) {
    let client = reqwest::Client::new();
    let mut pending: HashMap<String, PendingPush> = HashMap::new();
    let mut backoff: HashMap<String, (u32, std::time::Instant)> = HashMap::new();
    loop {
        tokio::time::sleep(
            retry_base
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
        )
        .await;
        for registration in appservices.all() {
            let Some(url) = &registration.url else {
                continue;
            };
            if let Some((_, until)) = backoff.get(&registration.id)
                && *until > std::time::Instant::now()
            {
                continue;
            }
            if !pending.contains_key(&registration.id) {
                let cursor = read_cursor(&store, &registration.id);
                let position = rooms.stream_position();
                if position <= cursor {
                    continue;
                }
                let Ok((events, advance_to)) =
                    collect_batch(&rooms, registration, &server_name, cursor, position)
                else {
                    continue;
                };
                if events.is_empty() {
                    write_cursor(&store, &registration.id, advance_to);
                    continue;
                }
                pending.insert(
                    registration.id.clone(),
                    PendingPush {
                        // Deterministic by range, not by attempt: the range
                        // is pinned until acknowledged, so a retry reuses
                        // the ID and redelivery is a no-op on the service.
                        txn_id: format!("s{}-{advance_to}", cursor + 1),
                        events,
                        advance_to,
                    },
                );
            }
            let Some(push) = pending.get(&registration.id) else {
                continue;
            };
            match deliver(&client, url, &registration.hs_token, push).await {
                Ok(()) => {
                    write_cursor(&store, &registration.id, push.advance_to);
                    pending.remove(&registration.id);
                    backoff.remove(&registration.id);
                }
                Err(error) => {
                    tracing::debug!("appservice push to {}: {error}", registration.id);
                    let failures = backoff.get(&registration.id).map_or(0, |(count, _)| *count) + 1;
                    let delay = retry_base * 2_u32.saturating_pow(failures.min(6));
                    backoff.insert(
                        registration.id.clone(),
                        (failures, std::time::Instant::now() + delay),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_regexes_match_the_whole_id_not_a_substring() {
        let mut namespace = Namespace {
            exclusive: true,
            regex: "@bot:server".to_owned(),
            compiled: None,
        };
        namespace.compile().unwrap();
        assert!(namespace.matches("@bot:server"));
        // Unanchored, both of these would match by containment — and a
        // namespace that matches by containment is a claim over IDs the
        // registration never wrote down.
        assert!(!namespace.matches("@bot:serverextra"));
        assert!(!namespace.matches("x@bot:server"));
    }
}
