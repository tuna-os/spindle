//! Push: telling a user's devices about the events their rules say to
//! notify about, through the gateways those devices registered.
//!
//! A pusher (`pushers.rs`) is a promise a client extracted from this
//! server: "when my rules say notify, call this URL". This module keeps
//! it. It walks the global stream the way the appservice push does, asks
//! every reader's ruleset about every event, and delivers the spec's
//! notification body to each gateway a matching reader registered.
//!
//! **Where the walk stops is not where delivery stops.** The one durable
//! cursor (`Keyspace::PushCursor`) advances once a batch has been read and
//! judged; what the judgement produced waits in memory, queued per
//! gateway, until that gateway acknowledges it. So a gateway that is down
//! delays only its own devices, and a crash loses only what was queued --
//! which is the trade a push notification can make: a badge that arrives
//! twice or a ring that arrives after the caller gave up is noise, and a
//! notification path that stalls every phone for one dead gateway is
//! worse than noise.
//!
//! **A pusher URL is an outbound fetch somebody else chose**, which makes
//! it the same request-forgery vector as a URL preview, and it is judged
//! by the same `netguard`: the address it resolves to is vetted at every
//! delivery, a literal address is vetted before the request is built, and
//! a redirect is vetted hop by hop. A registration is refused up front for
//! what can be seen up front -- the scheme, the spec's path, a literal
//! address inside the network -- so a client learns at `/pushers/set`
//! rather than by never being notified.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use spindle_store::{FjallStore, ReadView, Store};

use crate::account_data::AccountData;
use crate::netguard::{Cidr, VettingResolver, parse_allow_list, permits, redirect_policy};
use crate::profiles::Profiles;
use crate::pushers::Pushers;
use crate::rooms::Rooms;

/// The path the spec fixes for every push gateway.
pub const NOTIFY_PATH: &str = "/_matrix/push/v1/notify";

/// Events one pass reads from the stream. A burst larger than this is
/// walked over several passes, each advancing the cursor, so a backlog
/// after a restart is bounded work per tick rather than one long read.
const BATCH_LIMIT: usize = 256;

/// Notifications one gateway may have waiting. Past this the oldest is
/// dropped: a gateway that has been unreachable for a thousand
/// notifications is not going to want the first of them.
const QUEUE_CAP: usize = 1_000;

/// Attempts at one notification before it is dropped. With the retry
/// base doubling to 64× that is the better part of two minutes at the
/// default base, which is longer than any ring and long enough for a
/// gateway to come back from a restart.
const MAX_ATTEMPTS: u32 = 8;

/// The client every push goes through, and the judgement on where it may
/// go.
pub struct Gateway {
    client: reqwest::Client,
    allowed: Vec<Cidr>,
}

impl Gateway {
    /// # Errors
    ///
    /// Returns the first allow-list entry that does not parse -- a config
    /// error surfaced at startup, because a typo'd range that silently
    /// matched nothing is a judgement that fails in a way nobody sees.
    pub fn new(allow_internal: &[String]) -> Result<Self, String> {
        let allowed = parse_allow_list(allow_internal)?;
        let resolver = Arc::new(VettingResolver {
            allowed: allowed.clone(),
        });
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(redirect_policy(allowed.clone(), "pushable"))
            .timeout(Duration::from_secs(30))
            .user_agent("spindle-push")
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self { client, allowed })
    }

    /// Whether `url` is one this server will deliver to.
    ///
    /// Three things can be judged without a network: the scheme, the path
    /// the spec fixes, and a literal address -- which never touches DNS,
    /// so the resolver that vets every hostname would never see it. A
    /// hostname passes here and is judged by what it resolves to at each
    /// delivery.
    ///
    /// # Errors
    ///
    /// Returns why the URL is refused, in words meant for the client.
    pub fn vet_url(&self, url: &str) -> Result<(), String> {
        let parsed: reqwest::Url = url
            .parse()
            .map_err(|_| "data.url is not a URL".to_owned())?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("a pusher URL must be http or https".to_owned());
        }
        if parsed.path() != NOTIFY_PATH {
            return Err(format!("a pusher URL's path must be {NOTIFY_PATH}"));
        }
        if let Ok(literal) = parsed
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            && !permits(&self.allowed, literal)
        {
            return Err("that address is not one this server delivers push to".to_owned());
        }
        Ok(())
    }

    /// Deliver one notification. `Ok` carries the pushkeys the gateway
    /// reported `rejected`; `Err` says whether the attempt is worth
    /// repeating.
    async fn notify(&self, url: &str, body: &Value) -> Result<Vec<String>, Failure> {
        // A registration that was fine when it was stored may name an
        // address the allow-list no longer covers; the resolver cannot
        // catch a literal, so the judgement is repeated here.
        self.vet_url(url).map_err(Failure::Permanent)?;
        let response = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| Failure::Transient(error.to_string()))?;
        let status = response.status();
        if status.is_success() {
            let answer: Value = response
                .bytes()
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null);
            return Ok(answer["rejected"]
                .as_array()
                .map(|keys| {
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default());
        }
        // A gateway that says "you are wrong" will say it again; one that
        // says "not now" (429) or "I am broken" (5xx) may not.
        if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(Failure::Permanent(format!("gateway answered {status}")))
        } else {
            Err(Failure::Transient(format!("gateway answered {status}")))
        }
    }
}

enum Failure {
    /// Retry after a backoff.
    Transient(String),
    /// Do not retry this notification.
    Permanent(String),
}

/// What the loop reads, held weakly for the reason `spawn_delivery_loops`
/// gives: the loop must never be the store's last owner.
pub struct Sources {
    pub store: Weak<FjallStore>,
    pub rooms: Weak<Rooms>,
    pub pushers: Weak<Pushers>,
    pub account_data: Weak<AccountData>,
    pub profiles: Weak<Profiles>,
    pub gateway: Weak<Gateway>,
}

/// One notification body bound for one gateway, with the pushkeys it
/// carries so a `rejected` answer can be acted on.
struct Pending {
    user_id: String,
    body: Value,
    /// `(app_id, pushkey)` of every device in the body.
    devices: Vec<(String, String)>,
    attempts: u32,
}

/// The delivery loop: walk the stream, judge, queue, send.
///
/// A pass reads what the stream gained since the cursor, judges every
/// event for every reader with a pusher, queues the notifications per
/// gateway URL and advances the cursor; then it sends the head of every
/// queue whose gateway is not backing off. One request per gateway per
/// pass keeps a gateway's notifications in the order they happened, which
/// is the order a badge count has to arrive in to be right at the end.
///
/// Ends once the router is gone, like every delivery loop here.
pub async fn deliver_loop(sources: Sources, retry_base: Duration) {
    let mut queues: HashMap<String, VecDeque<Pending>> = HashMap::new();
    let mut backoff: HashMap<String, (u32, Instant)> = HashMap::new();
    loop {
        tokio::time::sleep(
            retry_base
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
        )
        .await;
        // Plan under the strong references, send under none: a request in
        // flight to a gateway that never answers must not be what keeps
        // the store open while the runtime shuts down (#292).
        let (Some(store), Some(rooms), Some(pushers), Some(account_data), Some(profiles)) = (
            sources.store.upgrade(),
            sources.rooms.upgrade(),
            sources.pushers.upgrade(),
            sources.account_data.upgrade(),
            sources.profiles.upgrade(),
        ) else {
            return;
        };
        let Some(gateway) = sources.gateway.upgrade() else {
            return;
        };

        let cursor = read_cursor(&store);
        let position = rooms.stream_position();
        if position > cursor {
            let mut pass = Pass {
                rooms: &rooms,
                pushers: &pushers,
                account_data: &account_data,
                profiles: &profiles,
                pushers_of: HashMap::new(),
                rulesets: HashMap::new(),
                facts: HashMap::new(),
            };
            match rooms.stream_events(cursor, position, BATCH_LIMIT) {
                Ok((records, advance_to)) => {
                    for (room_id, event) in records {
                        for (url, pending) in pass.notifications_for(&room_id, &event) {
                            let queue = queues.entry(url).or_default();
                            if queue.len() >= QUEUE_CAP {
                                queue.pop_front();
                            }
                            queue.push_back(pending);
                        }
                    }
                    write_cursor(&store, advance_to);
                }
                Err(error) => tracing::warn!("push: reading the stream: {error}"),
            }
        }
        drop((store, rooms, pushers, account_data, profiles));

        // One notification per gateway per pass, taken from the queues
        // that are not backing off. The gateway client owns no store.
        let now = Instant::now();
        let due: Vec<(String, Pending)> = queues
            .iter_mut()
            .filter(|(url, _)| backoff.get(*url).is_none_or(|(_, until)| *until <= now))
            .filter_map(|(url, queue)| queue.pop_front().map(|pending| (url.clone(), pending)))
            .collect();
        queues.retain(|_, queue| !queue.is_empty());

        let mut removals: Vec<(String, String, String)> = Vec::new();
        for (url, mut pending) in due {
            match gateway.notify(&url, &pending.body).await {
                Ok(rejected) => {
                    backoff.remove(&url);
                    for (app_id, pushkey) in &pending.devices {
                        if rejected.contains(pushkey) {
                            // The gateway has said this device is gone
                            // (the app was uninstalled, the token
                            // revoked). The spec has the homeserver
                            // remove the pusher, and nothing else would.
                            removals.push((
                                pending.user_id.clone(),
                                app_id.clone(),
                                pushkey.clone(),
                            ));
                        }
                    }
                }
                Err(Failure::Permanent(why)) => {
                    tracing::debug!("push to {url} dropped: {why}");
                }
                Err(Failure::Transient(why)) => {
                    tracing::debug!("push to {url}: {why}");
                    pending.attempts += 1;
                    if pending.attempts < MAX_ATTEMPTS {
                        queues.entry(url.clone()).or_default().push_front(pending);
                    }
                    let failures = backoff.get(&url).map_or(0, |(count, _)| *count) + 1;
                    let delay = retry_base * 2_u32.saturating_pow(failures.min(6));
                    backoff.insert(url, (failures, Instant::now() + delay));
                }
            }
        }
        if !removals.is_empty() {
            // The registrations outlive a shutdown either way: a rejected
            // pushkey the loop could not forget is forgotten on the next
            // answer from that gateway.
            let Some(pushers) = sources.pushers.upgrade() else {
                return;
            };
            for (user_id, app_id, pushkey) in removals {
                let _ = pushers.remove(&user_id, &app_id, &pushkey);
            }
        }
    }
}

/// The room facts the rules ask about, gathered once per room per pass.
struct RoomFacts {
    members: Arc<Vec<String>>,
    power_levels: Value,
    name: Option<String>,
    alias: Option<String>,
}

/// What one pass has already looked up, so a busy room does not pay a
/// member scan, a ruleset read and a profile read per event per reader.
struct Pass<'a> {
    rooms: &'a Rooms,
    pushers: &'a Pushers,
    account_data: &'a AccountData,
    profiles: &'a Profiles,
    pushers_of: HashMap<String, Vec<Value>>,
    rulesets: HashMap<String, Value>,
    facts: HashMap<String, RoomFacts>,
}

impl Pass<'_> {
    /// Every notification `event` produces: one per `(reader, gateway,
    /// format)`, carrying every device of that reader on that gateway.
    fn notifications_for(&mut self, room_id: &str, event: &Value) -> Vec<(String, Pending)> {
        let sender = event["sender"].as_str().unwrap_or_default().to_owned();
        let Some(facts) = self.facts_of(room_id) else {
            return Vec::new();
        };
        // The readers: everyone joined, and -- for an invite -- the one
        // person the event is addressed to, who is not joined yet and is
        // exactly who `.m.rule.invite_for_me` exists to reach.
        let mut readers: Vec<String> = facts.members.iter().cloned().collect();
        if event["type"] == "m.room.member"
            && event["content"]["membership"] == "invite"
            && let Some(invitee) = event["state_key"].as_str()
            && !readers.iter().any(|reader| reader == invitee)
        {
            readers.push(invitee.to_owned());
        }
        let member_count = facts.members.len();
        let power_levels = facts.power_levels.clone();
        let room_name = facts.name.clone();
        let room_alias = facts.alias.clone();
        let sender_display_name = self.display_name_in(room_id, &sender);

        let mut out = Vec::new();
        for reader in readers {
            // A reader's own events never notify: the spec's one rule the
            // ruleset does not spell out.
            if reader == sender {
                continue;
            }
            let http_pushers: Vec<Value> = self
                .pushers_for(&reader)
                .iter()
                .filter(|pusher| pusher["kind"] == "http" && pusher["data"]["url"].is_string())
                .cloned()
                .collect();
            if http_pushers.is_empty() {
                continue;
            }
            let ruleset = self.ruleset_of(&reader);
            let display_name = self.profiles.get(&reader).ok().and_then(|p| p.displayname);
            let context = crate::push_rules::Context {
                user_id: &reader,
                display_name: display_name.as_deref(),
                room_id,
                member_count,
                power_levels: &power_levels,
            };
            let Some(actions) = crate::push_rules::evaluate(&ruleset, event, &context) else {
                continue;
            };
            let tweaks = tweaks_of(&actions);
            let unread = self.unread_of(&reader);

            // One body per gateway per format: the spec lets devices on
            // the same gateway share a request, and the two formats say
            // different things.
            let mut by_gateway: BTreeMap<(String, bool), Vec<Value>> = BTreeMap::new();
            for pusher in http_pushers {
                let url = pusher["data"]["url"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let id_only = pusher["data"]["format"] == "event_id_only";
                let mut data = pusher["data"].clone();
                if let Some(object) = data.as_object_mut() {
                    object.remove("url");
                }
                by_gateway.entry((url, id_only)).or_default().push(json!({
                    "app_id": pusher["app_id"],
                    "pushkey": pusher["pushkey"],
                    "data": data,
                    "tweaks": tweaks,
                }));
            }
            for ((url, id_only), devices) in by_gateway {
                let device_ids = devices
                    .iter()
                    .map(|device| {
                        (
                            device["app_id"].as_str().unwrap_or_default().to_owned(),
                            device["pushkey"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect();
                let body = notification_body(
                    event,
                    room_id,
                    &reader,
                    id_only,
                    unread,
                    &tweaks,
                    sender_display_name.as_deref(),
                    room_name.as_deref(),
                    room_alias.as_deref(),
                    devices,
                );
                out.push((
                    url,
                    Pending {
                        user_id: reader.clone(),
                        body,
                        devices: device_ids,
                        attempts: 0,
                    },
                ));
            }
        }
        out
    }

    fn facts_of(&mut self, room_id: &str) -> Option<&RoomFacts> {
        if !self.facts.contains_key(room_id) {
            let members = self.rooms.joined_member_ids(room_id).ok()?;
            // `state_event_unscoped` answers with the event's content.
            let state = |event_type: &str, field: &str| {
                self.rooms
                    .state_event_unscoped(room_id, event_type, "")
                    .ok()
                    .and_then(|content| content[field].as_str().map(str::to_owned))
            };
            let facts = RoomFacts {
                members,
                power_levels: self
                    .rooms
                    .state_event_unscoped(room_id, "m.room.power_levels", "")
                    .unwrap_or_else(|_| json!({})),
                name: state("m.room.name", "name"),
                alias: state("m.room.canonical_alias", "alias"),
            };
            self.facts.insert(room_id.to_owned(), facts);
        }
        self.facts.get(room_id)
    }

    fn pushers_for(&mut self, user_id: &str) -> &Vec<Value> {
        if !self.pushers_of.contains_key(user_id) {
            let pushers = self.pushers.list(user_id).unwrap_or_default();
            self.pushers_of.insert(user_id.to_owned(), pushers);
        }
        &self.pushers_of[user_id]
    }

    fn ruleset_of(&mut self, user_id: &str) -> Value {
        if !self.rulesets.contains_key(user_id) {
            let ruleset = self
                .account_data
                .get(user_id, "", crate::push_rules::TYPE)
                .ok()
                .flatten()
                .unwrap_or_else(|| crate::push_rules::defaults(user_id));
            self.rulesets.insert(user_id.to_owned(), ruleset);
        }
        self.rulesets[user_id].clone()
    }

    /// The sender as the room knows them, falling back to their profile.
    fn display_name_in(&self, room_id: &str, user_id: &str) -> Option<String> {
        self.rooms
            .state_event_unscoped(room_id, "m.room.member", user_id)
            .ok()
            .and_then(|content| content["displayname"].as_str().map(str::to_owned))
            .or_else(|| self.profiles.get(user_id).ok().and_then(|p| p.displayname))
    }

    /// The badge: what the reader has not read across every room they are
    /// in, the same number `/sync` reports.
    fn unread_of(&self, user_id: &str) -> usize {
        self.rooms
            .joined(user_id)
            .unwrap_or_default()
            .iter()
            .map(|room_id| {
                self.rooms
                    .unread(room_id, user_id)
                    .map_or(0, |unread| unread.notification_count)
            })
            .sum()
    }
}

/// The `set_tweak` actions as the object the gateway expects: a tweak
/// with no value is `true`.
fn tweaks_of(actions: &[Value]) -> Value {
    let mut tweaks = serde_json::Map::new();
    for action in actions {
        if let Some(name) = action["set_tweak"].as_str() {
            tweaks.insert(
                name.to_owned(),
                action.get("value").cloned().unwrap_or(Value::Bool(true)),
            );
        }
    }
    Value::Object(tweaks)
}

/// The spec's notification object.
///
/// `prio` is what the gateway uses to decide whether to wake the device:
/// high for anything with a sound or a highlight -- a ring is a highlight,
/// through `m.mentions` -- and for an encrypted event, which the device
/// has to decrypt before it can know. `event_id_only` strips the body to
/// what its name says: the device fetches the rest itself, and a gateway
/// asked for that format is one the client does not trust with content.
#[allow(clippy::too_many_arguments)]
fn notification_body(
    event: &Value,
    room_id: &str,
    reader: &str,
    id_only: bool,
    unread: usize,
    tweaks: &Value,
    sender_display_name: Option<&str>,
    room_name: Option<&str>,
    room_alias: Option<&str>,
    devices: Vec<Value>,
) -> Value {
    let mut notification = serde_json::Map::new();
    notification.insert("event_id".to_owned(), event["event_id"].clone());
    notification.insert("room_id".to_owned(), json!(room_id));
    notification.insert("counts".to_owned(), json!({ "unread": unread }));
    notification.insert("devices".to_owned(), Value::Array(devices));
    if !id_only {
        let loud = tweaks["highlight"]
            .as_bool()
            .unwrap_or(tweaks["highlight"].is_string())
            || tweaks.get("sound").is_some()
            || event["type"] == "m.room.encrypted";
        notification.insert("prio".to_owned(), json!(if loud { "high" } else { "low" }));
        notification.insert("type".to_owned(), event["type"].clone());
        notification.insert("sender".to_owned(), event["sender"].clone());
        notification.insert("content".to_owned(), event["content"].clone());
        if let Some(name) = sender_display_name {
            notification.insert("sender_display_name".to_owned(), json!(name));
        }
        if let Some(name) = room_name {
            notification.insert("room_name".to_owned(), json!(name));
        }
        if let Some(alias) = room_alias {
            notification.insert("room_alias".to_owned(), json!(alias));
        }
        if event["type"] == "m.room.member" && event["state_key"] == reader {
            notification.insert("user_is_target".to_owned(), Value::Bool(true));
        }
    }
    json!({ "notification": Value::Object(notification) })
}

/// The stream position every event at or below which has been judged; 0
/// for never.
fn read_cursor(store: &FjallStore) -> u64 {
    ReadView::get(store, &spindle_core::keys::push_cursor())
        .ok()
        .flatten()
        .and_then(|raw| raw.get(..8).and_then(|bytes| bytes.try_into().ok()))
        .map_or(0, u64::from_be_bytes)
}

fn write_cursor(store: &FjallStore, position: u64) {
    let _ = Store::put(
        store,
        &spindle_core::keys::push_cursor(),
        &position.to_be_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pusher_url_is_judged_on_what_can_be_seen_without_a_network() {
        let gateway = Gateway::new(&[]).unwrap();
        assert!(
            gateway
                .vet_url("https://push.example.org/_matrix/push/v1/notify")
                .is_ok()
        );
        assert!(
            gateway
                .vet_url("http://push.example.org/_matrix/push/v1/notify")
                .is_ok()
        );
        // The wrong path is a URL that is not a push gateway, whatever host it names.
        assert!(gateway.vet_url("https://push.example.org/notify").is_err());
        assert!(
            gateway
                .vet_url("ftp://push.example.org/_matrix/push/v1/notify")
                .is_err()
        );
        assert!(gateway.vet_url("not a url").is_err());
        // A literal inside address never reaches DNS, so it is refused here.
        assert!(
            gateway
                .vet_url("http://127.0.0.1:9000/_matrix/push/v1/notify")
                .is_err()
        );
        assert!(
            gateway
                .vet_url("http://169.254.169.254/_matrix/push/v1/notify")
                .is_err()
        );
        assert!(
            gateway
                .vet_url("http://[::1]/_matrix/push/v1/notify")
                .is_err()
        );
        // Listing the range opens it back up.
        let opened = Gateway::new(&["127.0.0.0/8".to_owned()]).unwrap();
        assert!(
            opened
                .vet_url("http://127.0.0.1:9000/_matrix/push/v1/notify")
                .is_ok()
        );
    }

    #[test]
    fn a_bad_allow_list_entry_is_refused_at_construction() {
        assert!(Gateway::new(&["not-a-range".to_owned()]).is_err());
    }

    #[test]
    fn tweaks_are_rendered_as_the_gateway_expects() {
        let actions = vec![
            json!("notify"),
            json!({ "set_tweak": "sound", "value": "default" }),
            json!({ "set_tweak": "highlight" }),
        ];
        assert_eq!(
            tweaks_of(&actions),
            json!({ "sound": "default", "highlight": true })
        );
    }

    #[test]
    fn a_highlight_or_a_sound_is_high_priority_and_id_only_strips_the_body() {
        let event = json!({
            "event_id": "$e", "type": "m.room.message", "sender": "@alice:x",
            "content": { "body": "hi" },
        });
        let devices = vec![json!({ "app_id": "a", "pushkey": "k", "data": {}, "tweaks": {} })];
        let quiet = notification_body(
            &event,
            "!r",
            "@bob:x",
            false,
            3,
            &json!({}),
            None,
            None,
            None,
            devices.clone(),
        );
        assert_eq!(quiet["notification"]["prio"], "low");
        assert_eq!(quiet["notification"]["counts"]["unread"], 3);
        assert_eq!(quiet["notification"]["content"]["body"], "hi");
        let loud = notification_body(
            &event,
            "!r",
            "@bob:x",
            false,
            3,
            &json!({ "highlight": true }),
            Some("Alice"),
            Some("The room"),
            None,
            devices.clone(),
        );
        assert_eq!(loud["notification"]["prio"], "high");
        assert_eq!(loud["notification"]["sender_display_name"], "Alice");
        assert_eq!(loud["notification"]["room_name"], "The room");
        let stripped = notification_body(
            &event,
            "!r",
            "@bob:x",
            true,
            3,
            &json!({ "highlight": true }),
            Some("Alice"),
            None,
            None,
            devices,
        );
        assert_eq!(stripped["notification"]["event_id"], "$e");
        assert!(stripped["notification"].get("content").is_none());
        assert!(stripped["notification"].get("sender").is_none());
        assert!(stripped["notification"].get("prio").is_none());
    }
}
