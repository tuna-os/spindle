//! The rules deciding what a client is notified about.
//!
//! Push rules are the one thing in the client-server API that is both account
//! data *and* an endpoint: the spec models a user's ruleset as an
//! `m.push_rules` account-data event, and also gives `/pushrules/` its own
//! surface for reading and editing it. Both are implemented here over one
//! stored value, so a client that reads `/sync` and a client that reads
//! `/pushrules/` can never disagree.
//!
//! Nothing here evaluates a rule against an event yet — that belongs with the
//! notification count (#81), which is where the answer would be used. What
//! this module owns is the ruleset's *shape*: the defaults every user starts
//! with, the five kinds and their order, and the edits a client may make.

use serde_json::{Value, json};

/// The five rule kinds, **in the order they are evaluated**.
///
/// The order is not alphabetical and not arbitrary: the spec fixes it, and a
/// server that got it wrong would notify correctly for most events and
/// silently differently for the ones where two kinds both match. Kept as one
/// array so that every place needing the order reads it from here.
pub const KINDS: [&str; 5] = ["override", "content", "room", "sender", "underride"];

/// The account-data type a ruleset is stored and delivered under.
pub const TYPE: &str = "m.push_rules";

/// Rule IDs beginning with a dot are the server's.
///
/// A client may enable, disable, and re-action a default rule, but may not
/// create one -- the dot is what marks a rule as having a meaning the server
/// defined rather than one the user did.
#[must_use]
pub fn is_server_default(rule_id: &str) -> bool {
    rule_id.starts_with('.')
}

/// The ruleset a user has before they have changed anything.
///
/// Built per-user because three of the defaults name the user: the mention
/// rules match their user ID and the content rule matches their localpart. A
/// shared constant would notify everyone for everyone else's name.
#[must_use]
pub fn defaults(user_id: &str) -> Value {
    json!({
        "override": overrides(user_id),
        "content": content(user_id),
        "room": [],
        "sender": [],
        "underride": underrides(),
    })
}

/// The kind evaluated first, so it is where the rules that *suppress* live:
/// once an override matches, nothing after it is consulted.
fn overrides(user_id: &str) -> Value {
    json!([
        rule(".m.rule.master", false, json!([]), json!([])),
        rule(
            ".m.rule.suppress_notices",
            true,
            json!([event_match("content.msgtype", "m.notice")]),
            json!([]),
        ),
        rule(
            ".m.rule.invite_for_me",
            true,
            json!([
                event_match("type", "m.room.member"),
                event_match("content.membership", "invite"),
                event_match("state_key", user_id),
            ]),
            notify_with_sound("default"),
        ),
        rule(
            ".m.rule.member_event",
            true,
            json!([event_match("type", "m.room.member")]),
            json!([]),
        ),
        rule(
            ".m.rule.is_user_mention",
            true,
            json!([{
                "kind": "event_property_contains",
                "key": r"content.m\.mentions.user_ids",
                "value": user_id,
            }]),
            notify_highlight(),
        ),
        rule(
            ".m.rule.is_room_mention",
            true,
            json!([
                {
                    "kind": "event_property_is",
                    "key": r"content.m\.mentions.room",
                    "value": true,
                },
                { "kind": "sender_notification_permission", "key": "room" },
            ]),
            notify_highlight(),
        ),
        rule(
            ".m.rule.tombstone",
            true,
            json!([
                event_match("type", "m.room.tombstone"),
                event_match("state_key", ""),
            ]),
            notify_highlight(),
        ),
        rule(
            ".m.rule.reaction",
            true,
            json!([event_match("type", "m.reaction")]),
            json!([]),
        ),
        rule(
            ".m.rule.room.server_acl",
            true,
            json!([
                event_match("type", "m.room.server_acl"),
                event_match("state_key", ""),
            ]),
            json!([]),
        ),
    ])
}

/// A content rule carries a `pattern` instead of conditions -- the pattern
/// *is* the condition, matched against the message body.
///
/// The pattern is the localpart rather than the full user ID, because it is
/// matched against prose: people write "alice", not "@alice:example.org".
fn content(user_id: &str) -> Value {
    let localpart = user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split(':').next())
        .unwrap_or(user_id);
    json!([{
        "rule_id": ".m.rule.contains_user_name",
        "default": true,
        "enabled": true,
        "pattern": localpart,
        "actions": notify_highlight_with_sound("default"),
    }])
}

/// The kind evaluated last, so it is the catch-all: `.m.rule.message` is what
/// notifies for an ordinary message nothing more specific claimed.
fn underrides() -> Value {
    json!([
        rule(
            ".m.rule.call",
            true,
            json!([event_match("type", "m.call.invite")]),
            notify_with_sound("ring"),
        ),
        rule(
            ".m.rule.encrypted_room_one_to_one",
            true,
            json!([
                { "kind": "room_member_count", "is": "2" },
                event_match("type", "m.room.encrypted"),
            ]),
            notify_with_sound("default"),
        ),
        rule(
            ".m.rule.room_one_to_one",
            true,
            json!([
                { "kind": "room_member_count", "is": "2" },
                event_match("type", "m.room.message"),
            ]),
            notify_with_sound("default"),
        ),
        rule(
            ".m.rule.message",
            true,
            json!([event_match("type", "m.room.message")]),
            json!(["notify"]),
        ),
        rule(
            ".m.rule.encrypted",
            true,
            json!([event_match("type", "m.room.encrypted")]),
            json!(["notify"]),
        ),
    ])
}

/// Built by moving `conditions` and `actions` into the map rather than through
/// `json!`, which would only borrow them -- and a helper that borrows what it
/// is handed is one every caller has to clone for.
fn rule(rule_id: &str, enabled: bool, conditions: Value, actions: Value) -> Value {
    let mut rule = serde_json::Map::with_capacity(5);
    rule.insert("rule_id".to_owned(), Value::String(rule_id.to_owned()));
    rule.insert("default".to_owned(), Value::Bool(true));
    rule.insert("enabled".to_owned(), Value::Bool(enabled));
    rule.insert("conditions".to_owned(), conditions);
    rule.insert("actions".to_owned(), actions);
    Value::Object(rule)
}

fn event_match(key: &str, pattern: &str) -> Value {
    json!({ "kind": "event_match", "key": key, "pattern": pattern })
}

fn notify_with_sound(sound: &str) -> Value {
    json!(["notify", { "set_tweak": "sound", "value": sound }])
}

fn notify_highlight() -> Value {
    json!(["notify", { "set_tweak": "highlight" }])
}

fn notify_highlight_with_sound(sound: &str) -> Value {
    json!([
        "notify",
        { "set_tweak": "sound", "value": sound },
        { "set_tweak": "highlight" },
    ])
}

/// Find a rule by kind and ID, returning its index within that kind's array.
#[must_use]
pub fn position(ruleset: &Value, kind: &str, rule_id: &str) -> Option<usize> {
    ruleset
        .get(kind)?
        .as_array()?
        .iter()
        .position(|rule| rule["rule_id"] == rule_id)
}

/// Insert or replace a rule within its kind.
///
/// A new rule goes to the *front* of its kind, because the spec orders rules
/// within a kind by priority and a client that has just written a rule means
/// it to win. Replacing one leaves it where it was: an edit is not a
/// re-prioritisation, and silently promoting an edited rule would reorder a
/// ruleset the client did not ask to reorder.
pub fn upsert(ruleset: &mut Value, kind: &str, rule_id: &str, mut rule: Value) {
    rule["rule_id"] = Value::String(rule_id.to_owned());
    let existing = position(ruleset, kind, rule_id);
    let Some(rules) = ruleset[kind].as_array_mut() else {
        return;
    };
    match existing {
        Some(index) => rules[index] = rule,
        None => rules.insert(0, rule),
    }
}

/// Remove a rule, reporting whether it was there.
pub fn remove(ruleset: &mut Value, kind: &str, rule_id: &str) -> bool {
    let Some(index) = position(ruleset, kind, rule_id) else {
        return false;
    };
    let Some(rules) = ruleset[kind].as_array_mut() else {
        return false;
    };
    rules.remove(index);
    true
}
