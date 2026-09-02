//! The rules deciding what a client is notified about.
//!
//! Push rules are the one thing in the client-server API that is both account
//! data *and* an endpoint: the spec models a user's ruleset as an
//! `m.push_rules` account-data event, and also gives `/pushrules/` its own
//! surface for reading and editing it. Both are implemented here over one
//! stored value, so a client that reads `/sync` and a client that reads
//! `/pushrules/` can never disagree.
//!
//! This module owns the ruleset's *shape* -- the defaults every user starts
//! with, the five kinds and their order, and the edits a client may make --
//! and, in [`evaluate`], what the rules say about one event: the question
//! `/notifications` asks of every event it walks past.

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

/// What the evaluator knows beyond the event and the ruleset: who is asking,
/// and the room as it stands.
pub struct Context<'a> {
    /// The reader, whose ruleset this is.
    pub user_id: &'a str,
    /// Their display name, for `contains_display_name`; `None` matches nothing.
    pub display_name: Option<&'a str>,
    /// The room, for the room-kind rules.
    pub room_id: &'a str,
    /// Joined members, for `room_member_count`.
    pub member_count: usize,
    /// The room's `m.room.power_levels` content, for
    /// `sender_notification_permission`; an empty object is the defaults.
    pub power_levels: &'a Value,
}

/// The actions of the first enabled rule that matches `event`, if they say
/// to notify.
///
/// Kinds in [`KINDS`] order and rules in their stored order, first match
/// wins, exactly as the spec has it; a rule of a kind that carries no
/// conditions (`room`, `sender`) matches on its ID, and a `content` rule on
/// its pattern against the body. A condition of a kind this server does
/// not know matches nothing, which the spec also asks for: an unknown
/// condition must not be a rule that fires for everything.
///
/// `None` is "do not notify" -- no rule matched, or the one that did says
/// `dont_notify`, `coalesce`, or nothing at all (the master rule and the
/// suppressions are empty action lists). A reader's own events are their
/// caller's business: this asks the rules and nothing else.
#[must_use]
pub fn evaluate(ruleset: &Value, event: &Value, context: &Context<'_>) -> Option<Vec<Value>> {
    for kind in KINDS {
        let Some(rules) = ruleset.get(kind).and_then(Value::as_array) else {
            continue;
        };
        for rule in rules {
            if rule["enabled"] != true {
                continue;
            }
            let matched = match kind {
                "content" => rule["pattern"]
                    .as_str()
                    .is_some_and(|pattern| body_contains(event, pattern)),
                "room" => rule["rule_id"] == context.room_id,
                "sender" => rule["rule_id"] == event["sender"],
                _ => rule["conditions"].as_array().is_some_and(|conditions| {
                    conditions
                        .iter()
                        .all(|condition| condition_holds(condition, event, context))
                }),
            };
            if !matched {
                continue;
            }
            let actions = rule["actions"].as_array().cloned().unwrap_or_default();
            return actions
                .iter()
                .any(|action| action == "notify")
                .then_some(actions);
        }
    }
    None
}

/// Whether `actions` ask for a highlight: the `set_tweak: highlight` tweak,
/// present without a value (which means `true`) or with `true`.
#[must_use]
pub fn is_highlight(actions: &[Value]) -> bool {
    actions.iter().any(|action| {
        action["set_tweak"] == "highlight" && action.get("value").is_none_or(|value| value == true)
    })
}

fn condition_holds(condition: &Value, event: &Value, context: &Context<'_>) -> bool {
    match condition["kind"].as_str() {
        Some("event_match") => {
            let (Some(key), Some(pattern)) =
                (condition["key"].as_str(), condition["pattern"].as_str())
            else {
                return false;
            };
            let Some(text) = property(event, key).and_then(Value::as_str) else {
                return false;
            };
            // The body is prose, so the pattern may sit anywhere in it on
            // word boundaries; every other key is matched whole.
            if key == "content.body" {
                glob(pattern, true).is_some_and(|glob| glob.is_match(text))
            } else {
                glob(pattern, false).is_some_and(|glob| glob.is_match(text))
            }
        }
        Some("event_property_is") => property(event, condition["key"].as_str().unwrap_or_default())
            .is_some_and(|value| *value == condition["value"]),
        Some("event_property_contains") => {
            property(event, condition["key"].as_str().unwrap_or_default())
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(&condition["value"]))
        }
        Some("contains_display_name") => context.display_name.is_some_and(|name| {
            !name.is_empty() && body_contains(event, &name.replace(['*', '?'], ""))
        }),
        Some("room_member_count") => condition["is"]
            .as_str()
            .is_some_and(|is| member_count_is(is, context.member_count)),
        Some("sender_notification_permission") => {
            let key = condition["key"].as_str().unwrap_or_default();
            let required = context.power_levels["notifications"][key]
                .as_i64()
                .unwrap_or(50);
            let sender = event["sender"].as_str().unwrap_or_default();
            let level = context.power_levels["users"][sender]
                .as_i64()
                .or_else(|| context.power_levels["users_default"].as_i64())
                .unwrap_or(0);
            level >= required
        }
        _ => false,
    }
}

/// Does the message body contain `pattern`, as a word-bounded,
/// case-insensitive glob?
fn body_contains(event: &Value, pattern: &str) -> bool {
    event["content"]["body"]
        .as_str()
        .is_some_and(|body| glob(pattern, true).is_some_and(|glob| glob.is_match(body)))
}

/// The spec's `is` for `room_member_count`: a number with an optional
/// comparison in front, `==` when there is none.
fn member_count_is(is: &str, count: usize) -> bool {
    let (operator, number) = ["==", "<=", ">=", "<", ">"]
        .into_iter()
        .find_map(|operator| is.strip_prefix(operator).map(|rest| (operator, rest)))
        .unwrap_or(("==", is));
    let Ok(wanted) = number.trim().parse::<usize>() else {
        return false;
    };
    match operator {
        "<" => count < wanted,
        ">" => count > wanted,
        "<=" => count <= wanted,
        ">=" => count >= wanted,
        _ => count == wanted,
    }
}

/// The value at a dotted path into an event, where `\.` is a literal dot
/// (the spec's spelling for keys like `content.m\.mentions.user_ids`).
fn property<'a>(event: &'a Value, key: &str) -> Option<&'a Value> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = key.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'.') => {
                current.push('.');
                chars.next();
            }
            '.' => parts.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    parts.push(current);
    parts.iter().try_fold(event, |node, part| node.get(part))
}

/// A push-rule glob as a regex: `*` is anything, `?` is one character,
/// everything else is literal, and the match is case-insensitive. `bounded`
/// is the body form, which may sit anywhere in the text on word boundaries;
/// unbounded must cover the whole value. `None` only if the regex engine
/// refuses what was built, which nothing here should be able to make it
/// do; a rule that cannot be compiled matches nothing.
fn glob(pattern: &str, bounded: bool) -> Option<regex::Regex> {
    let mut source = String::from("(?i)");
    let first_is_word = pattern
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let last_is_word = pattern
        .chars()
        .last()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    if bounded {
        if first_is_word {
            source.push_str("\\b");
        }
    } else {
        source.push('^');
    }
    for c in pattern.chars() {
        match c {
            '*' => source.push_str(".*"),
            '?' => source.push('.'),
            other => source.push_str(&regex::escape(&other.to_string())),
        }
    }
    if bounded {
        if last_is_word {
            source.push_str("\\b");
        }
    } else {
        source.push('$');
    }
    regex::Regex::new(&source).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(sender: &str, body: &str) -> Value {
        json!({
            "type": "m.room.message",
            "sender": sender,
            "content": { "msgtype": "m.text", "body": body },
        })
    }

    fn context(power_levels: &Value, member_count: usize) -> Context<'_> {
        Context {
            user_id: "@alice:example.org",
            display_name: Some("Alice Liddell"),
            room_id: "!room:example.org",
            member_count,
            power_levels,
        }
    }

    #[test]
    fn a_plain_message_notifies_under_the_catch_all_and_a_notice_does_not() {
        let ruleset = defaults("@alice:example.org");
        let levels = json!({});
        let actions = evaluate(
            &ruleset,
            &message("@bob:example.org", "hello"),
            &context(&levels, 3),
        );
        assert_eq!(actions, Some(vec![json!("notify")]));
        let mut notice = message("@bob:example.org", "hello");
        notice["content"]["msgtype"] = json!("m.notice");
        assert_eq!(evaluate(&ruleset, &notice, &context(&levels, 3)), None);
    }

    #[test]
    fn the_name_and_a_mention_highlight_and_a_substring_of_the_name_does_not() {
        let ruleset = defaults("@alice:example.org");
        let levels = json!({});
        let by_name = evaluate(
            &ruleset,
            &message("@bob:example.org", "ALICE, look"),
            &context(&levels, 3),
        );
        assert!(by_name.as_deref().is_some_and(is_highlight), "{by_name:?}");
        let substring = evaluate(
            &ruleset,
            &message("@bob:example.org", "malice"),
            &context(&levels, 3),
        );
        assert!(
            substring
                .as_deref()
                .is_some_and(|actions| !is_highlight(actions)),
            "{substring:?}"
        );
        let mut mention = message("@bob:example.org", "hey");
        mention["content"]["m.mentions"] = json!({ "user_ids": ["@alice:example.org"] });
        let mentioned = evaluate(&ruleset, &mention, &context(&levels, 3));
        assert!(
            mentioned.as_deref().is_some_and(is_highlight),
            "{mentioned:?}"
        );
    }

    #[test]
    fn a_room_mention_needs_the_power_and_a_one_to_one_room_rings() {
        let ruleset = defaults("@alice:example.org");
        let mut at_room = message("@bob:example.org", "everyone");
        at_room["content"]["m.mentions"] = json!({ "room": true });
        let levels =
            json!({ "users": { "@bob:example.org": 50 }, "notifications": { "room": 50 } });
        assert!(
            evaluate(&ruleset, &at_room, &context(&levels, 3))
                .as_deref()
                .is_some_and(is_highlight)
        );
        let too_low = json!({ "users": { "@bob:example.org": 10 } });
        let actions = evaluate(&ruleset, &at_room, &context(&too_low, 3));
        assert!(
            actions
                .as_deref()
                .is_some_and(|actions| !is_highlight(actions)),
            "{actions:?}"
        );
        let rings = evaluate(
            &ruleset,
            &message("@bob:example.org", "hi"),
            &context(&levels, 2),
        );
        assert!(
            rings
                .as_deref()
                .is_some_and(|actions| actions.iter().any(|a| a["set_tweak"] == "sound")),
            "{rings:?}"
        );
    }

    #[test]
    fn the_master_switch_and_a_disabled_catch_all_silence_a_message() {
        let mut ruleset = defaults("@alice:example.org");
        let levels = json!({});
        let index = position(&ruleset, "underride", ".m.rule.message").unwrap();
        ruleset["underride"][index]["enabled"] = json!(false);
        assert_eq!(
            evaluate(
                &ruleset,
                &message("@bob:example.org", "hi"),
                &context(&levels, 3)
            ),
            None
        );
        let mut ruleset = defaults("@alice:example.org");
        ruleset["override"][0]["enabled"] = json!(true);
        assert_eq!(
            evaluate(
                &ruleset,
                &message("@bob:example.org", "alice"),
                &context(&levels, 3)
            ),
            None
        );
    }

    #[test]
    fn room_and_sender_rules_match_on_their_ids_and_an_unknown_condition_never_does() {
        let mut ruleset = defaults("@alice:example.org");
        let levels = json!({});
        upsert(
            &mut ruleset,
            "room",
            "!room:example.org",
            json!({ "enabled": true, "actions": ["dont_notify"] }),
        );
        assert_eq!(
            evaluate(
                &ruleset,
                &message("@bob:example.org", "hi"),
                &context(&levels, 3)
            ),
            None
        );
        let mut ruleset = defaults("@alice:example.org");
        upsert(
            &mut ruleset,
            "sender",
            "@bob:example.org",
            json!({ "enabled": true, "actions": ["notify", { "set_tweak": "highlight" }] }),
        );
        assert!(
            evaluate(
                &ruleset,
                &message("@bob:example.org", "hi"),
                &context(&levels, 3)
            )
            .as_deref()
            .is_some_and(is_highlight)
        );
        let mut ruleset = defaults("@alice:example.org");
        upsert(
            &mut ruleset,
            "override",
            "mystery",
            json!({ "enabled": true, "conditions": [{ "kind": "from_the_future" }], "actions": [] }),
        );
        assert_eq!(
            evaluate(
                &ruleset,
                &message("@bob:example.org", "hi"),
                &context(&levels, 3)
            ),
            Some(vec![json!("notify")])
        );
    }

    #[test]
    fn an_event_match_on_the_body_sits_on_word_boundaries_and_elsewhere_covers_the_value() {
        let mut ruleset = defaults("@alice:example.org");
        let levels = json!({});
        upsert(
            &mut ruleset,
            "override",
            "cake",
            json!({
                "enabled": true,
                "conditions": [{ "kind": "event_match", "key": "content.body", "pattern": "cake" }],
                "actions": ["notify", { "set_tweak": "highlight" }],
            }),
        );
        let in_prose = evaluate(
            &ruleset,
            &message("@bob:example.org", "I like cake"),
            &context(&levels, 3),
        );
        assert!(
            in_prose.as_deref().is_some_and(is_highlight),
            "{in_prose:?}"
        );
        let inside_a_word = evaluate(
            &ruleset,
            &message("@bob:example.org", "pancakes"),
            &context(&levels, 3),
        );
        assert!(
            inside_a_word.as_deref().is_some_and(|a| !is_highlight(a)),
            "{inside_a_word:?}"
        );
        upsert(
            &mut ruleset,
            "override",
            "text",
            json!({
                "enabled": true,
                "conditions": [{ "kind": "event_match", "key": "content.msgtype", "pattern": "m.te*" }],
                "actions": ["notify", { "set_tweak": "sound", "value": "ping" }],
            }),
        );
        let whole = evaluate(
            &ruleset,
            &message("@bob:example.org", "hello"),
            &context(&levels, 3),
        );
        assert!(
            whole
                .as_deref()
                .is_some_and(|a| a.iter().any(|t| t["value"] == "ping")),
            "{whole:?}"
        );
        let mut emote = message("@bob:example.org", "hello");
        emote["content"]["msgtype"] = json!("x.m.text");
        let partial = evaluate(&ruleset, &emote, &context(&levels, 3));
        assert!(
            partial
                .as_deref()
                .is_some_and(|a| !a.iter().any(|t| t["value"] == "ping")),
            "{partial:?}"
        );
    }

    #[test]
    fn member_count_comparisons_and_globs() {
        assert!(member_count_is("2", 2));
        assert!(member_count_is("<3", 2));
        assert!(member_count_is(">=2", 2));
        assert!(!member_count_is(">2", 2));
        assert!(!member_count_is("many", 2));
        assert!(glob("cake*", true).unwrap().is_match("I like cakes"));
        assert!(!glob("cake", true).unwrap().is_match("pancakes"));
        assert!(glob("m.notice", false).unwrap().is_match("M.NOTICE"));
        assert!(!glob("m.notice", false).unwrap().is_match("m.notice.extra"));
        assert!(
            glob("@*:example.org", false)
                .unwrap()
                .is_match("@bob:example.org")
        );
    }
}
