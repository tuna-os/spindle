//! Preserve imported decisions without changing new-event reconsideration.
use ruma::state_res::{StateMap, utils::event_id_set::EventIdSet};
use ruma::{OwnedEventId, RoomVersionId, events::StateEventType};
use serde_json::{Value, json};
use spindle_server::authorize::StoredEvent;
use std::collections::HashMap;

const ROOM: &str = "!history:example.org";
fn body(kind: &str, sender: &str, key: &str, time: u64, content: Value, auth: &[&str]) -> Value {
    let mut value = json!({"room_id":ROOM,"type":kind,"sender":sender,"state_key":key,
        "origin_server_ts":time,"prev_events":[],"auth_events":auth});
    value["content"] = content;
    value
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "seven explicit PDUs keep auth relationships reviewable"
)]
fn an_imported_rejected_ban_stays_rejected_while_a_new_rejection_can_be_reconsidered() {
    let bodies: HashMap<&str, Value> = HashMap::from([
        (
            "$create",
            body(
                "m.room.create",
                "@admin:example.org",
                "",
                1,
                json!({"creator":"@admin:example.org","room_version":"9"}),
                &[],
            ),
        ),
        (
            "$admin",
            body(
                "m.room.member",
                "@admin:example.org",
                "@admin:example.org",
                2,
                json!({"membership":"join"}),
                &["$create"],
            ),
        ),
        (
            "$powers",
            body(
                "m.room.power_levels",
                "@admin:example.org",
                "",
                3,
                json!({"users":{"@admin:example.org":100}}),
                &["$create", "$admin"],
            ),
        ),
        (
            "$public",
            body(
                "m.room.join_rules",
                "@admin:example.org",
                "",
                4,
                json!({"join_rule":"public"}),
                &["$create", "$admin", "$powers"],
            ),
        ),
        (
            "$join-a",
            body(
                "m.room.member",
                "@victim:example.org",
                "@victim:example.org",
                20,
                json!({"membership":"join"}),
                &["$create", "$powers", "$public"],
            ),
        ),
        (
            "$join-b",
            body(
                "m.room.member",
                "@victim:example.org",
                "@victim:example.org",
                30,
                json!({"membership":"join"}),
                &["$create", "$powers", "$public", "$join-a"],
            ),
        ),
        (
            "$rejected-ban",
            body(
                "m.room.member",
                "@admin:example.org",
                "@victim:example.org",
                40,
                json!({"membership":"ban"}),
                &["$create", "$powers", "$admin", "$join-b"],
            ),
        ),
    ]);
    let id = |value: &str| OwnedEventId::try_from(value).unwrap();
    let state = |join: &str| -> StateMap<OwnedEventId> {
        HashMap::from([
            ((StateEventType::RoomCreate, String::new()), id("$create")),
            (
                (StateEventType::RoomPowerLevels, String::new()),
                id("$powers"),
            ),
            (
                (StateEventType::RoomJoinRules, String::new()),
                id("$public"),
            ),
            (
                (StateEventType::RoomMember, "@admin:example.org".into()),
                id("$admin"),
            ),
            (
                (StateEventType::RoomMember, "@victim:example.org".into()),
                id(join),
            ),
        ])
    };
    let states = [state("$join-a"), state("$join-b")];
    let rules = RoomVersionId::try_from("9").unwrap().rules().unwrap();
    let ruma::room_version_rules::StateResolutionVersion::V2(v2) = &rules.state_res else {
        panic!("v9 uses state resolution v2")
    };
    let chains = || {
        vec![
            EventIdSet::from_iter([id("$rejected-ban")]),
            EventIdSet::new(),
        ]
    };
    let resolve = |imported| {
        ruma::state_res::resolve_with_candidate_policy(
            &rules.authorization,
            v2,
            states.iter(),
            chains(),
            |event_id| {
                StoredEvent::parse_auth_in(event_id.as_str(), ROOM, bodies.get(event_id.as_str())?)
                    .ok()
                    .map(|event| {
                        event
                            .with_rejected(event_id.as_str() == "$rejected-ban")
                            .with_preserved_rejection(
                                imported && event_id.as_str() == "$rejected-ban",
                            )
                    })
            },
            |_| None,
            |event| !event.preserved_rejection(),
        )
        .unwrap()
    };
    let key = (StateEventType::RoomMember, "@victim:example.org".into());
    assert_eq!(resolve(false)[&key], id("$rejected-ban"));
    assert_eq!(resolve(true)[&key], id("$join-b"));
}
