//! Auth selection for signed federation fixtures, from their actual parent state.

use serde_json::Value;
use spindle_core::StateKey;
use spindle_server::rooms::Rooms;
use spindle_store::FjallStore;
use std::sync::Arc;

pub fn with_auth_events(store: &Arc<FjallStore>, mut pdu: Value) -> Value {
    let rooms = Rooms::new(store.clone(), "example.org");
    let room = pdu["room_id"].as_str().unwrap();
    let parent = pdu["prev_events"][0].as_str().unwrap();
    let Ok(mut state) = rooms.state_before_event(room, parent) else {
        // Some hostile fixtures deliberately name an unknown room or parent.
        return pdu;
    };
    let previous = rooms.pdu(room, parent).unwrap();
    if let Some(key) = previous["state_key"].as_str() {
        state = state.apply(
            StateKey::new(previous["type"].as_str().unwrap(), key),
            parent,
        );
    }
    let version = rooms.room_version(room).unwrap();
    let event_type = ruma::events::TimelineEventType::from(pdu["type"].as_str().unwrap());
    let sender = ruma::UserId::parse(pdu["sender"].as_str().unwrap()).unwrap();
    let content = serde_json::value::to_raw_value(&pdu["content"]).unwrap();
    let keys = ruma::state_res::auth_types_for_event(
        &event_type,
        &sender,
        pdu["state_key"].as_str(),
        &content,
        &version.rules().unwrap().authorization,
    )
    .unwrap();
    let ids: Vec<_> = keys
        .into_iter()
        .filter_map(|(kind, key)| {
            state
                .get(&StateKey::new(kind.to_string(), key))
                .map(str::to_owned)
        })
        .collect();
    pdu["auth_events"] = serde_json::json!(ids);
    pdu
}
