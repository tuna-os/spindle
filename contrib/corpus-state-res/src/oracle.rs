//! Diagnostic v2 oracle using complete auth chains instead of the ranked walk.

use std::collections::{HashMap, HashSet};

use ruma::room_version_rules::StateResolutionVersion;
use ruma::state_res::utils::event_id_set::EventIdSet;
use ruma::{OwnedEventId, RoomVersionId};
use serde_json::{Value, json};
use spindle_core::{StateKey, StateSnapshot};
use spindle_server::authorize::StoredEvent;

pub fn compare(
    room: &str,
    parents: &[&StateSnapshot],
    bodies: &HashMap<String, Value>,
    rejected: &[String],
    expected: &StateSnapshot,
    live: &StateSnapshot,
    ignore: Option<&StateKey>,
) -> Value {
    let version = bodies
        .values()
        .find(|body| body["type"] == "m.room.create")
        .and_then(|body| body["content"]["room_version"].as_str())
        .unwrap_or("1");
    let Ok(version) = RoomVersionId::try_from(version) else {
        return json!({"error": "unknown version"});
    };
    let Some(rules) = version.rules() else {
        return json!({"error": "no rules"});
    };
    let StateResolutionVersion::V2(v2) = &rules.state_res else {
        return json!({"unsupported": version.as_str()});
    };
    if v2.consider_conflicted_state_subgraph {
        return json!({"unsupported": "v2.1 requires a subgraph oracle"});
    }
    let maps: Vec<ruma::state_res::StateMap<OwnedEventId>> = parents
        .iter()
        .map(|state| {
            let mut map = ruma::state_res::StateMap::new();
            state.for_each(|key, id| {
                if let Ok(id) = OwnedEventId::try_from(id) {
                    map.insert(
                        (
                            ruma::events::StateEventType::from(key.event_type().as_str()),
                            key.state_key().to_owned(),
                        ),
                        id,
                    );
                }
            });
            map
        })
        .collect();
    let chains: Vec<EventIdSet<OwnedEventId>> = maps
        .iter()
        .map(|map| {
            let mut chain = EventIdSet::new();
            let mut pending: Vec<OwnedEventId> = map.values().cloned().collect();
            while let Some(id) = pending.pop() {
                if !chain.insert(id.clone()) {
                    continue;
                }
                if let Some(edges) = bodies
                    .get(id.as_str())
                    .and_then(|body| body["auth_events"].as_array())
                {
                    pending.extend(edges.iter().filter_map(|edge| {
                        let id = edge.as_str().or_else(|| edge[0].as_str())?;
                        OwnedEventId::try_from(id).ok()
                    }));
                }
            }
            chain
        })
        .collect();
    let rejected: HashSet<&str> = rejected.iter().map(String::as_str).collect();
    let fetch = |id: &ruma::EventId| {
        StoredEvent::parse_auth_in(id.as_str(), room, bodies.get(id.as_str())?)
            .ok()
            .map(|event| event.with_rejected(rejected.contains(id.as_str())))
    };
    match ruma::state_res::resolve(&rules.authorization, v2, maps.iter(), chains, fetch, |_| {
        None
    }) {
        Ok(map) => {
            let mut snapshot = StateSnapshot::new();
            for ((kind, key), id) in map {
                snapshot = snapshot.apply(StateKey::new(kind.to_string(), key), id.as_str());
            }
            let differs = |other: &StateSnapshot| {
                snapshot
                    .diff(other)
                    .into_iter()
                    .filter(|(key, _, _)| Some(*key) != ignore)
                    .count()
            };
            json!({"differs_from_synapse": differs(expected), "differs_from_live": differs(live)})
        }
        Err(error) => json!({"error": error.to_string()}),
    }
}
