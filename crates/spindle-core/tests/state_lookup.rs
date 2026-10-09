use std::collections::HashMap;

use spindle_core::{StateKey, StateSnapshot};

#[test]
fn persisted_lookup_reads_only_the_requested_path() {
    let mut state = StateSnapshot::new();
    for i in 0..20_000 {
        state = state.apply(
            StateKey::new("m.room.member", format!("@user{i}:example.org")),
            format!("$event{i}"),
        );
    }
    let nodes: HashMap<_, _> = state.delta_nodes(None).into_iter().collect();
    for user in [0, 1, 10_000, 19_999, 20_001] {
        let key = StateKey::new("m.room.member", format!("@user{user}:example.org"));
        let mut reads = 0;
        let found = StateSnapshot::get_persisted(state.root(), &key, &mut |root| {
            reads += 1;
            nodes.get(root).cloned()
        })
        .unwrap();
        assert_eq!(found.as_deref(), state.get(&key));
        assert!(reads <= 53, "read {reads} nodes for one state slot");
    }
}

#[test]
fn lookup_checks_node_addresses_and_missing_nodes() {
    let key = StateKey::new("m.room.topic", "");
    let state = StateSnapshot::new().apply(key.clone(), "$topic");
    assert_eq!(
        StateSnapshot::get_persisted(state.root(), &key, &mut |_| None),
        Err(spindle_core::RehydrateError::MissingNode)
    );
    let mut bytes = state.delta_nodes(None).pop().unwrap().1;
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        StateSnapshot::get_persisted(state.root(), &key, &mut |_| Some(bytes.clone())),
        Err(spindle_core::RehydrateError::HashMismatch)
    );
    assert_eq!(
        StateSnapshot::get_persisted(StateSnapshot::new().root(), &key, &mut |_| panic!(
            "empty state needs no reads"
        )),
        Ok(None)
    );
}
