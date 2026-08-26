//! SPEC §5.3 / §13.3: the log chain is what makes a server's ordering
//! auditable rather than merely trusted.

use spindle_core::{ChainHash, EventInput, RoomLog, StateSnapshot};

fn room_with(events: &[&str]) -> RoomLog {
    let mut room = RoomLog::new();
    for event in events {
        room.append_local(*event, None).unwrap();
    }
    room
}

#[test]
fn the_same_sequence_always_produces_the_same_chain() {
    // Determinism is the precondition for everything else: two servers holding
    // the same history must be able to compare a single value and agree.
    assert_eq!(
        room_with(&["$a", "$b", "$c"]).head_chain(),
        room_with(&["$a", "$b", "$c"]).head_chain()
    );
}

#[test]
fn a_different_order_produces_a_different_chain() {
    // The same events in a different order are a different history, and the
    // chain says so. Without this the construction would attest to membership
    // but not to sequence, which is the only thing the serializer controls.
    assert_ne!(
        room_with(&["$a", "$b", "$c"]).head_chain(),
        room_with(&["$a", "$c", "$b"]).head_chain()
    );
}

#[test]
fn every_prefix_commits_to_everything_before_it() {
    let room = room_with(&["$a", "$b", "$c"]);
    let chains: Vec<ChainHash> = room.entries().filter_map(|entry| entry.chain).collect();
    assert_eq!(chains.len(), 3);

    // Recomputing forward from the seed reproduces every value, so any single
    // entry's chain pins the whole history up to it.
    let mut expected = ChainHash::seed();
    for (entry, recorded) in room.entries().zip(&chains) {
        expected = expected.extend(&entry.event_id);
        assert_eq!(&expected, recorded);
    }
    assert_eq!(room.head_chain(), chains[2]);
}

#[test]
fn a_divergence_is_visible_from_the_point_it_happens() {
    // The equivocation case from §13.3: a server that served one history and
    // later claims another cannot make the chains agree past the fork, and the
    // first differing index localises the lie.
    let honest = room_with(&["$a", "$b", "$c"]);
    let revised = room_with(&["$a", "$x", "$c"]);

    let honest_chains: Vec<_> = honest.entries().filter_map(|e| e.chain).collect();
    let revised_chains: Vec<_> = revised.entries().filter_map(|e| e.chain).collect();

    assert_eq!(honest_chains[0], revised_chains[0], "shared prefix agrees");
    assert_ne!(honest_chains[1], revised_chains[1], "divergence is caught");
    assert_ne!(
        honest_chains[2], revised_chains[2],
        "and never re-converges, even though $c is common to both"
    );
}

#[test]
fn backfilled_history_carries_no_attestation_and_does_not_disturb_the_chain() {
    let mut room = room_with(&["$a", "$b"]);
    let before = room.head_chain();

    room.prepend_remote(EventInput::new("$older", vec![]), StateSnapshot::new(), 40)
        .unwrap();

    // We did not sequence it, so we do not attest to it...
    let backfilled = room.entries().find(|entry| entry.li.get() == 0).unwrap();
    assert!(backfilled.chain.is_none());

    // ...and it leaves our own attestation untouched. A server's chain covers
    // what it ordered, not what a peer handed it.
    assert_eq!(room.head_chain(), before);

    // Appending after backfill continues from where we left off.
    room.append_local("$c", None).unwrap();
    assert_eq!(
        room.head_chain(),
        before.extend(&spindle_core::EventId::new("$c"))
    );
}

#[test]
fn the_seed_is_domain_separated_and_not_the_empty_hash() {
    // Guards against a refactor that seeds from an empty hasher: sharing an
    // input space with the state trie would let one construction's value be
    // replayed as the other's.
    assert_ne!(ChainHash::seed().as_bytes(), blake3::hash(b"").as_bytes());
    assert_ne!(
        ChainHash::seed().extend(&spindle_core::EventId::new("$a")),
        ChainHash::seed()
    );
}
