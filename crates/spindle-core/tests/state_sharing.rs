//! SPEC §6.1: updating one state slot must copy a path, not a state.
//!
//! The timing benchmark in `benches/state_snapshot.rs` cannot show this
//! cleanly — allocation cost is buried in wall clock and varies by allocator.
//! Node count is exact, and it is the property the design actually rests on.

use spindle_core::{StateKey, StateSnapshot};

fn seeded(count: usize) -> StateSnapshot {
    let mut state = StateSnapshot::new();
    for number in 0..count {
        state = state.apply(
            StateKey::new("m.room.member", format!("@user{number}:example.org")),
            format!("$event-{number}"),
        );
    }
    state
}

#[test]
fn one_update_creates_a_path_not_a_copy() {
    // Across two orders of magnitude of state, the number of nodes a single
    // update creates should stay flat. If it tracks state size, path copying
    // has been lost and every state event is writing the whole room.
    let mut counts = Vec::new();

    for size in [100_usize, 1_000, 10_000] {
        let before = seeded(size);
        let after = before.apply(StateKey::new("m.room.topic", ""), "$topic");

        let created = after.delta_nodes(Some(&before)).len();
        counts.push((size, created));

        assert!(
            created <= 8,
            "updating one slot in a {size}-entry state created {created} nodes"
        );
    }

    // Flat, not growing: the 10,000-entry case must not cost meaningfully more
    // than the 100-entry one.
    let smallest = counts.first().unwrap().1;
    let largest = counts.last().unwrap().1;
    assert!(
        largest <= smallest + 3,
        "nodes per update grew with state size: {counts:?}"
    );
}

#[test]
fn an_unchanged_state_creates_nothing() {
    let state = seeded(500);
    assert!(
        state.delta_nodes(Some(&state)).is_empty(),
        "a snapshot compared against itself shares every node"
    );
}

#[test]
fn rewriting_a_slot_to_the_same_value_still_shares_the_rest() {
    let before = seeded(1_000);
    let after = before.apply(
        StateKey::new("m.room.member", "@user0:example.org"),
        "$event-0",
    );

    // Identical content means identical content addresses, so nothing is new.
    assert_eq!(after.root(), before.root());
    assert!(after.delta_nodes(Some(&before)).is_empty());
}

/// `for_each` promises key order, and the server's `/state` renders its
/// response straight from that walk. The guarantee had no test: removing the
/// sort passed the entire workspace, because a handful of keys happen to come
/// out of the trie already in order. It takes enough of them to spread across
/// the trie's branches before the digest's own arrangement shows through.
#[test]
fn for_each_visits_in_key_order_however_the_trie_arranged_them() {
    let mut snapshot = StateSnapshot::new();
    for index in 0..256 {
        snapshot = snapshot.apply(
            StateKey::new("m.room.member", format!("@user{index:03}:example.org")),
            format!("$event{index}"),
        );
    }
    // Mixed types too: the order is over the whole key, not the state key alone.
    for kind in ["m.room.create", "m.room.topic", "m.room.avatar"] {
        snapshot = snapshot.apply(StateKey::new(kind, ""), format!("${kind}"));
    }

    let mut seen = Vec::new();
    snapshot.for_each(|key, _| {
        seen.push((
            key.event_type().as_str().to_owned(),
            key.state_key().to_owned(),
        ));
    });

    let mut expected = seen.clone();
    expected.sort();
    assert_eq!(seen, expected, "for_each visited entries out of key order");
    assert_eq!(seen.len(), 259);
}

/// State roots are content addresses: they name nodes in the store and appear
/// in every `LogEntry`. A change to how they are computed is a change to the
/// on-disk format, whatever the code looked like — so the values are frozen
/// here rather than left to be noticed by whatever breaks first.
///
/// Written while attempting a hashing optimisation that turned out to be a
/// regression and was reverted. The test outlived it, because the question it
/// answers — "did this change what we write to disk?" — is one every future
/// attempt at the same optimisation has to answer, and answering it by
/// inspection is how a format break ships unnoticed.
#[test]
fn state_roots_are_the_bytes_they_have_always_been() {
    let hex =
        |bytes: &[u8; 32]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };

    let mut state = StateSnapshot::new();
    for (kind, key, event_id, expected) in [
        (
            "m.room.create",
            "",
            "$create",
            "8bf5ea045e582975ee64c1dce97c448c3bdb5c0085eb9f631fa7f0b826fb51bc",
        ),
        (
            "m.room.member",
            "@alice:example.org",
            "$alice",
            "3097222177726e1a763c7efdd60a1b3d1610c87f77826b2571f6f9c5cde8e7bb",
        ),
        (
            "m.room.power_levels",
            "",
            "$power",
            "f3f1ae40f6229e21044c0c6d39bacd960939dd03f2b960823902a6310355d397",
        ),
    ] {
        state = state.apply(StateKey::new(kind, key), event_id);
        assert_eq!(hex(state.root().as_bytes()), expected, "after {kind}");
    }

    // A state key far larger than anything a fixed hashing buffer would hold.
    // Any implementation that special-cases short inputs has to produce the
    // same digest here, or one unusually long key would silently address
    // different nodes from every other key in the same room.
    let long = format!("@{}:example.org", "x".repeat(2000));
    let spilled = StateSnapshot::new().apply(StateKey::new("m.room.member", long), "$long");
    assert_eq!(
        hex(spilled.root().as_bytes()),
        "0504f8fc05f0d0a7ef74d2d29bb14d23e47c4882dce9c44b97dca457ac2ae24e",
        "a state key that overflows the hashing buffer changed its digest"
    );
}
