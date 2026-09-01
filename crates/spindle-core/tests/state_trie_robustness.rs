//! Part of #267, target 4: feed the state trie's node decoder bytes it
//! never wrote.
//!
//! Nodes are content-addressed and loaded by hash, so a wrong byte "cannot
//! happen" -- which is exactly the assumption worth testing, because the
//! check that would catch it runs after the node has been decoded and its
//! children rebuilt, not before. Two things in that window were fatal
//! rather than refusable: an entry count the node had no bytes to back,
//! which sized an allocation from a number off disk, and a child pointer
//! aimed back up the trie, which recursed until the stack was gone. Neither
//! returns. A failed allocation and a stack overflow both abort the
//! process, so each is measured from a child process whose exit status the
//! parent can read.

use std::collections::HashMap;
use std::process::Command;

use proptest::prelude::*;
use spindle_core::{RehydrateError, StateKey, StateRoot, StateSnapshot};

/// The environment variable that turns this test binary into the child.
const CASE: &str = "SPINDLE_HOSTILE_TRIE";

const TAG_LEAF: u8 = 0;
const TAG_BRANCH: u8 = 1;

// -- hostile nodes --------------------------------------------------------

/// A leaf well-formed up to its entry count, which then claims `entries`.
fn leaf_claiming(entries: u32) -> Vec<u8> {
    let mut node = vec![TAG_LEAF];
    node.extend_from_slice(&[0; 32]); // digest
    node.extend_from_slice(&entries.to_be_bytes());
    node
}

/// A branch well-formed up to its child count, which then claims `children`.
fn branch_claiming(children: u32) -> Vec<u8> {
    let mut node = vec![TAG_BRANCH];
    node.extend_from_slice(&1_u32.to_be_bytes()); // bitmap
    node.extend_from_slice(&children.to_be_bytes());
    node
}

/// A branch with one child, at `child`.
fn branch_to(child: &StateRoot) -> Vec<u8> {
    let mut node = branch_claiming(1);
    node.extend_from_slice(child.as_bytes());
    node
}

/// A real snapshot with enough entries to have branches under its root, and
/// every node it is made of.
fn honest_trie(entries: usize) -> (StateSnapshot, HashMap<StateRoot, Vec<u8>>) {
    let mut snapshot = StateSnapshot::new();
    for index in 0..entries {
        snapshot = snapshot.apply(
            StateKey::new("m.room.member", format!("@user{index}:example.org")),
            format!("$event{index}"),
        );
    }
    let nodes = snapshot.delta_nodes(None).into_iter().collect();
    (snapshot, nodes)
}

fn load_from(
    nodes: &HashMap<StateRoot, Vec<u8>>,
) -> impl FnMut(&StateRoot) -> Option<Vec<u8>> + '_ {
    move |address| nodes.get(address).cloned()
}

// -- the instrument -------------------------------------------------------

/// Run one named case in a child and report whether it came back.
fn survives(case: &str) -> bool {
    Command::new(std::env::current_exe().expect("this test binary"))
        .args(["rehydrates_one_hostile_trie", "--exact"])
        .env(CASE, case)
        .status()
        .expect("to run the child")
        .success()
}

/// The child. A no-op in the ordinary run; the whole point when the parent
/// sets [`CASE`].
#[test]
fn rehydrates_one_hostile_trie() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    let address = StateRoot::from_bytes([9; 32]);
    let node = match case.as_str() {
        "leaf" => leaf_claiming(u32::MAX),
        "branch" => branch_claiming(u32::MAX),
        // The branch's one child is itself: a trie that never bottoms out.
        "cycle" => branch_to(&address),
        other => panic!("no such case: {other}"),
    };
    let outcome = StateSnapshot::rehydrate(address, &mut |_: &StateRoot| Some(node.clone()));
    assert_eq!(outcome.map(|_| ()), Err(RehydrateError::Malformed));
}

#[test]
fn a_leaf_allocates_for_the_bytes_it_has_not_the_ones_it_claims() {
    // 37 bytes claiming 4_294_967_295 entries: before the bound, a
    // `Vec::with_capacity` of 206 GiB, and a failed allocation aborts.
    assert!(
        survives("leaf"),
        "a 37-byte leaf claiming u32::MAX entries took the process down"
    );
}

#[test]
fn a_branch_allocates_for_the_bytes_it_has_not_the_ones_it_claims() {
    assert!(
        survives("branch"),
        "a 9-byte branch claiming u32::MAX children took the process down"
    );
}

#[test]
fn a_trie_that_never_bottoms_out_is_refused_not_followed() {
    // 41 bytes whose one child pointer is its own address. The hash check
    // would refuse this node -- after rebuilding its children, which means
    // after rebuilding itself, forever. Before the depth bound that was a
    // stack overflow, which no caller can catch.
    assert!(
        survives("cycle"),
        "a branch whose child is itself took the process down"
    );
}

/// The realistic shape of the cycle: not a node that names itself, which
/// no honest encoder writes, but a real trie with one child pointer
/// corrupted to an ancestor's address.
#[test]
fn a_child_pointer_aimed_at_an_ancestor_is_refused() {
    let (snapshot, mut nodes) = honest_trie(200);
    let root = snapshot.root();
    let root_bytes = nodes.get(&root).expect("the root is stored").clone();
    assert_eq!(
        root_bytes.first(),
        Some(&TAG_BRANCH),
        "200 entries need a branch"
    );

    // Point the root's first child back at the root.
    let mut corrupt = root_bytes;
    corrupt[9..41].copy_from_slice(root.as_bytes());
    nodes.insert(root, corrupt);

    let outcome = StateSnapshot::rehydrate(root, &mut load_from(&nodes));
    assert_eq!(outcome.map(|_| ()), Err(RehydrateError::Malformed));
}

/// The other half of the bounds: honest counts are still believed and
/// honest depths still reached. A decoder that refused everything would
/// pass every test above.
#[test]
fn an_honest_trie_still_rehydrates() {
    let (snapshot, nodes) = honest_trie(2_000);
    let rebuilt =
        StateSnapshot::rehydrate(snapshot.root(), &mut load_from(&nodes)).expect("a real trie");
    assert_eq!(rebuilt.root(), snapshot.root());
    assert_eq!(rebuilt.len(), 2_000);
    snapshot.for_each(|key, event_id| assert_eq!(rebuilt.get(key), Some(event_id)));
}

// -- fuzzing --------------------------------------------------------------

proptest! {
    /// Bytes off the floor, served for every address asked.
    #[test]
    fn arbitrary_nodes_rehydrate_or_refuse(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let outcome = StateSnapshot::rehydrate(
            StateRoot::from_bytes([1; 32]),
            &mut |_: &StateRoot| Some(bytes.clone()),
        );
        prop_assert!(outcome.is_err());
    }

    /// A real root node that lost its tail, at every possible cut.
    #[test]
    fn truncated_nodes_rehydrate_or_refuse(entries in 1_usize..64) {
        let (snapshot, mut nodes) = honest_trie(entries);
        let root = snapshot.root();
        let whole = nodes.get(&root).expect("the root is stored").clone();
        for cut in 0..whole.len() {
            nodes.insert(root, whole[..cut].to_vec());
            let outcome = StateSnapshot::rehydrate(root, &mut load_from(&nodes));
            prop_assert!(outcome.is_err(), "a root cut to {cut} bytes rehydrated");
        }
    }

    /// A real root node whose length prefixes lie: every four-byte window
    /// overwritten with an arbitrary `u32`.
    #[test]
    fn lying_lengths_rehydrate_or_refuse(entries in 1_usize..64, claimed: u32) {
        let (snapshot, mut nodes) = honest_trie(entries);
        let root = snapshot.root();
        let whole = nodes.get(&root).expect("the root is stored").clone();
        for at in 0..whole.len().saturating_sub(4) {
            let mut corrupt = whole.clone();
            corrupt[at..at + 4].copy_from_slice(&claimed.to_be_bytes());
            nodes.insert(root, corrupt);
            let outcome = StateSnapshot::rehydrate(root, &mut load_from(&nodes));
            // A window that happens to hold what was already there is the
            // honest node; anything else must be refused.
            if whole[at..at + 4] != claimed.to_be_bytes() {
                prop_assert!(outcome.is_err(), "{claimed} at offset {at} rehydrated");
            }
        }
    }
}
