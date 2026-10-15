# State-key migration performance

Schema 2 to 3 changes state-key placement and node hashes. Historical room
snapshots use path copies, so two near v2 roots usually share almost all of
their nodes. A full rebuild of each root makes the conversion cost equal to
the history length multiplied by the size of the room state.

The offline migration now verifies the first v2 root in full. Then it compares
each next v2 trie with the trie before it, by address. Equal subtrees stop the
traversal. The migration applies the changed slots to the previous converted
snapshot, and it stages only the changed v3 nodes. For leaf/branch
transitions, additions, removals and empty state, the migration walks the full
affected subtree.

The migration keeps a memo of each repeated root. A nonadjacent repeat
discards the incremental baseline. The migration possibly staged the converted
nodes of that root, and these nodes are possibly not yet on disk.

On a partial retry, the migration checks the converted roots with a bounded
memo. The memo keeps the addresses and depths of v3 subtrees that it verified
in full. Thus the migration does not keep historical snapshot graphs, and it
does not check their shared descendants again. Each memo is for one room, one
store and one intern table. It is valid only while those nodes do not change.

The memo keeps a maximum of 1,000,000 entries. An eviction discards the memo.
This causes more verification work, but the result does not change. The server
paths continue to use their snapshot decoder and weak node cache.

The conversion walks also collect the old node addresses. This set includes
the first full root and each changed subtree that the migration reaches after
it. Deletion still waits until the migration converts all rooms. Each chunk
commit still includes the new intern rows, the new nodes and the rewritten
records. The schema marker moves forward only after success. The backup from
before the migration stays the rollback method.

A retry can leave old nodes that no root reaches. These nodes come from
records that an interrupted run committed. The migration before this change
also lets this occur.

## Regression measurement

Run:

```sh
cargo test -p spindle-store --test state_migration --locked -- --nocapture
```

The deterministic fixture has 2,048 membership slots and 64 revisions, with
replacements, additions and removals. The test compares each incremental root
with a full conversion against the same table. It also rehydrates each node
delta that the migration keeps. The measured loader calls are:

| Work | Full traversal | Incremental / memoized |
| --- | ---: | ---: |
| V2 conversion across 64 revisions | 176,885 | 488 |
| V3 validation across 64 revisions | 176,448 | 253 |

These numbers are node reads for this fixture. They are not a production
latency or an estimate of the completion time. Each regression test must show
a decrease in reads of more than 100 times. Other checks cover these items:

- root/leaf/branch/empty transitions
- missing and corrupt changed nodes
- memo eviction
- shared nodes across rooms
- staged repeated roots
- a new open after a committed chunk and a failure

The migration prints the room ordinal. Then it prints the checked records over
the counted room total every 15 seconds and at the last record of the room.
The node-loader calls and the elapsed time follow the count. The count for the
last record comes before the tail commit. The deletion phase and the last
schema result are separate from it. Rooms can be much different in size, so
the room ordinals do not give a total percentage or an ETA.
