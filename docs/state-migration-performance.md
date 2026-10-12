# State-key migration performance

Schema 2 to 3 changes state-key placement and node hashes. Historical room
snapshots use path copying, so nearby v2 roots normally share nearly all their
nodes. Rebuilding every root in full makes conversion cost proportional to
history length multiplied by room-state size.

The offline migration now verifies the first v2 root in full and compares
successive v2 tries by address. Equal subtrees stop the traversal. Changed slots
are applied to the previous converted snapshot, and only its changed v3 nodes
are staged. Leaf/branch transitions, additions, removals and empty state fall
back to walking the affected subtree. A repeated root is memoized; a
nonadjacent repeat discards the incremental baseline because its converted
nodes may still be staged rather than readable from disk.

On a partial retry, already converted roots are checked with a bounded memo of
fully verified v3 subtree addresses and depths. This avoids retaining historical
snapshot graphs or rechecking their shared descendants. The memo is scoped to
one room, one store and one intern table; it is valid only while those nodes
remain immutable. It stores at most 1,000,000 entries. Eviction discards the memo
and costs extra verification work without changing the result. Serving paths
continue to use their existing snapshot decoder and weak node cache.

Old-node addresses are collected during the same conversion walks. Their union
includes the initial complete root and every subsequently reached changed
subtree. Deletion still waits until all rooms have converted. Chunk commits
still include newly allocated intern rows, new nodes and rewritten records;
the schema marker advances only after success. The pre-migration backup remains
the rollback method. A retry may leave unreachable old nodes from records
committed by an earlier interrupted attempt, as the existing migration permits.

## Regression measurement

Run:

```sh
cargo test -p spindle-store --test state_migration --locked -- --nocapture
```

The deterministic fixture has 2,048 membership slots and 64 revisions, including
replacements, additions and removals. Every incremental root is compared with a
full conversion against the same table, and every persisted node delta is
rehydrated. The measured loader calls are:

| Work | Full traversal | Incremental / memoized |
| --- | ---: | ---: |
| V2 conversion across 64 revisions | 176,885 | 488 |
| V3 validation across 64 revisions | 176,448 | 253 |

These are node-read counts for this fixture, not production latency or a
completion-time estimate. Each regression requires more than a 100-fold read
reduction. Additional checks cover root/leaf/branch/empty transitions, missing
and corrupt changed nodes, memo eviction, shared nodes across rooms, staged
repeated roots, and reopening after a committed chunk followed by failure.

The migration prints the room ordinal, then checked records over the counted
room total every 15 seconds and at the room's final record. Node-loader calls
and elapsed time accompany the count. The final record count precedes the tail
commit; the deletion phase and final successful schema result remain separate.
Rooms can differ greatly in size, so room ordinals are not an overall percentage
or an ETA.
