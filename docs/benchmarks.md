# Benchmarks

Measurements, methodology, and the results that do not favour us. A suite that
only reports its wins is not evidence (#34).

## What is measured, and what is not

| Comparison | Status |
|---|---|
| Bounded fork search vs the exhaustive walk it replaced | Done (#33) |
| Persistent state trie vs `im` and vs cloning per event | Done, below |
| Structural sharing: nodes created per update | Done, asserted as a test |
| Storage append and reopen at a million events | Done (#47) |
| Durability cost: strict vs relaxed | Done (#47) |
| **Our state handling vs `ruma-state-res`** | **Not yet — see below** |
| `/messages`, `/sync`, join latency vs Synapse and Tuwunel | Needs a server; M1–M3 (#42) |

Everything here is **algorithmic**, measured inside the library. None of it is a
server throughput figure and none of it should be quoted as one. Server-to-
server comparison starts at M1 and is defined in #42.

## Method

Run on the development host, Rust 1.89, release mode, Criterion. Absolute times
are not portable between machines; the **shape across sizes** is the result, and
that is what the commentary below reads.

```bash
cargo bench -p spindle-core --bench state_snapshot
cargo bench -p spindle-core --bench fork_window
cargo test -p spindle-store --release --test scale -- --ignored --nocapture
```

## Fork window: bounded search vs exhaustive walk

| Room history | Bounded | Exhaustive | Ratio |
|---|---|---|---|
| 100 | 509 ns | 26.6 µs | 52× |
| 1,000 | 566 ns | 381 µs | 673× |
| 10,000 | 587 ns | 5.01 ms | 8,540× |

The ratio is not the point; the shape is. Bounded stays flat across a 100×
growth in history while exhaustive scales linearly with it. This is SPEC §9's
claim — that handling a fork costs what the fork costs, not what the room costs.

## State: retaining a snapshot per event

The log keeps every intermediate snapshot, so each run retains all of them.
Measuring only the final state would flatter the naive version by letting each
clone drop immediately, which is not how the log uses it.

| Updates | HAMT (ours) | `im` | Clone per event |
|---|---|---|---|
| 100 | 296 µs | **231 µs** | 549 µs |
| 1,000 | 4.19 ms | **3.16 ms** | 75.5 ms |
| 10,000 | **78.1 ms** | 83.4 ms | *did not finish* |

Cloning the whole map per event is quadratic and was omitted at 10,000 because
it does not complete — roughly 50M entry copies per iteration. **That omission
is the result, not a gap in the data.** At 1,000 it is already 18× the cost of
either persistent structure.

### The result that does not favour us

**`im` beats our hand-rolled HAMT at 100 and 1,000 updates**, by 20–30%. We are
ahead at 10,000, but by ~6%, which is close enough to noise that it should not
be claimed as a win.

So hand-rolling is **not** justified by raw speed. What it is justified by is
the thing `im` does not provide: **content-addressed nodes**. Every node's
identity is the hash of its contents, which is what makes

- persisting the trie to an ordered key-value store possible at all (#48),
- `delta_nodes` able to find exactly the nodes an update created by comparing
  addresses (#48), and
- a corrupted node detectable on read rather than silently served.

If those requirements ever go away, `im` is the better choice and this should be
revisited. They are not going away.

## State: lookups

| State size | HAMT | `HashMap` |
|---|---|---|
| 1,000 | 223 ns | **26 ns** |
| 50,000 | 231 ns | **29 ns** |

A plain hash map is **~8× faster**, as expected for a persistent trie. Ours is
flat across a 50× growth in state, which is the property that matters, and the
absolute cost is small enough not to matter for the workload: SPEC §7.1's
authorization path does at most six lookups per event, so ~1.3 µs against
~0.17 µs. Neither is close to being the bottleneck.

## Structural sharing

Timing cannot show this cleanly — allocation cost is buried in wall clock and
varies by allocator. Node count is exact, so it is asserted as a test
(`tests/state_sharing.rs`) rather than benchmarked: updating one slot creates a
bounded number of nodes regardless of state size, and that count must not grow
with the state. If it ever tracks state size, path copying has been lost and
every state event is rewriting the room.

## Storage

| | |
|---|---|
| 1,000,000 events appended | first 100k 0.694s, last 100k 1.224s |
| Reopen 1,000,000 events | 2.681s |
| Strict vs relaxed durability | **34× cost** |

The last decile costs 1.76× the first across ten times the data — sub-linear,
consistent with LSM compaction rather than per-append cost growing.

The durability ratio is the honest price of an fsync per commit, and it is the
concrete argument for the group-commit coalescing SPEC §8.3 describes and #46
documents as not yet implemented. It is printed rather than asserted: it is
dominated by host fsync latency and varies by orders of magnitude between an
NVMe workstation and a shared runner.

## Still to do: `ruma-state-res`

The comparison that tests the project's headline claim — our state handling
against the state resolution v2 implementation Conduit, Continuwuity and
Tuwunel actually run — is **not done**.

`ruma-state-res` is reachable through ruma's `state-res` feature, but its
`resolve()` needs a caller-supplied `Event` implementation plus valid state maps
and auth chains for a real room. The crate's own test helpers are gated behind a
private `__criterion` feature and cannot be used from outside, so a faithful
harness has to construct a spec-valid room graph by hand. That is the remaining
work in #34.

Worth stating plainly so the gap is not mistaken for a result: **nothing here
compares Spindle against another homeserver's code.**
