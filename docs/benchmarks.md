# Benchmarks

Measurements, methodology, and the results that do not favour us. A suite that
only reports its wins is not evidence (#34).

## Where the current numbers are

**Published automatically on every push to `main`:**
<https://tuna-os.github.io/spindle/> — with
[`latest.json`](https://tuna-os.github.io/spindle/latest.json) as the raw data
and a per-commit copy kept beside it, so a regression can be traced to the push
that caused it.

**The tables in this document are dated snapshots, not the live figures.** They
are here because the analysis around them needs something concrete to point at,
and they are what the numbers looked like when that analysis was written. The
published results are authoritative; where the two disagree, this document is
the stale one.

That split is deliberate. A figure typed into prose has nothing holding it to
the code, so it drifts the first time somebody changes one and not the other —
which is the same failure the rest of this repository spends effort avoiding
(see `crates/spindle-server/src/surface.rs`, or the frozen format fixtures).
What belongs in a document is the reasoning: what a comparison establishes, what
it does not, and which caveats travel with the number. Reasoning does not go
stale on a runner change. Wall times do.

## What is measured, and what is not

| Comparison | Status |
|---|---|
| Bounded fork search vs the exhaustive walk it replaced | Done (#33) |
| Persistent state trie vs `im` and vs cloning per event | Done, below |
| Structural sharing: nodes created per update | Done, asserted as a test |
| Storage append and reopen at a million events | Done (#47) |
| Durability cost: strict vs relaxed | Done (#47) |
| Our fast path vs `ruma-state-res`, **correctness** | Done (#55), below |
| Our fast path vs `ruma-state-res`, performance | Done, below — and the result is narrower than the spec implies |
| `/messages`, `/sync`, join latency vs **Synapse** | Done at M1, below (#42) |
| The same vs **Tuwunel** | Not yet — no build in the sandbox (#42) |

Everything here is **algorithmic**, measured inside the library. None of it is a
server throughput figure and none of it should be quoted as one. Server-to-
server comparison starts at M1 and is defined in #42.

## Method

Published runs execute on a GitHub Actions `ubuntu-24.04` runner, which is both
slower and noisier than a workstation by an amount that varies run to run. The
snapshots below were taken on the development host. Neither is comparable to the
other in absolute terms, which is why **ratios measured inside a single run are
the result** and wall times are context.

Rust 1.89, release mode, Criterion. Absolute times
are not portable between machines; the **shape across sizes** is the result, and
that is what the commentary below reads.

```bash
cargo bench -p spindle-core --bench state_snapshot
cargo bench -p spindle-core --bench fork_window
cargo test -p spindle-store --release --test scale -- --ignored --nocapture
```

## Client-server API vs Synapse, at M1

Run with `scripts/compare-against.sh`, which owns both servers: it installs
Synapse into a virtualenv, generates its config, runs the driver against it,
then builds Spindle and runs the same driver against that — same host, same
sitting, same `api-benchmark.py`. A number from one machine set against a
number from another is not evidence, so the script does not offer the option.

Synapse runs from a virtualenv rather than Docker deliberately. A Docker
daemon is not available in the sandbox where most of this work happens, and a
comparison that can be skipped for want of a daemon is a comparison that will
be skipped.

Spindle at M1 (`a883e0e` plus the leave section) against Synapse 1.159.0,
mean of 25 samples after 5 warmups, milliseconds:

| operation | spindle @1600 | synapse @1600 | ratio |
|---|---|---|---|
| join | 1.371 | 41.577 | **30.3× faster** |
| send | 1.485 | 24.628 | **16.6× faster** |
| messages_page | 1.088 | 5.411 | **5.0× faster** |
| state | 0.803 | 2.692 | **3.4× faster** |
| sync_initial | 1.722 | 3.302 | **1.9× faster** |

### What this establishes, and what it does not

It establishes that on a single-node local workload at these room sizes,
Spindle is faster than Synapse on every operation the driver measures. That is
a real result and it is the direction the design predicts.

**It does not establish the claim the design actually rests on.** SPEC §18.1 is
about how cost *changes* with room size and with fork depth, and at 1600 events
both servers are flat — Synapse's growth is 0.94×–1.18× across the same sweep.
A room of 1600 events is small. The costs a DAG server pays for state
resolution show up in rooms with deep or forked history, which this driver does
not construct, and until it does, the flat Synapse column here is evidence that
the workload is too easy rather than that the difference has been measured.

So the honest summary is: **we are faster, and we have not yet measured the
thing we say makes us faster.** #80 tracks the suite measuring what content
addressing buys rather than only what it costs, and the same gap applies here.

Tuwunel is not in this table. It needs a build the sandbox does not have; the
script is server-agnostic and takes a base URL, so adding it is a matter of
getting a binary rather than of writing code.

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

## `ruma-state-res`: correctness compared, performance not

The comparison that tests the project's headline claim is against
`ruma-state-res` — the state resolution v2 implementation Conduit, Continuwuity
and Tuwunel actually run. It has two halves, and only one is done.

**Correctness: done (#55).** `crates/spindle-core/tests/state_res_equivalence.rs`
resolves the same fork twice, once through our window-bounded path and once
through `resolve()`, and asserts the two agree. This is SPEC §19.2's oracle, and
it is the first thing in this repository that compares Spindle against another
implementation's code.

Getting there meant building what ruma does not export. `resolve()` needs a
caller-supplied `Event` implementation plus valid state maps and auth chains for
a real room; the crate's own helpers are gated behind a private `__criterion`
feature unreachable from outside. So `tests/oracle/` constructs a spec-valid v11
room by hand, wiring auth events per the v11 selection rules — which matters,
because `resolve()` walks auth chains to build its conflicted subgraph, and a
room naming the wrong auth events resolves wrongly in ways that look like a bug
in whatever it is being compared against.

The scope of the claim is narrower than "we match state resolution", and saying
so is the point of this document. Spindle only claims to skip state resolution
for SPEC §9.2's cases 1 and 2 — a fork whose sides touched disjoint state slots.
A same-slot conflict is case 3, which we hand to `ruma-state-res`, so agreement
there is trivial and proves nothing. The tested claim is: *for every fork the
fast path claims to handle without state resolution, the reference resolver
agrees.*

The oracle was checked against a deliberate regression rather than trusted
because it passed. Replacing our merge with a plausible wrong implementation —
"take the first parent's state" — makes it fail with our side missing a
membership event the reference keeps.

**Performance: measured, and it is a constant factor rather than an asymptotic
win.** `benches/state_res_comparison.rs` resolves the same disjoint fork both
ways, across fork sizes. Each side writes its own state slot, so the fork stays
in the case Spindle claims to handle without state resolution.

| Divergent events per side | `ruma-state-res` | Spindle window merge | Ratio |
|---|---|---|---|
| 1 | 26.7 µs | **11.9 µs** | 2.25× |
| 4 | 91.1 µs | **29.4 µs** | 3.10× |
| 16 | 347 µs | **121 µs** | 2.87× |
| 64 | 1.43 ms | **604 µs** | 2.37× |
| 256 (a full `max_fork_window`) | 6.34 ms | **2.67 ms** | 2.37× |

We are consistently faster, by between two and three times. **Both sides scale
linearly in the size of the fork, and per-event cost is flat for both** — about
11 µs per event for `resolve()`, about 5 µs for ours. That is the result, and it
is not the one SPEC §18.1's complexity table leads a reader to expect.

#34 asks specifically for the deep case, on the grounds that it is where the
advantage should shrink. It does not: 256 events a side fills SPEC §9.1's
512-event `max_fork_window` entirely, and the ratio there is the same 2.4× as at
64. Whatever the advantage is, it is not something that erodes as the fork
grows — but it is also not something that grows.

Three things this does not show, each of which matters more than the ratio:

1. **This is the exception path, not the common one.** Spindle's actual claim is
   that a fork-free append runs *no* state resolution at all. A DAG homeserver
   on that same path does not call `resolve()` either — it calls `auth_check`,
   as `docs/divergence.md` §3 notes both siblings do. So this table compares two
   fork handlers, not the hot path, and quoting it as "Spindle is 3× faster than
   Conduit" would be wrong.

2. **The auth chains here do not grow with the fork.** The synthetic room's auth
   chains stay about four events deep however large the fork gets, which is why
   `resolve()` comes out linear. State resolution v2 is `O(conflicted state ×
   auth chain)`, and the case it is supposed to blow up on is a long partition:
   a large conflicted set over deep auth chains. **That case is untested here**,
   and it is the one SPEC §18.1's asymptotic claim is actually about. Until it
   is measured, the honest statement is a 2–3× constant factor.

3. **The two sides start from different places, by design.** Ours starts from
   two materialized state snapshots, because Spindle paid for materialization at
   append time; theirs starts from state maps and auth chains, because that is
   what a DAG homeserver holds. That asymmetry is the design difference rather
   than a thumb on the scale, and the append-side cost it moves is measured
   separately above. The benchmark hoists auth-chain construction out of the
   timed loop for the same reason — a homeserver stores auth chains rather than
   rebuilding them per resolution. Leaving that walk inside inflated
   `resolve()`'s time by 4–7%.

Still true, and worth keeping stated plainly: **no measurement in this document
is a server-to-server comparison.** Everything is algorithmic, measured inside
the library. Synapse and Tuwunel under protocol workload is #42, at M1–M3.
