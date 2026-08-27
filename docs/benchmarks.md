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
| The same vs **Continuwuity** (conduwuit lineage) | Done, below (#42) |
| The same vs **Tuwunel** | Blocked: GitHub release downloads 403 through the sandbox proxy, and a source build compiles RocksDB against the disk allowance. Continuwuity stands in as the same-lineage bar. |

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
| context_deep (at 3200) | 1.076 | 5.501 | **5.1× faster** |

### What this establishes

On a single-node local workload, Spindle is faster than Synapse on every
operation the driver measures, at every room size measured. That is a real
result, and it is worth roughly what it looks like to a user: joins and sends
are the operations a client waits on most, and they are 17–30× quicker.

It is very likely a **constant-factor** win rather than an asymptotic one.
Synapse is Python with an ORM and Spindle is Rust reading a materialized
snapshot; a 20× gap on `send` is the sort of number that difference produces on
its own, with no help from the log being linear.

### What it does not establish — and why this method never will

SPEC §18.1's claims are about how cost *changes*: with room size, and with fork
depth. This driver cannot test them, and after extending it to try, the reason
turns out to be structural rather than a matter of turning the sizes up.

`context_deep` was added specifically to probe it. It asks `/context` for the
*oldest* event in the room, which is the sharpest question reachable over the
client-server API: what was the state back there? A server that stores state as
a DAG should have to resolve or walk to answer; a server keeping a
content-addressed snapshot per event reads one.

The result at 200 → 3200 events:

| | growth | |
|---|---|---|
| `context_deep`, Spindle | 0.97× | flat |
| `context_deep`, Synapse | 0.97× | **also flat** |

Synapse is flat because **there is nothing for it to resolve.** State
resolution runs when a room's history forks, and a single server linearizes
everything it accepts — forks arrive over *federation*. Synapse's state groups
make state-at-a-point a direct lookup in an unforked room, so on this workload
it is doing the same asymptotic work we are, more slowly.

That is a finding about the methodology, and it retires an assumption: **no
amount of client-server benchmarking against a single peer can demonstrate the
design's central claim**, because the workload that triggers the cost cannot be
constructed through that API. Bigger rooms will not fix it. More samples will
not fix it.

The rig that can is the federated one — #16's class-D fork handling against a
real Synapse, where forks exist because two servers accepted events
concurrently. Until that exists, this table should be read as "faster in
practice today", not as evidence for the architecture.

Tuwunel is not in this table. It needs a build the sandbox does not have; the
script is server-agnostic and takes a base URL, so adding it is a matter of
getting a binary rather than of writing code.

## Client-server API vs Continuwuity, at M1

The user's framing is the right one: Synapse is the API reference, but the
conduwuit-lineage Rust servers are the performance bar. Continuwuity 26.8.1,
**their `maxperf` release build**, same host, same driver, same sitting
(`--registration-token`, because continuwuity refuses open registration —
the driver adapting at the front door is what keeps the workload identical
behind it).

Milliseconds, mean of 15 samples, at 3 200 events:

| operation | spindle | continuwuity | ratio |
|---|---|---|---|
| join | 1.233 | 6.218 | **5.0× faster** |
| send | 1.350 | 4.530 | **3.4× faster** |
| context_deep | 1.189 | 3.543 | **3.0× faster** |
| messages_page | 0.929 | 2.769 | **3.0× faster** |
| state | 0.694 | 1.054 | **1.5× faster** |
| sync_initial | 2.077 | 2.518 | **1.2× faster** |

Two readings matter more than the ratios.

**Continuwuity's `send` grows 2.56× from 200 to 3 200 events while ours holds
1.07×.** This is the first competitor curve that bends on this workload —
Synapse's stayed flat everywhere — and `send` is the hot path the linear log
exists for. Against the sibling whose architecture is closest to ours, the
flat-cost claim finally has a comparative data point, not just an absolute
one.

**`sync_initial` is the closest race** (1.0× at 800 events — a tie inside
noise). If any operation deserves the next look, it is that one; #12's
sliding sync will reshape it anyway.

Same caveat as the Synapse table: no forks, so no state resolution on either
side. The curves compare storage and read-path shape, not the exception path.

## M2 progress: sliding sync on the curve, both competitors re-measured

Run at the sliding-sync slice (#105), with `sliding_window` added to the
driver: the MSC4186 request Element X makes where classic clients call
`/sync` — an 11-room window with names and a 3-event timeline. All three
servers implement the MSC, so for the first time the column is a
three-way comparison of the same feature.

Milliseconds, mean of 15 samples, at 3 200 events:

| operation | spindle | continuwuity 26.8.1 | synapse 1.159.0 |
|---|---|---|---|
| sliding_window | **1.079** | 1.361 (1.3×) | 8.902 (8.2×) |
| join | **1.412** | 6.073 (4.3×) | 43.873 (31×) |
| send | **1.481** | 4.858 (3.3×) | 23.937 (16×) |
| context_deep | **1.114** | 3.989 (3.6×) | 5.031 (4.5×) |
| messages_page | **1.225** | 2.787 (2.3×) | 6.771 (5.5×) |
| state | **0.548** | 0.813 (1.5×) | 2.798 (5.1×) |
| sync_initial | **1.712** | 2.775 (1.6×) | 3.302 (1.9×) |

Three findings:

**The send-growth result replicates.** Continuwuity's `send` grew 2.56× in
the M1 run and 2.67× here, against our 1.10× — two independent runs, same
shape. What looked like one run's curve is now a repeatable property of the
comparison.

**The new endpoint starts ahead.** `sliding_window` was implemented against
this storage the day it was measured, and already edges the conduwuit
lineage's own implementation of the same MSC (1.1–1.3×) and clears Synapse's
by 8×. The room-list question — "the visible slice, sorted by activity" — is
one point read per room here, and that shows.

**`sync_initial` stopped being the closest race.** The 1.0×-at-800 tie from
the M1 run reads as 1.6× here; run-to-run variance on this host is real, so
the honest statement is "between 1.0× and 1.6×", and sliding sync is the
endpoint that matters for new clients anyway.

Nothing is slower than either competitor at any size measured.

## M2 close-out: all three siblings, one sitting — and the loss that earned its keep

The milestone-closing run, 2026-08-27, on the M2-complete server (through
#113). Four servers, one host, one sitting, cold databases, the machine
otherwise idle, every serving binary verified by `pgrep` before its leg:
Spindle, Synapse 1.159.0, Continuwuity 26.8.1, and — for the first time —
**Tuwunel 1.9.0, built from source** (the release-asset 403 recorded in #42
stopped blocking once the source tree built here: `liburing-dev`, Rust
1.95.0, and `RUSTFLAGS="--cfg ruma_unstable_exhaustive_types"`, which
upstream injects outside the repo). Raw results:
`docs/benchmarks/data/m2-final.*`, rendered on the comparisons page.

**60 of 63 cells favour Spindle.** Medians, milliseconds, ratio = theirs/ours:

| op/size | spindle | synapse | continuwuity | tuwunel |
|---|---|---|---|---|
| send/3200 | 1.18 | 23.3 (19.8×) | 4.02 (3.4×) | 2.74 (2.3×) |
| join/3200 | 1.41 | 37.7 (26.7×) | 5.95 (4.2×) | 4.31 (3.1×) |
| messages_page/3200 | 1.00 | 6.99 (7.0×) | 4.08 (4.1×) | 1.86 (1.9×) |
| context_deep/3200 | 1.18 | 5.03 (4.3×) | 4.57 (3.9×) | 1.79 (1.5×) |
| state/3200 | 0.53 | 2.58 (4.9×) | 1.16 (2.2×) | 0.86 (1.6×) |
| sync_initial/3200 | 1.92 | 3.24 (1.7×) | 2.87 (1.5×) | 2.10 (1.1×) |
| sliding_window/3200 | 1.25 | 8.44 (6.8×) | 1.17 (0.94×) | 1.51 (1.2×) |

(Full 63-cell matrix on the comparisons page; the 200 and 800 columns tell
the same story.)

### The loss that was real, and what it bought

The first pass of this run reported `sliding_window` at **0.87×** against
Continuwuity — and it was the only operation whose curve grew with room
size. Investigated per the roadmap rule that a slower column is a defect
until explained: bisecting a live server pinned it to the unread count,
which read **every event body after the receipt floor** to learn its
sender. A user with no read receipt — every bot, every receipt-less
client, our own driver — paid O(room) store reads per room per sync,
classic and sliding alike: 11.79 ms for one sliding sync against a
3200-event room, 0.49 ms with a receipt at the head. #113 replaced the
walk with a per-room sender index (two binary searches); the same
pathological probe now reads 1.00 ms, and the curve above is flat.

### The three cells that remain, and why they stand

`sliding_window/200` (0.99×) and `/3200` (0.94×) vs Continuwuity, and
`state/200` (0.85×) vs Tuwunel. All three are sub-1.5 ms cells where the
two servers' bands overlap this host's run-to-run variance — measured, not
assumed: the same Spindle code produced 1.088, 1.198 and 0.829 ms for
`sliding_window/800` across three sittings today. None correlates with
room size (`state` is *flatter* for us: 0.68/0.68/0.53 against Tuwunel's
0.58/0.77/0.86 — the crossover by 800 is their constant factor being
smaller at trivial scale, not a curve). Disposition: within noise,
published, watched at the next milestone close rather than chased into the
noise floor now.

### What invalidated a run along the way

One intermediate Spindle leg was measured while a RocksDB build saturated
the cores, and read ~25% slow across the board. Same host and same sitting
are not enough — **same load** is part of the method, and that run was
discarded rather than averaged. The final sitting above ran on an idle
machine.

## M3: reading Tuwunel's code for the one cell it kept winning

`state` at 200 events was the only cell Tuwunel held across two sittings —
0.85× at the M2 close-out, 0.93× at M3 progress. Two sittings, same
direction, one below the noise floor: by the roadmap's rule, a defect until
explained. So this investigation started in *their* tree, not ours.

**What their code does.** Tuwunel's `/state` handler
(`state_accessor.room_state_full_pdus`) resolves the room's compressed
state (short IDs), then fetches each PDU through RocksDB reads whose hot
path is a block-cache hit — no disk, but still a deserialization per event
per request. Ours resolved the current state from the materialized
snapshot, then paid a room-lock acquisition, a stored-body read and a JSON
parse **per state event**, plus a re-serialization of the whole response —
per request.

**What the probes actually said.** A component probe against both servers,
same host, same minute, split every request into fixed cost (an
authenticated no-op) and marginal cost (the state machinery):

|                       | spindle before | spindle after | tuwunel |
| --------------------- | -------------- | ------------- | ------- |
| fixed (whoami)        | 0.48 ms        | 0.52 ms       | 0.30 ms |
| `/state` minus fixed  | 0.22 ms        | **0.01 ms**   | 0.60 ms |

Two findings, one expected and one not. The unexpected one: Tuwunel's
*state machinery* was never faster than ours — their per-request pipeline
is simply leaner (raw-socket probes bound the true server-side gap at
~30 µs on fresh connections; the rest of the fixed-cost spread is
benchmark-client overhead, paid identically by every server the driver
measures). Their block cache was hiding a marginal cost six times ours
behind a cheaper front door.

**The fix reads like the design.** The state snapshot is content-addressed:
its BLAKE3 root *is* the identity of the full-state answer. So the rendered
`/state` body is cached per room, keyed by the root it was rendered from —
a hit is provably current, a root mismatch is the only invalidation, and
there is no TTL or write-hook to get wrong. The same read now skips the
per-event room-lock round-trip the old path paid (`event()` re-proved the
room's existence once per state event).

Re-measured with the sitting's own driver, two rounds, same host:
`state/200` went from **0.85×/0.93× against to 1.91×/1.33× for** —
0.45–0.54 ms against Tuwunel's 0.72–0.87 ms. The staleness mutant — a
cache that serves a warmed render without comparing roots — dies on a
dedicated test (warm the render, change the state, the very next read
must show it).

The honest caveat, kept as measured: the published m2-final and
m3-progress tables retain the losses. This section is what those cells
link to, and the M3 close-out sitting is where the fix gets its four-way
number.

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
