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

## M3 progress: the four-way re-run mid-milestone, and the sort key that hid in a body read

Measured 2026-08-27 on the M3-in-progress tree (main through #123: the
whole inbound/outbound federation surface, TLS on 8448, backfill,
`get_missing_events`; remote joins were on a branch and not in the
measured binary). Same method as the M2 close-out: Synapse 1.159.0,
Continuwuity 26.8.1 and Tuwunel 1.9.0 built from source, one idle sitting,
cold databases per leg, serving binaries pgrep-verified, sizes 200/800/3,200.
Raw results: `docs/benchmarks/data/m3-progress.*.json`; the rendered
matrix and charts are on the site's comparisons page.

The sweep, 63 cells:

- **vs Synapse: 21 of 21 faster**, 2.0×–34.8× (join 27–35×, send ~21×,
  pagination 7–8×).
- **vs Tuwunel: 21 of 21 faster or within noise** — up to 3.1×, with
  send/sync_initial at 200 events and state at 200 sitting on the 1.0×
  line inside the noise band.
- **vs Continuwuity: 19 of 21**, with `sliding_window` at 800 and 3,200
  events reading 0.90× and 0.88× — just under the noise floor.

### The investigation the two red cells earned

The same cell sat at 0.83× in the M2 close-out and was published then as
within-variance-adjacent, to be watched. Two sittings agreeing on the
direction ends that: repeatable, so a defect until explained.

A component probe on the live bench server split the endpoint into its
pieces, and the piece that scaled with the observer's room count was the
room list's recency sort: `last_activity` answered by reading each room's
**head event body from the store and parsing its JSON — per room, on
every request — to extract one i64**. The fix (#126) makes the sort key a
per-room in-memory value, filled lazily on first read and refreshed by
the append that changes it, on the shared persist spine so local,
federated and seeded-join appends all keep it honest. A cache that could
go stale earned its own mutation test: filled-on-read-never-refreshed
passes every pre-existing test (the only reorder test bumped a room
before anything was warm) and dies on the new sync-then-bump test.

Re-measured with the fixed binary, same sitting conditions, fresh cold
database: the two cells recover to **0.96× and 1.00×** — parity — and
Spindle's own `sliding_window` growth flattens from 1.28× to 1.13×
across a 16× room-size increase. No other operation moved outside
run-to-run variance. The published `m3-progress` files keep the loss
exactly as measured; the fix's numbers become the baseline the M3
close-out sitting has to confirm.

### What the driver had to learn first

The first attempt at this sitting failed against Spindle itself: #120
made registration refuse an auth dict that names no session, and the
driver had been skipping the UIA dance. It now registers the way a real
client does — unauthenticated first, then citing the session from the
401 challenge — which also left it working unchanged against the other
three servers. A conformance fix breaking our own tooling is the system
working, and it is recorded here because the method promises the same
workload through every front door.

## M3 close-out: the four-way at milestone's end — 55 of 63, and a first sitting honest enough to discard

Main at the close of M3 — federation joins, invites, leaves, knocks,
backfill, profiles, media and typing all interoperating behind a 169-test
Complement ratchet — measured against Synapse 1.159.0, Continuwuity 26.8.1
and Tuwunel 1.9.0. Same ritual as every sitting: one host, cold databases
per leg, pgrep-verified binaries, sizes 200/800/3,200, means over 25
samples, raw files committed as `m3-final.*.json`.

**The first attempt was discarded, and that is part of the record.** The
host restarted minutes before the sitting and the release build left the
1-minute load at 2.28 when the first leg started — the method says
idleness is checked, not assumed, and a sitting whose legs run under
*decaying* load hands the early legs a handicap the late legs don't pay.
The rerun waited for load 0.29 and is the sitting published here.

**The scoreboard: 55 of 63 cells faster, 6 within noise, 2 below the
floor — both investigated, one to a null result worth reading.**

- **vs Synapse: 21/21 faster**, joins 36–48×, sends 25–27×, pagination
  and deep context 5–10×.
- **vs Tuwunel: 20/21 faster or in noise.** The `state` column — the M3
  investigation that started in their tree — is confirmed flipped:
  **1.09×, 1.85×, 1.10×** in Spindle's favour, against 0.85× before the
  render cache. `sync_initial/200` read 0.89× in this sitting and 1.21×
  in the same day's discarded run; a cell that flips sign between
  sittings hours apart is variance, and it is published as measured.
- **vs Continuwuity: 19/21**, with `sliding_window/3200` at 0.77× — and
  this one got the full second look the roadmap demands.

**The sliding_window investigation, null result and all.** Two runs the
same day put the cell below the floor (0.85× loaded, 0.77× idle), which
is the repeatability rule firing. So both servers were probed live,
minutes after the sitting, same client, same instant, two shapes: a
creator sliding a fresh 3,200-event room of their own, and the driver's
exact observer shape — a second user invited, joined, then sliding.
Like-for-like, the gap does not exist: **creator shape 0.844 ms vs
0.854 ms (parity); observer shape 0.785 ms vs 0.874 ms (Spindle 1.11×
faster)**. The sitting's own Spindle value (1.009 ms) is higher than
anything the same server produces under direct measurement, and the
sitting's Continuwuity value (0.78 ms) is lower than its own probes
(0.85–0.87 ms) — the two legs caught opposite sides of the machine's
same-day swing. Decomposition shows no growth pathology either: the
request's marginal is ~0.10 ms of timeline and ~0.11 ms of
required_state over a 0.61 ms base. No fix ships because no defect was
found; the cell keeps its measured value, and this note is what it
links to.

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

## M5: the axis the sweep never varied, and what it was hiding

Three findings, the first of which made the other two worth looking for.
All came out of asking a simple question about the comparisons page:
*can we fix the cells where we are slower?*

### The sweep held membership at two

`scripts/api-benchmark.py` measures every operation at 200, 800 and 3,200
**events** per room. It never varied the *members*. Every room it timed
`sliding_window` and `sync_initial` against had two people in it, at every
size, in every sitting since M2.

That is not a small omission. Every endpoint in that pair is answered out
of room **state**, and the member list is the part of state that grows
without bound in exactly the rooms people complain about. Holding it at
two measures the one case where the member list costs nothing.

Varying it instead — same driver, same request shapes, `--dimension
members` — the sliding-window read was not flat at all:

| joined members | before | after | Continuwuity |
|---|---|---|---|
| 50 | 1.28 ms | 0.67 ms | 1.22 ms |
| 200 | 2.74 ms | 1.00 ms | 1.14 ms |
| 800 | 9.69 ms | 1.07 ms | 1.12 ms |

Linear in the member count, against a competitor that was flat. At 800
members it was **8.7× slower than Continuwuity** — on the endpoint Element X
calls where classic clients call `/sync`, and the page reported the same
operation as a 0.81× loss at worst, because 0.81× is what it costs when the
room has two members in it.

Three causes, all the same mistake — answering a narrow question with a
whole-room read:

1. `required_state` naming concrete keys materialized and JSON-parsed
   **every state event in the room**, then filtered down to the two or
   three asked for. Now it reads the events it was asked for. A wildcard
   still scans, because a wildcard has to.
2. `joined_count` called `joined_members().len()` — a stored-body read and
   a JSON parse per member, per room in the window, per request, to produce
   one integer. Now cached against the state root, the same way the state
   render is, so a hit is provably current.
3. `state_event` and `state_event_full` found one key by walking the
   materialized state. The state trie is a map and has always had a point
   lookup; they now use it. This one is not sliding-sync-specific — every
   auth check and every power-level read went through that walk, so all of
   them scaled with the member list.

Fixing (1) and (2) took 800 members from 9.69 ms to ~1.6 ms; (3) took the
rest of the curve out, to 1.07 ms. The shape is now flat, which is the
result — the absolute numbers are one host on one day.

The dimension is now a first-class part of the driver (`--dimension
members`), written to its own results document, because 800 members and 800
events are different questions and a chart that silently mixes them is
wrong rather than mislabelled. The renderer reads the dimension from the
results and labels the axis from it; a group that mixes the two is refused.

### The same mistake again, one layer over: lazy member loading

Once the membership axis existed, it was worth asking what else it could
see. `sync_initial` at 800 members costs ~16.9 ms, which is a tie with
Continuwuity and is *correct* — with no filter the client asked for the
whole roster and is entitled to it.

The interesting case is the one the sweep still could not see: a client
that asks for **less**. Lazy member loading (`lazy_load_members`) exists
so a client is not sent a roster it will not render — in a large room the
roster *is* the initial sync. Spindle implemented it, and implemented it
in the wrong place. `Rooms::sync` materialized and JSON-parsed every state
event including every member; `sync_join` then discarded the members the
client had asked not to receive. The narrowing happened after the
expensive part, so a lazy-loading client — which is what Element is —
paid the full roster read and got only the serialization saving for
asking.

The fix is the same shape as the sliding-window one: decide on the state
*key*, which is already in hand from the trie, so an unwanted member
event is never fetched and never parsed. Two rounds, opposite order, one
idle host:

| joined members | before | after | speedup |
|---|---|---|---|
| 50 | 1.56 ms | 1.38 ms | 1.13× |
| 200 | 2.65 ms | 1.73 ms | 1.54× |
| 800 | 7.04 ms | 2.14 ms | 3.29× |

The 1.13× at 50 is inside the noise floor below and is not counted.

What makes the 3.29× believable is not the ratio but the **controls**.
The sweep measures three operations this change must not touch, and a
host that drifted between legs would have moved them too:
`sync_initial` (no filter) 16.91 → 16.91 ms, `state` 3.77 → 3.91 ms,
`sliding_window` 1.15 → 1.00 ms. Only the column that should have moved
moved.

Caveat that travels with the number: the probe's rooms carry no chat, so
their timeline is join events and the lazy set is the ~20 most recent
joiners rather than a handful of speakers. A real room narrows further,
which makes 3.29× a floor on the benefit rather than a ceiling.

Three findings, one root: **a narrow question answered with a whole-room
read**, in three different places, none of which the benchmark could see
because it never varied the thing that makes those reads expensive.

### The comparisons page's noise band is narrower than the harness

The second finding fell out of trying to measure the first honestly. The
page colours a cell a win above 1.10× and a loss below 0.90×, calling
everything between them noise. So: how repeatable is a cell, actually?

Six rounds, same binary, same workload, same idle host, one sitting —
`max/min` per cell across the six:

| | value |
|---|---|
| median cell | 1.38× |
| p75 cell | 1.55× |
| worst cell (`state/3200`) | 2.80× |
| cells whose own spread exceeds the ±10% band | **21 of 21** |

Every cell on the page varies more between runs of *identical code* than
the band that decides whether it is printed green or red. The driver's
25-samples-and-take-the-median already damps the within-round tail; this is
between-round variance, which a single round cannot see and therefore
cannot report.

This does not retract the published results — the large ratios (3–7× on
`context_deep`, 2–4× on `messages_page`) clear that floor comfortably, and
the milestone conclusions rest on those. It does mean the **±0.1 cells were
never evidence**, in either direction, including two of the three losses
that prompted this work.

The comparisons page kept colouring them anyway. For a year it printed a
cell green at 1.19× and red at 0.90× directly above a caption saying to
treat anything inside roughly ±0.4× as unmeasured — the page contradicting
its own evidence, in the same paragraph. Single-round sittings are now
coloured by the 1.38× measured here instead of the assumed ±10%, which
moves 45 of the page's cells to grey and leaves **no loss anywhere on it**:
every red cell ever published was inside this host's own repeatability, and
the two that were investigated had already concluded exactly that from
their own probes. The large ratios are untouched. What changed is which of
them the page claims, not any number behind them. Fixing it is a change to how a sitting is
collected rather than to any one number: a sitting becomes N rounds, a cell
becomes the median across them, and the band gets derived from the observed
spread instead of assumed. That is filed separately (#171) because it
re-collects every figure on the page, and it should not ride along with a
code fix.

The rule this project runs on is that a loss gets investigated rather than
explained away. This is the same rule turned on the instrument: the
benchmark was wrong about two cells because it could not see the axis that
mattered, and imprecise about all of them because it never asked itself the
question.

### The separation rule bounds one cell, and a table is many

The fix for the band above (#176) was a separation rule: a cell is called
only when the two servers' rounds do not overlap — our slowest beat their
fastest, or the reverse. Three rounds a side is the minimum, because if the
servers were identical the chance that one side's rounds all land below the
other's is `2/C(2n, n)` — one in three at n=2, **one in ten at n=3**, one in
thirty-five at n=4.

That is a per-cell rate, and it took a sitting to notice the consequence.
The #181 sitting ran 18 cells at three rounds. Expected calls from luck
alone: `18 × 0.1 ≈ 1.8`. Observed: one. `joined_members/200` separated
cleanly in the wrong direction — all three after-rounds above all three
before-rounds — and by the letter of the rule that was a regression against
our own change.

It was not one. `room_joined_members` calls `Rooms::joined_members`; the
diff touched `Rooms::sync`, `Rooms::initial_state` and the `/sync` handler.
There is no code path from the change to that endpoint. The corroborating
detail was that the same endpoint showed nothing at 50 or 800, and a real
per-member cost does not skip the largest size.

The right answer, reached the wrong way. The mechanism check settled it;
the statistics did not, and could not — the arithmetic says roughly how
many calls in a table are chance, never **which**. Had that false call
landed on a cell the diff plausibly touched, there would have been no
principled way to tell it from a real regression.

So three things now hold, and only the first two are automated:

1. **The page states the count.** Each resolved table reports how many
   comparable cells it has and how many of them should separate by chance
   at that many rounds, beside how many actually did. A table calling one
   cell in eighteen has said almost nothing about that cell.
2. **A call nothing else supports is marked.** Where an operation is
   measured at more than one size, a call that no other size agrees with
   carries a †: the size axis is where a real per-item cost shows itself,
   so an isolated call is the shape a chance separation takes. It is a
   marker, never a recolouring — overriding a verdict the arithmetic cannot
   identify would invent a certainty the numbers do not carry. An operation
   swept at a single size is never marked, because there the question was
   never asked. A loss with an investigation behind it is not marked
   either: a cause found in the other server's code outranks a neighbouring
   cell.
3. **A regression call against our own diff needs a code path.** Before a
   wrong-direction cell is reported as a regression, there has to be a
   route from the change to the endpoint. This is what actually worked on
   #181, and writing it down makes it a rule rather than a habit.

None of this changes a published cell. Every sitting on the page predates
#171 and is single-round, so it is coloured by the old band, where
`2/C(2n, n)` says nothing at all — the count and the marker are both
withheld there rather than applied to numbers they do not describe. They
take effect on the first multi-round sitting the page carries.

## The second axis the sweep never varied: concurrency

The M5 section above records holding room membership at two for every
sitting since M2, and what that hid. The same question asked of a
different axis has a sharper answer.

`scripts/api-benchmark.py` measures with `[timed(operation) for _ in
range(samples)]`. Every sample is sequential. **One request has been in
flight at a time, in every sitting on this page.**

So every figure published here is a *latency* at concurrency 1. That is a
real and useful number — it is what a user waits — but it is not the
number an operator sizing a server asks for, and no throughput figure
against any competitor exists.

Measured with `crates/spindle-server/tests/probe.rs`, eight tokio workers
sending to eight independent rooms, debug build, in process:

| concurrency | sends/sec | fsyncs | rode | coalescing |
|---|---|---|---|---|
| 1 | 615 | 200 | 0 | 1.00× |
| 2 | 669 | 200 | 0 | 1.00× |
| 4 | 649 | 200 | 0 | 1.00× |
| 8 | 656 | 200 | 0 | 1.00× |

**Flat.** Eight clients writing to eight different rooms get the
throughput of one. Absolute values are a debug build and would be higher
in release; the flatness is the result, and a shape does not move with a
build profile.

### Why, and what it retires

`Rooms::with_room` takes a single process-wide
`Mutex<HashMap<String, RoomLog>>` and holds it across the closure — which
contains the commit *and its fsync*. Two writers are therefore never
inside `commit()` together, which the `rode` column shows directly: with
group commit present and eight clients pushing, not one commit ever rode
another's fsync.

That retires a question worth stating plainly, because it is the obvious
first guess: **a faster WAL, or a different storage engine, cannot help
here.** Postgres, RocksDB, LMDB — none of them is the constraint, because
the server never asks the store to do two things at once. The 34×
strict-vs-relaxed ratio measured below is the cost of `fsync`, and
nothing makes `fsync` faster; systems make it *rarer*. Group commit does
exactly that, and will coalesce nothing at all until the fsync moves out
of that critical section.

The ceiling is arithmetic: one lock held for roughly the CPU of an append
plus one fsync, so server-wide write throughput is about
`1 / send_latency` however many cores or rooms there are.

### Moving the barrier out, and what it left behind

The fsync now runs after `with_room` releases the room lock rather than
inside it. Ordering is unchanged — the bytes still reach the journal in
lock order — so only the barrier moved. Re-measured, same probe, same
host:

| concurrency | fsync inside the lock | fsync outside it |
|---|---|---|
| 1 | 615 | 635 |
| 2 | 669 | **898** |
| 4 | 649 | **801** |
| 8 | 656 | **861** |

About 30% at any concurrency above one, which is roughly what one fsync
is worth against the rest of an append.

**And still flat from 2 to 8, with `rode` still at zero.** Commits never
overlapped, so group commit still coalesced nothing. That was the useful
result rather than a disappointing one: it said the barrier was never the
whole ceiling, and named what was — the single
`Mutex<HashMap<String, RoomLog>>`, held across all of an append's CPU
work.

### Replacing that registry with a lock per room

The map now holds an `Arc<RwLock<RoomLog>>` per room and the registry
itself is taken only long enough to clone one. Appends to different rooms
no longer meet:

| concurrency | sends/sec | fsyncs | rode | coalescing |
|---|---|---|---|---|
| 1 | 612 | 200 | 0 | 1.00× |
| 2 | 1 220 | 200 | 0 | 1.00× |
| 4 | 1 912 | 194 | 60 | 1.31× |
| 8 | 1 661 | 115 | **195** | **2.70×** |

**Read the `rode` column first.** It was zero at every concurrency in
every table above: however many clients were sending, two commits never
once overlapped. It is now 195 of 310 commits at eight clients — 310
sends costing 115 fsyncs.

That is a *direct observation* that two writers are inside `commit()` at
the same time, and it owes nothing to how many cores the box has, which
is what makes it worth more here than the rate column. It also means the
group commit added earlier is finally doing something: it was correct and
idle until there was concurrency for it to coalesce.

The rate column changed shape too — flat before, scaling now — while the
one-client figure did not move, which is what a contention fix should look
like.

### And end to end, on this box, it does not show at all

The table above is the *in-process* probe: no HTTP, no separate client,
the tokio workers are the only load. Driven over HTTP by
`api-benchmark.py` instead, two rounds each side:

| clients | before r1 | before r2 | after r1 | after r2 |
|---|---|---|---|---|
| 1 | 964 | 940 | 955 | 888 |
| 2 | 1 565 | 1 542 | 1 664 | 1 569 |
| 4 | 1 687 | 1 705 | 1 500 | 1 645 |
| 8 | 1 364 | 1 542 | 1 569 | 1 500 |

The separation rule calls two of the four cells — **one in each
direction**, two clients faster and four clients slower. At two rounds a
side a spurious separation runs at one cell in three (#183), so across
four cells roughly 1.3 are expected from chance alone and two were
observed. Neither call means anything.

So the honest statement has two halves and both are needed:

- **The mechanism works.** `rode` moving from zero to 195 is not a
  measurement that noise produces; two writers are in `commit()` together
  where they never were before.
- **The end-to-end benefit is below what this rig can resolve.** Over
  HTTP, on four cores shared with a Python driver, the request's cost is
  dominated by things this change does not touch. The 1 912 sends/sec in
  the in-process table is *not* an operator-facing throughput claim, and
  reading it as one would be the same mistake as the scaling curve
  retracted above.

What would settle it is the driver on a different machine from the
server, which this environment does not have. Recorded rather than
resolved.

Three changes were needed for any of it to pay, and each was inert alone:
group commit, moving the fsync out of the critical section, and the lock
split. A fourth made it *safe* rather than fast — SPEC §10.2's watermark,
without which concurrent writers hand clients sync tokens past events that
have not landed.

This is a methodology defect of the same class as the membership one, and
it is recorded the same way: as a limit on what every table above
establishes, not as a footnote to them.

## The third axis: whose traffic a client pays for

The membership axis was a variable the sweep held constant. This one is a
variable the sweep **cannot** vary, because it is not a property of the
request at all: it is how busy the rest of the server is.

An incremental `/sync` asks "what happened since my token". The token is a
position in the server-wide stream, so the answer was assembled by reading
every stream row in the range and keeping the ones that belonged to the
caller's rooms. Counted (`crates/spindle-server/tests/sync_cost.rs`), with
Alice in one room where nothing had happened and Bob talking in a room she
is not in:

| events elsewhere | 0 | 50 | 200 | 800 |
|---|---|---|---|---|
| point reads, before | 1 | 51 | 201 | 801 |
| point reads, after | 1 | 1 | 1 | 1 |

Exactly `elsewhere + 1`. Alice's sync got more expensive because strangers
were talking, and on a server with a thousand users she would have been
paying for the other nine hundred and ninety-nine on every poll. Every
benchmark on this page runs one tenant on an idle server, so every one of
them measured that factor at zero.

The fix is the reverse index — the same rows keyed `(room_id, stream_id)`
instead of `stream_id` — so the question is a range scan that starts at the
client's token and covers one room. `ReadView::scan_from` is the primitive
that makes "start at the token" possible; a filter over a prefix scan would
have returned the same rows at the cost of the room's whole history, which
is the same defect at a smaller radius and has its own assertion.

**No wall clock is quoted here, deliberately.** The reads are counted, and
the count is the result: it is the same on any machine, where a timing on
this four-core box could not resolve it against a 10–14% run-to-run spread.
What the count does not tell you is what it is worth on a real deployment,
and this environment cannot produce that number — it would take a server
with genuine multi-tenant traffic, which is exactly the condition the
factor is proportional to. So the claim is the shape, not a speedup.

## The first throughput numbers this project has ever had

`--dimension concurrency` measures the axis the other two hold at one. It
reports **operations per second** rather than a per-sample latency,
because the two are not interchangeable and a server can win one while
losing the other: latency is one request's path through the code,
throughput is what the *contended* parts of it allow. A server that
serializes every write behind one lock has the latency of one request and
the throughput of one client, however many cores it has.

Release build, over HTTP, one Spindle, each client writing to its own
room — sharing a room would measure contention on that room's ordering,
which every homeserver has by definition. Two rounds, because one round
cannot separate a difference from this host's variance (#171):

| clients | round 1 | round 2 | mean latency | p95 latency |
|---|---|---|---|---|
| 1 | 964/s | 940/s | 1.0 ms | 1.3 ms |
| 2 | 1 565/s | 1 542/s | 1.3 ms | 2.0 ms |
| 4 | **1 687/s** | **1 705/s** | 2.0 ms | 4.1 ms |
| 8 | 1 364/s | 1 542/s | 4.7 ms | 10.1 ms |

Peak write throughput on this host is around **1 700 sends per second**.

**The host has four cores, and the driver runs its clients as threads on
those same four cores.** So at eight clients the harness is competing
with the server it is measuring, and the fall from four to eight is *not*
a clean statement about the server — it is what any server would do when
the load generator takes half the machine. The rows at 1, 2 and 4 are the
ones this host can speak to, and even they are measured against a client
that is not free.

The first version of this section read "scales about 1.8× and then
stops", which asserted a property of Spindle that this rig cannot
establish. Recorded here rather than quietly edited, because the
correction is the same kind of finding as the two above: an axis whose
confound was not checked before the number was written down.

**What survives the confound**, because it does not depend on the shape
of the curve:

- The **ratios** against another server measured in the same sitting on
  the same box. That is this document's stated method — "ratios measured
  inside a single run are the result" — and it is why the Synapse
  comparison below stands while the scaling claim did not.
- `rode = 0`, from `tests/probe.rs`. Group commit never once coalesced
  two commits across 200 sends with eight workers. That is a *direct
  observation* that two writers were never inside `commit()` together,
  not an inference from a throughput curve, and no amount of core
  starvation produces it.

A clean scaling curve needs the driver off the box, or a box with more
cores than clients. Neither is available here, so the claim is not made.

### How to read this against the rest of the page

Every other table here is a latency at concurrency 1, and Spindle wins
almost all of them by large margins. Both things are true at once, and
neither replaces the other:

- What a **user** waits for one message is excellent.
- What an **operator** gets for a given box tops out at ~1 700 writes/s.

### Against Synapse, on the same axis

Synapse 1.159.0, same host, same driver, same sitting, single process,
measured on **both** back ends because for a throughput comparison the
database is not a detail — SQLite has a single-writer lock, which is
exactly the property under test:

| clients | Spindle | Synapse (SQLite) | Synapse (Postgres) |
|---|---|---|---|
| 1 | 964/s | 39/s | 24/s |
| 2 | 1 565/s | 43/s | 34/s |
| 4 | **1 705/s** | 46/s | 33/s |
| 8 | 1 364/s | 48/s | 33/s |

Latency under that load, mean / p95, at eight clients: Spindle
4.7 / 10.1 ms, Synapse 164 / 184 ms on SQLite and 238 / 283 ms on
Postgres.

**Spindle's per-process write throughput is 25–50× Synapse's**, and
unlike the latency figures elsewhere on this page, this one holds *under
concurrency* — which is the thing a 20× latency win does not on its own
imply. No separation arithmetic is offered for it because none is needed:
the repeatability rule (#171) exists to keep a 1.2× cell honest, and a
25× gap is not a cell that variance decides.

Synapse is flat too: 39 → 48 and 24 → 34 across an eightfold increase in
clients. Both were measured under the same four-core constraint as
Spindle, which is exactly why the comparison survives it — the handicap
is shared, so the ratio is the result and the curve is not.

**Postgres is slower than SQLite here, and that is not a surprise or a
misconfiguration.** At one process and this volume, Postgres pays
per-query and network overhead that a local file does not, and its
advantages — concurrency, larger working sets, replication — are the ones
this shape does not exercise. The Postgres instance is stock, and tuning
it would move the number.

### The caveat this comparison has to carry

Both Synapse configurations run as **one process**. That is the fair
like-for-like against Spindle today, and it is not the whole production
story: Synapse's actual answer to throughput is horizontal — worker
processes splitting the load across cores and hosts — and Spindle has no
scale-out at all (#24, deferred to M6).

So the honest statement is per-process, and it is still a large one: on
one process, Spindle does 25–50× the writes. What it does not establish
is a win against a *sharded* Synapse deployment, and it will not until
#24 exists.

The ceiling's cause is not a mystery, and it is not the storage engine:
the single `Mutex<HashMap<String, RoomLog>>` in `Rooms::with_room` is
held across an append's work, so appends to different rooms cannot
proceed at the same time. The fsync used to be inside it too, and moving
it out (see above) bought about 30%; what remains is the lock.

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
