# Spindle

**A Matrix homeserver with no state resolution on the hot path.**

**[Benchmarks vs Synapse, Continuwuity and Tuwunel](https://tuna-os.github.io/spindle/comparisons.html)**
— animated architecture explainer, per-operation latency curves, and a
color-coded heatmap where every slower cell links to its investigation.
Also on the site: [micro-benchmarks](https://tuna-os.github.io/spindle/) ·
[spec coverage dashboard](https://tuna-os.github.io/spindle/dashboard.html).

Status: implementation in progress. The M1 client-server surface — rooms,
timelines, state, membership and moderation, relations, redaction, receipts,
typing, account data, push rules, aliases, filters, `/context`, MSC3266
summaries, MSC4222 `state_after` — and the M2 surface (media, sliding sync,
E2EE transport) are implemented and tested, on an append-only log with
materialized state (`spindle-core`, `spindle-store`, `spindle-server`).
M3 federation is under way and interoperating: the join, invite and leave
handshakes, backfill, and event fetching work against real peers
(including live Spindle↔Synapse rooms in both directions), gated by a
169-test Complement ratchet in CI. SPEC.md remains the design the code is
held against.

Measured every milestone against Synapse and both Rust siblings on the same
host and driver ([method](docs/benchmarks.md), [live results](https://tuna-os.github.io/spindle/comparisons.html)):
at M3-progress, 61 of 63 cells faster or within noise — joins 27–35× and
sends ~21× vs Synapse — and the two slower cells were investigated and
fixed, with the losses published as measured. The honest caveat stands:
these are unforked workloads; the architectural claim gets its full test as
the federation rig grows.

## The idea

Matrix stores rooms as a replicated DAG, and everything expensive about running a
homeserver — state groups, auth-chain differences, topological ordering, forward
extremity churn — exists to answer one question: *given concurrent branches, what
is the room state?*

Almost no real traffic has concurrent branches. A room owned by one server, or a
room whose events all flow through one serializing node, has a DAG that is a
**chain**: every event has exactly one `prev_event` and there is never more than
one forward extremity. On a chain, state resolution is the identity function.

Spindle takes the Linearized Matrix idea (MSC3995 /
`draft-ralston-mimi-linearized-matrix`) and applies it *inward*, as a server
implementation strategy, rather than only outward as a federation profile for
thin third-party implementations:

- **Rooms are stored as an append-only linear log**, keyed by an `i64` linear
  index that *is* the topological order, assigned once at write time.
- **State is materialized, not computed** — a persistent, content-addressed HAMT
  with structural sharing. Advancing state copies ~3 nodes; state at any
  historical point is one index seek plus `O(log n)` lookups.
- **Authorization is ≤6 in-memory trie lookups.** No auth chain is traversed.
- **State resolution runs only inside a bounded fork window**, only when a legacy
  DAG peer actually forks, and only when that fork conflicts on state. In a
  non-federated room it never runs at all.

## Why existing clients and servers keep working

Native Spindle rooms are ordinary **room version 11** rooms. A chain is a valid
DAG, so the performance properties come from the implementation, not from a new
wire format — no new room version, no client capability, no peer negotiation.
Element, Element X, Cinny, Nheko and Fluffychat talk to it unmodified; Synapse,
Dendrite and Conduit federate with it over the unmodified Server-Server API.

The MSC3995 hub protocol is an opt-in optimization layered on top, negotiated per
room via `m.room.hub`. Where every peer supports it, forks become structurally
impossible and the exception path is dead code.

## Read the spec

**[SPEC.md](SPEC.md)** — the full design, covering:

| | |
|---|---|
| §3–5 | Where the time goes · room classes · the linear log |
| §6–9 | State without state resolution · authorization · ingest · fork handling |
| §10–12 | Client-Server API compatibility · federation · linearized mode |
| §13–15 | Trust model and equivocation proofs · storage · concurrency |
| §16–18 | Encryption (Megolm now, MLS track) · operations · performance model |
| §19–23 | Correctness strategy · migration · risks · roadmap · prior art |

**[docs/conformance-testing.md](docs/conformance-testing.md)** — how we prove
interoperability: adopting Complement, complement-crypto and the spec's own
OpenAPI schemas, plus the three things we have to build ourselves (a
heterogeneous Spindle↔Synapse interop rig, fork injection, and a property-test
oracle for the equivalence claim).

**[docs/delegated-auth.md](docs/delegated-auth.md)** — modern (MSC3861)
authentication, both ways to get it: the built-in OIDC provider that
gives Element X login from one binary with nothing else deployed, and
running Spindle behind a real Matrix Authentication Service — the config
on both sides, what turns off, the revocation window, and what an
unmodified MAS release binary has been proven to do against it.

**[docs/divergence.md](docs/divergence.md)** — the seam: what we inherit
unchanged from the Matrix spec, ruma and Complement, what is genuinely ours
(the linear index, the state trie, the bounded fork window, the log chain,
the store format), and what is deliberately deferred. Short version: we
diverge below the wire and nowhere above it — and there is no MSC3995
protocol code here yet, by design.

## What this is honest about

The load-bearing claim is the equivalence theorem in §9.3 — that window-bounded
state resolution produces exactly what full state resolution would. It is now
tested as one, differentially against `ruma-state-res` as an oracle (§19.2), for
every fork the fast path claims to handle without state resolution. A
counterexample is a release blocker.

**The comparison against another implementation is a constant factor, not the
asymptotic win the design thesis originally implied.** Resolving a fork is
2.2–3.1× cheaper than `ruma-state-res` across the whole range out to a full
`max_fork_window` — flat, not widening. And the current Rust homeservers already
skip state resolution on a fork-free event, so "we skip it and they don't" was
never true of them. What linear storage removes is the per-event *bookkeeping*
the algorithm needs to exist — extremity sets, state-group delta stacks — not
the algorithm. See [§3](SPEC.md#3-design-thesis-where-the-time-actually-goes)
and [docs/benchmarks.md](docs/benchmarks.md), which publishes the losses
alongside the wins.

Where everything stands — milestones, endpoint coverage parsed from the
router, and how each benchmark is published — is on the generated
[dashboard](docs/dashboard.md), kept in step with main by a CI drift gate
and republished to the [benchmark site](https://tuna-os.github.io/spindle/dashboard.html)
on every push.

Server-to-server numbers remain **design targets, not measurements** (§18.3):
everything measured so far is algorithmic, inside the library. Synapse and
Tuwunel under protocol workload needs a server and starts at M1.

The known risks, including the one that would invalidate the headline claim, are
enumerated in §21.
