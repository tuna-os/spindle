# Spindle

**A Matrix homeserver with no state resolution on the hot path.**

Status: design specification, v0.1. Nothing is implemented yet — this repository
is the spec and the argument for it.

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

## What this is honest about

The load-bearing claim is the equivalence theorem in §9.3 — that window-bounded
state resolution produces exactly what full state resolution would. It is stated
as a theorem and meant to be tested as one, differentially against
`ruma-state-res` as an oracle (§19.2). A counterexample is a release blocker.

The performance numbers in §18.3 are **design targets, not measurements**. They
exist so the design can be falsified by the benchmark harness in §19.4.

The known risks, including the one that would invalidate the headline claim, are
enumerated in §21.
