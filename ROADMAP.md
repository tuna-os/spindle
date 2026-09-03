# Spindle Roadmap

**Last updated**: 2026-09-02 | **Status**: Experiment under construction — not a deployment

Part of the [TunaOS](https://tunaos.org) ecosystem. A Matrix homeserver that
stores rooms as a linear log, so state resolution never runs on the hot path.

## What this file is, and is not

Milestone standings are **not** duplicated here. They live in
[docs/dashboard.md](docs/dashboard.md), which is generated from the router by
`scripts/coverage-dashboard.py` and gated in CI on drift — so it matches `main`
rather than matching whoever last edited a paragraph. A second hand-maintained
milestone table would be a second thing to drift, and the org has already paid
for that lesson once (`tuna-os/.github` ROADMAP-INDEX.md).

What this file carries is the part no generated artifact can produce: **the
maturity contract** — what has to be demonstrated before Spindle stops being an
experiment, and what is deliberately not being built yet.

- Milestone status: [docs/dashboard.md](docs/dashboard.md) (generated, drift-gated)
- Milestone scope and sequencing: [#4](https://github.com/tuna-os/spindle/issues/4)
- The design the code is held against: [SPEC.md](SPEC.md)
- What is inherited, what is ours, what is deferred: [docs/divergence.md](docs/divergence.md)

## Current foundation

- Rooms stored as an append-only log keyed by an `i64` linear index that *is* the
  topological order; state materialized in a content-addressed HAMT
- Client-server surface broad enough that Element, Element X, Cinny, Nheko and
  FluffyChat work unmodified against ordinary room version 11 rooms
- Federation interoperating with real Synapse in both directions, and
  Spindle-to-Spindle remote joins proven by a two-instance test
- Published benchmarks against Synapse, Continuwuity and Tuwunel — including the
  cells Spindle lost and two claims retracted after publication
- CI gates: the Complement ratchet, config drift, dashboard drift, pinned
  actions, and a semgrep rule for the authorization-shaped defect

## Release maturity

Spindle has **no tagged release**. That is the correct standing for the current
stage and the README says so plainly. What has been missing is a stated
condition under which it changes — so this section is that condition, and the
absence of a release is a decision with an exit rather than a default.

### `v0.0.x` — an addressable prerelease

The near-term step is not a stability promise. It is a *name*, so that a
benchmark result, a security fix, and a storage-format change can each be said
to belong to something.

| Gate | Required evidence |
|---|---|
| Addressability | A `v0.0.1` tag cut from `main`, with release notes stating what it is not: no upgrade path, no support window, storage format unstable |
| Storage format identity | A storage-format version distinct from the binary version, with the already-broken transition recorded as a numbered format change in [docs/lifecycle.md](docs/lifecycle.md) |
| Benchmark provenance | Every published comparison names the Spindle build it measured, as it already names Synapse 1.159.0 |

Tracked by [#308](https://github.com/tuna-os/spindle/issues/308).

### `v0.1.0` — the first release an outsider could reason about

Evidence-based, not a date. Each gate is a demonstration on one candidate
commit, and the candidate's evidence links belong in the release notes.

| Gate | Required evidence |
|---|---|
| Authorization surface | [#268](https://github.com/tuna-os/spindle/issues/268)'s systematic audit closed — the route table walked by a stranger for every room-scoped route, not "however much someone happened to look" |
| Vulnerability intake | Private vulnerability reporting enabled on this repository and a `SECURITY.md` naming the server-software classes: authorization bypass, federation forgery, cross-account disclosure, unauthenticated resource exhaustion ([#307](https://github.com/tuna-os/spindle/issues/307)) |
| The load-bearing claim | The SPEC §9.3 equivalence theorem's differential oracle against `ruma-state-res` passing on a schedule, not only on demand. A counterexample is a release blocker |
| Federation under adversity | [#16](https://github.com/tuna-os/spindle/issues/16)'s fork-proof rig green, and [#225](https://github.com/tuna-os/spindle/issues/225) — a federated fork wedging a room permanently — fixed with a regression test |
| Lifecycle round trip | `backup` → `restore` → `verify-media` demonstrated across a version boundary, with at least one real migration in the migration table rather than synthetic fixtures |
| Performance parity | [#42](https://github.com/tuna-os/spindle/issues/42)'s protocol-workload comparison against Tuwunel and Synapse published under the counting discipline the benchmark host requires |
| Operator readiness | Rate limits and resource caps inventoried with nothing load-bearing left unbounded ([#299](https://github.com/tuna-os/spindle/pull/299) began this), and a stated supported-version line |

A `v0.1.0` release note that cannot link evidence for a row above should not be
published; the row should be moved instead. Maturity is not inferred from
`main` being green or from a benchmark being fast.

## Contributor entry

The project's velocity has so far been single-author. Making Spindle joinable is
a roadmap item, not an afterthought — it is the org's only fresh Rust codebase
with an embedded store, no database to provision, and `cargo test --workspace`
as the whole gate.

Near-term, tracked by [#306](https://github.com/tuna-os/spindle/issues/306):

- Repository topics and a homepage link, so the benchmark site is reachable from
  the repository header
- `good first issue` and `help wanted` applied to the issues that already
  qualify — the labels exist and have never been used
- GitHub milestones matching the dashboard's `M0`–`M7`, so the frontier is
  visible where a newcomer would look for it

Build and test commands are in the [README](README.md#building-and-contributing);
org-wide contribution guidance is in
[tuna-os/.github](https://github.com/tuna-os/.github/blob/main/CONTRIBUTING.md).

## Deliberately not now

Recorded so that absence reads as a decision rather than an oversight:

- **Horizontal scale-out** — deferred until after a single-node production gate
  ([#24](https://github.com/tuna-os/spindle/issues/24))
- **MLS** — evaluated only after Megolm compatibility ships
  ([#23](https://github.com/tuna-os/spindle/issues/23))
- **Hub mode (MSC3995)** — the differentiator, behind a feature flag, after the
  ordinary-federation path is proven ([#22](https://github.com/tuna-os/spindle/issues/22))
- **Synapse importer** — parked behind the API surface and MatrixRTC
  ([#240](https://github.com/tuna-os/spindle/issues/240))
- **TURN, push gateway, identity server** — deliberately unbundled services, per
  [#4](https://github.com/tuna-os/spindle/issues/4)'s *what not to build early*

## Risks to the headline claim

The claim that window-bounded state resolution equals full state resolution is
the one that would invalidate the project if it broke. The enumerated risks live
in [SPEC §21](SPEC.md), and the metric the architecture is falsified by — the
fork-case counter — is exported and documented in [docs/metrics.md](docs/metrics.md).
Two further caveats the README states and this roadmap inherits: the
architectural win is a constant factor rather than an asymptotic one, and every
federation number so far is a design target measured on one server.
