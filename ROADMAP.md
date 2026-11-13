# Spindle Roadmap

**Last updated**: 2026-11-10 | **Status**: Prerelease. `v0.1.x` is the supported line, and one production deployment uses it

Part of the [TunaOS](https://tunaos.org) ecosystem. One binary for Matrix
chat, login and calls: a homeserver that stores rooms as a linear log, so
state resolution never runs on the hot path.

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
- GitHub work queues: [M0–M7 milestones](https://github.com/tuna-os/spindle/milestones?state=open)
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
- Published benchmarks against Synapse, Dendrite, Continuwuity and Tuwunel —
  including the cells Spindle lost and two claims retracted after publication
- A built-in OIDC provider and a built-in LiveKit JWT service, so Element X
  login and Element Call need no MAS and no `lk-jwt-service`
- A Synapse importer and a fenced cutover procedure, which carried the
  reilly.asia migration from Synapse on ESS
  ([#563](https://github.com/tuna-os/spindle/issues/563))
- CI gates: the Complement ratchet, config drift, dashboard drift, pinned
  actions, and a semgrep rule for the authorization-shaped defect

## Release maturity

Spindle tagged `v0.1.0` on 2026-10-10, and it is still a prerelease.
[docs/v0.1.0-readiness.md](docs/v0.1.0-readiness.md) holds the gate evidence
for that tag.

### `v0.0.x` — an addressable prerelease

The near-term step is not a stability promise. It is a *name*, so that a
benchmark result, a security fix, and a storage-format change can each be said
to belong to something.

| Gate | Required evidence |
|---|---|
| Addressability | `v0.0.x` tags cut from `main` weekly by the release workflow when CI is green, with release notes stating what they are not: no upgrade path, no support window, storage format unstable |
| Storage format identity | A storage-format version distinct from the binary version, with the already-broken transition recorded as a numbered format change in [docs/lifecycle.md](docs/lifecycle.md) |
| Benchmark provenance | Every published comparison names the Spindle build and the version of each competitor that it measured. Each sitting records them in its `sitting.json` sidecar ([docs/benchmarks.md](docs/benchmarks.md)) |

All three gates are met, and [#308](https://github.com/tuna-os/spindle/issues/308)
is closed. The release workflow cut `v0.0.1` to `v0.0.3`.
[docs/lifecycle.md](docs/lifecycle.md) records the format versions.

### `v0.1.0` — the first release an outsider could reason about

Evidence-based, not a date. Each gate is a demonstration on one candidate
commit, and the candidate's evidence links belong in the release notes.

| Gate | Required evidence |
|---|---|
| Authorization surface | [#268](https://github.com/tuna-os/spindle/issues/268)'s systematic audit closed — the route table walked by a stranger for every room-scoped route, not "however much someone happened to look" |
| Vulnerability intake | [#307](https://github.com/tuna-os/spindle/issues/307) closed — private vulnerability reporting is on for this repository, and `SECURITY.md` names the server-software classes: authorization bypass, federation forgery, cross-account disclosure, unauthenticated resource exhaustion |
| The load-bearing claim | Scheduled differential checks against `ruma-state-res`, including the retired merge counterexamples and resolver delegation (ADR 0005), plus the exhaustive fork-window oracle. A disagreement on the live path is a release blocker |
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

Completed under [#306](https://github.com/tuna-os/spindle/issues/306):

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

- **Horizontal scale-out** — deferred until the single-node ceilings are
  published ([#693](https://github.com/tuna-os/spindle/issues/693)); the design
  questions are [#694](https://github.com/tuna-os/spindle/issues/694) and
  [#695](https://github.com/tuna-os/spindle/issues/695)
- **MLS** — evaluated after Megolm compatibility shipped, and a no-go until a
  stable MSC, a maintained client and hub mode exist
  ([#23](https://github.com/tuna-os/spindle/issues/23), [docs/mls.md](docs/mls.md))
- **Hub mode (MSC3995) in release builds** — the code is on `main` behind the
  off-by-default `hub-mode` cargo feature and has tests between Spindle
  peers. It stays out of the release builds until the ordinary-federation
  path is proven ([#22](https://github.com/tuna-os/spindle/issues/22))
- **TURN, push gateway, identity server** — deliberately unbundled services, per
  [#4](https://github.com/tuna-os/spindle/issues/4)'s *what not to build early*

## What the 2026-11 review found

A review of the code and the documents on 2026-11-10 gave these work queues.
They are the largest distances between Spindle and a server that a stranger
can operate.

| Area | The gap | Issues |
|---|---|---|
| Durability outside the room log | Writes of one key do not sync. Restore is not atomic. The backup file is not synced, and a backup needs downtime | [#810](https://github.com/tuna-os/spindle/issues/810), [#811](https://github.com/tuna-os/spindle/issues/811), [#812](https://github.com/tuna-os/spindle/issues/812), [#813](https://github.com/tuna-os/spindle/issues/813), [#815](https://github.com/tuna-os/spindle/issues/815) |
| Growth without a bound | Open rooms stay in memory. History and some replay tables have no retention. Garbage collection is offline | [#814](https://github.com/tuna-os/spindle/issues/814), [#816](https://github.com/tuna-os/spindle/issues/816), [#817](https://github.com/tuna-os/spindle/issues/817), [#818](https://github.com/tuna-os/spindle/issues/818), [#821](https://github.com/tuna-os/spindle/issues/821), [#833](https://github.com/tuna-os/spindle/issues/833) |
| Sync and federation correctness | Clients do not get state that fork resolution changed. An incremental `/sync` has no limit. A refused event is not fetched again | [#819](https://github.com/tuna-os/spindle/issues/819), [#820](https://github.com/tuna-os/spindle/issues/820), [#822](https://github.com/tuna-os/spindle/issues/822), [#823](https://github.com/tuna-os/spindle/issues/823) |
| Moderation and abuse | No media quarantine, no federation allow or deny list for the server, no CAPTCHA. Rate limits by source address do not work behind a proxy | [#827](https://github.com/tuna-os/spindle/issues/827), [#828](https://github.com/tuna-os/spindle/issues/828), [#829](https://github.com/tuna-os/spindle/issues/829), [#831](https://github.com/tuna-os/spindle/issues/831), [#832](https://github.com/tuna-os/spindle/issues/832) |
| Deployment and product | No Compose file, systemd unit, Helm chart or packages. The Synapse importer is not in the release builds. Email pushers do not deliver, search has no index, and SPEC.md describes some mechanisms that are not built | [#825](https://github.com/tuna-os/spindle/issues/825), [#826](https://github.com/tuna-os/spindle/issues/826), [#824](https://github.com/tuna-os/spindle/issues/824), [#830](https://github.com/tuna-os/spindle/issues/830), [#834](https://github.com/tuna-os/spindle/issues/834) |

## Risks to the headline claim

The claim that window-bounded state resolution equals full state resolution is
the one that would invalidate the project if it broke. The enumerated risks live
in [SPEC §21](SPEC.md), and the metric the architecture is falsified by — the
fork-case counter — is exported and documented in [docs/metrics.md](docs/metrics.md).
Two further caveats the README states and this roadmap inherits: the
architectural win is a constant factor rather than an asymptotic one, and every
federation number so far is a design target measured on one server.
