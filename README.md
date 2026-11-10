# Spindle

**One binary for Matrix chat, login and calls. No PostgreSQL, no separate
identity service and no JWT sidecar.**

Spindle is a Matrix homeserver in Rust. It stores each room as a linear log
with materialized state, so state resolution never runs on the hot path.

[**Benchmarks vs Synapse, Dendrite, Continuwuity and Tuwunel**](https://tuna-os.github.io/spindle/comparisons.html)
· [micro-benchmarks](https://tuna-os.github.io/spindle/)
· [spec coverage dashboard](https://tuna-os.github.io/spindle/dashboard.html)
· [SPEC.md](SPEC.md)

> **Status: prerelease.** The client-server surface is broad and tested,
> and federation interoperates with Synapse. The first supported maturity
> line is `v0.1.x`, subject to the exact candidate checks and evidence in
> [v0.1.0 readiness](docs/v0.1.0-readiness.md). Use the newest patch and the
> [operator guide](docs/operations.md). Explicit migrations can need downtime;
> rollback restores a pre-migration backup. Earlier `v0.0.x` tags identify
> experimental builds and receive no backports.

---

## Why Spindle

Spindle is for an operator who wants a full Matrix deployment for a family,
a team or an event, and who does not want to operate five services to get it.

| You need | With Spindle | Evidence |
|---|---|---|
| A homeserver without a database server | One process and one directory. The store is embedded ([fjall](https://github.com/fjall-rs/fjall)). | [SPEC.md](SPEC.md) |
| Element X login (MSC3861) | A built-in OIDC provider with account pages, upstream SSO, email confirmation and password reset. A real MAS also works. | [docs/delegated-auth.md](docs/delegated-auth.md) |
| Element Call | MatrixRTC is served: delayed events (MSC4140), sticky events (MSC4354) and a built-in LiveKit JWT service. You supply only the SFU. | [docs/matrix-rtc.md](docs/matrix-rtc.md) |
| Modern clients | Simplified Sliding Sync (MSC4186), E2EE transport, key backup, cross-signing, authenticated media and threads. | [docs/dashboard.md](docs/dashboard.md) |
| Your Synapse tools | The admin API is also mounted at `/_synapse/admin`, and CI runs `synadm` against it. | [docs/spec-gaps.md](docs/spec-gaps.md) |
| A way off Synapse | An importer that reads a Synapse PostgreSQL database, an importer for MAS accounts, and a fenced cutover procedure for ESS on Kubernetes. | [docs/migration-workspace.md](docs/migration-workspace.md) |
| Low write latency on small hardware | Per-process write throughput 25–50× that of Synapse in the published comparison. The cells that Spindle lost are published too. | [docs/benchmarks.md](docs/benchmarks.md) |
| Proof, not promises | CI holds the route count, the Complement ratchet, the configuration reference and the MSC ledger to the code. Releases have an SBOM and a signed provenance attestation. | [docs/maintenance.md](docs/maintenance.md) |
| A permissive licence | MIT or Apache-2.0. Synapse and Dendrite are AGPL-3.0. | [LICENSING.md](LICENSING.md) |

### How it compares

This table is a summary on 2026-11-10. The other projects change; read their
documentation before you decide.

| | Spindle | Synapse | Continuwuity and Tuwunel |
|---|---|---|---|
| Language | Rust | Python and Rust | Rust |
| Storage | Embedded fjall | PostgreSQL | Embedded RocksDB |
| MSC3861 login | Built in, or MAS | MAS, a separate service | See their documentation |
| LiveKit JWT for calls | Built in, or `lk-jwt-service` | `lk-jwt-service`, a separate service | See their documentation |
| Administration | HTTP admin API with Synapse paths | HTTP admin API | Commands in an admin room |
| Import from Synapse | Yes | Not applicable | No |
| Scale-out across processes | No | Yes, with workers | No |
| Maturity | Prerelease, one known production deployment | Many years in production at large scale | Production use by many small servers |
| Licence | MIT or Apache-2.0 | AGPL-3.0 or commercial | Apache-2.0 |

### When to choose a different server

- You need more than one process for each deployment, or high availability.
  Spindle runs one process against each store
  ([#693](https://github.com/tuna-os/spindle/issues/693)).
- Most of your traffic is in very large public rooms that many servers
  share. Forks are frequent there, and the linear log then does the same
  state resolution as each other server. Each open room also keeps its
  index in memory ([#816](https://github.com/tuna-os/spindle/issues/816)).
- You need open public registration. Spindle has registration tokens and
  rate limits, but no CAPTCHA and no general storage quota for each account
  ([#829](https://github.com/tuna-os/spindle/issues/829)).
- You need message retention policies, LDAP or SAML, or third-party
  invites. Spindle does not have them
  ([#817](https://github.com/tuna-os/spindle/issues/817),
  [docs/spec-gaps.md](docs/spec-gaps.md)).
- You need a long record of stable releases. Each Spindle release is a
  prerelease, and a format migration can need downtime.

## Try it in three commands

```bash
cargo build --release -p spindle-server --bin spindle

cat > spindle.toml <<'EOF'
[server]
name = "localhost:8008"
bind = "127.0.0.1:8008"

[storage]
path = "./data"
EOF

./target/release/spindle spindle.toml
```

That is the whole minimum configuration — a name, an address, a directory. No
database to provision, no separate identity service, no reverse proxy needed to
get a first login.

```bash
# Register an account
curl -XPOST localhost:8008/_matrix/client/v3/register \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"hunter2",
       "auth":{"type":"m.login.dummy","session":"s"}}'

# → {"access_token":"syt_…","device_id":"DEV…","user_id":"@alice:localhost:8008"}
```

Point Element, Element X, Cinny, Nheko or FluffyChat at `http://localhost:8008`
and it works unmodified — Spindle serves ordinary rooms of room versions 1 to
12, so there is no client capability to negotiate.

[`spindle.example.toml`](spindle.example.toml) documents every setting, and a
CI gate fails if a config field exists in the code and not in that file.

**Registration is open in this minimum configuration.** That is safe on
loopback only. Before you expose the server, set `[registration]
require_token = true` and obey the [operator guide](docs/operations.md).

### Or run a release

Each release has tarballs for `x86_64` and `aarch64` Linux and a container
image for the same two architectures. No `latest` tag exists, so name a
release:

```bash
docker run -v ./spindle.toml:/etc/spindle/spindle.toml:ro \
           -v spindle-data:/var/lib/spindle \
           -p 8008:8008 ghcr.io/tuna-os/spindle:v0.1.2
```

In the container, set `bind = "0.0.0.0:8008"` and `[storage] path =
"/var/lib/spindle"`. [docs/releasing.md](docs/releasing.md) tells how to
verify the provenance of an image or a tarball.

**Other commands:** `promote-admin` (mints the first admin offline),
`set-password-hash` (imports Argon2 or bcrypt hashes),
`issue-reset-link` (a password-reset link that needs no mail),
`backup` / `restore` / `verify-media`, `migrate`, `gc` (frees unused state).
`import-mas` moves MAS accounts to the built-in provider. The release
builds have it; from source, build with `--features mas-import`.
`import-synapse` reads a Synapse PostgreSQL database. Build from source
with `--features synapse-import` to get it; the release builds do not
have it yet ([#826](https://github.com/tuna-os/spindle/issues/826)).
See [docs/lifecycle.md](docs/lifecycle.md) and
[docs/migration-workspace.md](docs/migration-workspace.md).

---

## The idea

Matrix stores rooms as a replicated DAG, and everything expensive about running
a homeserver — state groups, auth-chain differences, topological ordering,
forward-extremity churn — exists to answer one question: *given concurrent
branches, what is the room state?*

**Almost no real traffic has concurrent branches.** A room owned by one server,
or a room whose events all flow through one serializing node, has a DAG that is
a **chain**: every event has exactly one `prev_event`, and there is never more
than one forward extremity. On a chain, state resolution is the identity
function.

Spindle takes the Linearized Matrix idea (MSC3995 /
`draft-ralston-mimi-linearized-matrix`) and applies it *inward*, as a storage
and execution strategy, rather than only outward as a federation profile:

| | |
|---|---|
| **Rooms are an append-only log** | keyed by an `i64` linear index that *is* the topological order, assigned once at write time |
| **State is materialized, not computed** | a content-addressed HAMT with structural sharing; advancing state copies ~3 nodes, and state at any past point is one seek plus `O(log n)` lookups |
| **Authorization is ≤6 trie lookups** | no auth chain is ever traversed |
| **State resolution is the exception path** | it runs only inside a bounded fork window, only when a legacy DAG peer actually forks, and only when that fork conflicts on state |

In a non-federated room, state resolution never runs at all.

### Why clients and servers keep working

Native Spindle rooms are ordinary room version 11 rooms. A chain is a valid DAG,
so the performance properties come from the implementation, not a new wire
format — no new room version, no client capability, no peer negotiation.
Other homeservers federate with it over the unmodified Server-Server API.
CI proves this against Synapse in both directions, and the benchmark rig
federates with Tuwunel.

MSC3995 hub mode is an opt-in optimisation layered on top, negotiated per room
via `m.room.hub`. Where every peer supports it, forks become structurally
impossible and the exception path is dead code. It is behind the `hub-mode`
cargo feature, which is off by default and is not in the release builds.

---

## Where it stands

| Milestone | | |
|---|---|---|
| **M0** Prove the core | **Done** | Fork resolution vs `ruma-state-res` as a differential oracle; HAMT benchmarks; torn-write and restart recovery |
| **M1** Local homeserver | **Done** | Rooms, timelines, state, membership, moderation, relations, threads, redaction, receipts, typing, account data, push rules, aliases, filters, `/context` |
| **M2** Modern clients | **Done** | Media + thumbnails, S3 backend, Simplified Sliding Sync, E2EE transport, device lists, key backup, cross-signing, URL previews |
| **M3** Federation | Interoperating | Signed requests, join/invite/leave/knock handshakes, backfill, state reads, outbound queue with backoff — live Spindle↔Synapse rooms in both directions; MSC4242 state-DAG rooms (Hydra phase 2) and E2EE keys, to-device and device lists across the seam to a Neutrino mesh node, measured by a loopback rig |
| **M4** Ecosystem | Substantial | Appservices (transactions, MSC2409 to-device, MSC4190), MSC3861 delegated auth, the `/_synapse/mas/*` surface, and a built-in OIDC provider so Element X login needs one binary |
| **M5** Lifecycle | Substantial | An admin API (also at `/_synapse/admin`), `/metrics` with the fork-case counter, backup/restore/verify-media, versioned migrations, and a Synapse importer that carried one production cutover |
| **M6** Differentiators | In progress | Hub mode is built behind the off-by-default `hub-mode` feature and tested between Spindle peers. MLS is a recorded no-go ([docs/mls.md](docs/mls.md)) |
| **M7** MatrixRTC | Server side served | **MSC4140 delayed events** — the dead-man's switch that stops calls accumulating ghost participants, which no other Rust homeserver served when Spindle added it — plus MSC4354 sticky events, MSC4143 transport discovery, a built-in LiveKit JWT service or the OpenID round trip for an external one, ringing and decline. Element Call's own Playwright suite runs with Spindle in Synapse's seat: thirteen specs pass, among them a two-party call with video through LiveKit and MatrixRTC 2.0 sticky-event membership with a rejoin after an improper leave. Spindle's own specs in the same rig add ringing, churn, a restart mid-call and a federated call |

**316 routes** and a **424-test Complement ratchet** in CI, over a workspace of
100+ test suites. The first two are gated — the [dashboard](docs/dashboard.md)
is parsed from the router and CI fails on drift, and the ratchet is a file every
entry of which must pass — so what they say matches `main` rather than matching
when someone last edited this paragraph.

### Throughput (dated snapshot)

The table below is a dated analysis snapshot, not the current benchmark
result. See the [published benchmark results](https://tuna-os.github.io/spindle/)
for the latest run and [the benchmark notes](docs/benchmarks.md) for the
method and the limitations of comparing snapshots.

Same host, same driver, same sitting; Synapse 1.159.0 on both back ends,
because for a *write throughput* comparison the database is not a detail —
SQLite's single-writer lock is the property under test:

| clients | Spindle | Synapse (SQLite) | Synapse (Postgres) |
|---|---|---|---|
| 1 | 964/s | 39/s | 24/s |
| 2 | 1 565/s | 43/s | 34/s |
| 4 | **1 705/s** | 46/s | 33/s |
| 8 | 1 364/s | 48/s | 33/s |

Mean / p95 latency at eight clients: **4.7 / 10.1 ms** against Synapse's
164 / 184 ms (SQLite) and 238 / 283 ms (Postgres).

Per-process write throughput is **25–50× Synapse's**, and unlike a latency
figure this one holds *under concurrency*. Both servers ran under the same
four-core constraint, so the handicap is shared and the ratio is the result.

---

## What this is honest about

This section is longer than the marketing, on purpose.

**The architectural win is a constant factor, not an asymptotic one.**
Resolving a fork was 2.2–3.1× cheaper than `ruma-state-res` across the whole
measured range of fork depths — flat, not widening. And the current
Rust homeservers already skip state resolution on a fork-free event, so "we
skip it and they don't" was never true of them. What linear storage removes is
the per-event *bookkeeping* the algorithm needs in order to exist — extremity
sets, state-group delta stacks — not the algorithm.

**State resolution must agree with Matrix.** The old slot-wise fork merge
had counterexamples and was retired (ADR 0005). Differing fork states use
the room version's resolver. Scheduled checks preserve the counterexamples,
compare with `ruma-state-res`, and test the fork-window search against an
exhaustive walk. A disagreement on the live path is a release blocker.

**Losses are published next to wins.** [docs/benchmarks.md](docs/benchmarks.md)
carries the cells where Spindle lost, the investigations, and two claims that
were **retracted after being published here** — a scaling curve that turned out
to be the four-core test rig, and a 1.33× improvement measured against a
baseline from the wrong branch.

**The benchmark host cannot resolve small differences.** Four cores, 10–14%
run-to-run spread. So performance work is gated by *counting* — store reads,
lock acquisitions, coalesced fsyncs — not by wall clocks. When a change shows
in-process and not end-to-end, that is
[recorded as a non-result](docs/benchmarks.md).

**Federation numbers are still design targets.** Everything measured is one
server. The architectural claim gets its real test as the federation rig grows.

**Two authorization holes shipped and were found by reading, not by tests.**
Nine read endpoints served any room's contents to any account
(#257, #258). Both are fixed, with a route table walked by every test — and
#268 exists because the finding rate was "however much someone happened to
look".

**The rigour of the room log does not yet cover everything beside it.** A
review in 2026-11 found that writes of one key do not sync
([#810](https://github.com/tuna-os/spindle/issues/810)), that a restore is not
atomic ([#811](https://github.com/tuna-os/spindle/issues/811)), that clients do
not get the state that fork resolution changed
([#819](https://github.com/tuna-os/spindle/issues/819)), and that open rooms
stay in memory ([#816](https://github.com/tuna-os/spindle/issues/816)). The
[roadmap](ROADMAP.md#what-the-2026-11-review-found) has the full list.

The risks that would invalidate the headline claim are enumerated in
[SPEC §21](SPEC.md).

---

## Documentation

| | |
|---|---|
| [**SPEC.md**](SPEC.md) | The design the code is held against — the log, state without state resolution, authorization, fork handling, trust model, concurrency, performance model, risks |
| [docs/operations.md](docs/operations.md) | The supported release line and the controls a deployment must have |
| [docs/developer-guide.md](docs/developer-guide.md) | Crate boundaries and code paths for common contributor changes |
| [docs/benchmarks.md](docs/benchmarks.md) | Method, every measurement, and the retractions |
| [docs/divergence.md](docs/divergence.md) | The seam: what is inherited from Matrix, ruma and Complement; what is genuinely ours; what is deliberately deferred |
| [docs/conformance-testing.md](docs/conformance-testing.md) | How interoperability is proven |
| [docs/delegated-auth.md](docs/delegated-auth.md) | MSC3861, both ways — built-in provider or a real MAS |
| [docs/metrics.md](docs/metrics.md) | What is exported, including the number the architecture is falsified by |
| [docs/lifecycle.md](docs/lifecycle.md) | Backup, restore, migrations |
| [docs/migration-workspace.md](docs/migration-workspace.md) | Synapse cutover gates, evidence, authority, and recovery |
| [docs/synapse-kubernetes-cutover.md](docs/synapse-kubernetes-cutover.md) | Reversible ESS/Kubernetes quiesce and the production cutover gates |
| [docs/ess-kubernetes-driver.md](docs/ess-kubernetes-driver.md) | Discover, fence, switch, and recover an ESS deployment without two writers |
| [docs/rate-limits.md](docs/rate-limits.md) | Every rate and cap, and the growth nothing bounds yet |
| [docs/matrix-rtc.md](docs/matrix-rtc.md) | Calls end to end: the SFU, the JWT service built in or beside, and what a token cannot promise |
| [docs/operator.md](docs/operator.md) | The operator service and its admin console |
| [docs/mls.md](docs/mls.md) | Why MLS is a no-go today, and what reopens the question |
| [docs/policy-servers.md](docs/policy-servers.md) | Room opt-in, approval checks and Matrix Foundation enrollment |
| [docs/mesh-federation.md](docs/mesh-federation.md) | Federating with a Bluetooth mesh: the venue system, the loopback evidence, and the Neutrino gateway patch |
| [docs/venue-playbook.md](docs/venue-playbook.md) | Setting up the mesh and the conference Spindle, the test ladder, and the go/no-go list for 3,000 attendees |
| [docs/venue-gateway.md](docs/venue-gateway.md) | The venue gateway: the Neutrino node with the uplink, how to build, run, pair, and troubleshoot it |
| [docs/dashboard.md](docs/dashboard.md) | Generated endpoint and milestone coverage |
| [docs/mscs.md](docs/mscs.md) | Every MSC served, partly served, planned or declined — generated from the ledger CI holds to the code |
| [docs/spec-gaps.md](docs/spec-gaps.md) | What the pinned Matrix spec defines that the router does not serve, by the version that added it |
| [docs/maintenance.md](docs/maintenance.md) | Keeping up: the gates, the ratchets, the weekly upkeep report, and how a spec release or an MSC is absorbed |
| [docs/releasing.md](docs/releasing.md) | When the release workflow cuts a tag, what a release contains, and how to check a build |

---

## Building and contributing

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
scripts/complement.sh               # the interop ratchet (needs Docker)
```

`rust-toolchain.toml` pins **1.90.0** for development, so rustup fetches the
right compiler on its own. The release image pins its own compiler in the
`Dockerfile`. Storage is [fjall](https://github.com/fjall-rs/fjall) 3 — embedded,
so there is no database to provision.

CI gates on all of the above plus the Complement ratchet, a config-drift check,
a generated-dashboard drift check, and pinned-action and benchmark-tooling
checks. [CONTRIBUTING.md](CONTRIBUTING.md) has the longer version, and
[docs/releasing.md](docs/releasing.md) tells what a tag does. New performance
work is expected to arrive with a counting assertion rather than a timing one,
for the reason given above.

<!-- hive-contribute-plea: donated-compute appeal, keep in sync across repos -->
## Contribute compute — no code needed

**[Donate time with your AI CLI](https://hub.tunaos.org/#contribute).**

Your machine runs one task at a time using your signed-in AI coding CLI.
The relay alternates between eligible **School** (OS) and **Reef** (apps)
hives after each task. If one hive has no work, the other can continue.

The guide covers prerequisites, verified `just` setup, credentials, provider
costs, and how to stop with Ctrl+C. Your subscription quota or API charges apply.
Never post account credentials or API keys in issues or pull requests.

## License

Dual-licensed under **[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)**, at
your option; contributions are accepted under the same terms.
[`LICENSING.md`](LICENSING.md) records what was checked before choosing, why
not AGPL despite Synapse being AGPL, and why the copyright line reads as it
does.
