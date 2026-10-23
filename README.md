# Spindle

**A Matrix homeserver that stores rooms as a linear log, so state resolution
never runs on the hot path.**

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

<!-- hive-contribute-plea: donated-compute appeal, keep in sync across repos -->
## Contribute compute — no code needed

**[Donate time with your AI CLI](https://hub.tunaos.org/#contribute).**

Your machine runs one task at a time using your signed-in AI coding CLI.
The relay alternates between eligible **School** (OS) and **Reef** (apps)
hives after each task. If one hive has no work, the other can continue.

The guide covers prerequisites, verified `just` setup, credentials, provider
costs, and how to stop with Ctrl+C. Your subscription quota or API charges apply.
Never post account credentials or API keys in issues or pull requests.

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

Point Element, Element X, Cinny, Nheko or FluffyChat at `http://localhost:8008`.
They work without changes. Spindle serves rooms that use versions 1 to 12.
Clients do not need to negotiate capabilities.

[`spindle.example.toml`](spindle.example.toml) documents every setting, and a
CI gate fails if a config field exists in the code and not in that file.

**Other commands:** `promote-admin` (mints the first admin offline),
`set-password-hash` (imports Argon2 hashes, e.g. from MAS),
`issue-reset-link` (a password-reset link that needs no mail),
`backup` / `restore` / `verify-media`, `migrate`. See
[docs/lifecycle.md](docs/lifecycle.md).

---

## The idea

Matrix stores rooms as a replicated DAG. A homeserver does costly work for
state groups, auth-chain differences, topological order, and forward-extremity
churn. All this work answers one question: *what is the room state when
branches are concurrent?*

**Almost no real traffic has concurrent branches.** One server can own a room.
Alternatively, all events can flow through one node in sequence. Each case
gives the room a chain. Every event then has exactly one `prev_event`, and the
room never has more than one forward extremity. State resolution on a chain is
the identity function.

Spindle applies the Linearized Matrix idea (MSC3995 /
`draft-ralston-mimi-linearized-matrix`) *inward* as a storage and execution
strategy, not only outward as a federation profile:

| | |
|---|---|
| **Rooms are an append-only log** | keyed by an `i64` linear index that *is* the topological order, assigned once at write time |
| **State is materialized, not computed** | a content-addressed HAMT with structural sharing; advancing state copies ~3 nodes, and state at any past point is one seek plus `O(log n)` lookups |
| **Authorization is ≤6 trie lookups** | no auth chain is ever traversed |
| **State resolution is the exception path** | it runs only inside a bounded fork window, only when a legacy DAG peer actually forks, and only when that fork conflicts on state |

In a non-federated room, state resolution never runs at all.

### Why clients and servers keep working

Native Spindle rooms are ordinary room version 11 rooms. A chain is a valid DAG.
The implementation provides the performance without a new wire format, room
version, client capability, or peer negotiation. Synapse, Dendrite and Conduit
federate with it over the unmodified Server-Server API.

MSC3995 hub mode is an opt-in optimisation layered on top, negotiated per room
via `m.room.hub`. Where every peer supports it, forks become structurally
impossible and the exception path is dead code.

---

## Where it stands

| Milestone | | |
|---|---|---|
| **M0** Prove the core | **Done** | Fork resolution vs `ruma-state-res` as a differential oracle; HAMT benchmarks; torn-write and restart recovery |
| **M1** Local homeserver | **Done** | Rooms, timelines, state, membership, moderation, relations, threads, redaction, receipts, typing, account data, push rules, aliases, filters, `/context` |
| **M2** Modern clients | **Done** | Media + thumbnails, S3 backend, Simplified Sliding Sync, E2EE transport, device lists, key backup, cross-signing, URL previews |
| **M3** Federation | Interoperating | Signed requests, join/invite/leave/knock handshakes, backfill, state reads, outbound queue with backoff — live Spindle↔Synapse rooms in both directions; MSC4242 state-DAG rooms (Hydra phase 2) and E2EE keys, to-device and device lists across the seam to a Neutrino mesh node, measured by a loopback rig |
| **M4** Ecosystem | Substantial | Appservices (transactions, MSC2409 to-device, MSC4190), MSC3861 delegated auth, the `/_synapse/mas/*` surface, and a built-in OIDC provider so Element X login needs one binary |
| **M5** Lifecycle | Substantial | 18 admin endpoints (also at `/_synapse/admin/v1`), `/metrics` with the fork-case counter, backup/restore/verify-media, versioned migrations |
| **M6** Differentiators | Not started | Hub mode, MLS |
| **M7** MatrixRTC | Server side served | **MSC4140 delayed events** — the dead-man's switch that stops calls accumulating ghost participants, which no other Rust homeserver has — plus MSC4354 sticky events, MSC4143 transport discovery, a built-in LiveKit JWT service or the OpenID round trip for an external one, ringing and decline. Element Call's own Playwright suite runs with Spindle in Synapse's seat: thirteen specs pass, among them a two-party call with video through LiveKit and MatrixRTC 2.0 sticky-event membership with a rejoin after an improper leave. Ringing, churn, a restart mid-call and the federated call are what remains of the gate |

The workspace has **292 routes**, a **310-test Complement ratchet**, and more
than 100 test suites. CI gates the first two numbers. It parses the
[dashboard](docs/dashboard.md) from the router and fails on drift. The ratchet
file needs every entry to pass. Thus, the numbers match `main`, not the date
when someone last edited this paragraph.

### Throughput (dated snapshot)

The table below is a dated analysis snapshot, not the current benchmark result.
See the [published benchmark results](https://tuna-os.github.io/spindle/) for
the latest run. The [benchmark notes](docs/benchmarks.md) explain the method
and the limits of snapshot comparisons.

The trial used the same host and driver for each server. Synapse 1.159.0 ran on
both back ends. The database matters in a *write throughput* comparison.
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
figure this one holds *under concurrency*. Both servers had the same four-core
constraint, so each had the same handicap. The ratio is the result.

---

## What this is honest about

This section is longer than the promotional text, on purpose.

**The architectural win is a constant factor, not an asymptotic one.**
Fork resolution costs 2.2–3.1× less than `ruma-state-res` across the full
`max_fork_window` range. The ratio stays flat across that range. In current
homeservers written in Rust, state resolution does not run on a fork-free event.
Thus, "we skip it and they don't" was never true of them. Linear storage
removes the per-event records that the algorithm needs to exist. Examples
include extremity sets and state-group delta stacks.

**State resolution must agree with Matrix.** ADR 0005 retired the old merge of
fork slots after counterexamples. Each room version has a resolver for fork
states that differ. Scheduled checks preserve the counterexamples,
compare with `ruma-state-res`, and test the fork-window search against an
exhaustive walk. A disagreement on the live path is a release blocker.

**Benchmarks show losses next to wins.**
[docs/benchmarks.md](docs/benchmarks.md) lists the losses, investigations, and
two retracted claims. This README first published both claims. One curve showed
an incorrect improvement in scale; the test rig with four cores caused it. The
other claimed a 1.33× improvement against a baseline from the wrong branch.

**Small differences exceed the benchmark host's resolution.** Four cores
produce 10–14% spread between runs. Therefore, the gates for performance count
reads from storage, lock acquisitions, and coalesced fsyncs instead of
wall-clock time. The record marks any change that appears only in-process as a
[non-result](docs/benchmarks.md).

**Federation numbers are still design targets.** Everything measured is one
server. The architectural claim gets its real test as the federation rig grows.

**After release, reviewers found a flaw twice. Both flaws affected
authorization.** Nine read endpoints served any room's contents to any account
(#257, #258). The fixes add a route-table check to the test suite. Issue #268
exists because the discovery rate was "however much someone happened to look".

[SPEC §21](SPEC.md) lists the risks that would invalidate the headline claim.

---

## Documentation

| | |
|---|---|
| [**SPEC.md**](SPEC.md) | The design the code is held against — the log, state without state resolution, authorization, fork handling, trust model, concurrency, performance model, risks |
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
| [docs/policy-servers.md](docs/policy-servers.md) | Room opt-in, approval checks and Matrix Foundation enrollment |
| [docs/mesh-federation.md](docs/mesh-federation.md) | Federating with a Bluetooth mesh: the venue system, the loopback evidence, and the Neutrino gateway patch |
| [docs/venue-playbook.md](docs/venue-playbook.md) | Setting up the mesh and the conference Spindle, the test ladder, and the go/no-go list for 3,000 attendees |
| [docs/venue-gateway.md](docs/venue-gateway.md) | The venue gateway: the Neutrino node with the uplink, how to build, run, pair, and troubleshoot it |
| [docs/dashboard.md](docs/dashboard.md) | Generated endpoint and milestone coverage |
| [docs/mscs.md](docs/mscs.md) | Every MSC served, partly served, planned or declined — generated from the ledger CI holds to the code |
| [docs/spec-gaps.md](docs/spec-gaps.md) | What the pinned Matrix spec defines that the router does not serve, by the version that added it |
| [docs/maintenance.md](docs/maintenance.md) | Keeping up: the gates, the ratchets, the weekly upkeep report, and how a spec release or an MSC is absorbed |

---

## Building and contributing

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
scripts/complement.sh               # the interop ratchet (needs Docker)
```

`rust-toolchain.toml` pins **1.90.0**, so rustup fetches the right compiler on
its own. Storage is [fjall](https://github.com/fjall-rs/fjall) 3 — embedded,
so there is no database to provision.

CI gates on all of the above plus the Complement ratchet. It also checks config
drift, generated-dashboard drift, pinned actions, and benchmark tools. See
`CONTRIBUTING.md` for more detail and `docs/releasing.md` for tag behavior. New
performance work must include an assertion based on deterministic counts, not
elapsed time.

## License

Choose either the **[MIT](LICENSE-MIT) OR
[Apache-2.0](LICENSE-APACHE)** license. Contributions use the same terms.
[`LICENSING.md`](LICENSING.md) records the checks before the license choice.
It explains why the project does not use AGPL despite Synapse's AGPL license.
It also explains the copyright line.
