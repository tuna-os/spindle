# Spindle

**A Matrix homeserver that stores rooms as a linear log, so state resolution
never runs on the hot path.**

[**Benchmarks vs Synapse, Continuwuity and Tuwunel**](https://tuna-os.github.io/spindle/comparisons.html)
· [micro-benchmarks](https://tuna-os.github.io/spindle/)
· [spec coverage dashboard](https://tuna-os.github.io/spindle/dashboard.html)
· [SPEC.md](SPEC.md)

> **Status: an experiment under construction, not a deployment.** The
> client-server surface is broad and tested, federation interoperates with real
> Synapse, and nothing here has ever run in production. There is no release, no
> upgrade path promise, and the storage format has already broken once —
> deliberately, with the [test that caught it](crates/spindle-store/tests/backend_compatibility.rs)
> kept and inverted rather than deleted.

---

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
and it works unmodified — Spindle serves ordinary room version 11 and 12 rooms,
so there is no client capability to negotiate.

[`spindle.example.toml`](spindle.example.toml) documents every setting, and a
CI gate fails if a config field exists in the code and not in that file.

**Other commands:** `promote-admin` (mints the first admin offline),
`backup` / `restore` / `verify-media`, `migrate`. See
[docs/lifecycle.md](docs/lifecycle.md).

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
Synapse, Dendrite and Conduit federate with it over the unmodified
Server-Server API.

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
| **M3** Federation | Interoperating | Signed requests, join/invite/leave/knock handshakes, backfill, state reads, outbound queue with backoff — live Spindle↔Synapse rooms in both directions |
| **M4** Ecosystem | Substantial | Appservices (transactions, MSC2409 to-device, MSC4190), MSC3861 delegated auth, the `/_synapse/mas/*` surface, and a built-in OIDC provider so Element X login needs one binary |
| **M5** Lifecycle | Substantial | 18 admin endpoints (also at `/_synapse/admin/v1`), `/metrics` with the fork-case counter, backup/restore/verify-media, versioned migrations |
| **M6** Differentiators | Not started | Hub mode, MLS |
| **M7** MatrixRTC | Started | **MSC4140 delayed events** — the dead-man's switch that stops calls accumulating ghost participants. No other Rust homeserver has them |

**180 routes** and a **291-test Complement ratchet** in CI, over a workspace of
100+ test suites. The first two are gated — the [dashboard](docs/dashboard.md)
is parsed from the router and CI fails on drift, and the ratchet is a file every
entry of which must pass — so what they say matches `main` rather than matching
when someone last edited this paragraph.

### Throughput

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
Resolving a fork is 2.2–3.1× cheaper than `ruma-state-res` across the whole
range out to a full `max_fork_window` — flat, not widening. And the current
Rust homeservers already skip state resolution on a fork-free event, so "we
skip it and they don't" was never true of them. What linear storage removes is
the per-event *bookkeeping* the algorithm needs in order to exist — extremity
sets, state-group delta stacks — not the algorithm.

**The load-bearing claim is the equivalence theorem** (SPEC §9.3): that
window-bounded state resolution produces exactly what full state resolution
would. It is tested as one, differentially against `ruma-state-res`, for every
fork the fast path claims to handle. A counterexample is a release blocker.

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

The risks that would invalidate the headline claim are enumerated in
[SPEC §21](SPEC.md).

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
| [docs/rate-limits.md](docs/rate-limits.md) | Every rate and cap, and the growth nothing bounds yet |
| [docs/matrix-rtc.md](docs/matrix-rtc.md) | Calls end to end: the SFU, the JWT service built in or beside, and what a token cannot promise |
| [docs/dashboard.md](docs/dashboard.md) | Generated endpoint and milestone coverage |

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

CI gates on all of the above plus the Complement ratchet, a config-drift check,
a generated-dashboard drift check, and pinned-action and benchmark-tooling
checks. New performance work is expected to arrive with a counting assertion
rather than a timing one, for the reason given above.

## License

Dual-licensed under **[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)**, at
your option; contributions are accepted under the same terms.
[`LICENSING.md`](LICENSING.md) records what was checked before choosing, why
not AGPL despite Synapse being AGPL, and why the copyright line reads as it
does.
