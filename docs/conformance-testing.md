# Conformance and interoperability testing

How Spindle proves the two claims the design rests on: that **existing clients
cannot tell the difference**, and that **existing homeservers cannot tell the
difference**. Neither is self-evident — a server that stores rooms as a linear
log and skips state resolution has to earn them empirically.

Almost all of the machinery already exists. This document surveys it, says what
each piece buys us, and specifies the three places we have to build something
ourselves.

---

## 1. What has to be proven

| # | Claim | Failure mode if untested |
|---|---|---|
| **C1** | Any spec-compliant client works unmodified against Spindle. | Element renders a broken timeline, sync loops, E2EE silently fails to establish. |
| **C2** | Existing homeservers federate with Spindle without knowing it is different. | Synapse rejects our PDUs, forks the room, or diverges on state. |
| **C3** | Linearization is semantically identical to DAG state resolution. | Rooms drift: our state and a peer's state disagree, which is a state reset with extra steps. |

C1 and C2 are *conformance* — the existing suites cover them well. C3 is
Spindle-specific and nothing off the shelf tests it, because no other server
makes the claim. §5 is where that gets built.

---

## 2. The existing toolbox

| Tool | Language / form | Covers | Value to Spindle |
|---|---|---|---|
| **[Complement](https://github.com/matrix-org/complement)** | Go + Docker, black-box | CS API, federation, room semantics | **Primary gate.** The current conformance suite; what Synapse, Dendrite, Conduit and conduwuit are all measured against. |
| **[sytest](https://github.com/matrix-org/sytest)** | Perl, black-box, ~900 tests | Older/broader CS + federation coverage | Secondary. New tests go to Complement, but sytest still covers corners Complement has not reached. Worth running for coverage, not as the gate. |
| **[complement-crypto](https://github.com/matrix-org/complement-crypto)** | Go, drives real client SDKs | E2EE across rust-sdk FFI and js-sdk, including interop between them | **The E2EE gate.** Exercises the server's key/to-device/device-list plumbing through the SDKs clients actually ship. Has a stable GitHub Action. |
| **[matrix-spec](https://github.com/matrix-org/matrix-spec)** | OpenAPI + JSON Schema | Request/response shapes, event schemas | Machine-readable ground truth for schema-level assertions (§4.3). |
| **[are-we-synapse-yet.py](https://github.com/element-hq/dendrite/blob/main/are-we-synapse-yet.py)** | Python, parses `results.tap` | Reporting | Groups results into features and reports per-area percentages. Directly adaptable as our progress dashboard. |
| **[trafficlight](https://github.com/matrix-org/trafficlight)** | Coordinator + per-client adapters | Multi-client, client↔client scenarios | Later-stage. Adapters (element-web, element-call) register and poll for commands, so scenarios span two real clients. |
| **[Element Web Playwright suite](https://github.com/element-hq/element-web)** | TypeScript + Docker | Real client against a real homeserver | Its `playwright/plugins/homeserver/` starts homeservers in Docker; adding a Spindle plugin gives us Element's own test suite as our client-compat matrix. |
| **[matrix-federation-tester](https://github.com/matrix-org/matrix-federation-tester)** | Go service | Live deployment federation readiness | Deployment smoke test — `.well-known`, SRV, keys, TLS. Public instance at `federationtester.matrix.org/api/report?server_name=`. |
| **[Tuwunel](https://github.com/matrix-construct/tuwunel)** | Rust homeserver | Working Complement, complement-crypto, interop and appservice CI | **Reference implementation of this whole plan.** Its `docker/complement.sh` and `.github/workflows/summarise/` are the closest thing to a finished version of what §3–§5 describe. |
| **[Continuwuity](https://github.com/continuwuity/continuwuity)** | Rust homeserver | Complement image contract + committed results ledger | `complement/complement-entrypoint.sh` is a working image contract; `tests/test_results/complement/test_results.jsonl` is the ratchet ledger as a real artifact. |

---

## 3. Complement is the gate — what it costs to adopt

Complement is black-box over Docker: it knows nothing about the implementation,
which is exactly the property we need. Adopting it is a Dockerfile plus a CI job.

### 3.1 The image contract

Complement requires a homeserver image that:

- `EXPOSE`s **8008** (client, plain HTTP) and **8448** (federation, HTTPS).
- Reads `SERVER_NAME` from the environment at runtime.
- Trusts the CA mounted at `/complement/ca/ca.crt`, and signs its own federation
  certificate at container start with `/complement/ca/ca.key`.
- Answers `GET /_matrix/client/versions` with `200` once ready, and declares a
  `HEALTHCHECK` so Complement can wait for it (bounded by
  `COMPLEMENT_SPAWN_HS_TIMEOUT_SECS`).
- Manages its own storage inside the container and can be started repeatedly
  from the same `CMD`/`ENTRYPOINT`.
- Accepts `complement` as the registration shared secret on the admin register
  endpoint, so tests can provision users.

For Spindle this is small: generate a cert at startup, point the config at the
mounted CA, bind both listeners, and default the store to a container-local
path. It is a `Dockerfile` and a ~20-line entrypoint script, not an
architectural change.

### 3.2 Running it

```bash
COMPLEMENT_BASE_IMAGE=complement-spindle:latest \
  go test -v -tags="spindle_blacklist" ./tests/...
```

Complement uses **inverted build tags** for exclusions — `synapse_blacklist`,
`dendrite_blacklist`, `conduit_blacklist`, `conduwuit_blacklist` already exist.
We add `spindle_blacklist` the same way.

### 3.3 The ratchet

The blacklist is the honest version of "how compliant are we". Two rules make it
a ratchet rather than a rug:

1. **It may only shrink.** A CI job asserts the count never increases; adding an
   entry is a deliberate PR with a reason and a linked issue.
2. **Every entry carries a reason.** "Fails because Spindle is faster but
   different" is not a reason — that is a Spindle bug, per the spec's §19.1.

Report with an `are-we-synapse-yet`-style grouping so progress is legible per
feature area (registration, login, sync, federation, E2EE) rather than as one
number.

---

## 4. Coverage beyond Complement

### 4.1 Client E2E — proving C1 against real clients

Complement asserts the API is correct. It does not assert that *Element* works,
which is a different claim: clients depend on emergent behavior (sync token
stability, `prev_batch` semantics, ordering under gappy sync) that a
conformance test may not pin down.

- **Element Web / Desktop:** add a Spindle plugin under
  `playwright/plugins/homeserver/` alongside the Synapse and Dendrite ones, then
  run Element's own suite against us. This is the highest-value client test we
  can get, because it is maintained by the client's authors and updated as the
  client changes.
- **Element X (iOS/Android):** exercises **Simplified Sliding Sync (MSC4186)** —
  our newest and least-proven surface, and the one most likely to diverge.
  Priority target once M2 lands.
- **Others** (Cinny, Nheko, Fluffychat): manual matrix per release initially;
  automate only if a specific incompatibility recurs.

### 4.2 E2EE — complement-crypto

The server is a transport for E2EE, but the transport has sharp edges: one-time
key claim atomicity, to-device ordering, device-list change propagation across
federation. complement-crypto drives the real rust-sdk and js-sdk against a
homeserver and can run them **against each other**, which is precisely the
interop shape we need. Adopt it at M2 rather than writing E2EE tests by hand.

### 4.3 Schema conformance from the spec itself

`matrix-spec` ships OpenAPI definitions and JSON Schemas for every event type.
Building them is a documented step (`python ./scripts/dump-openapi.py` →
`scripts/openapi/api-docs.json`).

Wire that into an integration-test middleware that validates every response
Spindle emits against the schema for its endpoint, enabled in test builds. This
catches a whole class of "technically works, subtly wrong" bugs — a missing
optional field, a stringified integer — that black-box behavioral tests miss
because clients happen to tolerate them. Cheap to build, and it fails loudly.

---

## 5. What we have to build ourselves

Three gaps. The first is shared with every homeserver; the second and third are
consequences of Spindle's design and are the tests that actually matter.

### 5.1 Heterogeneous federation — mostly configuration

**Correction.** An earlier revision of this document claimed Complement drives a
single `COMPLEMENT_BASE_IMAGE` per run, could not put a real Synapse on the other
end of the wire, and therefore forced us to build a bespoke compose rig. **That
is wrong.** Complement natively supports per-homeserver image overrides, so
heterogeneous federation is a configuration of the suite we are already
adopting, not a second harness.

Upstream `config/config.go` documents `COMPLEMENT_BASE_IMAGE_*`:

> This allows you to override the base image used for a particular named
> homeserver. […] This allows Complement to test how different homeserver
> implementations work with each other.

So a mixed deployment is:

```bash
COMPLEMENT_BASE_IMAGE=complement-spindle:latest \
COMPLEMENT_BASE_IMAGE_hs2=ghcr.io/element-hq/synapse/complement-synapse:latest \
  go test -v -tags="spindle_blacklist" ./tests/...
```

`hs1` is Spindle, `hs2` is a real Synapse, and every federation test in the suite
now exercises the interop path. Element publishes that Synapse image, so we do
not build or maintain a peer.

**Gotcha — the suffix must be lowercase.** The upstream doc comment says matching
is case-insensitive and gives the example `COMPLEMENT_BASE_IMAGE_HS1=…`. It is
not, and that example does not work: `config.go` stores the captured suffix
verbatim into `BaseImageURIs`, while `deployer.go` looks it up by the blueprint's
lowercase homeserver name (`hs1`, `hs2`). A Go map lookup is case-sensitive, so
the conventional uppercase form is silently ignored and the run quietly stays
homogeneous — passing, and testing nothing. Use `COMPLEMENT_BASE_IMAGE_hs2`.
Tuwunel's runner lowercases the suffix for exactly this reason. Worth reporting
upstream, since a silently-ignored override is worse than an error.

**What Tuwunel does that we should copy.** It runs interop as a separate,
**report-only** board rather than gating the main one, because a heterogeneous
result set legitimately does not match the homogeneous baseline. Its summariser
then diffs interop against that baseline so a shared gap renders differently from
a true interop regression, and it annotates known peer-side false positives — for
example Synapse 404ing its own deprecated unauthenticated `/_matrix/media/v3`
endpoint per MSC3916, which is the peer's deprecation and not our bug. It also
runs the pairing in **both directions**, swapping which implementation is `hs1`.

**Built.** Heterogeneous Complement federation is wrapped in `scripts/complement.sh` via `COMPLEMENT_INTEROP_IMAGE` and per-homeserver lowercase overrides, and summarized against the homogeneous baseline by `scripts/complement-interop.py`. In addition, `crates/spindle-server/tests/federation_fork.rs` asserts that `/state` and `/state_ids` return the exact same agreed set across disjoint forks, and explicitly drives the partition-and-heal scenario where both servers converge without triggering state resolution.

### 5.2 Fork injection — testing the exception path

The spec's §9 claims forks are rare and cheap to resolve. Rare is an assumption
about production; **cheap and correct** must be tested, and can be, because
the federation test harness lets a test act as a homeserver and craft PDUs
with arbitrary `prev_events`.

The harness in `crates/spindle-server/tests/federation_fork.rs` deliberately produces each case:

| Case | Injection | Assert |
|---|---|---|
| 1 — non-state event on a stale head | Send a message PDU pointing at an old event | Appended at tail, no state res invoked, client order sane |
| 2 — state event, disjoint key | Fork with a `(type, state_key)` untouched in the window | Single `apply()`, result matches state res |
| 3 — genuine conflict | Two competing PL or membership changes in-window | Contested counter moves, deferred via 503 without corruption |
| Window overflow | Fork deeper than `resident_window` | Safely refuses merge via 503, stays *correct*, and alerts |

Instrument the case-1/2/3 counters (spec §17.2) and assert on them: a test that
passes while silently taking the expensive path is a test that has stopped
measuring what it claims to.

### 5.3 The equivalence oracle — testing C3 directly

The load-bearing claim is §9.3: window-bounded resolution produces exactly what
full resolution would. Test it as a property, in-process, against
`ruma-state-res` as the oracle — the same implementation running in production
elsewhere:

```
property linear_fold_matches_state_res:
    for arbitrary chain DAG D:
        assert fold_state(D) == ruma_state_res_v2(D)

property window_bounded_matches_full:
    for arbitrary forked DAG D, fork depth ≤ max_fork_window:
        assert window_state_res(D) == ruma_state_res_v2(D)

property linearization_is_valid_topological_order:
    for arbitrary DAG D:
        assert is_topological_order(li_order(D), D)
```

The generator has to produce adversarial shapes, not random ones: deep forks,
wide fan-in, power-level races, ban/unban races, concurrent membership on the
same target, restricted-join edge cases. This is fast (no Docker, no network),
so it runs on every commit, and a counterexample is a release blocker.

---

## 6. CI topology

| Stage | Runs | Gate |
|---|---|---|
| Per commit | Unit tests, §5.3 property tests, schema validation (§4.3), fuzz corpus | Blocking |
| Per PR | Complement with `spindle_blacklist`, blacklist-size ratchet | Blocking |
| Per PR | §5.2 fork injection | Blocking |
| Nightly | sytest, full fuzzing, §5.1 interop run against pinned Synapse (report-only board, both directions) | Non-blocking, tracked |
| Nightly | complement-crypto | Blocking from M2 |
| Weekly | Interop rig against Synapse `develop`; Element Web Playwright suite | Non-blocking, alerts |
| Release | Full matrix + manual client pass + federation tester against a live deploy | Blocking |

## 7. Sequencing against the milestones

| Spec milestone | Testing that lands with it |
|---|---|
| **M0** Core | §5.3 property tests. These come *first* — they are the design's proof, and they need no server. |
| **M1** Client API, local | Complement image + CS-API subset; schema validation; blacklist ratchet established. |
| **M2** E2EE + modern sync | complement-crypto; Element Web Playwright plugin; Element X manual pass. |
| **M3** Federation | Full Complement including federation; §5.2 fork injection; §5.1 interop run against Synapse plus the `/state_ids` agreement assertion. |
| **M4** Linearized mode | Two-Spindle hub/participant scenarios; hub failover under induced partition; equivocation-proof tests. |
| **M5** Production | sytest for residual coverage; trafficlight; federation tester in deploy verification; published benchmark harness. |

---

## 8. Honest assessment of cost

The conformance work is mostly **adoption, not invention** — one Dockerfile
gets us the industry-standard suite, and a GitHub Action gets us E2EE interop.
The invented parts are narrower than first scoped: cross-implementation
federation turned out to be configuration (§5.1), leaving the state-agreement
assertion, fork injection (§5.2), and the equivalence oracle (§5.3).

Two things are worth budgeting for honestly:

- **The long tail of client compatibility.** Spec §21/R6 names this as the
  historical failure mode for every alternative homeserver: clients depend on
  Synapse behaviors that are not in the spec. No suite finds these — only
  running real clients does, which is why §4.1 is not optional.
- **Complement's blacklist is a debt ledger.** Every entry is a compatibility
  gap someone will eventually hit. The ratchet keeps it honest; nothing keeps
  it small except doing the work.
