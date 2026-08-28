# Complement image

Black-box conformance against the real Matrix test suite (`docs/conformance-testing.md`).

## What this image does today

It satisfies Complement's **startup** contract:

- comes up from a single `ENTRYPOINT`, repeatedly, with its own storage,
- requires `SERVER_NAME` and fails loudly without it,
- installs the CA mounted at `/complement/ca/ca.crt` and signs a federation
  certificate with `/complement/ca/ca.key`,
- answers `GET /_matrix/client/versions` on **8008**,
- declares a `HEALTHCHECK` so Complement can wait for readiness,
- runs as a non-root user (uid 10001).

## The ratchet

`allowlist.txt` names every Complement test Spindle must pass — 117 test
nodes at seeding (19 whole CS-API suites plus federation-package subtests),
each verified across two consecutive full local runs before entering the
list. `scripts/complement-check.py` enforces it against a `go test -json`
ledger and fails naming whatever regressed.

CI (`complement-suite` in `.github/workflows/compliance.yml`) runs it two
ways:

- **pull requests** run exactly the protected subset, so the gate is fast
  and every merge proves the list still holds;
- **pushes to main** run the whole suite, so newly passing tests surface as
  candidates. Promotion is a reviewed edit to `allowlist.txt`, never
  automatic — a flaky test promoted by a script teaches everyone to ignore
  the gate.

The suite itself is upstream `matrix-org/complement`, unforked, pinned by
revision in `scripts/complement.sh` — the same arrangement Continuwuity and
Tuwunel use. TLS on 8448 is served with the Complement-CA-signed
certificate; the remaining large gaps (outbound remote joins, federated
invites, EDUs over federation) are tracked on the M3 issues.

## Why the image builds in two stages

`complement/Dockerfile` compiles the workspace's dependencies in a layer
that sees only `Cargo.toml`/`Cargo.lock` and placeholder sources, then the
real sources in a second layer. Every CI run changes our own code and
nothing else, and without the split that recompiles the entire dependency
graph — measured locally:

| | one-line source change | cold, no cache |
|---|---|---|
| single layer | 2m11s | 2m27s |
| split | **40s** | 2m36s |

Cold is 9s slower (two cargo invocations); the case that actually happens
is 3.3× faster. A runner has no layer cache of its own, so CI exports one
(`cache-to: type=gha` in `compliance.yml`) — without that export the split
buys nothing there.

Adding a crate without adding its manifest to the dependency layer is not
a correctness problem: that layer simply will not cover it and the real
build compiles it from scratch. The failure mode is a slower build, not a
wrong one.

## Running it

```bash
docker build -f complement/Dockerfile -t complement-spindle:latest .

# Homogeneous.
COMPLEMENT_BASE_IMAGE=complement-spindle:latest \
  go test -v ./tests/...

# Against a real Synapse peer. The suffix must be lowercase — the upstream
# doc's uppercase example is silently ignored and leaves the run homogeneous.
# See docs/conformance-testing.md §5.1.
COMPLEMENT_BASE_IMAGE=complement-spindle:latest \
COMPLEMENT_BASE_IMAGE_hs2=ghcr.io/element-hq/synapse/complement-synapse:latest \
  go test -v ./tests/...
```

`scripts/complement.sh` is the wrapper CI runs: it builds the image, clones
the pinned suite, and writes the ledger. The same stream passes through
`scripts/complement-progress.py`, so a run prints one line per test as it
lands and the log of a full suite reads as progress rather than ten minutes
of silence:

```
[   16.8s] PASS TestFetchEvent (15.8s)
[   22.4s] PASS TestSendMessageWithTxn (5.6s)
[   22.7s] ==== 2 passed, 0 failed, 0 skipped
```

Only *protected* failures print their captured log underneath — the place
the per-request traffic lives (`[CSAPI] PUT hs1/…/send/m.room.message =>
200 OK`). A full run fails around a hundred unclaimed tests, which is the
debt ledger working as intended; dumping each one's server tracing buried
the failures that actually break the build, so those get one line and a
`[not protected]` marker instead. The ledger keeps every line either way —
the printer renders, it never judges, and `scripts/complement-check.py`
remains the gate.
