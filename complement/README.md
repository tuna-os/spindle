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
