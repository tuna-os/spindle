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

## What it does not do

**No Complement test passes yet, and `allowlist.txt` is empty for that reason.**
The server currently implements discovery and health only — there is no
registration, no login, no room creation, so there is nothing for a conformance
test to exercise. The image exists so that the startup contract is satisfied
before the tests need it, not to imply the tests pass.

Specifically missing:

| Gap | Lands with |
|---|---|
| Registration, login, access tokens | #11 |
| Rooms, state, timelines | #7 |
| Sync | #10 |
| **TLS on 8448** — the certificate is generated but nothing serves it | #14 (M3 federation) |
| Admin shared-secret registration (`complement` secret) | #11 |

Until federation lands, only client-side tests are reachable at all, and none
of those pass either.

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
